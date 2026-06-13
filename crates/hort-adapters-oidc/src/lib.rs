//! # hort-adapters-oidc — OIDC Identity Provider Adapter
//!
//! Implements [`IdentityProvider`] by validating IdP-issued JWTs against a
//! JWKS fetched via OpenID-Connect discovery. Stateless per-request beyond
//! an in-memory JWKS cache with a configurable TTL and key-rotation-aware
//! invalidation.
//!
//! Design: ADR 0018 + `docs/auth-catalog.md`.
//!
//! ## Validation flow
//!
//! 1. Decode the JWT header without verification — read `kid` and `alg`.
//!    Reject `HS*` and `none` on the production path: HMAC keys have no
//!    place in an asymmetric IdP trust model.
//! 2. Look up the JWK by `kid` in the cache. On miss or TTL expiry,
//!    refresh the JWKS via `.well-known/openid-configuration` → `jwks_uri`.
//! 3. Verify signature, `iss`, `aud`, `exp`, and `nbf` using the matched
//!    JWK converted to a [`jsonwebtoken::DecodingKey`]. Leeway: 30 seconds.
//! 4. Map claims into [`IdpClaims`]. Missing `groups` is allowed (empty
//!    Vec). Missing `sub`, `email`, or `iat` → [`OidcValidationError::ClaimMissing`].
//!
//! Every failure surfaces as a variant of [`OidcValidationError`]:
//! - Integrity failures (bad signature against a JWK we already hold,
//!   unusable JWK, signing key absent from a freshly fetched JWKS) →
//!   [`OidcValidationError::SignatureInvalid`].
//! - Wrong audience (token's `aud` does not include the configured
//!   audience) → [`OidcValidationError::AudienceMismatch`]. Carved out
//!   of `SignatureInvalid` so the structured log names the actual cause
//!   — a Keycloak audience-mapper misconfiguration was being reported as
//!   "signature invalid", misdirecting operators.
//! - JWKS / discovery fetch failures (transport error, non-2xx upstream
//!   status, oversize body, malformed JSON) →
//!   [`OidcValidationError::IdpUnavailable`] — kept distinct from
//!   `SignatureInvalid` so the auth metric distinguishes an IdP outage
//!   from a credential-stuffing campaign.
//! - Expiry → [`OidcValidationError::Expired`].
//! - Wrong issuer → [`OidcValidationError::UnknownIssuer`].
//! - Token shape rejections before signature verification (bad header,
//!   disallowed algorithm, missing `kid`) → [`OidcValidationError::Malformed`].
//! - Missing / unparseable required claim → [`OidcValidationError::ClaimMissing`].
//!
//! The enum is the port-contract classifier (see `hort-domain`
//! `OidcValidationError`). Middleware pattern-matches on the variant;
//! no substring inspection crosses the port boundary.
//!
//! ## Key rotation handling
//!
//! On **signature-invalid** (not a kid miss — an actual bad-signature), the
//! cache is evicted so the NEXT request refetches the JWKS. Covers the
//! rotate-in-flight case where a withdrawn key is still presented by a
//! caller whose token was minted moments ago.
//!
//! ## No payload logging
//!
//! Tokens, claim payloads, and email addresses never appear in tracing
//! output. Only non-secret metadata (issuer URL, kid, error kind) does.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use chrono::{TimeZone, Utc};
use futures::StreamExt;
use hort_config::ExtraTrustAnchors;
use hort_domain::events::{system_actor, DomainEvent, OidcKeyRotated, StreamId};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::identity_provider::{IdentityProvider, IdpClaims, OidcValidationError};
use hort_domain::ports::BoxFuture;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

mod extra_ca;
mod internal;
mod metrics;
mod multi_issuer;

pub use extra_ca::ExtraCaApplyError;
pub use multi_issuer::MultiIssuerJwksValidator;

use crate::metrics::{
    emit_jwks_refresh, emit_oidc_key_rotation, JwksRefreshResult, OidcKeyRotationResult,
    USER_LOGIN_ISSUER,
};

// ---------------------------------------------------------------------------
// Public adapter
// ---------------------------------------------------------------------------

/// OIDC-backed [`IdentityProvider`].
///
/// Construct with [`OidcProvider::new`] — the constructor does NOT perform
/// any network I/O; the first `validate_token` call triggers the initial
/// JWKS fetch. This keeps startup deterministic and moves IdP-reachability
/// failures to a place where they can be surfaced as per-request auth
/// errors, not process-wide startup panics.
pub struct OidcProvider {
    issuer_url: String,
    audience: String,
    groups_claim: String,
    http: reqwest::Client,
    jwks: Arc<RwLock<JwksCache>>,
    /// Leeway (seconds) applied to `exp` / `nbf`.
    leeway_seconds: u64,
    /// Algorithms the adapter will accept. Production callers use
    /// [`OidcProvider::new`] which locks this down to asymmetric algs;
    /// tests can swap in HS256 via [`OidcProvider::with_algorithms`].
    accepted_algorithms: Vec<Algorithm>,
    /// Per-kid signature-mismatch eviction cooldown. A second
    /// `SignatureMismatch` eviction for the same kid within this window
    /// is throttled (no-op, no refetch). First-seen kids
    /// (`KidNotInCache`) bypass the backoff and always refresh — the
    /// legitimate-key-rotation invariant must not be blocked by the DoS
    /// mitigation.
    eviction_backoff: Duration,
    /// Upper bound on discovery + JWKS response body size. Responses
    /// larger than this are classified as
    /// [`JwksRefreshResult::BodyTooLarge`] and the cache stays stale.
    /// Closes the DoS vector where a malicious or misconfigured IdP
    /// returns an unbounded body and hort-server OOMs.
    body_max_bytes: usize,
    /// Optional event store for appending [`OidcKeyRotated`] events on
    /// observed JWKS rotations (ADR 0018). `None` in tests that do not
    /// exercise the audit pathway; `Some` in production wiring (see
    /// `hort-server::cli::serve`). When `None`, only the metric +
    /// tracing emission fires; the rotation observation is not lost
    /// to operators (it shows up in the metric and the structured
    /// log), only the immutable audit record is skipped.
    event_store: Option<Arc<dyn EventStore>>,
}

/// Default per-kid signature-mismatch eviction cooldown (design doc §2.11
/// — `HORT_JWKS_EVICTION_BACKOFF_SECS` default).
pub const DEFAULT_EVICTION_BACKOFF: Duration = Duration::from_secs(10);

/// Default discovery + JWKS response body cap (design doc §2.11 —
/// `HORT_JWKS_RESP_BODY_MAX_SIZE` default, 1 MiB).
pub const DEFAULT_BODY_MAX_BYTES: usize = 1024 * 1024;

/// Default per-request HTTP timeout for OIDC discovery + JWKS fetches.
///
/// 10 seconds matches the upstream-proxy default and is generous enough
/// for a real JWKS fetch on a healthy network. Prevents a slow-loris IdP
/// from pinning a request indefinitely on the validation path.
///
/// Hard-coded rather than threaded through `Config` because no
/// `OidcResilienceConfig` struct exists today and the existing per-knob
/// env-var pattern (`HORT_JWKS_EVICTION_BACKOFF_SECS`,
/// `HORT_JWKS_RESP_BODY_MAX_SIZE`) would expand `with_resilience`'s
/// signature. Promoting this to an operator knob is a follow-on.
///
/// Alias kept for public-API stability; the canonical value now lives in
/// [`crate::internal::HTTP_DEFAULT_TIMEOUT`] and is shared by the
/// single-issuer (`OidcProvider`) and multi-issuer
/// (`MultiIssuerJwksValidator`) paths.
pub const DEFAULT_HTTP_TIMEOUT: Duration = internal::HTTP_DEFAULT_TIMEOUT;

/// Maximum number of per-kid eviction timestamps the backoff map retains.
/// Exceeding this cap triggers drop-oldest eviction on insert — bounds
/// memory when a forged-kid flood uses many distinct kids. Set well above
/// any plausible legitimate key-rotation churn (a production IdP typically
/// has < 10 active kids at any time).
const EVICTION_MAP_MAX_ENTRIES: usize = 1024;

/// Reason for evicting a kid from the JWKS cache.
///
/// Distinguishes the two eviction paths so the caller knows whether to
/// apply the DoS-mitigation backoff (design doc §2.5 + §4).
///
/// - [`EvictionReason::SignatureMismatch`] — token signature failed against
///   a JWK currently in cache. Could be legitimate key rotation OR a
///   forged-kid flood. Apply backoff: same-kid re-evictions within
///   [`DEFAULT_EVICTION_BACKOFF`] are no-ops.
/// - [`EvictionReason::KidNotInCache`] — token header carries a kid we've
///   never seen. Always a first-seen refresh; never throttled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvictionReason {
    /// Signature failed against a JWK currently in cache. Apply backoff.
    SignatureMismatch,
    /// Kid absent from cache — benign first-seen. No backoff. Currently
    /// only surfaced via direct `JwksCache::evict` calls (unit tests and
    /// potential future callers that want the loud "this happened
    /// because the key was unknown" distinction). The production
    /// [`OidcProvider::resolve_jwk`] path goes through
    /// [`JwksCache::replace`] on kid-miss instead, which is semantically
    /// equivalent but skips the backoff map lookup entirely.
    #[allow(dead_code)]
    KidNotInCache,
}

/// Algorithms accepted on the production path.
///
/// `HS*` is excluded — HMAC belongs to the registry-minted-JWT path in
/// `/v2/token` (Item 9), not to IdP validation, where a symmetric secret
/// would imply the adapter and the IdP share a signing key. `none` is not
/// listed here either; `jsonwebtoken` 10.x has no `Algorithm::None`
/// variant to begin with.
const PRODUCTION_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

const DEFAULT_LEEWAY_SECONDS: u64 = 30;

impl OidcProvider {
    /// Build a new OIDC provider.
    ///
    /// - `issuer_url` — the IdP's issuer URL (must equal the JWT `iss`).
    /// - `audience` — the expected `aud` claim, i.e. this server's identifier.
    /// - `groups_claim` — top-level claim name carrying groups
    ///   (e.g. `"groups"`). Nested paths (`realm_access.roles`) are a
    ///   future enhancement.
    /// - `jwks_cache_ttl` — how long a fetched JWKS stays fresh before
    ///   the NEXT validation triggers a refresh.
    /// - `extra_trust_anchors` — optional process-wide extra CA bundle.
    ///   When `Some`, every certificate in the bundle is added to the
    ///   underlying `reqwest::Client` trust store via
    ///   `apply_to_reqwest_builder`. When `None`, the platform default
    ///   trust store is used unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ExtraCaApplyError`] if any certificate in `extra_trust_anchors`
    /// is rejected by reqwest, or if `ClientBuilder::build()` fails.
    pub fn new(
        issuer_url: String,
        audience: String,
        groups_claim: String,
        jwks_cache_ttl: Duration,
        extra_trust_anchors: Option<&ExtraTrustAnchors>,
    ) -> Result<Self, ExtraCaApplyError> {
        Self::with_resilience(
            issuer_url,
            audience,
            groups_claim,
            jwks_cache_ttl,
            DEFAULT_EVICTION_BACKOFF,
            DEFAULT_BODY_MAX_BYTES,
            extra_trust_anchors,
        )
    }

    /// Attach an event-store for [`OidcKeyRotated`] audit appends
    /// (ADR 0018). Composition-root wiring step: production callers in
    /// `hort-server::cli::serve` call this on the fully-built provider
    /// so the audit pathway is live; tests that only exercise the
    /// validation contract leave it unset (the metric + tracing emission
    /// still fires).
    pub fn with_event_store(mut self, events: Arc<dyn EventStore>) -> Self {
        self.event_store = Some(events);
        self
    }

    /// Construct with JWKS resilience knobs tuned explicitly. Production
    /// callers wire the two values from `HORT_JWKS_EVICTION_BACKOFF_SECS`
    /// and `HORT_JWKS_RESP_BODY_MAX_SIZE` via `hort-server::Config`;
    /// tests use short intervals + small caps to exercise the DoS and
    /// oversize-body paths.
    ///
    /// - `eviction_backoff` — per-kid signature-mismatch cooldown. A
    ///   second same-kid signature-mismatch eviction within this window
    ///   is a no-op. Does NOT gate `KidNotInCache` evictions (legitimate
    ///   key-rotation invariant — design doc §4).
    /// - `body_max_bytes` — upper bound on discovery + JWKS response
    ///   body size. Responses exceeding this are rejected with
    ///   [`JwksRefreshResult::BodyTooLarge`] before parsing.
    /// - `extra_trust_anchors` — optional process-wide extra CA bundle.
    ///   When `Some`, every certificate in the bundle is added to the
    ///   underlying `reqwest::Client` trust store via
    ///   [`extra_ca::apply_to_reqwest_builder`]. When `None`, the
    ///   platform default trust store is used unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ExtraCaApplyError`] if any certificate in
    /// `extra_trust_anchors` is rejected by reqwest, or if
    /// `ClientBuilder::build()` fails. Both are boot-time failures; the
    /// process cannot run in a partially-trusted state.
    pub fn with_resilience(
        issuer_url: String,
        audience: String,
        groups_claim: String,
        jwks_cache_ttl: Duration,
        eviction_backoff: Duration,
        body_max_bytes: usize,
        extra_trust_anchors: Option<&ExtraTrustAnchors>,
    ) -> Result<Self, ExtraCaApplyError> {
        // HTTP client construction (extra-CA, redirect cap, per-client
        // timeout, TLS version pin) is centralised in
        // `crate::internal::build_http_client` so the single-issuer and
        // multi-issuer paths cannot drift on the security-critical client
        // configuration. The full rationale for each policy lives at the
        // call site there (ADR 0010).
        let http = internal::build_http_client(extra_trust_anchors)?;
        Ok(Self {
            issuer_url,
            audience,
            groups_claim,
            http,
            jwks: Arc::new(RwLock::new(JwksCache::new(jwks_cache_ttl))),
            leeway_seconds: DEFAULT_LEEWAY_SECONDS,
            accepted_algorithms: PRODUCTION_ALGORITHMS.to_vec(),
            eviction_backoff,
            body_max_bytes,
            // Left as `None` from constructor and attached via
            // [`Self::with_event_store`] at the composition root.
            // Keeping the constructor signature unchanged preserves
            // call-site stability; the audit pathway opt-in is one
            // method call (ADR 0018).
            event_store: None,
        })
    }

    /// Test-only constructor that allows an explicit algorithm list.
    ///
    /// Used by this crate's unit tests to exercise both the happy path
    /// (RS256 with a checked-in test RSA key) and the rejection path
    /// (an HS256 token hitting a provider configured only for asymmetric
    /// algs). Callers outside `#[cfg(test)]` should use [`Self::new`] —
    /// the production surface never accepts symmetric algorithms on
    /// IdP-issued tokens.
    #[cfg(test)]
    fn with_algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.accepted_algorithms = algorithms;
        self
    }

    /// Core validation logic. Factored out of the port impl so that the
    /// `BoxFuture` wrapper stays trivial and this body is directly
    /// testable as an `async fn` without `.boxed()`.
    async fn validate_token_impl(&self, token: &str) -> Result<IdpClaims, OidcValidationError> {
        // Step 1: decode the header without verification so we can select
        // the JWK by `kid`. `decode_header` itself is a base64-only parse;
        // no signature trust is implied.
        let header = decode_header(token).map_err(|e| {
            warn!(kind = "invalid_token_shape", error = %e, "jwt header decode failed");
            OidcValidationError::Malformed
        })?;

        if !self.accepted_algorithms.contains(&header.alg) {
            warn!(
                kind = "rejected_algorithm",
                alg = ?header.alg,
                "jwt presented with disallowed algorithm"
            );
            return Err(OidcValidationError::Malformed);
        }

        let kid = header.kid.ok_or_else(|| {
            warn!(kind = "missing_kid", "jwt header has no kid");
            OidcValidationError::Malformed
        })?;

        // Step 2: resolve the JWK. Cache first; refresh on miss or stale.
        let jwk = self.resolve_jwk(&kid).await?;
        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            warn!(kind = "jwk_decode_failed", %kid, error = %e, "failed to convert jwk to decoding key");
            OidcValidationError::SignatureInvalid
        })?;

        // Step 3: configure `Validation` with issuer, audience, leeway.
        //
        // `validation.algorithms` is narrowed to the single header alg
        // here, deliberately. The algorithm gate upstream already
        // checked `header.alg` is in `self.accepted_algorithms`; telling
        // `jsonwebtoken::decode` to accept multiple algs at once runs
        // into its internal family-consistency check (the verifier it
        // builds from the JWK is family-specific, and it refuses to be
        // paired with an `algorithms` list spanning multiple families).
        // Narrowing to `[header.alg]` keeps the decode path clean
        // without loosening any security guarantee.
        let mut validation = Validation::new(header.alg);
        validation.leeway = self.leeway_seconds;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer_url]);

        let data = match decode::<RawClaims>(token, &decoding_key, &validation) {
            Ok(d) => d,
            Err(e) => {
                let (variant, should_evict) = classify_jwt_error(&e);
                warn!(kind = "jwt_validation_failed", reason = %variant, "jwt validation rejected");
                if should_evict {
                    // Key rotation mid-flight: evict the cache entry so
                    // the next request refetches. Any genuine
                    // bad-signature falls here too; cost of a spurious
                    // refetch is cheap compared to locking out a caller
                    // whose token was valid against the now-withdrawn key.
                    //
                    // Apply per-kid backoff on this path (signature
                    // mismatch is the forged-kid DoS vector; a flood of
                    // mismatching tokens would otherwise each trigger an
                    // upstream JWKS fetch). Throttled evictions leave the
                    // cache untouched; the triggering request still 401s,
                    // which is correct (the key IS wrong — throttling just
                    // prevents a refetch storm).
                    let evicted = {
                        let mut guard = self.jwks.write().await;
                        guard.evict(
                            &kid,
                            EvictionReason::SignatureMismatch,
                            self.eviction_backoff,
                        )
                    };
                    if !evicted {
                        // Audit: forged-kid flood detection evidence. Not
                        // an error — suppressing refetch is by design.
                        info!(
                            %kid,
                            "jwks signature-mismatch eviction throttled by per-kid backoff"
                        );
                        emit_jwks_refresh(USER_LOGIN_ISSUER, JwksRefreshResult::Throttled);
                    }
                }
                return Err(variant);
            }
        };

        // Step 4: map the raw claims into IdpClaims. Shape violations are
        // Validation errors (input problem), not Invariant (integrity).
        map_claims(data.claims, &self.groups_claim)
    }

    /// Resolve a JWK by `kid`, refreshing the cache if necessary.
    async fn resolve_jwk(&self, kid: &str) -> Result<jsonwebtoken::jwk::Jwk, OidcValidationError> {
        let now = Instant::now();

        // Fast path: read lock, look up. Miss? Drop read and refresh.
        {
            let guard = self.jwks.read().await;
            if guard.is_fresh(now) {
                if let Some(jwk) = guard.get(kid) {
                    debug!(%kid, "jwks cache hit");
                    return Ok(jwk.clone());
                }
                debug!(%kid, "jwks cache miss (fresh entry, unknown kid — refreshing)");
            } else {
                debug!(%kid, "jwks cache miss (stale — refreshing)");
            }
        }

        // Slow path: acquire write, double-check (another task may have
        // refreshed), then fetch.
        let mut guard = self.jwks.write().await;
        if guard.is_fresh(Instant::now()) {
            if let Some(jwk) = guard.get(kid) {
                // Someone else refreshed between our read-drop and
                // write-acquire.
                return Ok(jwk.clone());
            }
        }

        // Kid not in cache (or cache stale) — benign first-seen OR
        // legitimate key rotation. The backoff map MUST NOT be applied
        // here; it applies only to signature-mismatch evictions. Fetch
        // the fresh JWKS unconditionally so legitimate key rotation is
        // never blocked.
        let fresh = self.fetch_jwks().await?;
        emit_jwks_refresh(USER_LOGIN_ISSUER, JwksRefreshResult::Success);
        info!(%kid, "jwks refreshed successfully");
        let rotation = guard.replace(fresh);
        let resolved = guard.get(kid).cloned().ok_or_else(|| {
            warn!(%kid, "signing key not found after jwks refresh");
            OidcValidationError::SignatureInvalid
        });

        // Drop the cache write-lock BEFORE awaiting the event-store
        // append (we have the cloned JWK in `resolved` already). Holding
        // the JWKS write-lock across a network-bound append would
        // serialize every concurrent `resolve_jwk` call behind the
        // audit-store latency (ADR 0018).
        drop(guard);

        if let Some(rotation) = rotation {
            self.emit_oidc_key_rotated_audit(rotation).await;
        }

        resolved
    }

    /// Tracing + metric + (optional) event-store append for an observed
    /// JWKS rotation (ADR 0018). Decoupled from `resolve_jwk` so the
    /// cache write-lock is released before the network-bound append
    /// fires.
    async fn emit_oidc_key_rotated_audit(&self, rotation: JwksRotationObservation) {
        let JwksRotationObservation {
            kid_added,
            kid_evicted,
        } = rotation;
        let fetched_at = Utc::now();

        // Per design-doc §6: structured log alongside the metric +
        // event. `info` because rotation is a security-relevant state
        // transition operators want to see in the default-level log
        // stream without enabling debug.
        info!(
            kid_added = %kid_added,
            kid_evicted = ?kid_evicted,
            "OIDC key rotated"
        );

        let Some(store) = &self.event_store else {
            // No event store wired — emit the success metric so
            // operators still see the rotation count in the metric
            // stream. The audit log is missing this particular
            // rotation; this branch only fires in tests / minimal
            // deployments. Production wiring in `hort-server` always
            // attaches an event store.
            emit_oidc_key_rotation(OidcKeyRotationResult::Success);
            return;
        };

        let event = DomainEvent::OidcKeyRotated(OidcKeyRotated {
            kid_added: kid_added.clone(),
            kid_evicted: kid_evicted.clone(),
            fetched_at,
        });

        // Stream choice — see [`OidcKeyRotated`] doc comment for the
        // full rationale. Per-UTC-date auth-attempts stream:
        // smallest blast radius (no new StreamCategory), audit
        // consumers already reading the day's `auth-<uuid>` stream
        // see the rotation transitions in the same chronological
        // feed. Event-type filtering (`OidcKeyRotated` vs.
        // `AuthenticationAttempted`) separates the two cleanly.
        let stream_id = StreamId::auth_attempts(fetched_at.date_naive());

        // Actor: `system_actor()` is the documented public API for
        // constructing a System actor from any crate that depends on
        // `hort-domain` (`crates/hort-domain/src/events/mod.rs:537`). The
        // sealed `InternalActorToken` pattern restricts arbitrary
        // `InternalActor` variant construction; `system_actor()` is
        // one of the controlled factory functions that mints the
        // token internally. `Actor::from_persisted` would be the
        // wrong API here — it is the deserialization path for the
        // event-store adapter rebuilding actors from stored columns,
        // not for fresh construction at a new event's emission site.
        let actor = system_actor();

        let batch = AppendEvents {
            stream_id,
            // ExpectedVersion::Any: rotation events are independent
            // observations on a per-day-shared stream; concurrent
            // appends from `AuthenticationAttempted` and
            // `OidcKeyRotated` must not race on a per-stream version
            // check. Same convention as
            // `AuthenticateUseCase::record_attempt`.
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(event)],
            correlation_id: uuid::Uuid::new_v4(),
            causation_id: None,
            actor,
        };

        match store.append(batch).await {
            Ok(_) => {
                emit_oidc_key_rotation(OidcKeyRotationResult::Success);
            }
            Err(e) => {
                warn!(
                    kid_added = %kid_added,
                    kid_evicted = ?kid_evicted,
                    error = %e,
                    "OidcKeyRotated audit append failed; rotation observed but not persisted"
                );
                emit_oidc_key_rotation(OidcKeyRotationResult::Failure);
            }
        }
    }

    /// Fetch the JWKS via OIDC discovery.
    ///
    /// Fetch the JWKS via OIDC discovery. Both the discovery and the
    /// JWKS responses are bounded by [`Self::body_max_bytes`]. A response
    /// larger than the cap is rejected with
    /// [`JwksRefreshResult::BodyTooLarge`] BEFORE parsing — closes the
    /// OOM vector where a malicious or misconfigured IdP returns an
    /// unbounded body. DO NOT replace the streaming read with
    /// `Response::bytes().await` — that's the vulnerability being closed
    /// (reqwest will buffer to EOF).
    async fn fetch_jwks(&self) -> Result<Vec<jsonwebtoken::jwk::Jwk>, OidcValidationError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer_url.trim_end_matches('/')
        );
        debug!(url = %discovery_url, "fetching oidc discovery document");

        let discovery_bytes = self.get_capped_body(&discovery_url, "discovery").await?;
        let discovery: DiscoveryDocument =
            serde_json::from_slice(&discovery_bytes).map_err(|e| {
                emit_jwks_refresh(USER_LOGIN_ISSUER, JwksRefreshResult::ParseError);
                warn!(
                    url = %discovery_url,
                    error = %e,
                    "discovery body parse failed"
                );
                // Malformed discovery body is an upstream IdP
                // misconfiguration; surface as IdpUnavailable so the
                // auth metric splits IdP outage from credential-stuffing.
                OidcValidationError::IdpUnavailable
            })?;

        // Bind the discovery-supplied `jwks_uri` to the issuer's own host
        // (same-host binding) BEFORE the fetch. Additive: the TLS pin +
        // redirect cap on `self.http` (built by
        // `internal::build_http_client`) are unchanged. A rejection
        // surfaces as the SAME error + metric as any other JWKS-fetch
        // failure on this path (`IdpUnavailable` / `FetchFailed`); no
        // new wire error or metric variant. The routability leg was
        // dropped post-E2E (it rejected the internal-IdP case); see
        // `internal::check_jwks_uri_bound`.
        if let Err(e) = internal::check_jwks_uri_bound(&self.issuer_url, &discovery.jwks_uri) {
            emit_jwks_refresh(USER_LOGIN_ISSUER, JwksRefreshResult::FetchFailed);
            warn!(
                issuer = %self.issuer_url,
                jwks_uri = %discovery.jwks_uri,
                reason = ?e,
                "jwks_uri rejected by same-host origin guard (F-48)"
            );
            return Err(OidcValidationError::IdpUnavailable);
        }

        debug!(jwks_uri = %discovery.jwks_uri, "fetching jwks");

        let jwks_bytes = self.get_capped_body(&discovery.jwks_uri, "jwks").await?;
        let jwks: JwksResponse = serde_json::from_slice(&jwks_bytes).map_err(|e| {
            emit_jwks_refresh(USER_LOGIN_ISSUER, JwksRefreshResult::ParseError);
            warn!(
                jwks_uri = %discovery.jwks_uri,
                error = %e,
                "jwks body parse failed"
            );
            // M-3: same operator-actionable bucket as the discovery
            // parse failure above.
            OidcValidationError::IdpUnavailable
        })?;

        Ok(jwks.keys)
    }

    /// GET `url` and buffer the body up to [`Self::body_max_bytes`].
    ///
    /// Implementation strategy: stream via [`reqwest::Response::bytes_stream`]
    /// and accumulate chunks until either EOF or the running total
    /// exceeds the cap. `response.bytes().await` would buffer to EOF —
    /// exactly the behaviour we're hardening against.
    ///
    /// - Transport / non-2xx errors → [`JwksRefreshResult::FetchFailed`]
    ///   metric + [`OidcValidationError::IdpUnavailable`] — an
    ///   operator-actionable IdP outage, distinct from a forged signature.
    /// - Body exceeds cap → [`JwksRefreshResult::BodyTooLarge`] metric +
    ///   [`OidcValidationError::IdpUnavailable`] with no bytes propagated.
    ///   The cap-breaching IdP is misconfigured / under attack — that's
    ///   not a forged-signature event.
    async fn get_capped_body(
        &self,
        url: &str,
        kind: &'static str,
    ) -> Result<Bytes, OidcValidationError> {
        // Explicit per-request timeout alongside the per-client timeout
        // configured in `with_resilience`. Defence in depth: the
        // per-client timeout is already the gate on slow-loris reads,
        // but the per-request version makes the cap legible at the call
        // site and survives any future refactor that swaps in a shared
        // `reqwest::Client` missing the per-client timeout.
        let response = self
            .http
            .get(url)
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| self.jwks_fetch_error(kind, "request failed", &e.to_string()))?
            .error_for_status()
            .map_err(|e| self.jwks_fetch_error(kind, "non-2xx status", &e.to_string()))?;

        let cap = self.body_max_bytes;
        let mut buf = BytesMut::with_capacity(cap.min(64 * 1024));
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| self.jwks_fetch_error(kind, "stream read failed", &e.to_string()))?;
            if buf.len().saturating_add(chunk.len()) > cap {
                emit_jwks_refresh(USER_LOGIN_ISSUER, JwksRefreshResult::BodyTooLarge);
                warn!(
                    url = %url,
                    bytes_read = buf.len() + chunk.len(),
                    cap,
                    "jwks fetch rejected: response body exceeded cap"
                );
                // M-3: oversize body is an availability / misconfig
                // problem, not a forged-signature problem.
                return Err(OidcValidationError::IdpUnavailable);
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf.freeze())
    }

    fn jwks_fetch_error(
        &self,
        kind: &'static str,
        summary: &str,
        detail: &str,
    ) -> OidcValidationError {
        emit_jwks_refresh(USER_LOGIN_ISSUER, JwksRefreshResult::FetchFailed);
        // `detail` is the reqwest error's `to_string()`. reqwest redacts
        // URL password components automatically; it does NOT include
        // response body in the `to_string()` form (that would require
        // `.text().await` which we deliberately avoid). Safe to log.
        //
        // Design doc §5.3 specifies `warn!` level for JWKS upstream
        // failures (the request fails 401; the cache stays stale until
        // TTL — stale-but-safe). No `error!` emission — reserving that
        // level for operator-attention-required conditions.
        warn!(
            issuer = %self.issuer_url,
            kind,
            summary,
            detail,
            "jwks fetch failed"
        );
        // JWKS-fetch failures (transport, non-2xx upstream, stream read
        // errors) are operator-actionable IdP availability problems and
        // surface as `IdpUnavailable`. The previous `SignatureInvalid`
        // collapse made an IdP outage indistinguishable from a
        // forged-signature credential-stuffing campaign in the auth
        // metric. The wire-level outcome (401 / `Option<CallerPrincipal>
        // = None`) is unchanged; only the metric label and tracing
        // classification differ.
        OidcValidationError::IdpUnavailable
    }
}

impl IdentityProvider for OidcProvider {
    fn validate_token(&self, token: &str) -> BoxFuture<'_, Result<IdpClaims, OidcValidationError>> {
        let token = token.to_string();
        Box::pin(async move { self.validate_token_impl(&token).await })
    }
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

/// Observation of a JWKS replacement that actually changed the cached
/// key set. Returned by [`JwksCache::replace`] only on rotations (kid
/// set differs and at least one new kid is present); idle-refresh
/// replaces against a stable IdP yield `None` so we do not emit one
/// event per TTL refresh.
///
/// When multiple kids are added or evicted in a single rotation, the
/// lexicographically-smallest entry of each is reported. The event
/// payload carries single strings rather than full sets — the audit
/// fact is "rotation happened"; the full diff is recoverable from the
/// JWKS-uri fetch trace if forensics need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JwksRotationObservation {
    pub(crate) kid_added: String,
    pub(crate) kid_evicted: Option<String>,
}

/// In-memory JWKS cache. `kid → Jwk` with a single fetched-at instant and
/// TTL governing whole-cache freshness.
///
/// Per-entry TTL would make sense if different keys in the same JWKS could
/// expire independently, but OIDC treats a JWKS as a single document —
/// refresh replaces all entries atomically.
///
/// In-memory JWKS cache. The cache also tracks the last
/// `SignatureMismatch` eviction timestamp per kid in `evictions`, bounded
/// by [`EVICTION_MAP_MAX_ENTRIES`] via drop-oldest on overflow. A forged
/// JWT flood with many distinct kids cannot grow this map without bound.
/// `KidNotInCache` evictions never touch the map — they represent benign
/// first-seen kids, and blocking them by backoff would prevent legitimate
/// key rotation from recovering.
struct JwksCache {
    keys: HashMap<String, jsonwebtoken::jwk::Jwk>,
    fetched_at: Option<Instant>,
    ttl: Duration,
    /// Per-kid timestamp of the most recent [`EvictionReason::SignatureMismatch`]
    /// eviction. Consulted on each `SignatureMismatch` eviction to decide
    /// whether the DoS-mitigation backoff is active. See [`Self::evict`].
    evictions: HashMap<String, Instant>,
}

impl JwksCache {
    fn new(ttl: Duration) -> Self {
        Self {
            keys: HashMap::new(),
            fetched_at: None,
            ttl,
            evictions: HashMap::new(),
        }
    }

    fn is_fresh(&self, now: Instant) -> bool {
        match self.fetched_at {
            None => false,
            Some(at) => now.saturating_duration_since(at) < self.ttl,
        }
    }

    fn get(&self, kid: &str) -> Option<&jsonwebtoken::jwk::Jwk> {
        self.keys.get(kid)
    }

    /// Replace the cached key set with `keys` and return rotation
    /// observations.
    ///
    /// Returns `Some(JwksRotationObservation)` iff the kid set actually
    /// changed (at least one new kid present **and** that change is
    /// observable as a rotation — i.e. either we had a non-empty
    /// previous set, or this is the first-ever fetch with at least one
    /// kid). Returns `None` for no-op replaces (identical kid set,
    /// e.g. a periodic TTL-driven refresh against a stable IdP) so
    /// audit consumers do not see idle-refresh noise.
    ///
    /// The returned diff drives the `OidcKeyRotated` event and the
    /// `hort_oidc_key_rotation_total` metric (ADR 0018). Determinism:
    /// when multiple kids change, the lexicographically-smallest added
    /// kid and lexicographically-smallest evicted kid are reported (the
    /// event payload carries single strings; the full diff is recoverable
    /// from the JWKS-uri fetch trace if needed).
    fn replace(&mut self, keys: Vec<jsonwebtoken::jwk::Jwk>) -> Option<JwksRotationObservation> {
        // Snapshot the previous kid set BEFORE clearing so we can diff.
        let prev_kids: std::collections::BTreeSet<String> = self.keys.keys().cloned().collect();

        self.keys.clear();
        for jwk in keys {
            if let Some(kid) = jwk.common.key_id.clone() {
                self.keys.insert(kid, jwk);
            } else {
                // A JWKS entry without a `kid` is valid per RFC 7517 but
                // unusable here — we key the cache on `kid` because the
                // JWT header carries one. Log and skip.
                debug!("jwks entry lacks kid — skipping (unaddressable in header lookup)");
            }
        }
        self.fetched_at = Some(Instant::now());

        // Diff the new kid set against the previous one. Use BTreeSet
        // so "smallest" is well-defined (lexicographic on the kid
        // string) and the test assertion "added=C, evicted=A" with
        // initial=[A,B] → replace=[B,C] is deterministic.
        let new_kids: std::collections::BTreeSet<String> = self.keys.keys().cloned().collect();
        let mut added_iter = new_kids.difference(&prev_kids);
        let mut evicted_iter = prev_kids.difference(&new_kids);

        // Smallest-sorted added kid is required to emit a rotation —
        // an evict-only delta (rare; would require the IdP to shrink
        // its key set without replacement) is not a *rotation* in the
        // architectural sense (no "rotated TO" key exists). The
        // distinction matters because the event's `kid_added` field
        // is `String`, not `Option<String>`.
        let kid_added = added_iter.next().cloned()?;
        let kid_evicted = evicted_iter.next().cloned();

        Some(JwksRotationObservation {
            kid_added,
            kid_evicted,
        })
    }

    /// Evict the JWK for `kid` and, when `reason` is `SignatureMismatch`,
    /// apply the per-kid backoff.
    ///
    /// Returns `true` if the eviction actually took effect (cache entry
    /// removed, `fetched_at` cleared so the next `resolve_jwk` refetches)
    /// and `false` if throttled (signature-mismatch within the backoff
    /// window; cache untouched).
    ///
    /// Invariants:
    /// - `KidNotInCache` ALWAYS evicts (legitimate key rotation must still
    ///   trigger a refresh — design doc §4).
    /// - `SignatureMismatch` evicts only if the previous same-kid
    ///   mismatch was > `backoff` ago (or first-ever).
    /// - The per-kid eviction map is bounded by
    ///   [`EVICTION_MAP_MAX_ENTRIES`]; overflow drops the oldest timestamp
    ///   so a forged-kid flood cannot grow memory without bound.
    fn evict(&mut self, kid: &str, reason: EvictionReason, backoff: Duration) -> bool {
        if reason == EvictionReason::SignatureMismatch {
            let now = Instant::now();
            if let Some(&last) = self.evictions.get(kid) {
                if now.saturating_duration_since(last) < backoff {
                    // Within backoff window → throttled; cache untouched.
                    return false;
                }
            }
            // Record the eviction BEFORE mutating the cache so the
            // next same-kid mismatch sees this timestamp even if
            // another task wins the next read.
            self.record_eviction_timestamp(kid.to_string(), now);
        }
        self.keys.remove(kid);
        // Leave `fetched_at` cleared — a kid eviction forces the next
        // `resolve_jwk` for this kid to miss, re-fetch the full JWKS,
        // and (on legitimate key rotation) pick up the new key.
        self.fetched_at = None;
        true
    }

    /// Insert `ts` under `kid`, dropping the oldest timestamp if the map
    /// has already reached [`EVICTION_MAP_MAX_ENTRIES`]. The drop-oldest
    /// policy is cheap enough for an O(n) scan at the cap — tuned so
    /// this is a once-per-forged-kid cost, not a per-request cost.
    fn record_eviction_timestamp(&mut self, kid: String, ts: Instant) {
        if !self.evictions.contains_key(&kid) && self.evictions.len() >= EVICTION_MAP_MAX_ENTRIES {
            // Find the oldest entry and drop it.
            if let Some(oldest_kid) = self
                .evictions
                .iter()
                .min_by_key(|(_, &t)| t)
                .map(|(k, _)| k.clone())
            {
                self.evictions.remove(&oldest_kid);
            }
        }
        self.evictions.insert(kid, ts);
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<jsonwebtoken::jwk::Jwk>,
}

/// Adapter-internal claim struct. Deserialised from the validated JWT
/// body, then mapped to [`IdpClaims`]. Kept private — this is the only
/// place IdP-wire-shape claims live.
#[derive(Debug, Deserialize)]
struct RawClaims {
    sub: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
    iat: Option<i64>,
    /// Arbitrary remaining claims — we reach into this map for the
    /// configured `groups_claim`. `serde_json::Value` lets us accept
    /// either `Vec<String>` or `Option<Vec<String>>` without a custom
    /// deserialiser.
    #[serde(flatten)]
    extras: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Mapping + classification helpers
// ---------------------------------------------------------------------------

fn map_claims(raw: RawClaims, groups_claim: &str) -> Result<IdpClaims, OidcValidationError> {
    let subject = raw
        .sub
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OidcValidationError::ClaimMissing("sub".into()))?;
    let email = raw
        .email
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OidcValidationError::ClaimMissing("email".into()))?;
    let username = raw.preferred_username.unwrap_or_else(|| subject.clone());

    let iat = raw
        .iat
        .ok_or_else(|| OidcValidationError::ClaimMissing("iat".into()))?;
    let issued_at = Utc
        .timestamp_opt(iat, 0)
        .single()
        .ok_or_else(|| OidcValidationError::ClaimMissing("iat".into()))?;

    let groups = extract_groups(&raw.extras, groups_claim);

    Ok(IdpClaims {
        subject,
        username,
        email,
        groups,
        issued_at,
    })
}

fn extract_groups(extras: &HashMap<String, serde_json::Value>, claim: &str) -> Vec<String> {
    match extras.get(claim) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(ToString::to_string))
            .collect(),
        // Missing groups is NOT an error — some IdP configurations don't
        // emit the claim for users without group membership. An empty Vec
        // flows cleanly through `RbacEvaluator::resolve_roles_for_groups`.
        _ => Vec::new(),
    }
}

/// Classify a `jsonwebtoken::errors::Error` into
/// `(OidcValidationError variant, should-evict-cache?)`.
///
/// "Should evict" fires only for signature failures, where key rotation
/// mid-flight is the likely culprit. Claim-integrity failures (expired,
/// wrong aud, etc.) leave the cache alone — the key is still valid, it's
/// the token that isn't.
///
/// This function previously returned a string and the middleware
/// substring-matched the result. It now returns a typed variant so the
/// middleware can pattern-match and never inspects an error string.
fn classify_jwt_error(e: &jsonwebtoken::errors::Error) -> (OidcValidationError, bool) {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::InvalidSignature => (OidcValidationError::SignatureInvalid, true),
        ErrorKind::ExpiredSignature => (OidcValidationError::Expired, false),
        ErrorKind::InvalidIssuer => (OidcValidationError::UnknownIssuer, false),
        // Wrong audience: the token was minted for a different relying
        // party. Distinct from SignatureInvalid — the historic collapse
        // made the structured log say "signature invalid" for what was
        // really a Keycloak audience-mapper misconfiguration, sending
        // operators down the key-rotation rabbit hole. Same wire response
        // (401 invalid_token: subject_token invalid), distinct telemetry.
        ErrorKind::InvalidAudience => (OidcValidationError::AudienceMismatch, false),
        ErrorKind::ImmatureSignature => (OidcValidationError::Malformed, false),
        ErrorKind::InvalidAlgorithm => (OidcValidationError::Malformed, false),
        ErrorKind::MissingRequiredClaim(name) => {
            (OidcValidationError::ClaimMissing(name.clone()), false)
        }
        ErrorKind::InvalidToken => (OidcValidationError::Malformed, false),
        _ => (OidcValidationError::SignatureInvalid, false),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The test suite signs JWTs with a checked-in RSA-2048 keypair (generated
// at the time this file was written; never used for production). A stub
// JWKS endpoint is served by `wiremock` and exposes the public half. The
// adapter's real signature-verification path is exercised end-to-end —
// no bypass, no insecure-test flag on the critical path.
//
// Test-only surface:
// - `OidcProvider::with_algorithms` (cfg(test)) — swaps the accepted
//   algorithm list for one test that asserts HS256 is rejected. The
//   production constructor always uses `PRODUCTION_ALGORITHMS`.
#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    // In-process HTTPS JWKS test imports (see extra_ca_anchors_allows_tls_to_private_ca_jwks_server).
    use hort_config::ExtraTrustAnchors;

    // -- Test keypair ------------------------------------------------------
    //
    // RSA-2048 keypair generated at authoring time for test use only. Not
    // checked into any deployment; inlined here so tests are hermetic.
    // Corresponding JWK modulus (`n`) and exponent (`e`) are base64url-
    // encoded below.

    const TEST_PRIV_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmiCv0SfLHnYg6
MvXS0+73TDgXqNYeZDRcwvdps3kITM4OTZm0j+dA9cFNTu6wzO0M5JEjf1g5WUZc
GHWCPdjSil8BaotXKujGj4yofdsP1Jmg/y/u/2gTnnUOBBua9shQH1LJPPpTEpZG
pH6g+uKiKNtoEH5L2F+D7CTHF1F2pItWQn/f6A9bVDBdp8c7a9Z+YKAObDKii1mA
LQuCSrLcWLEoGzJii5sJE6ns/eIPt1OfwIxMLqx1jZhWKWfToHbhQ3dIb76xM1Ex
XqPljususvEldlBlSmGVX3sSgIZwx93WHfUjcYccDhPIWWuHUnmhupSLW0IJHLXf
uJZ0r4SvAgMBAAECggEABCCjOOvNnlBI5xW07WPJVsxx0MxOJPSw2OJlhXN9pXdZ
3WrjoLZhse96ugghzF9X5MDphAANAhGKDTr3S/dtH1LEpgwA+3PEed9m9L93JX5M
dya8BmgYKUb9JGV1AF3rexORAWHchnXoeZnBdbX3gLNoihIWlJn+oWNsn0P0W0S7
M9M7cGdrMB4Oz7jVPAyfIF1EdKlaBuSyrCpR73mAEa3BtmT37+/knYwFgH6BsE4s
dccz6tmzG8/rf3YvHxqQqUb0dlkqOPt2kQyDgVEZoyseFSMDW5DYznSKkD/U3iJf
uiAJjKmJfZLNHBW2LOUtGcngIvD+LULNgS2gJRBj4QKBgQDTPBkKoZaTeGiDMTzB
5so1waAx00fuap3bCvlWnLb90KZiR9ZZjgXx822TESp7U/qUVKw221KNHy9DFSlf
TXHc0pn+ouMNznUdfC+8WDCxh2QzXChZjC3Gj2Ggmg4hWlpwYABtmK0JPsRk5hA0
zDHeEkZgAje4/wdvY5Xh3mAFsQKBgQDJ0ttZqu3j+kJ5djt761KWpyaIgmicOjrk
my987XDldERzGdgnVNZ58cXCgyV71Erjwn2bq8I6u3Cr0qzv5IfXmZIicUi6AOUL
H4AJCxetw8Rua1ume/0ULC6MwKwBsq3bSN4r+C7ZhPvt/uSRyE+FgGFbcKMs2qXV
l27UUHXoXwKBgQDDyhuH4BiaXeu5VkTzkQBybSMXq7crhIUGR5iusBlpDyF5TQ6f
+WUHS1OQEkQnBcLoA8eQHR/aEEKVUiMD49ubC1WTUNVVsbyZ9MamM7QGiPDWLiB0
R9sSBUo/OyvHvGDBcipTa0VPoW8V+qyg03eRV60FRmjxvujcVRjSv3SPMQKBgATQ
/2MYbSzvn/5+D9VZPFNUEdtYIV75FMa33V5B3FvddnS4vSvTHnsyheGqd46I9nCR
B6ZbZvs31eyDzpS7A3Llu1MPGQk3VD/7tHaCyUHgViO8dCd49gUxOLsrLe+sb/G3
v3WVKqkOP2TinFnOSfeJpMkl2v8LCMIcJwzyDp5JAoGATY0FJTBBwobK/Xv239Y5
q7VgHb9M3LeHufhUVOCsEF8RO4M7s73bWSW4QASWcF6Vhy4DdPdQIT13kohb60wK
QyBTLwOFtYew7+nkfPGzqI8ZaodiTnRwO5MYyJ0aCjdpgh0HgCoJ0FSeYLUCyQMM
yDp6g/51WjALM10lhGCQasE=
-----END PRIVATE KEY-----
";

    // Matching public-key components (RFC 7518 base64url, no padding).
    const TEST_N: &str = "pogr9Enyx52IOjL10tPu90w4F6jWHmQ0XML3abN5CEzODk2ZtI_nQPXBTU7usMztDOSRI39YOVlGXBh1gj3Y0opfAWqLVyroxo-MqH3bD9SZoP8v7v9oE551DgQbmvbIUB9SyTz6UxKWRqR-oPrioijbaBB-S9hfg-wkxxdRdqSLVkJ_3-gPW1QwXafHO2vWfmCgDmwyootZgC0Lgkqy3FixKBsyYoubCROp7P3iD7dTn8CMTC6sdY2YViln06B24UN3SG--sTNRMV6j5Y7rLrLxJXZQZUphlV97EoCGcMfd1h31I3GHHA4TyFlrh1J5obqUi1tCCRy137iWdK-Erw";
    const TEST_E: &str = "AQAB";

    // A different RSA-2048 keypair used for the signature-mismatch test.
    const OTHER_PRIV_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6hwJ1vHkH5tj0
Oqc31jvT8bph9IUElKGBVnk9IHjGhw/eSXQaOGzYtXi4QqeG4YSxVO3IkfGsdSXq
xJ6mEEWcs3v9q3dACkYjpWZhFLAK1MqsT+970VBmjp3SEx7x3A/C0HQkSwK0Ry5v
eQOxsm4VgqV1oBo5LZH7EHxqAZ2Fre3cAXlfqxJAeD8zqwhWgyB2m6Wdese/CtpC
jEBe73DYVjNcrhP1xiH+2MDW1XlxVGTR06hDrbfYNYuGet9WeceNqd8+r7+OfZS/
QmWYFpn0xhty7Oxjv66QJRLJt3748hYoO4UIViSHlkpbLLkyRGfpSU4AifResIKo
zt2CSSg1AgMBAAECggEAA91FsAZAVKlT79ViPv4lfanZpGtiMRraMLmHp/xK/EPy
kHahnORz3tZ9ooWg/mKgMuNRTNE3Ok0wBKnfpo2aP5mZVUNO5GkCFH15/kNlNUg8
za6XRc+rlIBaZS6HuteGDRFwAot6Sh1aaS1O5gjODoyHHIV9XZdj2Zl5FmIjrxAH
GjPZhwWcUAdzBu1ZzatO6LZnIF8ThHe5g4FT77+Z+ONz/f26DToiwGelC80oDtfD
a+8U+/7t9XQc9YehDStGHb7dv94PLMnzC8mdC6Us6Snqkeq803htwKMOfQzXo6jP
UlZpEAcO/h4wZnHRA5fXupRkebm3mJpMGYxl4MBo+QKBgQDcyDLzYILYr0s/qO+H
bCjiIjTjLlQeIlZdI5FMEKNDgcHLK0mqdD/3Qg9vrftC1c6niwbpqUYPy3o7w9Tl
Z6geyrXWKQWcLvnSk9uNfp5GjOo7JY0injZC11ifdheqOIoNOS3sq6+yzigaTyN6
hMmpa4+rgPp7TvSa6eNImQjs+QKBgQDYR/8H7hFM6fqxUW/mWZ8YeZSna5PaM6+K
+6hVoQP4E1Re3tB9H6H7T2bDYdmIY9ckU9si/WiPg3Srgj4qbXYc5yhbt/IPmrHv
wNesix9SKc/0IZK+j5yELGoBVGkRyx20J26fHTpzMw5m+7uqWuw8aH2ehDzgLwF8
9n61pJzQHQKBgQCNLwTN97iUwjwXgHt0GSlnukIhyP2Hq6OYuebvQnB0+eQofQ0F
kINbJYZjf1l+2uTk5RXNlC62aQNIdqmM7aVn029GfUMWJkAhdeXfbMngCbq7if7f
1VaTlcwZZNYrRy6Y2CjTANNBP24LrPHeJk4jJiJgpQEIm2v2KHzsbthzWQKBgCEe
xVs9hcC1hAJraitoRgjFdZI90yJzD8rExv517dmrfBwbGupOUcveWOpKrblJMMUL
Yl91VvHDO7aX91Uf9hpu+6sv/A2Prvf8HAr8MwuuA35rNcGg1GMZOhKCDqT+6cmQ
0EvlefHyO55hpldsHQkTJ0mDDp92E1BDnxvJ3YmxAoGBAJNAK9RL/9Xi+mQKw6AU
kmRtYx8NKwNw+FuFsdKAo/DLzpYDOL/xQkDb2nLdjZxRviiv7F7aqhthu3fPwseS
KDV0TlERZ+WcEQYGTGP00ChR3vZE0KLYifBP3Nn6CydHT0Q8NGUA1//8tPq/Dumi
FtBmFfStik03XAfEPVCRWBMc
-----END PRIVATE KEY-----
";

    const DEFAULT_KID: &str = "test-key-1";
    const OTHER_KID: &str = "test-key-2";
    const OTHER_N: &str = "uocCdbx5B-bY9DqnN9Y70_G6YfSFBJShgVZ5PSB4xocP3kl0Gjhs2LV4uEKnhuGEsVTtyJHxrHUl6sSephBFnLN7_at3QApGI6VmYRSwCtTKrE_ve9FQZo6d0hMe8dwPwtB0JEsCtEcub3kDsbJuFYKldaAaOS2R-xB8agGdha3t3AF5X6sSQHg_M6sIVoMgdpulnXrHvwraQoxAXu9w2FYzXK4T9cYh_tjA1tV5cVRk0dOoQ6232DWLhnrfVnnHjanfPq-_jn2Uv0JlmBaZ9MYbcuzsY7-ukCUSybd--PIWKDuFCFYkh5ZKWyy5MkRn6UlOAIn0XrCCqM7dgkkoNQ";

    // -- Test helpers ------------------------------------------------------

    #[derive(Serialize)]
    struct TestClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        iat: i64,
        nbf: i64,
        email: String,
        preferred_username: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        groups: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        my_custom_groups: Option<Vec<String>>,
    }

    impl TestClaims {
        fn defaults(iss: &str, aud: &str) -> Self {
            let now = Utc::now().timestamp();
            Self {
                iss: iss.into(),
                sub: "subject-abc".into(),
                aud: aud.into(),
                exp: now + 300,
                iat: now - 10,
                nbf: now - 10,
                email: "alice@example.com".into(),
                preferred_username: "alice".into(),
                groups: Some(vec!["team-alpha".into()]),
                my_custom_groups: None,
            }
        }
    }

    fn sign(claims: &TestClaims, alg: Algorithm, kid: &str, pem: &str) -> String {
        let mut header = Header::new(alg);
        header.kid = Some(kid.into());
        let key = match alg {
            Algorithm::HS256 => EncodingKey::from_secret(pem.as_bytes()),
            _ => EncodingKey::from_rsa_pem(pem.as_bytes()).expect("valid rsa pem"),
        };
        encode(&header, claims, &key).expect("signing succeeds")
    }

    fn jwks_body_for(kid: &str, n: &str) -> serde_json::Value {
        json!({
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": kid,
                    "n": n,
                    "e": TEST_E,
                }
            ]
        })
    }

    /// Stand up a wiremock server pretending to be an OIDC IdP. Returns
    /// the mock + the issuer URL to pass to the provider.
    async fn start_idp(jwks: serde_json::Value) -> (MockServer, String) {
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;
        (server, base)
    }

    fn default_provider(issuer: &str) -> OidcProvider {
        OidcProvider::new(
            issuer.to_string(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(60),
            None,
        )
        .expect("default_provider: OidcProvider::new must succeed with None anchors")
    }

    // -- Tests --------------------------------------------------------------

    #[tokio::test]
    async fn validate_token_happy_path() {
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        let provider = default_provider(&issuer);

        let claims = TestClaims::defaults(&issuer, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);

        let out = provider.validate_token_impl(&token).await.expect("ok");
        assert_eq!(out.subject, "subject-abc");
        assert_eq!(out.username, "alice");
        assert_eq!(out.email, "alice@example.com");
        assert_eq!(out.groups, vec!["team-alpha".to_string()]);
        // iat is `now - 10`; just check it's a plausible recent timestamp.
        assert!(out.issued_at <= Utc::now());
    }

    #[tokio::test]
    async fn validate_token_expired() {
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        let provider = default_provider(&issuer);

        let mut claims = TestClaims::defaults(&issuer, "hort-server");
        let now = Utc::now().timestamp();
        claims.exp = now - 3600; // expired an hour ago
        claims.iat = now - 3700;
        claims.nbf = now - 3700;
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("should reject");
        assert_eq!(err, OidcValidationError::Expired);
    }

    #[tokio::test]
    async fn validate_token_wrong_audience() {
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        let provider = default_provider(&issuer);

        let claims = TestClaims::defaults(&issuer, "some-other-audience");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("should reject");
        // Audience mismatch surfaces its own variant so structured logs
        // name the real cause. Without this, the error collapsed to
        // SignatureInvalid, sending operators to check key rotation when
        // the actual fix was an IdP audience-mapper.
        assert_eq!(err, OidcValidationError::AudienceMismatch);
    }

    #[tokio::test]
    async fn validate_token_signature_mismatch() {
        // JWKS advertises TEST key; token is signed by the OTHER key.
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        let provider = default_provider(&issuer);

        let claims = TestClaims::defaults(&issuer, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, OTHER_PRIV_PEM);

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("should reject");
        assert_eq!(err, OidcValidationError::SignatureInvalid);
    }

    /// Single-issuer path: a discovery document whose `jwks_uri` points
    /// OFF the issuer host is rejected by `internal::check_jwks_uri_bound`
    /// BEFORE the JWKS fetch, with the existing JWKS-fetch error
    /// classification (`IdpUnavailable`).
    ///
    /// **Guard isolation.** The off-host JWKS server (server B) serves a
    /// VALID JWKS for the test key — so if the guard were absent, the
    /// fetch would succeed off-origin and `validate_token_impl` would
    /// return `Ok`. The issuer is addressed via the `localhost` name and
    /// the off-host `jwks_uri` via the `127.0.0.1` literal: same machine
    /// (so server B is reachable on loopback) but DIFFERENT host strings
    /// per URL `host_str()` semantics, which is exactly the off-origin
    /// mismatch the guard must reject. Server B's mock asserts it is hit
    /// ZERO times — proving the guard short-circuits before the fetch.
    #[tokio::test]
    async fn fetch_jwks_rejects_off_host_jwks_uri_f48() {
        // Server B — the off-host JWKS endpoint. Serves a VALID JWKS so
        // an absent guard would let validation succeed. `expect(0)`:
        // the guard must block the fetch before B is ever contacted.
        let jwks_server = MockServer::start().await;
        let jwks_port = jwks_server.address().port();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(jwks_body_for(DEFAULT_KID, TEST_N)),
            )
            .expect(0)
            .mount(&jwks_server)
            .await;

        // Server A — the issuer / discovery endpoint, addressed by the
        // `localhost` NAME (a different host string from the `127.0.0.1`
        // literal used for the jwks_uri, despite resolving to the same
        // loopback machine).
        let disco_server = MockServer::start().await;
        let issuer = format!("http://localhost:{}", disco_server.address().port());
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "jwks_uri": format!("http://127.0.0.1:{jwks_port}/jwks"),
            })))
            .mount(&disco_server)
            .await;

        let provider = default_provider(&issuer);
        let claims = TestClaims::defaults(&issuer, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("off-host jwks_uri must be rejected even when it serves valid keys");
        assert_eq!(
            err,
            OidcValidationError::IdpUnavailable,
            "off-host jwks_uri rejection must reuse the existing JWKS-fetch \
             error classification, not a new variant"
        );
        // The `.expect(0)` on the jwks mock is verified on drop: the
        // guard short-circuited before any request reached server B.
    }

    /// Minimal `EventStore` capture double for the `OidcKeyRotated`
    /// emission test. Records every appended batch in-memory; only the
    /// methods exercised here are implemented (read paths panic — they
    /// are not on this test's path and a panic flags accidental misuse).
    struct CapturingEventStore {
        appended: tokio::sync::Mutex<Vec<AppendEvents>>,
    }

    impl CapturingEventStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                appended: tokio::sync::Mutex::new(Vec::new()),
            })
        }

        async fn snapshot(&self) -> Vec<AppendEvents> {
            self.appended.lock().await.clone()
        }
    }

    impl EventStore for CapturingEventStore {
        fn append(
            &self,
            batch: AppendEvents,
        ) -> BoxFuture<
            '_,
            hort_domain::error::DomainResult<hort_domain::ports::event_store::AppendResult>,
        > {
            Box::pin(async move {
                let global_position = {
                    let mut guard = self.appended.lock().await;
                    let pos = (guard.len() as u64) + 1;
                    guard.push(batch);
                    pos
                };
                Ok(hort_domain::ports::event_store::AppendResult {
                    stream_position: global_position,
                    global_positions: vec![global_position],
                })
            })
        }

        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: hort_domain::ports::event_store::ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<hort_domain::events::PersistedEvent>>>
        {
            unimplemented!("CapturingEventStore::read_stream — not on this test path")
        }

        fn read_category(
            &self,
            _category: hort_domain::events::StreamCategory,
            _from: hort_domain::ports::event_store::SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<hort_domain::events::PersistedEvent>>>
        {
            unimplemented!("CapturingEventStore::read_category — not on this test path")
        }

        // `health_check` carries a default impl on the trait — no override needed.

        // Retention stubs: unreachable from the OIDC flow, panic on call.
        // Bare `unimplemented!` (no `Box::pin(async { ... })` wrapper)
        // matches this mock's existing read_stream/read_category idiom.
        fn delete_stream(
            &self,
            _stream_id: StreamId,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            unimplemented!("CapturingEventStore::delete_stream — not on this test path")
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            unimplemented!("CapturingEventStore::archive_stream — not on this test path")
        }
    }

    /// End-to-end regression: drive the JWKS through a rotation
    /// [DEFAULT_KID] → [OTHER_KID] via the real validation path, with a
    /// `CapturingEventStore` attached. Assert exactly one `OidcKeyRotated`
    /// event lands per rotation observation, with the expected
    /// `kid_added` / `kid_evicted`.
    ///
    /// The test mirrors `validate_token_unknown_kid_refreshes_cache`'s
    /// JWKS rotation setup (one MockServer, two scoped JWKS responses
    /// in sequence) so the audit pathway is exercised on the same code
    /// path that production runs against.
    #[tokio::test]
    async fn emits_oidc_key_rotated_on_successful_jwks_replace() {
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;

        // Phase 1: only DEFAULT_KID present (initial rotation: empty → [DEFAULT_KID]).
        let first = Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(jwks_body_for(DEFAULT_KID, TEST_N)),
            )
            .up_to_n_times(1)
            .mount_as_scoped(&server)
            .await;

        let store = CapturingEventStore::new();
        let provider = OidcProvider::new(
            base.clone(),
            "hort-server".into(),
            "groups".into(),
            // Long TTL — force a kid-miss refresh on rotation, not a
            // TTL-driven idle refresh. The latter would not change the
            // kid set and so would not emit.
            Duration::from_secs(600),
            None,
        )
        .expect("OidcProvider::new must succeed with None anchors")
        .with_event_store(store.clone() as Arc<dyn EventStore>);

        // Warm the cache with a token signed by DEFAULT_KID. Initial
        // populate of the cache (empty → [DEFAULT_KID]) IS a
        // rotation observation per the `JwksCache::replace`
        // semantics — the audit fact "we now trust DEFAULT_KID" is
        // worth recording.
        let claims = TestClaims::defaults(&base, "hort-server");
        let token1 = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        provider
            .validate_token_impl(&token1)
            .await
            .expect("first validation ok");

        // Phase 2: JWKS rotates — DEFAULT_KID is retired, OTHER_KID is
        // introduced. Token signed by OTHER_KID forces a kid-miss
        // refetch, which observes the rotation and emits the event.
        drop(first);
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": OTHER_KID,
                        "n": OTHER_N,
                        "e": TEST_E,
                    }
                ]
            })))
            .mount(&server)
            .await;

        let token2 = sign(&claims, Algorithm::RS256, OTHER_KID, OTHER_PRIV_PEM);
        provider
            .validate_token_impl(&token2)
            .await
            .expect("rotation should refresh and the new key validates");

        // Two appends expected: one for the initial fetch (empty →
        // [DEFAULT_KID]), one for the rotation ([DEFAULT_KID] →
        // [OTHER_KID]). Assert specifically on the rotation append
        // — that is the I-A10 acceptance fact.
        let appends = store.snapshot().await;
        let rotation_events: Vec<&DomainEvent> = appends
            .iter()
            .flat_map(|b| b.events.iter().map(|e| &e.event))
            .filter(|e| matches!(e, DomainEvent::OidcKeyRotated(_)))
            .collect();

        assert_eq!(
            rotation_events.len(),
            2,
            "expected one OidcKeyRotated per replace that changed the kid set; \
             got {} (appends={:?})",
            rotation_events.len(),
            appends.iter().map(|b| b.events.len()).collect::<Vec<_>>()
        );

        // Phase 1 emission: empty → [DEFAULT_KID]. kid_added = DEFAULT_KID,
        // kid_evicted = None.
        let DomainEvent::OidcKeyRotated(first_rot) = rotation_events[0] else {
            unreachable!()
        };
        assert_eq!(first_rot.kid_added, DEFAULT_KID);
        assert_eq!(first_rot.kid_evicted, None);

        // Phase 2 emission: [DEFAULT_KID] → [OTHER_KID]. kid_added =
        // OTHER_KID, kid_evicted = Some(DEFAULT_KID). This is the
        // canonical rotation transition the spec calls out.
        let DomainEvent::OidcKeyRotated(second_rot) = rotation_events[1] else {
            unreachable!()
        };
        assert_eq!(second_rot.kid_added, OTHER_KID);
        assert_eq!(second_rot.kid_evicted, Some(DEFAULT_KID.to_string()));

        // Both events landed on the per-UTC-date auth-attempts stream
        // (the documented stream choice). Confirm the category wire
        // form is `auth-<uuid>` so a future change to a dedicated
        // stream forces this test to be updated alongside the
        // documented choice.
        for batch in &appends {
            assert_eq!(
                batch.stream_id.category,
                hort_domain::events::StreamCategory::AuthAttempts,
                "OidcKeyRotated must land on the per-UTC-date auth-attempts stream"
            );
        }
    }

    #[tokio::test]
    async fn validate_token_unknown_kid_refreshes_cache() {
        // Start with only DEFAULT_KID in the JWKS; verify the first
        // request populates the cache. Then swap the JWKS for one
        // containing OTHER_KID and send a token signed with it.
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;

        // First JWKS: only DEFAULT_KID present.
        let first = Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(jwks_body_for(DEFAULT_KID, TEST_N)),
            )
            .up_to_n_times(1)
            .mount_as_scoped(&server)
            .await;

        let provider = OidcProvider::new(
            base.clone(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(600), // long TTL — force a kid-miss refresh, not TTL expiry
            None,
        )
        .expect("OidcProvider::new must succeed with None anchors");

        // Warm the cache with a token that hits DEFAULT_KID.
        let claims = TestClaims::defaults(&base, "hort-server");
        let token1 = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        provider
            .validate_token_impl(&token1)
            .await
            .expect("first validation ok");

        // Now the JWKS changes — OTHER_KID is rotated in.
        drop(first);
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": OTHER_KID,
                        "n": OTHER_N,
                        "e": TEST_E,
                    }
                ]
            })))
            .mount(&server)
            .await;

        // Token signed with the OTHER key, kid = OTHER_KID — cache miss
        // for OTHER_KID must trigger a refetch.
        let token2 = sign(&claims, Algorithm::RS256, OTHER_KID, OTHER_PRIV_PEM);
        let out = provider
            .validate_token_impl(&token2)
            .await
            .expect("kid-miss should refetch and succeed");
        assert_eq!(out.subject, "subject-abc");
    }

    #[tokio::test]
    async fn validate_token_configurable_groups_claim() {
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        let provider = OidcProvider::new(
            issuer.clone(),
            "hort-server".into(),
            "my_custom_groups".into(),
            Duration::from_secs(60),
            None,
        )
        .expect("OidcProvider::new must succeed with None anchors");

        let mut claims = TestClaims::defaults(&issuer, "hort-server");
        claims.groups = None;
        claims.my_custom_groups = Some(vec!["tenants/ops".into(), "tenants/data".into()]);
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);

        let out = provider.validate_token_impl(&token).await.expect("ok");
        assert_eq!(
            out.groups,
            vec!["tenants/ops".to_string(), "tenants/data".to_string()]
        );
    }

    #[tokio::test]
    async fn validate_token_missing_email_is_validation_error() {
        // Sign a token with empty email; the adapter must reject it as a
        // claim-shape (Validation) error, not a signature-integrity
        // (Invariant) error.
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        let provider = default_provider(&issuer);

        #[derive(Serialize)]
        struct NoEmailClaims {
            iss: String,
            sub: String,
            aud: String,
            exp: i64,
            iat: i64,
            preferred_username: String,
            groups: Vec<String>,
        }
        let now = Utc::now().timestamp();
        let no_email = NoEmailClaims {
            iss: issuer.clone(),
            sub: "subject-abc".into(),
            aud: "hort-server".into(),
            exp: now + 300,
            iat: now - 10,
            preferred_username: "alice".into(),
            groups: vec![],
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(DEFAULT_KID.into());
        let token = encode(
            &header,
            &no_email,
            &EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap(),
        )
        .unwrap();

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("should reject");
        assert_eq!(err, OidcValidationError::ClaimMissing("email".into()));
    }

    #[tokio::test]
    async fn validate_token_rejects_hs256_alg() {
        // A provider configured for RS256 sees an HS256 token — reject.
        // Even if the HMAC secret happened to match, the algorithm gate
        // fires before signature verification.
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        let provider = default_provider(&issuer);

        let claims = TestClaims::defaults(&issuer, "hort-server");
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(DEFAULT_KID.into());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"pretend-this-matches"),
        )
        .unwrap();

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("should reject");
        assert_eq!(err, OidcValidationError::Malformed);
    }

    #[tokio::test]
    async fn validate_token_accepts_hs256_when_explicitly_configured() {
        // Sanity check for the `with_algorithms` cfg(test) escape hatch —
        // HS256 works when both parties share the secret. Used by Item 9's
        // registry-minted-JWT path (HMAC-signed) when it lands; covered
        // here to prove the gate is algorithm-list-driven, not a hardcoded
        // check.
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        // This provider is constructed for the test and accepts HS256 only,
        // plus the default production algs for good measure.
        let provider = default_provider(&issuer).with_algorithms(vec![Algorithm::HS256]);

        // The JWK won't match for HS256 (HS uses symmetric secrets, not
        // JWKs), so the call should still fail — but with a non-algorithm
        // reason. Assert the rejection ISN'T the algorithm gate.
        let claims = TestClaims::defaults(&issuer, "hort-server");
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(DEFAULT_KID.into());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"shared-secret"),
        )
        .unwrap();

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("jwk is RSA so signature won't verify");
        // We passed the algorithm gate — failure must be a signature
        // problem, not Malformed.
        assert_eq!(err, OidcValidationError::SignatureInvalid);
    }

    // -- Algorithm allow-list regression-gate tests -------------------------
    //
    // These two tests pin the algorithm allow-list set up by the public
    // `OidcProvider::new` constructor. The port-level contract is prose
    // only (`crates/hort-domain/src/ports/identity_provider.rs` —
    // "Algorithm-rejection contract"); these are the structural tests
    // that fail CI if a future refactor regresses the gate. A second IdP
    // adapter (when one exists) must carry an equivalent pair.
    //
    // No wiremock IdP setup is required: the algorithm gate fires inside
    // `validate_token_impl` BEFORE `resolve_jwk` is called, so a token
    // crafted with a forbidden alg never reaches the network.

    #[tokio::test]
    async fn oidc_adapter_must_reject_hs256() {
        // Drive the real public `OidcProvider::new` constructor — the
        // same one production wiring uses (`hort-server::composition`) —
        // and present an HS256-signed token. The adapter must reject it
        // as `Malformed` because HS256 is not in `PRODUCTION_ALGORITHMS`.
        // No JWKS endpoint is wired: the gate must fire before any
        // network I/O. If a future change removes HS\* from the deny
        // list, this test fails loud.
        let provider = OidcProvider::new(
            "https://idp.example.invalid".into(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(60),
            None,
        )
        .expect("OidcProvider::new must succeed with None anchors");

        let claims = TestClaims::defaults("https://idp.example.invalid", "hort-server");
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(DEFAULT_KID.into());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"any-shared-secret"),
        )
        .expect("hs256 sign succeeds");

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("hs256 must be rejected by the production gate");
        assert_eq!(
            err,
            OidcValidationError::Malformed,
            "hs256 must surface as Malformed (algorithm gate), not as a signature \
             or idp-availability error"
        );
    }

    #[tokio::test]
    async fn oidc_adapter_must_reject_none() {
        // Drive the real public `OidcProvider::new` constructor and
        // present a `none`-alg token (RFC 7519 §6 unsecured JWS). The
        // `jsonwebtoken` 10.x `Algorithm` enum has no `None` variant, so
        // the adapter cannot type-encode such a token via `Header::new`;
        // we hand-craft the wire form directly. `decode_header` rejects
        // the unknown alg name → the adapter maps that to `Malformed`.
        // The end-to-end behaviour is identical to the HS\* path: the
        // token never reaches signature verification or the JWKS fetch.
        //
        // Precomputed token shape (header / payload / empty signature):
        //   header  = {"alg":"none","typ":"JWT","kid":"k"}
        //   payload = {}
        //   sig     = ""  (RFC 7519 §6.1 — none alg has no signature segment)
        const NONE_ALG_TOKEN: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoiayJ9.e30.";

        let provider = OidcProvider::new(
            "https://idp.example.invalid".into(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(60),
            None,
        )
        .expect("OidcProvider::new must succeed with None anchors");

        let err = provider
            .validate_token_impl(NONE_ALG_TOKEN)
            .await
            .expect_err("none-alg token must be rejected by the production gate");
        assert_eq!(
            err,
            OidcValidationError::Malformed,
            "none-alg must surface as Malformed; if it ever lands on \
             SignatureInvalid or IdpUnavailable, the gate has been bypassed",
        );
    }

    // -- Pure-function tests -----------------------------------------------

    #[test]
    fn classify_jwt_error_maps_signature() {
        let err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidSignature);
        let (variant, evict) = classify_jwt_error(&err);
        assert_eq!(variant, OidcValidationError::SignatureInvalid);
        assert!(evict, "signature failure should evict the kid");
    }

    #[test]
    fn classify_jwt_error_expired_does_not_evict() {
        let err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature);
        let (variant, evict) = classify_jwt_error(&err);
        assert_eq!(variant, OidcValidationError::Expired);
        assert!(!evict);
    }

    #[test]
    fn classify_jwt_error_wrong_issuer() {
        let err = jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidIssuer);
        let (variant, _) = classify_jwt_error(&err);
        assert_eq!(variant, OidcValidationError::UnknownIssuer);
    }

    #[test]
    fn classify_jwt_error_immature() {
        let err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ImmatureSignature);
        let (variant, _) = classify_jwt_error(&err);
        assert_eq!(variant, OidcValidationError::Malformed);
    }

    #[test]
    fn classify_jwt_error_wrong_audience_is_audience_mismatch() {
        // This previously returned SignatureInvalid, which made the
        // structured log line lie about the cause — operators saw
        // "signature invalid" for what was really a Keycloak
        // audience-mapper misconfiguration. The classifier now returns
        // the dedicated AudienceMismatch variant; the `should_evict`
        // flag stays false because the JWKS is still good (it's the
        // audience claim, not the key, that's wrong).
        let err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidAudience);
        let (variant, evict) = classify_jwt_error(&err);
        assert_eq!(variant, OidcValidationError::AudienceMismatch);
        assert!(!evict);
    }

    #[test]
    fn classify_jwt_error_invalid_algorithm_is_malformed() {
        let err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm);
        let (variant, _) = classify_jwt_error(&err);
        assert_eq!(variant, OidcValidationError::Malformed);
    }

    #[test]
    fn classify_jwt_error_missing_required_claim_carries_name() {
        let err = jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("exp".into()),
        );
        let (variant, _) = classify_jwt_error(&err);
        assert_eq!(variant, OidcValidationError::ClaimMissing("exp".into()));
    }

    #[test]
    fn classify_jwt_error_invalid_token_is_malformed() {
        let err = jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken);
        let (variant, _) = classify_jwt_error(&err);
        assert_eq!(variant, OidcValidationError::Malformed);
    }

    /// Pin the OIDC outbound TLS-version policy. Mirrors the parallel
    /// `outbound_tls_protocol_versions_pin_lists_only_tls13_then_tls12`
    /// test in `hort_adapters_upstream_http::tls_config`. If a future
    /// audit broadens or narrows the BSI TR-02102-2 §3 policy, BOTH
    /// tests must be updated together.
    ///
    /// Both the single-issuer and multi-issuer paths build their HTTP
    /// client via `internal::build_http_client`, which reads these
    /// constants, so this regression gate covers both code paths.
    #[test]
    fn oidc_outbound_tls_version_pin_matches_outbound_policy() {
        assert_eq!(
            internal::OUTBOUND_TLS_MIN_VERSION,
            reqwest::tls::Version::TLS_1_2,
            "OIDC outbound TLS minimum must be TLS 1.2 — BSI TR-02102-2 §3",
        );
        assert_eq!(
            internal::OUTBOUND_TLS_MAX_VERSION,
            reqwest::tls::Version::TLS_1_3,
            "OIDC outbound TLS maximum must be TLS 1.3 — BSI TR-02102-2 §3",
        );
    }

    #[test]
    fn extract_groups_missing_returns_empty() {
        let map = HashMap::new();
        assert!(extract_groups(&map, "groups").is_empty());
    }

    #[test]
    fn extract_groups_non_array_returns_empty() {
        let mut map = HashMap::new();
        map.insert("groups".to_string(), serde_json::json!("not-an-array"));
        assert!(extract_groups(&map, "groups").is_empty());
    }

    #[test]
    fn extract_groups_reads_array() {
        let mut map = HashMap::new();
        map.insert("groups".to_string(), serde_json::json!(["a", "b", 42, "c"]));
        // Non-string items are silently dropped (defensive); JWT groups
        // should always be strings, so this treats malformed entries as
        // absent rather than poisoning the whole claim.
        assert_eq!(
            extract_groups(&map, "groups"),
            vec!["a".to_string(), "b".into(), "c".into()]
        );
    }

    #[test]
    fn jwks_cache_fresh_and_stale() {
        let mut cache = JwksCache::new(Duration::from_millis(10));
        assert!(!cache.is_fresh(Instant::now()));
        cache.fetched_at = Some(Instant::now());
        assert!(cache.is_fresh(Instant::now()));
        // Can't sleep in a #[test] reliably, so construct a future instant
        // by adding the ttl + a margin via saturating arithmetic.
        let later = Instant::now()
            .checked_add(Duration::from_secs(3600))
            .unwrap();
        assert!(!cache.is_fresh(later));
    }

    #[test]
    fn jwks_cache_evict_clears_fetched_at() {
        let mut cache = JwksCache::new(Duration::from_secs(60));
        cache.fetched_at = Some(Instant::now());
        let actually_evicted = cache.evict(
            "nonexistent",
            EvictionReason::KidNotInCache,
            Duration::from_secs(10),
        );
        assert!(actually_evicted);
        assert!(cache.fetched_at.is_none());
    }

    #[test]
    fn map_claims_happy_path() {
        let raw = RawClaims {
            sub: Some("sub-1".into()),
            preferred_username: Some("alice".into()),
            email: Some("a@b.com".into()),
            iat: Some(1_700_000_000),
            extras: HashMap::new(),
        };
        let out = map_claims(raw, "groups").expect("ok");
        assert_eq!(out.subject, "sub-1");
        assert_eq!(out.username, "alice");
        assert_eq!(out.email, "a@b.com");
        assert!(out.groups.is_empty());
    }

    #[test]
    fn map_claims_missing_sub() {
        let raw = RawClaims {
            sub: None,
            preferred_username: None,
            email: Some("a@b.com".into()),
            iat: Some(1_700_000_000),
            extras: HashMap::new(),
        };
        let err = map_claims(raw, "groups").unwrap_err();
        assert_eq!(err, OidcValidationError::ClaimMissing("sub".into()));
    }

    #[test]
    fn map_claims_missing_email() {
        let raw = RawClaims {
            sub: Some("s".into()),
            preferred_username: None,
            email: None,
            iat: Some(1_700_000_000),
            extras: HashMap::new(),
        };
        let err = map_claims(raw, "groups").unwrap_err();
        assert_eq!(err, OidcValidationError::ClaimMissing("email".into()));
    }

    #[test]
    fn map_claims_missing_iat() {
        let raw = RawClaims {
            sub: Some("s".into()),
            preferred_username: None,
            email: Some("a@b.com".into()),
            iat: None,
            extras: HashMap::new(),
        };
        let err = map_claims(raw, "groups").unwrap_err();
        assert_eq!(err, OidcValidationError::ClaimMissing("iat".into()));
    }

    #[test]
    fn map_claims_iat_out_of_range_reports_iat() {
        let raw = RawClaims {
            sub: Some("s".into()),
            preferred_username: None,
            email: Some("a@b.com".into()),
            // chrono::Utc.timestamp_opt clamps; use i64::MAX so .single() fails.
            iat: Some(i64::MAX),
            extras: HashMap::new(),
        };
        let err = map_claims(raw, "groups").unwrap_err();
        assert_eq!(err, OidcValidationError::ClaimMissing("iat".into()));
    }

    #[test]
    fn map_claims_username_defaults_to_subject() {
        let raw = RawClaims {
            sub: Some("sub-1".into()),
            preferred_username: None,
            email: Some("a@b.com".into()),
            iat: Some(1_700_000_000),
            extras: HashMap::new(),
        };
        let out = map_claims(raw, "groups").expect("ok");
        assert_eq!(out.username, "sub-1");
    }

    // -- JWKS resilience tests -----------------------------------------------
    //
    // These tests pin the three JWKS resilience concerns:
    // 1. Forged-kid signature-mismatch flood is throttled (DoS mitigation).
    // 2. Legitimate key rotation is NOT blocked by the backoff (first-seen
    //    kid → refresh; post-backoff same-kid re-eviction → refresh).
    // 3. Oversize JWKS / discovery bodies are rejected before parsing.
    //
    // Clock injection strategy: real `tokio::time::sleep` against a short
    // (50 ms) `eviction_backoff` — lets us exercise both the within-window
    // (throttled) and after-window (refresh-fires) paths without pulling in
    // a clock trait. The absolute durations are small enough that test
    // runtime stays well under 1 s.

    #[test]
    fn jwks_cache_signature_mismatch_throttles_within_window() {
        // Same-kid `SignatureMismatch` eviction twice in succession: the
        // first actually evicts (returns true), the second is throttled
        // (returns false) because the backoff window has not elapsed.
        let mut cache = JwksCache::new(Duration::from_secs(60));
        cache.fetched_at = Some(Instant::now());
        let first = cache.evict(
            "kid-1",
            EvictionReason::SignatureMismatch,
            Duration::from_secs(60),
        );
        let second = cache.evict(
            "kid-1",
            EvictionReason::SignatureMismatch,
            Duration::from_secs(60),
        );
        assert!(
            first,
            "first signature-mismatch eviction should take effect"
        );
        assert!(
            !second,
            "second same-kid signature-mismatch eviction should be throttled"
        );
    }

    #[test]
    fn jwks_cache_kid_not_in_cache_bypasses_backoff() {
        // Even with the eviction map pre-populated (as if we had just
        // evicted this kid for signature-mismatch a moment ago), a
        // `KidNotInCache` eviction MUST still take effect. Legitimate
        // key rotation must not be suppressed by the DoS mitigation —
        // design doc §4 invariant.
        let mut cache = JwksCache::new(Duration::from_secs(60));
        cache.fetched_at = Some(Instant::now());
        let _ = cache.evict(
            "kid-rotating",
            EvictionReason::SignatureMismatch,
            Duration::from_secs(3600),
        );
        // Now evict the same kid as KidNotInCache; must still evict.
        let evicted = cache.evict(
            "kid-rotating",
            EvictionReason::KidNotInCache,
            Duration::from_secs(3600),
        );
        assert!(
            evicted,
            "KidNotInCache eviction must bypass the backoff window"
        );
    }

    #[test]
    fn jwks_cache_signature_mismatch_refreshes_after_backoff_window() {
        // After the backoff window elapses, a fresh same-kid
        // `SignatureMismatch` MUST evict again — otherwise legitimate
        // key rotation never recovers after a transient mismatch burst.
        let mut cache = JwksCache::new(Duration::from_secs(60));
        cache.fetched_at = Some(Instant::now());
        let backoff = Duration::from_millis(30);
        assert!(cache.evict("kid-x", EvictionReason::SignatureMismatch, backoff));
        assert!(
            !cache.evict("kid-x", EvictionReason::SignatureMismatch, backoff),
            "within-window re-evict must be throttled"
        );
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            cache.evict("kid-x", EvictionReason::SignatureMismatch, backoff),
            "post-window re-evict must take effect"
        );
    }

    /// Helper: build a minimal RSA JWK for diff-only tests. Uses
    /// `TEST_N` / `TEST_E` so the value parses; the kid is what
    /// the test cares about.
    fn jwk_with_kid(kid: &str) -> jsonwebtoken::jwk::Jwk {
        let body = serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": TEST_N,
            "e": TEST_E,
        });
        serde_json::from_value(body).expect("valid jwk shape")
    }

    /// RED-first regression: drive `JwksCache::replace` with two
    /// distinct kid sets and assert the rotation observation is
    /// reported deterministically.
    ///
    /// `initial = [A, B]`, then `replace = [B, C]`:
    ///   - first replace returns `Some(JwksRotationObservation { kid_added: "kid-A", kid_evicted: None })`
    ///     (first-ever fetch into an empty cache — there is something
    ///     to rotate to but nothing to evict)
    ///   - second replace returns `Some(JwksRotationObservation { kid_added: "kid-C", kid_evicted: Some("kid-A") })`
    ///     (B is unchanged; A is evicted; C is new — exactly one
    ///     rotation event landed for this delta).
    #[test]
    fn jwks_replace_returns_rotation_observation_on_kid_change() {
        let mut cache = JwksCache::new(Duration::from_secs(60));

        // First fetch: empty → [A, B]. There is a "rotated to A"
        // observable transition (smallest-sorted kid wins). No prior
        // kid set, so kid_evicted is None.
        let first = cache.replace(vec![jwk_with_kid("kid-A"), jwk_with_kid("kid-B")]);
        assert_eq!(
            first,
            Some(JwksRotationObservation {
                kid_added: "kid-A".into(),
                kid_evicted: None,
            }),
            "first-ever replace must report a rotation observation"
        );

        // Second fetch: [A, B] → [B, C]. B unchanged; A evicted; C
        // new. Smallest-added is "kid-C" (only added kid); smallest-
        // evicted is "kid-A" (only evicted kid).
        let second = cache.replace(vec![jwk_with_kid("kid-B"), jwk_with_kid("kid-C")]);
        assert_eq!(
            second,
            Some(JwksRotationObservation {
                kid_added: "kid-C".into(),
                kid_evicted: Some("kid-A".into()),
            }),
            "rotation [A,B] → [B,C] must report kid_added=C, kid_evicted=Some(A)"
        );
    }

    #[test]
    fn jwks_replace_returns_none_when_kid_set_unchanged() {
        // No-op refresh: identical kid set, e.g. periodic TTL refresh
        // against a stable IdP. Audit consumers must NOT see one
        // "rotation" event per refresh — `None` here is what gates
        // the no-op out of the audit log.
        let mut cache = JwksCache::new(Duration::from_secs(60));
        let _ = cache.replace(vec![jwk_with_kid("kid-A"), jwk_with_kid("kid-B")]);
        let again = cache.replace(vec![jwk_with_kid("kid-A"), jwk_with_kid("kid-B")]);
        assert_eq!(
            again, None,
            "identical kid set on refresh must NOT report a rotation"
        );
    }

    #[test]
    fn jwks_replace_returns_none_when_only_evictions() {
        // Edge case: IdP shrinks its key set. There is no "rotated
        // TO" key, so `kid_added` (which is `String`, not Option) has
        // no value to carry — emission is skipped. Suppression is
        // explicit so a later contributor doesn't try to make
        // `kid_added` optional and accidentally lose the audit fact
        // when keys roll forward.
        let mut cache = JwksCache::new(Duration::from_secs(60));
        let _ = cache.replace(vec![jwk_with_kid("kid-A"), jwk_with_kid("kid-B")]);
        let evict_only = cache.replace(vec![jwk_with_kid("kid-A")]);
        assert_eq!(
            evict_only, None,
            "evict-only delta is not a rotation; no event"
        );
    }

    #[test]
    fn jwks_replace_picks_lexicographically_smallest_kid_when_many_change() {
        // When multiple kids are added or evicted in a single
        // rotation (rare but legitimate — IdP swaps two keys at
        // once), the smallest-sorted of each is reported. This is
        // the determinism contract that lets the test assertion be
        // stable.
        let mut cache = JwksCache::new(Duration::from_secs(60));
        let _ = cache.replace(vec![
            jwk_with_kid("kid-old-1"),
            jwk_with_kid("kid-old-2"),
            jwk_with_kid("kid-stable"),
        ]);
        let observed = cache.replace(vec![
            jwk_with_kid("kid-new-1"),
            jwk_with_kid("kid-new-2"),
            jwk_with_kid("kid-stable"),
        ]);
        assert_eq!(
            observed,
            Some(JwksRotationObservation {
                kid_added: "kid-new-1".into(),
                kid_evicted: Some("kid-old-1".into()),
            }),
        );
    }

    #[test]
    fn jwks_cache_eviction_map_bounded_at_cap() {
        // With a tiny simulated cap, the map never grows past the cap —
        // drop-oldest on insert. Uses `record_eviction_timestamp` directly
        // to avoid the real-time `Instant::now()` coupling.
        let mut cache = JwksCache::new(Duration::from_secs(60));
        // Simulate: fill the map past the cap via direct inserts (would
        // correspond to a forged-kid flood using many distinct kids).
        let base = Instant::now();
        for i in 0..(EVICTION_MAP_MAX_ENTRIES + 50) {
            cache.record_eviction_timestamp(
                format!("kid-{i}"),
                base + Duration::from_nanos(i as u64),
            );
        }
        assert!(
            cache.evictions.len() <= EVICTION_MAP_MAX_ENTRIES,
            "eviction map grew past cap: {} > {}",
            cache.evictions.len(),
            EVICTION_MAP_MAX_ENTRIES
        );
    }

    // -- End-to-end wiremock tests ----------------------------------------

    /// Helper: count invocations of the `/jwks` endpoint by waiting for
    /// the server to record them. wiremock's `received_requests()` gives
    /// every request; we filter to `/jwks`.
    async fn jwks_hit_count(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == "/jwks")
            .count()
    }

    #[tokio::test]
    async fn forged_kid_flood_throttles_refetches() {
        // The forged-kid DoS scenario: 100 tokens signed by a key the IdP
        // does NOT publish are presented in quick succession. With per-kid
        // backoff in force, at most the first of each kid's evictions
        // causes a JWKS refetch; subsequent same-kid mismatches are
        // throttled. All 100 are signed with the same kid so the map stays
        // trivial. Asserts the refetch count stays bounded — NOT
        // one-per-request.
        let (server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;

        // Generous backoff — larger than the test's expected wall-clock.
        let provider = OidcProvider::with_resilience(
            issuer.clone(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(600),
            Duration::from_secs(10),
            DEFAULT_BODY_MAX_BYTES,
            None,
        )
        .expect("with_resilience must succeed with None anchors");

        // Warm the cache via one legitimate validation → 1 JWKS fetch.
        let good = TestClaims::defaults(&issuer, "hort-server");
        let good_token = sign(&good, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        provider
            .validate_token_impl(&good_token)
            .await
            .expect("legitimate warmup should succeed");
        let after_warmup = jwks_hit_count(&server).await;
        assert!(after_warmup >= 1, "warmup should have fetched JWKS");

        // Now flood 100 tokens signed with the WRONG key but the SAME kid
        // the IdP advertises. Each triggers the signature-mismatch path.
        let bad_token = sign(&good, Algorithm::RS256, DEFAULT_KID, OTHER_PRIV_PEM);
        for _ in 0..100 {
            let _ = provider.validate_token_impl(&bad_token).await;
        }
        let after_flood = jwks_hit_count(&server).await;

        // Because of the per-kid backoff, only the FIRST mismatch actually
        // evicts (and the cache-refresh that follows re-fetches JWKS
        // once). The other 99 are throttled — no extra upstream hits.
        assert!(
            after_flood - after_warmup <= 1,
            "forged-kid flood must produce at most one extra JWKS fetch, \
             got {after_flood} (warmup was {after_warmup})"
        );
    }

    #[tokio::test]
    async fn legitimate_key_rotation_after_backoff_still_refreshes() {
        // Scenario: attacker floods with a bad-signature token (same kid
        // as the valid one). After the backoff window elapses, a NEW
        // legitimate validation still works — the throttle did not
        // permanently disable refresh.
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(jwks_body_for(DEFAULT_KID, TEST_N)),
            )
            .mount(&server)
            .await;

        // Short backoff — 40 ms — lets us exercise both the throttled
        // and the refreshed paths in a single test without flakiness.
        let provider = OidcProvider::with_resilience(
            base.clone(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(600),
            Duration::from_millis(40),
            DEFAULT_BODY_MAX_BYTES,
            None,
        )
        .expect("with_resilience must succeed with None anchors");

        // Warm the cache.
        let good = TestClaims::defaults(&base, "hort-server");
        let good_token = sign(&good, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        provider.validate_token_impl(&good_token).await.unwrap();

        // First bad token → signature-mismatch → eviction + refresh.
        let bad_token = sign(&good, Algorithm::RS256, DEFAULT_KID, OTHER_PRIV_PEM);
        let _ = provider.validate_token_impl(&bad_token).await;
        // Immediate same-kid mismatch → throttled.
        let _ = provider.validate_token_impl(&bad_token).await;

        // Wait past the backoff window so the next flow isn't throttled.
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Legitimate token still validates — throttle did not permanently
        // lock the kid out.
        let out = provider.validate_token_impl(&good_token).await;
        assert!(
            out.is_ok(),
            "legitimate token after backoff window must still validate: {out:?}"
        );
    }

    #[tokio::test]
    async fn oversize_jwks_body_rejected_before_parsing() {
        // IdP returns a 2 MiB JWKS body; provider's cap is 1 MiB. The
        // adapter must reject the response WITHOUT parsing it (the DoS
        // vector being closed is an attacker who sends an
        // attacker-controlled unbounded body to trigger OOM). The
        // triggering validation 401s because the cache stays stale.
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;

        // 2 MiB of padding — well over the 1 MiB cap.
        let padding = "A".repeat(2 * 1024 * 1024);
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(padding))
            .mount(&server)
            .await;

        let provider = OidcProvider::with_resilience(
            base.clone(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(600),
            Duration::from_secs(10),
            1024 * 1024, // 1 MiB cap
            None,
        )
        .expect("with_resilience must succeed with None anchors");

        let claims = TestClaims::defaults(&base, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("oversize jwks body must cause validation to fail");
        // Oversize bodies are an operator-actionable IdP availability
        // problem (the IdP is misconfigured / under attack), distinct
        // from a real forged-signature rejection. Surface them as
        // IdpUnavailable so the auth metric splits cleanly between
        // credential-stuffing and IdP outage; both still 401 on the wire.
        assert_eq!(err, OidcValidationError::IdpUnavailable);
    }

    #[tokio::test]
    async fn oversize_discovery_body_rejected() {
        // Same vector as oversize JWKS, but the oversize response comes
        // from the discovery endpoint itself. The cap applies uniformly —
        // an attacker who controls the discovery document can't OOM the
        // process before we get to jwks_uri either.
        let server = MockServer::start().await;
        let base = server.uri();

        // 2 MiB padded discovery document. Still valid JSON; just huge.
        // Build via serde_json::to_string then pad with JSON-legal fluff.
        let body = format!(
            "{{\"issuer\":\"{base}\",\"jwks_uri\":\"{base}/jwks\",\"pad\":\"{}\"}}",
            "P".repeat(2 * 1024 * 1024)
        );
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let provider = OidcProvider::with_resilience(
            base.clone(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(600),
            Duration::from_secs(10),
            1024 * 1024,
            None,
        )
        .expect("with_resilience must succeed with None anchors");

        let claims = TestClaims::defaults(&base, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("oversize discovery body must cause validation to fail");
        // M-3: oversize discovery body is the same operator-actionable
        // class as the JWKS oversize case — IdP availability problem,
        // not a forged signature.
        assert_eq!(err, OidcValidationError::IdpUnavailable);
    }

    #[tokio::test]
    async fn fetch_failed_when_upstream_unreachable() {
        // No mock server bound → connect refused → FetchFailed metric.
        // (The metric itself is crate-private; we assert the error
        // surface + port-level classification.)
        let provider = OidcProvider::with_resilience(
            "http://127.0.0.1:1".to_string(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(600),
            Duration::from_secs(10),
            DEFAULT_BODY_MAX_BYTES,
            None,
        )
        .expect("with_resilience must succeed with None anchors");
        let claims = TestClaims::defaults("http://127.0.0.1:1", "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("unreachable upstream must surface an error");
        // Transport-failure path lands on IdpUnavailable, distinct from
        // the SignatureInvalid bucket reserved for real forged-signature
        // rejects.
        assert_eq!(err, OidcValidationError::IdpUnavailable);
    }

    #[tokio::test]
    async fn parse_error_on_jwks_body_is_idp_unavailable() {
        // An IdP that returns malformed JSON for the JWKS body is an
        // availability / misconfiguration problem, not a forged-signature
        // problem. Must surface as IdpUnavailable so SOC tooling can
        // pivot on the right label.
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;
        // Valid JSON shape but garbage payload — fails to deserialise
        // into JwksResponse.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json{"))
            .mount(&server)
            .await;

        let provider = default_provider(&base);
        let claims = TestClaims::defaults(&base, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("malformed jwks body must surface an error");
        assert_eq!(err, OidcValidationError::IdpUnavailable);
    }

    #[tokio::test]
    async fn parse_error_on_discovery_body_is_idp_unavailable() {
        // M-3 sibling case — the discovery document parse error must
        // also collapse to IdpUnavailable, not SignatureInvalid.
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json{"))
            .mount(&server)
            .await;
        let provider = default_provider(&base);
        let claims = TestClaims::defaults(&base, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("malformed discovery body must surface an error");
        assert_eq!(err, OidcValidationError::IdpUnavailable);
    }

    #[tokio::test]
    async fn upstream_5xx_on_jwks_is_idp_unavailable() {
        // M-3: a 5xx from the IdP is not a forged-signature problem.
        // get_capped_body uses error_for_status() which converts any
        // non-2xx into a transport-class reqwest error — must land on
        // IdpUnavailable.
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let provider = default_provider(&base);
        let claims = TestClaims::defaults(&base, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("503 from idp must surface an error");
        assert_eq!(err, OidcValidationError::IdpUnavailable);
    }

    #[tokio::test]
    async fn signature_mismatch_remains_signature_invalid() {
        // M-3 invariant the other way: a real forged-signature path —
        // the JWKS fetch succeeds, the kid resolves, but the signature
        // verification itself fails — MUST still surface as
        // SignatureInvalid (not IdpUnavailable). The split has to be
        // crisp: only fetch failures move; everything else stays put.
        let (_server, issuer) = start_idp(jwks_body_for(DEFAULT_KID, TEST_N)).await;
        let provider = default_provider(&issuer);

        let claims = TestClaims::defaults(&issuer, "hort-server");
        // Sign with the OTHER private key — the JWKS will resolve the
        // DEFAULT_KID's RSA modulus and signature verification will fail.
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, OTHER_PRIV_PEM);

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("forged signature must reject");
        assert_eq!(err, OidcValidationError::SignatureInvalid);
    }

    #[tokio::test]
    async fn capped_body_at_exact_limit_succeeds() {
        // Boundary test: response body length == cap. Must succeed
        // (strict >, not >=). Exercises the cap's off-by-one path.
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;
        let jwks_body = serde_json::to_string(&jwks_body_for(DEFAULT_KID, TEST_N)).unwrap();
        let body_len = jwks_body.len();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(jwks_body))
            .mount(&server)
            .await;

        // Cap == exactly the body length → succeeds.
        let provider = OidcProvider::with_resilience(
            base.clone(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(600),
            Duration::from_secs(10),
            body_len,
            None,
        )
        .expect("with_resilience must succeed with None anchors");
        let claims = TestClaims::defaults(&base, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);
        provider
            .validate_token_impl(&token)
            .await
            .expect("body at exact cap must succeed");
    }

    // -- Extra-CA HTTPS JWKS tests -------------------------------------------
    //
    // Acceptance: an in-process HTTPS server presents a JWKS endpoint signed
    // by a CA that is *only* available via `extra_trust_anchors`. With
    // `anchors=Some(...)` the fetch must succeed and return
    // `JwksRefreshResult::Refreshed { … }` (observable via a successful
    // `validate_token_impl`). With `anchors=None`, the TLS handshake must
    // fail (the CA is not in the system trust store) and the validation
    // must return `OidcValidationError::IdpUnavailable`.
    //
    // Test-server architecture: `axum-server` with `RustlsConfig::from_pem`
    // provides a minimal HTTPS listener. `rcgen` generates the CA + leaf
    // cert pair in-process — no PEM fixtures on disk, no reliance on the
    // OS trust store.

    /// Builds a self-signed CA and a leaf cert signed by that CA.
    /// Returns `(ca_pem, leaf_pem, leaf_key_pem)`.
    fn make_ca_and_leaf() -> (String, String, String) {
        // CA certificate
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "oidc-test-ca".to_string());
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("generate CA keypair");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA cert");

        // Leaf certificate signed by the CA — must include the SAN
        // `127.0.0.1` so TLS hostname/IP verification passes.
        let mut leaf_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
            .expect("rcgen CertificateParams::new");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "oidc-test-leaf".to_string());
        let leaf_key = rcgen::KeyPair::generate().expect("generate leaf keypair");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("sign leaf cert with CA");

        (ca_cert.pem(), leaf_cert.pem(), leaf_key.serialize_pem())
    }

    /// Stand up a minimal HTTPS server that serves a discovery document and
    /// JWKS endpoint. Returns the bound `SocketAddr` and the test JWK body.
    async fn https_jwks_server(leaf_pem: &str, leaf_key_pem: &str) -> std::net::SocketAddr {
        // Install the aws-lc-rs crypto provider (idempotent).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
            leaf_pem.as_bytes().to_vec(),
            leaf_key_pem.as_bytes().to_vec(),
        )
        .await
        .expect("RustlsConfig::from_pem with rcgen leaf cert");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("local_addr");
        let std_listener = listener.into_std().expect("convert to std listener");
        std_listener
            .set_nonblocking(true)
            .expect("set non-blocking");

        // Build the JWKS body inline — same RSA key and JWK shape the
        // existing tests use.
        let jwks_json = jwks_body_for(DEFAULT_KID, TEST_N);
        let base = format!("https://127.0.0.1:{}", addr.port());
        let discovery_json = serde_json::json!({
            "issuer": base,
            "jwks_uri": format!("{base}/jwks"),
        });

        let app: axum::Router = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get({
                    let d = discovery_json.clone();
                    move || {
                        let d = d.clone();
                        async move { axum::Json(d) }
                    }
                }),
            )
            .route(
                "/jwks",
                axum::routing::get({
                    let j = jwks_json.clone();
                    move || {
                        let j = j.clone();
                        async move { axum::Json(j) }
                    }
                }),
            );

        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(std_listener, tls_config)
                .serve(app.into_make_service())
                .await;
        });
        // Yield so the listener task is polled before the first connect.
        tokio::task::yield_now().await;
        addr
    }

    /// Positive test: JWKS fetch succeeds when `extra_trust_anchors` contains
    /// the CA that signed the server's TLS leaf certificate.
    ///
    /// Acceptance gate for the extra-CA HTTPS JWKS path (see `ExtraTrustAnchors`).
    #[tokio::test]
    async fn extra_ca_anchors_allows_tls_to_private_ca_jwks_server() {
        let (ca_pem, leaf_pem, leaf_key_pem) = make_ca_and_leaf();
        let addr = https_jwks_server(&leaf_pem, &leaf_key_pem).await;
        let base = format!("https://127.0.0.1:{}", addr.port());

        // Parse the CA PEM into ExtraTrustAnchors — this is the only cert
        // the server's CA is present in (not in the OS trust store).
        let anchors = ExtraTrustAnchors::parse_pem(ca_pem.as_bytes()).expect("parse rcgen CA PEM");

        let provider = OidcProvider::new(
            base.clone(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(60),
            Some(&anchors),
        )
        .expect("OidcProvider::new with extra CA must succeed");

        // Mint a token signed by the test RSA key — same as the happy-path tests.
        let claims = TestClaims::defaults(&base, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);

        // The HTTPS JWKS fetch must succeed: the server is trusted because the
        // CA is in `extra_trust_anchors`.
        let out = provider
            .validate_token_impl(&token)
            .await
            .expect("validate_token_impl must succeed when extra CA is trusted");
        assert_eq!(
            out.subject, "subject-abc",
            "expected correct subject claim after successful HTTPS JWKS fetch"
        );
    }

    /// Negative test: JWKS fetch fails with a TLS error when
    /// `extra_trust_anchors` is `None` and the server uses a private CA.
    ///
    /// The CA that signed the server's leaf cert is NOT in the OS trust store,
    /// so the TLS handshake fails. The adapter must surface this as
    /// `OidcValidationError::IdpUnavailable` (not `SignatureInvalid` or
    /// `Malformed`).
    #[tokio::test]
    async fn no_extra_ca_anchors_fails_tls_to_private_ca_jwks_server() {
        let (_ca_pem, leaf_pem, leaf_key_pem) = make_ca_and_leaf();
        let addr = https_jwks_server(&leaf_pem, &leaf_key_pem).await;
        let base = format!("https://127.0.0.1:{}", addr.port());

        // Build the provider WITHOUT the extra CA — the server's CA is not
        // in the OS trust store, so the TLS handshake must fail.
        let provider = OidcProvider::new(
            base.clone(),
            "hort-server".into(),
            "groups".into(),
            Duration::from_secs(60),
            None,
        )
        .expect("OidcProvider::new with None anchors must succeed");

        let claims = TestClaims::defaults(&base, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("TLS handshake must fail: CA not trusted by the system store");
        assert_eq!(
            err,
            OidcValidationError::IdpUnavailable,
            "TLS failure to private-CA JWKS endpoint must surface as IdpUnavailable \
             (not SignatureInvalid — that would conflate a network error with a \
             forged-signature credential-stuffing campaign)"
        );
    }

    // -- Redirect-cap hardening tests ----------------------------------------
    //
    // Redirect-cap regression for the OIDC reqwest client. The adapter
    // must cap JWKS-fetch redirect chains at 3 hops. The connect-time DNS
    // guard was considered but reverted — operator-pinned IdP URL has no
    // SSRF surface; redirect cap + timeout remain as the defense-in-depth.
    //
    // The test asserts `OidcValidationError::IdpUnavailable`. Any
    // transport-level failure (redirect-cap exceeded, connect error, TLS
    // failure) is classified as `IdpUnavailable` — the wire-level outcome
    // is 401 and the auth metric records an IdP-outage, distinct from a
    // forged-signature credential-stuffing campaign.

    /// Redirect-cap regression: the JWKS fetch must give up after 3 hops.
    /// We chain 5 redirects and assert the fetch fails without ever
    /// reaching the terminal `/jwks` endpoint.
    #[tokio::test]
    async fn jwks_uri_redirect_chain_exceeding_three_hops_is_blocked() {
        let server = MockServer::start().await;
        let issuer = server.uri();

        // Discovery → /redirect/0 (1) → /redirect/1 (2) → /redirect/2 (3)
        // → /redirect/3 (4) → /redirect/4 (5) → /jwks
        // With Policy::limited(3) reqwest follows at most 3 hops, so the
        // chain must be cut before reaching /jwks.
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "jwks_uri": format!("{issuer}/redirect/0"),
            })))
            .mount(&server)
            .await;

        for i in 0..4u32 {
            let next = format!("{issuer}/redirect/{}", i + 1);
            Mock::given(method("GET"))
                .and(path(format!("/redirect/{i}")))
                .respond_with(ResponseTemplate::new(302).insert_header("Location", next.as_str()))
                .mount(&server)
                .await;
        }
        // /redirect/4 → /jwks (the would-be terminal hop, must not be
        // reached because we cap at 3).
        Mock::given(method("GET"))
            .and(path("/redirect/4"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{issuer}/jwks").as_str()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(jwks_body_for(DEFAULT_KID, TEST_N)),
            )
            .mount(&server)
            .await;

        let provider = default_provider(&issuer);

        let claims = TestClaims::defaults(&issuer, "hort-server");
        let token = sign(&claims, Algorithm::RS256, DEFAULT_KID, TEST_PRIV_PEM);

        let err = provider
            .validate_token_impl(&token)
            .await
            .expect_err("redirect chain > 3 hops must be cut by Policy::limited(3)");
        assert_eq!(
            err,
            OidcValidationError::IdpUnavailable,
            "redirect-cap exceeded must surface as IdpUnavailable \
             (transport failure, M-3 bucket — not a forged-signature signal)"
        );
    }
}
