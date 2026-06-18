//! Multi-issuer JWT validator for the federation branch of
//! `/auth/token-exchange`.
//!
//! # Responsibilities
//!
//! Implements [`FederatedJwtValidator`] over a set of trusted
//! [`OidcIssuer`] rows (read via
//! [`OidcIssuerRepository`]). For each `validate()` call:
//!
//! 1. Decode the JWT header + payload without signature trust to extract
//!    `kid`, `alg`, and `iss`.
//! 2. Look up the trusted issuer by `iss` exact-match.
//! 3. Gate the JWT header `alg` against the issuer's
//!    `allowed_algorithms` BEFORE any signature work.
//! 4. Refresh the per-issuer JWKS cache when stale (per
//!    `OidcIssuer.jwks_refresh_interval`).
//! 5. Verify the signature, `aud`, `exp`, `nbf` with the
//!    configured leeway.
//! 6. Return [`ValidatedClaims`] on success or
//!    [`FederationDenyReason`] on the matching deny path.
//!
//! Step 7 of the federation flow (service-account matching) is the
//! federation handler's responsibility — this validator does NOT walk
//! `ServiceAccount.federated_identities[].claims`.
//!
//! # Cache shape
//!
//! Per-issuer entries in a `RwLock<HashMap<issuer_name, JwksCacheEntry>>`.
//! Each entry carries the current JWKS keyed by `kid` and the
//! `last_refreshed` timestamp (UTC, wall-clock so cache lifetime is
//! relative to the operator-declared interval, NOT the process uptime).
//!
//! Refresh is lazy: on a `validate()` call, the validator checks
//! `now - last_refreshed > issuer.jwks_refresh_interval`. Stale entries
//! refresh inline; the refresh emits `hort_jwks_refresh_total{issuer=
//! <issuer.name>, result=...}`.
//!
//! # HTTP client layering
//!
//! The HTTP client (extra-CA layering, redirect cap, timeout, TLS
//! version pin) and the body-capped GET helper are shared with
//! `OidcProvider` via `crate::internal`. The full discovery +
//! key-rotation audit flow lives on `OidcProvider`; this validator
//! does NOT emit `OidcKeyRotated` events — rotation observation is the
//! user-login adapter's job; the federation path lives on the issuer's
//! published JWKS without per-rotation audit.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use hort_domain::entities::oidc_issuer::{JwtAlg, OidcIssuer};
use hort_domain::ports::federated_jwt_validator::{
    FederatedJwtValidator, FederationDenyReason, ValidatedClaims,
};
use hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository;
use hort_domain::ports::BoxFuture;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::internal::{self, CappedBodyError};
use crate::metrics::{emit_jwks_refresh, JwksRefreshResult};

/// Default JWKS response-body cap when none is supplied to the
/// constructor — mirrors `OidcProvider`'s
/// [`crate::DEFAULT_BODY_MAX_BYTES`] (1 MiB). Federation IdPs publish
/// JWKS documents in the same shape as user-login IdPs, so the same
/// cap applies.
pub const DEFAULT_BODY_MAX_BYTES: usize = 1024 * 1024;

/// Leeway applied to `exp` / `nbf` / `iat` — 30 s, matching the
/// single-issuer `OidcProvider`. Hard-coded because federation has no
/// per-issuer leeway knob today; standardising on one value avoids
/// "looks like a clock-skew issue but it's actually because we used a
/// different leeway here" footguns.
const FEDERATION_LEEWAY_SECONDS: u64 = 30;

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

/// Multi-issuer JWT validator.
///
/// One instance per hort-server process; trusted-issuer rows are looked up
/// fresh on each `validate()` call so apply-time changes (gitops apply)
/// take effect immediately without bouncing the validator. The JWKS cache
/// is per-process, keyed by issuer name.
///
/// Construction is fallible only via the underlying
/// [`internal::build_http_client`] (extra-CA parsing). Once built, the
/// validator's `validate()` is infallible at construction time — every
/// failure surfaces as a [`FederationDenyReason`].
pub struct MultiIssuerJwksValidator {
    issuers: Arc<dyn OidcIssuerRepository>,
    http: reqwest::Client,
    caches: RwLock<HashMap<String, JwksCacheEntry>>,
    body_max_bytes: usize,
    leeway_seconds: u64,
}

/// One JWKS cache entry per trusted issuer.
struct JwksCacheEntry {
    keys: HashMap<String, jsonwebtoken::jwk::Jwk>,
    /// Wall-clock UTC timestamp of the last successful refresh.
    last_refreshed: DateTime<Utc>,
}

impl MultiIssuerJwksValidator {
    /// Construct the validator with the default body cap and leeway.
    ///
    /// `issuers` is the repository the validator consults for trusted
    /// rows. `extra_trust_anchors` is the optional process-wide extra
    /// CA bundle (`HORT_EXTRA_CA_BUNDLE`; see ADR 0010).
    ///
    /// # Errors
    ///
    /// Returns [`crate::ExtraCaApplyError`] if any certificate in
    /// `extra_trust_anchors` is rejected by reqwest, or if
    /// `ClientBuilder::build()` fails — both are boot-time failures.
    pub fn new(
        issuers: Arc<dyn OidcIssuerRepository>,
        extra_trust_anchors: Option<&hort_config::ExtraTrustAnchors>,
    ) -> Result<Self, crate::ExtraCaApplyError> {
        Self::with_body_cap(issuers, extra_trust_anchors, DEFAULT_BODY_MAX_BYTES)
    }

    /// Construct with an explicit body cap (tests use a small value to
    /// exercise the `BodyTooLarge` path).
    pub fn with_body_cap(
        issuers: Arc<dyn OidcIssuerRepository>,
        extra_trust_anchors: Option<&hort_config::ExtraTrustAnchors>,
        body_max_bytes: usize,
    ) -> Result<Self, crate::ExtraCaApplyError> {
        let http = internal::build_http_client(extra_trust_anchors)?;
        Ok(Self {
            issuers,
            http,
            caches: RwLock::new(HashMap::new()),
            body_max_bytes,
            leeway_seconds: FEDERATION_LEEWAY_SECONDS,
        })
    }

    /// Core validation flow — broken out from the trait impl so tests
    /// can drive it as a plain `async fn` without `BoxFuture` plumbing.
    async fn validate_impl(&self, jwt: &str) -> Result<ValidatedClaims, FederationDenyReason> {
        // ----- Step 1: decode header (no signature trust) -------------------
        let header = decode_header(jwt).map_err(|e| {
            debug!(error = %e, "federation jwt header decode failed");
            FederationDenyReason::InvalidFormat
        })?;
        let alg = header.alg;
        let kid = header.kid.ok_or_else(|| {
            debug!("federation jwt header has no kid");
            FederationDenyReason::InvalidFormat
        })?;

        // ----- Step 1 (cont.): decode payload to extract `iss` --------------
        let payload = extract_payload_claims(jwt)?;
        let iss = payload.iss.as_deref().ok_or_else(|| {
            debug!("federation jwt payload has no iss claim");
            FederationDenyReason::InvalidFormat
        })?;

        // ----- Step 2: trusted-issuer lookup --------------------------------
        let issuer = self
            .issuers
            .get_by_issuer_url(iss)
            .await
            .map_err(|e| {
                // Database lookup failed — the wire response shape is
                // the same as `UnknownIssuer` for the caller (denied),
                // but we log it distinctly to avoid an outage looking
                // like a config error in the dashboard. Surface as
                // `UnknownIssuer` because the federation path has no
                // distinct "infrastructure unavailable" deny variant.
                warn!(
                    iss = %iss,
                    error = %e,
                    "federation issuer-repository lookup failed; treating as unknown_issuer"
                );
                FederationDenyReason::UnknownIssuer
            })?
            .ok_or_else(|| {
                debug!(iss = %iss, "federation jwt iss did not match a trusted issuer");
                FederationDenyReason::UnknownIssuer
            })?;

        // ----- Step 3: algorithm gate (BEFORE signature work) ---------------
        if !algorithm_allowed(alg, &issuer.allowed_algorithms) {
            debug!(
                iss = %iss,
                alg = ?alg,
                "federation jwt presented with disallowed algorithm"
            );
            return Err(FederationDenyReason::AlgorithmNotAllowed);
        }

        // ----- Step 4: resolve JWK (cached refresh if stale) ----------------
        let jwk = self.resolve_jwk(&issuer, &kid).await?;

        // ----- Step 5: signature verification -------------------------------
        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            warn!(
                issuer = %issuer.name,
                %kid,
                error = %e,
                "federation jwk → decoding-key conversion failed"
            );
            FederationDenyReason::SignatureInvalid
        })?;

        // `Validation` is configured with the JWT header's `alg` (the
        // gate above guaranteed it's in the issuer's allowlist) and the
        // issuer URL. Audience validation is done manually below so we
        // can capture the *matched* audience for `ValidatedClaims`.
        let mut validation = Validation::new(alg);
        validation.leeway = self.leeway_seconds;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // Audience validated manually — see below.
        validation.validate_aud = false;
        validation.set_issuer(&[&issuer.issuer_url]);

        let data = decode::<RawFederationClaims>(jwt, &decoding_key, &validation).map_err(|e| {
            let variant = classify_federation_jwt_error(&e);
            debug!(
                issuer = %issuer.name,
                reason = variant.as_str(),
                "federation jwt validation rejected"
            );
            variant
        })?;

        // ----- Step 6: audience check ---------------------------------------
        let aud = data.claims.aud();
        let matched_audience = match_audience(&aud, &issuer.audiences).ok_or_else(|| {
            debug!(
                issuer = %issuer.name,
                "federation jwt aud did not intersect issuer.audiences"
            );
            FederationDenyReason::AudMismatch
        })?;

        // ----- Build the ValidatedClaims --------------------------------
        let subject = data.claims.sub().map(String::from).ok_or_else(|| {
            debug!(issuer = %issuer.name, "federation jwt missing sub claim");
            FederationDenyReason::InvalidFormat
        })?;
        let jti = data.claims.jti();
        // `validation.validate_exp = true` makes `decode` reject any JWT
        // without `exp`, so this `None` branch is unreachable on the
        // success path. `debug_assert` surfaces any future
        // jsonwebtoken-side contract change in tests; production
        // collapses the unreachable branch to `InvalidFormat` rather
        // than panicking.
        let exp_raw = data.claims.exp().ok_or_else(|| {
            debug_assert!(
                false,
                "RawFederationClaims::exp() returned None after \
                 jsonwebtoken decode succeeded with validate_exp=true"
            );
            debug!(
                issuer = %issuer.name,
                "federation jwt missing exp claim after signature verification \
                 (unexpected — validate_exp=true should have rejected it)"
            );
            FederationDenyReason::InvalidFormat
        })?;
        let expires_at = DateTime::<Utc>::from_timestamp(exp_raw, 0).ok_or_else(|| {
            debug!(
                issuer = %issuer.name,
                exp = exp_raw,
                "federation jwt exp is not a representable Utc timestamp"
            );
            FederationDenyReason::InvalidFormat
        })?;

        // Surface the raw `iat`/`exp` NumericDate values for the
        // `ReplayKey::Composite` fallback. No extra parse: `data.claims`
        // is the already-decoded payload. `exp_raw` reuses `exp_raw`
        // above (the validator enforced `exp`); `iat` is optional.
        let iat = data.claims.iat();

        Ok(ValidatedClaims {
            issuer: iss.to_string(),
            issuer_name: issuer.name.clone(),
            subject,
            audience: matched_audience,
            jti,
            expires_at,
            iat,
            exp_raw,
            all_claims: data.claims.into_all_claims(),
        })
    }

    /// Resolve the JWK for `kid` under `issuer`, refreshing the JWKS
    /// cache when stale per `issuer.jwks_refresh_interval`.
    async fn resolve_jwk(
        &self,
        issuer: &OidcIssuer,
        kid: &str,
    ) -> Result<jsonwebtoken::jwk::Jwk, FederationDenyReason> {
        // Fast path: read lock.
        {
            let guard = self.caches.read().await;
            if let Some(entry) = guard.get(&issuer.name) {
                if !is_stale(entry, issuer.jwks_refresh_interval) {
                    if let Some(jwk) = entry.keys.get(kid) {
                        debug!(issuer = %issuer.name, %kid, "federation jwks cache hit");
                        return Ok(jwk.clone());
                    }
                    // Fresh entry but missing kid: fall through to refresh.
                    // Kid rotation could have produced a new signing key
                    // that arrived between cache populations.
                    debug!(
                        issuer = %issuer.name,
                        %kid,
                        "federation jwks fresh but kid unknown — refreshing"
                    );
                } else {
                    debug!(issuer = %issuer.name, %kid, "federation jwks stale — refreshing");
                }
            }
        }

        // Slow path: write lock, double-check freshness, fetch.
        let mut guard = self.caches.write().await;
        if let Some(entry) = guard.get(&issuer.name) {
            if !is_stale(entry, issuer.jwks_refresh_interval) {
                if let Some(jwk) = entry.keys.get(kid) {
                    return Ok(jwk.clone());
                }
            }
        }

        let fresh_keys = self
            .fetch_jwks(issuer, RefreshContext::RuntimeValidate)
            .await?;
        let new_entry = JwksCacheEntry {
            keys: fresh_keys,
            last_refreshed: Utc::now(),
        };
        let resolved = new_entry.keys.get(kid).cloned();
        guard.insert(issuer.name.clone(), new_entry);
        drop(guard);

        resolved.ok_or_else(|| {
            debug!(
                issuer = %issuer.name,
                %kid,
                "federation jwt kid not present in freshly fetched jwks"
            );
            FederationDenyReason::UnknownKid
        })
    }

    /// Fetch the issuer's JWKS via OIDC discovery. Emits
    /// `hort_jwks_refresh_total{issuer=<issuer.name>, result=...}` for
    /// every refresh attempt.
    ///
    /// `context` selects the failure-side metric variant: the validator
    /// (`validate_impl`) path emits the granular [`JwksRefreshResult::FetchFailed`]
    /// / [`JwksRefreshResult::BodyTooLarge`] / [`JwksRefreshResult::ParseError`]
    /// variants; the apply-time warm-up ([`Self::refresh_issuer_impl`])
    /// collapses every failure to [`JwksRefreshResult::ApplyWarmupFailed`].
    /// `Success` is always emitted as `Success` regardless of context.
    async fn fetch_jwks(
        &self,
        issuer: &OidcIssuer,
        context: RefreshContext,
    ) -> Result<HashMap<String, jsonwebtoken::jwk::Jwk>, FederationDenyReason> {
        let issuer_label = issuer.name.as_str();
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.issuer_url.trim_end_matches('/')
        );
        debug!(
            issuer = %issuer.name,
            url = %discovery_url,
            "federation discovery fetch"
        );
        let discovery_bytes = match internal::get_capped_body(
            &self.http,
            &discovery_url,
            self.body_max_bytes,
        )
        .await
        {
            Ok(b) => b,
            Err(CappedBodyError::BodyTooLarge { bytes_read, cap }) => {
                emit_jwks_refresh(issuer_label, context.body_too_large_result());
                warn!(
                    issuer = %issuer.name,
                    url = %discovery_url,
                    bytes_read,
                    cap,
                    "federation discovery body exceeded cap"
                );
                return Err(FederationDenyReason::UnknownKid);
            }
            Err(CappedBodyError::FetchFailed(detail)) => {
                emit_jwks_refresh(issuer_label, context.fetch_failed_result());
                warn!(
                    issuer = %issuer.name,
                    url = %discovery_url,
                    detail,
                    "federation discovery fetch failed"
                );
                return Err(FederationDenyReason::UnknownKid);
            }
        };

        let discovery: DiscoveryDocument =
            serde_json::from_slice(&discovery_bytes).map_err(|e| {
                emit_jwks_refresh(issuer_label, context.parse_error_result());
                warn!(
                    issuer = %issuer.name,
                    url = %discovery_url,
                    error = %e,
                    "federation discovery body parse failed"
                );
                FederationDenyReason::UnknownKid
            })?;

        // Bind the discovery-supplied `jwks_uri` to the issuer's own host
        // (same-host binding) BEFORE the fetch. The check is additive:
        // the TLS pin + redirect cap on `self.http` (built by
        // `internal::build_http_client`) are unchanged. A rejection
        // collapses to the same deny reason + metric as any other
        // JWKS-fetch failure on this path (`UnknownKid` / `fetch_failed`);
        // no new wire error or metric. The routability leg was dropped
        // post-E2E (it rejected the internal-IdP case);
        // see `internal::check_jwks_uri_bound`.
        if let Err(e) = internal::check_jwks_uri_bound(&issuer.issuer_url, &discovery.jwks_uri) {
            emit_jwks_refresh(issuer_label, context.fetch_failed_result());
            warn!(
                issuer = %issuer.name,
                jwks_uri = %discovery.jwks_uri,
                reason = ?e,
                "federation jwks_uri rejected by same-host origin guard"
            );
            return Err(FederationDenyReason::UnknownKid);
        }

        let jwks_bytes =
            match internal::get_capped_body(&self.http, &discovery.jwks_uri, self.body_max_bytes)
                .await
            {
                Ok(b) => b,
                Err(CappedBodyError::BodyTooLarge { bytes_read, cap }) => {
                    emit_jwks_refresh(issuer_label, context.body_too_large_result());
                    warn!(
                        issuer = %issuer.name,
                        jwks_uri = %discovery.jwks_uri,
                        bytes_read,
                        cap,
                        "federation jwks body exceeded cap"
                    );
                    return Err(FederationDenyReason::UnknownKid);
                }
                Err(CappedBodyError::FetchFailed(detail)) => {
                    emit_jwks_refresh(issuer_label, context.fetch_failed_result());
                    warn!(
                        issuer = %issuer.name,
                        jwks_uri = %discovery.jwks_uri,
                        detail,
                        "federation jwks fetch failed"
                    );
                    return Err(FederationDenyReason::UnknownKid);
                }
            };

        let jwks: JwksResponse = serde_json::from_slice(&jwks_bytes).map_err(|e| {
            emit_jwks_refresh(issuer_label, context.parse_error_result());
            warn!(
                issuer = %issuer.name,
                jwks_uri = %discovery.jwks_uri,
                error = %e,
                "federation jwks body parse failed"
            );
            FederationDenyReason::UnknownKid
        })?;

        emit_jwks_refresh(issuer_label, JwksRefreshResult::Success);
        let mut keys = HashMap::with_capacity(jwks.keys.len());
        for jwk in jwks.keys {
            if let Some(kid) = jwk.common.key_id.clone() {
                keys.insert(kid, jwk);
            } else {
                // A JWKS entry without a `kid` is valid per RFC 7517 but
                // unusable here — the cache is keyed by `kid`. Mirrors
                // `JwksCache::replace` in the single-issuer path.
                debug!(
                    issuer = %issuer.name,
                    "federation jwks entry without kid — skipping"
                );
            }
        }
        Ok(keys)
    }

    /// Apply-time JWKS warm-up implementation.
    ///
    /// Fetches the JWKS via [`Self::fetch_jwks`] in [`RefreshContext::ApplyWarmup`]
    /// mode (every failure path emits `hort_jwks_refresh_total{result=
    /// apply_warmup_failed}` instead of the granular `fetch_failed` /
    /// `body_too_large` / `parse_error` variants — operators dashboard
    /// "apply pushed a config that the IdP can't serve" separately from
    /// "IdP went down during normal serving"). On success, the cache
    /// entry is populated so the first federation `validate()` call
    /// against this issuer skips the discovery + JWKS round trip.
    ///
    /// The caller (`ApplyConfigUseCase::apply_oidc_issuers`) treats
    /// every non-`Ok` return as warm-up-failed and proceeds with the
    /// apply — federation works lazily via the cache-miss path.
    async fn refresh_issuer_impl(&self, issuer: &OidcIssuer) -> Result<(), FederationDenyReason> {
        let fresh_keys = self.fetch_jwks(issuer, RefreshContext::ApplyWarmup).await?;
        let new_entry = JwksCacheEntry {
            keys: fresh_keys,
            last_refreshed: Utc::now(),
        };
        let mut guard = self.caches.write().await;
        guard.insert(issuer.name.clone(), new_entry);
        debug!(
            issuer = %issuer.name,
            "federation jwks apply-time warm-up populated cache"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RefreshContext
// ---------------------------------------------------------------------------

/// Selects which `JwksRefreshResult` variant `fetch_jwks` emits on the
/// failure path. The success path always emits [`JwksRefreshResult::Success`].
///
/// The validator's `validate()` path (`RuntimeValidate`) maps fetch /
/// body-cap / parse errors to the granular variants so a SIEM dashboard
/// can distinguish IdP outage flavours. The apply-time warm-up
/// (`ApplyWarmup`) collapses every failure to
/// [`JwksRefreshResult::ApplyWarmupFailed`] so operators see "the apply
/// pushed a config that the IdP can't serve" as a single signal,
/// distinct from "the IdP went down during normal serving".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshContext {
    /// Runtime `validate_impl` cache-refresh path. Granular failure
    /// labels (`fetch_failed`, `body_too_large`, `parse_error`).
    RuntimeValidate,
    /// Apply-time warm-up path. Every failure label collapses to
    /// `apply_warmup_failed`.
    ApplyWarmup,
}

impl RefreshContext {
    fn fetch_failed_result(self) -> JwksRefreshResult {
        match self {
            Self::RuntimeValidate => JwksRefreshResult::FetchFailed,
            Self::ApplyWarmup => JwksRefreshResult::ApplyWarmupFailed,
        }
    }
    fn body_too_large_result(self) -> JwksRefreshResult {
        match self {
            Self::RuntimeValidate => JwksRefreshResult::BodyTooLarge,
            Self::ApplyWarmup => JwksRefreshResult::ApplyWarmupFailed,
        }
    }
    fn parse_error_result(self) -> JwksRefreshResult {
        match self {
            Self::RuntimeValidate => JwksRefreshResult::ParseError,
            Self::ApplyWarmup => JwksRefreshResult::ApplyWarmupFailed,
        }
    }
}

impl FederatedJwtValidator for MultiIssuerJwksValidator {
    fn validate<'a>(
        &'a self,
        jwt: &'a str,
    ) -> BoxFuture<'a, Result<ValidatedClaims, FederationDenyReason>> {
        Box::pin(self.validate_impl(jwt))
    }

    fn refresh_issuer<'a>(
        &'a self,
        issuer: &'a OidcIssuer,
    ) -> BoxFuture<'a, Result<(), FederationDenyReason>> {
        Box::pin(self.refresh_issuer_impl(issuer))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_stale(entry: &JwksCacheEntry, refresh_interval: Duration) -> bool {
    let now = Utc::now();
    let elapsed = now.signed_duration_since(entry.last_refreshed);
    // `to_std()` returns `Err` for negative durations (clock-skew). Treat
    // negative as "not stale" — the wall clock jumped backwards, but the
    // cache contents are still valid; refreshing on every call until the
    // clock resyncs would be a self-DOS.
    match elapsed.to_std() {
        Ok(d) => d > refresh_interval,
        Err(_) => false,
    }
}

fn algorithm_allowed(alg: Algorithm, allowed: &[JwtAlg]) -> bool {
    allowed.iter().any(|a| jwt_alg_matches_algorithm(*a, alg))
}

/// Map [`JwtAlg`] (domain enum) to [`jsonwebtoken::Algorithm`] for the
/// allowlist comparison. The two enums are intentionally separated:
/// `JwtAlg` carries trust semantics (RS*/ES* only — no `HS*`) and lives
/// in `hort-domain`; `Algorithm` is the wire-form enum from the JWT
/// library and carries no trust intent.
///
/// Note: [`JwtAlg::Es512`] has no counterpart in `jsonwebtoken` 10.x —
/// the JWT library exposes ES256 and ES384 but not ES512 (jsonwebtoken
/// 10.3.0 `algorithms.rs`). An operator declaring `ES512` in
/// `OidcIssuer.allowed_algorithms` cannot have any incoming JWT
/// match it, because `decode_header` will surface the wire algorithm
/// as a different `Algorithm` variant. The function returns `false`
/// for that pair — the JWT is denied at the algorithm gate with
/// `AlgorithmNotAllowed`. Promoting ES512 support is a follow-on once
/// jsonwebtoken adds the variant.
fn jwt_alg_matches_algorithm(domain: JwtAlg, wire: Algorithm) -> bool {
    matches!(
        (domain, wire),
        (JwtAlg::Rs256, Algorithm::RS256)
            | (JwtAlg::Rs384, Algorithm::RS384)
            | (JwtAlg::Rs512, Algorithm::RS512)
            | (JwtAlg::Es256, Algorithm::ES256)
            | (JwtAlg::Es384, Algorithm::ES384)
    )
}

/// Match the JWT's `aud` claim against the issuer's audiences.
///
/// RFC 7519 §4.1.3: `aud` may be a single string OR an array of strings;
/// the JWT is valid for THIS RP iff any entry intersects.
fn match_audience(aud: &AudClaim, allowed: &[String]) -> Option<String> {
    match aud {
        AudClaim::Single(s) => allowed.iter().find(|a| *a == s).cloned(),
        AudClaim::Multi(many) => many
            .iter()
            .find(|s| allowed.iter().any(|a| a == *s))
            .cloned(),
        AudClaim::Absent => None,
    }
}

/// Extract enough of the JWT payload to find `iss` without paying for
/// the full claim deserialisation. The signature is NOT verified at
/// this point — the result is consumed only to drive issuer lookup; the
/// signature gate runs on a SECOND decode after the JWK is resolved.
fn extract_payload_claims(jwt: &str) -> Result<UnverifiedPayload, FederationDenyReason> {
    // JWT compact serialisation: header.payload.signature
    let mut parts = jwt.split('.');
    let _header = parts.next().ok_or(FederationDenyReason::InvalidFormat)?;
    let payload_b64 = parts.next().ok_or(FederationDenyReason::InvalidFormat)?;
    let _sig = parts.next().ok_or(FederationDenyReason::InvalidFormat)?;
    if parts.next().is_some() {
        return Err(FederationDenyReason::InvalidFormat);
    }

    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| FederationDenyReason::InvalidFormat)?;
    serde_json::from_slice::<UnverifiedPayload>(&bytes)
        .map_err(|_| FederationDenyReason::InvalidFormat)
}

/// Classify a `jsonwebtoken::errors::Error` from the post-key-resolution
/// decode into the matching deny reason. The signature-failure / expired
/// / not-yet-valid / aud paths each map to a distinct deny variant.
///
/// Audience errors should never reach here — we set
/// `validation.validate_aud = false` and do the audience check
/// manually so we can capture the matched value — but the variant is
/// listed for defensiveness.
fn classify_federation_jwt_error(e: &jsonwebtoken::errors::Error) -> FederationDenyReason {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::InvalidSignature => FederationDenyReason::SignatureInvalid,
        ErrorKind::ExpiredSignature => FederationDenyReason::Expired,
        ErrorKind::ImmatureSignature => FederationDenyReason::NotYetValid,
        ErrorKind::InvalidIssuer => FederationDenyReason::UnknownIssuer,
        ErrorKind::InvalidAudience => FederationDenyReason::AudMismatch,
        ErrorKind::InvalidAlgorithm => FederationDenyReason::AlgorithmNotAllowed,
        ErrorKind::MissingRequiredClaim(_) => FederationDenyReason::InvalidFormat,
        ErrorKind::InvalidToken => FederationDenyReason::InvalidFormat,
        // Any other kind (RSA / EC family mismatches, malformed key,
        // etc.) collapses to SignatureInvalid — the same wire response
        // a real signature failure produces.
        _ => FederationDenyReason::SignatureInvalid,
    }
}

// ---------------------------------------------------------------------------
// Wire-shape types
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct DiscoveryDocument {
    jwks_uri: String,
}

#[derive(Debug, serde::Deserialize)]
struct JwksResponse {
    keys: Vec<jsonwebtoken::jwk::Jwk>,
}

/// Minimal payload claims for issuer lookup. Decoded WITHOUT signature
/// verification — the resulting `iss` value drives issuer resolution,
/// after which a second decode (with signature verification) produces
/// the trusted [`RawFederationClaims`].
#[derive(Debug, serde::Deserialize)]
struct UnverifiedPayload {
    iss: Option<String>,
}

/// Post-signature-verification claims, deserialised from the JWT payload
/// by `jsonwebtoken::decode`.
///
/// # Why `#[serde(transparent)]` over a `BTreeMap` (and not named fields)
///
/// An earlier shape declared `sub`, `aud`, `exp`, `jti` as named fields
/// PLUS `#[serde(flatten)] all_claims: BTreeMap<...>`. That hits the
/// standard serde semantics for `flatten`: the map only captures the
/// fields NOT consumed by named ones. So `all_claims.get("sub")`
/// returned `None`, which silently broke the federation handler — it
/// walks `claims.all_claims.get(k)` against the
/// `ServiceAccount.federated_identities[].claims` map, and the k8s
/// how-to (`docs/architecture/how-to/federate-k8s-workload-identity.md`)
/// documents `sub: system:serviceaccount:<ns>:<name>` as the canonical
/// selector. Every k8s pod got a silent `no_sa_match` deny.
///
/// The fix: deserialise the entire payload into a
/// `BTreeMap<String, serde_json::Value>` first, then expose the four
/// typed accessors that pull from the same map. The accessors clone
/// what they need — the overhead is one extra `BTreeMap::get` + clone
/// per call, which is negligible against the network + cryptographic
/// work the path already does.
#[derive(Debug, serde::Deserialize)]
#[serde(transparent)]
struct RawFederationClaims(BTreeMap<String, serde_json::Value>);

impl RawFederationClaims {
    /// `sub` per RFC 7519 §4.1.2 — optional in the JWT itself, required
    /// for federation (the handler's `collect_sa_matches` cannot
    /// compare against a missing subject). The validator surfaces
    /// `FederationDenyReason::InvalidFormat` when absent.
    fn sub(&self) -> Option<&str> {
        self.0.get("sub").and_then(|v| v.as_str())
    }

    /// `aud` per RFC 7519 §4.1.3 — single string OR array of strings.
    /// Parsed via the same `AudClaim` decoder as before. A missing
    /// `aud` deserialises to [`AudClaim::Absent`] and the audience
    /// match later returns `None` → `FederationDenyReason::AudMismatch`.
    fn aud(&self) -> AudClaim {
        match self.0.get("aud") {
            None => AudClaim::Absent,
            Some(v) => serde_json::from_value::<AudClaim>(v.clone()).unwrap_or(AudClaim::Absent),
        }
    }

    /// `exp` per RFC 7519 §4.1.4.
    ///
    /// `jsonwebtoken::decode` is invoked with `validation.validate_exp
    /// = true`, which enforces `exp` presence at signature-verify time.
    /// On the success path of `validate_impl`, this accessor is
    /// therefore expected to return `Some(_)` — `None` would mean the
    /// JWT library accepted a payload without `exp`, which would be a
    /// jsonwebtoken regression. The validator surfaces
    /// `FederationDenyReason::InvalidFormat` defensively if it ever
    /// happens, with a `debug_assert` to surface the contract violation
    /// in test builds.
    fn exp(&self) -> Option<i64> {
        self.0.get("exp").and_then(serde_json::Value::as_i64)
    }

    /// `jti` per RFC 7519 §4.1.7 — optional; federation IdPs are
    /// inconsistent about emitting it.
    fn jti(&self) -> Option<String> {
        self.0.get("jti").and_then(|v| v.as_str()).map(String::from)
    }

    /// `iat` per RFC 7519 §4.1.6 — optional. Feeds `ValidatedClaims.iat`
    /// for the `ReplayKey::Composite` fallback. `None` when the JWT
    /// omitted `iat` (the composite key is then not constructible — the
    /// use case denies with `jti_required`-equivalent semantics).
    fn iat(&self) -> Option<i64> {
        self.0.get("iat").and_then(serde_json::Value::as_i64)
    }

    /// Consume `self` and surface the full claim map (every claim,
    /// including the four named ones above). Used to populate
    /// `ValidatedClaims.all_claims` so the federation handler can match
    /// against any claim by string key — see the type-level doc above.
    fn into_all_claims(self) -> BTreeMap<String, serde_json::Value> {
        self.0
    }
}

/// `aud` claim shape per RFC 7519 §4.1.3 — single string or array of
/// strings. Untagged so serde transparently accepts either form.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(untagged)]
enum AudClaim {
    Single(String),
    Multi(Vec<String>),
    // serde's `untagged` requires a variant for missing fields; we
    // model that explicitly so `aud = None` is distinguishable from
    // `aud = ""`. `#[serde(default)]` on the field uses this.
    #[default]
    #[serde(skip)]
    Absent,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Test strategy mirrors the `OidcProvider` suite in `lib.rs`:
// - Sign tokens with a checked-in RSA-2048 keypair (test-only).
// - Stand up a `wiremock` server pretending to be the IdP discovery +
//   JWKS endpoints.
// - Use a hand-rolled `OidcIssuerRepository` capture double that
//   resolves to a known issuer keyed off the wiremock base URL.
//
// Every `FederationDenyReason` variant is exercised by a deliberately-
// malformed input. The single-issuer `OidcProvider` tests remain in
// `lib.rs` and verify that path unchanged.

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;
    use serde_json::json;
    use std::sync::Mutex;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -- Test keypair (RSA-2048, test-only — same as the single-issuer suite) --

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

    const TEST_N: &str = "pogr9Enyx52IOjL10tPu90w4F6jWHmQ0XML3abN5CEzODk2ZtI_nQPXBTU7usMztDOSRI39YOVlGXBh1gj3Y0opfAWqLVyroxo-MqH3bD9SZoP8v7v9oE551DgQbmvbIUB9SyTz6UxKWRqR-oPrioijbaBB-S9hfg-wkxxdRdqSLVkJ_3-gPW1QwXafHO2vWfmCgDmwyootZgC0Lgkqy3FixKBsyYoubCROp7P3iD7dTn8CMTC6sdY2YViln06B24UN3SG--sTNRMV6j5Y7rLrLxJXZQZUphlV97EoCGcMfd1h31I3GHHA4TyFlrh1J5obqUi1tCCRy137iWdK-Erw";
    const TEST_E: &str = "AQAB";
    const DEFAULT_KID: &str = "fed-key-1";

    // -- Repository capture double -----------------------------------------

    struct StaticIssuerRepo {
        issuers: Mutex<Vec<OidcIssuer>>,
    }

    impl StaticIssuerRepo {
        fn new(issuers: Vec<OidcIssuer>) -> Arc<Self> {
            Arc::new(Self {
                issuers: Mutex::new(issuers),
            })
        }
    }

    impl OidcIssuerRepository for StaticIssuerRepo {
        fn list(&self) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<OidcIssuer>>> {
            let snap = self.issuers.lock().unwrap().clone();
            Box::pin(async move { Ok(snap) })
        }

        fn get_by_name(
            &self,
            name: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<OidcIssuer>>> {
            let name = name.to_string();
            let snap = self.issuers.lock().unwrap().clone();
            Box::pin(async move { Ok(snap.into_iter().find(|i| i.name == name)) })
        }

        fn get_by_issuer_url(
            &self,
            url: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<OidcIssuer>>> {
            let url = url.to_string();
            let snap = self.issuers.lock().unwrap().clone();
            Box::pin(async move { Ok(snap.into_iter().find(|i| i.issuer_url == url)) })
        }

        fn upsert(
            &self,
            _issuer: &OidcIssuer,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            unimplemented!("StaticIssuerRepo::upsert — not on the validator path")
        }

        fn delete_by_name(
            &self,
            _name: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            unimplemented!("StaticIssuerRepo::delete_by_name — not on the validator path")
        }
    }

    // -- Test helpers ------------------------------------------------------

    #[derive(Serialize)]
    struct FederationTestClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        iat: i64,
        nbf: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        jti: Option<String>,
        /// Arbitrary extra claim used to test the `all_claims` round trip.
        #[serde(skip_serializing_if = "Option::is_none")]
        repository: Option<String>,
    }

    impl FederationTestClaims {
        fn defaults(iss: &str, aud: &str) -> Self {
            let now = Utc::now().timestamp();
            Self {
                iss: iss.into(),
                sub: "workload-abc".into(),
                aud: aud.into(),
                exp: now + 300,
                iat: now - 10,
                nbf: now - 10,
                jti: Some("test-jti-1".into()),
                repository: Some("org/repo".into()),
            }
        }
    }

    fn sign_rs256<T: Serialize>(claims: &T, kid: &str, pem: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("valid rsa pem");
        encode(&header, claims, &key).expect("signing succeeds")
    }

    fn sign_hs256<T: Serialize>(claims: &T, kid: &str, secret: &str) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.into());
        let key = EncodingKey::from_secret(secret.as_bytes());
        encode(&header, claims, &key).expect("signing succeeds")
    }

    fn jwks_body() -> serde_json::Value {
        json!({
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": DEFAULT_KID,
                    "n": TEST_N,
                    "e": TEST_E,
                }
            ]
        })
    }

    /// Stand up a wiremock server pretending to be an OIDC IdP. Returns
    /// the mock + the issuer URL.
    async fn start_fed_idp() -> (MockServer, String) {
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
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
            .mount(&server)
            .await;
        (server, base)
    }

    fn issuer(name: &str, url: &str, audiences: Vec<&str>, algs: Vec<JwtAlg>) -> OidcIssuer {
        OidcIssuer {
            id: Uuid::nil(),
            name: name.into(),
            issuer_url: url.into(),
            audiences: audiences.into_iter().map(String::from).collect(),
            jwks_refresh_interval: Duration::from_secs(3600),
            allowed_algorithms: algs,
            require_jti: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn validator(repo: Arc<StaticIssuerRepo>) -> MultiIssuerJwksValidator {
        MultiIssuerJwksValidator::new(repo, None).expect("validator builds")
    }

    // -- Happy path --------------------------------------------------------

    #[tokio::test]
    async fn validate_happy_path_returns_validated_claims() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss.clone()]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults(&base, "hort-server");
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let out = v.validate_impl(&token).await.expect("must validate");
        assert_eq!(out.issuer, base);
        assert_eq!(out.issuer_name, "test-idp");
        assert_eq!(out.subject, "workload-abc");
        assert_eq!(out.audience, "hort-server");
        assert_eq!(out.jti.as_deref(), Some("test-jti-1"));
        // `repository` extra claim is reachable via `all_claims`
        assert_eq!(
            out.all_claims.get("repository"),
            Some(&serde_json::Value::String("org/repo".into()))
        );
        // `expires_at` matches `exp` claim within 1 s
        let delta = (out.expires_at.timestamp() - claims.exp).abs();
        assert!(
            delta < 2,
            "expected expires_at within 1s of exp; delta={delta}"
        );
        // The raw `iat`/`exp` NumericDate values are surfaced for the
        // composite replay key, verbatim from the decoded payload (no
        // re-parse).
        assert_eq!(
            out.exp_raw, claims.exp,
            "exp_raw must be the raw wire NumericDate, not a re-derived value"
        );
        assert_eq!(
            out.iat,
            Some(claims.iat),
            "iat must be surfaced raw for the composite replay key"
        );
    }

    /// Regression: `all_claims` must contain every claim from the JWT
    /// payload, INCLUDING `sub`, `aud`, `exp`, `jti` (which the
    /// validator also exposes via typed accessors).
    ///
    /// The federation handler (`exchange.rs::collect_sa_matches`) walks
    /// `ValidatedClaims.all_claims.get(k)` against the
    /// `ServiceAccount.federated_identities[].claims` map. The k8s
    /// how-to documents `sub: system:serviceaccount:<ns>:<name>` as the
    /// canonical selector — so `all_claims` must include those named
    /// claims, not just the "extras".
    ///
    /// Root cause of the original failure: `RawFederationClaims` declared
    /// those four as named fields plus `#[serde(flatten)] all_claims:
    /// BTreeMap<...>` — standard serde semantics mean the flattened map
    /// only captures fields NOT consumed by named ones, so
    /// `all_claims.get("sub")` returned `None` and every k8s-style
    /// federated identity got a silent `no_sa_match` deny.
    ///
    /// This test exercises the REAL deserialiser (existing tests bypass
    /// it: the `validate_happy_path` test only asserts on `repository`
    /// (a non-named claim); the handler-level tests use a hand-fabricated
    /// `MockFederatedJwtValidator` that puts the named claims into
    /// `all_claims` itself).
    #[tokio::test]
    async fn validated_claims_all_claims_contains_named_jwt_fields_regression_b1() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        // Use the documented k8s shape so the regression is obvious:
        // `sub: system:serviceaccount:<ns>:<name>`. See
        // `docs/architecture/how-to/federate-k8s-workload-identity.md`.
        let mut claims = FederationTestClaims::defaults(&base, "hort-server");
        claims.sub = "system:serviceaccount:ci-system:ci-pypi-pusher".into();
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let out = v.validate_impl(&token).await.expect("must validate");

        // The four named JWT fields MUST be reachable via `all_claims`
        // so the federation handler's `collect_sa_matches` works.
        assert_eq!(
            out.all_claims.get("sub"),
            Some(&serde_json::Value::String(
                "system:serviceaccount:ci-system:ci-pypi-pusher".into()
            )),
            "all_claims must carry `sub` (the canonical k8s SA selector); \
             without this, every k8s-style federated identity gets a \
             silent no_sa_match deny"
        );
        assert_eq!(
            out.all_claims.get("aud"),
            Some(&serde_json::Value::String("hort-server".into())),
            "all_claims must carry `aud` so identities can pin the audience"
        );
        // `exp` is an integer claim; check presence + numeric value.
        let exp_value = out
            .all_claims
            .get("exp")
            .expect("all_claims must carry `exp`");
        assert_eq!(
            exp_value.as_i64(),
            Some(claims.exp),
            "all_claims `exp` must round-trip the integer value"
        );
        assert_eq!(
            out.all_claims.get("jti"),
            Some(&serde_json::Value::String("test-jti-1".into())),
            "all_claims must carry `jti` even though it has a typed accessor"
        );

        // And the non-named extras must still be there (existing behaviour
        // must not regress).
        assert_eq!(
            out.all_claims.get("repository"),
            Some(&serde_json::Value::String("org/repo".into())),
            "extra (non-named) claims must continue to flow through"
        );
        // `iss` was in the payload too — it must round-trip as well.
        assert_eq!(
            out.all_claims.get("iss"),
            Some(&serde_json::Value::String(base.clone())),
            "all_claims must carry `iss` (the payload's issuer URL)"
        );

        // Typed accessors still return the right values — this is the
        // half of the contract that did NOT regress, but assert it so a
        // future refactor cannot quietly drop one of them.
        assert_eq!(
            out.subject,
            "system:serviceaccount:ci-system:ci-pypi-pusher"
        );
        assert_eq!(out.audience, "hort-server");
        assert_eq!(out.jti.as_deref(), Some("test-jti-1"));
    }

    // -- Each FederationDenyReason variant ---------------------------------

    #[tokio::test]
    async fn validate_invalid_format_on_garbage_input() {
        let repo = StaticIssuerRepo::new(vec![]);
        let v = validator(repo);
        let err = v.validate_impl("not-a-jwt").await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::InvalidFormat);
    }

    #[tokio::test]
    async fn validate_invalid_format_when_payload_lacks_iss() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        // Build a JWT whose payload has no `iss` claim.
        #[derive(Serialize)]
        struct NoIssClaims {
            sub: String,
            aud: String,
            exp: i64,
        }
        let claims = NoIssClaims {
            sub: "x".into(),
            aud: "hort-server".into(),
            exp: Utc::now().timestamp() + 300,
        };
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::InvalidFormat);
    }

    #[tokio::test]
    async fn validate_unknown_issuer_when_iss_not_trusted() {
        // No trusted issuers configured.
        let repo = StaticIssuerRepo::new(vec![]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults("https://unknown.example/", "hort-server");
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::UnknownIssuer);
    }

    #[tokio::test]
    async fn validate_algorithm_not_allowed_blocks_hs256_before_signature() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        // Sign with HS256 against an issuer whose allowed_algorithms = [RS256].
        let claims = FederationTestClaims::defaults(&base, "hort-server");
        let token = sign_hs256(&claims, DEFAULT_KID, "totally-not-the-rsa-key");

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::AlgorithmNotAllowed);
    }

    #[tokio::test]
    async fn validate_unknown_kid_when_jwks_lacks_signing_key() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults(&base, "hort-server");
        // JWKS endpoint serves DEFAULT_KID; token presents a different kid.
        let token = sign_rs256(&claims, "wrong-kid", TEST_PRIV_PEM);

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::UnknownKid);
    }

    /// Multi-issuer path: a discovery document whose `jwks_uri` points
    /// OFF the issuer host is rejected by
    /// `internal::check_jwks_uri_bound` BEFORE the JWKS fetch, with the
    /// existing federation JWKS-fetch deny classification (`UnknownKid`).
    ///
    /// **Guard isolation** (mirrors the single-issuer same-host test): the
    /// off-host JWKS server (server B) serves a VALID JWKS, so an absent
    /// guard would fetch off-origin and validation would SUCCEED. The
    /// issuer is addressed via the `localhost` name and the `jwks_uri`
    /// via the `127.0.0.1` literal — different host strings, same
    /// loopback machine. Server B's mock asserts ZERO hits, proving the
    /// guard short-circuits before the fetch.
    #[tokio::test]
    async fn validate_rejects_off_host_jwks_uri_f48() {
        // Server B — off-host JWKS endpoint, serves VALID keys, must be
        // hit zero times.
        let jwks_server = MockServer::start().await;
        let jwks_port = jwks_server.address().port();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
            .expect(0)
            .mount(&jwks_server)
            .await;

        // Server A — issuer / discovery, addressed by the `localhost`
        // name (a different host string from the `127.0.0.1` literal
        // used for the jwks_uri).
        let disco_server = MockServer::start().await;
        let issuer_url = format!("http://localhost:{}", disco_server.address().port());
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer_url,
                "jwks_uri": format!("http://127.0.0.1:{jwks_port}/jwks"),
            })))
            .mount(&disco_server)
            .await;

        let iss = issuer(
            "test-idp",
            &issuer_url,
            vec!["hort-server"],
            vec![JwtAlg::Rs256],
        );
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults(&issuer_url, "hort-server");
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let err = v
            .validate_impl(&token)
            .await
            .expect_err("off-host jwks_uri must be denied even when it serves valid keys");
        assert_eq!(
            err,
            FederationDenyReason::UnknownKid,
            "off-host jwks_uri rejection must reuse the existing federation \
             JWKS-fetch deny classification, not a new variant"
        );
        // The `.expect(0)` on the jwks mock is verified on drop: the
        // guard short-circuited before any request reached server B.
    }

    #[tokio::test]
    async fn validate_signature_invalid_when_signed_by_wrong_key() {
        // Different RSA key — sign the token with a non-test key.
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
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults(&base, "hort-server");
        // JWKS still presents TEST_N; token signed by OTHER key.
        let token = sign_rs256(&claims, DEFAULT_KID, OTHER_PRIV_PEM);

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::SignatureInvalid);
    }

    #[tokio::test]
    async fn validate_aud_mismatch_when_aud_not_in_issuer_audiences() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["bar"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults(&base, "foo");
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::AudMismatch);
    }

    #[tokio::test]
    async fn validate_aud_array_intersect_succeeds() {
        // RFC 7519 §4.1.3: aud may be an array.
        let (_server, base) = start_fed_idp().await;
        let iss = issuer(
            "test-idp",
            &base,
            vec!["hort-server", "secondary"],
            vec![JwtAlg::Rs256],
        );
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        #[derive(Serialize)]
        struct MultiAud {
            iss: String,
            sub: String,
            aud: Vec<String>,
            exp: i64,
            iat: i64,
            nbf: i64,
        }
        let now = Utc::now().timestamp();
        let claims = MultiAud {
            iss: base.clone(),
            sub: "workload-abc".into(),
            aud: vec!["other".into(), "secondary".into()],
            exp: now + 300,
            iat: now - 10,
            nbf: now - 10,
        };
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let out = v.validate_impl(&token).await.expect("array-aud must match");
        assert_eq!(out.audience, "secondary");
    }

    #[tokio::test]
    async fn validate_expired_when_exp_in_the_past() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let now = Utc::now().timestamp();
        let mut claims = FederationTestClaims::defaults(&base, "hort-server");
        claims.exp = now - 3600;
        claims.iat = now - 3700;
        claims.nbf = now - 3700;
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::Expired);
    }

    #[tokio::test]
    async fn validate_not_yet_valid_when_nbf_in_the_future() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let now = Utc::now().timestamp();
        let mut claims = FederationTestClaims::defaults(&base, "hort-server");
        // 30-min in the future, well beyond the 30 s leeway.
        claims.nbf = now + 1800;
        claims.iat = now + 1800;
        claims.exp = now + 3600;
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::NotYetValid);
    }

    // -- Cache behaviours --------------------------------------------------

    /// Refresh-when-stale: refresh_interval = 100 ms, sleep 200 ms,
    /// verify a SECOND JWKS fetch happens.
    #[tokio::test]
    async fn cache_refreshes_after_jwks_refresh_interval() {
        // Hand-rolled mock server so we can count requests.
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
        // Single JWKS mock — wiremock records every match; we read the
        // recorded count below.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
            .mount(&server)
            .await;

        let mut iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        iss.jwks_refresh_interval = Duration::from_millis(100);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults(&base, "hort-server");
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let _ = v.validate_impl(&token).await.expect("first call ok");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = v.validate_impl(&token).await.expect("second call ok");

        let jwks_hits = server
            .received_requests()
            .await
            .expect("recorded requests available")
            .into_iter()
            .filter(|r| r.url.path() == "/jwks")
            .count();
        assert_eq!(jwks_hits, 2, "stale cache must trigger a second JWKS fetch");
    }

    /// Reuse-when-fresh: two `validate()` calls within
    /// `jwks_refresh_interval` produce exactly ONE JWKS fetch.
    #[tokio::test]
    async fn cache_reuses_within_jwks_refresh_interval() {
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
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
            .mount(&server)
            .await;

        let mut iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        iss.jwks_refresh_interval = Duration::from_secs(3600);
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults(&base, "hort-server");
        let token = sign_rs256(&claims, DEFAULT_KID, TEST_PRIV_PEM);

        let _ = v.validate_impl(&token).await.expect("first call ok");
        let _ = v.validate_impl(&token).await.expect("second call ok");

        let jwks_hits = server
            .received_requests()
            .await
            .expect("recorded requests available")
            .into_iter()
            .filter(|r| r.url.path() == "/jwks")
            .count();
        assert_eq!(jwks_hits, 1, "fresh cache must not re-fetch JWKS");
    }

    // -- Algorithm gate ordering -------------------------------------------

    #[tokio::test]
    async fn algorithm_gate_fires_before_signature_work_when_idp_unreachable() {
        // No JWKS server stood up at all — the algorithm gate must
        // refuse the JWT BEFORE the validator tries to fetch the
        // JWKS, otherwise this test would hang on the reqwest timeout.
        let iss = issuer(
            "test-idp",
            "http://127.0.0.1:1/",
            vec!["hort-server"],
            vec![JwtAlg::Rs256],
        );
        let repo = StaticIssuerRepo::new(vec![iss]);
        let v = validator(repo);

        let claims = FederationTestClaims::defaults("http://127.0.0.1:1/", "hort-server");
        let token = sign_hs256(&claims, DEFAULT_KID, "wrong-symmetric-secret");

        let err = v.validate_impl(&token).await.expect_err("must deny");
        assert_eq!(err, FederationDenyReason::AlgorithmNotAllowed);
    }

    // -- Helper unit tests -------------------------------------------------

    #[test]
    fn is_stale_returns_false_within_interval() {
        let entry = JwksCacheEntry {
            keys: HashMap::new(),
            last_refreshed: Utc::now(),
        };
        assert!(!is_stale(&entry, Duration::from_secs(3600)));
    }

    #[test]
    fn is_stale_returns_true_after_interval() {
        let entry = JwksCacheEntry {
            keys: HashMap::new(),
            last_refreshed: Utc::now() - chrono::Duration::seconds(5),
        };
        assert!(is_stale(&entry, Duration::from_secs(1)));
    }

    #[test]
    fn is_stale_returns_false_on_clock_skew_backwards() {
        // Wall clock jumped backwards — entry timestamp is "in the
        // future" relative to now. Treat as fresh, not stale.
        let entry = JwksCacheEntry {
            keys: HashMap::new(),
            last_refreshed: Utc::now() + chrono::Duration::seconds(60),
        };
        assert!(!is_stale(&entry, Duration::from_secs(10)));
    }

    #[test]
    fn algorithm_allowed_matches_each_pair() {
        for (domain, wire) in [
            (JwtAlg::Rs256, Algorithm::RS256),
            (JwtAlg::Rs384, Algorithm::RS384),
            (JwtAlg::Rs512, Algorithm::RS512),
            (JwtAlg::Es256, Algorithm::ES256),
            (JwtAlg::Es384, Algorithm::ES384),
        ] {
            assert!(algorithm_allowed(wire, &[domain]));
        }
    }

    #[test]
    fn algorithm_allowed_es512_has_no_jsonwebtoken_match() {
        // `Algorithm::ES512` does not exist in jsonwebtoken 10.x —
        // operators may declare `JwtAlg::Es512` but no incoming JWT
        // can match it. Document this gap explicitly so a future
        // jsonwebtoken upgrade that adds `ES512` produces a test
        // failure here, forcing the match arm to be added.
        for wire in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::ES256,
            Algorithm::ES384,
        ] {
            assert!(
                !algorithm_allowed(wire, &[JwtAlg::Es512]),
                "JwtAlg::Es512 must not match any wire algorithm currently \
                 exposed by jsonwebtoken — promoting ES512 requires extending \
                 jwt_alg_matches_algorithm"
            );
        }
    }

    #[test]
    fn algorithm_allowed_rejects_unallowed() {
        // Allowed = [RS256]; HS256 is not in the JwtAlg enum at all, so
        // even if an attacker writes HS256 into the header, the match
        // arm returns false. Belt-and-braces against accidental enum
        // additions.
        assert!(!algorithm_allowed(Algorithm::HS256, &[JwtAlg::Rs256]));
    }

    #[test]
    fn algorithm_allowed_empty_list_rejects_everything() {
        assert!(!algorithm_allowed(Algorithm::RS256, &[]));
    }

    #[test]
    fn match_audience_single_intersects() {
        let aud = AudClaim::Single("hort-server".into());
        let allowed = vec!["other".into(), "hort-server".into()];
        assert_eq!(match_audience(&aud, &allowed), Some("hort-server".into()));
    }

    #[test]
    fn match_audience_multi_intersects() {
        let aud = AudClaim::Multi(vec!["a".into(), "b".into()]);
        let allowed = vec!["c".into(), "b".into()];
        assert_eq!(match_audience(&aud, &allowed), Some("b".into()));
    }

    #[test]
    fn match_audience_no_intersection_returns_none() {
        let aud = AudClaim::Single("x".into());
        let allowed = vec!["y".into()];
        assert_eq!(match_audience(&aud, &allowed), None);
    }

    #[test]
    fn match_audience_absent_returns_none() {
        assert_eq!(match_audience(&AudClaim::Absent, &["x".to_string()]), None);
    }

    #[test]
    fn classify_federation_jwt_error_covers_expected_kinds() {
        use jsonwebtoken::errors::{Error, ErrorKind};
        // The kinds we care about all map to the documented variants.
        let cases = [
            (
                ErrorKind::InvalidSignature,
                FederationDenyReason::SignatureInvalid,
            ),
            (ErrorKind::ExpiredSignature, FederationDenyReason::Expired),
            (
                ErrorKind::ImmatureSignature,
                FederationDenyReason::NotYetValid,
            ),
            (
                ErrorKind::InvalidIssuer,
                FederationDenyReason::UnknownIssuer,
            ),
            (
                ErrorKind::InvalidAudience,
                FederationDenyReason::AudMismatch,
            ),
            (
                ErrorKind::InvalidAlgorithm,
                FederationDenyReason::AlgorithmNotAllowed,
            ),
            (ErrorKind::InvalidToken, FederationDenyReason::InvalidFormat),
        ];
        for (kind, expected) in cases {
            let err = Error::from(kind);
            assert_eq!(classify_federation_jwt_error(&err), expected);
        }
    }

    #[test]
    fn classify_federation_jwt_error_missing_required_claim_is_invalid_format() {
        use jsonwebtoken::errors::{Error, ErrorKind};
        let err = Error::from(ErrorKind::MissingRequiredClaim("exp".into()));
        assert_eq!(
            classify_federation_jwt_error(&err),
            FederationDenyReason::InvalidFormat
        );
    }

    #[test]
    fn extract_payload_claims_rejects_malformed_jwt() {
        assert_eq!(
            extract_payload_claims("not-a-jwt").unwrap_err(),
            FederationDenyReason::InvalidFormat
        );
        assert_eq!(
            extract_payload_claims("a.b").unwrap_err(),
            FederationDenyReason::InvalidFormat
        );
        assert_eq!(
            extract_payload_claims("a.b.c.d").unwrap_err(),
            FederationDenyReason::InvalidFormat
        );
    }

    #[test]
    fn extract_payload_claims_rejects_bad_base64() {
        // Header valid, payload not valid base64url, signature absent → 3
        // parts but middle won't decode.
        let bad = "eyJhbGciOiJSUzI1NiJ9.!!!!.sig";
        assert_eq!(
            extract_payload_claims(bad).unwrap_err(),
            FederationDenyReason::InvalidFormat
        );
    }

    // =================================================================
    // Apply-time JWKS warm-up unit tests for
    // `MultiIssuerJwksValidator::refresh_issuer_impl`.
    //
    // The contract (per `FederatedJwtValidator::refresh_issuer` doc):
    // - On success, populate the cache so a subsequent `validate()`
    //   skips the discovery + JWKS round trip.
    // - On failure (network / body cap / parse error), return `Err` and
    //   emit `hort_jwks_refresh_total{result="apply_warmup_failed"}`.
    //   Granular fetch_failed / body_too_large / parse_error variants
    //   are NOT emitted from this path — operator dashboards distinguish
    //   apply-time warm-up failures from runtime serving failures.
    // =================================================================

    /// Warm-up happy path: a healthy IdP response populates the cache,
    /// and a subsequent `validate()` succeeds without re-fetching.
    #[tokio::test]
    async fn refresh_issuer_populates_cache_on_success() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss.clone()]);
        let v = validator(repo);

        // Cache is empty pre-warm-up.
        assert!(
            v.caches.read().await.is_empty(),
            "cache must be empty before warm-up"
        );

        // Warm-up succeeds.
        v.refresh_issuer_impl(&iss)
            .await
            .expect("warm-up against healthy IdP must succeed");

        // Cache is populated for the issuer name (the key the cache
        // uses internally).
        let cache_guard = v.caches.read().await;
        let entry = cache_guard
            .get(&iss.name)
            .expect("cache entry must exist for warmed issuer");
        assert!(
            entry.keys.contains_key(DEFAULT_KID),
            "cached entry must carry the JWKS kid"
        );
    }

    /// Warm-up failure path: IdP discovery endpoint is unreachable.
    /// Surfaces as `Err(FederationDenyReason::UnknownKid)` per the
    /// existing fetch-failure-to-deny mapping.
    #[tokio::test]
    async fn refresh_issuer_returns_err_on_network_failure() {
        // Use a port we know nothing listens on — connection refused.
        let unreachable_base = "http://127.0.0.1:1";
        let iss = issuer(
            "test-idp",
            unreachable_base,
            vec!["hort-server"],
            vec![JwtAlg::Rs256],
        );
        let repo = StaticIssuerRepo::new(vec![iss.clone()]);
        let v = validator(repo);

        let err = v
            .refresh_issuer_impl(&iss)
            .await
            .expect_err("unreachable IdP must surface as Err");
        // The exact variant is irrelevant to callers (apply-use-case
        // treats every Err as warm-up-failed); we assert *some* deny
        // reason — the typed pipeline through `FederationDenyReason` is
        // what matters here, not which variant.
        let _ = err.as_str(); // smoke: variant has a wire-form string.
    }

    /// Warm-up failure path: IdP discovery body exceeds the cap.
    /// Surfaces as `Err` and (in production) emits
    /// `hort_jwks_refresh_total{result="apply_warmup_failed"}`.
    #[tokio::test]
    async fn refresh_issuer_returns_err_on_body_too_large() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        // Discovery body is well over the 8-byte cap below.
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base.clone(),
                "jwks_uri": format!("{base}/jwks"),
                "padding": "x".repeat(100_000),
            })))
            .mount(&server)
            .await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss.clone()]);
        let v = MultiIssuerJwksValidator::with_body_cap(repo, None, 8)
            .expect("validator with tiny cap builds");

        let err = v
            .refresh_issuer_impl(&iss)
            .await
            .expect_err("oversize body must surface as Err");
        let _ = err.as_str(); // smoke: variant has a wire-form string.
    }

    /// Warm-up failure path: discovery body is malformed JSON.
    /// Surfaces as `Err` (parse-error class) and (in production) emits
    /// `hort_jwks_refresh_total{result="apply_warmup_failed"}`.
    #[tokio::test]
    async fn refresh_issuer_returns_err_on_parse_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        // Non-JSON body; well within the default cap, but cannot parse.
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<<not-json>>"))
            .mount(&server)
            .await;

        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss.clone()]);
        let v = validator(repo);

        let err = v
            .refresh_issuer_impl(&iss)
            .await
            .expect_err("malformed discovery JSON must surface as Err");
        let _ = err.as_str();
    }

    /// Trait-method smoke: the `FederatedJwtValidator::refresh_issuer`
    /// trait dispatch produces the same outcome as the direct impl.
    /// Pins the dyn-dispatch contract for the apply-use-case call
    /// site, which holds an `Arc<dyn FederatedJwtValidator>`.
    #[tokio::test]
    async fn refresh_issuer_trait_dispatch_matches_impl() {
        let (_server, base) = start_fed_idp().await;
        let iss = issuer("test-idp", &base, vec!["hort-server"], vec![JwtAlg::Rs256]);
        let repo = StaticIssuerRepo::new(vec![iss.clone()]);
        let v: Arc<dyn FederatedJwtValidator> = Arc::new(validator(repo));

        v.refresh_issuer(&iss)
            .await
            .expect("trait dispatch must succeed against healthy IdP");
    }
}
