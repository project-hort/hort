//! PAT (native API token) validation orchestration.
//!
//! This
//! module turns a `Bearer hort_<kind>_<body>` plaintext into an
//! [`ApiTokenValidation`] payload (or a typed [`PatValidationError`])
//! by sequencing:
//!
//! 1. **Brute-force lockout** — `EphemeralStore` flag at
//!    `pat-attempt:{client_ip_bucket}` is consulted *first* so a
//!    locked-out request short-circuits with `RateLimited` BEFORE any
//!    Argon2 verify (the
//!    `pat-attempt:` prefix is distinct from the password-login
//!    `auth:lockout:by_ip:` so PAT floods cannot lock out password
//!    logins from the same `/24`, and vice-versa).
//! 2. **Cache lookup** — [`PatCache::get`] hit + non-revoked +
//!    non-expired + user not deactivated → return the cached
//!    `ApiTokenValidation`. NO Argon2 call on the hit path.
//! 3. **Cache miss path:**
//!    a. Parse the token format (`^hort_(pat|svc|cli)_[a-z2-7]{32}$`). On
//!    parse failure, route to the sentinel-verify branch so a
//!    prefix-shape bug and a prefix-not-found cost the same.
//!    b. Extract the 8-char body prefix (chars 7..15 of the full
//!    plaintext when the kind is one of the three known prefixes —
//!    `hort_pat_` / `hort_svc_` / `hort_cli_` are all 7 bytes).
//!    c. `ApiTokenRepository::find_by_prefix` to fetch the row (or
//!    `None` on miss).
//!    d. ALWAYS call Argon2 verify exactly ONCE — with the looked-up
//!    hash on prefix-found, with the precomputed
//!    [`crate::argon2_hash::sentinel_hash`] on prefix-not-found.
//!    This is design doc §8 invariant 1 and the architect's
//!    constant-time-on-prefix-not-found rule.
//!    e. After verify: classify (`PrefixNotFound`, `HashMismatch`),
//!    then check `expires_at`, `revoked_at`, `user.is_active` in that
//!    order, each with its own [`PatValidationError`] variant on miss.
//!    f. All checks pass → cache the validation and return success.
//! 4. **Lockout bookkeeping** — every NON-`Success` outcome increments
//!    the counter at `pat-attempt-counter:{bucket}`; once the counter
//!    crosses [`PatLockoutConfig::threshold`] within
//!    [`PatLockoutConfig::window`], the flag at
//!    `pat-attempt:{bucket}` is set with TTL =
//!    [`PatLockoutConfig::duration`].
//! 5. **Metric emission** is the LAST step before returning on EVERY
//!    code path (cache hit, lockout short-circuit, every miss-path
//!    outcome). Per design doc §9 ("Metric-emission timing vs
//!    constant-time invariant") the increment must come *after* the
//!    Argon2 verify on the miss path so the counter call itself
//!    cannot become a covert timing oracle.
//!
//! # Scope of B5b
//!
//! B5b emits an [`ApiTokenValidation`] only. Building the
//! [`hort_domain::entities::caller::CallerPrincipal`] (with role
//! re-resolution per design §5 step 3) and integrating with the auth
//! middleware happens in B5c. This module deliberately stops at the
//! validation payload so the validator can be unit-tested in isolation
//! against the counter spy + metric spy harness.
//!
//! # What is NOT here
//!
//! - Plaintext-PAT-over-HTTP refusal (design §8 invariant 10) — that
//!   is a middleware concern (B5c).
//! - PgListener wiring of `ApiTokenCacheInvalidator` (B5c).
//! - `last_used_at` debounced bookkeeping — the fire-and-forget update
//!   spawn lives at the middleware boundary (B5c) so the validator
//!   stays free of `tokio::spawn` and side effects beyond the cache
//!   write.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest, Sha256};

use uuid::Uuid;

use hort_domain::entities::api_token::{TokenCap, TokenKind};
use hort_domain::error::DomainError;
use hort_domain::events::{system_actor, ApiTokenUsed, DomainEvent, StreamId};
use hort_domain::ports::api_token_repository::ApiTokenRepository;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::user_repository::UserRepository;

use crate::argon2_hash::{sentinel_hash, Argon2Verifier, DefaultArgon2Verifier};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    client_ip_bucket, emit_api_token_used_audit_dropped, labels, ApiTokenUsedAuditDropResult,
};
use crate::use_cases::pat_cache::{ApiTokenValidation, CacheKey, Clock, PatCache};

// ---------------------------------------------------------------------------
// Lockout key prefixes (design doc §5)
// ---------------------------------------------------------------------------

/// Per-IP active-lockout flag prefix. Full key:
/// `pat-attempt:{client_ip_bucket}` where `client_ip_bucket` is the
/// bucketed source IP (`/24` IPv4, `/48` IPv6 — see
/// [`crate::metrics::client_ip_bucket`]).
///
/// **Distinct from the password-login `auth:lockout:by_ip:`**:
/// PAT floods must not lock out password logins from the same `/24`
/// and vice-versa — the two attack shapes have different attacker
/// profiles (a credential-stuffing campaign against the local-auth
/// path is unrelated to a token-prefix probe campaign), and sharing
/// the keyspace would let either signal mask the other.
pub const PAT_LOCKOUT_BY_IP_FLAG_PREFIX: &str = "pat-attempt:";

/// Per-IP failed-attempt counter prefix. Full key:
/// `pat-attempt-counter:{client_ip_bucket}`. Sibling to
/// [`PAT_LOCKOUT_BY_IP_FLAG_PREFIX`]; distinct so a `client_ip_bucket`
/// value cannot collide between the flag and counter namespaces.
pub const PAT_LOCKOUT_BY_IP_COUNTER_PREFIX: &str = "pat-attempt-counter:";

// ---------------------------------------------------------------------------
// Token-use audit throttle
// ---------------------------------------------------------------------------

/// Per-`token_id` token-use audit-event throttle key prefix. Full key:
/// `token_use:audit:throttle:{token_id}`.
///
/// **Distinct prefix** from the `pat-attempt:` lockout keyspace and
/// from the `auth:event:throttle:` keyspace — the three throttle
/// concerns must not alias. Keyed per-`token_id` (a server-controlled,
/// bounded value — NOT attacker-supplied), so an attacker cannot mint
/// arbitrary keys per request and exhaust ephemeral memory; mirrors
/// the bounded-keyspace property of the bucketed-IP throttle key.
const TOKEN_USE_AUDIT_THROTTLE_PREFIX: &str = "token_use:audit:throttle:";

/// Window-size for the per-`token_id` token-use audit-event throttle
/// (1 hour). The first successful validation of a token
/// within a 1-hour window appends one [`ApiTokenUsed`]; the rest tick
/// `hort_api_token_used_audit_dropped{result="throttled"}` and append
/// nothing. A hot CI token used thousands of times per hour therefore
/// produces one audit event per hour, not one per request — the
/// throttle is the volume control (contrast the download-audit
/// opt-in flag).
const TOKEN_USE_AUDIT_THROTTLE_TTL: Duration = Duration::from_secs(3600);

/// Token-use audit-emit gate.
///
/// `PatValidationUseCase` holds an `Option<ApiTokenUsedGate>` so
/// legacy / test deployments that wire no event store keep working
/// with the audit-emit logic short-circuited — the same
/// optional-builder shape as `ArtifactUseCase`'s
/// `DownloadAuditGate` / `with_audit_events`. The throttle reuses the
/// `EphemeralStore` handle the use case already holds (no second
/// store handle); only the publisher is held here.
struct ApiTokenUsedGate {
    events: Arc<EventStorePublisher>,
}

// ---------------------------------------------------------------------------
// PatLockoutConfig
// ---------------------------------------------------------------------------

/// Brute-force lockout policy for the PAT validator.
///
/// Defaults: **30 misses / 5 min triggers a 15-min
/// lockout**. Argon2id at OWASP-2024 cost is ~50–80 ms per verify, so
/// an attacker botnet of N IPs × 60/min through `tower_governor`
/// would otherwise pin N×80 CPU-cores at no auth cost — this
/// gate caps the verify rate per IP-bucket regardless of where the
/// global rate-limiter is.
///
/// Window-anchored at first failure (no TTL extension on subsequent
/// failures, mirroring the password-login `LockoutConfig`); a paced
/// attacker staying just under threshold per window is throttled
/// rather than locked. The composition root reads operator
/// overrides from `HORT_PAT_LOCKOUT_*` env vars; that wiring is out of
/// scope for B5b.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatLockoutConfig {
    /// Number of failed PAT validations within `window` from one
    /// `client_ip_bucket` that trips the lockout. Default `30`.
    pub threshold: u32,
    /// Sliding window for the failed-attempt counter. Default `5 min`
    /// (300s). Counter is created with this TTL on the first failure
    /// of a streak.
    pub window: Duration,
    /// How long the lockout flag stays in effect after `threshold`
    /// trips. Default `15 min` (900s). During the lockout, every
    /// validation fast-fails with `RateLimited` and zero Argon2 calls.
    pub duration: Duration,
}

impl PatLockoutConfig {
    /// Design-doc default: 30 misses / 5-min window / 15-min lockout.
    pub const DEFAULT: Self = Self {
        threshold: 30,
        window: Duration::from_secs(300),
        duration: Duration::from_secs(900),
    };
}

impl Default for PatLockoutConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ---------------------------------------------------------------------------
// PatValidationError
// ---------------------------------------------------------------------------

/// Outcome enum for a single PAT validation attempt.
///
/// Each variant maps 1:1 to a `result` label on
/// `hort_api_token_validation_total` (design doc §9). The middleware in
/// B5c projects every variant — except `Infrastructure` — to a `401`
/// response; `Infrastructure` propagates as `500`.
#[derive(Debug, thiserror::Error)]
pub enum PatValidationError {
    /// Per-IP brute-force lockout flag was set; Argon2 verify was NOT
    /// called. Maps to `result="rate_limited", cache="miss"` per
    /// design doc §9 — the catalog explicitly notes lockout decisions
    /// use `cache="miss"` since they never come from the validation
    /// cache.
    #[error("rate limited")]
    RateLimited,
    /// Argon2 verify ran (against the sentinel hash) and returned
    /// false because no row matched the body prefix. Indistinguishable
    /// in wall time from [`Self::HashMismatch`] (the verify ran
    /// either way) and in metric label only via the bounded enum here.
    #[error("token prefix not found")]
    PrefixNotFound,
    /// Argon2 verify ran (against the looked-up row's hash) and
    /// returned false. Distinct from [`Self::PrefixNotFound`] only at
    /// the metric / tracing layer; both surface as the same generic
    /// 401 to the caller.
    #[error("token hash mismatch")]
    HashMismatch,
    /// `expires_at < now`. Returned BEFORE the cache write so an
    /// expired token never lands in the cache.
    #[error("token expired")]
    Expired,
    /// `revoked_at` is set. Same caching-discipline note as `Expired`.
    #[error("token revoked")]
    Revoked,
    /// `users.is_active = false`. Same caching-discipline note.
    #[error("user deactivated")]
    UserDeactivated,
    /// Database / ephemeral-store / repository error. Wraps a
    /// [`DomainError`] verbatim; B5c maps this to the existing
    /// `AppError::Domain` envelope at the middleware boundary.
    #[error("infrastructure error: {0}")]
    Infrastructure(#[from] DomainError),
}

// ---------------------------------------------------------------------------
// PatValidationUseCase
// ---------------------------------------------------------------------------

/// Application-layer orchestrator for the PAT validation hot path.
///
/// Holds `Arc<dyn …>` handles for every outbound port it consumes plus
/// the in-process [`PatCache`] (concrete `Arc<PatCache>` because the
/// cache is owned by `hort-app` and the validator is the only writer
/// — a `dyn` cache port would only buy us decoupling we don't need).
/// `Arc<dyn Argon2Verifier>` is the swap-point that lets B5b's tests
/// substitute a counter spy without forcing the production verifier
/// to run during unit tests.
pub struct PatValidationUseCase {
    tokens: Arc<dyn ApiTokenRepository>,
    users: Arc<dyn UserRepository>,
    ephemeral: Arc<dyn EphemeralStore>,
    cache: Arc<PatCache>,
    verifier: Arc<dyn Argon2Verifier>,
    clock: Arc<dyn Clock>,
    config: PatLockoutConfig,
    /// Throttled per-use token-use
    /// audit-emit gate. `None` when unwired (legacy / test
    /// deployments) — the emit logic short-circuits. Wired via
    /// [`Self::with_audit_events`] (production composition root only).
    audit_events: Option<ApiTokenUsedGate>,
}

impl PatValidationUseCase {
    /// Production constructor — wires [`DefaultArgon2Verifier`] for
    /// the verifier.
    pub fn new(
        tokens: Arc<dyn ApiTokenRepository>,
        users: Arc<dyn UserRepository>,
        ephemeral: Arc<dyn EphemeralStore>,
        cache: Arc<PatCache>,
        clock: Arc<dyn Clock>,
        config: PatLockoutConfig,
    ) -> Self {
        Self {
            tokens,
            users,
            ephemeral,
            cache,
            verifier: Arc::new(DefaultArgon2Verifier),
            clock,
            config,
            audit_events: None,
        }
    }

    /// Test constructor — accepts a custom [`Argon2Verifier`] so the
    /// counter-spy harness can pin "verify called exactly once /
    /// exactly zero times" on every code path.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_with_verifier(
        tokens: Arc<dyn ApiTokenRepository>,
        users: Arc<dyn UserRepository>,
        ephemeral: Arc<dyn EphemeralStore>,
        cache: Arc<PatCache>,
        verifier: Arc<dyn Argon2Verifier>,
        clock: Arc<dyn Clock>,
        config: PatLockoutConfig,
    ) -> Self {
        Self {
            tokens,
            users,
            ephemeral,
            cache,
            verifier,
            clock,
            config,
            audit_events: None,
        }
    }

    /// Enable throttled per-use token-use audit
    /// emits. Wires the [`EventStorePublisher`] handle
    /// used to `append` one [`ApiTokenUsed`] event per *successful*
    /// PAT validation that wins the per-`token_id` 1-hour throttle.
    /// Fail-open: an append or throttle-store error never blocks the
    /// validation result.
    ///
    /// Same builder shape as
    /// `ArtifactUseCase::with_audit_events` so every existing
    /// `PatValidationUseCase::new(..)` / `new_with_verifier(..)` call
    /// site stays compiling unchanged (additive `Option` field,
    /// defaulting `None` in both constructors); only the production
    /// composition root opts in.
    #[must_use]
    pub fn with_audit_events(mut self, events: Arc<EventStorePublisher>) -> Self {
        self.audit_events = Some(ApiTokenUsedGate { events });
        self
    }

    /// Validate a `Bearer` plaintext PAT against the prefix index +
    /// Argon2id hash. See the module-level docstring for the full
    /// algorithm.
    ///
    /// `client_ip` is `None` when the transport has no identifiable
    /// peer (in-process call sites). The brute-force lockout is a
    /// no-op for that case — there is no `client_ip_bucket` to key on
    /// — and validations proceed straight to the cache lookup.
    ///
    /// # Metrics
    ///
    /// This wrapper records the histogram
    /// `hort_api_token_validation_duration_seconds{result}` around the
    /// ENTIRE validation closure (not just the verify call): it
    /// includes the metric
    /// increment itself — but every code path increments exactly one
    /// counter, so the path lengths are equal. The histogram MUST
    /// observe a non-zero duration on every code path because
    /// `validate_pat_inner` performs the lockout / cache / verify /
    /// metric-increment work before returning.
    ///
    /// # Token-use audit
    ///
    /// On the success path **only** (`Ok(_)`), AND only when the audit
    /// gate is wired, a throttled best-effort [`ApiTokenUsed`] event is
    /// appended. This single site is OUTSIDE `validate_pat_inner` so it
    /// does not perturb the verify-exactly-once / constant-time
    /// counter-spy invariants (those tests exercise `validate_pat` but
    /// assert on the verifier-call count + the
    /// `hort_api_token_validation_total` metric, both produced inside
    /// `_inner` — the emit runs after the duration metric and never
    /// touches the verifier). It covers BOTH the cache-hit and
    /// cache-miss success returns, so the common cache-hit path is not
    /// an audit blind spot. A failed validation (`Err(_)`) emits
    /// nothing: a failed validation is not a *use*, and
    /// `AuthenticationAttempted` does not cover PATs — so there is no
    /// double-count and no gap. Fail-open: any throttle-store or
    /// append failure NEVER propagates to this method's `Result`.
    pub async fn validate_pat(
        &self,
        token_plaintext: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<ApiTokenValidation, PatValidationError> {
        let started_at = std::time::Instant::now();
        let result = self.validate_pat_inner(token_plaintext, client_ip).await;
        emit_validation_duration(&result, started_at.elapsed().as_secs_f64());
        if let Ok(ref v) = result {
            self.maybe_emit_token_use(v).await;
        }
        result
    }

    /// Throttled, best-effort append of one [`ApiTokenUsed`]
    /// event. No-op unless the audit gate
    /// is wired.
    ///
    /// **Throttle (1 hour).** The first successful
    /// validation of a given `token_id` within a 1-hour window wins
    /// (`put_if_absent` → `Ok(true)`); subsequent ones are suppressed
    /// (`Ok(false)`) and tick
    /// `hort_api_token_used_audit_dropped{result="throttled"}`. A
    /// throttle-store error is **fail-open**: treated as "won",
    /// appending continues, and a `warn!` surfaces for SREs (the audit
    /// trail is "as-good-as-it-can-be", not
    /// "must-succeed-before-return"; mirrors
    /// `maybe_append_auth_event`).
    ///
    /// **Append.** Per-`(token_id, UTC-date)` stream
    /// ([`StreamId::token_use`]) — NEVER the token-owner's `User`
    /// lifecycle stream (the stream-isolation property; asserted
    /// in tests). `ExpectedVersion::Any`; the batch recorder is
    /// `system_actor()` (the subject — token owner — rides the payload
    /// `user_id`). An append error is fail-open: the validation result
    /// already returned `Ok`; a `warn!` + the
    /// `result="append_error"` counter accompany the drop. A
    /// successful append produces NO metric and NO log (the auth hot
    /// path).
    async fn maybe_emit_token_use(&self, v: &ApiTokenValidation) {
        let Some(gate) = &self.audit_events else {
            return;
        };
        let throttle_key = format!("{TOKEN_USE_AUDIT_THROTTLE_PREFIX}{}", v.token_id);
        let was_first = match self
            .ephemeral
            .put_if_absent(
                &throttle_key,
                Bytes::from_static(b"1"),
                TOKEN_USE_AUDIT_THROTTLE_TTL,
            )
            .await
        {
            Ok(won) => won,
            Err(e) => {
                // Fail-open: the throttle store is operator-actionable
                // but must not block validation or silently drop the
                // audit fact. Treat as "won" and proceed to append.
                tracing::warn!(
                    error = %e,
                    "token-use audit throttle check failed; proceeding"
                );
                true
            }
        };
        if !was_first {
            emit_api_token_used_audit_dropped(ApiTokenUsedAuditDropResult::Throttled);
            tracing::debug!(
                token_id = %v.token_id,
                "token-use audit throttle engaged; suppressing append"
            );
            return;
        }
        let occurred_at = chrono::Utc::now();
        let event = ApiTokenUsed {
            token_id: v.token_id,
            user_id: v.user_id,
            kind: v.kind,
            occurred_at,
        };
        let batch = AppendEvents {
            // Per-(token_id, UTC-date) stream — NEVER the token-owner's
            // `User` lifecycle stream (the stream-isolation
            // property; asserted in tests).
            stream_id: StreamId::token_use(v.token_id, occurred_at.date_naive()),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::ApiTokenUsed(event))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            // The batch recorder is `system_actor()` (the recorder);
            // the subject — the token owner — rides the payload
            // `user_id` (same posture as B12's `system_actor()` +
            // payload `DownloadActor`).
            actor: system_actor(),
        };
        if let Err(e) = gate.events.append(batch).await {
            // Fail-open: the validation already returned `Ok`. NO
            // routine-success log on the Ok path (auth hot path);
            // only the drop path is observable.
            tracing::warn!(
                audit_write_failed = true,
                error = %e,
                token_id = %v.token_id,
                "token-use audit append failed; validation result unaffected"
            );
            emit_api_token_used_audit_dropped(ApiTokenUsedAuditDropResult::AppendError);
        }
    }

    async fn validate_pat_inner(
        &self,
        token_plaintext: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<ApiTokenValidation, PatValidationError> {
        // ----------------------------------------------------------------
        // 1. Brute-force lockout consult — BEFORE any Argon2 cost.
        // ----------------------------------------------------------------
        let lockout_keys = client_ip.map(LockoutKeys::new);
        if let Some(keys) = &lockout_keys {
            if self
                .ephemeral
                .get(&keys.flag_key)
                .await
                .map_err(PatValidationError::Infrastructure)?
                .is_some()
            {
                emit_validation_metric(ValidationMetric::RateLimited);
                return Err(PatValidationError::RateLimited);
            }
        }

        // ----------------------------------------------------------------
        // 2. Cache lookup — hit short-circuits BEFORE any Argon2 cost.
        // ----------------------------------------------------------------
        let cache_key = compute_cache_key(token_plaintext);
        if let Some(cached) = self.cache.get(&cache_key) {
            // Mid-cache-TTL freshness re-checks per design §5 step 2.
            // Negative-result paths bypass `cache.insert` so a hit here
            // means the entry was once-valid; we only need to revisit
            // expiry / revocation / deactivation in case any of them
            // flipped while the entry was warm.
            let now = self.clock.now();
            if let Some(exp) = cached.expires_at {
                if exp <= now {
                    self.bookkeep_failure(lockout_keys.as_ref()).await?;
                    emit_validation_metric(ValidationMetric::Expired);
                    return Err(PatValidationError::Expired);
                }
            }
            if cached.revoked_at.is_some() {
                self.bookkeep_failure(lockout_keys.as_ref()).await?;
                emit_validation_metric(ValidationMetric::Revoked);
                return Err(PatValidationError::Revoked);
            }
            // User-deactivation check on cache hit re-resolves the
            // user row. The LISTEN/NOTIFY path (B5c) is the fast
            // invalidator; this re-check is the fallback.
            let user = self
                .users
                .find_by_id(cached.user_id)
                .await
                .map_err(PatValidationError::Infrastructure)?;
            if !user.is_active {
                self.bookkeep_failure(lockout_keys.as_ref()).await?;
                emit_validation_metric(ValidationMetric::UserDeactivated);
                return Err(PatValidationError::UserDeactivated);
            }
            emit_validation_metric(ValidationMetric::SuccessHit);
            return Ok(cached);
        }

        // ----------------------------------------------------------------
        // 3. Cache miss — body prefix lookup + UNCONDITIONAL Argon2 verify.
        // ----------------------------------------------------------------
        let parsed = parse_pat_token_format(token_plaintext);
        // Always run exactly ONE verify call, no matter the parse
        // outcome. Routing the parse-failure shape through the
        // sentinel branch keeps the verify path-length identical with
        // prefix-not-found, so the architect's constant-time invariant
        // holds for malformed inputs too.
        let lookup = match parsed {
            Ok((_, prefix)) => self
                .tokens
                .find_by_prefix(prefix)
                .await
                .map_err(PatValidationError::Infrastructure)?,
            Err(_) => None,
        };

        let (verify_ok, found_token) = match &lookup {
            Some(token) => {
                let ok = self
                    .verifier
                    .verify(token_plaintext.as_bytes(), &token.token_hash);
                (ok, Some(token))
            }
            None => {
                // Sentinel branch: hand the verifier a known-good PHC
                // string so it does the FULL Argon2 cost. The verify
                // result is structurally false (sentinel plaintext is
                // fixed and not equal to any caller plaintext); we
                // discard it and classify as `PrefixNotFound`.
                let _ = self
                    .verifier
                    .verify(token_plaintext.as_bytes(), sentinel_hash());
                (false, None)
            }
        };

        if !verify_ok {
            // Distinguish prefix-not-found from hash-mismatch ONLY at
            // the metric / tracing layer; both surface as the same
            // generic 401 in B5c. The wall-clock cost is identical —
            // the sentinel branch above ran the same Argon2 cycles.
            self.bookkeep_failure(lockout_keys.as_ref()).await?;
            let metric = if found_token.is_some() {
                ValidationMetric::HashMismatch
            } else {
                ValidationMetric::PrefixNotFound
            };
            let err = if found_token.is_some() {
                PatValidationError::HashMismatch
            } else {
                PatValidationError::PrefixNotFound
            };
            emit_validation_metric(metric);
            return Err(err);
        }

        // ----------------------------------------------------------------
        // 4. Verify succeeded — apply expires/revoked/deactivation in
        //    that order. Each is its own variant on miss.
        // ----------------------------------------------------------------
        let token = found_token.expect("verify_ok ⇒ lookup matched");
        let now = self.clock.now();
        if let Some(exp) = token.expires_at {
            if exp <= now {
                self.bookkeep_failure(lockout_keys.as_ref()).await?;
                emit_validation_metric(ValidationMetric::Expired);
                return Err(PatValidationError::Expired);
            }
        }
        if token.revoked_at.is_some() {
            self.bookkeep_failure(lockout_keys.as_ref()).await?;
            emit_validation_metric(ValidationMetric::Revoked);
            return Err(PatValidationError::Revoked);
        }
        let user = self
            .users
            .find_by_id(token.user_id)
            .await
            .map_err(PatValidationError::Infrastructure)?;
        if !user.is_active {
            self.bookkeep_failure(lockout_keys.as_ref()).await?;
            emit_validation_metric(ValidationMetric::UserDeactivated);
            return Err(PatValidationError::UserDeactivated);
        }

        // ----------------------------------------------------------------
        // 5. All checks pass — cache the validation, increment success
        //    counter, return.
        // ----------------------------------------------------------------
        let validation = ApiTokenValidation {
            token_id: token.id,
            user_id: token.user_id,
            // Thread `kind` so
            // `authenticate_pat` can inject the matching role marker.
            kind: token.kind,
            token_cap: TokenCap {
                permissions: token.declared_permissions.clone(),
                repository_ids: token.repository_ids.clone(),
            },
            expires_at: token.expires_at,
            revoked_at: token.revoked_at,
        };
        self.cache.insert(cache_key, validation.clone());
        emit_validation_metric(ValidationMetric::SuccessMiss);
        Ok(validation)
    }

    /// Increment the per-IP failed-attempt counter and trip the
    /// lockout flag once threshold is reached. No-op when
    /// `client_ip` was `None` (no `LockoutKeys` to key on).
    ///
    /// The increment is best-effort and non-atomic — same shape as
    /// the password-login lockout's `increment_counter`. Two concurrent failures
    /// may each observe value `n` and write `n+1`, losing one
    /// increment; the lockout still trips eventually with at most one
    /// failure of slack under contention.
    async fn bookkeep_failure(&self, keys: Option<&LockoutKeys>) -> Result<(), PatValidationError> {
        let Some(keys) = keys else {
            return Ok(());
        };
        let new_count = match self
            .ephemeral
            .get(&keys.counter_key)
            .await
            .map_err(PatValidationError::Infrastructure)?
        {
            Some(value) => {
                let n = decode_count(&value).unwrap_or(0).saturating_add(1);
                self.ephemeral
                    .put(&keys.counter_key, encode_count(n), self.config.window)
                    .await
                    .map_err(PatValidationError::Infrastructure)?;
                n
            }
            None => {
                // First failure of the streak.
                self.ephemeral
                    .put_if_absent(&keys.counter_key, encode_count(1), self.config.window)
                    .await
                    .map_err(PatValidationError::Infrastructure)?;
                1
            }
        };
        if new_count >= u64::from(self.config.threshold) {
            self.ephemeral
                .put(
                    &keys.flag_key,
                    Bytes::from_static(b"1"),
                    self.config.duration,
                )
                .await
                .map_err(PatValidationError::Infrastructure)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LockoutKeys — internal
// ---------------------------------------------------------------------------

/// Per-IP lockout keys derived from the bucketed source IP.
///
/// The flag key matches the spec-pinned wire form
/// (`pat-attempt:{client_ip_bucket}`); the counter key uses the
/// sibling [`PAT_LOCKOUT_BY_IP_COUNTER_PREFIX`].
struct LockoutKeys {
    counter_key: String,
    flag_key: String,
}

impl LockoutKeys {
    fn new(client_ip: IpAddr) -> Self {
        let bucket = client_ip_bucket(client_ip);
        Self {
            counter_key: format!("{PAT_LOCKOUT_BY_IP_COUNTER_PREFIX}{bucket}"),
            flag_key: format!("{PAT_LOCKOUT_BY_IP_FLAG_PREFIX}{bucket}"),
        }
    }
}

fn encode_count(n: u64) -> Bytes {
    Bytes::copy_from_slice(&n.to_be_bytes())
}

fn decode_count(b: &[u8]) -> Option<u64> {
    if b.len() != 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(b);
    Some(u64::from_be_bytes(buf))
}

// ---------------------------------------------------------------------------
// Token-format parsing
// ---------------------------------------------------------------------------

/// Errors returned by [`parse_pat_token_format`].
///
/// All three variants surface to the caller as the same
/// `PatValidationError::PrefixNotFound` after the sentinel-verify
/// branch runs — the format-failure shape is structurally
/// indistinguishable from "no row matched" by design (design doc §5
/// F14 token-shape note: prefix-shape routing is observable, the body
/// is not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenFormatError {
    /// Total length not exactly `9 + 32 = 41` bytes.
    BadLength,
    /// First 4 bytes are not `hort_*_` shape OR the kind discriminator
    /// is not one of `pat` / `svc` / `cli`.
    UnknownKind,
    /// Body contains a byte outside the base32 alphabet
    /// (`a-z2-7`, RFC 4648 §6 lower-case).
    NonBase32Body,
}

/// Parse a PAT plaintext into `(TokenKind, body_prefix)`. The
/// `body_prefix` is the first 8 chars of the 32-char base32 body —
/// the column the prefix index is built on.
///
/// Format: `hort_(pat|svc|cli)_[a-z2-7]{32}`. Total length 41 chars.
/// Strict — no trailing whitespace, no upper-case base32, no padding.
pub fn parse_pat_token_format(s: &str) -> Result<(TokenKind, &str), TokenFormatError> {
    // Length check first — rejects empty, truncated, and oversize
    // inputs before any byte indexing.
    if s.len() != 41 {
        return Err(TokenFormatError::BadLength);
    }
    let bytes = s.as_bytes();
    if &bytes[..5] != b"hort_" || bytes[8] != b'_' {
        return Err(TokenFormatError::UnknownKind);
    }
    let kind = match &bytes[5..8] {
        b"pat" => TokenKind::Pat,
        b"svc" => TokenKind::ServiceAccount,
        // `cli` is intentionally NOT a valid
        // opaque-PAT kind. The CliSession access token is a
        // Hort-signed JWT (validated on the bearer path by the CliSession
        // verifier, NOT by this opaque parser). An `hort_cli_*` shape
        // therefore falls through to `UnknownKind` → routes to the OIDC
        // validator → 401 (no compat shim for the retired opaque shape).
        _ => return Err(TokenFormatError::UnknownKind),
    };
    // Body span: bytes [9..41], 32 chars.
    let body = &s[9..41];
    if !body
        .as_bytes()
        .iter()
        .all(|&b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    {
        return Err(TokenFormatError::NonBase32Body);
    }
    Ok((kind, &body[..8]))
}

// ---------------------------------------------------------------------------
// Cache-key derivation
// ---------------------------------------------------------------------------

/// SHA-256 the full plaintext token. The cache keys on this digest,
/// never the plaintext, so a memory disclosure does not leak issuable
/// tokens (the plaintext is one preimage step away — equivalent to
/// the on-disk Argon2id hash).
pub fn compute_cache_key(token_plaintext: &str) -> CacheKey {
    let mut hasher = Sha256::new();
    hasher.update(token_plaintext.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    CacheKey::new(digest)
}

// ---------------------------------------------------------------------------
// Metric emission
// ---------------------------------------------------------------------------

/// `result` label values on `hort_api_token_validation_total` per
/// design doc §9. Closed taxonomy — every variant maps to exactly one
/// catalog row. Adding a variant requires a `docs/metrics-catalog.md`
/// edit in the same PR.
///
/// The pair of `Success*` variants encodes the `cache` label too:
/// `cache="hit"` for [`Self::SuccessHit`], `cache="miss"` for the rest
/// (per the §9 catalog entry that pins `rate_limited` to `cache="miss"`
/// because lockout decisions never come from the validation cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationMetric {
    SuccessHit,
    SuccessMiss,
    Expired,
    Revoked,
    UserDeactivated,
    PrefixNotFound,
    HashMismatch,
    RateLimited,
}

impl ValidationMetric {
    fn result_label(self) -> &'static str {
        match self {
            Self::SuccessHit | Self::SuccessMiss => "success",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::UserDeactivated => "user_deactivated",
            Self::PrefixNotFound => "prefix_not_found",
            Self::HashMismatch => "hash_mismatch",
            Self::RateLimited => "rate_limited",
        }
    }

    fn cache_label(self) -> &'static str {
        match self {
            Self::SuccessHit => "hit",
            _ => "miss",
        }
    }
}

/// Emit `hort_api_token_validation_total{result, cache}` once per
/// validation attempt. MUST be the LAST step before returning on
/// every code path so the increment cannot become a covert timing
/// oracle (design doc §9).
fn emit_validation_metric(m: ValidationMetric) {
    metrics::counter!(
        "hort_api_token_validation_total",
        labels::RESULT => m.result_label(),
        labels::CACHE => m.cache_label(),
    )
    .increment(1);
}

/// Map a [`Result<ApiTokenValidation, PatValidationError>`] to the
/// `result` label of
/// `hort_api_token_validation_duration_seconds`. Mirrors
/// [`ValidationMetric::result_label`] minus
/// the `cache` distinction — the histogram does NOT carry a `cache`
/// label (per its `docs/metrics-catalog.md` row; cache hit/miss is
/// already split on the counter, and adding it to the histogram
/// would inflate the per-bucket sample count without operational
/// benefit).
fn validation_duration_result_label(
    result: &Result<ApiTokenValidation, PatValidationError>,
) -> &'static str {
    match result {
        Ok(_) => "success",
        Err(PatValidationError::Expired) => "expired",
        Err(PatValidationError::Revoked) => "revoked",
        Err(PatValidationError::UserDeactivated) => "user_deactivated",
        Err(PatValidationError::PrefixNotFound) => "prefix_not_found",
        Err(PatValidationError::HashMismatch) => "hash_mismatch",
        Err(PatValidationError::RateLimited) => "rate_limited",
        // Infrastructure errors don't have a corresponding row on the
        // counter — they fall into the catch-all `validation_error`
        // bucket on the histogram so dashboards can correlate spikes
        // with `hort_api_token_validation_total{result="rate_limited"}`
        // (no overlap — Infrastructure short-circuits before any of
        // the labeled paths).
        Err(PatValidationError::Infrastructure(_)) => "infrastructure_error",
    }
}

/// Emit `hort_api_token_validation_duration_seconds{result}` once per
/// validation attempt. Records the elapsed time of the ENTIRE
/// validation closure including the constant-time Argon2 verify, the
/// counter increment, and any cache writes — design doc §9 paragraph
/// "Metric-emission timing vs constant-time invariant".
///
/// Default histogram buckets apply (the `metrics` crate exposes them
/// to the recorder; hort-app does not override them per existing
/// `hort_*_duration_seconds` histograms — see `hort_download_duration_seconds`,
/// `hort_ingest_duration_seconds`).
fn emit_validation_duration(
    result: &Result<ApiTokenValidation, PatValidationError>,
    elapsed_seconds: f64,
) {
    metrics::histogram!(
        "hort_api_token_validation_duration_seconds",
        labels::RESULT => validation_duration_result_label(result),
    )
    .record(elapsed_seconds);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Mutex;

    use chrono::{DateTime, Duration as ChronoDuration, Utc};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};
    use uuid::Uuid;

    use hort_domain::entities::api_token::{ApiToken, TokenCap, TokenKind};
    use hort_domain::entities::rbac::Permission;
    use hort_domain::entities::user::{AuthProvider, User};
    use hort_domain::error::DomainResult;
    use hort_domain::ports::api_token_repository::ApiTokenRepository;
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::user_repository::UserRepository;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::{Page, PageRequest};

    use crate::use_cases::pat_cache::PatCache;

    // -----------------------------------------------------------------
    // Counter-spy verifier — pins the "verify exactly once / zero" rule
    // -----------------------------------------------------------------

    /// Verifier with a planted result and a call counter. Used in
    /// EVERY counter-spy test in this module so the assertions only
    /// see the validator's call sites — never the production
    /// `DefaultArgon2Verifier`'s slow path.
    struct CountingVerifier {
        calls: AtomicUsize,
        result: bool,
    }

    impl CountingVerifier {
        fn new(result: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                result,
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }

    impl Argon2Verifier for CountingVerifier {
        fn verify(&self, _plaintext: &[u8], _hash: &str) -> bool {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            self.result
        }
    }

    // -----------------------------------------------------------------
    // Mock clock — virtual-time advance for the lockout-window test
    // -----------------------------------------------------------------

    struct MockClock {
        // `chrono::DateTime` is not `Copy`; store the unix-seconds form
        // and rebuild on read so the counter is `AtomicI64`.
        now_secs: AtomicI64,
    }

    impl MockClock {
        fn at(secs: i64) -> Arc<Self> {
            Arc::new(Self {
                now_secs: AtomicI64::new(secs),
            })
        }
        /// Advance virtual time by `by` seconds. Used by the
        /// post-cache-write clock-stepping test below.
        fn advance(&self, by: Duration) {
            let add = i64::try_from(by.as_secs()).expect("test duration fits");
            self.now_secs.fetch_add(add, AtomicOrdering::SeqCst);
        }
    }

    impl Clock for Arc<MockClock> {
        fn now(&self) -> DateTime<Utc> {
            DateTime::<Utc>::from_timestamp(self.now_secs.load(AtomicOrdering::SeqCst), 0)
                .expect("test timestamp")
        }
    }

    // -----------------------------------------------------------------
    // Mock ApiTokenRepository
    // -----------------------------------------------------------------

    struct MockTokenRepo {
        by_prefix: Mutex<HashMap<String, ApiToken>>,
    }

    impl MockTokenRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                by_prefix: Mutex::new(HashMap::new()),
            })
        }
        fn insert(&self, prefix: &str, token: ApiToken) {
            self.by_prefix
                .lock()
                .unwrap()
                .insert(prefix.to_string(), token);
        }
    }

    impl ApiTokenRepository for MockTokenRepo {
        fn insert(&self, _token: &ApiToken) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("validator does not insert")
        }
        fn find_by_prefix(&self, prefix: &str) -> BoxFuture<'_, DomainResult<Option<ApiToken>>> {
            let result = self.by_prefix.lock().unwrap().get(prefix).cloned();
            Box::pin(async move { Ok(result) })
        }
        fn find_by_id(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<ApiToken>> {
            unreachable!("validator does not find_by_id")
        }
        fn list_for_user(
            &self,
            _user_id: Uuid,
            _page: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<ApiToken>>> {
            unreachable!("validator does not list")
        }
        fn update_last_used(
            &self,
            _token_id: Uuid,
            _at: DateTime<Utc>,
            _client_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("update_last_used is the middleware's job (B5c)")
        }
        fn revoke(&self, _token_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("validator does not revoke")
        }
    }

    // -----------------------------------------------------------------
    // Mock UserRepository — only `find_by_id` is reachable
    // -----------------------------------------------------------------

    struct MockUserRepo {
        users: Mutex<HashMap<Uuid, User>>,
    }

    impl MockUserRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                users: Mutex::new(HashMap::new()),
            })
        }
        fn insert(&self, user: User) {
            self.users.lock().unwrap().insert(user.id, user);
        }
    }

    impl UserRepository for MockUserRepo {
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<User>> {
            let result =
                self.users
                    .lock()
                    .unwrap()
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| DomainError::NotFound {
                        entity: "User",
                        id: id.to_string(),
                    });
            Box::pin(async move { result })
        }
        fn find_by_username(&self, _username: &str) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("validator does not call find_by_username")
        }
        fn find_by_email(&self, _email: &str) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("validator does not call find_by_email")
        }
        fn list(&self, _page: PageRequest) -> BoxFuture<'_, DomainResult<Page<User>>> {
            unreachable!("validator does not list users")
        }
        fn save(&self, _user: &User) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("validator does not save users")
        }
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("validator does not delete users")
        }
        fn find_by_external_id(
            &self,
            _ap: AuthProvider,
            _ext: &str,
        ) -> BoxFuture<'_, DomainResult<Option<User>>> {
            unreachable!("validator does not call find_by_external_id")
        }
        fn upsert_on_login(&self, _user: &User) -> BoxFuture<'_, DomainResult<User>> {
            unreachable!("validator does not call upsert_on_login")
        }
    }

    // -----------------------------------------------------------------
    // Mock EphemeralStore — same shape as the auth-use-case mock,
    // wall-clock-driven TTLs.
    // -----------------------------------------------------------------

    struct MockEphemeralStore {
        entries: Mutex<HashMap<String, (Bytes, std::time::Instant)>>,
    }

    impl MockEphemeralStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entries: Mutex::new(HashMap::new()),
            })
        }
        fn read_live(&self, key: &str) -> Option<Bytes> {
            let now = std::time::Instant::now();
            let mut map = self.entries.lock().unwrap();
            match map.get(key) {
                Some((value, expires_at)) if *expires_at > now => Some(value.clone()),
                Some(_) => {
                    map.remove(key);
                    None
                }
                None => None,
            }
        }
    }

    impl EphemeralStore for MockEphemeralStore {
        fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            let result = self.read_live(key);
            Box::pin(async move { Ok(result) })
        }
        fn put(&self, key: &str, value: Bytes, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            let expires_at = std::time::Instant::now() + ttl;
            self.entries
                .lock()
                .unwrap()
                .insert(key.to_string(), (value, expires_at));
            Box::pin(async { Ok(()) })
        }
        fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            let now = std::time::Instant::now();
            let mut map = self.entries.lock().unwrap();
            let live = matches!(map.get(key), Some((_, expires_at)) if *expires_at > now);
            let created = if live {
                false
            } else {
                map.insert(key.to_string(), (value, now + ttl));
                true
            };
            Box::pin(async move { Ok(created) })
        }
        fn compare_and_swap(
            &self,
            _k: &str,
            _v: u64,
            _nv: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            unreachable!("validator does not CAS")
        }
        fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
            self.entries.lock().unwrap().remove(key);
            Box::pin(async { Ok(()) })
        }
        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("validator does not extend_ttl")
        }
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    /// A valid 39-byte test token (`hort_pat_` + 32 lower-case base32
    /// chars). All tests reuse this so the body prefix is the
    /// constant `aaaaaaaa` and lookups are deterministic.
    const VALID_TOKEN: &str = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// Sibling token with a different body — used to exercise the
    /// "prefix found but hash mismatch" branch.
    const VALID_TOKEN_2: &str = "hort_pat_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn t0() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("epoch")
    }

    fn fixture_user(id: Uuid, active: bool) -> User {
        User {
            id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("k:1".into()),
            display_name: None,
            is_active: active,
            is_admin: false,
            is_service_account: false,
            last_login_at: None,
            created_at: t0(),
            updated_at: t0(),
        }
    }

    fn fixture_token(user_id: Uuid, prefix: &str) -> ApiToken {
        ApiToken {
            id: Uuid::new_v4(),
            user_id,
            name: "ci-publish".into(),
            description: None,
            kind: TokenKind::Pat,
            // `token_hash` is opaque to the validator — the spy
            // verifier returns its planted result regardless. We
            // store a plausible PHC string for fidelity.
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$saltsaltsaltsalt$digestdigestdigestdigest"
                .into(),
            token_prefix: prefix.into(),
            declared_permissions: vec![Permission::Read],
            repository_ids: None,
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: user_id,
            created_at: t0(),
        }
    }

    /// Bag of test handles returned alongside the use-case. Tuple
    /// alias keeps `make_uc`'s signature inside clippy's
    /// `type_complexity` budget — six handles is a lot but every one
    /// of them is consumed by at least one test.
    type Fixture = (
        PatValidationUseCase,
        Arc<MockTokenRepo>,
        Arc<MockUserRepo>,
        Arc<MockEphemeralStore>,
        Arc<PatCache>,
        Arc<MockClock>,
    );

    /// All-in-one fixture builder — returns the use-case + the
    /// handles tests need to plant rows / inspect counters.
    fn make_uc(verifier: Arc<dyn Argon2Verifier>) -> Fixture {
        let tokens = MockTokenRepo::new();
        let users = MockUserRepo::new();
        let ephemeral = MockEphemeralStore::new();
        let clock = MockClock::at(t0().timestamp());
        let cache = Arc::new(PatCache::new_with_clock(
            16,
            Duration::from_secs(300),
            Box::new(clock.clone()),
        ));
        let uc = PatValidationUseCase::new_with_verifier(
            tokens.clone() as Arc<dyn ApiTokenRepository>,
            users.clone() as Arc<dyn UserRepository>,
            ephemeral.clone() as Arc<dyn EphemeralStore>,
            cache.clone(),
            verifier,
            Arc::new(clock.clone()) as Arc<dyn Clock>,
            PatLockoutConfig::DEFAULT,
        );
        (uc, tokens, users, ephemeral, cache, clock)
    }

    /// Look up the integer value of `hort_api_token_validation_total`
    /// in a `metrics_util` snapshot for the given `(result, cache)`.
    fn snap_value(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        result: &str,
        cache: &str,
    ) -> u64 {
        for (key, _unit, _desc, value) in snap {
            if key.kind() != MetricKind::Counter {
                continue;
            }
            let k = key.key();
            if k.name() != "hort_api_token_validation_total" {
                continue;
            }
            let mut got_result = None;
            let mut got_cache = None;
            for label in k.labels() {
                match label.key() {
                    "result" => got_result = Some(label.value().to_string()),
                    "cache" => got_cache = Some(label.value().to_string()),
                    _ => {}
                }
            }
            if got_result.as_deref() == Some(result) && got_cache.as_deref() == Some(cache) {
                if let DebugValue::Counter(v) = value {
                    return *v;
                }
            }
        }
        0
    }

    /// Set up a recorder, run an async closure inside it, and return
    /// the resulting snapshot vec for assertion.
    fn capture_async<F, Fut>(
        f: F,
    ) -> Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Runtime::new().unwrap().block_on(f());
        });
        snapshotter.snapshot().into_vec()
    }

    fn ip() -> IpAddr {
        "203.0.113.42".parse().unwrap()
    }

    // =================================================================
    // 1. Counter-spy invariants (acceptance bullet 8)
    // =================================================================

    #[test]
    fn validate_pat_prefix_not_found_calls_verify_exactly_once() {
        // No row planted → sentinel branch. Verify must run exactly
        // once with the spy verifier (the architectural invariant
        // from design §8 invariant 1; counter-spy proof).
        let spy = CountingVerifier::new(false);
        let (uc, _tokens, _users, _store, _cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::PrefixNotFound));
        });
        assert_eq!(
            spy.calls(),
            1,
            "exactly one verify call on prefix-not-found"
        );
    }

    #[test]
    fn validate_pat_prefix_found_hash_mismatch_calls_verify_exactly_once() {
        let spy = CountingVerifier::new(false);
        let (uc, tokens, users, _store, _cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::HashMismatch));
        });
        assert_eq!(spy.calls(), 1, "exactly one verify call on hash-mismatch");
    }

    #[test]
    fn validate_pat_prefix_found_hash_match_calls_verify_exactly_once() {
        let spy = CountingVerifier::new(true);
        let (uc, tokens, users, _store, _cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let validation = uc
                .validate_pat(VALID_TOKEN, Some(ip()))
                .await
                .expect("planted token + planted match must succeed");
            assert_eq!(validation.user_id, user_id);
        });
        assert_eq!(spy.calls(), 1, "exactly one verify call on success");
    }

    #[test]
    fn validate_pat_rate_limited_calls_verify_zero_times() {
        // Pre-set the lockout flag for the bucketed IP. Validator MUST
        // short-circuit BEFORE any verify — counter spy MUST observe
        // zero calls. This is the load-bearing invariant for the
        // brute-force-lockout: the gate exists to cap Argon2 verify
        // CPU-cost, so a verify call after the gate would defeat its
        // purpose entirely.
        let spy = CountingVerifier::new(true);
        let (uc, _tokens, _users, store, _cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        let bucket = client_ip_bucket(ip());
        let flag_key = format!("{PAT_LOCKOUT_BY_IP_FLAG_PREFIX}{bucket}");
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            store
                .put(
                    &flag_key,
                    Bytes::from_static(b"1"),
                    Duration::from_secs(900),
                )
                .await
                .unwrap();
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::RateLimited));
        });
        assert_eq!(spy.calls(), 0, "lockout MUST short-circuit BEFORE verify");
    }

    // =================================================================
    // 2. Metric-emission ordering (acceptance bullet 9)
    // =================================================================

    #[test]
    fn metric_increments_after_verify_call_on_prefix_not_found() {
        // Wrap the spy in an outer assertion: at the moment the
        // metric is observed, the counter MUST already show 1.
        // Because `emit_validation_metric` is the LAST step before
        // returning, the snapshot at function exit captures both the
        // verify call AND the metric increment. The wrapper-spy
        // counts verify calls; the snapshot proves the metric was
        // ALSO emitted, in that same code path.
        let spy = CountingVerifier::new(false);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, _tokens, _users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        assert_eq!(spy.calls(), 1);
        assert_eq!(
            snap_value(&snap, "prefix_not_found", "miss"),
            1,
            "metric MUST increment on the prefix-not-found path"
        );
    }

    #[test]
    fn metric_increments_after_verify_call_on_hash_mismatch() {
        let spy = CountingVerifier::new(false);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, tokens, users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let user_id = Uuid::new_v4();
                users.insert(fixture_user(user_id, true));
                tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        assert_eq!(spy.calls(), 1);
        assert_eq!(snap_value(&snap, "hash_mismatch", "miss"), 1);
    }

    #[test]
    fn metric_increments_after_verify_call_on_success() {
        let spy = CountingVerifier::new(true);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, tokens, users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let user_id = Uuid::new_v4();
                users.insert(fixture_user(user_id, true));
                tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        assert_eq!(spy.calls(), 1);
        assert_eq!(
            snap_value(&snap, "success", "miss"),
            1,
            "first call is a cache miss → cache=miss"
        );
    }

    #[test]
    fn metric_increments_before_verify_on_rate_limited() {
        // Inverse of the post-verify-ordering tests. The lockout
        // short-circuit ALSO emits the metric, but does so without
        // reaching the verifier. The snapshot must show
        // `rate_limited, miss` = 1, AND the spy must show zero
        // calls — proving the lockout path is metric-emit-then-return,
        // never verify-then-metric.
        let spy = CountingVerifier::new(true);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, _tokens, _users, store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let bucket = client_ip_bucket(ip());
                let flag_key = format!("{PAT_LOCKOUT_BY_IP_FLAG_PREFIX}{bucket}");
                store
                    .put(
                        &flag_key,
                        Bytes::from_static(b"1"),
                        Duration::from_secs(900),
                    )
                    .await
                    .unwrap();
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        assert_eq!(spy.calls(), 0, "no verify on lockout short-circuit");
        assert_eq!(snap_value(&snap, "rate_limited", "miss"), 1);
    }

    // =================================================================
    // 3. Lockout state machine
    // =================================================================

    #[test]
    fn lockout_threshold_30_misses_in_window_trips_flag() {
        // 30 invalid validations → 31st short-circuits with zero
        // verify calls. The default config is 30/5min/15min so the
        // 30th failure trips the flag (>= threshold).
        let spy = CountingVerifier::new(false);
        let (uc, _tokens, _users, _store, _cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for _ in 0..30 {
                let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
                // Each failure routes through the sentinel branch.
                assert!(matches!(err, PatValidationError::PrefixNotFound));
            }
            assert_eq!(spy.calls(), 30, "30 verify calls before lockout trips");
            // 31st must be RateLimited and NOT bump the verify counter.
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::RateLimited));
            assert_eq!(
                spy.calls(),
                30,
                "31st request short-circuited — verify NOT called"
            );
        });
    }

    #[test]
    fn lockout_window_resets_after_window_secs() {
        // Pre-trip the lockout, then simulate the flag's TTL
        // elapsing by deleting the flag manually (the wall-clock
        // mock cannot fast-forward `std::time::Instant`). The
        // effect is identical from the validator's POV: a get-miss
        // on the flag means "not currently locked".
        let spy = CountingVerifier::new(false);
        let (uc, _tokens, _users, store, _cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for _ in 0..30 {
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
            let bucket = client_ip_bucket(ip());
            let flag_key = format!("{PAT_LOCKOUT_BY_IP_FLAG_PREFIX}{bucket}");
            // Sanity: flag was tripped.
            assert!(store.get(&flag_key).await.unwrap().is_some());
            // Simulate window elapse — clear the flag.
            store.delete(&flag_key).await.unwrap();
            // Next call MUST proceed through the verify path again.
            let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            assert_eq!(spy.calls(), 31, "post-window verify proceeds again");
        });
    }

    #[test]
    fn lockout_does_not_apply_when_client_ip_is_none() {
        // Anonymous-source PATs cannot be lockout-tracked — there is
        // no client_ip_bucket to key on. 30 failures still all route
        // to verify, no lockout is set up.
        let spy = CountingVerifier::new(false);
        let (uc, _tokens, _users, store, _cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for _ in 0..35 {
                let _ = uc.validate_pat(VALID_TOKEN, None).await;
            }
            assert_eq!(spy.calls(), 35, "no lockout when client_ip=None");
            // No flag, no counter — the keyspaces are simply unused.
            for (k, _) in store.entries.lock().unwrap().iter() {
                assert!(
                    !k.starts_with(PAT_LOCKOUT_BY_IP_FLAG_PREFIX)
                        && !k.starts_with(PAT_LOCKOUT_BY_IP_COUNTER_PREFIX),
                    "lockout keyspace must be empty when client_ip=None, found {k}"
                );
            }
        });
    }

    // =================================================================
    // 4. Validation paths (expiry / revocation / deactivation / cache)
    // =================================================================

    #[test]
    fn validate_pat_returns_expired_when_expires_at_in_past() {
        let spy = CountingVerifier::new(true);
        let (uc, tokens, users, _store, _cache, _clock) = make_uc(spy as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        let mut tok = fixture_token(user_id, "aaaaaaaa");
        tok.expires_at = Some(t0() - ChronoDuration::seconds(1));
        tokens.insert("aaaaaaaa", tok);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::Expired));
        });
    }

    #[test]
    fn validate_pat_returns_revoked_when_revoked_at_set() {
        let spy = CountingVerifier::new(true);
        let (uc, tokens, users, _store, _cache, _clock) = make_uc(spy as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        let mut tok = fixture_token(user_id, "aaaaaaaa");
        tok.revoked_at = Some(t0());
        tokens.insert("aaaaaaaa", tok);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::Revoked));
        });
    }

    #[test]
    fn validate_pat_returns_user_deactivated_when_user_inactive() {
        let spy = CountingVerifier::new(true);
        let (uc, tokens, users, _store, _cache, _clock) = make_uc(spy as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, false)); // is_active = false
        tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::UserDeactivated));
        });
    }

    #[test]
    fn validate_pat_caches_validation_on_success() {
        // After a successful validation, the cache MUST hold an
        // entry under `compute_cache_key(plaintext)`.
        let spy = CountingVerifier::new(true);
        let (uc, tokens, users, _store, cache, _clock) = make_uc(spy as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
            let key = compute_cache_key(VALID_TOKEN);
            assert!(cache.get(&key).is_some(), "cache must hold the validation");
        });
    }

    #[test]
    fn validate_pat_returns_cached_on_subsequent_call() {
        // First call populates the cache. Second call MUST be served
        // from the cache without invoking the verifier — the spy's
        // counter stays at 1.
        let spy = CountingVerifier::new(true);
        let (uc, tokens, users, _store, _cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
            let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
            assert_eq!(spy.calls(), 1, "second call MUST be a cache hit, no verify");
        });
    }

    #[test]
    fn validate_pat_does_not_cache_negative_results() {
        // Caching a hash-mismatch would be a timing oracle (the cache
        // hit path is observably different from the cache miss path).
        // After a failed validation the cache MUST stay empty for that
        // plaintext.
        let spy = CountingVerifier::new(false);
        let (uc, tokens, users, _store, cache, _clock) = make_uc(spy as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            let key = compute_cache_key(VALID_TOKEN);
            assert!(
                cache.get(&key).is_none(),
                "negative results MUST NOT be cached"
            );
        });
    }

    // =================================================================
    // 5. Token-format parsing
    // =================================================================

    #[test]
    fn parse_pat_token_format_recognises_pat_svc_prefixes() {
        let pat = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let svc = "hort_svc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(pat).unwrap(),
            (TokenKind::Pat, "aaaaaaaa")
        );
        assert_eq!(
            parse_pat_token_format(svc).unwrap(),
            (TokenKind::ServiceAccount, "aaaaaaaa")
        );
    }

    #[test]
    fn parse_pat_token_format_rejects_cli_prefix() {
        // CliSession is a Hort-signed JWT,
        // not an opaque `hort_cli_*` token, so the `cli` prefix is
        // not a valid PAT shape. An `hort_cli_*` shape is rejected as
        // an unknown kind (it would route to the OIDC validator → 401);
        // there is no compat shim for the retired opaque shape.
        let cli = "hort_cli_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(cli),
            Err(TokenFormatError::UnknownKind)
        );
    }

    #[test]
    fn parse_pat_token_format_rejects_unknown_kind() {
        // 41-char shape with a 3-letter kind that's not pat/svc.
        let bad = "hort_xyz_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(bad),
            Err(TokenFormatError::UnknownKind)
        );
        // Right length (41), wrong overall shape — no leading `hort_`.
        let no_hort = "xort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(no_hort),
            Err(TokenFormatError::UnknownKind)
        );
    }

    #[test]
    fn parse_pat_token_format_rejects_short_body() {
        // 38 chars — one short.
        let short = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(short),
            Err(TokenFormatError::BadLength)
        );
        // Empty.
        assert_eq!(parse_pat_token_format(""), Err(TokenFormatError::BadLength));
        // Way too long.
        let long = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(long),
            Err(TokenFormatError::BadLength)
        );
    }

    #[test]
    fn parse_pat_token_format_rejects_non_base32_body() {
        // Upper-case A is OUTSIDE the lower-case base32 alphabet
        // (`a-z2-7`).
        let upper = "hort_pat_Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(upper),
            Err(TokenFormatError::NonBase32Body)
        );
        // `0` and `1` are NOT in base32.
        let zero = "hort_pat_0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(zero),
            Err(TokenFormatError::NonBase32Body)
        );
        let one = "hort_pat_1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_pat_token_format(one),
            Err(TokenFormatError::NonBase32Body)
        );
    }

    // =================================================================
    // 6. Helpers
    // =================================================================

    #[test]
    fn compute_cache_key_is_stable_across_calls() {
        let a = compute_cache_key(VALID_TOKEN);
        let b = compute_cache_key(VALID_TOKEN);
        assert_eq!(a, b, "sha256 is deterministic");
        // Distinct plaintext → distinct digest.
        let c = compute_cache_key(VALID_TOKEN_2);
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------
    // Pin: error variant Display surfaces all variants.
    // -----------------------------------------------------------------

    #[test]
    fn pat_validation_error_display_pins() {
        // Pin the user-visible text on every variant; review-bypass
        // changes that drop a variant or rename one trip this test.
        assert_eq!(PatValidationError::RateLimited.to_string(), "rate limited");
        assert_eq!(
            PatValidationError::PrefixNotFound.to_string(),
            "token prefix not found"
        );
        assert_eq!(
            PatValidationError::HashMismatch.to_string(),
            "token hash mismatch"
        );
        assert_eq!(PatValidationError::Expired.to_string(), "token expired");
        assert_eq!(PatValidationError::Revoked.to_string(), "token revoked");
        assert_eq!(
            PatValidationError::UserDeactivated.to_string(),
            "user deactivated"
        );
        let infra: PatValidationError = DomainError::Invariant("oops".into()).into();
        assert!(infra.to_string().starts_with("infrastructure error:"));
    }

    #[test]
    fn pat_lockout_config_default_matches_spec() {
        let c = PatLockoutConfig::default();
        assert_eq!(c.threshold, 30);
        assert_eq!(c.window, Duration::from_secs(300));
        assert_eq!(c.duration, Duration::from_secs(900));
    }

    // -----------------------------------------------------------------
    // Cache-hit revocation/deactivation re-checks (design §5 step 2)
    // -----------------------------------------------------------------

    #[test]
    fn cache_hit_re_checks_revocation_mid_ttl() {
        // Plant a cached validation directly with `revoked_at` set —
        // simulating a revocation that happened between the original
        // insert and a subsequent lookup. The validator MUST return
        // `Revoked` and never reach the verifier.
        let spy = CountingVerifier::new(true);
        let (uc, _tokens, users, _store, cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        let key = compute_cache_key(VALID_TOKEN);
        cache.insert(
            key,
            ApiTokenValidation {
                token_id: Uuid::new_v4(),
                user_id,
                kind: TokenKind::Pat,
                token_cap: TokenCap {
                    permissions: vec![Permission::Read],
                    repository_ids: None,
                },
                expires_at: None,
                revoked_at: Some(t0()),
            },
        );
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::Revoked));
        });
        assert_eq!(spy.calls(), 0, "cache hit MUST NOT invoke verifier");
    }

    #[test]
    fn cache_hit_re_checks_expiry_mid_ttl() {
        let spy = CountingVerifier::new(true);
        let (uc, _tokens, users, _store, cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        let key = compute_cache_key(VALID_TOKEN);
        cache.insert(
            key,
            ApiTokenValidation {
                token_id: Uuid::new_v4(),
                user_id,
                kind: TokenKind::Pat,
                token_cap: TokenCap {
                    permissions: vec![Permission::Read],
                    repository_ids: None,
                },
                expires_at: Some(t0() - ChronoDuration::seconds(1)),
                revoked_at: None,
            },
        );
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::Expired));
        });
        assert_eq!(spy.calls(), 0);
    }

    #[test]
    fn cache_hit_re_checks_user_deactivation_mid_ttl() {
        let spy = CountingVerifier::new(true);
        let (uc, _tokens, users, _store, cache, _clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        // User is deactivated AFTER the cache entry was inserted.
        users.insert(fixture_user(user_id, false));
        let key = compute_cache_key(VALID_TOKEN);
        cache.insert(
            key,
            ApiTokenValidation {
                token_id: Uuid::new_v4(),
                user_id,
                kind: TokenKind::Pat,
                token_cap: TokenCap {
                    permissions: vec![Permission::Read],
                    repository_ids: None,
                },
                expires_at: None,
                revoked_at: None,
            },
        );
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::UserDeactivated));
        });
        assert_eq!(spy.calls(), 0);
    }

    // -----------------------------------------------------------------
    // Pin: lockout key prefix constants — spec-pinned wire forms.
    // -----------------------------------------------------------------

    #[test]
    fn cache_hit_detects_expiry_after_clock_advance() {
        // The validator's `now` is the injected clock. A cached
        // entry that was once-valid must be rejected with `Expired`
        // once the clock crosses `expires_at`. This is the time-
        // driven companion of `cache_hit_re_checks_expiry_mid_ttl`
        // (which plants an already-past `expires_at`) — together
        // they prove the comparison uses the live clock, not the
        // value at insert time.
        let spy = CountingVerifier::new(true);
        let (uc, _tokens, users, _store, cache, clock) =
            make_uc(spy.clone() as Arc<dyn Argon2Verifier>);
        let user_id = Uuid::new_v4();
        users.insert(fixture_user(user_id, true));
        let key = compute_cache_key(VALID_TOKEN);
        cache.insert(
            key,
            ApiTokenValidation {
                token_id: Uuid::new_v4(),
                user_id,
                kind: TokenKind::Pat,
                token_cap: TokenCap {
                    permissions: vec![Permission::Read],
                    repository_ids: None,
                },
                // Expires 60s after t0; advance >60s to trip.
                expires_at: Some(t0() + ChronoDuration::seconds(60)),
                revoked_at: None,
            },
        );
        clock.advance(Duration::from_secs(120));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
            assert!(matches!(err, PatValidationError::Expired));
        });
        assert_eq!(spy.calls(), 0, "cache hit MUST NOT invoke verifier");
    }

    #[test]
    fn lockout_key_prefixes_match_spec() {
        // `pat-attempt:` for the flag, distinct from
        // the password-login `auth:lockout:by_ip:`. The counter prefix
        // `pat-attempt-counter:` is the sibling we picked here so
        // the flag and counter do not collide on the same bucket.
        assert_eq!(PAT_LOCKOUT_BY_IP_FLAG_PREFIX, "pat-attempt:");
        assert_eq!(PAT_LOCKOUT_BY_IP_COUNTER_PREFIX, "pat-attempt-counter:");
        assert_ne!(
            PAT_LOCKOUT_BY_IP_FLAG_PREFIX, "auth:lockout:by_ip:",
            "must not share the password-login lockout prefix"
        );
    }

    // =================================================================
    // 5. `hort_api_token_validation_duration_seconds`
    // =================================================================

    /// Walk a snapshot for a histogram-kind metric and return its
    /// recorded samples (a `Vec<f64>`). Returns an empty vec when the
    /// metric+labels combination is absent.
    fn b9_histogram_samples(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        metric_name: &str,
        result_label: &str,
    ) -> Vec<f64> {
        for (key, _unit, _desc, value) in snap {
            if key.kind() != MetricKind::Histogram {
                continue;
            }
            if key.key().name() != metric_name {
                continue;
            }
            let mut got_result = None;
            for label in key.key().labels() {
                if label.key() == "result" {
                    got_result = Some(label.value().to_string());
                }
            }
            if got_result.as_deref() == Some(result_label) {
                if let DebugValue::Histogram(samples) = value {
                    return samples.iter().map(|s| s.into_inner()).collect();
                }
            }
        }
        Vec::new()
    }

    fn b9_collect_histogram_label_keys(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        metric_name: &str,
    ) -> std::collections::BTreeSet<String> {
        let mut keys = std::collections::BTreeSet::new();
        for (key, _, _, _) in snap {
            if key.kind() == MetricKind::Histogram && key.key().name() == metric_name {
                for label in key.key().labels() {
                    keys.insert(label.key().to_string());
                }
            }
        }
        keys
    }

    // -- happy path: success -------------------------------------------

    #[test]
    fn validation_duration_records_sample_on_success() {
        let spy = CountingVerifier::new(true);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, tokens, users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let user_id = Uuid::new_v4();
                users.insert(fixture_user(user_id, true));
                tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        let samples = b9_histogram_samples(
            &snap,
            "hort_api_token_validation_duration_seconds",
            "success",
        );
        assert_eq!(samples.len(), 1, "histogram MUST record exactly one sample");
        // The architectural invariant from §9: the histogram is
        // recorded around the entire closure. If the histogram had
        // recorded BEFORE the verify, the duration would be ~0 (just
        // the timer-Start + record overhead). Asserting non-zero
        // proves the closure body ran past the verify before record.
        assert!(
            samples[0] > 0.0,
            "histogram duration on success path MUST be > 0 (proves the closure ran \
             past the Argon2 verify before recording); got {}",
            samples[0]
        );
    }

    // -- failure path: prefix_not_found --------------------------------

    #[test]
    fn validation_duration_records_sample_on_prefix_not_found() {
        let spy = CountingVerifier::new(false);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, _tokens, _users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        let samples = b9_histogram_samples(
            &snap,
            "hort_api_token_validation_duration_seconds",
            "prefix_not_found",
        );
        assert_eq!(samples.len(), 1);
        assert!(
            samples[0] > 0.0,
            "duration > 0 on prefix_not_found proves the closure ran past the \
             sentinel-verify before recording; got {}",
            samples[0]
        );
    }

    // -- rate_limited path: short-circuit BEFORE verify -----------------

    #[test]
    fn validation_duration_records_sample_on_rate_limited() {
        // Per design doc §9: the histogram is recorded around the
        // ENTIRE closure on every code path including the lockout
        // short-circuit. The sample MUST land on result=rate_limited
        // and MUST be non-zero (the closure walks the ephemeral-store
        // get + counter-increment before returning).
        let spy = CountingVerifier::new(true);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, _tokens, _users, store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let bucket = client_ip_bucket(ip());
                let flag_key = format!("{PAT_LOCKOUT_BY_IP_FLAG_PREFIX}{bucket}");
                store
                    .put(
                        &flag_key,
                        Bytes::from_static(b"1"),
                        Duration::from_secs(900),
                    )
                    .await
                    .unwrap();
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        let samples = b9_histogram_samples(
            &snap,
            "hort_api_token_validation_duration_seconds",
            "rate_limited",
        );
        assert_eq!(samples.len(), 1);
        assert!(
            samples[0] > 0.0,
            "duration > 0 on rate_limited proves the closure ran past the lockout \
             check before recording; got {}",
            samples[0]
        );
    }

    // -- ordering invariant — duration > 0 on every code path -----------

    #[test]
    fn validation_duration_nonzero_on_every_code_path() {
        // Design doc §9: "the histogram is recorded around the entire
        // validation closure, not just the verify call, so it
        // includes the metric increment itself — but every code path
        // increments exactly one counter, so the path lengths are
        // equal." The architectural invariant: every code path's
        // histogram sample is > 0, which proves the closure body ran
        // past the verify (or the deliberate short-circuit) before
        // the record() call. If a future refactor moved record() to
        // the front of the closure, the duration would be ~0 and
        // this test would fail.

        // hash_mismatch
        let spy = CountingVerifier::new(false);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, tokens, users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let user_id = Uuid::new_v4();
                users.insert(fixture_user(user_id, true));
                tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        let samples = b9_histogram_samples(
            &snap,
            "hort_api_token_validation_duration_seconds",
            "hash_mismatch",
        );
        assert_eq!(samples.len(), 1);
        assert!(samples[0] > 0.0);

        // expired
        let spy = CountingVerifier::new(true);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, tokens, users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let user_id = Uuid::new_v4();
                users.insert(fixture_user(user_id, true));
                let mut tok = fixture_token(user_id, "aaaaaaaa");
                tok.expires_at = Some(t0() - ChronoDuration::seconds(1));
                tokens.insert("aaaaaaaa", tok);
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        let samples = b9_histogram_samples(
            &snap,
            "hort_api_token_validation_duration_seconds",
            "expired",
        );
        assert_eq!(samples.len(), 1);
        assert!(samples[0] > 0.0);

        // revoked
        let spy = CountingVerifier::new(true);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, tokens, users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let user_id = Uuid::new_v4();
                users.insert(fixture_user(user_id, true));
                let mut tok = fixture_token(user_id, "aaaaaaaa");
                tok.revoked_at = Some(t0());
                tokens.insert("aaaaaaaa", tok);
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        let samples = b9_histogram_samples(
            &snap,
            "hort_api_token_validation_duration_seconds",
            "revoked",
        );
        assert_eq!(samples.len(), 1);
        assert!(samples[0] > 0.0);

        // user_deactivated
        let spy = CountingVerifier::new(true);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, tokens, users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let user_id = Uuid::new_v4();
                users.insert(fixture_user(user_id, false)); // inactive
                tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        let samples = b9_histogram_samples(
            &snap,
            "hort_api_token_validation_duration_seconds",
            "user_deactivated",
        );
        assert_eq!(samples.len(), 1);
        assert!(samples[0] > 0.0);
    }

    // -- cardinality discipline -----------------------------------------

    #[test]
    fn validation_duration_label_set_is_exactly_result() {
        let spy = CountingVerifier::new(false);
        let snap = capture_async({
            let spy = spy.clone();
            move || async move {
                let (uc, _tokens, _users, _store, _cache, _clock) =
                    make_uc(spy as Arc<dyn Argon2Verifier>);
                let _ = uc.validate_pat(VALID_TOKEN, Some(ip())).await;
            }
        });
        let keys =
            b9_collect_histogram_label_keys(&snap, "hort_api_token_validation_duration_seconds");
        let expected: std::collections::BTreeSet<String> =
            ["result".to_string()].into_iter().collect();
        assert_eq!(
            keys, expected,
            "hort_api_token_validation_duration_seconds label set MUST be exactly {{result}}"
        );
        for forbidden in [
            "token_id",
            "user_id",
            "repo_id",
            "repository_name",
            "scope_string",
            "cache",
        ] {
            assert!(
                !keys.contains(forbidden),
                "forbidden label `{forbidden}` MUST NOT appear on \
                 hort_api_token_validation_duration_seconds"
            );
        }
    }

    // -- result-mapping table coverage ----------------------------------

    #[test]
    fn validation_duration_result_label_table_is_exhaustive() {
        // Pin the result-mapping. Mirrors ValidationMetric except
        // there is no `cache` distinction; an Infrastructure error
        // collapses to its own bucket.
        use PatValidationError::*;
        let ok: Result<ApiTokenValidation, _> = Ok(ApiTokenValidation {
            token_id: Uuid::nil(),
            user_id: Uuid::nil(),
            kind: TokenKind::Pat,
            token_cap: TokenCap {
                permissions: vec![],
                repository_ids: None,
            },
            expires_at: None,
            revoked_at: None,
        });
        assert_eq!(validation_duration_result_label(&ok), "success");
        let exp: Result<ApiTokenValidation, _> = Err(Expired);
        assert_eq!(validation_duration_result_label(&exp), "expired");
        let rev: Result<ApiTokenValidation, _> = Err(Revoked);
        assert_eq!(validation_duration_result_label(&rev), "revoked");
        let dea: Result<ApiTokenValidation, _> = Err(UserDeactivated);
        assert_eq!(validation_duration_result_label(&dea), "user_deactivated");
        let pnf: Result<ApiTokenValidation, _> = Err(PrefixNotFound);
        assert_eq!(validation_duration_result_label(&pnf), "prefix_not_found");
        let hm: Result<ApiTokenValidation, _> = Err(HashMismatch);
        assert_eq!(validation_duration_result_label(&hm), "hash_mismatch");
        let rl: Result<ApiTokenValidation, _> = Err(RateLimited);
        assert_eq!(validation_duration_result_label(&rl), "rate_limited");
        let infra: Result<ApiTokenValidation, _> =
            Err(Infrastructure(DomainError::Invariant("x".into())));
        assert_eq!(
            validation_duration_result_label(&infra),
            "infrastructure_error"
        );
    }

    // =================================================================
    // Throttled per-(token, date) token-use audit emit
    //
    // Mirrors the download-audit test module in
    // `artifact_use_case.rs`. Pins: cache-MISS emits; cache-HIT emits
    // (the audit-gap guard — the common path must not be a blind
    // spot); every failure path emits nothing; throttle → exactly one
    // append, 2nd ⇒ `throttled` metric; throttle-store Err ⇒
    // fail-open append + warn; append Err ⇒ `validate_pat` still Ok +
    // `append_error` metric + `hort_api_token_validation_total`
    // unaffected; gate unwired ⇒ Ok + no append; stream-shape
    // assertions; `as_str()` catalog-string pin. The
    // verify-exactly-once / constant-time tests above are UNCHANGED
    // and still pass (the emit is in the wrapper, after the duration
    // metric, and never touches the verifier).
    // =================================================================
    mod token_use_audit_b13 {
        use super::*;
        use crate::event_store_publisher::{wrap_for_test, EventStorePublisher};
        use crate::use_cases::test_support::MockEventStore;
        use hort_domain::events::{
            Actor, DomainEvent, InternalActor, StreamCategory, StreamId as DStreamId,
        };
        use hort_domain::ports::event_store::{
            AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
        };

        /// Build a validator wired to `publisher` (or unwired when
        /// `None`), with one planted user+token that validates `Ok`.
        /// Returns the use case + the planted `token_id` / `user_id`
        /// + the ephemeral store handle (for throttle-key inspection).
        #[allow(clippy::type_complexity)]
        fn harness(
            publisher: Option<Arc<EventStorePublisher>>,
        ) -> (PatValidationUseCase, Uuid, Uuid, Arc<MockEphemeralStore>) {
            let tokens = MockTokenRepo::new();
            let users = MockUserRepo::new();
            let ephemeral = MockEphemeralStore::new();
            let clock = MockClock::at(t0().timestamp());
            let cache = Arc::new(PatCache::new_with_clock(
                16,
                Duration::from_secs(300),
                Box::new(clock.clone()),
            ));
            let user_id = Uuid::new_v4();
            users.insert(fixture_user(user_id, true));
            let tok = fixture_token(user_id, "aaaaaaaa");
            let token_id = tok.id;
            tokens.insert("aaaaaaaa", tok);
            let mut uc = PatValidationUseCase::new_with_verifier(
                tokens as Arc<dyn ApiTokenRepository>,
                users as Arc<dyn UserRepository>,
                ephemeral.clone() as Arc<dyn EphemeralStore>,
                cache,
                CountingVerifier::new(true) as Arc<dyn Argon2Verifier>,
                Arc::new(clock) as Arc<dyn Clock>,
                PatLockoutConfig::DEFAULT,
            );
            if let Some(p) = publisher {
                uc = uc.with_audit_events(p);
            }
            (uc, token_id, user_id, ephemeral)
        }

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Runtime::new().unwrap()
        }

        /// Counter value of `hort_api_token_used_audit_dropped{result}`
        /// in a `metrics_util` snapshot (0 if absent). `DebugValue`
        /// is not `Clone`, so we read the count out by reference —
        /// same shape as the B5b `snap_value` helper above.
        fn dropped_count(
            snap: &[(
                CompositeKey,
                Option<metrics::Unit>,
                Option<metrics::SharedString>,
                DebugValue,
            )],
            result: &str,
        ) -> u64 {
            for (key, _u, _d, value) in snap {
                if key.kind() != MetricKind::Counter {
                    continue;
                }
                if key.key().name() != "hort_api_token_used_audit_dropped" {
                    continue;
                }
                let matches_result = key
                    .key()
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == result);
                if matches_result {
                    if let DebugValue::Counter(v) = value {
                        return *v;
                    }
                }
            }
            0
        }

        #[test]
        fn cache_miss_success_emits_one_token_used_event() {
            let events = Arc::new(MockEventStore::new());
            let publisher = wrap_for_test(events.clone());
            let (uc, token_id, user_id, _eph) = harness(Some(publisher));

            rt().block_on(async {
                // First call → cache MISS → DB path → Ok.
                let v = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
                assert_eq!(v.token_id, token_id);
            });

            let batches = events.appended_batches();
            assert_eq!(batches.len(), 1, "exactly one audit batch on cache miss");
            let batch = &batches[0];

            // Stream-shape assertions.
            assert_eq!(batch.expected_version, ExpectedVersion::Any);
            assert_eq!(batch.stream_id.category, StreamCategory::TokenUse);
            // NEVER the token-owner's `User` lifecycle stream, nor an
            // artifact stream.
            assert_ne!(
                batch.stream_id,
                DStreamId::user(user_id),
                "must NOT be the token-owner User lifecycle stream"
            );
            assert_ne!(batch.stream_id, DStreamId::artifact(token_id));
            // Batch recorder is system; subject rides the payload.
            assert!(matches!(
                batch.actor,
                Actor::Internal(InternalActor::System)
            ));
            assert_eq!(batch.events.len(), 1);
            match &batch.events[0].event {
                DomainEvent::ApiTokenUsed(e) => {
                    assert_eq!(e.token_id, token_id);
                    assert_eq!(e.user_id, user_id);
                    assert_eq!(e.kind, TokenKind::Pat);
                    // The stream is sharded on the payload's
                    // server-wall-clock `occurred_at` date (the emit
                    // uses real `chrono::Utc::now()`, mirroring B12 —
                    // NOT the injected MockClock).
                    assert_eq!(
                        batch.stream_id,
                        DStreamId::token_use(token_id, e.occurred_at.date_naive()),
                        "per-(token_id, UTC-date) stream"
                    );
                }
                other => panic!("expected ApiTokenUsed, got {other:?}"),
            }
        }

        #[test]
        fn cache_hit_success_also_emits_no_audit_blind_spot() {
            // The common cache-hit path MUST NOT be an audit blind
            // spot. The throttle is per-token: a fresh harness per
            // call would re-win, so we instead clear the throttle key
            // between the two calls to isolate the cache-hit emit.
            let events = Arc::new(MockEventStore::new());
            let publisher = wrap_for_test(events.clone());
            let (uc, token_id, _user_id, eph) = harness(Some(publisher));

            rt().block_on(async {
                // 1st: cache MISS → emits (wins throttle).
                uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
                // Clear the throttle so the 2nd emit is attributable
                // purely to "cache hit still emits", not throttle.
                eph.delete(&format!("{TOKEN_USE_AUDIT_THROTTLE_PREFIX}{token_id}"))
                    .await
                    .unwrap();
                // 2nd: cache HIT (no verify) → MUST still emit.
                uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
            });

            let batches = events.appended_batches();
            assert_eq!(
                batches.len(),
                2,
                "cache-hit path must also emit (no audit blind spot)"
            );
            for b in &batches {
                assert_eq!(b.stream_id.category, StreamCategory::TokenUse);
            }
        }

        #[test]
        fn throttle_engaged_second_use_within_window_does_not_append() {
            let events = Arc::new(MockEventStore::new());
            let publisher = wrap_for_test(events.clone());
            let (uc, _t, _u, _e) = harness(Some(publisher));

            let snap = capture_async({
                move || async move {
                    // 1st wins the per-token 1-hour throttle.
                    uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
                    // 2nd within the window → throttled, no append.
                    uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
                }
            });

            assert_eq!(
                events.appended_batches().len(),
                1,
                "exactly one append; the 2nd use is throttled"
            );
            // The throttled drop counter fired exactly once.
            assert_eq!(
                dropped_count(&snap, "throttled"),
                1,
                "exactly one throttled drop"
            );
            // ...and the append_error counter never fired.
            assert_eq!(dropped_count(&snap, "append_error"), 0);
        }

        #[test]
        fn throttle_store_error_is_fail_open_appends_anyway() {
            // An EphemeralStore that errors on `put_if_absent` → the
            // throttle check fails; B13 is fail-open: append proceeds.
            struct ThrottleErrEphemeral;
            impl EphemeralStore for ThrottleErrEphemeral {
                fn get(&self, _k: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
                    Box::pin(async { Ok(None) })
                }
                fn put(
                    &self,
                    _k: &str,
                    _v: Bytes,
                    _t: Duration,
                ) -> BoxFuture<'_, DomainResult<()>> {
                    Box::pin(async { Ok(()) })
                }
                fn put_if_absent(
                    &self,
                    _k: &str,
                    _v: Bytes,
                    _t: Duration,
                ) -> BoxFuture<'_, DomainResult<bool>> {
                    Box::pin(async { Err(DomainError::Invariant("throttle store down".into())) })
                }
                fn compare_and_swap(
                    &self,
                    _k: &str,
                    _v: u64,
                    _nv: Bytes,
                    _t: Duration,
                ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
                    Box::pin(async { Ok(None) })
                }
                fn delete(&self, _k: &str) -> BoxFuture<'_, DomainResult<()>> {
                    Box::pin(async { Ok(()) })
                }
                fn extend_ttl(&self, _k: &str, _t: Duration) -> BoxFuture<'_, DomainResult<()>> {
                    Box::pin(async { Ok(()) })
                }
            }

            let tokens = MockTokenRepo::new();
            let users = MockUserRepo::new();
            let clock = MockClock::at(t0().timestamp());
            let cache = Arc::new(PatCache::new_with_clock(
                16,
                Duration::from_secs(300),
                Box::new(clock.clone()),
            ));
            let user_id = Uuid::new_v4();
            users.insert(fixture_user(user_id, true));
            tokens.insert("aaaaaaaa", fixture_token(user_id, "aaaaaaaa"));
            let events = Arc::new(MockEventStore::new());
            let uc = PatValidationUseCase::new_with_verifier(
                tokens as Arc<dyn ApiTokenRepository>,
                users as Arc<dyn UserRepository>,
                Arc::new(ThrottleErrEphemeral) as Arc<dyn EphemeralStore>,
                cache,
                CountingVerifier::new(true) as Arc<dyn Argon2Verifier>,
                Arc::new(clock) as Arc<dyn Clock>,
                PatLockoutConfig::DEFAULT,
            )
            .with_audit_events(wrap_for_test(events.clone()));

            rt().block_on(async {
                // Validation still Ok (the brute-force lockout `get`
                // returns None; the throttle `put_if_absent` errors
                // only inside the best-effort emit).
                uc.validate_pat(VALID_TOKEN, None).await.unwrap();
            });
            assert_eq!(
                events.appended_batches().len(),
                1,
                "throttle-store Err is fail-open: append proceeds"
            );
        }

        /// Append-failing `EventStore` stub (B12 `FailingAppendEventStore`
        /// shape).
        struct FailingAppendEventStore;
        impl EventStore for FailingAppendEventStore {
            fn append(&self, _b: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
                Box::pin(async { Err(DomainError::Invariant("event-store outage".into())) })
            }
            fn read_stream(
                &self,
                _s: &DStreamId,
                _f: ReadFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
                Box::pin(async { unreachable!("validate_pat never reads streams") })
            }
            fn read_category(
                &self,
                _c: StreamCategory,
                _f: SubscribeFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
                Box::pin(async { unreachable!() })
            }
            fn delete_stream(&self, _s: DStreamId) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
            fn archive_stream(&self, _s: DStreamId, _t: &str) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
        }

        #[test]
        fn append_error_is_fail_open_validation_still_ok_metric_fires() {
            let publisher = Arc::new(EventStorePublisher::without_broadcast(Arc::new(
                FailingAppendEventStore,
            )));
            let (uc, _t, user_id, _e) = harness(Some(publisher));

            let snap = capture_async({
                move || async move {
                    // Fail-open: validation MUST still return Ok.
                    let v = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
                    assert_eq!(v.user_id, user_id);
                }
            });

            // The fail-open drop counter fired with result=append_error.
            assert_eq!(
                dropped_count(&snap, "append_error"),
                1,
                "exactly one append_error drop"
            );
            // ...and it was NOT throttled (the throttle was won).
            assert_eq!(dropped_count(&snap, "throttled"), 0);
            // `hort_api_token_validation_total` is UNAFFECTED by the
            // audit append failure — the success counter still fired.
            assert_eq!(snap_value(&snap, "success", "miss"), 1);
        }

        #[test]
        fn no_append_on_validation_failure_prefix_not_found() {
            // A failed validation is NOT a use → emits nothing.
            let events = Arc::new(MockEventStore::new());
            let publisher = wrap_for_test(events.clone());
            // No token planted → PrefixNotFound (still wires the gate).
            let tokens = MockTokenRepo::new();
            let users = MockUserRepo::new();
            let ephemeral = MockEphemeralStore::new();
            let clock = MockClock::at(t0().timestamp());
            let cache = Arc::new(PatCache::new_with_clock(
                16,
                Duration::from_secs(300),
                Box::new(clock.clone()),
            ));
            let uc = PatValidationUseCase::new_with_verifier(
                tokens as Arc<dyn ApiTokenRepository>,
                users as Arc<dyn UserRepository>,
                ephemeral as Arc<dyn EphemeralStore>,
                cache,
                CountingVerifier::new(false) as Arc<dyn Argon2Verifier>,
                Arc::new(clock) as Arc<dyn Clock>,
                PatLockoutConfig::DEFAULT,
            )
            .with_audit_events(publisher);

            rt().block_on(async {
                let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
                assert!(matches!(err, PatValidationError::PrefixNotFound));
            });
            assert!(
                events.appended_batches().is_empty(),
                "a failed validation is not a use — no ApiTokenUsed"
            );
        }

        #[test]
        fn no_append_on_rate_limited_validation() {
            // RateLimited is an Err → emits nothing.
            let events = Arc::new(MockEventStore::new());
            let publisher = wrap_for_test(events.clone());
            let (uc, _t, _u, eph) = harness(Some(publisher));
            let bucket = client_ip_bucket(ip());
            rt().block_on(async {
                eph.put(
                    &format!("{PAT_LOCKOUT_BY_IP_FLAG_PREFIX}{bucket}"),
                    Bytes::from_static(b"1"),
                    Duration::from_secs(900),
                )
                .await
                .unwrap();
                let err = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap_err();
                assert!(matches!(err, PatValidationError::RateLimited));
            });
            assert!(
                events.appended_batches().is_empty(),
                "rate-limited is not a use — no ApiTokenUsed"
            );
        }

        #[test]
        fn gate_unwired_validation_ok_and_no_append() {
            // No `.with_audit_events` → the emit logic short-circuits;
            // validation still works.
            let (uc, token_id, _u, _e) = harness(None);
            rt().block_on(async {
                let v = uc.validate_pat(VALID_TOKEN, Some(ip())).await.unwrap();
                assert_eq!(v.token_id, token_id);
            });
            // Nothing to assert on the (absent) event store — the
            // point is `validate_pat` returned Ok with no panic and
            // no gate.
        }

        #[test]
        fn drop_result_as_str_is_catalogued() {
            assert_eq!(ApiTokenUsedAuditDropResult::Throttled.as_str(), "throttled");
            assert_eq!(
                ApiTokenUsedAuditDropResult::AppendError.as_str(),
                "append_error"
            );
        }
    }
}
