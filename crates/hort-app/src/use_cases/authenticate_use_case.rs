//! # AuthenticateUseCase
//!
//! JIT user provisioning + principal construction.
//!
//! Single inbound entry point:
//!
//! - [`AuthenticateUseCase::authenticate_bearer`] — OIDC / registry-JWT /
//!   native-PAT. Validates the token via the [`IdentityProvider`] or
//!   [`PatValidationUseCase`] port, resolves (or JIT-creates) the user row,
//!   recomputes `is_admin` from the current group claim, persists via
//!   `upsert_on_login`, and returns a [`CallerPrincipal`] whose resolved
//!   claim set is derived by `resolve_claims` (ADR 0012) plus the
//!   synthetic `admin` claim via `add_admin_claim_if_admin`.
//!
//! There is no `authenticate_local` HTTP-Basic-against-local-admin-row
//! identity path (removed end-to-end; commit `320df574`).
//! Failure audit-event recording stays
//! on [`AuthenticateUseCase::record_auth_failure`], called from the
//! inbound bearer middleware on every 401-shaped reject.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use tracing::instrument;
use uuid::Uuid;

use hort_domain::entities::api_token::TokenKind;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::ClaimMapping;
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::events::{
    system_actor, AdminStatusChanged, AuthenticationAttempted, DomainEvent, StreamId,
};
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::user_repository::UserRepository;

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    client_ip_bucket, emit_auth_event, emit_is_admin_transition, AuthEventResult,
    IsAdminTransitionResult,
};
use crate::rbac::{add_admin_claim_if_admin, resolve_claims};
use crate::use_cases::pat_validation_use_case::{
    parse_pat_token_format, PatValidationError, PatValidationUseCase,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The synthetic `admin` claim string (ADR 0012).
/// A `claim_mappings` entry resolving to this exact string, OR a
/// `user.is_admin=true` bit (via [`add_admin_claim_if_admin`]), grants
/// the evaluator's lowercase-`"admin"` short-circuit (see
/// `crate::rbac::RbacEvaluator::authorize`). Under the earlier role
/// model this was the admin *role* string; the value is unchanged
/// (`"admin"`) so the OIDC `is_admin` derivation and the evaluator
/// short-circuit stay single-sourced across the rename.
///
/// `pub` because
/// `OciTokenExchangeUseCase::exchange` builds a synthetic `CallerPrincipal`
/// for `/v2/auth` PAT-bearing callers and seeds the synthetic `admin`
/// claim from the live `User.is_admin` bit, mirroring the
/// `authenticate_pat` derivation. Sharing this constant keeps the
/// admin-claim wire string single-sourced.
pub const ADMIN_ROLE: &str = "admin";

/// Auth-event audit gate.
///
/// `AuthenticateUseCase` holds an `Option<AuthEventGate>` so legacy /
/// test deployments that wire no event store keep working with the
/// audit-event logic short-circuited. The gate bundles the event-store
/// handle for `append` and the ephemeral-store handle for the throttle
/// (the throttle key is `auth:event:throttle:{result}:{ip_bucket}`,
/// 60s TTL, `put_if_absent` semantics). See
/// [`maybe_append_auth_event`] for the helper's full contract.
struct AuthEventGate {
    events: Arc<EventStorePublisher>,
    ephemeral: Arc<dyn EphemeralStore>,
}

/// Window-size for the per-`(client_ip_bucket, result)` audit-event
/// throttle. One append wins the window; the rest tick the
/// `hort_auth_events_appended_total{result="throttled"}` counter. 60s
/// matches the design-doc §3.4 "info-rate-equivalent" target —
/// operators need a strong-enough signal to alert on but not so dense
/// the events table fills with attacker-driven noise.
const AUTH_EVENT_THROTTLE_TTL: Duration = Duration::from_secs(60);

/// Best-effort, throttled append of an [`AuthenticationAttempted`]
/// event.
///
/// **Throttle.** The first call within a 60s window for a given
/// `(client_ip_bucket, result)` tuple wins; the rest are suppressed
/// and tick `hort_auth_events_appended_total{result="throttled"}`. The
/// throttle key is built from the *bucketed* IP (`/24` IPv4 / `/48`
/// IPv6 — see [`crate::metrics::client_ip_bucket`]) so an attacker
/// cannot mint arbitrary keys per request and exhaust ephemeral
/// memory. The RAW IP — not the bucket — lives in the event payload,
/// because the audit value belongs in the durable record.
///
/// **Best-effort.** Event-store errors do NOT propagate to the
/// caller. Authentication must continue to return its originating
/// 401 regardless of whether the audit log succeeded — the audit
/// trail is "as-good-as-it-can-be", not "must-succeed-before-401".
/// Errors are recorded as
/// `hort_auth_events_appended_total{result="error"}` and a `warn!`.
pub async fn maybe_append_auth_event(
    events: &dyn EventStore,
    ephemeral: &dyn EphemeralStore,
    event: AuthenticationAttempted,
) {
    let throttle_key = format!(
        "auth:event:throttle:{}:{}",
        event.result,
        client_ip_bucket(event.client_ip)
    );
    let was_first = match ephemeral
        .put_if_absent(
            &throttle_key,
            Bytes::from_static(b"1"),
            AUTH_EVENT_THROTTLE_TTL,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            // Ephemeral failure is operator-actionable but must not
            // block auth. Treat as "throttle unavailable, fail open"
            // — appending continues, never silently dropped — and
            // surface a `warn!` for SREs.
            tracing::warn!(
                error = %e,
                "auth event throttle check failed; proceeding without throttle"
            );
            true
        }
    };
    if !was_first {
        emit_auth_event(AuthEventResult::Throttled);
        tracing::debug!(
            result = %event.result,
            "auth event throttle engaged; suppressing append"
        );
        return;
    }
    let stream_id = StreamId::auth_attempts(event.at.date_naive());
    let domain_event = DomainEvent::AuthenticationAttempted(event);
    let batch = AppendEvents {
        stream_id,
        expected_version: ExpectedVersion::Any,
        events: vec![EventToAppend::new(domain_event)],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
    };
    match events.append(batch).await {
        Ok(_) => {
            emit_auth_event(AuthEventResult::Appended);
        }
        Err(e) => {
            emit_auth_event(AuthEventResult::Error);
            tracing::warn!(
                error = %e,
                "auth event append failed; auth path continues unaffected"
            );
        }
    }
}

/// Best-effort append of an [`AdminStatusChanged`] audit event plus
/// the `hort_is_admin_transition_total{result}` metric.
///
/// **No mechanism rewrite.** The OIDC login path still recomputes
/// `is_admin`
/// from the IdP `groups` claim and persists it via `upsert_on_login`
/// on *every* OIDC login — that path is untouched. This helper runs
/// *after* the persist succeeds and only when an **existing** user
/// row's prior `is_admin` actually differs from the recomputed value:
/// it makes a spurious flip (transient IdP outage / empty-groups
/// response — audit F-35) auditable without altering the persistence.
///
/// **Emission discipline.**
/// - `previous_is_admin == None` (JIT-provisioned user, no prior
///   durable bit) → silent. There is no transition, only an initial
///   value; the stream records flips of durable rows, not first
///   logins.
/// - `Some(prev)` with `prev == current` (idempotent recompute, the
///   common case — admins stay admins) → silent.
/// - `Some(prev)` with `prev != current` → emit the metric (`granted`
///   when `false → true`, `revoked` when `true → false`) and
///   best-effort append the event to the **per-user** stream.
///
/// **Best-effort.** Mirrors [`maybe_append_auth_event`]: an
/// event-store error does NOT propagate — the OIDC login still returns
/// its principal. Unlike the auth-failure path there is no throttle: a
/// persisted-admin flip is rare and *every* flip is audit-worthy (a
/// throttle could swallow exactly the spurious flip F-35 is about).
///
/// **Tracing.** `info!` (audit-style state change), never `err` — a
/// flip is an authority event, not an infrastructure error.
async fn maybe_emit_admin_transition(
    audit_events: Option<&AuthEventGate>,
    user_id: Uuid,
    external_id: &str,
    previous_is_admin: Option<bool>,
    current_is_admin: bool,
) {
    let Some(prev) = previous_is_admin else {
        return;
    };
    if prev == current_is_admin {
        return;
    }

    let result = if current_is_admin {
        IsAdminTransitionResult::Granted
    } else {
        IsAdminTransitionResult::Revoked
    };
    emit_is_admin_transition(result);
    tracing::info!(
        user_id = %user_id,
        result = result.as_str(),
        "persisted is_admin bit flipped on OIDC login (audit F-35)"
    );

    // The metric + the `info!` are unconditional once a flip is
    // observed. The durable event is best-effort — it requires a wired
    // event store, exactly like the auth-failure audit trail.
    let Some(gate) = audit_events else {
        return;
    };
    let event = AdminStatusChanged {
        user_id,
        external_id: sanitize_external_id(external_id),
        granted: current_is_admin,
        at: Utc::now(),
    };
    let batch = AppendEvents {
        stream_id: StreamId::user(user_id),
        expected_version: ExpectedVersion::Any,
        events: vec![EventToAppend::new(DomainEvent::AdminStatusChanged(event))],
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: system_actor(),
    };
    if let Err(e) = gate.events.append(batch).await {
        tracing::warn!(
            error = %e,
            "is_admin-transition audit append failed; OIDC login unaffected"
        );
    }
}

/// Construct a closed-taxonomy failure-result string from the supplied
/// raw `result` label.
///
/// Identity for known values (every `local_*` / `oidc_*` label this
/// codebase emits today); falls back to the supplied string verbatim.
/// This indirection exists so a future closed-enum refactor can land
/// without touching every emission site. Accepted
/// as-is: this is a metric-label closed-enum indirection, NOT an
/// actor-attribution gap — the call sites pass the same `&'static str`
/// they emit on the metric label, already drawn from a closed taxonomy
/// enforced at the catalog. A future label-enum refactor is optional.
pub fn auth_result_label(raw: &str) -> String {
    raw.to_string()
}

/// Helper used by `hort-http-core` to assemble an
/// [`AuthenticationAttempted`] from the auth-middleware classification
/// site. Lives here so the failure-classification labels and the
/// throttle helper stay co-located — neither side of the boundary
/// owns the audit shape independently.
pub fn build_auth_event(
    client_ip: IpAddr,
    result: &str,
    external_id_if_decoded: Option<&str>,
) -> AuthenticationAttempted {
    AuthenticationAttempted {
        client_ip,
        result: auth_result_label(result),
        external_id_if_decoded: external_id_if_decoded.map(sanitize_external_id),
        at: Utc::now(),
    }
}

/// Strip control characters from an attacker-supplied external-id
/// string before it lands in the event payload.
///
/// The local-auth path passes the raw username it was probed with —
/// useful as audit evidence ("which identities is the attacker
/// trying"), but the username is attacker-controlled. Dropping
/// control bytes (anything below 0x20 plus DEL) prevents log /
/// JSON-payload injection without altering the human-readable
/// portion of legitimate identifiers.
fn sanitize_external_id(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(512)
        .collect::<String>()
}

// ---------------------------------------------------------------------------
// AuthenticateUseCase
// ---------------------------------------------------------------------------

/// Application service that turns a bearer token or Local credential pair
/// into a validated [`CallerPrincipal`].
///
/// Construction injects the [`IdentityProvider`] port implementation (e.g.
/// the OIDC adapter in production, a deterministic mock in tests), the
/// [`UserRepository`] port, and the startup-loaded `ClaimMapping` config.
/// The use case owns neither transport concerns (extracting the header,
/// shaping HTTP responses) nor authorization (that's the `RbacEvaluator`
/// callsite in each handler).
pub struct AuthenticateUseCase {
    /// `Some` when an OIDC `IdentityProvider` is wired (production
    /// `HORT_AUTH_PROVIDER=oidc` path). `None` under
    /// `HORT_AUTH_PROVIDER=disabled` with native tokens enabled —
    /// `authenticate_bearer` still validates `Bearer hort_<kind>_*` PATs
    /// via the PAT validator; OIDC-shaped tokens fail with
    /// [`AppError::Unauthorized`] instead of being routed to a
    /// non-existent validator.
    idp: Option<Arc<dyn IdentityProvider>>,
    users: Arc<dyn UserRepository>,
    /// The operator-declared IdP-group → claim mapping
    /// snapshot (ADR 0012). Only
    /// the OIDC happy path consults this — per the
    /// `docs/auth-catalog.md` Entry 1 statement that OIDC bearer is the
    /// **only** mechanism that resolves `claim_mappings`. Native-token
    /// kinds (PAT / CliSession / ServiceAccount / Refresh) flow through
    /// `authenticate_pat` and never touch this field.
    claim_mappings: Vec<ClaimMapping>,
    /// Optional audit-event gate for
    /// failure paths. `None` means no audit (legacy / single-binary
    /// tests); production wires this via [`Self::with_audit_events`]
    /// in the composition root.
    audit_events: Option<AuthEventGate>,
    /// Optional native-API-token validator.
    /// `Some(_)` when `HORT_NATIVE_TOKENS_ENABLED=true`, wired by
    /// `composition.rs` with the cache, repo, ephemeral store, and
    /// argon2 verifier. `None` short-circuits the PAT branch so a
    /// `Bearer hort_<kind>_<body>` token under the disabled flag falls
    /// straight through to the OIDC validator (which rejects with
    /// `OidcValidationError::Malformed` — same 401 the unknown-prefix
    /// path produces).
    pat_validation: Option<Arc<PatValidationUseCase>>,
    /// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL`
    /// switch threaded onto `authenticate_pat`'s success path so the
    /// emitted `hort_service_account_authenticated_total{service_account}`
    /// label collapses to `_all` when the operator turns the toggle
    /// off. Defaults to `true` (the right posture for
    /// operator-declared SA counts <50).
    include_service_account_label: bool,
    /// CliSession access-token JWT verifier (ADR 0013).
    ///
    /// `Some(_)` whenever the CliSession credential is in play (auth
    /// enabled — CliSession tokens are minted via the OIDC `/exchange`
    /// flow). On the bearer path, a token that verifies as a CliSession
    /// JWT (correct issuer + CliSession `aud` + `token_kind` claim)
    /// builds a principal carrying the JWT's resolved claims (the §13
    /// footgun fix). A non-CliSession AK-JWT (e.g. an OCI `/v2/auth`
    /// token, wrong `aud`) falls through to the OIDC validator (→ 401),
    /// so it can never replay against the CliSession-gated surfaces.
    cli_session_verifier: Option<Arc<crate::cli_session_signing::CliSessionTokenSigner>>,
    /// The durable `jti` emergency-revocation
    /// denylist (`cli-session-revoked:{jti}`). Consulted on every
    /// CliSession-JWT validate: a revoked `jti` → 401 *before* the
    /// token's `exp` (the server-side immediate-revocation layer the JWT
    /// is otherwise missing). `Some(_)` is wired alongside
    /// `cli_session_verifier`. **Fail-closed**: a wired verifier with an
    /// unreachable denylist denies rather than admitting a possibly-
    /// revoked token (mirrors the federation replay-guard posture).
    cli_session_revocation_denylist: Option<Arc<dyn EphemeralStore>>,
}

impl AuthenticateUseCase {
    /// Build a new use case with an OIDC [`IdentityProvider`] wired.
    ///
    /// `claim_mappings` is the declarative YAML-loaded config snapshot
    /// (ADR 0012). It is held by value (cheap clone of
    /// `Vec<ClaimMapping>`); hot-reload is not supported.
    pub fn new(
        idp: Arc<dyn IdentityProvider>,
        users: Arc<dyn UserRepository>,
        claim_mappings: Vec<ClaimMapping>,
    ) -> Self {
        Self {
            idp: Some(idp),
            users,
            claim_mappings,
            audit_events: None,
            pat_validation: None,
            // Default `true` keeps every existing
            // `AuthenticateUseCase::new(..)` caller source-compatible.
            include_service_account_label: true,
            cli_session_verifier: None,
            cli_session_revocation_denylist: None,
        }
    }

    /// Build a use case for the local-only auth path
    /// (`HORT_AUTH_PROVIDER=disabled` with `HORT_NATIVE_TOKENS_ENABLED=true`).
    /// No OIDC `IdentityProvider` is required — `authenticate_bearer` will
    /// reject OIDC-shaped tokens with [`AppError::Unauthorized`] and route
    /// `Bearer hort_<kind>_*` shapes to the PAT validator.
    ///
    /// There is no HTTP-Basic-against-
    /// local-admin-row bootstrap path; the supported minimal-setup
    /// recipe is `admin issue-svc-token` + `hort-cli auth login
    /// --paste`.
    pub fn new_local_only(
        users: Arc<dyn UserRepository>,
        claim_mappings: Vec<ClaimMapping>,
    ) -> Self {
        Self {
            idp: None,
            users,
            claim_mappings,
            audit_events: None,
            pat_validation: None,
            include_service_account_label: true,
            cli_session_verifier: None,
            cli_session_revocation_denylist: None,
        }
    }

    /// Wire the CliSession access-token JWT
    /// verifier + its `jti` emergency-revocation denylist (ADR 0013).
    ///
    /// Builder-style opt-in mirroring [`Self::with_pat_validation`]: the
    /// composition root calls this iff auth is enabled (CliSession
    /// tokens are minted via the OIDC `/exchange` flow, which needs an
    /// IdP). The verifier and the denylist are wired together — the
    /// denylist is the server-side immediate-revocation layer the signed
    /// JWT otherwise lacks.
    pub fn with_cli_session_verification(
        mut self,
        verifier: Arc<crate::cli_session_signing::CliSessionTokenSigner>,
        revocation_denylist: Arc<dyn EphemeralStore>,
    ) -> Self {
        self.cli_session_verifier = Some(verifier);
        self.cli_session_revocation_denylist = Some(revocation_denylist);
        self
    }

    /// Flip the
    /// `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL` toggle on the PAT
    /// success path. Composition root threads
    /// `Config::include_service_account_label` here so a single env
    /// var governs both this counter and the rotation gauge.
    pub fn with_include_service_account_label(mut self, include: bool) -> Self {
        self.include_service_account_label = include;
        self
    }

    /// Wire the native-API-token validator so
    /// `authenticate_bearer` routes `hort_<kind>_<body>`-shaped tokens
    /// to [`PatValidationUseCase::validate_pat`] BEFORE falling through
    /// to the OIDC port. Composition root opts in iff
    /// `HORT_NATIVE_TOKENS_ENABLED=true`; legacy / OIDC-only deployments
    /// keep the no-op shape (`pat_validation = None`).
    ///
    /// Builder pattern matches [`Self::with_audit_events`] — every
    /// existing `AuthenticateUseCase::new(..)` call site remains
    /// unchanged.
    pub fn with_pat_validation(mut self, pat_validation: Arc<PatValidationUseCase>) -> Self {
        self.pat_validation = Some(pat_validation);
        self
    }

    /// Enable audit-event appends on failure paths.
    ///
    /// Wires the [`EventStore`] handle for `append` and the
    /// [`EphemeralStore`] handle for the per-`(client_ip_bucket,
    /// result)` 60s throttle. Failures classified by the inbound
    /// bearer middleware (`record_auth_failure` call sites in
    /// `hort-http-core::middleware::auth`) produce one
    /// [`AuthenticationAttempted`] event per throttle window —
    /// best-effort, errors never propagate to the caller. Successes
    /// do NOT produce events (tracing-only for the
    /// success volume).
    ///
    /// Builder shape keeps every plain
    /// `AuthenticateUseCase::new(..)` call site compiling unchanged;
    /// only the production composition root opts in.
    pub fn with_audit_events(
        mut self,
        events: Arc<EventStorePublisher>,
        ephemeral: Arc<dyn EphemeralStore>,
    ) -> Self {
        self.audit_events = Some(AuthEventGate { events, ephemeral });
        self
    }

    /// Append an audit event for an authentication failure.
    ///
    /// Best-effort, throttled.
    /// Callable from inbound-HTTP middleware ([`require_principal`] /
    /// [`extract_optional_principal`] in `hort-http-core`) AND from
    /// the use case's own failure paths so every failure emits one
    /// event regardless of which side classified it.
    ///
    /// No-op when [`Self::with_audit_events`] was never called or
    /// when `client_ip` is `None` (transports that genuinely have no
    /// peer — currently unused in production but kept symmetric for
    /// in-process test surfaces). Errors never propagate to the
    /// caller; the auth path returns its originating outcome
    /// regardless of whether the audit log succeeded.
    pub async fn record_auth_failure(
        &self,
        client_ip: Option<IpAddr>,
        result: &str,
        external_id_if_decoded: Option<&str>,
    ) {
        let Some(gate) = &self.audit_events else {
            return;
        };
        let Some(client_ip) = client_ip else {
            return;
        };
        let event = build_auth_event(client_ip, result, external_id_if_decoded);
        maybe_append_auth_event(gate.events.as_ref(), gate.ephemeral.as_ref(), event).await;
    }

    /// OIDC / registry-JWT entry point.
    ///
    /// Dispatches the token to the [`IdentityProvider`] port, JIT-provisions
    /// the user on first login, refreshes `last_login_at` / `username` /
    /// `email` on subsequent logins, and **recomputes `is_admin` from the
    /// current group claim on every call**. A user removed from the admin
    /// group loses admin immediately on their next login — the group claim
    /// is the source of truth, not the stale DB row.
    ///
    /// # Tracing
    ///
    /// `#[instrument(skip(self, token))]` — the token value is NEVER logged.
    /// On success, emits `info!` with `user_id`, `auth_provider = "oidc"`,
    /// and `jit_created = true` iff the user row was newly inserted.
    #[instrument(skip(self, token))]
    pub async fn authenticate_bearer(&self, token: &str) -> AppResult<CallerPrincipal> {
        // Legacy entry-point preserved for OIDC-only
        // callers that have no `client_ip` to thread (in-process tests,
        // bootstrap CLI, etc.). Delegates to the client-IP-aware path
        // with `None`, which makes the PAT validator's per-IP lockout
        // a no-op. Production middleware uses
        // [`Self::authenticate_bearer_with_client_ip`] so the lockout
        // keys on the bucketed source.
        self.authenticate_bearer_with_client_ip(token, None).await
    }

    /// Bearer-auth entry-point that routes
    /// `Bearer hort_<kind>_<body>`-shaped tokens to the native-API-token
    /// validator before falling through to the OIDC port.
    ///
    /// **Routing.** When `pat_validation` is wired AND
    /// [`parse_pat_token_format`] succeeds, the token is dispatched to
    /// [`PatValidationUseCase::validate_pat`]. Every typed
    /// [`PatValidationError`] arm collapses to a generic
    /// [`AppError::Unauthorized`] so the wire shape is byte-identical
    /// to an OIDC failure (the auth middleware's 401 + JSON envelope).
    /// `Infrastructure(_)` propagates unchanged so an adapter outage
    /// surfaces as 5xx, not a silent 401.
    ///
    /// **Live re-resolution.** On success, the principal's `roles` /
    /// `groups` come from a fresh `find_by_id` lookup + group-mapping
    /// resolution against the current snapshot —
    /// token cap is fixed at issuance, user grants
    /// re-resolve on every call. The token's [`TokenCap`] is carried
    /// onto the principal via `token_cap = Some(_)`, which the cap-
    /// intersection in `RbacEvaluator::authorize` consumes (ADR 0012).
    ///
    /// **Fallback.** A token whose shape is NOT a PAT prefix, OR whose
    /// PAT branch was disabled (`pat_validation = None`), falls
    /// through to the OIDC port — same behaviour as a PAT-less
    /// deployment.
    #[instrument(skip(self, token, client_ip))]
    pub async fn authenticate_bearer_with_client_ip(
        &self,
        token: &str,
        client_ip: Option<IpAddr>,
    ) -> AppResult<CallerPrincipal> {
        // ----------------------------------------------------------------
        // PAT branch — routed on parse-success alone. A malformed
        // `hort_*_*` shape (wrong length, bad base32 body) flows to the
        // OIDC port, which returns `OidcValidationError::Malformed` →
        // the same 401 the PAT-prefix-not-found branch produces.
        // Routing on the parse result instead of the literal `hort_`
        // prefix preserves the observable shape for malformed inputs
        // without paying the Argon2 cost on what is structurally not a
        // PAT.
        //
        // A parse-success PAT-shape token MUST NOT
        // fall through to OIDC — JWT-shape and PAT-shape are
        // disjoint, and feeding a PAT to the OIDC validator produces
        // a misleading "InvalidToken" error that sent operators on a
        // wild-goose chase debugging Keycloak when the real issue was
        // the auth-pipeline routing. When `pat_validation` is unwired
        // (`HORT_NATIVE_TOKENS_ENABLED=false`) but a PAT-shape token
        // arrives — typically because `HORT_TOKEN_EXCHANGE_ENABLED=true`
        // is minting `hort_cli_*` tokens with no validator behind them
        // — log the misconfiguration and reject cleanly. The
        // boot-time gate (config `TokenExchangeRequiresNativeTokens`)
        // is the primary defence; this branch is the runtime canary
        // that catches anyone who managed to bypass it.
        if parse_pat_token_format(token).is_ok() {
            let Some(pat_uc) = &self.pat_validation else {
                tracing::error!(
                    "PAT-shape bearer token received but PatValidationUseCase \
                     is not wired — server-side misconfiguration. The \
                     boot-time gate requires \
                     HORT_NATIVE_TOKENS_ENABLED=true whenever \
                     HORT_TOKEN_EXCHANGE_ENABLED=true; if you are seeing this, \
                     verify the config layer is enforcing the gate."
                );
                return Err(AppError::Unauthorized(
                    "native-token validator not configured".to_string(),
                ));
            };
            return self
                .authenticate_pat(pat_uc.as_ref(), token, client_ip)
                .await;
        }

        // ----------------------------------------------------------------
        // CliSession access-token JWT branch (ADR 0013).
        //
        // A CliSession token is a registry-signed JWT,
        // NOT an `hort_cli_*` shape, so it falls past the PAT
        // branch above. Try the CliSession verifier BEFORE the OIDC
        // fallthrough: a token that verifies as a CliSession JWT
        // (correct issuer + CliSession `aud` + `token_kind` claim) yields
        // a principal carrying the JWT's RESOLVED claim set — the §13
        // footgun fix.
        //
        // Discriminator (§13.4): the OCI `/v2/auth` token and the
        // CliSession token share the issuer + signing key, so
        // issuer/signature alone do NOT separate them. The verifier
        // gates on the CliSession `aud` + `token_kind`; a non-CliSession
        // AK-JWT (OCI scope) is `NotOurToken` and falls through to OIDC
        // (→ 401), so it can never replay against the CliSession-gated
        // surfaces.
        if let Some(verifier) = self.cli_session_verifier.as_ref() {
            use crate::cli_session_signing::{CliSessionRejection, CliSessionVerifyOutcome};
            match verifier.verify(token) {
                CliSessionVerifyOutcome::Verified(claims) => {
                    return self.build_cli_session_principal(*claims).await;
                }
                CliSessionVerifyOutcome::Rejected(reason) => {
                    // Structurally-ours but invalid (expired / wrong
                    // token_kind). Reject (401) — do NOT fall through to
                    // OIDC (an expired CliSession token must 401, not be
                    // re-tried as an IdP token). `info!` audit, not `err`.
                    let detail = match reason {
                        CliSessionRejection::Expired => "expired",
                        CliSessionRejection::WrongTokenKind => "wrong_token_kind",
                    };
                    tracing::info!(
                        result = "invalid_token",
                        token_kind = "cli_session",
                        reason = detail,
                        "auth attempt: cli-session JWT rejected"
                    );
                    return Err(AppError::Unauthorized(format!(
                        "cli session token invalid: {detail}"
                    )));
                }
                // Not a CliSession-family token (bad signature, wrong
                // `aud` — e.g. an OCI token, or simply an IdP JWT).
                // Fall through to the OIDC validator below.
                CliSessionVerifyOutcome::NotOurToken => {}
            }
        }

        // Local-only mode (no IdP wired): refuse OIDC-shaped tokens
        // with a clean Unauthorized rather than a misleading 500. The
        // PAT branch above is still wired when `pat_validation` is
        // set, so service-account `hort_*_*` tokens continue to work.
        let Some(idp) = self.idp.as_ref() else {
            tracing::info!(
                client_ip = ?client_ip,
                "OIDC bearer token received but no IdentityProvider is wired \
                 (HORT_AUTH_PROVIDER=disabled, local-only mode); rejecting"
            );
            return Err(AppError::Unauthorized(
                "OIDC bearer rejected: no identity provider configured \
                 (this server is running in local-only auth mode — use \
                 HTTP Basic against a local admin row, or a Bearer \
                 hort_<kind>_* native token)"
                    .to_string(),
            ));
        };
        let claims = idp.validate_token(token).await?;

        // Resolve the operator-declared claim set from the
        // IdP `groups` claim (ADR 0012). `is_admin` is derived from the
        // *resolved*
        // set BEFORE the synthetic-admin step: deriving it before keeps
        // the persisted
        // bit tracking the IdP admin claim; deriving it after would make
        // every is_admin-by-bit user also admin-by-mapping, collapsing
        // the distinction the invariant relies on.
        let mut resolved = resolve_claims(&self.claim_mappings, &claims.groups);
        let is_admin = resolved.iter().any(|c| c == ADMIN_ROLE);
        add_admin_claim_if_admin(&mut resolved, is_admin);

        let existing = self
            .users
            .find_by_external_id(AuthProvider::Oidc, &claims.subject)
            .await?;
        let jit_created = existing.is_none();
        // Snapshot the prior persisted
        // bit BEFORE the `match` moves `existing`. `None` for a
        // JIT-provisioned user (no prior durable row) so the
        // transition helper stays silent on first login; `Some(prev)`
        // for an existing row so a flip against `is_admin` is
        // detectable. The persist mechanism below is unchanged.
        let previous_is_admin = existing.as_ref().map(|u| u.is_admin);

        let now = Utc::now();
        let draft = match existing {
            Some(user) => User {
                // Preserve identity fields the claim doesn't own.
                id: user.id,
                auth_provider: AuthProvider::Oidc,
                external_id: Some(claims.subject.clone()),
                display_name: user.display_name,
                is_service_account: user.is_service_account,
                is_active: user.is_active,
                created_at: user.created_at,
                // Refresh from claim.
                username: claims.username.clone(),
                email: claims.email.clone(),
                // Admin is recomputed from current group claim every login
                // (design §7) — DB row is NOT the source of truth.
                is_admin,
                last_login_at: Some(now),
                updated_at: now,
            },
            None => User {
                id: Uuid::new_v4(),
                username: claims.username.clone(),
                email: claims.email.clone(),
                auth_provider: AuthProvider::Oidc,
                external_id: Some(claims.subject.clone()),
                display_name: None,
                is_active: true,
                is_admin,
                is_service_account: false,
                last_login_at: Some(now),
                created_at: now,
                updated_at: now,
            },
        };

        let upserted = self.users.upsert_on_login(&draft).await?;

        // Observability only, AFTER the
        // persist confirmed. Emits the metric + best-effort
        // `AdminStatusChanged` audit event iff an existing row's
        // `is_admin` actually flipped; JIT-create and idempotent
        // recompute are silent (see `maybe_emit_admin_transition`).
        maybe_emit_admin_transition(
            self.audit_events.as_ref(),
            upserted.id,
            &claims.subject,
            previous_is_admin,
            upserted.is_admin,
        )
        .await;

        if jit_created {
            tracing::info!(
                user_id = %upserted.id,
                auth_provider = "oidc",
                jit_created = true,
                "user authenticated"
            );
        } else {
            tracing::info!(
                user_id = %upserted.id,
                auth_provider = "oidc",
                "user authenticated"
            );
        }

        Ok(CallerPrincipal {
            user_id: upserted.id,
            external_id: claims.subject,
            username: upserted.username,
            email: upserted.email,
            // The resolved claim set (claim_mappings +
            // synthetic `admin`).
            claims: resolved,
            // OIDC-bearer principals are not native-token
            // kind discriminated; the token-kind carrier is `None`.
            token_kind: None,
            issued_at: Utc::now(),
            // OIDC-validated principals do not carry a native API token cap.
            // `token_cap = None` ⇒ cap leg returns true and
            // the user-grants leg is the sole authority gate.
            token_cap: None,
        })
    }

    /// Native-API-token (PAT/svc/cli) bearer
    /// authentication. Called by
    /// [`Self::authenticate_bearer_with_client_ip`] when the token
    /// shape parses as `hort_(pat|svc|cli)_[a-z2-7]{32}` AND
    /// `pat_validation` is wired.
    ///
    /// On `Ok(validation)`: re-resolve the user row (live
    /// deactivation, claim recomputation),
    /// build a [`CallerPrincipal`] carrying the validated cap.
    /// The claim set is the synthetic
    /// `admin` (when `user.is_admin`) or empty — `claim_mappings` is
    /// never consulted on this path (ADR 0012).
    ///
    /// On `Err(PatValidationError)`: every variant except
    /// `Infrastructure` collapses to [`AppError::Unauthorized`] so
    /// the wire shape is byte-identical to an OIDC failure (the
    /// auth middleware emits the same 401 envelope). The
    /// `Infrastructure` variant propagates as `AppError::Domain` so
    /// an adapter outage surfaces as 5xx.
    async fn authenticate_pat(
        &self,
        pat_uc: &PatValidationUseCase,
        token: &str,
        client_ip: Option<IpAddr>,
    ) -> AppResult<CallerPrincipal> {
        let validation = match pat_uc.validate_pat(token, client_ip).await {
            Ok(v) => v,
            Err(err) => return Err(map_pat_error(err)),
        };

        // Live re-resolution.
        // Token cap is fixed at issuance (carried via
        // `validation.token_cap` below); the user's grants re-resolve
        // every call so deactivating a role drops the token's
        // effective authority on the next request.
        let user = self.users.find_by_id(validation.user_id).await?;
        // PATs (and ALL native-token kinds: CliSession / ServiceAccount /
        // Refresh, since every one of them validates through this single
        // path) intentionally carry only the synthetic `admin` claim
        // (when `user.is_admin=true`). They do NOT consult
        // `claim_mappings` (ADR 0012).
        // The right way to grant non-admin authority to a
        // native-token user (incl. a ServiceAccount, whose
        // `claims` is therefore always `[]` — admin SA is forbidden at
        // gitops apply time, ADR 0018) is a direct
        // `PermissionGrant { subject: User(user.id), .. }` row, never a
        // foreign-JWT `groups` claim run through `claim_mappings`.
        let mut claims = Vec::new();
        add_admin_claim_if_admin(&mut claims, user.is_admin);
        // Token-kind discrimination rides
        // the typed `CallerPrincipal.token_kind`
        // carrier (set at the construction site below), never marker
        // claim strings. The match is
        // retained ONLY for the SA-metric side-effect;
        // it is exhaustive (no `_` arm) so a future `TokenKind` variant
        // is a compile error here — forward-compat by construction.
        match validation.kind {
            TokenKind::Pat | TokenKind::CliSession => {}
            TokenKind::ServiceAccount => {
                // Bump
                // `hort_service_account_authenticated_total` on the
                // PAT branch for service-account-kind tokens. The
                // SA name is the backing `users.username` with the
                // `sa:` prefix stripped (the apply use case writes
                // `username = "sa:" || sa.name`).
                // A SA-kind token whose owner username carries no
                // `sa:` prefix falls back to the full username —
                // shouldn't happen (the apply path is
                // the only writer), but guards against historical
                // rows produced by `hort-cli admin token issue --kind
                // svc` before the gitops surface existed.
                let sa_label = user
                    .username
                    .strip_prefix("sa:")
                    .unwrap_or(user.username.as_str());
                crate::metrics::emit_service_account_authenticated(
                    sa_label,
                    crate::metrics::SA_AUTH_SOURCE_PAT,
                    self.include_service_account_label,
                );
            }
        }

        // TODO(token-last-used): debounced `update_last_used` is
        // deliberately not wired — it is operator UX
        // (last-seen attribution in the admin token-list view), not a
        // security primitive. The intended debounce
        // window is 5 min per token. When wired, this is the natural
        // hook point: a fire-and-forget `tokio::spawn` enqueueing
        // `(token_id, at, client_ip, user_agent)` onto a ring buffer
        // drained by a background task that calls
        // `ApiTokenRepository::update_last_used` at most once per
        // 5 min per token. The `last_used_*` columns + the bucketed-IP
        // / 256-byte-UA truncation already exist on the adapter,
        // so the debounce is the only missing piece.
        tracing::info!(
            user_id = %user.id,
            token_id = %validation.token_id,
            auth_provider = "native_api_token",
            "user authenticated"
        );

        Ok(CallerPrincipal {
            user_id: user.id,
            external_id: user
                .external_id
                .clone()
                .unwrap_or_else(|| user.id.to_string()),
            username: user.username,
            email: user.email,
            // At most one element (`admin`) via this
            // path; `[]` for a non-admin native-token user.
            claims,
            // Typed token-kind carrier (never marker
            // claim strings). `authenticate_pat` is the
            // single validation path for every native-token kind, so the
            // discriminator is always `Some(_)` here.
            token_kind: Some(validation.kind),
            issued_at: Utc::now(),
            // The cap is the AND-intersect leg of
            // RbacEvaluator::authorize. Cap-bound principals carry
            // `Some(cap)`; OIDC / Local-session principals carry `None`
            // and the user-grants leg is the sole authority gate.
            token_cap: Some(validation.token_cap),
        })
    }

    /// Build a [`CallerPrincipal`] from a
    /// verified CliSession access-token JWT (ADR 0013).
    ///
    /// Steps:
    /// 1. **`jti` denylist check (fail-closed).** Consult the durable
    ///    `cli-session-revoked:{jti}` denylist. A present key ⇒ the
    ///    token was emergency-revoked ⇒ 401 *before* its `exp`. A
    ///    denylist *outage* (read error) ⇒ deny rather than admit a
    ///    possibly-revoked token (the AK-side immediate-revocation layer
    ///    is the whole point of the denylist; admitting on outage would
    ///    re-open the regression the denylist exists to close).
    /// 2. **Live user re-resolution.** `find_by_id` so a deactivated
    ///    user is rejected on the next request even though the JWT is
    ///    still cryptographically valid (mirrors the PAT path's live
    ///    re-resolution; §8 invariant 2).
    /// 3. **Principal build.** The principal's `claims` = the JWT's
    ///    resolved claim set (the §13 footgun fix — a CliSession now
    ///    authorizes `GrantSubject::Claims` grants), `token_kind =
    ///    Some(CliSession)`, `token_cap = None` (authority is claims +
    ///    live grants, not a per-token permission cap).
    async fn build_cli_session_principal(
        &self,
        claims: crate::cli_session_signing::CliSessionClaims,
    ) -> AppResult<CallerPrincipal> {
        // 1. Emergency-revocation denylist (fail-closed).
        let Some(denylist) = self.cli_session_revocation_denylist.as_ref() else {
            // Verifier wired without a denylist is a composition bug —
            // fail CLOSED (do not admit an unrevocable token).
            tracing::error!(
                "cli-session verifier wired without a revocation denylist — \
                 composition bug; failing closed"
            );
            return Err(AppError::Unauthorized(
                "cli session revocation denylist not configured".to_string(),
            ));
        };
        let revoke_key = format!("cli-session-revoked:{}", claims.jti);
        match denylist.get(&revoke_key).await {
            Ok(Some(_)) => {
                tracing::info!(
                    result = "invalid_token",
                    token_kind = "cli_session",
                    reason = "revoked",
                    jti = %claims.jti,
                    "auth attempt: revoked cli-session JWT rejected"
                );
                return Err(AppError::Unauthorized(
                    "cli session token revoked".to_string(),
                ));
            }
            Ok(None) => { /* not revoked — proceed */ }
            Err(e) => {
                // Fail-closed: the denylist could not be consulted, so
                // we cannot prove the token is NOT revoked. Deny.
                tracing::warn!(
                    error = %e,
                    token_kind = "cli_session",
                    "cli-session revocation denylist unavailable — failing closed"
                );
                return Err(AppError::Unauthorized(
                    "cli session revocation check unavailable".to_string(),
                ));
            }
        }

        // 2. Live user re-resolution (deactivation honored).
        let user = self.users.find_by_id(claims.sub).await?;
        if !user.is_active {
            tracing::info!(
                result = "invalid_token",
                token_kind = "cli_session",
                reason = "user_deactivated",
                user_id = %user.id,
                "auth attempt: cli-session JWT for deactivated user rejected"
            );
            return Err(AppError::Unauthorized("user deactivated".to_string()));
        }

        tracing::info!(
            user_id = %user.id,
            auth_provider = "cli_session_jwt",
            claim_count = claims.claims.len(),
            "user authenticated"
        );

        // 3. Build the principal carrying the JWT's RESOLVED claims.
        Ok(CallerPrincipal {
            user_id: user.id,
            external_id: user
                .external_id
                .clone()
                .unwrap_or_else(|| user.id.to_string()),
            username: user.username,
            email: user.email,
            // The IdP-resolved claim set carried IN the
            // token (NOT `[]`): a CliSession authorizes claim-subject
            // grants, unlike PAT/SA. The token-kind discriminator stays
            // the typed `token_kind` field, never a claim string.
            claims: claims.claims,
            token_kind: Some(TokenKind::CliSession),
            issued_at: Utc::now(),
            // CliSession authority = claims + live grants; no cap leg.
            token_cap: None,
        })
    }
}

/// Collapse [`PatValidationError`] variants
/// onto [`AppError`] so the auth middleware emits a single 401
/// envelope for every typed PAT failure.
///
/// Mapping table:
///
/// | `PatValidationError`       | `AppError`                       | Wire status |
/// |----------------------------|----------------------------------|-------------|
/// | `RateLimited`              | `Unauthorized("rate limited")`   | 401         |
/// | `PrefixNotFound`           | `Unauthorized("prefix not found")` | 401       |
/// | `HashMismatch`             | `Unauthorized("hash mismatch")`  | 401         |
/// | `Expired`                  | `Unauthorized("token expired")`  | 401         |
/// | `Revoked`                  | `Unauthorized("token revoked")`  | 401         |
/// | `UserDeactivated`          | `Unauthorized("user deactivated")` | 401       |
/// | `Infrastructure(domain)`   | `Domain(domain)` (verbatim)      | 5xx         |
///
/// `RateLimited` collapses to `Unauthorized` rather than a separate
/// 429 envelope so the wire shape stays byte-identical across every
/// PAT-failure variant — the operator-visible signal is the metric
/// `hort_api_token_validation_total{result="rate_limited"}`, not a
/// distinguishable status code (the §5 lockout's purpose is to mask
/// brute-force attribution from the caller). Operators can still
/// route on the metric label; clients see the same 401 they'd see for
/// a forged token.
fn map_pat_error(err: PatValidationError) -> AppError {
    match err {
        PatValidationError::Infrastructure(domain) => AppError::Domain(domain),
        PatValidationError::RateLimited => AppError::Unauthorized("rate limited".into()),
        PatValidationError::PrefixNotFound => AppError::Unauthorized("prefix not found".into()),
        PatValidationError::HashMismatch => AppError::Unauthorized("hash mismatch".into()),
        PatValidationError::Expired => AppError::Unauthorized("token expired".into()),
        PatValidationError::Revoked => AppError::Unauthorized("token revoked".into()),
        PatValidationError::UserDeactivated => AppError::Unauthorized("user deactivated".into()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::{TimeZone, Utc};

    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::user::AuthProvider;
    use hort_domain::ports::identity_provider::IdpClaims;

    use crate::use_cases::test_support::{MockIdentityProvider, MockUserRepository};

    // -- fixtures ----------------------------------------------------------

    fn sample_claims(sub: &str, groups: Vec<String>) -> IdpClaims {
        IdpClaims {
            subject: sub.into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            groups,
            issued_at: Utc.with_ymd_and_hms(2026, 4, 19, 12, 0, 0).unwrap(),
        }
    }

    /// Claim-mapping fixture.
    /// `admins` → the synthetic-equivalent `admin`
    /// claim; `team-alpha` → `developer`. `managed_by` is `Gitops` (the
    /// production source for these rows); `managed_by_digest` is `None`
    /// (not load-bearing for resolution — `resolve_claims` only reads
    /// `idp_group` + `claim`).
    fn admin_mapping() -> Vec<ClaimMapping> {
        vec![
            ClaimMapping {
                id: Uuid::new_v4(),
                idp_group: "admins".into(),
                claim: "admin".into(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: None,
            },
            ClaimMapping {
                id: Uuid::new_v4(),
                idp_group: "team-alpha".into(),
                claim: "developer".into(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: None,
            },
        ]
    }

    fn make_use_case(
        mappings: Vec<ClaimMapping>,
    ) -> (
        AuthenticateUseCase,
        Arc<MockIdentityProvider>,
        Arc<MockUserRepository>,
    ) {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let uc = AuthenticateUseCase::new(
            idp.clone() as Arc<dyn IdentityProvider>,
            users.clone() as Arc<dyn UserRepository>,
            mappings,
        );
        (uc, idp, users)
    }

    // -- CliSession JWT validate path ----------------------------------------

    use crate::cli_session_signing::CliSessionTokenSigner;
    use crate::oci_token_signing::OciTokenSigningKey;

    fn cli_session_rig() -> (Arc<CliSessionTokenSigner>, Arc<MockEphemeralStore>) {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let key = Arc::new(OciTokenSigningKey::new(sk, None));
        let signer = Arc::new(CliSessionTokenSigner::new(
            key,
            "https://hort.test".to_string(),
        ));
        (signer, Arc::new(MockEphemeralStore::new()))
    }

    /// A use case wired with the CliSession verifier + denylist, plus a
    /// seeded user row matching `sub`.
    fn make_cli_session_use_case(
        sub: Uuid,
    ) -> (
        AuthenticateUseCase,
        Arc<CliSessionTokenSigner>,
        Arc<MockEphemeralStore>,
        Arc<MockUserRepository>,
    ) {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        users.insert(User {
            id: sub,
            username: "dev-user".into(),
            email: "dev@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("keycloak:dev".into()),
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: false,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let (signer, denylist) = cli_session_rig();
        let uc = AuthenticateUseCase::new(
            idp.clone() as Arc<dyn IdentityProvider>,
            users.clone() as Arc<dyn UserRepository>,
            admin_mapping(),
        )
        .with_cli_session_verification(signer.clone(), denylist.clone() as Arc<dyn EphemeralStore>);
        (uc, signer, denylist, users)
    }

    fn exp_in(secs: i64) -> chrono::DateTime<Utc> {
        chrono::DateTime::<Utc>::from_timestamp(Utc::now().timestamp() + secs, 0).unwrap()
    }

    #[tokio::test]
    async fn authenticate_bearer_cli_session_jwt_carries_resolved_claims() {
        // §13 footgun fix (headline validate side): a CliSession JWT
        // builds a principal whose `claims` = the JWT's resolved claim
        // set (NOT `[]`), with `token_kind = Some(CliSession)`. This is
        // what lets a `GrantSubject::Claims([developer])` grant authorize
        // the CliSession-gated discovery/prefetch endpoints.
        let sub = Uuid::from_u128(0xD15C);
        let (uc, signer, _denylist, _users) = make_cli_session_use_case(sub);
        let jwt = signer
            .mint(sub, vec!["developer".into()], Uuid::new_v4(), exp_in(900))
            .expect("mint");

        let principal = uc.authenticate_bearer(&jwt).await.expect("verify");
        assert_eq!(principal.user_id, sub);
        assert_eq!(principal.claims, vec!["developer".to_string()]);
        assert_eq!(principal.token_kind, Some(TokenKind::CliSession));
        // No token cap — CliSession authority is claims + live grants
        // (the cap leg is None → the user-grants/claims leg gates).
        assert!(principal.token_cap.is_none());
    }

    #[tokio::test]
    async fn authenticate_bearer_cli_session_jwt_tamper_is_401() {
        let sub = Uuid::from_u128(0xD15C);
        let (uc, signer, _denylist, _users) = make_cli_session_use_case(sub);
        let mut jwt = signer
            .mint(sub, vec!["developer".into()], Uuid::new_v4(), exp_in(900))
            .expect("mint");
        let last = jwt.pop().unwrap();
        jwt.push(if last == 'A' { 'B' } else { 'A' });
        // A tampered CliSession JWT fails CliSession verify → falls
        // through to OIDC → rejected (the IdP mock doesn't know it).
        let err = uc.authenticate_bearer(&jwt).await.unwrap_err();
        assert!(
            matches!(err, AppError::OidcValidation(_) | AppError::Unauthorized(_)),
            "expected a 401-shaped error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_bearer_cli_session_jwt_wrong_issuer_falls_through() {
        // A CliSession JWT signed by a DIFFERENT key (wrong issuer) must
        // not validate — it falls through to OIDC and is rejected.
        let sub = Uuid::from_u128(0xD15C);
        let (uc, _signer, _denylist, _users) = make_cli_session_use_case(sub);
        let (attacker, _) = cli_session_rig();
        let forged = attacker
            .mint(sub, vec!["admin".into()], Uuid::new_v4(), exp_in(900))
            .expect("mint");
        let err = uc.authenticate_bearer(&forged).await.unwrap_err();
        assert!(matches!(
            err,
            AppError::OidcValidation(_) | AppError::Unauthorized(_)
        ));
    }

    #[tokio::test]
    async fn authenticate_bearer_revoked_cli_session_jti_is_rejected() {
        // §13.4 emergency revocation: a `jti` on the denylist → 401
        // BEFORE the token's `exp`, even though the signature is valid.
        let sub = Uuid::from_u128(0xD15C);
        let (uc, signer, denylist, _users) = make_cli_session_use_case(sub);
        let jti = Uuid::from_u128(0xBEEF);
        let jwt = signer
            .mint(sub, vec!["developer".into()], jti, exp_in(900))
            .expect("mint");
        // Pre-revocation: verifies fine.
        assert!(uc.authenticate_bearer(&jwt).await.is_ok());
        // Revoke the jti.
        denylist
            .put(
                &format!("cli-session-revoked:{jti}"),
                Bytes::from_static(b"1"),
                Duration::from_secs(900),
            )
            .await
            .unwrap();
        // Now rejected (Unauthorized), NOT fall-through to OIDC.
        let err = uc.authenticate_bearer(&jwt).await.unwrap_err();
        assert!(
            matches!(err, AppError::Unauthorized(_)),
            "revoked jti must 401, got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_bearer_cli_session_denylist_unavailable_fails_closed() {
        // §13.4 fail-closed: if the denylist cannot be read, deny rather
        // than admit a possibly-revoked token.
        let sub = Uuid::from_u128(0xD15C);
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        users.insert(User {
            id: sub,
            username: "dev-user".into(),
            email: "dev@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("keycloak:dev".into()),
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: false,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let (signer, _denylist) = cli_session_rig();
        let failing = Arc::new(FailingEphemeralStore);
        let uc = AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            admin_mapping(),
        )
        .with_cli_session_verification(signer.clone(), failing as Arc<dyn EphemeralStore>);
        let jwt = signer
            .mint(sub, vec!["developer".into()], Uuid::new_v4(), exp_in(900))
            .expect("mint");
        let err = uc.authenticate_bearer(&jwt).await.unwrap_err();
        assert!(
            matches!(err, AppError::Unauthorized(_) | AppError::Domain(_)),
            "denylist outage must fail closed, got {err:?}"
        );
    }

    /// An `EphemeralStore` whose every read fails — drives the
    /// fail-closed denylist branch.
    struct FailingEphemeralStore;
    impl EphemeralStore for FailingEphemeralStore {
        fn get(&self, _key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            Box::pin(async { Err(DomainError::Invariant("denylist down".into())) })
        }
        fn put(&self, _key: &str, _v: Bytes, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn put_if_absent(
            &self,
            _key: &str,
            _v: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn compare_and_swap(
            &self,
            _key: &str,
            _ev: u64,
            _nv: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            Box::pin(async { Ok(None) })
        }
        fn delete(&self, _key: &str) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -- Bearer: new user JIT ----------------------------------------------

    #[tokio::test]
    async fn authenticate_bearer_new_user_jit_creates_and_returns_principal() {
        let (uc, idp, users) = make_use_case(admin_mapping());
        let claims = sample_claims("keycloak:abc", vec!["team-alpha".into()]);
        idp.register_token("token-xyz", claims.clone());

        let principal = uc.authenticate_bearer("token-xyz").await.unwrap();

        // Principal carries claim data + resolved claim set.
        assert_eq!(principal.external_id, "keycloak:abc");
        assert_eq!(principal.username, "alice");
        assert_eq!(principal.email, "alice@example.com");
        // `team-alpha` resolves to the `developer` claim;
        // non-admin so no synthetic `admin`.
        assert_eq!(principal.claims, vec!["developer".to_string()]);
        // OIDC-bearer principals carry no token-kind marker.
        assert_eq!(principal.token_kind, None);
        assert!(!principal.user_id.is_nil());

        // User row persisted and discoverable by external_id.
        let persisted = users
            .find_by_external_id(AuthProvider::Oidc, "keycloak:abc")
            .await
            .unwrap();
        let persisted = persisted.expect("user was persisted");
        assert_eq!(persisted.id, principal.user_id);
        assert_eq!(persisted.auth_provider, AuthProvider::Oidc);
        assert_eq!(persisted.external_id.as_deref(), Some("keycloak:abc"));
        assert!(!persisted.is_admin, "developer group is not an admin group");
        assert!(persisted.last_login_at.is_some());
    }

    // -- Bearer: existing user refresh ------------------------------------

    #[tokio::test]
    async fn authenticate_bearer_existing_user_refreshes_and_returns_principal() {
        let (uc, idp, users) = make_use_case(admin_mapping());

        // Pre-existing OIDC user with stale email + stale last_login.
        let preexisting = User {
            id: Uuid::new_v4(),
            username: "old-name".into(),
            email: "old@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("keycloak:abc".into()),
            display_name: Some("Legacy Display".into()),
            is_active: true,
            is_admin: false,
            is_service_account: false,
            last_login_at: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            created_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        };
        let preexisting_id = preexisting.id;
        users.insert(preexisting);

        let claims = sample_claims("keycloak:abc", vec!["team-alpha".into()]);
        idp.register_token("tok", claims);

        let principal = uc.authenticate_bearer("tok").await.unwrap();

        // Same row, id preserved.
        assert_eq!(principal.user_id, preexisting_id);
        // Claim fields flowed into the row.
        let row = users.find_by_id(preexisting_id).await.unwrap();
        assert_eq!(row.username, "alice");
        assert_eq!(row.email, "alice@example.com");
        // last_login_at advanced.
        assert!(row.last_login_at.unwrap() > Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap());
        // Display name is not sourced from claims; preserved by the upsert mock.
        assert_eq!(row.display_name.as_deref(), Some("Legacy Display"));
    }

    // -- Bearer: invalid token --------------------------------------------

    #[tokio::test]
    async fn authenticate_bearer_invalid_token_surfaces_validation() {
        let (uc, _idp, _users) = make_use_case(admin_mapping());
        // No token registered → MockIdentityProvider returns
        // OidcValidationError::SignatureInvalid, which the use case
        // propagates as AppError::OidcValidation.
        let err = uc.authenticate_bearer("does-not-exist").await.unwrap_err();
        match err {
            AppError::OidcValidation(
                hort_domain::ports::identity_provider::OidcValidationError::SignatureInvalid,
            ) => {}
            other => panic!("expected OidcValidation(SignatureInvalid), got {other:?}"),
        }
    }

    // -- Bearer: admin group sets is_admin + admin role --------------------

    #[tokio::test]
    async fn authenticate_bearer_admin_group_sets_is_admin_and_admin_role() {
        let (uc, idp, users) = make_use_case(admin_mapping());
        idp.register_token(
            "admin-token",
            sample_claims("keycloak:admin", vec!["admins".into()]),
        );

        let principal = uc.authenticate_bearer("admin-token").await.unwrap();
        assert!(principal.claims.iter().any(|c| c == "admin"));

        let row = users.find_by_id(principal.user_id).await.unwrap();
        assert!(row.is_admin, "admin group must set is_admin on the DB row");
    }

    // -- Bearer: admin demotion ------------------------------------------

    #[tokio::test]
    async fn authenticate_bearer_admin_group_demotion() {
        let (uc, idp, users) = make_use_case(admin_mapping());

        // Pre-seed the row as admin. Next login drops the admin group from
        // the claim — the row MUST be demoted.
        let preexisting = User {
            id: Uuid::new_v4(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("keycloak:abc".into()),
            display_name: None,
            is_active: true,
            is_admin: true,
            is_service_account: false,
            last_login_at: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            created_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        };
        let preexisting_id = preexisting.id;
        users.insert(preexisting);

        // Claim now only has team-alpha — no admin group.
        idp.register_token(
            "tok",
            sample_claims("keycloak:abc", vec!["team-alpha".into()]),
        );

        let principal = uc.authenticate_bearer("tok").await.unwrap();

        assert!(
            !principal.claims.iter().any(|c| c == "admin"),
            "admin claim must not be resolved when admin group is absent"
        );

        let row = users.find_by_id(preexisting_id).await.unwrap();
        assert!(
            !row.is_admin,
            "DB row is_admin must be recomputed false when admin group is absent"
        );
    }

    // -- Bearer: is_admin-transition audit ------------------------------

    /// OIDC-capable use case wired with the audit-event gate, plus the
    /// mock handles each admin-transition test asserts against. Mirrors
    /// [`make_audit_use_case`] but for the OIDC bearer path (the
    /// recompute+persist site), not Local auth.
    fn make_oidc_audit_use_case() -> (
        AuthenticateUseCase,
        Arc<MockIdentityProvider>,
        Arc<MockUserRepository>,
        Arc<CapturingEventStore>,
    ) {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let ephemeral: Arc<MockEphemeralStore> = Arc::new(MockEphemeralStore::new());
        let events: Arc<CapturingEventStore> = Arc::new(CapturingEventStore::new());
        let uc = AuthenticateUseCase::new(
            idp.clone() as Arc<dyn IdentityProvider>,
            users.clone() as Arc<dyn UserRepository>,
            admin_mapping(),
        )
        .with_audit_events(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            ephemeral.clone() as Arc<dyn EphemeralStore>,
        );
        (uc, idp, users, events)
    }

    fn oidc_user(external_id: &str, is_admin: bool) -> User {
        User {
            id: Uuid::new_v4(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some(external_id.into()),
            display_name: None,
            is_active: true,
            is_admin,
            is_service_account: false,
            last_login_at: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            created_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        }
    }

    fn extract_admin_changed(batch: &AppendEvents) -> &AdminStatusChanged {
        match &batch.events[0].event {
            DomainEvent::AdminStatusChanged(e) => e,
            other => panic!("unexpected event variant: {other:?}"),
        }
    }

    fn admin_transition_results(snap: metrics_util::debugging::Snapshot) -> Vec<String> {
        let mut out = Vec::new();
        for (key, _, _, _) in snap.into_vec() {
            let inner = key.key();
            if inner.name() != "hort_is_admin_transition_total" {
                continue;
            }
            for label in inner.labels() {
                if label.key() == "result" {
                    out.push(label.value().to_string());
                }
            }
        }
        out
    }

    /// A `false → true` flip on an existing row emits the metric
    /// `result=granted` AND an `AdminStatusChanged{granted:true}`
    /// audit event on the per-user stream.
    #[test]
    fn admin_transition_granted_emits_event_and_metric() {
        let (uc, idp, users, events) = make_oidc_audit_use_case();
        let existing = oidc_user("keycloak:abc", false);
        let existing_id = existing.id;
        users.insert(existing);
        idp.register_token("tok", sample_claims("keycloak:abc", vec!["admins".into()]));

        let snap = capture_metrics(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    uc.authenticate_bearer("tok").await.unwrap();
                });
        });

        assert_eq!(admin_transition_results(snap), vec!["granted".to_string()]);

        let batches = events.captured();
        assert_eq!(batches.len(), 1, "exactly one audit append");
        let batch = &batches[0];
        assert_eq!(batch.stream_id.category, StreamCategory::User);
        assert_eq!(batch.stream_id.entity_id, existing_id);
        let event = extract_admin_changed(batch);
        assert_eq!(event.user_id, existing_id);
        assert_eq!(event.external_id, "keycloak:abc");
        assert!(event.granted, "false→true is a grant");
    }

    /// A `true → false` flip on an existing row emits the metric
    /// `result=revoked` AND an `AdminStatusChanged{granted:false}`.
    #[test]
    fn admin_transition_revoked_emits_event_and_metric() {
        let (uc, idp, users, events) = make_oidc_audit_use_case();
        let existing = oidc_user("keycloak:abc", true);
        let existing_id = existing.id;
        users.insert(existing);
        // No admin group this login — bit recomputes to false.
        idp.register_token(
            "tok",
            sample_claims("keycloak:abc", vec!["team-alpha".into()]),
        );

        let snap = capture_metrics(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    uc.authenticate_bearer("tok").await.unwrap();
                });
        });

        assert_eq!(admin_transition_results(snap), vec!["revoked".to_string()]);

        let batches = events.captured();
        assert_eq!(batches.len(), 1);
        let event = extract_admin_changed(&batches[0]);
        assert_eq!(event.user_id, existing_id);
        assert!(!event.granted, "true→false is a revoke");
    }

    /// An idempotent recompute that does NOT change the bit (admin
    /// stays admin) is silent — no metric, no event.
    #[test]
    fn admin_transition_no_flip_is_silent() {
        let (uc, idp, users, events) = make_oidc_audit_use_case();
        users.insert(oidc_user("keycloak:abc", true));
        // Admin group present again — bit recomputes to the same `true`.
        idp.register_token("tok", sample_claims("keycloak:abc", vec!["admins".into()]));

        let snap = capture_metrics(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    uc.authenticate_bearer("tok").await.unwrap();
                });
        });

        assert!(
            admin_transition_results(snap).is_empty(),
            "idempotent recompute must not emit the transition metric"
        );
        assert!(
            events.captured().is_empty(),
            "idempotent recompute must not append an audit event"
        );
    }

    /// A JIT-provisioned user (no prior durable row) is NOT a
    /// transition — first login sets an initial value, it does not
    /// flip a persisted bit. Silent even when the new bit is `true`.
    #[test]
    fn admin_transition_jit_create_is_silent() {
        let (uc, idp, _users, events) = make_oidc_audit_use_case();
        idp.register_token("tok", sample_claims("keycloak:new", vec!["admins".into()]));

        let snap = capture_metrics(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let p = uc.authenticate_bearer("tok").await.unwrap();
                    assert!(p.claims.iter().any(|c| c == "admin"));
                });
        });

        assert!(
            admin_transition_results(snap).is_empty(),
            "JIT-create is not a flip — no transition metric"
        );
        assert!(
            events.captured().is_empty(),
            "JIT-create must not append an AdminStatusChanged event"
        );
    }

    /// Best-effort: an event-store failure on the audit append does
    /// NOT fail the OIDC login, and the metric still fires (the metric
    /// is unconditional once a flip is observed; only the durable
    /// event is best-effort).
    #[test]
    fn admin_transition_event_store_failure_does_not_break_login() {
        let (uc, idp, users, events) = make_oidc_audit_use_case();
        users.insert(oidc_user("keycloak:abc", false));
        idp.register_token("tok", sample_claims("keycloak:abc", vec!["admins".into()]));
        events.arm_failure();

        let snap = capture_metrics(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    // Login still succeeds despite the audit append error.
                    let p = uc.authenticate_bearer("tok").await.unwrap();
                    assert!(p.claims.iter().any(|c| c == "admin"));
                });
        });

        assert_eq!(
            admin_transition_results(snap),
            vec!["granted".to_string()],
            "metric fires even when the durable append fails"
        );
        assert!(
            events.captured().is_empty(),
            "the armed-failure append captured nothing"
        );
    }

    // -- Shared utility cross-check --------------------------------------

    #[tokio::test]
    async fn resolve_claims_via_use_case_preserves_claim_mapping_semantics() {
        // The OIDC happy path's claim set equals
        // `resolve_claims` over the same mappings/groups, plus the
        // synthetic `admin` (the `admins` group resolves to the `admin`
        // claim here, so `add_admin_claim_if_admin` is idempotent and
        // adds nothing — pinning the no-double-admin invariant).
        let mappings = admin_mapping();
        let (uc, idp, _users) = make_use_case(mappings.clone());

        let groups = vec!["admins".to_string(), "team-alpha".to_string()];
        idp.register_token("t", sample_claims("keycloak:abc", groups.clone()));

        let principal = uc.authenticate_bearer("t").await.unwrap();
        // `admins` → "admin", `team-alpha` → "developer". is_admin is
        // derived from the resolved set (contains "admin"), so the
        // synthetic step is a no-op (idempotent — no duplicate "admin").
        let mut expected = resolve_claims(&mappings, &groups);
        let expected_is_admin = expected.iter().any(|c| c == "admin");
        add_admin_claim_if_admin(&mut expected, expected_is_admin);
        assert_eq!(principal.claims, expected);
        assert_eq!(
            principal.claims,
            vec!["admin".to_string(), "developer".to_string()]
        );
        // No duplicate synthetic admin even though `admins`→`admin`
        // mapping already produced it.
        assert_eq!(principal.claims.iter().filter(|c| *c == "admin").count(), 1);
    }

    // ---------------------------------------------------------------
    // OIDC happy path `principal.claims` resolution
    // ---------------------------------------------------------------
    //
    // Acceptance matrix:
    //   1. groups=[developer-team] + mapping{developers-team→developer}
    //      + is_admin=false → claims == ["developer"]
    //   2. same + is_admin (via admin group) → set-eq
    //      {developer, admin}
    //   3. groups=[] + admin group present (is_admin=true) →
    //      claims == ["admin"] (synthetic only)
    //   4. groups=[unknown-group] + is_admin=false → claims == []
    //
    // `user.is_admin` is NOT a pre-existing DB bit on the OIDC path: it
    // is recomputed from the resolved set every login (§5.2 as-built
    // ordering note). So "is_admin=true" is driven by the IdP returning
    // the `admins` group, which `admin_mapping()` maps to `admin`.

    /// One mapping pointing a single group at the `developer` claim,
    /// kept separate from `admin_mapping()` so cases 1/4 don't get the
    /// `admins`→`admin` row implicitly.
    fn developer_only_mapping() -> Vec<ClaimMapping> {
        vec![ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: "developers-team".into(),
            claim: "developer".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: None,
        }]
    }

    #[tokio::test]
    async fn oidc_claims_resolved_developer_non_admin() {
        // Case 1: developers-team → developer; not an admin group.
        let (uc, idp, users) = make_use_case(developer_only_mapping());
        idp.register_token("t", sample_claims("kc:dev", vec!["developers-team".into()]));

        let principal = uc.authenticate_bearer("t").await.unwrap();
        assert_eq!(principal.claims, vec!["developer".to_string()]);
        assert_eq!(principal.token_kind, None);
        // §6 invariant 3 — is_admin bit tracks the (absence of an)
        // admin claim.
        let row = users.find_by_id(principal.user_id).await.unwrap();
        assert!(!row.is_admin);
    }

    #[tokio::test]
    async fn oidc_claims_resolved_developer_and_admin_set_equal() {
        // Case 2: both `admins` (→admin) and `team-alpha` (→developer)
        // groups present. Order is implementation-defined; assert
        // set-equality per the backlog acceptance note.
        let (uc, idp, users) = make_use_case(admin_mapping());
        idp.register_token(
            "t",
            sample_claims("kc:both", vec!["admins".into(), "team-alpha".into()]),
        );

        let principal = uc.authenticate_bearer("t").await.unwrap();
        let got: std::collections::BTreeSet<&str> =
            principal.claims.iter().map(String::as_str).collect();
        let want: std::collections::BTreeSet<&str> = ["developer", "admin"].into_iter().collect();
        assert_eq!(got, want);
        // No duplicate `admin` (mapping produced it, synthesis is a
        // no-op).
        assert_eq!(principal.claims.iter().filter(|c| *c == "admin").count(), 1);
        let row = users.find_by_id(principal.user_id).await.unwrap();
        assert!(row.is_admin);
    }

    #[tokio::test]
    async fn oidc_claims_empty_groups_admin_user_gets_synthetic_admin_only() {
        // Case 3: no IdP groups, but the user is admin. The OIDC path
        // derives is_admin from the *resolved* set — with no groups the
        // resolved set is empty, so this exercises the synthetic-admin
        // path only when an `admins` group is present. To pin "empty
        // groups + is_admin=true → ['admin']" we drive is_admin via a
        // pre-existing admin DB row whose claim recompute yields [] then
        // synthesises `admin`… but the OIDC path RECOMPUTES is_admin
        // from groups (§5.2), so an empty-groups login is is_admin=FALSE
        // by construction. The faithful case-3 here is: the `admins`
        // group maps to `admin` and there is no other group, so the
        // resolved set is exactly ["admin"] (mapping-derived, and the
        // synthetic step is idempotent).
        let (uc, idp, users) = make_use_case(admin_mapping());
        idp.register_token("t", sample_claims("kc:admin", vec!["admins".into()]));

        let principal = uc.authenticate_bearer("t").await.unwrap();
        assert_eq!(principal.claims, vec!["admin".to_string()]);
        assert_eq!(principal.token_kind, None);
        let row = users.find_by_id(principal.user_id).await.unwrap();
        assert!(row.is_admin);
    }

    #[tokio::test]
    async fn oidc_claims_truly_empty_when_no_groups_and_not_admin() {
        // Case 3 corollary + the genuine empty-set shape: zero IdP
        // groups and no admin mapping hit → claims == [] and the
        // persisted is_admin bit is false (recomputed from the empty
        // resolved set per §5.2).
        let (uc, idp, users) = make_use_case(admin_mapping());
        idp.register_token("t", sample_claims("kc:none", vec![]));

        let principal = uc.authenticate_bearer("t").await.unwrap();
        assert!(principal.claims.is_empty());
        assert_eq!(principal.token_kind, None);
        let row = users.find_by_id(principal.user_id).await.unwrap();
        assert!(
            !row.is_admin,
            "empty IdP groups must recompute is_admin=false (§5.2)"
        );
    }

    #[tokio::test]
    async fn oidc_claims_unknown_group_resolves_empty() {
        // Case 4: a group with no matching ClaimMapping resolves to no
        // claims; non-admin → claims == [].
        let (uc, idp, users) = make_use_case(developer_only_mapping());
        idp.register_token("t", sample_claims("kc:ghost", vec!["unknown-group".into()]));

        let principal = uc.authenticate_bearer("t").await.unwrap();
        assert!(
            principal.claims.is_empty(),
            "unmapped group must resolve to no claims, got {:?}",
            principal.claims
        );
        assert_eq!(principal.token_kind, None);
        let row = users.find_by_id(principal.user_id).await.unwrap();
        assert!(!row.is_admin);
    }

    use crate::metrics::capture_metrics;
    use bytes::Bytes;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::BoxFuture;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::time::Instant;

    /// Minimal `EphemeralStore` impl backed by a `HashMap` and
    /// `tokio::time::Instant` for TTL. Exposes the methods the
    /// lockout gate actually calls; everything else is `unreachable!`.
    struct MockEphemeralStore {
        entries: Mutex<HashMap<String, (Bytes, Instant)>>,
        /// Latch that, when set, makes the NEXT `put_if_absent` call
        /// return `Err(...)` instead of consulting / mutating the map.
        /// Used by Item 16 tests to exercise the audit-event helper's
        /// fail-open branch (`maybe_append_auth_event` warns then
        /// proceeds when the throttle check itself fails). Resets
        /// itself after firing once.
        fail_next_put_if_absent: AtomicBool,
    }

    impl MockEphemeralStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                fail_next_put_if_absent: AtomicBool::new(false),
            }
        }

        /// Arm the latch — the next call to `put_if_absent` returns an
        /// `Err`. Mirrors `CapturingEventStore::arm_failure`'s shape so
        /// the test surface is symmetric across the two ports.
        fn arm_failure_on_next_put_if_absent(&self) {
            self.fail_next_put_if_absent.store(true, Ordering::SeqCst);
        }

        fn read_live(&self, key: &str) -> Option<Bytes> {
            let now = Instant::now();
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
            let expires_at = Instant::now() + ttl;
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
            if self.fail_next_put_if_absent.swap(false, Ordering::SeqCst) {
                return Box::pin(async {
                    Err(DomainError::Invariant(
                        "simulated ephemeral-store failure".into(),
                    ))
                });
            }
            let now = Instant::now();
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
            _key: &str,
            _expected_version: u64,
            _new_value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            unreachable!("lockout gate does not call compare_and_swap")
        }

        fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
            self.entries.lock().unwrap().remove(key);
            Box::pin(async { Ok(()) })
        }

        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("lockout gate does not call extend_ttl")
        }
    }

    // ---------------------------------------------------------------
    // auth-event audit trail tests
    // ---------------------------------------------------------------

    use hort_domain::events::{
        AuthenticationAttempted, DomainEvent, PersistedEvent, StreamCategory,
    };
    use hort_domain::ports::event_store::{
        AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicUsize;

    /// Minimal `EventStore` mock that captures every appended batch.
    /// Only the methods Item 16's helper invokes (`append`) actually
    /// do work; reads are stubbed.
    struct CapturingEventStore {
        batches: Mutex<Vec<AppendEvents>>,
        fail_next: AtomicBool,
        appends: AtomicUsize,
    }

    impl CapturingEventStore {
        fn new() -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                fail_next: AtomicBool::new(false),
                appends: AtomicUsize::new(0),
            }
        }

        fn arm_failure(&self) {
            self.fail_next.store(true, Ordering::SeqCst);
        }

        fn captured(&self) -> Vec<AppendEvents> {
            self.batches.lock().unwrap().clone()
        }

        fn append_count(&self) -> usize {
            self.appends.load(Ordering::SeqCst)
        }
    }

    impl EventStore for CapturingEventStore {
        fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            self.appends.fetch_add(1, Ordering::SeqCst);
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Box::pin(async {
                    Err(DomainError::Invariant("simulated event-store error".into()))
                });
            }
            self.batches.lock().unwrap().push(batch);
            Box::pin(async {
                Ok(AppendResult {
                    stream_position: 0,
                    global_positions: vec![0],
                })
            })
        }

        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn read_category(
            &self,
            _category: StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(vec![]) })
        }

        // Retention stubs: authenticate-test capture; retention paths
        // are unreachable from auth flow, panic on call.
        fn delete_stream(&self, _stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!("retention path unreachable from auth flow") })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!("retention path unreachable from auth flow") })
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn extract_auth_event(batch: &AppendEvents) -> &AuthenticationAttempted {
        match &batch.events[0].event {
            DomainEvent::AuthenticationAttempted(e) => e,
            other => panic!("unexpected event variant: {other:?}"),
        }
    }

    /// Test-harness helper that builds an `AuthenticateUseCase` wired
    /// with the audit-event gate, a pre-seeded Local user with bcrypt
    /// hash, and returns the use case alongside the mock handles each
    /// test asserts against. Avoids the nine-line setup boilerplate
    /// that previously preceded each Item 16 audit test.
    ///
    /// The helper is deliberately private to this module — promoting
    /// it to `test_support` is out of scope (the broader test surface
    /// has no need for the audit gate today).
    fn make_audit_use_case() -> (
        AuthenticateUseCase,
        Arc<MockEphemeralStore>,
        Arc<CapturingEventStore>,
    ) {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let ephemeral: Arc<MockEphemeralStore> = Arc::new(MockEphemeralStore::new());
        let events: Arc<CapturingEventStore> = Arc::new(CapturingEventStore::new());
        let uc = AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            admin_mapping(),
        )
        .with_audit_events(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            ephemeral.clone() as Arc<dyn EphemeralStore>,
        );
        (uc, ephemeral, events)
    }

    /// Acceptance test: a single Local-auth failure with the audit
    /// gate wired produces exactly one event on the auth-attempts
    /// stream, with the raw IP + sanitised username in the payload.
    #[tokio::test(start_paused = true)]
    async fn audit_event_appended_on_local_auth_failure() {
        let (uc, _ephemeral, events) = make_audit_use_case();

        uc.record_auth_failure(Some(ipv4(203, 0, 113, 42)), "invalid_token", None)
            .await;

        let batches = events.captured();
        assert_eq!(batches.len(), 1, "expected exactly one append");
        let batch = &batches[0];
        assert_eq!(batch.stream_id.category, StreamCategory::AuthAttempts);
        let event = extract_auth_event(batch);
        assert_eq!(event.client_ip, ipv4(203, 0, 113, 42));
        assert_eq!(event.result, "invalid_token");
        assert_eq!(event.external_id_if_decoded, None);
    }

    /// Acceptance test: two failures with the same `(ip_bucket, result)`
    /// inside the 60s window produce ONE event; the second is throttled.
    #[tokio::test(start_paused = true)]
    async fn audit_event_throttled_on_same_bucket_within_window() {
        let (uc, _ephemeral, events) = make_audit_use_case();

        // Same /24 bucket; same result → throttled.
        uc.record_auth_failure(Some(ipv4(203, 0, 113, 1)), "invalid_token", None)
            .await;
        uc.record_auth_failure(Some(ipv4(203, 0, 113, 254)), "invalid_token", None)
            .await;
        assert_eq!(events.append_count(), 1, "second event must throttle");
    }

    /// Different `(ip_bucket, result)` tuples both append within the
    /// same 60s window — the throttle is per-tuple, not global.
    #[tokio::test(start_paused = true)]
    async fn audit_event_distinct_buckets_both_append() {
        let (uc, _ephemeral, events) = make_audit_use_case();

        // /24 buckets differ (203.0.113 vs 198.51.100).
        uc.record_auth_failure(Some(ipv4(203, 0, 113, 42)), "invalid_token", None)
            .await;
        uc.record_auth_failure(Some(ipv4(198, 51, 100, 42)), "invalid_token", None)
            .await;
        assert_eq!(events.append_count(), 2);
    }

    /// After the 60s throttle window elapses, the next failure of
    /// the same `(ip_bucket, result)` tuple appends again.
    #[tokio::test(start_paused = true)]
    async fn audit_event_appends_again_after_throttle_ttl_expires() {
        let (uc, _ephemeral, events) = make_audit_use_case();

        uc.record_auth_failure(Some(ipv4(203, 0, 113, 42)), "invalid_token", None)
            .await;
        // Advance past the 60s throttle TTL — note the throttle TTL
        // and the test's tokio paused clock are independent of the
        // wall clock.
        tokio::time::advance(Duration::from_secs(61)).await;
        uc.record_auth_failure(Some(ipv4(203, 0, 113, 42)), "invalid_token", None)
            .await;
        assert_eq!(events.append_count(), 2);
    }

    /// An event-store error MUST NOT propagate to the auth caller.
    /// The 401 (here: the `Validation` error) still surfaces; only
    /// the audit log is best-effort. Also asserts that the
    /// `hort_auth_events_appended_total{result="error"}` counter ticks
    /// — the catalog promises operators that signal whenever the
    /// audit-log append itself fails.
    ///
    /// Plain `#[test]` (not `#[tokio::test]`) so `capture_metrics`
    /// can wrap the runtime construction — `metrics::with_local_recorder`
    /// takes a sync closure, and a nested `Runtime::new().block_on`
    /// inside a `#[tokio::test]` panics with "Cannot start a runtime
    /// from within a runtime". The other use-case tests in this
    /// workspace follow the same shape (e.g. `artifact_use_case.rs`
    /// `download_succeeds_for_none_status`).
    #[test]
    fn audit_event_store_error_does_not_propagate_to_caller() {
        let (uc, _ephemeral, events) = make_audit_use_case();
        events.arm_failure();

        // Capture metrics around the failing append so we can assert
        // the `error` result label was emitted exactly once. The
        // helper itself swallows the event-store error (best-effort
        // audit; design §3.4 — never propagate to the caller), so the
        // test passes by *not* panicking AND by observing the metric.
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                uc.record_auth_failure(Some(ipv4(203, 0, 113, 42)), "invalid_token", None)
                    .await;
            });
        });
        assert_eq!(count_auth_event_metric(snap, "error"), 1);
    }

    /// Sum the `hort_auth_events_appended_total{result=<expected>}`
    /// counter from a `capture_metrics` snapshot. Consumes the
    /// snapshot — `Snapshot::into_vec` takes ownership and the type
    /// is not `Clone`. Centralised so the new error-path assertion
    /// stays a one-liner.
    fn count_auth_event_metric(snap: metrics_util::debugging::Snapshot, expected: &str) -> u64 {
        let mut total: u64 = 0;
        for (key, _, _, value) in snap.into_vec() {
            if key.key().name() != "hort_auth_events_appended_total" {
                continue;
            }
            let result = key
                .key()
                .labels()
                .find(|l| l.key() == "result")
                .map(|l| l.value().to_string());
            if result.as_deref() != Some(expected) {
                continue;
            }
            if let metrics_util::debugging::DebugValue::Counter(n) = value {
                total += n;
            }
        }
        total
    }

    // ---------------------------------------------------------------
    // Branch-coverage tests for
    // `record_auth_failure` and `maybe_append_auth_event`. Each test
    // exercises exactly one previously-uncovered branch — the
    // hort-app-100% coverage target requires every match arm and every
    // error path be observed by a unit test.
    // ---------------------------------------------------------------

    /// `record_auth_failure` is a no-op when `with_audit_events` was
    /// never called on the use case. Proves the gate-not-wired branch
    /// short-circuits before the event-store handle is dereferenced
    /// (legacy / single-binary tests rely on this).
    #[tokio::test(start_paused = true)]
    async fn audit_event_not_appended_when_gate_not_wired() {
        // NB: NO `.with_audit_events(..)` — the gate is unwired.
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let uc = AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            admin_mapping(),
        );

        // The best-effort audit path is silently skipped. No
        // CapturingEventStore exists; the test passes by *not*
        // panicking — `record_auth_failure` returns early without
        // touching a (None) gate.
        uc.record_auth_failure(Some(ipv4(203, 0, 113, 42)), "invalid_token", None)
            .await;
    }

    /// `record_auth_failure` is a no-op when `client_ip` is `None`.
    /// Transports that genuinely have no peer (in-process call sites)
    /// still authenticate normally; the audit gate just doesn't fire.
    #[tokio::test(start_paused = true)]
    async fn audit_event_not_appended_when_client_ip_missing() {
        let (uc, _ephemeral, events) = make_audit_use_case();

        uc.record_auth_failure(None, "invalid_token", None).await;

        assert_eq!(
            events.append_count(),
            0,
            "client_ip=None must short-circuit the audit append"
        );
    }

    /// `maybe_append_auth_event` fail-opens when the ephemeral throttle
    /// check itself errors: a `warn!` is emitted (not asserted here —
    /// tracing capture would couple the test to log machinery) and the
    /// append proceeds anyway. Verifies the design-doc §3.4 invariant
    /// that ephemeral-store outages do not silently drop audit
    /// records.
    #[tokio::test(start_paused = true)]
    async fn audit_event_swallows_ephemeral_failure_and_proceeds() {
        let (uc, ephemeral, events) = make_audit_use_case();
        ephemeral.arm_failure_on_next_put_if_absent();

        // record_auth_failure must not panic even when the throttle
        // check itself errors.
        uc.record_auth_failure(Some(ipv4(203, 0, 113, 42)), "invalid_token", None)
            .await;

        // Fail-open: the throttle errored but the append still
        // happened.
        assert_eq!(
            events.append_count(),
            1,
            "fail-open semantics: throttle error must not suppress the append"
        );
    }

    /// IPv6 client addresses flow end-to-end through the use case:
    /// the raw IPv6 address lands in the event payload, and the
    /// throttle bucket coarsens to /48 (so two addresses in the same
    /// /48 share a throttle window — the second is suppressed).
    #[tokio::test(start_paused = true)]
    async fn audit_event_appended_for_ipv6_client_ip() {
        use std::net::Ipv6Addr;
        let (uc, _ephemeral, events) = make_audit_use_case();

        // First failure: 2001:db8:1234:: ... :1.
        let ip1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1234, 0, 0, 0, 0, 0x0001));
        // Second failure: same /48 (2001:db8:1234::/48), different
        // host bits. Should be throttled.
        let ip2 = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x1234, 0xffff, 0, 0, 0, 0x00ff,
        ));

        uc.record_auth_failure(Some(ip1), "invalid_token", None)
            .await;
        uc.record_auth_failure(Some(ip2), "invalid_token", None)
            .await;

        let batches = events.captured();
        assert_eq!(
            batches.len(),
            1,
            "second IPv6 in the same /48 must be throttled"
        );
        let event = extract_auth_event(&batches[0]);
        // The RAW address (NOT the /48 bucket) is what lands in the
        // durable event — the bucket is for throttle-key cardinality
        // bounding only.
        assert_eq!(event.client_ip, ip1);
    }

    /// `client_ip_bucket` lives in metrics; assert here that two IPs
    /// in the same /24 share a throttle bucket — the documented
    /// behaviour the use case relies on.
    #[test]
    fn client_ip_bucket_collapses_same_24() {
        use crate::metrics::client_ip_bucket;
        let a = client_ip_bucket(ipv4(203, 0, 113, 1));
        let b = client_ip_bucket(ipv4(203, 0, 113, 254));
        assert_eq!(a, b);
        assert_eq!(a, "203.0.113.0/24");
    }

    // ---------------------------------------------------------------------
    // PAT routing in authenticate_bearer
    // ---------------------------------------------------------------------
    //
    // The four tests below pin the dispatch contract:
    //  - happy path routes to the validator and surfaces token_cap
    //  - typed PatValidationError variants collapse to AppError::Unauthorized
    //  - infrastructure failures propagate as AppError::Domain (5xx)
    //  - non-PAT-shaped tokens still reach the OIDC port unaffected
    //
    // The harness uses a stub PatValidationUseCase wired with the same
    // mocks the validator's own tests use (MockTokenRepo / MockEphemeral),
    // re-imported here from the validator module under cfg(test). The
    // mocks are private to that module, so we re-define minimal
    // equivalents in this scope.

    mod pat_routing_tests {
        use super::*;
        use std::collections::HashMap as StdHashMap;
        use std::sync::atomic::{AtomicI64, Ordering as AtomicOrdering};
        use std::sync::Mutex as StdMutex;

        use bytes::Bytes;
        use chrono::DateTime;
        use hort_domain::entities::api_token::{ApiToken, TokenKind};
        use hort_domain::entities::rbac::Permission;
        use hort_domain::entities::user::AuthProvider;
        use hort_domain::error::DomainResult;
        use hort_domain::ports::api_token_repository::ApiTokenRepository;
        use hort_domain::ports::ephemeral_store::EphemeralStore;
        use hort_domain::ports::BoxFuture;
        use hort_domain::types::{Page, PageRequest};

        use crate::argon2_hash::Argon2Verifier;
        use crate::use_cases::pat_cache::{Clock, PatCache};
        use crate::use_cases::pat_validation_use_case::{PatLockoutConfig, PatValidationUseCase};

        // ---- minimal mocks (cribbed from pat_validation_use_case::tests) ----

        struct StubVerifier {
            ok: bool,
        }
        impl Argon2Verifier for StubVerifier {
            fn verify(&self, _plaintext: &[u8], _hash: &str) -> bool {
                self.ok
            }
        }

        struct StubClock(AtomicI64);
        impl Clock for StubClock {
            fn now(&self) -> DateTime<Utc> {
                DateTime::<Utc>::from_timestamp(self.0.load(AtomicOrdering::SeqCst), 0).unwrap()
            }
        }

        struct StubTokenRepo {
            by_prefix: StdMutex<StdHashMap<String, ApiToken>>,
            inject_repo_error: bool,
        }
        impl StubTokenRepo {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    by_prefix: StdMutex::new(StdHashMap::new()),
                    inject_repo_error: false,
                })
            }
            fn new_with_error() -> Arc<Self> {
                Arc::new(Self {
                    by_prefix: StdMutex::new(StdHashMap::new()),
                    inject_repo_error: true,
                })
            }
            fn insert(&self, prefix: &str, token: ApiToken) {
                self.by_prefix
                    .lock()
                    .unwrap()
                    .insert(prefix.to_string(), token);
            }
        }
        impl ApiTokenRepository for StubTokenRepo {
            fn insert(&self, _t: &ApiToken) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn find_by_prefix(
                &self,
                prefix: &str,
            ) -> BoxFuture<'_, DomainResult<Option<ApiToken>>> {
                if self.inject_repo_error {
                    return Box::pin(async {
                        Err(DomainError::Invariant("stub repo failure".into()))
                    });
                }
                let r = self.by_prefix.lock().unwrap().get(prefix).cloned();
                Box::pin(async move { Ok(r) })
            }
            fn find_by_id(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<ApiToken>> {
                Box::pin(async {
                    Err(DomainError::NotFound {
                        entity: "ApiToken",
                        id: "stub".into(),
                    })
                })
            }
            fn list_for_user(
                &self,
                _u: Uuid,
                _p: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<ApiToken>>> {
                Box::pin(async {
                    Ok(Page {
                        items: Vec::new(),
                        total: 0,
                    })
                })
            }
            fn update_last_used(
                &self,
                _t: Uuid,
                _at: DateTime<Utc>,
                _ip: Option<&str>,
                _ua: Option<&str>,
            ) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn revoke(&self, _t: Uuid) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        struct StubEphemeralStore {
            entries: StdMutex<StdHashMap<String, (Bytes, std::time::Instant)>>,
        }
        impl StubEphemeralStore {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    entries: StdMutex::new(StdHashMap::new()),
                })
            }
        }
        impl EphemeralStore for StubEphemeralStore {
            fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
                let now = std::time::Instant::now();
                let mut map = self.entries.lock().unwrap();
                let r = match map.get(key) {
                    Some((v, exp)) if *exp > now => Some(v.clone()),
                    Some(_) => {
                        map.remove(key);
                        None
                    }
                    None => None,
                };
                Box::pin(async move { Ok(r) })
            }
            fn put(
                &self,
                key: &str,
                value: Bytes,
                ttl: Duration,
            ) -> BoxFuture<'_, DomainResult<()>> {
                let exp = std::time::Instant::now() + ttl;
                self.entries
                    .lock()
                    .unwrap()
                    .insert(key.to_string(), (value, exp));
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
                let live = matches!(map.get(key), Some((_, e)) if *e > now);
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
                Box::pin(async { Ok(None) })
            }
            fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
                self.entries.lock().unwrap().remove(key);
                Box::pin(async { Ok(()) })
            }
            fn extend_ttl(&self, _k: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        // ---- fixtures ----

        const VALID_PAT: &str = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const VALID_PAT_2: &str = "hort_pat_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        // sentinel time used by the mock clock + token expiry
        const T0_SECS: i64 = 1_700_000_000;

        fn fixture_user(id: Uuid, active: bool, admin: bool) -> User {
            User {
                id,
                username: "alice".into(),
                email: "alice@example.com".into(),
                auth_provider: AuthProvider::Oidc,
                external_id: Some("k:1".into()),
                display_name: None,
                is_active: active,
                is_admin: admin,
                is_service_account: false,
                last_login_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }

        fn fixture_token(token_id: Uuid, user_id: Uuid) -> ApiToken {
            ApiToken {
                id: token_id,
                user_id,
                name: "ci".into(),
                description: None,
                kind: TokenKind::Pat,
                token_hash: "$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel".into(),
                token_prefix: "aaaaaaaa".into(),
                declared_permissions: vec![Permission::Read, Permission::Write],
                repository_ids: None,
                expires_at: Some(
                    DateTime::<Utc>::from_timestamp(T0_SECS + 86_400 * 30, 0).unwrap(),
                ),
                revoked_at: None,
                last_used_at: None,
                last_used_ip: None,
                last_used_user_agent: None,
                created_by_user_id: user_id,
                created_at: Utc::now(),
            }
        }

        struct PatHarness {
            uc: AuthenticateUseCase,
            users: Arc<MockUserRepository>,
            // `tokens` is held only for the harness's documented
            // lifetime — the caller seeds rows BEFORE constructing the
            // harness, so we don't need to expose the handle.
            #[allow(dead_code)]
            tokens: Arc<StubTokenRepo>,
        }

        fn build_harness(verify_ok: bool, tokens: Arc<StubTokenRepo>) -> PatHarness {
            let idp = Arc::new(MockIdentityProvider::new());
            let users = Arc::new(MockUserRepository::new());
            let ephemeral = StubEphemeralStore::new();
            let cache = Arc::new(PatCache::new(64, Duration::from_secs(300)));
            let clock = Arc::new(StubClock(AtomicI64::new(T0_SECS)));
            let verifier: Arc<dyn Argon2Verifier> = Arc::new(StubVerifier { ok: verify_ok });
            let pat_uc = Arc::new(PatValidationUseCase::new_with_verifier(
                tokens.clone() as Arc<dyn ApiTokenRepository>,
                users.clone() as Arc<dyn UserRepository>,
                ephemeral as Arc<dyn EphemeralStore>,
                cache,
                verifier,
                clock as Arc<dyn Clock>,
                PatLockoutConfig::DEFAULT,
            ));
            let uc = AuthenticateUseCase::new(
                idp as Arc<dyn IdentityProvider>,
                users.clone() as Arc<dyn UserRepository>,
                admin_mapping(),
            )
            .with_pat_validation(pat_uc);
            PatHarness { uc, users, tokens }
        }

        // ---- happy path ----

        #[tokio::test]
        async fn authenticate_bearer_with_pat_token_routes_to_pat_validator() {
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert("aaaaaaaa", fixture_token(token_id, user_id));

            let h = build_harness(true, tokens);
            h.users.insert(fixture_user(user_id, true, false));

            let principal = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert_eq!(principal.user_id, user_id);
            // §B6 — token_cap must be Some on the PAT-success path.
            let cap = principal.token_cap.expect("token_cap is Some on PAT");
            assert_eq!(cap.permissions, vec![Permission::Read, Permission::Write]);
        }

        // ---- token_cap discriminator ----

        #[tokio::test]
        async fn authenticate_bearer_pat_principal_carries_token_cap() {
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert("aaaaaaaa", fixture_token(token_id, user_id));

            let h = build_harness(true, tokens);
            h.users.insert(fixture_user(user_id, true, true));

            // PAT path → Some(cap)
            let principal_pat = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert!(principal_pat.token_cap.is_some());
            // Admin user → claims == ["admin"]
            // (synthetic, the only claim a native-token path can carry).
            assert_eq!(principal_pat.claims, vec![ADMIN_ROLE.to_string()]);
            // Native-token principal carries the typed kind.
            assert_eq!(principal_pat.token_kind, Some(TokenKind::Pat));

            // OIDC path on the SAME use case → token_cap = None
            // (we wire a registered token on the IdP mock to drive this).
            // We need a fresh harness because PatHarness pins a single
            // MockIdentityProvider — rebuild a peer that registers the
            // OIDC token and asserts None.
            let (uc2, idp2, _users2) = make_use_case(admin_mapping());
            idp2.register_token("oidc-tok", sample_claims("k:1", vec![]));
            let principal_oidc = uc2.authenticate_bearer("oidc-tok").await.unwrap();
            assert!(principal_oidc.token_cap.is_none());
        }

        // ---- error mapping ----

        #[tokio::test]
        async fn authenticate_bearer_with_pat_token_returns_unauthorized_on_pat_validation_error() {
            // Plant a token but make the verifier return false →
            // HashMismatch.
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert("aaaaaaaa", fixture_token(token_id, user_id));

            let h = build_harness(false, tokens);
            h.users.insert(fixture_user(user_id, true, false));

            let err = h.uc.authenticate_bearer(VALID_PAT).await.unwrap_err();
            match err {
                AppError::Unauthorized(msg) => {
                    assert!(msg.contains("hash mismatch"), "got: {msg}");
                }
                other => panic!("expected Unauthorized, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn authenticate_bearer_pat_prefix_not_found_maps_to_unauthorized() {
            // Empty repo → sentinel verify path → PrefixNotFound.
            let tokens = StubTokenRepo::new();
            let h = build_harness(true, tokens); // verifier ok, but no row
            let err = h.uc.authenticate_bearer(VALID_PAT_2).await.unwrap_err();
            match err {
                AppError::Unauthorized(msg) => {
                    assert!(msg.contains("prefix not found"), "got: {msg}");
                }
                other => panic!("expected Unauthorized(prefix not found), got {other:?}"),
            }
        }

        #[tokio::test]
        async fn authenticate_bearer_pat_user_deactivated_maps_to_unauthorized() {
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert("aaaaaaaa", fixture_token(token_id, user_id));
            let h = build_harness(true, tokens);
            // Inactive user — validator emits UserDeactivated.
            h.users.insert(fixture_user(user_id, false, false));

            let err = h.uc.authenticate_bearer(VALID_PAT).await.unwrap_err();
            match err {
                AppError::Unauthorized(msg) => {
                    assert!(msg.contains("user deactivated"), "got: {msg}");
                }
                other => panic!("expected Unauthorized(user deactivated), got {other:?}"),
            }
        }

        #[tokio::test]
        async fn authenticate_bearer_pat_infrastructure_error_propagates_as_domain() {
            // Repo error → PatValidationError::Infrastructure →
            // AppError::Domain (5xx wire shape).
            let tokens = StubTokenRepo::new_with_error();
            let h = build_harness(true, tokens);
            let err = h.uc.authenticate_bearer(VALID_PAT).await.unwrap_err();
            assert!(
                matches!(err, AppError::Domain(_)),
                "expected Domain on infrastructure error, got {err:?}"
            );
        }

        // ---- regression: OIDC-shaped tokens are unaffected ----

        #[tokio::test]
        async fn authenticate_bearer_with_oidc_token_unaffected_by_pat_branch() {
            let tokens = StubTokenRepo::new();
            let h = build_harness(true, tokens);

            // Build a use case with the IdP mock accessible — replicate
            // the build_harness wiring but capture the IdP. Easier:
            // assert that an obviously-non-PAT-shaped token reaches the
            // IdP and surfaces its rejection.
            let err =
                h.uc.authenticate_bearer("a-keycloak-jwt-not-a-pat")
                    .await
                    .unwrap_err();
            // MockIdentityProvider returns SignatureInvalid for unknown
            // tokens — the PAT branch must NOT have intercepted.
            match err {
                AppError::OidcValidation(
                    hort_domain::ports::identity_provider::OidcValidationError::SignatureInvalid,
                ) => {}
                other => panic!("expected OidcValidation, got {other:?}"),
            }
        }

        // ---- regression: malformed `hort_*_*` falls through to OIDC ----

        #[tokio::test]
        async fn authenticate_bearer_with_malformed_pat_shape_falls_through_to_oidc() {
            // Wrong total length but starts with `hort_`. The PAT
            // branch's parse fails → OIDC port handles it.
            let tokens = StubTokenRepo::new();
            let h = build_harness(true, tokens);
            let err =
                h.uc.authenticate_bearer("hort_pat_short")
                    .await
                    .unwrap_err();
            match err {
                AppError::OidcValidation(_) => {}
                other => panic!("malformed PAT must fall through, got {other:?}"),
            }
        }

        // ---- map_pat_error pure mapping table ----

        #[test]
        fn map_pat_error_collapses_typed_variants_to_unauthorized_or_domain() {
            // Every non-Infrastructure variant becomes Unauthorized;
            // Infrastructure becomes Domain.
            let cases: Vec<(PatValidationError, &'static str)> = vec![
                (PatValidationError::RateLimited, "rate limited"),
                (PatValidationError::PrefixNotFound, "prefix not found"),
                (PatValidationError::HashMismatch, "hash mismatch"),
                (PatValidationError::Expired, "token expired"),
                (PatValidationError::Revoked, "token revoked"),
                (PatValidationError::UserDeactivated, "user deactivated"),
            ];
            for (input, expected_substring) in cases {
                match map_pat_error(input) {
                    AppError::Unauthorized(s) => {
                        assert!(s.contains(expected_substring), "got: {s}");
                    }
                    other => panic!("expected Unauthorized for variant: {other:?}"),
                }
            }
            let infra = PatValidationError::Infrastructure(DomainError::Invariant("stub".into()));
            match map_pat_error(infra) {
                AppError::Domain(_) => {}
                other => panic!("Infrastructure must map to Domain, got {other:?}"),
            }
        }

        // ---- PAT-path under-privileged claim shape ----
        //
        // Acceptance:
        //   - PAT, is_admin=true  → claims == ["admin"]
        //   - PAT, is_admin=false → claims == []
        //   - ServiceAccount, is_admin=false → claims == [] (pin for
        //     the federated/rotated path)
        // None of these consult `claim_mappings` — the harness wires
        // `admin_mapping()` (which would resolve `admins`→`admin` /
        // `team-alpha`→`developer` IF it were consulted), and the user
        // row carries no IdP groups, so a non-empty `claims` on a
        // non-admin native token would prove a breach of the
        // no-claim-mappings-on-native-tokens invariant (ADR 0012).

        // `fixture_token_with_kind` is defined below in the
        // token-kind-carrier block; these tests reference it.

        #[tokio::test]
        async fn pat_admin_user_carries_only_synthetic_admin_claim() {
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert("aaaaaaaa", fixture_token(token_id, user_id));
            let h = build_harness(true, tokens);
            // active=true, admin=true
            h.users.insert(fixture_user(user_id, true, true));

            let principal = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert_eq!(principal.claims, vec!["admin".to_string()]);
            assert_eq!(principal.token_kind, Some(TokenKind::Pat));
            // Token cap flows through unchanged.
            assert!(principal.token_cap.is_some());
        }

        #[tokio::test]
        async fn pat_non_admin_user_carries_no_claims() {
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert("aaaaaaaa", fixture_token(token_id, user_id));
            let h = build_harness(true, tokens);
            // active=true, admin=false — invariant 1: no claim_mappings
            // consultation, so the resolved set is empty (the
            // `admin_mapping()` wired in build_harness must NOT leak in).
            h.users.insert(fixture_user(user_id, true, false));

            let principal = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert!(
                principal.claims.is_empty(),
                "non-admin PAT must carry no claims (invariant 1), got {:?}",
                principal.claims
            );
            assert_eq!(principal.token_kind, Some(TokenKind::Pat));
            assert!(principal.token_cap.is_some());
        }

        #[tokio::test]
        async fn service_account_non_admin_carries_no_claims_invariant_8() {
            // Pin: a `TokenKind::ServiceAccount` bearer
            // (federated OR fallback-rotated) flows through
            // `authenticate_pat` and gets `claims == []` — its entire
            // authority is `GrantSubject::User(backing_user_id)` grants,
            // never a foreign-JWT `groups` claim run through
            // `claim_mappings`. SA is admin-forbidden at gitops apply
            // time, so is_admin=false is the only legitimate shape.
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert(
                "aaaaaaaa",
                fixture_token_with_kind(token_id, user_id, TokenKind::ServiceAccount),
            );
            let h = build_harness(true, tokens);
            h.users.insert(fixture_user(user_id, true, false));

            let principal = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert!(
                principal.claims.is_empty(),
                "ServiceAccount must carry no claims (invariant 8), got {:?}",
                principal.claims
            );
            assert_eq!(principal.token_kind, Some(TokenKind::ServiceAccount));
        }

        // ---- typed token-kind carrier ----
        //
        // The token-kind discriminator is the typed
        // `CallerPrincipal.token_kind: Option<TokenKind>` carrier set in
        // `authenticate_pat` as `Some(validation.kind)` — never a marker
        // string in a roles/claims list. These tests are
        // the regression pin for the carrier.
        // The match in `authenticate_pat` stays exhaustive
        // (no `_` arm) so a future `TokenKind::Refresh` is a compile
        // error there — forward-compat by construction.
        // corollary: no token-kind string is ever pushed into `claims`.

        fn fixture_token_with_kind(token_id: Uuid, user_id: Uuid, kind: TokenKind) -> ApiToken {
            ApiToken {
                kind,
                ..fixture_token(token_id, user_id)
            }
        }

        #[tokio::test]
        async fn pat_kind_principal_carries_typed_pat_token_kind() {
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert(
                "aaaaaaaa",
                fixture_token_with_kind(token_id, user_id, TokenKind::Pat),
            );
            let h = build_harness(true, tokens);
            h.users.insert(fixture_user(user_id, true, false));

            let principal = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert_eq!(principal.token_kind, Some(TokenKind::Pat));
            // §6 invariant 6 corollary — the kind is NEVER a claim.
            assert!(
                !principal
                    .claims
                    .iter()
                    .any(|c| c == "cli_session" || c == "service_account" || c == "pat"),
                "token-kind string must never appear in claims, got {:?}",
                principal.claims
            );
        }

        #[tokio::test]
        async fn cli_session_kind_principal_carries_typed_cli_session_token_kind() {
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert(
                "aaaaaaaa",
                fixture_token_with_kind(token_id, user_id, TokenKind::CliSession),
            );
            let h = build_harness(true, tokens);
            h.users.insert(fixture_user(user_id, true, false));

            let principal = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert_eq!(principal.token_kind, Some(TokenKind::CliSession));
            assert!(
                !principal.claims.iter().any(|c| c == "cli_session"),
                "cli_session must never appear in claims, got {:?}",
                principal.claims
            );
        }

        #[tokio::test]
        async fn service_account_kind_principal_carries_typed_sa_token_kind() {
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert(
                "aaaaaaaa",
                fixture_token_with_kind(token_id, user_id, TokenKind::ServiceAccount),
            );
            let h = build_harness(true, tokens);
            h.users.insert(fixture_user(user_id, true, false));

            let principal = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert_eq!(principal.token_kind, Some(TokenKind::ServiceAccount));
            assert!(
                !principal.claims.iter().any(|c| c == "service_account"),
                "service_account must never appear in claims, got {:?}",
                principal.claims
            );
        }

        #[tokio::test]
        async fn token_kind_carrier_coexists_with_synthetic_admin_claim() {
            // The typed kind carrier and the synthetic `admin` claim are
            // independent. An admin CliSession carries both
            // `token_kind = Some(CliSession)` AND `claims = ["admin"]`
            // (the §1.5 admin-cap CLI session flow). The kind is NOT a
            // claim — `claims` is exactly `["admin"]`, nothing else.
            let token_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let tokens = StubTokenRepo::new();
            tokens.insert(
                "aaaaaaaa",
                fixture_token_with_kind(token_id, user_id, TokenKind::CliSession),
            );
            let h = build_harness(true, tokens);
            h.users.insert(fixture_user(user_id, true, true));

            let principal = h.uc.authenticate_bearer(VALID_PAT).await.unwrap();
            assert_eq!(principal.token_kind, Some(TokenKind::CliSession));
            assert_eq!(principal.claims, vec!["admin".to_string()]);
        }
    }
}
