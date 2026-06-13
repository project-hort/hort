//! RFC 8693 OAuth 2.0 Token Exchange handler.
//!
//! `POST /api/v1/auth/exchange` swaps an IdP-issued JWT for a
//! `kind = 'cli_session'` token (ADR 0013; mechanism inventory in
//! `docs/auth-catalog.md`).
//!
//! # Wire shape
//!
//! Request (RFC 8693 §2.1):
//!
//! ```text
//! POST /api/v1/auth/exchange HTTP/1.1
//! Content-Type: application/x-www-form-urlencoded
//!
//! grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//! &subject_token=<IdP-issued JWT>
//! &subject_token_type=urn:ietf:params:oauth:token-type:access_token
//! &requested_token_type=urn:ietf:params:oauth:token-type:access_token
//! &client_id=hort-cli/0.4.2
//! ```
//!
//! Response — success (RFC 8693 §2.2.1):
//!
//! ```text
//! HTTP/1.1 200 OK
//! Content-Type: application/json
//! Cache-Control: no-store
//!
//! { "access_token": "hort_cli_…", "issued_token_type": "…access_token",
//!   "token_type": "Bearer", "expires_in": 2592000 }
//! ```
//!
//! Response — failure (RFC 8693 §2.4 / RFC 6749 §5.2):
//!
//! ```text
//! HTTP/1.1 400 Bad Request
//! Content-Type: application/json
//! Cache-Control: no-store
//!
//! { "error": "invalid_request", "error_description": "<reason>" }
//! ```
//!
//! # Order of validation
//!
//! 1. Form parsing.
//! 2. `grant_type` URI match.
//! 3. `subject_token` / `subject_token_type` presence + allowed values.
//! 4. `requested_token_type` (when present) must be `access_token`.
//! 5. **PAT-shape gate** — `parse_pat_token_format` on the
//!    `subject_token`. Fires BEFORE any IdP call,
//!    so a chained PAT round-trips zero IdP traffic.
//! 6. IdP validation via `AuthenticateUseCase::authenticate_bearer`.
//! 7. Token mint via `ApiTokenUseCase::issue_cli_session`.
//!
//! # Headers
//!
//! `Cache-Control: no-store` on every response (success + error). The
//! plaintext token leaves the server exactly once.
//!
//! `WWW-Authenticate` is **NEVER** emitted. `/exchange` is target-of-
//! exchange, not target-of-protected-resource.
//!
//! # Tracing
//!
//! `#[tracing::instrument(skip(...))]` skips `form` / `request` so the
//! IdP token never lands in spans. `info!` on PAT-shape rejection
//! (security-relevant). NO `err` variant per CLAUDE.md observability
//! rules.
//!
//! # Metrics
//!
//! - `hort_token_exchange_total{kind, result}` — counter (the `kind`
//!   label discriminates
//!   `cli_session` / `federated_jwt` / future `refresh`).
//! - `hort_token_exchange_duration_seconds{result}` — histogram
//!
//! `result ∈ { success, source_token_invalid, source_token_expired,
//! source_token_pat_rejected, idp_unavailable, bad_request,
//! subject_not_authorised, cap_exceeds_authority, validation_error,
//! infrastructure_error }`. No high-cardinality labels (no username,
//! user_id, client_id, source_ip, external_id). The catalog row in
//! `docs/metrics-catalog.md` is authoritative. `bad_request` +
//! `subject_not_authorised` are deliberately distinct from
//! `source_token_invalid` — pre-IdP wire-shape rejects
//! and post-validation 403s must not share a label with OIDC
//! credential-abuse rejects.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Form, FromRequest, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use hort_app::error::AppError;
use hort_app::metrics::{emit_service_account_authenticated, SA_AUTH_SOURCE_FEDERATED};
use hort_app::use_cases::api_token_use_case::{
    ApiTokenError, FederationSource, IssueCliSessionRequest, IssueTokenRequest,
};
use hort_app::use_cases::pat_validation_use_case::parse_pat_token_format;
use hort_domain::entities::service_account::ServiceAccount;
use hort_domain::ports::federated_jwt_validator::{FederationDenyReason, ValidatedClaims};
use hort_domain::ports::identity_provider::OidcValidationError;

use crate::context::{AppContext, AuthContext};
use crate::handlers::token_exchange_common::{
    is_supported_subject_token_type, EXCHANGE_GRANT_TYPE, TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_JWT,
};
use crate::middleware::trust::RequestTrust;

// ---------------------------------------------------------------------------
// Constants — envelope strings (RFC 8693 wire URIs live in
// `crate::handlers::token_exchange_common` so `well_known.rs` and
// this handler read from the same source).
// ---------------------------------------------------------------------------

const TOKEN_TYPE_BEARER: &str = "Bearer";

/// Maximum length of the `client_id` form field forwarded into
/// `IssueCliSessionRequest.client_name`. The use case also truncates
/// defensively; the wire-level truncation here is the
/// documented contract (capped at 255 chars).
const CLIENT_ID_MAX_LEN: usize = 255;

// ---------------------------------------------------------------------------
// Metric labels — closed taxonomy; `docs/metrics-catalog.md` is the
// catalog of record.
// ---------------------------------------------------------------------------

mod metrics {
    pub(super) const RESULT_SUCCESS: &str = "success";
    /// OIDC validation reject only
    /// (`OidcValidationError::{UnknownIssuer, Malformed,
    /// SignatureInvalid, AudienceMismatch, ClaimMissing}`). Maps to HTTP 401
    /// `invalid_token`. Credential-abuse signal (forged or stale IdP
    /// token). Distinct from `bad_request` (wire-shape errors,
    /// pre-IdP) and `subject_not_authorised` (post-validation 403s,
    /// RBAC story) so dashboards can separate the three failure
    /// shapes.
    pub(super) const RESULT_SOURCE_TOKEN_INVALID: &str = "source_token_invalid";
    pub(super) const RESULT_SOURCE_TOKEN_EXPIRED: &str = "source_token_expired";
    pub(super) const RESULT_SOURCE_TOKEN_PAT_REJECTED: &str = "source_token_pat_rejected";
    pub(super) const RESULT_IDP_UNAVAILABLE: &str = "idp_unavailable";
    /// RFC 6749 wire-shape rejection: form parse
    /// failure, missing or wrong `grant_type`, missing or wrong
    /// `subject_token_type`, invalid `requested_token_type`,
    /// content-type mismatch. All HTTP 400. Distinct from
    /// `source_token_invalid` (which is reserved for OIDC validation
    /// errors) to keep credential-abuse signals separate from
    /// buggy-client signals — a sustained climb here typically means
    /// a client (most commonly `hort-cli` itself or a CI-side wrapper)
    /// is constructing the form body wrong.
    pub(super) const RESULT_BAD_REQUEST: &str = "bad_request";
    /// Post-validation 403: IdP-validated user
    /// rejected by the resource-server side (`AppError::Domain(_)` /
    /// `AppError::Unauthorized(_)`). Maps to HTTP 403 `access_denied`.
    /// Distinct from `source_token_invalid` (forged/stale IdP token)
    /// and `cap_exceeds_authority` (RBAC denial during issuance) so
    /// the three-way distinction is observable.
    pub(super) const RESULT_SUBJECT_NOT_AUTHORISED: &str = "subject_not_authorised";
    pub(super) const RESULT_CAP_EXCEEDS_AUTHORITY: &str = "cap_exceeds_authority";
    pub(super) const RESULT_VALIDATION_ERROR: &str = "validation_error";
    pub(super) const RESULT_INFRASTRUCTURE_ERROR: &str = "infrastructure_error";

    pub(super) const COUNTER: &str = "hort_token_exchange_total";
    pub(super) const HISTOGRAM: &str = "hort_token_exchange_duration_seconds";

    pub(super) const RESULT: &str = "result";

    /// The `kind` label discriminates the
    /// `subject_token_type` dispatch branch: `cli_session`,
    /// `federated_jwt`, future `refresh`. The label is **required**
    /// on every emission site.
    pub(super) const KIND: &str = "kind";
    pub(super) const KIND_CLI_SESSION: &str = "cli_session";
    /// Federation branch `kind` value. Emitted by every
    /// exit path of `handle_federated_jwt` (success + every deny
    /// reason). Distinct from `cli_session` so dashboards can split
    /// IdP-mediated CLI login from workload-identity federation.
    pub(super) const KIND_FEDERATED_JWT: &str = "federated_jwt";

    // Federation-specific `result` values. The eight
    // FederationDenyReason variants (via `as_str()`) plus the four
    // handler-layer outcomes.

    /// SA resolution: zero `ServiceAccount.federated_identities`
    /// entries matched the validated claims.
    pub(super) const RESULT_NO_SA_MATCH: &str = "no_sa_match";
    /// SA resolution: more than one `ServiceAccount` matched. Operator
    /// must narrow the trust policies — silently picking one would be
    /// a configuration footgun (design doc §4 "Multi-match policy").
    pub(super) const RESULT_MULTIPLE_SA_MATCH: &str = "multiple_sa_match";
    /// Step-8 mint: the system-mint pipeline rejected the request
    /// (typed `ApiTokenError`). Distinct from
    /// `RESULT_INFRASTRUCTURE_ERROR` so operator dashboards separate
    /// outages from caller-side gate denials at the mint step.
    pub(super) const RESULT_MINT_FAILED: &str = "mint_failed";
    /// Catch-all for unexpected internal errors during the federation
    /// branch (validator port returned a Domain error, SA listing
    /// failed, etc.). Maps to HTTP 500.
    pub(super) const RESULT_INTERNAL_ERROR: &str = "internal_error";

    // Replay-guard deny `result`
    // values on the existing `hort_token_exchange_total{kind=
    // federated_jwt}` taxonomy. `replayed_jti`/`replayed_composite`
    // additionally drive the dedicated `hort_jwt_replay_rejected_total`
    // counter (emitted in hort-app, not here); `jti_required` and
    // `replay_guard_unavailable` ride ONLY this exchange counter (no
    // replay was detected). The `replayed_*` literals mirror
    // `ReplayKey::replay_result_label` in `hort-domain` verbatim.

    /// `jti` replay detected by the durable seen-set. 401.
    pub(super) const RESULT_REPLAYED_JTI: &str = "replayed_jti";
    /// `(iss,sub,iat,exp)` composite replay detected. 401.
    pub(super) const RESULT_REPLAYED_COMPOSITE: &str = "replayed_composite";
    /// Issuer requires a `jti` claim, none present (or composite not
    /// constructible). Validation deny, NOT a replay. 401.
    pub(super) const RESULT_JTI_REQUIRED: &str = "jti_required";
    /// Replay guard unreachable — fail-CLOSED deny. 503.
    pub(super) const RESULT_REPLAY_GUARD_UNAVAILABLE: &str = "replay_guard_unavailable";

    // SA-resolution outcome
    // counter. This is a SEPARATE metric from `hort_token_exchange_total`:
    // the exchange counter classifies the protocol-level outcome of the
    // whole `/exchange` request, whereas `hort_fed_sa_match_total`
    // classifies the federation SA-selection decision specifically so a
    // security reviewer can see F-7 audience-confusion denies and F-8
    // empty-claims fail-closed skips without disentangling them from the
    // broader `no_sa_match` bucket. `{result}`-only label (closed
    // taxonomy, design §4); no high-cardinality labels.
    pub(super) const FED_SA_MATCH_COUNTER: &str = "hort_fed_sa_match_total";
    /// Exactly one `ServiceAccount` matched the validated claims (the
    /// only outcome that proceeds to mint). Counted once per successful
    /// SA resolution.
    pub(super) const FED_SA_RESULT_MATCHED: &str = "matched";
    /// A `FederatedIdentity` declared an `aud`
    /// claim selector that did NOT equal the validator-resolved
    /// audience (`ValidatedClaims.audience`). The confused-deputy /
    /// token-redirection vector the audit names: a JWT minted for a
    /// different relying party whose other claims happen to satisfy the
    /// fragment is now rejected at the audience gate rather than
    /// silently assuming the SA.
    pub(super) const FED_SA_RESULT_DENIED_AUDIENCE: &str = "denied_audience";
    /// A `FederatedIdentity` row carried
    /// an empty `claims` map. Apply-time validation rejects this shape
    /// (ADR 0018); this is the defense-in-depth
    /// RUNTIME fail-closed skip against an out-of-band `claims = '{}'`
    /// row (raw SQL / restore / migration bug). An empty exact-match
    /// set is vacuously-true and would otherwise let ANY JWT from the
    /// issuer assume the SA.
    pub(super) const FED_SA_RESULT_DENIED_EMPTY_CLAIMS: &str = "denied_empty_claims";
}

// ---------------------------------------------------------------------------
// Wire DTOs — request and response shapes per RFC 8693.
// ---------------------------------------------------------------------------

/// Form body shape per RFC 8693 §2.1. `resource` / `audience` are
/// intentionally absent — v1 ignores them per design doc §3 / §10
/// carry-forward; including unused fields would advertise a surface
/// that does not exist.
///
/// `scope` (space-separated permissions) and
/// `requested_token_lifetime` (seconds) follow the RFC 8693 §2.1 wire
/// spec. Empty/absent gets the defaults (scope
/// `[Read, Write, Delete]`, default lifetime 1 h).
#[derive(Debug, Deserialize)]
struct ExchangeForm {
    #[serde(default)]
    grant_type: Option<String>,
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
    #[serde(default)]
    requested_token_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    requested_token_lifetime: Option<u64>,
}

/// RFC 8693 §2.2.1 success body. `expires_in` is computed from the
/// issued token's `expires_at` so the wire value reflects the
/// per-cap-shape clamp applied by `clamp_lifetime`
/// rather than a hardcoded constant. The hort-cli client surfaces this
/// alongside its `note:` line when the server clamps a `--admin
/// --expires-in 4h` request down to 1 h.
#[derive(Debug, Serialize)]
struct ExchangeResponseBody {
    access_token: String,
    issued_token_type: &'static str,
    token_type: &'static str,
    expires_in: u64,
}

/// RFC 8693 §2.4 / RFC 6749 §5.2 error body.
#[derive(Debug, Serialize)]
struct ExchangeErrorBody {
    error: &'static str,
    error_description: String,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// Build the `/auth/exchange` route tree. The caller (`hort-server::http`)
/// nests under `/api/v1` and decides whether to mount this at all
/// based on `HORT_TOKEN_EXCHANGE_ENABLED` (design doc §9). When the flag
/// is off, the route is not mounted at all and axum's default 404
/// applies — matching the "no surface advertised" requirement.
pub fn token_exchange_routes() -> Router<Arc<AppContext>> {
    Router::new().route("/auth/exchange", post(post_exchange))
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/exchange` — RFC 8693 token exchange.
///
/// `request` carries the request extensions (the `RequestTrust` for
/// `client_ip` extraction); we deliberately do NOT use a typed
/// `Extension<RequestTrust>` extractor because `RequestTrust` may be
/// absent on test paths that do not run the trust middleware. The
/// `request.extensions().get::<RequestTrust>()` lookup falls back to
/// the literal `"unknown"` source IP in that case.
#[tracing::instrument(skip(ctx, request))]
async fn post_exchange(State(ctx): State<Arc<AppContext>>, request: Request) -> Response {
    let started = Instant::now();

    // Pull RequestTrust before consuming the request body in Form
    // extraction. The trust middleware populates it; tests without
    // the middleware fall back to "unknown" so the description string
    // is always well-formed.
    let source_ip = request
        .extensions()
        .get::<RequestTrust>()
        .map(|t| t.client_ip.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let response = run(&ctx, request, &source_ip).await;
    record_duration(
        response.kind,
        response.label,
        started.elapsed().as_secs_f64(),
    );
    emit_counter(response.kind, response.label);
    response.response
}

/// Internal handler outcome — the response, the metric `result` label,
/// and the metric `kind` label that caused it. Bundled so every exit
/// path emits the histogram + counter on its way out (the wrapper in
/// `post_exchange` is the only emission site).
///
/// The outcome carries `kind` so the federation branch
/// can emit `kind="federated_jwt"` alongside the existing
/// access_token-path `kind="cli_session"`.
struct Outcome {
    response: Response,
    label: &'static str,
    kind: &'static str,
}

async fn run(ctx: &Arc<AppContext>, request: Request, source_ip: &str) -> Outcome {
    // 1. Form parsing — RFC 8693 §2.1 wire body. Map axum's typed
    //    rejection into the RFC 8693 error envelope. Most variants
    //    return HTTP 400 `invalid_request`; `InvalidFormContentType`
    //    returns HTTP 415 `Unsupported Media Type` per RFC 7231
    //    §6.5.13 (matches Keycloak and
    //    Auth0 behaviour). The OAuth `error` code stays
    //    `invalid_request` per RFC 6749 §5.2; only the HTTP status
    //    differs. The metric label remains `bad_request` since the
    //    underlying category is still wire-shape.
    let form: ExchangeForm = match Form::<ExchangeForm>::from_request(request, ctx).await {
        Ok(Form(f)) => f,
        Err(rej) => return form_rejection_outcome(&rej),
    };

    // 2. grant_type — must be the RFC 8693 token-exchange URI.
    let grant_type = match form.grant_type.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return invalid_request_outcome("grant_type is required".to_string()),
    };
    if grant_type != EXCHANGE_GRANT_TYPE {
        return error_outcome(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("grant_type must be {EXCHANGE_GRANT_TYPE}"),
            metrics::RESULT_BAD_REQUEST,
        );
    }

    // 3. subject_token presence.
    let subject_token = match form.subject_token.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return invalid_request_outcome("subject_token is required".to_string()),
    };

    // 4. subject_token_type — must be access_token or id_token.
    let subject_token_type = match form.subject_token_type.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return invalid_request_outcome("subject_token_type is required".to_string()),
    };
    // The gate lives in
    // `crate::handlers::token_exchange_common` so the discovery doc
    // (`/.well-known/hort-client-config`) advertises the same closed
    // set the handler enforces.
    if !is_supported_subject_token_type(subject_token_type) {
        return invalid_request_outcome("subject_token_type unsupported".to_string());
    }

    // Branch on the validated subject_token_type
    // BEFORE the access_token-path gates (requested_token_type / scope
    // parse / PAT-shape gate / IdP authenticate). The federation path
    // has its own validation pipeline (`FederatedJwtValidator`) and
    // mints a `TokenKind::ServiceAccount` via the system-mint path; it
    // does NOT share any of the access_token-path gates below.
    //
    // Note: a federation-path `requested_token_type` other than
    // `access_token` would still be a wire-shape error; the federation
    // branch performs the same check immediately after entering
    // `handle_federated_jwt`.
    if subject_token_type == TOKEN_TYPE_JWT {
        return handle_federated_jwt(
            ctx,
            subject_token,
            form.requested_token_type.as_deref(),
            form.client_id.as_deref(),
            source_ip,
        )
        .await;
    }

    // 5. requested_token_type — if present, must be access_token.
    if let Some(req_type) = form.requested_token_type.as_deref() {
        if !req_type.is_empty() && req_type != TOKEN_TYPE_ACCESS_TOKEN {
            return error_outcome(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                format!("requested_token_type must be {TOKEN_TYPE_ACCESS_TOKEN}"),
                metrics::RESULT_BAD_REQUEST,
            );
        }
    }

    // 5b. Parse `scope` (space-separated permissions)
    //     and `requested_token_lifetime` (seconds). Unknown permission
    //     names or oversize/negative lifetimes are wire-shape errors
    //     (bad_request). The `lifetime` value itself is bounds-checked
    //     by `clamp_lifetime` inside `issue_cli_session_inner`; this
    //     site only enforces basic parse hygiene.
    let requested_scope: Vec<hort_domain::entities::rbac::Permission> = match form.scope.as_deref()
    {
        None | Some("") => Vec::new(),
        Some(raw) => {
            let mut out = Vec::new();
            for token in raw.split_whitespace() {
                match token.parse::<hort_domain::entities::rbac::Permission>() {
                    Ok(p) => out.push(p),
                    Err(_) => {
                        return invalid_request_outcome(format!(
                            "scope contains unknown permission: {token}"
                        ));
                    }
                }
            }
            out
        }
    };
    let requested_lifetime_secs = form.requested_token_lifetime;

    // 6. PAT-shape gate (design doc §8 invariant 3) — fires BEFORE
    //    any IdP call so chained-PAT attempts cost zero IdP traffic.
    if parse_pat_token_format(subject_token).is_ok() {
        tracing::info!(
            reason = "pat_shape_rejected",
            "/exchange refused PAT-shaped subject_token"
        );
        return error_outcome(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "source token must be an IdP-issued JWT".to_string(),
            metrics::RESULT_SOURCE_TOKEN_PAT_REJECTED,
        );
    }

    // 7. IdP validation via the existing AuthenticateUseCase. The
    //    AuthContext::Enabled branch is the only one that wires
    //    AuthenticateUseCase; under Disabled the route is unreachable
    //    in production (composition fails to wire token_exchange when
    //    auth is disabled) but we surface 503 so a misconfigured
    //    Disabled-context boot does not crash with a panic.
    let authenticate = match &ctx.auth {
        AuthContext::Enabled { authenticate, .. } => authenticate.clone(),
        AuthContext::Disabled | AuthContext::BearerOnly { .. } => {
            // Federation (`/exchange`) requires an OIDC IdP for the
            // subject-token validation step. Under Disabled there is
            // no auth at all; under BearerOnly the IdP slot is `None`
            // (native-token validation only). Either way, federation
            // is not configured — surface 503 rather than crashing
            // the validator.
            tracing::error!(
                auth = ?ctx.auth,
                "/exchange invoked without an OIDC IdentityProvider — composition bug"
            );
            return error_outcome(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "auth subsystem not configured".to_string(),
                metrics::RESULT_IDP_UNAVAILABLE,
            );
        }
    };

    let principal = match authenticate.authenticate_bearer(subject_token).await {
        Ok(p) => p,
        Err(AppError::OidcValidation(OidcValidationError::Expired)) => {
            return error_outcome(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "subject_token expired".to_string(),
                metrics::RESULT_SOURCE_TOKEN_EXPIRED,
            );
        }
        Err(AppError::OidcValidation(OidcValidationError::IdpUnavailable)) => {
            return error_outcome(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "identity provider unavailable".to_string(),
                metrics::RESULT_IDP_UNAVAILABLE,
            );
        }
        Err(AppError::OidcValidation(variant)) => {
            // Narrowed scope: this label fires only
            // for `OidcValidationError::{UnknownIssuer, Malformed,
            // SignatureInvalid, AudienceMismatch, ClaimMissing}`
            // (Expired and IdpUnavailable have their own labels above).
            // Treated as a credential-abuse signal — `info!` mirrors
            // the PAT-shape rejection pattern.
            tracing::info!(
                oidc_error = ?variant,
                "/exchange refused: subject_token failed OIDC validation"
            );
            return error_outcome(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "subject_token invalid".to_string(),
                metrics::RESULT_SOURCE_TOKEN_INVALID,
            );
        }
        // NOTE: AppError::Domain / AppError::Unauthorized is the
        // post-validation rejection path — the IdP token validated
        // cleanly but the resource-server side rejected the resolved
        // user (e.g. deactivated, no role mapping for the JIT-resolved
        // groups, generic credential-rejection from the auth pipeline).
        //
        // The metric label here is
        // `subject_not_authorised`. Collapsing it onto
        // `source_token_invalid` together with OIDC validation rejects
        // and pre-IdP wire-shape errors would hide the
        // three-way distinction between forged-token, buggy-client, and
        // RBAC-denial signals. The HTTP status (403 `access_denied`)
        // is unchanged. `info!` because this is a security-relevant
        // denial — mirrors the cap-exceeds-authority log level on the
        // post-issuance side.
        Err(AppError::Domain(_)) | Err(AppError::Unauthorized(_)) => {
            tracing::info!(
                denial_reason = "subject_not_authorised",
                "/exchange post-validation 403: IdP token validated but \
                 resolved user rejected by resource-server side"
            );
            return error_outcome(
                StatusCode::FORBIDDEN,
                "access_denied",
                "subject not authorised".to_string(),
                metrics::RESULT_SUBJECT_NOT_AUTHORISED,
            );
        }
        Err(_) => {
            return error_outcome(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error".to_string(),
                metrics::RESULT_INFRASTRUCTURE_ERROR,
            );
        }
    };

    // 8. Mint via the existing ApiTokenUseCase::issue_cli_session.
    //    Truncate client_id to 255 chars at a char boundary BEFORE
    //    handoff (design doc §3 wire-cap).
    let client_name = form.client_id.as_deref().map(|s| {
        if s.len() <= CLIENT_ID_MAX_LEN {
            s.to_string()
        } else {
            let mut cut = CLIENT_ID_MAX_LEN;
            while cut > 0 && !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s[..cut].to_string()
        }
    });

    // Item B6 — distinct mapping per ApiTokenError variant. Caller-side
    // denials (CapExceedsAuthority) MUST NOT collapse into the operator-
    // actionable infrastructure_error bucket; doing so generates false
    // positives on outage dashboards and obscures real outages behind
    // RBAC-denial noise.
    let issued = match ctx
        .api_token_use_case
        .issue_cli_session(
            &principal,
            IssueCliSessionRequest {
                client_name,
                source_ip: source_ip.to_string(),
                requested_scope,
                requested_lifetime_secs,
            },
        )
        .await
    {
        Ok(issued) => issued,
        Err(ApiTokenError::LifetimeBelowMinimum) => {
            // Caller asked for <300s. Wire-shape
            // error: surface 400 with the specific OAuth code so
            // clients can adjust without a 500-handler dance.
            return error_outcome(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "requested_token_lifetime below 300-second minimum".to_string(),
                metrics::RESULT_BAD_REQUEST,
            );
        }
        Err(ApiTokenError::AdminTokenDisallowed) => {
            // Admin scope requested but
            // HORT_TOKEN_ALLOW_ADMIN=false. Wire shape mirrors the Pat
            // path: 400 invalid_request rather than 403 to make the
            // deployment-config nature visible to operators.
            return error_outcome(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "admin tokens disabled by composition-root config".to_string(),
                metrics::RESULT_BAD_REQUEST,
            );
        }
        Err(ApiTokenError::AdminAuthorityRequired) => {
            // Admin scope requested but caller is
            // not admin. 403 access_denied (the same wire shape as
            // any other authority-denial).
            return error_outcome(
                StatusCode::FORBIDDEN,
                "access_denied",
                "admin authority required to declare admin permission".to_string(),
                metrics::RESULT_CAP_EXCEEDS_AUTHORITY,
            );
        }
        Err(ApiTokenError::CapExceedsAuthority { failed }) => {
            // Caller-side denial — security-relevant but not an outage.
            // Mirrors the PAT-shape rejection log pattern (info!).
            tracing::info!(
                user_id = %principal.user_id,
                denial_reason = "cap_exceeds_authority",
                failed_count = failed.len(),
                "cli session issuance denied: cap exceeds authority"
            );
            return error_outcome(
                StatusCode::FORBIDDEN,
                "access_denied",
                "issuance not authorized for the resolved user".to_string(),
                metrics::RESULT_CAP_EXCEEDS_AUTHORITY,
            );
        }
        Err(ApiTokenError::Infrastructure(e)) => {
            tracing::error!(
                user_id = %principal.user_id,
                error = %e,
                "cli session issuance failed: infrastructure error"
            );
            return error_outcome(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error".to_string(),
                metrics::RESULT_INFRASTRUCTURE_ERROR,
            );
        }
        Err(other) => {
            // Defensive catch-all — the typed ApiTokenError variants
            // we should ever see on this code path (CapExceedsAuthority,
            // Infrastructure, LifetimeBelowMinimum, AdminTokenDisallowed,
            // AdminAuthorityRequired) are matched above. There is no
            // hardcoded `declared_permissions` +
            // `expires_in_days` safety net — caller-supplied scope and
            // lifetime flow through `clamp_lifetime` and the existing
            // admin gate. `issue_cli_session_inner` still controls
            // `name`, `description`, and `repository_ids`, so
            // name/description/repo-set-shape errors AND the
            // service-account/admin-mint paths remain unreachable from
            // here. Reaching this arm indicates a server-side regression
            // in one of those remaining invariants — not user input.
            // Log at error! for dashboard alerting; do NOT leak the
            // typed variant name on the wire.
            tracing::error!(
                user_id = %principal.user_id,
                variant = ?other,
                "cli session issuance failed: unexpected ApiTokenError variant \
                 (defensive defect — see exchange.rs catch-all comment)"
            );
            return error_outcome(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal validation error".to_string(),
                metrics::RESULT_VALIDATION_ERROR,
            );
        }
    };

    // Surface the actual issued lifetime (post-clamp)
    // so hort-cli can render its `expires_at` + clamp `note:` lines.
    // `issued.expires_at` is always Some for CliSession (the
    // unbounded-svc path is service-account-only); the saturating
    // conversion bottoms out at 0 if the clock has already drifted
    // past, which surfaces as an immediately-expired token to the
    // client. Falling back to the per-cap-shape default would lie
    // to the client about its session lifetime.
    let expires_in = issued
        .expires_at
        .map(|exp| (exp - chrono::Utc::now()).num_seconds().max(0) as u64)
        .unwrap_or(0);
    let body = ExchangeResponseBody {
        access_token: issued.plaintext,
        issued_token_type: TOKEN_TYPE_ACCESS_TOKEN,
        token_type: TOKEN_TYPE_BEARER,
        expires_in,
    };
    Outcome {
        response: with_no_store((StatusCode::OK, Json(body)).into_response()),
        label: metrics::RESULT_SUCCESS,
        kind: metrics::KIND_CLI_SESSION,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn invalid_request_outcome(description: String) -> Outcome {
    // RFC 6749 wire-shape rejection. Metric label
    // `bad_request`, NOT `source_token_invalid`. Wire body still uses
    // the OAuth `invalid_request` error code per RFC 6749 §5.2.
    //
    // The dispatch-arm wire-shape gates (grant_type / subject_token /
    // subject_token_type / requested_token_type) ALL fire before the
    // `kind` branch can be decided — they cannot meaningfully be
    // attributed to either dispatch path, so they default to
    // `KIND_CLI_SESSION` for catalog
    // continuity.
    error_outcome(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        description,
        metrics::RESULT_BAD_REQUEST,
    )
}

fn error_outcome(
    status: StatusCode,
    error: &'static str,
    description: String,
    label: &'static str,
) -> Outcome {
    error_outcome_with_kind(status, error, description, label, metrics::KIND_CLI_SESSION)
}

/// `error_outcome` variant that lets the federation
/// branch emit its responses with `kind = "federated_jwt"`. The
/// access_token branch keeps using [`error_outcome`] so all its existing
/// emission sites stay attributed to `kind = "cli_session"`.
fn error_outcome_with_kind(
    status: StatusCode,
    error: &'static str,
    description: String,
    label: &'static str,
    kind: &'static str,
) -> Outcome {
    let body = ExchangeErrorBody {
        error,
        error_description: description,
    };
    Outcome {
        response: with_no_store((status, Json(body)).into_response()),
        label,
        kind,
    }
}

/// Apply `Cache-Control: no-store` to every response (success AND
/// error). Design doc §8 invariant 6 — plaintext leaves the server
/// exactly once.
fn with_no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Map axum's `FormRejection` into an `Outcome`.
/// `InvalidFormContentType` returns HTTP 415; every
/// other variant returns HTTP 400. Both share the OAuth `error` code
/// `invalid_request` (RFC 6749 §5.2) and the `bad_request` metric
/// label.
fn form_rejection_outcome(rej: &axum::extract::rejection::FormRejection) -> Outcome {
    use axum::extract::rejection::FormRejection as F;
    let (status, description) = match rej {
        F::InvalidFormContentType(_) => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/x-www-form-urlencoded".to_string(),
        ),
        F::FailedToDeserializeForm(e) => {
            (StatusCode::BAD_REQUEST, format!("malformed form body: {e}"))
        }
        F::FailedToDeserializeFormBody(e) => {
            (StatusCode::BAD_REQUEST, format!("malformed form body: {e}"))
        }
        F::BytesRejection(_) => (
            StatusCode::BAD_REQUEST,
            "failed to read request body".to_string(),
        ),
        // FormRejection is `#[non_exhaustive]` — fall back to a
        // generic invalid_request message for any future variant.
        _ => (StatusCode::BAD_REQUEST, "invalid request body".to_string()),
    };
    error_outcome(
        status,
        "invalid_request",
        description,
        metrics::RESULT_BAD_REQUEST,
    )
}

fn emit_counter(kind: &'static str, label: &'static str) {
    // The `kind` label MUST appear on every
    // emission: `cli_session` for the IdP-mediated path, `federated_jwt`
    // for the federation branch.
    ::metrics::counter!(
        metrics::COUNTER,
        metrics::KIND => kind,
        metrics::RESULT => label,
    )
    .increment(1);
}

fn record_duration(kind: &'static str, label: &'static str, seconds: f64) {
    ::metrics::histogram!(
        metrics::HISTOGRAM,
        metrics::KIND => kind,
        metrics::RESULT => label,
    )
    .record(seconds);
}

// ===========================================================================
// Federation branch on /auth/exchange
// ===========================================================================

/// Maximum minted-bearer lifetime for the federation branch. Per design
/// doc §4 step 8 ("validity = min(1h, jwt.exp - now)"). The federation
/// flow mints a non-refreshable bearer; ≤1 h keeps the laptop-theft /
/// CI-runner-leak blast radius bounded.
const FEDERATION_MAX_LIFETIME_SECS: u64 = 3600;

/// Handler-layer deny enum.
///
/// Wraps the validator port's [`FederationDenyReason`] (eight variants
/// describing JWT-validation rejections) with two handler-layer variants
/// — `NoSaMatch` and `MultipleSaMatch` — produced AFTER claims have been
/// validated and the SA-resolution walk runs. The two responsibilities
/// (claim validation vs SA resolution) are deliberately separated so the
/// port's enum stays exclusively the validator's contract; mixing the
/// SA-resolution variants into [`FederationDenyReason`] would pollute
/// the port enum with concerns the validator itself does not produce.
///
/// No `Deserialize` / `Serialize` impls — this enum is internal-only
/// and never crosses an HTTP boundary as a deserialised value.
#[derive(Debug)]
enum FederationHandlerError {
    /// Validator port rejected the JWT (step 1–6 of the §4 flow).
    Validator(FederationDenyReason),
    /// Step 7 of the §4 flow: zero `ServiceAccount`s matched the
    /// validated claims. Operator must declare a `ServiceAccount` with
    /// `federatedIdentities[].claims` matching this JWT shape.
    NoSaMatch,
    /// Step 7 of the §4 flow: multiple `ServiceAccount`s matched the
    /// validated claims. Per §4 "Multi-match policy" this is a
    /// configuration error, not an authorization choice — the handler
    /// denies and surfaces the SA names at INFO so the operator can
    /// narrow the trust policies.
    MultipleSaMatch { sa_names: Vec<String> },
    /// The presented JWT's identity
    /// is already in the durable replay seen-set within its TTL window.
    /// `composite` selects `replayed_composite` vs `replayed_jti`. 401
    /// `invalid_grant`. No token minted.
    ReplayDetected { composite: bool },
    /// The replay guard could not
    /// be evaluated (seen-set unreachable). Fail-CLOSED: 503
    /// `temporarily_unavailable`, mirroring the existing
    /// composition-unavailable 503 path. No token minted.
    ReplayGuardUnavailable,
    /// The resolved issuer
    /// requires a `jti` (none present), or allows missing `jti` but
    /// the JWT also lacks `iat` so the composite key is not
    /// constructible. A *validation* deny (never reached the guard).
    /// 401 `invalid_grant`.
    JtiRequired,
}

impl FederationHandlerError {
    /// Wire-form string for the `result` metric label and the
    /// `reason = ...` deny-log field.
    fn as_str(&self) -> &'static str {
        match self {
            Self::Validator(r) => r.as_str(),
            Self::NoSaMatch => metrics::RESULT_NO_SA_MATCH,
            Self::MultipleSaMatch { .. } => metrics::RESULT_MULTIPLE_SA_MATCH,
            Self::ReplayDetected { composite: false } => metrics::RESULT_REPLAYED_JTI,
            Self::ReplayDetected { composite: true } => metrics::RESULT_REPLAYED_COMPOSITE,
            Self::ReplayGuardUnavailable => metrics::RESULT_REPLAY_GUARD_UNAVAILABLE,
            Self::JtiRequired => metrics::RESULT_JTI_REQUIRED,
        }
    }

    /// Static deny-hint surfaced in the HTTP error body.
    /// Deny-hint pattern: short, operator-facing, no PII.
    fn deny_hint(&self) -> &'static str {
        match self {
            Self::Validator(FederationDenyReason::InvalidFormat) => {
                "subject_token is not a valid JWT"
            }
            Self::Validator(FederationDenyReason::UnknownIssuer) => {
                "no OidcIssuer matches `iss` — declare one or fix the JWT"
            }
            Self::Validator(FederationDenyReason::AlgorithmNotAllowed) => {
                "alg not in OidcIssuer.allowedAlgorithms"
            }
            Self::Validator(FederationDenyReason::UnknownKid) => {
                "kid not in trusted JWKS (rotate?)"
            }
            Self::Validator(FederationDenyReason::SignatureInvalid) => {
                "signature failed verification against trusted JWKS"
            }
            Self::Validator(FederationDenyReason::AudMismatch) => "aud not in OidcIssuer.audiences",
            Self::Validator(FederationDenyReason::Expired) => "subject_token expired",
            Self::Validator(FederationDenyReason::NotYetValid) => "subject_token nbf in future",
            Self::NoSaMatch => "no ServiceAccount matches the JWT's claims",
            Self::MultipleSaMatch { .. } => {
                "multiple ServiceAccounts match — config error, narrow the claim selectors"
            }
            Self::ReplayDetected { composite: false } => {
                "subject_token already exchanged (jti replay)"
            }
            Self::ReplayDetected { composite: true } => "subject_token already exchanged (replay)",
            Self::JtiRequired => "issuer requires a jti claim",
            Self::ReplayGuardUnavailable => "replay guard unavailable — retry",
        }
    }

    /// HTTP status for this deny reason. All federation denies map to
    /// 401 `invalid_grant` per RFC 8693 §2.4. (`InvalidFormat` could
    /// arguably be a 400 wire-shape error, but the validator's
    /// `FederationDenyReason::InvalidFormat` includes "missing kid /
    /// malformed payload" — both of which look like credential failures
    /// from the operator's perspective; 401 keeps the dispatch uniform.)
    fn status(&self) -> StatusCode {
        match self {
            // The replay-guard
            // outage is the ONLY non-401 federation deny: fail-CLOSED
            // 503, mirroring the existing composition-unavailable 503
            // path. Replays and `jti_required` stay 401 `invalid_grant`
            // per RFC 8693 §2.4.
            Self::ReplayGuardUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    /// RFC 6749 §5.2 / RFC 8693 §2.4 `error` body code. 401s are
    /// `invalid_grant`; the 503 fail-closed deny is
    /// `temporarily_unavailable` (mirrors the existing
    /// composition-unavailable 503 body code).
    fn error_code(&self) -> &'static str {
        match self {
            Self::ReplayGuardUnavailable => "temporarily_unavailable",
            _ => "invalid_grant",
        }
    }
}

/// Federation branch entry point.
///
/// Threads the validated JWT through: validator port → SA resolution
/// → system-mint pipeline. Every exit path (success + every deny
/// reason + every internal-error path) emits exactly one structured
/// `info!` deny log (on the failure paths) and exactly one
/// `hort_token_exchange_total{kind=federated_jwt, result=*}` counter
/// increment via the wrapper in `post_exchange`.
async fn handle_federated_jwt(
    ctx: &Arc<AppContext>,
    subject_token: &str,
    requested_token_type: Option<&str>,
    client_id: Option<&str>,
    source_ip: &str,
) -> Outcome {
    // 0. requested_token_type (if present) must still be access_token.
    //    The federation branch issues an access token (a TokenKind::ServiceAccount
    //    bearer); `jwt` as the issued type is meaningless here.
    if let Some(req_type) = requested_token_type {
        if !req_type.is_empty() && req_type != TOKEN_TYPE_ACCESS_TOKEN {
            return error_outcome_with_kind(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                format!("requested_token_type must be {TOKEN_TYPE_ACCESS_TOKEN}"),
                metrics::RESULT_BAD_REQUEST,
                metrics::KIND_FEDERATED_JWT,
            );
        }
    }

    // 1. Ports must be wired. Federation is opt-in (composition wires
    //    both slots only when auth is enabled); a None slot at this
    //    point is a composition bug.
    let Some(validator) = ctx.federated_jwt_validator.as_ref() else {
        tracing::error!(
            "/exchange (federated_jwt) invoked with federated_jwt_validator = None — \
             composition bug (auth disabled?)"
        );
        return error_outcome_with_kind(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "federation subsystem not configured".to_string(),
            metrics::RESULT_INTERNAL_ERROR,
            metrics::KIND_FEDERATED_JWT,
        );
    };
    let Some(service_accounts) = ctx.service_accounts.as_ref() else {
        tracing::error!(
            "/exchange (federated_jwt) invoked with service_accounts = None — composition bug"
        );
        return error_outcome_with_kind(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "federation subsystem not configured".to_string(),
            metrics::RESULT_INTERNAL_ERROR,
            metrics::KIND_FEDERATED_JWT,
        );
    };

    // 2. Run validator (steps 1-6 of the §4 flow).
    let claims = match validator.validate(subject_token).await {
        Ok(c) => c,
        Err(reason) => {
            // On a validator deny we did NOT successfully extract
            // iss/sub/aud — the validator's failure may have happened
            // before payload decode. Best-effort decode just for the
            // deny-log; signature trust is irrelevant here because we
            // are NOT going to mint a token, we are only labelling the
            // audit line.
            //
            // This is a second
            // base64+JSON parse of the same JWT bytes the validator
            // already parsed (it splits the JWT internally to find
            // `iss` for issuer lookup). The duplication is bounded
            // (one extra parse on the deny path only — never on
            // the success path) and the cost is negligible compared
            // to the network + cryptographic work the validator
            // already paid for. Lifting `UnverifiedPayload` out of
            // the adapter and re-using it here would couple two
            // layers across the port boundary; the deny-log audit
            // line is cheap enough to not warrant that coupling.
            let (iss, sub, aud) = peek_jwt_payload_unverified(subject_token);
            let err = FederationHandlerError::Validator(reason);
            return deny_outcome(&err, &iss, &sub, &aud);
        }
    };

    // 3. Walk SAs (step 7 of the §4 flow). Bounded by the operator's
    //    CRD count; the list reads back composed aggregates (one
    //    query, joined in Rust) so this is not an N+1.
    let sas = match service_accounts.list().await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(
                error = %err,
                iss = %claims.issuer,
                sub = %claims.subject,
                "federation: ServiceAccountRepository::list() failed"
            );
            return error_outcome_with_kind(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error".to_string(),
                metrics::RESULT_INTERNAL_ERROR,
                metrics::KIND_FEDERATED_JWT,
            );
        }
    };

    let SaMatchOutcome {
        matches,
        any_audience_denied,
        any_empty_claims,
    } = collect_sa_matches(&sas, &claims);

    let sa: &ServiceAccount = match matches.len() {
        0 => {
            // When the *sole* reason
            // no SA matched is the per-FI audience binding or the
            // empty-claims fail-closed skip, surface the
            // security-relevant signal on the dedicated counter. The
            // protocol outcome stays `no_sa_match` on
            // `hort_token_exchange_total` (the HTTP contract is
            // unchanged: still 401 `invalid_grant`, "no ServiceAccount
            // matches"), so dashboards keyed on the exchange counter do
            // not regress; the F-7/F-8 split rides only the new metric.
            // `info!` (audit, not `err`) on the empty-claims skip — a
            // `{}` row reaching runtime means an out-of-band write and
            // is security-relevant per design §4.
            if any_empty_claims {
                tracing::info!(
                    event = "federation_empty_claims_skipped",
                    iss = %claims.issuer,
                    sub = %claims.subject,
                    "F-8: a federated_identities row carried an empty claims map — \
                     fail-closed skip (apply-time validation should have rejected it; \
                     this row was likely written out-of-band)"
                );
                emit_fed_sa_match(metrics::FED_SA_RESULT_DENIED_EMPTY_CLAIMS);
            }
            if any_audience_denied {
                emit_fed_sa_match(metrics::FED_SA_RESULT_DENIED_AUDIENCE);
            }
            return deny_outcome(
                &FederationHandlerError::NoSaMatch,
                &claims.issuer,
                &claims.subject,
                &claims.audience,
            );
        }
        1 => {
            emit_fed_sa_match(metrics::FED_SA_RESULT_MATCHED);
            matches[0]
        }
        _ => {
            let sa_names: Vec<String> = matches.iter().map(|s| s.name.clone()).collect();
            return deny_outcome(
                &FederationHandlerError::MultipleSaMatch {
                    sa_names: sa_names.clone(),
                },
                &claims.issuer,
                &claims.subject,
                &claims.audience,
            );
        }
    };

    // 4. Compute validity cap (step 8): min(1h, jwt.exp - now). The
    //    `as_secs()` saturates at 0 if exp is already in the past — but
    //    the validator's `Expired` check would have caught that case
    //    upstream, so we treat any non-positive remaining lifetime here
    //    as a defensive 0 (clamped to the minimum below).
    let now = chrono::Utc::now();
    let remaining_secs = (claims.expires_at - now).num_seconds().max(0) as u64;
    let lifetime_secs = remaining_secs.min(FEDERATION_MAX_LIFETIME_SECS);

    // 5. Build the issue request. `client_name` carries the CRD name
    //    so the audit row's `name` column is operator-recognisable;
    //    `description` carries the source IP for revocation UX,
    //    mirroring the CliSession path.
    //
    //    alpha-F9b: `declared_permissions` is derived from the SA's
    //    role via `service_account_permission_for_role` — the SAME
    //    mapping the apply pipeline uses to expand the SA's role into
    //    a `GrantSubject::User(backing_user_id)` grant. An empty
    //    `declared_permissions` was the bug: the cap leg of
    //    `RbacEvaluator::authorize` (`cap_allows_optional_repo`)
    //    requires `cap.permissions.contains(&requested)` — empty
    //    permissions never contain anything, so an empty cap denies
    //    every authz check regardless of the User-subject grant. The
    //    pre-fix comment claimed "the backing SA user already carries
    //    the role + repo grants" which is true for the user-grants
    //    leg but irrelevant once the cap leg has already returned
    //    false. Per-repo scoping stays on the User-subject grant —
    //    we leave `repository_ids = None` so a future apply that
    //    extends the SA's `repositories` list doesn't strand
    //    already-minted tokens with a stale cap.
    // Resolve the matched
    // issuer's `require_jti` flag so the use-case replay guard can pick
    // the `Jti` vs `Composite` key (or deny `jti_required`). The
    // `OidcIssuerRepository` slot is wired iff auth is enabled (same
    // condition as the validator); reaching here with it unwired is a
    // composition bug, and a jti-less JWT must NOT silently fall to the
    // weaker composite path on a lookup failure — fail CLOSED to the
    // secure default (`require_jti = true`).
    let require_jti = match ctx.oidc_issuers.as_ref() {
        Some(repo) => match repo.get_by_name(&claims.issuer_name).await {
            Ok(Some(issuer)) => issuer.require_jti,
            Ok(None) => {
                // The validator resolved this issuer moments ago; a
                // None here means an apply-time delete raced the
                // exchange. Default to the secure posture.
                tracing::warn!(
                    iss = %claims.issuer,
                    issuer_name = %claims.issuer_name,
                    "federation: issuer vanished between validate and require_jti \
                     lookup — defaulting require_jti=true (secure)"
                );
                true
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    issuer_name = %claims.issuer_name,
                    "federation: OidcIssuerRepository::get_by_name failed — \
                     defaulting require_jti=true (secure)"
                );
                true
            }
        },
        None => {
            tracing::error!(
                "federation: oidc_issuers slot unwired (composition bug) — \
                 defaulting require_jti=true (secure)"
            );
            true
        }
    };

    let client_label = client_id.unwrap_or("federated").to_string();
    // alpha-F9b — role-derived cap permission. A corrupt `sa.role` is
    // an Invariant from the apply pipeline (apply-time validator gates
    // role ∈ {developer, reader}), so unreachable here in practice;
    // surface it as a 500 rather than mint an empty-cap token that
    // would deterministically deny.
    let role_permission =
        match hort_app::use_cases::apply_config_use_case::service_account_permission_for_role(
            &sa.role,
        ) {
            Ok(p) => p,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    sa_name = %sa.name,
                    role = %sa.role,
                    "federation: ServiceAccount carries an invalid role — \
                     apply-time validator should have rejected this. \
                     Failing closed."
                );
                return error_outcome_with_kind(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "internal error".to_string(),
                    metrics::RESULT_INTERNAL_ERROR,
                    metrics::KIND_FEDERATED_JWT,
                );
            }
        };
    let issue_request = IssueTokenRequest {
        name: sa.name.clone(),
        description: Some(format!(
            "Federated via /exchange from {source_ip} (client={client_label})"
        )),
        declared_permissions: vec![role_permission],
        repository_ids: None,
        expires_in_days: None,
        expires_in_seconds: Some(lifetime_secs),
        federation_source: Some(FederationSource {
            issuer: claims.issuer_name.clone(),
            jti: claims.jti.clone(),
            subject: claims.subject.clone(),
            // Raw wire values for the
            // composite replay key; `iss` is the literal claim, NOT the
            // resolved `OidcIssuer.name`.
            iss: claims.issuer.clone(),
            iat: claims.iat,
            exp: claims.exp_raw,
            require_jti,
        }),
    };

    let issued = match ctx
        .api_token_use_case
        .issue_for_service_account_system(sa.backing_user_id, issue_request)
        .await
    {
        Ok(i) => i,
        // The replay-guard denies
        // are first-class federation denies, routed through the SAME
        // single `deny_outcome` emission site as every other federation
        // deny so they get exactly one structured `info!` + one
        // `hort_token_exchange_total{kind=federated_jwt}` increment, the
        // identical shape. The `hort_jwt_replay_rejected_total` counter
        // for the two `replayed_*` cases is emitted in hort-app at the
        // guard call site (single emitter), NOT here.
        Err(ApiTokenError::ReplayDetected { composite }) => {
            return deny_outcome(
                &FederationHandlerError::ReplayDetected { composite },
                &claims.issuer,
                &claims.subject,
                &claims.audience,
            );
        }
        Err(ApiTokenError::ReplayGuardUnavailable) => {
            return deny_outcome(
                &FederationHandlerError::ReplayGuardUnavailable,
                &claims.issuer,
                &claims.subject,
                &claims.audience,
            );
        }
        Err(ApiTokenError::JtiRequired) => {
            return deny_outcome(
                &FederationHandlerError::JtiRequired,
                &claims.issuer,
                &claims.subject,
                &claims.audience,
            );
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                sa_name = %sa.name,
                iss = %claims.issuer,
                sub = %claims.subject,
                "federation: system-mint failed for matched ServiceAccount"
            );
            return error_outcome_with_kind(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error".to_string(),
                metrics::RESULT_MINT_FAILED,
                metrics::KIND_FEDERATED_JWT,
            );
        }
    };

    let expires_in = issued
        .expires_at
        .map(|exp| (exp - chrono::Utc::now()).num_seconds().max(0) as u64)
        .unwrap_or(lifetime_secs);
    let body = ExchangeResponseBody {
        access_token: issued.plaintext,
        // RFC 8693 §2.2.1 — `issued_token_type` describes the issued
        // token, not the subject token. The minted token is an
        // access_token (a `TokenKind::ServiceAccount` bearer) — only
        // the SUBJECT token differed (it was a JWT).
        issued_token_type: TOKEN_TYPE_ACCESS_TOKEN,
        token_type: TOKEN_TYPE_BEARER,
        expires_in,
    };
    // Bump
    // `hort_service_account_authenticated_total` on the federation
    // success path. Honours the workspace-wide
    // `METRICS_INCLUDE_SERVICE_ACCOUNT_LABEL` collapse so the per-SA
    // dimension stays governed by one env var across this counter
    // and the rotation gauge.
    emit_service_account_authenticated(
        &sa.name,
        SA_AUTH_SOURCE_FEDERATED,
        ctx.include_service_account_label,
    );
    tracing::info!(
        sa_name = %sa.name,
        token_id = %issued.id,
        iss = %claims.issuer_name,
        sub = %claims.subject,
        expires_in_secs = expires_in,
        "federation token minted"
    );
    Outcome {
        response: with_no_store((StatusCode::OK, Json(body)).into_response()),
        label: metrics::RESULT_SUCCESS,
        kind: metrics::KIND_FEDERATED_JWT,
    }
}

/// The `aud` claim key. When a
/// `FederatedIdentity` fragment pins this key it is bound against the
/// validator-resolved [`ValidatedClaims::audience`] (the single
/// audience `match_audience` already intersected against
/// `OidcIssuer.audiences`), NOT the raw `all_claims["aud"]`. The raw
/// value may be an RFC 7519 §4.1.3 array, which the generic
/// `.as_str()` path silently fails to match; binding to the resolved
/// scalar is both correct for the array case AND the F-7 fix —
/// without it, a JWT minted for a *different* relying party whose
/// other claims happen to satisfy the fragment could assume the SA
/// (confused-deputy / token-redirection).
const AUD_CLAIM_KEY: &str = "aud";

/// Per-FI evaluation outcome. `Match` / `NoMatch` are the only two
/// gate states; `AudienceDenied` and `EmptyClaims` are *refinements*
/// of `NoMatch` used solely to drive the
/// `hort_fed_sa_match_total{result=...}` observability split — neither
/// is ever a match.
#[derive(Debug, PartialEq, Eq)]
enum FiEval {
    /// Every claim (including any `aud` binding) matched.
    Match,
    /// At least one non-`aud` claim mismatched. Generic no-match.
    NoMatch,
    /// Every non-`aud` claim matched, but the FI pinned an `aud`
    /// selector that did not equal the validator-resolved audience.
    /// The F-7 confused-deputy signal.
    AudienceDenied,
    /// The FI's `claims` map is empty.
    /// Apply-time validation rejects this (ADR 0018), so a
    /// row reaching here means an out-of-band write (raw SQL /
    /// restore / migration bug). The empty exact-match set is
    /// vacuously-true (`[].iter().all() ⇒ true`) and would otherwise
    /// let ANY JWT from the issuer assume the SA — fail CLOSED: this
    /// FI never matches.
    EmptyClaims,
}

/// Evaluate one `FederatedIdentity` against the validated claims.
///
/// String-equality matching only (`FederatedIdentity.claims` is
/// `BTreeMap<String, String>` — regex/jq deliberately out of
/// scope). The `aud` key is special-cased to bind the
/// validator-resolved audience per [`AUD_CLAIM_KEY`].
fn evaluate_fi(
    fi: &hort_domain::entities::service_account::FederatedIdentity,
    claims: &ValidatedClaims,
) -> FiEval {
    if fi.issuer_name != claims.issuer_name {
        return FiEval::NoMatch;
    }
    // Fail-closed runtime skip BEFORE the
    // `.all()` walk. `[].iter().all(_) == true`, so an empty fragment
    // would otherwise match every JWT from the issuer. Apply-time
    // validation already rejects this shape (ADR 0018);
    // this is the defense-in-depth layer.
    if fi.claims.is_empty() {
        return FiEval::EmptyClaims;
    }
    let mut non_aud_all_match = true;
    let mut aud_ok = true;
    for (k, expected) in &fi.claims {
        if k == AUD_CLAIM_KEY {
            // F-7: bind to the resolved single audience, not the raw
            // (possibly-array) `all_claims["aud"]`.
            aud_ok = claims.audience == *expected;
        } else {
            let matched = claims
                .all_claims
                .get(k)
                .and_then(|v| v.as_str())
                .map(|actual| actual == expected)
                .unwrap_or(false);
            if !matched {
                non_aud_all_match = false;
            }
        }
    }
    match (non_aud_all_match, aud_ok) {
        (true, true) => FiEval::Match,
        // Sole reason for the non-match is the audience binding — the
        // F-7 confused-deputy case the audit names. Surfaced as a
        // distinct metric label so a reviewer sees token-redirection
        // attempts without disentangling them from generic no-match.
        (true, false) => FiEval::AudienceDenied,
        _ => FiEval::NoMatch,
    }
}

/// SA-resolution outcome. `matches` is the set of `ServiceAccount`s a
/// matching `FederatedIdentity` selected. `any_audience_denied` /
/// `any_empty_claims` are set when at least one FI was rejected
/// *solely* by the F-7 audience binding / the F-8 empty-claims
/// fail-closed skip and no SA matched — the call site uses them to
/// emit `hort_fed_sa_match_total{result=denied_audience|denied_empty_claims}`
/// so the confused-deputy and empty-claims signals are observable
/// without disentangling them from the generic `no_sa_match` bucket.
struct SaMatchOutcome<'a> {
    matches: Vec<&'a ServiceAccount>,
    any_audience_denied: bool,
    any_empty_claims: bool,
}

/// Walk every `ServiceAccount` looking for at least one
/// `FederatedIdentity` row whose `issuer_name` matches the validated
/// JWT's issuer AND whose `claims` map is a subset (every entry exact-
/// matches) of the validated JWT's claim map.
///
/// Empty-claims fragments would match every JWT; apply-time validation
/// rejects `FederatedIdentity` rows with an empty `claims` map
/// (anti-pattern checklist). There is also a
/// runtime fail-closed skip here as defense-in-depth against an
/// out-of-band `claims = '{}'` row — the walk no longer *trusts* that
/// invariant, it re-checks it.
fn collect_sa_matches<'a>(
    sas: &'a [ServiceAccount],
    claims: &ValidatedClaims,
) -> SaMatchOutcome<'a> {
    let mut matches: Vec<&ServiceAccount> = Vec::new();
    let mut any_audience_denied = false;
    let mut any_empty_claims = false;
    for sa in sas {
        for fi in &sa.federated_identities {
            match evaluate_fi(fi, claims) {
                FiEval::Match => {
                    matches.push(sa);
                    break; // One matching FI is enough for this SA.
                }
                FiEval::AudienceDenied => {
                    any_audience_denied = true;
                }
                FiEval::EmptyClaims => {
                    any_empty_claims = true;
                }
                FiEval::NoMatch => {}
            }
        }
    }
    // Only meaningful when nothing matched — a successful match
    // elsewhere makes a deny on a different FI moot.
    let no_match = matches.is_empty();
    SaMatchOutcome {
        matches,
        any_audience_denied: any_audience_denied && no_match,
        any_empty_claims: any_empty_claims && no_match,
    }
}

/// Emit the SA-resolution outcome counter. Single
/// emission helper so every result value goes through one site —
/// mirrors the `emit_counter` discipline for `hort_token_exchange_total`.
fn emit_fed_sa_match(result: &'static str) {
    ::metrics::counter!(
        metrics::FED_SA_MATCH_COUNTER,
        metrics::RESULT => result,
    )
    .increment(1);
}

/// Emit the structured deny log AND build the 401 response. Single
/// emission site so every deny variant produces an identical log shape
/// (design doc §4 "Deny logging" / §7 — no claim values beyond `iss`,
/// `sub`, `aud` at INFO; `MultipleSaMatch` additionally surfaces the
/// matched SA names per the multi-match policy).
fn deny_outcome(err: &FederationHandlerError, iss: &str, sub: &str, aud: &str) -> Outcome {
    let reason = err.as_str();
    // Empty audience renders as the explicit "<absent>" sentinel so the
    // log line is well-formed when the JWT carried no `aud`.
    let aud_field = if aud.is_empty() { "<absent>" } else { aud };
    match err {
        FederationHandlerError::MultipleSaMatch { sa_names } => {
            tracing::info!(
                event = "token_exchange_denied",
                subject_token_type = "jwt",
                reason = %reason,
                iss = %iss,
                sub = %sub,
                aud = %aud_field,
                sa_candidates = ?sa_names,
                "federation deny"
            );
        }
        _ => {
            tracing::info!(
                event = "token_exchange_denied",
                subject_token_type = "jwt",
                reason = %reason,
                iss = %iss,
                sub = %sub,
                aud = %aud_field,
                "federation deny"
            );
        }
    }
    error_outcome_with_kind(
        err.status(),
        err.error_code(),
        err.deny_hint().to_string(),
        reason,
        metrics::KIND_FEDERATED_JWT,
    )
}

/// Best-effort decode of a JWT header + payload for the deny-log shape.
/// **Signature trust irrelevant** — this helper runs only on validator
/// rejection paths, where the validator has ALREADY refused the token.
/// The output is used only to label the audit line.
///
/// Returns `(iss, sub, aud)` extracted from the payload. Each field is
/// the literal string `"unknown"` (or `""` for `aud`, which the
/// `deny_outcome` site re-renders as `"<absent>"`) when extraction
/// fails. No allocation budget — JWTs are size-bounded by `axum`'s
/// form-body limit upstream; this 20-line decoder is bounded by that.
fn peek_jwt_payload_unverified(jwt: &str) -> (String, String, String) {
    let mut parts = jwt.split('.');
    let _header = parts.next();
    let payload_b64 = match parts.next() {
        Some(p) if !p.is_empty() => p,
        _ => return ("unknown".to_string(), "unknown".to_string(), String::new()),
    };
    // RFC 7515 §2 — JWTs use base64url WITHOUT padding.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload_b64) else {
        return ("unknown".to_string(), "unknown".to_string(), String::new());
    };
    let Ok(payload): Result<serde_json::Value, _> = serde_json::from_slice(&payload_bytes) else {
        return ("unknown".to_string(), "unknown".to_string(), String::new());
    };
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    // `aud` may be a single string or an array; render the first entry
    // either way for the audit line.
    let aud = match payload.get("aud") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => arr
            .first()
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_default(),
        _ => String::new(),
    };
    (iss, sub, aud)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header as http_header, Request, StatusCode};
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;
    use uuid::Uuid;

    use base64::Engine as _;
    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::api_token_use_case::{ApiTokenIssuanceConfig, ApiTokenUseCase};
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::user::{AuthProvider, User};
    use hort_domain::ports::identity_provider::{IdentityProvider, IdpClaims, OidcValidationError};
    use hort_domain::ports::user_repository::UserRepository;

    use super::*;

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_api_token_use_case, with_auth, MockPorts};

    /// A CliSession JWT signer over a
    /// throwaway Ed25519 key (built via PEM so no `ed25519-dalek`
    /// dev-dep is needed). The exchange-test `ApiTokenUseCase` attaches
    /// it so `issue_cli_session` can mint the signed JWT.
    fn cli_session_signer() -> Arc<hort_app::cli_session_signing::CliSessionTokenSigner> {
        const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIDZ8p91dvQwtVEfepJLRhRzzpZilORVQ8b4YDZcteA1T\n\
-----END PRIVATE KEY-----\n";
        let key = Arc::new(
            hort_app::oci_token_signing::OciTokenSigningKey::from_pem(TEST_KEY_PEM, None)
                .expect("parse test signing key"),
        );
        Arc::new(hort_app::cli_session_signing::CliSessionTokenSigner::new(
            key,
            "https://hort.test".to_string(),
        ))
    }

    /// Build a fully-wired router exposing only `/api/v1/auth/exchange`.
    /// `register_token` and `register_error` on the returned mock IdP
    /// drive validation outcomes; `mocks.users` and `mocks.api_tokens`
    /// expose the persistence asserts.
    fn build_test_router() -> (Router, Arc<MockIdentityProvider>, MockPorts) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        let idp = Arc::new(MockIdentityProvider::new());
        let (router, _) = build_router_with_idp(&base, &mocks, idp.clone());
        (router, idp, mocks)
    }

    fn form_body(pairs: &[(&str, &str)]) -> String {
        let mut s = String::new();
        for (i, (k, v)) in pairs.iter().enumerate() {
            if i > 0 {
                s.push('&');
            }
            s.push_str(&urlencode(k));
            s.push('=');
            s.push_str(&urlencode(v));
        }
        s
    }

    fn urlencode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    fn post_form(router: Router, body: String) -> impl std::future::Future<Output = Response> {
        let req = Request::post("/api/v1/auth/exchange")
            .header(
                http_header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(body))
            .unwrap();
        async move { router.oneshot(req).await.unwrap() }
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
        })
    }

    fn sample_claims(subject: &str) -> IdpClaims {
        IdpClaims {
            subject: subject.to_string(),
            username: format!("{subject}-user"),
            email: format!("{subject}@example.com"),
            // `team-alpha` maps to the `developer` role per the
            // group_mappings seeded in build_router_with_idp; that
            // role's grants cover Read/Write/Delete which is what
            // the cli_session cap-vs-authority check requires.
            groups: vec!["team-alpha".into()],
            issued_at: Utc::now(),
        }
    }

    fn happy_form(token: &str) -> String {
        form_body(&[
            ("grant_type", EXCHANGE_GRANT_TYPE),
            ("subject_token", token),
            ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
            ("client_id", "hort-cli/0.4.2"),
        ])
    }

    // -- (a) wrong grant_type ------------------------------------------------
    //
    // Wire-shape rejection asserts both
    // HTTP shape AND `hort_token_exchange_total{result="bad_request"}` —
    // status-only assertions would let the metric
    // label be conflated with `source_token_invalid`
    // (credential-abuse). The DebuggingRecorder snapshot pins the
    // narrowed taxonomy.

    #[test]
    fn exchange_rejects_wrong_grant_type() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, _idp, _mocks) = build_test_router();
                let body = form_body(&[
                    ("grant_type", "password"),
                    ("subject_token", "tok"),
                    ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
                ]);
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "unsupported_grant_type");
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_BAD_REQUEST),
            1,
            "expected exactly one bad_request increment; saw: {snap:?}"
        );
        assert_eq!(
            counter_value(
                &snap,
                metrics::COUNTER,
                metrics::RESULT_SOURCE_TOKEN_INVALID
            ),
            0,
            "source_token_invalid must NOT increment on wire-shape rejection; saw: {snap:?}"
        );
    }

    // -- (b) missing required fields ----------------------------------------

    #[test]
    fn exchange_rejects_missing_grant_type() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, _, _) = build_test_router();
                let body = form_body(&[
                    ("subject_token", "tok"),
                    ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
                ]);
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_request");
                assert!(
                    v["error_description"]
                        .as_str()
                        .unwrap()
                        .contains("grant_type"),
                    "got: {v}"
                );
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_BAD_REQUEST),
            1,
            "expected exactly one bad_request increment; saw: {snap:?}"
        );
    }

    #[test]
    fn exchange_rejects_missing_subject_token() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, _, _) = build_test_router();
                let body = form_body(&[
                    ("grant_type", EXCHANGE_GRANT_TYPE),
                    ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
                ]);
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_request");
                assert!(
                    v["error_description"]
                        .as_str()
                        .unwrap()
                        .contains("subject_token"),
                    "got: {v}"
                );
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_BAD_REQUEST),
            1,
            "expected exactly one bad_request increment; saw: {snap:?}"
        );
    }

    #[test]
    fn exchange_rejects_missing_subject_token_type() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, _, _) = build_test_router();
                let body = form_body(&[
                    ("grant_type", EXCHANGE_GRANT_TYPE),
                    ("subject_token", "tok"),
                ]);
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_request");
                assert!(
                    v["error_description"]
                        .as_str()
                        .unwrap()
                        .contains("subject_token_type"),
                    "got: {v}"
                );
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_BAD_REQUEST),
            1,
            "expected exactly one bad_request increment; saw: {snap:?}"
        );
    }

    // -- (c) unsupported subject_token_type ---------------------------------

    #[test]
    fn exchange_rejects_unsupported_subject_token_type() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, _, _) = build_test_router();
                let body = form_body(&[
                    ("grant_type", EXCHANGE_GRANT_TYPE),
                    ("subject_token", "tok"),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:saml2",
                    ),
                ]);
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_request");
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_BAD_REQUEST),
            1,
            "expected exactly one bad_request increment; saw: {snap:?}"
        );
    }

    // -- (c2) id_token is rejected as subject_token_type
    //
    // The closed set deliberately excludes `id_token`. This test pins
    // the behaviour: `id_token` is treated identically to
    // any other unsupported URI (HTTP 400 `invalid_request`, counter
    // `result="bad_request"`).

    #[test]
    fn exchange_rejects_id_token_subject_token_type() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, _, _) = build_test_router();
                let body = form_body(&[
                    ("grant_type", EXCHANGE_GRANT_TYPE),
                    ("subject_token", "tok"),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:id_token",
                    ),
                ]);
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_request");
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_BAD_REQUEST),
            1,
            "expected exactly one bad_request increment for id_token; saw: {snap:?}"
        );
        assert_eq!(
            counter_value(
                &snap,
                metrics::COUNTER,
                metrics::RESULT_SOURCE_TOKEN_INVALID
            ),
            0,
            "id_token rejection is a wire-shape error, NOT a credential-abuse signal; saw: {snap:?}"
        );
    }

    // -- (d) invalid_target -------------------------------------------------

    #[test]
    fn exchange_rejects_invalid_target_when_requested_type_unsupported() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, _, _) = build_test_router();
                let body = form_body(&[
                    ("grant_type", EXCHANGE_GRANT_TYPE),
                    ("subject_token", "tok"),
                    ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
                    (
                        "requested_token_type",
                        "urn:ietf:params:oauth:token-type:jwt",
                    ),
                ]);
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_target");
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_BAD_REQUEST),
            1,
            "expected exactly one bad_request increment; saw: {snap:?}"
        );
    }

    /// Snapshot helper — runs `f` under a `metrics_util::debugging::DebuggingRecorder`
    /// scope and returns every `(name, label_kvs)` counter increment.
    /// We can't drive the async router with the local recorder when
    /// already inside a `#[tokio::test]` runtime (nested
    /// `block_on` panic), so the metric-capturing tests are sync
    /// `#[test]` with their own current-thread runtime per design.
    fn capture_counter_labels<F>(f: F) -> Vec<(String, Vec<(String, String)>)>
    where
        F: FnOnce(),
    {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        ::metrics::with_local_recorder(&recorder, f);
        let mut out = Vec::new();
        for (key, _unit, _desc, value) in snapshotter.snapshot().into_vec() {
            if key.kind() != MetricKind::Counter {
                continue;
            }
            if !matches!(value, DebugValue::Counter(n) if n > 0) {
                continue;
            }
            let labels: Vec<(String, String)> = key
                .key()
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            out.push((key.key().name().to_string(), labels));
        }
        out
    }

    fn has_counter(snapshot: &[(String, Vec<(String, String)>)], name: &str, result: &str) -> bool {
        // Every `hort_token_exchange_total` series carries
        // `kind` AND `result`. The IdP-mediated path emits `kind="cli_session"`. The
        // helper asserts both labels so a regression that drops the
        // kind label (or emits the wrong kind from a wrong branch) is
        // caught by the test that exercises that branch.
        snapshot.iter().any(|(n, labels)| {
            n == name
                && labels
                    .iter()
                    .any(|(k, v)| k == "kind" && v == "cli_session")
                && labels.iter().any(|(k, v)| k == "result" && v == result)
        })
    }

    // -- (e) PAT-shape gate -------------------------------------------------

    #[test]
    fn exchange_rejects_pat_shape_subject_token_before_idp() {
        let snap = capture_counter_labels(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                    let (base, mocks) = build_mock_ctx(metrics_handle);
                    let idp = Arc::new(MockIdentityProvider::new());
                    // Register an error so that any IdP call would
                    // surface as a different status code if the gate
                    // were skipped.
                    idp.register_error(
                        "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        OidcValidationError::SignatureInvalid,
                    );
                    let (router, _) = build_router_with_idp(&base, &mocks, idp);

                    let pat = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                    let body = happy_form(pat);
                    let resp = post_form(router, body).await;
                    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                    let v = body_json(resp).await;
                    assert_eq!(v["error"], "invalid_token");
                    assert!(
                        v["error_description"]
                            .as_str()
                            .unwrap()
                            .contains("IdP-issued JWT"),
                        "got: {v}"
                    );
                });
        });
        assert!(
            has_counter(
                &snap,
                "hort_token_exchange_total",
                "source_token_pat_rejected"
            ),
            "expected source_token_pat_rejected counter; saw: {snap:?}"
        );
    }

    // -- (f) OIDC expired ---------------------------------------------------

    #[test]
    fn exchange_returns_401_on_oidc_expired() {
        let snap = capture_counter_labels(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                    let (base, mocks) = build_mock_ctx(metrics_handle);
                    let idp = Arc::new(MockIdentityProvider::new());
                    idp.register_error("expired-token", OidcValidationError::Expired);
                    let (router, _) = build_router_with_idp(&base, &mocks, idp);
                    let body = happy_form("expired-token");
                    let resp = post_form(router, body).await;
                    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                    let v = body_json(resp).await;
                    assert_eq!(v["error"], "invalid_token");
                });
        });
        assert!(
            has_counter(&snap, "hort_token_exchange_total", "source_token_expired"),
            "expected source_token_expired counter; saw: {snap:?}"
        );
    }

    /// Builder that wires an enabled-auth context with:
    /// - The supplied [`MockIdentityProvider`] (caller pre-registers
    ///   tokens / errors).
    /// - A group mapping `team-alpha → developer` so JIT-resolved
    ///   principals carry a `developer` role.
    /// - An `RbacEvaluator` seeded with a `developer` role granting
    ///   global Read / Write / Delete — enough for the cli_session
    ///   issuance pipeline's cap-vs-authority check (which forces
    ///   `[Read, Write, Delete]` per design doc 039 §6) to succeed.
    fn build_router_with_idp(
        base: &Arc<AppContext>,
        mocks: &MockPorts,
        idp: Arc<MockIdentityProvider>,
    ) -> (Router, Arc<AppContext>) {
        // `team-alpha` IdP group maps to the `developer`
        // claim via `claim_mappings` (ADR 0012).
        let claim_mappings = vec![ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: "team-alpha".into(),
            claim: "developer".into(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }];
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            claim_mappings,
        ));

        // Seed RBAC with `GrantSubject::Claims(["developer"])` grants
        // covering Read / Write / Delete globally so the cli_session
        // cap-vs-authority check (which always requests Read, Write,
        // Delete) clears (flat claim-subject grant set — ADR 0012).
        let grants: Vec<PermissionGrant> =
            [Permission::Read, Permission::Write, Permission::Delete]
                .into_iter()
                .map(|p| PermissionGrant {
                    id: Uuid::new_v4(),
                    subject: GrantSubject::Claims(vec!["developer".into()]),
                    repository_id: None,
                    permission: p,
                    created_at: Utc::now(),
                    managed_by: ManagedBy::Local,
                    managed_by_digest: None,
                })
                .collect();
        let rbac_swap = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(grants)));
        // Wire the CliSession JWT signer +
        // denylist so `issue_cli_session` mints a signed JWT. Without
        // it, the CliSession mint fails closed ("signer not configured").
        let api_token_uc = Arc::new(
            ApiTokenUseCase::new(
                mocks.api_tokens.clone(),
                mocks.users.clone(),
                base.event_store.clone(),
                rbac_swap.clone(),
                ApiTokenIssuanceConfig::default(),
            )
            .with_cli_session_signing(cli_session_signer(), mocks.ephemeral_durable.clone()),
        );
        let ctx_with_auth = with_auth(
            base,
            AuthContext::Enabled {
                authenticate,
                rbac: rbac_swap,
                issuer_url: None,
            },
        );
        let ctx = with_api_token_use_case(&ctx_with_auth, api_token_uc);
        let router = Router::new()
            .nest("/api/v1", token_exchange_routes())
            .with_state(ctx.clone());
        (router, ctx)
    }

    // -- (g) other OIDC failures --------------------------------------------

    #[tokio::test]
    async fn exchange_returns_401_on_oidc_other_failures() {
        for variant in [
            OidcValidationError::UnknownIssuer,
            OidcValidationError::Malformed,
            OidcValidationError::SignatureInvalid,
            OidcValidationError::ClaimMissing("sub".into()),
        ] {
            let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(metrics_handle);
            let idp = Arc::new(MockIdentityProvider::new());
            idp.register_error("bad-token", variant.clone());
            let (router, _) = build_router_with_idp(&base, &mocks, idp);
            let body = happy_form("bad-token");
            let resp = post_form(router, body).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "variant {variant:?} expected 401"
            );
            let v = body_json(resp).await;
            assert_eq!(v["error"], "invalid_token", "variant {variant:?}");
        }
    }

    // -- (h) IdP unavailable ------------------------------------------------

    #[test]
    fn exchange_returns_503_on_idp_unavailable() {
        let snap = capture_counter_labels(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                    let (base, mocks) = build_mock_ctx(metrics_handle);
                    let idp = Arc::new(MockIdentityProvider::new());
                    idp.register_error("idp-down", OidcValidationError::IdpUnavailable);
                    let (router, _) = build_router_with_idp(&base, &mocks, idp);
                    let body = happy_form("idp-down");
                    let resp = post_form(router, body).await;
                    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
                    let v = body_json(resp).await;
                    assert_eq!(v["error"], "temporarily_unavailable");
                });
        });
        assert!(
            has_counter(&snap, "hort_token_exchange_total", "idp_unavailable"),
            "expected idp_unavailable counter; saw: {snap:?}"
        );
    }

    // -- (i) success path — JIT new user ------------------------------------

    #[test]
    fn exchange_succeeds_for_new_user_jit() {
        let mut status: Option<StatusCode> = None;
        let mut body: Option<serde_json::Value> = None;
        let mut cache_ctrl: Option<String> = None;
        let mut had_www_auth = true;
        let mut persisted: Option<User> = None;

        let snap = capture_counter_labels(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                    let (base, mocks) = build_mock_ctx(metrics_handle);
                    let idp = Arc::new(MockIdentityProvider::new());
                    idp.register_token("good-token", sample_claims("idp:abc"));
                    let (router, _) = build_router_with_idp(&base, &mocks, idp);

                    let before = mocks
                        .users
                        .find_by_external_id(AuthProvider::Oidc, "idp:abc")
                        .await
                        .unwrap();
                    assert!(before.is_none(), "no JIT user before the call");

                    let resp = post_form(router, happy_form("good-token")).await;
                    status = Some(resp.status());
                    cache_ctrl = resp
                        .headers()
                        .get(http_header::CACHE_CONTROL)
                        .map(|v| v.to_str().unwrap().to_string());
                    had_www_auth = resp.headers().get(http_header::WWW_AUTHENTICATE).is_some();
                    body = Some(body_json(resp).await);

                    persisted = mocks
                        .users
                        .find_by_external_id(AuthProvider::Oidc, "idp:abc")
                        .await
                        .unwrap();
                });
        });
        assert_eq!(status, Some(StatusCode::OK));
        assert_eq!(cache_ctrl.as_deref(), Some("no-store"));
        assert!(!had_www_auth, "WWW-Authenticate must NOT be emitted");
        let body = body.unwrap();
        let token = body["access_token"].as_str().unwrap();
        // The CliSession access token is a
        // hort-signed JWT (3 dot-separated segments), NOT an opaque
        // `hort_cli_*` token.
        assert!(!token.starts_with("hort_cli_"), "got opaque token: {token}");
        assert_eq!(token.split('.').count(), 3, "expected a JWT, got: {token}");
        assert_eq!(body["token_type"], "Bearer");
        // Default CliSession lifetime is 900 s.
        // The response field reflects the post-clamp issued
        // expiry. Tolerance: a few seconds drift.
        let expires_in = body["expires_in"].as_u64().unwrap();
        assert!(
            (890..=900).contains(&expires_in),
            "expected ≈ 900s (15 min default), got {expires_in}"
        );
        assert_eq!(
            body["issued_token_type"],
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert!(persisted.is_some(), "JIT user should have been inserted");
        assert!(
            has_counter(&snap, "hort_token_exchange_total", "success"),
            "expected success counter; saw: {snap:?}"
        );
    }

    // -- (j) success path — existing user -----------------------------------

    #[tokio::test]
    async fn exchange_succeeds_for_existing_user() {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        let idp = Arc::new(MockIdentityProvider::new());
        idp.register_token("good-token", sample_claims("idp:existing"));

        // Pre-seed an existing user with the same external_id.
        let existing_id = Uuid::new_v4();
        mocks.users.insert(User {
            id: existing_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("idp:existing".into()),
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: false,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let (router, _) = build_router_with_idp(&base, &mocks, idp);
        let body = happy_form("good-token");
        let resp = post_form(router, body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        // A CliSession JWT, not an opaque token.
        let token = v["access_token"].as_str().unwrap();
        assert!(!token.starts_with("hort_cli_"));
        assert_eq!(token.split('.').count(), 3, "expected a JWT");
        // No `api_tokens` row is persisted for a CliSession JWT — claims
        // live in the signed token, not a DB column (§1.1 hard-block).
        assert!(
            mocks.api_tokens.inserted().is_empty(),
            "CliSession JWT must NOT persist an api_tokens row"
        );
        // The JWT's `sub` is the existing user — verify by decoding the
        // payload segment (no signature check needed here; the mint side
        // owns the sub, and the hort-app unit tests verify the signature).
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("decode jwt payload");
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["sub"], existing_id.to_string());
    }

    // -- (k) oversize client_id truncation ---------------------------------

    #[tokio::test]
    async fn exchange_truncates_oversize_client_id() {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        let idp = Arc::new(MockIdentityProvider::new());
        idp.register_token("good-token", sample_claims("idp:big"));
        let (router, _) = build_router_with_idp(&base, &mocks, idp);

        let oversize = "a".repeat(300);
        let body = form_body(&[
            ("grant_type", EXCHANGE_GRANT_TYPE),
            ("subject_token", "good-token"),
            ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
            ("client_id", &oversize),
        ]);
        let resp = post_form(router, body).await;
        // Truncation still happens (the
        // `client_id` becomes the token `name`), but there is no
        // persisted row to inspect — the credential is a stateless JWT.
        // The wire-cap truncation contract is unchanged; the success
        // (200) confirms the oversize client_id was accepted (truncated)
        // rather than rejected. The truncation unit assertion lives in
        // the hort-app `issue_cli_session_oversize_client_name_truncated`
        // test (which inspects the returned `IssuedToken.name`).
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            mocks.api_tokens.inserted().is_empty(),
            "CliSession JWT must NOT persist an api_tokens row"
        );
    }

    // -- (k2) scope + requested_token_lifetime form fields ----

    #[tokio::test]
    async fn exchange_rejects_unknown_permission_in_scope() {
        // Unknown permission names in `scope` are
        // wire-shape errors (bad_request).
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        let idp = Arc::new(MockIdentityProvider::new());
        idp.register_token("good-token", sample_claims("idp:abc"));
        let (router, _) = build_router_with_idp(&base, &mocks, idp);
        let body = form_body(&[
            ("grant_type", EXCHANGE_GRANT_TYPE),
            ("subject_token", "good-token"),
            ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
            ("client_id", "hort-cli"),
            ("scope", "read write bogus"),
        ]);
        let resp = post_form(router, body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_json(resp).await;
        assert_eq!(v["error"], "invalid_request");
        assert!(
            v["error_description"].as_str().unwrap().contains("bogus"),
            "expected description to mention the unknown perm, got {v}"
        );
    }

    #[tokio::test]
    async fn exchange_rejects_lifetime_below_minimum() {
        // requested_token_lifetime < 300s →
        // ApiTokenError::LifetimeBelowMinimum, mapped to 400.
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        let idp = Arc::new(MockIdentityProvider::new());
        idp.register_token("good-token", sample_claims("idp:abc"));
        let (router, _) = build_router_with_idp(&base, &mocks, idp);
        let body = form_body(&[
            ("grant_type", EXCHANGE_GRANT_TYPE),
            ("subject_token", "good-token"),
            ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
            ("client_id", "hort-cli"),
            ("requested_token_lifetime", "200"),
        ]);
        let resp = post_form(router, body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_json(resp).await;
        assert_eq!(v["error"], "invalid_request");
        assert!(
            v["error_description"]
                .as_str()
                .unwrap()
                .contains("below 300-second minimum"),
            "expected description to mention the minimum, got {v}"
        );
    }

    #[tokio::test]
    async fn exchange_honors_explicit_lifetime_within_bounds() {
        // Both caps are 900 s, so a request
        // BELOW the ceiling (here 600 s) passes through unchanged; the
        // response surfaces the actual issued lifetime. (A request above
        // 900 s would clamp to 900 — see `exchange_clamps_*` siblings.)
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        let idp = Arc::new(MockIdentityProvider::new());
        idp.register_token("good-token", sample_claims("idp:abc"));
        let (router, _) = build_router_with_idp(&base, &mocks, idp);
        let body = form_body(&[
            ("grant_type", EXCHANGE_GRANT_TYPE),
            ("subject_token", "good-token"),
            ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
            ("client_id", "hort-cli"),
            ("scope", "read write delete"),
            ("requested_token_lifetime", "600"), // sub-ceiling
        ]);
        let resp = post_form(router, body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        let expires_in = v["expires_in"].as_u64().unwrap();
        assert!(
            (590..=600).contains(&expires_in),
            "expected ≈ 600s, got {expires_in}"
        );
    }

    // -- (l) feature-flag-off path: route absent → 404 ----------------------

    #[tokio::test]
    async fn exchange_route_absent_when_feature_disabled() {
        // Build a router that does NOT mount token_exchange_routes —
        // the production wiring (hort-server::http) skips the merge when
        // HORT_TOKEN_EXCHANGE_ENABLED is false. axum's default 404 fires.
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, _mocks) = build_mock_ctx(metrics_handle);
        let router: Router = Router::new()
            // Empty /api/v1 nest — exchange route is not mounted.
            .nest("/api/v1", Router::new())
            .with_state(base);
        let body = form_body(&[
            ("grant_type", EXCHANGE_GRANT_TYPE),
            ("subject_token", "tok"),
            ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
        ]);
        let resp = post_form(router, body).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -- (m) no WWW-Authenticate on 401 ------------------------------------

    #[tokio::test]
    async fn exchange_does_not_emit_www_authenticate() {
        // Verify on a 401 path (PAT-shape rejection — predictable, no IdP
        // call needed) that no WWW-Authenticate header is emitted.
        let (router, _idp, _mocks) = build_test_router();
        let pat = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let body = happy_form(pat);
        let resp = post_form(router, body).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            resp.headers().get(http_header::WWW_AUTHENTICATE).is_none(),
            "WWW-Authenticate must not appear on /exchange responses"
        );
        assert_eq!(
            resp.headers()
                .get(http_header::CACHE_CONTROL)
                .map(|v| v.to_str().unwrap()),
            Some("no-store"),
            "Cache-Control: no-store must apply to error responses too"
        );
    }

    // -- form-rejection path (unsupported content-type) ---------------------

    #[test]
    fn exchange_rejects_wrong_content_type() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, _idp, _mocks) = build_test_router();
                let req = Request::post("/api/v1/auth/exchange")
                    .header(http_header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"grant_type":"x"}"#))
                    .unwrap();
                let resp = router.oneshot(req).await.unwrap();
                // RFC 7231 §6.5.13
                // mandates 415 for content-type mismatch.
                // The OAuth `error` code stays
                // `invalid_request` per RFC 6749 §5.2; only the HTTP
                // status differs. Metric label remains `bad_request`.
                assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_request");
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_BAD_REQUEST),
            1,
            "expected exactly one bad_request increment; saw: {snap:?}"
        );
    }

    // -----------------------------------------------------------------------
    // B3 metric-emission tests
    // -----------------------------------------------------------------------
    //
    // These tests register a `metrics_util::debugging::DebuggingRecorder`
    // for the duration of a synthetic `/exchange` request and assert
    // that the (counter, histogram, label-set) shape matches the catalog
    // entry registered by Item B3. Each test runs its own
    // `tokio::runtime` because `metrics::with_local_recorder` is a
    // sync entry point and we cannot nest a `block_on` from inside a
    // surrounding `#[tokio::test]` runtime.
    //
    // The helper `capture_full_snapshot` returns the raw snapshot
    // (counters AND histograms in a single scope) so a single
    // exchange-call can be cross-asserted on both metric kinds and on
    // the `hort_api_token_issued_total` companion metric without firing
    // two separate requests.

    type FullSnapshot = Vec<(
        metrics_util::CompositeKey,
        Option<::metrics::Unit>,
        Option<::metrics::SharedString>,
        metrics_util::debugging::DebugValue,
    )>;

    /// Run `f` under a `DebuggingRecorder` scope and return the full
    /// snapshot (counters AND histograms). Sync wrapper so the
    /// `with_local_recorder` call itself is sync — callers spin up a
    /// per-test current-thread runtime inside `f` to drive the async
    /// router.
    fn capture_full_snapshot<F>(f: F) -> FullSnapshot
    where
        F: FnOnce(),
    {
        use metrics_util::debugging::DebuggingRecorder;
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        ::metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

    fn counter_value(snap: &FullSnapshot, name: &str, result: &str) -> u64 {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;
        for (key, _u, _d, value) in snap {
            if key.kind() != MetricKind::Counter || key.key().name() != name {
                continue;
            }
            if !key
                .key()
                .labels()
                .any(|l| l.key() == "result" && l.value() == result)
            {
                continue;
            }
            if let DebugValue::Counter(n) = value {
                return *n;
            }
        }
        0
    }

    /// Counter lookup that matches the exact `(kind, result)` label
    /// pair — used for `hort_api_token_issued_total{kind="cli", result=...}`
    /// where both labels are load-bearing.
    fn counter_value_kind_result(snap: &FullSnapshot, name: &str, kind: &str, result: &str) -> u64 {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;
        for (key, _u, _d, value) in snap {
            if key.kind() != MetricKind::Counter || key.key().name() != name {
                continue;
            }
            let mut got_kind = None;
            let mut got_result = None;
            for label in key.key().labels() {
                match label.key() {
                    "kind" => got_kind = Some(label.value()),
                    "result" => got_result = Some(label.value()),
                    _ => {}
                }
            }
            if got_kind == Some(kind) && got_result == Some(result) {
                if let DebugValue::Counter(n) = value {
                    return *n;
                }
            }
        }
        0
    }

    fn histogram_sample_count(snap: &FullSnapshot, name: &str, result: &str) -> usize {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;
        for (key, _u, _d, value) in snap {
            if key.kind() != MetricKind::Histogram || key.key().name() != name {
                continue;
            }
            if !key
                .key()
                .labels()
                .any(|l| l.key() == "result" && l.value() == result)
            {
                continue;
            }
            if let DebugValue::Histogram(samples) = value {
                return samples.len();
            }
        }
        0
    }

    /// Collect every distinct label key seen on `name` across both
    /// MetricKind variants. Used by the cardinality-discipline test
    /// to lock in `{result}`-only.
    fn collect_label_keys(snap: &FullSnapshot, name: &str) -> std::collections::BTreeSet<String> {
        let mut keys = std::collections::BTreeSet::new();
        for (key, _u, _d, _v) in snap {
            if key.key().name() != name {
                continue;
            }
            for label in key.key().labels() {
                keys.insert(label.key().to_string());
            }
        }
        keys
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    // -- B3.a: every result label fires at least once -----------------------
    //
    // `success`, `source_token_pat_rejected`, `source_token_expired`,
    // and `idp_unavailable` already have dedicated DebuggingRecorder
    // tests above (`exchange_succeeds_for_new_user_jit`,
    // `exchange_rejects_pat_shape_subject_token_before_idp`,
    // `exchange_returns_401_on_oidc_expired`,
    // `exchange_returns_503_on_idp_unavailable`). The two remaining
    // gaps — `source_token_invalid` and `infrastructure_error` —
    // are filled by the next two tests. Together with the existing
    // four they exercise every value of the catalog enum.

    /// Fills the `source_token_invalid` coverage gap. The existing
    /// `exchange_returns_401_on_oidc_other_failures` test asserts
    /// the HTTP status for the four `source_token_invalid`-mapping
    /// OIDC variants but does NOT pin the metric label — this test
    /// adds the DebuggingRecorder assertion.
    #[test]
    fn exchange_metric_fires_source_token_invalid_on_oidc_signature_invalid() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, mocks) = build_mock_ctx(metrics_handle);
                let idp = Arc::new(MockIdentityProvider::new());
                idp.register_error("bad-token", OidcValidationError::SignatureInvalid);
                let (router, _) = build_router_with_idp(&base, &mocks, idp);
                let resp = post_form(router, happy_form("bad-token")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            });
        });
        assert_eq!(
            counter_value(
                &snap,
                metrics::COUNTER,
                metrics::RESULT_SOURCE_TOKEN_INVALID
            ),
            1,
            "expected exactly one source_token_invalid increment; saw: {snap:?}"
        );
        assert!(
            histogram_sample_count(
                &snap,
                metrics::HISTOGRAM,
                metrics::RESULT_SOURCE_TOKEN_INVALID
            ) >= 1,
            "histogram must record on every exit path including source_token_invalid",
        );
    }

    /// Covers the genuine-`infrastructure_error`
    /// path. The cap-exceeds-authority test
    /// covers the 403 path; this test covers the 500 path
    /// when an actual port failure occurs during issuance.
    ///
    /// Setup:
    /// - JIT user provisions with sufficient grants (cap-vs-authority
    ///   passes — uses the `team-alpha` group that maps to the
    ///   `developer` role with `[Read, Write, Delete]`).
    /// - Mock `api_tokens` repository's `insert` is armed to fail once
    ///   with `DomainError::Invariant("injected")`, simulating an
    ///   event-store / DB outage during the `issue_inner` persist step.
    ///
    /// Assertions:
    /// - HTTP 500 server_error.
    /// - Response body `{"error": "server_error", ...}`.
    /// - Metric `hort_token_exchange_total{result="infrastructure_error"}`
    ///   increments exactly once.
    /// - Histogram records on the `infrastructure_error` exit path.
    /// - `mocks.api_tokens.inserted().is_empty()` — the row was NOT
    ///   persisted because `insert` failed before the in-memory
    ///   append. This is the contract that proves the head-of-insert
    ///   check fires before the side-effecting append.
    #[test]
    fn exchange_metric_fires_infrastructure_error_on_real_infra_failure() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, mocks) = build_mock_ctx(metrics_handle);
                let idp = Arc::new(MockIdentityProvider::new());
                // `team-alpha` → `developer` role mapping is seeded in
                // `build_router_with_idp`, so cap-vs-authority passes
                // and the request reaches the persist step.
                let claims = IdpClaims {
                    subject: "idp:authorised".to_string(),
                    username: "authorised-user".to_string(),
                    email: "authorised@example.com".to_string(),
                    groups: vec!["team-alpha".into()],
                    issued_at: Utc::now(),
                };
                idp.register_token("authorised-token", claims);
                // The CliSession JWT path
                // persists NO `api_tokens` row, so the issuance infra
                // failure is the `ApiTokenIssued` audit-event append.
                // Arm the event store's NEXT append to fail with a real
                // port error — simulates an event-store outage during
                // the mint's audit step.
                mocks
                    .events
                    .fail_next_append(hort_domain::error::DomainError::Invariant(
                        "injected".into(),
                    ));
                let (router, _) = build_router_with_idp(&base, &mocks, idp);
                let resp = post_form(router, happy_form("authorised-token")).await;
                assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "server_error");
                // No row is ever persisted on the CliSession JWT path.
                assert!(
                    mocks.api_tokens.inserted().is_empty(),
                    "CliSession JWT path persists no api_tokens row: {:?}",
                    mocks.api_tokens.inserted()
                );
            });
        });
        assert_eq!(
            counter_value(
                &snap,
                metrics::COUNTER,
                metrics::RESULT_INFRASTRUCTURE_ERROR
            ),
            1,
            "expected exactly one infrastructure_error increment; saw: {snap:?}"
        );
        assert!(
            histogram_sample_count(
                &snap,
                metrics::HISTOGRAM,
                metrics::RESULT_INFRASTRUCTURE_ERROR
            ) >= 1,
            "histogram must record on every exit path including infrastructure_error",
        );
    }

    /// Fills the `cap_exceeds_authority` coverage gap. Triggered by
    /// driving the IdP claims through a group that has no entry in
    /// the test wiring's `team-alpha → developer` mapping: the JIT
    /// user is provisioned with no role, and the cap-vs-grants check
    /// in `issue_cli_session` rejects the forced
    /// `[Read, Write, Delete]` declaration as `CapExceedsAuthority`.
    /// Per Item B6 the handler maps this to a caller-side denial —
    /// HTTP 403 access_denied with the
    /// `hort_token_exchange_total{result="cap_exceeds_authority"}`
    /// counter — NOT to the operator-actionable infrastructure_error
    /// bucket. (Pre-B6 the handler collapsed every ApiTokenError to
    /// infrastructure_error, generating false-positive outage alerts
    /// on RBAC denials; B6 fixes that.)
    #[test]
    fn exchange_metric_fires_cap_exceeds_authority_on_issuance_denial() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, mocks) = build_mock_ctx(metrics_handle);
                let idp = Arc::new(MockIdentityProvider::new());
                // `team-bravo` has no group_mapping → JIT user has no
                // role → cap-vs-grants check fails →
                // ApiTokenError::CapExceedsAuthority.
                let claims = IdpClaims {
                    subject: "idp:no-role".to_string(),
                    username: "no-role-user".to_string(),
                    email: "no-role@example.com".to_string(),
                    groups: vec!["team-bravo".into()],
                    issued_at: Utc::now(),
                };
                idp.register_token("no-role-token", claims);
                let (router, _) = build_router_with_idp(&base, &mocks, idp);
                let resp = post_form(router, happy_form("no-role-token")).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "access_denied");
            });
        });
        assert_eq!(
            counter_value(
                &snap,
                metrics::COUNTER,
                metrics::RESULT_CAP_EXCEEDS_AUTHORITY
            ),
            1,
            "expected exactly one cap_exceeds_authority increment; saw: {snap:?}"
        );
        // infrastructure_error MUST NOT fire on a caller-side denial.
        assert_eq!(
            counter_value(
                &snap,
                metrics::COUNTER,
                metrics::RESULT_INFRASTRUCTURE_ERROR
            ),
            0,
            "infrastructure_error must NOT increment on caller-side denial; saw: {snap:?}"
        );
        assert!(
            histogram_sample_count(
                &snap,
                metrics::HISTOGRAM,
                metrics::RESULT_CAP_EXCEEDS_AUTHORITY
            ) >= 1,
            "histogram must record on every exit path including cap_exceeds_authority",
        );
    }

    // -- B3.b: double-emission canonical test -------------------------------

    /// Locks in the contract that the success path of `/exchange`
    /// fires BOTH the handler-level counter and the use-case-level
    /// counter exactly once, with the documented label sets. A
    /// regression in either emission site (handler-side double-fire,
    /// use-case-side missed fire) breaks this test.
    #[test]
    fn exchange_double_emission_on_success() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, mocks) = build_mock_ctx(metrics_handle);
                let idp = Arc::new(MockIdentityProvider::new());
                idp.register_token("good-token", sample_claims("idp:double-emit"));
                let (router, _) = build_router_with_idp(&base, &mocks, idp);
                let resp = post_form(router, happy_form("good-token")).await;
                assert_eq!(resp.status(), StatusCode::OK);
            });
        });

        // Handler-level metric: `hort_token_exchange_total{result="success"}`.
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_SUCCESS),
            1,
            "handler-level success counter must fire exactly once; saw: {snap:?}"
        );

        // Use-case-level metric: `hort_api_token_issued_total{kind="cli", result="success"}`.
        // Source of truth: hort-app::api_token_use_case::issue_cli_session.
        assert_eq!(
            counter_value_kind_result(&snap, "hort_api_token_issued_total", "cli", "success"),
            1,
            "issuance-pipeline counter must fire exactly once on /exchange success; saw: {snap:?}"
        );
    }

    // -- B3.c + B3.d: histogram firing on success and error paths -----------

    #[test]
    fn exchange_histogram_records_duration_on_success() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, mocks) = build_mock_ctx(metrics_handle);
                let idp = Arc::new(MockIdentityProvider::new());
                idp.register_token("good-token", sample_claims("idp:hist-ok"));
                let (router, _) = build_router_with_idp(&base, &mocks, idp);
                let resp = post_form(router, happy_form("good-token")).await;
                assert_eq!(resp.status(), StatusCode::OK);
            });
        });
        let count = histogram_sample_count(&snap, metrics::HISTOGRAM, metrics::RESULT_SUCCESS);
        assert_eq!(
            count, 1,
            "duration histogram must record exactly one sample on success; saw count={count}",
        );
    }

    /// Histogram fires on at least one error path. The PAT-shape gate
    /// is the most economical choice — no IdP roundtrip, deterministic.
    #[test]
    fn exchange_histogram_records_duration_on_error() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, mocks) = build_mock_ctx(metrics_handle);
                let idp = Arc::new(MockIdentityProvider::new());
                let (router, _) = build_router_with_idp(&base, &mocks, idp);
                let pat = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let resp = post_form(router, happy_form(pat)).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            });
        });
        let count = histogram_sample_count(
            &snap,
            metrics::HISTOGRAM,
            metrics::RESULT_SOURCE_TOKEN_PAT_REJECTED,
        );
        assert_eq!(
            count, 1,
            "duration histogram must record on the PAT-rejection error path; saw count={count}",
        );
    }

    // -- B7.F4: AuthContext::Disabled fallback ------------------------------

    /// Pins the
    /// composition-bug-guard arm. The handler exposes a 503
    /// `temporarily_unavailable` + `idp_unavailable` metric label
    /// when reached with `AuthContext::Disabled` (production wiring
    /// declines to mount `/exchange` when auth is off, so this is
    /// strictly defensive — but the arm is real and a regression
    /// would silently swallow the misconfiguration).
    #[test]
    fn exchange_metric_fires_idp_unavailable_when_auth_disabled() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                // `build_mock_ctx` defaults to `AuthContext::Disabled`,
                // so we mount the route directly against the default
                // base context (no `with_auth` flip needed).
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, _mocks) = build_mock_ctx(metrics_handle);
                let router = Router::new()
                    .nest("/api/v1", token_exchange_routes())
                    .with_state(base);
                let body = happy_form("any-token");
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "temporarily_unavailable");
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::COUNTER, metrics::RESULT_IDP_UNAVAILABLE),
            1,
            "expected exactly one idp_unavailable increment; saw: {snap:?}"
        );
        assert!(
            histogram_sample_count(&snap, metrics::HISTOGRAM, metrics::RESULT_IDP_UNAVAILABLE) >= 1,
            "histogram must record on the AuthContext::Disabled exit path",
        );
    }

    // -- B7.F2 + B7.F3: REPORTED COVERAGE GAP -------------------------------
    //
    // The two remaining B7 coverage gaps require failure-injection
    // hooks on `MockUserRepository` that do not exist today. Per the
    // B7 starter prompt, B7 does NOT extend
    // `crates/hort-app/src/use_cases/test_support.rs`; this is reported
    // for a follow-on (parallel to B6a's `MockApiTokenRepository::fail_next_insert`):
    //
    // - **F2** (`exchange_metric_fires_subject_not_authorised_on_post_validation_403`)
    //   would need either (a) `MockUserRepository::fail_next_find_by_external_id`
    //   / `fail_next_upsert_on_login` to inject a `DomainError`, or
    //   (b) the `AuthenticateUseCase`'s OIDC path to actually reject
    //   `is_active=false` users (today it merely persists the flag —
    //   the §3 design row "user deactivated → 403" is not enforced
    //   in code yet, only documented).
    //
    // - **F3** (`exchange_metric_fires_infrastructure_error_on_authenticate_bearer_catchall`)
    //   would need a `fail_next_*` hook on `MockUserRepository` to
    //   surface `AppError::Domain` from a downstream port; the
    //   handler's `Err(_)` arm is otherwise unreachable in tests.
    //
    // The catch-all `Err(_)` arm IS exercised at compile time by
    // exhaustive matching, so a regression that mis-routed an
    // `AppError::Repository(_)` through the wrong arm would fail to
    // compile. Runtime coverage of the arm is the gap.
    //
    // Closing these requires a B7a-style follow-on adding
    // `MockUserRepository::fail_next_find_by_external_id` and
    // `MockUserRepository::fail_next_upsert_on_login` (mirroring the
    // existing ten `fail_next_*` precedents — `MockRefRegistryPort::fail_next_insert`
    // is the closest shape match).

    // -- B3.e: cardinality discipline ---------------------------------------

    /// Locks in the closed-`{kind, result}` label set against future
    /// regression. If someone adds `format=`, `client_id=`,
    /// `user_id=`, or any other label to either metric, this test
    /// fails. The schema is `{kind, result}`.
    #[test]
    fn exchange_metric_emission_carries_no_high_cardinality_labels() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, mocks) = build_mock_ctx(metrics_handle);
                let idp = Arc::new(MockIdentityProvider::new());
                idp.register_token("good-token", sample_claims("idp:card-ok"));
                idp.register_error("bad-token", OidcValidationError::SignatureInvalid);
                let (router, _) = build_router_with_idp(&base, &mocks, idp);

                // One success exercise.
                let ok = post_form(router.clone(), happy_form("good-token")).await;
                assert_eq!(ok.status(), StatusCode::OK);

                // One failure exercise.
                let err = post_form(router, happy_form("bad-token")).await;
                assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
            });
        });

        let expected: std::collections::BTreeSet<String> =
            ["kind".to_string(), "result".to_string()]
                .into_iter()
                .collect();

        let counter_keys = collect_label_keys(&snap, metrics::COUNTER);
        assert_eq!(
            counter_keys,
            expected,
            "{COUNTER} carries unexpected labels: {counter_keys:?}",
            COUNTER = metrics::COUNTER,
        );
        let histogram_keys = collect_label_keys(&snap, metrics::HISTOGRAM);
        assert_eq!(
            histogram_keys,
            expected,
            "{HISTOGRAM} carries unexpected labels: {histogram_keys:?}",
            HISTOGRAM = metrics::HISTOGRAM,
        );
    }

    // -- B7.B.5: closed-enum lock against the catalog ----------------------

    /// Locks in the closed
    /// `result` enum against the catalog for the **cli_session**
    /// branch — exactly 10 values.
    /// If a future change adds a value to the
    /// cli_session branch without updating the catalog (or vice versa),
    /// this test fails — the catalog and the constants must agree.
    ///
    /// The federation branch has an INDEPENDENT enum
    /// (`kind = "federated_jwt"`) — exercised by
    /// `federation_result_enum_matches_catalog` below. The two enums
    /// share the metric name but are gated by the `kind` label.
    #[test]
    fn exchange_result_enum_matches_catalog() {
        let actual: std::collections::BTreeSet<&'static str> = [
            metrics::RESULT_SUCCESS,
            metrics::RESULT_SOURCE_TOKEN_INVALID,
            metrics::RESULT_SOURCE_TOKEN_EXPIRED,
            metrics::RESULT_SOURCE_TOKEN_PAT_REJECTED,
            metrics::RESULT_IDP_UNAVAILABLE,
            metrics::RESULT_BAD_REQUEST,
            metrics::RESULT_SUBJECT_NOT_AUTHORISED,
            metrics::RESULT_CAP_EXCEEDS_AUTHORITY,
            metrics::RESULT_VALIDATION_ERROR,
            metrics::RESULT_INFRASTRUCTURE_ERROR,
        ]
        .into_iter()
        .collect();
        let expected: std::collections::BTreeSet<&'static str> = [
            "success",
            "source_token_invalid",
            "source_token_expired",
            "source_token_pat_rejected",
            "idp_unavailable",
            "bad_request",
            "subject_not_authorised",
            "cap_exceeds_authority",
            "validation_error",
            "infrastructure_error",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            actual, expected,
            "metric `result` enum diverges from the docs/metrics-catalog.md \
             post-B7 closed taxonomy: actual={actual:?}, expected={expected:?}"
        );
        assert_eq!(
            actual.len(),
            10,
            "post-B7 closed enum has exactly 10 values"
        );
    }

    // =====================================================================
    // Federation branch tests
    // =====================================================================

    /// Closed-enum lock for the federation `result` set.
    /// 13 distinct values (8 from `FederationDenyReason::as_str()` + 5
    /// handler-layer: success, no_sa_match, multiple_sa_match,
    /// mint_failed, internal_error). The `bad_request` value
    /// (`requested_token_type != access_token` on the federation
    /// branch) is intentionally shared with the cli_session enum — same
    /// wire-shape error semantics, distinguished by the `kind` label.
    #[test]
    fn federation_result_enum_matches_catalog() {
        // Every FederationDenyReason variant gets its own wire string
        // via `as_str()` — pin them here so a regression in
        // `FederationDenyReason::as_str` breaks this test alongside the
        // catalog mismatch.
        let mut expected: std::collections::BTreeSet<&'static str> = [
            "success",
            "invalid_format",
            "unknown_issuer",
            "algorithm_not_allowed",
            "unknown_kid",
            "signature_invalid",
            "aud_mismatch",
            "expired",
            "not_yet_valid",
            "no_sa_match",
            "multiple_sa_match",
            "mint_failed",
            "internal_error",
        ]
        .into_iter()
        .collect();
        // Bad-request is shared across branches — assert it stays
        // outside the federation-only enum so the test fails loudly if
        // the federation branch tries to invent its own `bad_request`
        // variant.
        expected.remove("bad_request");

        let mut actual: std::collections::BTreeSet<&'static str> = [
            metrics::RESULT_SUCCESS,
            metrics::RESULT_NO_SA_MATCH,
            metrics::RESULT_MULTIPLE_SA_MATCH,
            metrics::RESULT_MINT_FAILED,
            metrics::RESULT_INTERNAL_ERROR,
        ]
        .into_iter()
        .collect();
        for reason in [
            FederationDenyReason::InvalidFormat,
            FederationDenyReason::UnknownIssuer,
            FederationDenyReason::AlgorithmNotAllowed,
            FederationDenyReason::UnknownKid,
            FederationDenyReason::SignatureInvalid,
            FederationDenyReason::AudMismatch,
            FederationDenyReason::Expired,
            FederationDenyReason::NotYetValid,
        ] {
            actual.insert(reason.as_str());
        }
        assert_eq!(
            actual, expected,
            "federation `result` enum diverges from the catalog: \
             actual={actual:?}, expected={expected:?}"
        );
    }

    /// Build a router with the access_token mock harness PLUS the
    /// federation ports wired against a fresh `MockFederatedJwtValidator`
    /// and `MockServiceAccountRepository`. Returns the assembled router,
    /// the two federation mocks, and the broader `MockPorts` so tests
    /// can seed federation outcomes AND assert on the token-issuance
    /// side (api_tokens / events).
    fn build_federation_router() -> (
        Router,
        Arc<hort_app::use_cases::test_support::MockFederatedJwtValidator>,
        Arc<hort_app::use_cases::test_support::MockServiceAccountRepository>,
        MockPorts,
    ) {
        // Default: a `FirstSeen` replay guard (the success path — every
        // legacy federation test mints exactly once) + the secure
        // default issuer (`require_jti = true`).
        let guard = Arc::new(hort_app::use_cases::test_support::MockReplayGuardPort::first_seen());
        build_federation_router_with_guard(guard)
    }

    /// Federation router whose
    /// `ApiTokenUseCase` is wired with the supplied replay guard and
    /// whose `OidcIssuerRepository` is seeded with the `github-actions`
    /// issuer carrying `require_jti = require_jti`. Deny-path tests use
    /// this directly; the legacy 4-tuple builder delegates here with a
    /// `FirstSeen` guard + `require_jti = true`.
    fn build_federation_router_with_guard(
        guard: Arc<dyn hort_domain::ports::replay_guard::ReplayGuardPort>,
    ) -> (
        Router,
        Arc<hort_app::use_cases::test_support::MockFederatedJwtValidator>,
        Arc<hort_app::use_cases::test_support::MockServiceAccountRepository>,
        MockPorts,
    ) {
        build_federation_router_full(guard, true)
    }

    fn build_federation_router_full(
        guard: Arc<dyn hort_domain::ports::replay_guard::ReplayGuardPort>,
        require_jti: bool,
    ) -> (
        Router,
        Arc<hort_app::use_cases::test_support::MockFederatedJwtValidator>,
        Arc<hort_app::use_cases::test_support::MockServiceAccountRepository>,
        MockPorts,
    ) {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics_handle);
        let idp = Arc::new(MockIdentityProvider::new());
        let (router, ctx) = build_router_with_idp(&base, &mocks, idp);
        let validator =
            Arc::new(hort_app::use_cases::test_support::MockFederatedJwtValidator::new());
        let service_accounts =
            Arc::new(hort_app::use_cases::test_support::MockServiceAccountRepository::new());
        let ctx = crate::test_support::with_federation_ports(
            &ctx,
            validator.clone()
                as Arc<dyn hort_domain::ports::federated_jwt_validator::FederatedJwtValidator>,
            service_accounts.clone()
                as Arc<
                    dyn hort_domain::ports::service_account_repository::ServiceAccountRepository,
                >,
        );

        // Seed the OidcIssuerRepository the handler
        // resolves `require_jti` from. `sample_validated_claims` uses
        // `issuer_name = "github-actions"`, so seed that row.
        use hort_app::use_cases::api_token_use_case::{ApiTokenIssuanceConfig, ApiTokenUseCase};
        use hort_domain::entities::oidc_issuer::{JwtAlg, OidcIssuer};
        use hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository;
        let oidc_repo =
            Arc::new(hort_app::use_cases::test_support::MockOidcIssuerRepository::new());
        oidc_repo.seed(OidcIssuer {
            id: Uuid::new_v4(),
            name: "github-actions".into(),
            issuer_url: "https://token.actions.githubusercontent.com".into(),
            audiences: vec!["hort-server".into()],
            jwks_refresh_interval: std::time::Duration::from_secs(3600),
            allowed_algorithms: vec![JwtAlg::Rs256],
            require_jti,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let ctx = crate::test_support::with_oidc_issuer_repo(
            &ctx,
            oidc_repo as Arc<dyn OidcIssuerRepository>,
        );

        // Rebuild the ApiTokenUseCase with the replay guard attached so
        // the federation system-mint path is guarded. The
        // mock harness wraps the same MockEventStore in a no-broadcast
        // publisher; the rbac evaluator is the empty test default.
        let api_token_uc = Arc::new(
            ApiTokenUseCase::new(
                mocks.api_tokens.clone(),
                mocks.users.clone(),
                hort_app::event_store_publisher::wrap_for_test(mocks.events.clone()),
                Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
                    Vec::new(),
                ))),
                ApiTokenIssuanceConfig::default(),
            )
            .with_replay_guard(guard),
        );
        let ctx = with_api_token_use_case(&ctx, api_token_uc);

        let _ = router; // discard the original; we rebuild below.
        let router = Router::new()
            .nest("/api/v1", token_exchange_routes())
            .with_state(ctx);
        (router, validator, service_accounts, mocks)
    }

    fn federation_form(token: &str) -> String {
        form_body(&[
            ("grant_type", EXCHANGE_GRANT_TYPE),
            ("subject_token", token),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("client_id", "ci-runner/1.0"),
        ])
    }

    /// Build a `ValidatedClaims` shaped like a typical GitHub Actions
    /// workload-identity JWT. Tests further customise the `all_claims`
    /// map to match (or NOT match) the SA's `federated_identities[].claims`.
    fn sample_validated_claims(exp_offset_secs: i64) -> ValidatedClaims {
        use std::collections::BTreeMap;
        let mut all = BTreeMap::new();
        all.insert(
            "repository".to_string(),
            serde_json::Value::String("my-org/my-repo".into()),
        );
        all.insert(
            "environment".to_string(),
            serde_json::Value::String("production".into()),
        );
        all.insert(
            "sub".to_string(),
            serde_json::Value::String("repo:my-org/my-repo:ref:refs/heads/main".into()),
        );
        ValidatedClaims {
            issuer: "https://token.actions.githubusercontent.com".into(),
            issuer_name: "github-actions".into(),
            subject: "repo:my-org/my-repo:ref:refs/heads/main".into(),
            audience: "hort-server".into(),
            jti: Some("e1b2c3d4-9999-4111-aaaa-bbbbccccdddd".into()),
            expires_at: Utc::now() + chrono::Duration::seconds(exp_offset_secs),
            iat: Some(Utc::now().timestamp() - 30),
            exp_raw: (Utc::now() + chrono::Duration::seconds(exp_offset_secs)).timestamp(),
            all_claims: all,
        }
    }

    fn sample_sa() -> ServiceAccount {
        let mut claims = std::collections::BTreeMap::new();
        claims.insert("repository".to_string(), "my-org/my-repo".into());
        claims.insert("environment".to_string(), "production".into());
        ServiceAccount {
            id: Uuid::from_u128(0xC1A),
            name: "ci-pypi-pusher".into(),
            backing_user_id: Uuid::from_u128(0xC1AB),
            role: "developer".into(),
            repositories: vec!["pypi-internal".into()],
            federated_identities: vec![hort_domain::entities::service_account::FederatedIdentity {
                issuer_name: "github-actions".into(),
                claims,
            }],
            fallback_rotation: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Seed a backing service-account user with role `developer` (no
    /// admin authority) so the system-mint path passes its
    /// `is_service_account` gate.
    fn seed_sa_user(mocks: &MockPorts, sa: &ServiceAccount) {
        mocks.users.insert(User {
            id: sa.backing_user_id,
            username: format!("sa:{}", sa.name),
            email: format!("{}@service.local", sa.name),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    }

    // -- Validator deny paths -------------------------------------------------

    /// One test per `FederationDenyReason` variant. Each pins the wire
    /// status (401), the OAuth error code (`invalid_grant`), the deny
    /// hint string, and the metric `result` label.
    #[test]
    fn federation_deny_unknown_issuer() {
        deny_path_case(
            FederationDenyReason::UnknownIssuer,
            "unknown_issuer",
            "no OidcIssuer matches",
        );
    }

    #[test]
    fn federation_deny_algorithm_not_allowed() {
        deny_path_case(
            FederationDenyReason::AlgorithmNotAllowed,
            "algorithm_not_allowed",
            "allowedAlgorithms",
        );
    }

    #[test]
    fn federation_deny_signature_invalid() {
        deny_path_case(
            FederationDenyReason::SignatureInvalid,
            "signature_invalid",
            "signature failed verification",
        );
    }

    #[test]
    fn federation_deny_aud_mismatch() {
        deny_path_case(
            FederationDenyReason::AudMismatch,
            "aud_mismatch",
            "aud not in",
        );
    }

    #[test]
    fn federation_deny_expired() {
        deny_path_case(
            FederationDenyReason::Expired,
            "expired",
            "subject_token expired",
        );
    }

    #[test]
    fn federation_deny_not_yet_valid() {
        deny_path_case(
            FederationDenyReason::NotYetValid,
            "not_yet_valid",
            "nbf in future",
        );
    }

    #[test]
    fn federation_deny_unknown_kid() {
        deny_path_case(
            FederationDenyReason::UnknownKid,
            "unknown_kid",
            "kid not in",
        );
    }

    #[test]
    fn federation_deny_invalid_format() {
        deny_path_case(
            FederationDenyReason::InvalidFormat,
            "invalid_format",
            "not a valid JWT",
        );
    }

    /// Shared body for the eight `FederationDenyReason` cases — pins
    /// HTTP status, OAuth error, deny-hint substring, counter label,
    /// and `kind` label.
    fn deny_path_case(
        reason: FederationDenyReason,
        expected_label: &'static str,
        hint_substring: &str,
    ) {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, _sas, _mocks) = build_federation_router();
                validator.register_error("bad-jwt", reason);
                let resp = post_form(router, federation_form("bad-jwt")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_grant");
                let desc = v["error_description"].as_str().unwrap_or("");
                assert!(
                    desc.contains(hint_substring),
                    "deny-hint should contain {hint_substring:?}, got {desc:?}"
                );
            });
        });
        assert_eq!(
            counter_value_kind_result(&snap, metrics::COUNTER, "federated_jwt", expected_label),
            1,
            "expected exactly one federated_jwt={expected_label} increment; saw: {snap:?}"
        );
    }

    // -- SA-resolution deny paths ---------------------------------------------

    #[test]
    fn federation_deny_no_sa_match() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, _sas, _mocks) = build_federation_router();
                // No SAs seeded — validator OK, but the SA walk finds
                // zero matches.
                validator.register_token("ok-jwt", sample_validated_claims(600));
                let resp = post_form(router, federation_form("ok-jwt")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_grant");
                let desc = v["error_description"].as_str().unwrap_or("");
                assert!(
                    desc.contains("no ServiceAccount matches"),
                    "deny-hint should mention no SA match, got {desc:?}"
                );
            });
        });
        assert_eq!(
            counter_value_kind_result(&snap, metrics::COUNTER, "federated_jwt", "no_sa_match"),
            1,
        );
    }

    // === aud→ServiceAccount binding ===

    /// Build a `ServiceAccount` whose single `FederatedIdentity`
    /// constrains `repository` AND pins an explicit `aud` claim
    /// selector. This is the recommended shape: `aud` as a
    /// discriminating entry in the claims fragment.
    fn sa_with_aud_selector(expected_aud: &str) -> ServiceAccount {
        let mut claims = std::collections::BTreeMap::new();
        claims.insert("repository".to_string(), "my-org/my-repo".into());
        claims.insert("aud".to_string(), expected_aud.to_string());
        ServiceAccount {
            id: Uuid::from_u128(0xA0D0),
            name: "ci-aud-bound".into(),
            backing_user_id: Uuid::from_u128(0xA0D1),
            role: "developer".into(),
            repositories: vec!["pypi-internal".into()],
            federated_identities: vec![hort_domain::entities::service_account::FederatedIdentity {
                issuer_name: "github-actions".into(),
                claims,
            }],
            fallback_rotation: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// F-7 confused-deputy: a JWT minted (legitimately) for a DIFFERENT
    /// relying party — `audience = "other-rp"` — whose other claims
    /// (`repository`) satisfy the SA fragment must NOT assume the SA.
    /// The `aud` selector binds to the validator-resolved audience, so
    /// the foreign-`aud` token is denied at the audience gate. Pins:
    /// 401 `invalid_grant`, no token, and
    /// `hort_fed_sa_match_total{result="denied_audience"}`.
    #[test]
    fn federation_cross_rp_token_with_shared_issuer_aud_denied() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, sas, mocks) = build_federation_router();
                let sa = sa_with_aud_selector("hort-server");
                seed_sa_user(&mocks, &sa);
                sas.insert(sa);
                // JWT resolved-audience is "other-rp" (a different RP
                // still inside the shared OidcIssuer.audiences allowlist)
                // but `repository` matches the SA fragment.
                let mut claims = sample_validated_claims(600);
                claims.audience = "other-rp".into();
                validator.register_token("cross-rp-jwt", claims);
                let resp = post_form(router, federation_form("cross-rp-jwt")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_grant");
                assert!(
                    v.get("access_token").is_none(),
                    "a cross-RP token must NOT mint a token for the foreign SA"
                );
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::FED_SA_MATCH_COUNTER, "denied_audience"),
            1,
            "F-7: the audience-confusion deny must be observable; saw {snap:?}"
        );
        assert_eq!(
            counter_value(&snap, metrics::FED_SA_MATCH_COUNTER, "matched"),
            0,
            "no SA should have matched the cross-RP token"
        );
    }

    /// Happy path of the audience binding: the JWT's resolved audience
    /// equals the FI's `aud` selector, all other claims match ⇒ the SA
    /// is selected and `hort_fed_sa_match_total{result="matched"}` fires.
    #[test]
    fn federation_aud_selector_matches_resolved_audience() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, sas, mocks) = build_federation_router();
                let sa = sa_with_aud_selector("hort-server");
                seed_sa_user(&mocks, &sa);
                sas.insert(sa);
                // sample_validated_claims sets audience = "hort-server".
                validator.register_token("ok-jwt", sample_validated_claims(600));
                let resp = post_form(router, federation_form("ok-jwt")).await;
                assert_eq!(resp.status(), StatusCode::OK);
                let v = body_json(resp).await;
                assert!(
                    v["access_token"].as_str().unwrap().starts_with("hort_svc_"),
                    "audience-bound match should mint a service-account token"
                );
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::FED_SA_MATCH_COUNTER, "matched"),
            1,
            "audience-bound match must emit result=matched; saw {snap:?}"
        );
    }

    /// `hort_fed_sa_match_total` carries the `{result}` label ONLY — no
    /// high-cardinality leakage (design §4 / metrics-catalog rule).
    #[test]
    fn fed_sa_match_metric_carries_only_result_label() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, sas, mocks) = build_federation_router();
                let sa = sa_with_aud_selector("hort-server");
                seed_sa_user(&mocks, &sa);
                sas.insert(sa);
                validator.register_token("ok-jwt", sample_validated_claims(600));
                let _ = post_form(router, federation_form("ok-jwt")).await;
            });
        });
        let keys = collect_label_keys(&snap, metrics::FED_SA_MATCH_COUNTER);
        assert_eq!(
            keys,
            ["result"].iter().map(ToString::to_string).collect(),
            "hort_fed_sa_match_total must carry exactly the {{result}} label, saw {keys:?}"
        );
    }

    /// Pure-unit coverage of the audience binding inside
    /// `collect_sa_matches`: an FI `aud` selector binds to
    /// `ValidatedClaims.audience` (the validator-resolved single
    /// audience), NOT the raw `all_claims["aud"]` — so an array-shaped
    /// raw `aud` does not defeat the binding.
    #[test]
    fn collect_sa_matches_aud_selector_binds_resolved_audience() {
        let sa = sa_with_aud_selector("hort-server");
        let sas = vec![sa];

        // Matching resolved audience ⇒ matched.
        let mut ok = sample_validated_claims(600);
        ok.audience = "hort-server".into();
        let outcome = collect_sa_matches(&sas, &ok);
        assert_eq!(outcome.matches.len(), 1);
        assert!(!outcome.any_audience_denied);

        // Foreign resolved audience, all other claims still match ⇒
        // zero matches AND the audience-deny flag set so the call site
        // can emit `denied_audience` rather than the generic
        // `no_sa_match`.
        let mut foreign = sample_validated_claims(600);
        foreign.audience = "other-rp".into();
        let outcome = collect_sa_matches(&sas, &foreign);
        assert!(outcome.matches.is_empty());
        assert!(
            outcome.any_audience_denied,
            "the sole reason for non-match was the aud binding"
        );
    }

    /// A non-`aud` claim mismatch is NOT reported as an audience deny —
    /// it stays the generic `no_sa_match`.
    #[test]
    fn collect_sa_matches_non_aud_mismatch_is_not_audience_deny() {
        let sa = sa_with_aud_selector("hort-server");
        let sas = vec![sa];
        let mut claims = sample_validated_claims(600);
        claims.audience = "hort-server".into();
        // Break the `repository` claim — audience still matches.
        claims.all_claims.insert(
            "repository".to_string(),
            serde_json::Value::String("someone-else/repo".into()),
        );
        let outcome = collect_sa_matches(&sas, &claims);
        assert!(outcome.matches.is_empty());
        assert!(
            !outcome.any_audience_denied,
            "a non-aud claim mismatch must not be classified as an audience deny"
        );
    }

    // === Empty-claims defense-in-depth ===

    /// Build a `ServiceAccount` whose single `FederatedIdentity`
    /// carries an EMPTY claims map. Apply-time validation rejects this
    /// shape (ADR 0018); this fixture simulates the
    /// out-of-band write (raw SQL / restore / migration bug) the
    /// runtime layer must fail closed against.
    fn sa_with_empty_claims() -> ServiceAccount {
        ServiceAccount {
            id: Uuid::from_u128(0xE0C1),
            name: "ci-empty-claims".into(),
            backing_user_id: Uuid::from_u128(0xE0C2),
            role: "developer".into(),
            repositories: vec!["pypi-internal".into()],
            federated_identities: vec![hort_domain::entities::service_account::FederatedIdentity {
                issuer_name: "github-actions".into(),
                claims: std::collections::BTreeMap::new(),
            }],
            fallback_rotation: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// F-8 runtime fail-closed: an SA whose FI has `claims = {}` must
    /// NOT be matched by any JWT from the issuer (the vacuously-true
    /// `[].iter().all() ⇒ true` footgun). Pins: 401 `invalid_grant`,
    /// no token, and `hort_fed_sa_match_total{result="denied_empty_claims"}`.
    #[test]
    fn federation_empty_claims_fi_fails_closed() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, sas, mocks) = build_federation_router();
                let sa = sa_with_empty_claims();
                seed_sa_user(&mocks, &sa);
                sas.insert(sa);
                validator.register_token("any-jwt", sample_validated_claims(600));
                let resp = post_form(router, federation_form("any-jwt")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_grant");
                assert!(
                    v.get("access_token").is_none(),
                    "an empty-claims FI must never mint a token (F-8 fail-closed)"
                );
            });
        });
        assert_eq!(
            counter_value(&snap, metrics::FED_SA_MATCH_COUNTER, "denied_empty_claims"),
            1,
            "F-8: the empty-claims fail-closed skip must be observable; saw {snap:?}"
        );
        assert_eq!(
            counter_value(&snap, metrics::FED_SA_MATCH_COUNTER, "matched"),
            0,
            "an empty-claims FI must never count as a match"
        );
    }

    /// Pure-unit coverage of the F-8 fail-closed skip inside
    /// `collect_sa_matches`: `claims = {}` ⇒ zero matches AND the
    /// empty-claims flag set so the call site emits
    /// `denied_empty_claims` rather than the generic `no_sa_match`.
    #[test]
    fn collect_sa_matches_skips_empty_claims_fi() {
        let sas = vec![sa_with_empty_claims()];
        let outcome = collect_sa_matches(&sas, &sample_validated_claims(600));
        assert!(
            outcome.matches.is_empty(),
            "empty-claims FI must never match (fail closed)"
        );
        assert!(
            outcome.any_empty_claims,
            "the empty-claims skip must be flagged for the metric split"
        );
        assert!(
            !outcome.any_audience_denied,
            "an empty-claims skip is not an audience deny"
        );
    }

    /// `evaluate_fi` returns `EmptyClaims` for a `{}` fragment — the
    /// fail-closed branch is taken BEFORE the (vacuously-true) `.all()`.
    #[test]
    fn evaluate_fi_empty_claims_is_empty_claims_not_match() {
        let fi = hort_domain::entities::service_account::FederatedIdentity {
            issuer_name: "github-actions".into(),
            claims: std::collections::BTreeMap::new(),
        };
        let claims = sample_validated_claims(600);
        assert_eq!(evaluate_fi(&fi, &claims), FiEval::EmptyClaims);
    }

    /// A non-empty fragment that fully matches still returns `Match` —
    /// the F-8 guard does not regress the happy path.
    #[test]
    fn evaluate_fi_non_empty_match_unaffected_by_f8_guard() {
        let mut claims_map = std::collections::BTreeMap::new();
        claims_map.insert("repository".to_string(), "my-org/my-repo".to_string());
        claims_map.insert("environment".to_string(), "production".to_string());
        let fi = hort_domain::entities::service_account::FederatedIdentity {
            issuer_name: "github-actions".into(),
            claims: claims_map,
        };
        assert_eq!(
            evaluate_fi(&fi, &sample_validated_claims(600)),
            FiEval::Match
        );
    }

    // === Replay-guard deny paths ===

    /// Replay detected (guard returns `Replayed`) ⇒ 401 `invalid_grant`,
    /// deny-hint mentions replay, `hort_token_exchange_total{result=
    /// replayed_jti}`, and NO `WWW-Authenticate` header (the
    /// `/exchange` invariant).
    #[test]
    fn federation_replay_jti_denied_401_no_www_authenticate() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let guard =
                    Arc::new(hort_app::use_cases::test_support::MockReplayGuardPort::replayed());
                let (router, validator, sas, mocks) = build_federation_router_with_guard(guard);
                let sa = sample_sa();
                seed_sa_user(&mocks, &sa);
                sas.insert(sa);
                validator.register_token("dup-jwt", sample_validated_claims(600));
                let resp = post_form(router, federation_form("dup-jwt")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                assert!(
                    resp.headers().get(http_header::WWW_AUTHENTICATE).is_none(),
                    "WWW-Authenticate must NOT be emitted on /exchange replays"
                );
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_grant");
                let desc = v["error_description"].as_str().unwrap_or("");
                assert!(
                    desc.contains("already exchanged"),
                    "deny-hint should mention replay, got {desc:?}"
                );
            });
        });
        assert_eq!(
            counter_value_kind_result(&snap, metrics::COUNTER, "federated_jwt", "replayed_jti"),
            1,
        );
    }

    /// Fail-CLOSED at the HTTP boundary: guard `Unavailable` ⇒ 503
    /// `temporarily_unavailable`, NOT 200, NO token in the body.
    #[test]
    fn federation_guard_unavailable_503_temporarily_unavailable() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let guard =
                    Arc::new(hort_app::use_cases::test_support::MockReplayGuardPort::unavailable());
                let (router, validator, sas, mocks) = build_federation_router_with_guard(guard);
                let sa = sample_sa();
                seed_sa_user(&mocks, &sa);
                sas.insert(sa);
                validator.register_token("ok-jwt", sample_validated_claims(600));
                let resp = post_form(router, federation_form("ok-jwt")).await;
                assert_eq!(
                    resp.status(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "guard outage MUST fail closed with 503, never mint"
                );
                assert!(
                    resp.headers().get(http_header::WWW_AUTHENTICATE).is_none(),
                    "WWW-Authenticate must NOT be emitted"
                );
                let v = body_json(resp).await;
                assert_eq!(v["error"], "temporarily_unavailable");
                assert!(
                    v.get("access_token").is_none(),
                    "fail-closed response must carry NO token"
                );
            });
        });
        assert_eq!(
            counter_value_kind_result(
                &snap,
                metrics::COUNTER,
                "federated_jwt",
                "replay_guard_unavailable"
            ),
            1,
        );
        // The replay-rejected metric must NOT fire on a guard outage.
        assert_eq!(
            counter_value_kind_result(&snap, "hort_jwt_replay_rejected_total", "", ""),
            0,
        );
    }

    /// Issuer requires `jti` (default) and the JWT carries none ⇒ 401
    /// `invalid_grant`, `result=jti_required` on the exchange counter,
    /// and the dedicated replay counter does NOT fire (no replay was
    /// evaluated).
    #[test]
    fn federation_jti_required_denied_401_not_on_replay_metric() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                // Default `require_jti = true`; FirstSeen guard (never
                // reached — jti_required is a pre-guard validation deny).
                let guard =
                    Arc::new(hort_app::use_cases::test_support::MockReplayGuardPort::first_seen());
                let (router, validator, sas, mocks) = build_federation_router_with_guard(guard);
                let sa = sample_sa();
                seed_sa_user(&mocks, &sa);
                sas.insert(sa);
                // Claims with NO jti.
                let mut claims = sample_validated_claims(600);
                claims.jti = None;
                validator.register_token("no-jti", claims);
                let resp = post_form(router, federation_form("no-jti")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_grant");
                let desc = v["error_description"].as_str().unwrap_or("");
                assert!(
                    desc.contains("jti"),
                    "deny-hint should mention jti, got {desc:?}"
                );
            });
        });
        assert_eq!(
            counter_value_kind_result(&snap, metrics::COUNTER, "federated_jwt", "jti_required"),
            1,
        );
        assert_eq!(
            counter_value_kind_result(&snap, "hort_jwt_replay_rejected_total", "", ""),
            0,
            "jti_required must NOT touch the replay-rejected counter"
        );
    }

    /// `require_jti = false` issuer + jti-less JWT (with iat) ⇒ composite
    /// path; a replay is denied 401 `replayed_composite`.
    #[test]
    fn federation_composite_replay_denied_401() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let guard =
                    Arc::new(hort_app::use_cases::test_support::MockReplayGuardPort::replayed());
                // require_jti = false on the seeded issuer.
                let (router, validator, sas, mocks) = build_federation_router_full(guard, false);
                let sa = sample_sa();
                seed_sa_user(&mocks, &sa);
                sas.insert(sa);
                let mut claims = sample_validated_claims(600);
                claims.jti = None; // composite path
                validator.register_token("comp-jwt", claims);
                let resp = post_form(router, federation_form("comp-jwt")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_grant");
            });
        });
        assert_eq!(
            counter_value_kind_result(
                &snap,
                metrics::COUNTER,
                "federated_jwt",
                "replayed_composite"
            ),
            1,
        );
    }

    #[test]
    fn federation_deny_multiple_sa_match_logs_candidates() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, sas, _mocks) = build_federation_router();
                // Two SAs both matching the same claim set → ambiguous.
                let mut sa_a = sample_sa();
                sa_a.id = Uuid::from_u128(1);
                sa_a.name = "ci-a".into();
                sa_a.backing_user_id = Uuid::from_u128(101);
                let mut sa_b = sample_sa();
                sa_b.id = Uuid::from_u128(2);
                sa_b.name = "ci-b".into();
                sa_b.backing_user_id = Uuid::from_u128(102);
                sas.insert(sa_a);
                sas.insert(sa_b);
                validator.register_token("ok-jwt", sample_validated_claims(600));
                let resp = post_form(router, federation_form("ok-jwt")).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "invalid_grant");
                let desc = v["error_description"].as_str().unwrap_or("");
                assert!(
                    desc.contains("multiple ServiceAccounts match"),
                    "deny-hint should mention multi-match, got {desc:?}"
                );
            });
        });
        assert_eq!(
            counter_value_kind_result(
                &snap,
                metrics::COUNTER,
                "federated_jwt",
                "multiple_sa_match"
            ),
            1,
        );
    }

    // -- Happy path -----------------------------------------------------------

    #[test]
    fn federation_happy_path_emits_short_lived_bearer() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, sas, mocks) = build_federation_router();
                let sa = sample_sa();
                seed_sa_user(&mocks, &sa);
                sas.insert(sa.clone());
                validator.register_token("ok-jwt", sample_validated_claims(600));
                let resp = post_form(router, federation_form("ok-jwt")).await;
                assert_eq!(resp.status(), StatusCode::OK);
                let v = body_json(resp).await;
                let token = v["access_token"].as_str().unwrap();
                assert!(
                    token.starts_with("hort_svc_"),
                    "expected service-account-shaped token, got: {token}"
                );
                assert_eq!(
                    v["issued_token_type"],
                    "urn:ietf:params:oauth:token-type:access_token"
                );
                assert_eq!(v["token_type"], "Bearer");
                let expires_in = v["expires_in"].as_u64().unwrap();
                // 600s JWT.exp + 1h cap → expect ~600s.
                assert!(
                    (590..=610).contains(&expires_in),
                    "expected ~600s expires_in (JWT.exp - now), got {expires_in}"
                );
            });
        });
        assert_eq!(
            counter_value_kind_result(&snap, metrics::COUNTER, "federated_jwt", "success"),
            1,
        );
    }

    /// JWT.exp 10 minutes from now ⇒ minted token expires_at ≤ now + 10
    /// min. Pins design doc §4 step 8: validity = min(1h, jwt.exp - now).
    #[test]
    fn federation_validity_cap_respects_jwt_exp_when_below_1h() {
        rt().block_on(async {
            let (router, validator, sas, mocks) = build_federation_router();
            let sa = sample_sa();
            seed_sa_user(&mocks, &sa);
            sas.insert(sa.clone());
            // exp = now + 10 min (600s) — well below the 1h federation cap.
            validator.register_token("ok-jwt", sample_validated_claims(600));
            let resp = post_form(router, federation_form("ok-jwt")).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let v = body_json(resp).await;
            let expires_in = v["expires_in"].as_u64().unwrap();
            assert!(
                expires_in <= 600,
                "expires_in must be capped at min(1h, jwt.exp - now) = 600, got {expires_in}"
            );
            assert!(
                expires_in >= 590,
                "expires_in should be close to 600 (allowing a few seconds of \
                 issuance latency), got {expires_in}"
            );
        });
    }

    /// JWT.exp 24h from now ⇒ minted token expires_at ≤ now + 1h.
    /// Pins the 1h half of the min(1h, jwt.exp - now) cap.
    #[test]
    fn federation_validity_cap_clamps_to_1h_when_jwt_exp_far_away() {
        rt().block_on(async {
            let (router, validator, sas, mocks) = build_federation_router();
            let sa = sample_sa();
            seed_sa_user(&mocks, &sa);
            sas.insert(sa.clone());
            // exp = now + 24h — far above the 1h federation cap.
            validator.register_token("ok-jwt", sample_validated_claims(24 * 3600));
            let resp = post_form(router, federation_form("ok-jwt")).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let v = body_json(resp).await;
            let expires_in = v["expires_in"].as_u64().unwrap();
            assert!(
                expires_in <= 3600,
                "expires_in must be capped at the 1h federation max, got {expires_in}"
            );
            assert!(
                expires_in >= 3590,
                "expires_in should be close to 3600 (allowing issuance latency), \
                 got {expires_in}"
            );
        });
    }

    /// Pins design doc §4 step 8 — ApiTokenIssued event carries the
    /// three federation-attribution fields. The payload propagation
    /// is the federation-audit contract; an empty / wrong value would
    /// silently break correlation against the foreign issuer's JWT log.
    #[test]
    fn federation_emits_api_token_issued_with_source_fields() {
        rt().block_on(async {
            let (router, validator, sas, mocks) = build_federation_router();
            let sa = sample_sa();
            seed_sa_user(&mocks, &sa);
            sas.insert(sa.clone());
            validator.register_token("ok-jwt", sample_validated_claims(600));
            let resp = post_form(router, federation_form("ok-jwt")).await;
            assert_eq!(resp.status(), StatusCode::OK);

            // The event ends up on the SA-user's stream — find the
            // ApiTokenIssued event in the mock event store.
            let batches = mocks.events.appended_batches();
            let issued_event = batches
                .iter()
                .rev()
                .find_map(|b| match b.events.first().map(|e| &e.event) {
                    Some(hort_domain::events::DomainEvent::ApiTokenIssued(e)) => Some(e.clone()),
                    _ => None,
                })
                .expect("expected an ApiTokenIssued event on the SA stream");
            assert_eq!(
                issued_event.source_issuer.as_deref(),
                Some("github-actions")
            );
            assert_eq!(
                issued_event.source_jti.as_deref(),
                Some("e1b2c3d4-9999-4111-aaaa-bbbbccccdddd")
            );
            assert_eq!(
                issued_event.source_sub.as_deref(),
                Some("repo:my-org/my-repo:ref:refs/heads/main")
            );
        });
    }

    /// alpha-F9b — a federation-minted SA token MUST carry the SA's
    /// role-derived permission in `declared_permissions`; an empty cap
    /// deterministically denies every authz check because
    /// `cap_allows_optional_repo` requires
    /// `cap.permissions.contains(requested)`. Pin developer → Write.
    #[test]
    fn federation_minted_token_carries_role_derived_write_for_developer_sa() {
        rt().block_on(async {
            let (router, validator, sas, mocks) = build_federation_router();
            let sa = sample_sa();
            assert_eq!(sa.role, "developer", "sample_sa() is the developer SA");
            seed_sa_user(&mocks, &sa);
            sas.insert(sa.clone());
            validator.register_token("ok-jwt", sample_validated_claims(600));
            let resp = post_form(router, federation_form("ok-jwt")).await;
            assert_eq!(resp.status(), StatusCode::OK);

            let batches = mocks.events.appended_batches();
            let issued = batches
                .iter()
                .rev()
                .find_map(|b| match b.events.first().map(|e| &e.event) {
                    Some(hort_domain::events::DomainEvent::ApiTokenIssued(e)) => Some(e.clone()),
                    _ => None,
                })
                .expect("ApiTokenIssued event on the SA stream");
            assert_eq!(
                issued.declared_permissions,
                vec![Permission::Write],
                "developer SA federation mint must carry [Write]; empty was the alpha-F9b bug \
                 (the cap leg of RbacEvaluator::authorize denies every check on empty cap)"
            );
            assert!(
                issued.repository_ids.is_none(),
                "federation cap leaves per-repo scoping to the User-subject grant; got {:?}",
                issued.repository_ids
            );
        });
    }

    /// alpha-F9b — symmetric pin for the `reader` role → Read.
    #[test]
    fn federation_minted_token_carries_role_derived_read_for_reader_sa() {
        rt().block_on(async {
            let (router, validator, sas, mocks) = build_federation_router();
            let mut sa = sample_sa();
            sa.role = "reader".into();
            seed_sa_user(&mocks, &sa);
            sas.insert(sa.clone());
            validator.register_token("ok-jwt", sample_validated_claims(600));
            let resp = post_form(router, federation_form("ok-jwt")).await;
            assert_eq!(resp.status(), StatusCode::OK);

            let batches = mocks.events.appended_batches();
            let issued = batches
                .iter()
                .rev()
                .find_map(|b| match b.events.first().map(|e| &e.event) {
                    Some(hort_domain::events::DomainEvent::ApiTokenIssued(e)) => Some(e.clone()),
                    _ => None,
                })
                .expect("ApiTokenIssued event on the SA stream");
            assert_eq!(
                issued.declared_permissions,
                vec![Permission::Read],
                "reader SA federation mint must carry [Read]"
            );
        });
    }

    /// Composition-bug guard: if the federation ports are wired as
    /// None (auth disabled), the handler returns 503 + internal_error.
    #[test]
    fn federation_503_when_ports_unwired() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                // Don't wire the federation ports — use the access-token
                // harness directly.
                let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
                let (base, mocks) = build_mock_ctx(metrics_handle);
                let idp = Arc::new(MockIdentityProvider::new());
                let (router, _) = build_router_with_idp(&base, &mocks, idp);
                let resp = post_form(router, federation_form("any-jwt")).await;
                assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
                let v = body_json(resp).await;
                assert_eq!(v["error"], "temporarily_unavailable");
            });
        });
        assert_eq!(
            counter_value_kind_result(&snap, metrics::COUNTER, "federated_jwt", "internal_error"),
            1,
        );
    }

    /// peek_jwt_payload_unverified: extracts iss/sub/aud from a valid
    /// JWT payload (no signature trust). Pins the deny-log shape's
    /// best-effort decode invariant.
    #[test]
    fn peek_jwt_payload_extracts_iss_sub_aud() {
        // Construct a JWT-shaped string: header.payload.signature.
        // Only the payload matters for the unverified peek.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let payload = serde_json::json!({
            "iss": "https://idp.example",
            "sub": "user-123",
            "aud": "hort-server",
        });
        let header = URL_SAFE_NO_PAD.encode("{}");
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
        let jwt = format!("{header}.{payload_b64}.signature-irrelevant");
        let (iss, sub, aud) = peek_jwt_payload_unverified(&jwt);
        assert_eq!(iss, "https://idp.example");
        assert_eq!(sub, "user-123");
        assert_eq!(aud, "hort-server");
    }

    /// peek_jwt_payload_unverified: returns "unknown" sentinels when
    /// the payload is malformed (not base64) or has no iss/sub claims.
    #[test]
    fn peek_jwt_payload_handles_malformed_payload() {
        let (iss, sub, aud) = peek_jwt_payload_unverified("not-a-jwt");
        assert_eq!(iss, "unknown");
        assert_eq!(sub, "unknown");
        assert_eq!(aud, "");
    }

    /// peek_jwt_payload_unverified: accepts `aud` as either a string or
    /// an array (RFC 7519 §4.1.3) — array form picks the first entry.
    #[test]
    fn peek_jwt_payload_aud_array_takes_first() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let payload = serde_json::json!({
            "iss": "https://idp.example",
            "sub": "u",
            "aud": ["a-server", "b-server"],
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
        let jwt = format!(".{payload_b64}.");
        let (_, _, aud) = peek_jwt_payload_unverified(&jwt);
        assert_eq!(aud, "a-server");
    }

    /// `requested_token_type = jwt` on the federation branch is a
    /// wire-shape error (the federation branch issues an access_token —
    /// the *subject* token was the jwt, not the issued one).
    #[test]
    fn federation_rejects_wrong_requested_token_type() {
        rt().block_on(async {
            let (router, validator, sas, mocks) = build_federation_router();
            let sa = sample_sa();
            seed_sa_user(&mocks, &sa);
            sas.insert(sa);
            validator.register_token("ok-jwt", sample_validated_claims(600));
            let body = form_body(&[
                ("grant_type", EXCHANGE_GRANT_TYPE),
                ("subject_token", "ok-jwt"),
                ("subject_token_type", TOKEN_TYPE_JWT),
                ("requested_token_type", TOKEN_TYPE_JWT),
            ]);
            let resp = post_form(router, body).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let v = body_json(resp).await;
            assert_eq!(v["error"], "invalid_target");
        });
    }

    /// Bypass invariant: the PAT-shape gate fires on the access_token
    /// path BEFORE IdP authenticate. The federation path's early
    /// return means a PAT-shaped subject_token submitted with
    /// `subject_token_type = jwt` reaches the validator (which rejects
    /// it as InvalidFormat) — NOT the cli_session PAT-shape gate. This
    /// pins the design-doc §4 early-return invariant.
    #[test]
    fn federation_bypasses_pat_shape_gate() {
        let snap = capture_full_snapshot(|| {
            rt().block_on(async {
                let (router, validator, _sas, _mocks) = build_federation_router();
                let pat_shape = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                // The validator IS reached (rejects with InvalidFormat).
                validator.register_error(pat_shape, FederationDenyReason::InvalidFormat);
                let body = form_body(&[
                    ("grant_type", EXCHANGE_GRANT_TYPE),
                    ("subject_token", pat_shape),
                    ("subject_token_type", TOKEN_TYPE_JWT),
                ]);
                let resp = post_form(router, body).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                let v = body_json(resp).await;
                // Must be `invalid_grant` (federation branch),
                // NOT `invalid_token` (PAT-shape gate on cli_session
                // branch). This is the load-bearing assertion.
                assert_eq!(v["error"], "invalid_grant");
            });
        });
        // No PAT-rejection metric increments — the federation branch
        // owns this exit path.
        assert_eq!(
            counter_value(
                &snap,
                metrics::COUNTER,
                metrics::RESULT_SOURCE_TOKEN_PAT_REJECTED
            ),
            0,
        );
        assert_eq!(
            counter_value_kind_result(&snap, metrics::COUNTER, "federated_jwt", "invalid_format"),
            1,
        );
    }
}
