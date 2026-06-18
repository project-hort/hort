//! Authentication middleware.
//!
//! Two layers, both dispatching to the application-layer
//! [`AuthenticateUseCase`](hort_app::use_cases::authenticate_use_case::AuthenticateUseCase):
//!
//! - [`require_principal`] — write paths. Extracts
//!   `Authorization: Bearer <token>` (preferred) or `Authorization: Basic
//!   <b64>` (password field treated as the token, for clients like
//!   `twine` that cannot emit Bearer natively), validates it via the
//!   configured [`hort_domain::ports::identity_provider::IdentityProvider`],
//!   inserts the resulting [`CallerPrincipal`] in request extensions.
//!   Rejects with `401` on missing / invalid tokens.
//! - [`extract_optional_principal`] — read paths. Tries to validate but
//!   never fails: absent / invalid tokens still flow through with
//!   `Option<CallerPrincipal> = None` in extensions. Same Bearer →
//!   Basic-password fallback as the write path.
//!
//! Handlers use the [`req_principal`] helper to pull the principal out of
//! extensions.
//!
//! Clients obtain Bearer tokens from the IdP (Keycloak) directly; the
//! server never sees user credentials. There is no registry-minted JWT
//! layer — every incoming token is IdP-issued and validated via JWKS.
//!
//! The auth-mechanism inventory lives in `docs/auth-catalog.md`
//! (ADR 0018); read-path anonymity is ADR 0021.
//!
//! # Observability
//!
//! Every invocation of [`require_principal`] emits
//! `hort_auth_attempts_total{result}` exactly once with `result` drawn from
//! the catalog values `success` / `missing_header` / `invalid_token` /
//! `expired` / `unknown_issuer`. The token value is never logged.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine as _;

use hort_app::error::AppError;
use hort_app::metrics::labels::RESULT;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::error::DomainError;
use hort_domain::ports::identity_provider::OidcValidationError;

use crate::context::{AppContext, AuthContext};
use crate::error::ApiError;

// ---------------------------------------------------------------------------
// AuthenticatedPrincipal — the only typed slot a downstream extractor
// will accept.
//
// Wrapping `CallerPrincipal` in a newtype with a `pub(crate)` constructor
// makes "where can a principal come from" a compile-time constraint
// rather than a convention. Only modules inside `hort-http-core` (the auth
// middleware here, the OCI bearer middleware in `hort-http-oci` mints via
// the `test-support` re-export, and `extract_optional_principal` below)
// can construct one — anyone else with a bare `CallerPrincipal` cannot
// inject it into request extensions and silently grant authorization.
//
// `Deref` is deliberately NOT implemented; the explicit `as_caller`
// accessor keeps the unwrap visible at every call site (anti-patterns
// checklist §3.3). The newtype also does NOT implement `Deserialize` —
// principals must be server-constructed from a validated token, never
// reconstituted from a request body.
// ---------------------------------------------------------------------------

/// A [`CallerPrincipal`] that has been minted by a trusted authentication
/// boundary inside `hort-http-core`. Downstream extractors read this type
/// — never the bare [`CallerPrincipal`] — so an accidentally-introduced
/// middleware that injects a `CallerPrincipal` for any reason cannot
/// silently grant authorization.
///
/// The constructor is `pub(crate)`. Outside this crate the only ways to
/// place an `AuthenticatedPrincipal` into request extensions are via
/// [`require_principal`], [`extract_optional_principal`], or the
/// `pub fn`-but-named-for-review mint helpers re-exported below
/// (`mint_authenticated_principal_for_format_middleware` for per-format
/// auth crates, plus the test-support helper gated on the `test-support`
/// Cargo feature). Each of those is a load-bearing review surface.
///
/// `Deref` is deliberately NOT implemented; the explicit
/// [`AuthenticatedPrincipal::as_caller`] accessor keeps the unwrap
/// visible at every call site. The newtype also does NOT implement
/// `Deserialize` (anti-patterns checklist) — principals must be
/// server-constructed from a validated token, never reconstituted from
/// a request body.
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal(CallerPrincipal);

impl AuthenticatedPrincipal {
    /// Mint an [`AuthenticatedPrincipal`] from a [`CallerPrincipal`] that
    /// the auth middleware has already validated against the configured
    /// IdP. `pub(crate)` so only modules inside `hort-http-core` can call
    /// it.
    pub(crate) fn from_validated(principal: CallerPrincipal) -> Self {
        Self(principal)
    }

    /// Borrow the wrapped [`CallerPrincipal`] for read-only access. No
    /// `Deref` impl: the explicit accessor is the point — see the type
    /// docstring.
    pub fn as_caller(&self) -> &CallerPrincipal {
        &self.0
    }

    /// Consume this [`AuthenticatedPrincipal`] and return the wrapped
    /// [`CallerPrincipal`]. Used by handlers that need to thread an
    /// owned `CallerPrincipal` through a use-case API.
    pub fn into_caller(self) -> CallerPrincipal {
        self.0
    }
}

/// Per-format bearer middleware mint helper.
///
/// The OCI bearer middleware lives in a different crate (`hort-http-oci`)
/// so it cannot reach the `pub(crate)` constructor directly. This
/// function is the named, reviewable seam. It is `pub` but the name is
/// deliberately unwieldy so:
///
/// 1. Every call site is a `grep`-able audit checkpoint. The complete
///    list of production mint sites is `require_principal`,
///    `extract_optional_principal`, and every caller of this function.
/// 2. Any new format crate that adds bearer auth reuses this seam, so
///    the audit posture stays uniform.
///
/// The function body is identical to
/// [`AuthenticatedPrincipal::from_validated`]; the separate symbol is
/// the audit boundary.
pub fn mint_authenticated_principal_for_format_middleware(
    principal: CallerPrincipal,
) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal(principal)
}

// ---------------------------------------------------------------------------
// Result-label constants for hort_auth_attempts_total
// ---------------------------------------------------------------------------

/// `result=success` — token validated, principal inserted.
const RESULT_SUCCESS: &str = "success";
/// `result=missing_header` — no `Authorization` header (or empty bearer).
const RESULT_MISSING_HEADER: &str = "missing_header";
/// `result=invalid_token` — fallback classifier for any validation error
/// that isn't a recognised sub-case below.
const RESULT_INVALID_TOKEN: &str = "invalid_token";
/// `result=expired` — token rejected because `exp` is in the past.
const RESULT_EXPIRED: &str = "expired";
/// `result=unknown_issuer` — token's `iss` claim doesn't match configured.
const RESULT_UNKNOWN_ISSUER: &str = "unknown_issuer";
/// `result=idp_unavailable` — the JWKS /
/// discovery fetch failed (transport error, non-2xx status, oversize body,
/// or parse error). Distinct from `invalid_token` so SIEM consumers can
/// distinguish an IdP outage from a credential-stuffing campaign — both
/// land at 401 on the wire, but only the latter is a security signal.
const RESULT_IDP_UNAVAILABLE: &str = "idp_unavailable";

// ---------------------------------------------------------------------------
// require_principal
// ---------------------------------------------------------------------------

/// Write-path auth layer. Validates the caller's token and inserts the
/// [`CallerPrincipal`] into request extensions. Rejects with `401` on
/// missing or invalid tokens.
///
/// # Token source precedence
///
/// 1. `Authorization: Bearer <token>` — the modern path, used by every
///    first-party client.
/// 2. `Authorization: Basic <b64(username:token)>` — token *carrier*
///    only, for clients that cannot emit Bearer natively (notably
///    `twine` for PyPI, whose PyPI-targeting upload path is strictly
///    Basic). The username is ignored; the password field is treated
///    as the token and fed into the same validators as the Bearer
///    path.
///
/// Both paths deliver the raw token string to
/// [`AuthenticateUseCase::authenticate_bearer`], which validates the
/// token against the configured IdP (JWKS, issuer, audience) or as a
/// native token. The Basic-password carrier does not bypass any check
/// — it is a pure transport-layer adapter for clients that embed a
/// native token / IdP JWT in the password field.
///
/// # HTTP Basic is **not** an identity source
///
/// A raw username+password in HTTP Basic is **not** accepted as an
/// identity. There is no per-request
/// DB username-lookup + Argon2 password-verify
/// path. Native tokens carried in the Basic
/// password field cover every package-manager flow; accepting raw
/// passwords would make the public artifact plane a
/// password-brute-force surface. See
/// `docs/auth-catalog.md` Entry 8 (`Forbidden-in-release`).
pub async fn require_principal(
    State(ctx): State<Arc<AppContext>>,
    mut req: Request,
    next: Next,
) -> Response {
    let authenticate = match &ctx.auth {
        AuthContext::Disabled => {
            // The router builder skips attaching this layer when auth is
            // disabled. If the layer IS invoked under `Disabled`, that's a
            // composition bug — fail loudly rather than silently allow.
            tracing::error!(
                "require_principal invoked with AuthContext::Disabled — router wiring bug"
            );
            return internal_error_response("auth middleware attached with disabled context");
        }
        AuthContext::Enabled { authenticate, .. }
        | AuthContext::BearerOnly { authenticate, .. } => authenticate.clone(),
    };

    // Audit attribution: fail2ban / SIEM consumers of the auth-attempt
    // info log need `client_ip` to correlate with rate-limit rejections
    // (which include it). The request trust layer populates this;
    // absence is a composition bug. Fall back to an explicit sentinel
    // so the structured field always exists.
    let client_ip_raw: Option<std::net::IpAddr> = req
        .extensions()
        .get::<crate::middleware::trust::RequestTrust>()
        .map(|t| t.client_ip);
    let client_ip = client_ip_raw
        .as_ref()
        .map(std::net::IpAddr::to_string)
        .unwrap_or_else(|| "unknown".to_string());

    let path_is_oci = is_oci_path(&req);
    let token_source = resolve_token(&req);
    let token = match token_source.as_bearer_token() {
        Some(t) => t.to_string(),
        None => {
            emit_attempt_metric(RESULT_MISSING_HEADER);
            // Auth failures are audit events — fail2ban / SIEM
            // consumers need them at info level, not debug.
            tracing::info!(
                result = RESULT_MISSING_HEADER,
                client_ip = %client_ip,
                "auth attempt"
            );
            // Append a tamper-resistant
            // audit event. Best-effort; never blocks the 401 response.
            authenticate
                .record_auth_failure(client_ip_raw, RESULT_MISSING_HEADER, None)
                .await;
            return unauthorized_missing_header(&ctx.auth, path_is_oci);
        }
    };

    // Plaintext-bearer-refusal gate.
    // When the token shape is a native API token (or a
    // CliSession-family JWT) AND the request is NOT
    // proven-TLS AND the operator has not flipped
    // `HORT_BEARER_ALLOW_OVER_HTTP=true`, refuse with 426 Upgrade Required.
    // The check runs BEFORE `authenticate_bearer` so we never feed a
    // PAT plaintext through the validator on an unprotected wire.
    if let Some(reason) = pat_over_http_decision(&req, &token, &ctx) {
        return upgrade_required_response(reason);
    }

    // HTTP Basic is a token *carrier* only, never
    // an identity source. There is deliberately NO
    // `authenticate_local(username, password)` branch (a DB
    // username-lookup + Argon2 password-verify on every request):
    // that would make the public
    // artifact plane a password-brute-force surface, and native
    // tokens (`__token__:<hort_pat_*>` carried in the Basic password
    // field) fully cover every package-manager tooling flow.
    // auth-catalog Entry 8: Basic-as-token-carrier stays
    // `Active`; Basic carrying a raw username+password as an identity
    // source is `Forbidden-in-release`.
    //
    // Behaviour after the cutover: the Basic password field is still
    // fed to `authenticate_bearer` below via `as_bearer_token()` (the
    // carrier path — twine/pip/cargo/npm/docker embed the PAT/JWT
    // there with `__token__` or any username, which is ignored). A
    // raw username+password therefore reaches `authenticate_bearer`,
    // which rejects it (a password is not a valid JWT/native token)
    // → 401, WITHOUT any DB password check ever running. The reject
    // is an audit signal, not an error (`info!`, never `err`).
    if let TokenSource::Basic { username, password } = &token_source {
        if !username.is_empty() && !is_token_carrier_username(username) {
            // Shape of a raw username+password identity attempt
            // (a real username, not the `__token__` carrier
            // sentinel). The password field is still handed to the
            // bearer validator below; if it is not a valid token
            // this 401s. The DB password-check identity path no
            // longer exists. Log the reject here (audit, not an error)
            // so SIEM/fail2ban see the deprecated-shape attempt before
            // the generic bearer-validation 401.
            let _ = password;
            tracing::info!(
                result = "basic_identity_forbidden",
                client_ip = %client_ip,
                "auth attempt: HTTP Basic username+password rejected as identity source \
                 (Basic is a token carrier only; supply a native token in the \
                 password field)"
            );
        }
    }

    match authenticate.authenticate_bearer(&token).await {
        Ok(principal) => {
            emit_attempt_metric(RESULT_SUCCESS);
            // Success stays at debug — every authenticated request
            // would otherwise double the info-level log volume. Audit
            // consumers only need the failure signal elevated.
            tracing::debug!(
                result = RESULT_SUCCESS,
                client_ip = %client_ip,
                user_id = %principal.user_id,
                external_id = %principal.external_id,
                "auth attempt"
            );
            // The auth middleware
            // mints the only `AuthenticatedPrincipal` slot a downstream
            // extractor will read. The bare `CallerPrincipal` slot was
            // removed; a future middleware that injects a
            // `CallerPrincipal` for any reason can no longer silently
            // grant authorization because the extractors no longer
            // consult that slot.
            req.extensions_mut()
                .insert(AuthenticatedPrincipal::from_validated(principal));
            next.run(req).await
        }
        Err(err) => {
            let label = classify_auth_error(&err);
            emit_attempt_metric(label);
            // Per-failure audit log at info level.
            tracing::info!(result = label, client_ip = %client_ip, "auth attempt");
            // Best-effort audit event.
            // The audit-event `result` payload uses the SAME label
            // string as the `hort_auth_attempts_total{result}` metric
            // so SIEM consumers can join the metric series
            // with audit records on `result` directly. The token
            // itself is NEVER recorded.
            authenticate
                .record_auth_failure(client_ip_raw, label, None)
                .await;
            unauthorized_invalid_token(&ctx.auth, path_is_oci)
        }
    }
}

/// Whether this request targets an OCI Distribution Spec endpoint, which
/// determines the WWW-Authenticate challenge scheme on a 401 response.
///
/// containers/image (skopeo, crane, podman) follows OCI Distribution v2:
/// first request unauthenticated → parse WWW-Authenticate on 401 → retry
/// with the appropriate scheme. If the challenge advertises `Bearer`, the
/// client expects `realm` to be a real token-endpoint URL it can hit to
/// exchange credentials for a JWT. Without a configured OCI token
/// endpoint, advertising `Bearer realm="..."`
/// breaks the client because the realm isn't a resolvable URL.
///
/// For OCI paths we therefore advertise `Basic` instead. With `--dest-creds
/// USER:PASS`, skopeo retries directly with `Authorization: Basic`, and
/// require_principal accepts it via the existing Basic-with-JWT-password
/// path (the JWT in the password field flows through the same JWKS
/// validation as a Bearer token). With a real /v2/token
/// endpoint configured, this branch flips to
/// Bearer with a resolvable realm.
///
/// Non-OCI paths (pypi, npm, cargo, admin) keep the Bearer challenge —
/// those clients send Basic preemptively (twine, cargo, npm publish) and
/// never consume the challenge anyway, but the Bearer label is the
/// modern-correct one for browser-style consumers that may hit /admin.
fn is_oci_path(req: &Request) -> bool {
    let path = req.uri().path();
    path == "/v2" || path == "/v2/" || path.starts_with("/v2/")
}

// ---------------------------------------------------------------------------
// extract_optional_principal
// ---------------------------------------------------------------------------

/// Read-path auth layer. Always inserts `Option<CallerPrincipal>` into the
/// request extensions — `Some(_)` on a valid token, `None` when the header
/// is absent or validation fails. Never returns `401`.
///
/// Handlers that want to present authenticated-only information consult
/// the optional; plain read paths ignore it (reads are public
/// by design — ADR 0021).
///
/// # Observability
///
/// Read-path failures must NOT be invisible: an implementation that
/// `.ok()`-swallows every IdP error means token-stuffing on read
/// endpoints produces no metric and no tracing event, and fail2ban / SIEM
/// consumers have nothing to correlate. The layer emits
/// `hort_auth_attempts_total{result}` and a `tracing::info!` carrying
/// `client_ip` for every outcome — same labels and same shape as
/// [`require_principal`] — while still flowing through with
/// `Option<CallerPrincipal> = None` on failure (the wire-level invariant
/// the read path was originally designed around).
pub async fn extract_optional_principal(
    State(ctx): State<Arc<AppContext>>,
    mut req: Request,
    next: Next,
) -> Response {
    let authenticate = match &ctx.auth {
        AuthContext::Disabled => {
            req.extensions_mut()
                .insert::<Option<AuthenticatedPrincipal>>(None);
            return next.run(req).await;
        }
        AuthContext::Enabled { authenticate, .. }
        | AuthContext::BearerOnly { authenticate, .. } => authenticate.clone(),
    };

    // Audit attribution: same shape as require_principal — fail2ban /
    // SIEM consumers expect a `client_ip` field on every auth-attempt
    // info log so they can correlate read-side credential-stuffing with
    // rate-limit rejections from the same source.
    let client_ip_raw: Option<std::net::IpAddr> = req
        .extensions()
        .get::<crate::middleware::trust::RequestTrust>()
        .map(|t| t.client_ip);
    let client_ip = client_ip_raw
        .as_ref()
        .map(std::net::IpAddr::to_string)
        .unwrap_or_else(|| "unknown".to_string());

    // Same validation as require_principal, but never produce a
    // response — always pass through with `Option<CallerPrincipal>`
    // populated.
    let principal = match resolve_token(&req) {
        TokenSource::Absent => {
            emit_attempt_metric(RESULT_MISSING_HEADER);
            tracing::info!(
                result = RESULT_MISSING_HEADER,
                client_ip = %client_ip,
                "auth attempt"
            );
            // Best-effort audit event
            // on the read path too. The wire-level contract is
            // unchanged (200 with `Option<CallerPrincipal> = None`);
            // only the audit log gains the new tamper-resistant
            // record.
            authenticate
                .record_auth_failure(client_ip_raw, RESULT_MISSING_HEADER, None)
                .await;
            None
        }
        TokenSource::Bearer(tok) | TokenSource::Basic { password: tok, .. } => {
            match authenticate.authenticate_bearer(&tok).await {
                Ok(principal) => {
                    emit_attempt_metric(RESULT_SUCCESS);
                    // Success stays at debug to keep the info-level log
                    // volume bounded — mirrors require_principal's
                    // rationale. Audit consumers care about the failure
                    // signal at info level; success is reconstructible
                    // via correlation_id.
                    tracing::debug!(
                        result = RESULT_SUCCESS,
                        client_ip = %client_ip,
                        user_id = %principal.user_id,
                        external_id = %principal.external_id,
                        "auth attempt"
                    );
                    Some(principal)
                }
                Err(err) => {
                    let label = classify_auth_error(&err);
                    emit_attempt_metric(label);
                    // Failure goes to info — same level as the write
                    // path. The wire status is still 200; the audit
                    // signal is the metric + this log line, NOT a 401.
                    tracing::info!(result = label, client_ip = %client_ip, "auth attempt");
                    // The same label string
                    // is used for the audit-event `result` payload so
                    // it joins 1:1 with the metric label.
                    authenticate
                        .record_auth_failure(client_ip_raw, label, None)
                        .await;
                    None
                }
            }
        }
    };
    // Wrap into the
    // `AuthenticatedPrincipal` newtype before crossing the extension-
    // slot boundary. Anonymous reads stay distinguishable via the outer
    // `Option`; an authenticated read is unforgeable from outside this
    // crate's auth boundary.
    let principal = principal.map(AuthenticatedPrincipal::from_validated);
    req.extensions_mut()
        .insert::<Option<AuthenticatedPrincipal>>(principal);
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Handler helper
// ---------------------------------------------------------------------------

/// Pull the authenticated [`CallerPrincipal`] out of request extensions.
///
/// Returns a 500-shaped [`ApiError`] when the extension is missing — that
/// indicates the `require_principal` layer was NOT attached upstream,
/// which is always a router-wiring bug, not a request-shape bug.
///
/// Reads the
/// [`AuthenticatedPrincipal`] newtype slot, never the bare
/// [`CallerPrincipal`] slot. The bare slot is no longer populated; a
/// future middleware that injects a `CallerPrincipal` cannot reach this
/// helper.
pub fn req_principal(req: &Request) -> Result<&CallerPrincipal, ApiError> {
    req.extensions()
        .get::<AuthenticatedPrincipal>()
        .map(AuthenticatedPrincipal::as_caller)
        .ok_or_else(|| {
            ApiError::from(AppError::Domain(DomainError::Invariant(
                "require_principal layer not attached".into(),
            )))
        })
}

// ---------------------------------------------------------------------------
// Response / header helpers
// ---------------------------------------------------------------------------

/// Classification of `Authorization: Basic <...>` header parsing.
///
/// Replaces the former `Option<String>` return of
/// [`extract_basic_password_as_token`] so the middleware can distinguish
/// "no `Basic` header" (common — many requests use Bearer or are
/// unauthenticated by design) from "present but malformed" (worth a
/// `warn!` — possible credential-stuffing / probing).
// Retained alongside the richer `BasicCredentialsResult` so the
// pre-existing test suite (`extract_basic_password_as_token_*` /
// `basic_reason_renders_variants`) can keep pinning the legacy
// password-only contract. Production callers now use
// `extract_basic_credentials` via `resolve_token`.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BasicAuthResult {
    /// Header parsed cleanly; inner string is the password field (treated
    /// as an opaque bearer token — the username half is ignored, per the
    /// PyPI / Docker Hub convention of embedding a JWT in the password).
    Ok(String),
    /// Base64 decoding failed — the header was syntactically malformed.
    MalformedBase64,
    /// Base64 decoded but the payload was missing the `username:password`
    /// colon separator, carried non-UTF-8 bytes, or had an empty password
    /// half. All three collapse because they shape the same way to an
    /// operator monitoring probe traffic.
    MissingColon,
    /// No `Authorization: Basic` header present — the common, legitimate
    /// case. Callers treat this silently (no log).
    Absent,
}

/// Which transport carried the token we're about to validate.
#[derive(Debug)]
enum TokenSource {
    Bearer(String),
    /// HTTP Basic — carries BOTH the decoded username and the password.
    /// The password field is the "token" half (treated as Bearer for the
    /// JWT-in-password legacy flow). The username
    /// field is never an identity-routing input: Basic is a token
    /// carrier only (see `require_principal`'s doc-block). The
    /// username is retained on this struct because it is read for the
    /// `is_token_carrier_username` shape-classification log line — a
    /// raw username+password identity attempt is rejected by the
    /// downstream bearer validator (the password is not a valid
    /// token), and we surface the deprecated-shape attempt at `info!`
    /// so SIEM/fail2ban see it.
    Basic {
        username: String,
        password: String,
    },
    Absent,
}

impl TokenSource {
    /// The token to feed into bearer-style validators. For
    /// [`Self::Basic`] this is the password field, mirroring the
    /// long-standing PyPI/Docker convention of embedding a JWT or PAT in
    /// the password half.
    fn as_bearer_token(&self) -> Option<&str> {
        match self {
            Self::Bearer(t) | Self::Basic { password: t, .. } => Some(t.as_str()),
            Self::Absent => None,
        }
    }
}

/// Look up the token to validate, preferring Bearer over Basic.
///
/// `Absent` does NOT distinguish "no Authorization header at all" from
/// "Basic header present but malformed" — the middleware already emitted
/// a `warn!` in the latter case via [`classify_basic_auth`] (see
/// [`extract_basic_credentials`]). The downstream handler just
/// treats every absence mode uniformly.
fn resolve_token(req: &Request) -> TokenSource {
    if let Some(tok) = extract_bearer(req) {
        return TokenSource::Bearer(tok);
    }
    match extract_basic_credentials(req) {
        BasicCredentialsResult::Ok { username, password } => {
            TokenSource::Basic { username, password }
        }
        BasicCredentialsResult::Absent => TokenSource::Absent,
        other => {
            // Header-format failures are logged at warn level here
            // (scanning / probing is worth flagging), then collapsed
            // to `Absent` so the rest of the pipeline treats them as
            // "no credentials" → 401. The metric follows the normal
            // missing-header path.
            tracing::warn!(reason = %basic_creds_reason(&other), "basic-auth header rejected");
            TokenSource::Absent
        }
    }
}

/// Render a [`BasicAuthResult`] reason for logging. Extracted so tests
/// can assert the exact reason string without a `tracing` subscriber.
#[allow(dead_code)]
fn basic_reason(result: &BasicAuthResult) -> &'static str {
    match result {
        BasicAuthResult::MalformedBase64 => "malformed_base64",
        BasicAuthResult::MissingColon => "missing_colon",
        BasicAuthResult::Ok(_) | BasicAuthResult::Absent => "",
    }
}

/// Same shape as [`BasicAuthResult`] but preserves the decoded username
/// alongside the password. The
/// username is consumed only by `is_token_carrier_username` for the
/// deprecated-shape audit log (see [`require_principal`]). The legacy
/// [`extract_basic_password_as_token`] is preserved for tests that pin
/// the password-only contract; production callers use this richer
/// variant via [`resolve_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BasicCredentialsResult {
    Ok { username: String, password: String },
    MalformedBase64,
    MissingColon,
    Absent,
}

fn basic_creds_reason(result: &BasicCredentialsResult) -> &'static str {
    match result {
        BasicCredentialsResult::MalformedBase64 => "malformed_base64",
        BasicCredentialsResult::MissingColon => "missing_colon",
        BasicCredentialsResult::Ok { .. } | BasicCredentialsResult::Absent => "",
    }
}

/// Extract HTTP Basic credentials preserving BOTH the username and the
/// password. Mirrors [`extract_basic_password_as_token`] but does NOT
/// drop the username half.
///
/// Empty-password is still folded into `MissingColon` (same as the
/// legacy helper): it's indistinguishable from "no credential" and
/// gives a single, operator-readable bucket for probe traffic.
fn extract_basic_credentials(req: &Request) -> BasicCredentialsResult {
    let Some(value) = req.headers().get(header::AUTHORIZATION) else {
        return BasicCredentialsResult::Absent;
    };
    let Ok(raw) = value.to_str() else {
        return BasicCredentialsResult::MalformedBase64;
    };
    let Some(encoded) = raw.strip_prefix("Basic ") else {
        return BasicCredentialsResult::Absent;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return BasicCredentialsResult::MalformedBase64;
    };
    let Ok(decoded_str) = String::from_utf8(decoded) else {
        return BasicCredentialsResult::MissingColon;
    };
    let Some((username, password)) = decoded_str.split_once(':') else {
        return BasicCredentialsResult::MissingColon;
    };
    if password.is_empty() {
        BasicCredentialsResult::MissingColon
    } else {
        BasicCredentialsResult::Ok {
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

/// The conventional HTTP Basic *username* package-manager tooling emits
/// when the credential is a token carried in the password field, rather
/// than a real account username. `twine`/`pip` (PyPI), and `cargo`/`npm`
/// via their token configs, send `__token__` here; the password half is
/// the actual native token / JWT.
///
/// A Basic header whose username is **not** this
/// carrier sentinel and is non-empty has the *shape* of a raw
/// username+password identity attempt. Basic is a token carrier only —
/// such requests are logged as a forbidden-identity attempt and then
/// rejected by the bearer validator (the password is not a valid
/// token), with **no DB password check**. The carrier sentinel and the
/// empty-username case stay silent: those are legitimate token-carrier
/// traffic whose password field flows to `authenticate_bearer`
/// unchanged.
fn is_token_carrier_username(username: &str) -> bool {
    username == "__token__"
}

/// Extract `Authorization: Bearer <token>` into an owned `String`.
/// Returns `None` for missing, non-UTF-8, non-`Bearer`, or empty-token
/// variants — the caller treats all absence modes as "no token".
fn extract_bearer(req: &Request) -> Option<String> {
    let value = req.headers().get(header::AUTHORIZATION)?;
    let s = value.to_str().ok()?;
    let token = s.strip_prefix("Bearer ")?;
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Extract a token from `Authorization: Basic <b64>` by decoding the
/// password field. The username is ignored — the JWT in the password
/// position carries the `sub` claim that identifies the principal.
///
/// Rationale: clients that cannot emit `Authorization: Bearer` natively
/// (notably `twine` for PyPI — strictly Basic) wrap a registry- or
/// IdP-issued JWT in the password field of HTTP Basic. This is the
/// pattern used by Docker Hub and Artifactory for the same reason.
///
/// The username half is ignored entirely — callers typically emit
/// `__token__` (PyPI convention) or their real username, and both
/// should work. Verification happens downstream via the JWT signature,
/// NOT via matching the username.
///
/// Returns a structured [`BasicAuthResult`] so callers can log
/// header-format failures distinctly from a legitimately-absent header.
#[allow(dead_code)]
fn extract_basic_password_as_token(req: &Request) -> BasicAuthResult {
    let Some(value) = req.headers().get(header::AUTHORIZATION) else {
        return BasicAuthResult::Absent;
    };
    let Ok(raw) = value.to_str() else {
        // Non-UTF-8 header value. Could be a probe or a broken client;
        // callers will classify as malformed.
        return BasicAuthResult::MalformedBase64;
    };
    let Some(encoded) = raw.strip_prefix("Basic ") else {
        // Authorization present but not Basic (e.g. Bearer handled
        // separately, or Digest). Not our problem.
        return BasicAuthResult::Absent;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return BasicAuthResult::MalformedBase64;
    };
    let Ok(decoded_str) = String::from_utf8(decoded) else {
        // Decoded to non-UTF-8 bytes. Unsalvageable.
        return BasicAuthResult::MissingColon;
    };
    let Some((_username, password)) = decoded_str.split_once(':') else {
        return BasicAuthResult::MissingColon;
    };
    if password.is_empty() {
        // Empty password half is indistinguishable from "no credential"
        // — fold it into the missing-colon bucket so the log line
        // matches the operator's mental model.
        BasicAuthResult::MissingColon
    } else {
        BasicAuthResult::Ok(password.to_string())
    }
}

/// Config-aware `WWW-Authenticate` challenge selector.
///
/// There is no `has_local_users` axis: the Basic challenge under
/// `Enabled` advertises the token-carrier path (pip / twine / cargo /
/// docker embed a PAT in the Basic password field) regardless of
/// whether any local user happens to exist — there is no
/// HTTP-Basic-against-local-admin-row identity path. The
/// `(AuthContext, is_oci) → challenge` decision is:
///
/// 1. **OCI path (`is_oci=true`) — always `Basic`.** OCI Distribution
///    Spec interop: skopeo / docker / podman send Basic preemptively
///    and don't consume a Bearer challenge. This branch fires
///    *before* the `AuthContext` arms so the multi-scheme outcome
///    cannot leak into the OCI surface.
/// 2. **`AuthContext::Disabled` — always `Basic`.** Defense-in-depth
///    backstop; `serve::ensure_auth_enabled` rejects this combo at
///    boot.
/// 3. **`AuthContext::BearerOnly` — multi-scheme `Bearer + Basic`.**
///    No OIDC IdP; native-token bearer is the inbound path, Basic
///    advertises the token-carrier shape. No issuer URL to advertise.
/// 4. **`AuthContext::Enabled` — multi-scheme Bearer-first
///    `Bearer realm="<issuer>", Basic realm="hort"`.** RFC
///    7235 §2.1 lets a single header carry multiple challenges;
///    clients try the schemes in order. Bearer-first surfaces OIDC
///    discovery (the realm URL is the IdP's), and Basic advertises
///    the token-carrier path for package-manager tooling.
///
/// `error="invalid_token"` is intentionally NOT included here — that
/// parameter is appended by [`unauthorized_invalid_token`] only when
/// the header carried a token that failed validation. The
/// missing-header path uses the bare challenge.
pub(crate) fn www_authenticate_for(ctx: &AuthContext, is_oci: bool) -> String {
    if is_oci {
        return r#"Basic realm="hort""#.to_string();
    }
    match ctx {
        AuthContext::Disabled => r#"Basic realm="hort""#.to_string(),
        AuthContext::BearerOnly { .. } => r#"Bearer realm="hort", Basic realm="hort""#.to_string(),
        AuthContext::Enabled { issuer_url, .. } => {
            // The fallback realm covers
            // tests that construct `AuthContext::Enabled` without
            // pinning an issuer URL. Production composition always
            // populates `issuer_url`.
            let realm = issuer_url.as_deref().unwrap_or("hort");
            format!(r#"Bearer realm="{realm}", Basic realm="hort""#)
        }
    }
}

/// `401` response used when the `Authorization` header is missing.
///
/// The challenge scheme is selected by [`www_authenticate_for`] based
/// on the live `(AuthContext, is_oci)` tuple. The internal
/// [`is_oci_path`] classifier still feeds the `is_oci` argument.
fn unauthorized_missing_header(auth: &AuthContext, is_oci: bool) -> Response {
    let www = www_authenticate_for(auth, is_oci);
    // tracing::debug! — challenge selection is not a security-sensitive
    // state change; debug-level keeps the log volume bounded while
    // still letting an operator confirm the selector wired up correctly.
    tracing::debug!(
        scheme = www.split_once(' ').map(|(s, _)| s).unwrap_or(www.as_str()),
        is_oci,
        "challenge selected (missing header)",
    );
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, www)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"error":"missing Authorization header"}"#))
        .expect("static response")
}

/// `401` response used when the `Authorization` header carried a token
/// that failed validation. RFC 6750 `error="invalid_token"` parameter
/// lets Bearer-aware clients distinguish "needs credentials" from
/// "credentials were bad".
///
/// Selector logic delegates to [`www_authenticate_for`]; the
/// `error="invalid_token"` parameter is appended only when the
/// resulting challenge is a Bearer-style one (multi-scheme
/// Bearer-first counts; the parameter still applies to the leading
/// Bearer challenge per RFC 6750).
fn unauthorized_invalid_token(auth: &AuthContext, is_oci: bool) -> Response {
    let base = www_authenticate_for(auth, is_oci);
    // OCI / Disabled rows yield `Basic …` — RFC 6750's
    // `error="invalid_token"` only applies to Bearer challenges, so
    // the parameter is appended only when the leading scheme is
    // Bearer.
    let www = if base.starts_with("Bearer ") {
        // Multi-scheme: `Bearer realm="…", Basic realm="…"` →
        // `Bearer realm="…", error="invalid_token", Basic realm="…"`.
        // Bearer-only: `Bearer realm="…"` →
        // `Bearer realm="…", error="invalid_token"`.
        if let Some((bearer_part, rest)) = base.split_once(", Basic ") {
            format!(r#"{bearer_part}, error="invalid_token", Basic {rest}"#)
        } else {
            format!(r#"{base}, error="invalid_token""#)
        }
    } else {
        base
    };
    tracing::debug!(
        scheme = www.split_once(' ').map(|(s, _)| s).unwrap_or(www.as_str()),
        is_oci,
        "challenge selected (invalid token)",
    );
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, www)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"error":"invalid or expired token"}"#))
        .expect("static response")
}

/// `500` response used when the middleware is misconfigured. Produced only
/// by the `AuthContext::Disabled` guard inside [`require_principal`];
/// callers that reach this path have a router-wiring bug, not a request
/// bug.
fn internal_error_response(msg: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"error":"{msg}"}}"#)))
        .expect("static response")
}

// ---------------------------------------------------------------------------
// Error classification and metric emission
// ---------------------------------------------------------------------------

/// Map an [`AppError`] to one of the catalog values for
/// `hort_auth_attempts_total{result}`.
///
/// The port returns a structured
/// [`OidcValidationError`] variant which the middleware pattern-matches
/// — no substring matching, so the error string
/// never crosses a semantic boundary.
///
/// Non-OIDC errors (e.g. `DomainError` raised by `AuthenticateUseCase`'s
/// JIT-provisioning path, `AppError::Repository`) collapse to
/// `invalid_token` — they indicate a valid-looking token that hit a
/// downstream failure, which from the caller's perspective is the same
/// "401 invalid or expired token" outcome.
fn classify_auth_error(err: &AppError) -> &'static str {
    match err {
        AppError::OidcValidation(e) => classify_oidc_error(e),
        _ => RESULT_INVALID_TOKEN,
    }
}

/// Pure mapping from [`OidcValidationError`] variant to the corresponding
/// catalog value. Extracted so the mapping is independently testable
/// without constructing an [`AppError`] wrapper.
fn classify_oidc_error(err: &OidcValidationError) -> &'static str {
    match err {
        OidcValidationError::Expired => RESULT_EXPIRED,
        OidcValidationError::UnknownIssuer => RESULT_UNKNOWN_ISSUER,
        OidcValidationError::IdpUnavailable => RESULT_IDP_UNAVAILABLE,
        OidcValidationError::Malformed
        | OidcValidationError::SignatureInvalid
        | OidcValidationError::AudienceMismatch
        | OidcValidationError::ClaimMissing(_) => RESULT_INVALID_TOKEN,
    }
}

/// Emit `hort_auth_attempts_total{result}` with the supplied label.
fn emit_attempt_metric(result: &'static str) {
    metrics::counter!(
        "hort_auth_attempts_total",
        RESULT => result,
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Plaintext-PAT-refusal gate
// ---------------------------------------------------------------------------

/// `true` when the supplied bearer-token plaintext is shaped like an
/// opaque native API token (`hort_(pat|svc)_…`). Cheap byte-level check
/// — no body validation; the validator owns full parsing per
/// `hort_app::use_cases::pat_validation_use_case::parse_pat_token_format`.
///
/// We only need shape-level discrimination here so the gate refuses
/// the right traffic; rejecting a malformed `hort_*_*` shape over HTTP
/// is just as correct as rejecting a well-formed one (the malformed
/// case would otherwise fall through to the OIDC port and 401).
///
/// There is deliberately no `hort_cli_` arm — the
/// CliSession access token is an Ed25519 JWT
/// (`aud=urn:hort:cli-session`, `token_kind=cli_session`), so NO token
/// carries a `hort_cli_` prefix (`issue_cli_session` mints a
/// JWT via the signer; the only `generate_token_plaintext` callers are
/// the `Pat`/`ServiceAccount` opaque paths). The CliSession family is
/// refused over plaintext HTTP by [`looks_like_cli_session_jwt`].
fn looks_like_pat_token(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 9
        && &bytes[..5] == b"hort_"
        && bytes[8] == b'_'
        && matches!(&bytes[5..8], b"pat" | b"svc")
}

/// `true` when the supplied bearer-token plaintext is shaped like a
/// CliSession access-token JWT: a 3-segment JWT whose
/// **unverified** payload carries `aud == CLI_SESSION_AUDIENCE` AND
/// `token_kind == CLI_SESSION_TOKEN_KIND`.
///
/// This is a deliberately **pre-signature**
/// payload peek — the same posture as [`looks_like_pat_token`]'s
/// shape-only check. The 426 gate's job is to refuse the *credential*
/// before it crosses an unprotected wire to the validator; decoding the
/// (unverified) payload to recognise the CliSession discriminators is
/// fail-closed by design: a token *shaped* like a CliSession bearer is
/// refused over cleartext regardless of whether its signature is valid,
/// so we never leak — nor process — the credential over HTTP. An OIDC
/// bearer (different `aud`, no `token_kind=cli_session`) and an opaque
/// token (not a JWT) both fail this check and are unaffected.
///
/// The `aud`/`token_kind` literals are sourced from
/// [`hort_app::cli_session_signing`] so the two discriminators stay in
/// lock-step with the signer.
fn looks_like_cli_session_jwt(token: &str) -> bool {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // A JWT is `header.payload.signature`. We only need the payload.
    let mut segments = token.split('.');
    let (Some(_header), Some(payload), Some(_sig), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
        return false;
    };
    claims.get("aud").and_then(|v| v.as_str())
        == Some(hort_app::cli_session_signing::CLI_SESSION_AUDIENCE)
        && claims.get("token_kind").and_then(|v| v.as_str())
            == Some(hort_app::cli_session_signing::CLI_SESSION_TOKEN_KIND)
}

/// Reason string for the 426 response body — also passed verbatim to
/// the `tracing::warn!` so operators can grep one keyword to see how
/// many requests landed on this gate.
const PAT_OVER_HTTP_REFUSAL_REASON: &str = "pat over http refused";

/// Decide whether to refuse this request with 426 Upgrade Required.
///
/// Returns `Some(reason)` when ALL of:
/// - the token plaintext shapes as an opaque PAT prefix
///   ([`looks_like_pat_token`]) OR as a CliSession-family JWT
///   ([`looks_like_cli_session_jwt`])
/// - `pat_over_http_allowed = false` on the AppContext
/// - the request has no positive evidence of TLS — i.e.
///   `RequestTrust.public_url.scheme() != "https"` (the trust layer
///   already folds `X-Forwarded-Proto: https` from a trusted peer
///   into `public_url`; we deliberately do NOT introduce a new trust
///   path here).
///
/// Returns `None` when ANY of the above is false — the auth pipeline
/// proceeds normally.
fn pat_over_http_decision(req: &Request, token: &str, ctx: &AppContext) -> Option<&'static str> {
    if !looks_like_pat_token(token) && !looks_like_cli_session_jwt(token) {
        return None;
    }
    if ctx.pat_over_http_allowed {
        return None;
    }
    let proven_https = req
        .extensions()
        .get::<crate::middleware::trust::RequestTrust>()
        .map(|t| t.public_url.scheme() == "https")
        .unwrap_or(false);
    if proven_https {
        return None;
    }
    Some(PAT_OVER_HTTP_REFUSAL_REASON)
}

/// Build the 426 response advertised by the gate above. Body carries
/// the reason; headers include the spec-conformant
/// `Upgrade: TLS/1.2, HTTP/1.1` per RFC 9110 §15.6.7. Operators
/// alerting on `426` see one signal per refusal in their access log.
fn upgrade_required_response(reason: &'static str) -> Response {
    tracing::warn!(
        reason = reason,
        "bearer-over-HTTP refused — set HORT_BEARER_ALLOW_OVER_HTTP=true to override (TLS strongly recommended)"
    );
    let body = format!(r#"{{"error":"{reason}"}}"#);
    Response::builder()
        .status(StatusCode::UPGRADE_REQUIRED)
        .header("Upgrade", "TLS/1.2, HTTP/1.1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static response")
}

// ---------------------------------------------------------------------------
// Test support
// ---------------------------------------------------------------------------

/// Handler-test helpers. Gated on `cfg(any(test, feature = "test-support"))`
/// so downstream `hort-http-<format>` crates that enable
/// `hort-http-core/test-support` for their dev-deps can reach into the
/// auth pipeline's mint seam from their own test modules. The
/// `test-support` feature is dev-only — production builds never see
/// these symbols.
///
/// `inject_principal` wraps the
/// supplied [`CallerPrincipal`] in the [`AuthenticatedPrincipal`]
/// newtype before insertion. Tests that previously bypassed
/// `require_principal` by writing the bare slot must use this helper
/// instead; the principal extractor no longer reads the bare slot.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use axum::http::Request;

    use hort_domain::entities::caller::CallerPrincipal;

    use super::AuthenticatedPrincipal;

    /// Insert a pre-built [`CallerPrincipal`] into a test request's
    /// extensions as an [`AuthenticatedPrincipal`], bypassing the entire
    /// auth validation pipeline. Used by handler tests that don't care
    /// about token mechanics.
    pub fn inject_principal<B>(req: &mut Request<B>, principal: CallerPrincipal) {
        req.extensions_mut()
            .insert(AuthenticatedPrincipal::from_validated(principal));
    }

    /// Mint an [`AuthenticatedPrincipal`] without inserting it into a
    /// request. For tests that need to construct the type directly
    /// (e.g. building an `Extension<AuthenticatedPrincipal>` payload
    /// to pass to a handler under test).
    pub fn authenticated_principal(principal: CallerPrincipal) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal::from_validated(principal)
    }

    /// Insert a pre-built [`CallerPrincipal`] into a test request's
    /// extensions in the SAME shape `extract_optional_principal`
    /// produces in production:
    /// `Option<AuthenticatedPrincipal> = Some(...)`. Sibling of
    /// [`inject_principal`], which inserts the `require_principal`
    /// shape (bare `AuthenticatedPrincipal`).
    ///
    /// Use this in handler tests whose production route dispatches via
    /// `extract_optional_principal` (GET/HEAD/OPTIONS — see
    /// `crate::router::auth_dispatch`). A test that injects via
    /// [`inject_principal`] instead masks bugs in handlers that
    /// incorrectly extract `Option<Extension<AuthenticatedPrincipal>>`
    /// instead of reading both slots — the test sees the bare slot
    /// the helper writes, production never produces that shape on the
    /// GET path.
    pub fn inject_optional_principal_some<B>(req: &mut Request<B>, principal: CallerPrincipal) {
        req.extensions_mut()
            .insert::<Option<AuthenticatedPrincipal>>(Some(
                AuthenticatedPrincipal::from_validated(principal),
            ));
    }

    /// Insert the `extract_optional_principal` "auth ran, no token"
    /// sentinel: `Option<AuthenticatedPrincipal> = None`. Used by
    /// tests that want to assert a handler's behaviour for the
    /// authenticated-via-GET-middleware-but-anonymous case.
    pub fn inject_optional_principal_none<B>(req: &mut Request<B>) {
        req.extensions_mut()
            .insert::<Option<AuthenticatedPrincipal>>(None);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::body::to_bytes;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{MockIdentityProvider, MockUserRepository};
    use hort_domain::entities::rbac::ClaimMapping;
    use hort_domain::ports::identity_provider::{IdentityProvider, IdpClaims};
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::{AppContext, AuthContext};
    use crate::test_support::{build_mock_ctx, with_auth};

    // -- Fixtures ---------------------------------------------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn sample_claims(sub: &str) -> IdpClaims {
        IdpClaims {
            subject: sub.into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            groups: vec!["team-alpha".into()],
            issued_at: Utc::now(),
        }
    }

    /// `team-alpha` IdP group maps to the `developer` claim
    /// via `claim_mappings` (ADR 0012).
    fn claim_mappings() -> Vec<ClaimMapping> {
        vec![ClaimMapping {
            id: Uuid::new_v4(),
            idp_group: "team-alpha".into(),
            claim: "developer".into(),
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
        }]
    }

    /// Build a mock [`AppContext`] with [`AuthContext::Enabled`]. Returns
    /// the context and the underlying `MockIdentityProvider` so the test
    /// can register valid tokens.
    fn enabled_ctx(
        handle: metrics_exporter_prometheus::PrometheusHandle,
    ) -> (Arc<AppContext>, Arc<MockIdentityProvider>) {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp.clone() as Arc<dyn IdentityProvider>,
            users.clone() as Arc<dyn UserRepository>,
            claim_mappings(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let (base, _) = build_mock_ctx(handle);
        let ctx = with_auth(
            &base,
            AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        (ctx, idp)
    }

    /// Test fixture — same shape as
    /// [`enabled_ctx`] but wires the [`AuthenticateUseCase`] with an
    /// audit-event gate. Returns the context, the IdP mock, and the
    /// `MockEventStore` handle so tests can assert on appended
    /// batches.
    fn enabled_ctx_with_audit(
        handle: metrics_exporter_prometheus::PrometheusHandle,
    ) -> (
        Arc<AppContext>,
        Arc<MockIdentityProvider>,
        Arc<hort_app::use_cases::test_support::MockEventStore>,
    ) {
        use hort_app::use_cases::test_support::MockEventStore;
        use hort_domain::ports::ephemeral_store::EphemeralStore;

        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let event_store: Arc<MockEventStore> = Arc::new(MockEventStore::new());
        let (base, ports) = build_mock_ctx(handle);
        // The auth audit-event throttle writes to the
        // `auth:event:` keyspace, registered as Durable.
        let ephemeral_handle: Arc<dyn EphemeralStore> = ports.ephemeral_durable.clone();
        let authenticate = Arc::new(
            AuthenticateUseCase::new(
                idp.clone() as Arc<dyn IdentityProvider>,
                users.clone() as Arc<dyn UserRepository>,
                claim_mappings(),
            )
            .with_audit_events(
                hort_app::event_store_publisher::wrap_for_test(event_store.clone()),
                ephemeral_handle,
            ),
        );
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        (ctx, idp, event_store)
    }

    /// Build a mock [`AppContext`] with [`AuthContext::BearerOnly`] —
    /// the `HORT_AUTH_PROVIDER=disabled` + native-tokens-enabled shape.
    /// Returns the context and the `MockIdentityProvider` so the
    /// carrier path can be exercised with a registered token.
    ///
    /// No password seed: there is no `authenticate_local` path, so an
    /// Argon2id password hash on the Local user would be dead weight
    /// — the
    /// `BearerOnly` branch's only inbound shape is `Bearer
    /// hort_<kind>_*` (PAT) or Basic-as-token-carrier
    /// (`__token__:<token>` in the password field).
    fn bearer_only_ctx(
        handle: metrics_exporter_prometheus::PrometheusHandle,
    ) -> (Arc<AppContext>, Arc<MockIdentityProvider>) {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());

        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp.clone() as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            claim_mappings(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let (base, _) = build_mock_ctx(handle);
        let ctx = with_auth(&base, AuthContext::BearerOnly { authenticate, rbac });
        (ctx, idp)
    }

    /// Build a `RequestTrust` extension for tests so the auth
    /// middleware sees a deterministic `client_ip`. Mirrors the
    /// `request_trust_layer`'s output without standing up the full
    /// layer for tests that only care about auth-event recording.
    fn make_request_trust(client_ip: std::net::IpAddr) -> crate::middleware::trust::RequestTrust {
        crate::middleware::trust::RequestTrust {
            client_ip,
            public_url: url::Url::parse("http://localhost:8080").unwrap(),
        }
    }

    fn disabled_ctx(handle: metrics_exporter_prometheus::PrometheusHandle) -> Arc<AppContext> {
        build_mock_ctx(handle).0
    }

    // No local `base_ctx` duplicating ~100 lines of
    // AppContext wiring here —
    // `crate::test_support::build_mock_ctx` owns that logic, and
    // `disabled_ctx` / `enabled_ctx` above call it directly (the
    // enabled variant goes through `with_auth` to flip the `auth`
    // branch without rebuilding every port).

    /// Build a minimal router with the layer under test wrapping a
    /// handler that echoes back whether it saw a principal. Returns the
    /// router.
    fn router_with_require(ctx: Arc<AppContext>) -> Router {
        async fn handler(req: Request) -> Response {
            match req_principal(&req) {
                Ok(p) => Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(p.user_id.to_string()))
                    .unwrap(),
                Err(err) => err.into_response(),
            }
        }
        Router::new()
            .route("/protected", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                ctx.clone(),
                require_principal,
            ))
            .with_state(ctx)
    }

    fn router_with_optional(ctx: Arc<AppContext>) -> Router {
        async fn handler(req: Request) -> Response {
            let opt = req
                .extensions()
                .get::<Option<AuthenticatedPrincipal>>()
                .cloned();
            let body = match opt.flatten() {
                Some(p) => format!("some:{}", p.as_caller().user_id),
                None => "none".to_string(),
            };
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(body))
                .unwrap()
        }
        Router::new()
            .route("/read", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                ctx.clone(),
                extract_optional_principal,
            ))
            .with_state(ctx)
    }

    fn find<'a>(
        entries: &'a [MetricEntry],
        kind: MetricKind,
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != kind || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    /// Run a closure under a local metrics recorder and a single-thread
    /// runtime. Returns the snapshot along with whatever the closure
    /// produced.
    fn capture<T, F>(f: F) -> (Snapshot, T)
    where
        F: FnOnce() -> T,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let out = metrics::with_local_recorder(&recorder, f);
        (snapshotter.snapshot(), out)
    }

    fn prom_handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    // -- require_principal ---------------------------------------------

    #[test]
    fn require_principal_returns_401_on_missing_authorization_header() {
        let (snap, status) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, _idp) = enabled_ctx(prom_handle());
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(HttpRequest::get("/protected").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    let status = resp.status();
                    // WWW-Authenticate must include `Bearer` so clients
                    // know how to respond.
                    let www = resp
                        .headers()
                        .get(header::WWW_AUTHENTICATE)
                        .expect("WWW-Authenticate header missing")
                        .to_str()
                        .unwrap()
                        .to_string();
                    assert!(www.contains("Bearer"), "got: {www}");
                    status
                })
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "missing_header")],
        )
        .expect("missing_header counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn require_principal_returns_401_on_invalid_token() {
        let (snap, body_bytes) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, _idp) = enabled_ctx(prom_handle());
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, "Bearer not-registered")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                    let www = resp
                        .headers()
                        .get(header::WWW_AUTHENTICATE)
                        .expect("WWW-Authenticate missing")
                        .to_str()
                        .unwrap()
                        .to_string();
                    assert!(www.contains("invalid_token"), "got: {www}");
                    to_bytes(resp.into_body(), 1024).await.unwrap().to_vec()
                })
        });
        let body = String::from_utf8(body_bytes).unwrap();
        assert!(body.contains("invalid or expired token"), "got: {body}");
        let entries = snap.into_vec();
        // MockIdentityProvider returns `OidcValidationError::SignatureInvalid`
        // on unknown inputs — classifier pattern-matches the variant
        // and resolves to `invalid_token`.
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "invalid_token")],
        )
        .expect("invalid_token counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn require_principal_accepts_valid_token_and_inserts_principal() {
        let (snap, body_bytes) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = enabled_ctx(prom_handle());
                    idp.register_token("good", sample_claims("kc:abc"));
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, "Bearer good")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(resp.status(), StatusCode::OK);
                    to_bytes(resp.into_body(), 1024).await.unwrap().to_vec()
                })
        });
        // Handler returned the user_id — verifies the principal round-
        // tripped through request extensions.
        let body = String::from_utf8(body_bytes).unwrap();
        assert!(!body.is_empty());
        assert!(
            Uuid::parse_str(&body).is_ok(),
            "handler body {body:?} is not a uuid"
        );
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "success")],
        )
        .expect("success counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // -- /v2/ Basic challenge ------------------------------------------
    //
    // OCI Distribution clients (skopeo, containers/image) parse the 401's
    // WWW-Authenticate header to decide what scheme to retry with. Bearer
    // requires a resolvable realm URL pointing at a token endpoint; when
    // none is configured, /v2/ paths advertise
    // Basic, and the existing Basic-with-JWT-password fallback in
    // resolve_token routes the credential through the same JWT validator
    // as a Bearer token.

    fn router_with_require_at_path(ctx: Arc<AppContext>, path: &'static str) -> Router {
        async fn handler(req: Request) -> Response {
            match req_principal(&req) {
                Ok(p) => Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(p.user_id.to_string()))
                    .unwrap(),
                Err(err) => err.into_response(),
            }
        }
        Router::new()
            .route(path, get(handler))
            .layer(axum::middleware::from_fn_with_state(
                ctx.clone(),
                require_principal,
            ))
            .with_state(ctx)
    }

    #[test]
    fn require_principal_emits_basic_challenge_on_v2_path_without_auth() {
        let www = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, _idp) = enabled_ctx(prom_handle());
                    let router = router_with_require_at_path(ctx, "/v2/myrepo/blobs/uploads/");
                    let resp = router
                        .oneshot(
                            HttpRequest::post("/v2/myrepo/blobs/uploads/")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                    resp.headers()
                        .get(header::WWW_AUTHENTICATE)
                        .expect("WWW-Authenticate missing")
                        .to_str()
                        .unwrap()
                        .to_string()
                })
        })
        .1;
        assert!(
            www.starts_with("Basic"),
            "expected Basic challenge on /v2/, got: {www}"
        );
        assert!(www.contains("realm="), "got: {www}");
    }

    #[test]
    fn require_principal_emits_basic_challenge_on_v2_invalid_token() {
        let www = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = router_with_require_at_path(ctx, "/v2/myrepo/blobs/uploads/");
                let resp = router
                    .oneshot(
                        HttpRequest::post("/v2/myrepo/blobs/uploads/")
                            .header(header::AUTHORIZATION, "Bearer not-registered")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                resp.headers()
                    .get(header::WWW_AUTHENTICATE)
                    .expect("WWW-Authenticate missing")
                    .to_str()
                    .unwrap()
                    .to_string()
            });
        assert!(
            www.starts_with("Basic"),
            "expected Basic challenge on /v2/ with invalid token, got: {www}"
        );
    }

    #[test]
    fn require_principal_keeps_bearer_challenge_on_non_v2_paths() {
        let www = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = router_with_require_at_path(ctx, "/admin/repositories");
                let resp = router
                    .oneshot(
                        HttpRequest::get("/admin/repositories")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                resp.headers()
                    .get(header::WWW_AUTHENTICATE)
                    .expect("WWW-Authenticate missing")
                    .to_str()
                    .unwrap()
                    .to_string()
            });
        assert!(
            www.starts_with("Bearer"),
            "expected Bearer challenge on /admin/, got: {www}"
        );
    }

    #[test]
    fn is_oci_path_classification() {
        let cases: &[(&str, bool)] = &[
            ("/v2", true),
            ("/v2/", true),
            ("/v2/foo", true),
            ("/v2/foo/blobs/uploads/", true),
            ("/v2x", false),
            ("/admin", false),
            ("/admin/repositories", false),
            ("/", false),
            ("/pypi/test/simple/", false),
        ];
        for (path, expected) in cases {
            let req: Request<Body> = HttpRequest::get(*path).body(Body::empty()).unwrap();
            assert_eq!(is_oci_path(&req), *expected, "is_oci_path({path:?}) wrong");
        }
    }

    // -- End-to-end: port-contract enum → metric label -----------------
    //
    // These prove the typed variant travels all the way from the
    // MockIdentityProvider through the `?` in AuthenticateUseCase and
    // lands as the right label on hort_auth_attempts_total. A regression
    // that re-introduces string classification would fail these.

    #[test]
    fn require_principal_expired_variant_emits_expired_label() {
        let snap = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = enabled_ctx(prom_handle());
                    idp.register_error("tok", OidcValidationError::Expired);
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, "Bearer tok")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                })
        })
        .0;
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "expired")],
        )
        .expect("expired counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn require_principal_unknown_issuer_variant_emits_unknown_issuer_label() {
        let snap = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = enabled_ctx(prom_handle());
                    idp.register_error("tok", OidcValidationError::UnknownIssuer);
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, "Bearer tok")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                })
        })
        .0;
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "unknown_issuer")],
        )
        .expect("unknown_issuer counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn require_principal_claim_missing_variant_emits_invalid_token_label() {
        // ClaimMissing collapses to invalid_token — the metric set is
        // catalogued + narrow; see the classify_oidc_error pure test
        // for the full variant coverage.
        let snap = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = enabled_ctx(prom_handle());
                    idp.register_error("tok", OidcValidationError::ClaimMissing("sub".into()));
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, "Bearer tok")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                })
        })
        .0;
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "invalid_token")],
        )
        .expect("invalid_token counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // -- extract_optional_principal ------------------------------------

    #[test]
    fn extract_optional_principal_inserts_none_when_absent() {
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = router_with_optional(ctx);
                let resp = router
                    .oneshot(HttpRequest::get("/read").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                to_bytes(resp.into_body(), 1024).await.unwrap().to_vec()
            });
        assert_eq!(String::from_utf8(body).unwrap(), "none");
    }

    #[test]
    fn extract_optional_principal_inserts_some_when_valid() {
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, idp) = enabled_ctx(prom_handle());
                idp.register_token("tok", sample_claims("kc:def"));
                let router = router_with_optional(ctx);
                let resp = router
                    .oneshot(
                        HttpRequest::get("/read")
                            .header(header::AUTHORIZATION, "Bearer tok")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                to_bytes(resp.into_body(), 1024).await.unwrap().to_vec()
            });
        let body = String::from_utf8(body).unwrap();
        assert!(body.starts_with("some:"), "got: {body}");
    }

    #[test]
    fn extract_optional_principal_inserts_none_when_invalid() {
        // Invalid token (not registered on the mock) must NOT trigger
        // a 401 from this layer; it simply surfaces as None in the
        // handler's Option<AuthenticatedPrincipal>.
        let (status, body) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = router_with_optional(ctx);
                let resp = router
                    .oneshot(
                        HttpRequest::get("/read")
                            .header(header::AUTHORIZATION, "Bearer nope")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, body)
            });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(String::from_utf8(body).unwrap(), "none");
    }

    // -- Read-path observability ---------
    //
    // A read layer that swallows every IdP failure with `.ok()` leaves
    // token-stuffing on read endpoints invisible to fail2ban / SIEM.
    // These tests pin the emission contract:
    // - the wire status stays 200 (handler runs, principal is None);
    // - the metric AND the tracing::info! both fire with the right label.

    #[test]
    fn extract_optional_principal_emits_invalid_token_metric_on_unknown_token() {
        // Read-path token-stuffing canary: an unregistered token must now
        // increment hort_auth_attempts_total{result="invalid_token"}. The
        // 401 wire stays absent — we still flow through with None.
        let (snap, status_and_body) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, _idp) = enabled_ctx(prom_handle());
                    let router = router_with_optional(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/read")
                                .header(header::AUTHORIZATION, "Bearer not-registered")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    let status = resp.status();
                    let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                    (status, body)
                })
        });
        let (status, body_bytes) = status_and_body;
        // Wire-level invariant: read path NEVER 401s on a bad token.
        assert_eq!(status, StatusCode::OK);
        assert_eq!(String::from_utf8(body_bytes).unwrap(), "none");
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "invalid_token")],
        )
        .expect("invalid_token counter absent on read path");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    #[test]
    fn extract_optional_principal_emits_idp_unavailable_metric_on_idp_outage() {
        // Read-path IdP-outage canary: when the upstream IdP is
        // unreachable (mock returns OidcValidationError::IdpUnavailable),
        // the metric must increment idp_unavailable, NOT invalid_token.
        // This distinction between idp_unavailable and invalid_token is what operators rely on.
        let (snap, status) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = enabled_ctx(prom_handle());
                    idp.register_error("any-token", OidcValidationError::IdpUnavailable);
                    let router = router_with_optional(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/read")
                                .header(header::AUTHORIZATION, "Bearer any-token")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    resp.status()
                })
        });
        // Same wire-level outcome — read path never 401s.
        assert_eq!(status, StatusCode::OK);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "idp_unavailable")],
        )
        .expect("idp_unavailable counter absent on read path");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
        // And explicitly NOT invalid_token — the whole point of the split.
        let v_invalid = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "invalid_token")],
        );
        assert!(
            v_invalid.is_none(),
            "idp outage must not be classified as invalid_token"
        );
    }

    #[test]
    fn extract_optional_principal_emits_success_metric_on_valid_token() {
        // Counterpart to the failure cases — the read path must also
        // emit the success label on a valid token, mirroring the write
        // path's behaviour. Keeps the metric a complete picture of the
        // read-side auth signal, not just failures.
        let (snap, status) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = enabled_ctx(prom_handle());
                    idp.register_token("good", sample_claims("kc:read-success"));
                    let router = router_with_optional(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/read")
                                .header(header::AUTHORIZATION, "Bearer good")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    resp.status()
                })
        });
        assert_eq!(status, StatusCode::OK);
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "success")],
        )
        .expect("success counter absent on read path");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // -- AuthContext::Disabled guard -----------------------------------

    #[test]
    fn auth_context_disabled_returns_500_when_layer_attached() {
        // The router builder normally skips attaching this layer under
        // Disabled. If a composition root ever wires it in anyway, the
        // layer must fail loudly — not silently allow anonymous access.
        let (status, body) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let ctx = disabled_ctx(prom_handle());
                let router = router_with_require(ctx);
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, "Bearer anything")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, body)
            });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // 5xx responses must never surface internal paths / crate
        // identifiers. Helper is a no-op for non-5xx statuses.
        crate::error::assert_no_internal_leakage(status, &body);
    }

    #[test]
    fn extract_optional_principal_under_disabled_inserts_none() {
        // Read layer SHOULD remain cheap under Disabled — insert None
        // and pass through without consulting any use case.
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let ctx = disabled_ctx(prom_handle());
                let router = router_with_optional(ctx);
                let resp = router
                    .oneshot(
                        HttpRequest::get("/read")
                            .header(header::AUTHORIZATION, "Bearer anything")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                to_bytes(resp.into_body(), 1024).await.unwrap().to_vec()
            });
        assert_eq!(String::from_utf8(body).unwrap(), "none");
    }

    // -- req_principal helper ------------------------------------------

    #[test]
    fn req_principal_returns_error_when_extension_missing() {
        let req: Request<Body> = HttpRequest::get("/").body(Body::empty()).unwrap();
        // `ApiError` does NOT implement Debug (wrapping AppError), so
        // unwrap_err is not available — pattern-match instead.
        let resp = match req_principal(&req) {
            Ok(_) => panic!("expected missing-extension error"),
            Err(err) => err.into_response(),
        };
        // Surfaces as a 500 via IntoResponse — matches the Invariant
        // mapping in error.rs.
        let status = resp.status();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { to_bytes(resp.into_body(), 1024).await.unwrap().to_vec() });
        // Sanitisation invariant applies to every 5xx leaving the
        // ApiError -> Response mapper.
        crate::error::assert_no_internal_leakage(status, &body);
    }

    // -- AuthenticatedPrincipal-newtype security lock --------------
    //
    // The newtype boundary is the point. These tests pin BOTH directions:
    //
    // 1. Negative (the lock): a request whose extensions contain ONLY a
    //    bare `CallerPrincipal` — no `AuthenticatedPrincipal` — is treated
    //    as if no principal had been authenticated. Any future middleware
    //    that injects a `CallerPrincipal` for any reason cannot bypass
    //    auth.
    // 2. Positive: a request whose extensions contain an
    //    `AuthenticatedPrincipal` (minted via the `pub(crate)` constructor
    //    that only this crate's auth boundary can call) round-trips
    //    through `req_principal` cleanly.

    fn sample_principal() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::from_u128(0xc0ffee),
            external_id: "kc:lock-test".into(),
            username: "lock-test".into(),
            email: "lock@example.com".into(),
            claims: vec!["admin".into()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    #[test]
    fn req_principal_rejects_bare_caller_principal_extension() {
        // Negative test (security lock): a foreign middleware injects a
        // bare `CallerPrincipal` directly. `req_principal` MUST refuse —
        // the only acceptable typed slot is `AuthenticatedPrincipal`,
        // and the bare slot is no longer consulted at all.
        let mut req: Request<Body> = HttpRequest::get("/").body(Body::empty()).unwrap();
        req.extensions_mut().insert(sample_principal());
        let resp = match req_principal(&req) {
            Ok(_) => panic!("bare CallerPrincipal must NOT authenticate"),
            Err(err) => err.into_response(),
        };
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn req_principal_accepts_authenticated_principal_minted_via_constructor() {
        // Positive test: the auth-module constructor produces an
        // AuthenticatedPrincipal that round-trips. The constructor is
        // `pub(crate)`; outside this crate the only mints are via the
        // bearer middlewares and the `test-support` helpers.
        let principal = sample_principal();
        let mut req: Request<Body> = HttpRequest::get("/").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(AuthenticatedPrincipal::from_validated(principal.clone()));
        let Ok(read) = req_principal(&req) else {
            panic!("AuthenticatedPrincipal must authenticate");
        };
        assert_eq!(read, &principal);
    }

    #[test]
    fn require_principal_writes_authenticated_principal_only() {
        // Round-trip through the production `require_principal` layer.
        // The terminal handler asserts the request carries an
        // `AuthenticatedPrincipal` AND does NOT carry a bare
        // `CallerPrincipal` slot — pins the contract that the middleware
        // owns the only mint site on the wire path.
        async fn handler(req: Request) -> Response {
            let has_authed = req.extensions().get::<AuthenticatedPrincipal>().is_some();
            let has_bare = req.extensions().get::<CallerPrincipal>().is_some();
            let body = format!("authed={has_authed},bare={has_bare}");
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(body))
                .unwrap()
        }
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, idp) = enabled_ctx(prom_handle());
                idp.register_token("rt", sample_claims("kc:rt"));
                let router = Router::new()
                    .route("/protected", get(handler))
                    .layer(axum::middleware::from_fn_with_state(
                        ctx.clone(),
                        require_principal,
                    ))
                    .with_state(ctx);
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, "Bearer rt")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                to_bytes(resp.into_body(), 1024).await.unwrap().to_vec()
            });
        assert_eq!(String::from_utf8(body).unwrap(), "authed=true,bare=false");
    }

    #[test]
    fn extract_optional_principal_writes_authenticated_principal_only() {
        // Read-path companion to the test above. The middleware must
        // write `Option<AuthenticatedPrincipal>` and NOT write any
        // `Option<CallerPrincipal>` slot.
        async fn handler(req: Request) -> Response {
            let has_authed_opt = req
                .extensions()
                .get::<Option<AuthenticatedPrincipal>>()
                .is_some();
            let has_bare_opt = req.extensions().get::<Option<CallerPrincipal>>().is_some();
            let body = format!("authed_opt={has_authed_opt},bare_opt={has_bare_opt}");
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(body))
                .unwrap()
        }
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = Router::new()
                    .route("/read", get(handler))
                    .layer(axum::middleware::from_fn_with_state(
                        ctx.clone(),
                        extract_optional_principal,
                    ))
                    .with_state(ctx);
                let resp = router
                    .oneshot(HttpRequest::get("/read").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                to_bytes(resp.into_body(), 1024).await.unwrap().to_vec()
            });
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "authed_opt=true,bare_opt=false"
        );
    }

    #[test]
    fn authenticated_principal_as_caller_round_trips() {
        // Pure-data test — no router. The accessor returns the same
        // `CallerPrincipal` that was minted; `Deref` is deliberately
        // not implemented (anti-patterns checklist).
        let principal = sample_principal();
        let authed = AuthenticatedPrincipal::from_validated(principal.clone());
        assert_eq!(authed.as_caller(), &principal);
        let unwrapped = authed.into_caller();
        assert_eq!(unwrapped, principal);
    }

    /// Mint helper for `hort-http-oci` is `pub` (the constructor is
    /// `pub(crate)`, but the OCI bearer middleware lives in a different
    /// crate). This test is the audit checkpoint that the seam exists
    /// and produces a working `AuthenticatedPrincipal`. Anyone adding
    /// a new caller of `mint_authenticated_principal_for_format_middleware`
    /// will be visible in `git grep` of the symbol — by design.
    #[test]
    fn mint_helper_for_format_middleware_produces_round_tripping_principal() {
        let principal = sample_principal();
        let authed = mint_authenticated_principal_for_format_middleware(principal.clone());
        assert_eq!(authed.as_caller(), &principal);
    }

    #[test]
    fn test_support_inject_principal_round_trip() {
        let principal = CallerPrincipal {
            user_id: Uuid::from_u128(0xdead_beef),
            external_id: "test:sub".into(),
            username: "tester".into(),
            email: "tester@example.com".into(),
            claims: vec!["admin".into()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        };
        let mut req: Request<Body> = HttpRequest::get("/").body(Body::empty()).unwrap();
        test_support::inject_principal(&mut req, principal.clone());
        let Ok(read) = req_principal(&req) else {
            panic!("expected principal to round-trip");
        };
        assert_eq!(read, &principal);
    }

    // -- classify_auth_error -------------------------------------------
    //
    // The classifier pattern-matches the
    // port-contract enum instead of substring-matching a message. Each
    // variant is exercised here — a drift in the mapping will fail a
    // test, not silently produce the wrong metric label.

    #[test]
    fn classify_oidc_expired_maps_to_expired_label() {
        let err = AppError::OidcValidation(OidcValidationError::Expired);
        assert_eq!(classify_auth_error(&err), "expired");
    }

    #[test]
    fn classify_oidc_unknown_issuer_maps_to_unknown_issuer_label() {
        let err = AppError::OidcValidation(OidcValidationError::UnknownIssuer);
        assert_eq!(classify_auth_error(&err), "unknown_issuer");
    }

    #[test]
    fn classify_oidc_malformed_maps_to_invalid_token() {
        let err = AppError::OidcValidation(OidcValidationError::Malformed);
        assert_eq!(classify_auth_error(&err), "invalid_token");
    }

    #[test]
    fn classify_oidc_signature_invalid_maps_to_invalid_token() {
        let err = AppError::OidcValidation(OidcValidationError::SignatureInvalid);
        assert_eq!(classify_auth_error(&err), "invalid_token");
    }

    #[test]
    fn classify_oidc_claim_missing_maps_to_invalid_token() {
        let err = AppError::OidcValidation(OidcValidationError::ClaimMissing("sub".into()));
        assert_eq!(classify_auth_error(&err), "invalid_token");
    }

    #[test]
    fn classify_oidc_idp_unavailable_maps_to_idp_unavailable_label() {
        // IdP outage, oversize JWKS, parse
        // error must NOT collapse to the forged-signature bucket. Operators
        // need to see an IdP availability blip distinctly from a
        // credential-stuffing campaign.
        let err = AppError::OidcValidation(OidcValidationError::IdpUnavailable);
        assert_eq!(classify_auth_error(&err), "idp_unavailable");
    }

    #[test]
    fn classify_non_oidc_error_falls_through_to_invalid_token() {
        // AuthenticateUseCase may raise DomainError during JIT provisioning
        // after a token validates — that's still a caller-facing 401.
        let err = AppError::Domain(DomainError::Invariant("user row corrupted".into()));
        assert_eq!(classify_auth_error(&err), "invalid_token");
    }

    #[test]
    fn classify_oidc_error_pure_fn_covers_every_variant() {
        // Direct test of the pure classifier — lets coverage see every arm
        // without going through the AppError wrapper.
        assert_eq!(
            classify_oidc_error(&OidcValidationError::Expired),
            "expired"
        );
        assert_eq!(
            classify_oidc_error(&OidcValidationError::UnknownIssuer),
            "unknown_issuer"
        );
        assert_eq!(
            classify_oidc_error(&OidcValidationError::Malformed),
            "invalid_token"
        );
        assert_eq!(
            classify_oidc_error(&OidcValidationError::SignatureInvalid),
            "invalid_token"
        );
        assert_eq!(
            classify_oidc_error(&OidcValidationError::IdpUnavailable),
            "idp_unavailable"
        );
        assert_eq!(
            classify_oidc_error(&OidcValidationError::ClaimMissing("email".into())),
            "invalid_token"
        );
    }

    // -- extract_bearer -------------------------------------------------

    #[test]
    fn extract_bearer_rejects_non_bearer_scheme() {
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, "Basic aGVsbG86d29ybGQ=")
            .body(Body::empty())
            .unwrap();
        assert!(extract_bearer(&req).is_none());
    }

    #[test]
    fn extract_bearer_rejects_empty_token() {
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, "Bearer ")
            .body(Body::empty())
            .unwrap();
        assert!(extract_bearer(&req).is_none());
    }

    #[test]
    fn extract_bearer_happy_path_returns_token() {
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, "Bearer abcdef")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer(&req).as_deref(), Some("abcdef"));
    }

    // -- extract_basic_password_as_token -------------------------------

    /// Build an `Authorization: Basic <b64(user:pass)>` request for the
    /// Basic-password extractor unit tests.
    fn basic_req(user: &str, pass: &str) -> Request<Body> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        HttpRequest::get("/")
            .header(header::AUTHORIZATION, format!("Basic {encoded}"))
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn extract_basic_password_as_token_happy_path() {
        // The PyPI/twine convention: username `__token__` with the
        // real token in the password position.
        let req = basic_req("__token__", "my-jwt");
        assert_eq!(
            extract_basic_password_as_token(&req),
            BasicAuthResult::Ok("my-jwt".into())
        );
    }

    #[test]
    fn extract_basic_password_as_token_ignores_username() {
        // Username is deliberately ignored — the JWT signature is the
        // only identity check that matters.
        let req = basic_req("alice", "my-jwt");
        assert_eq!(
            extract_basic_password_as_token(&req),
            BasicAuthResult::Ok("my-jwt".into())
        );
    }

    #[test]
    fn extract_basic_password_as_token_empty_password_is_missing_colon() {
        // Empty-password case folds into MissingColon — from an operator
        // monitoring probes, an empty credential and a malformed payload
        // classify the same way.
        let req = basic_req("user", "");
        assert_eq!(
            extract_basic_password_as_token(&req),
            BasicAuthResult::MissingColon
        );
    }

    #[test]
    fn extract_basic_password_as_token_missing_colon() {
        // "nocolon" base64-encoded — no `:` separator after decoding.
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, format!("Basic {encoded}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_basic_password_as_token(&req),
            BasicAuthResult::MissingColon
        );
    }

    #[test]
    fn extract_basic_password_as_token_invalid_base64() {
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, "Basic !@#$")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_basic_password_as_token(&req),
            BasicAuthResult::MalformedBase64
        );
    }

    #[test]
    fn extract_basic_password_as_token_absent_header() {
        let req: Request<Body> = HttpRequest::get("/").body(Body::empty()).unwrap();
        assert_eq!(
            extract_basic_password_as_token(&req),
            BasicAuthResult::Absent
        );
    }

    #[test]
    fn extract_basic_password_as_token_non_basic_scheme_is_absent() {
        // A Bearer header is handled separately — from the Basic
        // extractor's POV, the header is absent, not malformed. Matters
        // for the log-level rule: we don't want to warn! on every
        // Bearer-authenticated request.
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, "Bearer something")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_basic_password_as_token(&req),
            BasicAuthResult::Absent
        );
    }

    #[test]
    fn extract_basic_password_as_token_non_utf8_decoded_is_missing_colon() {
        // Valid base64 that decodes to non-UTF-8 bytes (no colon present
        // in the decoded stream). Shapes the same as MissingColon.
        let encoded = base64::engine::general_purpose::STANDARD.encode([0xffu8, 0xfeu8, 0xfdu8]);
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, format!("Basic {encoded}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            extract_basic_password_as_token(&req),
            BasicAuthResult::MissingColon
        );
    }

    #[test]
    fn basic_reason_renders_variants() {
        // The reason string is what gets emitted via warn! — pin it so
        // log-grep-based operators don't silently break when we
        // reshuffle the enum.
        assert_eq!(
            basic_reason(&BasicAuthResult::MalformedBase64),
            "malformed_base64"
        );
        assert_eq!(
            basic_reason(&BasicAuthResult::MissingColon),
            "missing_colon"
        );
        // Absent / Ok don't log — the reason is an empty string.
        assert_eq!(basic_reason(&BasicAuthResult::Absent), "");
        assert_eq!(basic_reason(&BasicAuthResult::Ok("x".into())), "");
    }

    #[test]
    fn is_token_carrier_username_only_matches_pypi_sentinel() {
        // The `__token__` sentinel is the one
        // username value that means "this is a token carrier, stay
        // silent". Everything else (real account names, empty handled
        // separately at the call site) has the shape of a raw-identity
        // attempt and is logged as a forbidden-identity reject.
        assert!(is_token_carrier_username("__token__"));
        assert!(!is_token_carrier_username("alice"));
        assert!(!is_token_carrier_username("bootstrap"));
        assert!(!is_token_carrier_username("__token__ "));
        assert!(!is_token_carrier_username("_token_"));
        assert!(!is_token_carrier_username(""));
    }

    #[test]
    fn resolve_token_prefers_bearer_over_basic() {
        // When both Bearer and Basic could theoretically match (they
        // can't in a real request since both share the Authorization
        // header slot), Bearer wins — matches the documented precedence
        // in require_principal's doc comment.
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, "Bearer tok")
            .body(Body::empty())
            .unwrap();
        match resolve_token(&req) {
            TokenSource::Bearer(t) => assert_eq!(t, "tok"),
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    #[test]
    fn resolve_token_collapses_malformed_basic_to_absent() {
        // Structural check: a malformed Basic header must not be treated
        // as "token present" — it must fall into Absent so the caller
        // returns 401, and the warn! branch in resolve_token fires. We
        // inspect the outcome directly here; a subscriber-based assertion
        // for the warn! emission would buy nothing beyond this structural
        // check.
        let req: Request<Body> = HttpRequest::get("/")
            .header(header::AUTHORIZATION, "Basic !@#$")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(resolve_token(&req), TokenSource::Absent));
    }

    #[test]
    fn resolve_token_absent_when_no_auth_header() {
        let req: Request<Body> = HttpRequest::get("/").body(Body::empty()).unwrap();
        assert!(matches!(resolve_token(&req), TokenSource::Absent));
    }

    #[test]
    fn resolve_token_basic_carries_password() {
        let req = basic_req("alice", "the-token");
        match resolve_token(&req) {
            TokenSource::Basic { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "the-token");
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn require_principal_accepts_basic_password_with_valid_idp_token() {
        // IdP token wrapped inside HTTP Basic with `__token__` as the
        // username must authenticate the caller. Mirrors the Bearer
        // happy-path test and covers the `twine`-style client shape
        // where the upload tool cannot emit `Authorization: Bearer`
        // natively and embeds the token in the Basic password field.
        let (snap, status_and_body) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = enabled_ctx(prom_handle());
                    idp.register_token("kc-token", sample_claims("kc:basic"));
                    let encoded =
                        base64::engine::general_purpose::STANDARD.encode("__token__:kc-token");
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, format!("Basic {encoded}"))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    let status = resp.status();
                    let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                    (status, body)
                })
        });
        let (status, body_bytes) = status_and_body;
        assert_eq!(status, StatusCode::OK);
        assert!(Uuid::parse_str(&String::from_utf8(body_bytes).unwrap()).is_ok());
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            "hort_auth_attempts_total",
            &[("result", "success")],
        )
        .expect("success counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // ---------------------------------------------------------------
    // HTTP Basic is a token carrier only;
    // raw username+password is NOT an identity source.
    // auth-catalog Entry 8 → Forbidden-in-release.
    // ---------------------------------------------------------------

    #[test]
    fn r1_basic_token_carrier_still_authenticates_under_bearer_only() {
        // CONTRACT: Basic carrying a native token in the password field
        // (`__token__:<token>`, the twine/pip/cargo/npm shape) keeps
        // working untouched under BearerOnly. This path must NOT break.
        let (snap, status) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = bearer_only_ctx(prom_handle());
                    idp.register_token("carried-token", sample_claims("svc:carrier"));
                    let encoded =
                        base64::engine::general_purpose::STANDARD.encode("__token__:carried-token");
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, format!("Basic {encoded}"))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    resp.status()
                })
        });
        assert_eq!(
            status,
            StatusCode::OK,
            "Basic-as-token-carrier must keep authenticating under BearerOnly"
        );
        let entries = snap.into_vec();
        assert!(
            find(
                &entries,
                MetricKind::Counter,
                "hort_auth_attempts_total",
                &[("result", "success")],
            )
            .is_some(),
            "carrier path must record a success auth attempt"
        );
    }

    #[test]
    fn r1_basic_raw_username_password_identity_is_rejected() {
        // CONTRACT: a raw `username:password` is REJECTED as an
        // identity source. There is no DB
        // password-check identity path (no
        // `authenticate_local`). The bearer
        // validator sees the password-field bytes as not-a-token and
        // 401s — there is no DB password-check anywhere in the
        // request path to consult.
        let (_snap, status) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, _idp) = bearer_only_ctx(prom_handle());
                    let encoded =
                        base64::engine::general_purpose::STANDARD.encode("bootstrap:s3cr3t-pw");
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, format!("Basic {encoded}"))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    resp.status()
                })
        });
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a raw username+password must NOT authenticate under BearerOnly"
        );
    }

    #[test]
    fn r1_no_db_password_check_runs_when_password_is_a_valid_token() {
        // Defense-in-depth on the contract: when the username is a real
        // username (not `__token__`) but the password field IS a valid
        // native token, the carrier path still wins — the token in the
        // password authenticates and NO DB password-check identity path
        // is taken (it no longer exists). This pins that the username
        // half is ignored for the carrier path regardless of its value,
        // i.e. the identity branch was removed entirely rather than
        // gating it on the `__token__` sentinel.
        let (_snap, status) = capture(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (ctx, idp) = bearer_only_ctx(prom_handle());
                    idp.register_token("real-token", sample_claims("svc:ignored-user"));
                    // Username is a plausible account name (NOT
                    // `__token__`); password is a valid token.
                    let encoded =
                        base64::engine::general_purpose::STANDARD.encode("ci-runner:real-token");
                    let router = router_with_require(ctx);
                    let resp = router
                        .oneshot(
                            HttpRequest::get("/protected")
                                .header(header::AUTHORIZATION, format!("Basic {encoded}"))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    resp.status()
                })
        });
        assert_eq!(
            status,
            StatusCode::OK,
            "carrier path must validate the password-field token \
             regardless of the (ignored) username half"
        );
    }

    // ---------------------------------------------------------------
    // Auth-event audit trail tests
    // ---------------------------------------------------------------

    /// Build a router that injects RequestTrust (so the auth middleware
    /// sees a deterministic client_ip) and then runs the layer under
    /// test, finally invoking `req_principal`-echoing handler.
    fn router_with_require_and_trust(ctx: Arc<AppContext>, client_ip: std::net::IpAddr) -> Router {
        async fn handler(req: Request) -> Response {
            match req_principal(&req) {
                Ok(p) => Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(p.user_id.to_string()))
                    .unwrap(),
                Err(err) => err.into_response(),
            }
        }
        let trust = make_request_trust(client_ip);
        Router::new()
            .route("/protected", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                ctx.clone(),
                require_principal,
            ))
            .layer(axum::Extension(trust))
            .with_state(ctx)
    }

    fn router_with_optional_and_trust(ctx: Arc<AppContext>, client_ip: std::net::IpAddr) -> Router {
        async fn handler(req: Request) -> Response {
            let opt = req
                .extensions()
                .get::<Option<AuthenticatedPrincipal>>()
                .cloned();
            let body = match opt.flatten() {
                Some(p) => format!("some:{}", p.as_caller().user_id),
                None => "none".to_string(),
            };
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(body))
                .unwrap()
        }
        let trust = make_request_trust(client_ip);
        Router::new()
            .route("/read", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                ctx.clone(),
                extract_optional_principal,
            ))
            .layer(axum::Extension(trust))
            .with_state(ctx)
    }

    /// Acceptance test 11: OIDC token-validation failure on the read
    /// path appends an audit event AND keeps the wire response at 200
    /// (Option<None>). The audit signal lives in the event store +
    /// the metric, NOT in the wire status.
    #[test]
    fn extract_optional_principal_appends_audit_event_on_invalid_token() {
        use hort_domain::events::{DomainEvent, StreamCategory};
        let event_store = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp, event_store) = enabled_ctx_with_audit(prom_handle());
                let router = router_with_optional_and_trust(
                    ctx,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 42)),
                );
                let resp = router
                    .oneshot(
                        HttpRequest::get("/read")
                            .header(header::AUTHORIZATION, "Bearer not-registered")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                event_store
            });
        let batches = event_store.appended_batches();
        assert_eq!(batches.len(), 1, "expected one audit-event append");
        let batch = &batches[0];
        assert_eq!(batch.stream_id.category, StreamCategory::AuthAttempts);
        let DomainEvent::AuthenticationAttempted(event) = &batch.events[0].event else {
            panic!("unexpected event variant: {:?}", batch.events[0].event);
        };
        assert_eq!(
            event.client_ip,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 42))
        );
        assert_eq!(event.result, "invalid_token");
    }

    /// Acceptance test 12: OIDC token-validation failure on the
    /// write path appends an audit event AND returns 401.
    #[test]
    fn require_principal_appends_audit_event_on_invalid_token() {
        use hort_domain::events::{DomainEvent, StreamCategory};
        let event_store = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp, event_store) = enabled_ctx_with_audit(prom_handle());
                let router = router_with_require_and_trust(
                    ctx,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 42)),
                );
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, "Bearer not-registered")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                event_store
            });
        let batches = event_store.appended_batches();
        assert_eq!(batches.len(), 1, "expected one audit-event append");
        let batch = &batches[0];
        assert_eq!(batch.stream_id.category, StreamCategory::AuthAttempts);
        let DomainEvent::AuthenticationAttempted(event) = &batch.events[0].event else {
            panic!("unexpected event variant: {:?}", batch.events[0].event);
        };
        assert_eq!(event.result, "invalid_token");
    }

    /// Missing-Authorization-header on the write path appends an
    /// audit event with `result="missing_header"` AND returns 401.
    #[test]
    fn require_principal_appends_audit_event_on_missing_header() {
        let event_store = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp, event_store) = enabled_ctx_with_audit(prom_handle());
                let router = router_with_require_and_trust(
                    ctx,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 42)),
                );
                let resp = router
                    .oneshot(HttpRequest::get("/protected").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                event_store
            });
        let batches = event_store.appended_batches();
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        if let hort_domain::events::DomainEvent::AuthenticationAttempted(e) = &batch.events[0].event
        {
            assert_eq!(e.result, "missing_header");
        } else {
            panic!("unexpected event variant");
        }
    }

    #[test]
    fn extract_optional_principal_accepts_basic_password_with_valid_idp_token() {
        // Read-path layer must accept the same Basic-wrapped IdP token
        // and surface `Some(principal)` to downstream handlers.
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, idp) = enabled_ctx(prom_handle());
                idp.register_token("kc-token", sample_claims("kc:basic-read"));
                let encoded = base64::engine::general_purpose::STANDARD.encode("alice:kc-token");
                let router = router_with_optional(ctx);
                let resp = router
                    .oneshot(
                        HttpRequest::get("/read")
                            .header(header::AUTHORIZATION, format!("Basic {encoded}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                to_bytes(resp.into_body(), 1024).await.unwrap().to_vec()
            });
        let body = String::from_utf8(body).unwrap();
        assert!(body.starts_with("some:"), "got: {body}");
    }

    // -----------------------------------------------------------------
    // `WWW-Authenticate` challenge selector regression suite.
    //
    // There is no `has_local_users` axis (no
    // HTTP-Basic-against-local-admin-row
    // identity path exists). Decision matrix:
    //
    // | AuthContext | is_oci | Challenge                                                 |
    // |-------------|--------|-----------------------------------------------------------|
    // | Enabled(c)  | true   | `Basic realm="hort"`                           |
    // | Enabled(c)  | false  | `Bearer realm="<c.issuer_url>", Basic realm="..."`        |
    // | BearerOnly  | false  | `Bearer realm="hort", Basic realm="..."`       |
    // | Disabled    | n/a    | `Basic realm="hort"`                           |
    //
    // Basic is always advertised on the multi-scheme arms as the
    // token-carrier path (pip / twine / cargo / docker embed PATs in
    // the Basic password field), unrelated to user-row existence.
    // -----------------------------------------------------------------

    /// Build a minimal `AuthContext::Enabled` carrying `issuer_url`. The
    /// `authenticate` and `rbac` handles are unused by `www_authenticate_for`
    /// but required to construct the variant.
    fn enabled_auth_with_issuer(issuer_url: Option<&str>) -> AuthContext {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        AuthContext::Enabled {
            authenticate,
            rbac,
            issuer_url: issuer_url.map(str::to_string),
        }
    }

    /// `AuthContext::Disabled` always returns the Basic challenge,
    /// regardless of `is_oci`. Defense-in-depth backstop.
    #[test]
    fn www_authenticate_for_disabled_is_always_basic() {
        let auth = AuthContext::Disabled;
        for is_oci in [false, true] {
            let challenge = www_authenticate_for(&auth, is_oci);
            assert_eq!(
                challenge, r#"Basic realm="hort""#,
                "Disabled must always yield Basic; got {challenge:?} for is_oci={is_oci}",
            );
        }
    }

    /// OCI paths under `AuthContext::Enabled` (OIDC) always get `Basic`.
    /// Required by the OCI Distribution Spec for skopeo / docker /
    /// podman interop — these clients send Basic preemptively and
    /// don't consume a Bearer challenge. The `is_oci` check fires
    /// before the `AuthContext` arms, so this short-circuit overrides
    /// the multi-scheme `Enabled` branch.
    #[test]
    fn www_authenticate_for_oci_path_always_basic_under_oidc() {
        let auth = enabled_auth_with_issuer(Some("https://keycloak.example/realms/hort"));
        assert_eq!(www_authenticate_for(&auth, true), r#"Basic realm="hort""#,);
    }

    /// OIDC + non-OCI path — multi-scheme Bearer-first challenge.
    /// Bearer surfaces the issuer URL for OIDC discovery; Basic
    /// advertises the token-carrier path (pip / twine / cargo / docker
    /// embed a PAT in the Basic password field). RFC 7235 §2.1
    /// supports multiple challenges in a single header.
    #[test]
    fn www_authenticate_for_oidc_offers_multi_scheme() {
        let issuer = "https://keycloak.example/realms/hort";
        let auth = enabled_auth_with_issuer(Some(issuer));
        let challenge = www_authenticate_for(&auth, false);
        assert_eq!(
            challenge,
            format!(r#"Bearer realm="{issuer}", Basic realm="hort""#),
        );
        // Defensive substring assertion — pins that the issuer URL
        // appears verbatim in the realm field.
        assert!(
            challenge.contains(issuer),
            "issuer URL {issuer:?} not present in challenge {challenge:?}",
        );
    }

    // -------------------------------------------------------------------
    // Plaintext-PAT-refusal middleware tests
    //
    // Pins the contract: a `Bearer hort_<kind>_<body>`
    // token over plaintext HTTP, with `pat_over_http_allowed = false`,
    // returns 426 Upgrade Required without invoking the PAT validator.
    // The four branches enumerated below cover every leaf of the
    // decision tree from `pat_over_http_decision`.
    // -------------------------------------------------------------------

    /// Constant-shape PAT used in every refusal-path test. Body byte
    /// values are irrelevant to this layer (the validator is the next
    /// stop, not us); the prefix is what `looks_like_pat_token` keys
    /// on.
    const PAT_TOKEN: &str = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// Build a `RequestTrust` with the given scheme on `public_url`,
    /// pinned to a localhost peer. Mirrors the trust layer's output
    /// without standing it up; lets the test pin the gate's input.
    fn trust_with_scheme(scheme: &str) -> crate::middleware::trust::RequestTrust {
        let url = format!("{scheme}://test.example.invalid:8080");
        crate::middleware::trust::RequestTrust {
            client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            public_url: url::Url::parse(&url).expect("test scheme parses"),
        }
    }

    /// Build a router that injects the supplied `RequestTrust` BEFORE
    /// the auth layer so the gate's `req.extensions().get::<RequestTrust>`
    /// finds it.
    fn router_with_trust(
        ctx: Arc<AppContext>,
        trust: crate::middleware::trust::RequestTrust,
    ) -> Router {
        async fn handler(_req: Request) -> Response {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("ok"))
                .unwrap()
        }
        Router::new()
            .route("/protected", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                ctx.clone(),
                require_principal,
            ))
            .layer(axum::Extension(trust))
            .with_state(ctx)
    }

    /// `pat_over_http_allowed = false` (default) AND the wire is HTTP →
    /// 426 Upgrade Required, validator NEVER invoked. The body carries
    /// the reason string and the response includes the spec-mandated
    /// `Upgrade: TLS/1.2, HTTP/1.1` header.
    #[test]
    fn pat_token_over_http_returns_426_when_flag_unset() {
        let (status, headers, body) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                // Default: `pat_over_http_allowed = false`.
                let router = router_with_trust(ctx, trust_with_scheme("http"));
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, format!("Bearer {PAT_TOKEN}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = resp.status();
                let upgrade = resp.headers().get("Upgrade").cloned();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, upgrade, body)
            });
        assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
        let upgrade_value = headers
            .expect("Upgrade header missing")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            upgrade_value.contains("TLS"),
            "Upgrade must advertise TLS, got {upgrade_value:?}"
        );
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains(PAT_OVER_HTTP_REFUSAL_REASON), "got: {body}");
    }

    /// `pat_over_http_allowed = true` (operator opt-in) → the gate
    /// short-circuits and the request flows through to the OIDC port
    /// (which rejects with 401 because no PAT validator is wired in
    /// the mock). The 401 — NOT 426 — is the assertion: the gate is
    /// off; downstream auth runs as if the gate didn't exist.
    #[test]
    fn pat_token_over_http_returns_normal_response_when_flag_set() {
        let status = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let ctx = crate::test_support::with_pat_over_http_allowed(&ctx, true);
                let router = router_with_trust(ctx, trust_with_scheme("http"));
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, format!("Bearer {PAT_TOKEN}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                resp.status()
            });
        // The PAT validator is not wired on the mock, so the OIDC port
        // sees the PAT plaintext and rejects with `SignatureInvalid`
        // → 401. Either way: NOT 426.
        assert_ne!(status, StatusCode::UPGRADE_REQUIRED);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// An OIDC-shaped token (no `hort_<kind>_` prefix) flows through the
    /// gate untouched even on plain HTTP — the gate only refuses PAT
    /// shapes. This is the regression guard against accidentally
    /// breaking the OIDC over-HTTP dev workflow when the operator
    /// enables auth on a localhost setup.
    #[test]
    fn oidc_token_over_http_unaffected_by_pat_refusal() {
        let status = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, idp) = enabled_ctx(prom_handle());
                idp.register_token("oidc-tok", sample_claims("kc:over-http"));
                let router = router_with_trust(ctx, trust_with_scheme("http"));
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, "Bearer oidc-tok")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                resp.status()
            });
        // 200 OK — OIDC token validates and the request proceeds.
        assert_eq!(status, StatusCode::OK);
    }

    /// `RequestTrust.public_url` carries `https://…` (operator-pinned
    /// `HORT_PUBLIC_BASE_URL` OR `X-Forwarded-Proto: https` from a
    /// trusted proxy, both folded into `public_url` by the trust layer)
    /// → the gate is satisfied and the request flows through to auth.
    #[test]
    fn pat_token_over_https_proceeds_normally() {
        let status = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = router_with_trust(ctx, trust_with_scheme("https"));
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, format!("Bearer {PAT_TOKEN}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                resp.status()
            });
        // Validator is unwired → OIDC port rejects → 401 (NOT 426).
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// `X-Forwarded-Proto: https` from a trusted proxy is folded into
    /// `RequestTrust.public_url.scheme()` by the trust layer — by the
    /// time auth sees it, the trust is encoded as the scheme. This
    /// test pins that contract: a request with the trust-rendered
    /// `https://` public_url proceeds normally on the PAT path even
    /// when the literal request URL is HTTP.
    #[test]
    fn pat_token_over_http_with_x_forwarded_proto_https_proceeds_normally() {
        // The trust layer is the single source of truth for "is
        // this https?". We don't re-evaluate forwarding here. The
        // contract under test: a `RequestTrust` whose `public_url`
        // scheme is `https://` satisfies the gate, regardless of the
        // wire-level transport. (This is the supported deployment
        // shape: TLS-terminating proxy + plaintext upstream.)
        let status = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = router_with_trust(ctx, trust_with_scheme("https"));
                let resp = router
                    .oneshot(
                        // Note: literal scheme on the test request is
                        // irrelevant — the gate reads `RequestTrust`,
                        // populated above with `https://`.
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, format!("Bearer {PAT_TOKEN}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                resp.status()
            });
        assert_ne!(status, StatusCode::UPGRADE_REQUIRED);
    }

    // -------------------------------------------------------------------
    // CliSession-JWT-over-HTTP refusal
    //
    // The CliSession access token is an Ed25519-signed JWT
    // (`aud=urn:hort:cli-session`, `token_kind=cli_session`), not an opaque
    // `hort_cli_*` token, so it does not match the `hort_(pat|svc)_` byte
    // prefix the opaque-PAT
    // 426 gate keys on. Without a dedicated check, an
    // (up-to-admin-capable, ≤15 min) CliSession
    // bearer would NOT be refused over cleartext HTTP under the secure
    // default
    // `HORT_BEARER_ALLOW_OVER_HTTP=false`. The gate therefore refuses a
    // Bearer whose UNVERIFIED payload carries the CliSession `aud` +
    // `token_kind` (fail-closed pre-signature peek — we never decode the
    // credential over the validator on an unprotected wire).
    // -------------------------------------------------------------------

    /// Build a JWT-shaped string (`header.payload.signature`) whose
    /// payload carries the supplied `aud` + `token_kind`. The signature
    /// segment is a placeholder — the gate is a *pre-verification*
    /// payload peek (it never checks the signature), so a valid signature
    /// is deliberately NOT required to exercise the refusal path. This
    /// mirrors a real CliSession JWT's wire shape.
    fn cli_session_shaped_jwt(aud: &str, token_kind: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"iss":"https://hort.example.com","sub":"00000000-0000-0000-0000-000000000001","aud":"{aud}","exp":9999999999,"jti":"00000000-0000-0000-0000-000000000002","token_kind":"{token_kind}","claims":["admin"]}}"#
        ));
        // Placeholder signature segment — irrelevant to the pre-verify peek.
        let sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
        format!("{header}.{payload}.{sig}")
    }

    /// A genuine CliSession JWT (correct `aud` + `token_kind`) over
    /// plaintext HTTP with the secure-default `pat_over_http_allowed =
    /// false` → 426 Upgrade Required, validator NEVER invoked. This is
    /// The credential is refused on cleartext just like a `hort_pat_*`
    /// token.
    #[test]
    fn cli_session_jwt_over_http_returns_426_when_flag_unset() {
        let token = cli_session_shaped_jwt(
            hort_app::cli_session_signing::CLI_SESSION_AUDIENCE,
            hort_app::cli_session_signing::CLI_SESSION_TOKEN_KIND,
        );
        let (status, body) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = router_with_trust(ctx, trust_with_scheme("http"));
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, format!("Bearer {token}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 1024).await.unwrap().to_vec();
                (status, body)
            });
        assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains(PAT_OVER_HTTP_REFUSAL_REASON), "got: {body}");
    }

    /// The same CliSession JWT over proven-HTTPS → NOT refused (the gate
    /// only fires on a non-proven-HTTPS wire). Flows through to the auth
    /// validator (which 401s on the placeholder signature), proving the
    /// 426 is gated on transport, not on the token shape alone.
    #[test]
    fn cli_session_jwt_over_https_proceeds_normally() {
        let token = cli_session_shaped_jwt(
            hort_app::cli_session_signing::CLI_SESSION_AUDIENCE,
            hort_app::cli_session_signing::CLI_SESSION_TOKEN_KIND,
        );
        let status = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _idp) = enabled_ctx(prom_handle());
                let router = router_with_trust(ctx, trust_with_scheme("https"));
                let resp = router
                    .oneshot(
                        HttpRequest::get("/protected")
                            .header(header::AUTHORIZATION, format!("Bearer {token}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                resp.status()
            });
        assert_ne!(status, StatusCode::UPGRADE_REQUIRED);
    }

    // ---- pure unit tests on the gate's component fns ----

    #[test]
    fn looks_like_pat_token_recognises_pat_and_svc_prefixes() {
        assert!(looks_like_pat_token("hort_pat_anything"));
        assert!(looks_like_pat_token("hort_svc_anything"));
    }

    #[test]
    fn looks_like_pat_token_rejects_oidc_tokens_and_short_inputs() {
        assert!(!looks_like_pat_token("hort"));
        assert!(!looks_like_pat_token(""));
        assert!(!looks_like_pat_token("eyJhbGc.foo.bar")); // OIDC JWT shape
        assert!(!looks_like_pat_token("hort_xyz_body")); // wrong kind
        assert!(!looks_like_pat_token("hort-pat-body")); // wrong separator
                                                         // The `hort_cli_` prefix is dead (CliSession is a JWT now);
                                                         // the gate no longer keys on it. A `hort_cli_*` shape is treated
                                                         // like any other unknown opaque token — it is NOT a PAT prefix.
        assert!(!looks_like_pat_token("hort_cli_anything"));
    }

    #[test]
    fn looks_like_cli_session_jwt_matches_only_the_cli_session_family() {
        // Genuine CliSession-family payload (aud + token_kind both set).
        let cli = cli_session_shaped_jwt(
            hort_app::cli_session_signing::CLI_SESSION_AUDIENCE,
            hort_app::cli_session_signing::CLI_SESSION_TOKEN_KIND,
        );
        assert!(looks_like_cli_session_jwt(&cli));

        // Right aud, wrong token_kind → not the CliSession family.
        let wrong_kind = cli_session_shaped_jwt(
            hort_app::cli_session_signing::CLI_SESSION_AUDIENCE,
            "service_account",
        );
        assert!(!looks_like_cli_session_jwt(&wrong_kind));

        // CliSession token_kind but a different aud (e.g. an OCI token's
        // registry-host aud) → not the CliSession family.
        let wrong_aud = cli_session_shaped_jwt(
            "registry.example.com",
            hort_app::cli_session_signing::CLI_SESSION_TOKEN_KIND,
        );
        assert!(!looks_like_cli_session_jwt(&wrong_aud));

        // Non-JWT / non-CliSession shapes are not matched.
        assert!(!looks_like_cli_session_jwt("")); // empty
        assert!(!looks_like_cli_session_jwt("oidc-tok")); // opaque OIDC mock token
        assert!(!looks_like_cli_session_jwt("hort_pat_anything")); // PAT shape
        assert!(!looks_like_cli_session_jwt("a.b")); // too few segments
        assert!(!looks_like_cli_session_jwt("!!!.@@@.###")); // un-decodable payload

        // A well-formed JWT whose payload is valid JSON but lacks the
        // discriminator claims (an OIDC-shaped JWT) is not matched.
        let oidc_shaped = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let h = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
            let p = URL_SAFE_NO_PAD.encode(r#"{"iss":"https://kc.example.com","aud":"hort"}"#);
            let s = URL_SAFE_NO_PAD.encode([0u8; 8]);
            format!("{h}.{p}.{s}")
        };
        assert!(!looks_like_cli_session_jwt(&oidc_shaped));
    }
}
