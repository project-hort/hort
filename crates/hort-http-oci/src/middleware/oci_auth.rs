//! OCI bearer-token auth middleware (ADR 0012).
//!
//! Attached to the `/v2/*` subtree only — EXCEPT `/v2/auth`, which is
//! path-skipped at the top of [`oci_bearer_auth`]: the Distribution-Spec
//! token-exchange handler validates the inbound `Basic <PAT>` itself, so a
//! native PAT (or federated CI token) — which verifies as `NotOurToken`
//! against the OCI signing key — must not be intercepted here (under
//! `HORT_AUTH_PROVIDER=disabled` that interception `401`'d every credentialed
//! mint request before the handler ran). The global
//! `method_based_auth_dispatch` from `hort-http-core::router`
//! short-circuits on OCI paths and lets this middleware own auth
//! for the OCI surface.
//!
//! # Behaviour
//!
//! 1. **No `Authorization` header** → a *safe* method (GET/HEAD/OPTIONS)
//!    inserts `Option<CallerPrincipal>::None` into request extensions and
//!    forwards; reads on public repos succeed (anonymous-by-default,
//!    ADR 0021). A *non-safe* method (POST/PUT/PATCH/DELETE) is a write and
//!    always requires auth, so it is challenged here with the mode-aware
//!    `WWW-Authenticate` (Bearer + `/v2/auth` realm when the OCI signing
//!    key is wired, legacy `Basic realm="hort"` otherwise; `scope=` derived
//!    from the path via `path_to_scope`), so the client re-issues with the
//!    correct scheme. Under `AuthContext::Disabled` the write challenge is
//!    suppressed — its `/v2/auth` realm is unsatisfiable there — and the
//!    request forwards with a `None` principal exactly as before.
//!
//! 2. **`Authorization: Bearer <jwt>`** → verified FIRST against the OCI
//!    signing key (`verify_inbound`): a native hort-minted `/v2/auth` token
//!    is accepted; a structurally-ours-but-invalid one (expired / wrong
//!    `aud`) is a hard 401. A `NotOurToken` falls through to
//!    `AuthenticateUseCase::authenticate_bearer` whenever an auth context is
//!    wired — i.e. under BOTH `AuthContext::Enabled` and
//!    `AuthContext::BearerOnly` (`ctx.auth.authenticate()` is `Some` for
//!    each). That shared validator routes an IdP-shaped JWT to the OIDC
//!    JWKS path (Keycloak bearers keep working under `Enabled`) and a
//!    native `hort_pat_*` / `hort_svc_*` to the PAT validator, so a
//!    directly-presented native token authenticates on `/v2/*` reads under
//!    `BearerOnly` (`HORT_AUTH_PROVIDER=disabled` +
//!    `HORT_NATIVE_TOKENS_ENABLED=true` — the registry.hort.rs shape)
//!    exactly as it does under `Enabled`.
//!
//! 3. **`Authorization: Basic <b64(user:secret)>`** — the password is
//!    treated as the bearer token and runs the same two-stage verify as
//!    (2); legacy clients embed an IdP-issued JWT in the password slot
//!    (Docker Hub convention) and native-token clients embed a
//!    `hort_pat_*` / `hort_svc_*` there. NB this is the *consume* carrier —
//!    the native *mint* path is a `Basic <PAT>` to `/v2/auth` (Entry 7/8 of
//!    `docs/auth-catalog.md`), which this middleware path-skips (see above).
//!
//! 4. **`AuthContext::Disabled`** (no IdP AND no native-token validator
//!    wired — `HORT_AUTH_PROVIDER=disabled` + `HORT_NATIVE_TOKENS_ENABLED=false`,
//!    a combination the boot gate rejects in production):
//!    `ctx.auth.authenticate()` is `None`, so the (2)/(3) fall-through
//!    short-circuits to 401 — a presented token that is not a native OCI
//!    JWT is rejected, never silently elevated. A client can still mint at
//!    `/v2/auth` (Basic `<PAT>`, exempt from this middleware) and present
//!    the resulting hort-signed JWT, which `verify_inbound` accepts
//!    independently of the auth provider; anonymous reads on public repos
//!    also pass through. Contrast `BearerOnly` (item 2), where the same
//!    fall-through validates a directly-presented native token.
//!
//! hort DOES mint OCI tokens: `/v2/auth` issues a short-lived Ed25519 JWT
//! (Entry 7) that this middleware verifies on `/v2/*`. IdP bearers
//! (Keycloak) remain supported via the (2)/(3) fall-through, as do
//! directly-presented native `hort_pat_*` / `hort_svc_*` tokens under both
//! `Enabled` and `BearerOnly`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use hort_app::use_cases::oci_token_exchange_use_case::OciVerifyOutcome;
use hort_domain::entities::caller::CallerPrincipal;

use hort_http_core::context::{AppContext, AuthContext};
use hort_http_core::middleware::auth::{
    mint_authenticated_principal_for_format_middleware, AuthenticatedPrincipal,
};

use crate::error::OciError;
use crate::v2_auth::{path_to_scope, V2_AUTH_PATH};

/// Bearer middleware for `/v2/*`. See module-level docstring.
///
/// When `ctx.oci_signing_key` is
/// `Some(_)` (i.e. native tokens are enabled and the OCI signing key
/// is configured), the middleware behaviour changes in three ways:
/// 1. Unauthenticated `/v2/*` requests (other than the version probe)
///    receive a `WWW-Authenticate: Bearer realm=<…>/v2/auth,…`
///    challenge instead of the legacy `Basic` challenge.
/// 2. Inbound `Authorization: Bearer <jwt>` is verified against the
///    OCI signing key first; on success the principal is constructed
///    from the JWT's `sub` + `access[]` claims (the `access[]`
///    becomes a synthetic `TokenCap` so downstream
///    `RbacEvaluator::authorize` applies the cap leg correctly).
/// 3. Bearer JWTs that fail signing-key verification fall through to
///    the legacy IdP-JWT validator (existing behaviour) so Keycloak-
///    issued bearers continue to work alongside native tokens.
pub async fn oci_bearer_auth(
    State(ctx): State<Arc<AppContext>>,
    mut req: Request,
    next: Next,
) -> Response {
    // `/v2/auth` owns its OWN credential validation: the Distribution-Spec
    // token-exchange handler validates the inbound `Basic <PAT>` directly via
    // `OciTokenExchangeUseCase`. This consume-side bearer middleware must NOT
    // intercept it — a native PAT (and a federated CI token) verifies as
    // `NotOurToken` here, so without this skip it would fall through to the
    // native-token/IdP path below: under `AuthContext::Disabled` that hard-
    // rejects it (breaking the `Basic <PAT> → OCI JWT` exchange for every
    // credentialed request), and under `Enabled` / `BearerOnly` it would be
    // consumed as an already-authenticated PAT instead of being exchanged for
    // the short-lived OCI JWT the mint endpoint exists to issue — either way
    // the mint handler never runs. This is the skip the `/v2/auth` route
    // comment in `lib.rs` already promises. `path()` is query-stripped, so
    // `/v2/auth?service=…&scope=…` matches. The `None` principal slot is set to
    // honour this middleware's "always populate the `Option` slot" contract
    // (same shape as the anonymous-pass-through below).
    if req.uri().path() == V2_AUTH_PATH {
        req.extensions_mut()
            .insert::<Option<AuthenticatedPrincipal>>(None);
        return next.run(req).await;
    }

    // Resolve a token from `Authorization`. Bearer or Basic-as-JWT
    // both supply the same string; absent → anonymous pass-through.
    let token = extract_token(&req);
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let principal: Option<CallerPrincipal> = match token {
        None => {
            // Anonymous request (no credential presented). A non-safe
            // method (POST/PUT/PATCH/DELETE) is always a write and always
            // requires auth: challenge here with the same mode-aware
            // `WWW-Authenticate` the read-denial helper uses (Bearer +
            // `/v2/auth` realm when the OCI signing key is wired, legacy
            // `Basic realm="hort"` otherwise; `scope=` derived from the path
            // via `path_to_scope` — `push` for uploads/manifest-PUT,
            // `delete` for DELETE), so the client re-issues with the correct
            // scheme. Without this the request would fall through to the
            // shared authz extractor's hardcoded `Basic realm="hort"` 401
            // (`hort-http-core::authz::extractors`), which advertises the
            // wrong scheme in native-token mode. Safe methods
            // (GET/HEAD/OPTIONS) stay anonymous-by-default (ADR 0021): a
            // `None` principal forwards and public reads succeed.
            //
            // `AuthContext::Disabled` carve-out: the `/v2/auth` realm the
            // challenge advertises is unsatisfiable under Disabled — this
            // middleware hard-rejects any presented token (item 4 above) —
            // so emitting it would loop the client. Anonymous writes forward
            // with a `None` principal exactly as before (the shared authz
            // extractor answers the legacy `Basic` 401), and writes are
            // unreachable in production under Disabled anyway (boot gate).
            // Mirrors `read_denied_response`'s Disabled carve-out.
            if is_non_safe_method(&method) && !matches!(ctx.auth, AuthContext::Disabled) {
                return unauthorized_response(&ctx, &method, &path);
            }
            None
        }
        Some(token) => {
            // Single consume-side verify entrypoint. The middleware
            // maps the typed `OciVerifyOutcome` returned by
            // `OciTokenExchangeUseCase::verify_inbound` without ever
            // inspecting the raw verification error. The gate is
            // `ctx.oci_token_exchange` — it holds the signing key and
            // the single authoritative `aud`.
            let mut native_match: Option<CallerPrincipal> = None;
            if let Some(exchange) = ctx.oci_token_exchange.as_ref() {
                match exchange.verify_inbound(&token) {
                    OciVerifyOutcome::Verified(p) => {
                        native_match = Some(*p);
                    }
                    OciVerifyOutcome::NotOurToken => {
                        // Not an hort-server-OCI-minted JWT; fall through
                        // to the legacy IdP path (Basic-as-IdP-JWT and
                        // Keycloak bearers keep working).
                    }
                    OciVerifyOutcome::Rejected(_) => {
                        // Structurally-ours token that is invalid
                        // (expired / wrong aud). HARD reject — must NOT
                        // fall through. (The audit `info!` with the
                        // reason is emitted at the `hort-app` verify
                        // site, per the one-metric-one-layer rule.)
                        return unauthorized_response(&ctx, &method, &path);
                    }
                }
            }

            if let Some(p) = native_match {
                Some(p)
            } else {
                // Native-token / IdP validation path. `authenticate()`
                // returns the shared `AuthenticateUseCase` for BOTH
                // authenticated modes (`Enabled` and `BearerOnly`), so a
                // directly-presented native `hort_pat_*` / `hort_svc_*` — a
                // `NotOurToken` against the OCI signing key — reaches the PAT
                // branch of `authenticate_bearer` under `BearerOnly`
                // (`HORT_AUTH_PROVIDER=disabled` +
                // `HORT_NATIVE_TOKENS_ENABLED=true`) exactly as under
                // `Enabled`. `None` only under `Disabled` (no IdP, native
                // tokens off): there a presented token is rejected, never
                // silently elevated.
                let Some(authenticate) = ctx.auth.authenticate() else {
                    tracing::info!(
                        result = "auth_disabled_token_rejected",
                        "oci_bearer_auth: token presented while auth is disabled"
                    );
                    return unauthorized_response(&ctx, &method, &path);
                };
                match authenticate.authenticate_bearer(&token).await {
                    Ok(p) => Some(p),
                    Err(err) => {
                        tracing::info!(
                            result = "invalid_token",
                            error = %err,
                            "oci_bearer_auth: token validation failed"
                        );
                        return unauthorized_response(&ctx, &method, &path);
                    }
                }
            }
        }
    };

    // Write the `AuthenticatedPrincipal` newtype, not a bare
    // `CallerPrincipal`. The named mint helper is the load-bearing
    // auth checkpoint: this is the per-format bearer middleware's seam
    // into the auth-typed extension slot. A future format crate adding
    // its own bearer middleware MUST reuse the same seam — `git grep
    // mint_authenticated_principal_for_format_middleware` is the
    // complete production audit list.
    if let Some(p) = principal {
        let authed = mint_authenticated_principal_for_format_middleware(p);
        req.extensions_mut().insert(authed.clone());
        req.extensions_mut()
            .insert::<Option<AuthenticatedPrincipal>>(Some(authed));
    } else {
        req.extensions_mut()
            .insert::<Option<AuthenticatedPrincipal>>(None);
    }
    next.run(req).await
}

/// Whether an HTTP method is "non-safe" (a write) per RFC 7231 §4.2.1 —
/// exactly `POST` / `PUT` / `PATCH` / `DELETE`. `GET` / `HEAD` / `OPTIONS`
/// are safe and stay anonymous-by-default on `/v2/*` (ADR 0021). Drives the
/// anonymous-write challenge in [`oci_bearer_auth`]: a credential-less
/// non-safe `/v2/*` request is challenged; a safe one is forwarded.
fn is_non_safe_method(method: &axum::http::Method) -> bool {
    use axum::http::Method;
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Pull a token out of `Authorization`. Accepts:
/// - `Bearer <jwt>` — native flow.
/// - `Basic <b64(user:jwt)>` — legacy clients (twine, docker pre-
///   OCI-spec, skopeo with `--dest-creds USER:JWT`) embed the
///   IdP-issued JWT in the password field. Username is informational;
///   the JWT carries the `sub` claim.
///
/// Returns `None` for missing / malformed / non-Bearer-non-Basic
/// headers — every absence mode collapses to "no token".
fn extract_token(req: &Request<Body>) -> Option<String> {
    use base64::Engine as _;

    let header_val = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(rest) = header_val.strip_prefix("Bearer ") {
        let token = rest.trim();
        if token.is_empty() {
            return None;
        }
        return Some(token.to_string());
    }
    if let Some(encoded) = header_val.strip_prefix("Basic ") {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (_username, password) = decoded.split_once(':')?;
        let password = password.trim();
        if password.is_empty() {
            return None;
        }
        return Some(password.to_string());
    }
    None
}

/// 401 with `WWW-Authenticate: Basic` — the challenge OCI clients
/// (skopeo, docker, podman) react to by sending `Authorization: Basic
/// <b64(user:jwt)>` preemptively on subsequent requests. Pairs with
/// `extract_token`'s Basic-as-JWT path: clients pre-fetch an IdP
/// token and present it in the password slot.
///
/// Carries `Docker-Distribution-API-Version: registry/2.0` for parity
/// with the Bearer branch and the `GET /v2/` probe — every `/v2/*`
/// response advertises the spec API version, the legacy-Basic challenge
/// included.
fn unauthorized_basic_response() -> Response {
    let mut response = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, r#"Basic realm="hort""#)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#,
        ))
        .expect("static unauthorized response builds");
    response.headers_mut().insert(
        "Docker-Distribution-API-Version",
        axum::http::HeaderValue::from_static("registry/2.0"),
    );
    response
}

/// Challenge selector. Picks Bearer when the OCI signing key is wired
/// (native-tokens-on path), Basic otherwise (legacy behaviour
/// preserved). The version probe `GET /v2/` is anonymous — callers
/// should NOT be reaching this helper for it; the routing layer answers
/// 200 directly.
///
/// `pub(crate)` so the shared [`read_denied_response`] read-denial
/// helper reuses the exact same mode-aware challenge as the middleware.
pub(crate) fn unauthorized_response(
    ctx: &AppContext,
    method: &axum::http::Method,
    path: &str,
) -> Response {
    if ctx.oci_signing_key.is_none() {
        return unauthorized_basic_response();
    }
    let scope = path_to_scope(method, path);
    let challenge = v2_auth_challenge_value(
        ctx.oci_public_base_url.as_deref(),
        ctx.oci_public_base_url.as_deref().map(host_of),
        scope.as_deref(),
    );
    let mut response = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#,
        ))
        .expect("static unauthorized response builds");
    if let Ok(value) = axum::http::HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response.headers_mut().insert(
        "Docker-Distribution-API-Version",
        axum::http::HeaderValue::from_static("registry/2.0"),
    );
    response
}

/// Shared repo-level read-denial representation (D1/D2, ADR 0021).
///
/// The use-case layer collapses "missing repo" and "invisible private
/// repo" into a single `DomainError::NotFound` (ADR 0021's single-gate
/// shape); this helper — invoked at every repo-level read-denial site —
/// picks the HTTP representation from `actor`:
///
/// - **Anonymous** (`actor.is_none()` — the credential was never
///   solicited): 401 with the mode-aware `WWW-Authenticate` challenge
///   (Bearer + `/v2/auth` realm when `ctx.oci_signing_key` is wired,
///   legacy `Basic realm="hort"` otherwise), so a challenge-based
///   client presents its credential and retries. `actor == None` ⇔ no
///   credential presented, because an *invalid* credential already 401s
///   at the middleware.
/// - **Authenticated**: the existing `NAME_UNKNOWN` 404 anti-enumeration
///   envelope.
///
/// **`AuthContext::Disabled` carve-out.** In the open-registry / no-auth
/// mode the anonymous 401+challenge is suppressed and *every* denial —
/// anonymous or not — returns the `NAME_UNKNOWN` 404. The challenge
/// points clients at `/v2/auth`, but under Disabled this middleware
/// hard-rejects any presented token, so the challenge can never be
/// satisfied — advertising it would loop the client forever. Disabled
/// mode also admits every read at `RbacAccess`, so the only denial that
/// can reach this helper is a genuinely-absent repo, which the 404 already
/// represents. This mirrors the `GET /v2/` probe's Disabled short-circuit
/// (`version.rs`) and is why the read-path challenge is a production-mode
/// (`Enabled` / `BearerOnly`) fix only — Disabled behaviour is unchanged.
///
/// Anti-enumeration equivalence (ADR 0021) is preserved: anonymous
/// `{nonexistent, private-existing}` now map to one uniform
/// 401+challenge (byte-identical modulo the `scope=` echo of the
/// caller's own request path), authenticated `{nonexistent,
/// private-existing}` keep mapping to one uniform 404 — the partition of
/// observable outcomes is unchanged.
///
/// Pure response construction: emits **no** metric. A denial site that
/// tracks a counter keeps that emission at the call site, before
/// invoking this helper.
pub(crate) fn read_denied_response(
    ctx: &AppContext,
    actor: Option<&CallerPrincipal>,
    method: &axum::http::Method,
    path: &str,
    repo_key: &str,
) -> Response {
    tracing::debug!(
        repo_key,
        anonymous = actor.is_none(),
        "OCI repo-level read denied"
    );
    let name_unknown = || {
        OciError::NameUnknown {
            repository: repo_key.to_string(),
        }
        .into_response()
    };
    // Disabled-mode carve-out (see the doc comment): an unsatisfiable
    // `/v2/auth` challenge must never be emitted here, so collapse straight
    // to the 404 anti-enum envelope regardless of `actor`.
    if matches!(ctx.auth, AuthContext::Disabled) {
        return name_unknown();
    }
    match actor {
        None => unauthorized_response(ctx, method, path),
        Some(_) => name_unknown(),
    }
}

/// Build the value of the `WWW-Authenticate: Bearer …` header per
/// Distribution Spec. `realm` is computed from `public_base_url`
/// (falling back to a relative path), `service` is the registry host
/// (matches the `service=` query param the client must echo),
/// `scope` is the path-derived hint.
///
/// Public so the `/v2/auth` handler can re-emit the same challenge
/// on its own 401 responses.
pub fn v2_auth_challenge_value(
    public_base_url: Option<&str>,
    service: Option<impl AsRef<str>>,
    scope: Option<&str>,
) -> String {
    let realm = match public_base_url {
        Some(base) => {
            let trimmed = base.trim_end_matches('/');
            format!("{trimmed}/v2/auth")
        }
        None => "/v2/auth".to_string(),
    };
    let mut buf = format!(r#"Bearer realm="{realm}""#);
    if let Some(s) = service {
        buf.push_str(&format!(r#",service="{}""#, s.as_ref()));
    }
    if let Some(sc) = scope {
        buf.push_str(&format!(r#",scope="{sc}""#));
    }
    buf
}

/// Extract just the host portion of a URL string. Used for the
/// `service=` parameter: per spec the `aud` claim and the `service=`
/// echo are the registry hostname (no scheme, no path). `pub(crate)`
/// so the `GET /v2/` version probe builds the same `service=` value
/// for its challenge.
pub(crate) fn host_of(url: &str) -> &str {
    // Strip scheme.
    let after_scheme = match url.find("://") {
        Some(pos) => &url[pos + 3..],
        None => url,
    };
    // Strip path.
    match after_scheme.find('/') {
        Some(pos) => &after_scheme[..pos],
        None => after_scheme,
    }
}

// `synthesize_principal_from_jwt` is co-located with the verifier in
// `hort_app::use_cases::oci_token_exchange_use_case` behind
// `verify_inbound`. The inbound crate no longer constructs the principal
// nor inspects `VerificationError`.

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use axum::middleware::from_fn_with_state;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use serde_json::json;
    use tower::ServiceExt;

    use std::time::Duration;

    use hort_app::argon2_hash::Argon2Verifier;
    use hort_app::oci_token_signing::OciTokenSigningKey;
    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::oci_token_exchange_use_case::{
        OciTokenExchangeConfig, OciTokenExchangeUseCase,
    };
    use hort_app::use_cases::pat_cache::{PatCache, SystemClock};
    use hort_app::use_cases::pat_validation_use_case::{PatLockoutConfig, PatValidationUseCase};
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::api_token::{ApiToken, TokenKind};
    use hort_domain::entities::rbac::Permission;
    use hort_domain::entities::user::{AuthProvider, User};
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::api_token_repository::ApiTokenRepository;
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::identity_provider::{IdentityProvider, IdpClaims};
    use hort_domain::ports::repository_repository::RepositoryRepository;
    use hort_domain::ports::user_repository::UserRepository;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::{Page, PageRequest};

    use hort_http_core::test_support::{
        build_mock_ctx, with_auth, with_oci_signing_key, with_oci_token_exchange,
    };

    fn run<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Echo-style terminal handler: reports whether the request reached it
    /// with an `AuthenticatedPrincipal` extension. The bare `CallerPrincipal`
    /// slot is not populated; the middleware writes the newtype.
    async fn echo_principal_handler(req: Request) -> Response {
        let principal = req
            .extensions()
            .get::<AuthenticatedPrincipal>()
            .map(|p| p.as_caller().clone());
        let body = match principal {
            Some(p) => json!({
                "authenticated": true,
                "username": p.username,
                // The principal's resolved authority is the additive
                // `claims` set (ADR 0012). `token_kind` + `token_cap` are
                // echoed so the bespoke OCI / native-token principal shape
                // stays observable in these middleware tests — the B1 cap
                // backstop / grants∩cap AND is evaluated downstream, so
                // these tests only prove the shape survives to the handler.
                "claims": p.claims,
                "token_kind": format!("{:?}", p.token_kind),
                "token_cap": format!("{:?}", p.token_cap),
            }),
            None => json!({"authenticated": false}),
        };
        (StatusCode::OK, axum::Json(body)).into_response()
    }

    fn build_test_router(ctx: &Arc<AppContext>) -> Router {
        Router::new()
            .route("/v2/probe", get(echo_principal_handler))
            .layer(from_fn_with_state(ctx.clone(), oci_bearer_auth))
            .with_state(ctx.clone())
    }

    /// Wire BOTH the OCI signing key AND a real `OciTokenExchangeUseCase`
    /// (carrying the same key + a config `jwt_audience`) onto the ctx.
    /// The consume-side verify path gates on `ctx.oci_token_exchange`
    /// (it holds the key and the authoritative `aud`), so tests that
    /// exercise inbound-JWT verification must wire it. The
    /// verify path never touches PAT/RBAC, but the constructor needs
    /// collaborators; mock handles from `build_mock_ctx` suffice.
    fn with_native_oci_tokens(
        ctx: &Arc<AppContext>,
        mocks: &hort_http_core::test_support::MockPorts,
        signing_key: Arc<OciTokenSigningKey>,
        jwt_audience: &str,
    ) -> Arc<AppContext> {
        let users: Arc<dyn UserRepository> = mocks.users.clone();
        let tokens: Arc<dyn ApiTokenRepository> = mocks.api_tokens.clone();
        let ephemeral: Arc<dyn EphemeralStore> = mocks.ephemeral_durable.clone();
        let pat_cache = Arc::new(PatCache::new(8, Duration::from_secs(60)));
        let pat_validation = Arc::new(PatValidationUseCase::new(
            tokens,
            users.clone(),
            ephemeral,
            pat_cache,
            Arc::new(SystemClock),
            PatLockoutConfig::DEFAULT,
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let repo_access = Arc::new(
            hort_app::use_cases::repository_access::RepositoryAccessUseCase::new(
                mocks.repositories.clone() as Arc<dyn RepositoryRepository>,
                hort_app::use_cases::repository_access::RbacAccess::Enabled(rbac.clone()),
                true,
            ),
        );
        let cfg = OciTokenExchangeConfig::new(
            "https://hort.example.com/v2/auth".to_string(),
            jwt_audience.to_string(),
        );
        let exchange = Arc::new(OciTokenExchangeUseCase::new(
            pat_validation,
            users,
            rbac,
            repo_access,
            signing_key.clone(),
            cfg,
        ));
        let ctx = with_oci_signing_key(ctx, Some(signing_key));
        with_oci_token_exchange(&ctx, Some(exchange))
    }

    /// Build an enabled-auth ctx whose IdP recognises one fixture
    /// JWT (`"valid-jwt"`) for a synthetic `dev-user`.
    fn enabled_auth_ctx_with_token(token: &str) -> Arc<AppContext> {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);

        let idp = Arc::new(MockIdentityProvider::new());
        idp.register_token(
            token,
            IdpClaims {
                subject: "dev-user-sub".into(),
                username: "dev-user".into(),
                email: "dev@example.com".into(),
                groups: vec!["test-developers".into()],
                issued_at: Utc::now(),
            },
        );

        let auth = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        with_auth(
            &ctx,
            AuthContext::Enabled {
                authenticate: auth,
                rbac,
                // Tests in this module do not exercise the WWW-Authenticate
                // challenge selector; see `bearer_challenge_selector` tests below.
                issuer_url: None,
            },
        )
    }

    /// Empty-IdP variant — every token rejects.
    fn enabled_auth_ctx_no_tokens() -> Arc<AppContext> {
        enabled_auth_ctx_no_tokens_with_mocks().0
    }

    /// `enabled_auth_ctx_no_tokens` but also returns the `MockPorts`
    /// handles — needed post-R2 to wire a real `OciTokenExchangeUseCase`
    /// (the consume-side verify path gates on `ctx.oci_token_exchange`).
    fn enabled_auth_ctx_no_tokens_with_mocks(
    ) -> (Arc<AppContext>, hort_http_core::test_support::MockPorts) {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);
        let idp = Arc::new(MockIdentityProvider::new());
        let auth = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &ctx,
            AuthContext::Enabled {
                authenticate: auth,
                rbac,
                // Tests in this module do not exercise the WWW-Authenticate
                // challenge selector; see `bearer_challenge_selector` tests below.
                issuer_url: None,
            },
        );
        (ctx, mocks)
    }

    // A valid 39-byte native token body (`hort_<kind>_` + 32 lower-case
    // base32 chars). Reused across the `BearerOnly` parity tests so the
    // stub token repo's planted row is reached by the constant `aaaaaaaa`
    // body prefix.
    const VALID_PAT: &str = "hort_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALID_SVC: &str = "hort_svc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// Stub [`Argon2Verifier`] returning a fixed verdict, so a native
    /// `hort_pat_*` / `hort_svc_*` test token validates (or fails) without
    /// computing a real Argon2 hash. Mirrors the `StubVerifier` in
    /// `hort_app::use_cases::authenticate_use_case`'s PAT tests.
    struct StubVerifier(bool);
    impl Argon2Verifier for StubVerifier {
        fn verify(&self, _plaintext: &[u8], _hash: &str) -> bool {
            self.0
        }
    }

    /// Stub [`ApiTokenRepository`] whose `find_by_prefix` returns one
    /// planted token — the native-PAT validate path's hot lookup (the
    /// shared `MockApiTokenRepository` always returns `None` there). The
    /// other methods carry only enough behaviour to satisfy the trait.
    struct StubTokenRepo {
        token: ApiToken,
    }
    impl ApiTokenRepository for StubTokenRepo {
        fn insert(&self, _t: &ApiToken) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_prefix(&self, _prefix: &str) -> BoxFuture<'_, DomainResult<Option<ApiToken>>> {
            let t = self.token.clone();
            Box::pin(async move { Ok(Some(t)) })
        }
        fn find_by_id(&self, id: uuid::Uuid) -> BoxFuture<'_, DomainResult<ApiToken>> {
            Box::pin(async move {
                Err(DomainError::NotFound {
                    entity: "ApiToken",
                    id: id.to_string(),
                })
            })
        }
        fn list_for_user(
            &self,
            _user_id: uuid::Uuid,
            _page: PageRequest,
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
            _token_id: uuid::Uuid,
            _at: chrono::DateTime<Utc>,
            _ip: Option<&str>,
            _ua: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn revoke(&self, _token_id: uuid::Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Build a `BearerOnly` ctx (`HORT_AUTH_PROVIDER=disabled` +
    /// `HORT_NATIVE_TOKENS_ENABLED=true` — the registry.hort.rs shape)
    /// whose `AuthenticateUseCase` routes native `hort_pat_*` / `hort_svc_*`
    /// tokens to a `PatValidationUseCase` backed by a single planted token
    /// (`kind`) + a stub verifier (`verify_ok`). The backing user is active
    /// and seeded on the shared user repo, so the PAT success path resolves
    /// a live principal carrying `token_kind: Some(kind)` and
    /// `token_cap: Some(..)`.
    fn bearer_only_ctx_with_pat(kind: TokenKind, verify_ok: bool) -> Arc<AppContext> {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);

        let user_id = uuid::Uuid::new_v4();
        mocks.users.insert(User {
            id: user_id,
            username: "sa:ci-reader".into(),
            email: "ci@example.com".into(),
            auth_provider: AuthProvider::Oidc,
            external_id: Some("k:ci".into()),
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: matches!(kind, TokenKind::ServiceAccount),
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let token = ApiToken {
            id: uuid::Uuid::new_v4(),
            user_id,
            name: "ci".into(),
            description: None,
            kind,
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel".into(),
            token_prefix: "aaaaaaaa".into(),
            declared_permissions: vec![Permission::Read],
            repository_ids: None,
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: user_id,
            created_at: Utc::now(),
        };

        let pat_cache = Arc::new(PatCache::new(8, Duration::from_secs(60)));
        let pat_validation = Arc::new(PatValidationUseCase::new_with_verifier(
            Arc::new(StubTokenRepo { token }) as Arc<dyn ApiTokenRepository>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            mocks.ephemeral_durable.clone() as Arc<dyn EphemeralStore>,
            pat_cache,
            Arc::new(StubVerifier(verify_ok)) as Arc<dyn Argon2Verifier>,
            Arc::new(SystemClock),
            PatLockoutConfig::DEFAULT,
        ));

        let idp = Arc::new(MockIdentityProvider::new());
        let auth = Arc::new(
            AuthenticateUseCase::new(
                idp as Arc<dyn IdentityProvider>,
                mocks.users.clone() as Arc<dyn UserRepository>,
                Vec::new(),
            )
            .with_pat_validation(pat_validation),
        );
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        with_auth(
            &ctx,
            AuthContext::BearerOnly {
                authenticate: auth,
                rbac,
            },
        )
    }

    // -------------------- 1. Anonymous (no header) -----------------------

    #[test]
    fn no_authorization_header_passes_through_anonymous_under_enabled_auth() {
        let parsed = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(HttpRequest::get("/v2/probe").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(parsed["authenticated"], false);
    }

    /// Under `AuthContext::Disabled` the OCI middleware MUST NOT synthesise
    /// an admin principal. An anonymous request receives the same
    /// `Option<CallerPrincipal>::None` sentinel as under `Enabled`-no-header,
    /// so downstream extractors fail closed with 401.
    #[test]
    fn disabled_auth_anonymous_request_inserts_no_principal() {
        let parsed = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(HttpRequest::get("/v2/probe").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(
            parsed["authenticated"], false,
            "Disabled mode must not synthesise a principal"
        );
    }

    /// Under `Disabled` the middleware cannot validate a presented bearer
    /// (no IdP wired), so the request fails closed with 401 + Basic challenge
    /// instead of being silently elevated to admin.
    #[test]
    fn disabled_auth_bearer_header_returns_401() {
        let (status, www) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, "Bearer some-jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            (status, www)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let www = www.expect("WWW-Authenticate present");
        assert!(www.starts_with("Basic"), "expected Basic challenge: {www}");
    }

    /// REGRESSION — the `/v2/auth` middleware-skip bug. The `oci_bearer_auth`
    /// `route_layer` wraps `/v2/auth` (lib.rs), but that endpoint owns its OWN
    /// credential validation (`Basic <PAT>` → `OciTokenExchangeUseCase`). A
    /// `Basic <PAT>` verifies as `NotOurToken` here and — under
    /// `AuthContext::Disabled` — was rejected at the `auth_disabled_token_rejected`
    /// guard BEFORE the handler, breaking the entire `Basic <PAT> → OCI JWT`
    /// exchange (native PAT *and* the federated CI token). The path-skip lets
    /// the request reach the handler. Contrast `disabled_auth_bearer_header_returns_401`:
    /// the SAME credential on a non-`/v2/auth` path still 401s at the middleware.
    #[test]
    fn v2_auth_basic_credential_skips_middleware_and_reaches_handler() {
        use base64::Engine as _;
        let parsed = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle); // AuthContext::Disabled
            let router = Router::new()
                .route("/v2/auth", get(echo_principal_handler))
                .layer(from_fn_with_state(ctx.clone(), oci_bearer_auth))
                .with_state(ctx.clone());
            // A native PAT carried as the Basic password — exactly what
            // `docker login` / `mvn deploy` send. Pre-fix this 401'd at the
            // middleware (NotOurToken under Disabled) before the handler ran.
            let creds = base64::engine::general_purpose::STANDARD.encode("x:hort_pat_deadbeef");
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/auth?service=hort.test&scope=repository:foo:pull")
                        .header(header::AUTHORIZATION, format!("Basic {creds}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "Basic-PAT GET /v2/auth must reach the handler, NOT the middleware's 401"
            );
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        // The skip injects the `None` principal slot and does NOT synthesise a
        // principal from the Basic-PAT — the handler owns that validation.
        assert_eq!(
            parsed["authenticated"], false,
            "the skip must not validate the PAT here (handler owns /v2/auth auth)"
        );
    }

    // -------------------- 2. Bearer with valid token --------------------

    #[test]
    fn valid_bearer_token_inserts_principal() {
        let parsed = run(async {
            let ctx = enabled_auth_ctx_with_token("valid-jwt");
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, "Bearer valid-jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(parsed["authenticated"], true);
        assert_eq!(parsed["username"], "dev-user");
    }

    // -------------------- 3. Basic-as-JWT fallback ---------------------

    /// `Authorization: Basic <b64(user:jwt)>` validates the same way
    /// as a Bearer of `<jwt>`. Legacy-client compatibility.
    #[test]
    fn basic_authorization_password_as_jwt_validates() {
        let parsed = run(async {
            let ctx = enabled_auth_ctx_with_token("valid-jwt");
            use base64::Engine as _;
            let creds = base64::engine::general_purpose::STANDARD.encode("alice:valid-jwt");
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, format!("Basic {creds}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(parsed["authenticated"], true);
    }

    // -------------------- 4. Invalid bearer ----------------------------

    #[test]
    fn invalid_bearer_returns_401_with_basic_challenge() {
        let (status, www) = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, "Bearer not-a-jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            (status, www)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let www = www.expect("WWW-Authenticate present");
        assert!(www.starts_with("Basic"), "expected Basic challenge: {www}");
    }

    /// Malformed Basic header (invalid base64) collapses to "no
    /// token" → anonymous, NOT 401. Skopeo / docker emit weird
    /// Authorization headers on probe requests; treating those as
    /// anonymous keeps the read path public on public repos.
    #[test]
    fn malformed_basic_header_treated_as_anonymous() {
        let parsed = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, "Basic !!!not-base64!!!")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(parsed["authenticated"], false);
    }

    // -------------------- 5. extract_token -----------------------------

    #[test]
    fn extract_token_handles_bearer_basic_and_absent() {
        use base64::Engine as _;

        let bearer = HttpRequest::get("/v2/probe")
            .header(header::AUTHORIZATION, "Bearer  abc.def.ghi  ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_token(&bearer).as_deref(), Some("abc.def.ghi"));

        let creds = base64::engine::general_purpose::STANDARD.encode("alice:eyJjbGFpbXMK");
        let basic = HttpRequest::get("/v2/probe")
            .header(header::AUTHORIZATION, format!("Basic {creds}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_token(&basic).as_deref(), Some("eyJjbGFpbXMK"));

        let empty_pw = base64::engine::general_purpose::STANDARD.encode("alice:");
        let basic_empty = HttpRequest::get("/v2/probe")
            .header(header::AUTHORIZATION, format!("Basic {empty_pw}"))
            .body(Body::empty())
            .unwrap();
        assert!(extract_token(&basic_empty).is_none());

        let absent = HttpRequest::get("/v2/probe").body(Body::empty()).unwrap();
        assert!(extract_token(&absent).is_none());
    }

    // -------------------- Bearer challenge selector ----------

    #[test]
    fn host_of_strips_scheme_and_path() {
        assert_eq!(host_of("https://hort.example.com/api"), "hort.example.com");
        assert_eq!(host_of("http://hort.example.com"), "hort.example.com");
        assert_eq!(host_of("hort.example.com"), "hort.example.com");
        assert_eq!(
            host_of("https://hort.example.com/v2/auth"),
            "hort.example.com"
        );
    }

    #[test]
    fn v2_auth_challenge_value_full_form() {
        let challenge = v2_auth_challenge_value(
            Some("https://hort.example.com"),
            Some("hort.example.com"),
            Some("repository:foo:pull"),
        );
        assert!(challenge.starts_with("Bearer "));
        assert!(challenge.contains(r#"realm="https://hort.example.com/v2/auth""#));
        assert!(challenge.contains(r#"service="hort.example.com""#));
        assert!(challenge.contains(r#"scope="repository:foo:pull""#));
    }

    #[test]
    fn v2_auth_challenge_value_no_public_url_uses_relative_realm() {
        let challenge = v2_auth_challenge_value(None, Some("hort.example.com"), None);
        assert!(challenge.contains(r#"realm="/v2/auth""#));
        assert!(challenge.contains(r#"service="hort.example.com""#));
        assert!(!challenge.contains("scope="));
    }

    #[test]
    fn v2_auth_challenge_value_strips_trailing_slash_on_base() {
        let challenge = v2_auth_challenge_value(
            Some("https://hort.example.com/"),
            Some("hort.example.com"),
            None,
        );
        // Single slash, not double.
        assert!(challenge.contains("https://hort.example.com/v2/auth"));
        assert!(!challenge.contains("//v2/auth"));
    }

    // The `synthesize_principal_from_jwt_*` unit tests moved to
    // `hort_app::use_cases::oci_token_exchange_use_case` with the function.
    // Principal-shape behaviour is exercised there + via the
    // `inbound_oci_jwt_validates_via_signing_key` test below (which proves
    // the moved synthesis still produces the byte-identical `oci-jwt:<sub>`
    // principal through the `verify_inbound` seam).

    /// Native tokens ON + unauthenticated `/v2/*` request →
    /// `WWW-Authenticate: Bearer realm=…/v2/auth,…`.
    #[test]
    fn unauthenticated_v2_request_returns_bearer_challenge_when_native_tokens_on() {
        use hort_http_core::test_support::{with_oci_public_base_url, with_oci_signing_key};
        let (status, www) = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            // Wire a fresh OCI signing key — the presence of the slot
            // is what flips the challenge path to Bearer.
            let sk = OciTokenSigningKey::new(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            );
            let ctx = with_oci_signing_key(&ctx, Some(Arc::new(sk)));
            let ctx = with_oci_public_base_url(&ctx, Some("https://hort.example.com".to_string()));
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, "Bearer not-a-jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            (status, www)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let www = www.expect("WWW-Authenticate present");
        assert!(
            www.starts_with("Bearer"),
            "expected Bearer challenge: {www}"
        );
        assert!(www.contains("https://hort.example.com/v2/auth"));
    }

    /// Native tokens OFF (no signing key wired) → legacy Basic challenge
    /// preserved.
    #[test]
    fn unauthenticated_v2_request_returns_basic_challenge_when_native_tokens_off() {
        let (status, www) = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, "Bearer not-a-jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            (status, www)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let www = www.expect("WWW-Authenticate present");
        assert!(www.starts_with("Basic"), "expected Basic challenge: {www}");
    }

    /// Inbound JWT signed by the OCI signing key validates via the `hort-app`
    /// `verify_inbound` seam and produces the byte-identical synthetic
    /// `oci-jwt:<sub>` principal. Proves the moved
    /// `synthesize_principal_from_jwt` is behaviour-preserving through the
    /// typed `OciVerifyOutcome::Verified` mapping.
    #[test]
    fn inbound_oci_jwt_validates_via_signing_key() {
        use hort_app::oci_token_signing::{AccessEntry, OciAccessClaims};
        use hort_http_core::test_support::with_oci_public_base_url;
        let parsed = run(async {
            let (ctx, mocks) = enabled_auth_ctx_no_tokens_with_mocks();
            let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let signing = OciTokenSigningKey::new(sk, None);

            // Mint a token outside the test, then exercise the verify
            // path through the middleware → `verify_inbound`.
            let claims = OciAccessClaims {
                iss: "https://hort.example.com/v2/auth".into(),
                sub: uuid::Uuid::from_u128(0xC0FFEE),
                aud: "hort.example.com".into(),
                exp: Utc::now() + chrono::Duration::seconds(300),
                access: vec![AccessEntry {
                    resource_type: "repository".into(),
                    name: "foo/bar".into(),
                    actions: vec!["pull".into()],
                }],
            };
            let jwt = signing.mint(&claims).expect("mint");

            // Post-R2 the consume path gates on `ctx.oci_token_exchange`
            // (D4) whose config `jwt_audience` is the authoritative
            // verify `aud` (D3) — wire both with the same key.
            let ctx = with_native_oci_tokens(&ctx, &mocks, Arc::new(signing), "hort.example.com");
            let ctx = with_oci_public_base_url(&ctx, Some("https://hort.example.com".to_string()));
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(parsed["authenticated"], true);
        // username uses the synthetic shape per the moved
        // `synthesize_principal_from_jwt` (now in `hort-app`, behind
        // `verify_inbound` → `OciVerifyOutcome::Verified`).
        assert_eq!(
            parsed["username"],
            format!("oci-jwt:{}", uuid::Uuid::from_u128(0xC0FFEE))
        );
    }

    /// Tampered JWT (signature fails to verify against active OR previous key)
    /// maps to `OciVerifyOutcome::NotOurToken`, falls through to the legacy
    /// IdP path which has no JWKS for the fake → 401.
    #[test]
    fn inbound_oci_jwt_with_tampered_signature_rejected() {
        let status = run(async {
            let (ctx, mocks) = enabled_auth_ctx_no_tokens_with_mocks();
            // Active key: SK_A. JWT will be signed by SK_B (attacker).
            let active = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let attacker = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let active_signing = Arc::new(OciTokenSigningKey::new(active, None));
            let attacker_signing = OciTokenSigningKey::new(attacker, None);
            let claims = hort_app::oci_token_signing::OciAccessClaims {
                iss: "issuer".into(),
                sub: uuid::Uuid::new_v4(),
                aud: "hort.example.com".into(),
                exp: Utc::now() + chrono::Duration::seconds(300),
                access: vec![],
            };
            let jwt = attacker_signing.mint(&claims).expect("mint");
            let ctx = with_native_oci_tokens(&ctx, &mocks, active_signing, "hort.example.com");
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            resp.status()
        });
        // Falls through to the legacy IdP path which has no JWKS for
        // this fake; still 401.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // -------------------- 6. BearerOnly native-token parity (D3) ---------

    /// `BearerOnly` + a valid native `hort_pat_*` → the PAT branch of
    /// `authenticate_bearer` mints an authenticated principal that reaches
    /// the handler. Pre-D3 the too-narrow `AuthContext::Enabled` guard 401'd
    /// this at the middleware under `BearerOnly`; the widened
    /// `ctx.auth.authenticate()` accessor covers BOTH authenticated modes,
    /// so a directly-presented native token now validates on `/v2/*` reads
    /// exactly as under `Enabled`.
    #[test]
    fn bearer_only_valid_pat_mints_principal() {
        let parsed = run(async {
            let ctx = bearer_only_ctx_with_pat(TokenKind::Pat, true);
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, format!("Bearer {VALID_PAT}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(parsed["authenticated"], true);
        assert_eq!(parsed["username"], "sa:ci-reader");
        // The native-token principal shape (typed `token_kind` + `token_cap`)
        // survives the `mint_authenticated_principal_for_format_middleware`
        // seam to the handler; the B1 cap backstop / grants∩cap AND is
        // downstream.
        assert_eq!(parsed["token_kind"], "Some(Pat)");
        let cap = parsed["token_cap"].as_str().expect("token_cap echoed");
        assert!(
            cap.starts_with("Some(TokenCap"),
            "token_cap should be Some: {cap}"
        );
        assert!(
            cap.contains("Read"),
            "cap should carry the declared Read: {cap}"
        );
    }

    /// `BearerOnly` + a valid native `hort_svc_*` → principal minted with
    /// the typed `token_kind: Some(ServiceAccount)` — the registry.hort.rs
    /// CI credential shape. Same parity as the PAT case.
    #[test]
    fn bearer_only_valid_svc_token_mints_service_account_principal() {
        let parsed = run(async {
            let ctx = bearer_only_ctx_with_pat(TokenKind::ServiceAccount, true);
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, format!("Bearer {VALID_SVC}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(parsed["authenticated"], true);
        assert_eq!(parsed["token_kind"], "Some(ServiceAccount)");
        let cap = parsed["token_cap"].as_str().expect("token_cap echoed");
        assert!(cap.starts_with("Some(TokenCap"), "{cap}");
    }

    /// `BearerOnly` + an invalid native token (PAT-shaped, but the Argon2
    /// verify fails → hash mismatch) → 401 at the middleware. Proves the
    /// widened fall-through still REJECTS a bad credential rather than
    /// passing it through anonymously.
    #[test]
    fn bearer_only_invalid_pat_returns_401() {
        let (status, www) = run(async {
            let ctx = bearer_only_ctx_with_pat(TokenKind::Pat, false); // verifier rejects
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, format!("Bearer {VALID_PAT}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            (status, www)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let www = www.expect("WWW-Authenticate present");
        assert!(
            www.starts_with("Basic"),
            "expected Basic challenge (no signing key wired): {www}"
        );
    }

    /// REGRESSION (D3 load-bearing constraint) — under `AuthContext::Disabled`
    /// a presented native `hort_pat_*` token MUST still 401 at the
    /// middleware. The widened fall-through uses `ctx.auth.authenticate()`,
    /// which returns `None` under `Disabled`, so the token is rejected —
    /// never validated as a PAT, never elevated, never passed through. The
    /// SAME token shape validates under `BearerOnly`
    /// (`bearer_only_valid_pat_mints_principal`); the discriminator is the
    /// auth mode, which is exactly the D3 fix.
    #[test]
    fn disabled_auth_native_pat_token_still_returns_401() {
        let (status, www) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle); // AuthContext::Disabled
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::get("/v2/probe")
                        .header(header::AUTHORIZATION, format!("Bearer {VALID_PAT}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            (status, www)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let www = www.expect("WWW-Authenticate present");
        assert!(
            www.starts_with("Basic"),
            "expected Basic challenge under Disabled: {www}"
        );
    }

    // -------------------- read_denied_response (D1/D2) --------------------

    /// Anonymous denial under `Enabled` auth with the OCI signing key
    /// UNWIRED → 401 carrying the legacy `Basic realm="hort"` challenge AND
    /// the `Docker-Distribution-API-Version` header (Basic-branch parity
    /// fix). This is a production-mode challenge; the challenge selector only
    /// runs outside the `Disabled` carve-out, so the ctx is `Enabled`.
    #[test]
    fn read_denied_anonymous_challenges_basic_when_key_unwired() {
        let (status, www, api) = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let resp = read_denied_response(
                &ctx,
                None,
                &axum::http::Method::GET,
                "/v2/some/img/manifests/v1",
                "some",
            );
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let api = resp
                .headers()
                .get("Docker-Distribution-API-Version")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            (status, www, api)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(www, r#"Basic realm="hort""#);
        assert_eq!(api, "registry/2.0");
    }

    /// Anonymous denial under `Enabled` auth with the OCI signing key WIRED
    /// (native-tokens-on) → 401 carrying the native-token Bearer challenge
    /// (`/v2/auth` realm + path-derived `scope=`) plus the API-version
    /// header. Production-mode challenge, so the ctx is `Enabled` (the
    /// `Disabled` carve-out would collapse this to a 404).
    #[test]
    fn read_denied_anonymous_challenges_bearer_when_key_wired() {
        use hort_http_core::test_support::with_oci_public_base_url;
        let (status, www, api) = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let sk = OciTokenSigningKey::new(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            );
            let ctx = with_oci_signing_key(&ctx, Some(Arc::new(sk)));
            let ctx =
                with_oci_public_base_url(&ctx, Some("https://registry.example.com".to_string()));
            let resp = read_denied_response(
                &ctx,
                None,
                &axum::http::Method::GET,
                "/v2/some/img/manifests/v1",
                "some",
            );
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let api = resp
                .headers()
                .get("Docker-Distribution-API-Version")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            (status, www, api)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(www.starts_with("Bearer "), "{www}");
        assert!(
            www.contains(r#"realm="https://registry.example.com/v2/auth""#),
            "{www}"
        );
        assert!(www.contains(r#"scope="repository:some/img:pull""#), "{www}");
        assert_eq!(api, "registry/2.0");
    }

    /// Authenticated denial under `Enabled` auth → the unchanged
    /// `NAME_UNKNOWN` 404 anti-enumeration envelope (ADR 0021), never a
    /// challenge. `Enabled` so the `Some(actor)` branch is exercised
    /// directly rather than the `Disabled` short-circuit.
    #[test]
    fn read_denied_authenticated_returns_name_unknown_404() {
        let (status, has_www, body) = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let principal = CallerPrincipal {
                user_id: uuid::Uuid::new_v4(),
                external_id: "test:sub".into(),
                username: "denied".into(),
                email: "d@example.com".into(),
                claims: Vec::new(),
                token_kind: None,
                issued_at: Utc::now(),
                token_cap: None,
            };
            let resp = read_denied_response(
                &ctx,
                Some(&principal),
                &axum::http::Method::GET,
                "/v2/some/img/manifests/v1",
                "some",
            );
            let status = resp.status();
            let has_www = resp.headers().get(header::WWW_AUTHENTICATE).is_some();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            (status, has_www, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!has_www);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
        assert_eq!(parsed["errors"][0]["detail"]["name"], "some");
    }

    /// REGRESSION — under `AuthContext::Disabled` (open-registry / no-auth
    /// mode) an anonymous denied read must NOT emit the 401 challenge: the
    /// `/v2/auth` realm it advertises is unsatisfiable there (a presented
    /// token is hard-rejected by this middleware), so the denial collapses
    /// to the `NAME_UNKNOWN` 404 anti-enum envelope with NO
    /// `WWW-Authenticate`. The guard is key-independent — wiring the OCI
    /// signing key does not re-open the challenge. Mirrors the `GET /v2/`
    /// probe's Disabled carve-out (`version.rs`); keeps Disabled behaviour
    /// unchanged (the read-path challenge is a production-mode fix only).
    #[test]
    fn read_denied_disabled_mode_returns_404_regardless_of_key() {
        run(async {
            for key_wired in [false, true] {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, _mocks) = build_mock_ctx(handle); // AuthContext::Disabled
                let ctx = if key_wired {
                    let sk = OciTokenSigningKey::new(
                        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                        None,
                    );
                    with_oci_signing_key(&ctx, Some(Arc::new(sk)))
                } else {
                    ctx
                };
                let resp = read_denied_response(
                    &ctx,
                    None, // anonymous
                    &axum::http::Method::GET,
                    "/v2/some/img/manifests/v1",
                    "some",
                );
                assert_eq!(
                    resp.status(),
                    StatusCode::NOT_FOUND,
                    "Disabled anonymous denial must be 404 (key_wired={key_wired})"
                );
                assert!(
                    resp.headers().get(header::WWW_AUTHENTICATE).is_none(),
                    "Disabled denial must carry no challenge (key_wired={key_wired})"
                );
                let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
                let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
                assert_eq!(parsed["errors"][0]["detail"]["name"], "some");
            }
        });
    }

    // -------------------- 7. anonymous-write challenge (D4) ---------------

    /// Router exposing the echo handler under the OCI write verbs. Anonymous
    /// writes short-circuit at the middleware BEFORE routing (so the route
    /// set is irrelevant to those tests); the routes exist so a
    /// *credentialed* write — or an anonymous write under `Disabled`, which
    /// forwards — can reach the handler.
    fn build_write_test_router(ctx: &Arc<AppContext>) -> Router {
        use axum::routing::{post, put};
        Router::new()
            .route(
                "/v2/myrepo/library/nginx/blobs/uploads/",
                post(echo_principal_handler),
            )
            .route(
                "/v2/myrepo/library/nginx/manifests/v1",
                put(echo_principal_handler).delete(echo_principal_handler),
            )
            .layer(from_fn_with_state(ctx.clone(), oci_bearer_auth))
            .with_state(ctx.clone())
    }

    /// `is_non_safe_method` classifies exactly the write verbs; the safe
    /// read/preflight verbs stay anonymous-by-default.
    #[test]
    fn is_non_safe_method_classifies_write_verbs() {
        use axum::http::Method;
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(is_non_safe_method(&m), "{m} should be non-safe");
        }
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!is_non_safe_method(&m), "{m} should be safe");
        }
    }

    /// Native tokens ON — an anonymous `POST /v2/<repo>/blobs/uploads/`
    /// (blob-upload initiate) is challenged at the middleware with a Bearer
    /// `WWW-Authenticate` carrying the `/v2/auth` realm and a `push` scope
    /// derived from the path. Pre-D4 this fell through to the shared authz
    /// extractor's hardcoded `Basic realm="hort"`, advertising the wrong
    /// scheme in native-token mode.
    #[test]
    fn anonymous_post_upload_challenges_bearer_push_when_native_tokens_on() {
        use hort_http_core::test_support::{with_oci_public_base_url, with_oci_signing_key};
        let (status, www) = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let sk = OciTokenSigningKey::new(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            );
            let ctx = with_oci_signing_key(&ctx, Some(Arc::new(sk)));
            let ctx = with_oci_public_base_url(&ctx, Some("https://hort.example.com".to_string()));
            let router = build_write_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            (status, www)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let www = www.expect("WWW-Authenticate present");
        assert!(www.starts_with("Bearer "), "{www}");
        assert!(
            www.contains(r#"realm="https://hort.example.com/v2/auth""#),
            "{www}"
        );
        assert!(
            www.contains(r#"scope="repository:myrepo/library/nginx:push""#),
            "{www}"
        );
    }

    /// Native tokens OFF (no signing key wired) — the same anonymous upload
    /// initiate is challenged with the legacy `Basic realm="hort"`,
    /// preserving pre-native behaviour but now emitted at the OCI middleware
    /// (with the `Docker-Distribution-API-Version` header).
    #[test]
    fn anonymous_post_upload_challenges_basic_when_native_tokens_off() {
        let (status, www, api) = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let router = build_write_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let www = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            let api = resp
                .headers()
                .get("Docker-Distribution-API-Version")
                .map(|v| v.to_str().unwrap().to_string());
            (status, www, api)
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(www.as_deref(), Some(r#"Basic realm="hort""#));
        assert_eq!(api.as_deref(), Some("registry/2.0"));
    }

    /// Native tokens ON — an anonymous `PUT …/manifests/<ref>` (manifest
    /// push) is challenged with a Bearer `push` scope.
    #[test]
    fn anonymous_put_manifest_challenges_bearer_push() {
        use hort_http_core::test_support::{with_oci_public_base_url, with_oci_signing_key};
        let www = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let sk = OciTokenSigningKey::new(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            );
            let ctx = with_oci_signing_key(&ctx, Some(Arc::new(sk)));
            let ctx = with_oci_public_base_url(&ctx, Some("https://hort.example.com".to_string()));
            let router = build_write_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::put("/v2/myrepo/library/nginx/manifests/v1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            resp.headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        });
        assert!(www.starts_with("Bearer "), "{www}");
        assert!(
            www.contains(r#"scope="repository:myrepo/library/nginx:push""#),
            "{www}"
        );
    }

    /// Native tokens ON — an anonymous `DELETE …/manifests/<ref>` is
    /// challenged with a Bearer `delete` scope (the delete-verb scope
    /// mapping in `path_to_scope`).
    #[test]
    fn anonymous_delete_manifest_challenges_bearer_delete() {
        use hort_http_core::test_support::{with_oci_public_base_url, with_oci_signing_key};
        let www = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let sk = OciTokenSigningKey::new(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                None,
            );
            let ctx = with_oci_signing_key(&ctx, Some(Arc::new(sk)));
            let ctx = with_oci_public_base_url(&ctx, Some("https://hort.example.com".to_string()));
            let router = build_write_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::delete("/v2/myrepo/library/nginx/manifests/v1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            resp.headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        });
        assert!(www.starts_with("Bearer "), "{www}");
        assert!(
            www.contains(r#"scope="repository:myrepo/library/nginx:delete""#),
            "{www}"
        );
    }

    /// A *safe* anonymous method (HEAD) on `/v2/*` is NOT challenged — it
    /// forwards anonymously (reads stay anonymous-by-default, ADR 0021).
    /// The GET pass-through is covered by
    /// `no_authorization_header_passes_through_anonymous_under_enabled_auth`.
    #[test]
    fn anonymous_head_passes_through_not_challenged() {
        let status = run(async {
            let ctx = enabled_auth_ctx_no_tokens();
            let router = build_test_router(&ctx);
            let resp = router
                .oneshot(HttpRequest::head("/v2/probe").body(Body::empty()).unwrap())
                .await
                .unwrap();
            resp.status()
        });
        assert_eq!(status, StatusCode::OK);
    }

    /// A *credentialed* write is NOT intercepted by the anonymous-write
    /// challenge: a valid Bearer on a `POST …/blobs/uploads/` runs the
    /// existing verify path and reaches the handler as an authenticated
    /// principal. Only credential-*less* non-safe requests are challenged.
    #[test]
    fn authenticated_post_reaches_handler_not_challenged() {
        let parsed = run(async {
            let ctx = enabled_auth_ctx_with_token("valid-jwt");
            let router = build_write_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                        .header(header::AUTHORIZATION, "Bearer valid-jwt")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        assert_eq!(parsed["authenticated"], true);
        assert_eq!(parsed["username"], "dev-user");
    }

    /// REGRESSION (D4 Disabled carve-out) — under `AuthContext::Disabled`
    /// an anonymous write is NOT challenged at this middleware: the
    /// `/v2/auth` realm is unsatisfiable there, so the request forwards with
    /// a `None` principal (reaching the handler here; in production the
    /// shared authz extractor answers the legacy `Basic` 401). Writes are
    /// unreachable in production under Disabled anyway (boot gate). Mirrors
    /// `read_denied_disabled_mode_returns_404_regardless_of_key`.
    #[test]
    fn disabled_auth_anonymous_write_passes_through() {
        let (status, parsed) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle); // AuthContext::Disabled
            let router = build_write_test_router(&ctx);
            let resp = router
                .oneshot(
                    HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            assert!(
                resp.headers().get(header::WWW_AUTHENTICATE).is_none(),
                "Disabled anonymous write must NOT carry a challenge"
            );
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
            let parsed = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
            (status, parsed)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(parsed["authenticated"], false);
    }
}
