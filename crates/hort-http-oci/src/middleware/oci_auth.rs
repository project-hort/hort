//! OCI bearer-token auth middleware (ADR 0012).
//!
//! Attached to the `/v2/*` subtree only. The global
//! `method_based_auth_dispatch` from `hort-http-core::router`
//! short-circuits on OCI paths and lets this middleware own auth
//! for the OCI surface.
//!
//! # Behaviour
//!
//! 1. **No `Authorization` header** → insert
//!    `Option<CallerPrincipal>::None` into request extensions and
//!    forward. Read paths on public repos succeed; write paths fail
//!    at the `WriteRepoAccess` extractor with 401 + Basic challenge.
//!
//! 2. **`Authorization: Bearer <jwt>`** → call
//!    `AuthenticateUseCase::authenticate_bearer(jwt)` (IdP JWKS
//!    validation). On success, insert the resulting `CallerPrincipal`.
//!    On failure, 401 with Basic challenge.
//!
//! 3. **`Authorization: Basic <b64(user:jwt)>`** — same as Bearer.
//!    The password field is treated as the bearer token. Legacy
//!    clients (twine, docker pre-OCI-spec) embed an IdP-issued JWT
//!    in the password slot; this is the documented Docker Hub
//!    convention and what `require_principal` accepted.
//!
//! 4. **`AuthContext::Disabled`** (dev / single-node bootstrap): the
//!    middleware runs the same code path as `Enabled`, but the
//!    bearer-validation arm short-circuits to 401 (no IdP is wired
//!    under Disabled), and an anonymous request flows through with
//!    `Option<CallerPrincipal>::None` so downstream extractors fail
//!    closed with 401. The OCI surface is therefore unusable when
//!    `AUTH=disabled` — operators wanting OCI must wire a real IdP.
//!
//! There is **no hort-server-minted token** in this flow. Tokens come
//! from the configured IdP.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use hort_app::use_cases::oci_token_exchange_use_case::OciVerifyOutcome;
use hort_domain::entities::caller::CallerPrincipal;

use hort_http_core::context::{AppContext, AuthContext};
use hort_http_core::middleware::auth::{
    mint_authenticated_principal_for_format_middleware, AuthenticatedPrincipal,
};

use crate::v2_auth::path_to_scope;

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
    // Resolve a token from `Authorization`. Bearer or Basic-as-JWT
    // both supply the same string; absent → anonymous pass-through.
    let token = extract_token(&req);
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let principal: Option<CallerPrincipal> = match token {
        None => None,
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
                // Legacy IdP path.
                let AuthContext::Enabled { authenticate, .. } = &ctx.auth else {
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
fn unauthorized_basic_response() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, r#"Basic realm="hort""#)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#,
        ))
        .expect("static unauthorized response builds")
}

/// Challenge selector. Picks Bearer when the OCI signing key is wired
/// (native-tokens-on path), Basic otherwise (legacy behaviour
/// preserved). The version probe `GET /v2/` is anonymous — callers
/// should NOT be reaching this helper for it; the routing layer answers
/// 200 directly.
fn unauthorized_response(ctx: &AppContext, method: &axum::http::Method, path: &str) -> Response {
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
/// echo are the registry hostname (no scheme, no path).
fn host_of(url: &str) -> &str {
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

    use hort_app::oci_token_signing::OciTokenSigningKey;
    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::oci_token_exchange_use_case::{
        OciTokenExchangeConfig, OciTokenExchangeUseCase,
    };
    use hort_app::use_cases::pat_cache::{PatCache, SystemClock};
    use hort_app::use_cases::pat_validation_use_case::{PatLockoutConfig, PatValidationUseCase};
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::ports::api_token_repository::ApiTokenRepository;
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::identity_provider::{IdentityProvider, IdpClaims};
    use hort_domain::ports::repository_repository::RepositoryRepository;
    use hort_domain::ports::user_repository::UserRepository;

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
                // `claims` set (ADR 0012). `token_kind` is echoed so
                // the bespoke OCI principal shape stays observable in
                // these middleware tests.
                "claims": p.claims,
                "token_kind": format!("{:?}", p.token_kind),
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
}
