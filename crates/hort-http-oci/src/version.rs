//! `GET /v2/` — OCI Distribution API-version probe.
//!
//! Every conformant OCI client begins a session with this request. The
//! response signals which auth scheme the server expects:
//!
//! - **Auth enabled, no credentials** → `401 Unauthorized` + the
//!   mode-appropriate challenge, matching the `/v2/*` middleware's
//!   selector (`oci_auth::unauthorized_response`):
//!   - native tokens on (`ctx.oci_signing_key` present) →
//!     `WWW-Authenticate: Bearer realm="<base>/v2/auth",service="<host>"`.
//!     Clients follow the realm to `/v2/auth`, mint a capability JWT
//!     with their Basic credentials (native PAT / `hort_svc_*` are
//!     validated there), and present it as `Bearer` from then on.
//!   - native tokens off → `WWW-Authenticate: Basic realm="hort"`
//!     (legacy IdP-JWT-in-the-password-slot flow).
//!
//!   Clients cache the scheme this probe advertises for the whole
//!   session (skopeo / docker / podman / cosign's
//!   go-containerregistry), so the probe IS the auth-discovery
//!   handshake: advertising `Basic` while native tokens are on makes
//!   clients embed their opaque `hort_svc_*` token in the Basic
//!   password slot — which no read-path validator accepts — instead
//!   of minting at `/v2/auth`, silently degrading every read to
//!   anonymous (private repos then anti-enumerate to 404).
//! - **Auth enabled, valid credentials** → `200 OK` +
//!   `Docker-Distribution-API-Version: registry/2.0`.
//! - **Auth disabled** → `200 OK` (anonymous flow; no challenge).
//!
//! See `docs/architecture/how-to/oci-pull-through.md` for the OCI
//! registry design and auth-discovery handshake.
//!
//! # Why no `tracing::info!`
//!
//! This handler is a cheap liveness probe — OCI clients hit it on every
//! `docker pull`, `docker push`, `cosign sign`, etc. Emitting per-request
//! logs would multiply log volume for zero operational value. Request-
//! level spans from `tower-http` (configured on the main router) already
//! capture path + status + latency; that is the right layer for observing
//! this route.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};

use hort_http_core::context::{AppContext, AuthContext};
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

/// HTTP header advertising the OCI Distribution API version. Required by
/// the spec on every response to `GET /v2/`; conformance test suites
/// check for its presence.
///
/// Header names are canonicalised to lowercase on the wire; `HeaderName`
/// accepts the lowercase form without runtime validation cost.
const DOCKER_API_VERSION_HEADER: HeaderName =
    HeaderName::from_static("docker-distribution-api-version");

/// Header value pinned to `registry/2.0` — the only version string the
/// OCI Distribution Spec v1.1 defines, unchanged since Docker v2.
const DOCKER_API_VERSION_VALUE: &str = "registry/2.0";

/// Empty JSON object body. The spec leaves the body unspecified; `{}` is
/// the de-facto standard choice (Docker Hub, GHCR, Harbor, zot all emit
/// it) and is what every client's tolerant JSON parser expects.
const EMPTY_JSON_BODY: &str = "{}";

/// `GET /v2/` handler.
///
/// Drives the OCI auth-discovery handshake: clients use the response
/// to decide whether (and how) to authenticate. See module docs for
/// the response matrix.
pub async fn get_version(State(ctx): State<Arc<AppContext>>, req: Request) -> Response {
    // Disabled auth: classic 200 OK probe response, no challenge.
    // The bearer middleware does not synthesise a principal under
    // Disabled — it inserts only `Option<CallerPrincipal>::None`.
    // Without this short-circuit the anonymous-falls-through-to-401
    // branch below would fire and the OCI version probe would be
    // unreachable in Disabled mode. The probe is harmless (it merely
    // advertises that an OCI registry exists); actual operations still
    // fail closed at the extractors.
    if matches!(ctx.auth, AuthContext::Disabled) {
        return ok_response();
    }

    // Auth enabled. The OCI bearer middleware ran upstream and either
    // inserted an `AuthenticatedPrincipal` (token presented and
    // validated) or `Option<AuthenticatedPrincipal>::None` (anonymous).
    // Anonymous → 401 with the mode-appropriate challenge (Bearer →
    // `/v2/auth` when native tokens are on, legacy Basic otherwise —
    // see the module docs) so clients know how to authenticate.
    // Authenticated → 200.
    //
    // The `AuthenticatedPrincipal` newtype slot is the only signal
    // consulted; a future middleware that injects a bare
    // `CallerPrincipal` cannot trick this probe into reporting an
    // authenticated session.
    if req.extensions().get::<AuthenticatedPrincipal>().is_some() {
        ok_response()
    } else {
        unauthorized_response(&ctx)
    }
}

fn ok_response() -> Response {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/json"),
            (DOCKER_API_VERSION_HEADER, DOCKER_API_VERSION_VALUE),
        ],
        EMPTY_JSON_BODY,
    )
        .into_response()
}

/// 401 with the challenge matching the deployment's token mode. The
/// probe advertises the same scheme the `/v2/*` middleware enforces:
/// Bearer → `/v2/auth` when the OCI signing key is wired (native
/// capability-token flow), legacy Basic otherwise. No `scope=` hint —
/// the root probe is not repository-scoped; clients echo the realm +
/// `service=` and supply scope on the per-repository token request.
fn unauthorized_response(ctx: &AppContext) -> Response {
    let challenge = if ctx.oci_signing_key.is_some() {
        crate::middleware::oci_auth::v2_auth_challenge_value(
            ctx.oci_public_base_url.as_deref(),
            ctx.oci_public_base_url
                .as_deref()
                .map(crate::middleware::oci_auth::host_of),
            None,
        )
    } else {
        r#"Basic realm="hort""#.to_string()
    };
    (
        StatusCode::UNAUTHORIZED,
        [
            (CONTENT_TYPE, "application/json".to_string()),
            (WWW_AUTHENTICATE, challenge),
            (
                DOCKER_API_VERSION_HEADER,
                DOCKER_API_VERSION_VALUE.to_string(),
            ),
        ],
        r#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::Request as HttpRequest;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use uuid::Uuid;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use hort_http_core::middleware::auth::test_support::inject_principal;
    use hort_http_core::test_support::{build_mock_ctx, with_auth};

    fn req_with_principal(p: Option<CallerPrincipal>) -> Request {
        let mut req: Request = HttpRequest::get("/v2/").body(Body::empty()).unwrap();
        // Wrap in `AuthenticatedPrincipal` via the test-support helper.
        // The version probe reads the newtype slot, not the bare slot.
        if let Some(p) = p {
            inject_principal(&mut req, p);
        }
        req
    }

    fn principal() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: vec!["developer".into()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn enabled_ctx() -> Arc<AppContext> {
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
        with_auth(
            &ctx,
            AuthContext::Enabled {
                authenticate: auth,
                rbac,
                // Version handler tests don't exercise the
                // WWW-Authenticate selector.
                issuer_url: None,
            },
        )
    }

    #[tokio::test]
    async fn disabled_auth_returns_200_with_api_version_header() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, _mocks) = build_mock_ctx(handle);
        let response = get_version(State(ctx), req_with_principal(None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let header = response
            .headers()
            .get(DOCKER_API_VERSION_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(header, DOCKER_API_VERSION_VALUE);
    }

    /// Legacy mode (no OCI signing key): the probe challenges Basic —
    /// the IdP-JWT-in-the-password-slot flow.
    #[tokio::test]
    async fn enabled_auth_anonymous_without_signing_key_challenges_basic() {
        let ctx = enabled_ctx();
        let response = get_version(State(ctx), req_with_principal(None)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let www = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www.starts_with("Basic"), "got: {www}");
    }

    /// Native-token mode (OCI signing key wired): the probe challenges
    /// Bearer with the `/v2/auth` realm + `service=` host, matching the
    /// `/v2/*` middleware's selector. Clients cache the scheme this
    /// probe advertises, so a Basic challenge here would keep them from
    /// ever minting at `/v2/auth` — an opaque `hort_svc_*` credential
    /// would ride the Basic password slot, fail every read-path
    /// validator, and degrade all reads to anonymous.
    #[tokio::test]
    async fn enabled_auth_anonymous_with_signing_key_challenges_bearer_v2_auth() {
        use hort_http_core::test_support::{with_oci_public_base_url, with_oci_signing_key};

        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rand_core::UnwrapErr(
            rand::rngs::SysRng,
        ));
        let key = hort_app::oci_token_signing::OciTokenSigningKey::new(sk, None);
        let ctx = with_oci_signing_key(&enabled_ctx(), Some(Arc::new(key)));
        let ctx = with_oci_public_base_url(&ctx, Some("https://registry.example.com".into()));

        let response = get_version(State(ctx), req_with_principal(None)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let www = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            www.starts_with(r#"Bearer realm="https://registry.example.com/v2/auth""#),
            "got: {www}"
        );
        assert!(
            www.contains(r#"service="registry.example.com""#),
            "got: {www}"
        );
        assert!(
            !www.contains("scope="),
            "root probe carries no scope: {www}"
        );
    }

    #[tokio::test]
    async fn enabled_auth_with_principal_returns_200() {
        let ctx = enabled_ctx();
        let response = get_version(State(ctx), req_with_principal(Some(principal()))).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ok_body_is_empty_json_object() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, _mocks) = build_mock_ctx(handle);
        let response = get_version(State(ctx), req_with_principal(None)).await;
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], b"{}");
    }
}
