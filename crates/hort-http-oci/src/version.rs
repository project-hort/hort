//! `GET /v2/` — OCI Distribution API-version probe.
//!
//! Every conformant OCI client begins a session with this request. The
//! response signals which auth scheme the server expects:
//!
//! - **Auth enabled, no credentials** → `401 Unauthorized` +
//!   `WWW-Authenticate: Basic realm="hort"`. Skopeo /
//!   docker / podman cache this auth scheme for the registry and
//!   send `Authorization: Basic ...` preemptively on every
//!   subsequent request to that host. Without this challenge,
//!   skopeo would treat the registry as anonymous and not retry
//!   when later endpoints challenge — which broke the e2e push
//!   path before this fix landed.
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
    // Anonymous → 401 with the Basic challenge so clients know how to
    // authenticate. Authenticated → 200.
    //
    // The `AuthenticatedPrincipal` newtype slot is the only signal
    // consulted; a future middleware that injects a bare
    // `CallerPrincipal` cannot trick this probe into reporting an
    // authenticated session.
    if req.extensions().get::<AuthenticatedPrincipal>().is_some() {
        ok_response()
    } else {
        unauthorized_response()
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

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (CONTENT_TYPE, "application/json"),
            (WWW_AUTHENTICATE, r#"Basic realm="hort""#),
            (DOCKER_API_VERSION_HEADER, DOCKER_API_VERSION_VALUE),
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

    #[tokio::test]
    async fn enabled_auth_anonymous_returns_401_with_basic_challenge() {
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
