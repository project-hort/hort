//! `/metrics` endpoint authentication and listener placement.
//!
//! Coverage for the metrics lockdown:
//!
//! 1. Anonymous `GET /metrics` on the admin listener returns 401 (no
//!    bearer at all — `require_principal` denies before the handler is
//!    ever reached). An anonymous request presents no credential, so the
//!    transport decision never reaches it: the status is about authority,
//!    not about the wire.
//! 2. An authenticated principal WITHOUT the `read_metrics` grant gets 403
//!    on the admin listener (`require_principal` passes; the handler's
//!    `MetricsReaderPrincipal` extractor denies).
//! 3. `GET /metrics` on the main/public listener returns 404 — the
//!    `metrics_require_auth && path=="/metrics"` carve-out is gone, so
//!    the main router never mounts `/metrics` at all, regardless of any
//!    config. There is no flag left that puts it back.
//! 4. `HORT_METRICS_PUBLIC_BIND` gates the `0.0.0.0` bind refusal at
//!    config-parse time (covered in `config.rs`'s own tests, not here).
//!
//! A scrape that presents a credential crosses the credential-transport
//! boundary first, so (2) declares its loopback hop with
//! `HORT_TLS_NOT_REQUIRED_FROM` — otherwise the authority answer it is
//! about is masked by a `426`, which
//! `authenticated_scrape_without_a_declared_hop_is_refused` pins on its
//! own.
//!
//! These tests intentionally drive the real router via
//! `tower::util::ServiceExt::oneshot` — including the real
//! `require_principal` middleware layer `build_admin_router` attaches —
//! so the middleware stack is exercised end-to-end, not just the handler
//! extractor. Auth is wired via `with_auth` to flip the default-disabled
//! mock context to `AuthContext::Enabled` — the production startup guard
//! already refuses `AUTH=disabled`, so the auth-required path is the only
//! relevant production posture.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::test_support::MockIdentityProvider;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::ports::identity_provider::{IdentityProvider, IdpClaims};
use hort_domain::ports::user_repository::UserRepository;

use hort_http_core::context::{AppContext, AuthContext};
use hort_http_core::middleware::trust::TrustConfig;
use hort_http_core::test_support::{
    build_mock_ctx as build_base_ctx, with_auth, with_trust_config,
};

use hort_server::http::{build_admin_router, build_router};

/// Global (`repository_id = None`) `read_metrics` grant bound to the
/// `scraper` claim — the scraper-`ServiceAccount` shape the design
/// describes.
fn read_metrics_grant() -> PermissionGrant {
    PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec!["scraper".into()]),
        repository_id: None,
        permission: Permission::ReadMetrics,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    }
}

/// Build a mock `AppContext` with `AuthContext::Enabled`: a mock IdP that
/// accepts `token` (mapped to NO claims — no `ClaimMapping`s are wired, so
/// `resolve_claims` always yields `[]` regardless of IdP groups) and the
/// given RBAC grants. A caller presenting `token` authenticates
/// successfully (passes `require_principal`) but carries no claims, so a
/// claim-scoped grant like [`read_metrics_grant`] never matches — exactly
/// the "authenticated, no grant" shape #113 item 3 needs to distinguish
/// from "anonymous".
fn build_enabled_auth_ctx(
    handle: metrics_exporter_prometheus::PrometheusHandle,
    token: &str,
    grants: Vec<PermissionGrant>,
) -> Arc<AppContext> {
    let (base, mocks) = build_base_ctx(handle);

    let idp = Arc::new(MockIdentityProvider::new());
    idp.register_token(
        token,
        IdpClaims {
            subject: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            groups: vec![],
            issued_at: Utc::now(),
        },
    );
    let users: Arc<dyn UserRepository> = mocks.users.clone();
    let authenticate = Arc::new(AuthenticateUseCase::new(
        idp as Arc<dyn IdentityProvider>,
        users,
        Vec::new(),
    ));
    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(grants)));

    with_auth(
        &base,
        AuthContext::Enabled {
            authenticate,
            rbac,
            // Metrics-auth tests don't
            // exercise the WWW-Authenticate selector.
            issuer_url: None,
        },
    )
}

/// **RED → GREEN regression test.**
///
/// Anonymous `GET /metrics` on the admin listener must return 401.
/// Pre-fix the admin router had ZERO middleware and exposed every scrape
/// anonymously.
#[test]
fn anonymous_get_metrics_on_admin_listener_returns_401() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let status = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let ctx = build_enabled_auth_ctx(
                    handle.clone(),
                    "irrelevant",
                    vec![read_metrics_grant()],
                );
                let router = build_admin_router(ctx);

                let response = router
                    .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                response.status()
            })
    });

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "anonymous /metrics on admin listener must 401"
    );
}

/// A loopback scrape carrying `valid-token`, with the loopback hop
/// optionally declared as not requiring TLS — the sidecar-scrape posture.
///
/// The context is built inside the runtime because the mock ephemeral
/// store registers a timer on construction.
fn scrape_status(
    handle: metrics_exporter_prometheus::PrometheusHandle,
    declare_loopback_hop: bool,
) -> StatusCode {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let ctx = build_enabled_auth_ctx(handle, "valid-token", vec![read_metrics_grant()]);
            let ctx = if declare_loopback_hop {
                with_trust_config(
                    &ctx,
                    TrustConfig::default().with_tls_not_required_from(vec!["127.0.0.1/32"
                        .parse()
                        .expect("loopback CIDR parses")]),
                )
            } else {
                ctx
            };
            let req = Request::get("/metrics")
                .header("authorization", "Bearer valid-token")
                .extension(axum::extract::ConnectInfo(SocketAddr::from((
                    [127, 0, 0, 1],
                    40000,
                ))))
                .body(Body::empty())
                .unwrap();
            build_admin_router(ctx).oneshot(req).await.unwrap().status()
        })
}

/// **Authenticated-but-ungranted → 403.**
///
/// A caller with a VALID bearer (passes `require_principal`) but no
/// `read_metrics` grant reaches `MetricsReaderPrincipal` and is denied —
/// distinct from the anonymous 401 case above.
#[test]
fn authenticated_without_grant_on_admin_listener_returns_403() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let status = metrics::with_local_recorder(&recorder, || scrape_status(handle.clone(), true));

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "authenticated caller without read_metrics must 403 on the admin listener"
    );
}

/// The same scrape on a plaintext listener with no declared hop is
/// refused `426` before any authority is evaluated: a credential is on
/// the wire, and the refusal is what tells the scraper to stop sending it.
/// A deployment that cannot terminate TLS in front of the metrics
/// listener declares that hop instead — which admits every process
/// sharing the listener's network namespace, so it is a deliberate
/// operator statement rather than a default.
#[test]
fn authenticated_scrape_without_a_declared_hop_is_refused() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let status = metrics::with_local_recorder(&recorder, || scrape_status(handle.clone(), false));

    assert_eq!(
        status,
        StatusCode::UPGRADE_REQUIRED,
        "a credential presented on an unproven transport must be refused"
    );
}

/// **RED → GREEN regression test, #113 item 3.**
///
/// `GET /metrics` on the main/public listener is GONE — no route, no
/// carve-out, no config flag brings it back. A request for it 404s
/// exactly like any other unmatched path.
#[test]
fn get_metrics_on_main_listener_returns_404() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let status = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let ctx = build_enabled_auth_ctx(
                    handle.clone(),
                    "irrelevant",
                    vec![read_metrics_grant()],
                );
                let router = build_router(ctx);

                let response = router
                    .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                response.status()
            })
    });

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/metrics must not be routed on the main listener at all"
    );
}
