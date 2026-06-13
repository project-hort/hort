//! `/metrics` endpoint authentication.
//!
//! Regression coverage for the lockdown:
//!
//! 1. Anonymous `GET /metrics` on the admin listener returns 401 by
//!    default (auth required).
//! 2. Anonymous `GET /metrics` on the main listener returns 401 by
//!    default when the operator runs single-listener (no
//!    `HORT_METRICS_BIND`).
//! 3. `HORT_METRICS_REQUIRE_AUTH=false` re-permits anonymous scraping
//!    for legacy deployments.
//! 4. `HORT_METRICS_PUBLIC_BIND` gates the `0.0.0.0` bind refusal at
//!    config-parse time.
//!
//! These tests intentionally drive the real router via
//! `tower::util::ServiceExt::oneshot` so the middleware stack is
//! exercised end-to-end. Auth is wired via `with_auth` to flip the
//! default-disabled mock context to `AuthContext::Enabled` — the
//! production startup guard already refuses
//! `AUTH=disabled`, so the auth-required path is the only relevant
//! production posture.

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
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::user_repository::UserRepository;

use hort_http_core::context::{AppContext, AuthContext};
use hort_http_core::test_support::{build_mock_ctx as build_base_ctx, with_auth, MockPorts};

use hort_server::http::{build_admin_router, build_router};

/// Build a mock `AppContext` with `AuthContext::Enabled`, returning the
/// underlying mock-port handles so individual tests can seed RBAC /
/// users / repositories as they need.
fn build_enabled_auth_ctx(
    handle: metrics_exporter_prometheus::PrometheusHandle,
) -> (Arc<AppContext>, MockPorts) {
    let (base, mocks) = build_base_ctx(handle);

    let idp = Arc::new(MockIdentityProvider::new());
    let users: Arc<dyn UserRepository> = mocks.users.clone();
    let authenticate = Arc::new(AuthenticateUseCase::new(
        idp as Arc<dyn IdentityProvider>,
        users,
        Vec::new(),
    ));
    // Claim-based RBAC (ADR 0012) — global Admin grant bound to the
    // `admin` claim (there is no role-keyed grant map; the
    // lowercase-`admin` claim also short-circuits the evaluator).
    let grant = PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec!["admin".into()]),
        repository_id: None,
        permission: Permission::Admin,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    };
    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
        grant,
    ])));

    let ctx = with_auth(
        &base,
        AuthContext::Enabled {
            authenticate,
            rbac,
            // Metrics-auth tests don't
            // exercise the WWW-Authenticate selector.
            issuer_url: None,
        },
    );
    (ctx, mocks)
}

/// **RED → GREEN regression test, acceptance bar (a) + (b).**
///
/// Anonymous `GET /metrics` on the admin listener must return 401 with
/// the `metrics_require_auth=true` default. Pre-fix the admin router
/// had ZERO middleware and exposed every scrape anonymously.
#[test]
fn anonymous_get_metrics_on_admin_listener_returns_401_by_default() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let status = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _mocks) = build_enabled_auth_ctx(handle.clone());
                // Default = require auth.
                let router = build_admin_router(ctx, true);

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
        "anonymous /metrics on admin listener must 401 by default"
    );
}

/// **RED → GREEN regression test, acceptance bar (b).**
///
/// When `HORT_METRICS_BIND` is unset and `metrics_require_auth=true`
/// (default), anonymous `GET /metrics` on the MAIN listener must also
/// return 401. Auth dispatch must route this specific path through
/// `require_principal` rather than `extract_optional_principal`.
#[test]
fn anonymous_get_metrics_on_main_listener_returns_401_by_default() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let status = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _mocks) = build_enabled_auth_ctx(handle.clone());
                // include_metrics=true (dev-mode single-listener),
                // metrics_require_auth=true (the new default).
                let router = build_router(ctx, true, true);

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
        "anonymous /metrics on main listener must 401 by default"
    );
}

/// **RED → GREEN regression test, acceptance bar (c) — bypass.**
///
/// Setting `metrics_require_auth=false` re-permits anonymous scraping.
/// Operators with legacy Prometheus configs that cannot supply a
/// bearer token use this escape hatch (the WARN log is asserted
/// separately at config-parse time).
#[test]
fn anonymous_get_metrics_allowed_when_require_auth_is_false() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let (admin_status, main_status) = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (ctx, _mocks) = build_enabled_auth_ctx(handle.clone());
                let admin = build_admin_router(ctx.clone(), false);
                let main = build_router(ctx, true, false);

                let admin_res = admin
                    .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let main_res = main
                    .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                (admin_res.status(), main_res.status())
            })
    });

    assert_eq!(
        admin_status,
        StatusCode::OK,
        "admin /metrics must allow anonymous when require_auth=false"
    );
    assert_eq!(
        main_status,
        StatusCode::OK,
        "main /metrics must allow anonymous when require_auth=false"
    );
}
