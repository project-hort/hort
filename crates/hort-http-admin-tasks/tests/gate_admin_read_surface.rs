//! Gate guard: the admin-task READ surface must require `Permission::Admin`,
//! not merely authentication (see `docs/architecture/explanation/security.md`).
//!
//! Before the fix, `GET /api/v1/admin/tasks` and
//! `GET /api/v1/admin/tasks/:id` used the `AuthenticatedCaller` extractor
//! (authentication only, NO permission check), so any authenticated
//! principal — including a low-privilege read-only PAT — could read the
//! full `jobs` queue including raw `params`, `last_error`, and
//! `result_summary`. That was asymmetric with the RBAC-gated
//! `POST /invoke` write tier and a function-level access-control gap.
//!
//! Fixed by swapping the extractor to `AdminPrincipal`; the `hort-app`
//! task use case stays port-only (the gate is purely the handler extractor).
//!
//! These tests build an `AuthContext::Enabled` (the default mock context
//! is `Disabled`, under which every extractor grants unconditionally) so
//! the `Permission::Admin` check is actually exercised. They cover both
//! injection shapes — the bare `AuthenticatedPrincipal` slot
//! (POST-path / `inject_principal`) AND the
//! `Option<AuthenticatedPrincipal>` slot the GET-path
//! `extract_optional_principal` middleware writes — to prove the swap to
//! `AdminPrincipal` does NOT reintroduce the 2026-05-11 GET-only 403 bug
//! (`extract_principal`'s optional-slot fallback resolves the principal on
//! these GET routes).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::test_support::{MockIdentityProvider, MockUserRepository};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, Permission, PermissionGrant};
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
use hort_domain::ports::user_repository::UserRepository;

use hort_http_core::context::{AppContext, AuthContext};
use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_auth, MockPorts};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn new_ctx() -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    build_mock_ctx(handle)
}

fn build_test_router(ctx: Arc<AppContext>) -> axum::Router {
    axum::Router::new()
        .nest("/api/v1/admin/tasks", hort_http_admin_tasks::router())
        .with_state(ctx)
}

/// A principal whose resolved claim set is exactly `claims`.
fn principal(external_id: &str, claims: &[&str]) -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: external_id.into(),
        username: external_id.into(),
        email: format!("{external_id}@example.com"),
        claims: claims.iter().map(|s| (*s).to_string()).collect(),
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

/// An `AuthContext::Enabled` whose RBAC evaluator carries the supplied
/// grants. Mirrors the `enabled_auth` helper in
/// `hort-http-core::authz::extractors::tests` (which is private to that
/// crate). The `AdminPrincipal` extractor reads `state.auth.rbac`
/// directly (not the task use case's evaluator), so the grants here are
/// what actually decide the 403/200 outcome.
fn enabled_auth(rbac: RbacEvaluator) -> AuthContext {
    let idp = Arc::new(MockIdentityProvider::new());
    let users = Arc::new(MockUserRepository::new());
    let authenticate = Arc::new(AuthenticateUseCase::new(
        idp as Arc<dyn IdentityProvider>,
        users as Arc<dyn UserRepository>,
        vec![] as Vec<ClaimMapping>,
    ));
    AuthContext::Enabled {
        authenticate,
        rbac: Arc::new(arc_swap::ArcSwap::from_pointee(rbac)),
        issuer_url: None,
    }
}

/// An evaluator that grants `Permission::Admin` (no repo scope) to any
/// caller carrying the `admin` claim.
fn rbac_with_admin_grant() -> RbacEvaluator {
    let grant = PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec!["admin".into()]),
        repository_id: None,
        permission: Permission::Admin,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    };
    RbacEvaluator::new(vec![grant])
}

fn sample_job_row(id: Uuid, kind: &str) -> JobRow {
    JobRow {
        id,
        kind: kind.to_string(),
        status: JobStatus::Pending,
        params: Some(json!({})),
        actor_id: None,
        priority: 0,
        trigger_source: "api".to_string(),
        attempts: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        completed_at: None,
        last_error: None,
        result_summary: None,
        kind_fields: KindFields::Other,
    }
}

// ---------------------------------------------------------------------------
// LIST — non-admin denied (403), admin allowed (200)
// ---------------------------------------------------------------------------

/// A non-admin (read-only) principal calling `GET /api/v1/admin/tasks`
/// must get **403**. This test pins the access-control gap where a
/// non-admin principal could previously read the queue.
#[tokio::test]
async fn list_tasks_non_admin_principal_returns_403() {
    let (ctx, mocks) = new_ctx();
    // Seed rows so a leak (200) would actually expose the queue.
    mocks
        .jobs
        .seed_list(vec![sample_job_row(Uuid::new_v4(), "noop")]);
    let ctx = with_auth(&ctx, enabled_auth(rbac_with_admin_grant()));
    let router = build_test_router(ctx);

    // Read-only principal — carries `reader`, NOT `admin`.
    let mut req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, principal("reader-user", &["reader"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a non-admin principal must NOT be able to read the admin-task queue"
    );
}

/// Same as above but through the GET-path `Option<AuthenticatedPrincipal>`
/// slot (`extract_optional_principal`) — the production GET shape. Still 403.
#[tokio::test]
async fn list_tasks_non_admin_optional_principal_returns_403() {
    let (ctx, _mocks) = new_ctx();
    let ctx = with_auth(&ctx, enabled_auth(rbac_with_admin_grant()));
    let router = build_test_router(ctx);

    let mut req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, principal("reader-user", &["reader"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// An admin principal calling `GET /api/v1/admin/tasks` still gets **200**
/// (preserve the existing passing behaviour for the privileged tier).
#[tokio::test]
async fn list_tasks_admin_principal_returns_200() {
    let (ctx, mocks) = new_ctx();
    mocks
        .jobs
        .seed_list(vec![sample_job_row(Uuid::new_v4(), "noop")]);
    let ctx = with_auth(&ctx, enabled_auth(rbac_with_admin_grant()));
    let router = build_test_router(ctx);

    let mut req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, principal("admin-user", &["admin"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an admin principal must still be able to list tasks"
    );
}

/// Admin via the GET-path optional slot — proves the swap to
/// `AdminPrincipal` does NOT reintroduce the 2026-05-11 GET-only 403 bug.
#[tokio::test]
async fn list_tasks_admin_optional_principal_returns_200() {
    let (ctx, _mocks) = new_ctx();
    let ctx = with_auth(&ctx, enabled_auth(rbac_with_admin_grant()));
    let router = build_test_router(ctx);

    let mut req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, principal("admin-user", &["admin"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET routes through extract_optional_principal in production — the AdminPrincipal \
         swap must resolve via the optional-slot fallback, no GET-403 regression"
    );
}

// ---------------------------------------------------------------------------
// GET /:id — non-admin denied (403), admin allowed (200)
// ---------------------------------------------------------------------------

/// A non-admin principal calling `GET /api/v1/admin/tasks/:id` must get
/// **403** — before the fix it returned the full job row (incl. raw
/// `params`/`last_error`).
#[tokio::test]
async fn get_task_non_admin_principal_returns_403() {
    let (ctx, mocks) = new_ctx();
    let job_id = Uuid::new_v4();
    mocks.jobs.seed_get(sample_job_row(job_id, "staging-sweep"));
    let ctx = with_auth(&ctx, enabled_auth(rbac_with_admin_grant()));
    let router = build_test_router(ctx);

    let mut req = Request::get(format!("/api/v1/admin/tasks/{job_id}"))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, principal("reader-user", &["reader"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a non-admin principal must NOT read a single task row"
    );
}

/// Same via the GET-path optional slot — still 403.
#[tokio::test]
async fn get_task_non_admin_optional_principal_returns_403() {
    let (ctx, mocks) = new_ctx();
    let job_id = Uuid::new_v4();
    mocks.jobs.seed_get(sample_job_row(job_id, "staging-sweep"));
    let ctx = with_auth(&ctx, enabled_auth(rbac_with_admin_grant()));
    let router = build_test_router(ctx);

    let mut req = Request::get(format!("/api/v1/admin/tasks/{job_id}"))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, principal("reader-user", &["reader"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// An admin principal calling `GET /api/v1/admin/tasks/:id` still gets
/// **200** with the seeded row.
#[tokio::test]
async fn get_task_admin_principal_returns_200() {
    let (ctx, mocks) = new_ctx();
    let job_id = Uuid::new_v4();
    mocks.jobs.seed_get(sample_job_row(job_id, "staging-sweep"));
    let ctx = with_auth(&ctx, enabled_auth(rbac_with_admin_grant()));
    let router = build_test_router(ctx);

    let mut req = Request::get(format!("/api/v1/admin/tasks/{job_id}"))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, principal("admin-user", &["admin"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an admin principal must still be able to read a single task row"
    );
}

// ---------------------------------------------------------------------------
// Anonymous GET (auth ran, no token) — 401 on both routes
// ---------------------------------------------------------------------------

/// Auth ran but the caller presented no token (`Option<_> = None`) →
/// 401 + Bearer challenge, unchanged by the gate (the same shape
/// `AuthenticatedCaller` produced — `extract_principal` is shared).
#[tokio::test]
async fn list_tasks_anonymous_returns_401() {
    let (ctx, _mocks) = new_ctx();
    let ctx = with_auth(&ctx, enabled_auth(rbac_with_admin_grant()));
    let router = build_test_router(ctx);

    let mut req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_none(&mut req);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
