//! Anti-regression guard: every destructive task kind MUST reach
//! `TaskUseCase::enqueue` with `Some(IdempotencyKey)` so the DB
//! partial-unique-index single-flight invariant fires. The idempotency
//! contract is documented in `how-to/using-hort-cli-with-admin-ops.md`
//! and ADR 0028.
//!
//! # Why this guard exists (load-bearing)
//!
//! The rule is structural:
//! `task_kind_is_destructive(P::KIND) == true ⇒ db_idempotency_key.is_some()`.
//! The guard walks the **closed** `DESTRUCTIVE_TASK_KINDS` set
//! (`crates/hort-domain/src/events/authorization_events.rs:467-471`) and
//! drives the real handler for each through `tower::ServiceExt::oneshot`,
//! asserting the mocked `enqueue_task` received `idempotency_key.is_some()`.
//!
//! Closed-set semantics: a future addition to `DESTRUCTIVE_TASK_KINDS`
//! automatically extends this guard's coverage — adding a fourth
//! destructive kind without wiring the server-derived key path through
//! `invoke.rs` fails this test before the kind can ship.
//!
//! Mirrors the closed-set walker shape from
//! `crates/hort-server/tests/task_use_case_enqueue_real_db.rs:154,165-185`
//! (the `VALID_TASK_KINDS` walker) but stays at the HTTP layer (mocked
//! ports — no real DB) because the contract here is between the handler
//! and the use-case port, not between the use case and Postgres.
//!
//! # What this does NOT guard
//!
//! - Non-destructive kinds passing `None` — covered by a separate spot
//!   test below (`invoke_noop_passes_none_db_idempotency_key`); not part
//!   of the closed-set walker (the closure is over the *destructive*
//!   set, by design).
//! - The full per-UTC-day key shape — covered by the inline shape
//!   assertion in the walker.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::task_use_case::TaskUseCase;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::events::DESTRUCTIVE_TASK_KINDS;

use hort_http_core::context::AppContext;
use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_task_use_case, MockPorts};

fn new_ctx() -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    build_mock_ctx(handle)
}

fn build_test_router(ctx: Arc<AppContext>) -> axum::Router {
    axum::Router::new()
        .nest("/api/v1/admin/tasks", hort_http_admin_tasks::router())
        .with_state(ctx)
}

/// Permit grant that AUTHORISES the destructive kinds — `Permission::AdminTaskInvoke`
/// for callers carrying `task-admin`, exercised through a principal whose
/// claim set also includes `task:destructive` (see ADR 0012 / ADR 0028).
fn task_use_case_permit_destructive(
    mocks: &MockPorts,
    events: Arc<hort_app::event_store_publisher::EventStorePublisher>,
) -> Arc<TaskUseCase> {
    let grant = PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec!["task-admin".into()]),
        repository_id: None,
        permission: Permission::AdminTaskInvoke,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    };
    let evaluator = RbacEvaluator::new(vec![grant]);
    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(evaluator));
    Arc::new(TaskUseCase::new(mocks.jobs.clone(), events, rbac))
}

/// Caller authorised for destructive kinds (both `task-admin` and
/// `task:destructive` claims).
fn destructive_principal() -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "destructive-admin".into(),
        username: "destructive-admin".into(),
        email: "destructive@example.com".into(),
        claims: vec!["task-admin".into(), "task:destructive".into()],
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

/// Caller authorised only for ordinary (non-destructive) kinds — holds
/// `task-admin` but NOT `task:destructive`. Used by the spot test on a
/// non-destructive kind (which doesn't need the destructive claim).
fn ordinary_principal() -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "ordinary-admin".into(),
        username: "ordinary-admin".into(),
        email: "ordinary@example.com".into(),
        claims: vec!["task-admin".into()],
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

// ---------------------------------------------------------------------------
// RT-2 closed-set walker (the load-bearing guard)
// ---------------------------------------------------------------------------

/// For every kind in `DESTRUCTIVE_TASK_KINDS`, fire `POST /api/v1/admin/tasks/<kind>`
/// against the real handler and assert the mocked `enqueue_task` received
/// `Some(server-derived-key)` with the per-UTC-day shape
/// `cron:<kind>:<YYYY-MM-DD>`.
///
/// Closed-set semantics: adding a fourth destructive kind to
/// `DESTRUCTIVE_TASK_KINDS` without routing the new kind through the
/// `task_kind_is_destructive` branch in `invoke.rs` fails this test on
/// the new iteration.
#[tokio::test]
async fn destructive_kinds_carry_db_idempotency() {
    // The closed set is non-empty — this is the same invariant the
    // VALID_TASK_KINDS walker pins for its closed-set guarantee.
    assert!(
        !DESTRUCTIVE_TASK_KINDS.is_empty(),
        "DESTRUCTIVE_TASK_KINDS must be non-empty — the loop below would silently pass",
    );

    for kind in DESTRUCTIVE_TASK_KINDS {
        let (ctx, mocks) = new_ctx();
        let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
        let uc = task_use_case_permit_destructive(&mocks, events);
        let ctx = with_task_use_case(&ctx, uc);
        let router = build_test_router(ctx);

        // Capture the date BEFORE firing the request — the handler
        // computes `Utc::now().format("%Y-%m-%d")` between Steps 4 and
        // 5. UTC date can roll over inside this test on a midnight
        // boundary; we accept either the pre- or post-fire date below.
        let before = Utc::now().format("%Y-%m-%d").to_string();

        let principal = destructive_principal();
        let mut req = Request::post(format!("/api/v1/admin/tasks/{kind}"))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("valid request");
        auth_test::inject_principal(&mut req, principal);

        let resp = router.oneshot(req).await.expect("router responded");
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "destructive kind {kind:?} must enqueue successfully when the caller is authorised; \
             status={status} (RBAC denial here usually means the test fixture forgot the \
             task:destructive claim)",
            status = resp.status(),
        );

        let after = Utc::now().format("%Y-%m-%d").to_string();
        let acceptable_keys: Vec<String> = if before == after {
            vec![format!("cron:{kind}:{before}")]
        } else {
            // Midnight UTC rollover landed inside the test — accept
            // both same-day shapes. Vanishingly rare; the explicit
            // handling makes the guard non-flaky.
            vec![
                format!("cron:{kind}:{before}"),
                format!("cron:{kind}:{after}"),
            ]
        };

        // The mock captured exactly one enqueue with idempotency_key=Some(_).
        let calls = mocks.jobs.enqueue_calls();
        assert_eq!(
            calls.len(),
            1,
            "destructive kind {kind:?}: expected exactly one enqueue call, got {calls:?}",
        );
        let idem_keys = mocks.jobs.enqueue_idem_keys();
        assert_eq!(
            idem_keys.len(),
            1,
            "destructive kind {kind:?}: expected exactly one recorded idempotency_key entry",
        );
        let key = idem_keys[0].as_ref().unwrap_or_else(|| {
            panic!(
                "destructive kind {kind:?}: handler MUST pass Some(idempotency_key) to \
                 TaskUseCase::enqueue (see how-to/using-hort-cli-with-admin-ops.md + \
                 ADR 0028 for the destructive-kind idempotency contract). \
                 The closed-set DESTRUCTIVE_TASK_KINDS walker fired this assertion, so a \
                 future destructive kind needs the same server-derived key wiring \
                 in crates/hort-http-admin-tasks/src/handlers/invoke.rs:Step 4b."
            )
        });
        assert!(
            acceptable_keys.iter().any(|k| k == key.as_str()),
            "destructive kind {kind:?}: key shape mismatch. Expected one of {acceptable_keys:?}, \
             got {key_str:?}. The shape `cron:<kind>:<YYYY-MM-DD>` is required \
             to be distinct from the client's `<window>:<kind>` shape so the \
             Redis and DB layers cannot collide on a key.",
            key_str = key.as_str(),
        );
    }
}

// ---------------------------------------------------------------------------
// Spot test — non-destructive kinds pass `None`
// ---------------------------------------------------------------------------

/// Acceptance (7b): for at least one non-destructive kind (`noop`), the
/// handler passes `idempotency_key = None`. Pins the negative side of
/// the `task_kind_is_destructive` branch — without it, a future change
/// that always passes `Some(...)` would still pass the closed-set
/// walker above.
#[tokio::test]
async fn invoke_noop_passes_none_db_idempotency_key() {
    let (ctx, mocks) = new_ctx();
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    let uc = task_use_case_permit_destructive(&mocks, events);
    let ctx = with_task_use_case(&ctx, uc);
    let router = build_test_router(ctx);

    let principal = ordinary_principal();
    let mut req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("valid request");
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.expect("router responded");
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let idem_keys = mocks.jobs.enqueue_idem_keys();
    assert_eq!(idem_keys.len(), 1, "expected one enqueue call");
    assert!(
        idem_keys[0].is_none(),
        "non-destructive kind `noop` MUST pass None for db_idempotency_key, got Some({:?})",
        idem_keys[0],
    );
}

// ---------------------------------------------------------------------------
// Acceptance (7c) — Duplicate outcome returns 200 + existing id + result="ok"
// ---------------------------------------------------------------------------

/// On `EnqueueOutcome::Duplicate { existing_job_id }`, the handler
/// returns 200 + `task_job_id == existing_job_id` and emits the same
/// `result="ok"` metric the Redis fast-path hit produces. The DB-layer dedup is
/// semantically equivalent to a Redis cache-hit from the operator's
/// perspective; only the audit log distinguishes them
/// (`TaskInvoked.duplicate_of = Some(_)`).
#[tokio::test]
async fn invoke_destructive_duplicate_returns_200_and_existing_id() {
    use axum::body::to_bytes;

    let (ctx, mocks) = new_ctx();
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    let uc = task_use_case_permit_destructive(&mocks, events);
    let ctx = with_task_use_case(&ctx, uc);

    // Seed the mock to return EnqueueOutcome::Duplicate on the next call.
    let existing_id = Uuid::new_v4();
    mocks.jobs.seed_next_enqueue_duplicate(existing_id);

    let router = build_test_router(ctx);

    let principal = destructive_principal();
    let mut req = Request::post("/api/v1/admin/tasks/retention-purge")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("valid request");
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.expect("router responded");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "DB-layer dedup hit returns 200 (same shape as Redis fast-path hit)",
    );

    let bytes = to_bytes(resp.into_body(), 32 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let returned: Uuid = body["task_job_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("parseable task_job_id");
    assert_eq!(
        returned, existing_id,
        "Duplicate branch must return the EXISTING row's task_job_id, not a fresh one",
    );
}
