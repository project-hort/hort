//! Integration tests for the admin-task REST surface.
//!
//! Drives the router through `tower::ServiceExt::oneshot` — same pattern
//! as every other per-format/per-admin crate in the workspace. The mock
//! harness comes from `hort_http_core::test_support::build_mock_ctx`, which
//! wires `MockJobsRepository` and `TaskUseCase` and exposes them via
//! `MockPorts.jobs`.
//!
//! # Test list (15 required)
//!
//! 1. `invoke_noop_under_disabled_returns_403`
//! 2. `invoke_noop_under_disabled_never_calls_use_case`
//! 3. `invoke_noop_with_valid_principal_and_rbac_returns_202`
//! 4. `invoke_noop_invalid_params_returns_422`   (label > 256 bytes → 422)
//! 5. `invoke_idempotency_key_cache_hit_returns_200`
//! 6. `invoke_idempotency_key_fresh_returns_202_and_stores_key`
//! 7. `invoke_unknown_kind_is_not_mounted`       (route simply does not exist)
//! 8. `list_tasks_under_disabled_returns_403`
//! 9. `list_tasks_with_principal_returns_200_and_jobs`
//! 10. `list_tasks_invalid_status_filter_returns_400`
//! 11. `get_task_returns_404_for_missing_id`
//! 12. `get_task_returns_200_for_seeded_row`
//! 13. `invoke_emits_hort_admin_tasks_enqueued_ok_on_success` (Item 13 metric)
//! 14. `invoke_emits_hort_admin_tasks_enqueued_rbac_denied`   (Item 13 metric)
//! 15. `invoke_emits_hort_admin_tasks_enqueued_validation_error` (Item 13 metric)

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use bytes::Bytes;
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::{CompositeKey, MetricKind};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::task_use_case::TaskUseCase;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::error::DomainError;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};

use hort_http_core::context::AppContext;
use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_task_use_case, MockPorts};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn new_ctx() -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    build_mock_ctx(handle)
}

/// Build the admin-tasks router under the canonical `/api/v1/admin/tasks`
/// prefix so tests fire against real path strings.
fn build_test_router(ctx: Arc<AppContext>) -> axum::Router {
    axum::Router::new()
        .nest("/api/v1/admin/tasks", hort_http_admin_tasks::router())
        .with_state(ctx)
}

/// A `CallerPrincipal` whose resolved claim set contains `task-admin`.
fn task_admin_principal() -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "task-admin-user".into(),
        username: "task-admin-user".into(),
        email: "task-admin@example.com".into(),
        claims: vec!["task-admin".into()],
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

/// Build a `TaskUseCase` that grants `Permission::AdminTaskInvoke` to any
/// caller whose resolved claims contain `task-admin` (flat
/// `GrantSubject::Claims` grant set, no role row — see ADR 0012).
fn task_use_case_with_permit(
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

/// Build a minimal `JobRow` for testing `get_job` / `list_jobs`.
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Test 1 — invoke noop under AuthContext::Disabled returns 403
// ---------------------------------------------------------------------------

/// Router-wiring-bug regression: with no auth middleware in the test
/// router, neither principal slot is populated. `AuthenticatedCaller`'s
/// extractor correctly classifies this as a wiring bug and returns 500
/// — the prior misleading 403 ("authentication required") was masking
/// the production bug where GET routes through extract_optional_principal
/// produced `Option<_>=None/Some(_)` and the buggy handler read the wrong
/// slot. Production never reaches a handler without one of the two
/// auth-middleware variants running first, so 500 is the correct shape.
#[tokio::test]
async fn invoke_returns_500_when_auth_middleware_did_not_run() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    // No principal injected — neither bare AuthenticatedPrincipal nor
    // Option<AuthenticatedPrincipal>. In production this can't happen
    // because router::auth_dispatch is unconditional; in this test
    // we deliberately omit middleware to pin the router-wiring-bug
    // shape.
    let req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ---------------------------------------------------------------------------
// Test 2 — router-wiring bug never calls the use case
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_never_calls_use_case_when_auth_middleware_did_not_run() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // No enqueue calls must have been made — the extractor short-circuits
    // before the handler body runs.
    assert!(
        mocks.jobs.enqueue_calls().is_empty(),
        "enqueue_task must not be called when no principal is present"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — invoke noop with valid principal and RBAC returns 202
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_noop_with_valid_principal_and_rbac_returns_202() {
    let (ctx, mocks) = new_ctx();
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    // Replace the deny-all task use case with a permit-all one.
    let uc = task_use_case_with_permit(&mocks, events);
    let ctx = with_task_use_case(&ctx, uc);
    let router = build_test_router(ctx);

    let principal = task_admin_principal();
    let mut req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"label":"test-run"}"#))
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let body = body_json(resp).await;
    assert!(
        body["task_job_id"].is_string(),
        "expected task_job_id in response"
    );

    // The mock recorded the enqueue call.
    let calls = mocks.jobs.enqueue_calls();
    assert_eq!(calls.len(), 1);
    let (kind, _params, _actor) = &calls[0];
    assert_eq!(kind, "noop");
}

// ---------------------------------------------------------------------------
// Test 4 — invoke noop with invalid params (label > 256 bytes) returns 422
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_noop_invalid_params_returns_422() {
    let (ctx, mocks) = new_ctx();
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    let uc = task_use_case_with_permit(&mocks, events);
    let ctx = with_task_use_case(&ctx, uc);
    let router = build_test_router(ctx);

    // 257-byte label should fail validation.
    let long_label = "x".repeat(257);
    let body = json!({ "label": long_label }).to_string();

    let principal = task_admin_principal();
    let mut req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    // validate() returns Err → mapped to 400 Bad Request (DomainError::Validation)
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Test 5 — idempotency key cache hit returns 200 with cached task_job_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_idempotency_key_cache_hit_returns_200() {
    let (ctx, mocks) = new_ctx();
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    let uc = task_use_case_with_permit(&mocks, events);
    let ctx = with_task_use_case(&ctx, uc);

    // Pre-seed a UUID into the durable ephemeral store under the idem-task key.
    let existing_job_id = Uuid::new_v4();
    let idem_key = "my-idempotency-key-001";
    let store_key = format!("idem-task:{idem_key}");
    mocks
        .ephemeral_durable
        .put(
            &store_key,
            Bytes::copy_from_slice(existing_job_id.as_bytes()),
            Duration::from_secs(300),
        )
        .await
        .expect("pre-seed failed");

    let router = build_test_router(ctx);

    let principal = task_admin_principal();
    let mut req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .header("Idempotency-Key", idem_key)
        .body(Body::from("{}"))
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    // Cache hit — 200 OK with the cached job_id.
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp).await;
    let returned_id: Uuid = body["task_job_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("expected parseable task_job_id");
    assert_eq!(returned_id, existing_job_id);

    // No new enqueue calls.
    assert!(
        mocks.jobs.enqueue_calls().is_empty(),
        "must not enqueue on idempotency cache hit"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — fresh idempotency key returns 202 and stores the mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_idempotency_key_fresh_returns_202_and_stores_key() {
    let (ctx, mocks) = new_ctx();
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    let uc = task_use_case_with_permit(&mocks, events);
    let ctx = with_task_use_case(&ctx, uc);
    let ephemeral_durable = mocks.ephemeral_durable.clone();
    let router = build_test_router(ctx);

    let idem_key = "fresh-key-xyz";
    let principal = task_admin_principal();
    let mut req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .header("Idempotency-Key", idem_key)
        .body(Body::from("{}"))
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let body = body_json(resp).await;
    let returned_id: Uuid = body["task_job_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("expected parseable task_job_id");

    // The idempotency key must now be stored in ephemeral_durable.
    let store_key = format!("idem-task:{idem_key}");
    let cached = ephemeral_durable.get(&store_key).await.expect("get failed");
    let cached_bytes = cached.expect("expected cached entry");
    assert_eq!(cached_bytes.len(), 16, "UUID is 16 bytes");
    let cached_id = Uuid::from_bytes(cached_bytes[..16].try_into().unwrap());
    assert_eq!(cached_id, returned_id);
}

// ---------------------------------------------------------------------------
// Test 7 — unknown kind returns 404 (route not mounted)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoke_unknown_kind_is_not_mounted() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let req = Request::post("/api/v1/admin/tasks/completely-unknown-kind")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    // Axum returns 405 Method Not Allowed or 404 — either way not 200/202.
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::METHOD_NOT_ALLOWED,
        "unexpected status for unmounted route: {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Test 8 — list tasks under AuthContext::Disabled returns 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_tasks_returns_500_when_auth_middleware_did_not_run() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    // Mirror of `invoke_returns_500_when_auth_middleware_did_not_run` —
    // neither principal slot present, extractor maps to a router-wiring
    // bug response. Production `extract_optional_principal` always
    // populates `Option<_>` so this shape never occurs in real traffic.
    let req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ---------------------------------------------------------------------------
// Test 9 — list tasks with principal returns 200 and seeded rows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_tasks_with_principal_returns_200_and_jobs() {
    let (ctx, mocks) = new_ctx();

    // Seed two job rows.
    let job1 = sample_job_row(Uuid::new_v4(), "noop");
    let job2 = sample_job_row(Uuid::new_v4(), "scan");
    mocks.jobs.seed_list(vec![job1.clone(), job2.clone()]);

    let router = build_test_router(ctx);

    let principal = task_admin_principal();
    let mut req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp).await;
    let tasks = body["tasks"].as_array().expect("expected tasks array");
    assert_eq!(tasks.len(), 2);
    let kinds: Vec<&str> = tasks.iter().map(|t| t["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"noop"));
    assert!(kinds.contains(&"scan"));
}

// ---------------------------------------------------------------------------
// Test 10 — list tasks with invalid status filter returns 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_tasks_invalid_status_filter_returns_400() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let principal = task_admin_principal();
    let mut req = Request::get("/api/v1/admin/tasks?status=bogus-status")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Test 11 — get task returns 404 for missing id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_task_returns_404_for_missing_id() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let unknown_id = Uuid::new_v4();
    let principal = task_admin_principal();
    let mut req = Request::get(format!("/api/v1/admin/tasks/{unknown_id}"))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 12 — get task returns 200 for seeded row
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_task_returns_200_for_seeded_row() {
    let (ctx, mocks) = new_ctx();

    let job_id = Uuid::new_v4();
    let row = sample_job_row(job_id, "staging-sweep");
    mocks.jobs.seed_get(row);

    let router = build_test_router(ctx);

    let principal = task_admin_principal();
    let mut req = Request::get(format!("/api/v1/admin/tasks/{job_id}"))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp).await;
    assert_eq!(body["id"].as_str().unwrap(), job_id.to_string());
    assert_eq!(body["kind"].as_str().unwrap(), "staging-sweep");
    assert_eq!(body["status"].as_str().unwrap(), "pending");
}

// ---------------------------------------------------------------------------
// Metric helpers (Tests 13-15) — design §6.2
// ---------------------------------------------------------------------------

type MetricEntry = (
    CompositeKey,
    Option<metrics::Unit>,
    Option<metrics::SharedString>,
    DebugValue,
);

/// Find a counter entry whose name and labels match the given predicates.
/// Returns the counter value if found, or `None`.
fn find_counter<F>(entries: &[MetricEntry], name: &str, label_predicate: F) -> Option<u64>
where
    F: Fn(&[metrics::Label]) -> bool,
{
    entries.iter().find_map(|(ck, _, _, dv)| {
        if ck.kind() != MetricKind::Counter || ck.key().name() != name {
            return None;
        }
        let labels: Vec<metrics::Label> = ck.key().labels().cloned().collect();
        if !label_predicate(&labels) {
            return None;
        }
        match dv {
            DebugValue::Counter(n) => Some(*n),
            _ => None,
        }
    })
}

// ---------------------------------------------------------------------------
// Test 13 — successful enqueue emits result="ok"
// ---------------------------------------------------------------------------
//
// These metric tests use `#[test]` (not `#[tokio::test]`) so they can
// build a dedicated `current_thread` runtime inside the
// `metrics::with_local_recorder` closure. The async-within-sync pattern
// is the canonical approach used throughout this workspace for metric
// emission tests (see `crates/hort-server/tests/metrics_auth.rs`).

#[test]
fn invoke_emits_hort_admin_tasks_enqueued_ok_on_success() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let status = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
                let uc = task_use_case_with_permit(&mocks, events);
                let ctx = with_task_use_case(&ctx, uc);
                let router = build_test_router(ctx);

                let principal = task_admin_principal();
                let mut req = Request::post("/api/v1/admin/tasks/noop")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"label":"item-13-ok"}"#))
                    .unwrap();
                auth_test::inject_principal(&mut req, principal);

                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
    });

    assert_eq!(status, StatusCode::ACCEPTED, "expected 202");

    let entries = snapshotter.snapshot().into_vec();
    let count = find_counter(&entries, "hort_admin_tasks_enqueued_total", |labels| {
        labels
            .iter()
            .any(|l| l.key() == "kind" && l.value() == "noop")
            && labels
                .iter()
                .any(|l| l.key() == "result" && l.value() == "ok")
    });
    assert_eq!(
        count,
        Some(1),
        "expected hort_admin_tasks_enqueued_total{{kind=noop,result=ok}}=1, entries: {entries:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 14 — RBAC denial emits result="rbac_denied"
// ---------------------------------------------------------------------------

#[test]
fn invoke_emits_hort_admin_tasks_enqueued_rbac_denied() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    // Build a principal with a role that has no AdminTaskInvoke grant.
    // The default `new_ctx()` RBAC has no grants at all — any principal
    // will be denied.
    let principal = CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "rbac-denied-user".into(),
        username: "rbac-denied-user".into(),
        email: "denied@example.com".into(),
        // A non-`admin`, non-`task-admin` claim; the empty-grant
        // evaluator denies it (flat claims model, see ADR 0012).
        claims: vec!["some-unprivileged-role".into()],
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    };

    let status = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                // Use the default deny-all context (no AdminTaskInvoke grant).
                let (ctx, _mocks) = build_mock_ctx(handle);
                let router = build_test_router(ctx);

                let mut req = Request::post("/api/v1/admin/tasks/noop")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap();
                auth_test::inject_principal(&mut req, principal);

                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
    });

    assert_eq!(status, StatusCode::FORBIDDEN, "expected 403");

    let entries = snapshotter.snapshot().into_vec();
    let count = find_counter(&entries, "hort_admin_tasks_enqueued_total", |labels| {
        labels
            .iter()
            .any(|l| l.key() == "kind" && l.value() == "noop")
            && labels
                .iter()
                .any(|l| l.key() == "result" && l.value() == "rbac_denied")
    });
    assert_eq!(
        count,
        Some(1),
        "expected hort_admin_tasks_enqueued_total{{kind=noop,result=rbac_denied}}=1, \
         entries: {entries:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 15 — invalid params emit result="validation_error"
// ---------------------------------------------------------------------------

#[test]
fn invoke_emits_hort_admin_tasks_enqueued_validation_error() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    // 257-byte label triggers NoopParams::validate() → ValidationError.
    let long_label = "x".repeat(257);
    let body_str = json!({ "label": long_label }).to_string();

    let status = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
                let uc = task_use_case_with_permit(&mocks, events);
                let ctx = with_task_use_case(&ctx, uc);
                let router = build_test_router(ctx);

                let principal = task_admin_principal();
                let mut req = Request::post("/api/v1/admin/tasks/noop")
                    .header("content-type", "application/json")
                    .body(Body::from(body_str))
                    .unwrap();
                auth_test::inject_principal(&mut req, principal);

                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
    });

    // DomainError::Validation maps to 400 Bad Request via ApiError.
    assert_eq!(status, StatusCode::BAD_REQUEST, "expected 400");

    let entries = snapshotter.snapshot().into_vec();
    let count = find_counter(&entries, "hort_admin_tasks_enqueued_total", |labels| {
        labels
            .iter()
            .any(|l| l.key() == "kind" && l.value() == "noop")
            && labels
                .iter()
                .any(|l| l.key() == "result" && l.value() == "validation_error")
    });
    assert_eq!(
        count,
        Some(1),
        "expected hort_admin_tasks_enqueued_total{{kind=noop,result=validation_error}}=1, \
         entries: {entries:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 16 — use-case enqueue error from the jobs repository emits
//           result="validation_error" for DomainError::Validation
// ---------------------------------------------------------------------------

#[test]
fn invoke_emits_validation_error_when_use_case_returns_validation_domain_error() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let status = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
                let uc = task_use_case_with_permit(&mocks, events);
                let ctx = with_task_use_case(&ctx, uc);

                // Configure the jobs mock to return a DomainError::Validation on enqueue.
                mocks
                    .jobs
                    .fail_next_enqueue(DomainError::Validation("repo-level validation".into()));

                let router = build_test_router(ctx);

                let principal = task_admin_principal();
                let mut req = Request::post("/api/v1/admin/tasks/noop")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap();
                auth_test::inject_principal(&mut req, principal);

                let resp = router.oneshot(req).await.unwrap();
                resp.status()
            })
    });

    assert_eq!(status, StatusCode::BAD_REQUEST, "expected 400");

    let entries = snapshotter.snapshot().into_vec();
    let count = find_counter(&entries, "hort_admin_tasks_enqueued_total", |labels| {
        labels
            .iter()
            .any(|l| l.key() == "kind" && l.value() == "noop")
            && labels
                .iter()
                .any(|l| l.key() == "result" && l.value() == "validation_error")
    });
    assert_eq!(
        count,
        Some(1),
        "expected hort_admin_tasks_enqueued_total{{kind=noop,result=validation_error}}=1 \
         when use case returns DomainError::Validation; entries: {entries:?}"
    );
}

// ---------------------------------------------------------------------------
// Production-shape regression tests
//
// The existing list/get tests above use `auth_test::inject_principal`, which
// writes the BARE `AuthenticatedPrincipal` extension — the shape the
// `require_principal` middleware produces on POST/PUT/DELETE/PATCH paths.
//
// Production routes `GET /api/v1/admin/tasks*` through
// `extract_optional_principal` (see `hort_http_core::router::auth_dispatch`),
// which produces `Option<AuthenticatedPrincipal>` instead. The tests below
// inject in the production GET shape to pin the slot-reading contract that
// the handlers depend on. Without these, a regression to the old
// `Option<Extension<AuthenticatedPrincipal>>` pattern would 403 every
// authenticated GET in production while the bare-slot tests above continued
// to pass — exactly the bug surfaced 2026-05-11.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_tasks_with_optional_principal_some_returns_200() {
    let (ctx, mocks) = new_ctx();
    let job = sample_job_row(Uuid::new_v4(), "noop");
    mocks.jobs.seed_list(vec![job]);

    let router = build_test_router(ctx);

    let principal = task_admin_principal();
    let mut req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET routes through extract_optional_principal in production — \
         the handler must accept Option<AuthenticatedPrincipal>=Some shape"
    );
}

#[tokio::test]
async fn list_tasks_with_optional_principal_none_returns_401() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let mut req = Request::get("/api/v1/admin/tasks")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_none(&mut req);

    let resp = router.oneshot(req).await.unwrap();
    // The canonical "auth ran, no token" response is 401 + Bearer
    // challenge so OCI clients can dance through the token endpoint.
    // Same shape an admin-tasks GET should produce when the middleware
    // ran and no token was presented.
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_task_with_optional_principal_some_returns_200() {
    let (ctx, mocks) = new_ctx();
    let job_id = Uuid::new_v4();
    let row = sample_job_row(job_id, "staging-sweep");
    mocks.jobs.seed_get(row);

    let router = build_test_router(ctx);

    let principal = task_admin_principal();
    let mut req = Request::get(format!("/api/v1/admin/tasks/{job_id}"))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET routes through extract_optional_principal in production — \
         the handler must accept Option<AuthenticatedPrincipal>=Some shape"
    );
}

#[tokio::test]
async fn get_task_with_optional_principal_none_returns_401() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let unknown_id = Uuid::new_v4();
    let mut req = Request::get(format!("/api/v1/admin/tasks/{unknown_id}"))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_none(&mut req);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Authz runs BEFORE param-validate + idempotency
// ---------------------------------------------------------------------------

/// An unauthorized caller submitting an **invalid** param body must get
/// the authz `403` — NOT the param-validation `400`. Proves the RBAC
/// check moved ahead of `params.validate()` (the pre-fix order returned
/// 400 because validation ran first). Default `new_ctx` wires a
/// deny-everything `TaskUseCase`.
#[tokio::test]
async fn invoke_unauthorized_with_invalid_params_returns_403_not_400() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    // 257-byte label → would fail params.validate() with 400 if validation
    // ran first. Principal lacks `task-admin` → deny-all use case denies.
    let long_label = "x".repeat(257);
    let body = json!({ "label": long_label }).to_string();
    let principal = task_admin_principal(); // claims=["task-admin"], but ctx RBAC has zero grants
    let mut req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "authz must run before param-validate: expected 403, got {}",
        resp.status()
    );
    assert!(
        mocks.jobs.enqueue_calls().is_empty(),
        "enqueue must never run for an unauthorized caller"
    );
}

/// An unauthorized caller whose `Idempotency-Key` is already cached must
/// get the authz `403` — NOT the idempotency `200` cache-hit. Proves the
/// RBAC check moved ahead of the attacker-controlled ephemeral-store
/// probe (pre-fix order returned 200 from the cache before authz).
#[tokio::test]
async fn invoke_unauthorized_does_not_probe_idempotency_store() {
    let (ctx, mocks) = new_ctx();

    // Pre-seed a cache entry the buggy (pre-authz) lookup would hit.
    let seeded_job_id = Uuid::new_v4();
    let idem_key = "attacker-controlled-key-001";
    let store_key = format!("idem-task:{idem_key}");
    mocks
        .ephemeral_durable
        .put(
            &store_key,
            Bytes::copy_from_slice(seeded_job_id.as_bytes()),
            Duration::from_secs(300),
        )
        .await
        .expect("pre-seed failed");

    let router = build_test_router(ctx);

    let principal = task_admin_principal(); // deny-all ctx RBAC → unauthorized
    let mut req = Request::post("/api/v1/admin/tasks/noop")
        .header("content-type", "application/json")
        .header("Idempotency-Key", idem_key)
        .body(Body::from("{}"))
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "authz must run before the idempotency-store probe: expected 403, \
         got {} (a 200 means the cache was consulted pre-authz)",
        resp.status()
    );
    assert!(
        mocks.jobs.enqueue_calls().is_empty(),
        "enqueue must never run for an unauthorized caller"
    );
}

/// A destructive kind (`retention-purge`) invoked by a caller holding
/// `AdminTaskInvoke` but NOT the `task:destructive` claim is rejected
/// `403` at the handler boundary (per-kind destructive-claim tier).
#[tokio::test]
async fn invoke_destructive_kind_without_destructive_claim_returns_403() {
    let (ctx, mocks) = new_ctx();
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    // Permit grants AdminTaskInvoke to `task-admin` callers only — no
    // `task:destructive` claim is carried by `task_admin_principal()`.
    let uc = task_use_case_with_permit(&mocks, events);
    let ctx = with_task_use_case(&ctx, uc);
    let router = build_test_router(ctx);

    let principal = task_admin_principal();
    let mut req = Request::post("/api/v1/admin/tasks/retention-purge")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    auth_test::inject_principal(&mut req, principal);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "destructive kind without task:destructive claim must be 403"
    );
    assert!(
        mocks.jobs.enqueue_calls().is_empty(),
        "destructive enqueue must not run without the claim"
    );
}
