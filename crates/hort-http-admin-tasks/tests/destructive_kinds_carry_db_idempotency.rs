//! Anti-regression guard: every destructive **invocation** MUST reach
//! `TaskUseCase::enqueue` with `Some(IdempotencyKey)` so the DB
//! partial-unique-index single-flight invariant fires, and nothing else
//! may. The idempotency contract is documented in
//! `how-to/using-hort-cli-with-admin-ops.md` and ADR 0028.
//!
//! # Why this guard exists (load-bearing)
//!
//! The rule is structural, and it is stated over the invocation rather
//! than over the kind:
//!
//! ```text
//! task_invocation_is_destructive(P::KIND, params) == true
//!     <=> db_idempotency_key.is_some()
//! ```
//!
//! It is an equivalence, not an implication, in both directions for a
//! reason. The key is a single-flight claim on *destroying something*: a
//! destructive invocation that slips through without one can re-fire
//! after a controller restart, and a non-destructive one that takes one
//! makes itself unrepeatable for the rest of the UTC day. A retention
//! preview that cannot be re-run is how a second preview silently hands
//! back the first one's observation, so `apply` compares a proposal
//! against itself and reports "nothing changed" while the execute step
//! works from different data.
//!
//! The coarser `task_kind_is_destructive(P::KIND)` is deliberately NOT
//! the predicate here. It stays correct for audit routing — a dry run's
//! `TaskInvoked` still belongs on the never-deleted destructive-kind
//! stream — but `retention-evaluate` carries a mode, and only `execute`
//! destroys anything.
//!
//! The guard walks the **closed** `DESTRUCTIVE_TASK_KINDS` set
//! (`crates/hort-domain/src/events/authorization_events.rs`) and drives
//! the real handler for each through `tower::ServiceExt::oneshot`,
//! asserting the mocked `enqueue_task` received the key the invocation's
//! own classification calls for. The walker posts `{}` for every kind,
//! which is exactly what the shipped CronJob posts: `retention-evaluate`
//! reads an absent `mode` as `execute`, so every kind in the walk is a
//! destructive invocation and every one of them must carry a key. Read
//! the walker's pass as "the default invocation of each destructive kind
//! is keyed", not as "the kind is keyed" — the mode-split side is pinned
//! by `retention_preview_takes_no_durable_key_and_execute_keeps_its_own`
//! below.
//!
//! Closed-set semantics: a future addition to `DESTRUCTIVE_TASK_KINDS`
//! automatically extends this guard's coverage — adding a fourth
//! destructive kind without wiring the server-derived key path through
//! `invoke.rs` fails this test before the kind can ship.
//!
//! Mirrors the closed-set walker shape from
//! `crates/hort-server/tests/task_use_case_enqueue_real_db.rs:154,165-185`
//! (the `ADMIN_INVOKABLE_TASK_KINDS` walker) but stays at the HTTP layer (mocked
//! ports — no real DB) because the contract here is between the handler
//! and the use-case port, not between the use case and Postgres.
//!
//! # What this does NOT guard
//!
//! - Non-destructive **kinds** passing `None` — covered by a separate
//!   spot test below (`invoke_noop_passes_none_db_idempotency_key`); not
//!   part of the closed-set walker (the closure is over the *destructive*
//!   set, by design).
//! - The operator-visible consequences of the rule (two previews are two
//!   jobs and two `202`s; a second execution is still deduplicated) —
//!   pinned by `retention_dry_run_is_repeatable.rs`, which drives the
//!   handler against a jobs mock that emulates the partial unique index.
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
/// `cron:<kind>:<YYYY-MM-DD>`, except retention evaluation, whose mode is
/// an explicit key segment.
///
/// Every request in the walk posts `{}` — the shipped CronJob's body —
/// so `retention-evaluate` resolves to `execute` and the whole walk is a
/// walk over *destructive invocations*. That is why each iteration
/// expects a key: not because its kind is destructive, but because the
/// default invocation of that kind is.
///
/// Closed-set semantics: adding a fourth destructive kind to
/// `DESTRUCTIVE_TASK_KINDS` without routing the new kind through the
/// `task_invocation_is_destructive` branch in `invoke.rs` fails this test
/// on the new iteration.
#[tokio::test]
async fn destructive_kinds_carry_db_idempotency() {
    // The closed set is non-empty — this is the same invariant the
    // ADMIN_INVOKABLE_TASK_KINDS walker pins for its closed-set guarantee.
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
        let expected = |day: &str| {
            if *kind == "retention-evaluate" {
                format!("cron:{kind}:execute:{day}")
            } else {
                format!("cron:{kind}:{day}")
            }
        };
        let acceptable_keys: Vec<String> = if before == after {
            vec![expected(&before)]
        } else {
            // Midnight UTC rollover landed inside the test — accept
            // both same-day shapes. Vanishingly rare; the explicit
            // handling makes the guard non-flaky.
            vec![expected(&before), expected(&after)]
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
                "destructive kind {kind:?}: an empty body is a destructive invocation of \
                 this kind, and the handler MUST pass Some(idempotency_key) for one to \
                 TaskUseCase::enqueue (see how-to/using-hort-cli-with-admin-ops.md + \
                 ADR 0028 for the destructive-invocation idempotency contract). \
                 The closed-set DESTRUCTIVE_TASK_KINDS walker fired this assertion, so a \
                 future destructive kind needs the same server-derived key wiring \
                 in crates/hort-http-admin-tasks/src/handlers/invoke.rs:Step 4b."
            )
        });
        assert!(
            acceptable_keys.iter().any(|k| k == key.as_str()),
            "destructive kind {kind:?}: key shape mismatch. Expected one of {acceptable_keys:?}, \
             got {key_str:?}. The server-derived per-day shape is required \
             to be distinct from the client's `<window>:<kind>` shape so the \
             Redis and DB layers cannot collide on a key.",
            key_str = key.as_str(),
        );
    }
}

/// The mode-split side of the rule: a retention preview is an
/// observation, so it takes **no** durable key at all, while an execution
/// keeps the per-UTC-day key it has always had, mode segment included.
///
/// This is the half the closed-set walker above cannot see (it posts `{}`
/// for every kind, which is `execute`). It is also the half that makes
/// the preview repeatable: with no key there is nothing for the partial
/// unique index to collide with, so a second preview in the same UTC day
/// is a second sweep rather than the first one handed back.
///
/// The mode stays in the execute key even though no other mode now
/// reaches that branch — it names the dimension the key separates on, so
/// a second kind gaining a mode cannot silently collapse two invocations
/// onto one key.
#[tokio::test]
async fn retention_preview_takes_no_durable_key_and_execute_keeps_its_own() {
    let (ctx, mocks) = new_ctx();
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    let uc = task_use_case_permit_destructive(&mocks, events);
    let ctx = with_task_use_case(&ctx, uc);
    let router = build_test_router(ctx);

    let before = Utc::now().format("%Y-%m-%d").to_string();

    let mut preview = Request::post("/api/v1/admin/tasks/retention-evaluate")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"mode":"dry_run"}"#))
        .expect("request");
    auth_test::inject_principal(&mut preview, ordinary_principal());
    assert_eq!(
        router.clone().oneshot(preview).await.unwrap().status(),
        StatusCode::ACCEPTED
    );

    let mut execute = Request::post("/api/v1/admin/tasks/retention-evaluate")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"mode":"execute"}"#))
        .expect("request");
    auth_test::inject_principal(&mut execute, destructive_principal());
    assert_eq!(
        router.oneshot(execute).await.unwrap().status(),
        StatusCode::ACCEPTED
    );

    let after = Utc::now().format("%Y-%m-%d").to_string();

    let keys = mocks.jobs.enqueue_idem_keys();
    assert_eq!(keys.len(), 2);
    assert!(
        keys[0].is_none(),
        "a dry run is not destructive and must reach enqueue with NO durable key; \
         got Some({:?}). A key here makes the second preview of a UTC day a \
         deduplicated echo of the first.",
        keys[0],
    );
    let execute_key = keys[1]
        .as_ref()
        .expect("an execution keeps its key")
        .as_str();
    let acceptable = [
        format!("cron:retention-evaluate:execute:{before}"),
        // Midnight UTC can roll over mid-test; both same-day shapes pass.
        format!("cron:retention-evaluate:execute:{after}"),
    ];
    assert!(
        acceptable.contains(&execute_key.to_owned()),
        "the execute key shape is unchanged by the preview fix. \
         Expected one of {acceptable:?}, got {execute_key:?}",
    );
}

// ---------------------------------------------------------------------------
// Spot test — non-destructive kinds pass `None`
// ---------------------------------------------------------------------------

/// Acceptance (7b): for at least one non-destructive kind (`noop`), the
/// handler passes `idempotency_key = None`. Pins the negative side of
/// the `task_invocation_is_destructive` branch for a kind that has no
/// mode at all — without it, a future change that always passes
/// `Some(...)` would still pass the closed-set walker above.
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
