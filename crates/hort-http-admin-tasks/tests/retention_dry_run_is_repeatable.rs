//! The operator-visible half of the destructive-invocation idempotency
//! rule (ADR 0028): what a second `POST /api/v1/admin/tasks/retention-evaluate`
//! in the same UTC day actually returns.
//!
//! The sibling guard
//! (`destructive_kinds_carry_db_idempotency.rs`) pins the *argument* the
//! handler passes to `TaskUseCase::enqueue`. That is necessary and not
//! sufficient: the argument only matters because of what the database
//! then does with it. These tests drive the same handler against a jobs
//! mock configured to emulate the `jobs_idempotency_key_uq` partial
//! unique index — first call with a key inserts, later calls with that
//! key resolve to the first row, an unkeyed call always inserts — and
//! assert the status code and job id an operator receives.
//!
//! # The workflow this protects
//!
//! `hort-cli admin retention apply --from-preview <A>` takes a fresh
//! preview immediately before executing, precisely so it can show what
//! moved between the proposal the operator read and the world as it is
//! now. When a preview carries a durable per-UTC-day key, that fresh
//! preview is deduplicated back to job A: the delta is A against A, so it
//! is always empty, and the operator reads "nothing changed" and then
//! authorises an execution computed from different data. Previewing first
//! is what guarantees the collision, so it fired on every day the
//! intended workflow was followed.
//!
//! A dry run destroys nothing, so it takes no single-flight claim and
//! stays repeatable. An execution still takes one: re-firing a
//! destructive sweep after a controller restart is the hazard ADR 0028
//! exists for, and that is unchanged.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
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

use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_task_use_case, MockPorts};

const RETENTION_EVALUATE: &str = "/api/v1/admin/tasks/retention-evaluate";

/// A router whose jobs port deduplicates on `idempotency_key` exactly as
/// the partial unique index does, so a test observes the outcome an
/// operator would see rather than the argument the handler passed.
fn router_with_index_emulation() -> (axum::Router, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    let (ctx, mocks) = build_mock_ctx(handle);
    mocks.jobs.enforce_idempotency_keys();

    let grant = PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec!["task-admin".into()]),
        repository_id: None,
        permission: Permission::AdminTaskInvoke,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    };
    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
        grant,
    ])));
    let events = hort_app::event_store_publisher::wrap_for_test(mocks.events.clone());
    let uc = Arc::new(TaskUseCase::new(mocks.jobs.clone(), events, rbac));
    let ctx = with_task_use_case(&ctx, uc);

    let router = axum::Router::new()
        .nest("/api/v1/admin/tasks", hort_http_admin_tasks::router())
        .with_state(ctx);
    (router, mocks)
}

fn principal(claims: &[&str]) -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "retention-operator".into(),
        username: "retention-operator".into(),
        email: "retention@example.com".into(),
        claims: claims.iter().map(|c| (*c).to_string()).collect(),
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

/// Holds `task:destructive` — may execute as well as observe.
fn executing_operator() -> CallerPrincipal {
    principal(&["task-admin", "task:destructive"])
}

/// Holds only the coarse admin-task permission — may observe, not execute.
fn observing_operator() -> CallerPrincipal {
    principal(&["task-admin"])
}

/// Fire one invocation and return `(status, task_job_id)`. `task_job_id`
/// is `None` when the response carries no body worth reading (a denial).
async fn invoke(
    router: &axum::Router,
    mode: &str,
    caller: CallerPrincipal,
) -> (StatusCode, Option<Uuid>) {
    let mut req = Request::post(RETENTION_EVALUATE)
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"mode":"{mode}"}}"#)))
        .expect("valid request");
    auth_test::inject_principal(&mut req, caller);

    let resp = router.clone().oneshot(req).await.expect("router responded");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 32 * 1024).await.expect("body");
    let job_id = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v["task_job_id"].as_str().and_then(|s| s.parse().ok()));
    (status, job_id)
}

// ---------------------------------------------------------------------------
// A dry run is repeatable
// ---------------------------------------------------------------------------

/// Two previews in one UTC day are two sweeps. `202` both times, two
/// distinct job ids: an observation has nothing to single-flight, and a
/// preview that cannot be repeated cannot answer "has anything moved?".
#[tokio::test]
async fn two_previews_in_one_utc_day_are_two_jobs_and_two_202s() {
    let (router, mocks) = router_with_index_emulation();

    let (first_status, first_job) = invoke(&router, "dry_run", observing_operator()).await;
    let (second_status, second_job) = invoke(&router, "dry_run", observing_operator()).await;

    assert_eq!(first_status, StatusCode::ACCEPTED);
    assert_eq!(
        second_status,
        StatusCode::ACCEPTED,
        "the second preview of a UTC day must be accepted as a fresh sweep, not \
         answered 200 with the first one's job",
    );
    let (first_job, second_job) = (
        first_job.expect("first job id"),
        second_job.expect("second job id"),
    );
    assert_ne!(
        first_job, second_job,
        "two previews must be two jobs; the same id back means the server handed \
         over a stale observation as if it were fresh",
    );

    let keys = mocks.jobs.enqueue_idem_keys();
    assert_eq!(keys.len(), 2, "both previews reached the jobs port");
    assert!(
        keys.iter().all(Option::is_none),
        "a dry run must claim no durable idempotency key: {keys:?}",
    );
}

/// The exact `apply --from-preview <A>` sequence: the operator's preview,
/// then the fresh preview `apply` takes immediately before executing,
/// then the execution itself.
///
/// The fresh preview must be its own sweep — a delta computed against a
/// job that *is* the baseline is empty by construction, which reads as
/// "nothing changed since you looked" no matter what actually changed.
#[tokio::test]
async fn apply_from_preview_compares_a_fresh_sweep_not_the_preview_it_names() {
    let (router, mocks) = router_with_index_emulation();

    // 1. `hort-cli admin retention preview` — the proposal the operator reads.
    let (baseline_status, baseline) = invoke(&router, "dry_run", executing_operator()).await;
    // 2. `apply --from-preview <baseline>` re-measures before executing.
    let (fresh_status, fresh) = invoke(&router, "dry_run", executing_operator()).await;
    // 3. ... and only then executes.
    let (execute_status, executed) = invoke(&router, "execute", executing_operator()).await;

    assert_eq!(baseline_status, StatusCode::ACCEPTED);
    assert_eq!(fresh_status, StatusCode::ACCEPTED);
    assert_eq!(execute_status, StatusCode::ACCEPTED);

    let baseline = baseline.expect("baseline job id");
    let fresh = fresh.expect("fresh job id");
    let executed = executed.expect("execute job id");
    assert_ne!(
        baseline, fresh,
        "the pre-execution re-measure must be a new sweep, or the delta apply \
         renders is the baseline diffed against itself",
    );
    assert_ne!(executed, baseline);
    assert_ne!(executed, fresh);

    let keys = mocks.jobs.enqueue_idem_keys();
    assert_eq!(keys.len(), 3);
    assert!(keys[0].is_none(), "the operator's preview is unkeyed");
    assert!(keys[1].is_none(), "apply's fresh preview is unkeyed");
    assert!(
        keys[2]
            .as_ref()
            .is_some_and(|k| k.as_str().contains(":execute:")),
        "the execution keeps its per-UTC-day key, mode segment included: {:?}",
        keys[2],
    );
}

// ---------------------------------------------------------------------------
// An execution is still single-flighted
// ---------------------------------------------------------------------------

/// The property the fix must not regress: a second execution in the same
/// UTC day is still deduplicated, still answers `200`, and still returns
/// the earlier job. The cron schedule is the retry mechanism; re-firing a
/// destructive sweep inside the day is the hazard ADR 0028 closes.
#[tokio::test]
async fn a_second_execution_in_one_utc_day_is_still_deduplicated() {
    let (router, _mocks) = router_with_index_emulation();

    let (first_status, first_job) = invoke(&router, "execute", executing_operator()).await;
    let (second_status, second_job) = invoke(&router, "execute", executing_operator()).await;

    assert_eq!(first_status, StatusCode::ACCEPTED);
    assert_eq!(
        second_status,
        StatusCode::OK,
        "a second execution in one UTC day is a dedup hit, answered 200",
    );
    assert_eq!(
        second_job, first_job,
        "the dedup hit must return the job the first execution created",
    );
}

/// A preview and an execution in the same UTC day stay independent jobs:
/// previewing must never suppress the execution that follows it.
#[tokio::test]
async fn a_preview_does_not_suppress_the_execution_that_follows_it() {
    let (router, _mocks) = router_with_index_emulation();

    let (preview_status, preview_job) = invoke(&router, "dry_run", executing_operator()).await;
    let (execute_status, execute_job) = invoke(&router, "execute", executing_operator()).await;

    assert_eq!(preview_status, StatusCode::ACCEPTED);
    assert_eq!(
        execute_status,
        StatusCode::ACCEPTED,
        "the execution is a fresh job, not a dedup hit on the preview",
    );
    assert_ne!(preview_job, execute_job);
}

// ---------------------------------------------------------------------------
// The two consumers of the one decision
// ---------------------------------------------------------------------------

/// The `task:destructive` claim gate and the durable-key derivation read
/// the same answer to "will this invocation destroy anything?", so they
/// cannot disagree about any mode.
///
/// For each mode this observes both answers independently — whether a
/// caller lacking `task:destructive` is refused, and whether the handler
/// claims a durable key — and asserts they moved together. Re-deriving
/// either answer next to the other, which is how they came apart in the
/// first place, fails here as soon as the two derivations differ for any
/// mode: the gate would refuse a call the key treats as harmless, or the
/// key would single-flight a call the gate waves through.
#[tokio::test]
async fn the_claim_gate_and_the_key_derivation_cannot_disagree() {
    for mode in ["execute", "dry_run"] {
        // Answer 1 — does this invocation need the destructive claim?
        let (router, _) = router_with_index_emulation();
        let (status, _) = invoke(&router, mode, observing_operator()).await;
        let claim_required = match status {
            StatusCode::FORBIDDEN => true,
            StatusCode::ACCEPTED => false,
            other => panic!("mode {mode:?}: unexpected status {other} for an observing caller"),
        };

        // Answer 2 — does this invocation claim the durable key?
        let (router, mocks) = router_with_index_emulation();
        let (status, _) = invoke(&router, mode, executing_operator()).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "mode {mode:?}: a fully authorised caller must be accepted",
        );
        let keys = mocks.jobs.enqueue_idem_keys();
        assert_eq!(keys.len(), 1);
        let key_claimed = keys[0].is_some();

        assert_eq!(
            claim_required, key_claimed,
            "mode {mode:?}: the destructive-claim gate says {claim_required} and the \
             durable-key derivation says {key_claimed}. Both must read the one \
             `task_invocation_is_destructive` answer; a second derivation beside the \
             first is what let a dry run take a single-flight key it has no reason \
             to hold.",
        );
    }
}
