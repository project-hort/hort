//! `replay-seen-prune` TaskHandler (federated-JWT replay guard, the
//! cleanup half). TTL & cleanup run as a periodic delete-expired
//! admin/worker task; the `replay-seen-prune` CronJob is
//! **default-ENABLED**.
//!
//! Triggered by the k8s CronJob (or operator host cron) hitting
//! `POST /api/v1/admin/tasks/replay-seen-prune` (the admin-task
//! framework). The handler is a thin orchestration step: one call to
//! [`ReplaySeenPrunePort::prune_expired`], which deletes every
//! `jwt_replay_seen` row whose `expires_at` is in the past, and a
//! result-summary carrying the deleted-row count.
//!
//! # Cleanup degrades SAFE
//!
//! The danger pattern is a *fail-open*
//! evictable cache amplifying load. Here the opposite holds — if the
//! prune never runs the table only grows; the seen-set never *forgets*
//! a recorded `jti`/composite within its TTL window, so a
//! stale-but-present row still correctly reports `Replayed`. A cleanup
//! outage costs storage, **not** security. Therefore a prune failure is
//! a `warn!` + `TaskOutcome::fail(reason, retry: true)` (retry on the
//! next CronJob tick) — it must **never** fail the worker hard or be
//! treated as an ERROR. This matches the `staging-sweep` sibling's
//! posture exactly (`list` failure → `Failed { retry: true }`).
//!
//! # Cadence / default-ENABLED divergence
//!
//! The `hort_svc_*` CronJob-template convention is **default-
//! disabled**. The `replay-seen-prune` CronJob is the justified
//! exception: a never-pruned `jwt_replay_seen` is a
//! pure storage-growth liability and the prune has **no security
//! effect either way** (the seen-set never forgets within TTL; pruning
//! only reclaims storage of already-expired rows the validator would
//! reject as `Expired` upstream anyway). So the chart ships it
//! enabled-by-default — see `deploy/helm/hort-server/values.yaml`
//! (`cronJobs.replaySeenPrune.enabled: true`) and
//! `cronjob-replay-seen-prune.yaml`.
//!
//! # Observability
//!
//! `info!` on a successful prune (security-relevant maintenance — the
//! deleted-row count, no key material); `warn!` on a prune failure
//! (cleanup degrades safe, the worker retries — **not** `error!`).
//! `#[tracing::instrument(skip(self))]` WITHOUT `err` (a prune failure
//! is a `TaskOutcome::Failed`, not a `Result::Err`; it is explicitly NOT
//! an ERROR-level condition). **No new metric**: only
//! `hort_jwt_replay_rejected_total` (the guard's metric, emitted in
//! `hort-app` at the claim site, not here) is tracked. A prune-outage
//! gauge is a *recommended-but-optional* follow-on, **not mandated** —
//! inventing one here without a catalog row would violate the
//! metrics-catalog hard rule, so it is deliberately not added.

use std::sync::Arc;

use hort_domain::error::DomainResult;
use hort_domain::ports::replay_seen_prune::ReplaySeenPrunePort;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use serde_json::json;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] that runs a single seen-set TTL-prune tick.
///
/// Constructed at composition time with the one port it touches
/// ([`ReplaySeenPrunePort`], implemented by the Postgres
/// `PgReplayGuardRepository`). The k8s CronJob drives cadence by
/// POSTing to `/api/v1/admin/tasks/replay-seen-prune`; this handler
/// runs ONE delete-expired tick per call.
pub struct ReplaySeenPruneHandler {
    prune: Arc<dyn ReplaySeenPrunePort>,
}

impl ReplaySeenPruneHandler {
    /// Construct the handler from its single port dependency.
    pub fn new(prune: Arc<dyn ReplaySeenPrunePort>) -> Self {
        Self { prune }
    }
}

impl TaskHandler for ReplaySeenPruneHandler {
    fn kind(&self) -> &'static str {
        "replay-seen-prune"
    }

    #[tracing::instrument(skip(self, _params, _ctx))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            match self.prune.prune_expired().await {
                Ok(deleted) => {
                    // Security-relevant maintenance → info!. Count only;
                    // never any key/jti material (none is available here
                    // anyway — the port returns a bare row count).
                    tracing::info!(
                        deleted_rows = deleted,
                        "replay-seen-prune: deleted expired jwt_replay_seen rows"
                    );
                    Ok(TaskOutcome::Completed {
                        result_summary: json!({ "deleted_rows": deleted }),
                    })
                }
                Err(err) => {
                    // Cleanup degrades SAFE: a missed prune only grows
                    // the table — the seen-set never forgets a recorded
                    // replay within TTL. So this is warn! +
                    // retry-on-next-tick, NEVER error! and NEVER a hard
                    // worker failure.
                    tracing::warn!(
                        error = %err.unavailable_cause(),
                        "replay-seen-prune: prune failed; cleanup degrades safe \
                         (seen-set still authoritative — only storage grows); \
                         will retry on next tick"
                    );
                    Ok(TaskOutcome::fail(
                        format!("replay-seen prune failed: {}", err.unavailable_cause()),
                        true,
                    ))
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Local helper — extract the non-sensitive cause string from the shared
// ReplayGuardError without depending on its Display (the error enum has
// a single Unavailable variant; pattern-matching keeps this resilient if
// the cause field ever moves, and avoids a Display impl assumption).
// ---------------------------------------------------------------------------

trait UnavailableCause {
    fn unavailable_cause(&self) -> &str;
}

impl UnavailableCause for hort_domain::ports::replay_guard::ReplayGuardError {
    fn unavailable_cause(&self) -> &str {
        match self {
            hort_domain::ports::replay_guard::ReplayGuardError::Unavailable(c) => c,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use hort_domain::ports::replay_guard::ReplayGuardError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    // ---------------- Mock ReplaySeenPrunePort ------------------------------

    /// Mock that returns a programmed `prune_expired` outcome and counts
    /// how many times it was invoked (the handler must call it exactly
    /// once per tick).
    struct MockPrune {
        outcome: Result<u64, ReplayGuardError>,
        calls: AtomicUsize,
    }

    impl MockPrune {
        fn ok(deleted: u64) -> Self {
            Self {
                outcome: Ok(deleted),
                calls: AtomicUsize::new(0),
            }
        }

        fn unavailable(msg: &str) -> Self {
            Self {
                outcome: Err(ReplayGuardError::Unavailable(msg.to_string())),
                calls: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ReplaySeenPrunePort for MockPrune {
        fn prune_expired(&self) -> BoxFuture<'_, Result<u64, ReplayGuardError>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let r = self.outcome.clone();
            Box::pin(async move { r })
        }
    }

    fn make_handler(mock: Arc<MockPrune>) -> ReplaySeenPruneHandler {
        ReplaySeenPruneHandler::new(mock as Arc<dyn ReplaySeenPrunePort>)
    }

    fn test_job_row() -> JobRow {
        let now = Utc::now();
        JobRow {
            id: Uuid::nil(),
            kind: "replay-seen-prune".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id: None,
            priority: 0,
            trigger_source: "cron".to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    fn make_context() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: test_job_row(),
        }
    }

    // =====================================================================
    // kind() returns the exact kebab literal the migration + CronJob use
    // =====================================================================

    #[test]
    fn kind_returns_replay_seen_prune() {
        let handler = make_handler(Arc::new(MockPrune::ok(0)));
        assert_eq!(handler.kind(), "replay-seen-prune");
    }

    // =====================================================================
    // The handler dispatches prune_expired exactly once and reports the
    // deleted-row count in the result summary.
    // =====================================================================

    #[tokio::test]
    async fn run_dispatches_prune_and_reports_deleted_count() {
        let mock = Arc::new(MockPrune::ok(7));
        let handler = make_handler(mock.clone());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("handler run is infallible (degrades via TaskOutcome)");

        assert_eq!(
            mock.call_count(),
            1,
            "prune_expired must be invoked exactly once per tick"
        );
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["deleted_rows"], 7);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_completes_with_zero_when_nothing_expired() {
        let mock = Arc::new(MockPrune::ok(0));
        let handler = make_handler(mock.clone());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("handler run is infallible");

        assert_eq!(mock.call_count(), 1);
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["deleted_rows"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Cleanup-error path degrades SAFE: the worker is NOT failed hard —
    // the handler returns Ok(Failed { retry: true }) so the CronJob
    // retries on the next tick and the seen-set stays authoritative.
    // =====================================================================

    #[tokio::test]
    async fn run_degrades_safe_on_prune_failure() {
        let mock = Arc::new(MockPrune::unavailable("connection refused"));
        let handler = make_handler(mock.clone());

        // `run` returns Ok (NOT Err) — a prune outage must never
        // propagate as a Result::Err that fails the worker.
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("prune failure must NOT surface as Result::Err (degrades safe)");

        assert_eq!(mock.call_count(), 1);
        match outcome {
            TaskOutcome::Failed { reason, retry } => {
                assert!(retry, "a prune outage must be retried on the next tick");
                assert!(
                    reason.contains("connection refused"),
                    "reason should carry the non-sensitive cause: {reason}"
                );
            }
            other => panic!("expected Failed {{ retry: true }}, got {other:?}"),
        }
    }

    // =====================================================================
    // Dyn dispatch smoke — the handler is registered as
    // Arc<dyn TaskHandler> in the worker dispatch table.
    // =====================================================================

    #[tokio::test]
    async fn run_through_dyn_task_handler_ref() {
        let handler: Arc<dyn TaskHandler> = Arc::new(make_handler(Arc::new(MockPrune::ok(3))));
        assert_eq!(handler.kind(), "replay-seen-prune");
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("dyn dispatch run succeeds");
        assert!(matches!(outcome, TaskOutcome::Completed { .. }));
    }
}
