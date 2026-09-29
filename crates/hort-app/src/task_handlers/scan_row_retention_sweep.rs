//! `scan-row-retention-sweep`
//! `TaskHandler` — completed/failed `kind='scan'` rows are
//! GC'd; the retention sweep deletes terminal `jobs` rows older than N
//! days.
//!
//! Terminal `kind='scan'` rows accumulate unbounded: each stranded-
//! requeue exhaustion cycle leaves a permanent `failed` row during a
//! scanner outage, and every successful scan — including every
//! periodic rescan — leaves a `completed` row forever. This handler
//! runs the retention sweep:
//!
//! ```sql
//! DELETE FROM public.jobs
//!  WHERE kind = 'scan'
//!    AND status IN ('completed', 'failed')
//!    AND updated_at < now() - $horizon
//! ```
//!
//! **`kind = 'scan'` exactly** — every other `jobs.kind` keeps its
//! newest terminal row as durable state (e.g. `verify-event-chain`'s
//! liveness breadcrumb checkpoint); the transitive-cascade `prefetch%`
//! rows have their own sweep (`prefetch-row-retention-sweep`). Widening
//! this handler's scope would delete another kind's durable state out
//! from under it.
//!
//! Pairs with the per-table autovacuum tuning on `public.jobs`
//! (migration 009): the sweep deletes the rows, autovacuum reclaims
//! the page space (lowered `autovacuum_vacuum_scale_factor` = 0.02
//! ensures the daemon kicks in after a few thousand dead tuples
//! rather than after the table is 20% dead).
//!
//! # Params shape
//!
//! ```json
//! { "horizon_seconds": 604800 }
//! ```
//!
//! `horizon_seconds` is optional, and **no supported path supplies
//! it.** The Helm CronJob and the systemd timer both run `hort-server
//! enqueue-scan-row-retention-sweep`, which takes no arguments and
//! writes `params` unconditionally empty; this kind has no
//! `hort-http-admin-tasks` invoke route (that router enumerates its
//! routes one by one and this kind is not among them, so `POST
//! /api/v1/admin/tasks/scan-row-retention-sweep` answers 404). So
//! [`DEFAULT_HORIZON`] (7 days) is the horizon in force on every
//! deployment; nothing short of a hand-written `INSERT` into
//! `public.jobs` produces another one.
//!
//! # Why a handler instead of a CLI subcommand
//!
//! Mirrors the `prefetch-row-retention-sweep` posture:
//! a single TaskHandler registered in the worker dispatcher +
//! enqueued by a Helm CronJob is the smallest-surface-area answer
//! that fits the established pattern. A CLI subcommand variant
//! would need a separate runtime-DSN connection path; the
//! TaskHandler reuses the worker's existing `JobsRepository`
//! adapter.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use super::sweep_horizon::resolve_sweep_horizon;

/// 7 days — the retention horizon, and the only one any supported path
/// produces (see the module docs). Same rationale as the prefetch
/// sweep's default: long enough that an operator debugging a scan
/// failure can read the failed rows the next morning; short enough
/// that a high-throughput registry does not accumulate millions of
/// historical scan rows.
pub const DEFAULT_HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Hard upper bound on any horizon that reaches this handler — 365
/// days. Beyond a year the deleted-rows count is dominated by
/// extremely old terminal entries no audit window wants, and the
/// failure mode stays "rejected on the way in" rather than "ran a
/// year-wide DELETE in production".
///
/// The cap is **not** a query-plan argument. No migration creates an
/// index on `jobs.updated_at` — migration 009 adds `jobs_scan_unique`,
/// `jobs_claim_idx`, `jobs_prefetch_unique`,
/// `jobs_prefetch_dependencies_unique` and `jobs_idempotency_key_uq`;
/// migration 015 adds `idx_jobs_scan_artifact_created_at` — so every
/// horizon, wide or narrow, plans as a sequential scan. That is the
/// right shape at this table size and daily cadence; widening the
/// horizon changes how many rows the scan deletes, not how it finds
/// them.
///
/// Since no supported path supplies a horizon at all, the cap's live
/// job is to keep a hand-written `INSERT` from becoming a year-wide
/// DELETE.
pub const MAX_HORIZON: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// `TaskHandler` for the terminal `kind='scan'` row retention sweep.
/// Constructed at worker composition time with the `JobsRepository`
/// port.
pub struct ScanRowRetentionSweepHandler {
    jobs: Arc<dyn JobsRepository>,
}

impl ScanRowRetentionSweepHandler {
    pub fn new(jobs: Arc<dyn JobsRepository>) -> Self {
        Self { jobs }
    }
}

impl TaskHandler for ScanRowRetentionSweepHandler {
    fn kind(&self) -> &'static str {
        "scan-row-retention-sweep"
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let horizon =
                match resolve_sweep_horizon(self.kind(), params, DEFAULT_HORIZON, MAX_HORIZON) {
                    Ok(h) => h,
                    Err(outcome) => return Ok(outcome),
                };

            let deleted = match self
                .jobs
                .delete_terminal_scan_rows_older_than(horizon)
                .await
            {
                Ok(n) => n,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("delete_terminal_scan_rows_older_than failed: {err}"),
                        true,
                    ));
                }
            };

            tracing::info!(
                horizon_seconds = horizon.as_secs(),
                deleted,
                "scan-row-retention-sweep complete",
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "horizon_seconds": horizon.as_secs(),
                    "deleted": deleted,
                }),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use uuid::Uuid;

    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};

    use crate::use_cases::test_support::MockJobsRepository;

    fn make_context() -> TaskContext {
        let now = Utc::now();
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "scan-row-retention-sweep".to_string(),
                status: JobStatus::Running,
                params: Some(serde_json::Value::Null),
                actor_id: None,
                priority: 0,
                trigger_source: "test".to_string(),
                attempts: 1,
                created_at: now,
                updated_at: now,
                completed_at: None,
                last_error: None,
                result_summary: None,
                kind_fields: KindFields::Other,
            },
        }
    }

    #[test]
    fn kind_returns_scan_row_retention_sweep() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = ScanRowRetentionSweepHandler::new(jobs);
        assert_eq!(h.kind(), "scan-row-retention-sweep");
    }

    #[tokio::test]
    async fn bare_params_uses_default_horizon_and_reports_deleted_count() {
        let jobs = Arc::new(MockJobsRepository::new());
        jobs.set_scan_retention_deleted_count(42);
        let h = ScanRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], 7 * 24 * 60 * 60);
        assert_eq!(result_summary["deleted"], 42);
        let calls = jobs.scan_retention_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], DEFAULT_HORIZON);
    }

    #[tokio::test]
    async fn operator_supplied_horizon_overrides_default() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = ScanRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h
            .run(&json!({"horizon_seconds": 3600}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], 3600);
        let calls = jobs.scan_retention_calls();
        assert_eq!(calls[0], Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn horizon_above_cap_rejected_non_retry() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = ScanRowRetentionSweepHandler::new(jobs);
        let outcome = h
            .run(
                &json!({"horizon_seconds": MAX_HORIZON.as_secs() + 1}),
                make_context(),
            )
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(
            !retry,
            "cap-exceeded is a configuration error, not transient"
        );
        assert!(reason.contains("365 days"), "{reason}");
    }

    #[tokio::test]
    async fn bad_params_non_retry() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = ScanRowRetentionSweepHandler::new(jobs);
        let outcome = h
            .run(&json!({"horizon_seconds": "not-a-number"}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, .. } = outcome else {
            panic!("expected Failed");
        };
        assert!(!retry);
    }

    #[tokio::test]
    async fn pending_running_rows_not_touched_only_terminal_swept() {
        // The mock returns whatever count we seed; the SQL-side
        // filter on `status IN ('completed', 'failed')` is what
        // enforces the "pending/running untouched" guarantee (proven
        // against a real database by the adapter's DB-gated test).
        // We pin the mock returning 0 deleted when nothing terminal
        // exists.
        let jobs = Arc::new(MockJobsRepository::new());
        jobs.set_scan_retention_deleted_count(0);
        let h = ScanRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["deleted"], 0);
    }

    #[tokio::test]
    async fn port_error_returns_retry_failed() {
        // No infrastructure failure injection in the current mock —
        // exercise the error arm via the default-impl `Bare`
        // repository that returns `Invariant` for the cascade
        // methods.
        struct Bare;
        impl JobsRepository for Bare {
            fn claim_scan_jobs<'a>(
                &'a self,
                _w: &'a str,
                _b: u32,
                _l: Duration,
            ) -> BoxFuture<'a, DomainResult<Vec<hort_domain::ports::jobs_repository::ScanJob>>>
            {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn mark_completed<'a>(
                &'a self,
                _id: Uuid,
                _result_summary: serde_json::Value,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn reschedule<'a>(
                &'a self,
                _id: Uuid,
                _b: Duration,
                _e: &'a str,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn mark_failed<'a>(
                &'a self,
                _id: Uuid,
                _e: &'a str,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn enqueue_scan<'a>(
                &'a self,
                _aid: Uuid,
                _rid: Uuid,
                _ch: &'a hort_domain::types::ContentHash,
                _f: &'a str,
                _p: i16,
                _ts: &'a str,
            ) -> BoxFuture<'a, DomainResult<Uuid>> {
                Box::pin(async { Ok(Uuid::nil()) })
            }
        }
        let jobs: Arc<dyn JobsRepository> = Arc::new(Bare);
        let h = ScanRowRetentionSweepHandler::new(jobs);
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(retry, "infrastructure failures retry");
        assert!(
            reason.contains("delete_terminal_scan_rows_older_than"),
            "{reason}"
        );
    }
}
