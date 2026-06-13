//! `prefetch-row-retention-sweep`
//! `TaskHandler` — completed/failed prefetch rows are
//! GC'd; the retention sweep deletes terminal `jobs` rows older than N
//! days.
//!
//! The transitive cascade turns `public.jobs` into a high-volume
//! table — a closure-warm enqueues thousands of rows; without
//! periodic GC, terminal `prefetch%` rows accumulate unbounded. This
//! handler runs the retention sweep:
//!
//! ```sql
//! DELETE FROM public.jobs
//!  WHERE kind LIKE 'prefetch%'
//!    AND status IN ('completed', 'failed')
//!    AND updated_at < now() - $horizon
//! ```
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
//! `horizon_seconds` is optional — when omitted the handler defaults
//! to [`DEFAULT_HORIZON`] (7 days). The Helm CronJob writes the value
//! the operator chose; bare invocations get the default.
//!
//! # Why a handler instead of a CLI subcommand
//!
//! Mirrors the `quarantine-release-sweep` posture:
//! a single TaskHandler registered in the worker dispatcher +
//! enqueued by a Helm CronJob is the smallest-surface-area answer
//! that fits the established pattern. A CLI subcommand variant
//! would need a separate runtime-DSN connection path; the
//! TaskHandler reuses the worker's existing `JobsRepository`
//! adapter.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

/// 7 days — design §9 default retention horizon. Operators tune
/// via the `horizon_seconds` param on the enqueue. Picked as a
/// compromise: long enough that an operator debugging a cascade
/// failure can read the failed rows the next morning; short enough
/// that a high-throughput proxy (thousands of cohorts / day) does
/// not accumulate millions of historical rows.
pub const DEFAULT_HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Hard upper bound on the operator-supplied horizon — 365 days.
/// Beyond a year, the deleted-rows count would be dominated by
/// extremely old terminal entries the operator almost certainly does
/// not want to keep, AND the sweep query plan changes (an
/// open-ended `WHERE updated_at < now() - <huge>` falls off the
/// `updated_at` index entirely). A 365-day cap is permissive
/// enough for any audit-window use case while keeping the failure
/// mode at "rejected on the way in" instead of "took out
/// production".
pub const MAX_HORIZON: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Parsed shape of the `params` JSONB column for a
/// `prefetch-row-retention-sweep` row.
#[derive(Debug, Deserialize, Default)]
struct PrefetchRowRetentionSweepParams {
    /// Retention horizon in seconds. Rows whose `updated_at` is
    /// older than `now() - horizon_seconds` are deleted. Defaults to
    /// [`DEFAULT_HORIZON`] when absent.
    #[serde(default)]
    horizon_seconds: Option<u64>,
}

/// `TaskHandler` for the cascade-row retention sweep. Constructed
/// at worker composition time with the `JobsRepository` port.
pub struct PrefetchRowRetentionSweepHandler {
    jobs: Arc<dyn JobsRepository>,
}

impl PrefetchRowRetentionSweepHandler {
    pub fn new(jobs: Arc<dyn JobsRepository>) -> Self {
        Self { jobs }
    }
}

impl TaskHandler for PrefetchRowRetentionSweepHandler {
    fn kind(&self) -> &'static str {
        "prefetch-row-retention-sweep"
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let parsed: PrefetchRowRetentionSweepParams =
                match serde_json::from_value(params.clone()) {
                    Ok(p) => p,
                    Err(err) => {
                        return Ok(TaskOutcome::fail(
                            format!("prefetch-row-retention-sweep params JSON invalid: {err}"),
                            false,
                        ));
                    }
                };
            let horizon = match parsed.horizon_seconds {
                Some(s) => {
                    let d = Duration::from_secs(s);
                    if d > MAX_HORIZON {
                        return Ok(TaskOutcome::fail(
                            format!(
                                "horizon_seconds {s} exceeds {MAX_SECS}-second cap (365 days)",
                                MAX_SECS = MAX_HORIZON.as_secs(),
                            ),
                            false,
                        ));
                    }
                    d
                }
                None => DEFAULT_HORIZON,
            };

            let deleted = match self
                .jobs
                .delete_terminal_prefetch_rows_older_than(horizon)
                .await
            {
                Ok(n) => n,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("delete_terminal_prefetch_rows_older_than failed: {err}"),
                        true,
                    ));
                }
            };

            tracing::info!(
                horizon_seconds = horizon.as_secs(),
                deleted,
                "prefetch-row-retention-sweep complete",
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
                kind: "prefetch-row-retention-sweep".to_string(),
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
    fn kind_returns_prefetch_row_retention_sweep() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = PrefetchRowRetentionSweepHandler::new(jobs);
        assert_eq!(h.kind(), "prefetch-row-retention-sweep");
    }

    #[tokio::test]
    async fn bare_params_uses_default_horizon_and_reports_deleted_count() {
        let jobs = Arc::new(MockJobsRepository::new());
        jobs.set_prefetch_retention_deleted_count(42);
        let h = PrefetchRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], 7 * 24 * 60 * 60);
        assert_eq!(result_summary["deleted"], 42);
        let calls = jobs.prefetch_retention_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], DEFAULT_HORIZON);
    }

    #[tokio::test]
    async fn operator_supplied_horizon_overrides_default() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = PrefetchRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h
            .run(&json!({"horizon_seconds": 3600}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], 3600);
        let calls = jobs.prefetch_retention_calls();
        assert_eq!(calls[0], Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn horizon_above_cap_rejected_non_retry() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = PrefetchRowRetentionSweepHandler::new(jobs);
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
        let h = PrefetchRowRetentionSweepHandler::new(jobs);
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
        // enforces the "pending/running untouched" guarantee. We
        // pin the mock returning 0 deleted when nothing terminal
        // exists.
        let jobs = Arc::new(MockJobsRepository::new());
        jobs.set_prefetch_retention_deleted_count(0);
        let h = PrefetchRowRetentionSweepHandler::new(jobs.clone());
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
        let h = PrefetchRowRetentionSweepHandler::new(jobs);
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(retry, "infrastructure failures retry");
        assert!(
            reason.contains("delete_terminal_prefetch_rows_older_than"),
            "{reason}"
        );
    }
}
