//! `jobs-row-retention-sweep` `TaskHandler` — the horizon for every
//! `jobs.kind` the two kind-specific retention sweeps do not reach.
//!
//! `public.jobs` had no general horizon. Two sweeps existed
//! (`prefetch-row-retention-sweep` over the pull-through ingest cascade,
//! `scan-row-retention-sweep` over `kind = 'scan'`); every other kind in
//! the `jobs_kind_check` allow-list accumulated terminal rows forever.
//! The highest-churn of them, `staging-sweep`, runs every five minutes
//! — roughly 288 terminal rows a day that nothing reclaimed. This
//! handler closes that gap:
//!
//! ```sql
//! WITH live AS (
//!     SELECT kind,
//!            max(completed_at) FILTER (WHERE status = 'completed')
//!              AS newest_completed_at,
//!            max(created_at) AS newest_created_at
//!       FROM public.jobs
//!      WHERE status IN ('completed', 'failed')
//!        AND (kind NOT LIKE 'prefetch%' OR kind = 'prefetch-tick')
//!        AND kind NOT IN ('scan', 'oci-index-child-ingest')
//!      GROUP BY kind
//! )
//! DELETE FROM public.jobs j
//!  USING live l
//!  WHERE l.kind = j.kind
//!    AND j.status IN ('completed', 'failed')
//!    AND j.updated_at < now() - $horizon
//!    AND NOT (j.status = 'completed'
//!             AND j.completed_at IS NOT DISTINCT FROM l.newest_completed_at)
//!    AND j.created_at <> l.newest_created_at
//! ```
//!
//! # The newest terminal row per kind is state, not garbage
//!
//! A terminal `jobs` row is accounting for most kinds and **live state**
//! for some. Two readers make the newest row per kind load-bearing:
//!
//! - `JobsRepository::last_completed_at_by_kind` — `max(completed_at)`
//!   over the `completed` rows of one kind. Two boot-time liveness gauges
//!   read it: `hort_staging_sweep_overdue` (expected interval 300 s) and
//!   `hort_event_chain_verify_overdue` (86400 s).
//! - `JobsRepository::last_result_summary_by_kind` — the newest
//!   `completed` row's `result_summary`, which is where the
//!   `prefetch-tick` rotation persists its keyset cursor. That kind is
//!   swept **here**, not by the cascade sweep whose name prefix it
//!   shares, precisely so this retention clause covers it.
//!
//! **Both filter `status = 'completed'`.** That is why retaining "the
//! newest terminal row" alone would not be enough: a kind that ran
//! successfully and then started failing has a `failed` newest terminal
//! row, so retaining only that row would delete the `completed` row
//! underneath it and make `last_completed_at_by_kind` answer `None` —
//! "never ran" — for a task that demonstrably ran. The sweep therefore
//! retains the newest `completed` row per kind **and** the newest
//! terminal row per kind, at most two rows each, ~50 rows across the
//! whole allow-list.
//!
//! # Why the two existing sweeps' kinds are excluded
//!
//! Exactly one sweep must own each kind. Two sweeps over the same rows
//! carry two horizon constants, and the shorter one silently wins — so a
//! kind covered twice ages out on a horizon neither of its two sweeps
//! documents. The three constants all read 7 days today, which makes the
//! overlap invisible rather than harmless: it would surface the first
//! time one of them moved. The exclusions are therefore the textual
//! complement of the other two predicates, so the property holds by
//! construction rather than by the constants happening to agree, and a
//! future `prefetch%` kind inherits the cascade sweep with no edit here.
//!
//! # Why `prefetch-tick` is swept here and not by the cascade sweep
//!
//! `prefetch-tick` matches `kind LIKE 'prefetch%'` by name, but it is
//! not cascade work: it is a scheduled tick, like `cron-rescan-tick` and
//! `staging-sweep`, and its newest `completed` row's `result_summary`
//! holds the rotation's keyset cursor. The cascade sweep's whole premise
//! is that none of its rows hold durable state, and it carries no
//! keep-newest clause because of it. Carving `prefetch-tick` out of that
//! predicate and admitting it here puts the kind with its actual class
//! and leaves "the newest terminal row per kind is state" implemented in
//! exactly one statement.
//!
//! # Abandoned non-terminal rows are out of scope
//!
//! `pending`/`running` rows are never deleted, and a row left `running`
//! by a crashed worker is not reclaimed here. Deleting a row that is
//! genuinely still running loses its completion when it lands
//! (`mark_completed` would update zero rows) — for `staging-sweep` that
//! means destroying the very liveness breadcrumb this handler is
//! careful to preserve.
//!
//! Recovering an abandoned row is a requeue (`running` → `pending`), not
//! a delete, and it belongs with the claim lifecycle rather than with a
//! retention horizon. It lives there:
//! `JobsRepository::requeue_abandoned`, run inline on the dispatcher's
//! poll loop and paired with the lease renewal
//! (`JobsRepository::renew_lease`) that makes an expired lease mean "the
//! holder stopped writing to the database" rather than "the task is
//! slower than its 15-minute default lease". Widening this predicate to
//! reach non-terminal rows would put a second, delete-shaped mechanism
//! on top of it.
//!
//! Pairs with the per-table autovacuum tuning on `public.jobs`
//! (migration 009: `autovacuum_vacuum_scale_factor = 0.02`) — the sweep
//! deletes the rows, autovacuum reclaims the page space.
//!
//! # Params shape
//!
//! ```json
//! { "horizon_seconds": 604800 }
//! ```
//!
//! `horizon_seconds` is optional, and **no supported path supplies
//! it.** The Helm CronJob and the systemd timer both run `hort-server
//! enqueue-jobs-row-retention-sweep`, which takes no arguments and
//! writes `params` unconditionally empty; this kind has no
//! `hort-http-admin-tasks` invoke route, so `POST
//! /api/v1/admin/tasks/jobs-row-retention-sweep` answers 404. So
//! [`DEFAULT_HORIZON`] (7 days) is the horizon in force on every
//! deployment; nothing short of a hand-written `INSERT` into
//! `public.jobs` produces another one.
//!
//! # Why a handler instead of a CLI subcommand
//!
//! Mirrors the `prefetch-row-retention-sweep` /
//! `scan-row-retention-sweep` posture: one `TaskHandler` registered in
//! the worker dispatcher, enqueued by a Helm CronJob running
//! `hort-server enqueue-jobs-row-retention-sweep` on the runtime DSN. A
//! CLI subcommand that did the DELETE itself would need its own runtime
//! connection path; the handler reuses the worker's existing
//! `JobsRepository` adapter.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use super::sweep_horizon::resolve_sweep_horizon;

/// 7 days — the retention horizon, and the only one any supported path
/// produces (see the module docs).
///
/// The value matches the two sibling sweeps, but not because they chose
/// it: the kinds this sweep covers argue for it independently, from both
/// ends.
///
/// **Lower bound — the off-shift gap.** Most kinds here run on a daily
/// CronJob (`retention-purge`, `eventstore-archive`,
/// `service-account-rotation`, `quarantine-release-sweep`, …), and for a
/// worker-dispatched task the `jobs` row is the *only* durable record of
/// a failure: terminal failures are recorded by
/// `JobsRepository::mark_failed`, a column update with no event-store
/// append to fall back on. Once the row is swept the failure detail
/// (`last_error`, `attempts`, timings) is gone outright. The window must
/// therefore span the longest interval between a failure and the first
/// operator who could look at it — a Friday-evening failure read on
/// Monday morning, plus margin. 7 days clears that; 72 hours does not,
/// and 24 hours routinely would not survive a weekend.
///
/// **Upper bound — nothing pushes back.** The churn argument that would
/// normally pull the horizon down does not bind at this value. The
/// dominant kind is `staging-sweep` at ~288 rows/day, so 7 days is a
/// steady state of ~2,000 rows plus a handful per daily kind — against
/// the ~83,000 unreclaimed rows that motivated the sweep. Widening to 30
/// days would still be small (~8,600 rows) but buys nothing: a
/// five-minute sweep's failure from three weeks ago describes a world
/// several thousand subsequent runs have replaced, and every kind here
/// has a live alarm of its own (the two liveness gauges, the
/// `hort_admin_tasks_*` counters, CronJob failure events) so the row is
/// the detail behind an alarm, never the alarm itself. A 7-day detail
/// window behind a live alarm is adequate; a 30-day one serves incidents
/// whose alarm fired weeks earlier and went unread, which is a different
/// problem.
pub const DEFAULT_HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Hard upper bound on any horizon that reaches this handler — 365
/// days, the same cap the two sibling sweeps enforce. Beyond a year the
/// deleted count is dominated by rows no audit window wants, and the
/// failure mode stays "rejected on the way in" rather than "ran a
/// year-wide DELETE in production". It is not a query-plan argument —
/// see the sibling sweeps' `MAX_HORIZON` docs for why there is no
/// `jobs.updated_at` index to fall off. Since no supported path
/// supplies a horizon at all, the cap's live job is to keep a
/// hand-written `INSERT` from becoming a year-wide DELETE.
pub const MAX_HORIZON: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// `TaskHandler` for the general terminal-`jobs`-row retention sweep.
/// Constructed at worker composition time with the `JobsRepository`
/// port.
pub struct JobsRowRetentionSweepHandler {
    jobs: Arc<dyn JobsRepository>,
}

impl JobsRowRetentionSweepHandler {
    pub fn new(jobs: Arc<dyn JobsRepository>) -> Self {
        Self { jobs }
    }
}

impl TaskHandler for JobsRowRetentionSweepHandler {
    fn kind(&self) -> &'static str {
        "jobs-row-retention-sweep"
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
                .delete_terminal_other_kind_rows_older_than(horizon)
                .await
            {
                Ok(n) => n,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("delete_terminal_other_kind_rows_older_than failed: {err}"),
                        true,
                    ));
                }
            };

            tracing::info!(
                horizon_seconds = horizon.as_secs(),
                deleted,
                "jobs-row-retention-sweep complete",
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
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields, ResultWriteOutcome};

    use crate::use_cases::test_support::MockJobsRepository;

    fn make_context() -> TaskContext {
        let now = Utc::now();
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "jobs-row-retention-sweep".to_string(),
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
    fn kind_returns_jobs_row_retention_sweep() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = JobsRowRetentionSweepHandler::new(jobs);
        assert_eq!(h.kind(), "jobs-row-retention-sweep");
    }

    /// The kind literal must be in the admin-invoke allow-list so the
    /// `jobs.kind` CHECK constraint accepts the row the CronJob's
    /// `enqueue_task` inserts (the two lists are kept in lock-step by
    /// `task_kind_check_lockstep_guard`, which reads
    /// `EVENT_TASK_KINDS` — the superset).
    #[test]
    fn kind_is_registered_in_the_task_kind_vocabularies() {
        use hort_domain::events::{ADMIN_INVOKABLE_TASK_KINDS, EVENT_TASK_KINDS};
        let kind = "jobs-row-retention-sweep";
        assert!(
            EVENT_TASK_KINDS.contains(&kind),
            "{kind} MUST be in EVENT_TASK_KINDS or the migration's kind CHECK rejects the row"
        );
        assert!(
            ADMIN_INVOKABLE_TASK_KINDS.contains(&kind),
            "{kind} MUST be in ADMIN_INVOKABLE_TASK_KINDS so an operator-driven enqueue \
             through TaskUseCase is not rejected before any I/O"
        );
    }

    /// Deleting historical job rows releases no authority — it touches
    /// no artifact, event stream, or scan data.
    #[test]
    fn kind_is_not_destructive() {
        assert!(
            !hort_domain::events::task_kind_is_destructive("jobs-row-retention-sweep"),
            "job-row GC is not a destructive kind; it deletes operational accounting only"
        );
    }

    #[tokio::test]
    async fn bare_params_uses_default_horizon_and_reports_deleted_count() {
        let jobs = Arc::new(MockJobsRepository::new());
        jobs.set_other_kind_retention_deleted_count(42);
        let h = JobsRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], 7 * 24 * 60 * 60);
        assert_eq!(result_summary["deleted"], 42);
        let calls = jobs.other_kind_retention_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], DEFAULT_HORIZON);
    }

    #[tokio::test]
    async fn operator_supplied_horizon_overrides_default() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = JobsRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h
            .run(&json!({"horizon_seconds": 3600}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["horizon_seconds"], 3600);
        let calls = jobs.other_kind_retention_calls();
        assert_eq!(calls[0], Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn horizon_at_the_cap_is_accepted() {
        // Pins the boundary as inclusive — the cap check is `>`, so the
        // cap value itself must sweep rather than be rejected.
        let jobs = Arc::new(MockJobsRepository::new());
        let h = JobsRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h
            .run(
                &json!({"horizon_seconds": MAX_HORIZON.as_secs()}),
                make_context(),
            )
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed at exactly the cap");
        };
        assert_eq!(result_summary["horizon_seconds"], MAX_HORIZON.as_secs());
        assert_eq!(jobs.other_kind_retention_calls()[0], MAX_HORIZON);
    }

    #[tokio::test]
    async fn horizon_above_cap_rejected_non_retry() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = JobsRowRetentionSweepHandler::new(jobs.clone());
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
        assert!(
            jobs.other_kind_retention_calls().is_empty(),
            "an over-cap horizon must be rejected before the DELETE is issued"
        );
    }

    #[tokio::test]
    async fn bad_params_non_retry() {
        let jobs = Arc::new(MockJobsRepository::new());
        let h = JobsRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h
            .run(&json!({"horizon_seconds": "not-a-number"}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, .. } = outcome else {
            panic!("expected Failed");
        };
        assert!(!retry);
        assert!(
            jobs.other_kind_retention_calls().is_empty(),
            "unparseable params must be rejected before the DELETE is issued"
        );
    }

    #[tokio::test]
    async fn nothing_aged_reports_zero_deleted() {
        // The mock returns whatever count we seed; the per-kind state
        // retention and the `status IN ('completed','failed')` filter
        // are SQL-side and proven against a real database by the
        // adapter's DB-gated tests. This pins the handler's zero path.
        let jobs = Arc::new(MockJobsRepository::new());
        jobs.set_other_kind_retention_deleted_count(0);
        let h = JobsRowRetentionSweepHandler::new(jobs.clone());
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["deleted"], 0);
    }

    #[tokio::test]
    async fn port_error_returns_retry_failed() {
        // No infrastructure-failure injection in the current mock —
        // exercise the error arm via a `Bare` repository that leaves the
        // sweep method on its `Invariant`-returning default impl.
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
                _attempt: u32,
                _result_summary: serde_json::Value,
            ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
                Box::pin(async { Ok(ResultWriteOutcome::Applied) })
            }
            fn reschedule<'a>(
                &'a self,
                _id: Uuid,
                _attempt: u32,
                _b: Duration,
                _e: &'a str,
            ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
                Box::pin(async { Ok(ResultWriteOutcome::Applied) })
            }
            fn mark_failed<'a>(
                &'a self,
                _id: Uuid,
                _attempt: u32,
                _e: &'a str,
            ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
                Box::pin(async { Ok(ResultWriteOutcome::Applied) })
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
        let h = JobsRowRetentionSweepHandler::new(jobs);
        let outcome = h.run(&json!({}), make_context()).await.expect("Ok");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(retry, "infrastructure failures retry");
        assert!(
            reason.contains("delete_terminal_other_kind_rows_older_than"),
            "{reason}"
        );
    }
}
