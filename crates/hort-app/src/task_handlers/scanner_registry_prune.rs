//! `scanner-registry-prune` TaskHandler — scanner-worker registry
//! housekeeping.
//!
//! Deletes `scanner_registry` rows whose `last_heartbeat` is older than
//! [`STALE_RETENTION`] (the cold-path GC for the worker-coordination
//! table). Pod churn — rollouts, HPA scaling — leaves a row per retired
//! `worker_id` that never heartbeats again, so without this the table grows
//! without bound and the admin worker-list (`GET /api/v1/admin/workers`)
//! accumulates dead rows. Mirrors the `replay-seen-prune` /
//! `prefetch-row-retention-sweep` cleanup-task pattern: a worker
//! `TaskHandler` driven by a k8s CronJob, **default-enabled**.
//!
//! ## Cleanup degrades safe
//!
//! A missed prune only grows the table; it never affects correctness — a
//! live worker heartbeats every 60 s so it is never near the horizon, and a
//! stale row's only effect is a `live = false` entry in the admin list (the
//! liveness flag is recomputed on every read from `last_heartbeat`,
//! independent of pruning). So a prune failure is `warn!` +
//! retry-on-next-tick, never `error!` and never a hard worker failure.
//!
//! `info!` on a successful prune (the deleted-row count — no worker
//! identifiers); `warn!` on failure. `#[tracing::instrument(skip(self))]`
//! WITHOUT `err` (a prune failure is a `TaskOutcome::Failed`, not a
//! `Result::Err`). **No new metric** (mirrors `replay-seen-prune`; a
//! prune-outage gauge would need a metrics-catalog row and is deliberately
//! not invented here).

use std::sync::Arc;
use std::time::Duration;

use hort_domain::error::DomainResult;
use hort_domain::ports::scanner_registry_repository::ScannerRegistryRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use serde_json::json;

/// Workers whose last heartbeat is older than this are pruned.
///
/// 7 days: long enough that the admin worker-list shows a week of churn
/// (operators can see "what rolled out this week"), bounded enough that the
/// table cannot grow without limit. A live worker heartbeats every 60 s, so
/// it is never within four orders of magnitude of this horizon — only
/// genuinely retired `worker_id`s are deleted.
pub const STALE_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);

/// [`TaskHandler`] that runs a single scanner-registry prune tick.
///
/// Constructed at composition time with the one port it touches
/// ([`ScannerRegistryRepository`], implemented by
/// `PgScannerRegistryRepository` — the same handle the worker heartbeat
/// already holds). The k8s CronJob drives cadence by POSTing to
/// `/api/v1/admin/tasks/scanner-registry-prune`; this handler runs ONE
/// delete-stale tick per call.
pub struct ScannerRegistryPruneHandler {
    registry: Arc<dyn ScannerRegistryRepository>,
}

impl ScannerRegistryPruneHandler {
    /// Construct the handler from its single port dependency.
    pub fn new(registry: Arc<dyn ScannerRegistryRepository>) -> Self {
        Self { registry }
    }
}

impl TaskHandler for ScannerRegistryPruneHandler {
    fn kind(&self) -> &'static str {
        "scanner-registry-prune"
    }

    #[tracing::instrument(skip(self, _params, _ctx))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            match self.registry.prune_stale(STALE_RETENTION).await {
                Ok(deleted) => {
                    tracing::info!(
                        deleted_rows = deleted,
                        retention_days = STALE_RETENTION.as_secs() / 86_400,
                        "scanner-registry-prune: deleted stale scanner_registry rows"
                    );
                    Ok(TaskOutcome::Completed {
                        result_summary: json!({ "deleted_rows": deleted }),
                    })
                }
                Err(err) => {
                    // Cleanup degrades SAFE: a missed prune only grows the
                    // table — liveness is recomputed from `last_heartbeat` on
                    // every read, independent of pruning. So warn! +
                    // retry-on-next-tick, NEVER error! and NEVER a hard
                    // worker failure.
                    tracing::warn!(
                        error = %err,
                        "scanner-registry-prune: prune failed; cleanup degrades safe \
                         (only the worker-coordination table grows; liveness flags \
                         unaffected); will retry on next tick"
                    );
                    Ok(TaskOutcome::fail(
                        format!("scanner-registry prune failed: {err}"),
                        true,
                    ))
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::Utc;
    use hort_domain::error::DomainError;
    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use hort_domain::ports::scanner_registry_repository::ScannerRegistryEntry;
    use uuid::Uuid;

    /// Programmed `prune_stale` outcome (avoids requiring `DomainError:
    /// Clone`). Records how many times `prune_stale` was invoked.
    enum PruneOutcome {
        Ok(u64),
        Err(String),
    }

    struct MockRegistry {
        prune_calls: AtomicUsize,
        outcome: PruneOutcome,
        last_horizon: std::sync::Mutex<Option<Duration>>,
    }

    impl MockRegistry {
        fn ok(deleted: u64) -> Self {
            Self {
                prune_calls: AtomicUsize::new(0),
                outcome: PruneOutcome::Ok(deleted),
                last_horizon: std::sync::Mutex::new(None),
            }
        }
        fn err(msg: &str) -> Self {
            Self {
                prune_calls: AtomicUsize::new(0),
                outcome: PruneOutcome::Err(msg.to_string()),
                last_horizon: std::sync::Mutex::new(None),
            }
        }
        fn prune_call_count(&self) -> usize {
            self.prune_calls.load(Ordering::SeqCst)
        }
    }

    impl ScannerRegistryRepository for MockRegistry {
        fn upsert_self<'a>(
            &'a self,
            _worker_id: &'a str,
            _backends: Vec<String>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn refresh_heartbeat<'a>(&'a self, _worker_id: &'a str) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn list_all<'a>(&'a self) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn prune_stale<'a>(&'a self, older_than: Duration) -> BoxFuture<'a, DomainResult<u64>> {
            self.prune_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_horizon.lock().unwrap() = Some(older_than);
            let out = match &self.outcome {
                PruneOutcome::Ok(n) => Ok(*n),
                PruneOutcome::Err(msg) => Err(DomainError::Invariant(msg.clone())),
            };
            Box::pin(async move { out })
        }
    }

    fn make_context() -> TaskContext {
        let now = Utc::now();
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "scanner-registry-prune".to_string(),
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
            },
        }
    }

    #[test]
    fn kind_returns_scanner_registry_prune() {
        let handler = ScannerRegistryPruneHandler::new(Arc::new(MockRegistry::ok(0)));
        assert_eq!(handler.kind(), "scanner-registry-prune");
    }

    #[tokio::test]
    async fn run_dispatches_prune_with_retention_and_reports_deleted_count() {
        let mock = Arc::new(MockRegistry::ok(5));
        let handler = ScannerRegistryPruneHandler::new(mock.clone());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("handler run is infallible (degrades via TaskOutcome)");

        assert_eq!(mock.prune_call_count(), 1, "prune_stale once per tick");
        assert_eq!(
            *mock.last_horizon.lock().unwrap(),
            Some(STALE_RETENTION),
            "handler must pass the STALE_RETENTION horizon"
        );
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["deleted_rows"], 5);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_completes_with_zero_when_nothing_stale() {
        let mock = Arc::new(MockRegistry::ok(0));
        let handler = ScannerRegistryPruneHandler::new(mock.clone());
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("infallible");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["deleted_rows"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_degrades_safe_on_prune_failure() {
        let mock = Arc::new(MockRegistry::err("connection refused"));
        let handler = ScannerRegistryPruneHandler::new(mock.clone());

        // `run` returns Ok (NOT Err) — a prune outage must never propagate
        // as a Result::Err that fails the worker.
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("prune failure must NOT surface as Result::Err (degrades safe)");

        assert_eq!(mock.prune_call_count(), 1);
        match outcome {
            TaskOutcome::Failed { reason, retry } => {
                assert!(retry, "a prune outage must be retried on the next tick");
                assert!(
                    reason.contains("connection refused"),
                    "reason should carry the cause: {reason}"
                );
            }
            other => panic!("expected Failed {{ retry: true }}, got {other:?}"),
        }
    }
}
