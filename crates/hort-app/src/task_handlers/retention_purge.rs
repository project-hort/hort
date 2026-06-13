//! `RetentionPurgeHandler`.
//!
//! The `kind = "retention-purge"` TaskHandler. Triggered by the k8s
//! CronJob hitting `POST /api/v1/admin/tasks/retention-purge`
//! (the route lives in `hort-http-admin-tasks`).
//! Default schedule `0 4 * * *`. Thin orchestration over
//! [`PurgeUseCase::process_expired`] (the destructive storage-GC
//! walk). The use case **refuses to run** until the
//! [`RefcountReconcileGate`](crate::use_cases::purge_use_case::RefcountReconcileGate)
//! reports the refcount reconcile has converged — a gate-false purge surfaces here as a
//! retryable `TaskOutcome::fail` (fail-safe; the worker boot sweep
//! flips the gate true on the next run).

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::use_cases::purge_use_case::PurgeUseCase;

/// [`TaskHandler`] for the periodic storage-GC purge sweep.
pub struct RetentionPurgeHandler {
    purge: Arc<PurgeUseCase>,
}

impl RetentionPurgeHandler {
    pub fn new(purge: Arc<PurgeUseCase>) -> Self {
        Self { purge }
    }
}

impl TaskHandler for RetentionPurgeHandler {
    fn kind(&self) -> &'static str {
        "retention-purge"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();
            match self.purge.process_expired(now).await {
                Ok(s) => {
                    tracing::info!(
                        artifacts_visited = s.artifacts_visited,
                        blobs_deleted = s.blobs_deleted,
                        blobs_kept = s.blobs_kept,
                        purged_events = s.purged_events,
                        skipped_protected = s.skipped_protected,
                        errors = s.errors,
                        "retention-purge sweep complete"
                    );
                    Ok(TaskOutcome::Completed {
                        result_summary: json!({
                            "artifacts_visited": s.artifacts_visited,
                            "blobs_deleted": s.blobs_deleted,
                            "blobs_kept": s.blobs_kept,
                            "purged_events": s.purged_events,
                            "skipped_protected": s.skipped_protected,
                            "errors": s.errors,
                        }),
                    })
                }
                Err(e) => {
                    // The B3.5-converged start-gate refusal and any
                    // transient port failure both surface here. Both
                    // are fail-safe-and-retry: the `ArtifactExpired`
                    // decisions are retained and the next cron tick
                    // retries (the worker boot sweep flips the gate
                    // true; transient infra recovers).
                    tracing::warn!(
                        error = %e,
                        "retention-purge: process_expired refused/failed — \
                         retry next tick (fail-safe: ArtifactExpired retained)"
                    );
                    Ok(TaskOutcome::fail(
                        format!("process_expired failed: {e}"),
                        true,
                    ))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use chrono::{DateTime, Utc};
    use hort_domain::error::DomainError;
    use hort_domain::events::system_actor;
    use hort_domain::ports::purge_gc::{PendingPurge, PurgeGcPort, PurgedRef};
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use uuid::Uuid;

    use crate::use_cases::purge_use_case::RefcountReconcileGate;
    use crate::use_cases::test_support::{MockEventStore, MockStoragePort};

    struct Gate(bool);
    impl RefcountReconcileGate for Gate {
        fn is_converged(&self) -> bool {
            self.0
        }
    }

    struct MockGc {
        pending: Mutex<Vec<PendingPurge>>,
    }
    impl PurgeGcPort for MockGc {
        fn list_pending_purge(&self) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
            let v = self.pending.lock().unwrap().clone();
            Box::pin(async move { Ok(v) })
        }
        fn purge_artifact_refs(&self, _a: Uuid) -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn purge_uc(gate: bool) -> Arc<PurgeUseCase> {
        Arc::new(PurgeUseCase::new(
            Arc::new(MockGc {
                pending: Mutex::new(Vec::new()),
            }),
            Arc::new(MockStoragePort::new()),
            crate::event_store_publisher::wrap_for_test(Arc::new(MockEventStore::new())),
            Arc::new(Gate(gate)),
        ))
    }

    fn ctx() -> TaskContext {
        use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "retention-purge".into(),
                status: JobStatus::Running,
                params: Some(serde_json::Value::Null),
                actor_id: None,
                priority: 0,
                trigger_source: "test".into(),
                attempts: 1,
                created_at: DateTime::<Utc>::UNIX_EPOCH,
                updated_at: DateTime::<Utc>::UNIX_EPOCH,
                completed_at: None,
                last_error: None,
                result_summary: None,
                kind_fields: KindFields::Other,
            },
        }
    }

    #[test]
    fn kind_is_retention_purge() {
        assert_eq!(
            RetentionPurgeHandler::new(purge_uc(true)).kind(),
            "retention-purge"
        );
    }

    #[tokio::test]
    async fn gate_converged_empty_pending_completes_with_zeroed_summary() {
        let h = RetentionPurgeHandler::new(purge_uc(true));
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["artifacts_visited"], 0);
                assert_eq!(result_summary["blobs_deleted"], 0);
                assert_eq!(result_summary["errors"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// BLOCKER-2-D fail-safe: gate not converged → PurgeUseCase
    /// refuses → handler returns retryable Failed (NOT a panic, NOT a
    /// silent success).
    #[tokio::test]
    async fn gate_false_returns_failed_retry_fail_safe() {
        let h = RetentionPurgeHandler::new(purge_uc(false));
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "gate-false must be retryable (boot sweep flips it)");
                assert!(reason.contains("process_expired"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// Port error inside process_expired surfaces as retryable Failed
    /// (the ArtifactExpired decisions are retained for the next tick).
    #[tokio::test]
    async fn list_pending_error_returns_failed_retry() {
        struct FailGc;
        impl PurgeGcPort for FailGc {
            fn list_pending_purge(&self) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
                Box::pin(async { Err(DomainError::Invariant("db down".into())) })
            }
            fn purge_artifact_refs(&self, _a: Uuid) -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
        }
        let uc = Arc::new(PurgeUseCase::new(
            Arc::new(FailGc),
            Arc::new(MockStoragePort::new()),
            crate::event_store_publisher::wrap_for_test(Arc::new(MockEventStore::new())),
            Arc::new(Gate(true)),
        ));
        let h = RetentionPurgeHandler::new(uc);
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, .. } => assert!(retry),
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
