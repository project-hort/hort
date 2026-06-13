//! `EventStoreArchiveHandler`.
//!
//! The `kind = "eventstore-archive"` TaskHandler. Triggered by the k8s
//! CronJob hitting `POST /api/v1/admin/tasks/eventstore-archive`
//! (the route lives in `hort-http-admin-tasks`).
//! Default schedule `0 5 * * 0` (weekly). Thin orchestration over
//! [`EventStoreRetentionUseCase::archive_terminal_streams`] — the
//! audit-retention stream sweep (seal terminal / age-gated streams
//! once their retention floor has elapsed, via the `seal_and_remove`
//! `StreamSealed`-tombstone chokepoint).
//!
//! When `HORT_RETENTION_DATABASE_URL` is unset the
//! composition root wires this use case's `EventStorePublisher` over
//! the `hort_app_role` pool — every `delete_stream` then fails fail-safe
//! via the still-active `events_immutable` trigger (the
//! seal-tombstone-first transaction rolls back, zero rows removed). A
//! per-stream failure is recorded in the summary and the sweep
//! continues; only `list_terminal_candidates` failing aborts the sweep
//! (→ retryable `TaskOutcome::fail`).

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::use_cases::eventstore_retention_use_case::EventStoreRetentionUseCase;

/// [`TaskHandler`] for the periodic audit-retention stream sweep.
pub struct EventStoreArchiveHandler {
    retention: Arc<EventStoreRetentionUseCase>,
}

impl EventStoreArchiveHandler {
    pub fn new(retention: Arc<EventStoreRetentionUseCase>) -> Self {
        Self { retention }
    }
}

impl TaskHandler for EventStoreArchiveHandler {
    fn kind(&self) -> &'static str {
        "eventstore-archive"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();
            match self.retention.archive_terminal_streams(now).await {
                Ok(s) => {
                    tracing::info!(
                        candidates = s.candidates_visited,
                        archived = s.archived,
                        deleted = s.deleted,
                        skipped_non_terminal = s.skipped_non_terminal,
                        skipped_floor_not_elapsed = s.skipped_floor_not_elapsed,
                        skipped_meta_stream = s.skipped_meta_stream,
                        skipped_already_sealed = s.skipped_already_sealed,
                        skipped_unregistered_category = s.skipped_unregistered_category,
                        errors = s.errors,
                        "eventstore-archive sweep complete"
                    );
                    Ok(TaskOutcome::Completed {
                        result_summary: json!({
                            "candidates": s.candidates_visited,
                            "archived": s.archived,
                            "deleted": s.deleted,
                            "skipped_non_terminal": s.skipped_non_terminal,
                            "skipped_floor_not_elapsed": s.skipped_floor_not_elapsed,
                            "skipped_meta_stream": s.skipped_meta_stream,
                            "skipped_already_sealed": s.skipped_already_sealed,
                            "skipped_unregistered_category": s.skipped_unregistered_category,
                            "errors": s.errors,
                        }),
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "eventstore-archive: list_terminal_candidates failed — \
                         retry next tick (fail-safe: nothing sealed)"
                    );
                    Ok(TaskOutcome::fail(
                        format!("archive_terminal_streams failed: {e}"),
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
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::ports::terminal_stream_reader::{
        TerminalStreamCandidate, TerminalStreamReader,
    };
    use uuid::Uuid;

    use crate::use_cases::eventstore_retention_use_case::StreamRetentionModeRef;
    use crate::use_cases::test_support::MockEventStore;

    struct MockReader {
        candidates: Mutex<Vec<TerminalStreamCandidate>>,
        err: Mutex<Option<DomainError>>,
    }
    impl MockReader {
        fn empty() -> Self {
            Self {
                candidates: Mutex::new(Vec::new()),
                err: Mutex::new(None),
            }
        }
        fn failing() -> Self {
            Self {
                candidates: Mutex::new(Vec::new()),
                err: Mutex::new(Some(DomainError::Invariant("boom".into()))),
            }
        }
    }
    impl TerminalStreamReader for MockReader {
        fn list_terminal_candidates(
            &self,
        ) -> BoxFuture<'_, DomainResult<Vec<TerminalStreamCandidate>>> {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            let v = self.candidates.lock().unwrap().clone();
            Box::pin(async move { Ok(v) })
        }
    }

    fn uc(reader: Arc<MockReader>) -> Arc<EventStoreRetentionUseCase> {
        Arc::new(EventStoreRetentionUseCase::new(
            reader,
            crate::event_store_publisher::wrap_for_test(Arc::new(MockEventStore::new())),
            Vec::new(),
            StreamRetentionModeRef::Delete,
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
                kind: "eventstore-archive".into(),
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
    fn kind_is_eventstore_archive() {
        assert_eq!(
            EventStoreArchiveHandler::new(uc(Arc::new(MockReader::empty()))).kind(),
            "eventstore-archive"
        );
    }

    #[tokio::test]
    async fn empty_candidates_completes_with_zeroed_summary() {
        let h = EventStoreArchiveHandler::new(uc(Arc::new(MockReader::empty())));
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidates"], 0);
                assert_eq!(result_summary["archived"], 0);
                assert_eq!(result_summary["deleted"], 0);
                assert_eq!(result_summary["errors"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reader_error_returns_failed_retry() {
        let h = EventStoreArchiveHandler::new(uc(Arc::new(MockReader::failing())));
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "list_terminal_candidates failure must retry");
                assert!(reason.contains("archive_terminal_streams"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
