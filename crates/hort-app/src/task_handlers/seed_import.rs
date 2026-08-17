//! `seed-import` TaskHandler.
//!
//! Wraps [`SeedImportUseCase`] for worker dispatch. The
//! `hort-server seed-import` subcommand enqueues a single
//! `kind = 'seed-import'` row carrying the parsed item set in
//! `params.items`; the worker claims the row and dispatches here.
//!
//! The handler is a thin adapter — params parsing + delegation. The
//! per-item ingest / quarantine work lives in the use case.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::events::ApiActor;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::use_cases::seed_import_use_case::{SeedImportItem, SeedImportUseCase};

/// Shape of the `params` JSON the subcommand writes onto the job row.
///
/// One field — `items` — a JSON array of [`SeedImportItem`]. Extending
/// the shape (per-run options) lands as additional optional fields.
#[derive(Debug, Deserialize)]
struct SeedImportParams {
    items: Vec<SeedImportItem>,
}

/// `TaskHandler` impl for `kind = "seed-import"`. Constructed at worker
/// composition time with the use case.
pub struct SeedImportHandler {
    use_case: Arc<SeedImportUseCase>,
}

impl SeedImportHandler {
    pub fn new(use_case: Arc<SeedImportUseCase>) -> Self {
        Self { use_case }
    }
}

impl TaskHandler for SeedImportHandler {
    fn kind(&self) -> &'static str {
        "seed-import"
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            // Parse params.items. Invalid JSON → non-retryable Failed
            // (operator error, not infrastructure flake).
            let parsed: SeedImportParams = match serde_json::from_value(params.clone()) {
                Ok(p) => p,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("seed-import params JSON invalid: {err}"),
                        false,
                    ));
                }
            };

            // Use the job's `actor_id` for the per-row
            // `ArtifactIngested.uploaded_by` attribution. **Today this
            // is always `None`** — the `hort-server seed-import`
            // subcommand parses `MinimalConfig` (no svc-token / no
            // auth-context to capture, by design — DB-only, runtime
            // DSN; ADR 0009) and explicitly passes `actor_id: None`
            // to `JobsRepository::enqueue_task` (see the comment at
            // the subcommand's `enqueue_task(..., None, …)` call).
            // The fall-through to the nil-uuid system-actor sentinel
            // below is therefore the **steady-state branch**, not the
            // exception; `actor_to_uploaded_by` maps it to a `NULL`
            // `uploaded_by` on the artifact row.
            //
            // Audit-trail mitigation: the
            // subcommand DOES stamp `trigger_source = 'seed-import'`
            // on the `jobs` row so the operator-driven enqueue is at
            // least distinguishable from cron / advisory / other
            // `'manual'` enqueues at the trigger-source layer. Full
            // per-row operator attribution (OS-user, Helm-injected
            // token, or `hort-cli`-bridged operator JWT) remains a
            // separate larger ask — when it lands, the `actor_id`
            // will be populated by the subcommand and the
            // nil-uuid branch below becomes the genuine exception
            // (worker-internal callers only).
            let actor_user_id = match ctx.job_row.actor_id {
                Some(id) => id,
                None => uuid::Uuid::nil(),
            };
            let actor = ApiActor {
                user_id: actor_user_id,
            };

            let summary = match self.use_case.run(parsed.items, actor).await {
                Ok(s) => s,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("seed-import run failed: {err}"),
                        true,
                    ));
                }
            };

            // Per-item errors are NOT a failed task — the operator
            // wants the partition counts (registered / already_imported
            // / errors) in the result_summary. A failed *task* would
            // mean the whole batch couldn't be processed (infra flake).
            let result_summary = json!({
                "total": summary.total,
                "registered": summary.registered,
                "already_imported": summary.already_imported,
                "errors": summary.errors,
            });

            tracing::info!(
                total = summary.total,
                registered = summary.registered,
                already_imported = summary.already_imported,
                error_count = summary.errors.len(),
                "seed-import task complete"
            );

            Ok(TaskOutcome::Completed { result_summary })
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
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};

    fn test_job_row(actor_id: Option<Uuid>) -> JobRow {
        let now = chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        JobRow {
            id: Uuid::nil(),
            kind: "seed-import".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id,
            priority: 0,
            trigger_source: "manual".to_string(),
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
            job_row: test_job_row(Some(Uuid::new_v4())),
        }
    }

    #[test]
    fn kind_returns_seed_import() {
        // Build a minimal use case with default mocks — the handler
        // doesn't dispatch on construction.
        let use_case = make_use_case_empty();
        let handler = SeedImportHandler::new(use_case);
        assert_eq!(handler.kind(), "seed-import");
    }

    /// Invalid params JSON → non-retryable Failed (operator error).
    #[tokio::test]
    async fn invalid_params_returns_failed_non_retry() {
        let use_case = make_use_case_empty();
        let handler = SeedImportHandler::new(use_case);

        let bad_params = json!({ "not_items": [] });

        let outcome = handler
            .run(&bad_params, make_context())
            .await
            .expect("Ok — invalid params surface via TaskOutcome::Failed");

        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(!retry, "operator-error params must NOT retry");
                assert!(
                    reason.contains("params JSON invalid") || reason.contains("invalid"),
                    "reason should mention invalid params: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// Empty `items` → Completed with all-zero summary.
    #[tokio::test]
    async fn empty_items_returns_completed_with_zero_summary() {
        let use_case = make_use_case_empty();
        let handler = SeedImportHandler::new(use_case);

        let params = json!({ "items": [] });

        let outcome = handler.run(&params, make_context()).await.expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["total"], 0);
                assert_eq!(result_summary["registered"], 0);
                assert_eq!(result_summary["already_imported"], 0);
                assert_eq!(result_summary["errors"], json!([]));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// Missing `actor_id` on the job row falls back to the nil-uuid
    /// sentinel — matches the system-actor convention.
    #[tokio::test]
    async fn missing_actor_id_falls_back_to_nil_uuid() {
        let use_case = make_use_case_empty();
        let handler = SeedImportHandler::new(use_case);

        let params = json!({ "items": [] });
        let ctx = TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: test_job_row(None),
        };

        let outcome = handler.run(&params, ctx).await.expect("Ok");
        assert!(matches!(outcome, TaskOutcome::Completed { .. }));
    }

    // -- helpers --------------------------------------------------------

    /// Build a fully-wired `SeedImportUseCase` with empty mocks so the
    /// handler tests can exercise param-parsing without seeding state.
    fn make_use_case_empty() -> Arc<SeedImportUseCase> {
        use std::collections::HashMap;

        use hort_domain::ports::format_handler::FormatHandler;

        use crate::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
        use crate::use_cases::ingest_use_case::IngestUseCase;
        use crate::use_cases::test_support::{
            MockArtifactGroupLifecyclePort, MockArtifactGroupRepository, MockArtifactLifecycle,
            MockArtifactRepository, MockContentReferenceIndex, MockCurationRuleRepository,
            MockEventStore, MockJobsRepository, MockPolicyProjectionRepository,
            MockRepositoryRepository, MockStoragePort, StubFormatHandler,
        };

        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_uc = Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let content_refs = Arc::new(MockContentReferenceIndex::new());
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let jobs = Arc::new(MockJobsRepository::default());

        let ingest = Arc::new(IngestUseCase::new(
            storage,
            lifecycle,
            artifacts.clone(),
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events),
            curation_rules,
            group_uc,
            true,
            HashMap::new(),
            0,
            content_refs,
            policies.clone(),
            jobs,
        ));

        let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
        handlers.insert("pypi".to_string(), Arc::new(StubFormatHandler::new("pypi")));

        Arc::new(SeedImportUseCase::new(
            ingest, policies, repos, artifacts, handlers,
        ))
    }
}
