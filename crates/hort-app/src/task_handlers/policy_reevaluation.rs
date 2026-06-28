//! `policy-reevaluation` TaskHandler (ADR 0041 Item 3).
//!
//! Wraps [`PolicyUseCase`] for worker dispatch. A gate-affecting
//! scan-policy mutation (`update_policy` gate fields, `add_exclusion`,
//! `remove_exclusion`, `reactivate_policy`) enqueues ONE row of this kind
//! carrying `{ policy_id, trigger }` in `params`; the worker claims the
//! row and dispatches here, off the policy-mutation request path.
//!
//! The handler is a thin adapter — params parsing + delegation. The
//! population walk + both-direction transitions live in
//! [`PolicyUseCase::run_policy_re_evaluation_pass`], which re-derives each
//! in-scope artifact's verdict from its **stored findings** under the
//! bumped policy and transitions in both directions (loosen → release /
//! re-quarantine; tighten → re-hold). It reads stored evidence only — no
//! scanner is invoked.
//!
//! **Idempotency / concurrency model (ADR 0041, explicit).** This is
//! **not** an ADR 0028 destructive task; it carries no per-UTC-day
//! idempotency key and needs no seal-pool single-flight. The pass is
//! naturally **verdict-idempotent** — a re-run over the same stored
//! evidence + policy reaches the same verdict, so a duplicate enqueue at
//! worst re-runs an all-no-ops pass. And `commit_transition` carries
//! event-version optimistic concurrency, so two passes racing over the
//! same population are safe: a stale transition fails its version check
//! and is skipped as a best-effort. The pass itself is total — a
//! per-artifact infrastructure failure is logged and skipped, never
//! aborting the population — so this handler maps every successful pass
//! invocation to [`TaskOutcome::Completed`]; only a malformed `params`
//! envelope (operator/enqueuer error, not infrastructure) is a
//! non-retryable [`TaskOutcome::Failed`].
//!
//! Worker registration in the dispatch table lives in the `hort-worker`
//! composition root, not here.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use hort_domain::error::DomainResult;
use hort_domain::events::ReEvaluationTrigger;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::use_cases::policy_use_case::PolicyUseCase;

/// Shape of the `params` JSON the enqueue path writes onto the job row
/// (`PolicyUseCase::enqueue_re_evaluation`).
///
/// `policy_id` is the policy whose population is re-evaluated; `trigger`
/// is the [`ReEvaluationTrigger`] discriminator naming the driving
/// change (for the `ArtifactReEvaluated` audit attribution, invariant
/// #3). Both are required — a missing/garbled field is an enqueuer bug,
/// surfaced as a non-retryable `Failed`.
#[derive(Debug, Deserialize)]
struct PolicyReEvaluationParams {
    policy_id: Uuid,
    trigger: ReEvaluationTrigger,
}

/// `TaskHandler` impl for `kind = "policy-reevaluation"`. Constructed at
/// worker composition time with the use case.
pub struct PolicyReEvaluationHandler {
    use_case: Arc<PolicyUseCase>,
}

impl PolicyReEvaluationHandler {
    pub fn new(use_case: Arc<PolicyUseCase>) -> Self {
        Self { use_case }
    }
}

impl TaskHandler for PolicyReEvaluationHandler {
    fn kind(&self) -> &'static str {
        "policy-reevaluation"
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            // Parse params. Invalid JSON → non-retryable Failed (the
            // enqueue path wrote a fixed shape; a malformed envelope is an
            // enqueuer defect, not a transient flake — retrying re-parses
            // the same bad bytes).
            let parsed: PolicyReEvaluationParams = match serde_json::from_value(params.clone()) {
                Ok(p) => p,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("policy-reevaluation params JSON invalid: {err}"),
                        false,
                    ));
                }
            };

            // Delegate. The pass is best-effort and total (it logs +
            // skips per-artifact failures and never errors), so a
            // completed invocation is always `Completed`. The rich
            // per-pass observability (info! on pass-start + each
            // transition, the outcome metric, the completeness gauge)
            // lives inside `run_policy_re_evaluation_pass`.
            self.use_case
                .run_policy_re_evaluation_pass(parsed.policy_id, parsed.trigger)
                .await;

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "policy_id": parsed.policy_id,
                    "trigger": parsed.trigger,
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

    use chrono::{DateTime, Utc};

    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};

    fn test_job_row() -> JobRow {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        JobRow {
            id: Uuid::nil(),
            kind: "policy-reevaluation".to_string(),
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

    /// Build a `PolicyReEvaluationHandler` over a `PolicyUseCase` wired
    /// with default empty mocks (mirrors `seed_import.rs`'s
    /// `make_use_case_empty`). Every mock is empty, so the wrapped pass
    /// walks an empty population: `find_by_id` returns `None`
    /// (policy-missing → no-op) for the default-context tests, which is
    /// sufficient to exercise the handler's params-parse + delegation +
    /// outcome-mapping branches without re-testing the pass body (covered
    /// in `policy_use_case.rs`).
    fn handler() -> PolicyReEvaluationHandler {
        use crate::use_cases::repository_access::RbacAccess;
        use crate::use_cases::repository_access::RepositoryAccessUseCase;
        use crate::use_cases::test_support::{
            MockArtifactLifecycle, MockArtifactRepository, MockCurationRuleRepository,
            MockEventStore, MockJobsRepository, MockPolicyProjectionRepository,
            MockRepositoryRepository, MockStoragePort,
        };

        let artifacts = Arc::new(MockArtifactRepository::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let events = Arc::new(MockEventStore::new());
        let projections = Arc::new(MockPolicyProjectionRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let repository_access = Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Disabled,
            true,
        ));
        let jobs = Arc::new(MockJobsRepository::default());

        let use_case = PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events),
            projections,
            artifacts,
            lifecycle,
            storage,
            repository_access,
            curation_rules,
            jobs,
        );
        PolicyReEvaluationHandler::new(Arc::new(use_case))
    }

    #[test]
    fn kind_returns_policy_reevaluation() {
        assert_eq!(handler().kind(), "policy-reevaluation");
    }

    /// Well-formed params (the exact shape `enqueue_re_evaluation` writes)
    /// → the pass runs over an empty population and the handler returns
    /// `Completed` echoing the policy_id + trigger in the summary.
    #[tokio::test]
    async fn run_with_valid_params_completes() {
        let policy_id = Uuid::new_v4();
        let params = json!({
            "policy_id": policy_id,
            "trigger": ReEvaluationTrigger::PolicyUpdated { policy_id },
        });
        let outcome = handler().run(&params, make_context()).await.expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["policy_id"], json!(policy_id));
                assert_eq!(
                    result_summary["trigger"],
                    json!(ReEvaluationTrigger::PolicyUpdated { policy_id }),
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// The `ExclusionAdded` / `ExclusionRemoved` trigger variants the
    /// enqueue path writes also round-trip through the params.
    #[tokio::test]
    async fn run_round_trips_exclusion_triggers() {
        let policy_id = Uuid::new_v4();
        let exclusion_id = Uuid::new_v4();
        for trigger in [
            ReEvaluationTrigger::ExclusionAdded { exclusion_id },
            ReEvaluationTrigger::ExclusionRemoved { exclusion_id },
        ] {
            let params = json!({ "policy_id": policy_id, "trigger": trigger });
            let outcome = handler().run(&params, make_context()).await.expect("Ok");
            assert!(matches!(outcome, TaskOutcome::Completed { .. }));
        }
    }

    /// Malformed params (missing `trigger`) → non-retryable `Failed`. An
    /// enqueuer that wrote the wrong shape is a defect; retrying re-parses
    /// the same bad bytes, so `retry = false`.
    #[tokio::test]
    async fn run_with_missing_trigger_fails_non_retryable() {
        let params = json!({ "policy_id": Uuid::new_v4() });
        let outcome = handler()
            .run(&params, make_context())
            .await
            .expect("Ok — bad params surface as Failed, not an Err");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(!retry, "malformed params must NOT retry");
                assert!(
                    reason.contains("params JSON invalid"),
                    "reason should mention params: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
