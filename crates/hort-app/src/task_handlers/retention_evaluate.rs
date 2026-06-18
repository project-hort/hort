//! `RetentionEvaluateHandler`.
//!
//! The `kind = "retention-evaluate"` TaskHandler. Triggered by the
//! k8s CronJob (or operator host cron) hitting
//! `POST /api/v1/admin/tasks/retention-evaluate` (the route +
//! raw-params live in
//! `hort-http-admin-tasks`; this module only registers the handler
//! with the worker). Default schedule `0 3 * * *`. Thin orchestration, modelled
//! 1:1 on [`CronRescanTickHandler`](super::cron_rescan_tick):
//!
//! 1. Capture `now`.
//! 2. `RetentionPolicyProjectionRepository::list_active()` → the
//!    active retention policies (O(1) projection read, NOT a stream
//!    replay).
//! 3. Loop `RetentionCandidateReader::list_candidates(BATCH_SIZE,
//!    cursor, now)` advancing the keyset cursor until a short page (a
//!    per-tick total cap bounds one tick; the daily cron drains any
//!    backlog — identical posture to cron-rescan's single-shot cap).
//! 4. Per batch, map `RetentionCandidateRow → RetentionUseCase::
//!    RetentionCandidate` (a trivial field copy — the type stays in
//!    `hort-app`) and call
//!    `RetentionUseCase::evaluate_policies(now, &policies,
//!    &candidates)`, accumulating the per-batch [`EvaluateSummary`].
//! 5. Return [`TaskOutcome::Completed`] with the projected JSON.
//!
//! The handler appends nothing directly — `evaluate_policies` owns the
//! `ArtifactExpired` append. No new metrics are introduced; the handler
//! returns `result_summary` JSON only.

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::retention_candidate_reader::RetentionCandidateReader;
use hort_domain::ports::retention_policy_projection_repository::RetentionPolicyProjectionRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::use_cases::retention_use_case::{EvaluateSummary, RetentionCandidate, RetentionUseCase};

/// Per-batch keyset page size. Mirrors `CronRescanTickHandler`'s
/// `BATCH_SIZE` (a single tick fetches in 1000-row pages). The daily
/// cron drains backlog across runs; one tick cannot walk the entire
/// artifact table unbounded — see [`MAX_BATCHES_PER_TICK`].
const BATCH_SIZE: u32 = 1000;

/// Per-tick batch cap: at most this many keyset pages per invocation
/// (`MAX_BATCHES_PER_TICK * BATCH_SIZE` artifacts). Bounds one tick's
/// work even on a huge table; subsequent daily ticks drain the rest
/// (the cron-rescan single-shot-cap posture, applied to a keyset loop
/// because retention has no in-flight-job dedup to bound re-visits).
const MAX_BATCHES_PER_TICK: usize = 64;

/// [`TaskHandler`] for the periodic retention-evaluate sweep.
pub struct RetentionEvaluateHandler {
    policies: Arc<dyn RetentionPolicyProjectionRepository>,
    candidates: Arc<dyn RetentionCandidateReader>,
    retention: Arc<RetentionUseCase>,
}

impl RetentionEvaluateHandler {
    pub fn new(
        policies: Arc<dyn RetentionPolicyProjectionRepository>,
        candidates: Arc<dyn RetentionCandidateReader>,
        retention: Arc<RetentionUseCase>,
    ) -> Self {
        Self {
            policies,
            candidates,
            retention,
        }
    }
}

impl TaskHandler for RetentionEvaluateHandler {
    fn kind(&self) -> &'static str {
        "retention-evaluate"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();

            let policies = match self.policies.list_active().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "retention-evaluate: list_active failed");
                    return Ok(TaskOutcome::fail(format!("list_active failed: {e}"), true));
                }
            };
            if policies.is_empty() {
                // Steady state: no policies configured → no-op.
                tracing::info!("retention-evaluate: no active policies — no-op");
                return Ok(TaskOutcome::Completed {
                    result_summary: json!({
                        "policies": 0,
                        "evaluated": 0,
                        "expired": 0,
                        "already_expired": 0,
                        "skipped_protected": 0,
                        "skipped_stale_scan": 0,
                        "errors": 0,
                    }),
                });
            }

            let mut total = EvaluateSummary::default();
            let mut cursor: Option<uuid::Uuid> = None;
            for _ in 0..MAX_BATCHES_PER_TICK {
                let rows = match self
                    .candidates
                    .list_candidates(BATCH_SIZE, cursor, now)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "retention-evaluate: list_candidates failed"
                        );
                        return Ok(TaskOutcome::fail(
                            format!("list_candidates failed: {e}"),
                            true,
                        ));
                    }
                };
                if rows.is_empty() {
                    break;
                }
                cursor = rows.last().map(|r| r.artifact.id);
                let short_page = (rows.len() as u32) < BATCH_SIZE;

                // RetentionCandidateRow → RetentionCandidate
                // (trivial field copy).
                let candidates: Vec<RetentionCandidate> = rows
                    .into_iter()
                    .map(|r| RetentionCandidate {
                        artifact: r.artifact,
                        format: r.format,
                        resolved_rescan_interval_hours: r.resolved_rescan_interval_hours,
                    })
                    .collect();

                match self
                    .retention
                    .evaluate_policies(now, &policies, &candidates)
                    .await
                {
                    Ok(s) => accumulate(&mut total, &s),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "retention-evaluate: evaluate_policies failed"
                        );
                        return Ok(TaskOutcome::fail(
                            format!("evaluate_policies failed: {e}"),
                            true,
                        ));
                    }
                }

                if short_page {
                    break;
                }
            }

            tracing::info!(
                policies = policies.len(),
                evaluated = total.evaluated,
                expired = total.expired,
                already_expired = total.already_expired,
                skipped_protected = total.skipped_protected,
                skipped_stale_scan = total.skipped_stale_scan,
                errors = total.errors,
                "retention-evaluate sweep complete"
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "policies": policies.len(),
                    "evaluated": total.evaluated,
                    "expired": total.expired,
                    "already_expired": total.already_expired,
                    "skipped_protected": total.skipped_protected,
                    "skipped_stale_scan": total.skipped_stale_scan,
                    "errors": total.errors,
                }),
            })
        })
    }
}

fn accumulate(total: &mut EvaluateSummary, batch: &EvaluateSummary) {
    total.evaluated += batch.evaluated;
    total.expired += batch.expired;
    total.already_expired += batch.already_expired;
    total.skipped_protected += batch.skipped_protected;
    total.skipped_stale_scan += batch.skipped_stale_scan;
    total.errors += batch.errors;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use chrono::{DateTime, Utc};
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::error::DomainError;
    use hort_domain::events::{system_actor, StreamId};
    use hort_domain::ports::event_store::{
        AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
    };
    use hort_domain::ports::retention_candidate_reader::RetentionCandidateRow;
    use hort_domain::ports::retention_scan_reader::RetentionScanReader;
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::retention::RetentionPolicy;
    use uuid::Uuid;

    fn art(id: Uuid) -> Artifact {
        Artifact {
            id,
            repository_id: Uuid::new_v4(),
            name: "pkg".into(),
            name_as_published: "pkg".into(),
            version: Some("1.0.0".into()),
            path: "pkg/1.0.0".into(),
            size_bytes: 10,
            sha256_checksum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::Released,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            updated_at: DateTime::<Utc>::UNIX_EPOCH,
        }
    }

    // -- mock projection reader --
    struct MockPolicies {
        rows: Mutex<Vec<RetentionPolicy>>,
        err: Mutex<Option<DomainError>>,
    }
    impl MockPolicies {
        fn new(rows: Vec<RetentionPolicy>) -> Self {
            Self {
                rows: Mutex::new(rows),
                err: Mutex::new(None),
            }
        }
        fn failing() -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                err: Mutex::new(Some(DomainError::Invariant("boom".into()))),
            }
        }
    }
    impl RetentionPolicyProjectionRepository for MockPolicies {
        fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicy>>> {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            let v = self.rows.lock().unwrap().clone();
            Box::pin(async move { Ok(v) })
        }
        fn find_by_name(
            &self,
            _n: &str,
        ) -> BoxFuture<
            '_,
            DomainResult<
                Option<
                    hort_domain::ports::retention_policy_projection_repository::RetentionPolicyRow,
                >,
            >,
        > {
            Box::pin(async { Ok(None) })
        }
        fn find_by_name_including_archived(
            &self,
            _n: &str,
        ) -> BoxFuture<
            '_,
            DomainResult<
                Option<
                    hort_domain::ports::retention_policy_projection_repository::RetentionPolicyRow,
                >,
            >,
        > {
            Box::pin(async { Ok(None) })
        }
        fn list_active_rows(
            &self,
        ) -> BoxFuture<
            '_,
            DomainResult<
                Vec<hort_domain::ports::retention_policy_projection_repository::RetentionPolicyRow>,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn upsert(
            &self,
            _r: &hort_domain::ports::retention_policy_projection_repository::RetentionPolicyRow,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -- mock candidate reader --
    struct MockCandidates {
        pages: Mutex<Vec<Vec<RetentionCandidateRow>>>,
        err: Mutex<Option<DomainError>>,
    }
    impl MockCandidates {
        fn new(pages: Vec<Vec<RetentionCandidateRow>>) -> Self {
            Self {
                pages: Mutex::new(pages),
                err: Mutex::new(None),
            }
        }
        fn failing() -> Self {
            Self {
                pages: Mutex::new(Vec::new()),
                err: Mutex::new(Some(DomainError::Invariant("boom".into()))),
            }
        }
    }
    impl RetentionCandidateReader for MockCandidates {
        fn list_candidates<'a>(
            &'a self,
            _b: u32,
            _after: Option<Uuid>,
            _now: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>> {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            let next = {
                let mut p = self.pages.lock().unwrap();
                if p.is_empty() {
                    Vec::new()
                } else {
                    p.remove(0)
                }
            };
            Box::pin(async move { Ok(next) })
        }
    }

    // -- mock event store + scan reader for the RetentionUseCase --
    struct InertEvents;
    impl EventStore for InertEvents {
        fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            let n = batch.events.len() as u64;
            Box::pin(async move {
                Ok(AppendResult {
                    stream_position: n.saturating_sub(1),
                    global_positions: (0..n).collect(),
                })
            })
        }
        fn read_stream(
            &self,
            _s: &StreamId,
            _f: ReadFrom,
            _m: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn read_category(
            &self,
            _c: hort_domain::events::StreamCategory,
            _f: SubscribeFrom,
            _m: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn delete_stream(&self, _s: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!() })
        }
        fn archive_stream(&self, _s: StreamId, _t: &str) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!() })
        }
    }
    struct InertScan;
    impl RetentionScanReader for InertScan {
        fn list_findings_for_artifact(
            &self,
            _a: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::types::Finding>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn repo_security_score(
            &self,
            _r: Uuid,
        ) -> BoxFuture<
            '_,
            DomainResult<
                Option<hort_domain::ports::repo_security_score_repository::RepoSecurityScore>,
            >,
        > {
            Box::pin(async { Ok(None) })
        }
    }

    fn retention_uc() -> Arc<RetentionUseCase> {
        Arc::new(RetentionUseCase::new(
            crate::event_store_publisher::wrap_for_test(Arc::new(InertEvents)),
            Arc::new(InertScan),
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
                kind: "retention-evaluate".into(),
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

    fn age_policy() -> RetentionPolicy {
        // A pure-age policy that matches nothing here (artifacts are
        // UNIX_EPOCH..now; the evaluator's pure match is exercised by
        // the use-case's own tests — this handler test only asserts
        // orchestration counts + the projection/JSON shape).
        RetentionPolicy::project(&[hort_domain::retention::RetentionPolicyEvent::Created {
            id: Uuid::new_v4(),
            name: "p".into(),
            predicate: hort_domain::retention::PolicyPredicate::AgeExceeds(100 * 365 * 24 * 3600),
            scope: hort_domain::retention::RetentionScope::AllRepos,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
        }])
        .unwrap()
    }

    #[test]
    fn kind_is_retention_evaluate() {
        let h = RetentionEvaluateHandler::new(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![])),
            retention_uc(),
        );
        assert_eq!(h.kind(), "retention-evaluate");
    }

    #[tokio::test]
    async fn empty_policies_is_completed_noop() {
        let h = RetentionEvaluateHandler::new(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![vec![]])),
            retention_uc(),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["policies"], 0);
                assert_eq!(result_summary["evaluated"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn happy_path_evaluates_candidates_and_projects_summary() {
        let rows = vec![
            RetentionCandidateRow {
                artifact: art(Uuid::new_v4()),
                format: hort_domain::entities::repository::RepositoryFormat::Generic,
                resolved_rescan_interval_hours: Some(24),
            },
            RetentionCandidateRow {
                artifact: art(Uuid::new_v4()),
                format: hort_domain::entities::repository::RepositoryFormat::Generic,
                resolved_rescan_interval_hours: None,
            },
        ];
        let h = RetentionEvaluateHandler::new(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            Arc::new(MockCandidates::new(vec![rows])),
            retention_uc(),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["policies"], 1);
                // 1 policy × 2 candidates evaluated.
                assert_eq!(result_summary["evaluated"], 2);
                assert_eq!(result_summary["expired"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_active_error_fails_with_retry() {
        let h = RetentionEvaluateHandler::new(
            Arc::new(MockPolicies::failing()),
            Arc::new(MockCandidates::new(vec![])),
            retention_uc(),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry);
                assert!(reason.contains("list_active"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_candidates_error_fails_with_retry() {
        let h = RetentionEvaluateHandler::new(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            Arc::new(MockCandidates::failing()),
            retention_uc(),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry);
                assert!(reason.contains("list_candidates"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
