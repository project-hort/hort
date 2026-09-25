//! `RetentionEvaluateHandler`.
//!
//! The `kind = "retention-evaluate"` TaskHandler. Triggered by the
//! k8s CronJob (or operator host cron) hitting
//! `POST /api/v1/admin/tasks/retention-evaluate` (the route +
//! typed params live in
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
//!    `RetentionUseCase::evaluate_policies_in_mode(now, &policies,
//!    &candidates, mode)`, accumulating the per-batch [`EvaluateSummary`]
//!    and matched rows.
//! 5. For a dry run, simulate the purge refcount decision and build a
//!    bounded operator sample; for execution, append expiry events at the
//!    same use-case boundary used before modes existed.
//! 6. Return [`TaskOutcome::Completed`] with the projected JSON.
//!
//! The handler appends nothing directly — `evaluate_policies_in_mode` owns
//! the `ArtifactExpired` append in execute mode and suppresses that append
//! in dry-run mode. No new metrics are introduced; the handler returns
//! `result_summary` JSON only.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use hort_domain::error::DomainResult;
use hort_domain::ports::retention_candidate_reader::RetentionCandidateReader;
use hort_domain::ports::retention_policy_projection_repository::RetentionPolicyProjectionRepository;
use hort_domain::ports::retention_preview::{RetentionContentSimulation, RetentionPreview};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use hort_domain::retention::RetentionEvaluationMode;

use crate::use_cases::retention_use_case::{
    EvaluateSummary, EvaluationMatch, EvaluationReport, RetentionCandidate, RetentionUseCase,
};

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

/// The curation queue's listing cap is the operator-facing precedent for a
/// bounded sanity-check sample.
const MAX_SAMPLE_SIZE: usize = 500;

/// Exact byte accounting is intentionally bounded. Above either limit the
/// result says `omitted`; it never extrapolates from a partial set.
const MAX_SIMULATION_ARTIFACTS: usize = 10_000;
const MAX_SIMULATION_TARGETS: u32 = 10_000;

/// [`TaskHandler`] for the periodic retention-evaluate sweep.
pub struct RetentionEvaluateHandler {
    policies: Arc<dyn RetentionPolicyProjectionRepository>,
    candidates: Arc<dyn RetentionCandidateReader>,
    retention: Arc<RetentionUseCase>,
    preview: Arc<dyn RetentionPreview>,
    storage: Arc<dyn StoragePort>,
}

impl RetentionEvaluateHandler {
    pub fn new(
        policies: Arc<dyn RetentionPolicyProjectionRepository>,
        candidates: Arc<dyn RetentionCandidateReader>,
        retention: Arc<RetentionUseCase>,
        preview: Arc<dyn RetentionPreview>,
        storage: Arc<dyn StoragePort>,
    ) -> Self {
        Self {
            policies,
            candidates,
            retention,
            preview,
            storage,
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
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();
            let mode_raw = params
                .get("mode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("execute");
            let mode = match RetentionEvaluationMode::from_str(mode_raw) {
                Ok(mode) => mode,
                Err(message) => return Ok(TaskOutcome::fail(message, false)),
            };

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
                        "mode": mode.as_str(),
                        "coverage": "complete",
                        "evaluated": 0,
                        "expired": 0,
                        "already_expired": 0,
                        "skipped_protected": 0,
                        "skipped_stale_scan": 0,
                        "errors": 0,
                        "preview": if mode == RetentionEvaluationMode::DryRun {
                            Some(json!({
                                "rows": 0,
                                "distinct_contents": 0,
                                "freed_bytes": { "status": "exact", "bytes": 0 },
                                "groups": [],
                                "sample": [],
                            }))
                        } else {
                            None
                        },
                    }),
                });
            }

            let mut total = EvaluateSummary::default();
            let mut matches = Vec::new();
            let mut cursor: Option<uuid::Uuid> = None;
            let mut coverage_complete = true;
            for batch_index in 0..MAX_BATCHES_PER_TICK {
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
                        repository_key: r.repository_key,
                        resolved_rescan_interval_hours: r.resolved_rescan_interval_hours,
                        keep_rank: r.keep_rank,
                        tag_targeted: r.tag_targeted,
                    })
                    .collect();

                match self
                    .retention
                    .evaluate_policies_in_mode(now, &policies, &candidates, mode)
                    .await
                {
                    Ok(report) => accumulate(&mut total, &mut matches, report),
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
                if batch_index + 1 == MAX_BATCHES_PER_TICK {
                    coverage_complete = false;
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

            let preview = if mode == RetentionEvaluationMode::DryRun {
                Some(self.build_preview(now, &matches).await)
            } else {
                None
            };

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "mode": mode.as_str(),
                    "coverage": if coverage_complete { "complete" } else { "partial" },
                    "policies": policies.len(),
                    "evaluated": total.evaluated,
                    "expired": total.expired,
                    "already_expired": total.already_expired,
                    "skipped_protected": total.skipped_protected,
                    "skipped_stale_scan": total.skipped_stale_scan,
                    "errors": total.errors,
                    "preview": preview,
                }),
            })
        })
    }
}

impl RetentionEvaluateHandler {
    async fn build_preview(
        &self,
        now: chrono::DateTime<Utc>,
        matches: &[EvaluationMatch],
    ) -> serde_json::Value {
        #[derive(Default)]
        struct Group {
            policy_name: String,
            repository_key: String,
            rows: u64,
            checksums: BTreeSet<String>,
        }

        let mut groups: BTreeMap<(uuid::Uuid, uuid::Uuid), Group> = BTreeMap::new();
        let mut distinct_contents = BTreeSet::new();
        let mut artifact_ids = BTreeSet::new();
        let mut sample = Vec::new();

        for hit in matches {
            let group = groups
                .entry((hit.policy_id, hit.repository_id))
                .or_default();
            group.policy_name.clone_from(&hit.policy_name);
            group.repository_key.clone_from(&hit.repository_key);
            group.rows += 1;
            group.checksums.insert(hit.checksum_sha256.clone());
            distinct_contents.insert(hit.checksum_sha256.clone());
            artifact_ids.insert(hit.artifact_id);
            if sample.len() < MAX_SAMPLE_SIZE {
                sample.push(json!({
                    "artifact_id": hit.artifact_id,
                    "policy_id": hit.policy_id,
                    "repository_id": hit.repository_id,
                    "repository_key": hit.repository_key,
                    "name": hit.name,
                    "version": hit.version,
                    "age_seconds": now.signed_duration_since(hit.created_at).num_seconds().max(0),
                }));
            }
        }

        let group_rows: Vec<_> = groups
            .into_iter()
            .map(|((policy_id, repository_id), group)| {
                json!({
                    "policy_id": policy_id,
                    "policy_name": group.policy_name,
                    "repository_id": repository_id,
                    "repository_key": group.repository_key,
                    "rows": group.rows,
                    "distinct_contents": group.checksums.len(),
                })
            })
            .collect();

        let artifact_ids: Vec<_> = artifact_ids.into_iter().collect();
        let freed_bytes = match self
            .preview
            .reclaimable_content(
                &artifact_ids,
                MAX_SIMULATION_ARTIFACTS,
                MAX_SIMULATION_TARGETS,
            )
            .await
        {
            Ok(RetentionContentSimulation::Exact(hashes)) => {
                let mut total = 0_u64;
                let mut omitted_reason = None;
                for hash in hashes {
                    match self.storage.size_of(&hash).await {
                        Ok(size) => match total.checked_add(size) {
                            Some(next) => total = next,
                            None => {
                                omitted_reason = Some("byte total overflowed u64");
                                break;
                            }
                        },
                        Err(error) => {
                            tracing::warn!(error = %error, "retention dry-run storage size lookup failed");
                            omitted_reason = Some("a reclaimable target size was unavailable");
                            break;
                        }
                    }
                }
                match omitted_reason {
                    Some(reason) => json!({ "status": "omitted", "reason": reason }),
                    None => json!({ "status": "exact", "bytes": total }),
                }
            }
            Ok(RetentionContentSimulation::Omitted) => json!({
                "status": "omitted",
                "reason": "simulation cardinality exceeded its exact-accounting bound",
            }),
            Err(error) => {
                tracing::warn!(error = %error, "retention dry-run refcount simulation failed");
                json!({
                    "status": "omitted",
                    "reason": "refcount simulation was unavailable",
                })
            }
        };

        json!({
            "rows": matches.len(),
            "distinct_contents": distinct_contents.len(),
            "freed_bytes": freed_bytes,
            "groups": group_rows,
            "sample": sample,
            "sample_limit": MAX_SAMPLE_SIZE,
        })
    }
}

fn accumulate(
    total: &mut EvaluateSummary,
    matches: &mut Vec<EvaluationMatch>,
    batch: EvaluationReport,
) {
    total.evaluated += batch.summary.evaluated;
    total.expired += batch.summary.expired;
    total.already_expired += batch.summary.already_expired;
    total.skipped_protected += batch.summary.skipped_protected;
    total.skipped_stale_scan += batch.summary.skipped_stale_scan;
    total.errors += batch.summary.errors;
    matches.extend(batch.matches);
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
    use hort_domain::ports::retention_preview::RetentionContentSimulation;
    use hort_domain::ports::retention_scan_reader::RetentionScanReader;
    use hort_domain::ports::storage::PutResult;
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::retention::RetentionPolicy;
    use hort_domain::types::{ByteRange, ContentHash};
    use tokio::io::AsyncRead;
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
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            provenance_hold_indefinite: false,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: None,
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

    struct InertPreview;
    impl RetentionPreview for InertPreview {
        fn reclaimable_content<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            _max_artifacts: usize,
            _max_targets: u32,
        ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
            Box::pin(async { Ok(RetentionContentSimulation::Exact(Vec::new())) })
        }
    }

    #[derive(Default)]
    struct InertStorage {
        sizes: std::collections::HashMap<ContentHash, u64>,
        fail_size: bool,
    }
    impl StoragePort for InertStorage {
        fn put(
            &self,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<PutResult>> {
            Box::pin(async { Err(DomainError::Invariant("unused put".into())) })
        }

        fn get(
            &self,
            _hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { Err(DomainError::Invariant("unused get".into())) })
        }

        fn get_range(
            &self,
            _hash: &ContentHash,
            _range: ByteRange,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { Err(DomainError::Invariant("unused get_range".into())) })
        }

        fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { Ok(false) })
        }

        fn size_of(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
            let result = if self.fail_size {
                Err(DomainError::Invariant("size unavailable".into()))
            } else {
                Ok(self.sizes.get(hash).copied().unwrap_or(0))
            };
            Box::pin(async move { result })
        }
    }

    fn handler(
        policies: Arc<dyn RetentionPolicyProjectionRepository>,
        candidates: Arc<dyn RetentionCandidateReader>,
    ) -> RetentionEvaluateHandler {
        RetentionEvaluateHandler::new(
            policies,
            candidates,
            retention_uc(),
            Arc::new(InertPreview),
            Arc::new(InertStorage::default()),
        )
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

    fn archived_age_policy() -> RetentionPolicy {
        let id = Uuid::new_v4();
        RetentionPolicy::project(&[
            hort_domain::retention::RetentionPolicyEvent::Created {
                id,
                name: "archived".into(),
                predicate: hort_domain::retention::PolicyPredicate::AgeExceeds(1),
                scope: hort_domain::retention::RetentionScope::AllRepos,
                created_at: DateTime::<Utc>::UNIX_EPOCH,
            },
            hort_domain::retention::RetentionPolicyEvent::Archived {
                id,
                by: Uuid::nil(),
                archived_at: DateTime::<Utc>::UNIX_EPOCH,
            },
        ])
        .unwrap()
    }

    #[test]
    fn kind_is_retention_evaluate() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![])),
        );
        assert_eq!(h.kind(), "retention-evaluate");
    }

    #[tokio::test]
    async fn empty_policies_is_completed_noop() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![vec![]])),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["policies"], 0);
                assert_eq!(result_summary["evaluated"], 0);
                assert_eq!(result_summary["mode"], "execute");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_policies_dry_run_returns_an_exact_empty_preview() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![vec![]])),
        );
        match h.run(&json!({ "mode": "dry_run" }), ctx()).await.unwrap() {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["mode"], "dry_run");
                assert_eq!(result_summary["preview"]["rows"], 0);
                assert_eq!(result_summary["preview"]["distinct_contents"], 0);
                assert_eq!(result_summary["preview"]["freed_bytes"]["bytes"], 0);
                assert_eq!(result_summary["preview"]["groups"], json!([]));
                assert_eq!(result_summary["preview"]["sample"], json!([]));
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
                repository_key: "npm-proxy".into(),
                resolved_rescan_interval_hours: Some(24),
                keep_rank: Some((4, 10)),
                tag_targeted: false,
            },
            RetentionCandidateRow {
                artifact: art(Uuid::new_v4()),
                format: hort_domain::entities::repository::RepositoryFormat::Generic,
                repository_key: "npm-proxy".into(),
                resolved_rescan_interval_hours: None,
                keep_rank: None,
                tag_targeted: true,
            },
        ];
        let h = handler(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            Arc::new(MockCandidates::new(vec![rows])),
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
        let h = handler(
            Arc::new(MockPolicies::failing()),
            Arc::new(MockCandidates::new(vec![])),
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
        let h = handler(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            Arc::new(MockCandidates::failing()),
        );
        match h.run(&serde_json::Value::Null, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry);
                assert!(reason.contains("list_candidates"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_mode_fails_without_retry() {
        let h = handler(
            Arc::new(MockPolicies::new(vec![age_policy()])),
            Arc::new(MockCandidates::new(vec![])),
        );
        match h
            .run(&json!({ "mode": "preview" }), ctx())
            .await
            .expect("outcome")
        {
            TaskOutcome::Failed { retry, reason } => {
                assert!(!retry);
                assert!(reason.contains("execute, dry_run"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    fn evaluation_match(
        artifact_id: Uuid,
        policy_id: Uuid,
        repository_id: Uuid,
        checksum: &str,
    ) -> EvaluationMatch {
        evaluation_match_in(artifact_id, policy_id, repository_id, "npm-proxy", checksum)
    }

    fn evaluation_match_in(
        artifact_id: Uuid,
        policy_id: Uuid,
        repository_id: Uuid,
        repository_key: &str,
        checksum: &str,
    ) -> EvaluationMatch {
        EvaluationMatch {
            policy_id,
            policy_name: "cleanup".into(),
            artifact_id,
            repository_id,
            repository_key: repository_key.into(),
            name: "pkg".into(),
            version: Some("1.0.0".into()),
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            checksum_sha256: checksum.into(),
        }
    }

    struct FixedPreview(RetentionContentSimulation);
    impl RetentionPreview for FixedPreview {
        fn reclaimable_content<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            _max_artifacts: usize,
            _max_targets: u32,
        ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
            let value = self.0.clone();
            Box::pin(async move { Ok(value) })
        }
    }

    struct FailingPreview;
    impl RetentionPreview for FailingPreview {
        fn reclaimable_content<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            _max_artifacts: usize,
            _max_targets: u32,
        ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
            Box::pin(async { Err(DomainError::Invariant("simulation unavailable".into())) })
        }
    }

    fn preview_handler(
        preview: Arc<dyn RetentionPreview>,
        storage: Arc<dyn StoragePort>,
    ) -> RetentionEvaluateHandler {
        RetentionEvaluateHandler::new(
            Arc::new(MockPolicies::new(vec![])),
            Arc::new(MockCandidates::new(vec![])),
            retention_uc(),
            preview,
            storage,
        )
    }

    #[tokio::test]
    async fn preview_reports_literal_bytes_and_caps_sample() {
        const HASH_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        const HASH_B: &str = "4444444444444444444444444444444444444444444444444444444444444444";
        let hash_a: ContentHash = HASH_A.parse().unwrap();
        let hash_b: ContentHash = HASH_B.parse().unwrap();
        let mut sizes = std::collections::HashMap::new();
        sizes.insert(hash_a.clone(), 11);
        sizes.insert(hash_b.clone(), 29);
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![
                hash_a, hash_b,
            ]))),
            Arc::new(InertStorage {
                sizes,
                fail_size: false,
            }),
        );
        let policy_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let matches: Vec<_> = (0..501)
            .map(|_| evaluation_match(Uuid::new_v4(), policy_id, repository_id, HASH_A))
            .collect();

        let preview = h.build_preview(Utc::now(), &matches).await;
        assert_eq!(preview["rows"], 501);
        assert_eq!(preview["distinct_contents"], 1);
        assert_eq!(preview["groups"][0]["rows"], 501);
        assert_eq!(preview["groups"][0]["distinct_contents"], 1);
        assert_eq!(preview["sample"].as_array().unwrap().len(), 500);
        assert_eq!(preview["sample_limit"], 500);
        assert_eq!(preview["freed_bytes"]["status"], "exact");
        assert_eq!(preview["freed_bytes"]["bytes"], 40);
    }

    /// The preview names repositories by the key an operator writes into
    /// a policy, beside the id a machine consumer joins on — in both the
    /// grouped rollup and the sample. Two repositories with distinct keys
    /// must stay distinguishable without resolving a UUID.
    #[tokio::test]
    async fn preview_carries_the_repository_key_in_groups_and_sample() {
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![]))),
            Arc::new(InertStorage::default()),
        );
        let policy_id = Uuid::new_v4();
        let npm_repo = Uuid::new_v4();
        let pypi_repo = Uuid::new_v4();
        let matches = vec![
            evaluation_match_in(
                Uuid::new_v4(),
                policy_id,
                npm_repo,
                "npm-proxy",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            evaluation_match_in(
                Uuid::new_v4(),
                policy_id,
                pypi_repo,
                "pypi-proxy",
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
        ];

        let preview = h.build_preview(Utc::now(), &matches).await;

        let groups = preview["groups"].as_array().expect("groups array");
        assert_eq!(groups.len(), 2, "one group per (policy, repository)");
        let keyed: BTreeMap<&str, &str> = groups
            .iter()
            .map(|g| {
                (
                    g["repository_id"].as_str().expect("repository_id"),
                    g["repository_key"].as_str().expect("repository_key"),
                )
            })
            .collect();
        assert_eq!(keyed.get(npm_repo.to_string().as_str()), Some(&"npm-proxy"));
        assert_eq!(
            keyed.get(pypi_repo.to_string().as_str()),
            Some(&"pypi-proxy")
        );

        let sample = preview["sample"].as_array().expect("sample array");
        let sample_keys: BTreeSet<&str> = sample
            .iter()
            .map(|row| row["repository_key"].as_str().expect("repository_key"))
            .collect();
        assert_eq!(
            sample_keys,
            ["npm-proxy", "pypi-proxy"].into_iter().collect(),
            "the sample names repositories by key too"
        );
        for row in sample {
            assert!(
                row["repository_id"].is_string(),
                "the id stays beside the key for machine consumers"
            );
        }
    }

    #[tokio::test]
    async fn preview_explicitly_omits_bytes_for_bounds_or_port_failure() {
        let bounded = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Omitted)),
            Arc::new(InertStorage::default()),
        );
        let omitted = bounded.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .unwrap()
            .contains("cardinality"));

        let failed = preview_handler(Arc::new(FailingPreview), Arc::new(InertStorage::default()));
        let omitted = failed.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .unwrap()
            .contains("unavailable"));
    }

    #[tokio::test]
    async fn preview_omits_bytes_when_storage_size_is_unavailable() {
        let hash: ContentHash = "1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![hash]))),
            Arc::new(InertStorage {
                sizes: Default::default(),
                fail_size: true,
            }),
        );
        let omitted = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .unwrap()
            .contains("size"));
    }

    #[tokio::test]
    async fn preview_omits_bytes_when_exact_total_overflows() {
        let first: ContentHash = "1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let second: ContentHash =
            "4444444444444444444444444444444444444444444444444444444444444444"
                .parse()
                .unwrap();
        let mut sizes = std::collections::HashMap::new();
        sizes.insert(first.clone(), u64::MAX);
        sizes.insert(second.clone(), 1);
        let h = preview_handler(
            Arc::new(FixedPreview(RetentionContentSimulation::Exact(vec![
                first, second,
            ]))),
            Arc::new(InertStorage {
                sizes,
                fail_size: false,
            }),
        );

        let omitted = h.build_preview(Utc::now(), &[]).await;
        assert_eq!(omitted["freed_bytes"]["status"], "omitted");
        assert!(omitted["freed_bytes"]["reason"]
            .as_str()
            .unwrap()
            .contains("overflowed"));
    }

    #[tokio::test]
    async fn inert_storage_non_size_methods_are_explicit_test_failures() {
        let storage = InertStorage::default();
        let hash: ContentHash = "1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        assert!(storage.put(Box::new(tokio::io::empty())).await.is_err());
        assert!(storage.get(&hash).await.is_err());
        assert!(storage
            .get_range(&hash, ByteRange::Inclusive { start: 0, end: 0 })
            .await
            .is_err());
        assert!(!storage.exists(&hash).await.unwrap());
    }

    struct FullPageCandidates {
        row: RetentionCandidateRow,
    }

    impl RetentionCandidateReader for FullPageCandidates {
        fn list_candidates<'a>(
            &'a self,
            batch_size: u32,
            _after: Option<Uuid>,
            _now: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>> {
            let rows = vec![self.row.clone(); batch_size as usize];
            Box::pin(async move { Ok(rows) })
        }
    }

    #[tokio::test]
    async fn batch_ceiling_is_reported_as_partial_coverage() {
        let row = RetentionCandidateRow {
            artifact: art(Uuid::new_v4()),
            format: hort_domain::entities::repository::RepositoryFormat::Generic,
            repository_key: "npm-proxy".into(),
            resolved_rescan_interval_hours: None,
            keep_rank: None,
            tag_targeted: false,
        };
        let h = handler(
            Arc::new(MockPolicies::new(vec![archived_age_policy()])),
            Arc::new(FullPageCandidates { row }),
        );
        match h.run(&json!({ "mode": "dry_run" }), ctx()).await.unwrap() {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["coverage"], "partial");
                assert_eq!(result_summary["preview"]["rows"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }
}
