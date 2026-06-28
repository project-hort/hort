//! TaskHandler for the periodic advisory-watch sweep.
//!
//! Triggered by the k8s CronJob (or operator host cron) hitting
//! `POST /api/v1/admin/tasks/advisory-watch-tick` (the admin-task
//! framework). Default schedule `0 */6 * * *` (every 6 hours). The
//! handler is a thin orchestration step:
//!
//! 1. Read the per-feed `last_sync_at` checkpoint from
//!    [`AdvisorySyncStateRepository`]. Defensive `now() - 24h` fallback
//!    when the row is missing — production is seeded at install time,
//!    but a fresh test database / manually-truncated row must
//!    not crash the watch tick.
//! 2. Call [`AdvisoryPort::pull_diff_since`] which fans out across the
//!    configured per-ecosystem `osv-vulnerabilities` archives, returns
//!    the flat union of advisory entries with `modified > since`, and
//!    flags partial-ecosystem failure via
//!    [`AdvisoryDiffResult::all_ecosystems_ok`].
//! 3. For each fresh entry, look up the matching artifacts in the local
//!    SBOM index via [`SbomComponentRepository::list_artifacts_by_match`]
//!    keyed on `(ecosystem, name, affected_versions)`, then load each
//!    artifact's `(repository_id, content_hash)` from
//!    [`ArtifactRepository::find_by_id`] plus the repo's `format` from
//!    [`RepositoryRepository::find_by_id`], and insert a `kind='scan'`
//!    row via [`JobsRepository::enqueue_scan`] with `priority=5` and
//!    `trigger_source="advisory"`.
//! 4. Advance the checkpoint via
//!    [`AdvisorySyncStateRepository::set_last_sync_at`] **only when
//!    every ecosystem succeeded** — partial failure preserves the prior
//!    timestamp so the next tick re-attempts the missed window.
//!
//! `ON CONFLICT DO NOTHING` semantics for `enqueue_scan` are layered:
//! the partial unique index `(artifact_id) WHERE kind='scan'` surfaces
//! a race against another trigger source as `DomainError::Conflict`,
//! which the handler swallows per-row (mirroring
//! the cron rescan's behaviour).
//!
//! Worker registration in the dispatch table lives in the
//! `hort-worker` composition root, not here.

use std::sync::Arc;

use chrono::{Duration, Utc};
use serde_json::json;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::advisory::AdvisoryPort;
use hort_domain::ports::advisory_sync_state::AdvisorySyncStateRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::sbom_component_repository::SbomComponentRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::metrics::{emit_scan_jobs_enqueued, TriggerSourceLabel};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Priority bucket for advisory-enqueued scans.
///
/// Lower than cron (10) and manual (20) — the cron rescan is the
/// safety-net path that catches anything advisory missed, so it gets
/// claimed first.
const ADVISORY_PRIORITY: i16 = 5;

/// `trigger_source` literal — must match the SQL CHECK constraint on
/// `jobs.trigger_source` (`'manual' | 'cron' | 'advisory' | 'ingest'`).
/// Mirrors [`hort_domain::ports::jobs_repository::TriggerSource::Advisory`].
///
/// The literal is `"advisory"` NOT `"advisory_watch"` — this is the
/// exact wire form the `TriggerSource::as_str` pin and the
/// SQL CHECK accept. A drift here would either fail the INSERT loudly
/// or, if the CHECK were ever loosened, end up filed under the wrong
/// observability bucket silently.
const ADVISORY_TRIGGER_SOURCE: &str = "advisory";

/// `feed` PRIMARY-KEY literal in `advisory_sync_state`. v1 only carries
/// the OSV feed; future feeds (GitHub Advisory) add their own row
/// without a schema change.
const FEED_OSV: &str = "osv";

/// Defensive cold-start window (the production path is
/// the install-time seed at `now() - 24h`, but a fresh test DB or a
/// manually-truncated row must not crash).
const COLD_START_WINDOW_HOURS: i64 = 24;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the periodic advisory-watch sweep. Constructed at
/// composition time with the six ports it touches.
pub struct AdvisoryWatchTickHandler {
    advisory: Arc<dyn AdvisoryPort>,
    sbom: Arc<dyn SbomComponentRepository>,
    jobs: Arc<dyn JobsRepository>,
    sync_state: Arc<dyn AdvisorySyncStateRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    repositories: Arc<dyn RepositoryRepository>,
}

impl AdvisoryWatchTickHandler {
    /// Construct the handler from its six port dependencies.
    pub fn new(
        advisory: Arc<dyn AdvisoryPort>,
        sbom: Arc<dyn SbomComponentRepository>,
        jobs: Arc<dyn JobsRepository>,
        sync_state: Arc<dyn AdvisorySyncStateRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        repositories: Arc<dyn RepositoryRepository>,
    ) -> Self {
        Self {
            advisory,
            sbom,
            jobs,
            sync_state,
            artifacts,
            repositories,
        }
    }
}

impl TaskHandler for AdvisoryWatchTickHandler {
    fn kind(&self) -> &'static str {
        "advisory-watch-tick"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            // 1. Read the checkpoint. None resolves to `now() - 24h`
            //    defensively (the production path always sees Some(_)
            //    post-migration).
            let now = Utc::now();
            let last_sync_at = match self.sync_state.get_last_sync_at(FEED_OSV).await {
                Ok(Some(t)) => t,
                Ok(None) => {
                    tracing::warn!(
                        feed = FEED_OSV,
                        "advisory watch tick: sync-state row missing; falling back to now() - 24h",
                    );
                    now - Duration::hours(COLD_START_WINDOW_HOURS)
                }
                Err(err) => {
                    tracing::warn!(
                        feed = FEED_OSV,
                        error = %err,
                        "advisory watch tick: get_last_sync_at failed; will retry on next tick",
                    );
                    return Ok(TaskOutcome::fail(
                        format!("get_last_sync_at failed: {err}"),
                        true,
                    ));
                }
            };

            // 2. Pull the diff. A pull-level error short-circuits the
            //    entire tick — no entries to process, no checkpoint to
            //    advance.
            let diff = match self.advisory.pull_diff_since(last_sync_at).await {
                Ok(d) => d,
                Err(err) => {
                    tracing::warn!(
                        feed = FEED_OSV,
                        %last_sync_at,
                        error = %err,
                        "advisory watch tick: pull_diff_since failed; will retry on next tick",
                    );
                    return Ok(TaskOutcome::fail(
                        format!("pull_diff_since failed: {err}"),
                        true,
                    ));
                }
            };

            // 3. For each fresh entry, find matching artifacts and
            //    enqueue per-artifact scan jobs.
            let mut considered: u64 = 0;
            let mut enqueued: u64 = 0;
            for entry in &diff.entries {
                // Belt-and-braces — the adapter already filters
                // `modified > since`, but the handler re-checks so a
                // future adapter change can't accidentally re-process
                // the entire feed.
                if entry.modified <= last_sync_at {
                    continue;
                }
                for pkg in &entry.affected {
                    if pkg.affected_versions.is_empty() {
                        // Empty `versions` short-circuits the SBOM
                        // lookup contract; skip without round-trip.
                        continue;
                    }
                    let artifact_ids = match self
                        .sbom
                        .list_artifacts_by_match(&pkg.ecosystem, &pkg.name, &pkg.affected_versions)
                        .await
                    {
                        Ok(ids) => ids,
                        Err(err) => {
                            tracing::warn!(
                                advisory_id = %entry.id,
                                ecosystem = ?pkg.ecosystem,
                                name = %pkg.name,
                                error = %err,
                                "advisory watch tick: list_artifacts_by_match failed; \
                                 will retry on next tick",
                            );
                            return Ok(TaskOutcome::fail(
                                format!("list_artifacts_by_match failed: {err}"),
                                true,
                            ));
                        }
                    };
                    considered += artifact_ids.len() as u64;

                    for aid in artifact_ids {
                        // Resolve artifact → (repository_id, content_hash).
                        let artifact = match self.artifacts.find_by_id(aid).await {
                            Ok(a) => a,
                            Err(DomainError::NotFound { .. }) => {
                                // Race: the artifact was deleted
                                // between the SBOM lookup and the
                                // per-row enqueue. Skip — the SBOM
                                // projection will catch up on the next
                                // record_scan_result.
                                tracing::debug!(
                                    artifact_id = %aid,
                                    advisory_id = %entry.id,
                                    "advisory watch tick: artifact disappeared between \
                                     sbom match and enqueue; skipping",
                                );
                                continue;
                            }
                            Err(err) => {
                                tracing::warn!(
                                    artifact_id = %aid,
                                    error = %err,
                                    "advisory watch tick: artifact lookup failed; \
                                     will retry on next tick",
                                );
                                return Ok(TaskOutcome::fail(
                                    format!("find_artifact_by_id failed: {err}"),
                                    true,
                                ));
                            }
                        };

                        // Resolve parent repo → format string. Same
                        // `Display`-rendered lowercase literal the
                        // worker dispatches on; mirrors the manual
                        // rescan use case.
                        let repo = match self.repositories.find_by_id(artifact.repository_id).await
                        {
                            Ok(r) => r,
                            Err(DomainError::NotFound { .. }) => {
                                tracing::debug!(
                                    artifact_id = %aid,
                                    repository_id = %artifact.repository_id,
                                    advisory_id = %entry.id,
                                    "advisory watch tick: parent repo disappeared between \
                                     sbom match and enqueue; skipping",
                                );
                                continue;
                            }
                            Err(err) => {
                                tracing::warn!(
                                    artifact_id = %aid,
                                    repository_id = %artifact.repository_id,
                                    error = %err,
                                    "advisory watch tick: repository lookup failed; \
                                     will retry on next tick",
                                );
                                return Ok(TaskOutcome::fail(
                                    format!("find_repository_by_id failed: {err}"),
                                    true,
                                ));
                            }
                        };
                        let format = repo.format.to_string();

                        match self
                            .jobs
                            .enqueue_scan(
                                aid,
                                artifact.repository_id,
                                &artifact.sha256_checksum,
                                &format,
                                ADVISORY_PRIORITY,
                                ADVISORY_TRIGGER_SOURCE,
                            )
                            .await
                        {
                            Ok(_) => {
                                enqueued += 1;
                            }
                            Err(DomainError::Conflict(_)) => {
                                // ON CONFLICT (against the partial
                                // unique index `(artifact_id) WHERE
                                // kind='scan'`) DO NOTHING — a race
                                // against ingest, manual rescan, or
                                // cron resolves harmlessly.
                                tracing::debug!(
                                    artifact_id = %aid,
                                    advisory_id = %entry.id,
                                    "advisory watch tick: enqueue conflict swallowed \
                                     (race against another trigger source)",
                                );
                            }
                            Err(err) => {
                                tracing::warn!(
                                    artifact_id = %aid,
                                    error = %err,
                                    "advisory watch tick: enqueue_scan failed; \
                                     will retry on next tick",
                                );
                                return Ok(TaskOutcome::fail(
                                    format!("enqueue_scan failed: {err}"),
                                    true,
                                ));
                            }
                        }
                    }
                }
            }

            // 4. Advance the checkpoint only on full success across
            //    every ecosystem. Partial failure preserves the prior
            //    timestamp so the next tick re-attempts the missed
            //    window.
            let checkpoint_advanced = diff.all_ecosystems_ok;
            if checkpoint_advanced {
                if let Err(err) = self.sync_state.set_last_sync_at(FEED_OSV, now).await {
                    tracing::warn!(
                        feed = FEED_OSV,
                        error = %err,
                        "advisory watch tick: set_last_sync_at failed; \
                         enqueued jobs persisted but checkpoint not advanced",
                    );
                    return Ok(TaskOutcome::fail(
                        format!("set_last_sync_at failed: {err}"),
                        true,
                    ));
                }
            }

            // `hort_scan_jobs_enqueued_total{trigger_source="advisory"}`.
            // Conflict-on-enqueue rows do NOT count; only landed rows
            // increment. Per-ecosystem `hort_advisory_diff_processed_total`
            // and `hort_advisory_diff_duration_seconds` are emitted from
            // the OSV adapter at the I/O boundary (the adapter knows
            // per-ecosystem outcomes).
            if enqueued > 0 {
                emit_scan_jobs_enqueued(TriggerSourceLabel::Advisory, enqueued);
            }

            tracing::info!(
                entries = diff.entries.len(),
                considered,
                enqueued,
                checkpoint_advanced,
                "advisory watch tick complete",
            );

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "entries": diff.entries.len(),
                    "considered_artifacts": considered,
                    "enqueued": enqueued,
                    "checkpoint_advanced": checkpoint_advanced,
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

    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration as StdDuration;

    use chrono::DateTime;
    use uuid::Uuid;

    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{
        IndexMode, PrefetchPolicy, ReplicationPriority, Repository, RepositoryFormat,
        RepositoryType,
    };
    use hort_domain::error::DomainError;
    use hort_domain::events::system_actor;
    use hort_domain::ports::advisory::{
        AdvisoryAffectedPackage, AdvisoryDiffResult, AdvisoryEntry,
    };
    use hort_domain::ports::jobs_repository::{
        JobRow, JobStatus, JobsRepository, KindFields, ListJobsFilter, ListJobsPage, ScanJob,
    };
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::sbom::Ecosystem;
    use hort_domain::types::ContentHash;

    // ---------- helpers ---------------------------------------------------

    fn test_hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("static valid SHA-256 hex")
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn make_artifact(id: Uuid, repository_id: Uuid) -> Artifact {
        let now = ts(0);
        Artifact {
            id,
            repository_id,
            name: "lodash".into(),
            name_as_published: "lodash".into(),
            version: Some("4.17.20".into()),
            path: "lodash/lodash-4.17.20.tgz".into(),
            size_bytes: 1024,
            sha256_checksum: test_hash(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: QuarantineStatus::Released,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_repository(id: Uuid, format: RepositoryFormat) -> Repository {
        let now = ts(0);
        Repository {
            id,
            key: format!("repo-{id}"),
            name: "test-repo".into(),
            description: None,
            format,
            repo_type: RepositoryType::Hosted,
            storage_backend: "filesystem".into(),
            storage_path: format!("/data/repos/{id}"),
            upstream_url: None,
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: now,
            updated_at: now,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    fn npm_advisory_entry(
        id: &str,
        modified_secs: i64,
        name: &str,
        versions: &[&str],
    ) -> AdvisoryEntry {
        AdvisoryEntry {
            id: id.to_string(),
            modified: ts(modified_secs),
            affected: vec![AdvisoryAffectedPackage {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                affected_versions: versions.iter().map(|s| (*s).to_string()).collect(),
            }],
        }
    }

    fn test_job_row() -> JobRow {
        let now = ts(0);
        JobRow {
            id: Uuid::nil(),
            kind: "advisory-watch-tick".to_string(),
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

    // ---------- mock AdvisoryPort -----------------------------------------

    struct MockAdvisory {
        result: Mutex<Option<DomainResult<AdvisoryDiffResult>>>,
        last_since: Mutex<Option<DateTime<Utc>>>,
    }

    impl MockAdvisory {
        fn ok(entries: Vec<AdvisoryEntry>, all_ok: bool) -> Self {
            Self {
                result: Mutex::new(Some(Ok(AdvisoryDiffResult {
                    entries,
                    all_ecosystems_ok: all_ok,
                }))),
                last_since: Mutex::new(None),
            }
        }
        fn err(err: DomainError) -> Self {
            Self {
                result: Mutex::new(Some(Err(err))),
                last_since: Mutex::new(None),
            }
        }
        fn last_since(&self) -> Option<DateTime<Utc>> {
            *self.last_since.lock().unwrap()
        }
    }

    impl AdvisoryPort for MockAdvisory {
        fn query<'a>(
            &'a self,
            _components: &'a [hort_domain::types::SbomComponent],
        ) -> BoxFuture<'a, DomainResult<Vec<hort_domain::types::Finding>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn pull_diff_since<'a>(
            &'a self,
            since: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<AdvisoryDiffResult>> {
            *self.last_since.lock().unwrap() = Some(since);
            // Take so a second call surfaces a panic — the handler
            // should call exactly once per tick.
            let result = self.result.lock().unwrap().take();
            Box::pin(async move {
                match result {
                    Some(Ok(diff)) => Ok(diff),
                    Some(Err(e)) => Err(e),
                    None => panic!("MockAdvisory::pull_diff_since called more than once"),
                }
            })
        }
    }

    // ---------- mock SbomComponentRepository ------------------------------

    struct MockSbom {
        // Map (ecosystem-repr-via-debug, name) → matched artifact ids.
        // Versions ignored in the mock — production filtering is the
        // adapter's job; the handler tests only need the dispatch shape.
        by_match: Mutex<HashMap<(String, String), Vec<Uuid>>>,
    }

    impl MockSbom {
        fn new() -> Self {
            Self {
                by_match: Mutex::new(HashMap::new()),
            }
        }
        fn add_match(&self, eco: &Ecosystem, name: &str, ids: Vec<Uuid>) {
            self.by_match
                .lock()
                .unwrap()
                .insert((format!("{eco:?}"), name.to_string()), ids);
        }
    }

    impl SbomComponentRepository for MockSbom {
        fn replace_for_artifact<'a>(
            &'a self,
            _artifact_id: Uuid,
            _components: &'a [hort_domain::types::SbomComponent],
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn list_artifacts_by_match<'a>(
            &'a self,
            ecosystem: &'a Ecosystem,
            name: &'a str,
            versions: &'a [String],
        ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
            // Honour the empty-versions short-circuit contract.
            if versions.is_empty() {
                return Box::pin(async { Ok(Vec::new()) });
            }
            let key = (format!("{ecosystem:?}"), name.to_string());
            let ids = self
                .by_match
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default();
            Box::pin(async move { Ok(ids) })
        }
    }

    // ---------- mock AdvisorySyncStateRepository --------------------------

    struct MockSyncState {
        get: Mutex<DomainResult<Option<DateTime<Utc>>>>,
        set: Mutex<Option<DateTime<Utc>>>,
        set_err: Mutex<Option<DomainError>>,
    }

    impl MockSyncState {
        fn with_initial(t: Option<DateTime<Utc>>) -> Self {
            Self {
                get: Mutex::new(Ok(t)),
                set: Mutex::new(None),
                set_err: Mutex::new(None),
            }
        }
        fn last_set(&self) -> Option<DateTime<Utc>> {
            *self.set.lock().unwrap()
        }
    }

    impl AdvisorySyncStateRepository for MockSyncState {
        fn get_last_sync_at<'a>(
            &'a self,
            _feed: &'a str,
        ) -> BoxFuture<'a, DomainResult<Option<DateTime<Utc>>>> {
            // Clone the current state out of the Mutex.
            let v = match &*self.get.lock().unwrap() {
                Ok(opt) => Ok(*opt),
                Err(e) => Err(e.clone()),
            };
            Box::pin(async move { v })
        }
        fn set_last_sync_at<'a>(
            &'a self,
            _feed: &'a str,
            t: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            if let Some(err) = self.set_err.lock().unwrap().take() {
                return Box::pin(async move { Err(err) });
            }
            *self.set.lock().unwrap() = Some(t);
            Box::pin(async { Ok(()) })
        }
    }

    // ---------- mock ArtifactRepository -----------------------------------

    struct MockArtifacts {
        by_id: Mutex<HashMap<Uuid, Artifact>>,
    }

    impl MockArtifacts {
        fn new() -> Self {
            Self {
                by_id: Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, a: Artifact) {
            self.by_id.lock().unwrap().insert(a.id, a);
        }
    }

    impl ArtifactRepository for MockArtifacts {
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Artifact>> {
            let got = self.by_id.lock().unwrap().get(&id).cloned();
            Box::pin(async move {
                got.ok_or(DomainError::NotFound {
                    entity: "Artifact",
                    id: id.to_string(),
                })
            })
        }
        fn find_by_checksum(
            &self,
            _sha256: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn find_by_repo_and_checksum(
            &self,
            _repository_id: Uuid,
            _sha256: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn list_by_repository(
            &self,
            _repository_id: Uuid,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_path(
            &self,
            _repository_id: Uuid,
            _path: &str,
        ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
            Box::pin(async { Ok(None) })
        }
        fn list_distinct_names(
            &self,
            _repository_id: Uuid,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<String>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_in_repo(
            &self,
            _repository_id: Uuid,
            _normalized_name: &str,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_as_published(
            &self,
            _repository_id: Uuid,
            _raw_name: &str,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn list_active_for_repo(
            &self,
            _repository_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::LimitedList<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn list_rejected_for_policy(
            &self,
            _policy_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::LimitedList<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn list_active_for_policy(
            &self,
            _policy_id: Uuid,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Artifact>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn package_version_status(
            &self,
            _repository_id: Uuid,
            _package: &str,
        ) -> BoxFuture<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn find_pypi_wheels_without_kind(
            &self,
            _kind: &str,
            _limit: u32,
        ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    // ---------- mock RepositoryRepository ---------------------------------

    struct MockRepositories {
        by_id: Mutex<HashMap<Uuid, Repository>>,
    }

    impl MockRepositories {
        fn new() -> Self {
            Self {
                by_id: Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, r: Repository) {
            self.by_id.lock().unwrap().insert(r.id, r);
        }
    }

    impl RepositoryRepository for MockRepositories {
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Repository>> {
            let got = self.by_id.lock().unwrap().get(&id).cloned();
            Box::pin(async move {
                got.ok_or(DomainError::NotFound {
                    entity: "Repository",
                    id: id.to_string(),
                })
            })
        }
        fn find_by_key(&self, _key: &str) -> BoxFuture<'_, DomainResult<Repository>> {
            Box::pin(async {
                Err(DomainError::NotFound {
                    entity: "Repository",
                    id: "n/a".into(),
                })
            })
        }
        fn list(
            &self,
            _page: hort_domain::types::PageRequest,
            _search: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Repository>>> {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn save(&self, _repository: &Repository) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn get_virtual_members(
            &self,
            _virtual_repo_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<Repository>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn add_virtual_member(
            &self,
            _virtual_repo_id: Uuid,
            _member_repo_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn remove_virtual_member(
            &self,
            _virtual_repo_id: Uuid,
            _member_repo_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn replace_virtual_members(
            &self,
            _virtual_repo_id: Uuid,
            _ordered_member_ids: &[Uuid],
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn get_storage_usage(&self, _repo_id: Uuid) -> BoxFuture<'_, DomainResult<u64>> {
            Box::pin(async { Ok(0) })
        }
        fn save_managed(
            &self,
            _repository: &Repository,
            _digest: &[u8; 32],
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn delete_managed(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // ---------- mock JobsRepository ---------------------------------------

    /// Recorded `enqueue_scan` invocation.
    #[derive(Debug, Clone)]
    struct EnqueueCall {
        artifact_id: Uuid,
        repository_id: Uuid,
        format: String,
        priority: i16,
        trigger_source: String,
    }

    /// Programmable failure mode. `ConflictAt(N)` fails the Nth call
    /// (0-indexed) with a Conflict; `InternalAt(N)` fails it with an
    /// Invariant — anything else returns Ok.
    enum FailureMode {
        None,
        ConflictAt(usize),
        InternalAt(usize),
    }

    struct MockJobs {
        calls: Mutex<Vec<EnqueueCall>>,
        failure: Mutex<FailureMode>,
    }

    impl MockJobs {
        fn new(failure: FailureMode) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                failure: Mutex::new(failure),
            }
        }
        fn calls(&self) -> Vec<EnqueueCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl JobsRepository for MockJobs {
        fn claim_scan_jobs<'a>(
            &'a self,
            _w: &'a str,
            _b: u32,
            _l: StdDuration,
        ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
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
            _b: StdDuration,
            _e: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn mark_failed<'a>(&'a self, _id: Uuid, _e: &'a str) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn enqueue_scan<'a>(
            &'a self,
            artifact_id: Uuid,
            repository_id: Uuid,
            _content_hash: &'a ContentHash,
            format: &'a str,
            priority: i16,
            trigger_source: &'a str,
        ) -> BoxFuture<'a, DomainResult<Uuid>> {
            let mut calls = self.calls.lock().unwrap();
            let idx = calls.len();
            calls.push(EnqueueCall {
                artifact_id,
                repository_id,
                format: format.to_string(),
                priority,
                trigger_source: trigger_source.to_string(),
            });
            drop(calls);
            let failure = self.failure.lock().unwrap();
            match &*failure {
                FailureMode::ConflictAt(n) if *n == idx => Box::pin(async move {
                    Err(DomainError::Conflict(format!(
                        "scan job already exists for artifact {artifact_id}"
                    )))
                }),
                FailureMode::InternalAt(n) if *n == idx => {
                    Box::pin(async { Err(DomainError::Invariant("simulated db error".into())) })
                }
                _ => Box::pin(async { Ok(Uuid::new_v4()) }),
            }
        }
        fn pending_scan_count<'a>(&'a self) -> BoxFuture<'a, DomainResult<i64>> {
            Box::pin(async { Ok(0) })
        }
        fn list_jobs<'a>(
            &'a self,
            _f: ListJobsFilter,
            _l: u32,
            _c: Option<Uuid>,
        ) -> BoxFuture<'a, DomainResult<ListJobsPage>> {
            Box::pin(async {
                Ok(ListJobsPage {
                    items: Vec::new(),
                    next_cursor: None,
                })
            })
        }
    }

    // ---------- builder ---------------------------------------------------

    struct Harness {
        advisory: Arc<MockAdvisory>,
        sbom: Arc<MockSbom>,
        jobs: Arc<MockJobs>,
        sync_state: Arc<MockSyncState>,
        artifacts: Arc<MockArtifacts>,
        repositories: Arc<MockRepositories>,
    }

    impl Harness {
        fn new(advisory: MockAdvisory, jobs: MockJobs, sync_state: MockSyncState) -> Self {
            Self {
                advisory: Arc::new(advisory),
                sbom: Arc::new(MockSbom::new()),
                jobs: Arc::new(jobs),
                sync_state: Arc::new(sync_state),
                artifacts: Arc::new(MockArtifacts::new()),
                repositories: Arc::new(MockRepositories::new()),
            }
        }

        fn handler(&self) -> AdvisoryWatchTickHandler {
            AdvisoryWatchTickHandler::new(
                self.advisory.clone() as Arc<dyn AdvisoryPort>,
                self.sbom.clone() as Arc<dyn SbomComponentRepository>,
                self.jobs.clone() as Arc<dyn JobsRepository>,
                self.sync_state.clone() as Arc<dyn AdvisorySyncStateRepository>,
                self.artifacts.clone() as Arc<dyn ArtifactRepository>,
                self.repositories.clone() as Arc<dyn RepositoryRepository>,
            )
        }
    }

    // =====================================================================
    // kind() returns "advisory-watch-tick"
    // =====================================================================

    #[test]
    fn kind_returns_advisory_watch_tick() {
        let h = Harness::new(
            MockAdvisory::ok(Vec::new(), true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        let handler = h.handler();
        assert_eq!(handler.kind(), "advisory-watch-tick");
    }

    // =====================================================================
    // happy path: 2 entries, 1 affecting lodash@4.17.20 → 1 enqueue
    // checkpoint advanced to ~now()
    // =====================================================================

    #[tokio::test]
    async fn happy_path_enqueues_one_advisory_job_with_correct_priority_and_trigger_source() {
        let aid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        // since = 1_000s. After-entry modified at 2_000s; before-entry modified at 500s.
        let entries = vec![
            npm_advisory_entry("GHSA-after", 2_000, "lodash", &["4.17.20"]),
            npm_advisory_entry("GHSA-before", 500, "old", &["1.0.0"]),
        ];
        let h = Harness::new(
            MockAdvisory::ok(entries, true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        h.sbom.add_match(&Ecosystem::Npm, "lodash", vec![aid]);
        h.artifacts.insert(make_artifact(aid, rid));
        h.repositories
            .insert(make_repository(rid, RepositoryFormat::Npm));

        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["entries"], 2);
                assert_eq!(result_summary["enqueued"], 1);
                assert_eq!(result_summary["considered_artifacts"], 1);
                assert_eq!(result_summary["checkpoint_advanced"], true);
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        let calls = h.jobs.calls();
        assert_eq!(calls.len(), 1, "only the after-entry's match enqueues");
        assert_eq!(calls[0].artifact_id, aid);
        assert_eq!(calls[0].repository_id, rid);
        assert_eq!(calls[0].format, "npm");
        assert_eq!(calls[0].priority, ADVISORY_PRIORITY);
        assert_eq!(calls[0].priority, 5);
        assert_eq!(calls[0].trigger_source, ADVISORY_TRIGGER_SOURCE);
        assert_eq!(calls[0].trigger_source, "advisory");

        // Adapter saw the configured `since` and the checkpoint moved
        // forward.
        assert_eq!(h.advisory.last_since(), Some(ts(1_000)));
        assert!(
            h.sync_state.last_set().is_some(),
            "checkpoint must advance on full success",
        );
    }

    // =====================================================================
    // belt-and-braces: entry with modified <= last_sync_at filtered out
    // even if the adapter mistakenly returned it
    // =====================================================================

    #[tokio::test]
    async fn handler_filters_old_modified_entries_even_if_adapter_mistakenly_returns_them() {
        let aid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        // Adapter (mistakenly) returns an entry at modified == since.
        let entries = vec![npm_advisory_entry(
            "GHSA-edge",
            1_000,
            "lodash",
            &["4.17.20"],
        )];
        let h = Harness::new(
            MockAdvisory::ok(entries, true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        h.sbom.add_match(&Ecosystem::Npm, "lodash", vec![aid]);
        h.artifacts.insert(make_artifact(aid, rid));
        h.repositories
            .insert(make_repository(rid, RepositoryFormat::Npm));

        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["enqueued"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            h.jobs.calls().len(),
            0,
            "modified == since must NOT enqueue"
        );
    }

    // =====================================================================
    // partial failure: all_ecosystems_ok=false → checkpoint NOT advanced
    // but matched entries DID enqueue
    // =====================================================================

    #[tokio::test]
    async fn partial_ecosystem_failure_does_not_advance_checkpoint_but_enqueues_what_succeeded() {
        let aid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let entries = vec![npm_advisory_entry("GHSA-x", 2_000, "lodash", &["4.17.20"])];
        let h = Harness::new(
            // all_ecosystems_ok = false simulates "npm succeeded but
            // PyPI's fetch errored".
            MockAdvisory::ok(entries, false),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        h.sbom.add_match(&Ecosystem::Npm, "lodash", vec![aid]);
        h.artifacts.insert(make_artifact(aid, rid));
        h.repositories
            .insert(make_repository(rid, RepositoryFormat::Npm));

        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["enqueued"], 1);
                assert_eq!(result_summary["checkpoint_advanced"], false);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(h.jobs.calls().len(), 1, "matched advisory still enqueues");
        assert!(
            h.sync_state.last_set().is_none(),
            "partial failure must NOT advance checkpoint",
        );
    }

    // =====================================================================
    // pull failure (all ecosystems): TaskOutcome::Failed{retry:true}
    // =====================================================================

    #[tokio::test]
    async fn pull_diff_since_error_returns_failed_with_retry_true() {
        let h = Harness::new(
            MockAdvisory::err(DomainError::Invariant("all ecosystems 500".into())),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "transient pull failure must retry");
                assert!(
                    reason.contains("pull_diff_since"),
                    "reason should mention pull_diff_since: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(
            h.jobs.calls().len(),
            0,
            "pull failure must short-circuit before any enqueue"
        );
        assert!(
            h.sync_state.last_set().is_none(),
            "pull failure must NOT advance checkpoint",
        );
    }

    // =====================================================================
    // idempotent no-op: empty diff, all_ecosystems_ok → checkpoint advances
    // but zero enqueues
    // =====================================================================

    #[tokio::test]
    async fn empty_diff_with_all_ecosystems_ok_advances_checkpoint_with_zero_enqueues() {
        let h = Harness::new(
            MockAdvisory::ok(Vec::new(), true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["entries"], 0);
                assert_eq!(result_summary["enqueued"], 0);
                assert_eq!(result_summary["checkpoint_advanced"], true);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(h.jobs.calls().len(), 0);
        assert!(
            h.sync_state.last_set().is_some(),
            "no-op success must still advance checkpoint",
        );
    }

    // =====================================================================
    // missing checkpoint row → defensive `now() - 24h` fallback
    // =====================================================================

    #[tokio::test]
    async fn missing_sync_state_row_falls_back_to_24h_window() {
        // sync_state returns None — the production path is the seeded
        // row, but a fresh DB / truncated row must not crash.
        let h = Harness::new(
            MockAdvisory::ok(Vec::new(), true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(None),
        );
        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        assert!(matches!(outcome, TaskOutcome::Completed { .. }));

        // Adapter saw a `since` roughly 24 hours in the past.
        let since = h.advisory.last_since().expect("adapter was called");
        let elapsed = Utc::now().signed_duration_since(since);
        // Allow a minute of slop on either side.
        assert!(
            elapsed >= Duration::hours(23),
            "since within ~24h: {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::hours(25),
            "since within ~24h: {elapsed:?}"
        );
    }

    // =====================================================================
    // get_last_sync_at error → TaskOutcome::Failed{retry:true}
    // =====================================================================

    #[tokio::test]
    async fn get_last_sync_at_error_returns_failed_with_retry_true() {
        struct FailingSyncState;
        impl AdvisorySyncStateRepository for FailingSyncState {
            fn get_last_sync_at<'a>(
                &'a self,
                _feed: &'a str,
            ) -> BoxFuture<'a, DomainResult<Option<DateTime<Utc>>>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
            fn set_last_sync_at<'a>(
                &'a self,
                _feed: &'a str,
                _t: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }
        let advisory: Arc<dyn AdvisoryPort> = Arc::new(MockAdvisory::ok(Vec::new(), true));
        let sbom: Arc<dyn SbomComponentRepository> = Arc::new(MockSbom::new());
        let jobs: Arc<dyn JobsRepository> = Arc::new(MockJobs::new(FailureMode::None));
        let sync_state: Arc<dyn AdvisorySyncStateRepository> = Arc::new(FailingSyncState);
        let artifacts: Arc<dyn ArtifactRepository> = Arc::new(MockArtifacts::new());
        let repositories: Arc<dyn RepositoryRepository> = Arc::new(MockRepositories::new());
        let handler = AdvisoryWatchTickHandler::new(
            advisory.clone(),
            sbom,
            jobs.clone(),
            sync_state,
            artifacts,
            repositories,
        );
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "checkpoint read failure must retry");
                assert!(
                    reason.contains("get_last_sync_at"),
                    "reason should mention get_last_sync_at: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // =====================================================================
    // Conflict swallowed: 2 candidates, 1 returns Conflict → enqueued=1,
    // not Failed
    // =====================================================================

    #[tokio::test]
    async fn enqueue_conflict_is_swallowed_and_loop_continues() {
        let aid1 = Uuid::new_v4();
        let aid2 = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let entries = vec![npm_advisory_entry("GHSA-x", 2_000, "lodash", &["4.17.20"])];
        let h = Harness::new(
            MockAdvisory::ok(entries, true),
            // Second enqueue (idx 1) returns Conflict; first succeeds.
            MockJobs::new(FailureMode::ConflictAt(1)),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        h.sbom
            .add_match(&Ecosystem::Npm, "lodash", vec![aid1, aid2]);
        h.artifacts.insert(make_artifact(aid1, rid));
        h.artifacts.insert(make_artifact(aid2, rid));
        h.repositories
            .insert(make_repository(rid, RepositoryFormat::Npm));

        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — Conflict is swallowed");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["enqueued"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // Both enqueues attempted — Conflict does not abort the loop.
        assert_eq!(h.jobs.calls().len(), 2);
        // Checkpoint still advances (all ecosystems ok).
        assert!(h.sync_state.last_set().is_some());
    }

    // =====================================================================
    // non-Conflict enqueue error → TaskOutcome::Failed{retry:true}
    // =====================================================================

    #[tokio::test]
    async fn non_conflict_enqueue_error_returns_failed_with_retry_true() {
        let aid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let entries = vec![npm_advisory_entry("GHSA-x", 2_000, "lodash", &["4.17.20"])];
        let h = Harness::new(
            MockAdvisory::ok(entries, true),
            MockJobs::new(FailureMode::InternalAt(0)),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        h.sbom.add_match(&Ecosystem::Npm, "lodash", vec![aid]);
        h.artifacts.insert(make_artifact(aid, rid));
        h.repositories
            .insert(make_repository(rid, RepositoryFormat::Npm));

        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — wrapped in Failed");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry);
                assert!(
                    reason.contains("enqueue_scan"),
                    "reason should mention enqueue_scan: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Checkpoint must NOT advance on enqueue failure.
        assert!(h.sync_state.last_set().is_none());
    }

    // =====================================================================
    // empty affected_versions short-circuits per the SBOM port contract
    // =====================================================================

    #[tokio::test]
    async fn empty_affected_versions_skips_lookup_and_enqueue() {
        let entry = AdvisoryEntry {
            id: "GHSA-empty".into(),
            modified: ts(2_000),
            affected: vec![AdvisoryAffectedPackage {
                ecosystem: Ecosystem::Npm,
                name: "lodash".into(),
                affected_versions: Vec::new(), // empty
            }],
        };
        let h = Harness::new(
            MockAdvisory::ok(vec![entry], true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["enqueued"], 0);
                assert_eq!(result_summary["considered_artifacts"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(h.jobs.calls().len(), 0);
    }

    // =====================================================================
    // artifact disappears between SBOM match and enqueue → skip, not Failed
    // =====================================================================

    #[tokio::test]
    async fn missing_artifact_is_skipped_not_failed() {
        let aid = Uuid::new_v4();
        let entries = vec![npm_advisory_entry("GHSA-x", 2_000, "lodash", &["4.17.20"])];
        let h = Harness::new(
            MockAdvisory::ok(entries, true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        h.sbom.add_match(&Ecosystem::Npm, "lodash", vec![aid]);
        // intentionally do NOT insert the artifact — find_by_id returns NotFound.

        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — NotFound on artifact is skip-not-fail");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["enqueued"], 0);
                assert_eq!(result_summary["considered_artifacts"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(h.jobs.calls().len(), 0);
    }

    // =====================================================================
    // repository disappears → skip, not Failed
    // =====================================================================

    #[tokio::test]
    async fn missing_repository_is_skipped_not_failed() {
        let aid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let entries = vec![npm_advisory_entry("GHSA-x", 2_000, "lodash", &["4.17.20"])];
        let h = Harness::new(
            MockAdvisory::ok(entries, true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        h.sbom.add_match(&Ecosystem::Npm, "lodash", vec![aid]);
        h.artifacts.insert(make_artifact(aid, rid));
        // intentionally do NOT insert the repository — find_by_id returns NotFound.

        let handler = h.handler();
        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — NotFound on repository is skip-not-fail");
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["enqueued"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(h.jobs.calls().len(), 0);
    }

    // =====================================================================
    // two consecutive runs against unchanged data → zero new jobs
    // (idempotent on no-op feed) — hard requirement
    // =====================================================================

    #[tokio::test]
    async fn two_consecutive_runs_against_unchanged_data_produce_zero_new_jobs() {
        // First run: empty diff, checkpoint advances.
        let h1 = Harness::new(
            MockAdvisory::ok(Vec::new(), true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        let outcome1 = h1
            .handler()
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome1 {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["enqueued"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(h1.jobs.calls().len(), 0);

        // Second run: empty diff, still zero enqueues. The checkpoint
        // is a fresh harness because the mock takes the result on first
        // pull; the property under test is "no enqueues when the feed
        // is unchanged", regardless of the checkpoint internals.
        let h2 = Harness::new(
            MockAdvisory::ok(Vec::new(), true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(h1.sync_state.last_set()),
        );
        let outcome2 = h2
            .handler()
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");
        match outcome2 {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["enqueued"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(h2.jobs.calls().len(), 0);
    }

    // =====================================================================
    // `hort_scan_jobs_enqueued_total{trigger_source="advisory"}`
    // =====================================================================

    /// Happy path emits the advisory-trigger-source counter once with the
    /// landed-rows count, and exposes NO high-cardinality labels.
    #[test]
    fn run_emits_scan_jobs_enqueued_with_advisory_trigger_source() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let aid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let entries = vec![npm_advisory_entry("GHSA-x", 2_000, "lodash", &["4.17.20"])];
        let h = Harness::new(
            MockAdvisory::ok(entries, true),
            MockJobs::new(FailureMode::None),
            MockSyncState::with_initial(Some(ts(1_000))),
        );
        h.sbom.add_match(&Ecosystem::Npm, "lodash", vec![aid]);
        h.artifacts.insert(make_artifact(aid, rid));
        h.repositories
            .insert(make_repository(rid, RepositoryFormat::Npm));

        let handler = h.handler();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(handler.run(&serde_json::Value::Null, make_context()))
                .expect("Ok");
        });

        let snap = snapshotter.snapshot().into_vec();
        let counter = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_scan_jobs_enqueued_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "trigger_source" && l.value() == "advisory")
        });
        let (key, _, _, value) =
            counter.expect("scan_jobs_enqueued{trigger_source=advisory} must fire");
        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 1, "exactly one row landed"),
            other => panic!("expected Counter, got {other:?}"),
        }
        for forbidden in &["artifact_id", "purl", "vulnerability_id", "package_name"] {
            assert!(
                !key.key().labels().any(|l| l.key() == *forbidden),
                "forbidden label `{forbidden}` must not appear on hort_scan_jobs_enqueued_total",
            );
        }
    }
}
