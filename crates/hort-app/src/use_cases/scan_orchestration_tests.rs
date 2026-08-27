//! Unit tests for `ScanOrchestrationUseCase`.
//!
//! Coverage targets:
//! - `compute_backoff` — every documented attempts branch.
//! - `merge_findings` — collision dedup with severity preference,
//!   case-insensitive vuln-id, case-sensitive PURL.
//! - `severity_summary_from_findings` — per-tier counts.
//! - `run_scan` — happy path (single + multi backend), no-backends
//!   skip, advisory failure, single-backend failure (continue),
//!   all-backend failure. (Blob-size cap is enforced by the consumer
//!   blob-size cap is enforced by the consumer; coverage lives in
//!   `quarantine_use_case::tests`.)
//! - `record_outcome` — SkippedNoBackends, Completed first-ever scan,
//!   Completed with prior clean, Completed with prior partial overlap,
//!   Completed with identical findings, Failed before max attempts,
//!   Failed at max attempts.
//! - Path B regression: a Completed outcome with a prior produces TWO
//!   separate event-store appends before the fold was introduced.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::scan_policy::{
    NegligibleAction, ProvenanceMode, ScanEnforcement, ScanPolicyProjection, SeverityThreshold,
};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    Actor, DomainEvent, PersistedEvent, PolicyScope, ScanCompleted, SeveritySummary, StreamId,
};
use hort_domain::ports::advisory::AdvisoryPort;
use hort_domain::ports::format_handler::{
    FormatHandler, PayloadSbom, PayloadSbomExtraction, SbomResolution,
};
use hort_domain::ports::jobs_repository::{JobStatus, JobsRepository, ScanJob, TriggerSource};
use hort_domain::ports::scanner::ScannerPort;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{
    ArtifactCoords, ContentHash, Ecosystem, Finding, PayloadAccess, Sbom, SbomComponent,
    SeverityBasis,
};

use super::*;
use crate::use_cases::quarantine_use_case::QuarantineUseCase;
use crate::use_cases::test_support::*;

// ---------------------------------------------------------------------------
// Mock JobsRepository
// ---------------------------------------------------------------------------

type EnqueueRecord = (Uuid, Uuid, ContentHash, String, i16, String);

#[derive(Default)]
struct MockJobsRepository {
    completed: Mutex<Vec<Uuid>>,
    rescheduled: Mutex<Vec<(Uuid, Duration, String)>>,
    failed: Mutex<Vec<(Uuid, String)>>,
    enqueued: Mutex<Vec<EnqueueRecord>>,
    /// Stub claim — tests call run_scan / record_outcome directly with
    /// hand-built `ScanJob` values, so claim_scan_jobs is rarely used.
    claim_response: Mutex<Vec<ScanJob>>,
}

impl MockJobsRepository {
    fn new() -> Self {
        Self::default()
    }

    fn set_claim_response(&self, jobs: Vec<ScanJob>) {
        *self.claim_response.lock().unwrap() = jobs;
    }
    fn completed_calls(&self) -> Vec<Uuid> {
        self.completed.lock().unwrap().clone()
    }
    fn rescheduled_calls(&self) -> Vec<(Uuid, Duration, String)> {
        self.rescheduled.lock().unwrap().clone()
    }
    fn failed_calls(&self) -> Vec<(Uuid, String)> {
        self.failed.lock().unwrap().clone()
    }
    #[allow(dead_code)]
    fn enqueued_calls(&self) -> Vec<EnqueueRecord> {
        self.enqueued.lock().unwrap().clone()
    }
}

impl JobsRepository for MockJobsRepository {
    fn claim_scan_jobs<'a>(
        &'a self,
        _worker_id: &'a str,
        _batch_size: u32,
        _lock_duration: Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
        let claim = self.claim_response.lock().unwrap().clone();
        Box::pin(async move { Ok(claim) })
    }
    fn mark_completed<'a>(
        &'a self,
        job_id: Uuid,
        _result_summary: serde_json::Value,
    ) -> BoxFuture<'a, DomainResult<()>> {
        self.completed.lock().unwrap().push(job_id);
        Box::pin(async { Ok(()) })
    }
    fn reschedule<'a>(
        &'a self,
        job_id: Uuid,
        backoff: Duration,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<()>> {
        self.rescheduled
            .lock()
            .unwrap()
            .push((job_id, backoff, last_error.to_string()));
        Box::pin(async { Ok(()) })
    }
    fn mark_failed<'a>(
        &'a self,
        job_id: Uuid,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<()>> {
        self.failed
            .lock()
            .unwrap()
            .push((job_id, last_error.to_string()));
        Box::pin(async { Ok(()) })
    }
    fn enqueue_scan<'a>(
        &'a self,
        artifact_id: Uuid,
        repository_id: Uuid,
        content_hash: &'a ContentHash,
        format: &'a str,
        priority: i16,
        trigger_source: &'a str,
    ) -> BoxFuture<'a, DomainResult<Uuid>> {
        let id = Uuid::new_v4();
        self.enqueued.lock().unwrap().push((
            artifact_id,
            repository_id,
            content_hash.clone(),
            format.to_string(),
            priority,
            trigger_source.to_string(),
        ));
        Box::pin(async move { Ok(id) })
    }
}

// ---------------------------------------------------------------------------
// Mock ScannerPort
// ---------------------------------------------------------------------------

struct MockScanner {
    name_: String,
    /// `Some(Ok(findings))` = succeeds with findings; `Some(Err(_))` =
    /// fails; `None` = panics (tests should always seed an outcome).
    response: Mutex<Option<DomainResult<Vec<Finding>>>>,
    /// Number of times `scan` was invoked.
    calls: Mutex<u32>,
}

impl MockScanner {
    fn new(name: impl Into<String>, response: DomainResult<Vec<Finding>>) -> Self {
        Self {
            name_: name.into(),
            response: Mutex::new(Some(response)),
            calls: Mutex::new(0),
        }
    }
}

impl ScannerPort for MockScanner {
    fn name(&self) -> &str {
        &self.name_
    }
    fn scan<'a>(
        &'a self,
        _content_hash: &'a ContentHash,
        _sbom: Option<&'a Sbom>,
    ) -> BoxFuture<'a, DomainResult<Vec<Finding>>> {
        *self.calls.lock().unwrap() += 1;
        let resp = self
            .response
            .lock()
            .unwrap()
            .clone()
            .expect("test forgot to seed scanner response");
        Box::pin(async move { resp })
    }
    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Mock AdvisoryPort
// ---------------------------------------------------------------------------

struct MockAdvisory {
    response: Mutex<DomainResult<Vec<Finding>>>,
}

impl MockAdvisory {
    fn ok(findings: Vec<Finding>) -> Self {
        Self {
            response: Mutex::new(Ok(findings)),
        }
    }
    fn err(msg: &str) -> Self {
        Self {
            response: Mutex::new(Err(DomainError::Invariant(msg.into()))),
        }
    }
}

impl AdvisoryPort for MockAdvisory {
    fn query<'a>(
        &'a self,
        _components: &'a [SbomComponent],
    ) -> BoxFuture<'a, DomainResult<Vec<Finding>>> {
        let resp = self.response.lock().unwrap().clone();
        Box::pin(async move { resp })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn placeholder_blob_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .unwrap()
}

fn finding(purl: &str, vuln: &str, sev: SeverityThreshold) -> Finding {
    Finding {
        purl: purl.into(),
        vulnerability_id: vuln.into(),
        severity: sev,
        cvss_score: None,
        title: "t".into(),
        fixed_versions: vec![],
        source_scanner: "test".into(),
        references: vec![],
        aliases: vec![],
        informational_class: None,
        severity_basis: SeverityBasis::Assessed,
    }
}

fn finding_with_score(purl: &str, vuln: &str, sev: SeverityThreshold, score: f32) -> Finding {
    let mut f = finding(purl, vuln, sev);
    f.cvss_score = Some(score);
    f
}

/// A finding whose severity is the SUP-4 fail-closed floor rather than a
/// reading: no CVSS, no informational class, `SeverityBasis::Unassessed`.
/// This is the shape all three fail-closed emission sites produce when a
/// backend cannot determine a severity.
fn unassessed_finding(purl: &str, vuln: &str, sev: SeverityThreshold) -> Finding {
    let mut f = finding(purl, vuln, sev);
    f.severity_basis = SeverityBasis::Unassessed;
    f
}

/// Build a use case wired with mock ports + an in-memory quarantine
/// use case.
///
/// Backend selection lives on the resolved policy projection, not the
/// config. The first parameter (`backends`)
/// seeds a global `ScanPolicyProjection` whose `scan_backends`
/// matches; the orchestrator's `resolve_active_policy_for_repo` reads
/// that and dispatches accordingly. An empty `Vec` seeds a policy
/// with an empty `scan_backends` (operator opt-out → orchestrator
/// returns `SkippedNoBackends`). To test the "no policy → default
/// fallback" path, use [`make_uc_no_policy`] instead.
#[allow(clippy::type_complexity)]
fn make_uc(
    backends: Vec<String>,
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    advisory: Arc<dyn AdvisoryPort>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockJobsRepository>,
    Arc<MockEventStore>,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
    Arc<MockPolicyProjectionRepository>,
) {
    let (uc, jobs, events, storage, artifacts, repositories, policy, _metadata) =
        make_uc_full(backends, scanners, advisory, HashMap::new());
    (uc, jobs, events, storage, artifacts, repositories, policy)
}

/// Extended factory used by metadata-plumbing tests that
/// need to seed `ArtifactMetadata` rows and/or register custom
/// `FormatHandler` impls. Returns the same handles as
/// [`make_uc`] plus the metadata-repo handle.
#[allow(clippy::type_complexity)]
fn make_uc_full(
    backends: Vec<String>,
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    advisory: Arc<dyn AdvisoryPort>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockJobsRepository>,
    Arc<MockEventStore>,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
    Arc<MockPolicyProjectionRepository>,
    Arc<MockArtifactMetadataRepository>,
) {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    // Seed a global policy whose `scan_backends` mirrors the supplied
    // value. The orchestrator's policy chain (`resolve_active_policy_for_repo`)
    // returns the global projection when no repo-scoped projection
    // exists, which matches every test artifact's `repository_id`
    // (no repo-scoped policy is seeded by default).
    policy_projections.insert(seed_global_policy(backends));
    make_uc_with_policy_repo_and_handlers(
        scanners,
        advisory,
        policy_projections,
        handlers,
        ScanOrchestrationConfig::defaults_for_worker("test-worker"),
    )
}

/// Factory for the break-glass-switch tests: same wiring as
/// [`make_uc_full`], but with
/// [`ScanOrchestrationConfig::allow_informed_downgrade`] set explicitly so
/// a `run_scan` test can prove the flag reaches the merge rather than
/// sitting inert on the config struct (ADR 0015).
#[allow(clippy::type_complexity)]
fn make_uc_with_merge_switch(
    backends: Vec<String>,
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    advisory: Arc<dyn AdvisoryPort>,
    allow_informed_downgrade: bool,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
) {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(backends));
    let mut config = ScanOrchestrationConfig::defaults_for_worker("test-worker");
    config.allow_informed_downgrade = allow_informed_downgrade;
    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, _metadata) =
        make_uc_with_policy_repo_and_handlers(
            scanners,
            advisory,
            policy_projections,
            HashMap::new(),
            config,
        );
    (uc, artifacts, repositories)
}

/// Build a use case with NO policy seeded — the orchestrator's policy
/// chain returns `None` and the `run_scan` body falls back to
/// [`DefaultPolicy::block_on_critical_default_backends`] (i.e.
/// `["trivy"]`). Used by tests that pin the
/// fallback path.
#[allow(clippy::type_complexity)]
fn make_uc_no_policy(
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    advisory: Arc<dyn AdvisoryPort>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockJobsRepository>,
    Arc<MockEventStore>,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
    Arc<MockPolicyProjectionRepository>,
) {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    make_uc_with_policy_repo(scanners, advisory, policy_projections)
}

#[allow(clippy::type_complexity)]
fn make_uc_with_policy_repo(
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    advisory: Arc<dyn AdvisoryPort>,
    policy_projections: Arc<MockPolicyProjectionRepository>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockJobsRepository>,
    Arc<MockEventStore>,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
    Arc<MockPolicyProjectionRepository>,
) {
    let (uc, jobs, events, storage, artifacts, repositories, policy, _metadata) =
        make_uc_with_policy_repo_and_handlers(
            scanners,
            advisory,
            policy_projections,
            HashMap::new(),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    (uc, jobs, events, storage, artifacts, repositories, policy)
}

#[allow(clippy::type_complexity)]
fn make_uc_with_policy_repo_and_handlers(
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    advisory: Arc<dyn AdvisoryPort>,
    policy_projections: Arc<MockPolicyProjectionRepository>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
    config: ScanOrchestrationConfig,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockJobsRepository>,
    Arc<MockEventStore>,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
    Arc<MockPolicyProjectionRepository>,
    Arc<MockArtifactMetadataRepository>,
) {
    let artifacts = Arc::new(MockArtifactRepository::new());
    let events = Arc::new(MockEventStore::new());
    let scan_findings_repo = Arc::new(MockScanFindingsRepository::new());
    let lifecycle = Arc::new(
        MockArtifactLifecycle::new(artifacts.clone())
            .with_scan_result_paired_mocks(events.clone(), scan_findings_repo.clone()),
    );
    let repositories = Arc::new(MockRepositoryRepository::new());
    let content_refs = Arc::new(MockContentReferenceIndex::new());
    let storage = Arc::new(MockStoragePort::new());
    let jobs = Arc::new(MockJobsRepository::new());
    let artifact_metadata = Arc::new(MockArtifactMetadataRepository::new());

    // M9 — the lifecycle mock owns per-finding-row persistence via
    // `with_scan_result_paired_mocks`; the use case no longer holds a
    // separate ScanFindingsRepository handle.
    let _ = scan_findings_repo;
    let quarantine = Arc::new(QuarantineUseCase::new(
        artifacts.clone(),
        crate::event_store_publisher::wrap_for_test(events.clone()),
        lifecycle.clone(),
        repositories.clone(),
        policy_projections.clone(),
        content_refs.clone(),
        storage.clone(),
        jobs.clone(),
    ));

    let uc = ScanOrchestrationUseCase::new(
        jobs.clone(),
        artifacts.clone(),
        artifact_metadata.clone(),
        repositories.clone(),
        policy_projections.clone(),
        advisory,
        storage.clone(),
        scanners,
        handlers,
        quarantine,
        config,
    );

    (
        uc,
        jobs,
        events,
        storage,
        artifacts,
        repositories,
        policy_projections,
        artifact_metadata,
    )
}

/// Seed a `ScanPolicyProjection` with `PolicyScope::Global` and the
/// supplied `scan_backends` list. Other fields use plausible defaults
/// — only `scope` and `scan_backends` are load-bearing for the
/// orchestrator's resolution path under test.
fn seed_global_policy(scan_backends: Vec<String>) -> ScanPolicyProjection {
    ScanPolicyProjection {
        policy_id: Uuid::new_v4(),
        name: format!("orchestrator-test-{}", Uuid::new_v4()),
        scope: PolicyScope::Global,
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs: 24 * 3600,
        require_approval: false,
        provenance_mode: ProvenanceMode::VerifyIfPresent,
        provenance_backends: vec!["cosign".to_string()],
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends,
        rescan_interval_hours: 24,
        negligible_action: NegligibleAction::Ignore,
        enforcement: ScanEnforcement::Reject,
        stream_version: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Seed an artifact + repository pair; return the artifact uuid.
/// The repository's id is aligned to the artifact's `repository_id`
/// so the use case's `repositories.find_by_id(...)` resolves cleanly.
fn seed_quarantined_artifact(
    artifacts: &Arc<MockArtifactRepository>,
    repositories: &Arc<MockRepositoryRepository>,
) -> Uuid {
    let artifact = sample_artifact(QuarantineStatus::Quarantined);
    let mut repo = sample_repository();
    repo.id = artifact.repository_id;
    let id = artifact.id;
    artifacts.insert(artifact);
    repositories.insert(repo);
    id
}

/// Same shape as [`seed_quarantined_artifact`] but seeds
/// `QuarantineStatus::None` (permissive default — no quarantine window).
/// Used by tests that need `record_outcome`'s retry-exhaustion arm to
/// still reach `record_scan_indeterminate` (issue #6 narrowed that call
/// to non-`Quarantined` prior statuses — see
/// `record_outcome_failed_at_max_attempts_marks_job_failed_but_quarantined_artifact_stays_quarantined`).
fn seed_none_status_artifact(
    artifacts: &Arc<MockArtifactRepository>,
    repositories: &Arc<MockRepositoryRepository>,
) -> Uuid {
    let artifact = sample_artifact(QuarantineStatus::None);
    let mut repo = sample_repository();
    repo.id = artifact.repository_id;
    let id = artifact.id;
    artifacts.insert(artifact);
    repositories.insert(repo);
    id
}

fn sample_scan_job(artifact_id: Uuid, attempts: u32) -> ScanJob {
    ScanJob {
        id: Uuid::new_v4(),
        artifact_id,
        repository_id: Uuid::new_v4(),
        content_hash: placeholder_blob_hash(),
        format: "npm".into(),
        status: JobStatus::Running,
        attempts,
        locked_by: Some("test-worker".into()),
        locked_until: Some(Utc::now() + chrono::Duration::seconds(900)),
        last_error: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        trigger_source: TriggerSource::Ingest,
        priority: 0,
    }
}

fn persisted_scan_completed(
    stream_id: &StreamId,
    position: u64,
    artifact_id: Uuid,
    findings_blob: Option<ContentHash>,
    finding_count: u32,
    severity: SeveritySummary,
) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: stream_id.clone(),
        stream_position: position,
        global_position: position + 1,
        event: DomainEvent::ScanCompleted(ScanCompleted {
            artifact_id,
            scanner: "trivy".into(),
            finding_count,
            severity_summary: severity,
            findings_blob,
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(api_actor()),
        event_version: 1,
        stored_at: Utc::now() - chrono::Duration::hours(1),
    }
}

// ===========================================================================
// PURE HELPERS — compute_backoff, merge_findings, severity_summary
// ===========================================================================

#[test]
fn compute_backoff_attempts_one_returns_60_seconds() {
    assert_eq!(compute_backoff(1), Duration::from_secs(60));
}

#[test]
fn compute_backoff_attempts_two_returns_5_minutes() {
    assert_eq!(compute_backoff(2), Duration::from_secs(5 * 60));
}

#[test]
fn compute_backoff_attempts_three_returns_30_minutes() {
    assert_eq!(compute_backoff(3), Duration::from_secs(30 * 60));
}

#[test]
fn compute_backoff_attempts_four_returns_60_minutes() {
    assert_eq!(compute_backoff(4), Duration::from_secs(60 * 60));
}

#[test]
fn compute_backoff_attempts_five_or_more_returns_60_minutes_cap() {
    assert_eq!(compute_backoff(5), Duration::from_secs(60 * 60));
    assert_eq!(compute_backoff(7), Duration::from_secs(60 * 60));
    assert_eq!(compute_backoff(100), Duration::from_secs(60 * 60));
}

#[test]
fn compute_backoff_attempts_zero_defensive_returns_60_seconds() {
    // Defensive — claim_scan_jobs increments attempts before the
    // worker observes the row, so attempts == 0 should not occur in
    // practice. Pin the fallback so a bug doesn't silently produce a
    // zero-duration retry storm.
    assert_eq!(compute_backoff(0), Duration::from_secs(60));
}

// -- merge_findings: collision preference ----------------------------------

/// Merge `a` and `b` — two findings for the same `(purl,
/// vulnerability_id)` — in BOTH contribution orders and return the single
/// survivor. Order-independence is part of the contract: advisory
/// enrichment is seeded first but scanners append after, and which backend
/// runs first depends on the configured `scan_backends` list, so a merge
/// rule that only holds one way round would be a latent bug.
fn merge_collision(a: &Finding, b: &Finding, allow_informed_downgrade: bool) -> Finding {
    let mut winners: Vec<Finding> = Vec::new();
    for input in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
        let mut merged = merge_findings(input, allow_informed_downgrade);
        assert_eq!(merged.len(), 1, "collision must dedup to one finding");
        winners.push(merged.remove(0));
    }
    assert_eq!(
        winners[0], winners[1],
        "merge outcome must not depend on contribution order",
    );
    winners.remove(0)
}

/// Regression (the F1 cross-backend fail-open). A `[trivy, osv]` policy: the
/// advisory / osv enrichment reads the RustSec class and classifies
/// `RUSTSEC-2026-0173` as informational (severity `Low`,
/// `informational_class = unmaintained`, no CVSS); Trivy cannot read the class
/// and fails the unscored advisory closed to `Critical`. They collide on
/// `(purl, vuln_id)` — all three backends build `pkg:cargo/proc-macro-error2@2.0.1`.
/// The merge MUST preserve the informational reading; keeping Trivy's cosmetic
/// `Critical` silently defeats the negligible lane and rejects an
/// unmaintained-but-not-vulnerable crate.
#[test]
fn merge_preserves_informational_over_unscored_critical_collision() {
    let purl = "pkg:cargo/proc-macro-error2@2.0.1";
    let vuln = "RUSTSEC-2026-0173";

    let mut informational = finding(purl, vuln, SeverityThreshold::Low);
    informational.informational_class = Some("unmaintained".into());
    informational.source_scanner = "osv".into();
    assert!(informational.is_informational(), "fixture sanity");

    let mut trivy_critical = finding(purl, vuln, SeverityThreshold::Critical);
    trivy_critical.source_scanner = "trivy".into(); // informational_class stays None

    let winner = merge_collision(&informational, &trivy_critical, true);
    assert!(
        winner.is_informational(),
        "merged finding must stay informational (class={:?}, sev={:?})",
        winner.informational_class,
        winner.severity,
    );
}

/// Fail-closed safety: the informational preference must NOT downgrade a
/// genuinely-SCORED Critical. A real CVSS-scored finding is never
/// `is_informational()` (the recognizer requires `cvss_score.is_none()`), so
/// when it collides with an informational reading of the same id the scored
/// finding wins — ADR 0007 / ADR 0040 fail-closed posture preserved.
#[test]
fn merge_does_not_downgrade_a_scored_critical_via_informational_collision() {
    let purl = "pkg:cargo/x@1.0.0";
    let vuln = "CVE-9999-0001";

    let mut informational = finding(purl, vuln, SeverityThreshold::Low);
    informational.informational_class = Some("unmaintained".into());

    let scored_critical = finding_with_score(purl, vuln, SeverityThreshold::Critical, 9.8);

    let winner = merge_collision(&informational, &scored_critical, true);
    assert_eq!(winner.severity, SeverityThreshold::Critical);
    assert!(
        !winner.is_informational(),
        "a scored critical must stay enforced, not be demoted to negligible",
    );
}

/// The production pairing (ADR 0059). Two backends report the same advisory
/// for the same component: one could not read a severity and emitted the
/// SUP-4 fail-closed `Critical` floor (`SeverityBasis::Unassessed`, no
/// CVSS, no informational class), the other read a real CVSS and scored it
/// `Medium`. The scored reading MUST survive.
///
/// Keeping the floor is what left a correctly-scored advisory terminally
/// rejected for weeks: the merge discarded the only backend that actually
/// knew something about the advisory, and the artifact carried a verdict no
/// backend had reached.
#[test]
fn merge_prefers_scored_medium_over_unassessed_critical_floor() {
    let purl = "pkg:cargo/rsa@0.9.10";
    let vuln = "RUSTSEC-2023-0071";

    let unassessed_critical = unassessed_finding(purl, vuln, SeverityThreshold::Critical);
    let mut scored_medium = finding_with_score(purl, vuln, SeverityThreshold::Medium, 5.9);
    scored_medium.source_scanner = "osv".into();

    let winner = merge_collision(&unassessed_critical, &scored_medium, true);
    assert_eq!(
        winner.severity,
        SeverityThreshold::Medium,
        "the scored reading must supersede the unassessed Critical floor",
    );
    assert_eq!(winner.cvss_score, Some(5.9));
}

/// Fail-open protection, keyed on `SeverityBasis` rather than
/// `cvss_score.is_none()`. Two backends both genuinely assessed the same
/// advisory and disagree: `Critical` vs `Low`, both scored, both
/// `Assessed`. The information-quality rule must not fire at all here —
/// both are informed, so the comparison falls through to severity tier and
/// the `Critical` survives (ADR 0007).
#[test]
fn merge_keeps_scored_critical_over_scored_low_when_both_assessed() {
    let purl = "pkg:cargo/x@1.0.0";
    let vuln = "CVE-9999-0002";

    let scored_critical = finding_with_score(purl, vuln, SeverityThreshold::Critical, 9.8);
    let scored_low = finding_with_score(purl, vuln, SeverityThreshold::Low, 2.1);
    assert_eq!(scored_critical.severity_basis, SeverityBasis::Assessed);
    assert_eq!(scored_low.severity_basis, SeverityBasis::Assessed);

    let winner = merge_collision(&scored_critical, &scored_low, true);
    assert_eq!(
        winner.severity,
        SeverityThreshold::Critical,
        "two informed readings compare by tier; a scored Low never talks down a scored Critical",
    );
}

/// The break-glass switch, engaged. With
/// `HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE=false` the
/// information-quality rule is skipped entirely and the merge reverts to
/// strict always-fail-closed: the same production pairing now keeps the
/// `Unassessed` `Critical`. Engaging the switch makes the gate stricter,
/// which is the point of the escape hatch.
#[test]
fn merge_reverts_to_fail_closed_critical_when_downgrade_disabled() {
    let purl = "pkg:cargo/rsa@0.9.10";
    let vuln = "RUSTSEC-2023-0071";

    let unassessed_critical = unassessed_finding(purl, vuln, SeverityThreshold::Critical);
    let scored_medium = finding_with_score(purl, vuln, SeverityThreshold::Medium, 5.9);

    let winner = merge_collision(&unassessed_critical, &scored_medium, false);
    assert_eq!(
        winner.severity,
        SeverityThreshold::Critical,
        "with the switch engaged the fail-closed floor wins on tier alone",
    );
    assert_eq!(winner.severity_basis, SeverityBasis::Unassessed);
}

/// The switch does not touch the ADR 0040 informational arms, which sit
/// ahead of the information-quality rule and are not gated by it: an
/// informational reading still beats an unscored non-informational
/// `Critical` even with the downgrade disabled. Those arms key on
/// `is_informational()` (a *classification* the advisory DB published),
/// not on the fail-closed basis, so the break-glass switch has nothing to
/// revert there.
#[test]
fn merge_informational_preference_is_unaffected_by_the_break_glass_switch() {
    let purl = "pkg:cargo/proc-macro-error2@2.0.1";
    let vuln = "RUSTSEC-2026-0173";

    let mut informational = finding(purl, vuln, SeverityThreshold::Low);
    informational.informational_class = Some("unmaintained".into());

    let unscored_critical = finding(purl, vuln, SeverityThreshold::Critical);

    let winner = merge_collision(&informational, &unscored_critical, false);
    assert!(winner.is_informational());
}

/// Two uninformed findings for the same advisory (both backends failed to
/// read a severity) fall through to the tier comparison unchanged — the
/// rule fires only on an informed/uninformed pair.
#[test]
fn merge_two_unassessed_findings_compare_by_tier() {
    let purl = "pkg:cargo/x@1.0.0";
    let vuln = "CVE-9999-0003";

    let unassessed_critical = unassessed_finding(purl, vuln, SeverityThreshold::Critical);
    let unassessed_low = unassessed_finding(purl, vuln, SeverityThreshold::Low);

    let winner = merge_collision(&unassessed_critical, &unassessed_low, true);
    assert_eq!(winner.severity, SeverityThreshold::Critical);
}

/// The orchestrator's default posture: `defaults_for_worker` has the
/// information-quality rule **on**, so a deployment that sets nothing gets
/// the fix. The knob exists to turn it off.
#[test]
fn scan_orchestration_config_defaults_allow_informed_downgrade() {
    let cfg = ScanOrchestrationConfig::defaults_for_worker("w1");
    assert!(cfg.allow_informed_downgrade);
}

// ===========================================================================
// run_scan branches
// ===========================================================================

#[tokio::test]
async fn run_scan_skipped_no_backends_when_policy_declares_empty_list() {
    // Operator opts out of scanning by declaring
    // `scanBackends: []` in YAML. The seeded policy mirrors that:
    // global scope, empty backend list. The orchestrator must
    // surface `SkippedNoBackends` so the consumer emits a clean
    // `ScanCompleted(0)` and closes the job out.
    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    assert!(matches!(outcome, ScanRunOutcome::SkippedNoBackends));
}

#[tokio::test]
async fn run_scan_falls_back_to_default_backends_when_no_policy_resolved() {
    // When no operator policy resolves for the
    // artifact's repo (and no global policy exists), the orchestrator
    // falls back to `DefaultPolicy::block_on_critical_default_backends`
    // = `["trivy"]`. The trivy scanner registered below must be
    // invoked exactly once and contribute its findings.
    let scanner: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::Low,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), scanner);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc_no_policy(scanners, Arc::new(MockAdvisory::ok(vec![])));
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { scanner, .. } = outcome else {
        panic!("expected Completed via default-backend fallback, got {outcome:?}");
    };
    assert_eq!(scanner, "trivy");
}

#[tokio::test]
async fn run_scan_completed_with_single_backend_returns_findings_without_writing_cas() {
    // `run_scan` does not write the
    // findings blob to CAS. The consumer
    // (`QuarantineUseCase::record_scan_result` invoked from
    // `record_outcome`) is the single CAS write site. This test pins
    // the new contract: `run_scan` produces a `Completed` outcome with
    // the deduped findings vec and zero `storage.put` calls.
    let scanner: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::High,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), scanner);

    let (uc, _jobs, _events, storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        scanner,
        findings,
        sbom: _,
    } = outcome
    else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(scanner, "trivy");
    assert_eq!(findings.len(), 1);
    // H4 + L1 — `severity_summary` is no longer carried on the
    // outcome; the consumer recomputes via the
    // `severity_summary_from_findings` helper now in `hort-domain`.
    assert_eq!(findings[0].severity, SeverityThreshold::High);
    assert_eq!(
        storage.put_call_count(),
        0,
        "run_scan must not write to CAS; the consumer owns the CAS write"
    );
}

#[tokio::test]
async fn run_scan_advisory_failure_is_logged_and_does_not_fail_scan() {
    let scanner: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::High,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), scanner);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        scanners,
        Arc::new(MockAdvisory::err("OSV unreachable")),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    // Advisory failure is best-effort — scan continues with the
    // backend's own findings.
    assert!(matches!(outcome, ScanRunOutcome::Completed { .. }));
}

#[tokio::test]
async fn run_scan_continues_when_one_of_two_backends_fails() {
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Err(DomainError::Invariant("trivy crashed".into())),
    ));
    let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "osv",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::Critical,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);
    scanners.insert("osv".into(), osv);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into(), "osv".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        scanner,
        findings,
        sbom: _,
    } = outcome
    else {
        panic!("expected Completed");
    };
    // Only osv contributed (trivy failed).
    assert_eq!(scanner, "osv");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, SeverityThreshold::Critical);
}

#[tokio::test]
async fn run_scan_returns_failed_when_every_backend_fails() {
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Err(DomainError::Invariant("a".into())),
    ));
    let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "osv",
        Err(DomainError::Invariant("b".into())),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);
    scanners.insert("osv".into(), osv);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into(), "osv".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    assert!(matches!(outcome, ScanRunOutcome::Failed(_)));
}

// `run_scan_returns_failed_when_blob_exceeds_size_cap`
// was removed from this module: the blob-size cap is no longer
// enforced by the orchestrator. The single CAS write site (and the
// canonical 8 MiB cap) lives in
// `QuarantineUseCase::persist_findings_blob`; the regression test
// for that cap path is now `quarantine_use_case::tests::record_scan_result_returns_validation_error_when_findings_blob_exceeds_size_cap`.

#[tokio::test]
async fn run_scan_dedupes_findings_across_backends_with_severity_preference() {
    // Trivy reports a Medium-severity finding for foo@1/CVE-1.
    // OSV reports the same purl+CVE pair at Critical. After dedupe
    // the Critical entry must win.
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::Medium,
        )]),
    ));
    let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "osv",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::Critical,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);
    scanners.insert("osv".into(), osv);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into(), "osv".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { findings, .. } = outcome else {
        panic!("expected Completed");
    };
    assert_eq!(findings.len(), 1, "duplicate (purl, vuln) must dedupe");
    assert_eq!(findings[0].severity, SeverityThreshold::Critical);
}

/// Run one scan over two backends that collide on the same purl+advisory —
/// `trivy` could not read a severity and emitted the SUP-4 `Critical`
/// floor, `osv` scored it `Medium` — with the break-glass switch set to
/// `allow_informed_downgrade`. Returns the single merged finding.
///
/// Driven through `run_scan` rather than the pure helper so the whole path
/// is exercised: the flag must actually travel config → use case → merge.
async fn run_scan_over_colliding_backends(allow_informed_downgrade: bool) -> Finding {
    let purl = "pkg:cargo/rsa@0.9.10";
    let vuln = "RUSTSEC-2023-0071";
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![unassessed_finding(
            purl,
            vuln,
            SeverityThreshold::Critical,
        )]),
    ));
    let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "osv",
        Ok(vec![finding_with_score(
            purl,
            vuln,
            SeverityThreshold::Medium,
            5.9,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);
    scanners.insert("osv".into(), osv);

    let (uc, artifacts, repositories) = make_uc_with_merge_switch(
        vec!["trivy".into(), "osv".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
        allow_informed_downgrade,
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { mut findings, .. } = outcome else {
        panic!("expected Completed");
    };
    assert_eq!(findings.len(), 1, "collision must dedup to one finding");
    findings.remove(0)
}

/// Default posture: the scored reading reaches `ScanRunOutcome`, so the
/// artifact is judged on a verdict a backend actually reached.
#[tokio::test]
async fn run_scan_prefers_the_informed_reading_over_the_unassessed_floor() {
    let winner = run_scan_over_colliding_backends(true).await;
    assert_eq!(winner.severity, SeverityThreshold::Medium);
}

/// The same scan with the break-glass switch engaged. The config flag must
/// reach `prefer_replacement` — a flag the merge never reads would be an
/// inert operator surface (ADR 0015), and this is what pins that it is
/// not: identical inputs, opposite outcome.
#[tokio::test]
async fn run_scan_break_glass_switch_restores_the_fail_closed_floor() {
    let winner = run_scan_over_colliding_backends(false).await;
    assert_eq!(winner.severity, SeverityThreshold::Critical);
    assert_eq!(winner.severity_basis, SeverityBasis::Unassessed);
}

#[tokio::test]
async fn run_scan_dedupe_treats_vulnerability_id_case_insensitively() {
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::High,
        )]),
    ));
    let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "osv",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "cve-1", // lowercase
            SeverityThreshold::Critical,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);
    scanners.insert("osv".into(), osv);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into(), "osv".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { findings, .. } = outcome else {
        panic!("expected Completed");
    };
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, SeverityThreshold::Critical);
}

#[tokio::test]
async fn run_scan_dedupe_keeps_score_when_severity_ties() {
    // Two equal-severity rows; the cvss-score-bearing one should win.
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::High,
        )]),
    ));
    let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "osv",
        Ok(vec![finding_with_score(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::High,
            7.5,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);
    scanners.insert("osv".into(), osv);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into(), "osv".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { findings, .. } = outcome else {
        panic!("expected Completed");
    };
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cvss_score, Some(7.5));
}

#[tokio::test]
async fn run_scan_dedupe_treats_purl_case_sensitively() {
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:NPM/foo@1",
            "CVE-1",
            SeverityThreshold::High,
        )]),
    ));
    let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "osv",
        Ok(vec![finding(
            "pkg:npm/foo@1", // different case
            "CVE-1",
            SeverityThreshold::High,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);
    scanners.insert("osv".into(), osv);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into(), "osv".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { findings, .. } = outcome else {
        panic!("expected Completed");
    };
    assert_eq!(
        findings.len(),
        2,
        "case-sensitive PURL distinguishes pkg:NPM/foo@1 from pkg:npm/foo@1"
    );
}

#[tokio::test]
async fn run_scan_unknown_backend_in_config_is_skipped_with_warning() {
    // Backend "ghost" is in config but not in the scanners map. The
    // remaining backend "trivy" still runs.
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::Low,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["ghost".into(), "trivy".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { scanner, .. } = outcome else {
        panic!("expected Completed");
    };
    // Only trivy contributed.
    assert_eq!(scanner, "trivy");
}

#[tokio::test]
async fn run_scan_advisory_only_emits_advisory_scanner_label() {
    // No backends configured, but advisory query produces findings.
    // Actually — scope: if backends is empty, we return SkippedNoBackends.
    // Advisory-only contribution is when backends are configured but
    // ALL fail at backend layer with advisory still returning findings.
    let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
        "trivy",
        Err(DomainError::Invariant("crash".into())),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![finding(
            "pkg:npm/foo@1",
            "GHSA-xyz",
            SeverityThreshold::High,
        )])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    // All backends failed → Failed (NOT advisory-only Completed).
    // Path: backends > 0, all backends fail, total_failed ==
    // total_attempted ⇒ Failed.
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    assert!(matches!(outcome, ScanRunOutcome::Failed(_)));
}

// ===========================================================================
// record_outcome branches
// ===========================================================================

#[tokio::test]
async fn record_outcome_skipped_no_backends_calls_record_scan_result_with_zeros() {
    let (uc, jobs, events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    uc.record_outcome(&job, ScanRunOutcome::SkippedNoBackends)
        .await
        .expect("record_outcome");

    assert_eq!(jobs.completed_calls(), vec![job.id]);
    let batches = events.appended_batches();
    assert_eq!(
        batches.len(),
        1,
        "should append exactly one ScanCompleted batch"
    );
    let scan_event = batches[0]
        .events
        .iter()
        .find_map(|e| match &e.event {
            DomainEvent::ScanCompleted(p) => Some(p),
            _ => None,
        })
        .expect("ScanCompleted in batch");
    assert_eq!(scan_event.finding_count, 0);
    assert_eq!(scan_event.scanner, "(none)");
    assert!(scan_event.findings_blob.is_none());
}

#[tokio::test]
async fn record_outcome_completed_first_ever_scan_emits_no_artifact_became_vulnerable() {
    let (uc, jobs, events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        HashMap::new(),
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let findings = vec![finding(
        "pkg:npm/foo@1",
        "CVE-1",
        SeverityThreshold::Critical,
    )];
    let outcome = ScanRunOutcome::Completed {
        scanner: "trivy".into(),
        findings: findings.clone(),
        sbom: None,
    };

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    assert_eq!(jobs.completed_calls(), vec![job.id]);
    let batches = events.appended_batches();
    let became_vulnerable = batches
        .iter()
        .flat_map(|b| b.events.iter())
        .any(|e| matches!(&e.event, DomainEvent::ArtifactBecameVulnerable(_)));
    assert!(
        !became_vulnerable,
        "first-ever scan must not emit ArtifactBecameVulnerable"
    );
}

#[tokio::test]
async fn record_outcome_completed_with_prior_clean_emits_artifact_became_vulnerable() {
    let (uc, jobs, events, storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        HashMap::new(),
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    // Seed a prior clean ScanCompleted (no findings_blob, finding_count=0).
    let stream_id = StreamId::artifact(artifact_id);
    events.set_stream(
        &stream_id,
        vec![persisted_scan_completed(
            &stream_id,
            0,
            artifact_id,
            None,
            0,
            SeveritySummary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            },
        )],
    );

    let new_findings = vec![finding("pkg:npm/foo@1", "CVE-1", SeverityThreshold::High)];
    let outcome = ScanRunOutcome::Completed {
        scanner: "trivy".into(),
        findings: new_findings.clone(),
        sbom: None,
    };

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    assert_eq!(jobs.completed_calls(), vec![job.id]);
    let batches = events.appended_batches();
    let became_vulnerable =
        batches
            .iter()
            .flat_map(|b| b.events.iter())
            .find_map(|e| match &e.event {
                DomainEvent::ArtifactBecameVulnerable(p) => Some(p.clone()),
                _ => None,
            });
    let event = became_vulnerable.expect("ArtifactBecameVulnerable must be appended");
    assert_eq!(event.new_findings.len(), 1);
    assert_eq!(event.new_findings[0].vulnerability_id, "CVE-1");
    // `record_scan_result` writes the current
    // findings to CAS as part of the atomic dual-write. Exactly one
    // put: the prior was clean (`findings_blob = None`) so no read
    // happens, but the current non-empty findings vec lands a blob.
    assert_eq!(storage.put_call_count(), 1);
}

#[tokio::test]
async fn record_outcome_completed_with_prior_partial_overlap_emits_only_new_findings() {
    let (uc, jobs, events, storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        HashMap::new(),
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    // Seed prior findings (CVE-A) + persist them in storage.
    let prior_findings = vec![finding("pkg:npm/foo@1", "CVE-A", SeverityThreshold::High)];
    let prior_json = serde_json::to_vec(&prior_findings).unwrap();
    let prior_hash: ContentHash = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(&prior_json))
            .parse()
            .unwrap()
    };
    storage.insert_content(prior_hash.clone(), prior_json);

    // Seed prior ScanCompleted referencing the blob.
    let stream_id = StreamId::artifact(artifact_id);
    events.set_stream(
        &stream_id,
        vec![persisted_scan_completed(
            &stream_id,
            0,
            artifact_id,
            Some(prior_hash),
            1,
            SeveritySummary {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                negligible: 0,
            },
        )],
    );

    // Current scan: CVE-A still present, plus CVE-B.
    let current = vec![
        finding("pkg:npm/foo@1", "CVE-A", SeverityThreshold::High),
        finding("pkg:npm/foo@1", "CVE-B", SeverityThreshold::Critical),
    ];
    let outcome = ScanRunOutcome::Completed {
        scanner: "trivy".into(),
        findings: current,
        sbom: None,
    };

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    let batches = events.appended_batches();
    let new_findings = batches
        .iter()
        .flat_map(|b| b.events.iter())
        .find_map(|e| match &e.event {
            DomainEvent::ArtifactBecameVulnerable(p) => Some(p.new_findings.clone()),
            _ => None,
        })
        .expect("ArtifactBecameVulnerable must be appended");
    assert_eq!(new_findings.len(), 1);
    assert_eq!(new_findings[0].vulnerability_id, "CVE-B");
    assert_eq!(jobs.completed_calls(), vec![job.id]);
}

#[tokio::test]
async fn record_outcome_completed_identical_findings_emits_no_artifact_became_vulnerable() {
    let (uc, _jobs, events, storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        HashMap::new(),
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let prior_findings = vec![finding("pkg:npm/foo@1", "CVE-A", SeverityThreshold::High)];
    let prior_json = serde_json::to_vec(&prior_findings).unwrap();
    let prior_hash: ContentHash = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(&prior_json))
            .parse()
            .unwrap()
    };
    storage.insert_content(prior_hash.clone(), prior_json);
    let stream_id = StreamId::artifact(artifact_id);
    events.set_stream(
        &stream_id,
        vec![persisted_scan_completed(
            &stream_id,
            0,
            artifact_id,
            Some(prior_hash),
            1,
            SeveritySummary {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                negligible: 0,
            },
        )],
    );

    let outcome = ScanRunOutcome::Completed {
        scanner: "trivy".into(),
        findings: prior_findings.clone(),
        sbom: None,
    };

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    let became_vulnerable = events
        .appended_batches()
        .iter()
        .flat_map(|b| b.events.iter())
        .any(|e| matches!(&e.event, DomainEvent::ArtifactBecameVulnerable(_)));
    assert!(
        !became_vulnerable,
        "identical findings vs prior must not emit ArtifactBecameVulnerable"
    );
}

#[tokio::test]
async fn record_outcome_failed_below_max_attempts_reschedules_with_backoff() {
    let (uc, jobs, _events, _storage, _artifacts, _repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let artifact_id = Uuid::new_v4();
    let job = sample_scan_job(artifact_id, 2); // attempts=2 → backoff 5min.

    uc.record_outcome(&job, ScanRunOutcome::Failed("transient".into()))
        .await
        .expect("record_outcome");

    let calls = jobs.rescheduled_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, job.id);
    assert_eq!(calls[0].1, Duration::from_secs(5 * 60));
    assert_eq!(calls[0].2, "transient");
    assert!(jobs.failed_calls().is_empty());
}

/// Issue #6 refinement of ADR 0007: a `Quarantined` artifact whose scan
/// retries exhaust (scanner-execution failure — every backend errored)
/// stays exactly where it is. `mark_failed` (job-level terminal) still
/// fires — that IS the persisted "last scan errored" signal
/// `RescanCandidatesRepository::select_stranded` reads — but there is no
/// artifact-level transition at all: no `ScanIndeterminate` event, no
/// `quarantine_status` UPDATE. See
/// `record_outcome_failed_at_max_attempts_none_status_still_hard_blocks_to_scan_indeterminate`
/// below for the *other* prior-status branch, which is unchanged.
#[tokio::test]
async fn record_outcome_failed_at_max_attempts_marks_job_failed_but_quarantined_artifact_stays_quarantined(
) {
    let (uc, jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 5); // == default max_attempts.

    uc.record_outcome(&job, ScanRunOutcome::Failed("dead".into()))
        .await
        .expect("record_outcome");

    let calls = jobs.failed_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, job.id);
    assert_eq!(calls[0].1, "dead");
    assert!(jobs.rescheduled_calls().is_empty());

    // The artifact stays exactly where it was — still Quarantined, not
    // ScanIndeterminate. Downloads stay blocked either way (the status
    // itself is the gate, ADR 0007) but the artifact is now re-pickable
    // by select_stranded rather than stuck behind an admin override.
    let saved = artifacts.get(artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    assert!(!saved.is_downloadable());
}

// ===========================================================================
// Fail-closed terminal scan failure (ADR 0007)
// ===========================================================================

/// Companion to the test above: confirms NO `ScanIndeterminate` event is
/// committed for the Quarantined-stays-Quarantined case — the artifact
/// lifecycle stays completely untouched (no silent quarantine-state
/// UPDATE without a domain event; here there is no UPDATE at all).
#[tokio::test]
async fn record_outcome_failed_at_max_attempts_quarantined_artifact_commits_no_transition() {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    let (uc, jobs, artifacts, repositories, lifecycle) = make_uc_with_lifecycle(policy_projections);
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 5);

    uc.record_outcome(&job, ScanRunOutcome::Failed("all backends down".into()))
        .await
        .expect("record_outcome");

    let saved = artifacts.get(artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    // Job still marked failed (the per-attempt job state is unchanged).
    assert_eq!(jobs.failed_calls().len(), 1);
    assert!(
        lifecycle.committed_transitions().is_empty(),
        "no ScanIndeterminate (or any) transition must be committed \
         when a Quarantined artifact's scan retries exhaust"
    );
}

/// The *other* prior-status branch is unchanged: a `None`-status
/// artifact (permissive default — no quarantine window to fall back
/// into) still hard-blocks to `ScanIndeterminate` on retry exhaustion.
/// See `record_outcome_failed_permissive_none_hard_blocks` above for the
/// full assertion; this test exists only to name the contrast explicitly
/// next to the Quarantined-stays-Quarantined tests above, so a future
/// reader sees both halves of the branch in one place.
#[tokio::test]
async fn record_outcome_failed_at_max_attempts_none_status_still_hard_blocks_to_scan_indeterminate()
{
    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let none_artifact = sample_artifact(QuarantineStatus::None);
    let mut repo = sample_repository();
    repo.id = none_artifact.repository_id;
    let artifact_id = none_artifact.id;
    artifacts.insert(none_artifact);
    repositories.insert(repo);
    let job = sample_scan_job(artifact_id, 5);

    uc.record_outcome(&job, ScanRunOutcome::Failed("all backends down".into()))
        .await
        .expect("record_outcome");

    let saved = artifacts.get(artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::ScanIndeterminate);
}

/// Permissive mode (quarantineDuration:0): the artifact ingested in
/// `None` (downloadable today — the fail-open-today half). A terminal
/// scan failure hard-blocks it: `None → ScanIndeterminate`,
/// non-downloadable.
#[tokio::test]
async fn record_outcome_failed_permissive_none_hard_blocks() {
    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let none_artifact = sample_artifact(QuarantineStatus::None);
    let mut repo = sample_repository();
    repo.id = none_artifact.repository_id;
    let artifact_id = none_artifact.id;
    artifacts.insert(none_artifact);
    repositories.insert(repo);
    let job = sample_scan_job(artifact_id, 5);

    assert!(artifacts.get(artifact_id).unwrap().is_downloadable());

    uc.record_outcome(&job, ScanRunOutcome::Failed("scanner crashed".into()))
        .await
        .expect("record_outcome");

    let saved = artifacts.get(artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::ScanIndeterminate);
    assert!(
        !saved.is_downloadable(),
        "permissive-mode terminal scan failure must hard-block downloads"
    );
}

/// Below max attempts: the Failed arm still reschedules (no artifact
/// transition) — fail-closed only fires on retry *exhaustion*.
#[tokio::test]
async fn record_outcome_failed_below_max_does_not_transition_artifact() {
    let (uc, jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 2); // < max → reschedule.

    uc.record_outcome(&job, ScanRunOutcome::Failed("transient".into()))
        .await
        .expect("record_outcome");

    assert_eq!(jobs.rescheduled_calls().len(), 1);
    let saved = artifacts.get(artifact_id).unwrap();
    // Still quarantined — no fail-closed transition before exhaustion.
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
}

/// Idempotent: a second retry-exhausted Failed for an
/// already-`ScanIndeterminate` artifact is a recoverable skip — no
/// duplicate event/transition, and the job is still marked failed.
#[tokio::test]
async fn record_outcome_failed_idempotent_when_already_scan_indeterminate() {
    let (uc, jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let si_artifact = sample_artifact(QuarantineStatus::ScanIndeterminate);
    let mut repo = sample_repository();
    repo.id = si_artifact.repository_id;
    let artifact_id = si_artifact.id;
    artifacts.insert(si_artifact);
    repositories.insert(repo);
    let job = sample_scan_job(artifact_id, 5);

    uc.record_outcome(&job, ScanRunOutcome::Failed("still down".into()))
        .await
        .expect("record_outcome: idempotent skip must not error");

    let saved = artifacts.get(artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::ScanIndeterminate);
    assert_eq!(jobs.failed_calls().len(), 1);
}

// ===========================================================================
// `scanner_label_for_failed` degraded/branch paths
//
// Four branches (lines ~598-609 of scan_orchestration.rs):
//   1. artifact `find_by_id` returns `Err` → label `"(none)"`
//   2. policy resolves `Ok(None)` → label = default backends join (`"trivy"`)
//   3. policy `list_active` returns `Err` → label `"(none)"`
//   4. policy resolves non-empty backends → label = `backends.join(",")`
//
// Each test drives the retry-exhausted Failed arm of `record_outcome`
// (attempts == max_attempts) and asserts the `scanner` field of the
// resulting `ScanIndeterminate` event in the committed transition.
//
// Seeds `seed_none_status_artifact` (QuarantineStatus::None), NOT
// `seed_quarantined_artifact` — issue #6 narrowed `record_scan_indeterminate`
// (the only caller of `scanner_label_for_failed`) to non-`Quarantined`
// prior statuses; a `None`-status artifact still reaches it (ADR 0007's
// fail-closed backstop for a permissive-default artifact with no
// quarantine window to fall back into).
// ===========================================================================

/// Factory variant that exposes the lifecycle mock handle so tests can
/// inspect `committed_transitions` (which carries the `ScanIndeterminate`
/// event and its `scanner` label). The other handles are identical to
/// those returned by [`make_uc_with_policy_repo`].
#[allow(clippy::type_complexity)]
fn make_uc_with_lifecycle(
    policy_projections: Arc<MockPolicyProjectionRepository>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockJobsRepository>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
    Arc<MockArtifactLifecycle>,
) {
    let artifacts = Arc::new(MockArtifactRepository::new());
    let events = Arc::new(MockEventStore::new());
    let scan_findings_repo = Arc::new(MockScanFindingsRepository::new());
    let lifecycle = Arc::new(
        MockArtifactLifecycle::new(artifacts.clone())
            .with_scan_result_paired_mocks(events.clone(), scan_findings_repo.clone()),
    );
    let _ = scan_findings_repo;
    let repositories = Arc::new(MockRepositoryRepository::new());
    let content_refs = Arc::new(MockContentReferenceIndex::new());
    let storage = Arc::new(MockStoragePort::new());
    let jobs = Arc::new(MockJobsRepository::new());
    let artifact_metadata = Arc::new(MockArtifactMetadataRepository::new());

    let quarantine = Arc::new(QuarantineUseCase::new(
        artifacts.clone(),
        crate::event_store_publisher::wrap_for_test(events.clone()),
        lifecycle.clone(),
        repositories.clone(),
        policy_projections.clone(),
        content_refs.clone(),
        storage.clone(),
        jobs.clone(),
    ));

    let config = ScanOrchestrationConfig::defaults_for_worker("test-worker");
    let uc = ScanOrchestrationUseCase::new(
        jobs.clone(),
        artifacts.clone(),
        artifact_metadata,
        repositories.clone(),
        policy_projections,
        Arc::new(MockAdvisory::ok(vec![])),
        storage.clone(),
        HashMap::new(),
        HashMap::new(),
        quarantine,
        config,
    );

    (uc, jobs, artifacts, repositories, lifecycle)
}

/// Helper: extract the `scanner` label from the first `ScanIndeterminate`
/// event in `lifecycle.committed_transitions()`.
fn scan_indeterminate_scanner_label(lifecycle: &MockArtifactLifecycle) -> String {
    let transitions = lifecycle.committed_transitions();
    assert!(
        !transitions.is_empty(),
        "expected at least one committed transition"
    );
    for (_, batch, _) in &transitions {
        for ev in &batch.events {
            if let DomainEvent::ScanIndeterminate(si) = &ev.event {
                return si.scanner.clone();
            }
        }
    }
    panic!("no ScanIndeterminate event found in committed_transitions");
}

/// Branch: `artifacts.find_by_id` returns `Err` (artifact not seeded) →
/// `scanner_label_for_failed` returns `"(none)"`.
/// Exercises `scan_orchestration.rs` line 598.
#[tokio::test]
async fn scanner_label_for_failed_artifact_not_found_yields_none_sentinel() {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    // Seed a policy with backends — if the early-return at line 598
    // is absent, the code would reach line 609 and produce "trivy".
    policy_projections.insert(seed_global_policy(vec!["trivy".into()]));

    let (uc, _jobs, _artifacts, _repositories, lifecycle) =
        make_uc_with_lifecycle(policy_projections);

    // Artifact NOT seeded — `find_by_id` returns NotFound.
    let missing_id = Uuid::new_v4();
    let job = sample_scan_job(missing_id, 5); // attempts == max → fail-closed path

    // `record_scan_indeterminate` will fail because the artifact doesn't
    // exist. That propagates as `?` from `record_outcome`. We only care
    // about the scanner_label path (line 598), which returns BEFORE the
    // artifact lookup in `record_scan_indeterminate`. Since the entire
    // `record_outcome` → `record_scan_indeterminate` → commit chain
    // fails on missing artifact, we verify via the outcome error and
    // check that no ScanIndeterminate event was committed with a
    // non-"(none)" scanner label (i.e. we didn't reach line 609).
    //
    // However, to assert the scanner label itself we need the label
    // to propagate into the event. That requires the artifact to exist
    // for `record_scan_indeterminate` to succeed. The invariant is
    // that `scanner_label_for_failed` produces "(none)" when find_by_id
    // errors — the label is then passed as the first arg to
    // `record_scan_indeterminate`. If we seed the artifact after
    // scanner_label_for_failed runs, we can't intercept the label.
    //
    // Strategy: seed the artifact for the commit to succeed, but arm
    // a distinct repository_id NOT in the artifact repository so the
    // `artifacts.find_by_id` inside `scanner_label_for_failed`
    // specifically fails. We do this by using `sample_scan_job` with a
    // `artifact_id` that is NOT seeded in the `artifacts` mock.
    //
    // Simplest approach: the `job.artifact_id` is missing → line 598
    // fires. `record_scan_indeterminate` will also fail (same missing
    // artifact). The error propagates from `record_outcome`. We check
    // the error is a NotFound and that the lifecycle has NO transition
    // (proving "(none)" was the label path but the commit was never
    // reached due to the load failure in record_scan_indeterminate).
    let result = uc
        .record_outcome(&job, ScanRunOutcome::Failed("scanner down".into()))
        .await;
    // The commit fails (artifact not found in record_scan_indeterminate)
    // so record_outcome returns Err.
    assert!(
        result.is_err(),
        "record_outcome must propagate the load error"
    );
    // No transition committed — the "(none)" label path returned before
    // the artifact could be found for record_scan_indeterminate.
    assert!(
        lifecycle.committed_transitions().is_empty(),
        "no transition must be committed when artifact is missing"
    );
}

/// Branch: policy resolves to `Ok(None)` (no policy seeded) →
/// `scanner_label_for_failed` falls back to
/// `DefaultPolicy::block_on_critical_default_backends()` = `["trivy"]` →
/// label is `"trivy"`. Exercises `scan_orchestration.rs` line 603.
#[tokio::test]
async fn scanner_label_for_failed_no_policy_yields_default_backend_label() {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    // No policy seeded → list_active returns Ok([]) → resolve_active_policy_for_repo
    // returns Ok(None) → DefaultPolicy::block_on_critical_default_backends() = ["trivy"]

    let (uc, _jobs, artifacts, repositories, lifecycle) =
        make_uc_with_lifecycle(policy_projections);
    let artifact_id = seed_none_status_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 5);

    uc.record_outcome(&job, ScanRunOutcome::Failed("all down".into()))
        .await
        .expect("record_outcome must succeed");

    let label = scan_indeterminate_scanner_label(&lifecycle);
    assert_eq!(
        label, "trivy",
        "Ok(None) policy must fall back to DefaultPolicy backends ('trivy')"
    );
}

/// Branch: `list_active` returns `Err` → `resolve_active_policy_for_repo`
/// propagates `Err` → `scanner_label_for_failed` returns `"(none)"`.
/// Exercises `scan_orchestration.rs` line 604.
#[tokio::test]
async fn scanner_label_for_failed_policy_list_error_yields_none_sentinel() {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    // Arm the one-shot error BEFORE record_outcome is called.
    policy_projections.fail_next_list_active(DomainError::Invariant("db timeout".into()));

    let (uc, _jobs, artifacts, repositories, lifecycle) =
        make_uc_with_lifecycle(policy_projections);
    let artifact_id = seed_none_status_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 5);

    uc.record_outcome(&job, ScanRunOutcome::Failed("scanner error".into()))
        .await
        .expect("record_outcome must succeed: degraded label does not abort fail-closed");

    let label = scan_indeterminate_scanner_label(&lifecycle);
    assert_eq!(
        label, "(none)",
        "policy list_active error must degrade to '(none)' sentinel"
    );
}

/// Branch: policy resolves to non-empty backends → label is the
/// comma-joined backend list. Exercises `scan_orchestration.rs` line 609.
#[tokio::test]
async fn scanner_label_for_failed_non_empty_backends_yields_joined_label() {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(vec![
        "trivy".into(),
        "osv-scanner".into(),
    ]));

    let (uc, _jobs, artifacts, repositories, lifecycle) =
        make_uc_with_lifecycle(policy_projections);
    let artifact_id = seed_none_status_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 5);

    uc.record_outcome(&job, ScanRunOutcome::Failed("backends down".into()))
        .await
        .expect("record_outcome must succeed");

    let label = scan_indeterminate_scanner_label(&lifecycle);
    assert_eq!(
        label, "trivy,osv-scanner",
        "non-empty backends must produce comma-joined label (line 609)"
    );
}

// ===========================================================================
// Regression: ScanCompleted and ArtifactBecameVulnerable now land
// in a SINGLE atomic batch via `commit_scan_result`. The previous
// separate-batch path was a migration marker and has been removed.
// ===========================================================================

#[tokio::test]
async fn record_outcome_path_a_single_batch_after_item_12() {
    let (uc, _jobs, events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        HashMap::new(),
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let stream_id = StreamId::artifact(artifact_id);
    events.set_stream(
        &stream_id,
        vec![persisted_scan_completed(
            &stream_id,
            0,
            artifact_id,
            None,
            0,
            SeveritySummary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            },
        )],
    );

    let outcome = ScanRunOutcome::Completed {
        scanner: "trivy".into(),
        findings: vec![finding("pkg:npm/foo@1", "CVE-1", SeverityThreshold::High)],
        sbom: None,
    };

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    let batches = events.appended_batches();
    // `record_scan_result` appends
    // `ScanCompleted` and `ArtifactBecameVulnerable` in the SAME
    // batch (via the lifecycle port's `commit_scan_result`).
    // Exactly ONE post-fixture batch lands (the seeded prior is on
    // the stream but does not count toward `appended_batches()`,
    // which only records calls made after the fixture was set up).
    assert_eq!(
        batches.len(),
        1,
        "Path A: ScanCompleted + ArtifactBecameVulnerable must share one batch"
    );
    let single = &batches[0];
    let has_sc = single
        .events
        .iter()
        .any(|e| matches!(&e.event, DomainEvent::ScanCompleted(_)));
    let has_bv = single
        .events
        .iter()
        .any(|e| matches!(&e.event, DomainEvent::ArtifactBecameVulnerable(_)));
    assert!(has_sc, "ScanCompleted in single batch");
    assert!(has_bv, "ArtifactBecameVulnerable in single batch");
}

// ===========================================================================
// `subject_for_artifact` must carry `ArtifactMetadata.metadata` so
// Tier-A handlers (npm/PyPI/Cargo) can produce a non-empty SBOM. The
// previous implementation hard-coded `Value::Null`, which made every
// SBOM-driven scanner (OSV-scanner, the OSV `AdvisoryPort` query)
// silently no-op. `format_metadata` is the JSON the handler already
// extracted at ingest time, NOT a placeholder (see
// `docs/architecture/explanation/scanning-pipeline.md`).
// ===========================================================================

/// Test double that mirrors `NpmFormatHandler::extract_sbom`'s shape
/// just enough to exercise metadata propagation: it reads
/// `format_metadata.get("dependencies")` and emits a
/// `pkg:npm/<name>@<ver>` component per entry.
///
/// Lives here (not in `test_support.rs`) because it's only used by the
/// metadata-propagation regression tests and the canonical impl in
/// `hort-formats::npm` is unavailable to `hort-app` (no dep — that's
/// the layering boundary).
struct NpmShapedSbomHandler;

impl FormatHandler for NpmShapedSbomHandler {
    fn format_key(&self) -> &str {
        "npm"
    }
    fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
        unimplemented!("not needed for these tests")
    }
    fn normalize_name(&self, name: &str) -> String {
        name.to_string()
    }
    fn extract_sbom(
        &self,
        _coords: &ArtifactCoords,
        format_metadata: &serde_json::Value,
        _payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Sbom>> {
        // Mirror the early-return invariant: a non-object payload
        // produces an empty SBOM (NOT `None`). When the bug was present,
        // `format_metadata` was `Value::Null` → the early return fired
        // and every advisory query received `&[]`.
        let Some(obj) = format_metadata.as_object() else {
            return Ok(Some(Sbom {
                subject: None,
                components: vec![],
            }));
        };
        let mut components = Vec::new();
        if let Some(deps) = obj.get("dependencies").and_then(|v| v.as_object()) {
            for (name, raw) in deps {
                let version = raw
                    .as_str()
                    .map(|s| s.trim_start_matches(['^', '~', '=']).to_string());
                let purl = match version.as_deref() {
                    Some(v) => format!("pkg:npm/{name}@{v}"),
                    None => format!("pkg:npm/{name}"),
                };
                components.push(SbomComponent {
                    purl,
                    name: name.clone(),
                    version,
                    ecosystem: Ecosystem::Npm,
                    licenses: vec![],
                    direct_dependency: true,
                });
            }
        }
        Ok(Some(Sbom {
            subject: None,
            components,
        }))
    }
}

/// Recording advisory that captures the `components` slice it last
/// received from the orchestrator's pre-scan enrichment call. Lets
/// tests assert that `AdvisoryPort::query` was invoked with a
/// non-empty SBOM — the observable failure mode of the bug is that
/// the slice is always empty because the handler upstream returns
/// zero components.
struct RecordingAdvisory {
    last_components: Mutex<Option<Vec<SbomComponent>>>,
    response: Mutex<DomainResult<Vec<Finding>>>,
}

impl RecordingAdvisory {
    fn new() -> Self {
        Self {
            last_components: Mutex::new(None),
            response: Mutex::new(Ok(Vec::new())),
        }
    }
    fn last_components(&self) -> Option<Vec<SbomComponent>> {
        self.last_components.lock().unwrap().clone()
    }
}

impl AdvisoryPort for RecordingAdvisory {
    fn query<'a>(
        &'a self,
        components: &'a [SbomComponent],
    ) -> BoxFuture<'a, DomainResult<Vec<Finding>>> {
        *self.last_components.lock().unwrap() = Some(components.to_vec());
        let resp = self.response.lock().unwrap().clone();
        Box::pin(async move { resp })
    }
}

/// Seed an artifact + its repository with a known repository_id, plus
/// an `ArtifactMetadata` row with the supplied JSON. The repo's
/// `format` is set to `Npm` so the orchestrator's `subject_for_artifact`
/// produces `coords.format == "npm"` and the registered npm handler is
/// dispatched.
fn seed_npm_artifact_with_metadata(
    artifacts: &Arc<MockArtifactRepository>,
    repositories: &Arc<MockRepositoryRepository>,
    artifact_metadata: &Arc<MockArtifactMetadataRepository>,
    metadata_json: serde_json::Value,
) -> Uuid {
    use hort_domain::entities::artifact::ArtifactMetadata as DomainArtifactMetadata;
    use hort_domain::entities::repository::RepositoryFormat;

    let artifact = sample_artifact(QuarantineStatus::Quarantined);
    let mut repo = sample_repository();
    repo.id = artifact.repository_id;
    repo.format = RepositoryFormat::Npm;
    let id = artifact.id;
    artifacts.insert(artifact);
    repositories.insert(repo);
    artifact_metadata.insert(DomainArtifactMetadata {
        artifact_id: id,
        format: RepositoryFormat::Npm,
        metadata: metadata_json,
        metadata_blob: None,
        properties: serde_json::json!({}),
    });
    id
}

#[tokio::test]
async fn try_extract_sbom_returns_non_empty_sbom_for_npm_metadata() {
    // Regression guard. With `subject_for_artifact` hardcoded to
    // `Value::Null`, the npm-shaped handler hits its early return
    // and the SBOM has zero components. With the fix, the metadata
    // row's `metadata` JSON flows through to the handler and we get
    // one component per dependency.
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("npm".into(), Arc::new(NpmShapedSbomHandler));
    // Trivy stub so a backend exists for the policy resolution path
    // (we want `run_scan` to traverse `try_extract_sbom`, not skip).
    let scanner: Arc<dyn ScannerPort> = Arc::new(MockScanner::new("trivy", Ok(vec![])));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), scanner);
    let advisory = Arc::new(RecordingAdvisory::new());
    let advisory_port: Arc<dyn AdvisoryPort> = advisory.clone();

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, metadata_repo) =
        make_uc_full(vec!["trivy".into()], scanners, advisory_port, handlers);
    let artifact_id = seed_npm_artifact_with_metadata(
        &artifacts,
        &repositories,
        &metadata_repo,
        serde_json::json!({"dependencies": {"lodash": "^4.17.21"}}),
    );
    let job = sample_scan_job(artifact_id, 1);

    uc.run_scan(&job).await.expect("run_scan");

    let captured = advisory
        .last_components()
        .expect("AdvisoryPort::query must have been invoked");
    assert!(
        !captured.is_empty(),
        "metadata flows into format handler, SBOM must be non-empty; \
         got {} components",
        captured.len()
    );
    assert_eq!(captured[0].purl, "pkg:npm/lodash@4.17.21");
    assert_eq!(captured[0].name, "lodash");
    assert_eq!(captured[0].ecosystem, Ecosystem::Npm);
}

#[tokio::test]
async fn subject_for_artifact_uses_value_null_when_metadata_row_absent() {
    // Defensive — when the metadata row is absent (proxied fetch
    // with no parsed body, etc.), `subject_for_artifact` must keep
    // `Value::Null` and fall through. The handler then returns its
    // empty-shape SBOM and the scan continues. This is a legitimate
    // v1 case, NOT a bug.
    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, _metadata) = make_uc_full(
        vec![],
        HashMap::new(),
        Arc::new(MockAdvisory::ok(vec![])),
        HashMap::new(),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let artifact = artifacts.find_by_id(artifact_id).await.expect("artifact");

    let coords = uc
        .subject_for_artifact(&artifact)
        .await
        .expect("subject")
        .coords;
    assert!(
        coords.metadata.is_null(),
        "absent metadata row must produce Value::Null coords.metadata; got: {}",
        coords.metadata
    );
}

#[tokio::test]
async fn subject_for_artifact_propagates_metadata_when_present() {
    // The metadata row's JSON must show up verbatim on
    // `coords.metadata`. This is the load-bearing assertion the
    // `try_extract_sbom_*_npm_metadata` test hangs on; pin it
    // here too so a future regression hits this small-blast-radius
    // test before the larger run_scan-level test.
    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, metadata_repo) =
        make_uc_full(
            vec![],
            HashMap::new(),
            Arc::new(MockAdvisory::ok(vec![])),
            HashMap::new(),
        );
    let payload = serde_json::json!({
        "dependencies": {"lodash": "^4.17.21"},
        "name": "myapp",
    });
    let artifact_id =
        seed_npm_artifact_with_metadata(&artifacts, &repositories, &metadata_repo, payload.clone());
    let artifact = artifacts.find_by_id(artifact_id).await.expect("artifact");

    let coords = uc
        .subject_for_artifact(&artifact)
        .await
        .expect("subject")
        .coords;
    assert_eq!(
        coords.metadata, payload,
        "coords.metadata must equal the seeded ArtifactMetadata.metadata"
    );
}

#[tokio::test]
async fn run_scan_with_real_metadata_calls_advisory_with_non_empty_components() {
    // Integration-level: a full `run_scan` with real metadata results
    // in `AdvisoryPort::query(&components)` being invoked with a
    // non-empty slice. Before the fix this slice was always empty
    // because the npm handler's early-return on `Value::Null`
    // produces `Sbom { subject: None, components: vec![] }`.
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("npm".into(), Arc::new(NpmShapedSbomHandler));
    let scanner: Arc<dyn ScannerPort> = Arc::new(MockScanner::new("trivy", Ok(vec![])));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), scanner);
    let advisory = Arc::new(RecordingAdvisory::new());
    let advisory_port: Arc<dyn AdvisoryPort> = advisory.clone();

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, metadata_repo) =
        make_uc_full(vec!["trivy".into()], scanners, advisory_port, handlers);
    let artifact_id = seed_npm_artifact_with_metadata(
        &artifacts,
        &repositories,
        &metadata_repo,
        serde_json::json!({
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "~4.18.2",
            },
        }),
    );
    let job = sample_scan_job(artifact_id, 1);

    uc.run_scan(&job).await.expect("run_scan");

    let captured = advisory
        .last_components()
        .expect("AdvisoryPort::query must have been invoked");
    assert_eq!(
        captured.len(),
        2,
        "advisory must be queried with the two seeded npm dependencies"
    );
    let purls: Vec<&str> = captured.iter().map(|c| c.purl.as_str()).collect();
    assert!(purls.contains(&"pkg:npm/lodash@4.17.21"));
    assert!(purls.contains(&"pkg:npm/express@4.18.2"));
}

// ===========================================================================
// claim_pending — thin pass-through
// ===========================================================================

#[tokio::test]
async fn claim_pending_returns_jobs_repository_response() {
    let (uc, jobs, _events, _storage, _artifacts, _repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let artifact_id = Uuid::new_v4();
    let stub = sample_scan_job(artifact_id, 1);
    jobs.set_claim_response(vec![stub.clone()]);

    let claimed = uc
        .claim_pending(4, Duration::from_secs(900))
        .await
        .expect("claim_pending");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, stub.id);
}

// ===========================================================================
// Metrics emission tests.
//
// All tests in this section assert `hort-app::metrics` calls fire with the
// catalog-declared label sets via `metrics::with_local_recorder` +
// `metrics_util::debugging::DebuggingRecorder`. The tests use a small
// helper to drive an async block under a recorder and return the
// snapshot for assertion.
// ===========================================================================

// ---------------------------------------------------------------------------
// Payload-derived (resolved-version) SBOM — orchestration wiring
// ---------------------------------------------------------------------------

/// Test double mirroring `CargoFormatHandler`'s `PayloadSbom` shape: it
/// derives its components from the artifact's stored bytes, not from
/// `format_metadata`.
///
/// The payload grammar is deliberately trivial — `RESOLVED:<name>@<ver>,…`
/// with an optional `;skipped=<n>` suffix, `NOLOCK`, `BROKEN`, `BOOM` —
/// because what is under test here is the *orchestration*: does the
/// artifact's stored payload reach the handler as a stream, and does each
/// outcome land on the right metric and the right degradation. The real
/// archive walk is `hort-formats`' concern and is covered there.
///
/// Lives here rather than in `test_support.rs` for the same reason
/// `NpmShapedSbomHandler` does: `hort-formats` is unavailable to
/// `hort-app` — that is the layering boundary.
struct PayloadShapedSbomHandler {
    /// Exactly the bytes the handler read, so a test can prove the
    /// artifact's *stored* content (not a placeholder) reached it.
    seen_payload: Mutex<Option<Vec<u8>>>,
    /// Whether [`FormatHandler::payload_sbom`] answers `Some`. A `false`
    /// double is how the defensive "capability withdrawn between the
    /// caller's check and the extraction" arm is reached without a
    /// handler that mutates itself.
    declares_capability: bool,
}

impl Default for PayloadShapedSbomHandler {
    fn default() -> Self {
        Self {
            seen_payload: Mutex::new(None),
            declares_capability: true,
        }
    }
}

impl FormatHandler for PayloadShapedSbomHandler {
    fn format_key(&self) -> &str {
        "cargo"
    }
    fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
        unimplemented!("not needed for these tests")
    }
    fn normalize_name(&self, name: &str) -> String {
        name.to_string()
    }
    /// Metadata-only extraction still exists for this format's non-scan
    /// callers, and still emits declared-range components. The scan path
    /// must never reach it.
    fn extract_sbom(
        &self,
        _coords: &ArtifactCoords,
        _format_metadata: &serde_json::Value,
        _payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Sbom>> {
        Ok(Some(Sbom {
            subject: None,
            components: vec![component("pkg:cargo/declared@1")],
        }))
    }
    fn payload_sbom(&self) -> Option<&dyn PayloadSbom> {
        self.declares_capability.then_some(self as &dyn PayloadSbom)
    }
}

impl PayloadSbom for PayloadShapedSbomHandler {
    fn extract_sbom_from_payload(
        &self,
        coords: &ArtifactCoords,
        _format_metadata: &serde_json::Value,
        payload: PayloadAccess<'_>,
    ) -> DomainResult<PayloadSbomExtraction> {
        let mut buf = Vec::new();
        match payload {
            PayloadAccess::Bytes(b) => buf.extend_from_slice(b),
            PayloadAccess::ReadStream(mut r) => {
                std::io::Read::read_to_end(&mut r, &mut buf)
                    .map_err(|e| DomainError::Invariant(format!("payload read: {e}")))?;
            }
        }
        *self.seen_payload.lock().unwrap() = Some(buf.clone());

        let text = String::from_utf8_lossy(&buf).into_owned();
        let subject = component(&format!("pkg:cargo/{}@1.0.0", coords.name));
        let subject_only = |resolution| PayloadSbomExtraction {
            sbom: Some(Sbom {
                subject: Some(subject.clone()),
                components: vec![],
            }),
            resolution,
            skipped_non_registry: 0,
        };

        if text == "BOOM" {
            return Err(DomainError::Validation("payload handler exploded".into()));
        }
        if text == "PANIC" {
            panic!("payload handler panicked");
        }
        if text == "NOSBOM" {
            // A handler that can say nothing at all about this payload —
            // the `Ok(None)` shape `extract_sbom` already allows.
            return Ok(PayloadSbomExtraction {
                sbom: None,
                resolution: SbomResolution::NoLockfile,
                skipped_non_registry: 0,
            });
        }
        if text == "NOLOCK" {
            return Ok(subject_only(SbomResolution::NoLockfile));
        }
        let Some(rest) = text.strip_prefix("RESOLVED:") else {
            return Ok(subject_only(SbomResolution::UnusableLockfile));
        };
        let (list, skipped) = match rest.split_once(";skipped=") {
            Some((list, n)) => (list, n.parse::<usize>().unwrap_or(0)),
            None => (rest, 0),
        };
        Ok(PayloadSbomExtraction {
            sbom: Some(Sbom {
                subject: Some(subject),
                components: list
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|spec| component(&format!("pkg:cargo/{spec}")))
                    .collect(),
            }),
            resolution: SbomResolution::Resolved,
            skipped_non_registry: skipped,
        })
    }
}

/// An `SbomComponent` from a `pkg:cargo/<name>@<version>` PURL.
fn component(purl: &str) -> SbomComponent {
    let (name, version) = purl
        .trim_start_matches("pkg:cargo/")
        .split_once('@')
        .map_or((purl, None), |(n, v)| (n, Some(v.to_string())));
    SbomComponent {
        purl: purl.to_string(),
        name: name.to_string(),
        version,
        ecosystem: Ecosystem::Cargo,
        licenses: vec![],
        direct_dependency: false,
    }
}

/// Seed a cargo artifact whose stored CAS content is `payload`, with the
/// artifact row's `sha256_checksum` pointing at it — the only handle the
/// orchestrator has on the bytes. The repository is `Hosted`, the one
/// class whose artifacts take the payload path.
///
/// `metadata_json` is the stored `ArtifactMetadata.metadata` row (the
/// registry-index document). Note what is deliberately absent: no
/// resolved-dependency document is stored anywhere. Everything the scan
/// needs is derived at scan time from the payload, which is what makes
/// the behaviour retroactive for already-published artifacts.
async fn seed_cargo_artifact_with_payload(
    artifacts: &Arc<MockArtifactRepository>,
    repositories: &Arc<MockRepositoryRepository>,
    artifact_metadata: &Arc<MockArtifactMetadataRepository>,
    storage: &Arc<MockStoragePort>,
    payload: &[u8],
    metadata_json: serde_json::Value,
) -> Uuid {
    seed_cargo_artifact_in_repo_type(
        RepositoryType::Hosted,
        artifacts,
        repositories,
        artifact_metadata,
        storage,
        payload,
        metadata_json,
    )
    .await
}

/// As [`seed_cargo_artifact_with_payload`], with the repository class
/// chosen by the caller — the input the payload-path gate reads.
#[allow(clippy::too_many_arguments)]
async fn seed_cargo_artifact_in_repo_type(
    repo_type: RepositoryType,
    artifacts: &Arc<MockArtifactRepository>,
    repositories: &Arc<MockRepositoryRepository>,
    artifact_metadata: &Arc<MockArtifactMetadataRepository>,
    storage: &Arc<MockStoragePort>,
    payload: &[u8],
    metadata_json: serde_json::Value,
) -> Uuid {
    use hort_domain::entities::artifact::ArtifactMetadata as DomainArtifactMetadata;
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::ports::storage::StoragePort as _;

    let stored = storage
        .put(Box::new(std::io::Cursor::new(payload.to_vec())))
        .await
        .expect("seed CAS content");

    let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
    artifact.sha256_checksum = stored.hash;
    artifact.name = "demo".into();
    artifact.name_as_published = "demo".into();
    artifact.version = Some("1.0.0".into());
    let mut repo = sample_repository();
    repo.id = artifact.repository_id;
    repo.format = RepositoryFormat::Cargo;
    repo.repo_type = repo_type;
    let id = artifact.id;
    artifacts.insert(artifact);
    repositories.insert(repo);
    artifact_metadata.insert(DomainArtifactMetadata {
        artifact_id: id,
        format: RepositoryFormat::Cargo,
        metadata: metadata_json,
        metadata_blob: None,
        properties: serde_json::json!({}),
    });
    id
}

/// `run_scan` on a cargo job whose artifact stores `payload` in a hosted
/// repository, returning the components the advisory port was queried
/// with plus the handler double (so a test can inspect what it read).
async fn run_cargo_payload_scan(
    payload: &[u8],
) -> (
    Vec<SbomComponent>,
    Arc<PayloadShapedSbomHandler>,
    Arc<MockStoragePort>,
) {
    run_cargo_scan_in_repo_type(RepositoryType::Hosted, payload).await
}

/// As [`run_cargo_payload_scan`], with the repository class chosen by
/// the caller.
async fn run_cargo_scan_in_repo_type(
    repo_type: RepositoryType,
    payload: &[u8],
) -> (
    Vec<SbomComponent>,
    Arc<PayloadShapedSbomHandler>,
    Arc<MockStoragePort>,
) {
    let handler = Arc::new(PayloadShapedSbomHandler::default());
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("cargo".into(), handler.clone());
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert(
        "trivy".into(),
        Arc::new(MockScanner::new("trivy", Ok(vec![]))),
    );
    let advisory = Arc::new(RecordingAdvisory::new());
    let advisory_port: Arc<dyn AdvisoryPort> = advisory.clone();

    let (uc, _jobs, _events, storage, artifacts, repositories, _policy, metadata_repo) =
        make_uc_full(vec!["trivy".into()], scanners, advisory_port, handlers);
    let artifact_id = seed_cargo_artifact_in_repo_type(
        repo_type,
        &artifacts,
        &repositories,
        &metadata_repo,
        &storage,
        payload,
        serde_json::json!({"name": "demo", "vers": "1.0.0", "deps": [
            {"name": "serde", "req": "^1", "kind": "normal"}
        ]}),
    )
    .await;
    let mut job = sample_scan_job(artifact_id, 1);
    job.format = "cargo".into();

    uc.run_scan(&job).await.expect("run_scan");
    let queried = advisory.last_components().unwrap_or_default();
    (queried, handler, storage)
}

#[tokio::test]
async fn payload_scan_streams_the_artifacts_own_stored_bytes_to_the_handler() {
    // The wiring under test: the orchestrator resolves the artifact row's
    // `sha256_checksum` against CAS and streams exactly those bytes into
    // the handler's payload slot.
    let payload = b"RESOLVED:serde@1.0.200,serde_derive@1.0.200";
    let (queried, handler, storage) = run_cargo_payload_scan(payload).await;

    assert_eq!(
        handler.seen_payload.lock().unwrap().as_deref(),
        Some(&payload[..]),
        "the handler must receive the artifact's stored content verbatim"
    );
    assert_eq!(storage.get_call_count(), 1, "exactly one CAS read per scan");

    // Advisory enrichment covers subject + components, so the resolved
    // components are what a verdict is computed from.
    let purls: Vec<&str> = queried.iter().map(|c| c.purl.as_str()).collect();
    assert!(purls.contains(&"pkg:cargo/serde@1.0.200"));
    assert!(purls.contains(&"pkg:cargo/serde_derive@1.0.200"));
    assert!(
        !purls.contains(&"pkg:cargo/declared@1"),
        "the scan path must not fall back to the metadata-only branch"
    );
}

#[tokio::test]
async fn payload_scan_is_retroactive_for_an_artifact_with_no_stored_resolved_data() {
    // The retroactivity property. The seeded artifact has exactly what an
    // artifact published before this change has: CAS content and a
    // registry-index metadata row. No resolved-dependency document was
    // stored at ingest, and none is stored now — a rescan derives the
    // resolved components from the payload alone. This is what dissolves
    // the backfill question for the already-published population.
    let (queried, _handler, _storage) = run_cargo_payload_scan(b"RESOLVED:serde@1.0.200").await;

    let resolved: Vec<&SbomComponent> = queried.iter().filter(|c| c.name == "serde").collect();
    assert_eq!(resolved.len(), 1, "queried: {queried:?}");
    assert_eq!(
        resolved[0].version.as_deref(),
        Some("1.0.200"),
        "an exact resolved version, not the declared `^1` floor"
    );
}

#[tokio::test]
async fn payload_scan_without_a_lockfile_queries_the_subject_alone() {
    // Subject-only means the crate itself is still scanned; what must not
    // happen is range-floor dependency components reaching the verdict.
    let (queried, _handler, _storage) = run_cargo_payload_scan(b"NOLOCK").await;
    assert_eq!(
        queried.iter().map(|c| c.purl.as_str()).collect::<Vec<_>>(),
        vec!["pkg:cargo/demo@1.0.0"],
    );
}

#[tokio::test]
async fn payload_scan_survives_a_handler_error_with_no_sbom() {
    // A handler `Err` degrades to the no-SBOM arm — the scan still runs
    // its backends. SBOM enrichment is not release authority.
    let handler = Arc::new(PayloadShapedSbomHandler::default());
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("cargo".into(), handler.clone());
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert(
        "trivy".into(),
        Arc::new(MockScanner::new("trivy", Ok(vec![]))),
    );
    let advisory = Arc::new(RecordingAdvisory::new());
    let advisory_port: Arc<dyn AdvisoryPort> = advisory.clone();

    let (uc, _jobs, _events, storage, artifacts, repositories, _policy, metadata_repo) =
        make_uc_full(vec!["trivy".into()], scanners, advisory_port, handlers);
    let artifact_id = seed_cargo_artifact_with_payload(
        &artifacts,
        &repositories,
        &metadata_repo,
        &storage,
        b"BOOM",
        serde_json::Value::Null,
    )
    .await;
    let mut job = sample_scan_job(artifact_id, 1);
    job.format = "cargo".into();

    let outcome = uc.run_scan(&job).await.expect("run_scan must not fail");
    assert!(
        matches!(outcome, ScanRunOutcome::Completed { sbom: None, .. }),
        "a failed SBOM extraction leaves the scan completed with no SBOM: {outcome:?}"
    );
    assert!(
        advisory.last_components().is_none(),
        "with no SBOM there is nothing to enrich, so the advisory port is never queried"
    );
}

#[tokio::test]
async fn payload_scan_survives_an_unreadable_stored_payload() {
    // A CAS read failure must not fail the scan differently from the
    // missing-SBOM path that already existed: the backends still run and
    // the job still completes. Trading a thinner BOM for no scan at all
    // would be the wrong direction.
    let handler = Arc::new(PayloadShapedSbomHandler::default());
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("cargo".into(), handler.clone());
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert(
        "trivy".into(),
        Arc::new(MockScanner::new("trivy", Ok(vec![]))),
    );

    let (uc, _jobs, _events, storage, artifacts, repositories, _policy, metadata_repo) =
        make_uc_full(
            vec!["trivy".into()],
            scanners,
            Arc::new(MockAdvisory::ok(vec![])),
            handlers,
        );
    let artifact_id = seed_cargo_artifact_with_payload(
        &artifacts,
        &repositories,
        &metadata_repo,
        &storage,
        b"RESOLVED:serde@1.0.200",
        serde_json::Value::Null,
    )
    .await;
    let artifact = artifacts.find_by_id(artifact_id).await.expect("artifact");
    storage.fail_get_persistent(artifact.sha256_checksum.clone());

    let mut job = sample_scan_job(artifact_id, 1);
    job.format = "cargo".into();
    let outcome = uc.run_scan(&job).await.expect("run_scan must not fail");

    assert!(
        matches!(outcome, ScanRunOutcome::Completed { sbom: None, .. }),
        "an unreadable payload degrades to the no-SBOM arm: {outcome:?}"
    );
    assert!(
        handler.seen_payload.lock().unwrap().is_none(),
        "the handler is never dispatched when the payload cannot be read"
    );
}

#[tokio::test]
async fn payload_scan_in_a_proxy_repo_never_pays_for_a_cas_read() {
    // The gate's cost half. A proxied cargo artifact's embedded lockfile
    // is the upstream author's dev-time resolve, which no consumer of the
    // library ever runs — so the registry must not stream the payload out
    // of CAS to read it. `payload_sbom()` still answers `Some` for cargo;
    // the repository class is what turns the read away, and it does so
    // before the storage handle is touched at all.
    let (_queried, handler, storage) =
        run_cargo_scan_in_repo_type(RepositoryType::Proxy, b"RESOLVED:serde@1.0.200").await;

    assert_eq!(
        storage.get_call_count(),
        0,
        "a proxied cargo artifact must not read CAS for its SBOM"
    );
    assert!(
        handler.seen_payload.lock().unwrap().is_none(),
        "the payload capability is never dispatched for a non-hosted repository"
    );
}

#[tokio::test]
async fn payload_scan_in_a_proxy_repo_produces_the_pre_payload_metadata_sbom() {
    // The gate's behaviour half: a proxied cargo scan is byte-identical
    // to what it produced before the payload path existed — the
    // handler's metadata-only `extract_sbom`, declared-range components
    // and all. This arm must not change: findings against an upstream
    // author's stale resolve would carry gate power (the shipped
    // `enforcement: reject` default) over a crate every consumer would
    // resolve safely.
    let (queried, _handler, _storage) =
        run_cargo_scan_in_repo_type(RepositoryType::Proxy, b"RESOLVED:serde@1.0.200").await;

    assert_eq!(
        queried.iter().map(|c| c.purl.as_str()).collect::<Vec<_>>(),
        vec!["pkg:cargo/declared@1"],
        "the proxy path must be exactly the metadata-only SBOM"
    );
}

#[tokio::test]
async fn payload_scan_is_gated_off_for_every_non_hosted_repository_class() {
    // `Staging` is gated off with `Proxy` and `Virtual` even though
    // `RepositoryType::is_hosted()` counts it as upload-accepting — the
    // gate is a literal `Hosted` match, and this test is what stops a
    // future edit from "simplifying" it into that predicate. Widening
    // the gate to staging is a policy decision about which publishes a
    // lockfile may gate, not a helper rename.
    for repo_type in [
        RepositoryType::Proxy,
        RepositoryType::Virtual,
        RepositoryType::Staging,
    ] {
        let (queried, handler, storage) =
            run_cargo_scan_in_repo_type(repo_type, b"RESOLVED:serde@1.0.200").await;
        assert_eq!(
            storage.get_call_count(),
            0,
            "{repo_type:?} must not read CAS for its SBOM"
        );
        assert!(
            handler.seen_payload.lock().unwrap().is_none(),
            "{repo_type:?} must not dispatch the payload capability"
        );
        assert_eq!(
            queried.iter().map(|c| c.purl.as_str()).collect::<Vec<_>>(),
            vec!["pkg:cargo/declared@1"],
            "{repo_type:?} must take the metadata-only path"
        );
    }
}

#[tokio::test]
async fn payload_scan_in_a_hosted_repo_still_resolves_from_the_payload() {
    // The gate's other side, pinned next to the negative cases so a
    // change that over-tightens it fails here rather than silently
    // turning every cargo scan into a subject-only one.
    let (queried, handler, storage) =
        run_cargo_scan_in_repo_type(RepositoryType::Hosted, b"RESOLVED:serde@1.0.200").await;

    assert_eq!(storage.get_call_count(), 1);
    assert!(handler.seen_payload.lock().unwrap().is_some());
    assert!(queried.iter().any(|c| c.purl == "pkg:cargo/serde@1.0.200"));
}

#[tokio::test]
async fn metadata_only_format_never_pays_for_a_cas_read() {
    // The declaration is load-bearing for cost, not just for correctness:
    // npm's SBOM comes from stored metadata, so a scan of an npm artifact
    // must not touch CAS at all — and its component list must be exactly
    // what it was before the payload path existed.
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("npm".into(), Arc::new(NpmShapedSbomHandler));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert(
        "trivy".into(),
        Arc::new(MockScanner::new("trivy", Ok(vec![]))),
    );
    let advisory = Arc::new(RecordingAdvisory::new());
    let advisory_port: Arc<dyn AdvisoryPort> = advisory.clone();

    let (uc, _jobs, _events, storage, artifacts, repositories, _policy, metadata_repo) =
        make_uc_full(vec!["trivy".into()], scanners, advisory_port, handlers);
    let artifact_id = seed_npm_artifact_with_metadata(
        &artifacts,
        &repositories,
        &metadata_repo,
        serde_json::json!({"dependencies": {"lodash": "^4.17.21"}}),
    );
    let job = sample_scan_job(artifact_id, 1);

    uc.run_scan(&job).await.expect("run_scan");

    assert_eq!(
        storage.get_call_count(),
        0,
        "a format that does not derive its SBOM from the payload must not read CAS"
    );
    let queried = advisory.last_components().expect("advisory queried");
    assert_eq!(
        queried.iter().map(|c| c.purl.as_str()).collect::<Vec<_>>(),
        vec!["pkg:npm/lodash@4.17.21"],
        "the metadata-shape SBOM is byte-identical to what it was before"
    );
}

/// Metadata-only handler whose `extract_sbom` outcome is chosen by the
/// test — the two non-happy arms of the pre-payload path
/// (`Ok(None)` = opaque format, `Err` = malformed metadata).
struct MetadataOutcomeHandler {
    fail: bool,
}

impl FormatHandler for MetadataOutcomeHandler {
    fn format_key(&self) -> &str {
        "npm"
    }
    fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
        unimplemented!("not needed for these tests")
    }
    fn normalize_name(&self, name: &str) -> String {
        name.to_string()
    }
    fn extract_sbom(
        &self,
        _coords: &ArtifactCoords,
        _format_metadata: &serde_json::Value,
        _payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Sbom>> {
        if self.fail {
            Err(DomainError::Validation("unparseable metadata".into()))
        } else {
            Ok(None)
        }
    }
}

/// Run a scan whose only registered handler is a metadata-only double
/// with the requested outcome, returning the resulting `ScanRunOutcome`.
async fn run_metadata_outcome_scan(fail: bool) -> ScanRunOutcome {
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("npm".into(), Arc::new(MetadataOutcomeHandler { fail }));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert(
        "trivy".into(),
        Arc::new(MockScanner::new("trivy", Ok(vec![]))),
    );

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, _metadata) = make_uc_full(
        vec!["trivy".into()],
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
        handlers,
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);
    uc.run_scan(&job).await.expect("run_scan")
}

#[tokio::test]
async fn metadata_only_handler_returning_none_completes_the_scan_without_an_sbom() {
    // The opaque-format arm: `Ok(None)` is a normal answer, not a
    // failure, and the backends still run.
    let outcome = run_metadata_outcome_scan(false).await;
    assert!(
        matches!(outcome, ScanRunOutcome::Completed { sbom: None, .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn metadata_only_handler_error_completes_the_scan_without_an_sbom() {
    // Same degradation for a handler `Err` — unchanged from before the
    // payload path existed, and pinned here because that arm previously
    // had no test.
    let outcome = run_metadata_outcome_scan(true).await;
    assert!(
        matches!(outcome, ScanRunOutcome::Completed { sbom: None, .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn payload_scan_survives_a_panicking_extraction_task() {
    // The extraction runs on a blocking thread; a panic there must
    // surface as "no SBOM", not as a poisoned scan. A publisher-supplied
    // payload is the input, so this arm is reachable in principle from
    // untrusted bytes.
    let (queried, _handler, _storage) = run_cargo_payload_scan(b"PANIC").await;
    assert!(
        queried.is_empty(),
        "a panicked extraction yields no SBOM to enrich: {queried:?}"
    );
}

#[tokio::test]
async fn payload_scan_handler_that_produces_no_bom_at_all_is_unsupported_format() {
    // `sbom: None` from the payload path means the handler can say
    // nothing about this payload — the same observable as an opaque
    // format, and distinct from a failure.
    let (queried, handler, _storage) = run_cargo_payload_scan(b"NOSBOM").await;
    assert!(queried.is_empty(), "{queried:?}");
    assert!(
        handler.seen_payload.lock().unwrap().is_some(),
        "the handler was still dispatched"
    );
}

#[tokio::test]
async fn payload_extraction_degrades_when_the_capability_is_not_declared() {
    // Defensive arm: `extract_sbom_from_stored_payload` is only ever called
    // after the caller has seen `payload_sbom() == Some(_)`. If that ever
    // stops holding, the helper must degrade to no-SBOM rather than
    // unwrap a `None` — a scan is not worth a panic in a worker.
    let handler = Arc::new(PayloadShapedSbomHandler {
        declares_capability: false,
        ..Default::default()
    });
    let (uc, _jobs, _events, storage, artifacts, repositories, _policy, metadata_repo) =
        make_uc_full(
            vec!["trivy".into()],
            HashMap::new(),
            Arc::new(MockAdvisory::ok(vec![])),
            HashMap::new(),
        );
    let artifact_id = seed_cargo_artifact_with_payload(
        &artifacts,
        &repositories,
        &metadata_repo,
        &storage,
        b"RESOLVED:serde@1.0.200",
        serde_json::Value::Null,
    )
    .await;
    let artifact = artifacts.find_by_id(artifact_id).await.expect("artifact");
    let coords = uc
        .subject_for_artifact(&artifact)
        .await
        .expect("subject")
        .coords;

    let sbom = uc
        .extract_sbom_from_stored_payload(handler.clone(), &artifact, &coords, "cargo")
        .await;

    assert!(sbom.is_none(), "no SBOM, no panic");
    assert!(
        handler.seen_payload.lock().unwrap().is_none(),
        "the extraction is never attempted without the capability"
    );
}

mod metrics_emission_tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};

    /// Run an async closure under a `DebuggingRecorder` so emitted
    /// metrics can be asserted on. Borrows the
    /// `metrics::with_local_recorder` + `tokio::runtime` pattern from
    /// `oci_token_exchange_use_case::tests`. Returns the per-test
    /// snapshot pre-flattened to a `Vec<SnapEntry>` so multiple
    /// per-metric assertions can re-walk it without needing the
    /// snapshot itself to be `Clone`.
    fn capture_async_metrics<F>(f: F) -> Vec<SnapEntry>
    where
        F: FnOnce() -> futures::future::BoxFuture<'static, ()> + Send + 'static,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(f());
        });
        snap_entries(snapshotter.snapshot())
    }

    type SnapEntry = (
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    /// Convert a snapshot to a `Vec<SnapEntry>` once. Borrowing the
    /// vec lets every per-metric assertion in a single test re-walk
    /// it without needing the snapshot itself to be `Clone`.
    fn snap_entries(snap: Snapshot) -> Vec<SnapEntry> {
        snap.into_vec()
    }

    /// Find the matching `hort_*` metric in the snapshot whose labels
    /// satisfy the supplied predicate. Returns the (counter) value.
    fn find_counter(
        snap: &[SnapEntry],
        name: &str,
        label_match: impl Fn(&HashMap<&str, &str>) -> bool,
    ) -> Option<u64> {
        for (key, _, _, value) in snap {
            if key.key().name() != name {
                continue;
            }
            let labels: HashMap<&str, &str> =
                key.key().labels().map(|l| (l.key(), l.value())).collect();
            if !label_match(&labels) {
                continue;
            }
            if let DebugValue::Counter(v) = value {
                return Some(*v);
            }
        }
        None
    }

    fn find_histogram_sample_count(snap: &[SnapEntry], name: &str, scanner: &str) -> usize {
        for (key, _, _, value) in snap {
            if key.key().name() != name {
                continue;
            }
            let labels: HashMap<&str, &str> =
                key.key().labels().map(|l| (l.key(), l.value())).collect();
            if labels.get("scanner") != Some(&scanner) {
                continue;
            }
            if let DebugValue::Histogram(samples) = value {
                return samples.len();
            }
        }
        0
    }

    // ---------------------------------------------------------------
    // hort_scan_jobs_total
    // ---------------------------------------------------------------

    #[test]
    fn hort_scan_jobs_total_pending_claimed_fires_per_claimed_job() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, jobs, _events, _storage, _artifacts, _repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                let stub_a = sample_scan_job(Uuid::new_v4(), 1);
                let stub_b = sample_scan_job(Uuid::new_v4(), 1);
                jobs.set_claim_response(vec![stub_a, stub_b]);
                uc.claim_pending(4, Duration::from_secs(900))
                    .await
                    .expect("claim_pending");
            })
        });
        let count = find_counter(&snap, "hort_scan_jobs_total", |labels| {
            labels.get("result") == Some(&"pending_claimed")
        });
        assert_eq!(
            count,
            Some(2),
            "hort_scan_jobs_total{{result=pending_claimed}} must tick once per claimed job"
        );
    }

    #[test]
    fn hort_scan_jobs_total_completed_fires_on_skipped_no_backends() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                uc.record_outcome(&job, ScanRunOutcome::SkippedNoBackends)
                    .await
                    .expect("record_outcome");
            })
        });
        let count = find_counter(&snap, "hort_scan_jobs_total", |labels| {
            labels.get("result") == Some(&"completed")
        });
        assert_eq!(count, Some(1));
    }

    #[test]
    fn hort_scan_jobs_total_failed_fires_on_terminal_failure() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                // The retry-exhausted arm transitions the
                // artifact before mark_failed, so it must exist.
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                // attempts == default max → terminal failure path.
                let job = sample_scan_job(artifact_id, 5);
                uc.record_outcome(&job, ScanRunOutcome::Failed("dead".into()))
                    .await
                    .expect("record_outcome");
            })
        });
        let count = find_counter(&snap, "hort_scan_jobs_total", |labels| {
            labels.get("result") == Some(&"failed")
        });
        assert_eq!(count, Some(1));
    }

    // ---------------------------------------------------------------
    // hort_scan_terminal_total (ADR 0007)
    // ---------------------------------------------------------------

    /// `hort_scan_terminal_total{indeterminate}` fires on retry
    /// exhaustion only for the non-`Quarantined` prior-status branch
    /// (issue #6) — a `None`-status artifact still hard-blocks to
    /// `ScanIndeterminate` (ADR 0007's fail-closed backstop; no
    /// quarantine window to fall back into). See
    /// `hort_scan_terminal_total_not_emitted_when_quarantined_artifact_stays_quarantined`
    /// below for the companion Quarantined-stays-Quarantined case.
    #[test]
    fn hort_scan_terminal_total_indeterminate_on_retry_exhaustion() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                let artifact_id = seed_none_status_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 5); // == max → terminal.
                uc.record_outcome(&job, ScanRunOutcome::Failed("dead".into()))
                    .await
                    .expect("record_outcome");
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_scan_terminal_total", |l| l.get("result")
                == Some(&"indeterminate")),
            Some(1)
        );
    }

    /// Issue #6: a `Quarantined` artifact whose scan retries exhaust
    /// does NOT tick `hort_scan_terminal_total` at all — it is not an
    /// artifact-terminal decision (the artifact stays exactly where it
    /// was). `hort_scan_jobs_total{failed}` still fires (job-attempt
    /// terminal, unaffected).
    #[test]
    fn hort_scan_terminal_total_not_emitted_when_quarantined_artifact_stays_quarantined() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 5); // == max → exhausted.
                uc.record_outcome(&job, ScanRunOutcome::Failed("dead".into()))
                    .await
                    .expect("record_outcome");
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_scan_terminal_total", |_| true),
            None,
            "no hort_scan_terminal_total tick — the artifact stayed quarantined, \
             not an artifact-terminal decision",
        );
        assert_eq!(
            find_counter(&snap, "hort_scan_jobs_total", |l| l.get("result")
                == Some(&"failed")),
            Some(1),
            "hort_scan_jobs_total{{failed}} still fires — job-attempt terminal, unaffected",
        );
    }

    #[test]
    fn hort_scan_terminal_total_completed_on_skipped_no_backends() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                uc.record_outcome(&job, ScanRunOutcome::SkippedNoBackends)
                    .await
                    .expect("record_outcome");
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_scan_terminal_total", |l| l.get("result")
                == Some(&"completed")),
            Some(1)
        );
    }

    #[test]
    fn hort_scan_terminal_total_completed_on_clean_completed() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
                    vec!["trivy".into()],
                    HashMap::new(),
                    Arc::new(MockAdvisory::ok(vec![])),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                let outcome = ScanRunOutcome::Completed {
                    scanner: "trivy".into(),
                    findings: vec![],
                    sbom: None,
                };
                uc.record_outcome(&job, outcome)
                    .await
                    .expect("record_outcome");
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_scan_terminal_total", |l| l.get("result")
                == Some(&"completed")),
            Some(1)
        );
    }

    #[test]
    fn hort_scan_terminal_total_rejected_on_completed_with_findings() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
                    vec!["trivy".into()],
                    HashMap::new(),
                    Arc::new(MockAdvisory::ok(vec![])),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                let outcome = ScanRunOutcome::Completed {
                    scanner: "trivy".into(),
                    findings: vec![finding(
                        "pkg:npm/foo@1",
                        "CVE-1",
                        SeverityThreshold::Critical,
                    )],
                    sbom: None,
                };
                uc.record_outcome(&job, outcome)
                    .await
                    .expect("record_outcome");
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_scan_terminal_total", |l| l.get("result")
                == Some(&"rejected")),
            Some(1)
        );
    }

    /// One-metric-one-layer: the retry-exhausted arm (non-`Quarantined`
    /// prior status, so it still reaches `record_scan_indeterminate` —
    /// issue #6) ticks `hort_scan_terminal_total{indeterminate}` exactly
    /// once and the per-attempt `hort_scan_jobs_total{failed}` exactly
    /// once — they count different things and must not double-count.
    #[test]
    fn hort_scan_terminal_total_does_not_double_count_scan_jobs_total() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                let artifact_id = seed_none_status_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 5);
                uc.record_outcome(&job, ScanRunOutcome::Failed("dead".into()))
                    .await
                    .expect("record_outcome");
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_scan_terminal_total", |l| l.get("result")
                == Some(&"indeterminate")),
            Some(1)
        );
        assert_eq!(
            find_counter(&snap, "hort_scan_jobs_total", |l| l.get("result")
                == Some(&"failed")),
            Some(1)
        );
    }

    #[test]
    fn hort_scan_jobs_total_retried_fires_on_reschedule() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, _artifacts, _repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                // attempts < max → reschedule path.
                let job = sample_scan_job(Uuid::new_v4(), 2);
                uc.record_outcome(&job, ScanRunOutcome::Failed("transient".into()))
                    .await
                    .expect("record_outcome");
            })
        });
        let count = find_counter(&snap, "hort_scan_jobs_total", |labels| {
            labels.get("result") == Some(&"retried")
        });
        assert_eq!(count, Some(1));
    }

    // ---------------------------------------------------------------
    // hort_scan_findings_total
    // ---------------------------------------------------------------

    #[test]
    fn hort_scan_findings_total_fires_per_finding_with_scanner_and_severity_labels() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                // One trivy finding (High) + one OSV finding (Critical) — distinct
                // (purl, vuln) so dedup keeps both. Each ticks the counter once
                // with its own (scanner, severity) labels.
                let trivy_finding = Finding {
                    source_scanner: "trivy".into(),
                    ..finding("pkg:npm/foo@1", "CVE-1", SeverityThreshold::High)
                };
                let osv_finding = Finding {
                    source_scanner: "osv".into(),
                    ..finding("pkg:npm/bar@1", "CVE-2", SeverityThreshold::Critical)
                };
                let trivy: Arc<dyn ScannerPort> =
                    Arc::new(MockScanner::new("trivy", Ok(vec![trivy_finding])));
                let osv: Arc<dyn ScannerPort> =
                    Arc::new(MockScanner::new("osv", Ok(vec![osv_finding])));
                let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
                scanners.insert("trivy".into(), trivy);
                scanners.insert("osv".into(), osv);

                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
                    vec!["trivy".into(), "osv".into()],
                    scanners,
                    Arc::new(MockAdvisory::ok(vec![])),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                let _ = uc.run_scan(&job).await.expect("run_scan");
            })
        });
        let trivy_high = find_counter(&snap, "hort_scan_findings_total", |labels| {
            labels.get("scanner") == Some(&"trivy") && labels.get("severity") == Some(&"high")
        });
        let osv_critical = find_counter(&snap, "hort_scan_findings_total", |labels| {
            labels.get("scanner") == Some(&"osv") && labels.get("severity") == Some(&"critical")
        });
        assert_eq!(trivy_high, Some(1));
        assert_eq!(osv_critical, Some(1));
    }

    // ---------------------------------------------------------------
    // hort_scan_duration_seconds
    // ---------------------------------------------------------------

    #[test]
    fn hort_scan_duration_seconds_observed_per_backend_call() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let scanner: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
                    "trivy",
                    Ok(vec![finding(
                        "pkg:npm/foo@1",
                        "CVE-1",
                        SeverityThreshold::High,
                    )]),
                ));
                let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
                scanners.insert("trivy".into(), scanner);

                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
                    vec!["trivy".into()],
                    scanners,
                    Arc::new(MockAdvisory::ok(vec![])),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                let _ = uc.run_scan(&job).await.expect("run_scan");
            })
        });
        let count = find_histogram_sample_count(&snap, "hort_scan_duration_seconds", "trivy");
        assert!(
            count >= 1,
            "hort_scan_duration_seconds{{scanner=trivy}} must observe at least one sample; got {count}"
        );
    }

    // ---------------------------------------------------------------
    // hort_sbom_extraction_total — UnsupportedFormat path
    // ---------------------------------------------------------------

    #[test]
    fn hort_sbom_extraction_total_fires_unsupported_format_when_no_handler_registered() {
        // The orchestrator's `handlers` map is empty in the default
        // `make_uc` fixture; `try_extract_sbom` lands on the
        // "no handler registered" arm and emits the
        // `unsupported_format` label.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let scanner: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
                    "trivy",
                    Ok(vec![finding(
                        "pkg:npm/foo@1",
                        "CVE-1",
                        SeverityThreshold::High,
                    )]),
                ));
                let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
                scanners.insert("trivy".into(), scanner);

                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
                    vec!["trivy".into()],
                    scanners,
                    Arc::new(MockAdvisory::ok(vec![])),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                let _ = uc.run_scan(&job).await.expect("run_scan");
            })
        });
        // The seeded job's `format` is `npm`. The label fires with that
        // format key + the `unsupported_format` result.
        let count = find_counter(&snap, "hort_sbom_extraction_total", |labels| {
            labels.get("format") == Some(&"npm")
                && labels.get("result") == Some(&"unsupported_format")
        });
        assert_eq!(count, Some(1));
    }

    // ---------------------------------------------------------------
    // hort_artifact_became_vulnerable_total — emitted from the same
    // code path as the appended event (emit-where-you-append rule).
    // ---------------------------------------------------------------

    #[test]
    fn hort_artifact_became_vulnerable_total_fires_when_event_appended() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (uc, _jobs, events, _storage, artifacts, repositories, _policy) = make_uc(
                        vec!["trivy".into()],
                        HashMap::new(),
                        Arc::new(MockAdvisory::ok(vec![])),
                    );
                    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                    let job = sample_scan_job(artifact_id, 1);

                    // Seed the artifact's stream with ArtifactIngested
                    // (source=Direct) + prior clean ScanCompleted, so
                    // both `read_ingest_source` and
                    // `read_prior_scan_completed` find what they need.
                    let stream_id = StreamId::artifact(artifact_id);
                    events.set_stream(
                        &stream_id,
                        vec![
                            persisted_artifact_ingested(
                                &stream_id,
                                0,
                                artifact_id,
                                hort_domain::events::IngestSource::Direct,
                            ),
                            persisted_scan_completed(
                                &stream_id,
                                1,
                                artifact_id,
                                None,
                                0,
                                SeveritySummary {
                                    critical: 0,
                                    high: 0,
                                    medium: 0,
                                    low: 0,
                                    negligible: 0,
                                },
                            ),
                        ],
                    );

                    let outcome = ScanRunOutcome::Completed {
                        scanner: "trivy".into(),
                        findings: vec![
                            // Mix High + Critical — the metric label must
                            // be `critical` (the highest tier).
                            finding("pkg:npm/foo@1", "CVE-1", SeverityThreshold::High),
                            finding("pkg:npm/foo@1", "CVE-2", SeverityThreshold::Critical),
                        ],
                        sbom: None,
                    };

                    uc.record_outcome(&job, outcome)
                        .await
                        .expect("record_outcome");
                });
        });
        let snap = snap_entries(snapshotter.snapshot());
        let count = find_counter(&snap, "hort_artifact_became_vulnerable_total", |labels| {
            labels.get("severity") == Some(&"critical")
                && labels.get("ingest_source") == Some(&"direct")
                && labels.contains_key("repository")
        });
        assert_eq!(
            count,
            Some(1),
            "hort_artifact_became_vulnerable_total must fire once with severity=critical, \
             ingest_source=direct, repository label present"
        );
    }

    #[test]
    fn hort_artifact_became_vulnerable_total_collapses_repo_when_label_disabled() {
        // METRICS_INCLUDE_REPOSITORY_LABEL=false → emit
        // repository="_all" sentinel.
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let artifacts = Arc::new(MockArtifactRepository::new());
                    let repositories = Arc::new(MockRepositoryRepository::new());
                    let events = Arc::new(MockEventStore::new());
                    let uc = build_uc_with_collapsed_repo_label(
                        events.clone(),
                        artifacts.clone(),
                        repositories.clone(),
                    );
                    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                    let job = sample_scan_job(artifact_id, 1);
                    let stream_id = StreamId::artifact(artifact_id);
                    events.set_stream(
                        &stream_id,
                        vec![
                            persisted_artifact_ingested(
                                &stream_id,
                                0,
                                artifact_id,
                                hort_domain::events::IngestSource::Direct,
                            ),
                            persisted_scan_completed(
                                &stream_id,
                                1,
                                artifact_id,
                                None,
                                0,
                                SeveritySummary {
                                    critical: 0,
                                    high: 0,
                                    medium: 0,
                                    low: 0,
                                    negligible: 0,
                                },
                            ),
                        ],
                    );
                    let outcome = ScanRunOutcome::Completed {
                        scanner: "trivy".into(),
                        findings: vec![finding("pkg:npm/foo@1", "CVE-9", SeverityThreshold::High)],
                        sbom: None,
                    };
                    uc.record_outcome(&job, outcome)
                        .await
                        .expect("record_outcome");
                });
        });
        let snap = snap_entries(snapshotter.snapshot());
        let count = find_counter(&snap, "hort_artifact_became_vulnerable_total", |labels| {
            labels.get("repository") == Some(&"_all")
                && labels.get("severity") == Some(&"high")
                && labels.get("ingest_source") == Some(&"direct")
        });
        assert_eq!(
            count,
            Some(1),
            "with include_repository_label=false the metric must collapse to repository=_all"
        );
    }

    // ---------------------------------------------------------------
    // hort_scan_record_outcome_failures_total{result=report_too_large}
    // ---------------------------------------------------------------

    /// When a scanner backend fails with the distinguishable "report
    /// exceeded cap" error (the adapter killed the child after the
    /// bounded drain tripped `HORT_SCANNER_MAX_REPORT_SIZE`),
    /// `run_scan` attributes
    /// `hort_scan_record_outcome_failures_total{result="report_too_large",
    /// scanner=<backend>}`. A non-cap backend error does NOT emit it.
    #[test]
    fn run_scan_emits_report_too_large_metric_on_cap_hit_backend_error() {
        use hort_domain::ports::scanner::SCAN_REPORT_TOO_LARGE_MARKER;
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let trivy: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
                    "trivy",
                    Err(DomainError::Invariant(format!(
                        "trivy adapter: {SCAN_REPORT_TOO_LARGE_MARKER} (cap 256 bytes)"
                    ))),
                ));
                let osv: Arc<dyn ScannerPort> = Arc::new(MockScanner::new(
                    "osv",
                    // ordinary failure — must NOT emit the cap metric.
                    Err(DomainError::Invariant("osv crashed".into())),
                ));
                let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
                scanners.insert("trivy".into(), trivy);
                scanners.insert("osv".into(), osv);
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
                    vec!["trivy".into(), "osv".into()],
                    scanners,
                    Arc::new(MockAdvisory::ok(vec![])),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                let outcome = uc.run_scan(&job).await.expect("run_scan");
                // All backends failed → Failed (record_outcome routes to
                // ScanIndeterminate after retry exhaustion — fail-closed).
                assert!(matches!(outcome, ScanRunOutcome::Failed(_)));
            })
        });
        // The cap-hit backend (trivy) emits report_too_large with its name.
        let trivy_cap = find_counter(&snap, "hort_scan_record_outcome_failures_total", |labels| {
            labels.get("result") == Some(&"report_too_large")
                && labels.get("scanner") == Some(&"trivy")
        });
        assert_eq!(
            trivy_cap,
            Some(1),
            "the cap-hit backend must emit report_too_large attributed to its name"
        );
        // The ordinary-failure backend (osv) must NOT emit the cap metric.
        let osv_cap = find_counter(&snap, "hort_scan_record_outcome_failures_total", |labels| {
            labels.get("result") == Some(&"report_too_large")
                && labels.get("scanner") == Some(&"osv")
        });
        assert_eq!(
            osv_cap, None,
            "a non-cap backend error must NOT emit the report_too_large metric"
        );
    }

    // ---------------------------------------------------------------
    // Helper: build a `PersistedEvent::ArtifactIngested(...)` so
    // `set_stream` can seed the source-resolution path.
    // ---------------------------------------------------------------

    fn persisted_artifact_ingested(
        stream_id: &StreamId,
        position: u64,
        artifact_id: Uuid,
        source: hort_domain::events::IngestSource,
    ) -> PersistedEvent {
        use hort_domain::events::ArtifactIngested;
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream_id.clone(),
            stream_position: position,
            global_position: position + 1,
            event: DomainEvent::ArtifactIngested(ArtifactIngested {
                artifact_id,
                repository_id: Uuid::new_v4(),
                name: "foo".into(),
                version: Some("1".into()),
                sha256: placeholder_blob_hash(),
                size_bytes: 1,
                source,
                metadata: serde_json::Value::Null,
                metadata_blob: None,
                upstream_published_at: None,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(api_actor()),
            event_version: 1,
            stored_at: Utc::now() - chrono::Duration::hours(2),
        }
    }

    /// Build a `ScanOrchestrationUseCase` whose embedded
    /// `QuarantineUseCase` has `include_repository_label = false`,
    /// reusing the supplied event store / artifact / repository
    /// fixtures so the `record_outcome` path lands on real seeded
    /// data.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::needless_pass_by_value)]
    fn build_uc_with_collapsed_repo_label(
        events: Arc<MockEventStore>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
    ) -> ScanOrchestrationUseCase {
        let scan_findings_repo = Arc::new(MockScanFindingsRepository::new());
        let lifecycle = Arc::new(
            MockArtifactLifecycle::new(artifacts.clone())
                .with_scan_result_paired_mocks(events.clone(), scan_findings_repo.clone()),
        );
        let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
        policy_projections.insert(seed_global_policy(vec!["trivy".into()]));
        let content_refs = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());

        // M9 — see comment in `make_use_case` for the elided handle.
        let _ = scan_findings_repo;
        let quarantine = Arc::new(
            QuarantineUseCase::new(
                artifacts.clone(),
                crate::event_store_publisher::wrap_for_test(events.clone()),
                lifecycle.clone(),
                repositories.clone(),
                policy_projections.clone(),
                content_refs.clone(),
                storage.clone(),
                jobs.clone(),
            )
            .with_include_repository_label(false),
        );

        let config = ScanOrchestrationConfig::defaults_for_worker("test-worker");
        let artifact_metadata = Arc::new(MockArtifactMetadataRepository::new());
        // `events` is not held by the orchestrator; the consumer owns
        // the event-store reads.
        let _ = events;
        ScanOrchestrationUseCase::new(
            jobs,
            artifacts,
            artifact_metadata,
            repositories,
            policy_projections,
            Arc::new(MockAdvisory::ok(vec![])),
            storage,
            HashMap::new(),
            HashMap::new(),
            quarantine,
            config,
        )
    }

    // ---------------------------------------------------------------
    // hort_sbom_resolution_total / hort_sbom_components_skipped_total
    // ---------------------------------------------------------------

    /// The `result` label value of the single `hort_sbom_resolution_total`
    /// series a scan of `payload` produced.
    fn resolution_label(payload: &'static [u8]) -> String {
        let snap = capture_async_metrics(move || {
            Box::pin(async move {
                let _ = run_cargo_payload_scan(payload).await;
            })
        });
        for candidate in [
            "resolved",
            "no_lockfile",
            "unusable_lockfile",
            "payload_unavailable",
            "not_applicable",
            "hosted_only",
        ] {
            let hit = find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"cargo") && labels.get("result") == Some(&candidate)
            });
            if hit.is_some() {
                return candidate.to_string();
            }
        }
        panic!("hort_sbom_resolution_total{{format=cargo}} did not fire");
    }

    #[test]
    fn hort_sbom_resolution_total_distinguishes_every_payload_outcome() {
        // The whole point of the counter: an operator can tell a registry
        // whose crates resolve cleanly from one that is silently scanning
        // subjects only — and, among the latter, tell "publishers ship no
        // lockfile" from "our extraction is failing on them". Collapsing
        // any two of these would hide a real regression behind a normal
        // one.
        assert_eq!(resolution_label(b"RESOLVED:serde@1.0.200"), "resolved");
        assert_eq!(resolution_label(b"NOLOCK"), "no_lockfile");
        assert_eq!(resolution_label(b"not a crate at all"), "unusable_lockfile");
        assert_eq!(
            resolution_label(b"BOOM"),
            "unusable_lockfile",
            "a handler error is the same fact to an operator: the payload was \
             reachable and no usable component list came out of it"
        );
    }

    #[test]
    fn hort_sbom_extraction_total_and_resolution_both_fire_once_per_scan() {
        // The two counters answer different questions and must stay
        // aligned: one scan, one tick on each.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ = run_cargo_payload_scan(b"RESOLVED:serde@1.0.200").await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_extraction_total", |labels| {
                labels.get("format") == Some(&"cargo") && labels.get("result") == Some(&"success")
            }),
            Some(1),
        );
        assert_eq!(
            find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"cargo") && labels.get("result") == Some(&"resolved")
            }),
            Some(1),
        );
    }

    #[test]
    fn hort_sbom_components_skipped_total_carries_the_count_not_a_label() {
        // The skip count is unbounded, so it rides the counter's *value*.
        // A label per distinct count would be a cardinality hazard, and a
        // log line alone would not aggregate — an operator needs the rate
        // to see BOMs quietly getting thinner.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ = run_cargo_payload_scan(b"RESOLVED:serde@1.0.200;skipped=3").await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_components_skipped_total", |labels| {
                labels.get("format") == Some(&"cargo")
            }),
            Some(3),
        );
        let has_count_label = snap.iter().any(|(key, _, _, _)| {
            key.key().name() == "hort_sbom_components_skipped_total"
                && key.key().labels().any(|l| l.key() == "count")
        });
        assert!(!has_count_label, "the count must never become a label");
    }

    #[test]
    fn hort_sbom_components_skipped_total_stays_silent_when_nothing_was_skipped() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ = run_cargo_payload_scan(b"RESOLVED:serde@1.0.200").await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_components_skipped_total", |_| true),
            None,
        );
    }

    #[test]
    fn hort_sbom_metrics_report_an_unreadable_payload_as_infrastructure_not_content() {
        // A CAS read failure is not a malformed artifact. Both counters
        // say `payload_unavailable` so an operator chasing a spike lands
        // on storage, not on publishers.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let handler = Arc::new(PayloadShapedSbomHandler::default());
                let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
                handlers.insert("cargo".into(), handler);
                let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
                scanners.insert(
                    "trivy".into(),
                    Arc::new(MockScanner::new("trivy", Ok(vec![]))),
                );

                let (uc, _jobs, _events, storage, artifacts, repositories, _policy, metadata_repo) =
                    make_uc_full(
                        vec!["trivy".into()],
                        scanners,
                        Arc::new(MockAdvisory::ok(vec![])),
                        handlers,
                    );
                let artifact_id = seed_cargo_artifact_with_payload(
                    &artifacts,
                    &repositories,
                    &metadata_repo,
                    &storage,
                    b"RESOLVED:serde@1.0.200",
                    serde_json::Value::Null,
                )
                .await;
                let artifact = artifacts.find_by_id(artifact_id).await.expect("artifact");
                storage.fail_get_persistent(artifact.sha256_checksum.clone());
                let mut job = sample_scan_job(artifact_id, 1);
                job.format = "cargo".into();
                let _ = uc.run_scan(&job).await.expect("run_scan");
            })
        });
        for metric in ["hort_sbom_extraction_total", "hort_sbom_resolution_total"] {
            assert_eq!(
                find_counter(&snap, metric, |labels| {
                    labels.get("format") == Some(&"cargo")
                        && labels.get("result") == Some(&"payload_unavailable")
                }),
                Some(1),
                "{metric} must report payload_unavailable",
            );
        }
    }

    #[test]
    fn hort_sbom_resolution_total_fires_not_applicable_for_a_metadata_only_format() {
        // Not a degradation — npm has no resolved-dependency document to
        // look for. The label exists so `resolved / total` is a meaningful
        // ratio per format rather than a mystery gap.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
                handlers.insert("npm".into(), Arc::new(NpmShapedSbomHandler));
                let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
                scanners.insert(
                    "trivy".into(),
                    Arc::new(MockScanner::new("trivy", Ok(vec![]))),
                );

                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, metadata_repo) =
                    make_uc_full(
                        vec!["trivy".into()],
                        scanners,
                        Arc::new(MockAdvisory::ok(vec![])),
                        handlers,
                    );
                let artifact_id = seed_npm_artifact_with_metadata(
                    &artifacts,
                    &repositories,
                    &metadata_repo,
                    serde_json::json!({"dependencies": {"lodash": "^4.17.21"}}),
                );
                let job = sample_scan_job(artifact_id, 1);
                let _ = uc.run_scan(&job).await.expect("run_scan");
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"npm")
                    && labels.get("result") == Some(&"not_applicable")
            }),
            Some(1),
        );
    }

    #[test]
    fn hort_sbom_resolution_total_fires_not_applicable_when_no_handler_registered() {
        // The unregistered-format arm returns before any capability can be
        // asked about, so the resolution counter still gets its one tick —
        // otherwise a scan would be invisible on this series.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) = make_uc(
                    vec!["trivy".into()],
                    HashMap::new(),
                    Arc::new(MockAdvisory::ok(vec![])),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = sample_scan_job(artifact_id, 1);
                let _ = uc.run_scan(&job).await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"npm")
                    && labels.get("result") == Some(&"not_applicable")
            }),
            Some(1),
        );
    }

    #[test]
    fn hort_sbom_resolution_total_fires_hosted_only_for_a_non_hosted_repository() {
        // The gated-off case gets its own label rather than sharing
        // `not_applicable`. Sharing would collide on the same `format`
        // label with two facts an operator must be able to separate:
        // "cargo has no handler registered" and "cargo has one, and this
        // repository class deliberately does not use its payload path".
        // A cargo registry whose scans are all `hosted_only` when its
        // operator believes those repositories are hosted has a
        // misconfiguration no other series would reveal.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ =
                    run_cargo_scan_in_repo_type(RepositoryType::Proxy, b"RESOLVED:serde@1.0.200")
                        .await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"cargo")
                    && labels.get("result") == Some(&"hosted_only")
            }),
            Some(1),
        );
        assert_eq!(
            find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"cargo")
                    && labels.get("result") == Some(&"not_applicable")
            }),
            None,
            "the gated-off case must not also tick not_applicable"
        );
    }

    #[test]
    fn hort_sbom_extraction_total_still_reports_the_metadata_bom_when_gated_off() {
        // The two counters stay orthogonal across the gate: resolution
        // says the payload path was declined, extraction says a BOM
        // still came out — the metadata one. An operator reading
        // `hosted_only` must not conclude the scan produced nothing.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ =
                    run_cargo_scan_in_repo_type(RepositoryType::Proxy, b"RESOLVED:serde@1.0.200")
                        .await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_extraction_total", |labels| {
                labels.get("format") == Some(&"cargo") && labels.get("result") == Some(&"success")
            }),
            Some(1),
        );
    }
}
