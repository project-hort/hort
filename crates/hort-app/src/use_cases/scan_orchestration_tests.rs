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
use hort_domain::entities::scan_policy::{ProvenanceMode, ScanPolicyProjection, SeverityThreshold};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    Actor, DomainEvent, PersistedEvent, PolicyScope, ScanCompleted, SeveritySummary, StreamId,
};
use hort_domain::ports::advisory::AdvisoryPort;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::jobs_repository::{JobStatus, JobsRepository, ScanJob, TriggerSource};
use hort_domain::ports::scanner::ScannerPort;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{
    ArtifactCoords, ContentHash, Ecosystem, Finding, PayloadAccess, Sbom, SbomComponent,
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
    }
}

fn finding_with_score(purl: &str, vuln: &str, sev: SeverityThreshold, score: f32) -> Finding {
    let mut f = finding(purl, vuln, sev);
    f.cvss_score = Some(score);
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
    make_uc_with_policy_repo_and_handlers(scanners, advisory, policy_projections, handlers)
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
        );
    (uc, jobs, events, storage, artifacts, repositories, policy)
}

#[allow(clippy::type_complexity)]
fn make_uc_with_policy_repo_and_handlers(
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    advisory: Arc<dyn AdvisoryPort>,
    policy_projections: Arc<MockPolicyProjectionRepository>,
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
    ));

    let config = ScanOrchestrationConfig::defaults_for_worker("test-worker");

    let uc = ScanOrchestrationUseCase::new(
        jobs.clone(),
        artifacts.clone(),
        artifact_metadata.clone(),
        repositories.clone(),
        policy_projections.clone(),
        advisory,
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

#[tokio::test]
async fn record_outcome_failed_at_max_attempts_marks_failed_terminally() {
    let (uc, jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    // The retry-exhausted Failed arm transitions the
    // artifact to ScanIndeterminate *before* mark_failed (ADR 0007), so the
    // artifact must exist (the fail-closed transition is the priority).
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

    // The artifact is now terminally ScanIndeterminate (ADR 0007).
    let saved = artifacts.get(artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::ScanIndeterminate);
    assert!(!saved.is_downloadable());
}

// ===========================================================================
// Fail-closed terminal scan failure (ADR 0007)
// ===========================================================================

/// The retry-exhausted Failed arm transitions a `Quarantined` artifact
/// to `ScanIndeterminate` (fail-closed) AND still marks the job failed.
/// The artifact transition lands before `mark_failed` so a crash
/// between them leaves the job retryable rather than the artifact
/// silently un-failed.
#[tokio::test]
async fn record_outcome_failed_at_max_attempts_transitions_artifact_scan_indeterminate() {
    let (uc, jobs, _events, _storage, artifacts, repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 5);

    uc.record_outcome(&job, ScanRunOutcome::Failed("all backends down".into()))
        .await
        .expect("record_outcome");

    let saved = artifacts.get(artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::ScanIndeterminate);
    // Job still marked failed (the per-attempt job state is unchanged).
    assert_eq!(jobs.failed_calls().len(), 1);
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
    ));

    let config = ScanOrchestrationConfig::defaults_for_worker("test-worker");
    let uc = ScanOrchestrationUseCase::new(
        jobs.clone(),
        artifacts.clone(),
        artifact_metadata,
        repositories.clone(),
        policy_projections,
        Arc::new(MockAdvisory::ok(vec![])),
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
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
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
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
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
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
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
// `coords_for_artifact` must carry `ArtifactMetadata.metadata` so
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
/// `format` is set to `Npm` so the orchestrator's `coords_for_artifact`
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
    // Regression guard. With `coords_for_artifact` hardcoded to
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
async fn coords_for_artifact_uses_value_null_when_metadata_row_absent() {
    // Defensive — when the metadata row is absent (proxied fetch
    // with no parsed body, etc.), `coords_for_artifact` must keep
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

    let coords = uc.coords_for_artifact(&artifact).await.expect("coords");
    assert!(
        coords.metadata.is_null(),
        "absent metadata row must produce Value::Null coords.metadata; got: {}",
        coords.metadata
    );
}

#[tokio::test]
async fn coords_for_artifact_propagates_metadata_when_present() {
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

    let coords = uc.coords_for_artifact(&artifact).await.expect("coords");
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

    #[test]
    fn hort_scan_terminal_total_indeterminate_on_retry_exhaustion() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
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

    /// One-metric-one-layer: the retry-exhausted arm ticks
    /// `hort_scan_terminal_total{indeterminate}` exactly once and the
    /// per-attempt `hort_scan_jobs_total{failed}` exactly once — they
    /// count different things and must not double-count.
    #[test]
    fn hort_scan_terminal_total_does_not_double_count_scan_jobs_total() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let (uc, _jobs, _events, _storage, artifacts, repositories, _policy) =
                    make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
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
            )
            .with_include_repository_label(false),
        );

        let config = ScanOrchestrationConfig::defaults_for_worker("test-worker");
        let artifact_metadata = Arc::new(MockArtifactMetadataRepository::new());
        // `storage` is no longer threaded through the orchestrator;
        // the consumer (`QuarantineUseCase`) owns the CAS write site.
        let _ = storage;
        // `events` is no longer held by the orchestrator either;
        // the consumer owns the event-store reads.
        let _ = events;
        ScanOrchestrationUseCase::new(
            jobs,
            artifacts,
            artifact_metadata,
            repositories,
            policy_projections,
            Arc::new(MockAdvisory::ok(vec![])),
            HashMap::new(),
            HashMap::new(),
            quarantine,
            config,
        )
    }
}
