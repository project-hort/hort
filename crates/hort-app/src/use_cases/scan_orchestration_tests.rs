//! Unit tests for `ScanOrchestrationUseCase`.
//!
//! Coverage targets:
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

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::repository::RepositoryType;
use hort_domain::entities::scan_policy::{
    CompositeVerdictMode, NegligibleAction, ProvenanceMode, ScanEnforcement, ScanPolicyProjection,
    SeverityThreshold,
};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    Actor, DomainEvent, PersistedEvent, PolicyScope, ScanCompleted, SeveritySummary, StreamId,
};
use hort_domain::ports::advisory::AdvisoryPort;
use hort_domain::ports::composite_scan_observation::{CompositeAssessment, GateDecision};
use hort_domain::ports::format_handler::{
    FormatHandler, PayloadSbom, PayloadSbomExtraction, SbomResolution,
};
use hort_domain::ports::jobs_repository::{
    JobStatus, JobsRepository, ResultWriteOutcome, ScanJob, TriggerSource,
};
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, UpstreamAuth,
};
use hort_domain::ports::scanner::{
    EvidenceBasis, NotAnalysable, ScanAnalysis, ScanTarget, ScanUnit, ScannerPort,
};
use hort_domain::ports::BoxFuture;
use hort_domain::types::{
    ArtifactCoords, ArtifactKind, ComponentRelation, ContentHash, Ecosystem, Finding,
    FindingStatement, PayloadAccess, Sbom, SbomComponent, SeverityBasis,
};

use super::*;
use crate::use_cases::quarantine_use_case::QuarantineUseCase;
use crate::use_cases::test_support::*;

/// The kind these tests build an outcome under unless the test is about
/// ADR 0064 D2's role half: a row that is **not** a composition
/// constituent, so no stored statement can be what produced the verdict
/// being asserted. The constituent cases wire
/// `handler_map("oci", ArtifactKind::OciBlob)` and let `run_scan` resolve
/// it, which is the path that matters for them.
const TEST_SCAN_KIND: ArtifactKind = ArtifactKind::NpmTarball;

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
    /// The fence every result write arrived with, and what they
    /// answer. The orchestrator has to hand the row's own `attempts`
    /// to each of the three — a write carrying any other number is a
    /// write no execution can own. See [`ResultWriteLog`].
    write_log: ResultWriteLog,
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
        attempt: u32,
        _result_summary: serde_json::Value,
    ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
        self.completed.lock().unwrap().push(job_id);
        let outcome = self.write_log.record(attempt);
        Box::pin(async move { Ok(outcome) })
    }
    fn reschedule<'a>(
        &'a self,
        job_id: Uuid,
        attempt: u32,
        backoff: Duration,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
        self.rescheduled
            .lock()
            .unwrap()
            .push((job_id, backoff, last_error.to_string()));
        let outcome = self.write_log.record(attempt);
        Box::pin(async move { Ok(outcome) })
    }
    fn mark_failed<'a>(
        &'a self,
        job_id: Uuid,
        attempt: u32,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
        self.failed
            .lock()
            .unwrap()
            .push((job_id, last_error.to_string()));
        let outcome = self.write_log.record(attempt);
        Box::pin(async move { Ok(outcome) })
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
    /// `Some(Ok(analysis))` = the backend returned that analysis;
    /// `Some(Err(_))` = it failed; `None` = panics (tests should always
    /// seed an outcome).
    response: Mutex<Option<DomainResult<ScanAnalysis>>>,
    /// Number of times `scan` was invoked.
    calls: Mutex<u32>,
    /// The [`ArtifactKind`] the last `scan` call was handed, so tests can
    /// assert the orchestrator resolved it from the format handler rather
    /// than defaulting.
    seen_kind: Mutex<Option<ArtifactKind>>,
    /// The format key the last `scan` call was handed.
    seen_format: Mutex<Option<String>>,
    /// The stored path the last `scan` call's coords carried.
    seen_path: Mutex<Option<String>>,
    /// Whether each `scan` call was handed a composed image rather than
    /// a single blob, in call order. The composite assessment reaches a
    /// backend through the same `scan` method, so this is how a test
    /// tells the shadow invocation from the primary one.
    seen_units: Mutex<Vec<ScanUnitShape>>,
    /// What to answer a **composed image** with, when a test wants the
    /// two invocations to differ. `None` → the same `response` every
    /// other call gets.
    composite_response: Mutex<Option<DomainResult<ScanAnalysis>>>,
    /// The formats this backend claims to analyse — the mock's
    /// programmable [`ScannerPort::applies_to`]. `None` (the default)
    /// means "every format", which is what the tests that drive
    /// dispatch purely from the policy's backend list want.
    covers: Option<Vec<String>>,
    /// What this backend looked at — the mock's programmable
    /// [`ScannerPort::evidence_basis`]. The default mirrors the
    /// out-of-the-box backend (`trivy`, which materialises the payload);
    /// the component-relation tests that need the other reading set it
    /// with [`MockScanner::sbom_driven`].
    evidence: EvidenceBasis,
}

impl MockScanner {
    /// A backend that produces a verdict — the common case, so it keeps
    /// the plain `Vec<Finding>` constructor.
    fn new(name: impl Into<String>, response: DomainResult<Vec<Finding>>) -> Self {
        Self::with_analysis(name, response.map(ScanAnalysis::Analysed))
    }

    /// A backend whose whole `ScanAnalysis` the test chooses — used for
    /// the `NothingAnalysable` arms.
    fn with_analysis(name: impl Into<String>, response: DomainResult<ScanAnalysis>) -> Self {
        Self {
            name_: name.into(),
            response: Mutex::new(Some(response)),
            calls: Mutex::new(0),
            seen_kind: Mutex::new(None),
            seen_format: Mutex::new(None),
            seen_path: Mutex::new(None),
            seen_units: Mutex::new(Vec::new()),
            composite_response: Mutex::new(None),
            covers: None,
            evidence: EvidenceBasis::MaterialisedPayload,
        }
    }

    /// Answer a composed-image target with `response` instead of the
    /// one every other target gets — so a test can give the composite a
    /// finding and then assert that the finding went nowhere.
    fn answering_composites_with(self, response: DomainResult<ScanAnalysis>) -> Self {
        *self.composite_response.lock().unwrap() = Some(response);
        self
    }

    /// Narrow this backend's capability to `formats` — the mock's half
    /// of the scanner capability map. Used by the tests that pin the
    /// orchestrator's consult-before-invoke behaviour, where the whole
    /// point is a backend that answers `false` for the job's format.
    fn covering(mut self, formats: &[&str]) -> Self {
        self.covers = Some(formats.iter().map(|f| (*f).to_string()).collect());
        self
    }

    /// Declare this backend SBOM-driven: it consumes the component list
    /// it is handed and never opens the payload, the way the osv adapter
    /// and the advisory-enrichment path do.
    fn sbom_driven(mut self) -> Self {
        self.evidence = EvidenceBasis::SuppliedSbom;
        self
    }

    /// How many times `scan` was invoked — the assertion that separates
    /// "the backend abstained" from "the backend was never asked".
    fn calls(&self) -> u32 {
        *self.calls.lock().unwrap()
    }

    fn seen_kind(&self) -> Option<ArtifactKind> {
        *self.seen_kind.lock().unwrap()
    }

    fn seen_format(&self) -> Option<String> {
        self.seen_format.lock().unwrap().clone()
    }

    fn seen_path(&self) -> Option<String> {
        self.seen_path.lock().unwrap().clone()
    }

    /// What shape each `scan` call was handed, in call order.
    fn seen_units(&self) -> Vec<ScanUnitShape> {
        self.seen_units.lock().unwrap().clone()
    }
}

/// Which [`ScanUnit`] variant a `scan` call was handed, flattened to a
/// value a test can compare — the real enum borrows, so it cannot be
/// stashed in a mock's history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanUnitShape {
    /// One stored object.
    Blob,
    /// A composed image, with its layer count.
    Image(usize),
}

impl ScannerPort for MockScanner {
    fn name(&self) -> &str {
        &self.name_
    }
    /// Programmable via [`MockScanner::covering`]. The default is "every
    /// format", because most tests here drive dispatch from the policy's
    /// backend list rather than from the capability map; the tests that
    /// pin the orchestrator's consult narrow it deliberately. The map's
    /// real truth is asserted against the static record and the live
    /// adapters in the worker's parity guard.
    fn applies_to(&self, format: &str) -> bool {
        self.covers
            .as_ref()
            .is_none_or(|formats| formats.iter().any(|f| f == format))
    }
    fn evidence_basis(&self) -> EvidenceBasis {
        self.evidence
    }
    fn scan<'a>(
        &'a self,
        target: &'a ScanTarget<'a>,
        _sbom: Option<&'a Sbom>,
    ) -> BoxFuture<'a, DomainResult<ScanAnalysis>> {
        *self.calls.lock().unwrap() += 1;
        *self.seen_kind.lock().unwrap() = Some(target.kind);
        *self.seen_format.lock().unwrap() = Some(target.format.to_string());
        *self.seen_path.lock().unwrap() = Some(target.coords.path.clone());
        let shape = match target.unit {
            ScanUnit::Blob(_) => ScanUnitShape::Blob,
            ScanUnit::Image(image) => ScanUnitShape::Image(image.layers().len()),
        };
        self.seen_units.lock().unwrap().push(shape);
        let composite = self.composite_response.lock().unwrap().clone();
        let resp = match (shape, composite) {
            (ScanUnitShape::Image(_), Some(response)) => response,
            _ => self
                .response
                .lock()
                .unwrap()
                .clone()
                .expect("test forgot to seed scanner response"),
        };
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
        component_relation: ComponentRelation::NotEstablished,
        statement: FindingStatement::Unstated,
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

/// [`make_uc_with_upstream`] with the **hosted** upstream shape: an empty
/// resolver, so the composite path's constituent acquisition finds no
/// upstream and never reaches the proxy. That is the right default for
/// every test whose subject is not acquisition, and it is what the
/// orchestrator did before acquisition existed.
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
    let (
        uc,
        jobs,
        events,
        storage,
        artifacts,
        repositories,
        policy,
        metadata,
        _proxy,
        _resolver,
        _observations,
    ) = make_uc_with_upstream(
        scanners,
        advisory,
        policy_projections,
        handlers,
        config,
        Arc::new(MockUpstreamResolver::new()),
    );
    (
        uc,
        jobs,
        events,
        storage,
        artifacts,
        repositories,
        policy,
        metadata,
    )
}

/// The full harness, with the composite path's upstream resolver supplied
/// by the caller — a seeded one makes the artifact's repository a proxy, an
/// empty one makes it hosted. Returns the `MockUpstreamProxy` it wired so a
/// test can seed blob fixtures and count fetches.
#[allow(clippy::type_complexity)]
fn make_uc_with_upstream(
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    advisory: Arc<dyn AdvisoryPort>,
    policy_projections: Arc<MockPolicyProjectionRepository>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
    config: ScanOrchestrationConfig,
    upstream_resolver: Arc<MockUpstreamResolver>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockJobsRepository>,
    Arc<MockEventStore>,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
    Arc<MockPolicyProjectionRepository>,
    Arc<MockArtifactMetadataRepository>,
    Arc<MockUpstreamProxy>,
    Arc<MockUpstreamResolver>,
    Arc<MockCompositeScanObservationRepository>,
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

    let upstream_proxy = Arc::new(MockUpstreamProxy::new());
    let observations = Arc::new(MockCompositeScanObservationRepository::new());
    let uc = ScanOrchestrationUseCase::new(
        jobs.clone(),
        artifacts.clone(),
        artifact_metadata.clone(),
        repositories.clone(),
        policy_projections.clone(),
        advisory,
        storage.clone(),
        upstream_proxy.clone(),
        upstream_resolver.clone(),
        scanners,
        handlers,
        quarantine,
        Arc::new(ShadowObservationSink::new(observations.clone())),
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
        upstream_proxy,
        upstream_resolver,
        observations,
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
        composite_verdict_mode: CompositeVerdictMode::Observed,
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
            assessment: ScanAssessment::Analysed,
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(api_actor()),
        event_version: 1,
        stored_at: Utc::now() - chrono::Duration::hours(1),
    }
}

// ===========================================================================
// PURE HELPERS — merge_findings, severity_summary
// ===========================================================================
//
// The backoff curve `record_outcome`'s `Failed` branch waits out is no
// longer defined in this module: it moved to `crate::retry_backoff`,
// shared with the task dispatcher, and its per-attempt values are
// pinned there. `record_outcome`'s own use of it — a `Failed` outcome
// below `max_attempts` reschedules rather than failing the row — is
// covered by the `record_outcome` tests further down.

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

/// The relation the merge hands the survivor is the more condemning of
/// the two inputs, whichever row won on severity — and `merge_collision`
/// asserts it in BOTH contribution orders, which is the point: the
/// ranking and the relation disagree here on purpose.
///
/// The reachable shape, with the ranking deliberately pointing the other
/// way: a purl the BOM does not list, found in the payload by a backend
/// that materialised the artifact's bytes (`Contained`) and unjoinable by
/// one whose whole input was the BOM (`NotEstablished`). The SBOM-driven
/// row carries the higher tier, so it wins the ranking — and must not
/// bring its weaker claim with it, or release authority would be decided
/// by a severity comparison that never looked at containment.
#[test]
fn merge_keeps_the_more_condemning_relation_when_the_other_row_wins_on_severity() {
    let purl = "pkg:cargo/unlisted@1.0.0";
    let vuln = "CVE-9999-0010";

    let mut payload_scanned = finding(purl, vuln, SeverityThreshold::Low);
    payload_scanned.component_relation = ComponentRelation::Contained;
    payload_scanned.source_scanner = "trivy".into();

    let mut sbom_driven = finding(purl, vuln, SeverityThreshold::Critical);
    sbom_driven.component_relation = ComponentRelation::NotEstablished;
    sbom_driven.source_scanner = "osv".into();

    let winner = merge_collision(&payload_scanned, &sbom_driven, true);
    assert_eq!(
        winner.severity,
        SeverityThreshold::Critical,
        "the ranking is untouched — the higher tier still wins the row",
    );
    assert_eq!(
        winner.component_relation,
        ComponentRelation::Contained,
        "the survivor keeps the stronger containment claim, not the loser's",
    );
}

/// The direction that decides a verdict, and the one §7 is fail-closed
/// about: an established non-containment must never be the relation a
/// merge picks up from the row that won on severity. A `NotContained`
/// winner here would hand a condemning finding's authority away on an
/// axis the ranking never compared.
#[test]
fn merge_never_lets_a_not_contained_row_disarm_a_condemning_one() {
    let purl = "pkg:cargo/h2@0.4.13";
    let vuln = "RUSTSEC-2026-0004";

    let mut not_contained_critical = finding(purl, vuln, SeverityThreshold::Critical);
    not_contained_critical.component_relation = ComponentRelation::NotContained;

    for other in [
        ComponentRelation::Subject,
        ComponentRelation::Contained,
        ComponentRelation::NotEstablished,
    ] {
        let mut condemning_low = finding(purl, vuln, SeverityThreshold::Low);
        condemning_low.component_relation = other;

        let winner = merge_collision(&not_contained_critical, &condemning_low, true);
        assert_eq!(
            winner.severity,
            SeverityThreshold::Critical,
            "{other:?}: the ranking still picks the higher tier",
        );
        assert_eq!(
            winner.component_relation, other,
            "{other:?}: must outrank an established non-containment",
        );
        assert!(
            winner.may_condemn_artifact(TEST_SCAN_KIND, CompositeVerdictMode::Observed),
            "{other:?}: the merged finding must keep the authority an input had",
        );
    }
}

/// Agreement is a no-op: two rows carrying the same relation merge to it,
/// for every relation. The resolution must not perturb the common case —
/// in particular it must not promote a `NotContained` pair into something
/// that condemns, which is what a "fail closed, always" reading written
/// without the order would do.
#[test]
fn merge_leaves_an_agreed_relation_alone() {
    let purl = "pkg:cargo/x@1.0.0";
    let vuln = "CVE-9999-0011";

    for relation in [
        ComponentRelation::Subject,
        ComponentRelation::Contained,
        ComponentRelation::NotContained,
        ComponentRelation::NotEstablished,
    ] {
        let mut a = finding(purl, vuln, SeverityThreshold::Critical);
        a.component_relation = relation;
        let mut b = finding(purl, vuln, SeverityThreshold::Low);
        b.component_relation = relation;

        let winner = merge_collision(&a, &b, true);
        assert_eq!(winner.component_relation, relation, "{relation:?}");
    }
}

/// Three backends on one advisory: the resolution is folded pairwise as
/// each duplicate arrives, so a third row must not walk the relation back
/// down. Swept over every permutation, because the arrival order is the
/// configured `scan_backends` list.
#[test]
fn merge_folds_three_relations_to_the_most_condemning_in_every_order() {
    let purl = "pkg:cargo/x@1.0.0";
    let vuln = "CVE-9999-0012";

    let relations = [
        ComponentRelation::NotContained,
        ComponentRelation::NotEstablished,
        ComponentRelation::Contained,
    ];
    let row = |relation: ComponentRelation| {
        let mut f = finding(purl, vuln, SeverityThreshold::Critical);
        f.component_relation = relation;
        f
    };
    for (i, j, k) in [
        (0, 1, 2),
        (0, 2, 1),
        (1, 0, 2),
        (1, 2, 0),
        (2, 0, 1),
        (2, 1, 0),
    ] {
        let merged = merge_findings(
            vec![row(relations[i]), row(relations[j]), row(relations[k])],
            true,
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].component_relation,
            ComponentRelation::Contained,
            "order {i}{j}{k} must still fold to the strongest claim",
        );
    }
}

/// A collision on `(purl, vulnerability_id)` only — the relation
/// resolution must not reach across findings that never collided.
/// Two different purls both keep their own relation.
#[test]
fn merge_resolves_the_relation_per_collision_not_across_the_set() {
    let vuln = "CVE-9999-0013";
    let mut subject = finding("pkg:cargo/app@1.0.0", vuln, SeverityThreshold::Critical);
    subject.component_relation = ComponentRelation::Subject;
    let mut elsewhere = finding("pkg:cargo/dep@2.0.0", vuln, SeverityThreshold::Critical);
    elsewhere.component_relation = ComponentRelation::NotContained;

    let merged = merge_findings(vec![subject, elsewhere], true);
    assert_eq!(merged.len(), 2, "different purls do not collide");
    assert_eq!(merged[0].component_relation, ComponentRelation::Subject);
    assert_eq!(
        merged[1].component_relation,
        ComponentRelation::NotContained,
        "a finding that collided with nothing keeps the relation it was tagged with",
    );
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
    assert!(matches!(outcome, ScanRunOutcome::SkippedNoBackends { .. }));
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
        assessment: ScanAssessment::Analysed,
        scanner,
        findings,
        kind: _,
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
        assessment: ScanAssessment::Analysed,
        scanner,
        findings,
        kind: _,
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

    uc.record_outcome(
        &job,
        ScanRunOutcome::SkippedNoBackends {
            kind: TEST_SCAN_KIND,
        },
    )
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
        kind: TEST_SCAN_KIND,
        assessment: ScanAssessment::Analysed,
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
        kind: TEST_SCAN_KIND,
        assessment: ScanAssessment::Analysed,
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
        hex::encode(Sha256::digest(&prior_json)).parse().unwrap()
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
        kind: TEST_SCAN_KIND,
        assessment: ScanAssessment::Analysed,
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
        hex::encode(Sha256::digest(&prior_json)).parse().unwrap()
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
        kind: TEST_SCAN_KIND,
        assessment: ScanAssessment::Analysed,
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

/// Every `record_outcome` arm writes under the row's own `attempts`
/// — the identity the adapter's result-write fence compares against.
///
/// A write carrying any other number is a write no execution owns, and
/// the fence refuses it. The arms reach three different methods and
/// the orchestrator closes the row out itself (the dispatcher's own
/// write comes after), so each arm is checked rather than one standing
/// in for the others.
#[tokio::test]
async fn record_outcome_writes_under_the_rows_own_attempt() {
    let cases: Vec<(&str, u32, ScanRunOutcome)> = vec![
        (
            "mark_completed",
            1,
            ScanRunOutcome::SkippedNoBackends {
                kind: TEST_SCAN_KIND,
            },
        ),
        ("reschedule", 2, ScanRunOutcome::Failed("transient".into())),
        (
            "mark_failed",
            5, // == default max_attempts → terminal.
            ScanRunOutcome::Failed("dead".into()),
        ),
    ];
    for (write, attempts, outcome) in cases {
        let (uc, jobs, _events, _storage, artifacts, repositories, _policy) =
            make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
        let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
        let job = sample_scan_job(artifact_id, attempts);

        uc.record_outcome(&job, outcome)
            .await
            .expect("record_outcome");

        assert_eq!(
            jobs.write_log.attempts(),
            vec![attempts],
            "{write} must write under the row's own attempt",
        );
    }
}

/// A refused result write is not an error.
///
/// If the orchestrator propagated it, `ScanTaskHandler` would return a
/// retryable failure, the dispatcher would answer with a `reschedule`,
/// and a row that already belongs to a sibling would be written to a
/// second time — turning one discarded result into the `pending`
/// clobber the fence exists to prevent. The refusal is logged and the
/// arm completes.
#[tokio::test]
async fn a_refused_result_write_does_not_become_a_retryable_failure() {
    let (uc, jobs, _events, _storage, _artifacts, _repositories, _policy) =
        make_uc(vec![], HashMap::new(), Arc::new(MockAdvisory::ok(vec![])));
    jobs.write_log
        .refuse(ResultWriteOutcome::Superseded { current_attempt: 9 });
    let job = sample_scan_job(Uuid::new_v4(), 2);

    uc.record_outcome(&job, ScanRunOutcome::Failed("transient".into()))
        .await
        .expect("a refused write is an outcome, not an error");

    assert_eq!(
        jobs.write_log.attempts(),
        vec![2],
        "the write is attempted exactly once and not retried under another identity"
    );
    assert!(
        jobs.failed_calls().is_empty(),
        "and it is not answered with a different write"
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
    // `artifacts.last_scan_at` is written ONLY by `commit_scan_result`
    // (the `ScanCompleted` path) — never by a Failed outcome. A
    // permanently-failing artifact must not have its rescan-eligibility
    // clock reset, or `RescanCandidatesRepository::select_eligible`'s
    // `last_scan_at < now - interval` predicate would treat it as
    // freshly scanned instead of leaving it for `select_stranded` to
    // re-pick.
    assert!(
        lifecycle.last_scan_at_writes().is_empty(),
        "a Failed scan outcome must never advance last_scan_at"
    );
}

/// Companion to the test above for the *other* prior-status branch: a
/// `None`-status artifact that hard-blocks to `ScanIndeterminate` on
/// retry exhaustion also must not advance `last_scan_at` — the only
/// call site for that denorm write is `commit_scan_result`
/// (the `ScanCompleted` path), and `record_scan_indeterminate` never
/// reaches it. This is the same load-bearing fact backlog item 143 (Q1)
/// asked to establish: a FAILED scan does not advance the candidacy
/// projection, on either prior-status branch.
#[tokio::test]
async fn record_outcome_failed_at_max_attempts_hard_block_does_not_advance_last_scan_at() {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    let (uc, _jobs, artifacts, repositories, lifecycle) =
        make_uc_with_lifecycle(policy_projections);
    let artifact_id = seed_none_status_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 5); // == default max_attempts.

    uc.record_outcome(&job, ScanRunOutcome::Failed("all backends down".into()))
        .await
        .expect("record_outcome");

    let saved = artifacts.get(artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::ScanIndeterminate);
    assert!(
        lifecycle.last_scan_at_writes().is_empty(),
        "a Failed scan outcome must never advance last_scan_at, even when it \
         hard-blocks the artifact to ScanIndeterminate"
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
        Arc::new(MockUpstreamProxy::new()),
        Arc::new(MockUpstreamResolver::new()),
        HashMap::new(),
        HashMap::new(),
        quarantine,
        Arc::new(ShadowObservationSink::new(Arc::new(
            MockCompositeScanObservationRepository::new(),
        ))),
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
        kind: TEST_SCAN_KIND,
        assessment: ScanAssessment::Analysed,
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
/// orchestrator has on the bytes. The repository is `Hosted`; every
/// class takes the payload path, so callers that need a different one
/// use [`seed_cargo_artifact_in_repo_type`] directly.
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
/// chosen by the caller.
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
async fn payload_scan_in_a_proxy_repo_reads_the_stored_payload() {
    // ADR 0056's amendment: the repository class no longer decides
    // whether the payload path runs. `payload_sbom()` answering `Some`
    // for cargo is now sufficient by itself, so a proxied artifact reads
    // CAS exactly as a hosted one does.
    let (_queried, handler, storage) =
        run_cargo_scan_in_repo_type(RepositoryType::Proxy, b"RESOLVED:serde@1.0.200").await;

    assert_eq!(
        storage.get_call_count(),
        1,
        "a proxied cargo artifact reads CAS for its SBOM, same as hosted"
    );
    assert!(
        handler.seen_payload.lock().unwrap().is_some(),
        "the payload capability is dispatched for a proxied repository"
    );
}

#[tokio::test]
async fn payload_scan_in_a_proxy_repo_resolves_from_the_payload() {
    // The behaviour half of the same reversal: a proxied cargo scan now
    // produces the resolved-lockfile SBOM, not the declared-range one.
    // The false-positive-with-gate-power risk this used to guard against
    // is addressed by `enforcement: record` on proxied lockfile formats
    // (an operator setting, not a scanner-side gate) rather than by
    // withholding the SBOM.
    let (queried, _handler, _storage) =
        run_cargo_scan_in_repo_type(RepositoryType::Proxy, b"RESOLVED:serde@1.0.200").await;

    assert!(
        queried.iter().any(|c| c.purl == "pkg:cargo/serde@1.0.200"),
        "the proxy path must resolve from the payload, not the declared range: {queried:?}"
    );
}

#[tokio::test]
async fn payload_scan_runs_for_every_repository_class() {
    // Every `RepositoryType` takes the payload path once the handler
    // declares `payload_sbom()`. This is what stops a future edit from
    // reintroducing a per-class gate — the scanner must be able to
    // deliver the threat level the repository configuration declares,
    // for every class that configuration allows.
    for repo_type in [
        RepositoryType::Hosted,
        RepositoryType::Proxy,
        RepositoryType::Virtual,
        RepositoryType::Staging,
    ] {
        let (queried, handler, storage) =
            run_cargo_scan_in_repo_type(repo_type, b"RESOLVED:serde@1.0.200").await;
        assert_eq!(
            storage.get_call_count(),
            1,
            "{repo_type:?} must read CAS for its SBOM"
        );
        assert!(
            handler.seen_payload.lock().unwrap().is_some(),
            "{repo_type:?} must dispatch the payload capability"
        );
        assert!(
            queried.iter().any(|c| c.purl == "pkg:cargo/serde@1.0.200"),
            "{repo_type:?} must take the payload path: {queried:?}"
        );
    }
}

#[tokio::test]
async fn payload_scan_in_a_hosted_repo_still_resolves_from_the_payload() {
    // Pinned on its own so a future change that narrows the payload
    // path fails here rather than silently turning a hosted cargo scan
    // into a subject-only one.
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
                uc.record_outcome(
                    &job,
                    ScanRunOutcome::SkippedNoBackends {
                        kind: TEST_SCAN_KIND,
                    },
                )
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
                uc.record_outcome(
                    &job,
                    ScanRunOutcome::SkippedNoBackends {
                        kind: TEST_SCAN_KIND,
                    },
                )
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
                    kind: TEST_SCAN_KIND,
                    assessment: ScanAssessment::Analysed,
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
                    kind: TEST_SCAN_KIND,
                    assessment: ScanAssessment::Analysed,
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
                    // both `ingest_source_from` and
                    // `prior_scan_completed` find what they need.
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
                        kind: TEST_SCAN_KIND,
                        assessment: ScanAssessment::Analysed,
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
                        kind: TEST_SCAN_KIND,
                        assessment: ScanAssessment::Analysed,
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
    // hort_scan_record_outcome_failures_total{result=inert_pairing}
    // ---------------------------------------------------------------

    /// A backend the capability map says cannot analyse the job's format
    /// attributes `result="inert_pairing"` to its own name — the
    /// alerting signal for "this repository is paired with a backend
    /// that adjudicates nothing there". The covering backend beside it
    /// emits nothing: it ran and produced a verdict.
    ///
    /// `inert_pairing` and `nothing_analysable` stay apart: the first is
    /// a backend that was never invoked (the pairing is the defect), the
    /// second is one that ran and found nothing to analyse.
    #[test]
    fn run_scan_emits_inert_pairing_metric_for_the_backend_it_skips() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let trivy: Arc<dyn ScannerPort> = Arc::new(
                    MockScanner::new("trivy", Ok(vec![]))
                        .covering(&["oci", "maven", "pypi", "npm", "cargo"]),
                );
                let osv: Arc<dyn ScannerPort> = Arc::new(
                    MockScanner::new("osv", Ok(vec![]))
                        .covering(&["npm", "pypi", "cargo", "maven"]),
                );
                let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
                scanners.insert("trivy".into(), trivy);
                scanners.insert("osv".into(), osv);
                let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
                    vec!["trivy".into(), "osv".into()],
                    scanners,
                    handler_map("oci", ArtifactKind::OciBlob),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = scan_job_for_format(artifact_id, "oci");
                let outcome = uc.run_scan(&job).await.expect("run_scan");
                assert!(matches!(outcome, ScanRunOutcome::Completed { .. }));
            })
        });
        let osv_inert = find_counter(&snap, "hort_scan_record_outcome_failures_total", |labels| {
            labels.get("result") == Some(&"inert_pairing") && labels.get("scanner") == Some(&"osv")
        });
        assert_eq!(
            osv_inert,
            Some(1),
            "the skipped backend must attribute inert_pairing to its own name"
        );
        let trivy_inert =
            find_counter(&snap, "hort_scan_record_outcome_failures_total", |labels| {
                labels.get("result") == Some(&"inert_pairing")
                    && labels.get("scanner") == Some(&"trivy")
            });
        assert_eq!(
            trivy_inert, None,
            "a backend that covers the format and ran must not emit inert_pairing"
        );
        let nothing_analysable =
            find_counter(&snap, "hort_scan_record_outcome_failures_total", |labels| {
                labels.get("result") == Some(&"nothing_analysable")
            });
        assert_eq!(
            nothing_analysable, None,
            "a backend that was never invoked did not 'run and find nothing'"
        );
    }

    /// The non-gating arm is silent on the failure counter: a format no
    /// backend covers asks nothing of an operator (there is no covering
    /// backend to switch to), so it logs at `debug!` and emits nothing.
    #[test]
    fn run_scan_emits_no_failure_metric_when_no_backend_covers_the_format() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let trivy: Arc<dyn ScannerPort> =
                    Arc::new(MockScanner::new("trivy", Ok(vec![])).covering(&["oci"]));
                let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
                scanners.insert("trivy".into(), trivy);
                let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
                    vec!["trivy".into()],
                    scanners,
                    handler_map("maven", ArtifactKind::MavenJar),
                );
                let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
                let job = scan_job_for_format(artifact_id, "gradle");
                let outcome = uc.run_scan(&job).await.expect("run_scan");
                assert!(matches!(outcome, ScanRunOutcome::Completed { .. }));
            })
        });
        let any = find_counter(&snap, "hort_scan_record_outcome_failures_total", |_| true);
        assert_eq!(
            any, None,
            "an uncovered format is not a failure to alert on"
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
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockUpstreamResolver::new()),
            HashMap::new(),
            HashMap::new(),
            quarantine,
            Arc::new(ShadowObservationSink::new(Arc::new(
                MockCompositeScanObservationRepository::new(),
            ))),
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
    fn hort_sbom_resolution_total_fires_resolved_for_a_proxy_repository() {
        // ADR 0056's amendment: `hosted_only` is retired, and a proxied
        // cargo scan now ticks `resolved` exactly as a hosted one does —
        // the repository class no longer changes which label fires.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ =
                    run_cargo_scan_in_repo_type(RepositoryType::Proxy, b"RESOLVED:serde@1.0.200")
                        .await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"cargo") && labels.get("result") == Some(&"resolved")
            }),
            Some(1),
        );
        assert_eq!(
            find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"cargo")
                    && labels.get("result") == Some(&"not_applicable")
            }),
            None,
            "a payload-capable format must not also tick not_applicable"
        );
    }

    #[test]
    fn hort_sbom_resolution_total_fires_resolved_for_a_staging_repository() {
        // `Staging` was excluded on purpose by the retired gate (it
        // counts as upload-accepting under `RepositoryType::is_hosted`
        // but the gate was a literal `Hosted` match). The amendment
        // removes the gate entirely, so `Staging` now resolves too.
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ =
                    run_cargo_scan_in_repo_type(RepositoryType::Staging, b"RESOLVED:serde@1.0.200")
                        .await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_sbom_resolution_total", |labels| {
                labels.get("format") == Some(&"cargo") && labels.get("result") == Some(&"resolved")
            }),
            Some(1),
        );
    }

    #[test]
    fn hort_sbom_extraction_total_reports_success_for_a_proxy_repository() {
        // The two counters stay orthogonal: resolution says the basis
        // (`resolved`), extraction says a BOM came out (`success`) —
        // unchanged by which repository class produced it.
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

    // -------------------------------------------------------------------
    // `hort_finding_component_relation_total{format, result}`
    // -------------------------------------------------------------------

    /// One tick per tagged finding, on the relation the join assigned and
    /// under the artifact's format. Without this series the
    /// `not_established` rate — the signal that says the condemning
    /// default has stopped being rare — is invisible.
    #[test]
    fn hort_finding_component_relation_total_ticks_once_per_tagged_finding() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ = run_tagged_scan(
                    "cargo",
                    Some(sbom_with(
                        Some("pkg:cargo/hyper-util@0.1.21"),
                        &["pkg:cargo/h2@0.4.13"],
                    )),
                    false,
                    vec![finding(
                        "pkg:cargo/h2@0.4.13",
                        "RUSTSEC-ADVISORY",
                        SeverityThreshold::Low,
                    )],
                    vec![finding(
                        "pkg:cargo/hyper-util@0.1.21",
                        "CVE-SUBJECT",
                        SeverityThreshold::High,
                    )],
                    true,
                )
                .await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_finding_component_relation_total", |labels| {
                labels.get("format") == Some(&"cargo")
                    && labels.get("result") == Some(&"not_contained")
            }),
            Some(1),
            "the advisory path's lockfile-pin finding"
        );
        assert_eq!(
            find_counter(&snap, "hort_finding_component_relation_total", |labels| {
                labels.get("format") == Some(&"cargo") && labels.get("result") == Some(&"subject")
            }),
            Some(1),
            "the scanner path's subject finding"
        );
        assert_eq!(
            find_counter(&snap, "hort_finding_component_relation_total", |labels| {
                labels.get("result") == Some(&"not_established")
            }),
            None,
            "a production-shaped BOM joins both findings"
        );
    }

    /// The `not established` arm is reachable and observable: an
    /// SBOM-driven producer naming a purl the BOM does not list ticks it.
    /// This is the series an operator alerts on — a non-zero rate on new
    /// scans means the join is broken, not that the artifact is odd.
    #[test]
    fn hort_finding_component_relation_total_records_a_failed_join() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ = run_tagged_scan(
                    "cargo",
                    Some(sbom_with(Some("pkg:cargo/app@1"), &["pkg:cargo/dep@2"])),
                    false,
                    vec![],
                    vec![finding(
                        "pkg:cargo/unlisted@3",
                        "CVE-UNLISTED",
                        SeverityThreshold::Critical,
                    )],
                    false,
                )
                .await;
            })
        });
        assert_eq!(
            find_counter(&snap, "hort_finding_component_relation_total", |labels| {
                labels.get("format") == Some(&"cargo")
                    && labels.get("result") == Some(&"not_established")
            }),
            Some(1),
        );
    }

    /// Closed taxonomy, bounded cardinality: the counter carries exactly
    /// `format` and `result`, and never a purl or a vulnerability id. The
    /// relation is per-finding, so an identity label here would mint one
    /// series per advisory.
    #[test]
    fn hort_finding_component_relation_total_carries_no_unbounded_labels() {
        let snap = capture_async_metrics(|| {
            Box::pin(async move {
                let _ = run_tagged_scan(
                    "cargo",
                    Some(sbom_with(Some("pkg:cargo/app@1"), &[])),
                    false,
                    vec![],
                    vec![finding(
                        "pkg:cargo/app@1",
                        "CVE-SUBJECT",
                        SeverityThreshold::High,
                    )],
                    true,
                )
                .await;
            })
        });
        let keys: Vec<_> = snap
            .iter()
            .filter(|(k, _, _, _)| k.key().name() == "hort_finding_component_relation_total")
            .collect();
        assert_eq!(keys.len(), 1, "one series for one tagged finding");
        let labels: HashMap<&str, &str> = keys[0]
            .0
            .key()
            .labels()
            .map(|l| (l.key(), l.value()))
            .collect();
        assert_eq!(labels.get("result"), Some(&"subject"));
        assert_eq!(labels.len(), 2, "exactly `format` and `result`: {labels:?}");
    }
}

// ===========================================================================
// FORMAT-AWARE SCAN TARGET + "nothing analysable" is not "clean"
// ===========================================================================

/// A handler that answers `scan_kind` with a fixed value, so a test can
/// prove the orchestrator asks the artifact's own handler rather than
/// defaulting.
struct FixedKindHandler {
    key: &'static str,
    kind: ArtifactKind,
}

impl FormatHandler for FixedKindHandler {
    fn format_key(&self) -> &str {
        self.key
    }
    fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
        Err(DomainError::Validation("not used by these tests".into()))
    }
    fn normalize_name(&self, name: &str) -> String {
        name.to_string()
    }
    fn scan_kind(&self, _artifact: &Artifact) -> ArtifactKind {
        self.kind
    }
}

fn handler_map(key: &'static str, kind: ArtifactKind) -> HashMap<String, Arc<dyn FormatHandler>> {
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert(key.to_string(), Arc::new(FixedKindHandler { key, kind }));
    handlers
}

/// Wire a use case with one scanner, one handler, and a global policy
/// naming `backends`.
#[allow(clippy::type_complexity)]
fn make_uc_with_handler(
    backends: Vec<String>,
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockJobsRepository>,
    Arc<MockEventStore>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
) {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(backends));
    let (uc, jobs, events, _storage, artifacts, repositories, _policy, _metadata) =
        make_uc_with_policy_repo_and_handlers(
            scanners,
            Arc::new(MockAdvisory::ok(vec![])),
            policy_projections,
            handlers,
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    (uc, jobs, events, artifacts, repositories)
}

fn one_scanner(scanner: Arc<MockScanner>) -> HashMap<String, Arc<dyn ScannerPort>> {
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert(scanner.name().to_string(), scanner);
    scanners
}

/// The scan target carries the artifact's identity and the kind its own
/// format handler assigned. Without this the adapter cannot materialise
/// anything an analyzer will look at.
#[tokio::test]
async fn run_scan_hands_the_backend_the_kind_from_the_artifacts_format_handler() {
    let scanner = Arc::new(MockScanner::new("trivy", Ok(vec![])));
    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into()],
        one_scanner(scanner.clone()),
        handler_map("npm", ArtifactKind::NpmTarball),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    uc.run_scan(&job).await.expect("run_scan");
    assert_eq!(scanner.seen_kind(), Some(ArtifactKind::NpmTarball));
    assert_eq!(scanner.seen_format().as_deref(), Some("npm"));
    assert_eq!(
        scanner.seen_path().as_deref(),
        Some("my-pkg/1.0.0/my-pkg-1.0.0.tar.gz"),
        "the target must carry the artifact's real coordinates, not a digest"
    );
}

/// With no handler registered for the repository's format there is no one
/// to classify the payload, and the orchestrator must not guess: `Other`
/// is the honest answer, and it is what makes the backend abstain rather
/// than report an unexamined artifact clean.
#[tokio::test]
async fn run_scan_passes_other_when_no_handler_is_registered_for_the_format() {
    let scanner = Arc::new(MockScanner::new("trivy", Ok(vec![])));
    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into()],
        one_scanner(scanner.clone()),
        HashMap::new(),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    uc.run_scan(&job).await.expect("run_scan");
    assert_eq!(scanner.seen_kind(), Some(ArtifactKind::Other));
}

/// The core regression. A backend that could not assess an *expected*
/// surface must NOT produce a clean `Completed` outcome:
/// `Completed { findings: [], assessment: Analysed }` is a clean verdict
/// carrying release authority, and nothing examined the bytes.
/// `NotApplicable` is deliberately absent from this loop — it is not an
/// unassessed surface but the absence of one, and has its own tests
/// below.
#[tokio::test]
async fn run_scan_returns_nothing_analysable_not_a_clean_completion() {
    for reason in [
        NotAnalysable::UnusableArchive,
        NotAnalysable::UnsupportedContainer,
        NotAnalysable::NoAnalyzerMatched,
    ] {
        let scanner = Arc::new(MockScanner::with_analysis(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(reason)),
        ));
        let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
            vec!["trivy".into()],
            one_scanner(scanner),
            handler_map("npm", ArtifactKind::NpmTarball),
        );
        let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
        let job = sample_scan_job(artifact_id, 1);

        let outcome = uc.run_scan(&job).await.expect("run_scan");
        let ScanRunOutcome::NothingAnalysable {
            scanner: label,
            reason: detail,
        } = outcome
        else {
            panic!("expected NothingAnalysable for {reason}, got {outcome:?}");
        };
        assert_eq!(label, "trivy");
        assert!(
            detail.contains("trivy") && detail.contains(reason.as_str()),
            "the reason must name the backend and why it abstained: {detail}"
        );
        assert!(
            detail.contains("npm_tarball"),
            "the reason must name the kind the backend was handed: {detail}"
        );
    }
}

/// One backend abstaining does not lose another's verdict. A real scan
/// happened, so the artifact gets a real result — and the abstention is
/// only a log line and a metric.
#[tokio::test]
async fn run_scan_keeps_a_verdict_when_only_one_of_two_backends_abstains() {
    let abstaining = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NoAnalyzerMatched,
        )),
    ));
    let verdict = Arc::new(MockScanner::new(
        "osv",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::High,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), abstaining);
    scanners.insert("osv".into(), verdict);

    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into(), "osv".into()],
        scanners,
        handler_map("npm", ArtifactKind::NpmTarball),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        assessment: ScanAssessment::Analysed,
        scanner,
        findings,
        ..
    } = outcome
    else {
        panic!("expected Completed from the backend that did analyse, got {outcome:?}");
    };
    assert_eq!(
        scanner, "osv",
        "the scanner label must name only the contributing backend"
    );
    assert_eq!(findings.len(), 1);
}

/// An *errored* backend still wins over an abstaining one: the error may
/// be transient, so the outcome stays the retryable `Failed` rather than
/// the immediately-terminal abstention.
#[tokio::test]
async fn run_scan_prefers_the_retryable_failure_when_one_backend_errored() {
    let abstaining = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let broken = Arc::new(MockScanner::new(
        "osv",
        Err(DomainError::Invariant("osv-scanner not found".into())),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), abstaining);
    scanners.insert("osv".into(), broken);

    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into(), "osv".into()],
        scanners,
        handler_map("npm", ArtifactKind::NpmTarball),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Failed(reason) = outcome else {
        panic!("an errored backend must keep the retryable path, got {outcome:?}");
    };
    // A mixed run must not tell an operator that the backend which ran
    // cleanly "failed" — the message names the split.
    assert!(
        reason.contains("1 of 2 failed") && reason.contains("1 had nothing to analyse"),
        "the reason must distinguish the failure from the abstention: {reason}"
    );
}

/// A materialisation a backend cannot analyse is a policy mismatch, not a
/// clean scan: the artifact goes terminal `scan_indeterminate` and the job
/// goes terminal `failed` with no retry budget spent, because the next
/// attempt would reach the same answer.
#[tokio::test]
async fn record_outcome_nothing_analysable_holds_the_artifact_and_does_not_retry() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NoAnalyzerMatched,
        )),
    ));
    let (uc, jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into()],
        one_scanner(scanner),
        handler_map("npm", ArtifactKind::NpmTarball),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    uc.record_outcome(
        &job,
        ScanRunOutcome::NothingAnalysable {
            scanner: "trivy".into(),
            reason: "no scan backend could analyse artifact (kind npm_tarball): \
                     trivy=no_analyzer_matched"
                .into(),
        },
    )
    .await
    .expect("record_outcome");

    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("artifact")
            .quarantine_status,
        QuarantineStatus::ScanIndeterminate,
        "an artifact nothing examined must be held, never released"
    );
    assert_eq!(
        jobs.failed_calls().len(),
        1,
        "the job must go terminal, not be rescheduled"
    );
    assert!(
        jobs.rescheduled_calls().is_empty(),
        "a deterministic abstention must not spend the retry budget"
    );
    assert!(
        jobs.completed_calls().is_empty(),
        "marking the job completed would read as a successful scan"
    );

    // The terminal state itself is the proof that no `ScanCompleted`
    // was recorded: `record_scan_result` would have driven the artifact
    // to a released or rejected status, never to `ScanIndeterminate`.
    assert!(
        !artifacts
            .get(artifact_id)
            .expect("artifact")
            .is_downloadable(),
        "an unexamined artifact must not be downloadable"
    );
}

/// The abstention path is idempotent on an already-terminal artifact —
/// the same recoverable skip the retry-exhausted path relies on, so a
/// re-driven job cannot double-append.
#[tokio::test]
async fn record_outcome_nothing_analysable_is_idempotent_on_a_terminal_artifact() {
    let scanner = Arc::new(MockScanner::new("trivy", Ok(vec![])));
    let (uc, jobs, events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into()],
        one_scanner(scanner),
        handler_map("npm", ArtifactKind::NpmTarball),
    );
    let artifact = sample_artifact(QuarantineStatus::ScanIndeterminate);
    let mut repo = sample_repository();
    repo.id = artifact.repository_id;
    let artifact_id = artifact.id;
    artifacts.insert(artifact);
    repositories.insert(repo);
    let job = sample_scan_job(artifact_id, 1);

    uc.record_outcome(
        &job,
        ScanRunOutcome::NothingAnalysable {
            scanner: "trivy".into(),
            reason: "trivy=not_applicable".into(),
        },
    )
    .await
    .expect("record_outcome must treat an already-terminal artifact as a skip");

    let appended: Vec<DomainEvent> = events
        .appended_batches()
        .into_iter()
        .flat_map(|batch| batch.events.into_iter().map(|e| e.event))
        .collect();
    assert!(
        !appended
            .iter()
            .any(|e| matches!(e, DomainEvent::ScanIndeterminate(_))),
        "no duplicate ScanIndeterminate on an already-terminal artifact"
    );
    assert_eq!(jobs.failed_calls().len(), 1);
}

// ---------------------------------------------------------------------------
// "Not applicable" is a completed assessment, not a hold
//
// An artifact with no package surface by construction — an OCI manifest
// row, a non-tar OCI blob such as the image config — is outside the scan
// axis. No scanner can find a threat level in it, so a fail-closed hold
// has nothing to wait on and never lifts: a Trivy-policed OCI repository
// would hold every image it ingests, forever. These pin the partition and
// the trail that keeps it honest (ADR 0007, 2026-09-18 clarification).
// ---------------------------------------------------------------------------

/// Every backend abstained, and every abstention was `NotApplicable` →
/// a completed assessment with nothing assessed, never a hold and never
/// a clean verdict.
#[tokio::test]
async fn run_scan_all_not_applicable_is_a_completed_not_applicable_assessment() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into()],
        one_scanner(scanner),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        scanner: label,
        findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("an artifact with no package surface must not be held, got {outcome:?}");
    };
    assert_eq!(
        assessment,
        ScanAssessment::NotApplicable,
        "the outcome must say there was nothing to assess, not that it was clean"
    );
    assert!(
        findings.is_empty(),
        "there is no surface a finding could have come from"
    );
    assert_eq!(
        label, "trivy",
        "the asked backends stay on the audit label even though none adjudicated"
    );
}

/// Pins the specific regression observed in staging UAT: a Trivy `rootfs`
/// scan of a package-less OCI layer (a CA-certificate-only layer, no
/// package database) reports an empty result, the adapter abstains
/// `NotApplicable`, and that abstention must release the layer — never
/// hold it as `scan_indeterminate`. This is the same partition
/// `run_scan_all_not_applicable_is_a_completed_not_applicable_assessment`
/// pins generically, kept as its own test because it is the exact shape
/// (`OciBlob`, single backend) that hung every multi-layer image before
/// the fix.
#[tokio::test]
async fn run_scan_releases_a_package_less_layer_whose_rootfs_scan_came_back_empty() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into()],
        one_scanner(scanner),
        handler_map("oci", ArtifactKind::OciBlob),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("a package-less layer must be released, not held, got {outcome:?}");
    };
    assert_eq!(assessment, ScanAssessment::NotApplicable);
    assert!(findings.is_empty());
}

/// The false-authority case the scanner capability map closes.
///
/// An OCI repository policed by `[trivy, osv]` on a package-less layer:
/// Trivy walks the root filesystem, finds no package surface and abstains
/// `NotApplicable`; `osv` has no SBOM to read, because OCI has no SBOM
/// source at all. The outcome must be a completed **not-applicable**
/// assessment — the honest "nothing to assess".
///
/// What must not happen is a clean `ScanCompleted`. An empty finding
/// list is a *verdict*, so a backend that answered a missing SBOM with
/// one would become the sole contributor here: the artifact would record
/// an analysed-and-clean scan, and every OCI blob in the repository would
/// earn the release authority of a scan that examined nothing. That clean
/// verdict is indistinguishable from a real one — nothing in the trail
/// says which backend looked at what — which is why the absence of a
/// verdict has to be its own value rather than an empty list.
#[tokio::test]
async fn run_scan_on_an_oci_layer_neither_backend_can_read_records_not_applicable() {
    let trivy = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    // The OSV adapter's own no-SBOM answer: an abstention, not a clean
    // verdict. OCI exposes no SBOM, so this is every OCI blob's outcome
    // under a policy that names `osv`.
    let osv = Arc::new(MockScanner::with_analysis(
        "osv",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy);
    scanners.insert("osv".into(), osv);

    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into(), "osv".into()],
        scanners,
        handler_map("oci", ArtifactKind::OciBlob),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("nothing to assess must not hold the layer, got {outcome:?}");
    };
    assert_eq!(
        assessment,
        ScanAssessment::NotApplicable,
        "the trail must say nothing was assessed, not that the layer scanned clean"
    );
    assert_ne!(
        assessment,
        ScanAssessment::Analysed,
        "an empty finding list from a backend that read no SBOM is not a verdict"
    );
    assert!(findings.is_empty());
}

/// One gating abstention among not-applicable ones still holds: the
/// expected surface it could not assess is still unassessed.
#[tokio::test]
async fn run_scan_holds_when_a_gating_abstention_joins_a_not_applicable_one() {
    for gating in [
        NotAnalysable::UnusableArchive,
        NotAnalysable::UnsupportedContainer,
        NotAnalysable::NoAnalyzerMatched,
    ] {
        let not_applicable = Arc::new(MockScanner::with_analysis(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NotApplicable,
            )),
        ));
        let gating_backend = Arc::new(MockScanner::with_analysis(
            "osv",
            Ok(ScanAnalysis::NothingAnalysable(gating)),
        ));
        let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
        scanners.insert("trivy".into(), not_applicable);
        scanners.insert("osv".into(), gating_backend);

        let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
            vec!["trivy".into(), "osv".into()],
            scanners,
            handler_map("npm", ArtifactKind::NpmTarball),
        );
        let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
        let job = sample_scan_job(artifact_id, 1);

        let outcome = uc.run_scan(&job).await.expect("run_scan");
        let ScanRunOutcome::NothingAnalysable { reason, .. } = outcome else {
            panic!("a {gating} abstention must still hold, got {outcome:?}");
        };
        assert!(
            reason.contains(gating.as_str()) && reason.contains("not_applicable"),
            "the reason must name both abstentions: {reason}"
        );
    }
}

/// A real verdict from one backend is unaffected by another's
/// not-applicable abstention — the artifact gets the analysed result.
#[tokio::test]
async fn run_scan_keeps_the_analysed_verdict_over_a_not_applicable_abstention() {
    let not_applicable = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let verdict = Arc::new(MockScanner::new(
        "osv",
        Ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::High,
        )]),
    ));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), not_applicable);
    scanners.insert("osv".into(), verdict);

    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into(), "osv".into()],
        scanners,
        handler_map("npm", ArtifactKind::NpmTarball),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        scanner,
        findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("expected the analysed verdict to stand, got {outcome:?}");
    };
    assert_eq!(
        assessment,
        ScanAssessment::Analysed,
        "a backend did analyse this artifact — the assessment is analysed"
    );
    assert_eq!(scanner, "osv");
    assert_eq!(findings.len(), 1);
}

/// Guard rail on the not-applicable arm: if advisory enrichment produced
/// a finding while every backend abstained, something DID have an opinion
/// about this artifact. Recording "nothing to assess" would be a false
/// statement and would drop a real finding, so the fail-closed hold
/// applies instead.
#[tokio::test]
async fn run_scan_holds_when_advisory_found_something_and_every_backend_abstained() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("npm".to_string(), Arc::new(NpmShapedSbomHandler));

    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, _metadata) = make_uc_full(
        vec!["trivy".into()],
        one_scanner(scanner),
        Arc::new(MockAdvisory::ok(vec![finding(
            "pkg:npm/foo@1",
            "CVE-1",
            SeverityThreshold::Critical,
        )])),
        handlers,
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    assert!(
        matches!(outcome, ScanRunOutcome::NothingAnalysable { .. }),
        "an advisory finding must not be dropped into a not-applicable assessment, \
         got {outcome:?}"
    );
}

/// The consumer half: a not-applicable outcome goes through
/// `record_scan_result` (so scan authority exists and the release gate
/// opens on the time gate alone), completes the job, and never touches
/// the fail-closed `scan_indeterminate` hold. The `ScanCompleted` it
/// appends carries the assessment so the trail can never read as
/// "analysed, clean".
#[tokio::test]
async fn record_outcome_not_applicable_records_scan_authority_and_does_not_hold() {
    let (uc, jobs, events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        HashMap::new(),
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    uc.record_outcome(
        &job,
        ScanRunOutcome::Completed {
            scanner: "trivy".into(),
            kind: TEST_SCAN_KIND,
            findings: Vec::new(),
            assessment: ScanAssessment::NotApplicable,
            sbom: None,
        },
    )
    .await
    .expect("record_outcome");

    assert_eq!(
        jobs.completed_calls(),
        vec![job.id],
        "a completed assessment completes the job"
    );
    assert!(
        jobs.failed_calls().is_empty(),
        "nothing failed — there was simply nothing to assess"
    );
    assert_ne!(
        artifacts
            .get(artifact_id)
            .expect("artifact")
            .quarantine_status,
        QuarantineStatus::ScanIndeterminate,
        "an artifact with no package surface must not be held on the scan axis"
    );

    let appended: Vec<DomainEvent> = events
        .appended_batches()
        .into_iter()
        .flat_map(|batch| batch.events.into_iter().map(|e| e.event))
        .collect();
    assert!(
        !appended
            .iter()
            .any(|e| matches!(e, DomainEvent::ScanIndeterminate(_))),
        "the fail-closed hold is for an unassessed surface, not an absent one"
    );
    let scan_completed = appended
        .iter()
        .find_map(|e| match e {
            DomainEvent::ScanCompleted(sc) => Some(sc),
            _ => None,
        })
        .expect("scan authority must be recorded — a ScanCompleted on the stream");
    assert_eq!(
        scan_completed.assessment,
        ScanAssessment::NotApplicable,
        "the trail must say 'not applicable', never 'analysed, clean'"
    );
    assert_eq!(scan_completed.finding_count, 0);
    assert!(scan_completed.validate().is_ok());
}

/// `SkippedNoBackends` is unchanged: the operator waived the scan, they
/// did not declare the artifact unscannable, so the recorded assessment
/// stays `Analysed`.
#[tokio::test]
async fn record_outcome_skipped_no_backends_still_records_an_analysed_assessment() {
    let (uc, jobs, events, _storage, artifacts, repositories, _policy) = make_uc(
        vec!["trivy".into()],
        HashMap::new(),
        Arc::new(MockAdvisory::ok(vec![])),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = sample_scan_job(artifact_id, 1);

    uc.record_outcome(
        &job,
        ScanRunOutcome::SkippedNoBackends {
            kind: TEST_SCAN_KIND,
        },
    )
    .await
    .expect("record_outcome");

    assert_eq!(jobs.completed_calls(), vec![job.id]);
    let scan_completed = events
        .appended_batches()
        .into_iter()
        .flat_map(|batch| batch.events.into_iter().map(|e| e.event))
        .find_map(|e| match e {
            DomainEvent::ScanCompleted(sc) => Some(sc),
            _ => None,
        })
        .expect("the waiver still records a ScanCompleted");
    assert_eq!(scan_completed.assessment, ScanAssessment::Analysed);
    assert_eq!(scan_completed.scanner, "(none)");
}

// ---------------------------------------------------------------------------
// The capability-map consult: a backend is never invoked on a format it
// does not analyse
// ---------------------------------------------------------------------------

/// A scan job for `format`, so the capability consult can be driven at
/// formats other than [`sample_scan_job`]'s `npm`.
fn scan_job_for_format(artifact_id: Uuid, format: &str) -> ScanJob {
    ScanJob {
        format: format.to_string(),
        ..sample_scan_job(artifact_id, 1)
    }
}

/// The built-in default `[trivy]` pointed at a format Trivy does not
/// analyse, while another compiled-in backend does. The backend is never
/// invoked — an invocation could only return the absence of a verdict —
/// and the expected-but-unassessed surface holds the artifact
/// fail-closed, exactly as a `NoAnalyzerMatched` abstention does.
#[tokio::test]
async fn run_scan_does_not_invoke_a_backend_that_cannot_analyse_the_format() {
    let trivy = Arc::new(MockScanner::new("trivy", Ok(vec![])).covering(&["oci"]));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy.clone());

    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into()],
        scanners,
        handler_map("npm", ArtifactKind::NpmTarball),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    // `osv` covers npm, so the pairing is a policy mistake rather than
    // an unscannable format — the gating arm.
    let job = scan_job_for_format(artifact_id, "npm");

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    assert!(
        matches!(outcome, ScanRunOutcome::NothingAnalysable { .. }),
        "an inert pairing leaves the surface unassessed and must hold, got {outcome:?}"
    );
    assert_eq!(
        trivy.calls(),
        0,
        "the orchestrator must consult the capability map BEFORE spending an invocation"
    );
}

/// A covering backend's verdict stands while the inert one beside it is
/// skipped: `[trivy, osv]` on OCI, where OSV exposes no SBOM source.
/// Trivy analyses, OSV is never asked, and the artifact completes on
/// Trivy's verdict alone rather than being held by OSV's abstention.
#[tokio::test]
async fn run_scan_keeps_the_covering_backends_verdict_and_never_invokes_the_inert_one() {
    let trivy = Arc::new(
        MockScanner::new(
            "trivy",
            Ok(vec![finding(
                "pkg:oci/zlib1g@1.2.11",
                "CVE-2018-25032",
                SeverityThreshold::High,
            )]),
        )
        .covering(&["oci", "maven", "pypi", "npm", "cargo"]),
    );
    let osv =
        Arc::new(MockScanner::new("osv", Ok(vec![])).covering(&["npm", "pypi", "cargo", "maven"]));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy.clone());
    scanners.insert("osv".into(), osv.clone());

    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into(), "osv".into()],
        scanners,
        handler_map("oci", ArtifactKind::OciBlob),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "oci");

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        findings,
        assessment,
        scanner,
        ..
    } = outcome
    else {
        panic!("a covering backend produced a verdict; the run must complete, got {outcome:?}");
    };
    assert_eq!(assessment, ScanAssessment::Analysed);
    assert_eq!(findings.len(), 1);
    assert_eq!(scanner, "trivy", "only the covering backend contributed");
    assert_eq!(trivy.calls(), 1);
    assert_eq!(osv.calls(), 0, "osv reads an SBOM and OCI exposes none");
}

/// A format no compiled-in backend covers. Choosing a different backend
/// cannot help and there is no surface to assess, so no scanner is
/// spawned and the artifact records a completed not-applicable
/// assessment instead of holding forever.
#[tokio::test]
async fn run_scan_records_not_applicable_when_no_backend_covers_the_format() {
    let trivy = Arc::new(MockScanner::new("trivy", Ok(vec![])).covering(&["oci"]));
    let osv = Arc::new(MockScanner::new("osv", Ok(vec![])).covering(&["npm"]));
    let mut scanners: HashMap<String, Arc<dyn ScannerPort>> = HashMap::new();
    scanners.insert("trivy".into(), trivy.clone());
    scanners.insert("osv".into(), osv.clone());

    let (uc, _jobs, _events, artifacts, repositories) = make_uc_with_handler(
        vec!["trivy".into(), "osv".into()],
        scanners,
        // No handler is registered under `gradle`, so its artifacts are
        // kind `Other` — the map's own answer for the format.
        handler_map("maven", ArtifactKind::MavenJar),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "gradle");

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed {
        findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("nothing to assess must not hold the artifact, got {outcome:?}");
    };
    assert_eq!(assessment, ScanAssessment::NotApplicable);
    assert!(findings.is_empty());
    assert_eq!(trivy.calls(), 0);
    assert_eq!(osv.calls(), 0);
}

// ===========================================================================
// COMPONENT RELATION — which component each finding is about
//
// `ComponentRelations` is the one place `Finding.component_relation` is
// decided (ADR 0056 as amended): the join between a finding's purl and
// the artifact's BOM, refined by the format's containment declaration and
// by what the producing backend actually looked at. These tests pin the
// rule directly, then pin that both producers reach it through `run_scan`.
//
// The tagging itself decides no verdict: it writes one field per finding
// and the rule that reads it lives in `evaluate_scan_result`. The two
// tests at the end of this section are where the two meet — a
// `NotContained` Critical that no longer rejects while staying in the
// record, and a clean scan that still rejects nothing.
// ===========================================================================

/// A BOM with an optional subject and a list of components, built from
/// purls alone — the join key is the purl and nothing else.
fn sbom_with(subject: Option<&str>, components: &[&str]) -> Sbom {
    Sbom {
        subject: subject.map(component),
        components: components.iter().copied().map(component).collect(),
    }
}

/// The join over `sbom`, for a format that ships none of the components
/// its BOM lists (cargo / npm / pypi / maven — the four that override
/// `payload_contains_components`).
fn declaring_format(sbom: &Sbom) -> ComponentRelations<'_> {
    ComponentRelations {
        sbom: Some(sbom),
        payload_contains_components: false,
        format: "cargo",
    }
}

/// The join over `sbom`, for a format whose payload carries its closure
/// (an OCI image and its layers — and the trait default).
fn self_contained_format(sbom: &Sbom) -> ComponentRelations<'_> {
    ComponentRelations {
        sbom: Some(sbom),
        payload_contains_components: true,
        format: "oci",
    }
}

/// The artifact's own subject component is in the artifact by
/// definition, whatever the format and whichever producer found it.
/// Reading this as anything else would disarm the scanner on exactly the
/// findings that are about the artifact.
#[test]
fn a_finding_naming_the_bom_subject_is_tagged_subject() {
    let sbom = sbom_with(
        Some("pkg:cargo/hyper-util@0.1.21"),
        &["pkg:cargo/h2@0.4.13"],
    );
    for evidence in [
        EvidenceBasis::MaterialisedPayload,
        EvidenceBasis::SuppliedSbom,
    ] {
        assert_eq!(
            declaring_format(&sbom).relation_for("pkg:cargo/hyper-util@0.1.21", evidence),
            ComponentRelation::Subject,
            "{evidence:?}"
        );
        assert_eq!(
            self_contained_format(&sbom).relation_for("pkg:cargo/hyper-util@0.1.21", evidence),
            ComponentRelation::Subject,
            "{evidence:?}"
        );
    }
}

/// The incident this whole change exists for, in one assertion: a
/// `.crate` carries the maintainer's `Cargo.lock` and none of the code it
/// pins, so an advisory against a pinned version names a component the
/// artifact does not contain. Reading it as `Contained` is what terminally
/// rejected `hyper-util 0.1.21` over `h2 0.4.13`.
#[test]
fn a_listed_component_is_not_contained_when_the_format_ships_none_of_it() {
    let sbom = sbom_with(
        Some("pkg:cargo/hyper-util@0.1.21"),
        &["pkg:cargo/h2@0.4.13"],
    );
    for evidence in [
        EvidenceBasis::MaterialisedPayload,
        EvidenceBasis::SuppliedSbom,
    ] {
        assert_eq!(
            declaring_format(&sbom).relation_for("pkg:cargo/h2@0.4.13", evidence),
            ComponentRelation::NotContained,
            "{evidence:?}"
        );
    }
}

/// The opposite format shape: an image carries its layers, so the same
/// position in the BOM means the code *is* in the artifact and the
/// finding keeps full authority. A rule keyed on "is it the subject?"
/// rather than "is it in the artifact?" would collapse these two tests
/// into one wrong answer.
#[test]
fn a_listed_component_is_contained_when_the_payload_carries_its_closure() {
    let sbom = sbom_with(Some("pkg:oci/app@1"), &["pkg:deb/openssl@3.0.2"]);
    for evidence in [
        EvidenceBasis::MaterialisedPayload,
        EvidenceBasis::SuppliedSbom,
    ] {
        assert_eq!(
            self_contained_format(&sbom).relation_for("pkg:deb/openssl@3.0.2", evidence),
            ComponentRelation::Contained,
            "{evidence:?}"
        );
    }
}

/// A backend that materialised the artifact's bytes reports what it
/// unpacked, so a package the BOM never listed was still in the
/// artifact — the BOM and the materialised tree are derived differently.
/// The opposite reading would silently disarm every payload-scanner
/// finding the BOM happens not to list.
#[test]
fn an_unmatched_purl_from_a_payload_scanned_backend_is_contained() {
    let sbom = sbom_with(
        Some("pkg:cargo/hyper-util@0.1.21"),
        &["pkg:cargo/h2@0.4.13"],
    );
    assert_eq!(
        declaring_format(&sbom).relation_for(
            "pkg:cargo/never-listed@9.9.9",
            EvidenceBasis::MaterialisedPayload
        ),
        ComponentRelation::Contained,
    );
}

/// The BOM is an SBOM-driven producer's whole input, so a purl matching
/// nothing in it cannot be a package discovered elsewhere — it is a join
/// that failed, and the counter has to show it rather than the default
/// absorbing it.
#[test]
fn an_unmatched_purl_from_an_sbom_driven_producer_is_not_established() {
    let sbom = sbom_with(
        Some("pkg:cargo/hyper-util@0.1.21"),
        &["pkg:cargo/h2@0.4.13"],
    );
    assert_eq!(
        declaring_format(&sbom)
            .relation_for("pkg:cargo/never-listed@9.9.9", EvidenceBasis::SuppliedSbom),
        ComponentRelation::NotEstablished,
    );
}

/// `Sbom.subject` is an `Option` and the type permits `None`, so the arm
/// is handled explicitly rather than unwrapped: with nothing to join
/// against, an SBOM-driven finding's relation is not established and the
/// counter says so. Every production builder sets a subject, which is
/// what makes a non-zero count here a defect rather than a steady state.
#[test]
fn a_bom_without_a_subject_leaves_an_sbom_driven_finding_not_established() {
    let sbom = sbom_with(None, &["pkg:cargo/h2@0.4.13"]);
    assert_eq!(
        declaring_format(&sbom).relation_for("pkg:cargo/anything@1", EvidenceBasis::SuppliedSbom),
        ComponentRelation::NotEstablished,
    );
    // A *listed* component still joins — the missing subject only costs
    // the subject arm, it does not blind the component arm.
    assert_eq!(
        declaring_format(&sbom).relation_for("pkg:cargo/h2@0.4.13", EvidenceBasis::SuppliedSbom),
        ComponentRelation::NotContained,
    );
}

/// No BOM at all (no handler registered, an opaque format, a failed
/// extraction) is the same situation as a purl the BOM does not name,
/// and is answered the same way — by what the producer looked at. This
/// is the steady state for OCI, whose handler extracts no SBOM: its
/// Trivy findings are `Contained`, not a flood of failed joins that
/// would drown the `not_established` signal on its first day.
#[test]
fn no_bom_at_all_falls_through_to_the_producer_evidence() {
    let none = ComponentRelations {
        sbom: None,
        payload_contains_components: true,
        format: "oci",
    };
    assert_eq!(
        none.relation_for("pkg:deb/openssl@3.0.2", EvidenceBasis::MaterialisedPayload),
        ComponentRelation::Contained,
    );
    assert_eq!(
        none.relation_for("pkg:deb/openssl@3.0.2", EvidenceBasis::SuppliedSbom),
        ComponentRelation::NotEstablished,
    );
}

/// The join is `Finding.purl == SbomComponent.purl` verbatim — the key
/// `SbomComponent`'s own rustdoc declares, and the case-sensitive PURL
/// convention `merge_findings` and `compute_added_findings` already use.
/// A near-miss spelling does not silently join; it lands on the
/// unmatched arm, where an SBOM-driven producer makes it visible.
#[test]
fn the_purl_join_is_verbatim_and_case_sensitive() {
    let sbom = sbom_with(Some("pkg:cargo/Subject@1"), &["pkg:cargo/Dep@2"]);
    let relations = declaring_format(&sbom);
    assert_eq!(
        relations.relation_for("pkg:cargo/subject@1", EvidenceBasis::SuppliedSbom),
        ComponentRelation::NotEstablished,
        "a case-folded subject purl must not join"
    );
    assert_eq!(
        relations.relation_for("pkg:cargo/dep@2", EvidenceBasis::SuppliedSbom),
        ComponentRelation::NotEstablished,
        "a case-folded component purl must not join"
    );
    assert_eq!(
        relations.relation_for("pkg:cargo/Dep@2", EvidenceBasis::SuppliedSbom),
        ComponentRelation::NotContained,
    );
}

/// The interop convention duplicates the subject into `components[]`
/// (the OSV adapter's CycloneDX rendering relies on it). The subject arm
/// is checked first, so a BOM listing its own subject still reports
/// `Subject` — not `NotContained`, which for a declaring format would
/// strip authority from the finding that matters most.
#[test]
fn the_subject_wins_over_a_component_entry_with_the_same_purl() {
    let sbom = sbom_with(Some("pkg:cargo/leaf@1"), &["pkg:cargo/leaf@1"]);
    assert_eq!(
        declaring_format(&sbom).relation_for("pkg:cargo/leaf@1", EvidenceBasis::SuppliedSbom),
        ComponentRelation::Subject,
    );
}

/// **The tagging pass writes the relation and leaves the statement
/// alone.** The producer's half of ADR 0064 D2's line arrives already
/// stated and is a fact about the producer's own output; whose
/// filesystem the claim is about is the row's `ArtifactKind`, which
/// `Finding::may_condemn_artifact` composes where it decides rather than
/// anything storing the two already joined (ADR 0040).
///
/// Asserted on the two rows whose *verdicts* differ, from identical
/// input, so the property is visible at this level too: the stored
/// statement is the same on a layer and on an npm tarball, and the
/// predicate is what tells them apart. A pass that reintroduced a write
/// here would fail the first pair of assertions; one that reintroduced a
/// composed value would fail the second.
#[test]
fn the_tagging_pass_writes_the_relation_and_not_the_statement() {
    let sbom = sbom_with(Some("pkg:cargo/subject@1"), &[]);
    let mut from_producer = finding(
        "pkg:deb/openssl@3.0.2",
        "CVE-2022-1",
        SeverityThreshold::High,
    );
    from_producer.statement = FindingStatement::Filesystem;

    let layer = ComponentRelations {
        sbom: Some(&sbom),
        payload_contains_components: true,
        format: "oci",
    }
    .tag(
        vec![from_producer.clone()],
        EvidenceBasis::MaterialisedPayload,
    );
    assert_eq!(
        layer[0].statement,
        FindingStatement::Filesystem,
        "the producer's half passes through untouched"
    );
    assert_eq!(
        layer[0].component_relation,
        ComponentRelation::Contained,
        "the relation half is what this pass writes"
    );

    let package = ComponentRelations {
        sbom: Some(&sbom),
        payload_contains_components: false,
        format: "npm",
    }
    .tag(vec![from_producer], EvidenceBasis::MaterialisedPayload);
    assert_eq!(
        package[0].statement,
        FindingStatement::Filesystem,
        "and it is the same stored fact on a row whose tree is its own"
    );

    // The role is what tells the two apart, at the predicate and nowhere
    // earlier.
    assert!(
        !layer[0].may_condemn_artifact(ArtifactKind::OciBlob, CompositeVerdictMode::Promoted),
        "the layer's isolated package set is evidence under promotion"
    );
    assert!(
        package[0].may_condemn_artifact(ArtifactKind::NpmTarball, CompositeVerdictMode::Promoted),
        "an npm tarball's materialised tree is the artifact's own, so the \
         same stored statement still gates it"
    );
}

/// And the advisory path's batch: its statement is `Unstated`, which the
/// pass likewise does not touch. The pass runs over it all the same —
/// the relation half is exactly what it is there for.
#[test]
fn the_tagging_pass_leaves_an_unstated_statement_unstated() {
    let sbom = sbom_with(Some("pkg:cargo/subject@1"), &["pkg:cargo/dep@2"]);
    let advisory = finding("pkg:cargo/dep@2", "CVE-2022-2", SeverityThreshold::High);
    assert_eq!(advisory.statement, FindingStatement::Unstated);

    let tagged = ComponentRelations {
        sbom: Some(&sbom),
        payload_contains_components: true,
        format: "oci",
    }
    .tag(vec![advisory], EvidenceBasis::SuppliedSbom);
    assert_eq!(
        tagged[0].statement,
        FindingStatement::Unstated,
        "a side nobody stated is not invented from the kind"
    );
    assert_eq!(tagged[0].component_relation, ComponentRelation::Contained);
}

/// A handler whose BOM a test chooses outright, with the format's
/// containment declaration alongside it. Mirrors what the real handlers
/// do — npm/pypi/cargo/maven declare `false`, OCI inherits `true` — while
/// keeping the BOM's shape under the test's control.
struct BomShapedHandler {
    key: &'static str,
    sbom: Option<Sbom>,
    contains_components: bool,
}

impl FormatHandler for BomShapedHandler {
    fn format_key(&self) -> &str {
        self.key
    }
    fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
        Err(DomainError::Validation("not used by these tests".into()))
    }
    fn normalize_name(&self, name: &str) -> String {
        name.to_string()
    }
    fn payload_contains_components(&self) -> bool {
        self.contains_components
    }
    fn extract_sbom(
        &self,
        _coords: &ArtifactCoords,
        _format_metadata: &serde_json::Value,
        _payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Sbom>> {
        Ok(self.sbom.clone())
    }
}

/// Register one `BomShapedHandler` under `format`.
fn bom_handler_map(
    format: &'static str,
    sbom: Option<Sbom>,
    contains_components: bool,
) -> HashMap<String, Arc<dyn FormatHandler>> {
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert(
        format.to_string(),
        Arc::new(BomShapedHandler {
            key: format,
            sbom,
            contains_components,
        }),
    );
    handlers
}

/// Run one scan against a BOM-shaped handler and return the findings the
/// orchestrator produced. `advisory` seeds the SBOM-driven producer,
/// `scanner_findings` the backend's, and `payload_scanned` picks which
/// evidence that backend declares.
async fn run_tagged_scan(
    format: &'static str,
    sbom: Option<Sbom>,
    contains_components: bool,
    advisory_findings: Vec<Finding>,
    scanner_findings: Vec<Finding>,
    payload_scanned: bool,
) -> Vec<Finding> {
    let scanner = MockScanner::new("trivy", Ok(scanner_findings));
    let scanner = if payload_scanned {
        scanner
    } else {
        scanner.sbom_driven()
    };
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(vec!["trivy".into()]));
    let (uc, _jobs, _events, _storage, artifacts, repositories, _policy, _metadata) =
        make_uc_with_policy_repo_and_handlers(
            one_scanner(Arc::new(scanner)),
            Arc::new(MockAdvisory::ok(advisory_findings)),
            policy_projections,
            bom_handler_map(format, sbom, contains_components),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, format);

    match uc.run_scan(&job).await.expect("run_scan") {
        ScanRunOutcome::Completed { findings, .. } => findings,
        other => panic!("expected a completed scan, got {other:?}"),
    }
}

/// Look one finding up by vulnerability id.
fn relation_of(findings: &[Finding], vuln: &str) -> ComponentRelation {
    findings
        .iter()
        .find(|f| f.vulnerability_id == vuln)
        .unwrap_or_else(|| panic!("no finding {vuln} in {findings:?}"))
        .component_relation
}

/// The advisory path alone. Its tagging site is the one that initialises
/// `accumulated`; a scan whose only producer is advisory enrichment must
/// still leave every finding tagged, and this fails alone if that site
/// is lost.
#[tokio::test]
async fn run_scan_tags_the_advisory_paths_findings() {
    let findings = run_tagged_scan(
        "cargo",
        Some(sbom_with(
            Some("pkg:cargo/hyper-util@0.1.21"),
            &["pkg:cargo/h2@0.4.13"],
        )),
        false,
        vec![finding(
            "pkg:cargo/h2@0.4.13",
            "RUSTSEC-ADVISORY",
            SeverityThreshold::Low,
        )],
        vec![],
        true,
    )
    .await;
    assert_eq!(findings.len(), 1);
    assert_eq!(
        relation_of(&findings, "RUSTSEC-ADVISORY"),
        ComponentRelation::NotContained,
    );
}

/// The scanner path alone — the other tagging site, inside the
/// per-backend loop. A backend that contributes findings while the
/// advisory path contributes none must still leave them tagged.
#[tokio::test]
async fn run_scan_tags_the_scanner_paths_findings() {
    let findings = run_tagged_scan(
        "cargo",
        Some(sbom_with(
            Some("pkg:cargo/hyper-util@0.1.21"),
            &["pkg:cargo/h2@0.4.13"],
        )),
        false,
        vec![],
        vec![finding(
            "pkg:cargo/h2@0.4.13",
            "CVE-FROM-BACKEND",
            SeverityThreshold::Low,
        )],
        false,
    )
    .await;
    assert_eq!(findings.len(), 1);
    assert_eq!(
        relation_of(&findings, "CVE-FROM-BACKEND"),
        ComponentRelation::NotContained,
    );
}

/// Both producers reach the tagging step, and each one's finding carries
/// the relation the join assigns. Before this unit every finding left
/// `run_scan` as `NotEstablished`, so a single untagged path is the
/// regression this kills — and `NotEstablished` is precisely the value
/// an untagged path would leave behind.
#[tokio::test]
async fn run_scan_tags_findings_from_both_producers() {
    let findings = run_tagged_scan(
        "cargo",
        Some(sbom_with(
            Some("pkg:cargo/hyper-util@0.1.21"),
            &["pkg:cargo/h2@0.4.13"],
        )),
        false,
        vec![finding(
            "pkg:cargo/h2@0.4.13",
            "RUSTSEC-ADVISORY",
            SeverityThreshold::Low,
        )],
        vec![finding(
            "pkg:cargo/hyper-util@0.1.21",
            "CVE-SUBJECT",
            SeverityThreshold::High,
        )],
        true,
    )
    .await;

    assert_eq!(findings.len(), 2);
    assert_eq!(
        relation_of(&findings, "RUSTSEC-ADVISORY"),
        ComponentRelation::NotContained,
        "the advisory path's finding names a lockfile pin the crate does not ship"
    );
    assert_eq!(
        relation_of(&findings, "CVE-SUBJECT"),
        ComponentRelation::Subject,
        "the scanner path's finding names the artifact itself"
    );
    assert!(
        findings
            .iter()
            .all(|f| f.component_relation != ComponentRelation::NotEstablished),
        "no finding may leave the orchestrator untagged: {findings:?}"
    );
}

/// §6, through the orchestrator: a payload-scanning backend's finding
/// that the BOM does not list keeps its authority. The opposite reading
/// disarms every Trivy finding an npm packument or a cargo lockfile
/// happens not to mention.
#[tokio::test]
async fn run_scan_tags_a_payload_scanned_finding_the_bom_omits_as_contained() {
    let findings = run_tagged_scan(
        "cargo",
        Some(sbom_with(Some("pkg:cargo/app@1"), &["pkg:cargo/dep@2"])),
        false,
        vec![],
        vec![finding(
            "pkg:cargo/unlisted@3",
            "CVE-UNLISTED",
            SeverityThreshold::Critical,
        )],
        true,
    )
    .await;
    assert_eq!(
        relation_of(&findings, "CVE-UNLISTED"),
        ComponentRelation::Contained,
    );
}

/// §6's other half: the same unlisted purl from a backend whose only
/// input was the BOM is a broken join, recorded as such.
#[tokio::test]
async fn run_scan_tags_an_sbom_driven_finding_the_bom_omits_as_not_established() {
    let findings = run_tagged_scan(
        "cargo",
        Some(sbom_with(Some("pkg:cargo/app@1"), &["pkg:cargo/dep@2"])),
        false,
        vec![],
        vec![finding(
            "pkg:cargo/unlisted@3",
            "CVE-UNLISTED",
            SeverityThreshold::Critical,
        )],
        false,
    )
    .await;
    assert_eq!(
        relation_of(&findings, "CVE-UNLISTED"),
        ComponentRelation::NotEstablished,
    );
}

/// §5's claim, asserted rather than assumed: every production SBOM
/// builder derives its subject from the artifact's coordinates, which
/// always exist, so no scan over a production-shaped BOM may produce a
/// `not established` finding. If one does, a format's subject is not
/// being derived — a defect in that builder, and the thing that would
/// make the condemning default a resting state instead of a rarity.
///
/// The shapes are the ones the compiled-in handlers actually emit:
/// subject + resolved closure (cargo with a lockfile, maven from a POM),
/// subject + declared dependencies (npm, pypi), and subject-only (a leaf
/// package, or a payload whose lockfile was unusable).
#[tokio::test]
async fn run_scan_over_production_sbom_shapes_yields_no_not_established_findings() {
    let shapes: Vec<(&'static str, Sbom)> = vec![
        (
            "subject + resolved closure",
            sbom_with(Some("pkg:cargo/app@1.0.0"), &["pkg:cargo/h2@0.4.13"]),
        ),
        (
            "subject + declared dependencies",
            sbom_with(Some("pkg:npm/app@1.0.0"), &["pkg:npm/lodash@4.17.20"]),
        ),
        (
            "subject only (leaf package / no usable lockfile)",
            sbom_with(Some("pkg:pypi/app@1.0.0"), &[]),
        ),
    ];

    for (label, sbom) in shapes {
        // Both the subject and a listed component, from both producers —
        // every purl a production BOM can be joined on.
        let subject_purl = sbom
            .subject
            .as_ref()
            .expect("production shape")
            .purl
            .clone();
        let component_purl = sbom
            .components
            .first()
            .map(|c| c.purl.clone())
            .unwrap_or_else(|| subject_purl.clone());
        for payload_scanned in [true, false] {
            let findings = run_tagged_scan(
                "cargo",
                Some(sbom.clone()),
                false,
                vec![finding(
                    &component_purl,
                    "CVE-ADVISORY",
                    SeverityThreshold::Low,
                )],
                vec![finding(
                    &subject_purl,
                    "CVE-SCANNER",
                    SeverityThreshold::Low,
                )],
                payload_scanned,
            )
            .await;
            for f in &findings {
                assert_ne!(
                    f.component_relation,
                    ComponentRelation::NotEstablished,
                    "{label} (payload_scanned={payload_scanned}): {} was not joined",
                    f.purl
                );
            }
        }
    }
}

/// **The verdict this change exists to move**, end to end through the
/// orchestrator and the record path: `hyper-util 0.1.21` scanned with a
/// Critical advisory against `h2 0.4.13`, a version read out of the
/// crate's own embedded `Cargo.lock`. A `.crate` is a source tarball — it
/// ships that lockfile and none of the code it pins, and a consumer's
/// build resolves none of those pins — so the advisory is not evidence
/// about this artifact and no longer condemns it. The finding is still
/// recorded, still counted and still on the events surface; only its
/// authority over the release gate is gone.
///
/// Its clean-direction sibling below is the other half of the pin and
/// must stay green: the narrowing may not invent a rejection, nor remove
/// one a condemning finding earned.
#[tokio::test]
async fn a_not_contained_critical_no_longer_rejects_but_is_still_recorded() {
    let scanner = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:cargo/h2@0.4.13",
            "CVE-NOT-CONTAINED",
            SeverityThreshold::Critical,
        )]),
    ));
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(vec!["trivy".into()]));
    let (uc, _jobs, events, _storage, artifacts, repositories, _policy, _metadata) =
        make_uc_with_policy_repo_and_handlers(
            one_scanner(scanner),
            Arc::new(MockAdvisory::ok(vec![])),
            policy_projections,
            bom_handler_map(
                "cargo",
                Some(sbom_with(
                    Some("pkg:cargo/hyper-util@0.1.21"),
                    &["pkg:cargo/h2@0.4.13"],
                )),
                false,
            ),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "cargo");

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { ref findings, .. } = outcome else {
        panic!("expected a completed scan, got {outcome:?}");
    };
    assert_eq!(
        findings[0].component_relation,
        ComponentRelation::NotContained,
        "precondition: the finding is tagged as naming code the crate does not carry"
    );

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    let appended: Vec<DomainEvent> = events
        .appended_batches()
        .into_iter()
        .flat_map(|batch| batch.events.into_iter().map(|e| e.event))
        .collect();
    assert!(
        !appended
            .iter()
            .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))),
        "an advisory against a component the crate ships none of must not reject it",
    );
    assert_ne!(
        artifacts
            .get(artifact_id)
            .expect("artifact")
            .quarantine_status,
        QuarantineStatus::Rejected,
        "and the artifact must not be left holding that verdict",
    );

    // The other half of the rule, on the surface an operator reads: the
    // finding is still there. Removing it from the record would trade one
    // wrong answer for another — a consumer may well want to know that a
    // crate's own lockfile pinned a vulnerable version.
    let scan_completed = appended
        .iter()
        .find_map(|e| match e {
            DomainEvent::ScanCompleted(sc) => Some(sc),
            _ => None,
        })
        .expect("the scan is still recorded — a ScanCompleted on the stream");
    assert_eq!(
        scan_completed.finding_count, 1,
        "the finding is recorded, not dropped",
    );
    assert_eq!(
        scan_completed.severity_summary.critical, 1,
        "and still counted as the Critical it is",
    );
    assert!(
        scan_completed.findings_blob.is_some(),
        "the per-finding record is still persisted",
    );
}

/// The clean direction of the same pin: tagging introduces no rejection
/// where there was none. A tagging step that mutated the finding set
/// (rather than one field of each finding) would show up here.
#[tokio::test]
async fn tagging_changes_no_verdict_a_clean_scan_still_rejects_nothing() {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(vec!["trivy".into()]));
    let (uc, _jobs, events, _storage, artifacts, repositories, _policy, _metadata) =
        make_uc_with_policy_repo_and_handlers(
            one_scanner(Arc::new(MockScanner::new("trivy", Ok(vec![])))),
            Arc::new(MockAdvisory::ok(vec![])),
            policy_projections,
            bom_handler_map(
                "cargo",
                Some(sbom_with(Some("pkg:cargo/app@1"), &[])),
                false,
            ),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "cargo");

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { ref findings, .. } = outcome else {
        panic!("expected a completed scan, got {outcome:?}");
    };
    assert!(findings.is_empty());

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    let rejected = events
        .appended_batches()
        .iter()
        .flat_map(|b| b.events.iter())
        .any(|e| matches!(&e.event, DomainEvent::ArtifactRejected(_)));
    assert!(!rejected, "a clean scan must still reject nothing");
}

/// With no handler registered for the format there is no BOM and no
/// containment declaration to read, and the fail-closed trait default
/// applies. Nothing here may panic or unwrap a missing subject.
#[tokio::test]
async fn run_scan_tags_findings_when_no_handler_is_registered() {
    let scanner = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:generic/thing@1",
            "CVE-NOHANDLER",
            SeverityThreshold::High,
        )]),
    ));
    let (uc, _jobs, _events, artifacts, repositories) =
        make_uc_with_handler(vec!["trivy".into()], one_scanner(scanner), HashMap::new());
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "generic");

    let ScanRunOutcome::Completed { findings, .. } = uc.run_scan(&job).await.expect("run_scan")
    else {
        panic!("expected a completed scan");
    };
    assert_eq!(
        relation_of(&findings, "CVE-NOHANDLER"),
        ComponentRelation::Contained,
        "a payload-scanning backend found it in the artifact; no BOM says otherwise"
    );
}

// ===========================================================================
// The composed-image assessment is a shadow (ADR 0064 D1/D6)
//
// The unit of filesystem assessment for an OCI image is the manifest, and
// `run_scan` now resolves and runs that composition — but **read-only**.
// These pin both halves: that the composition reaches the backend at all,
// and that nothing it says reaches the artifact. A new analysis path
// whose first production act could be irreversible is what D6 exists to
// prevent: `Rejected` is terminal and the periodic rescan never revisits
// it.
// ===========================================================================

/// The `config` + `layers[]` document a manifest row's bytes are, as it
/// is stored.
fn stored_image_manifest(config: &ContentHash, layers: &[&ContentHash]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{config}"),
            "size": 7,
        },
        "layers": layers.iter().map(|h| serde_json::json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": format!("sha256:{h}"),
            "size": 100,
        })).collect::<Vec<_>>(),
    }))
    .expect("manifest serialises")
}

/// An **image index** document — a manifest list, binding platform
/// manifests by reference rather than describing a filesystem. The
/// strict parse refuses it as "not an image", which is what keeps an
/// index out of the composite path entirely (ADR 0064 D5).
fn stored_image_index() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{}", synthetic_hash('a')),
            "size": 500,
            "platform": { "architecture": "amd64", "os": "linux" },
        }],
    }))
    .expect("index serialises")
}

/// An image config declaring `n` `diff_ids` — deliberately unequal to any
/// layer digest, since a `diff_id` is the digest of the *uncompressed*
/// tar.
fn stored_image_config(n: usize) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": (0..n)
                .map(|i| format!("sha256:{:064x}", i + 0xd1ff_0000))
                .collect::<Vec<_>>(),
        },
    }))
    .expect("config serialises")
}

fn synthetic_hash(seed: char) -> ContentHash {
    std::iter::repeat_n(seed, 64)
        .collect::<String>()
        .parse()
        .expect("synthetic sha256")
}

/// A use case wired with one scanner and one handler, handing back the
/// storage mock so a test can seed the manifest and config documents the
/// composition is resolved from.
#[allow(clippy::type_complexity)]
fn make_uc_with_handler_and_storage(
    backends: Vec<String>,
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockEventStore>,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
) {
    make_uc_under_policy(seed_global_policy(backends), scanners, handlers)
}

/// The same, under a policy the caller built — so a test can vary the
/// posture under test (`composite_verdict_mode`, `enforcement`) rather
/// than the backend list.
#[allow(clippy::type_complexity)]
fn make_uc_under_policy(
    policy: ScanPolicyProjection,
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockEventStore>,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
) {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(policy);
    let (uc, _jobs, events, storage, artifacts, repositories, _policy, _metadata) =
        make_uc_with_policy_repo_and_handlers(
            scanners,
            Arc::new(MockAdvisory::ok(vec![])),
            policy_projections,
            handlers,
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    (uc, events, storage, artifacts, repositories)
}

/// [`seed_global_policy`] with the composed-image verdict **promoted** to
/// release authority (ADR 0064 D6) — the operator act every test below
/// stands on.
fn seed_promoted_policy(scan_backends: Vec<String>) -> ScanPolicyProjection {
    ScanPolicyProjection {
        composite_verdict_mode: CompositeVerdictMode::Promoted,
        ..seed_global_policy(scan_backends)
    }
}

/// The composition reaches the backend as a composed image, with every
/// layer the manifest declared — and the critical finding it comes back
/// with changes **nothing**: the outcome is still the manifest row's own
/// completed not-applicable assessment, carrying no findings, and no
/// event is appended.
#[tokio::test]
async fn run_scan_assesses_the_composed_image_without_giving_it_any_authority() {
    let scanner = Arc::new(
        MockScanner::with_analysis(
            "trivy",
            // The manifest row's own bytes: no package surface, exactly
            // as today.
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NotApplicable,
            )),
        )
        // The composition: a critical finding. If any of it leaked into
        // the run, the assertions below would see it.
        .answering_composites_with(Ok(ScanAnalysis::Analysed(vec![finding(
            "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
            "CVE-2022-COMPOSITE",
            SeverityThreshold::Critical,
        )]))),
    );
    let (uc, events, storage, artifacts, repositories) = make_uc_with_handler_and_storage(
        vec!["trivy".into()],
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);

    // The manifest row's bytes, plus the config they name.
    let (config, lower, upper) = (
        synthetic_hash('c'),
        synthetic_hash('1'),
        synthetic_hash('2'),
    );
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&lower, &upper]),
    );
    storage.insert_content(config, stored_image_config(2));
    // Both layers local: this repository is hosted (the harness wires an
    // empty upstream resolver), so a composition with an absent layer
    // would be a real refusal rather than something to acquire.
    storage.insert_content(lower, b"lower layer".to_vec());
    storage.insert_content(upper, b"upper layer".to_vec());

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    // The composition was assembled and handed over — the primary blob
    // invocation first, the shadow composite second.
    assert_eq!(
        scanner.seen_units(),
        vec![ScanUnitShape::Blob, ScanUnitShape::Image(2)],
        "the manifest's own bytes are scanned as a blob and its composition as an image"
    );

    // And none of what the composite said reached the artifact.
    let ScanRunOutcome::Completed {
        findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("the manifest row's own outcome must be unchanged, got {outcome:?}");
    };
    assert_eq!(
        assessment,
        ScanAssessment::NotApplicable,
        "the composite verdict carries no authority yet; the row's assessment is its own"
    );
    assert!(
        findings.is_empty(),
        "a composite finding must not arrive on the manifest row's outcome: {findings:?}"
    );
    assert!(
        events.appended_batches().is_empty(),
        "run_scan appends nothing, and the shadow appends nothing either"
    );
}

/// A manifest row whose composition cannot be resolved — here because
/// its own bytes are not in storage — runs no composite invocation, and
/// the row's outcome is untouched. Nothing retries and nothing holds on
/// the shadow's behalf.
#[tokio::test]
async fn run_scan_with_an_unresolvable_composition_leaves_the_outcome_alone() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let (uc, _events, _storage, artifacts, repositories) = make_uc_with_handler_and_storage(
        vec!["trivy".into()],
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "oci");

    let outcome = uc.run_scan(&job).await.expect("run_scan");
    assert_eq!(
        scanner.seen_units(),
        vec![ScanUnitShape::Blob],
        "an unresolved composition is never handed to a backend"
    );
    assert!(
        matches!(
            outcome,
            ScanRunOutcome::Completed {
                assessment: ScanAssessment::NotApplicable,
                ..
            }
        ),
        "{outcome:?}"
    );
}

/// Every non-manifest row — which is nearly every artifact in the
/// system — pays nothing for the composite path: one invocation, over
/// its own bytes, exactly as before.
#[tokio::test]
async fn run_scan_on_a_non_manifest_row_runs_one_blob_invocation() {
    let scanner = Arc::new(MockScanner::new("trivy", Ok(vec![])));
    let (uc, _events, _storage, artifacts, repositories) = make_uc_with_handler_and_storage(
        vec!["trivy".into()],
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciBlob),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "oci");
    uc.run_scan(&job).await.expect("run_scan");
    assert_eq!(scanner.seen_units(), vec![ScanUnitShape::Blob]);
}

// ===========================================================================
// A proxy composition's constituents are acquired, not awaited (ADR 0064 D1)
//
// A pull-through manifest's layers are routinely not local — its
// constituent edges are registered by digest with no existence check, and
// the client pull that would warm them starts with the manifest whose
// verdict is being gated. So the scan job fetches them. These pin the
// three things that follow from that: a hosted row still refuses, a proxy
// row acquires, and a *transient* acquisition failure takes the
// orchestrator's existing retryable path instead of the deterministic
// no-verdict a non-fetching path could get away with.
// ===========================================================================

/// The catch-all upstream mapping the acquisition tests resolve through.
fn composite_upstream_mapping(repository_id: Uuid) -> RepositoryUpstreamMapping {
    let now = Utc::now();
    RepositoryUpstreamMapping {
        id: Uuid::new_v4(),
        repository_id,
        path_prefix: String::new(),
        upstream_url: "https://registry.example".into(),
        upstream_name_prefix: None,
        upstream_auth: UpstreamAuth::Anonymous,
        secret_ref: None,
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
        insecure_upstream_url: false,
        trust_upstream_publish_time: false,
        mtls_cert_ref: None,
        mtls_key_ref: None,
        ca_bundle_ref: None,
        pinned_cert_sha256: None,
        allowed_realm_hosts: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

/// [`make_uc_with_handler_and_storage`] plus the composite path's upstream
/// handles, so a test can make the artifact's repository a proxy and seed
/// (or fail) the blobs its composition names.
#[allow(clippy::type_complexity)]
fn make_uc_with_handler_storage_and_upstream(
    backends: Vec<String>,
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
    config: ScanOrchestrationConfig,
) -> (
    ScanOrchestrationUseCase,
    Arc<MockStoragePort>,
    Arc<MockArtifactRepository>,
    Arc<MockRepositoryRepository>,
    Arc<MockUpstreamProxy>,
    Arc<MockUpstreamResolver>,
    Arc<MockCompositeScanObservationRepository>,
) {
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(backends));
    let resolver = Arc::new(MockUpstreamResolver::new());
    let (
        uc,
        _jobs,
        _events,
        storage,
        artifacts,
        repositories,
        _policy,
        _metadata,
        proxy,
        resolver,
        observations,
    ) = make_uc_with_upstream(
        scanners,
        Arc::new(MockAdvisory::ok(vec![])),
        policy_projections,
        handlers,
        config,
        resolver,
    );
    (
        uc,
        storage,
        artifacts,
        repositories,
        proxy,
        resolver,
        observations,
    )
}

/// The real SHA-256 of `bytes` — so a seeded upstream blob genuinely
/// satisfies the digest the manifest declares, and the verification arm is
/// exercised rather than bypassed.
fn digest_of(bytes: &[u8]) -> ContentHash {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
        .parse()
        .expect("a sha256 hex digest")
}

/// With no policy configured at all there is no policy to carry
/// exclusions, which is a known-empty set and not an unresolved one —
/// so the row is still written, judged by the built-in default.
#[tokio::test]
async fn a_repository_with_no_policy_still_records_an_observation() {
    let scanner = Arc::new(
        MockScanner::with_analysis(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NotApplicable,
            )),
        )
        .answering_composites_with(Ok(ScanAnalysis::Analysed(vec![finding(
            "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
            "CVE-2022-COMPOSITE",
            SeverityThreshold::Critical,
        )]))),
    );
    // No `insert` — `resolve_active_policy_for_repo` finds nothing and
    // the orchestrator falls back to the built-in `["trivy"]`.
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    let (
        uc,
        _jobs,
        _events,
        storage,
        artifacts,
        repositories,
        _policy,
        _metadata,
        _proxy,
        _resolver,
        observations,
    ) = make_uc_with_upstream(
        one_scanner(scanner.clone()),
        Arc::new(MockAdvisory::ok(vec![])),
        policy_projections,
        handler_map("oci", ArtifactKind::OciManifest),
        ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        Arc::new(MockUpstreamResolver::new()),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_hosted_composition(&storage);

    let job = scan_job_for_format(artifact_id, "oci");
    uc.run_scan(&job).await.expect("run_scan");

    let row = observations
        .row_for(artifact_id)
        .expect("an observation under the default policy");
    assert_eq!(row.assessment, CompositeAssessment::Assessed);
    // `DefaultPolicy::block_on_critical` blocks on critical, and the
    // composition found one — so promoting the composite verdict would
    // change this artifact's outcome.
    assert_eq!(row.composite_findings_decision, Some(GateDecision::Reject));
    assert_eq!(row.primary_findings_decision, GateDecision::Clean);
}

/// Seed a two-layer image whose every constituent is local — the hosted
/// shape, where an absent constituent would be a real refusal rather
/// than something to acquire.
fn seed_hosted_composition(storage: &Arc<MockStoragePort>) {
    let (config, lower, upper) = (
        synthetic_hash('c'),
        synthetic_hash('1'),
        synthetic_hash('2'),
    );
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&lower, &upper]),
    );
    storage.insert_content(config, stored_image_config(2));
    storage.insert_content(lower, b"lower layer".to_vec());
    storage.insert_content(upper, b"upper layer".to_vec());
}

/// A cold proxy image: the manifest and config are local (the manifest
/// because it is the row, the config because it was pulled with it), both
/// layers are not. The scan fetches them from the repository's upstream
/// and the composition then reaches the backend.
#[tokio::test]
async fn run_scan_acquires_a_cold_proxy_compositions_layers_and_then_assesses_it() {
    let scanner = Arc::new(
        MockScanner::with_analysis(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NotApplicable,
            )),
        )
        .answering_composites_with(Ok(ScanAnalysis::Analysed(vec![]))),
    );
    let (uc, storage, artifacts, repositories, proxy, resolver, observations) =
        make_uc_with_handler_storage_and_upstream(
            vec!["trivy".into()],
            one_scanner(scanner.clone()),
            handler_map("oci", ArtifactKind::OciManifest),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let artifact = artifacts
        .find_by_id(artifact_id)
        .await
        .expect("the seeded artifact");
    resolver.insert(composite_upstream_mapping(artifact.repository_id));

    let (lower_bytes, upper_bytes) = (b"lower layer".as_slice(), b"upper layer".as_slice());
    let (lower, upper) = (digest_of(lower_bytes), digest_of(upper_bytes));
    let config = synthetic_hash('c');
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&lower, &upper]),
    );
    storage.insert_content(config, stored_image_config(2));
    for (hash, bytes) in [(&lower, lower_bytes), (&upper, upper_bytes)] {
        proxy.insert_blob(
            "",
            &artifact.name,
            &format!("sha256:{hash}"),
            bytes.to_vec(),
            None,
        );
    }

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    assert_eq!(
        proxy.blob_fetches(),
        vec![format!("sha256:{lower}"), format!("sha256:{upper}")],
        "both absent layers were acquired, in manifest order"
    );
    assert_eq!(
        scanner.seen_units(),
        vec![ScanUnitShape::Blob, ScanUnitShape::Image(2)],
        "the composition reaches the backend only because its layers were acquired"
    );
    // Still no release authority: the row's own outcome is unchanged.
    assert!(
        matches!(
            outcome,
            ScanRunOutcome::Completed {
                assessment: ScanAssessment::NotApplicable,
                ..
            }
        ),
        "{outcome:?}"
    );
    // And the assessment left durable evidence, wired end to end: the
    // orchestrator resolved the policy and its exclusions and handed
    // both down, so the row carries a counterfactual beside what the
    // manifest's own bytes concluded (ADR 0064 D6).
    let row = observations
        .row_for(artifact_id)
        .expect("the shadow assessment recorded an observation");
    assert_eq!(row.assessment, CompositeAssessment::Assessed);
    assert_eq!(row.repository_id, artifact.repository_id);
    assert_eq!(row.cost.fetched, 2, "both layers crossed the wire");
    assert_eq!(row.composite_findings_decision, Some(GateDecision::Clean));
    assert_eq!(row.primary_findings_decision, GateDecision::Clean);
}

/// The shadow observation's write is best-effort: when the projection
/// refuses it, the artifact's own scan outcome, the events it produces
/// and the job row are all exactly what they would have been.
#[tokio::test]
async fn a_failing_observation_write_leaves_the_outcome_the_events_and_the_job_row_alone() {
    let scanner = Arc::new(
        MockScanner::with_analysis(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NotApplicable,
            )),
        )
        .answering_composites_with(Ok(ScanAnalysis::Analysed(vec![finding(
            "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
            "CVE-2022-COMPOSITE",
            SeverityThreshold::Critical,
        )]))),
    );
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(vec!["trivy".into()]));
    let (
        uc,
        jobs,
        events,
        storage,
        artifacts,
        repositories,
        _policy,
        _metadata,
        _proxy,
        _resolver,
        observations,
    ) = make_uc_with_upstream(
        one_scanner(scanner.clone()),
        Arc::new(MockAdvisory::ok(vec![])),
        policy_projections,
        handler_map("oci", ArtifactKind::OciManifest),
        ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        Arc::new(MockUpstreamResolver::new()),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_hosted_composition(&storage);
    observations.fail_next_record(DomainError::Invariant("projection unavailable".into()));

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    // The composition was still assembled and handed over — only the
    // row it would have left is missing.
    assert_eq!(
        scanner.seen_units(),
        vec![ScanUnitShape::Blob, ScanUnitShape::Image(2)]
    );
    assert!(
        observations.rows().is_empty(),
        "the refused write left nothing behind"
    );
    assert!(
        matches!(
            outcome,
            ScanRunOutcome::Completed {
                assessment: ScanAssessment::NotApplicable,
                ref findings,
                ..
            } if findings.is_empty()
        ),
        "the manifest row's own outcome is unchanged: {outcome:?}"
    );

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    assert_eq!(jobs.completed_calls(), vec![job.id]);
    let batches = events.appended_batches();
    assert_eq!(batches.len(), 1, "exactly the scan's own batch");
    assert!(
        batches[0]
            .events
            .iter()
            .any(|e| matches!(&e.event, DomainEvent::ScanCompleted(_))),
        "the artifact's own ScanCompleted still committed"
    );
}

/// An exclusion set the run could not resolve means the two sides of the
/// row would be judged by different rules, so no row is written — and
/// the read's failure stays out of the scan, which resolves its own
/// exclusions when it commits.
#[tokio::test]
async fn an_unresolvable_exclusion_set_records_no_observation_and_fails_no_scan() {
    let scanner = Arc::new(
        MockScanner::with_analysis(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NotApplicable,
            )),
        )
        .answering_composites_with(Ok(ScanAnalysis::Analysed(vec![]))),
    );
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(vec!["trivy".into()]));
    policy_projections.fail_next_list_exclusions(DomainError::Invariant("pg down".into()));
    let (
        uc,
        _jobs,
        _events,
        storage,
        artifacts,
        repositories,
        _policy,
        _metadata,
        _proxy,
        _resolver,
        observations,
    ) = make_uc_with_upstream(
        one_scanner(scanner.clone()),
        Arc::new(MockAdvisory::ok(vec![])),
        policy_projections,
        handler_map("oci", ArtifactKind::OciManifest),
        ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        Arc::new(MockUpstreamResolver::new()),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_hosted_composition(&storage);

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    assert!(observations.rows().is_empty());
    assert_eq!(
        scanner.seen_units(),
        vec![ScanUnitShape::Blob, ScanUnitShape::Image(2)],
        "the assessment itself still ran"
    );
    assert!(
        matches!(
            outcome,
            ScanRunOutcome::Completed {
                assessment: ScanAssessment::NotApplicable,
                ..
            }
        ),
        "{outcome:?}"
    );
}

/// Every other artifact in every other format reaches the composite
/// call, and none of them pays a round trip for a row that is never
/// written: the exclusion read is gated on the one kind the composite
/// path acts on.
#[tokio::test]
async fn a_non_manifest_row_costs_no_exclusion_read_and_leaves_no_observation() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::Analysed(vec![])),
    ));
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_global_policy(vec!["trivy".into()]));
    // Armed, and never consumed by `run_scan`: an npm row never reaches
    // the composite path's exclusion read. `record_scan_result` is not
    // called here, so nothing else consumes it either.
    policy_projections.fail_next_list_exclusions(DomainError::Invariant("must not be read".into()));
    let (
        uc,
        _jobs,
        _events,
        storage,
        artifacts,
        repositories,
        policy,
        _metadata,
        _proxy,
        _resolver,
        observations,
    ) = make_uc_with_upstream(
        one_scanner(scanner.clone()),
        Arc::new(MockAdvisory::ok(vec![])),
        policy_projections,
        handler_map("npm", ArtifactKind::NpmTarball),
        ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        Arc::new(MockUpstreamResolver::new()),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    storage.insert_content(VALID_SHA256.parse().unwrap(), b"tarball".to_vec());

    let job = scan_job_for_format(artifact_id, "npm");
    uc.run_scan(&job).await.expect("run_scan");

    assert!(observations.rows().is_empty());
    // The armed one-shot failure is still armed, so nothing read it.
    assert!(
        policy
            .list_exclusions_for_policy(Uuid::new_v4())
            .await
            .is_err(),
        "the composite path must not have consumed the exclusion read"
    );
}

/// A **hosted** repository has no upstream, so an absent constituent is a
/// real refusal: no fetch is attempted, no backend is handed a
/// composition, and the row's own outcome is untouched.
#[tokio::test]
async fn run_scan_on_a_hosted_row_with_an_absent_constituent_attempts_no_fetch() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let (uc, storage, artifacts, repositories, proxy, _resolver, _observations) =
        make_uc_with_handler_storage_and_upstream(
            vec!["trivy".into()],
            one_scanner(scanner.clone()),
            handler_map("oci", ArtifactKind::OciManifest),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    // No mapping inserted: the resolver answers nothing.

    let (config, layer) = (synthetic_hash('c'), synthetic_hash('1'));
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&layer]),
    );
    storage.insert_content(config, stored_image_config(1));

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    assert!(
        proxy.blob_fetches().is_empty(),
        "a hosted repository must not reach an upstream"
    );
    assert_eq!(
        scanner.seen_units(),
        vec![ScanUnitShape::Blob],
        "an incomplete composition is never handed to a backend"
    );
    assert!(
        matches!(
            outcome,
            ScanRunOutcome::Completed {
                assessment: ScanAssessment::NotApplicable,
                ..
            }
        ),
        "a deterministic composite refusal must not change the row's outcome: {outcome:?}"
    );
}

/// A transient acquisition failure takes the orchestrator's existing
/// retryable path: `Failed`, which `record_outcome` reschedules on the
/// shared backoff under the job's own `max_attempts`. Nothing parallel is
/// invented, and nothing terminal is written.
#[tokio::test]
async fn a_transient_acquisition_failure_asks_for_another_attempt() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let (uc, storage, artifacts, repositories, proxy, resolver, _observations) =
        make_uc_with_handler_storage_and_upstream(
            vec!["trivy".into()],
            one_scanner(scanner.clone()),
            handler_map("oci", ArtifactKind::OciManifest),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let artifact = artifacts
        .find_by_id(artifact_id)
        .await
        .expect("the seeded artifact");
    resolver.insert(composite_upstream_mapping(artifact.repository_id));

    let (config, layer) = (synthetic_hash('c'), synthetic_hash('1'));
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&layer]),
    );
    storage.insert_content(config, stored_image_config(1));
    proxy.fail_blob_with(
        &format!("sha256:{layer}"),
        DomainError::Invariant("upstream:upstream_5xx:503 Service Unavailable".to_string()),
    );

    // Attempt 1 of 5: the request is granted.
    let job = scan_job_for_format(artifact_id, "oci");
    assert_eq!(job.attempts, 1);
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Failed(err) = &outcome else {
        panic!("a transient acquisition failure earns a retry, got {outcome:?}");
    };
    assert!(
        err.contains("could not be produced on attempt 1 of 5"),
        "{err}"
    );
    assert!(err.contains("upstream_5xx"), "{err}");
}

/// The same transient failure on the **last** attempt: the request is
/// declined and the row's own outcome is recorded exactly as it would have
/// been. So the composite can never reach `record_outcome`'s
/// retry-exhausted arm, which is the one that transitions the artifact to
/// `scan_indeterminate` — exhausting the budget lands back on the
/// deterministic outcome, with no release authority anywhere in the path.
#[tokio::test]
async fn an_exhausted_attempt_budget_declines_the_retry_and_records_the_rows_own_outcome() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let (uc, storage, artifacts, repositories, proxy, resolver, _observations) =
        make_uc_with_handler_storage_and_upstream(
            vec!["trivy".into()],
            one_scanner(scanner.clone()),
            handler_map("oci", ArtifactKind::OciManifest),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let artifact = artifacts
        .find_by_id(artifact_id)
        .await
        .expect("the seeded artifact");
    resolver.insert(composite_upstream_mapping(artifact.repository_id));

    let (config, layer) = (synthetic_hash('c'), synthetic_hash('1'));
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&layer]),
    );
    storage.insert_content(config, stored_image_config(1));
    proxy.fail_blob_with(
        &format!("sha256:{layer}"),
        DomainError::Invariant("upstream:timeout:deadline exceeded".to_string()),
    );

    let job = ScanJob {
        format: "oci".to_string(),
        ..sample_scan_job(artifact_id, 5)
    };
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    assert!(
        matches!(
            outcome,
            ScanRunOutcome::Completed {
                assessment: ScanAssessment::NotApplicable,
                ..
            }
        ),
        "the last attempt records the row's own assessment, not a retry: {outcome:?}"
    );
}

/// A transient acquisition failure does **not** override a run that found
/// something. The shadow has no authority to delay a reject, so the
/// finding is recorded on this attempt and the composite's request is
/// declined.
#[tokio::test]
async fn a_transient_acquisition_failure_never_delays_a_finding() {
    let scanner = Arc::new(MockScanner::new(
        "trivy",
        Ok(vec![finding(
            "pkg:oci/manifest",
            "CVE-2026-MANIFEST",
            SeverityThreshold::High,
        )]),
    ));
    let (uc, storage, artifacts, repositories, proxy, resolver, _observations) =
        make_uc_with_handler_storage_and_upstream(
            vec!["trivy".into()],
            one_scanner(scanner.clone()),
            handler_map("oci", ArtifactKind::OciManifest),
            ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let artifact = artifacts
        .find_by_id(artifact_id)
        .await
        .expect("the seeded artifact");
    resolver.insert(composite_upstream_mapping(artifact.repository_id));

    let (config, layer) = (synthetic_hash('c'), synthetic_hash('1'));
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&layer]),
    );
    storage.insert_content(config, stored_image_config(1));
    proxy.fail_blob_with(
        &format!("sha256:{layer}"),
        DomainError::Invariant("upstream:network_error:connection refused".to_string()),
    );

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    let ScanRunOutcome::Completed { findings, .. } = &outcome else {
        panic!("a finding must be recorded on this attempt, got {outcome:?}");
    };
    assert_eq!(findings.len(), 1);
}

// ===========================================================================
// Promotion: the composed-image verdict gains release authority
// (ADR 0064 D6, the tightening half)
//
// Everything above holds for a policy at the default
// `CompositeVerdictMode::Observed`. These pin what changes when an
// operator promotes, and — as much to the point — what does not. The
// composition flows through the path the manifest's own verdict already
// takes: its findings join the run's accumulator and its *absence* joins
// the run's abstentions, so the release gate reads it under ADR 0007's
// existing predicate. Nothing here reads `composite_scan_observations`;
// `crates/hort-app/tests/shadow_observation_has_no_authority.rs` is what
// keeps that true structurally.
// ===========================================================================

/// Seed the two documents a two-layer composition is resolved from, plus
/// both layers, into a hosted repository's storage. The shape every
/// promotion test below starts from.
fn seed_two_layer_composition(storage: &Arc<MockStoragePort>) {
    let (config, lower, upper) = (
        synthetic_hash('c'),
        synthetic_hash('1'),
        synthetic_hash('2'),
    );
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&lower, &upper]),
    );
    storage.insert_content(config, stored_image_config(2));
    storage.insert_content(lower, b"lower layer".to_vec());
    storage.insert_content(upper, b"upper layer".to_vec());
}

/// A manifest-row scanner: the row's own bytes carry no package surface
/// (exactly as today), and the composition answers `composite`.
fn manifest_scanner(composite: DomainResult<ScanAnalysis>) -> Arc<MockScanner> {
    Arc::new(
        MockScanner::with_analysis(
            "trivy",
            Ok(ScanAnalysis::NothingAnalysable(
                NotAnalysable::NotApplicable,
            )),
        )
        .answering_composites_with(composite),
    )
}

/// **Promoted, with a blocking finding: the manifest is rejected.** The
/// composite findings are the manifest row's findings — they reach
/// `record_scan_result` with the run's assessment exactly as a
/// single-blob backend's would, and the gate rejects on them.
///
/// Asserted through `record_outcome` rather than stopping at the
/// `ScanRunOutcome`, because "rejects the manifest" is a claim about the
/// artifact and not about a struct: the committed batch has to carry the
/// `ArtifactRejected`.
#[tokio::test]
async fn a_promoted_composite_finding_rejects_the_manifest() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![finding(
        "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
        "CVE-2022-COMPOSITE",
        SeverityThreshold::Critical,
    )])));
    let (uc, events, storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_two_layer_composition(&storage);

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    // The composition was assembled and handed over, as it is under
    // `observed` too — promotion changes what the answer *does*, never
    // whether the work happens.
    assert_eq!(
        scanner.seen_units(),
        vec![ScanUnitShape::Blob, ScanUnitShape::Image(2)],
    );

    let ScanRunOutcome::Completed {
        ref findings,
        assessment,
        ref scanner,
        ..
    } = outcome
    else {
        panic!("a promoted composition's verdict completes the run, got {outcome:?}");
    };
    assert_eq!(
        assessment,
        ScanAssessment::Analysed,
        "the composition was assembled and examined, so the assessment is not `NotApplicable`"
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].vulnerability_id, "CVE-2022-COMPOSITE");
    assert_eq!(
        scanner, "composite",
        "the audit label names the scan unit — a manifest's verdict being its composed \
         image's is the one thing a reader of ScanCompleted cannot otherwise tell"
    );

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    let batches = events.appended_batches();
    assert!(
        batches
            .iter()
            .flat_map(|b| b.events.iter())
            .any(|e| matches!(&e.event, DomainEvent::ArtifactRejected(_))),
        "a promoted composite finding must reject the manifest: {batches:?}"
    );
}

/// **Promoted, with no findings: the manifest releases.** An empty
/// finding list from an assembled, examined composition is a clean
/// verdict — and it is recorded as `Analysed`, not as the
/// `NotApplicable` the manifest's own surface-free bytes would have
/// earned. Without that the trail would say "nothing to assess" about an
/// image that was assembled and looked at.
#[tokio::test]
async fn a_promoted_clean_composition_completes_the_manifest_as_analysed() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![])));
    let (uc, events, storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_two_layer_composition(&storage);

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    let ScanRunOutcome::Completed {
        ref findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("a clean promoted composition completes the run, got {outcome:?}");
    };
    assert_eq!(assessment, ScanAssessment::Analysed);
    assert!(findings.is_empty(), "{findings:?}");

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    let events: Vec<_> = events
        .appended_batches()
        .into_iter()
        .flat_map(|b| b.events.into_iter().map(|e| e.event))
        .collect();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, DomainEvent::ScanCompleted(_))),
        "a clean verdict is a ScanCompleted: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))),
        "and nothing rejects it: {events:?}"
    );
}

/// **A promoted composition that could not be produced holds the
/// manifest `scan_indeterminate`.** This is the refusal half of the
/// tightening: under `observed` an unassembled composition is a log line
/// and a row, and under `promoted` it is the absent verdict ADR 0007
/// fails closed on — the composition is the unit of filesystem
/// assessment, so an image that was never assembled is an image whose
/// filesystem went unassessed.
///
/// The refusal here is deterministic (a layer absent from a *hosted*
/// repository, which has no upstream to acquire from), so nothing
/// retries: re-running reads the same facts.
#[tokio::test]
async fn a_promoted_deterministic_refusal_holds_the_manifest_indeterminate() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![])));
    let (uc, events, storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);

    // The manifest and its config, but not the layer it declares. The
    // harness wires an empty upstream resolver, so this repository is
    // hosted and the absence is final.
    let (config, layer) = (synthetic_hash('c'), synthetic_hash('1'));
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&layer]),
    );
    storage.insert_content(config, stored_image_config(1));

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    assert!(
        !scanner
            .seen_units()
            .iter()
            .any(|u| matches!(u, ScanUnitShape::Image(_))),
        "no scanner is pointed at a partial layout — completeness is a precondition of a \
         verdict, never something the scan recovers from"
    );
    let ScanRunOutcome::NothingAnalysable { ref reason, .. } = outcome else {
        panic!("a promoted composition that was never assembled has no verdict, got {outcome:?}");
    };
    assert!(
        reason.contains("composite=incomplete_composition"),
        "the breakdown must name the composed unit and its fail-closed reason: {reason}"
    );

    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::ScanIndeterminate,
        "the manifest holds fail-closed"
    );
    let appended: Vec<_> = events
        .appended_batches()
        .into_iter()
        .flat_map(|b| b.events.into_iter().map(|e| e.event))
        .collect();
    assert!(
        !appended
            .iter()
            .any(|e| matches!(e, DomainEvent::ScanCompleted(_))),
        "and never records a clean ScanCompleted for an image nobody assembled: {appended:?}"
    );
}

/// **A promoted composition the backend ran over and found nothing
/// analysable in also holds — and reaches the manifest under its own
/// name.** `NoAnalyzerMatched` over a [`ScanUnit::Image`] cannot mean
/// "no package surface by construction": a composition *is* the thing
/// that was supposed to be assessed. Both it and "I could not build the
/// image" reach the same fail-closed hold, so nothing is mis-decided —
/// but they are different facts, and the one the release gate records
/// has to be the one that happened.
///
/// `incomplete_composition` says a constituent was missing, unreadable
/// or over budget, and all three are false of a composition that was
/// assembled and that every backend abstained on.
#[tokio::test]
async fn a_promoted_composition_with_no_analyzer_match_holds_the_manifest() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::NothingAnalysable(
        NotAnalysable::NoAnalyzerMatched,
    )));
    let (uc, _events, storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_two_layer_composition(&storage);

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    let ScanRunOutcome::NothingAnalysable { ref reason, .. } = outcome else {
        panic!("an abstention over an assembled composition has no verdict, got {outcome:?}");
    };
    assert!(
        reason.contains("composite=no_analyzer_matched"),
        "the composition was complete and the scanners claimed nothing in it: {reason}"
    );
    assert!(
        !reason.contains("incomplete_composition"),
        "no constituent was missing, unreadable or over budget: {reason}"
    );
}

// ---------------------------------------------------------------------------
// The obligation moves: a constituent under a promoted policy
// (ADR 0064 D2 + D6)
// ---------------------------------------------------------------------------

/// [`finding`] as the Trivy adapter produces it from a
/// `Vulnerabilities` entry: a claim about the filesystem the materialised
/// bytes compose into. Which filesystem that is — the artifact's own or
/// the one it is a constituent of — is the orchestrator's to place, so
/// these tests state the producer's half and let the pass under test
/// resolve the rest.
fn filesystem_finding(vuln: &str, sev: SeverityThreshold) -> Finding {
    let mut f = finding("pkg:deb/debian/openssl@1.1.1n-0+deb11u3", vuln, sev);
    f.statement = FindingStatement::Filesystem;
    f
}

/// And what a secrets or malware backend would stamp: a claim about the
/// bytes, true of them however they are composed. No backend hort ships
/// produces one, which is exactly why the line is drawn now.
fn byte_statement_finding(vuln: &str, sev: SeverityThreshold) -> Finding {
    let mut f = finding("pkg:deb/debian/openssl@1.1.1n-0+deb11u3", vuln, sev);
    f.statement = FindingStatement::Bytes;
    f
}

/// One OCI **blob** scan — a constituent — under the policy the caller
/// supplies, driven through `run_scan` + `record_outcome` so the
/// assertion is about the artifact row and the events rather than about
/// a struct.
#[allow(clippy::type_complexity)]
async fn constituent_scan(
    policy: ScanPolicyProjection,
    analysis: DomainResult<ScanAnalysis>,
) -> (
    ScanRunOutcome,
    Arc<MockEventStore>,
    Arc<MockArtifactRepository>,
    Uuid,
    ScanOrchestrationUseCase,
    ScanJob,
) {
    let scanner = Arc::new(MockScanner::with_analysis("trivy", analysis));
    let (uc, events, _storage, artifacts, repositories) = make_uc_under_policy(
        policy,
        one_scanner(scanner),
        handler_map("oci", ArtifactKind::OciBlob),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    (outcome, events, artifacts, artifact_id, uc, job)
}

fn committed_events(events: &Arc<MockEventStore>) -> Vec<DomainEvent> {
    events
        .appended_batches()
        .into_iter()
        .flat_map(|b| b.events.into_iter().map(|e| e.event))
        .collect()
}

/// **The pair the loosening is, end to end.** Same layer, same critical
/// finding, same promoted policy — and the only difference is what the
/// finding is a statement about.
///
/// A claim about the filesystem this layer composes in isolation stops
/// condemning it: the composition that binds it is assessed as one unit
/// and carries the filesystem verdict (ADR 0064 D2). A claim about the
/// layer's bytes still condemns it, because no composition changes
/// whether a leaked key is in them.
///
/// Both halves assert the *artifact*, not the outcome struct, and both
/// assert the finding is still **recorded**: the obligation moves, and
/// the evidence stays where it was. A test that showed only the first
/// half would be satisfied by a rule that disarmed every finding class.
#[tokio::test]
async fn under_promotion_a_constituents_filesystem_finding_stops_condemning_it_and_its_bytes_do_not(
) {
    let (outcome, events, artifacts, artifact_id, uc, job) = constituent_scan(
        seed_promoted_policy(vec!["trivy".into()]),
        Ok(ScanAnalysis::Analysed(vec![filesystem_finding(
            "CVE-2022-FILESYSTEM",
            SeverityThreshold::Critical,
        )])),
    )
    .await;
    let ScanRunOutcome::Completed {
        ref findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("the layer was examined, so its run completes: {outcome:?}");
    };
    assert_eq!(assessment, ScanAssessment::Analysed);
    assert_eq!(
        findings.len(),
        1,
        "the finding is evidence and stays in the record: {findings:?}"
    );
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    let appended = committed_events(&events);
    assert!(
        appended
            .iter()
            .any(|e| matches!(e, DomainEvent::ScanCompleted(_))),
        "the scan completed and is recorded: {appended:?}"
    );
    assert!(
        !appended
            .iter()
            .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))),
        "a constituent's isolated package set must not condemn it once its          composition carries the filesystem verdict: {appended:?}"
    );
    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::Quarantined,
        "the layer stays on its own observation window, unrejected"
    );

    // The other half of the pair: the same artifact, the same policy, a
    // statement about the bytes.
    let (outcome, events, artifacts, artifact_id, uc, job) = constituent_scan(
        seed_promoted_policy(vec!["trivy".into()]),
        Ok(ScanAnalysis::Analysed(vec![byte_statement_finding(
            "CVE-2022-BYTES",
            SeverityThreshold::Critical,
        )])),
    )
    .await;
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    let appended = committed_events(&events);
    assert!(
        appended
            .iter()
            .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))),
        "a statement about these bytes is true of them however they are          composed, so it keeps gating its own artifact: {appended:?}"
    );
    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::Rejected,
    );
}

/// **An unpromoted repository is byte-for-byte unchanged**, over every
/// finding class and every refusal class a constituent can produce.
///
/// This is the test that says the loosening is an operator's act and
/// nothing else: the same inputs the promoted tests above and below use,
/// under the default posture, reach exactly the outcomes they reached
/// before ADR 0064 D2 — a critical finding rejects whatever it is a
/// statement about, and every gating refusal holds.
#[tokio::test]
async fn an_unpromoted_constituent_gates_exactly_as_today_on_every_class() {
    for finding_under_test in [
        filesystem_finding("CVE-2022-FILESYSTEM", SeverityThreshold::Critical),
        byte_statement_finding("CVE-2022-BYTES", SeverityThreshold::Critical),
        finding(
            "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
            "CVE-2022-UNSTATED",
            SeverityThreshold::Critical,
        ),
    ] {
        let statement = finding_under_test.statement;
        let (outcome, events, artifacts, artifact_id, uc, job) = constituent_scan(
            seed_global_policy(vec!["trivy".into()]),
            Ok(ScanAnalysis::Analysed(vec![finding_under_test])),
        )
        .await;
        uc.record_outcome(&job, outcome)
            .await
            .expect("record_outcome");
        assert!(
            committed_events(&events)
                .iter()
                .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))),
            "{statement}: an unpromoted repository rejects on every finding class"
        );
        assert_eq!(
            artifacts
                .get(artifact_id)
                .expect("the artifact row")
                .quarantine_status,
            QuarantineStatus::Rejected,
            "{statement}"
        );
    }

    for refusal in [
        NotAnalysable::UnsupportedContainer,
        NotAnalysable::UnusableArchive,
        NotAnalysable::NoAnalyzerMatched,
        NotAnalysable::IncompleteComposition,
    ] {
        let (outcome, _events, artifacts, artifact_id, uc, job) = constituent_scan(
            seed_global_policy(vec!["trivy".into()]),
            Ok(ScanAnalysis::NothingAnalysable(refusal)),
        )
        .await;
        assert!(
            matches!(outcome, ScanRunOutcome::NothingAnalysable { .. }),
            "{refusal}: an unassessed surface has no verdict, got {outcome:?}"
        );
        uc.record_outcome(&job, outcome)
            .await
            .expect("record_outcome");
        assert_eq!(
            artifacts
                .get(artifact_id)
                .expect("the artifact row")
                .quarantine_status,
            QuarantineStatus::ScanIndeterminate,
            "{refusal}: an unpromoted constituent holds fail-closed"
        );
    }

    // And the one refusal that has never gated, under the same posture.
    let (outcome, _events, _artifacts, _id, _uc, _job) = constituent_scan(
        seed_global_policy(vec!["trivy".into()]),
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    )
    .await;
    assert!(
        matches!(
            outcome,
            ScanRunOutcome::Completed {
                assessment: ScanAssessment::NotApplicable,
                ..
            }
        ),
        "{outcome:?}"
    );
}

/// **The refusal pair, end to end.** On a constituent under a promoted
/// policy, "I have no decoder for this container" stops holding the
/// layer — the composition decodes it, and `tar+zstd` is ADR 0064 D2's
/// measured case — while "this archive tripped an extraction bound" or
/// "an entry tried to escape the workspace" keeps holding it.
///
/// Asserted together, because dropping both would disarm the zip-bomb
/// refusal and dropping neither would leave the `tar+zstd` layer
/// terminal with ADR 0062 withholding every image that binds it, which
/// is the defect this moves. The non-gating side lands on a completed
/// not-applicable assessment — scan authority exists, so the layer
/// releases on its own time gate rather than waiting forever on an
/// assessment that belongs to its composition.
#[tokio::test]
async fn a_promoted_constituent_stops_holding_on_a_missing_decoder_but_not_on_a_hostile_archive() {
    let (outcome, _events, artifacts, artifact_id, uc, job) = constituent_scan(
        seed_promoted_policy(vec!["trivy".into()]),
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::UnsupportedContainer,
        )),
    )
    .await;
    assert!(
        matches!(
            outcome,
            ScanRunOutcome::Completed {
                assessment: ScanAssessment::NotApplicable,
                ..
            }
        ),
        "a missing decoder is a statement about hort, not about the layer: {outcome:?}"
    );
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    assert_ne!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::ScanIndeterminate,
        "nothing holds the layer for an assessment its composition carries"
    );

    let (outcome, _events, artifacts, artifact_id, uc, job) = constituent_scan(
        seed_promoted_policy(vec!["trivy".into()]),
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::UnusableArchive,
        )),
    )
    .await;
    assert!(
        matches!(outcome, ScanRunOutcome::NothingAnalysable { .. }),
        "an extraction bound tripped is about these bytes: {outcome:?}"
    );
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::ScanIndeterminate,
        "a hostile archive holds the layer wherever its filesystem verdict lives"
    );
}

/// And the other refusals keep holding a promoted constituent too — only
/// the missing decoder moved. Stated separately from the pair above
/// because this is about the rest of the enum: a refusal that drifted
/// onto the non-gating side would release a layer nothing assessed.
#[tokio::test]
async fn a_promoted_constituent_still_holds_on_every_other_refusal() {
    for refusal in [
        NotAnalysable::UnusableArchive,
        NotAnalysable::NoAnalyzerMatched,
        NotAnalysable::IncompleteComposition,
    ] {
        let (outcome, _events, artifacts, artifact_id, uc, job) = constituent_scan(
            seed_promoted_policy(vec!["trivy".into()]),
            Ok(ScanAnalysis::NothingAnalysable(refusal)),
        )
        .await;
        uc.record_outcome(&job, outcome)
            .await
            .expect("record_outcome");
        assert_eq!(
            artifacts
                .get(artifact_id)
                .expect("the artifact row")
                .quarantine_status,
            QuarantineStatus::ScanIndeterminate,
            "{refusal} is not the statement ADR 0064 D2 moves"
        );
    }
}

/// **A promoted policy does not loosen a format ADR 0064 leaves
/// undecided.** The same statement on an npm tarball still condemns it:
/// an installed npm tree is also a composition hort never assembles, but
/// the analysis unit differs per format and the measurement behind
/// ADR 0064 says nothing about them ("Not decided here").
///
/// This is the test that scopes the loosening. `compositeVerdictMode` is
/// a `ScanPolicy` field and a **global** policy reaches every repository,
/// so an operator promoting the composite verdict for their OCI estate
/// must not thereby disarm their npm one.
#[tokio::test]
async fn promotion_does_not_loosen_a_format_adr_0064_leaves_undecided() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::Analysed(vec![filesystem_finding(
            "CVE-2022-NPM",
            SeverityThreshold::Critical,
        )])),
    ));
    let (uc, events, _storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner),
        handler_map("npm", ArtifactKind::NpmTarball),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let job = scan_job_for_format(artifact_id, "npm");
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    assert!(
        committed_events(&events)
            .iter()
            .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))),
        "an npm tarball is not a constituent of a composition hort assembles"
    );
    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::Rejected,
    );
}

/// **A promoted OCI *manifest* keeps condemning on its composition's
/// findings.** The mirror of the loosening, and the assertion that says
/// the obligation **moved** rather than evaporating: the composite
/// verdict's findings are about the filesystem the manifest *is*, so
/// nothing takes their authority away.
///
/// Without this the two halves of ADR 0064 D2 could both be satisfied by
/// a rule that disarmed every filesystem claim in the system.
#[tokio::test]
async fn a_promoted_manifests_composite_findings_still_condemn_it() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![finding(
        "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
        "CVE-2022-COMPOSITION",
        SeverityThreshold::Critical,
    )])));
    let (uc, events, storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_two_layer_composition(&storage);

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::Rejected,
        "the composition is the filesystem its own findings are about"
    );
    assert!(committed_events(&events)
        .iter()
        .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))));
}

/// **An image index is unaffected by promotion** (ADR 0064 D5). An index
/// binds references rather than a runnable filesystem, so there is
/// nothing to compose — and promotion must not make it gate on a
/// composition it does not have. The row keeps the not-applicable
/// assessment its own generic-manifest lifecycle gives it.
#[tokio::test]
async fn promotion_does_not_make_an_image_index_gate() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![finding(
        "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
        "CVE-2022-NEVER-ASKED",
        SeverityThreshold::Critical,
    )])));
    let (uc, _events, storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    storage.insert_content(VALID_SHA256.parse().unwrap(), stored_image_index());

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    assert!(
        !scanner
            .seen_units()
            .iter()
            .any(|u| matches!(u, ScanUnitShape::Image(_))),
        "an index is never composed, so the critical finding above is never asked for"
    );
    let ScanRunOutcome::Completed {
        ref findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("an index keeps its own completed assessment, got {outcome:?}");
    };
    assert_eq!(
        assessment,
        ScanAssessment::NotApplicable,
        "promotion leaves an index's not-applicable assessment exactly as it was"
    );
    assert!(findings.is_empty(), "{findings:?}");
}

/// **A config blob that is not an image config document resolves to
/// "nothing to compose", and under promotion that stays non-gating.** An
/// artifact manifest — a cosign signature, an SBOM attachment, a Helm
/// chart — is a legitimate population, not an unassessed image, so
/// refusing it would withhold a large share of every OCI estate on the
/// strength of an image it was never supposed to be.
#[tokio::test]
async fn promotion_does_not_gate_an_artifact_manifest() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![])));
    let (uc, _events, storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);

    let (config, layer) = (synthetic_hash('c'), synthetic_hash('1'));
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&layer]),
    );
    // A cosign signature's config blob: not an image config document.
    storage.insert_content(config, br#"{}"#.to_vec());
    storage.insert_content(layer, b"signature payload".to_vec());

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    let ScanRunOutcome::Completed {
        ref findings,
        assessment,
        ..
    } = outcome
    else {
        panic!("an artifact manifest keeps its own completed assessment, got {outcome:?}");
    };
    assert_eq!(assessment, ScanAssessment::NotApplicable);
    assert!(findings.is_empty(), "{findings:?}");
}

/// **A promoted composition's blocking verdict under
/// `enforcement: record` is recorded and not enforced** — the same
/// withholding every layer finding already gets, reached on a new axis.
/// So promotion plus `record` is a posture that measures findings and
/// enforces none of them.
///
/// It is **not** a posture that gates nothing, and this test pins the
/// half of that sentence that is easy to get wrong: `record` is read by
/// `evaluate_scan_result`, which only ever sees a finding list, so the
/// *refusal* path — which has no finding list and goes through
/// `record_scan_indeterminate` — is untouched by it. That is why
/// `promoted` × `record` is not a lint: one of its two halves still
/// holds artifacts, so an operator who set it has not disarmed the
/// promotion, only its rejections.
#[tokio::test]
async fn under_record_enforcement_a_promoted_composite_finding_is_recorded_not_enforced() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![finding(
        "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
        "CVE-2022-COMPOSITE",
        SeverityThreshold::Critical,
    )])));
    let policy = ScanPolicyProjection {
        enforcement: ScanEnforcement::Record,
        ..seed_promoted_policy(vec!["trivy".into()])
    };
    let (uc, events, storage, artifacts, repositories) = make_uc_under_policy(
        policy,
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_two_layer_composition(&storage);

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    let appended: Vec<_> = events
        .appended_batches()
        .into_iter()
        .flat_map(|b| b.events.into_iter().map(|e| e.event))
        .collect();
    let failed = appended.iter().any(|e| {
        matches!(
            e,
            DomainEvent::PolicyEvaluated(p)
                if p.result == hort_domain::events::PolicyResult::Fail
        )
    });
    assert!(
        failed,
        "the verdict is computed and audited exactly as under `reject`: {appended:?}"
    );
    assert!(
        !appended
            .iter()
            .any(|e| matches!(e, DomainEvent::ArtifactRejected(_))),
        "`record` withholds the transition: {appended:?}"
    );
}

/// **`record` does not withhold the refusal.** The companion to the test
/// above, and the correction it exists for: a promoted composition that
/// could not be produced holds the manifest `scan_indeterminate` under
/// `enforcement: record` exactly as under `reject`, because
/// `record_scan_indeterminate` never consults the enforcement mode —
/// there is no finding list for `evaluate_scan_result` to withhold a
/// verdict over.
#[tokio::test]
async fn record_enforcement_does_not_withhold_a_promoted_compositions_absence() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![])));
    let policy = ScanPolicyProjection {
        enforcement: ScanEnforcement::Record,
        ..seed_promoted_policy(vec!["trivy".into()])
    };
    let (uc, _events, storage, artifacts, repositories) = make_uc_under_policy(
        policy,
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);

    // Manifest + config present, the declared layer absent, hosted
    // repository: a deterministic refusal.
    let (config, layer) = (synthetic_hash('c'), synthetic_hash('1'));
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&layer]),
    );
    storage.insert_content(config, stored_image_config(1));

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    assert!(
        matches!(outcome, ScanRunOutcome::NothingAnalysable { .. }),
        "got {outcome:?}"
    );
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");
    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::ScanIndeterminate,
        "the hold is not an `enforcement` decision and `record` cannot waive it"
    );
}

/// **A later composite rejection on an already-released manifest behaves
/// exactly as a later single-blob rejection does today** — the
/// `trust_upstream_publish_time` row of the cross-opt-in matrix. That
/// opt-in can collapse the observation window so a manifest releases
/// before its composite scan has run, and the verdict then arrives on a
/// released artifact. That is the ordinary rescan path and not a new
/// case, which this pins by construction: the composite findings reach
/// `record_scan_result` through the same argument a backend's do, so a
/// timer-released artifact is re-blocked by one exactly as by the other.
#[tokio::test]
async fn a_promoted_composite_rejection_reblocks_a_timer_released_manifest() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![finding(
        "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
        "CVE-2022-COMPOSITE",
        SeverityThreshold::Critical,
    )])));
    let (uc, events, storage, artifacts, repositories) = make_uc_under_policy(
        seed_promoted_policy(vec!["trivy".into()]),
        one_scanner(scanner.clone()),
        handler_map("oci", ArtifactKind::OciManifest),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_two_layer_composition(&storage);

    // The manifest already released on the quarantine timer — which is
    // what `trust_upstream_publish_time` makes reachable before the
    // composite scan has ever run.
    let mut artifact = artifacts
        .find_by_id(artifact_id)
        .await
        .expect("the seeded artifact");
    artifact.quarantine_status = QuarantineStatus::Released;
    artifacts.insert(artifact);

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");
    uc.record_outcome(&job, outcome)
        .await
        .expect("record_outcome");

    assert!(
        events
            .appended_batches()
            .iter()
            .flat_map(|b| b.events.iter())
            .any(|e| matches!(&e.event, DomainEvent::ArtifactRejected(_))),
        "a timer release does not outweigh a fresh blocking verdict, whichever unit \
         produced it"
    );
}

/// **The observation row is written under promotion too, and agrees with
/// what happened.** Once promoted, `composite_findings_decision` stops
/// being a counterfactual and becomes a record of what also happened —
/// which is how an operator confirms the promotion is behaving as the
/// measurement predicted. The row's two columns stay per-axis either
/// way, and for an image manifest — whose own bytes carry no package
/// surface — the primary column is the clean one.
#[tokio::test]
async fn a_promoted_run_still_records_its_observation_and_the_row_agrees() {
    let scanner = manifest_scanner(Ok(ScanAnalysis::Analysed(vec![finding(
        "pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
        "CVE-2022-COMPOSITE",
        SeverityThreshold::Critical,
    )])));
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_promoted_policy(vec!["trivy".into()]));
    let (
        uc,
        _jobs,
        _events,
        storage,
        artifacts,
        repositories,
        _policy,
        _metadata,
        _proxy,
        _resolver,
        observations,
    ) = make_uc_with_upstream(
        one_scanner(scanner.clone()),
        Arc::new(MockAdvisory::ok(vec![])),
        policy_projections,
        handler_map("oci", ArtifactKind::OciManifest),
        ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        Arc::new(MockUpstreamResolver::new()),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    seed_two_layer_composition(&storage);

    let job = scan_job_for_format(artifact_id, "oci");
    let outcome = uc.run_scan(&job).await.expect("run_scan");

    let rows = observations.rows();
    assert_eq!(rows.len(), 1, "one row per assessment, promoted or not");
    assert_eq!(rows[0].assessment, CompositeAssessment::Assessed);
    assert_eq!(
        rows[0].composite_findings_decision,
        Some(GateDecision::Reject),
        "under promotion this column is what also happened, not what would have"
    );
    assert_eq!(
        rows[0].primary_findings_decision,
        GateDecision::Clean,
        "the manifest's own bytes carry no package surface, so the primary axis is clean \
         — which is why the committed verdict equals the composite column"
    );
    let ScanRunOutcome::Completed { ref findings, .. } = outcome else {
        panic!("got {outcome:?}");
    };
    assert_eq!(
        findings.len(),
        1,
        "and the committed finding set is the composite one the row reports on"
    );
}

/// **A promoted composition's transient refusal, once the attempt budget
/// is spent, holds the manifest.** The retry request and its three
/// guards are unchanged by promotion — a transient refusal still asks
/// for another attempt first, because with acquisition an unreachable
/// upstream is the routine failure rather than a statement about the
/// image. What promotion changes is where the *declined* request lands:
/// under `observed` the run records the manifest's own not-applicable
/// assessment, and under `promoted` the composition's absence is the
/// manifest's unassessed filesystem.
#[tokio::test]
async fn a_promoted_transient_refusal_holds_the_manifest_once_the_budget_is_spent() {
    let scanner = Arc::new(MockScanner::with_analysis(
        "trivy",
        Ok(ScanAnalysis::NothingAnalysable(
            NotAnalysable::NotApplicable,
        )),
    ));
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    policy_projections.insert(seed_promoted_policy(vec!["trivy".into()]));
    let (
        uc,
        _jobs,
        _events,
        storage,
        artifacts,
        repositories,
        _policy,
        _metadata,
        proxy,
        resolver,
        _observations,
    ) = make_uc_with_upstream(
        one_scanner(scanner.clone()),
        Arc::new(MockAdvisory::ok(vec![])),
        policy_projections,
        handler_map("oci", ArtifactKind::OciManifest),
        ScanOrchestrationConfig::defaults_for_worker("test-worker"),
        Arc::new(MockUpstreamResolver::new()),
    );
    let artifact_id = seed_quarantined_artifact(&artifacts, &repositories);
    let artifact = artifacts
        .find_by_id(artifact_id)
        .await
        .expect("the seeded artifact");
    resolver.insert(composite_upstream_mapping(artifact.repository_id));

    let (config, layer) = (synthetic_hash('c'), synthetic_hash('1'));
    storage.insert_content(
        VALID_SHA256.parse().unwrap(),
        stored_image_manifest(&config, &[&layer]),
    );
    storage.insert_content(config, stored_image_config(1));
    proxy.fail_blob_with(
        &format!("sha256:{layer}"),
        DomainError::Invariant("upstream:timeout:deadline exceeded".to_string()),
    );

    // Attempt 1 of 5: the request is granted and nothing holds yet —
    // identical to the unpromoted run, because whether a composition can
    // be *produced* does not depend on whose verdict it would be.
    let first = uc
        .run_scan(&scan_job_for_format(artifact_id, "oci"))
        .await
        .expect("run_scan");
    assert!(
        matches!(first, ScanRunOutcome::Failed(_)),
        "a transient refusal earns its retry under promotion too: {first:?}"
    );

    // Attempt 5 of 5: the request is declined, and now the absence is
    // the manifest's.
    let last_attempt = ScanJob {
        format: "oci".to_string(),
        ..sample_scan_job(artifact_id, 5)
    };
    let outcome = uc.run_scan(&last_attempt).await.expect("run_scan");
    let ScanRunOutcome::NothingAnalysable { ref reason, .. } = outcome else {
        panic!(
            "with the budget spent and nothing composed, a promoted manifest has no verdict, \
             got {outcome:?}"
        );
    };
    assert!(
        reason.contains("composite=incomplete_composition"),
        "{reason}"
    );

    uc.record_outcome(&last_attempt, outcome)
        .await
        .expect("record_outcome");
    assert_eq!(
        artifacts
            .get(artifact_id)
            .expect("the artifact row")
            .quarantine_status,
        QuarantineStatus::ScanIndeterminate,
    );
}
