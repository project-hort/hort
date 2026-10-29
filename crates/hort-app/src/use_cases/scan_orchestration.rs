//! Scan-orchestration use case.
//!
//! Implements the worker-side flow that ties the scanning producer
//! pipeline together: claim a `kind='scan'` job → load the artifact +
//! its policy → extract an SBOM via the format handler → query
//! advisories → invoke each configured scanner backend → dedupe
//! findings → hand the per-finding `Vec<Finding>` to
//! [`QuarantineUseCase::record_scan_result`], which atomically writes
//! the blob to CAS (single-source-of-truth for the CAS write site),
//! persists the per-finding rows, and emits the event batch
//! (`ScanCompleted` + optional `ArtifactBecameVulnerable` + the policy
//! reject path) → close out the job row.
//!
//! See `docs/architecture/explanation/scanning-pipeline.md` for
//! the full job lifecycle and the
//! newly-vulnerable-detection contract.
//!
//! # Single atomic batch
//!
//! A split-append shape (this orchestrator
//! appending `ArtifactBecameVulnerable` as a *second*
//! `EventStore::append` batch after `record_scan_result` had already
//! committed `ScanCompleted` + the policy reject events) is deliberately
//! avoided: the delta computation is folded into the consumer's
//! transaction, so a single
//! `commit_scan_result` writes `ScanCompleted` +
//! `ArtifactBecameVulnerable` (when applicable) + the policy reject
//! path + the per-finding `scan_findings` rows + `last_scan_at` in one
//! SQL transaction. The orchestrator passes the full
//! `Vec<Finding>` directly to `record_scan_result` and does no further
//! event-store work.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::scan_policy::{
    ExclusionProjection, ScanPolicyProjection, SeverityThreshold,
};
use hort_domain::error::DomainError;
use hort_domain::events::ScanAssessment;
use hort_domain::policy::scan::{composite_verdict_mode_of, DefaultPolicy};
use hort_domain::ports::advisory::AdvisoryPort;
use hort_domain::ports::artifact_metadata_repository::ArtifactMetadataRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::jobs_repository::{JobsRepository, ScanJob};
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::scanner::{
    EvidenceBasis, NotAnalysable, ScanAnalysis, ScanTarget, ScanUnit, ScannerPort,
    SCAN_REPORT_TOO_LARGE_MARKER,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::types::{
    severity_label, ArtifactCoords, ArtifactKind, ComponentRelation, Finding, PayloadAccess, Sbom,
};

use crate::error::AppResult;
use crate::metrics::{
    emit_component_relation, emit_sbom_components_skipped, emit_sbom_extraction,
    emit_sbom_resolution, emit_scan_failure, emit_scan_findings, emit_scan_jobs,
    emit_scan_terminal, observe_scan_duration, SbomExtractionResult, SbomResolutionResult,
    ScanFailureResult, ScanJobsResult, ScanTerminalResult,
};
use crate::result_write_fence::surface_result_write;
// `record_outcome`'s `Failed` branch waits out the workspace's one
// retry curve. The four-step shape used to be defined here and the task
// dispatcher carried its own, differently-shaped copy behind the same
// agreed attempt cap; the definition moved to `crate::retry_backoff` so
// the number and the window it spans cannot diverge again.
use crate::retry_backoff::compute_backoff;
use crate::scanning::any_scan_backend_applies_to;
use crate::use_cases::composite_scan::{
    CompositeDisposition, CompositeScan, CompositeVerdict, ShadowObservationSink,
    COMPOSITE_CONTRIBUTOR,
};
use crate::use_cases::policy_resolution::resolve_active_policy_for_repo;
use crate::use_cases::quarantine_use_case::QuarantineUseCase;
use crate::use_cases::scan_kind_resolution::scan_kind_of;

/// True when a scanner backend's error
/// is the distinguishable "report exceeded cap" failure (the adapter
/// killed the child after the bounded report drain tripped
/// `HORT_SCANNER_MAX_REPORT_SIZE`). Matched on the centralised
/// [`SCAN_REPORT_TOO_LARGE_MARKER`] substring so producer (adapter) and
/// consumer (this orchestrator) cannot drift on the literal. Both
/// adapters surface the cap-hit as a `DomainError::Invariant` (the same
/// kind as the timeout/kill branch), so we only inspect that variant.
fn is_report_too_large_error(err: &DomainError) -> bool {
    matches!(err, DomainError::Invariant(msg) if msg.contains(SCAN_REPORT_TOO_LARGE_MARKER))
}

/// The `jobs.kind` of every row this orchestrator closes out. Only
/// used as the label on a refused-write log line — the orchestrator is
/// reached through `ScanTaskHandler`, which the dispatcher registers
/// under this same literal.
const KIND: &str = "scan";

/// Default cap on the number of attempts before a job is moved to the
/// terminal `failed` status. Mirrors `HORT_SCANNER_MAX_ATTEMPTS`.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default for [`ScanOrchestrationConfig::allow_informed_downgrade`].
/// Mirrors `HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE`'s default: the
/// information-quality merge rule is **on**, and the operator switch
/// exists to turn it off (which makes the gate stricter, never looser).
const DEFAULT_ALLOW_INFORMED_DOWNGRADE: bool = true;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Composition-root configuration for the orchestrator. Built from
/// `WorkerConfig::from_env` at boot time.
///
/// Backend selection lives on
/// the resolved `ScanPolicyProjection.scan_backends`, not on this
/// struct. The orchestrator
/// reads from the policy chain (repo-scoped → global → default) and
/// falls back to [`DefaultPolicy::block_on_critical_default_backends`]
/// (`["trivy"]`) only when no policy is configured.
#[derive(Debug, Clone)]
pub struct ScanOrchestrationConfig {
    /// Identifier this worker reports on `jobs.locked_by` claims.
    pub worker_id: String,
    /// Cap on retry attempts before a job is `mark_failed` permanently.
    pub max_attempts: u32,
    /// **Deprecated, transitional.** Kept on the
    /// struct so the existing `hort-worker` composition root
    /// continues to compile while the worker's setter is migrated to
    /// the policy-projection path. The orchestrator's `run_scan`
    /// **does not read this field** — backend selection comes from
    /// `ScanPolicyProjection.scan_backends`. A follow-up MR will
    /// remove the field once the worker stops setting it.
    #[doc(hidden)]
    pub default_scan_backends: Vec<String>,
    /// Break-glass switch for the information-quality half of the
    /// cross-backend merge (ADR 0059). Sourced from
    /// `HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE`; **default `true`**.
    ///
    /// `true` — an *informed* finding (real CVSS, recognised
    /// informational class, or
    /// [`SeverityBasis::Assessed`](hort_domain::types::SeverityBasis::Assessed))
    /// supersedes an
    /// *uninformed* one for the same advisory across severity tiers, so a
    /// scored `Medium` wins over another backend's unreadable-severity
    /// `Critical` floor.
    ///
    /// `false` — reverts to strict always-fail-closed: the `Critical`
    /// floor wins on tier alone, as it did before this switch existed.
    /// Engaging the switch makes the release gate **stricter**, so it is a
    /// fail-closed escape hatch, not a relaxation. Read on every merge by
    /// `prefer_replacement` — a config value that the consumer ignored
    /// would be an inert operator surface (ADR 0015).
    pub allow_informed_downgrade: bool,
}

impl ScanOrchestrationConfig {
    /// Sensible defaults for tests; production overrides via the
    /// worker's env-derived `WorkerConfig`.
    pub fn defaults_for_worker(worker_id: impl Into<String>) -> Self {
        Self {
            worker_id: worker_id.into(),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            default_scan_backends: Vec::new(),
            allow_informed_downgrade: DEFAULT_ALLOW_INFORMED_DOWNGRADE,
        }
    }
}

// ---------------------------------------------------------------------------
// ScanRunOutcome
// ---------------------------------------------------------------------------

/// Result of a single `run_scan` invocation. Consumed by
/// `record_outcome` to drive the event-store append + job-row update.
///
/// There is deliberately no
/// `severity_summary: SeveritySummary` here (it is always recomputed
/// from `findings` by the consumer, hence would be dead in this
/// variant). Dropped:
/// the consumer's `record_scan_result` recomputes the summary via the
/// shared `severity_summary_from_findings` helper.
///
/// `sbom: Option<Sbom>` rides the `Completed`
/// variant. The alternative "drop the SBOM, reload at commit time" plan
/// was abandoned: there is no current place to re-extract the SBOM
/// at commit time without rerunning the format handler against the
/// payload, which would defeat the whole point of doing it once at
/// scan time. Carrying the typed value through the outcome lets
/// `record_outcome` thread `Option<&Sbom>` into
/// `QuarantineUseCase::record_scan_result` so the projection
/// REPLACE lands inside the same transaction as the event append.
#[derive(Debug)]
pub enum ScanRunOutcome {
    /// All configured backends ran (or were skipped on advisory-only
    /// failure) and produced a deduplicated finding set.
    Completed {
        /// Comma-joined contributing backend names — e.g. `"trivy,osv"`.
        /// Lands on `ScanCompleted.scanner` for audit. The empty-string
        /// case (no backend produced output) is impossible: we land on
        /// `Failed` instead.
        scanner: String,
        /// What this artifact's own format handler said its bytes are,
        /// resolved once by the run that produced `findings`.
        ///
        /// Carried on the outcome rather than re-resolved by
        /// `record_outcome`, because it is an input to the verdict
        /// `QuarantineUseCase::record_scan_result` computes over those
        /// same findings (ADR 0064 D2, via
        /// `Finding::may_condemn_artifact`). A second resolution would be
        /// a second answer about one run: the scanner materialised the
        /// payload under this kind, and a verdict taken under a different
        /// one would be judging a different artifact.
        kind: ArtifactKind,
        /// Deduplicated findings in scanner-emit order.
        findings: Vec<Finding>,
        /// Whether a package surface was examined, or there was none to
        /// examine. [`ScanAssessment::NotApplicable`] is reached only
        /// via the all-`NotAnalysable::NotApplicable` partition in
        /// `run_scan` and always pairs with an empty `findings`; it
        /// lands on `ScanCompleted.assessment` so the trail never reads
        /// "analysed, clean" for an artifact nothing could analyse.
        assessment: ScanAssessment,
        /// The SBOM extracted at the start of
        /// `run_scan`. `None` for formats whose handler does not
        /// produce one (the format is opaque, or no handler is
        /// registered for the repository's format). Threaded into
        /// `record_scan_result` so the `sbom_components` projection
        /// REPLACE lands inside the same Postgres tx as the event
        /// append; on `None` the projection write is skipped and
        /// existing rows for the artifact stay.
        sbom: Option<Sbom>,
    },
    /// Policy declared no scan backends — emit a clean
    /// `ScanCompleted(0)` and complete the job.
    ///
    /// Carries the artifact's `kind` for [`Self::Completed`]'s reason:
    /// this arm records a scan result too, so it reaches the verdict
    /// function, and the kind is one of that function's inputs. There is
    /// nothing in a waived scan for it to decide — the finding list is
    /// empty — but supplying a placeholder here would put a
    /// release-authority input in the orchestrator's gift rather than the
    /// handler's, which is exactly what the next arm to grow a finding
    /// list would inherit.
    SkippedNoBackends { kind: ArtifactKind },
    /// Every configured backend ran without error and **none of them
    /// produced a verdict**: each reported it had nothing to analyse
    /// (`ScanAnalysis::NothingAnalysable`), and at least one of those
    /// abstentions was an unassessed *expected* surface
    /// ([`NotAnalysable::gates_release`]). The artifact was never
    /// examined, so there is no clean result to record — it fails closed
    /// to `ScanIndeterminate` (ADR 0007).
    ///
    /// The all-`NotApplicable` case does **not** land here: an artifact
    /// with no package surface by construction has nothing for a hold to
    /// wait on, and takes the [`Self::Completed`] arm with
    /// [`ScanAssessment::NotApplicable`] instead.
    ///
    /// Distinct from [`Self::Failed`] because the two call for opposite
    /// job handling: a backend that *errored* may succeed on the next
    /// attempt, so `Failed` earns the retry budget. A backend that had
    /// nothing to analyse will have nothing to analyse again — the
    /// artifact's kind and the backend's analyzers are both fixed — so
    /// retrying only delays the hold by `max_attempts` backoffs. This
    /// arm goes terminal immediately.
    NothingAnalysable {
        /// Comma-joined backend names that were asked, for the
        /// `ScanIndeterminate` event's audit label.
        scanner: String,
        /// Human-readable `backend=reason` breakdown, e.g.
        /// `"trivy=no_analyzer_matched"`. Lands on the event's reason.
        reason: String,
    },
    /// Every configured backend errored. `record_outcome` reschedules
    /// or marks failed based on the job's attempt count.
    Failed(String),
}

/// The artifact's repository row, reduced to the fact the SBOM step
/// reads off it. Resolved once per scan by
/// [`ScanOrchestrationUseCase::subject_for_artifact`].
struct ScanSubject {
    coords: ArtifactCoords,
}

/// What the SBOM step produced — three facts rather than one `Option`,
/// because the scan axis reads them differently.
///
/// A bare `Option<Sbom>` merged "this format declares no dependencies"
/// with "the declaration could not be read", and a backend whose entire
/// input is the BOM ([`EvidenceBasis::SuppliedSbom`]) is handed only
/// that `Option`: it answers `NotApplicable` to both, which does not
/// gate. On a policy where such a backend is the only one configured,
/// the BOM **is** the subject, so an unreadable declaration recorded
/// `ScanCompleted(0, not_applicable)` over an artifact nothing had
/// examined. The orchestrator performed the extraction and is the only
/// place that knows which happened, so the distinction is kept here and
/// spent in `run_scan`'s abstention arm.
///
/// [`EvidenceBasis::SuppliedSbom`]: hort_domain::ports::scanner::EvidenceBasis::SuppliedSbom
enum SbomExtraction {
    /// A BOM came out of the handler.
    Extracted(Sbom),
    /// No BOM, for the reason carried.
    Absent(SbomAbsence),
}

/// Why no BOM came out of the SBOM step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SbomAbsence {
    /// A completed fact about the artifact: no handler is registered for
    /// the format, or the handler declares these bytes carry no
    /// dependency information. Nothing was expected, so nothing went
    /// unassessed.
    NotDeclared,
    /// A dependency declaration was expected and could not be read: the
    /// handler errored over the payload, or the extraction task did not
    /// complete. Deterministic — the same bytes read the same way on the
    /// next attempt, so a backend that had only this to go on earns a
    /// terminal no-verdict rather than a retry.
    Unreadable,
    /// The stored payload could not be reached at all. A property of the
    /// machine rather than of the artifact, and it may clear — so a
    /// backend that had only this to go on earns the scan job's existing
    /// attempt budget, the same answer the adapters' transient
    /// composition refusal takes.
    Unavailable,
}

impl SbomExtraction {
    /// The BOM, for the consumers that only need "is there one".
    fn sbom(&self) -> Option<&Sbom> {
        match self {
            Self::Extracted(sbom) => Some(sbom),
            Self::Absent(_) => None,
        }
    }

    /// The BOM, by value, for the outcome that carries it onward.
    fn into_sbom(self) -> Option<Sbom> {
        match self {
            Self::Extracted(sbom) => Some(sbom),
            Self::Absent(_) => None,
        }
    }

    /// Why no BOM exists, or `None` when one does.
    fn absence(&self) -> Option<SbomAbsence> {
        match self {
            Self::Extracted(_) => None,
            Self::Absent(why) => Some(*why),
        }
    }
}

// ---------------------------------------------------------------------------
// Use case
// ---------------------------------------------------------------------------

/// Scan-orchestration use case.
///
/// See the module docstring's single-atomic-batch note. The orchestrator
/// does not read the event store directly; the consumer
/// (`QuarantineUseCase::record_scan_result`) owns the prior-scan
/// reverse scan and the atomic event batch append. There is
/// deliberately no `events: Arc<dyn EventStore>` field
/// on this struct.
pub struct ScanOrchestrationUseCase {
    jobs: Arc<dyn JobsRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    artifact_metadata: Arc<dyn ArtifactMetadataRepository>,
    repositories: Arc<dyn RepositoryRepository>,
    policy_projections: Arc<dyn PolicyProjectionRepository>,
    advisory: Arc<dyn AdvisoryPort>,
    /// CAS handle for the scan-time payload read. Only formats that
    /// declare `FormatHandler::payload_sbom`, in a `Hosted` repository,
    /// reach it — every other scan costs no storage round-trip. Wired to
    /// the same CAS the Trivy
    /// adapter reads from (which has streamed artifact bytes at scan
    /// time since it shipped; this field puts the SBOM path on the same
    /// footing).
    storage: Arc<dyn StoragePort>,
    /// Upstream blob fetch for the composite path's constituent
    /// acquisition. A composed OCI image is the scan unit of a manifest
    /// (ADR 0064 D1), and for a **pull-through** manifest the layers that
    /// composition names are routinely not local — the client pull that
    /// would warm them begins with the manifest whose verdict is being
    /// gated, so waiting is not available. Reached only from the composite
    /// path, and only for a repository whose configuration names an
    /// upstream; every other scan costs no upstream round-trip.
    upstream_proxy: Arc<dyn UpstreamProxy>,
    /// Establishes whether the scanned artifact's repository has an
    /// upstream for its name, from the same configuration a client pull of
    /// that name would resolve through. A hosted repository resolves to
    /// nothing, and an absent constituent there is a real refusal.
    upstream_resolver: Arc<dyn UpstreamResolver>,
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
    quarantine: Arc<QuarantineUseCase>,
    /// Where the composite path's shadow assessment leaves its durable
    /// evidence (ADR 0064 D6). A sink and not the projection's
    /// repository: the orchestrator is what commits the artifact's own
    /// scan result, and nothing that decides release may hold a handle
    /// on a table of shadow verdicts.
    observations: Arc<ShadowObservationSink>,
    config: ScanOrchestrationConfig,
}

impl ScanOrchestrationUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        jobs: Arc<dyn JobsRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        artifact_metadata: Arc<dyn ArtifactMetadataRepository>,
        repositories: Arc<dyn RepositoryRepository>,
        policy_projections: Arc<dyn PolicyProjectionRepository>,
        advisory: Arc<dyn AdvisoryPort>,
        storage: Arc<dyn StoragePort>,
        upstream_proxy: Arc<dyn UpstreamProxy>,
        upstream_resolver: Arc<dyn UpstreamResolver>,
        scanners: HashMap<String, Arc<dyn ScannerPort>>,
        handlers: HashMap<String, Arc<dyn FormatHandler>>,
        quarantine: Arc<QuarantineUseCase>,
        observations: Arc<ShadowObservationSink>,
        config: ScanOrchestrationConfig,
    ) -> Self {
        Self {
            jobs,
            artifacts,
            artifact_metadata,
            repositories,
            policy_projections,
            advisory,
            storage,
            upstream_proxy,
            upstream_resolver,
            scanners,
            handlers,
            quarantine,
            observations,
            config,
        }
    }

    /// Claim a batch of pending `kind='scan'` rows. Thin pass-through
    /// over the [`JobsRepository`] port so the worker poll loop owns
    /// only one async call site for this concern.
    ///
    /// Emits `hort_scan_jobs_total{result=pending_claimed}`
    /// once per claimed job so the `pending → running` rate is
    /// observable on a single Prometheus series.
    #[tracing::instrument(skip(self))]
    pub async fn claim_pending(
        &self,
        batch_size: u32,
        lock_duration: Duration,
    ) -> AppResult<Vec<ScanJob>> {
        let claimed = self
            .jobs
            .claim_scan_jobs(&self.config.worker_id, batch_size, lock_duration)
            .await?;
        for _ in 0..claimed.len() {
            emit_scan_jobs(ScanJobsResult::PendingClaimed);
        }
        Ok(claimed)
    }

    /// Run every configured scanner backend against `job`'s artifact
    /// content + extracted SBOM, deduplicate the union of findings,
    /// write the JSON-serialised finding list to CAS, and return a
    /// `ScanRunOutcome` describing the result.
    ///
    /// This method is **pure work** — it does NOT mutate the job row
    /// or append events. The caller threads the returned outcome into
    /// [`record_outcome`](Self::record_outcome).
    #[tracing::instrument(skip(self, job))]
    pub async fn run_scan(&self, job: &ScanJob) -> AppResult<ScanRunOutcome> {
        // Step 1: load the artifact.
        let artifact = self.artifacts.find_by_id(job.artifact_id).await?;

        // Two things only the artifact's own format handler can answer,
        // both off this registry under this one key — and resolved HERE,
        // before any arm can return, because `kind` is an input to the
        // verdict every arm that records one reaches: an
        // operator-waived scan (`SkippedNoBackends`) records a result
        // too, and a default supplied for it would be a release-authority
        // decision taken by this function rather than by the artifact's
        // handler.
        //
        // `kind` goes through `scan_kind_of` rather than this `handler`
        // binding, which costs a second `HashMap` read and buys the thing
        // that matters: the policy re-evaluation paths resolve the kind
        // through the same helper, so a verdict re-taken over an
        // artifact's stored findings cannot read a different role for the
        // row than this run read.
        //
        // `kind` — what the bytes are, so an adapter can materialise them
        // the way its analyzers expect: a content scanner selects
        // analyzers by file name and directory layout, and a bare content
        // hash cannot answer "under what name?". It is also the role half
        // of ADR 0064 D2's line, which `Finding::may_condemn_artifact`
        // spends at the verdict. `Other` when no handler is registered
        // for the format — the honest "no materialisation applies"
        // answer, and a non-constituent, so every finding keeps its
        // authority rather than a guess letting an unexamined artifact
        // look clean.
        //
        // `payload_contains_components` — whether the payload carries the
        // code of the components its BOM lists, which is what decides
        // whether a finding against a non-subject component is about this
        // artifact at all (ADR 0056). With no handler registered the
        // trait's fail-closed default applies: no evidence was gathered
        // that would take authority away from a finding.
        let handler = self.handlers.get(&job.format);
        let kind = scan_kind_of(&self.handlers, &job.format, &artifact);

        // Step 2: resolve active policy and derive backends.
        // Backend selection lives on the policy
        // projection. Resolution order:
        //   - policy resolved (repo-scoped wins over global) and its
        //     `scan_backends` is non-empty → use those, in declared
        //     order;
        //   - policy resolved with `scan_backends == []` → operator
        //     opted out of scanning → return `SkippedNoBackends`;
        //   - no policy resolved → fall back to
        //     `DefaultPolicy::block_on_critical_default_backends`,
        //     which is `["trivy"]` so out-of-the-box deployments scan
        //     with Trivy.
        let policy =
            resolve_active_policy_for_repo(&*self.policy_projections, artifact.repository_id)
                .await?;
        let backends: Vec<String> = match policy.as_ref() {
            Some(p) if !p.scan_backends.is_empty() => p.scan_backends.clone(),
            Some(_) => {
                tracing::info!(
                    artifact_id = %artifact.id,
                    "scan skipped — policy declares empty scanBackends list",
                );
                return Ok(ScanRunOutcome::SkippedNoBackends { kind });
            }
            None => DefaultPolicy::block_on_critical_default_backends(),
        };

        if backends.is_empty() {
            // Defensive — `block_on_critical_default_backends` is
            // documented as non-empty (`["trivy"]`). A future change
            // that returns an empty Vec would surface here as a
            // skipped scan rather than panicking, which matches the
            // operator's expected "no-scan" semantics.
            tracing::info!(
                artifact_id = %artifact.id,
                "scan skipped — resolved backend list is empty",
            );
            return Ok(ScanRunOutcome::SkippedNoBackends { kind });
        }

        // The resolved composite-verdict posture for this repository
        // (ADR 0064 D6). Read once, from the policy just resolved, and
        // spent twice below — on the log level an abstention earns, and on
        // the partition that decides whether an abstention holds the
        // artifact. Both are the same question about the same run, so a
        // second resolution would be a second answer.
        //
        // What it decides for a **constituent** is ADR 0064 D2's
        // loosening: an OCI layer's filesystem is assessed as part of the
        // composition that binds it, so an absence of *that* assessment —
        // "I have no decoder for this container" — is the composition's
        // business and not the layer's. The derivation that pairs the
        // posture with the row's kind lives in
        // `NotAnalysable::gates_release`; the finding side pairs the same
        // two inputs in `Finding::may_condemn_artifact`, which the
        // consumer reaches through `evaluate_scan_result` with the `kind`
        // resolved above — so an absent assessment and a finding over the
        // same surface cannot disagree about whether this row is a
        // constituent.
        let composite_verdict = composite_verdict_mode_of(policy.as_ref());

        // Step 3-5: extract SBOM via the format handler (best-effort for
        // the run, but the *reason* no BOM came out is kept — see
        // `SbomExtraction` and the abstention arm below).
        let subject = self.subject_for_artifact(&artifact).await?;
        let extraction = self
            .try_extract_sbom(&artifact, &subject, &job.format)
            .await;
        let sbom_absence = extraction.absence();

        let relations = ComponentRelations {
            sbom: extraction.sbom(),
            payload_contains_components: handler.is_none_or(|h| h.payload_contains_components()),
            format: &job.format,
        };

        // Step 6: pre-scan advisory enrichment (best-effort).
        //
        // Advisory enrichment must cover BOTH the subject (the artifact
        // itself, e.g. lodash@4.17.20) and every dependency in
        // `components`. Iterating only over `components` is the bug
        // that would leave leaf packages undetected.
        let advisory_findings: Vec<Finding> = match extraction.sbom() {
            Some(s) => {
                let all = s.all_components_owned();
                match self.advisory.query(&all).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            artifact_id = %artifact.id,
                            error = %e,
                            "advisory query failed; proceeding with empty enrichment",
                        );
                        Vec::new()
                    }
                }
            }
            None => Vec::new(),
        };

        let target = ScanTarget {
            unit: ScanUnit::Blob(&artifact.sha256_checksum),
            format: &job.format,
            coords: &subject.coords,
            kind,
        };

        // Step 7-8: invoke each configured backend in declared order.
        // `hort_scan_duration_seconds{scanner}` brackets
        // exactly the `ScannerPort::scan` call (start before, observe
        // after). Adjacent dedup / CAS persist run outside the timer.
        //
        // Tagging site — the advisory half. The enrichment path is handed
        // the component list and nothing else, so its evidence is the BOM
        // by construction.
        let mut accumulated: Vec<Finding> =
            relations.tag(advisory_findings, EvidenceBasis::SuppliedSbom);
        let mut contributors: Vec<String> = Vec::new();
        let mut total_attempted: u32 = 0;
        let mut total_failed: u32 = 0;
        // Backends that ran cleanly but produced no verdict, with the
        // reason each gave — the material for the outcome partition
        // below (fail-closed hold vs. completed not-applicable
        // assessment).
        let mut abstentions: Vec<(String, NotAnalysable)> = Vec::new();
        for backend in &backends {
            total_attempted += 1;
            let Some(scanner) = self.scanners.get(backend) else {
                // Apply-time validation should have caught this.
                // Defensive at runtime.
                tracing::warn!(
                    artifact_id = %artifact.id,
                    backend,
                    "scan backend not registered with orchestrator; skipping",
                );
                total_failed += 1;
                continue;
            };
            // Consult the scanner capability map before spending an
            // invocation. A backend that cannot analyse this format can
            // only ever return the absence of a verdict, so invoking it
            // buys a CAS read, a materialisation and a subprocess for an
            // answer already known — and, worse, the answer arrives as
            // an abstention indistinguishable from "this artifact had no
            // surface", losing the one fact an operator needs: the
            // *pairing* is wrong.
            //
            // The abstention arm follows the same two-flavour split the
            // apply-time linter rejects on. Another backend covers this
            // format ⇒ the policy simply names the wrong one, an
            // expected surface goes unassessed, and the artifact holds
            // fail-closed (ADR 0007). Nobody covers it ⇒ there is no
            // surface any scanner could assess, so a hold would have
            // nothing to wait on.
            if !scanner.applies_to(&job.format) {
                if any_scan_backend_applies_to(&job.format) {
                    tracing::warn!(
                        artifact_id = %artifact.id,
                        scanner = backend,
                        format = %job.format,
                        kind = kind.as_str(),
                        "capability map: this backend does not analyse this format; the policy \
                         (or the built-in default `[trivy]`) is inert for this repository — \
                         configure a covering backend or waive scanning explicitly",
                    );
                    emit_scan_failure(ScanFailureResult::InertPairing, backend);
                    abstentions.push((backend.clone(), NotAnalysable::NoAnalyzerMatched));
                } else {
                    tracing::debug!(
                        artifact_id = %artifact.id,
                        scanner = backend,
                        format = %job.format,
                        kind = kind.as_str(),
                        "capability map: no compiled-in backend analyses this format — nothing \
                         to assess, so no scanner is invoked",
                    );
                    abstentions.push((backend.clone(), NotAnalysable::NotApplicable));
                }
                continue;
            }
            let started = Instant::now();
            let scan_result = scanner.scan(&target, extraction.sbom()).await;
            observe_scan_duration(backend, started.elapsed());
            match scan_result {
                Ok(ScanAnalysis::Analysed(findings)) => {
                    contributors.push(backend.clone());
                    // Tagging site — the scanner half. The backend states
                    // what it looked at; the orchestrator holds the SBOM.
                    accumulated.extend(relations.tag(findings, scanner.evidence_basis()));
                    tracing::info!(
                        artifact_id = %artifact.id,
                        scanner = backend,
                        finding_count = accumulated.len(),
                        "scan completed",
                    );
                }
                Ok(ScanAnalysis::NothingAnalysable(why)) => {
                    // The backend ran and reported it had nothing to
                    // analyse. It contributes NO verdict: folding this
                    // into the finding set would make it indistinguishable
                    // from "examined and clean", which is exactly the
                    // release authority an unexamined artifact must not
                    // earn (ADR 0007).
                    //
                    // **First, read the abstention against what this run
                    // actually handed the backend.** A backend whose
                    // entire input is the supplied BOM
                    // (`EvidenceBasis::SuppliedSbom`) receives an
                    // `Option` and nothing else, so its `NotApplicable`
                    // means "I was given no component list" — which is
                    // the absence of a surface only when the handler
                    // *declared* there is none. Where the declaration
                    // existed and could not be read, the surface was
                    // expected and went unassessed, and where the
                    // payload could not be reached the machine failed
                    // rather than the artifact. The extraction step
                    // cannot make this call (a payload-reading backend
                    // on the same policy assesses the artifact
                    // regardless, and must not lose its scan to a CAS
                    // hiccup) and the backend cannot see it, so it is
                    // made here, per backend, from the two facts only
                    // this scope holds.
                    let why = match (scanner.evidence_basis(), why, sbom_absence) {
                        (
                            EvidenceBasis::SuppliedSbom,
                            NotAnalysable::NotApplicable,
                            Some(SbomAbsence::Unreadable),
                        ) => NotAnalysable::UnusableArchive,
                        (
                            EvidenceBasis::SuppliedSbom,
                            NotAnalysable::NotApplicable,
                            Some(SbomAbsence::Unavailable),
                        ) => {
                            // Counted as a backend failure, not an
                            // abstention: the condition may clear, and
                            // `Failed` is the path this orchestrator
                            // already uses for a retryable scan failure
                            // — the job's own `max_attempts` bounds it,
                            // and exhausting the budget lands on the
                            // fail-closed terminal arm. A backend that
                            // succeeded on this run still carries the
                            // outcome, so a payload-reading sibling's
                            // verdict is not thrown away.
                            tracing::warn!(
                                artifact_id = %artifact.id,
                                scanner = backend,
                                format = %job.format,
                                kind = kind.as_str(),
                                "this backend's whole input is the artifact's component list \
                                 and the stored payload it is derived from could not be read \
                                 — no verdict from this backend on this attempt",
                            );
                            total_failed += 1;
                            continue;
                        }
                        (_, why, _) => why,
                    };

                    // The log level follows `gates_release`, because the
                    // two abstention classes ask different things of an
                    // operator. An unassessed *expected* surface is
                    // actionable — `warn!` naming format × backend, since
                    // the actionable fact is the *pairing*: an operator
                    // seeing `format=npm scanner=trivy` reads it as "this
                    // backend cannot adjudicate this format" and changes
                    // the policy. An artifact with no package surface at
                    // all (an OCI manifest row, an image config blob) is
                    // the expected steady state for every OCI push and
                    // asks nothing of anyone, so it is `debug!`: warning
                    // once per blob would bury the actionable half.
                    // Per-artifact detail stays on the span either way.
                    if why.gates_release(kind, composite_verdict) {
                        tracing::warn!(
                            artifact_id = %artifact.id,
                            scanner = backend,
                            format = %job.format,
                            kind = kind.as_str(),
                            reason = why.as_str(),
                            "scan backend had nothing to analyse — no verdict from this backend",
                        );
                        emit_scan_failure(ScanFailureResult::NothingAnalysable, backend);
                    } else {
                        tracing::debug!(
                            artifact_id = %artifact.id,
                            scanner = backend,
                            format = %job.format,
                            kind = kind.as_str(),
                            reason = why.as_str(),
                            "scan backend has no package surface to analyse for this artifact \
                             kind — nothing to assess",
                        );
                    }
                    abstentions.push((backend.clone(), why));
                }
                Err(e) => {
                    tracing::warn!(
                        artifact_id = %artifact.id,
                        scanner = backend,
                        error = %e,
                        "scanner backend failed; will continue with other backends",
                    );
                    // When the backend
                    // failed because its report drain hit
                    // `HORT_SCANNER_MAX_REPORT_SIZE` (the adapter
                    // killed the child + returned the distinguishable
                    // bounded-drain error), attribute the existing
                    // scan-failure metric with `result="report_too_large"`
                    // and the backend name. The failure still flows
                    // through the normal fail-closed path
                    // (`total_failed` → all-backends-failed → `Failed`
                    // → `record_scan_indeterminate`); this only adds the
                    // distinguishing observable.
                    if is_report_too_large_error(&e) {
                        emit_scan_failure(ScanFailureResult::ReportTooLarge, backend);
                    }
                    total_failed += 1;
                }
            }
        }
        // The composed-image assessment (ADR 0064 D1). It is produced,
        // mapped, logged and recorded on every manifest scan; whether it
        // reaches the artifact is the resolved policy's
        // `composite_verdict_mode` (ADR 0064 D6). Under `observed` — the
        // default, and every policy that predates the field — the
        // returned verdict is `Withheld` and this run's outcome is
        // byte-for-byte what it would be with no composite path at all.
        // Under `promoted` the composition's answer joins the loop's own
        // bookkeeping below, which is the path the manifest's verdict
        // already takes; nothing reads the observation projection to
        // decide anything, which is what keeps that table a measurement
        // surface. Only an OCI image manifest has a composition; every
        // other row returns immediately.
        //
        // Placed after the loop so it cannot perturb what the loop
        // *produced*, and before the partition below because that
        // partition is where a promoted composition's answer has to be
        // counted: an image manifest's own bytes carry no package
        // surface, so without the fold every promoted manifest would
        // take the partition's not-applicable early return no matter
        // what the composition said.
        //
        // The assessment leaves a durable row (ADR 0064 D6): a `tracing`
        // line reaches a log aggregator if one is configured and is gone
        // when its retention expires, and the promotion criterion —
        // "across this estate, what would promoting the composite
        // verdict have changed?" — has to be a query. The exclusion set
        // that row's two sides are judged against is resolved **here**,
        // once, and handed down; the counterfactual never fetches its
        // own, because a second resolution is a second set and the row
        // would be comparing two verdicts reached under different rules.
        //
        // Resolved only for the one row shape the composite path acts
        // on. Every other artifact in every other format reaches this
        // line, and a round trip for a row that is never written is a
        // round trip per scan.
        let composite_exclusions: Option<Vec<ExclusionProjection>> =
            if kind == ArtifactKind::OciManifest {
                self.exclusions_for_composite_observation(policy.as_ref())
                    .await
            } else {
                None
            };
        let composite = CompositeScan {
            storage: &self.storage,
            upstream_proxy: &self.upstream_proxy,
            upstream_resolver: &self.upstream_resolver,
            scanners: &self.scanners,
            artifact: &artifact,
            format: &job.format,
            coords: &subject.coords,
            kind,
            backends: &backends,
            sbom: extraction.sbom(),
            observations: &self.observations,
            policy: policy.as_ref(),
            exclusions: composite_exclusions.as_deref(),
            primary_findings: &accumulated,
            allow_informed_downgrade: self.config.allow_informed_downgrade,
        }
        .run()
        .await;

        // The composite path's one request of the run: another attempt,
        // because the composition was not produced for a condition that
        // may clear — an upstream that is down, rate-limiting or slow,
        // storage that did not answer. With acquisition that is the
        // *routine* failure, and reporting it as a deterministic
        // no-verdict would turn a momentary hiccup into a
        // permanent-looking absence of assessment.
        //
        // It is routed through `Failed`, which is the path the
        // orchestrator ALREADY uses for a retryable scan failure:
        // `record_outcome` reschedules on the shared backoff and the job's
        // own `max_attempts` is the bound, so a transient classification
        // never means unbounded attempts. Nothing parallel is invented and
        // no new terminal state exists.
        //
        // Three guards, and each one is what keeps this request free of
        // release authority:
        //
        // - **The attempt budget still has room.** On the last attempt the
        //   request is declined and the primary outcome is recorded
        //   exactly as it would have been — so the composite can never
        //   reach `record_outcome`'s retry-exhausted arm, which transitions
        //   the artifact to `scan_indeterminate`. Exhausting the budget
        //   lands back on the deterministic outcome: still no composite
        //   verdict, and now also no more tries.
        // - **No backend produced a verdict** (`contributors` empty) and
        //   **nothing was found** (`accumulated` empty). Both are outcomes
        //   the primary axis earned over the manifest's own bytes, and a
        //   retry would delay them — a clean `ScanCompleted` in the first
        //   case, a reject in the second. The composite path has no
        //   authority to spend either, promoted or not: promotion decides
        //   whose verdict gates, never whose outcome is thrown away.
        // - **No backend errored.** That run is already taking the
        //   retryable path below, with its own message; overriding it here
        //   would replace the operator's actual error with a second one.
        //
        // What the request does cost when it is granted: the manifest's
        // own `ScanCompleted` waits out the backoff. That is bounded by the
        // budget, and it is unobservable to a client in the case that
        // produces it — when the upstream will not serve the layers to
        // hort, it will not serve them to a pull through hort either, so
        // the image was not pullable during the wait regardless.
        if let CompositeDisposition::Retry(why) = composite.disposition {
            if accumulated.is_empty()
                && contributors.is_empty()
                && total_failed == 0
                && job.attempts < self.config.max_attempts
            {
                return Ok(ScanRunOutcome::Failed(format!(
                    "the composed image of artifact {} could not be produced on attempt {} \
                     of {}: {why}",
                    artifact.id, job.attempts, self.config.max_attempts
                )));
            }
            tracing::warn!(
                artifact_id = %artifact.id,
                attempts = job.attempts,
                max_attempts = self.config.max_attempts,
                reason = %why,
                "composite scan: no further attempt for the composed image — the run has an \
                 outcome of its own, or the attempt budget is spent; the composition stays \
                 unassessed for this run",
            );
        }

        // A **promoted** composition's answer, folded into the same
        // per-unit bookkeeping a backend's answer over the manifest's own
        // bytes goes into (ADR 0064 D6). Under `observed` this is
        // `Withheld` and the match is three no-ops, which is what makes
        // "an unpromoted run is byte-for-byte today's behaviour" a
        // property of one place rather than of every arm below.
        //
        // The fold is **after** the retry decision because a granted
        // retry has already returned: a transient refusal asks for
        // another attempt first, and only once that request is declined —
        // the budget is spent, or the run earned an outcome of its own —
        // does its absence become the manifest's unassessed filesystem.
        //
        // `total_attempted` grows with it, and that is the load-bearing
        // part rather than bookkeeping tidiness: the partition below
        // fires when *every* unit asked produced no verdict, so a
        // composition that was assessed has to be one of the units
        // asked. Without it a promoted manifest whose composition came
        // back clean would still take the not-applicable early return —
        // recording "nothing to assess" about an image that was
        // assembled and examined.
        match composite.verdict {
            CompositeVerdict::Withheld => {}
            CompositeVerdict::Assessed { evidence, findings } => {
                total_attempted += 1;
                contributors.push(COMPOSITE_CONTRIBUTOR.to_string());
                // Tagged through the same relation rule every other
                // producer's batch goes through, with the basis the
                // composite path read off the backend that answered —
                // so a composite finding naming a package the BOM never
                // listed is classified exactly as the same backend's
                // blob finding would be.
                accumulated.extend(relations.tag(findings, evidence));
            }
            CompositeVerdict::Absent(why) => {
                total_attempted += 1;
                // An abstention and not a `total_failed`: the question of
                // whether another attempt is worth making was already
                // asked and answered above, and counting it as a failure
                // here would route the run through the retryable path a
                // second time under a different message.
                abstentions.push((COMPOSITE_CONTRIBUTOR.to_string(), why));
            }
        }

        // No backend produced a verdict. Two different situations, and
        // the error case takes precedence: an errored backend might
        // succeed on retry, so if even one failed we take the retryable
        // `Failed` path exactly as before. Only when every backend ran
        // cleanly and every one of them abstained is the no-verdict
        // deterministic, and then retrying is pure delay.
        let abstained = abstentions.len() as u32;
        let no_verdict = total_failed + abstained;
        if total_attempted > 0 && no_verdict == total_attempted {
            if total_failed > 0 {
                // Wording preserved for the all-errored case (the only
                // one reachable before abstentions existed); a mixed run
                // names the split so an operator is not told a backend
                // that ran cleanly "failed".
                return Ok(ScanRunOutcome::Failed(if abstained == 0 {
                    format!(
                        "all {total_attempted} scan backends failed for artifact {}",
                        artifact.id
                    )
                } else {
                    format!(
                        "no scan backend produced a verdict for artifact {} \
                         ({total_failed} of {total_attempted} failed, {abstained} had \
                         nothing to analyse)",
                        artifact.id
                    )
                }));
            }

            // Partition the abstentions. Two classes that must not be
            // conflated:
            //
            // - An *expected* surface that could not be assessed —
            //   every abstention whose `gates_release()` is true — is
            //   the absent verdict ADR 0007 holds on: fail closed,
            //   exactly as before. One of these is enough to hold the
            //   artifact even when the rest are not-applicable, because
            //   the unassessed surface is still unassessed. The
            //   partition is read off `gates_release` rather than from a
            //   list of variant names here, so splitting or adding a
            //   reason cannot silently move an artifact across it.
            // - An artifact with *no* package surface by construction
            //   (an OCI manifest row, a non-tar OCI blob such as the
            //   image config) is outside the scan axis entirely. No
            //   scanner can find a threat level in it, so a hold has
            //   nothing to wait on and would hold forever. It records a
            //   completed assessment with nothing assessed: scan
            //   authority exists, the release gate opens on the time
            //   gate alone, and the trail says "not applicable".
            //
            // `accumulated` is non-empty here only when the advisory
            // enrichment produced findings while every backend
            // abstained. Something did have an opinion about this
            // artifact, so "nothing to assess" would be a false
            // statement and would drop a real finding — that case keeps
            // the fail-closed hold.
            if accumulated.is_empty()
                && !abstentions
                    .iter()
                    .any(|(_, why)| why.gates_release(kind, composite_verdict))
            {
                tracing::info!(
                    artifact_id = %artifact.id,
                    format = %job.format,
                    kind = kind.as_str(),
                    scanner = %backends.join(","),
                    reasons = %abstentions
                        .iter()
                        .map(|(backend, why)| format!("{backend}={}", why.as_str()))
                        .collect::<Vec<_>>()
                        .join(","),
                    composite_verdict = %composite_verdict,
                    "no assessable surface belongs to this artifact — recording a completed \
                     not-applicable assessment (nothing for a hold to wait on)",
                );
                return Ok(ScanRunOutcome::Completed {
                    scanner: backends.join(","),
                    kind,
                    findings: Vec::new(),
                    assessment: ScanAssessment::NotApplicable,
                    sbom: extraction.into_sbom(),
                });
            }

            return Ok(ScanRunOutcome::NothingAnalysable {
                scanner: backends.join(","),
                reason: format!(
                    "no scan backend could analyse artifact {} (format {}, kind {}): {}",
                    artifact.id,
                    job.format,
                    kind.as_str(),
                    abstentions
                        .iter()
                        .map(|(backend, why)| format!("{backend}={}", why.as_str()))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            });
        }

        // Step 9: dedupe across backends + advisory.
        let merged = merge_findings(accumulated, self.config.allow_informed_downgrade);
        let scanner_label = if contributors.is_empty() {
            // Only advisory contributed; surface that explicitly.
            "advisory".to_string()
        } else {
            contributors.join(",")
        };

        // `hort_scan_findings_total{scanner, severity}`
        // ticks once per (deduplicated) finding. The `scanner` label is
        // the per-finding `source_scanner` field (set by the adapter
        // that produced the finding) so a `(trivy, osv)` dedup
        // collision attributes to whichever backend won the merge.
        for finding in &merged {
            emit_scan_findings(&finding.source_scanner, severity_label(finding.severity));
        }

        // The orchestrator does not write
        // the findings blob to CAS. `QuarantineUseCase::record_scan_result`
        // owns the canonical write site (single-source-of-truth for the
        // 8 MiB cap and the JSON serialisation). Forwarding the full
        // `Vec<Finding>` to the consumer is sufficient.
        //
        // The typed `sbom` is forwarded through the
        // outcome so `record_outcome` can thread `Option<&Sbom>` into
        // `record_scan_result`'s SBOM-components arg. The earlier
        // "discard sbom; reload at commit time" plan was abandoned:
        // there is no commit-time reload path that doesn't rerun the
        // format handler over the payload.
        Ok(ScanRunOutcome::Completed {
            scanner: scanner_label,
            kind,
            findings: merged,
            assessment: ScanAssessment::Analysed,
            sbom: extraction.into_sbom(),
        })
    }

    /// The exclusion set the shadow composite observation's two sides
    /// are judged against, or `None` when this run cannot supply one.
    ///
    /// `None` is not "no exclusions". An empty set in its place would
    /// judge the counterfactual more harshly than the primary axis was
    /// judged and attribute the difference to the composition, so the
    /// caller skips the row instead. The read's failure is swallowed
    /// here for the reason the whole unit exists under: the shadow may
    /// not fail a scan, and this read happens only because the shadow
    /// wants it. The primary path resolves its own exclusions inside
    /// `record_scan_result`, where a failure still propagates exactly
    /// as it did before.
    async fn exclusions_for_composite_observation(
        &self,
        policy: Option<&ScanPolicyProjection>,
    ) -> Option<Vec<ExclusionProjection>> {
        // No policy resolved ⇒ no policy to carry exclusions, which is
        // a known-empty set rather than an unresolved one.
        let Some(policy) = policy else {
            return Some(Vec::new());
        };
        match self
            .policy_projections
            .list_exclusions_for_policy(policy.policy_id)
            .await
        {
            Ok(exclusions) => Some(exclusions),
            Err(e) => {
                tracing::warn!(
                    policy_id = %policy.policy_id,
                    error = %e,
                    "composite scan: could not resolve the policy's exclusions for the \
                     shadow observation; no observation is recorded for this run",
                );
                None
            }
        }
    }

    /// Persist a [`ScanRunOutcome`]. The success branches forward the
    /// full per-finding `Vec<Finding>` to
    /// [`QuarantineUseCase::record_scan_result`], which atomically:
    ///
    /// - Writes the JSON-serialised findings to CAS.
    /// - Inserts the `scan_findings` projection rows.
    /// - Appends `ScanCompleted` + (when applicable)
    ///   `ArtifactBecameVulnerable` + the policy reject events.
    /// - Updates `artifacts.last_scan_at`.
    ///
    /// The orchestrator never issues a
    /// second `EventStore::append` for `ArtifactBecameVulnerable`; the
    /// consumer owns the delta computation and the atomic batch.
    #[tracing::instrument(skip(self, outcome))]
    pub async fn record_outcome(&self, job: &ScanJob, outcome: ScanRunOutcome) -> AppResult<()> {
        match outcome {
            ScanRunOutcome::SkippedNoBackends { kind } => {
                // Emit a clean ScanCompleted via the consumer. The
                // reject path is a no-op for zero findings; the
                // delta path is a no-op when both prior and current
                // findings are empty.
                //
                // No SBOM is extracted on the
                // skipped-no-backends path (we never reached step 3),
                // so the consumer is invoked with `sbom = None` and
                // the `sbom_components` projection write is skipped.
                // `Analysed`: the operator waived the scan, they did not
                // declare the artifact unscannable. Recording it as
                // not-applicable would attribute the waiver to the
                // artifact's shape.
                self.quarantine
                    .record_scan_result(
                        job.artifact_id,
                        "(none)".to_string(),
                        Vec::new(),
                        ScanAssessment::Analysed,
                        kind,
                        None,
                    )
                    .await?;
                // H17 — scan's forensics are the ScanCompleted event + the
                // findings projection; the JSON `result_summary`
                // (`{scanner, finding_count}`) is built by ScanTaskHandler and
                // persisted by the dispatcher's own (second, authoritative,
                // idempotent) mark_completed call, so pass Null here.
                let outcome = self
                    .jobs
                    .mark_completed(job.id, job.attempts, serde_json::Value::Null)
                    .await?;
                surface_result_write(outcome, "mark_completed", job.id, KIND, job.attempts);
                emit_scan_jobs(ScanJobsResult::Completed);
                // Operator-waiver clean outcome.
                emit_scan_terminal(ScanTerminalResult::Completed);
                Ok(())
            }
            ScanRunOutcome::Completed {
                scanner,
                kind,
                findings,
                assessment,
                sbom,
            } => {
                // Classify the artifact-terminal
                // decision BEFORE the consumer moves `findings`: a
                // non-empty finding set rejects the artifact; an empty
                // one is a clean completion, unless there was nothing to
                // assess in the first place — which is a completed
                // assessment of its own and gets its own label rather
                // than borrowing `completed`'s claim of an examination.
                // (The consumer owns the actual reject transition; this
                // only labels the terminal-outcome counter — one metric,
                // one layer.)
                let terminal = match (findings.is_empty(), assessment.is_not_applicable()) {
                    (true, true) => ScanTerminalResult::NotApplicable,
                    (true, false) => ScanTerminalResult::Completed,
                    // `NotApplicable` with findings is rejected by
                    // `ScanCompleted::validate` before it can commit;
                    // the verdict still governs the label.
                    (false, _) => ScanTerminalResult::Rejected,
                };
                // Pass the full findings vec to the consumer; it owns
                // the per-scan path (CAS write + scan_findings projection
                // + atomic event batch + last_scan_at).
                //
                // Thread the extracted SBOM through
                // so the `sbom_components` projection REPLACE lands
                // inside the same Postgres tx as the scan result.
                // `None` (handler returned no SBOM, or no handler
                // registered) signals "skip the projection write,
                // existing rows preserved" per the design contract.
                self.quarantine
                    .record_scan_result(
                        job.artifact_id,
                        scanner,
                        findings,
                        assessment,
                        kind,
                        sbom.as_ref(),
                    )
                    .await?;
                // H17 — scan's forensics are the ScanCompleted event + the
                // findings projection; the JSON `result_summary`
                // (`{scanner, finding_count}`) is built by ScanTaskHandler and
                // persisted by the dispatcher's own (second, authoritative,
                // idempotent) mark_completed call, so pass Null here.
                let outcome = self
                    .jobs
                    .mark_completed(job.id, job.attempts, serde_json::Value::Null)
                    .await?;
                surface_result_write(outcome, "mark_completed", job.id, KIND, job.attempts);
                emit_scan_jobs(ScanJobsResult::Completed);
                emit_scan_terminal(terminal);
                Ok(())
            }
            ScanRunOutcome::NothingAnalysable { scanner, reason } => {
                // FAIL-CLOSED (ADR 0007). Every backend ran and none
                // examined the artifact, so no verdict exists — the same
                // situation an absent verdict already puts the scan axis
                // in, and it gets the same terminal state. Recording a
                // clean `ScanCompleted(0)` here is the defect this arm
                // exists to remove: it would hand release authority to a
                // scan that never looked at the bytes.
                //
                // No retry budget and no "stay quarantined" carve-out.
                // The retry-exhausted `Failed` arm below keeps an
                // already-`Quarantined` artifact where it is because a
                // scanner *outage* is transient and the rescan sweep will
                // re-pick it on recovery. Here nothing is transient: the
                // artifact's kind and the backend's analyzers are both
                // fixed, so the next attempt has the same outcome.
                // `record_scan_indeterminate` is idempotent on an
                // already-terminal artifact.
                tracing::warn!(
                    artifact_id = %job.artifact_id,
                    format = %job.format,
                    scanner = %scanner,
                    reason = %reason,
                    "no scan backend produced a verdict — holding artifact scan_indeterminate \
                     (fail-closed); a backend that cannot analyse this format is a policy \
                     mismatch, not a clean scan",
                );
                self.quarantine
                    .record_scan_indeterminate(
                        job.artifact_id,
                        scanner,
                        reason.clone(),
                        job.attempts,
                    )
                    .await?;
                let outcome = self.jobs.mark_failed(job.id, job.attempts, &reason).await?;
                surface_result_write(outcome, "mark_failed", job.id, KIND, job.attempts);
                emit_scan_jobs(ScanJobsResult::Failed);
                emit_scan_terminal(ScanTerminalResult::Indeterminate);
                Ok(())
            }
            ScanRunOutcome::Failed(err) => {
                if job.attempts >= self.config.max_attempts {
                    // A dead scanner is a real operational error operators
                    // should alert on; keep the `error!`.
                    tracing::error!(
                        artifact_id = %job.artifact_id,
                        attempts = job.attempts,
                        last_error = %err,
                        "scan job exhausted retries",
                    );

                    // This `Failed` outcome is a scanner-EXECUTION failure
                    // (every configured backend errored — the scan could
                    // not run at all), not a genuinely-ambiguous scan
                    // RESULT. Issue #6 / ADR 0007 refinement: when the
                    // artifact is already `Quarantined` (mid-observation-
                    // window), a scanner outage must not escalate it to
                    // the stricter terminal `scan_indeterminate` — it
                    // fails closed by staying exactly where it already is
                    // (downloads still blocked; `quarantine_status`
                    // untouched, no event, no state UPDATE at all).
                    // `mark_failed` alone (`jobs.status='failed'`,
                    // `last_error`) IS the persisted "last scan errored"
                    // fact `RescanCandidatesRepository::select_stranded`
                    // reads to re-pick the artifact once the scanner
                    // recovers (`CronRescanTickHandler`).
                    //
                    // Any OTHER current status still routes through
                    // `record_scan_indeterminate`, exactly as before this
                    // change: a `None`-status artifact (permissive
                    // default — no quarantine window to fall back into)
                    // has no "stay where you are" option, so ADR 0007's
                    // fail-closed backstop (never-successfully-scanned →
                    // blocked) still applies; an already-terminal status
                    // (`ScanIndeterminate` / `Rejected` / `Released`)
                    // hits `record_scan_indeterminate`'s existing
                    // idempotent-skip. Best-effort load — on a genuine
                    // load failure `current_status` is `None` here, which
                    // falls through to `record_scan_indeterminate`
                    // (unchanged behavior: it re-loads and propagates the
                    // same error).
                    let current_status = self
                        .artifacts
                        .find_by_id(job.artifact_id)
                        .await
                        .ok()
                        .map(|a| a.quarantine_status);

                    if current_status == Some(QuarantineStatus::Quarantined) {
                        tracing::info!(
                            artifact_id = %job.artifact_id,
                            attempts = job.attempts,
                            "scan retries exhausted while quarantined — staying quarantined \
                             (not scan_indeterminate); will be re-picked by the rescan sweep \
                             once the scanner recovers",
                        );
                        let outcome = self.jobs.mark_failed(job.id, job.attempts, &err).await?;
                        surface_result_write(outcome, "mark_failed", job.id, KIND, job.attempts);
                        emit_scan_jobs(ScanJobsResult::Failed);
                    } else {
                        // FAIL-CLOSED (ADR 0007): transition the
                        // artifact to ScanIndeterminate BEFORE mark_failed
                        // so a crash between them leaves the job
                        // retryable rather than the artifact silently
                        // un-failed. The use case loads the artifact,
                        // calls `fail_scan_indeterminate`, and commits the
                        // event + status transition atomically via the
                        // EXISTING `commit_transition_with_score`. An
                        // already-terminal artifact is a recoverable skip
                        // (returns Ok); a genuine load/commit error
                        // propagates and we do NOT mark the job failed
                        // (fail-closed: keep the job retryable so the
                        // transition is retried).
                        let scanner_label = self.scanner_label_for_failed(job).await;
                        self.quarantine
                            .record_scan_indeterminate(
                                job.artifact_id,
                                scanner_label,
                                err.clone(),
                                job.attempts,
                            )
                            .await?;
                        let outcome = self.jobs.mark_failed(job.id, job.attempts, &err).await?;
                        surface_result_write(outcome, "mark_failed", job.id, KIND, job.attempts);
                        emit_scan_jobs(ScanJobsResult::Failed);
                        // Artifact-terminal: indeterminate.
                        emit_scan_terminal(ScanTerminalResult::Indeterminate);
                    }
                } else {
                    let backoff = compute_backoff(job.attempts);
                    tracing::info!(
                        artifact_id = %job.artifact_id,
                        attempts = job.attempts,
                        max_attempts = self.config.max_attempts,
                        backoff_secs = backoff.as_secs(),
                        "scan failure classified as transient (scanner-execution) — rescheduling",
                    );
                    let outcome = self
                        .jobs
                        .reschedule(job.id, job.attempts, backoff, &err)
                        .await?;
                    surface_result_write(outcome, "reschedule", job.id, KIND, job.attempts);
                    emit_scan_jobs(ScanJobsResult::Retried);
                }
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /// Extract the scan's SBOM, reading the artifact's stored payload
    /// when — and only when — the format handler declares it derives its
    /// components from the payload (`FormatHandler::payload_sbom() ==
    /// Some(_)`). The repository class the artifact lives in plays no
    /// part in the decision: a scanner must be able to deliver the
    /// threat level the repository's configuration declares, for every
    /// class the configuration allows.
    ///
    /// # Operator note: proxied lockfile formats
    ///
    /// An archive like a `.crate` does not contain its dependencies'
    /// code, so a finding derived from its embedded lockfile is a claim
    /// about code that is **not in the artifact** — unlike a container
    /// image, where the scanner reads the vulnerable bytes themselves.
    /// On a proxy, that lockfile is the upstream author's dev-time
    /// resolve, not the consumer's: a consumer of a library re-resolves
    /// and never runs it, so a finding against a stale upstream resolve
    /// is hearsay about code nobody downstream will build. Under
    /// `enforcement: reject` that hearsay carries gate power over an
    /// artifact every consumer would in fact resolve safely.
    /// `enforcement: record` is the recommended mode on proxied
    /// lockfile-resolving formats for exactly this reason — the finding
    /// is kept and observable without becoming release authority. A
    /// **binary** crate installed with `cargo install --locked` really
    /// does run its embedded resolve, so for bins the upstream signal is
    /// genuine; bin and lib cannot be told apart cheaply at scan time,
    /// which is why this stays an operator-facing note rather than a
    /// per-class code decision.
    ///
    /// Two counters fire exactly once per call and answer different
    /// questions: `hort_sbom_extraction_total{format, result}` — did a
    /// BOM come out — and `hort_sbom_resolution_total{format, result}` —
    /// on what basis were its component versions derived. The
    /// `unsupported_format` arm of the first covers both "no handler
    /// registered for this format" and "handler returned `Ok(None)`":
    /// both surface to operators as "this format does not produce an
    /// SBOM" with no actionable distinction.
    ///
    /// **Fail-soft, and that is a statement about this step rather than
    /// about the run.** Nothing here can fail the scan: a storage read
    /// that fails degrades to the no-SBOM path a format with no handler
    /// takes, with the metric saying which happened, because letting a
    /// CAS hiccup abort a scan a payload-reading backend could have
    /// performed would trade a thinner BOM for no scan at all.
    ///
    /// What it must not do is *erase the reason*. ADR 0007's fail-closed
    /// rule governs release authority, and for a backend whose entire
    /// input is this BOM the BOM **is** the authority — so an absence
    /// the handler declared and an absence the machine caused are
    /// different facts, and the return type keeps them apart
    /// ([`SbomExtraction`]). Which of them gates is decided in
    /// `run_scan`, where the configured backends are known; nothing is
    /// decided here.
    async fn try_extract_sbom(
        &self,
        artifact: &Artifact,
        subject: &ScanSubject,
        format_key: &str,
    ) -> SbomExtraction {
        let Some(handler) = self.handlers.get(format_key) else {
            emit_sbom_extraction(format_key, SbomExtractionResult::UnsupportedFormat);
            emit_sbom_resolution(format_key, SbomResolutionResult::NotApplicable);
            return SbomExtraction::Absent(SbomAbsence::NotDeclared);
        };

        if handler.payload_sbom().is_some() {
            let handler = Arc::clone(handler);
            return self
                .extract_sbom_from_stored_payload(handler, artifact, &subject.coords, format_key)
                .await;
        }

        // The metadata-only path — reached only by a format that never
        // consumes the payload. Unchanged from before the payload path
        // existed: no storage read, and the empty-payload call the
        // handlers have always ignored.
        emit_sbom_resolution(format_key, SbomResolutionResult::NotApplicable);
        match handler.extract_sbom(
            &subject.coords,
            &subject.coords.metadata,
            PayloadAccess::Bytes(&[]),
        ) {
            Ok(Some(sbom)) => {
                emit_sbom_extraction(format_key, SbomExtractionResult::Success);
                SbomExtraction::Extracted(sbom)
            }
            Ok(None) => {
                emit_sbom_extraction(format_key, SbomExtractionResult::UnsupportedFormat);
                SbomExtraction::Absent(SbomAbsence::NotDeclared)
            }
            Err(e) => {
                emit_sbom_extraction(format_key, SbomExtractionResult::ParseError);
                tracing::warn!(
                    format_key,
                    error = %e,
                    "extract_sbom failed; proceeding with no SBOM",
                );
                SbomExtraction::Absent(SbomAbsence::Unreadable)
            }
        }
    }

    /// Stream the artifact's stored bytes out of CAS and hand them to the
    /// handler's [`PayloadSbom`](hort_domain::ports::format_handler::PayloadSbom)
    /// implementation.
    ///
    /// **The payload never lands in a buffer here (ADR 0026).**
    /// `StoragePort::get` yields an `AsyncRead`; `SyncIoBridge` adapts it
    /// to the synchronous `std::io::Read` the format port speaks, and the
    /// whole extraction runs on a blocking thread — so the bytes flow CAS
    /// → bridge → the handler's archive walk with only the handler's own
    /// documented caps in the path. `spawn_blocking` is mandatory rather
    /// than incidental: the bridge parks the calling thread on runtime
    /// I/O, and the extraction itself (gunzip, tar scan, TOML parse) is
    /// CPU-bound work that has no business on an async worker thread.
    async fn extract_sbom_from_stored_payload(
        &self,
        handler: Arc<dyn FormatHandler>,
        artifact: &Artifact,
        coords: &ArtifactCoords,
        format_key: &str,
    ) -> SbomExtraction {
        let stream = match self.storage.get(&artifact.sha256_checksum).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    format_key,
                    error = %e,
                    "stored payload unreadable; proceeding with no SBOM",
                );
                emit_sbom_extraction(format_key, SbomExtractionResult::PayloadUnavailable);
                emit_sbom_resolution(format_key, SbomResolutionResult::PayloadUnavailable);
                return SbomExtraction::Absent(SbomAbsence::Unavailable);
            }
        };

        let bridge = tokio_util::io::SyncIoBridge::new(stream);
        let coords_owned = coords.clone();
        let joined = tokio::task::spawn_blocking(move || {
            // Re-asked inside the closure because the capability is
            // borrowed from `handler` and cannot cross the thread
            // boundary on its own. The caller established it is `Some`.
            let Some(payload_sbom) = handler.payload_sbom() else {
                return Err(DomainError::Invariant(
                    "format handler withdrew its PayloadSbom capability between calls".to_string(),
                ));
            };
            payload_sbom.extract_sbom_from_payload(
                &coords_owned,
                &coords_owned.metadata,
                PayloadAccess::ReadStream(Box::new(bridge)),
            )
        })
        .await;

        // A handler error and a panicked extraction task are the same
        // fact to an operator — the payload was reachable and no usable
        // component list came out of it — so they are normalised to one
        // reason string and share one degradation arm. Both are
        // deterministic over the same bytes, which is what puts them on
        // `Unreadable` rather than on the retryable arm above.
        let extraction = match joined {
            Ok(inner) => inner.map_err(|e| e.to_string()),
            Err(join) => Err(format!("extraction task did not complete: {join}")),
        };
        let extraction = match extraction {
            Ok(extraction) => extraction,
            Err(reason) => {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    format_key,
                    reason,
                    "payload SBOM extraction produced nothing usable; proceeding with no SBOM",
                );
                emit_sbom_extraction(format_key, SbomExtractionResult::ParseError);
                emit_sbom_resolution(format_key, SbomResolutionResult::UnusableLockfile);
                return SbomExtraction::Absent(SbomAbsence::Unreadable);
            }
        };

        emit_sbom_resolution(format_key, extraction.resolution.into());
        if extraction.skipped_non_registry > 0 {
            emit_sbom_components_skipped(format_key, extraction.skipped_non_registry as u64);
        }
        match extraction.sbom {
            Some(sbom) => {
                emit_sbom_extraction(format_key, SbomExtractionResult::Success);
                SbomExtraction::Extracted(sbom)
            }
            // The handler reached the payload and declares it carries no
            // dependency information — the same answer an opaque format
            // gives, and a completed fact rather than a failure.
            None => {
                emit_sbom_extraction(format_key, SbomExtractionResult::UnsupportedFormat);
                SbomExtraction::Absent(SbomAbsence::NotDeclared)
            }
        }
    }

    /// Everything the SBOM step needs off the artifact's repository row,
    /// resolved in the single `find_by_id` this path already pays for:
    /// the coords a format handler speaks. Reading the row here rather
    /// than re-querying keeps the scan at one repository lookup.
    async fn subject_for_artifact(&self, artifact: &Artifact) -> AppResult<ScanSubject> {
        let repo = self.repositories.find_by_id(artifact.repository_id).await?;
        // `format_metadata` on `extract_sbom` is the
        // JSON the format handler extracted at ingest time. The
        // `ArtifactMetadata` projection row carries it; the orchestrator
        // must thread it onto `ArtifactCoords` so Tier-A handlers
        // (npm/PyPI/Cargo) produce a non-empty SBOM. When the row is
        // absent (proxied fetch with no parsed body — a legitimate v1
        // case) the fallback is `Value::Null`, which the handlers'
        // early-returns interpret as "opaque payload, empty SBOM".
        let metadata = self
            .artifact_metadata
            .find_by_artifact_id(artifact.id)
            .await?
            .map(|row| row.metadata)
            .unwrap_or(serde_json::Value::Null);
        Ok(ScanSubject {
            coords: ArtifactCoords {
                name: artifact.name.clone(),
                name_as_published: artifact.name_as_published.clone(),
                version: artifact.version.clone(),
                path: artifact.path.clone(),
                format: repo.format,
                metadata,
            },
        })
    }

    /// Best-effort `scanner` audit label for the
    /// retry-exhausted `Failed` arm. The configured backends are not
    /// carried on `ScanRunOutcome::Failed` (it only holds the last
    /// error string), so resolve them from the artifact's policy chain
    /// the same way `run_scan` does. Any failure to resolve degrades to
    /// the `"(none)"` sentinel when backend resolution itself fails —
    /// the label is audit-only, never an invariant, so a degraded label
    /// must not abort the fail-closed transition.
    async fn scanner_label_for_failed(&self, job: &ScanJob) -> String {
        let repo_id = match self.artifacts.find_by_id(job.artifact_id).await {
            Ok(a) => a.repository_id,
            Err(_) => return "(none)".to_string(),
        };
        let backends =
            match resolve_active_policy_for_repo(&*self.policy_projections, repo_id).await {
                Ok(Some(p)) if !p.scan_backends.is_empty() => p.scan_backends,
                Ok(Some(_)) => Vec::new(),
                Ok(None) => DefaultPolicy::block_on_critical_default_backends(),
                Err(_) => return "(none)".to_string(),
            };
        if backends.is_empty() {
            "(none)".to_string()
        } else {
            backends.join(",")
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (testable without the full use case)
// ---------------------------------------------------------------------------

/// The join between a scan's findings and the artifact they were found
/// on — **the one place** `Finding.component_relation` is decided.
///
/// # Why here and not in the producers
///
/// There are three producers of findings in this pipeline (two scanner
/// adapters and the advisory-enrichment path) and they all return into
/// `run_scan` with the same SBOM still in hand. A rule typed once per
/// producer is the shape `crates/hort-app/tests/https_rule_is_single_sourced.rs`
/// exists to prevent: the https-metadata rule had been re-typed five
/// times before the consumer that carried no copy at all turned up. The
/// adapters also sit below the format layer (ADR 0008) and cannot ask a
/// `FormatHandler` whether the payload contains its components.
///
/// This pass writes **one** fact and no longer touches the other. A
/// finding's [`FindingStatement`] is the producer's own half of
/// ADR 0064 D2's line and arrives already stated; *whose* filesystem the
/// claim is about is the row's [`ArtifactKind`], which
/// [`Finding::may_condemn_artifact`] composes where it decides rather
/// than anything storing the two already joined (ADR 0040 — see that
/// predicate). So there is nothing for this pass to place, and the
/// statement field is read-only outside the file that defines it.
///
/// # The rule
///
/// The join key is the one [`hort_domain::types::SbomComponent`]'s own
/// rustdoc declares, `Finding.purl == SbomComponent.purl`, compared
/// verbatim and case-sensitively (the convention `merge_findings` and
/// `compute_added_findings` already use for a PURL).
///
/// 1. The finding names the BOM's **subject** — the artifact itself, so
///    [`ComponentRelation::Subject`].
/// 2. The finding names a **listed component**. Whether the artifact
///    carries that component's code is a property of the format, asked of
///    the handler that declares it
///    ([`FormatHandler::payload_contains_components`]): `Contained` for a
///    payload that carries its closure, `NotContained` for one whose BOM
///    merely *names* what a consumer will resolve elsewhere.
/// 3. The finding names **nothing in the BOM**, and here the two kinds of
///    producer mean opposite things — see [`EvidenceBasis`]. A backend
///    that materialised the artifact's bytes found the package *in* the
///    artifact, so `Contained`; a backend whose whole input was the BOM
///    cannot have found it anywhere else, so the join failed and the
///    relation is `NotEstablished`, which the counter then shows. Reading
///    the first case as a failed join instead would silently disarm every
///    payload-scanner finding the BOM happens not to list.
///
/// A scan with no SBOM at all (no handler, an opaque format, a failed
/// extraction) lands on rule 3 for the same reason: there is nothing to
/// join against, so the producer's evidence is all there is.
struct ComponentRelations<'a> {
    /// The BOM this scan extracted, if any.
    sbom: Option<&'a Sbom>,
    /// [`FormatHandler::payload_contains_components`] for this
    /// artifact's format.
    payload_contains_components: bool,
    /// Format key — the `format` label on the relation counter.
    format: &'a str,
}

impl ComponentRelations<'_> {
    /// Decide one finding's relation. Pure: the counter is emitted by
    /// [`Self::tag`], so this can be asserted directly.
    fn relation_for(&self, purl: &str, evidence: EvidenceBasis) -> ComponentRelation {
        let Some(sbom) = self.sbom else {
            return Self::unjoined(evidence);
        };
        if sbom.subject.as_ref().is_some_and(|s| s.purl == purl) {
            return ComponentRelation::Subject;
        }
        if sbom.components.iter().any(|c| c.purl == purl) {
            return if self.payload_contains_components {
                ComponentRelation::Contained
            } else {
                ComponentRelation::NotContained
            };
        }
        Self::unjoined(evidence)
    }

    /// Rule 3: what a purl the BOM does not name means, which only the
    /// producer's evidence can answer.
    fn unjoined(evidence: EvidenceBasis) -> ComponentRelation {
        match evidence {
            EvidenceBasis::MaterialisedPayload => ComponentRelation::Contained,
            EvidenceBasis::SuppliedSbom => ComponentRelation::NotEstablished,
        }
    }

    /// Tag a producer's batch and emit
    /// `hort_finding_component_relation_total{format, result}` once per
    /// finding, before the cross-backend dedup — a tagging decision a
    /// merge later discards was still made, and the counter's job is to
    /// show the `not_established` rate honestly.
    fn tag(&self, findings: Vec<Finding>, evidence: EvidenceBasis) -> Vec<Finding> {
        findings
            .into_iter()
            .map(|mut f| {
                let relation = self.relation_for(&f.purl, evidence);
                emit_component_relation(self.format, relation);
                f.component_relation = relation;
                f
            })
            .collect()
    }
}

/// Deduplicate a finding set by `(purl, vulnerability_id)`. Collision
/// preference (see [`prefer_replacement`]): a recognised-informational
/// reading (no CVSS) wins over an UNSCORED non-informational finding for the
/// same advisory — so a backend that cannot read the RustSec class and fails
/// the unscored advisory closed to Critical does not discard the
/// classification. Then an *informed* reading wins over an *uninformed* one
/// across tiers (ADR 0059), unless `allow_informed_downgrade` is off.
/// Otherwise severity tier wins (`Critical > … > Low`); ties
/// prefer `Some(cvss_score)` over `None`; remaining ties keep the first-seen
/// entry. A SCORED finding is never informational, so it is never downgraded
/// by this preference. Vulnerability id matching is case-insensitive; PURL
/// matching is case-sensitive (matches `compute_added_findings`'s convention).
///
/// The surviving row's `component_relation` is resolved separately from the
/// ranking — see the collision arm below.
pub(crate) fn merge_findings(input: Vec<Finding>, allow_informed_downgrade: bool) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::with_capacity(input.len());
    let mut seen: Vec<(String, String, usize)> = Vec::with_capacity(input.len());
    for f in input {
        let purl = f.purl.clone();
        let vuln_lower = f.vulnerability_id.to_ascii_lowercase();
        if let Some(idx) = seen
            .iter()
            .find(|(p, v, _)| p == &purl && v == &vuln_lower)
            .map(|(_, _, idx)| *idx)
        {
            // Collision — apply the merge preference.
            //
            // The relation is resolved alongside the ranking, not by it.
            // `prefer_replacement` ranks severity, information quality and
            // CVSS and deliberately never reads the component relation,
            // so the winner's relation would otherwise be whichever the
            // severity comparison happened to carry along — and after the
            // release gate reads the relation, that is a verdict decided
            // on an axis nobody compared. The survivor keeps the more
            // condemning of the two instead
            // (`ComponentRelation::more_condemning`, the single
            // definition of that order): authority is withheld only where
            // non-containment was actually established. Applied before
            // the replacement so it holds whichever row wins, and folded
            // pairwise, so a third backend reporting the same advisory
            // cannot walk it back down.
            let existing = &out[idx];
            let relation = existing
                .component_relation
                .more_condemning(f.component_relation);
            if prefer_replacement(existing, &f, allow_informed_downgrade) {
                out[idx] = f;
            }
            out[idx].component_relation = relation;
        } else {
            let idx = out.len();
            out.push(f);
            seen.push((purl, vuln_lower, idx));
        }
    }
    out
}

/// Decide whether `incoming` should replace `existing` in the
/// dedup-merge step.
///
/// `allow_informed_downgrade` is the operator break-glass switch
/// (`HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE`, default `true`). With it
/// off, the information-quality rule below is skipped and the comparison
/// falls straight through to severity tier — the strict always-fail-closed
/// behaviour that predates ADR 0059. It is read here, on the merge path,
/// because a config field the consumer ignores is an inert operator
/// surface (ADR 0015).
///
/// **`component_relation` is deliberately not an input here.** Ranking on
/// it would re-key the merge: a weakly-claimed Low would then outrank a
/// well-evidenced Critical and the surviving row would carry a severity no
/// backend reached, which is the failure ADR 0059's ordering exists to
/// prevent. Which row survives is a question about information quality;
/// which relation it carries is a separate one, resolved beside this call
/// in [`merge_findings`].
fn prefer_replacement(
    existing: &Finding,
    incoming: &Finding,
    allow_informed_downgrade: bool,
) -> bool {
    // Informational classification preference (ADR 0040). For the same
    // advisory, a finding carrying a recognised RustSec informational class
    // (`is_informational()` — unmaintained / unsound / notice, and no CVSS)
    // is the authoritative reading. It beats an UNSCORED non-informational
    // finding for the same id — e.g. a backend (Trivy) that cannot read the
    // class and fails the unscored advisory closed to Critical (SUP-4).
    // Without this, that cosmetic Critical wins the severity-tier rule below
    // and silently discards the classification, defeating the negligible
    // lane (the cross-backend fail-open). A SCORED finding (real CVSS) is
    // never `is_informational()`, so these arms never fire against it — it
    // falls through to the severity / score rules and is never downgraded
    // (ADR 0007 fail-closed preserved).
    match (existing.is_informational(), incoming.is_informational()) {
        (true, false) if incoming.cvss_score.is_none() => return false,
        (false, true) if existing.cvss_score.is_none() => return true,
        _ => {}
    }

    // Information-quality preference (ADR 0059). A finding is *informed*
    // when the producing backend actually read a severity — a real CVSS,
    // a recognised informational class, or a `SeverityBasis::Assessed`
    // marker. The complement is a finding whose `Critical` is the SUP-4
    // fail-closed floor: the backend could not read a severity at all, so
    // the tier says nothing about the advisory. An informed reading
    // supersedes an uninformed one ACROSS TIERS — a scored Medium beats
    // an unassessed Critical — because keeping the floor would discard the
    // only real information anyone has about this advisory and strand the
    // artifact on a verdict no backend actually reached.
    //
    // Two informed findings fall through to the severity comparison
    // below, so a scored Critical is never talked down by a scored Low
    // (ADR 0007 fail-closed preserved). Legacy findings persisted before
    // `severity_basis` existed deserialise as `Assessed`, so they are
    // informed and this rule never demotes one.
    //
    // Accepted residual risk: where two backends disagree and the lower
    // reading is the wrong one, a wrong Low now outranks the other's
    // unknown-defaulted Critical. That is the deliberate trade — an
    // unassessed Critical is not evidence of severity, and treating it as
    // such kept correctly-scored advisories terminally rejected.
    if allow_informed_downgrade {
        match (existing.is_informed(), incoming.is_informed()) {
            (false, true) => return true,
            (true, false) => return false,
            _ => {}
        }
    }

    let existing_tier = severity_tier(existing.severity);
    let incoming_tier = severity_tier(incoming.severity);
    if incoming_tier < existing_tier {
        // Lower tier number = higher severity (Critical = 0).
        true
    } else if incoming_tier > existing_tier {
        false
    } else {
        // Tier tie — prefer `Some(cvss_score)` over `None`.
        existing.cvss_score.is_none() && incoming.cvss_score.is_some()
    }
}

fn severity_tier(s: SeverityThreshold) -> u8 {
    match s {
        SeverityThreshold::Critical => 0,
        SeverityThreshold::High => 1,
        SeverityThreshold::Medium => 2,
        SeverityThreshold::Low => 3,
    }
}

// Tests live in the sibling module file `scan_orchestration_tests.rs`
// for readability — the pure-helper + happy-path + per-branch + Path-B
// regression tests run to nearly 600 lines, comparable in size to the
// quarantine_use_case test module.
#[cfg(test)]
#[path = "scan_orchestration_tests.rs"]
mod tests;
