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
use hort_domain::entities::repository::RepositoryType;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::error::DomainError;
use hort_domain::policy::scan::DefaultPolicy;
use hort_domain::ports::advisory::AdvisoryPort;
use hort_domain::ports::artifact_metadata_repository::ArtifactMetadataRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::jobs_repository::{JobsRepository, ScanJob};
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::scanner::{ScannerPort, SCAN_REPORT_TOO_LARGE_MARKER};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{severity_label, ArtifactCoords, Finding, PayloadAccess, Sbom};

use crate::error::AppResult;
use crate::metrics::{
    emit_sbom_components_skipped, emit_sbom_extraction, emit_sbom_resolution, emit_scan_failure,
    emit_scan_findings, emit_scan_jobs, emit_scan_terminal, observe_scan_duration,
    SbomExtractionResult, SbomResolutionResult, ScanFailureResult, ScanJobsResult,
    ScanTerminalResult,
};
use crate::use_cases::policy_resolution::resolve_active_policy_for_repo;
use crate::use_cases::quarantine_use_case::QuarantineUseCase;

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

/// Default cap on the number of attempts before a job is moved to the
/// terminal `failed` status. Mirrors `HORT_SCANNER_MAX_ATTEMPTS`.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

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
}

impl ScanOrchestrationConfig {
    /// Sensible defaults for tests; production overrides via the
    /// worker's env-derived `WorkerConfig`.
    pub fn defaults_for_worker(worker_id: impl Into<String>) -> Self {
        Self {
            worker_id: worker_id.into(),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            default_scan_backends: Vec::new(),
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
        /// Deduplicated findings in scanner-emit order.
        findings: Vec<Finding>,
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
    SkippedNoBackends,
    /// Every configured backend errored. `record_outcome` reschedules
    /// or marks failed based on the job's attempt count.
    Failed(String),
}

/// The artifact's repository row, reduced to the two facts the SBOM
/// step reads off it. Resolved once per scan by
/// [`ScanOrchestrationUseCase::subject_for_artifact`].
struct ScanSubject {
    coords: ArtifactCoords,
    /// Decides whether the payload-closure SBOM path applies — see
    /// [`ScanOrchestrationUseCase::try_extract_sbom`] for why the
    /// answer depends on the repository class rather than the format
    /// alone.
    repo_type: RepositoryType,
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
    scanners: HashMap<String, Arc<dyn ScannerPort>>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
    quarantine: Arc<QuarantineUseCase>,
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
        scanners: HashMap<String, Arc<dyn ScannerPort>>,
        handlers: HashMap<String, Arc<dyn FormatHandler>>,
        quarantine: Arc<QuarantineUseCase>,
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
            scanners,
            handlers,
            quarantine,
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
                return Ok(ScanRunOutcome::SkippedNoBackends);
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
            return Ok(ScanRunOutcome::SkippedNoBackends);
        }

        // Step 3-5: extract SBOM via the format handler (best-effort).
        let subject = self.subject_for_artifact(&artifact).await?;
        let sbom = self
            .try_extract_sbom(&artifact, &subject, &job.format)
            .await;

        // Step 6: pre-scan advisory enrichment (best-effort).
        //
        // Advisory enrichment must cover BOTH the subject (the artifact
        // itself, e.g. lodash@4.17.20) and every dependency in
        // `components`. Iterating only over `components` is the bug
        // that would leave leaf packages undetected.
        let advisory_findings: Vec<Finding> = match sbom.as_ref() {
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

        // Step 7-8: invoke each configured backend in declared order.
        // `hort_scan_duration_seconds{scanner}` brackets
        // exactly the `ScannerPort::scan` call (start before, observe
        // after). Adjacent dedup / CAS persist run outside the timer.
        let mut accumulated: Vec<Finding> = advisory_findings;
        let mut contributors: Vec<String> = Vec::new();
        let mut total_attempted: u32 = 0;
        let mut total_failed: u32 = 0;
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
            let started = Instant::now();
            let scan_result = scanner.scan(&artifact.sha256_checksum, sbom.as_ref()).await;
            observe_scan_duration(backend, started.elapsed());
            match scan_result {
                Ok(mut findings) => {
                    contributors.push(backend.clone());
                    accumulated.append(&mut findings);
                    tracing::info!(
                        artifact_id = %artifact.id,
                        scanner = backend,
                        finding_count = accumulated.len(),
                        "scan completed",
                    );
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
        // If every configured backend errored, treat as Failed.
        if total_attempted > 0 && total_failed == total_attempted {
            return Ok(ScanRunOutcome::Failed(format!(
                "all {total_attempted} scan backends failed for artifact {}",
                artifact.id
            )));
        }

        // Step 9: dedupe across backends + advisory.
        let merged = merge_findings(accumulated);
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
            findings: merged,
            sbom,
        })
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
            ScanRunOutcome::SkippedNoBackends => {
                // Emit a clean ScanCompleted via the consumer. The
                // reject path is a no-op for zero findings; the
                // delta path is a no-op when both prior and current
                // findings are empty.
                //
                // No SBOM is extracted on the
                // skipped-no-backends path (we never reached step 3),
                // so the consumer is invoked with `sbom = None` and
                // the `sbom_components` projection write is skipped.
                self.quarantine
                    .record_scan_result(job.artifact_id, "(none)".to_string(), Vec::new(), None)
                    .await?;
                // H17 — scan's forensics are the ScanCompleted event + the
                // findings projection; the JSON `result_summary`
                // (`{scanner, finding_count}`) is built by ScanTaskHandler and
                // persisted by the dispatcher's own (second, authoritative,
                // idempotent) mark_completed call, so pass Null here.
                self.jobs
                    .mark_completed(job.id, serde_json::Value::Null)
                    .await?;
                emit_scan_jobs(ScanJobsResult::Completed);
                // Operator-waiver clean outcome.
                emit_scan_terminal(ScanTerminalResult::Completed);
                Ok(())
            }
            ScanRunOutcome::Completed {
                scanner,
                findings,
                sbom,
            } => {
                // Classify the artifact-terminal
                // decision BEFORE the consumer moves `findings`: a
                // non-empty finding set rejects the artifact; an empty
                // one is a clean completion. (The consumer owns the
                // actual reject transition; this only labels the
                // terminal-outcome counter — one metric, one layer.)
                let terminal = if findings.is_empty() {
                    ScanTerminalResult::Completed
                } else {
                    ScanTerminalResult::Rejected
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
                    .record_scan_result(job.artifact_id, scanner, findings, sbom.as_ref())
                    .await?;
                // H17 — scan's forensics are the ScanCompleted event + the
                // findings projection; the JSON `result_summary`
                // (`{scanner, finding_count}`) is built by ScanTaskHandler and
                // persisted by the dispatcher's own (second, authoritative,
                // idempotent) mark_completed call, so pass Null here.
                self.jobs
                    .mark_completed(job.id, serde_json::Value::Null)
                    .await?;
                emit_scan_jobs(ScanJobsResult::Completed);
                emit_scan_terminal(terminal);
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
                        self.jobs.mark_failed(job.id, &err).await?;
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
                        self.jobs.mark_failed(job.id, &err).await?;
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
                    self.jobs.reschedule(job.id, backoff, &err).await?;
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
    /// components from the payload
    /// (`FormatHandler::payload_sbom() == Some(_)`) **and** the artifact
    /// lives in a [`RepositoryType::Hosted`] repository.
    ///
    /// # Why the repository class gates the payload path
    ///
    /// An archive like a `.crate` does not contain its dependencies'
    /// code, so a finding derived from its embedded lockfile is a claim
    /// about code that is **not in the artifact** — unlike a container
    /// image, where the scanner reads the vulnerable bytes themselves.
    /// The evidentiary weight of that claim depends on who wrote the
    /// lockfile:
    ///
    /// - **Hosted** — the lockfile is the authenticated publisher's own
    ///   build witness. Holding their release gate to it is the point:
    ///   they resolved those versions, they shipped them.
    /// - **Proxy / virtual / staging** — the lockfile is the upstream
    ///   author's dev-time resolve. Consumers of a library re-resolve
    ///   and never run it, so a stale upstream resolve would carry gate
    ///   power (the shipped default is `enforcement: reject`) over a
    ///   crate every consumer would resolve safely — the
    ///   false-positive-with-gate-power class this path exists to
    ///   remove, reintroduced on the other face.
    ///
    /// The known counter-nuance, deliberately left open rather than
    /// decided here: a **binary** crate installed with
    /// `cargo install --locked` really does run its embedded resolve,
    /// so for bins the upstream signal is real — but bin and lib cannot
    /// be told apart cheaply at scan time.
    ///
    /// Note that `Staging` is excluded even though
    /// [`RepositoryType::is_hosted`] counts it as upload-accepting: the
    /// gate is a literal `Hosted` match, not that predicate.
    ///
    /// Two counters fire exactly once per call and answer different
    /// questions: `hort_sbom_extraction_total{format, result}` — did a
    /// BOM come out — and `hort_sbom_resolution_total{format, result}` —
    /// on what basis were its component versions derived. The
    /// `unsupported_format` arm of the first covers both "no handler
    /// registered for this format" and "handler returned `Ok(None)`":
    /// both surface to operators as "this format does not produce an
    /// SBOM" with no actionable distinction. The second's `hosted_only`
    /// arm is the gate above firing.
    ///
    /// **Fail-soft.** Nothing here can fail the scan run. A storage read
    /// that fails degrades to the same no-SBOM path a format with no
    /// handler takes, with the metric saying which happened. ADR 0007's
    /// fail-closed rule governs release *authority*; SBOM enrichment is
    /// not authority, and letting a CAS hiccup abort a scan would trade a
    /// thinner BOM for no scan at all.
    async fn try_extract_sbom(
        &self,
        artifact: &Artifact,
        subject: &ScanSubject,
        format_key: &str,
    ) -> Option<Sbom> {
        let Some(handler) = self.handlers.get(format_key) else {
            emit_sbom_extraction(format_key, SbomExtractionResult::UnsupportedFormat);
            emit_sbom_resolution(format_key, SbomResolutionResult::NotApplicable);
            return None;
        };

        let resolution = if handler.payload_sbom().is_none() {
            // Metadata-only format — there is no resolved-dependency
            // document to look for in the first place.
            SbomResolutionResult::NotApplicable
        } else if matches!(subject.repo_type, RepositoryType::Hosted) {
            let handler = Arc::clone(handler);
            return self
                .extract_sbom_from_stored_payload(handler, artifact, &subject.coords, format_key)
                .await;
        } else {
            SbomResolutionResult::HostedOnly
        };

        // The metadata-only path — reached by a format that never
        // consumes the payload, and by a payload-consuming format whose
        // repository class the gate above turned away. Unchanged from
        // before the payload path existed: no storage read, and the
        // empty-payload call the handlers have always ignored.
        emit_sbom_resolution(format_key, resolution);
        match handler.extract_sbom(
            &subject.coords,
            &subject.coords.metadata,
            PayloadAccess::Bytes(&[]),
        ) {
            Ok(Some(sbom)) => {
                emit_sbom_extraction(format_key, SbomExtractionResult::Success);
                Some(sbom)
            }
            Ok(None) => {
                emit_sbom_extraction(format_key, SbomExtractionResult::UnsupportedFormat);
                None
            }
            Err(e) => {
                emit_sbom_extraction(format_key, SbomExtractionResult::ParseError);
                tracing::warn!(
                    format_key,
                    error = %e,
                    "extract_sbom failed; proceeding with no SBOM",
                );
                None
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
    ) -> Option<Sbom> {
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
                return None;
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
        // reason string and share one degradation arm.
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
                return None;
            }
        };

        emit_sbom_resolution(format_key, extraction.resolution.into());
        if extraction.skipped_non_registry > 0 {
            emit_sbom_components_skipped(format_key, extraction.skipped_non_registry as u64);
        }
        match extraction.sbom {
            Some(sbom) => {
                emit_sbom_extraction(format_key, SbomExtractionResult::Success);
                Some(sbom)
            }
            None => {
                emit_sbom_extraction(format_key, SbomExtractionResult::UnsupportedFormat);
                None
            }
        }
    }

    /// Everything the SBOM step needs off the artifact's repository row,
    /// resolved in the single `find_by_id` this path already pays for:
    /// the coords a format handler speaks, plus the repository class
    /// that decides whether the payload-closure path applies at all.
    /// Reading the type here rather than re-querying keeps the scan at
    /// one repository lookup.
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
            repo_type: repo.repo_type,
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

/// Backoff schedule for `record_outcome`'s `Failed` branch.
///
/// `attempts` is the value already on the job row at the time of the
/// failure (the post-claim, pre-decision number). The schedule:
///
/// - `attempts == 1` → 1 minute
/// - `attempts == 2` → 5 minutes
/// - `attempts == 3` → 30 minutes
/// - `attempts == 4` → 60 minutes
/// - `attempts >= 5` → 60 minutes (defensive cap; `max_attempts == 5`
///   default would have routed to `mark_failed` instead)
/// - `attempts == 0` → 1 minute (defensive — `claim_scan_jobs`
///   increments attempts before we observe the row, so this branch is
///   not normally reached).
pub fn compute_backoff(attempts: u32) -> Duration {
    match attempts {
        0 | 1 => Duration::from_secs(60),
        2 => Duration::from_secs(5 * 60),
        3 => Duration::from_secs(30 * 60),
        _ => Duration::from_secs(60 * 60),
    }
}

/// Deduplicate a finding set by `(purl, vulnerability_id)`. Collision
/// preference (see [`prefer_replacement`]): a recognised-informational
/// reading (no CVSS) wins over an UNSCORED non-informational finding for the
/// same advisory — so a backend that cannot read the RustSec class and fails
/// the unscored advisory closed to Critical does not discard the
/// classification. Otherwise severity tier wins (`Critical > … > Low`); ties
/// prefer `Some(cvss_score)` over `None`; remaining ties keep the first-seen
/// entry. A SCORED finding is never informational, so it is never downgraded
/// by this preference. Vulnerability id matching is case-insensitive; PURL
/// matching is case-sensitive (matches `compute_added_findings`'s convention).
fn merge_findings(input: Vec<Finding>) -> Vec<Finding> {
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
            // Collision — apply severity-tier preference.
            let existing = &out[idx];
            if prefer_replacement(existing, &f) {
                out[idx] = f;
            }
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
fn prefer_replacement(existing: &Finding, incoming: &Finding) -> bool {
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
