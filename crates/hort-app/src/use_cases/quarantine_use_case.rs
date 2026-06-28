use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::{
    Artifact, ProvenanceClearance, QuarantineStatus, ReleaseAuthorization,
};
use hort_domain::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection};
use hort_domain::error::DomainError;
use hort_domain::events::{system_actor, timer_actor};
use hort_domain::events::{
    Actor, ApiActor, ArtifactBecameVulnerable, DomainEvent, IngestSource, PolicyEvaluated,
    PolicyResult, PolicyScope, ReleaseReason, ScanCompleted, StreamId, NO_POLICY,
};
use hort_domain::policy::scan_delta::compute_added_findings;
use hort_domain::policy::{
    effective_quarantine_deadline, evaluate_scan_result, DefaultPolicy, ScanOutcome,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ReadFrom};
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::upstream_index_cache_invalidator::UpstreamIndexCacheInvalidator;

use crate::event_store_publisher::EventStorePublisher;
use crate::use_cases::upstream_index_cache_invalidator::invalidate_after_reject;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::scan_findings_repository::ScanFindingsRow;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::sbom::Sbom;
use hort_domain::types::{
    highest_severity, severity_label, severity_summary_from_findings, ArtifactCoords, ContentHash,
    Finding,
};
use tokio::io::AsyncReadExt;

use hort_domain::ports::repo_security_score_repository::ScoreDelta;

use crate::error::{AppError, AppResult};
use crate::metrics::{
    emit_artifact_became_vulnerable, emit_policy_evaluation, emit_policy_violations, labels,
    policy_decision_point, values, PolicyEvaluationResult,
};
use crate::projectors::repo_security_score::RepoSecurityScoreProjector;
use crate::use_cases::{read_expected_version, CallerPrivileges};

/// The static authority-kind label for the timer-release
/// `info!` line. Only the two timer-authorities reach this:
/// `AdminOverride` / `PolicyReEvaluation` never pair with
/// `ReleaseReason::Timer` (they would be rejected by the domain
/// predicate before producing an event), and the resolver only ever
/// returns `ScanSucceeded` / `ScanWaived`. The remaining arms are an
/// exhaustive-match guard, not a reachable path.
fn release_authority_label(authz: ReleaseAuthorization) -> &'static str {
    match authz {
        ReleaseAuthorization::ScanSucceeded => "scan_succeeded",
        ReleaseAuthorization::ScanWaived => "scan_waived",
        ReleaseAuthorization::AdminOverride => "admin_override",
        ReleaseAuthorization::PolicyReEvaluation => "policy_re_evaluation",
        // Curator-waive surface label. The
        // `QuarantineUseCase` release paths do not currently construct
        // this token (curator-waive is `CurationUseCase`'s
        // surface); the arm is required for exhaustive-match.
        ReleaseAuthorization::CuratorWaiver => "curator_waiver",
    }
}

/// Emit `hort_quarantine_released_total` with the given reason.
fn emit_release(reason: &'static str) {
    metrics::counter!(
        "hort_quarantine_released_total",
        labels::REASON => reason,
    )
    .increment(1);
}

/// Map per-finding values onto the `scan_findings` projection row
/// shape. `scan_id` correlates the rows with the
/// `ScanCompleted` event in the same atomic batch.
fn build_scan_findings_rows(
    findings: &[Finding],
    artifact_id: Uuid,
    scan_id: Uuid,
    detected_at: DateTime<Utc>,
) -> Vec<ScanFindingsRow> {
    findings
        .iter()
        .map(|f| ScanFindingsRow {
            artifact_id,
            scan_id,
            purl: f.purl.clone(),
            vulnerability_id: f.vulnerability_id.clone(),
            severity: f.severity,
            cvss_score: f.cvss_score,
            source_scanner: f.source_scanner.clone(),
            title: f.title.clone(),
            detected_at,
            informational_class: f.informational_class.clone(),
        })
        .collect()
}

/// Cap on the serialised `findings_blob` byte length. This consumer is
/// the single CAS write site for the findings blob, so this cap is the
/// canonical enforcement point. 8 MiB.
const FINDINGS_BLOB_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Cap on the number of events read when scanning for the prior
/// `ScanCompleted`. Mirrors `use_cases::STREAM_EVENT_CAP` (200).
const STREAM_READ_LIMIT: u64 = 200;

/// Wire string for the `ingest_source` label.
/// Mirrors the `IngestSource` enum (`Direct` / `Proxied`). Returns
/// the `"unknown"` sentinel when the artifact's stream did not carry
/// an `ArtifactIngested` (defensive — every artifact stream begins
/// with one).
fn ingest_source_label(s: Option<IngestSource>) -> &'static str {
    match s {
        Some(IngestSource::Direct) => "direct",
        Some(IngestSource::Proxied) => "proxied",
        None => "unknown",
    }
}

/// Application use case for quarantine lifecycle operations.
pub struct QuarantineUseCase {
    artifacts: Arc<dyn ArtifactRepository>,
    events: Arc<EventStorePublisher>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    repositories: Arc<dyn RepositoryRepository>,
    policy_projections: Arc<dyn PolicyProjectionRepository>,
    /// Refcount projection. The
    /// reject paths (`record_scan_result` Reject branch) sweep every
    /// `content_references` row whose `source_artifact_id` matches the
    /// rejected artifact, mirroring the ingest-path warn-on-fail
    /// posture: a transient PG outage between the lifecycle commit and
    /// the refcount sweep does NOT abort the rejection (the artifact
    /// row is the authoritative state). The
    /// `RefcountReconcileUseCase` sweep heals any drift before
    /// `PurgeUseCase` runs. Stored as the raw port handle (not the
    /// `ContentReferenceUseCase` wrapper) for the same reason as
    /// `IngestUseCase`: composition order — the wrapper is built later.
    content_references: Arc<dyn ContentReferenceIndex>,
    /// The per-finding `Vec<Finding>` is JSON-serialised
    /// and written to CAS via `StoragePort::put`; the returned
    /// `ContentHash` lands on `ScanCompleted.findings_blob`.
    /// This field was previously
    /// `Option<…>` to permit a split constructor that omitted the
    /// scan-result ports; the runtime invariant
    /// `DomainError::Invariant("QuarantineUseCase missing StoragePort
    /// …")` then surfaced as a misconfiguration error from
    /// `persist_findings_blob`. The split is gone — every
    /// composition wires storage up front.
    storage: Arc<dyn StoragePort>,
    /// `METRICS_INCLUDE_REPOSITORY_LABEL` toggle (metrics-catalog
    /// cardinality precedent). When `false`, `hort_artifact_became_vulnerable_total`
    /// emits `repository="_all"` rather than the per-repo key, dropping
    /// the cardinality ceiling from `≤10k × 4 × 2 = 80k` to `4 × 2 =
    /// 8`. Defaults to `true` so existing constructors stay
    /// source-compatible; the composition root flips it via
    /// [`Self::with_include_repository_label`].
    include_repository_label: bool,
    /// Optional invalidator for cached
    /// upstream packument / simple-index entries on `ArtifactRejected`.
    /// `None` keeps the use case constructable without the dependency
    /// (most test harnesses); production wires it via
    /// [`Self::with_upstream_index_cache_invalidator`]. See the curator-
    /// block site's `upstream_index_cache_invalidator` field on
    /// `CurationUseCase` for the design rationale (mirror).
    upstream_index_cache_invalidator: Option<Arc<dyn UpstreamIndexCacheInvalidator>>,
}

impl QuarantineUseCase {
    /// Construct a fully-wired `QuarantineUseCase`. Threads the
    /// storage port the dual-write path (`record_scan_result`)
    /// requires; non-scan paths (`quarantine_artifact`,
    /// `admin_release`, `release_expired`) don't read it but it must
    /// still be supplied so a composition root can never accidentally
    /// end up on the misuse path that surfaced as
    /// `DomainError::Invariant("QuarantineUseCase missing
    /// StoragePort; …")` (the previous
    /// split-constructor design has been collapsed).
    ///
    /// The per-finding `ScanFindingsRow`
    /// projection is persisted by the lifecycle port's
    /// `commit_scan_result_with_score`; this constructor no longer
    /// holds a separate `ScanFindingsRepository` handle.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        events: Arc<EventStorePublisher>,
        lifecycle: Arc<dyn ArtifactLifecyclePort>,
        repositories: Arc<dyn RepositoryRepository>,
        policy_projections: Arc<dyn PolicyProjectionRepository>,
        content_references: Arc<dyn ContentReferenceIndex>,
        storage: Arc<dyn StoragePort>,
    ) -> Self {
        Self {
            artifacts,
            events,
            lifecycle,
            repositories,
            policy_projections,
            content_references,
            storage,
            include_repository_label: true,
            upstream_index_cache_invalidator: None,
        }
    }

    /// Install the upstream packument /
    /// simple-index cache invalidator. Called from the composition
    /// root after [`Self::new`]; without it, the post-`record_scan_result`
    /// Reject-branch cache-invalidation hook is a no-op. Builder-
    /// shaped exactly like [`Self::with_include_repository_label`].
    #[must_use]
    pub fn with_upstream_index_cache_invalidator(
        mut self,
        invalidator: Arc<dyn UpstreamIndexCacheInvalidator>,
    ) -> Self {
        self.upstream_index_cache_invalidator = Some(invalidator);
        self
    }

    /// Set the `METRICS_INCLUDE_REPOSITORY_LABEL` toggle
    /// (metrics-catalog cardinality precedent). The composition root reads
    /// `Config::include_repository_label` and forwards it via this
    /// builder; when `false`, `hort_artifact_became_vulnerable_total`
    /// emits `repository="_all"`.
    #[must_use]
    pub fn with_include_repository_label(mut self, include: bool) -> Self {
        self.include_repository_label = include;
        self
    }

    /// Place an artifact into quarantine.
    ///
    /// Reads the event stream to enforce the 200-event cap and determine
    /// expected version for optimistic concurrency, then transitions the
    /// artifact state machine and persists both the event and the mutated
    /// artifact.
    ///
    /// **Actor type is a placeholder.** Currently accepts `ApiActor`, but
    /// quarantine is not a user action — it is a system-driven reaction
    /// triggered by repository policy (`quarantine_duration_minutes`) during
    /// the ingest pipeline. Resolving the correct actor remains an
    /// open item. Expected outcomes:
    /// - **System-triggered quarantine on upload** → `system_actor()`, no
    ///   actor parameter (same pattern as `record_scan_result`).
    /// - **Admin-initiated quarantine** (manual hold on a suspicious
    ///   artifact) → separate `admin_quarantine` method with `ApiActor` +
    ///   `CallerPrivileges`, following the `admin_release` pattern.
    #[tracing::instrument(skip(self))]
    pub async fn quarantine_artifact(
        &self,
        artifact_id: Uuid,
        until: DateTime<Utc>,
        actor: Actor,
    ) -> AppResult<()> {
        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();

        let expected_version = read_expected_version(&*self.events, &stream_id, true).await?;

        // Load and transition artifact
        let mut artifact = self.artifacts.find_by_id(artifact_id).await?;
        let repository_id = artifact.repository_id;
        let event_payload = artifact.quarantine(until)?;

        // Bump quarantined_count in the same tx.
        let score_delta = RepoSecurityScoreProjector::compute_quarantined_delta();

        // Atomic commit: event + artifact state + score upsert in one transaction
        self.lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactQuarantined(
                        event_payload,
                    ))],
                    correlation_id,
                    causation_id: None,
                    actor,
                },
                None, // metadata is ingest-time-only; quarantine does not overwrite it
                Some((repository_id, score_delta)),
            )
            .await?;

        Ok(())
    }

    /// Record a per-finding scan result for a quarantined artifact.
    ///
    /// **Atomic dual-write**
    /// (`docs/architecture/explanation/scanning-pipeline.md`):
    ///
    /// 1. Validate every finding via [`Finding::validate`].
    /// 2. Compute aggregate `(finding_count, severity_summary)` from
    ///    `findings` — single source of truth, no caller-supplied
    ///    aggregates.
    /// 3. Resolve the active policy + its exclusions; evaluate via
    ///    [`evaluate_scan_result`].
    /// 4. Read the prior `ScanCompleted` (reverse-stream scan) +
    ///    hydrate its findings from CAS.
    /// 5. Compute `new_findings` via
    ///    [`compute_added_findings`] — feeds
    ///    `ArtifactBecameVulnerable.new_findings`.
    /// 6. Serialise `findings` to JSON, enforce 8 MiB cap, write to
    ///    CAS via [`StoragePort::put`] → `findings_blob` hash.
    /// 7. Build the event batch:
    ///    - `ScanCompleted` always.
    ///    - `PolicyEvaluated(Fail) + ArtifactRejected` on Reject.
    ///    - `ArtifactBecameVulnerable` when a prior scan existed AND
    ///      the delta is non-empty.
    /// 8. Atomically persist via the lifecycle port's
    ///    `commit_scan_result`: events + per-finding rows + artifact
    ///    state mutation + `artifacts.last_scan_at`. The Postgres
    ///    adapter wraps all four writes in a single transaction
    ///    (orphan projections forbidden).
    ///
    /// No actor parameter — uses [`system_actor`] internally.
    ///
    /// **The previous split-append sequence —
    /// `record_scan_result` appends `ScanCompleted` and the
    /// orchestrator separately appends `ArtifactBecameVulnerable` —
    /// is gone.** Both events now ride the same atomic batch.
    ///
    /// **`sbom` parameter.** When `Some`, the SBOM's
    /// components REPLACE the `sbom_components` projection rows for
    /// `artifact_id` inside the same Postgres transaction as the
    /// scan result (DELETE-then-INSERT for `(artifact_id, purl)`).
    /// When `None`, the projection write is skipped and any existing
    /// rows are preserved — the artifact had no extractable SBOM
    /// (e.g. an opaque format with no manifest), and stale-row
    /// cleanup for retired SBOMs is a future concern.
    #[tracing::instrument(skip(self, findings, sbom))]
    pub async fn record_scan_result(
        &self,
        artifact_id: Uuid,
        scanner: String,
        findings: Vec<Finding>,
        sbom: Option<&Sbom>,
    ) -> AppResult<()> {
        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();
        let actor = system_actor();
        let now = Utc::now();

        // Step 1 — validate every finding.
        for f in &findings {
            f.validate()?;
        }

        // Step 2 — compute aggregate counts from the per-finding list.
        let finding_count: u32 = u32::try_from(findings.len()).map_err(|_| {
            AppError::Domain(DomainError::Validation(format!(
                "scan_result: findings.len() {} exceeds u32::MAX",
                findings.len()
            )))
        })?;
        let severity = severity_summary_from_findings(&findings);
        severity.validate()?;

        // Step 3 — load artifact + resolve policy + exclusions + coords.
        let mut artifact = self.artifacts.find_by_id(artifact_id).await?;
        let policy = self
            .resolve_active_policy_for_repo(artifact.repository_id)
            .await?;
        let exclusions: Vec<ExclusionProjection> = match &policy {
            Some(p) => {
                self.policy_projections
                    .list_exclusions_for_policy(p.policy_id)
                    .await?
            }
            None => Vec::new(),
        };
        let coords = self.coords_for_artifact(&artifact).await?;

        // Step 4 — evaluate per-finding outcome.
        let outcome = evaluate_scan_result(&coords, &findings, policy.as_ref(), &exclusions, now);

        // Step 5 — read prior ScanCompleted (for delta detection).
        let prior = self.read_prior_scan_completed(artifact_id).await?;
        let prior_findings: Vec<Finding> = match prior.as_ref() {
            Some((event, _ts)) => self.hydrate_prior_findings(event).await?,
            None => Vec::new(),
        };
        let new_findings = compute_added_findings(&prior_findings, &findings);

        // Step 6 — serialise + size-cap-check + CAS write.
        let blob_hash = self.persist_findings_blob(&findings).await?;

        // Step 7 — assemble ScanCompleted (validate before persist).
        let scan_event = ScanCompleted {
            artifact_id,
            scanner,
            finding_count,
            severity_summary: severity.clone(),
            findings_blob: blob_hash.clone(),
        };
        scan_event.validate()?;

        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;

        // Step 8 — drive the per-outcome path.
        let scan_id = Uuid::new_v4();
        let scan_findings_rows = build_scan_findings_rows(&findings, artifact_id, scan_id, now);
        // Capture the prior status BEFORE mutation so
        // the projector can compute the (prior → new) bucket delta.
        let prior_status = artifact.quarantine_status;
        let repository_id = artifact.repository_id;

        // Resolve the `IngestSource` from the artifact's
        // stream ahead of the per-outcome branches so the metric label
        // is available for either path. Best-effort — a stream that
        // somehow lacks `ArtifactIngested` lands the `"unknown"`
        // sentinel rather than blocking the scan-result commit.
        let ingest_source = self.read_ingest_source(artifact_id).await?;

        // `became_vulnerable_pushed` mirrors the bool returned by
        // [`Self::maybe_push_became_vulnerable`] in the chosen branch.
        // The metric fires post-commit on this flag —
        // event-and-metric must rise together (emit-where-you-append rule).
        let became_vulnerable_pushed: bool;

        match outcome {
            ScanOutcome::Clean => {
                // `record_clean_scan` enforces that the artifact is in a
                // quarantine state where a clean scan is observable. It
                // does NOT mutate state — the fast-path
                // below may transition `Quarantined → Released` inline
                // when the computed deadline has already elapsed; the
                // window-completes-last case still leaves the artifact
                // `Quarantined` for the `release_expired` sweep.
                artifact.record_clean_scan()?;

                let mut events_vec = Vec::with_capacity(3);
                events_vec.push(EventToAppend::new(DomainEvent::ScanCompleted(
                    scan_event.clone(),
                )));

                // Step 7 (continued) — append ArtifactBecameVulnerable
                // when a prior scan existed AND the delta is non-empty.
                became_vulnerable_pushed = self.maybe_push_became_vulnerable(
                    &mut events_vec,
                    artifact_id,
                    &new_findings,
                    prior.as_ref().map(|(_, ts)| *ts),
                )?;

                // Event-driven fast-path release (ADR 0007).
                //
                // When the artifact is still `Quarantined` and its
                // computed deadline (`window_start + effective
                // duration`, resolved from the matched
                // `ScanPolicy.quarantineDuration` or
                // `DefaultPolicy::quarantine_duration_secs()`) is at or
                // before `now`, release it INLINE in the same
                // `commit_scan_result_with_score` batch as the
                // `ScanCompleted` append. Not "early release" — the
                // observation window has elapsed; this collapses the
                // latency from "up to one sweep interval" to zero.
                //
                // Uses the EXISTING accepted pair
                // `(ReleaseReason::Timer, ReleaseAuthorization::ScanSucceeded)`
                // the `release_expired` sweep already uses — no new
                // authorization. The atomicity invariant is the batch:
                // a reader rebuilding the projection from the event
                // store MUST see `[ScanCompleted, ArtifactReleased]`
                // as one append, never a clean-but-still-quarantined
                // intermediate.
                //
                // When the deadline is still in the future, behaviour
                // is unchanged — the artifact stays `Quarantined` and
                // the `release_expired` sweep releases it after the deadline
                // passes. When the artifact is not `Quarantined`
                // (`None` — permissive mode under
                // `quarantineDuration:0`), `record_clean_scan` is a
                // no-op and the fast-path does not fire (there is
                // nothing to release).
                let effective_duration_secs: i64 = policy
                    .as_ref()
                    .map(|p| p.quarantine_duration_secs)
                    .unwrap_or_else(DefaultPolicy::quarantine_duration_secs);
                let fast_path_fires = artifact.quarantine_status == QuarantineStatus::Quarantined
                    && artifact
                        .quarantine_window_start
                        .map(|anchor| {
                            effective_quarantine_deadline(
                                anchor,
                                chrono::Duration::seconds(effective_duration_secs),
                            ) <= now
                        })
                        .unwrap_or(false);

                // Tracks whether the inline release ACTUALLY fired (vs.
                // candidacy alone). The post-commit metric + `info!` below
                // gate on this, not on `fast_path_fires`, so a release
                // suppressed by the provenance gate is not mis-reported.
                let mut fast_path_released = false;
                if fast_path_fires {
                    // Release-predicate invariant preserved (ADR 0007 +
                    // ADR 0027): the timer arm carries the SAME provenance
                    // AND-precondition the `release_expired` sweep applies.
                    // Resolve the real clearance for this artifact/policy —
                    // `NotRequired` for `provenance_mode ∈ {Off,
                    // VerifyIfPresent}`; under `Required`, `Cleared` iff a
                    // `ProvenanceVerified` event exists on the stream, else
                    // `Pending`. The window-elapsed candidacy check (above)
                    // is the sweep's filter, never authorization;
                    // `Artifact::release`'s deny-by-default predicate
                    // re-verifies the (reason, authority, provenance) triple.
                    let provenance = self
                        .resolve_provenance_clearance(artifact_id, artifact.repository_id)
                        .await?;
                    match artifact.release(
                        ReleaseReason::Timer,
                        ReleaseAuthorization::ScanSucceeded,
                        provenance,
                    ) {
                        Ok(release_event) => {
                            events_vec.push(EventToAppend::new(DomainEvent::ArtifactReleased(
                                release_event,
                            )));
                            fast_path_released = true;
                        }
                        Err(_) => {
                            // Fail-closed (ADR 0007 + ADR 0027): the only
                            // way the predicate denies a `(Timer,
                            // ScanSucceeded)` release from a `Quarantined`
                            // candidate is a `Pending` provenance clearance
                            // (Required mode, not yet verified). Suppress the
                            // inline release — the clean `ScanCompleted`
                            // still commits and the artifact stays
                            // `Quarantined`; the `release_expired` sweep
                            // releases it once a `ProvenanceVerified` lands.
                            tracing::debug!(
                                artifact_id = %artifact_id,
                                "fast-path release suppressed: provenance gate not cleared (Required, pending)"
                            );
                        }
                    }
                }

                // Compute the score delta AFTER any in-batch release
                // so the (prior → current) transition reflects both
                // the scan-completion (severity counts) and the
                // potential `Quarantined → Released` move. For a clean
                // scan severity counts are all zero; the status delta
                // is non-zero only when the fast-path fired.
                let score_delta = RepoSecurityScoreProjector::compute_scan_completed_delta(
                    prior_status,
                    artifact.quarantine_status,
                    &severity,
                    now,
                );

                // Pass the BOM's subject AND
                // dependencies to the `sbom_components` projection so
                // the artifact-under-scan is queryable (leaf packages
                // were previously absent from the projection because
                // only `components` was forwarded).
                let sbom_components_owned = sbom.map(Sbom::all_components_owned);
                self.commit_scan_result_dual_write(
                    &artifact,
                    AppendEvents {
                        stream_id,
                        expected_version,
                        events: events_vec,
                        correlation_id,
                        causation_id: None,
                        actor,
                    },
                    &scan_findings_rows,
                    now,
                    Some((repository_id, score_delta)),
                    sbom_components_owned.as_deref(),
                )
                .await?;

                // Post-commit observability for the fast-path release.
                // The sweep's `release_expired` emits
                // `hort_quarantine_released_total{reason=timer}` and a
                // per-release `info!`; mirror that here so dashboards
                // see both release paths under the same counter. The
                // `source` field distinguishes this path from the
                // sweep for log readers. Gated on `fast_path_released`
                // (the release actually fired), NOT `fast_path_fires`
                // (mere candidacy) — a release suppressed by the
                // provenance gate must not increment the counter.
                if fast_path_released {
                    emit_release(values::REASON_TIMER);
                    tracing::info!(
                        artifact_id = %artifact_id,
                        correlation_id = %correlation_id,
                        authority = "scan_succeeded",
                        source = "scan_complete_fast_path",
                        "released expired artifact"
                    );
                }

                tracing::info!(
                    artifact_id = %artifact_id,
                    correlation_id = %correlation_id,
                    outcome = "clean",
                    policy_id = ?policy.as_ref().map(|p| p.policy_id),
                    "scan-result evaluated"
                );

                emit_policy_evaluation(
                    policy_decision_point::SCAN_RESULT,
                    PolicyEvaluationResult::Pass,
                );
            }
            ScanOutcome::Reject(violations) => {
                // First-violation message drives the `ArtifactRejected.reason`
                // string (used only on a fresh reject); the full violation list
                // is carried by `PolicyEvaluated.violations` for audit.
                let reason = violations
                    .first()
                    .map(|v| v.message.clone())
                    .unwrap_or_else(|| "policy evaluation rejected scan result".to_string());

                // Transition to `Rejected`. A re-scan that re-derives a reject on
                // an artifact ALREADY terminal (`Rejected` / `Released`) is a
                // recoverable, idempotent re-scan: we still record the fresh
                // `ScanCompleted` + findings below (so a manual rescan refreshes
                // the stored result instead of silently doing nothing), but skip
                // the duplicate `ArtifactRejected` event and the score re-count.
                // Propagating the already-terminal invariant instead would fail
                // the job and loop it forever (the original churn bug).
                let already_terminal;
                let reject_event = match artifact.reject_from_scan(reason) {
                    Ok(ev) => {
                        already_terminal = false;
                        Some(ev)
                    }
                    Err(DomainError::Invariant(msg)) => {
                        already_terminal = true;
                        tracing::debug!(
                            artifact_id = %artifact_id,
                            status = %artifact.quarantine_status,
                            reason = %msg,
                            "re-scan of already-terminal artifact: recording fresh \
                             findings, skipping duplicate reject + score re-count"
                        );
                        None
                    }
                    Err(e) => return Err(AppError::Domain(e)),
                };

                let policy_event = PolicyEvaluated {
                    artifact_id,
                    // L3 — when the evaluator fell back to the
                    // default policy (no operator policy resolved
                    // for this repository), use the named
                    // `NO_POLICY` sentinel rather than a bare
                    // `Uuid::nil()`. The schema requires NOT NULL;
                    // the named constant is the documentation hook
                    // that lets downstream readers match on the
                    // "no policy" case explicitly.
                    policy_id: policy.as_ref().map(|p| p.policy_id).unwrap_or(NO_POLICY),
                    result: PolicyResult::Fail,
                    violations: violations.clone(),
                };
                policy_event.validate()?;

                let violations_count = violations.len();

                let mut events_vec = Vec::with_capacity(4);
                events_vec.push(EventToAppend::new(DomainEvent::ScanCompleted(
                    scan_event.clone(),
                )));
                became_vulnerable_pushed = self.maybe_push_became_vulnerable(
                    &mut events_vec,
                    artifact_id,
                    &new_findings,
                    prior.as_ref().map(|(_, ts)| *ts),
                )?;
                events_vec.push(EventToAppend::new(DomainEvent::PolicyEvaluated(
                    policy_event,
                )));
                if let Some(reject_event) = reject_event {
                    events_vec.push(EventToAppend::new(DomainEvent::ArtifactRejected(
                        reject_event,
                    )));
                }

                // No score re-count on an already-terminal re-scan: the status
                // is unchanged and the original reject already counted it.
                let score_update = if already_terminal {
                    None
                } else {
                    Some((
                        repository_id,
                        RepoSecurityScoreProjector::compute_scan_completed_delta(
                            prior_status,
                            artifact.quarantine_status,
                            &severity,
                            now,
                        ),
                    ))
                };

                // See the matching block above
                // for the clean-path; same reason.
                let sbom_components_owned = sbom.map(Sbom::all_components_owned);
                self.commit_scan_result_dual_write(
                    &artifact,
                    AppendEvents {
                        stream_id,
                        expected_version,
                        events: events_vec,
                        correlation_id,
                        causation_id: None,
                        actor,
                    },
                    &scan_findings_rows,
                    now,
                    score_update,
                    sbom_components_owned.as_deref(),
                )
                .await?;

                // Post-commit refcount sweep + upstream-index invalidation run
                // only on the FIRST reject (a fresh transition); an
                // already-terminal re-scan already swept these when it was
                // originally rejected.
                if !already_terminal {
                    // Refcount sweep on reject (post-commit,
                    // warn-on-fail; see prior implementation comment).
                    if let Err(e) = self.content_references.delete_by_source(artifact_id).await {
                        tracing::warn!(
                            artifact_id = %artifact_id,
                            error = %e,
                            stage = "content_references_delete_on_reject",
                            "content_references delete failed on reject; refcount row not deleted \
                             on reject — refcount eventual, operator reconcile is future work"
                        );
                    }

                    // Best-effort upstream-index
                    // cache invalidation. Same post-commit-warn-on-fail
                    // posture as the refcount sweep above: the reject
                    // append already committed; the `NonServableStatusFilter`
                    // on the next index build is the load-bearing close.
                    // No-op when the composition root did not wire an
                    // invalidator (`with_upstream_index_cache_invalidator`
                    // not called) — TTL-only posture.
                    if let Some(invalidator) = self.upstream_index_cache_invalidator.as_ref() {
                        invalidate_after_reject(
                            invalidator,
                            artifact_id,
                            repository_id,
                            &artifact.name,
                        )
                        .await;
                    }
                }

                tracing::info!(
                    artifact_id = %artifact_id,
                    correlation_id = %correlation_id,
                    outcome = "reject",
                    policy_id = ?policy.as_ref().map(|p| p.policy_id),
                    violations_count,
                    "scan-result evaluated"
                );

                emit_policy_evaluation(
                    policy_decision_point::SCAN_RESULT,
                    PolicyEvaluationResult::Reject,
                );
                emit_policy_violations(policy_decision_point::SCAN_RESULT, &violations);
            }
        }

        // Emit-where-you-append rule — emit
        // `hort_artifact_became_vulnerable_total` exactly when the
        // matching event was appended (and the commit succeeded —
        // both reachable here only post-`commit_scan_result_dual_write`
        // returning Ok). Severity = highest tier among `new_findings`;
        // ingest_source mirrors the `ArtifactIngested.source`;
        // repository honours the `METRICS_INCLUDE_REPOSITORY_LABEL`
        // toggle.
        if became_vulnerable_pushed {
            let repo_label_owned: String;
            let repo_label: &str = if self.include_repository_label {
                // Resolve the repository key for the per-repo label.
                // A failed repo lookup falls back to the
                // [`values::REPOSITORY_UNKNOWN`] sentinel — matches
                // the convention in
                // `ArtifactUseCase::resolve_repository_label`.
                match self.repositories.find_by_id(repository_id).await {
                    Ok(r) => {
                        repo_label_owned = r.key;
                        repo_label_owned.as_str()
                    }
                    Err(_) => values::REPOSITORY_UNKNOWN,
                }
            } else {
                values::REPOSITORY_ALL
            };
            // `became_vulnerable_pushed` is
            // true only when `maybe_push_became_vulnerable` returned
            // `true`, which requires `new_findings` to be non-empty.
            // `highest_severity` therefore cannot return `None` on
            // this branch; surface the contradiction loudly rather
            // than silently labelling the metric `low`.
            let severity_lbl = match highest_severity(&new_findings) {
                Some(s) => severity_label(s),
                None => unreachable!(
                    "artifact_became_vulnerable emitted without findings; \
                     maybe_push_became_vulnerable returned true but \
                     new_findings.is_empty()"
                ),
            };
            let ingest_lbl = ingest_source_label(ingest_source);
            emit_artifact_became_vulnerable(repo_label, severity_lbl, ingest_lbl);
        }

        Ok(())
    }

    /// Read the most recent prior `ScanCompleted` from the artifact's
    /// stream — used by [`record_scan_result`] to detect a clean →
    /// vulnerable transition and to anchor the
    /// `ArtifactBecameVulnerable.previously_clean_at` timestamp.
    async fn read_prior_scan_completed(
        &self,
        artifact_id: Uuid,
    ) -> AppResult<Option<(ScanCompleted, DateTime<Utc>)>> {
        let stream_id = StreamId::artifact(artifact_id);
        let persisted = self
            .events
            .read_stream(&stream_id, ReadFrom::Start, STREAM_READ_LIMIT)
            .await?;
        for event in persisted.iter().rev() {
            if let DomainEvent::ScanCompleted(payload) = &event.event {
                return Ok(Some((payload.clone(), event.stored_at)));
            }
        }
        Ok(None)
    }

    /// Hydrate the per-finding `Vec<Finding>` referenced by a prior
    /// `ScanCompleted`. A prior with `findings_blob = None`
    /// (clean scan) returns `vec![]`. A prior with
    /// `findings_blob = Some(_)` reads the blob from CAS and
    /// deserialises. Surfaces a clean Validation error if the blob
    /// is absent or malformed (a `findings_blob = Some(_)`
    /// pointing at missing CAS content is corruption — fail loud).
    async fn hydrate_prior_findings(&self, prior: &ScanCompleted) -> AppResult<Vec<Finding>> {
        let Some(blob_hash) = prior.findings_blob.as_ref() else {
            return Ok(Vec::new());
        };
        let mut reader = self.storage.get(blob_hash).await?;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.map_err(|e| {
            AppError::Storage(format!("read findings_blob {blob_hash} failed: {e}"))
        })?;
        let findings: Vec<Finding> = serde_json::from_slice(&buf).map_err(|e| {
            AppError::Domain(DomainError::Validation(format!(
                "prior findings_blob {blob_hash} malformed: {e}"
            )))
        })?;
        Ok(findings)
    }

    /// Serialise `findings` to JSON, enforce the 8 MiB cap, and write
    /// to CAS. Returns `None` when `findings.is_empty()` (clean scans
    /// never allocate a blob — clean scans have no findings to store).
    async fn persist_findings_blob(&self, findings: &[Finding]) -> AppResult<Option<ContentHash>> {
        if findings.is_empty() {
            return Ok(None);
        }
        let json = serde_json::to_vec(findings)
            .map_err(|e| AppError::Storage(format!("serialise findings_blob failed: {e}")))?;
        if json.len() > FINDINGS_BLOB_MAX_BYTES {
            return Err(AppError::Domain(DomainError::Validation(format!(
                "findings_blob {} bytes exceeds {} byte cap",
                json.len(),
                FINDINGS_BLOB_MAX_BYTES,
            ))));
        }
        let put_result = self
            .storage
            .put(Box::new(std::io::Cursor::new(json)))
            .await?;
        Ok(Some(put_result.hash))
    }

    /// Append an `ArtifactBecameVulnerable` event when a prior
    /// `ScanCompleted` existed AND the delta against it is non-empty.
    /// First-ever scans never emit this event ("always
    /// was vulnerable, just discovered now" is not a transition).
    ///
    /// Returns `true` when the event was appended, `false` otherwise.
    /// The boolean drives the metric emission in the
    /// caller — see [`Self::record_scan_result`].
    fn maybe_push_became_vulnerable(
        &self,
        events_vec: &mut Vec<EventToAppend>,
        artifact_id: Uuid,
        new_findings: &[Finding],
        previously_clean_at: Option<DateTime<Utc>>,
    ) -> AppResult<bool> {
        if new_findings.is_empty() {
            return Ok(false);
        }
        let Some(previously_clean_at) = previously_clean_at else {
            return Ok(false);
        };
        let event = ArtifactBecameVulnerable {
            artifact_id,
            new_findings: new_findings.to_vec(),
            previously_clean_at,
        };
        event.validate()?;
        events_vec.push(EventToAppend::new(DomainEvent::ArtifactBecameVulnerable(
            event,
        )));
        Ok(true)
    }

    /// Read the artifact's stream and surface its `ArtifactIngested.source`.
    ///
    /// The `hort_artifact_became_vulnerable_total.ingest_source`
    /// label mirrors `IngestSource`. Returns `None` when the stream
    /// contains no `ArtifactIngested` event within
    /// [`STREAM_READ_LIMIT`] (defensive — every artifact stream begins
    /// with one, but we surface the absence rather than panic). The
    /// caller folds `None` into the
    /// [`values::FORMAT_UNKNOWN`]-equivalent sentinel
    /// (`"unknown"`) on the metric label.
    async fn read_ingest_source(&self, artifact_id: Uuid) -> AppResult<Option<IngestSource>> {
        let stream_id = StreamId::artifact(artifact_id);
        let persisted = self
            .events
            .read_stream(&stream_id, ReadFrom::Start, STREAM_READ_LIMIT)
            .await?;
        for event in persisted.iter() {
            if let DomainEvent::ArtifactIngested(payload) = &event.event {
                return Ok(Some(payload.source));
            }
        }
        Ok(None)
    }

    /// Drive the lifecycle port's `commit_scan_result_with_score`
    /// dual-write (events + per-finding rows + artifact state +
    /// `last_scan_at` + optional `repo_security_scores` projection
    /// upsert).
    ///
    /// `score_delta` is `Some` whenever the caller
    /// has a non-zero projection bump for the repo. Threaded into the
    /// `_with_score` lifecycle method so the upsert lands in the same
    /// SQL transaction as the event append.
    ///
    /// The previous body pattern-matched
    /// on the magic string `"commit_scan_result not implemented"` to
    /// fall back to a per-row insert + transition path; the trait
    /// default that produced that string is gone, every impl now
    /// implements `commit_scan_result_with_score` directly, and this
    /// dispatch is a single method call.
    async fn commit_scan_result_dual_write(
        &self,
        artifact: &Artifact,
        events: AppendEvents,
        scan_findings_rows: &[ScanFindingsRow],
        last_scan_at: DateTime<Utc>,
        score_delta: Option<(Uuid, ScoreDelta)>,
        sbom_components: Option<&[hort_domain::types::sbom::SbomComponent]>,
    ) -> AppResult<()> {
        self.lifecycle
            .commit_scan_result_with_score(
                artifact,
                events,
                scan_findings_rows,
                last_scan_at,
                score_delta,
                sbom_components,
            )
            .await
            .map(|_| ())
            .map_err(AppError::Domain)
    }

    /// Build an [`ArtifactCoords`] for the supplied artifact by joining
    /// the repository's format. Used by [`record_scan_result`] to feed
    /// the pure evaluator. The repository-side fetch is one row per
    /// scan-completion — the contention path is the artifact stream
    /// append, not this lookup.
    async fn coords_for_artifact(&self, artifact: &Artifact) -> AppResult<ArtifactCoords> {
        let repo = self.repositories.find_by_id(artifact.repository_id).await?;
        Ok(ArtifactCoords {
            name: artifact.name.clone(),
            name_as_published: artifact.name_as_published.clone(),
            version: artifact.version.clone(),
            path: artifact.path.clone(),
            format: repo.format,
            metadata: serde_json::Value::Null,
        })
    }

    /// Resolve the active scan policy for `repo_id`.
    ///
    /// Repo-scoped wins over global; absent both, the caller passes
    /// `None` to the evaluator and `DefaultPolicy::block_on_critical`
    /// supplies the threshold. v1 simplification: scan the projection
    /// list once per call. If projection counts grow past low-thousands
    /// a dedicated `find_for_repo` port method becomes the next step;
    /// today it is overhead the contention path doesn't notice. The
    /// helper is private and may be extracted to a shared module if a
    /// second caller appears.
    async fn resolve_active_policy_for_repo(
        &self,
        repo_id: Uuid,
    ) -> AppResult<Option<ScanPolicyProjection>> {
        let active = self.policy_projections.list_active().await?;
        let mut repo_scoped: Option<ScanPolicyProjection> = None;
        let mut global: Option<ScanPolicyProjection> = None;
        for projection in active {
            match &projection.scope {
                PolicyScope::Repository(id) if *id == repo_id => {
                    repo_scoped = Some(projection);
                }
                PolicyScope::Global if global.is_none() => {
                    global = Some(projection);
                }
                _ => {}
            }
        }
        Ok(repo_scoped.or(global))
    }

    /// Timer-release authority resolution (ADR 0007).
    ///
    /// Construct the timer-release authority for a candidate, **fail
    /// closed**. The candidacy filter (`quarantine_until <= now()`) is
    /// the *caller's* concern and is NEVER consulted here — this helper
    /// reads only the artifact's event stream and resolved scan policy,
    /// so expiry can never become a release authority.
    ///
    /// Order:
    /// 1. A successful [`DomainEvent::ScanCompleted`] anywhere on the
    ///    artifact stream ⇒ [`ReleaseAuthorization::ScanSucceeded`].
    ///    Terminal scan *failure* emits `ScanIndeterminate`, not
    ///    `ScanCompleted`, so the mere presence of a
    ///    `ScanCompleted` is exactly "a successful scan exists".
    /// 2. Else, resolve the artifact's `ScanPolicy`; if it exists AND
    ///    `scan_backends == []` (operator declared this scope unscanned)
    ///    ⇒ [`ReleaseAuthorization::ScanWaived`].
    /// 3. Else ⇒ `None` — no authority is constructible; the candidate
    ///    stays quarantined. An *absent* policy is **not** a waiver:
    ///    `DefaultPolicy` governs an unconfigured repo and it scans
    ///    (never auto-release a never-successfully-scanned
    ///    artifact).
    async fn resolve_release_authority(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> AppResult<Option<ReleaseAuthorization>> {
        let stream_id = StreamId::artifact(artifact_id);
        let persisted = self
            .events
            .read_stream(&stream_id, ReadFrom::Start, STREAM_READ_LIMIT)
            .await?;
        if persisted
            .iter()
            .any(|e| matches!(e.event, DomainEvent::ScanCompleted(_)))
        {
            return Ok(Some(ReleaseAuthorization::ScanSucceeded));
        }

        let policy = self.resolve_active_policy_for_repo(repository_id).await?;
        if matches!(policy, Some(p) if p.scan_backends.is_empty()) {
            return Ok(Some(ReleaseAuthorization::ScanWaived));
        }

        Ok(None)
    }

    /// Compute the provenance side of the
    /// release gate for a candidate (ADR 0027). Mirrors
    /// [`Self::resolve_release_authority`]'s shape (reads the artifact
    /// stream + resolved policy; never reads the quarantine window).
    ///
    /// - `provenance_mode ∈ {Off, VerifyIfPresent}` ⇒
    ///   [`ProvenanceClearance::NotRequired`]. `VerifyIfPresent` never
    ///   gates release — its protection is
    ///   `complete_provenance(Rejected) -> rejected`, which removes a bad
    ///   artifact from candidacy, not a release-gate.
    /// - `provenance_mode == Required` ⇒ [`ProvenanceClearance::Cleared`]
    ///   iff a [`DomainEvent::ProvenanceVerified`] exists anywhere on the
    ///   artifact stream, else [`ProvenanceClearance::Pending`]
    ///   (fail-closed — a never-verified `Required` artifact does not
    ///   timer-release before verification completes).
    ///
    /// An absent policy resolves to the [`ProvenanceMode`] default
    /// (`VerifyIfPresent`) ⇒ `NotRequired` — provenance never blocks an
    /// unconfigured repo's timer release (the scan gate still applies via
    /// `resolve_release_authority`).
    async fn resolve_provenance_clearance(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> AppResult<ProvenanceClearance> {
        let policy = self.resolve_active_policy_for_repo(repository_id).await?;
        let mode = policy
            .as_ref()
            .map(|p| p.provenance_mode)
            .unwrap_or_default();

        // Single-source the verdict mapping (ADR 0027 + 0041): the
        // post-exclusion scan re-evaluation pass in `PolicyUseCase` calls
        // the SAME helper, so the two release-gating provenance
        // computations cannot drift (the MR !39 `negligible_action`
        // drift). This use case owns only the policy-mode resolution.
        crate::use_cases::release_clearance::resolve_provenance_clearance(
            &*self.events,
            artifact_id,
            mode,
        )
        .await
    }

    /// Admin override: release a quarantined artifact regardless of scan results.
    ///
    /// Requires admin privilege. The emitted
    /// [`DomainEvent::ArtifactReleased`] carries
    /// `released_by_user_id = Some(actor.user_id)` and the operator-
    /// supplied `justification` so the override is attributable in
    /// the audit log. The HTTP boundary is responsible for rejecting
    /// empty / oversize justifications before the call reaches this
    /// method; the domain validation here is the second gate
    /// (`ArtifactReleased::validate` enforces the variant invariant
    /// and the 512-byte cap on `justification`).
    #[tracing::instrument(skip(self, privileges, justification))]
    pub async fn admin_release(
        &self,
        artifact_id: Uuid,
        actor: ApiActor,
        privileges: CallerPrivileges,
        justification: String,
    ) -> AppResult<()> {
        if let Err(e) = privileges.require_admin() {
            tracing::info!(artifact_id = %artifact_id, user_id = %actor.user_id, "admin_release denied: not admin");
            return Err(e);
        }

        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();
        let user_id = actor.user_id;

        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;

        let mut artifact = self.artifacts.find_by_id(artifact_id).await?;
        // Capture the prior status BEFORE mutation so
        // the projector can compute the (prior → released) delta.
        let prior_status = artifact.quarantine_status;
        let repository_id = artifact.repository_id;
        // Admin override is the AdminOverride authority;
        // it pairs with ReleaseReason::Admin in the deny-by-default
        // release predicate. The source-state guard now also accepts
        // ScanIndeterminate so an admin can clear a stuck-scanner
        // artifact directly.
        let mut event_payload = artifact.release(
            ReleaseReason::Admin,
            ReleaseAuthorization::AdminOverride,
            // Admin overrides ignore the provenance param
            // regardless, so `NotRequired` is semantically correct here.
            ProvenanceClearance::NotRequired,
        )?;
        // Populate the attribution fields before append. `release()`
        // returns a skeleton event with both fields `None`; the
        // variant invariant for `Admin` requires both `Some`. Domain
        // `validate()` runs at the event-store boundary; populating
        // here keeps the entity free of API-layer concerns while
        // still making the override attributable.
        event_payload.released_by_user_id = Some(user_id);
        event_payload.justification = Some(justification);

        let score_delta = RepoSecurityScoreProjector::compute_released_delta(prior_status);

        self.lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactReleased(
                        event_payload,
                    ))],
                    correlation_id,
                    causation_id: None,
                    actor: Actor::Api(actor),
                },
                None, // admin_release does not overwrite ingest metadata
                Some((repository_id, score_delta)),
            )
            .await?;

        emit_release(values::REASON_ADMIN);

        tracing::info!(
            artifact_id = %artifact_id,
            user_id = %user_id,
            reason = "admin",
            "admin released quarantined artifact"
        );
        Ok(())
    }

    /// Release artifacts whose quarantine period has expired.
    ///
    /// No actor parameter — uses `timer_actor()` internally (C2).
    /// Skips artifacts that fail validation (already released, wrong state).
    /// Returns the list of successfully released artifact IDs.
    ///
    /// **Fail-closed release predicate (ADR 0007).**
    /// A timer release is authorized ONLY
    /// when the application layer can prove a release authority for the
    /// candidate:
    ///
    /// - a successful `ScanCompleted` exists on the artifact stream ⇒
    ///   [`ReleaseAuthorization::ScanSucceeded`], OR
    /// - the resolved `ScanPolicy` has `scan_backends == []` (scanning
    ///   explicitly waived by operator policy) ⇒
    ///   [`ReleaseAuthorization::ScanWaived`].
    ///
    /// Otherwise **no authority is constructed and the artifact stays
    /// quarantined** — the candidate is skipped, the sweep continues.
    /// `quarantine_until <= now()` is the *caller's* candidacy filter
    /// and is never read here, so window expiry can never be a release
    /// authority. Consequence: a
    /// never-successfully-scanned, non-waived artifact can NEVER
    /// timer-release. Do NOT "fix" this by minting `ScanSucceeded`
    /// unconditionally — that re-opens the latent-Critical.
    #[tracing::instrument(skip(self))]
    pub async fn release_expired(&self, artifact_ids: Vec<Uuid>) -> AppResult<Vec<Uuid>> {
        let actor = timer_actor();
        let mut released = Vec::new();

        for artifact_id in artifact_ids {
            let stream_id = StreamId::artifact(artifact_id);
            let correlation_id = Uuid::new_v4();

            let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;

            let mut artifact = self.artifacts.find_by_id(artifact_id).await?;
            // Capture prior status BEFORE mutation.
            let prior_status = artifact.quarantine_status;
            let repository_id = artifact.repository_id;

            // Construct the real release
            // authority, fail-closed (ADR 0007). No authority ⇒ skip; the
            // artifact stays quarantined. quarantine_until is
            // candidacy-only and is never consulted here.
            let Some(authz) = self
                .resolve_release_authority(artifact_id, repository_id)
                .await?
            else {
                tracing::debug!(
                    artifact_id = %artifact_id,
                    status = %artifact.quarantine_status,
                    "skipping: no release authority (no successful scan, scanning not waived)"
                );
                continue;
            };
            let authority_kind = release_authority_label(authz);

            // Compute the provenance side of
            // the gate per candidate (ADR 0027).
            // `NotRequired` for Off/VerifyIfPresent; `Required` →
            // `Cleared` iff a `ProvenanceVerified` event exists, else
            // `Pending` (fail-closed — denies the timer arm). The scan gate
            // (`authz`) is unchanged; provenance is an AND-precondition on
            // the timer arm only.
            let provenance = self
                .resolve_provenance_clearance(artifact_id, repository_id)
                .await?;

            match artifact.release(ReleaseReason::Timer, authz, provenance) {
                Ok(event_payload) => {
                    let score_delta =
                        RepoSecurityScoreProjector::compute_released_delta(prior_status);
                    self.lifecycle
                        .commit_transition_with_score(
                            &artifact,
                            AppendEvents {
                                stream_id,
                                expected_version,
                                events: vec![EventToAppend::new(DomainEvent::ArtifactReleased(
                                    event_payload,
                                ))],
                                correlation_id,
                                causation_id: None,
                                actor: actor.clone(),
                            },
                            None, // timer release does not overwrite ingest metadata
                            Some((repository_id, score_delta)),
                        )
                        .await?;
                    emit_release(values::REASON_TIMER);
                    released.push(artifact_id);
                    // Security-relevant state change: `info!`
                    // with the resolved authority kind. Tracing-only;
                    // no new metric (the existing
                    // `hort_quarantine_released_total{reason=timer}`
                    // counter already covers the release count).
                    tracing::info!(
                        artifact_id = %artifact_id,
                        correlation_id = %correlation_id,
                        authority = authority_kind,
                        "released expired artifact"
                    );
                }
                Err(_) => {
                    // Authority was constructible but the domain
                    // source-state guard refused (e.g. the candidate is
                    // already Released / not in a releasable state).
                    tracing::debug!(
                        artifact_id = %artifact_id,
                        status = %artifact.quarantine_status,
                        "skipping: not in releasable state"
                    );
                }
            }
        }

        Ok(released)
    }

    /// Record a terminal scan failure: the scan job
    /// exhausted its retry budget with every backend errored, so the
    /// scanner could not decide. Transitions the artifact to the
    /// terminal `ScanIndeterminate` state (fail-closed) and appends the
    /// `ScanIndeterminate` event **atomically with the status
    /// transition** via the EXISTING
    /// [`ArtifactLifecyclePort::commit_transition_with_score`] — the
    /// same atomic-append method `record_scan_result` / `release_expired`
    /// use. No new or altered port signature.
    ///
    /// No actor parameter — uses [`system_actor`] internally: a
    /// fail-closed quarantine is a system-driven reaction, not an
    /// operator action (mirrors `record_scan_result`).
    ///
    /// **Idempotent skip.** When the artifact is already terminal
    /// (`ScanIndeterminate` / `Rejected` / `Released`),
    /// [`Artifact::fail_scan_indeterminate`] returns
    /// `Err(DomainError::Invariant)`; this is a *recoverable* "already
    /// terminal" skip — the method returns `Ok(())` and appends no
    /// duplicate event, mirroring the corruption path
    /// (`tombstone_from_corruption`). A non-`Invariant` domain error
    /// (e.g. an oversized scanner/reason failing the event invariant)
    /// propagates.
    ///
    /// **Fail-closed ordering (ADR 0007).** The artifact transition is
    /// committed here, *before* the orchestrator's
    /// `jobs.mark_failed(...)`. The caller
    /// (`scan_orchestration::record_outcome`) runs this step first so a
    /// crash between them leaves the job retryable rather than the
    /// artifact silently un-failed.
    #[tracing::instrument(skip(self, reason))]
    pub async fn record_scan_indeterminate(
        &self,
        artifact_id: Uuid,
        scanner: String,
        reason: String,
        attempts: u32,
    ) -> AppResult<()> {
        let stream_id = StreamId::artifact(artifact_id);
        let correlation_id = Uuid::new_v4();

        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;

        let mut artifact = self.artifacts.find_by_id(artifact_id).await?;
        let prior_status = artifact.quarantine_status;
        let repository_id = artifact.repository_id;

        let event_payload =
            match artifact.fail_scan_indeterminate(scanner.clone(), reason.clone(), attempts) {
                Ok(ev) => ev,
                // Already-terminal (ScanIndeterminate / Rejected / Released)
                // is an idempotent, recoverable skip — do not append a
                // duplicate event. Mirrors the corruption path's
                // already-rejected branch and the sweep's Err(_) skip arm.
                Err(DomainError::Invariant(msg)) => {
                    tracing::debug!(
                        artifact_id = %artifact_id,
                        status = %artifact.quarantine_status,
                        reason = %msg,
                        "skipping scan-indeterminate: artifact already terminal"
                    );
                    return Ok(());
                }
                // Any other domain error (e.g. oversized scanner/reason
                // failing the event invariant) is a real failure.
                Err(e) => return Err(AppError::Domain(e)),
            };

        // quarantined/none → scan_indeterminate score
        // delta (released/rejected buckets untouched).
        let score_delta =
            RepoSecurityScoreProjector::compute_scan_indeterminate_delta(prior_status);

        // Atomic: ScanIndeterminate event + the quarantine_status
        // transition (+ score) in one transaction via the EXISTING
        // port method — no new/altered port signature.
        self.lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ScanIndeterminate(
                        event_payload,
                    ))],
                    correlation_id,
                    causation_id: None,
                    actor: system_actor(),
                },
                None, // fail-closed transition does not overwrite ingest metadata
                Some((repository_id, score_delta)),
            )
            .await?;

        // A fail-closed quarantine is a
        // security-relevant state change and an *expected* outcome, not
        // an ERROR (audit fact, not ERROR).
        // The dead-scanner `error!` stays at the orchestrator
        // (infra failure); this is the security-transition audit line.
        // No secret/credential material — scanner label + truncated
        // reason only.
        tracing::info!(
            artifact_id = %artifact_id,
            scanner = %scanner,
            attempts,
            reason = %truncate_reason(&reason),
            "artifact transitioned to scan_indeterminate (fail-closed)"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// QuarantineReleasePort
// ---------------------------------------------------------------------------

/// Bridge the application-layer `release_expired`
/// into the trait-only [`QuarantineReleaseSweepHandler`](crate::task_handlers::QuarantineReleaseSweepHandler).
///
/// The handler depends on
/// [`hort_domain::ports::quarantine_release::QuarantineReleasePort`]
/// (a one-method trait — keeps the handler crate-light and testable
/// without a full `QuarantineUseCase` composition); this impl is the
/// only production wiring. Non-domain `AppError` variants (event
/// store, repository) collapse to
/// [`DomainError::Invariant`](hort_domain::error::DomainError::Invariant)
/// so the handler's per-tick retry path treats them as transient.
/// `AppError::Domain` round-trips unwrapped — the `?`-friendly path
/// preserves the variant for the handler's `tracing::warn!` line.
impl hort_domain::ports::quarantine_release::QuarantineReleasePort for QuarantineUseCase {
    fn release_expired<'a>(
        &'a self,
        artifact_ids: Vec<Uuid>,
    ) -> hort_domain::ports::BoxFuture<'a, hort_domain::error::DomainResult<Vec<Uuid>>> {
        Box::pin(async move {
            match QuarantineUseCase::release_expired(self, artifact_ids).await {
                Ok(ids) => Ok(ids),
                Err(AppError::Domain(de)) => Err(de),
                Err(other) => Err(DomainError::Invariant(format!(
                    "release_expired: non-domain failure surfaced through port: {other}"
                ))),
            }
        })
    }
}

/// Truncate an operator-readable scanner error for the audit log line.
/// Keeps the log bounded; the full reason is on the persisted
/// `ScanIndeterminate.reason` (capped by the event invariant). No
/// secret material is expected here — the input is the job's last
/// scanner error string.
fn truncate_reason(reason: &str) -> std::borrow::Cow<'_, str> {
    const MAX_LOG_REASON: usize = 256;
    if reason.len() <= MAX_LOG_REASON {
        std::borrow::Cow::Borrowed(reason)
    } else {
        let mut end = MAX_LOG_REASON;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        std::borrow::Cow::Owned(format!("{}…", &reason[..end]))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::scan_policy::{
        ExclusionProjection, NegligibleAction, ProvenanceMode, ScanPolicyProjection,
        SeverityThreshold,
    };
    use hort_domain::events::{
        system_actor, Actor, DomainEvent, PersistedEvent, PolicyResult, PolicyScope, ReleaseReason,
        SeveritySummary, StreamId,
    };
    use hort_domain::ports::event_store::ExpectedVersion;
    use uuid::Uuid;

    use metrics::SharedString;
    use metrics_util::debugging::DebugValue;
    use metrics_util::{CompositeKey, MetricKind};

    use super::*;
    use crate::metrics::capture_metrics;
    use crate::use_cases::test_support::*;

    use crate::use_cases::test_support::MockArtifactLifecycle;

    // -- Metric helpers -------------------------------------------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<SharedString>,
        DebugValue,
    );

    fn assert_release_counter(entries: &[MetricEntry], expected_reason: &str, expected_value: u64) {
        let found = entries.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_quarantine_released_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "reason" && l.value() == expected_reason)
        });
        match found {
            Some((_, _, _, DebugValue::Counter(got))) => assert_eq!(
                *got, expected_value,
                "hort_quarantine_released_total{{reason={expected_reason}}} had {got}"
            ),
            Some(_) => panic!("release metric is not a counter"),
            None => {
                let seen: Vec<&str> = entries
                    .iter()
                    .map(|(ck, _, _, _)| ck.key().name())
                    .collect();
                panic!(
                    "hort_quarantine_released_total{{reason={expected_reason}}} not found; seen: {seen:?}"
                );
            }
        }
    }

    // -- Use-case factory -----------------------------------------------------

    /// Tuple alias keeps the `make_use_case()` signature inside clippy's
    /// `type_complexity` budget without losing the per-mock handle access
    /// that every test relies on.
    type UseCaseFixture = (
        QuarantineUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockRepositoryRepository>,
        Arc<MockPolicyProjectionRepository>,
    );

    fn make_use_case() -> UseCaseFixture {
        let (uc, artifacts, events, lifecycle, repositories, projections, _content_refs) =
            make_use_case_with_content_refs();
        (uc, artifacts, events, lifecycle, repositories, projections)
    }

    /// Extended fixture exposing the
    /// `MockContentReferenceIndex` so the reject-sweep tests can
    /// assert on row deletion. Mirrors the ingest-path
    /// `make_use_case_with_content_refs` shape; existing tests keep
    /// the original 6-tuple via [`make_use_case`].
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_content_refs() -> (
        QuarantineUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockRepositoryRepository>,
        Arc<MockPolicyProjectionRepository>,
        Arc<MockContentReferenceIndex>,
    ) {
        let (uc, artifacts, events, lifecycle, repositories, projections, content_references, _) =
            make_use_case_with_storage();
        (
            uc,
            artifacts,
            events,
            lifecycle,
            repositories,
            projections,
            content_references,
        )
    }

    /// Extension of the standard fixture
    /// that returns the [`MockStoragePort`] handle so tests can seed
    /// failure injection (`fail_next_put`) and assert that the use
    /// case surfaces the CAS write error before any event-store
    /// append happens.
    #[allow(clippy::type_complexity)]
    fn make_use_case_with_storage() -> (
        QuarantineUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockEventStore>,
        Arc<MockArtifactLifecycle>,
        Arc<MockRepositoryRepository>,
        Arc<MockPolicyProjectionRepository>,
        Arc<MockContentReferenceIndex>,
        Arc<MockStoragePort>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let scan_findings = Arc::new(MockScanFindingsRepository::new());
        let lifecycle = Arc::new(
            MockArtifactLifecycle::new(artifacts.clone())
                .with_scan_result_paired_mocks(events.clone(), scan_findings.clone()),
        );
        let repositories = Arc::new(MockRepositoryRepository::new());
        let projections = Arc::new(MockPolicyProjectionRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());
        let storage = Arc::new(MockStoragePort::new());
        // M9 — the dedicated ScanFindingsRepository handle is gone;
        // the lifecycle mock owns the per-finding-row write via the
        // paired `commit_scan_result_with_score`. The scan_findings
        // mock is still wired into the lifecycle (see
        // `with_scan_result_paired_mocks`) so tests can assert on
        // `inserted_batches()`.
        let _ = scan_findings;
        let uc = QuarantineUseCase::new(
            artifacts.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            lifecycle.clone(),
            repositories.clone(),
            projections.clone(),
            content_references.clone(),
            storage.clone(),
        );
        (
            uc,
            artifacts,
            events,
            lifecycle,
            repositories,
            projections,
            content_references,
            storage,
        )
    }

    /// Build a `Vec<Finding>` whose per-tier counts match the supplied
    /// [`SeveritySummary`]. Synthesises distinct CVE ids so the
    /// evaluator's exact-id matching is observable in
    /// test output. Negligible (which `Finding.severity` does not
    /// support — that enum is `SeverityThreshold`) is intentionally
    /// dropped: the pre-existing tests passed `negligible: 0` in
    /// every case, so the migration is lossless.
    fn findings_from_summary(severity: &SeveritySummary) -> Vec<Finding> {
        let mut out = Vec::new();
        for i in 0..severity.critical {
            out.push(Finding {
                purl: format!("pkg:npm/c-{i}@1"),
                vulnerability_id: format!("CVE-C-{i}"),
                severity: SeverityThreshold::Critical,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            });
        }
        for i in 0..severity.high {
            out.push(Finding {
                purl: format!("pkg:npm/h-{i}@1"),
                vulnerability_id: format!("CVE-H-{i}"),
                severity: SeverityThreshold::High,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            });
        }
        for i in 0..severity.medium {
            out.push(Finding {
                purl: format!("pkg:npm/m-{i}@1"),
                vulnerability_id: format!("CVE-M-{i}"),
                severity: SeverityThreshold::Medium,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            });
        }
        for i in 0..severity.low {
            out.push(Finding {
                purl: format!("pkg:npm/l-{i}@1"),
                vulnerability_id: format!("CVE-L-{i}"),
                severity: SeverityThreshold::Low,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            });
        }
        out
    }

    /// Seed an artifact + its repository in one shot. The default
    /// repository's format is irrelevant for the v1 evaluator (the
    /// `coords.name` glob path doesn't depend on format) but it must
    /// exist so the repo lookup in `record_scan_result` succeeds.
    fn seed_artifact_with_repo(
        artifacts: &Arc<MockArtifactRepository>,
        repositories: &Arc<MockRepositoryRepository>,
        status: QuarantineStatus,
    ) -> Uuid {
        let artifact = sample_artifact(status);
        let mut repo = sample_repository();
        // Align the repository's id with the artifact's repository_id so
        // the use case's `repositories.find_by_id(artifact.repository_id)`
        // resolves the seeded row.
        repo.id = artifact.repository_id;
        let id = artifact.id;
        artifacts.insert(artifact);
        repositories.insert(repo);
        id
    }

    /// Seed an artifact stream whose tail carries a
    /// successful `ScanCompleted` (clean: zero findings, no blob — the
    /// invariant for a finding-free scan). `release_expired` reads
    /// the stream and, finding any `ScanCompleted`, constructs
    /// `ReleaseAuthorization::ScanSucceeded`. A position-0
    /// `ArtifactQuarantined` precedes it so `read_expected_version`
    /// resolves a non-`NoStream` version, mirroring a real lifecycle.
    fn seed_stream_with_scan_completed(events: &Arc<MockEventStore>, artifact_id: Uuid) {
        let stream_id = StreamId::artifact(artifact_id);
        let quarantined = dummy_persisted_event(&stream_id, artifact_id, 0);
        let scan_completed = PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream_id.clone(),
            stream_position: 1,
            global_position: 2,
            event: DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "trivy".into(),
                finding_count: 0,
                severity_summary: SeveritySummary {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    negligible: 0,
                },
                findings_blob: None,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: system_actor(),
            event_version: 1,
            stored_at: Utc::now(),
        };
        events.set_stream(&stream_id, vec![quarantined, scan_completed]);
    }

    /// Seed an active repo-scoped policy whose
    /// `scan_backends` is empty: the operator declared this repo
    /// un-scanned by design. `release_expired` resolves this policy and
    /// constructs `ReleaseAuthorization::ScanWaived`.
    fn seed_scan_waived_policy(
        projections: &Arc<MockPolicyProjectionRepository>,
        repository_id: Uuid,
    ) {
        let mut p = projection(
            PolicyScope::Repository(repository_id),
            SeverityThreshold::Critical,
        );
        p.scan_backends = vec![];
        projections.insert(p);
    }

    fn projection(scope: PolicyScope, threshold: SeverityThreshold) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: format!("test-policy-{}", Uuid::new_v4()),
            scope,
            severity_threshold: threshold,
            quarantine_duration_secs: 0,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn exclusion_for(policy_id: Uuid, cve_id: &str) -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id: Uuid::new_v4(),
            policy_id,
            cve_id: cve_id.to_string(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "test".into(),
            added_by_actor_id: None,
            expires_at: None,
        }
    }

    // -- Tests ----------------------------------------------------------------

    #[tokio::test]
    async fn quarantine_artifact_success() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::None);

        let until = Utc::now() + chrono::Duration::hours(24);
        uc.quarantine_artifact(artifact_id, until, Actor::Api(api_actor()))
            .await
            .unwrap();

        // Atomic commit_transition should have been called (not separate append + save)
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved_artifact, batch, _metadata) = &transitions[0];
        assert_eq!(
            saved_artifact.quarantine_status,
            QuarantineStatus::Quarantined
        );
        assert_eq!(saved_artifact.quarantine_window_start, Some(until));
        assert_eq!(batch.events.len(), 1);
        assert!(matches!(
            &batch.events[0].event,
            DomainEvent::ArtifactQuarantined(_)
        ));
    }

    #[tokio::test]
    async fn quarantine_artifact_already_quarantined_fails() {
        let (uc, artifacts, _events, _lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let until = Utc::now() + chrono::Duration::hours(24);
        let err = uc
            .quarantine_artifact(artifact_id, until, Actor::Api(api_actor()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot quarantine"));
    }

    #[tokio::test]
    async fn quarantine_artifact_stream_cap_rejects() {
        let (uc, artifacts, events, _lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::None);
        let stream_id = StreamId::artifact(artifact_id);

        // Populate stream with 201 events to exceed the 200 cap
        let dummy_events: Vec<_> = (0..201)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy_events);

        let until = Utc::now() + chrono::Duration::hours(24);
        let err = uc
            .quarantine_artifact(artifact_id, until, Actor::Api(api_actor()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds 200-event cap"));
    }

    #[tokio::test]
    async fn quarantine_artifact_existing_stream_uses_exact() {
        let (uc, artifacts, events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::None);
        let stream_id = StreamId::artifact(artifact_id);

        // Stream has 2 events at positions 0 and 1
        let dummy_events: Vec<_> = (0..2)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy_events);

        let until = Utc::now() + chrono::Duration::hours(24);
        uc.quarantine_artifact(artifact_id, until, Actor::Api(api_actor()))
            .await
            .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].1.expected_version, ExpectedVersion::Exact(1));
    }

    #[tokio::test]
    async fn quarantine_artifact_generates_fresh_correlation_id() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::None);

        let until = Utc::now() + chrono::Duration::hours(24);
        uc.quarantine_artifact(artifact_id, until, Actor::Api(api_actor()))
            .await
            .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        assert!(!transitions[0].1.correlation_id.is_nil());
    }

    // -- record_scan_result tests --------------------------------------------

    /// One critical CVE with no policy → DefaultPolicy::block_on_critical
    /// rejects. ScanCompleted + PolicyEvaluated(Fail) + ArtifactRejected
    /// must land in a single atomic commit_transition.
    #[tokio::test]
    async fn record_scan_result_default_policy_blocks_on_critical() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let severity = SeveritySummary {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved_artifact, batch, _metadata) = &transitions[0];
        // Three events appended atomically: ScanCompleted, PolicyEvaluated, ArtifactRejected.
        assert_eq!(batch.events.len(), 3);
        assert!(matches!(
            &batch.events[0].event,
            DomainEvent::ScanCompleted(_)
        ));
        assert!(matches!(
            &batch.events[1].event,
            DomainEvent::PolicyEvaluated(_)
        ));
        assert!(matches!(
            &batch.events[2].event,
            DomainEvent::ArtifactRejected(_)
        ));

        // PolicyEvaluated.policy_id is nil (no operator policy) and
        // result is Fail with at least one violation.
        if let DomainEvent::PolicyEvaluated(p) = &batch.events[1].event {
            assert_eq!(p.policy_id, Uuid::nil());
            assert_eq!(p.result, PolicyResult::Fail);
            assert!(!p.violations.is_empty());
        }

        // Actor is system; artifact ends in Rejected.
        assert_eq!(batch.actor, system_actor());
        assert_eq!(saved_artifact.quarantine_status, QuarantineStatus::Rejected);
    }

    /// When the storage port's `put` call
    /// fails (e.g. transient PG / S3 outage), `record_scan_result`
    /// must surface the error verbatim and abort *before* any event
    /// is appended. Mirrors the production adapter's all-or-nothing
    /// posture: the per-finding rows live behind a `findings_blob`
    /// hash that does not yet exist on disk; appending
    /// `ScanCompleted.findings_blob = Some(<missing_hash>)` would
    /// leave the audit trail pointing at a corrupt CAS reference.
    #[tokio::test]
    async fn record_scan_result_aborts_when_storage_put_fails() {
        let (uc, artifacts, events, lifecycle, repositories, _projections, _refs, storage) =
            make_use_case_with_storage();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        // Seed a one-shot put failure. Use a Storage error so the
        // surfaced AppError variant is unambiguous (storage failures
        // wrap into `AppError::Domain(DomainError::*)` per the
        // ?-coercion in `persist_findings_blob`).
        storage.fail_next_put(DomainError::Invariant(
            "simulated CAS write failure (test fixture)".into(),
        ));

        let severity = SeveritySummary {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        let result = uc
            .record_scan_result(
                artifact_id,
                "trivy".into(),
                findings_from_summary(&severity),
                None,
            )
            .await;

        // The use case surfaces the storage failure as an
        // AppError::Domain wrapping the seeded Invariant.
        let err = result.expect_err("record_scan_result must fail when storage.put errors");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("simulated CAS write failure"),
            "expected the seeded storage error to be surfaced verbatim, got {msg}"
        );

        // Crucially, no events were appended and no transitions were
        // committed: the use case bailed before the lifecycle write
        // path. `put` is the gate that catches storage failures
        // before any persistence side-effect lands.
        assert_eq!(
            lifecycle.committed_transitions().len(),
            0,
            "no transitions should commit on storage failure"
        );
        assert_eq!(
            events.appended_batches().len(),
            0,
            "no events should append on storage failure"
        );
        assert_eq!(
            storage.put_call_count(),
            1,
            "exactly one put attempt should have been made"
        );
    }

    /// `high` finding under the default Critical threshold passes
    /// through cleanly — only `critical` blocks under the default. The
    /// artifact stays Quarantined and only ScanCompleted is appended.
    #[tokio::test]
    async fn record_scan_result_below_threshold_clean_default_policy() {
        let (uc, artifacts, events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let severity = SeveritySummary {
            critical: 0,
            high: 5,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events.len(), 1);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::ScanCompleted(_)
        ));
        // Clean path uses the events port directly — no commit_transition.
        assert_eq!(
            lifecycle.committed_transitions().len(),
            1,
            "clean record_scan_result still commits the dual-write"
        );
        assert_eq!(lifecycle.last_scan_at_writes().len(), 1);
        // Artifact stays Quarantined per invariant 2.
        let saved = artifacts.get(artifact_id).unwrap();
        assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// Repo-scoped policy with `severity_threshold = High` rejects on a
    /// `high` finding (the default threshold of Critical would have let
    /// it through). Verifies the use case threads the resolved policy
    /// into the evaluator.
    #[tokio::test]
    async fn record_scan_result_repo_scoped_policy_threshold_rejects() {
        let (uc, artifacts, _events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let repo_id = artifacts.get(artifact_id).unwrap().repository_id;

        let policy = projection(PolicyScope::Repository(repo_id), SeverityThreshold::High);
        let policy_id = policy.policy_id;
        projections.insert(policy);

        let severity = SeveritySummary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (_saved, batch, _metadata) = &transitions[0];
        assert_eq!(batch.events.len(), 3);
        if let DomainEvent::PolicyEvaluated(p) = &batch.events[1].event {
            assert_eq!(p.policy_id, policy_id);
        } else {
            panic!("expected PolicyEvaluated as second event");
        }
    }

    /// Repo-scoped policy wins over a global policy with conflicting
    /// thresholds. Repo-scoped sets High → reject; global sets Low.
    /// We expect the High threshold to apply (repo-scoped wins).
    /// Verifies the resolution helper picks repo-scoped over global.
    #[tokio::test]
    async fn record_scan_result_repo_scoped_overrides_global() {
        let (uc, artifacts, _events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let repo_id = artifacts.get(artifact_id).unwrap().repository_id;

        let global = projection(PolicyScope::Global, SeverityThreshold::Low);
        let repo_scoped = projection(PolicyScope::Repository(repo_id), SeverityThreshold::High);
        let repo_policy_id = repo_scoped.policy_id;
        projections.insert(global);
        projections.insert(repo_scoped);

        // High finding → blocks under repo-scoped's High threshold and
        // would also block under global's Low. The PolicyEvaluated
        // event's policy_id witnesses which one was active.
        let severity = SeveritySummary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        if let DomainEvent::PolicyEvaluated(p) = &transitions[0].1.events[1].event {
            assert_eq!(p.policy_id, repo_policy_id);
        } else {
            panic!("expected PolicyEvaluated event");
        }
    }

    /// Repo-scoped policy that targets a different repository is
    /// IGNORED. Verifies the resolution helper's `_` match arm
    /// (PolicyScope::Repository(id) where id != repo_id). With no
    /// matching policy and no global, the default policy applies — a
    /// `high` finding is below `Critical` so the scan stays Clean.
    #[tokio::test]
    async fn record_scan_result_unrelated_repo_scoped_policy_ignored() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        // Repo-scoped policy bound to a *different* repository.
        let other_repo_id = Uuid::new_v4();
        let policy = projection(
            PolicyScope::Repository(other_repo_id),
            SeverityThreshold::Low,
        );
        projections.insert(policy);

        let severity = SeveritySummary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        // No policy resolved → DefaultPolicy::block_on_critical →
        // `high` finding is below threshold → Clean.
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events.len(), 1);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::ScanCompleted(_)
        ));
        assert_eq!(
            lifecycle.committed_transitions().len(),
            1,
            "clean record_scan_result still commits the dual-write"
        );
        assert_eq!(lifecycle.last_scan_at_writes().len(), 1);
    }

    /// Archived projections are excluded by `list_active`. Verifies the
    /// projection's archived flag short-circuits resolution — an
    /// archived repo-scoped policy with `severity_threshold = Low`
    /// must not block a `high` finding.
    #[tokio::test]
    async fn record_scan_result_archived_policy_is_skipped() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let repo_id = artifacts.get(artifact_id).unwrap().repository_id;

        let mut policy = projection(PolicyScope::Repository(repo_id), SeverityThreshold::Low);
        policy.archived = true;
        projections.insert(policy);

        let severity = SeveritySummary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        // Archived policy ignored → DefaultPolicy → high < Critical → Clean.
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(
            lifecycle.committed_transitions().len(),
            1,
            "clean record_scan_result still commits the dual-write"
        );
        assert_eq!(lifecycle.last_scan_at_writes().len(), 1);
    }

    /// Two global policies — the resolution helper's `if global.is_none()`
    /// guard keeps the first one. Demonstrates determinism even though
    /// the apply pipeline forbids two active globals at the same time
    /// today.
    #[tokio::test]
    async fn record_scan_result_first_global_policy_wins() {
        let (uc, artifacts, _events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        // Two globals; both with thresholds that would block a high
        // finding. We can't assert WHICH global wins (HashMap iteration
        // order is non-deterministic) — only that exactly one
        // PolicyEvaluated event lands and references one of the seeded
        // policy_ids.
        let g1 = projection(PolicyScope::Global, SeverityThreshold::High);
        let g2 = projection(PolicyScope::Global, SeverityThreshold::High);
        let g1_id = g1.policy_id;
        let g2_id = g2.policy_id;
        projections.insert(g1);
        projections.insert(g2);

        let severity = SeveritySummary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        if let DomainEvent::PolicyEvaluated(p) = &transitions[0].1.events[1].event {
            assert!(
                p.policy_id == g1_id || p.policy_id == g2_id,
                "policy_id must match one of the seeded globals"
            );
        } else {
            panic!("expected PolicyEvaluated event");
        }
    }

    /// Global policy applies when no repo-scoped policy is active.
    /// Uses a `high` finding so the severity-escalation primitive
    /// produces `Block` (and thus a Reject outcome) — `medium` / `low`
    /// only escalate to `Warn`, which the v1 scan path treats as Clean.
    #[tokio::test]
    async fn record_scan_result_global_policy_applies_without_repo_scoped() {
        let (uc, artifacts, _events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let global = projection(PolicyScope::Global, SeverityThreshold::Low);
        let global_policy_id = global.policy_id;
        projections.insert(global);

        let severity = SeveritySummary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        if let DomainEvent::PolicyEvaluated(p) = &transitions[0].1.events[1].event {
            assert_eq!(p.policy_id, global_policy_id);
        } else {
            panic!("expected PolicyEvaluated event");
        }
    }

    /// Findings excluded by an active exclusion → outcome flips to Clean
    /// (only ScanCompleted lands; no rejection). Verifies the use case
    /// loads exclusions for the resolved policy and threads them into
    /// the evaluator.
    #[tokio::test]
    async fn record_scan_result_excluded_finding_returns_clean() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        // Pin the resolved policy to a non-zero
        // `quarantine_duration_secs` so the artifact's deadline is in
        // the future and the fast-path stays dormant. This test
        // exercises the exclusion-list ⇒ Clean outcome, not the
        // window-deadline release; the default `projection()` helper
        // carries `quarantine_duration_secs: 0` (permissive), which
        // would trip the fast-path on the
        // `Utc::now()`-anchored seed and conflate the two concerns.
        let mut policy = projection(PolicyScope::Global, SeverityThreshold::Critical);
        policy.quarantine_duration_secs = 24 * 3600;
        let policy_id = policy.policy_id;
        projections.insert(policy);
        // Active exclusion drops the one critical finding by exact CVE-id
        // match (per-finding evaluator).
        projections.insert_exclusion(exclusion_for(policy_id, "CVE-A"));

        let findings = vec![Finding {
            purl: "pkg:npm/foo@1".into(),
            vulnerability_id: "CVE-A".into(),
            severity: SeverityThreshold::Critical,
            cvss_score: None,
            title: "t".into(),
            fixed_versions: vec![],
            source_scanner: "trivy".into(),
            references: vec![],
            aliases: vec![],
            informational_class: None,
        }];
        uc.record_scan_result(artifact_id, "trivy".into(), findings, None)
            .await
            .unwrap();

        // Clean path: ScanCompleted only — no Reject events. The
        // clean dual-write routes through the lifecycle
        // port, so a single commit_scan_result lands.
        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events.len(), 1);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::ScanCompleted(_)
        ));
        assert_eq!(
            lifecycle.committed_transitions().len(),
            1,
            "clean record_scan_result still commits the dual-write"
        );
        assert_eq!(lifecycle.last_scan_at_writes().len(), 1);
        let saved = artifacts.get(artifact_id).unwrap();
        assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// License policy alone with empty SBOM input (v1 has no SBOM port)
    /// produces zero license-content violations; the accumulator stays at
    /// Allow → ScanOutcome::Clean. This documents the current behavior
    /// (`evaluate_scan_result` is called with `&[]` for licenses in v1)
    /// — license-content violations become reachable when a follow-on
    /// change wires the SBOM port. The `license-policy-shape`
    /// `Warn` case (operator typo in YAML) is covered by `scan.rs` tests
    /// at the domain layer; in the scan path it does NOT block.
    #[tokio::test]
    async fn record_scan_result_license_policy_no_sbom_input_returns_clean() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let mut policy = projection(PolicyScope::Global, SeverityThreshold::Critical);
        policy.license_policy = serde_json::json!({
            "denied_licenses": ["GPL-3.0"],
            "action": "Block",
        });
        projections.insert(policy);

        let severity = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::ScanCompleted(_)
        ));
        assert_eq!(
            lifecycle.committed_transitions().len(),
            1,
            "clean record_scan_result still commits the dual-write"
        );
        assert_eq!(lifecycle.last_scan_at_writes().len(), 1);
    }

    /// No findings + no policy → Clean; ScanCompleted only.
    #[tokio::test]
    async fn record_scan_result_clean_no_policy() {
        let (uc, artifacts, events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let severity = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events.len(), 1);
        assert!(matches!(
            &batches[0].events[0].event,
            DomainEvent::ScanCompleted(_)
        ));
        assert_eq!(
            lifecycle.committed_transitions().len(),
            1,
            "clean record_scan_result still commits the dual-write"
        );
        assert_eq!(lifecycle.last_scan_at_writes().len(), 1);
        let saved = artifacts.get(artifact_id).unwrap();
        assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// Validation failures (oversized scanner name) short-circuit before
    /// any port call.
    #[tokio::test]
    async fn record_scan_result_oversized_scanner_name() {
        let (uc, artifacts, _events, _lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let big_scanner = "x".repeat(300);
        let severity = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        let err = uc
            .record_scan_result(
                artifact_id,
                big_scanner,
                findings_from_summary(&severity),
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("validation"));
    }

    #[tokio::test]
    async fn record_scan_result_uses_system_actor() {
        let (uc, artifacts, events, _lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let severity = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let batches = events.appended_batches();
        assert_eq!(batches[0].actor, system_actor());
    }

    /// Repository lookup failure during coords resolution propagates as
    /// an error before any event lands. Covers the error path on
    /// `repositories.find_by_id`.
    #[tokio::test]
    async fn record_scan_result_missing_repository_errors() {
        let (uc, artifacts, events, lifecycle, _repositories, _projections) = make_use_case();
        // Insert artifact WITHOUT seeding a repository row — the coords
        // resolution path will fail.
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let artifact_id = artifact.id;
        artifacts.insert(artifact);

        let severity = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        let err = uc
            .record_scan_result(
                artifact_id,
                "trivy".into(),
                findings_from_summary(&severity),
                None,
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not found") || msg.contains("Repository"),
            "expected repository-not-found error, got: {msg}"
        );
        // No events appended, no commit — the failure surfaces before
        // any side effect lands.
        assert!(events.appended_batches().is_empty());
        assert!(lifecycle.committed_transitions().is_empty());
        assert!(lifecycle.last_scan_at_writes().is_empty());
    }

    /// Exclusion-list lookup failure propagates and prevents emission.
    #[tokio::test]
    async fn record_scan_result_exclusion_lookup_failure_propagates() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let policy = projection(PolicyScope::Global, SeverityThreshold::Critical);
        projections.insert(policy);
        projections.fail_next_list_exclusions(DomainError::Invariant("injected".into()));

        let severity = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        let err = uc
            .record_scan_result(
                artifact_id,
                "trivy".into(),
                findings_from_summary(&severity),
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("injected"));
        assert!(events.appended_batches().is_empty());
        assert!(lifecycle.committed_transitions().is_empty());
        assert!(lifecycle.last_scan_at_writes().is_empty());
    }

    // -- event-driven fast-path release on clean scan -------------------------

    /// Seed a quarantined artifact + its repository where the
    /// observation-window anchor is `now - window_age_back`. Used by
    /// the fast-path tests to construct the
    /// deadline-elapsed / deadline-future cases under the 24h
    /// `DefaultPolicy` window without touching the seeded policy.
    fn seed_quarantined_with_anchor(
        artifacts: &Arc<MockArtifactRepository>,
        repositories: &Arc<MockRepositoryRepository>,
        window_age_back: chrono::Duration,
    ) -> Uuid {
        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.quarantine_window_start = Some(Utc::now() - window_age_back);
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let id = artifact.id;
        artifacts.insert(artifact);
        repositories.insert(repo);
        id
    }

    /// Fast-path fires.
    ///
    /// Artifact is `Quarantined` with `quarantine_window_start = now - 25h`;
    /// no operator `ScanPolicy` resolves, so the effective duration is
    /// `DefaultPolicy::quarantine_duration_secs()` (24h). The computed
    /// deadline (`anchor + 24h`) is ~1h in the past at scan-completion
    /// time, so the use case releases the artifact INLINE in the same
    /// batch as `ScanCompleted` rather than waiting for the
    /// `release_expired` sweep. The release uses the accepted pair
    /// `(ReleaseReason::Timer, ReleaseAuthorization::ScanSucceeded)` —
    /// the same pair the sweep already uses; no new authorization.
    #[tokio::test]
    async fn clean_scan_deadline_elapsed_releases_inline() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        // Anchor 25h in the past; default policy = 24h; deadline elapsed by ~1h.
        let artifact_id =
            seed_quarantined_with_anchor(&artifacts, &repositories, chrono::Duration::hours(25));

        // Clean scan — no findings.
        uc.record_scan_result(artifact_id, "trivy".into(), Vec::new(), None)
            .await
            .unwrap();

        // Exactly one transactional commit, carrying BOTH events.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved_artifact, batch, _metadata) = &transitions[0];
        assert_eq!(
            batch.events.len(),
            2,
            "fast-path: ScanCompleted + ArtifactReleased commit in ONE batch (atomicity invariant)"
        );
        assert!(
            matches!(&batch.events[0].event, DomainEvent::ScanCompleted(_)),
            "ScanCompleted must be the first event in the batch"
        );
        let released = match &batch.events[1].event {
            DomainEvent::ArtifactReleased(r) => r,
            other => panic!("expected ArtifactReleased as second event; got {other:?}"),
        };
        // Accepted pair: Timer + ScanSucceeded (the same pair the timer
        // sweep uses for elapsed-deadline-with-clean-scan releases).
        // released_by_user_id / justification stay None — this is a
        // system-driven timer release, not an admin override.
        assert_eq!(released.released_by, ReleaseReason::Timer);
        assert!(released.released_by_user_id.is_none());
        assert!(released.justification.is_none());

        // In-memory artifact state mutated to Released.
        assert_eq!(saved_artifact.quarantine_status, QuarantineStatus::Released);

        // The scan dual-write path was used (last_scan_at written).
        assert_eq!(lifecycle.last_scan_at_writes().len(), 1);

        // Score projection delta reflects the combined transition:
        // scan-completion (last_scan_at) + Quarantined → Released
        // (quarantined_delta = -1, released_delta = +1).
        let deltas = lifecycle.score_deltas();
        assert_eq!(deltas.len(), 1);
        let (_, delta) = &deltas[0];
        assert_eq!(delta.quarantined_delta, -1);
        assert_eq!(delta.released_delta, 1);
        assert!(delta.last_scan_at.is_some());

        // `hort_quarantine_released_total{reason=timer}` is incremented
        // inline by `emit_release(REASON_TIMER)` — reused for both the
        // sweep and the fast-path. The
        // event-batch assertion above is the structural witness;
        // counter-emission is exercised end-to-end by the sweep's
        // existing metric tests (`release_expired_*`).
    }

    /// Fast-path provenance gate (ADR 0007 + ADR 0027).
    ///
    /// Under `provenance_mode = Required`, a clean scan that lands after the
    /// quarantine deadline but BEFORE a `ProvenanceVerified` event exists
    /// resolves to `ProvenanceClearance::Pending`, which denies the timer
    /// arm of `Artifact::release`. The inline fast-path release is therefore
    /// SUPPRESSED: only `ScanCompleted` commits, the artifact stays
    /// `Quarantined`, and `hort_quarantine_released_total{reason=timer}` does
    /// NOT fire. The `release_expired` sweep releases it later, once
    /// provenance verifies. This pins the fix for the scan-completion
    /// fast-path that previously hardcoded `ProvenanceClearance::NotRequired`
    /// and bypassed the `Required`-mode gate.
    #[test]
    fn clean_scan_deadline_elapsed_required_without_provenance_does_not_release_inline() {
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, _events, lifecycle, repositories, projections) =
                    make_use_case();
                // Quarantined, anchor 25h back; the Required policy's
                // quarantine_duration is 0 ⇒ deadline (anchor + 0) is in
                // the past ⇒ the fast-path is a candidate.
                let artifact_id = seed_quarantined_with_anchor(
                    &artifacts,
                    &repositories,
                    chrono::Duration::hours(25),
                );
                let repo_id = artifacts.get(artifact_id).unwrap().repository_id;
                // Required provenance, but NO `ProvenanceVerified` on the
                // stream ⇒ clearance resolves to `Pending`.
                seed_required_provenance_policy(&projections, repo_id);

                uc.record_scan_result(artifact_id, "trivy".into(), Vec::new(), None)
                    .await
                    .unwrap();

                let transitions = lifecycle.committed_transitions();
                assert_eq!(transitions.len(), 1);
                let (saved_artifact, batch, _metadata) = &transitions[0];
                assert_eq!(
                    batch.events.len(),
                    1,
                    "fail-closed: only ScanCompleted commits; the inline release is \
                     suppressed because provenance is Pending (Required, not yet verified)"
                );
                assert!(
                    matches!(&batch.events[0].event, DomainEvent::ScanCompleted(_)),
                    "the single committed event is the clean ScanCompleted"
                );
                assert_eq!(
                    saved_artifact.quarantine_status,
                    QuarantineStatus::Quarantined,
                    "artifact stays quarantined until provenance verifies"
                );
            });
        });

        // A suppressed fast-path must not increment the timer release counter.
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_quarantine_released_total",
                "reason",
                "timer"
            )
            .is_none(),
            "suppressed fast-path must NOT emit hort_quarantine_released_total{{reason=timer}}"
        );
    }

    /// Fast-path provenance gate, cleared (ADR 0027).
    ///
    /// Under `provenance_mode = Required` with a `ProvenanceVerified` event
    /// already on the stream, the clearance resolves to `Cleared`, which
    /// satisfies the timer-arm AND-precondition. A clean scan after the
    /// deadline therefore DOES release inline — `ScanCompleted` +
    /// `ArtifactReleased` commit in one batch, exactly as the default-mode
    /// fast-path does.
    #[tokio::test]
    async fn clean_scan_deadline_elapsed_required_with_provenance_releases_inline() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_quarantined_with_anchor(&artifacts, &repositories, chrono::Duration::hours(25));
        let repo_id = artifacts.get(artifact_id).unwrap().repository_id;
        seed_required_provenance_policy(&projections, repo_id);
        // Stream carries a `ProvenanceVerified` ⇒ clearance `Cleared`.
        seed_stream_scanned_and_provenance_verified(&events, artifact_id);

        uc.record_scan_result(artifact_id, "trivy".into(), Vec::new(), None)
            .await
            .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved_artifact, batch, _metadata) = &transitions[0];
        assert_eq!(
            batch.events.len(),
            2,
            "Required + provenance Cleared: ScanCompleted + ArtifactReleased commit in one batch"
        );
        assert!(matches!(
            &batch.events[0].event,
            DomainEvent::ScanCompleted(_)
        ));
        let released = match &batch.events[1].event {
            DomainEvent::ArtifactReleased(r) => r,
            other => panic!("expected ArtifactReleased; got {other:?}"),
        };
        assert_eq!(released.released_by, ReleaseReason::Timer);
        assert_eq!(saved_artifact.quarantine_status, QuarantineStatus::Released);
    }

    /// Fast-path does NOT fire when the deadline is
    /// still in the future.
    ///
    /// Artifact is `Quarantined` with `quarantine_window_start = now - 1h`
    /// and the default 24h window; the computed deadline (~23h in the
    /// future) has not elapsed, so the artifact stays `Quarantined`.
    /// Only `ScanCompleted` is appended — no `ArtifactReleased`. The
    /// `release_expired` sweep handles release after the deadline passes.
    #[tokio::test]
    async fn clean_scan_deadline_future_stays_quarantined() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        // Anchor 1h ago; default policy = 24h; deadline ~23h in the future.
        let artifact_id =
            seed_quarantined_with_anchor(&artifacts, &repositories, chrono::Duration::hours(1));

        uc.record_scan_result(artifact_id, "trivy".into(), Vec::new(), None)
            .await
            .unwrap();

        // Exactly one transactional commit, carrying ONLY ScanCompleted.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved_artifact, batch, _metadata) = &transitions[0];
        assert_eq!(
            batch.events.len(),
            1,
            "deadline still future ⇒ NO ArtifactReleased in the batch; sweep handles it later"
        );
        assert!(
            matches!(&batch.events[0].event, DomainEvent::ScanCompleted(_)),
            "deadline-future clean path: only ScanCompleted lands"
        );
        for ev in &batch.events {
            assert!(
                !matches!(&ev.event, DomainEvent::ArtifactReleased(_)),
                "ArtifactReleased MUST NOT appear when the deadline is still in the future"
            );
        }

        // Artifact still Quarantined — the `release_expired` sweep is
        // the release path on this branch.
        assert_eq!(
            saved_artifact.quarantine_status,
            QuarantineStatus::Quarantined
        );

        // Score-delta: no status change (no Quarantined → Released bump).
        let deltas = lifecycle.score_deltas();
        assert_eq!(deltas.len(), 1);
        let (_, delta) = &deltas[0];
        assert_eq!(delta.quarantined_delta, 0);
        assert_eq!(delta.released_delta, 0);
    }

    // -- sbom_components projection threading ---------------------------------

    /// When `record_scan_result` is invoked with
    /// `Some(&Sbom)`, the lifecycle port receives the components
    /// slice on the new `sbom_components` arg. The mock records the
    /// pair so we assert the slice is the same components vector
    /// (not None, not empty) — proving the SBOM-replace surface is
    /// actually exercised.
    #[tokio::test]
    async fn record_scan_result_threads_some_sbom_to_lifecycle() {
        use hort_domain::types::sbom::{Ecosystem, Sbom, SbomComponent};

        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let sbom = Sbom {
            subject: None,
            components: vec![
                SbomComponent {
                    purl: "pkg:npm/foo@1.0.0".into(),
                    name: "foo".into(),
                    version: Some("1.0.0".into()),
                    ecosystem: Ecosystem::Npm,
                    licenses: vec![],
                    direct_dependency: true,
                },
                SbomComponent {
                    purl: "pkg:npm/bar@2.0.0".into(),
                    name: "bar".into(),
                    version: Some("2.0.0".into()),
                    ecosystem: Ecosystem::Npm,
                    licenses: vec![],
                    direct_dependency: false,
                },
            ],
        };

        // Clean scan — no findings — so the dual-write commits cleanly
        // through the lifecycle mock (no policy interaction).
        uc.record_scan_result(artifact_id, "trivy".into(), Vec::new(), Some(&sbom))
            .await
            .unwrap();

        let calls = lifecycle.sbom_replace_calls();
        assert_eq!(calls.len(), 1, "expected one lifecycle call");
        assert_eq!(calls[0].0, artifact_id, "artifact_id mismatch");
        let captured = calls[0].1.as_ref().expect(
            "lifecycle must receive Some(components) when record_scan_result got Some(sbom)",
        );
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].purl, "pkg:npm/foo@1.0.0");
        assert_eq!(captured[1].purl, "pkg:npm/bar@2.0.0");
    }

    /// When `record_scan_result` is invoked with
    /// `None` (no SBOM extracted), the lifecycle port receives `None`
    /// on the SBOM arg. The projection write is then skipped by the
    /// adapter and any pre-existing `sbom_components` rows for the
    /// artifact stay ("None → skip" contract).
    #[tokio::test]
    async fn record_scan_result_threads_none_sbom_to_lifecycle() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        uc.record_scan_result(artifact_id, "trivy".into(), Vec::new(), None)
            .await
            .unwrap();

        let calls = lifecycle.sbom_replace_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, artifact_id);
        assert!(
            calls[0].1.is_none(),
            "lifecycle must receive None when record_scan_result got None — \
             the adapter then skips the projection write entirely"
        );
    }

    /// `Some(&Sbom { subject: None, components: vec![] })` (the
    /// "format had a manifest but listed no dependencies" case) is
    /// observably distinct from `None`: the lifecycle still gets
    /// `Some(&[])`, which the adapter interprets as "REPLACE with
    /// nothing" (DELETE existing rows, INSERT none). This pins the
    /// behaviour so an adapter that conflated the two cases would
    /// fail this test.
    #[tokio::test]
    async fn record_scan_result_threads_some_empty_sbom_to_lifecycle() {
        use hort_domain::types::sbom::Sbom;

        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let sbom = Sbom {
            subject: None,
            components: vec![],
        };
        uc.record_scan_result(artifact_id, "trivy".into(), Vec::new(), Some(&sbom))
            .await
            .unwrap();

        let calls = lifecycle.sbom_replace_calls();
        assert_eq!(calls.len(), 1);
        let captured = calls[0].1.as_ref().expect(
            "Some(&Sbom) must surface as Some(_) on the lifecycle, even if components empty",
        );
        assert!(
            captured.is_empty(),
            "empty-components SBOM must arrive as an empty slice on the lifecycle"
        );
    }

    // -- reject path sweeps content_references --------------------------------

    /// Acceptance:
    /// "ingest with metadata blob → assert two rows → reject → assert
    /// both gone." A scan-driven rejection MUST sweep every
    /// `content_references` row whose `source_artifact_id` matches the
    /// rejected artifact, regardless of `kind`. Without this, the
    /// `ArtifactRejected` row stays alive (rejection is sticky — the
    /// artifact is evidence and is not hard-deleted) and the
    /// surviving refcount rows would mislead a future
    /// `PurgeUseCase::process_expired` into treating the blobs as
    /// live references.
    #[tokio::test]
    async fn quarantine_reject_sweeps_content_references() {
        use hort_domain::ports::content_reference_index::ContentReference;
        let (uc, artifacts, _events, _lifecycle, repositories, _projections, content_refs) =
            make_use_case_with_content_refs();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let artifact = artifacts.get(artifact_id).unwrap();
        let repo_id = artifact.repository_id;
        // Seed both refcount rows that the ingest path would have
        // produced for an artifact that took the HashReference
        // metadata-blob split: one primary_content row + one
        // metadata_blob row, sharing the source_artifact_id.
        let primary_hash = artifact.sha256_checksum.clone();
        let blob_hash: ContentHash =
            "1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap();
        content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: primary_hash.clone(),
                kind: "primary_content".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: blob_hash.clone(),
                kind: "metadata_blob".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(
            content_refs.entry_count(),
            2,
            "fixture: two refcount rows seeded for the artifact-about-to-reject"
        );

        // Trigger the Reject path: critical finding under the default
        // policy → block_on_critical fires.
        let severity = SeveritySummary {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        // After reject, every refcount row keyed by this source must
        // be gone — both primary_content and metadata_blob, regardless
        // of kind. The artifact row itself stays alive (Rejected is
        // sticky), so this gone-ness can only be the explicit
        // `delete_by_source` sweep — there is no FK CASCADE to mask it.
        assert_eq!(
            content_refs.entry_count(),
            0,
            "ArtifactRejected must sweep every content_references row for the source"
        );
        let primary_rows = content_refs
            .find_by_target(repo_id, &primary_hash, Some("primary_content"))
            .await
            .unwrap();
        assert_eq!(primary_rows.len(), 0, "primary_content row gone");
        let blob_rows = content_refs
            .find_by_target(repo_id, &blob_hash, Some("metadata_blob"))
            .await
            .unwrap();
        assert_eq!(blob_rows.len(), 0, "metadata_blob row gone");
    }

    /// Branch coverage for the
    /// warn-on-fail arm at `record_scan_result` after `reject_from_scan`.
    /// The refcount sweep is post-commit eventual
    /// — when `delete_by_source` fails, the outer
    /// `record_scan_result` MUST still return `Ok` because the
    /// `ArtifactRejected` event has already been appended and the
    /// rejection is the authoritative state change. The refcount row
    /// is left in place and is repaired by the
    /// `RefcountReconcileUseCase` sweep. The test would fail if a
    /// future change aborts on delete-failure.
    #[tokio::test]
    async fn quarantine_reject_refcount_delete_failure_is_warn_only() {
        use hort_domain::ports::content_reference_index::ContentReference;
        let (uc, artifacts, _events, lifecycle, repositories, _projections, content_refs) =
            make_use_case_with_content_refs();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let artifact = artifacts.get(artifact_id).unwrap();
        let repo_id = artifact.repository_id;

        // Seed one refcount row so the post-reject `delete_by_source`
        // has something to (try to) delete. The test would still
        // exercise the warn arm with zero seeded rows, but the
        // assertion "row remained" is sharper than "still empty".
        let primary_hash = artifact.sha256_checksum.clone();
        content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: primary_hash.clone(),
                kind: "primary_content".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(content_refs.entry_count(), 1, "fixture seeded");

        // Arm the failure on the next delete_by_source call.
        content_refs.fail_next_delete(DomainError::Invariant(
            "synthetic failure: delete_by_source on reject".into(),
        ));

        // Trigger the Reject path. The reject event must commit and
        // the outer call must return Ok despite the refcount sweep
        // failure.
        let severity = SeveritySummary {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .expect("record_scan_result must succeed even when refcount sweep fails");

        // The reject event committed — exactly one ArtifactRejected
        // transition recorded by the lifecycle mock. A future change
        // that aborts the use case on delete-failure would either
        // produce zero transitions (commit happened first, was then
        // unwound — but the mock doesn't unwind, so the count stays
        // 1 either way) or surface the error to the caller above
        // and fail the `.expect`.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(
            transitions.len(),
            1,
            "ArtifactRejected must still commit when refcount delete_by_source fails"
        );

        // The seeded refcount row remained — the failed sweep was
        // warned and skipped, exactly the drift Item B3.5 is
        // designed to repair.
        assert_eq!(
            content_refs.entry_count(),
            1,
            "warn-on-fail must leave the seeded row in place; reconcile is future work"
        );
        let rows = content_refs
            .find_by_target(repo_id, &primary_hash, Some("primary_content"))
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "primary_content row still present after the warn arm fired"
        );
    }

    /// Reject path: `ArtifactRejected.reason` carries the first
    /// violation's message verbatim. PolicyEvaluated.violations holds
    /// all of them.
    #[tokio::test]
    async fn record_scan_result_reject_reason_uses_first_violation_message() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let severity = SeveritySummary {
            critical: 1,
            high: 1,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let transitions = lifecycle.committed_transitions();
        let batch = &transitions[0].1;
        let DomainEvent::PolicyEvaluated(policy_event) = &batch.events[1].event else {
            panic!("PolicyEvaluated expected");
        };
        let DomainEvent::ArtifactRejected(reject_event) = &batch.events[2].event else {
            panic!("ArtifactRejected expected");
        };
        // Default Critical threshold means `critical` is the first
        // tier above threshold; cve.rs accumulates one violation per
        // non-zero tier above threshold.
        assert_eq!(reject_event.reason, policy_event.violations[0].message);
    }

    // -- admin_release tests -------------------------------------------------

    /// Justification used by `admin_release` happy-path tests.
    /// 80-byte free text — well under the 512-byte cap, includes a
    /// realistic CVE-acceptance phrasing so the assertions on the
    /// emitted event read meaningfully.
    fn sample_justification() -> String {
        "CVE-2026-XXXX accepted: false-positive after manual review on 2026-04-30".into()
    }

    #[test]
    fn admin_release_success() {
        let actor = api_actor();
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, _events, lifecycle, repositories, _projections) =
                    make_use_case();
                let artifact_id = seed_artifact_with_repo(
                    &artifacts,
                    &repositories,
                    QuarantineStatus::Quarantined,
                );

                uc.admin_release(
                    artifact_id,
                    actor.clone(),
                    admin_privileges(),
                    sample_justification(),
                )
                .await
                .unwrap();

                let transitions = lifecycle.committed_transitions();
                assert_eq!(transitions.len(), 1);
                let (saved_artifact, batch, _metadata) = &transitions[0];
                assert!(matches!(
                    &batch.events[0].event,
                    DomainEvent::ArtifactReleased(_)
                ));
                assert_eq!(batch.actor, Actor::Api(actor.clone()));
                assert_eq!(saved_artifact.quarantine_status, QuarantineStatus::Released);

                // Assert the emitted event is attributable:
                // released_by_user_id matches the actor's user_id and
                // justification carries the operator-supplied text.
                let DomainEvent::ArtifactReleased(release_event) = &batch.events[0].event else {
                    panic!("expected ArtifactReleased")
                };
                assert_eq!(release_event.released_by, ReleaseReason::Admin);
                assert_eq!(release_event.released_by_user_id, Some(actor.user_id));
                assert_eq!(release_event.justification, Some(sample_justification()));
            });
        });

        let entries = snap.into_vec();
        assert_release_counter(&entries, "admin", 1);
    }

    #[tokio::test]
    async fn admin_release_without_admin_forbidden() {
        let (uc, artifacts, _events, _lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let err = uc
            .admin_release(
                artifact_id,
                api_actor(),
                unprivileged(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("admin"));
    }

    #[tokio::test]
    async fn admin_release_non_quarantined_fails() {
        let (uc, artifacts, _events, _lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::None);

        let err = uc
            .admin_release(
                artifact_id,
                api_actor(),
                admin_privileges(),
                sample_justification(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot release"));
    }

    // -- release_expired tests (real release authority, ADR 0007) -------------

    /// The MANDATORY fail-closed regression (ADR 0007).
    /// A `Quarantined` artifact whose window has expired (candidacy
    /// satisfied) with **no** successful `ScanCompleted` on its stream
    /// AND **no** `scan_backends:[]` waiver is **NOT** released by
    /// `release_expired` — it stays quarantined. The app layer can
    /// construct neither `ScanSucceeded` (no `ScanCompleted`) nor
    /// `ScanWaived` (the seeded policy has `scan_backends:["trivy"]`),
    /// so no authority is passed to `Artifact::release` and the
    /// candidate falls through the "skipping: not in releasable state"
    /// arm. This is the latent-Critical guard. Do NOT "fix"
    /// this by unconditionally minting `ScanSucceeded` — that re-opens
    /// the never-successfully-scanned auto-release.
    #[test]
    fn release_expired_fail_closed_does_not_release_unscanned() {
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, _events, lifecycle, repositories, projections) =
                    make_use_case();

                let id1 = seed_artifact_with_repo(
                    &artifacts,
                    &repositories,
                    QuarantineStatus::Quarantined,
                );
                let id2 = seed_artifact_with_repo(
                    &artifacts,
                    &repositories,
                    QuarantineStatus::Quarantined,
                );
                // Seed a *scanning* policy (scan_backends:["trivy"]) for
                // each repo so the only path to release would be a
                // successful ScanCompleted — which we deliberately do
                // NOT seed. No ScanCompleted ∧ no waiver ⇒ fail-closed.
                for id in [id1, id2] {
                    let repo_id = artifacts.get(id).unwrap().repository_id;
                    projections.insert(projection(
                        PolicyScope::Repository(repo_id),
                        SeverityThreshold::Critical,
                    ));
                }
                // already released — not a releasable state regardless.
                let id3 =
                    seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Released);
                let ids = vec![id1, id2, id3];

                let released = uc.release_expired(ids).await.unwrap();

                // Nothing is released — no authority is constructible
                // for any candidate.
                assert!(
                    released.is_empty(),
                    "fail-closed: a never-successfully-scanned, non-waived \
                     artifact must NOT timer-release on window expiry"
                );

                // No atomic transitions committed at all.
                let transitions = lifecycle.committed_transitions();
                assert!(transitions.is_empty());
            });
        });

        // No release → the timer counter never fires.
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_quarantine_released_total",
                "reason",
                "timer"
            )
            .is_none(),
            "fail-closed: hort_quarantine_released_total{{reason=timer}} must not fire"
        );
    }

    /// A candidate with a successful `ScanCompleted` on its
    /// stream is released via `ReleaseAuthorization::ScanSucceeded`. The
    /// atomic transition lands `ArtifactReleased` with the timer actor
    /// and `ReleaseReason::Timer`.
    #[tokio::test]
    async fn release_expired_releases_via_scan_succeeded() {
        let (uc, artifacts, events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        seed_stream_with_scan_completed(&events, artifact_id);

        let released = uc.release_expired(vec![artifact_id]).await.unwrap();

        assert_eq!(released, vec![artifact_id]);
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved, batch, _meta) = &transitions[0];
        assert_eq!(saved.quarantine_status, QuarantineStatus::Released);
        assert_eq!(batch.events.len(), 1);
        let DomainEvent::ArtifactReleased(ev) = &batch.events[0].event else {
            panic!("ArtifactReleased expected");
        };
        assert_eq!(ev.released_by, ReleaseReason::Timer);
        // Timer release is system-driven attribution, never admin.
        assert!(ev.released_by_user_id.is_none());
        assert!(ev.justification.is_none());
        assert_eq!(batch.actor, timer_actor());
    }

    /// A candidate whose resolved `ScanPolicy` has
    /// `scan_backends == []` (scanning waived by operator policy) is
    /// released via `ReleaseAuthorization::ScanWaived` even with **no**
    /// `ScanCompleted` on its stream.
    #[tokio::test]
    async fn release_expired_releases_via_scan_waived() {
        let (uc, artifacts, _events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let repo_id = artifacts.get(artifact_id).unwrap().repository_id;
        seed_scan_waived_policy(&projections, repo_id);

        let released = uc.release_expired(vec![artifact_id]).await.unwrap();

        assert_eq!(released, vec![artifact_id]);
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved, batch, _meta) = &transitions[0];
        assert_eq!(saved.quarantine_status, QuarantineStatus::Released);
        let DomainEvent::ArtifactReleased(ev) = &batch.events[0].event else {
            panic!("ArtifactReleased expected");
        };
        assert_eq!(ev.released_by, ReleaseReason::Timer);
    }

    /// Seed a repo-scoped policy with
    /// `provenance_mode = Required` (+ a valid identity so the apply-time
    /// linter would accept it; the projection
    /// shape mirrors a valid one). `scan_backends` stays non-empty so the
    /// scan gate still requires a `ScanCompleted` — the sweep tests pair
    /// this with `seed_stream_with_scan_completed` so the scan authority is
    /// satisfied and the provenance gate is the variable under test.
    fn seed_required_provenance_policy(
        projections: &Arc<MockPolicyProjectionRepository>,
        repository_id: Uuid,
    ) {
        let mut p = projection(
            PolicyScope::Repository(repository_id),
            SeverityThreshold::Critical,
        );
        p.provenance_mode = ProvenanceMode::Required;
        p.provenance_backends = vec!["cosign".to_string()];
        p.provenance_identities = vec![
            hort_domain::entities::scan_policy::SignerIdentityPattern::new(
                "https://token.actions.githubusercontent.com",
                "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
            )
            .expect("valid identity pattern"),
        ];
        projections.insert(p);
    }

    /// Seed an artifact stream carrying
    /// `ArtifactQuarantined` + `ScanCompleted` (so the scan gate passes)
    /// **plus** a `ProvenanceVerified` event (so the provenance gate
    /// clears). Used by the `Required` + cleared sweep test. Built as one
    /// full stream (the `MockEventStore` has no append-on-existing getter;
    /// `set_stream` replaces wholesale).
    fn seed_stream_scanned_and_provenance_verified(
        events: &Arc<MockEventStore>,
        artifact_id: Uuid,
    ) {
        let stream_id = StreamId::artifact(artifact_id);
        let quarantined = dummy_persisted_event(&stream_id, artifact_id, 0);
        let scan_completed = PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream_id.clone(),
            stream_position: 1,
            global_position: 2,
            event: DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "trivy".into(),
                finding_count: 0,
                severity_summary: SeveritySummary {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    negligible: 0,
                },
                findings_blob: None,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: system_actor(),
            event_version: 1,
            stored_at: Utc::now(),
        };
        let verified = PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream_id.clone(),
            stream_position: 2,
            global_position: 3,
            event: DomainEvent::ProvenanceVerified(hort_domain::events::ProvenanceVerified {
                artifact_id,
                content_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .parse()
                    .unwrap(),
                backend: "cosign".into(),
                signer: hort_domain::ports::provenance::SignerIdentity {
                    issuer: "https://token.actions.githubusercontent.com".into(),
                    san:
                        "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                            .into(),
                },
                predicate_type: None,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: system_actor(),
            event_version: 1,
            stored_at: Utc::now(),
        };
        events.set_stream(&stream_id, vec![quarantined, scan_completed, verified]);
    }

    /// A `Required`-mode artifact with NO
    /// `ProvenanceVerified` event does NOT timer-release even when the scan
    /// gate (`ScanCompleted`) passes. The provenance clearance computes to
    /// `Pending`, which denies the timer arm (fail-closed).
    #[tokio::test]
    async fn release_expired_required_without_provenance_verified_does_not_release() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let repo_id = artifacts.get(artifact_id).unwrap().repository_id;
        // Scan gate passes (ScanCompleted on stream) ...
        seed_stream_with_scan_completed(&events, artifact_id);
        // ... but the policy is Required and there is NO ProvenanceVerified.
        seed_required_provenance_policy(&projections, repo_id);

        let released = uc.release_expired(vec![artifact_id]).await.unwrap();

        assert!(
            released.is_empty(),
            "Required + no ProvenanceVerified ⇒ Pending ⇒ NOT released, \
             even though the scan gate passes"
        );
        assert!(
            lifecycle.committed_transitions().is_empty(),
            "fail-closed: no release transition committed"
        );
    }

    /// A `Required`-mode artifact WITH a
    /// `ProvenanceVerified` event DOES timer-release (the scan gate also
    /// passing). The provenance clearance computes to `Cleared`, which
    /// satisfies the AND-precondition on the timer arm.
    #[tokio::test]
    async fn release_expired_required_with_provenance_verified_releases() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let repo_id = artifacts.get(artifact_id).unwrap().repository_id;
        // Stream carries ScanCompleted (scan gate) + ProvenanceVerified
        // (provenance gate).
        seed_stream_scanned_and_provenance_verified(&events, artifact_id);
        seed_required_provenance_policy(&projections, repo_id);

        let released = uc.release_expired(vec![artifact_id]).await.unwrap();

        assert_eq!(
            released,
            vec![artifact_id],
            "Required + ProvenanceVerified ⇒ Cleared ⇒ released (scan gate passing)"
        );
        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved, batch, _meta) = &transitions[0];
        assert_eq!(saved.quarantine_status, QuarantineStatus::Released);
        let DomainEvent::ArtifactReleased(ev) = &batch.events[0].event else {
            panic!("ArtifactReleased expected");
        };
        assert_eq!(ev.released_by, ReleaseReason::Timer);
    }

    /// A `VerifyIfPresent`-mode artifact timer-releases
    /// normally (provenance never gates release in that mode — the
    /// clearance is `NotRequired`), with the scan gate passing.
    #[tokio::test]
    async fn release_expired_verify_if_present_releases_normally() {
        let (uc, artifacts, events, _lifecycle, repositories, projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let repo_id = artifacts.get(artifact_id).unwrap().repository_id;
        seed_stream_with_scan_completed(&events, artifact_id);
        // Default projection() carries provenance_mode = VerifyIfPresent.
        projections.insert(projection(
            PolicyScope::Repository(repo_id),
            SeverityThreshold::Critical,
        ));

        let released = uc.release_expired(vec![artifact_id]).await.unwrap();

        assert_eq!(
            released,
            vec![artifact_id],
            "VerifyIfPresent never gates release — clearance is NotRequired"
        );
    }

    /// `quarantine_until` is the sweep's
    /// *candidacy* filter only, NEVER a release authority. This test
    /// proves the converse of authority: an artifact whose
    /// `quarantine_until` is still in the future but which has a
    /// successful `ScanCompleted` IS released (authority, not the
    /// clock, drives release). `release_expired` takes a pre-filtered
    /// candidate list — it never inspects `quarantine_until` itself; the
    /// release decision is purely the `ScanSucceeded`/`ScanWaived`
    /// authority. Symmetrically, the
    /// `release_expired_fail_closed_does_not_release_unscanned` test
    /// proves an *expired* window with no authority does NOT release —
    /// together they pin "expiry is candidacy, authority is release".
    #[tokio::test]
    async fn release_expired_quarantine_window_is_candidacy_only_not_authority() {
        let (uc, artifacts, events, lifecycle, repositories, _projections) = make_use_case();
        // Artifact whose stored window anchor is set; the candidacy
        // computation lives in the adapter's query, never in
        // `release_expired` itself.
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let pre = artifacts.get(artifact_id).unwrap().quarantine_window_start;
        assert!(
            pre.is_some(),
            "fixture precondition: a quarantined artifact carries a window anchor"
        );
        // The authority — a successful ScanCompleted — exists.
        seed_stream_with_scan_completed(&events, artifact_id);

        let released = uc.release_expired(vec![artifact_id]).await.unwrap();

        // Released because authority exists, NOT because of the clock:
        // `release_expired` never reads the window.
        assert_eq!(
            released,
            vec![artifact_id],
            "release is driven by ScanSucceeded authority, not the window"
        );
        assert_eq!(lifecycle.committed_transitions().len(), 1);
    }

    /// Mixed batch: only the authorized candidates release;
    /// the fail-closed one does NOT, and the sweep continues past it
    /// (the skip arm does not abort the loop). Three artifacts:
    /// (a) ScanCompleted → released; (b) scan_backends:[] → released;
    /// (c) no scan, no waiver → stays quarantined.
    #[tokio::test]
    async fn release_expired_mixed_batch_only_authorized_release_sweep_continues() {
        let (uc, artifacts, events, lifecycle, repositories, projections) = make_use_case();

        let a_succeeded =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        seed_stream_with_scan_completed(&events, a_succeeded);

        let b_waived =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let b_repo = artifacts.get(b_waived).unwrap().repository_id;
        seed_scan_waived_policy(&projections, b_repo);

        let c_failclosed =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let c_repo = artifacts.get(c_failclosed).unwrap().repository_id;
        // Scanning policy, no ScanCompleted ⇒ no authority.
        projections.insert(projection(
            PolicyScope::Repository(c_repo),
            SeverityThreshold::Critical,
        ));

        // Order the fail-closed one in the MIDDLE so we prove the skip
        // does not abort the remaining iterations.
        let released = uc
            .release_expired(vec![a_succeeded, c_failclosed, b_waived])
            .await
            .unwrap();

        assert_eq!(released.len(), 2, "exactly the two authorized release");
        assert!(released.contains(&a_succeeded));
        assert!(released.contains(&b_waived));
        assert!(
            !released.contains(&c_failclosed),
            "fail-closed: the unscanned, non-waived artifact must NOT release"
        );
        assert_eq!(
            lifecycle.committed_transitions().len(),
            2,
            "sweep continues past the skipped candidate"
        );
    }

    /// The resolved `info!` line on an actual timer release
    /// carries the authority kind: `scan_succeeded` for a ScanCompleted
    /// release, `scan_waived` for a `scan_backends:[]` release. Tracing-
    /// only (no new metric).
    #[test]
    fn release_expired_info_log_carries_resolved_authority_kind() {
        install_audit_passthrough_subscriber();
        let _serial = AUDIT_TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = AuditCapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (uc, artifacts, events, _lifecycle, repositories, projections) = make_use_case();

            let a_succeeded =
                seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
            seed_stream_with_scan_completed(&events, a_succeeded);

            let b_waived =
                seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
            let b_repo = artifacts.get(b_waived).unwrap().repository_id;
            seed_scan_waived_policy(&projections, b_repo);

            uc.release_expired(vec![a_succeeded, b_waived])
                .await
                .unwrap();
        });

        let records = captured.lock().unwrap();
        assert!(
            records.iter().any(|(lvl, msg)| *lvl == tracing::Level::INFO
                && msg.contains("released expired artifact")
                && msg.contains("scan_succeeded")),
            "B11: info! release line must carry authority=scan_succeeded; saw {records:?}"
        );
        assert!(
            records.iter().any(|(lvl, msg)| *lvl == tracing::Level::INFO
                && msg.contains("released expired artifact")
                && msg.contains("scan_waived")),
            "B11: info! release line must carry authority=scan_waived; saw {records:?}"
        );
    }

    #[tokio::test]
    async fn release_expired_empty_list() {
        let (uc, _artifacts, _events, _lifecycle, _repositories, _projections) = make_use_case();
        let released = uc.release_expired(vec![]).await.unwrap();
        assert!(released.is_empty());
    }

    /// `release_authority_label` maps every
    /// [`ReleaseAuthorization`] arm. The two timer authorities
    /// (`ScanSucceeded`/`ScanWaived`) are the live mapping; the
    /// `AdminOverride`/`PolicyReEvaluation` arms are an
    /// exhaustive-match guard (never reached on the timer path) and are
    /// pinned here so the 100%-coverage `hort-app` requirement holds
    /// without a reachable production caller for them.
    #[test]
    fn release_authority_label_maps_every_arm() {
        assert_eq!(
            release_authority_label(ReleaseAuthorization::ScanSucceeded),
            "scan_succeeded"
        );
        assert_eq!(
            release_authority_label(ReleaseAuthorization::ScanWaived),
            "scan_waived"
        );
        assert_eq!(
            release_authority_label(ReleaseAuthorization::AdminOverride),
            "admin_override"
        );
        assert_eq!(
            release_authority_label(ReleaseAuthorization::PolicyReEvaluation),
            "policy_re_evaluation"
        );
    }

    // -- record_scan_indeterminate tests --------------------------------------

    /// Strict mode: a `Quarantined` artifact whose scan job exhausted
    /// retries transitions to `ScanIndeterminate`. The event +
    /// status transition commit atomically via the EXISTING
    /// `commit_transition_with_score` (one transition recorded).
    #[tokio::test]
    async fn record_scan_indeterminate_from_quarantined_commits_transition() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        uc.record_scan_indeterminate(
            artifact_id,
            "trivy,osv".into(),
            "all backends down".into(),
            5,
        )
        .await
        .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (saved, batch, _meta) = &transitions[0];
        assert_eq!(saved.quarantine_status, QuarantineStatus::ScanIndeterminate);
        assert_eq!(batch.events.len(), 1);
        let DomainEvent::ScanIndeterminate(ev) = &batch.events[0].event else {
            panic!("expected ScanIndeterminate event")
        };
        assert_eq!(ev.artifact_id, artifact_id);
        assert_eq!(ev.scanner, "trivy,osv");
        assert_eq!(ev.reason, "all backends down");
        assert_eq!(ev.attempts, 5);
        // System actor — no operator attribution on a fail-closed
        // system transition (mirrors record_scan_result).
        assert_eq!(batch.actor, system_actor());
    }

    /// Permissive mode (quarantineDuration:0): a `None` artifact (still
    /// downloadable today — fail-open until first scan) transitions
    /// to `ScanIndeterminate`, retroactively blocking downloads.
    #[tokio::test]
    async fn record_scan_indeterminate_from_none_permissive_hard_blocks() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::None);

        uc.record_scan_indeterminate(artifact_id, "trivy".into(), "scanner crashed".into(), 5)
            .await
            .unwrap();

        let transitions = lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let saved = &transitions[0].0;
        assert_eq!(saved.quarantine_status, QuarantineStatus::ScanIndeterminate);
        assert!(!saved.is_downloadable());
    }

    /// Idempotent skip: an artifact already in a terminal state
    /// (`ScanIndeterminate`/`Rejected`/`Released`) returns Ok (recoverable
    /// skip) and commits NO transition — mirrors the corruption path's
    /// already-terminal branch.
    #[tokio::test]
    async fn record_scan_indeterminate_already_terminal_is_recoverable_skip() {
        for status in [
            QuarantineStatus::ScanIndeterminate,
            QuarantineStatus::Rejected,
            QuarantineStatus::Released,
        ] {
            let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
            let artifact_id = seed_artifact_with_repo(&artifacts, &repositories, status);

            // Returns Ok — the orchestrator treats it as a recoverable
            // "already terminal" skip, not a hard error.
            uc.record_scan_indeterminate(artifact_id, "trivy".into(), "down".into(), 5)
                .await
                .unwrap();

            assert!(
                lifecycle.committed_transitions().is_empty(),
                "no duplicate event/transition for already-{status} artifact"
            );
        }
    }

    /// Load failure (artifact not found) propagates as an error — the
    /// orchestrator must not silently swallow a missing artifact.
    #[tokio::test]
    async fn record_scan_indeterminate_load_failure_propagates() {
        let (uc, _artifacts, _events, lifecycle, _repositories, _projections) = make_use_case();
        let missing = Uuid::new_v4();

        let err = uc
            .record_scan_indeterminate(missing, "trivy".into(), "down".into(), 5)
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("artifact"));
        assert!(lifecycle.committed_transitions().is_empty());
    }

    /// Commit failure propagates (the atomic event+state append failed).
    #[tokio::test]
    async fn record_scan_indeterminate_commit_failure_propagates() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        lifecycle.fail_next_commit(DomainError::Invariant("boom".into()));

        let err = uc
            .record_scan_indeterminate(artifact_id, "trivy".into(), "down".into(), 5)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("boom"));
    }

    /// The `hort_scan_terminal_total{result}` metric
    /// is NOT emitted by this use case (it is emitted at exactly one
    /// layer: `scan_orchestration::record_outcome`). Asserting absence
    /// here pins the one-metric-one-layer rule.
    #[test]
    fn record_scan_indeterminate_does_not_emit_terminal_metric() {
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, _events, _lifecycle, repositories, _projections) =
                    make_use_case();
                let artifact_id = seed_artifact_with_repo(
                    &artifacts,
                    &repositories,
                    QuarantineStatus::Quarantined,
                );
                uc.record_scan_indeterminate(artifact_id, "trivy".into(), "down".into(), 5)
                    .await
                    .unwrap();
            });
        });
        let entries = snap.into_vec();
        assert!(
            !entries
                .iter()
                .any(|(ck, _, _, _)| ck.key().name() == "hort_scan_terminal_total"),
            "hort_scan_terminal_total must be emitted only by scan_orchestration::record_outcome"
        );
    }

    // -- truncate_reason unit tests --------------------------------------------

    /// Short reason (≤256 bytes) is returned as-is (Borrowed variant —
    /// no allocation, no `…` suffix).
    #[test]
    fn truncate_reason_short_returns_unchanged() {
        let input = "scanner timeout";
        let got = truncate_reason(input);
        assert_eq!(
            got.as_ref(),
            input,
            "short reason must pass through unchanged"
        );
        // Borrow means no copy — verify the pointer equality as a proxy.
        assert!(
            matches!(got, std::borrow::Cow::Borrowed(_)),
            "short reason must be Cow::Borrowed (no allocation)"
        );
    }

    /// Reason exactly 256 bytes is still short — boundary must not
    /// truncate.
    #[test]
    fn truncate_reason_exactly_256_bytes_returns_unchanged() {
        // 256 ASCII 'a' chars = 256 bytes.
        let input = "a".repeat(256);
        let got = truncate_reason(&input);
        assert_eq!(got.as_ref(), input.as_str());
    }

    /// Reason longer than 256 bytes is truncated with a `…` suffix and
    /// the result is shorter than the input. This exercises lines
    /// 1102-1106 (the Owned / format branch).
    #[test]
    fn truncate_reason_long_ascii_is_truncated_with_ellipsis() {
        // 300 ASCII 'x' chars — well above the 256-byte threshold.
        let input = "x".repeat(300);
        let got = truncate_reason(&input);
        assert!(
            got.ends_with('…'),
            "truncated reason must end with the ellipsis character"
        );
        assert!(
            got.len() < input.len(),
            "truncated reason must be shorter than the input"
        );
        // The result must be valid UTF-8 (String/&str are always UTF-8
        // in Rust, but this assertion documents the contract explicitly).
        assert!(std::str::from_utf8(got.as_bytes()).is_ok());
    }

    /// Reason whose 256-byte boundary falls *inside* a multi-byte UTF-8
    /// character exercises the `while !reason.is_char_boundary(end) { end -= 1 }`
    /// loop (lines 1103-1104). The loop must back up to a valid boundary
    /// so the slice is sound and the result is valid UTF-8.
    ///
    /// Construction: fill 255 ASCII bytes, then append a 2-byte UTF-8
    /// character (`é` = U+00E9, encoded as `\xc3\xa9`). The boundary
    /// between the 255th and 256th byte is the first byte of `é` — a
    /// non-char-boundary — so the loop fires.
    #[test]
    fn truncate_reason_multibyte_boundary_does_not_panic_and_produces_valid_utf8() {
        // 255 ASCII 'a' chars + 'é' (2 bytes) + enough 'b' chars to push
        // total well past 256 bytes.  The naive 256-byte cut lands inside
        // 'é' — the char-boundary loop must retreat one byte to 255.
        let mut input = "a".repeat(255);
        input.push('é'); // 2 bytes: 0xc3 0xa9 — straddles the cut
        input.push_str(&"b".repeat(50)); // ensure total > 256
        assert!(
            input.len() > 256,
            "input must exceed 256 bytes for the long branch to fire"
        );

        // Must not panic.
        let got = truncate_reason(&input);

        // Result must be valid UTF-8.
        assert!(
            std::str::from_utf8(got.as_bytes()).is_ok(),
            "truncated string must be valid UTF-8"
        );
        // Must carry the ellipsis suffix.
        assert!(
            got.ends_with('…'),
            "must end with ellipsis after multibyte trim"
        );
        // Must be shorter than the input.
        assert!(got.len() < input.len(), "must be shorter than the input");
    }

    // -- policy-evaluation metric emission tests -------------------------------

    fn find_counter(entries: &[MetricEntry], name: &str, label: &str, value: &str) -> Option<u64> {
        entries.iter().find_map(|(ck, _, _, v)| {
            if ck.kind() == MetricKind::Counter
                && ck.key().name() == name
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == label && l.value() == value)
            {
                match v {
                    DebugValue::Counter(c) => Some(*c),
                    _ => None,
                }
            } else {
                None
            }
        })
    }

    /// Reject path emits `decision_point=scan_result, result=reject` and
    /// at least one violations counter (catalog rule: emission per
    /// distinct rule, not per violation).
    #[test]
    fn record_scan_result_reject_emits_evaluation_and_violations_metrics() {
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, _events, _lifecycle, repositories, _projections) =
                    make_use_case();
                let artifact_id = seed_artifact_with_repo(
                    &artifacts,
                    &repositories,
                    QuarantineStatus::Quarantined,
                );

                let severity = SeveritySummary {
                    critical: 1,
                    high: 0,
                    medium: 0,
                    low: 0,
                    negligible: 0,
                };
                uc.record_scan_result(
                    artifact_id,
                    "trivy".into(),
                    findings_from_summary(&severity),
                    None,
                )
                .await
                .unwrap();
            });
        });

        let entries = snap.into_vec();
        assert_eq!(
            find_counter(
                &entries,
                "hort_policy_evaluation_total",
                "decision_point",
                "scan_result",
            ),
            Some(1),
            "scan_result evaluation counter must fire on reject"
        );
        assert_eq!(
            find_counter(&entries, "hort_policy_evaluation_total", "result", "reject"),
            Some(1),
            "result=reject must be emitted"
        );
        // At least one violation rule must be reported.
        assert!(
            entries
                .iter()
                .any(|(ck, _, _, _)| ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_policy_violations_total"),
            "violations counter must fire on reject"
        );
    }

    /// Clean path emits `decision_point=scan_result, result=pass` and NO
    /// violations counter.
    #[test]
    fn record_scan_result_clean_emits_pass_no_violations() {
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let (uc, artifacts, _events, _lifecycle, repositories, _projections) =
                    make_use_case();
                let artifact_id = seed_artifact_with_repo(
                    &artifacts,
                    &repositories,
                    QuarantineStatus::Quarantined,
                );

                let severity = SeveritySummary {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    negligible: 0,
                };
                uc.record_scan_result(
                    artifact_id,
                    "trivy".into(),
                    findings_from_summary(&severity),
                    None,
                )
                .await
                .unwrap();
            });
        });

        let entries = snap.into_vec();
        assert_eq!(
            find_counter(&entries, "hort_policy_evaluation_total", "result", "pass"),
            Some(1),
            "result=pass must be emitted on Clean outcome"
        );
        assert!(
            !entries
                .iter()
                .any(|(ck, _, _, _)| ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_policy_violations_total"),
            "no violations counter on Clean"
        );
    }

    /// Fail-closed regression: a `Quarantined`
    /// artifact with no `ScanCompleted` on its stream and no resolvable
    /// policy at all (so neither `ScanSucceeded` nor a `scan_backends:[]`
    /// `ScanWaived` can be constructed — absent policy is governed by
    /// `DefaultPolicy`, which scans, not a waiver) commits **no**
    /// transition. The released-event shape (timer actor, no admin
    /// attribution) is covered by
    /// `release_expired_releases_via_scan_succeeded`.
    #[tokio::test]
    async fn release_expired_fail_closed_commits_no_transition() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        let released = uc.release_expired(vec![artifact_id]).await.unwrap();

        assert!(released.is_empty());
        assert!(lifecycle.committed_transitions().is_empty());
    }

    // -- audit-log completeness ------------------------------------------------
    //
    // AUDIT-info-1: `admin_release` SUCCESS log line must include `user_id`
    //   (the DENIAL branch already does); SOC operators correlate by user_id
    //   across denial+success.
    // AUDIT-info-2: `record_scan_result` (system_actor path) and
    //   `release_expired` (timer_actor path) log lines must include
    //   `correlation_id` — the value is already minted on the event, the
    //   log line was missing it.
    //
    // The capture infrastructure mirrors `repository_access.rs`'s
    // `Write-grant denial log assertion` block — see the comments there
    // for why `Interest::sometimes()`, the global passthrough subscriber,
    // and the serialising mutex are all required.

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    #[derive(Clone, Default)]
    struct AuditCapturingLayer {
        records: Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for AuditCapturingLayer
    where
        S: tracing::Subscriber,
    {
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = AuditMessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }
    }

    #[derive(Default)]
    struct AuditMessageVisitor {
        combined: String,
    }
    impl tracing::field::Visit for AuditMessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    static AUDIT_TRACING_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn install_audit_passthrough_subscriber() {
        use std::sync::OnceLock;
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let global_layer = AuditCapturingLayer::default();
            let global_subscriber = Registry::default().with(global_layer);
            let _ = tracing::subscriber::set_global_default(global_subscriber);
        });
    }

    /// AUDIT-info-1: `admin_release` success info-log carries `user_id`,
    /// matching the denial branch's shape so SOC can correlate.
    #[test]
    fn admin_release_success_log_carries_user_id() {
        install_audit_passthrough_subscriber();
        let _serial = AUDIT_TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = AuditCapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let actor = api_actor();
        let actor_user_id = actor.user_id;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (uc, artifacts, _events, _lifecycle, repositories, _projections) = make_use_case();
            let artifact_id =
                seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
            uc.admin_release(
                artifact_id,
                actor.clone(),
                admin_privileges(),
                sample_justification(),
            )
            .await
            .unwrap();
        });

        let records = captured.lock().unwrap();
        let success_event = records
            .iter()
            .find(|(_, msg)| msg.contains("admin released quarantined artifact"))
            .expect("expected admin_release success info log");
        let msg = &success_event.1;
        assert!(
            msg.contains(&actor_user_id.to_string()),
            "admin_release success log must carry user_id (AUDIT-info-1): {msg}"
        );
    }

    /// AUDIT-info-2 (system_actor path): `record_scan_result`'s info log
    /// includes `correlation_id`. We exercise the Reject branch (critical
    /// finding under the default policy) so the structured log line fires.
    #[test]
    fn record_scan_result_log_carries_correlation_id() {
        install_audit_passthrough_subscriber();
        let _serial = AUDIT_TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = AuditCapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (uc, artifacts, _events, _lifecycle, repositories, _projections) = make_use_case();
            let artifact_id =
                seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
            let severity = SeveritySummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            };
            uc.record_scan_result(
                artifact_id,
                "trivy".into(),
                findings_from_summary(&severity),
                None,
            )
            .await
            .unwrap();
        });

        let records = captured.lock().unwrap();
        let scan_event = records
            .iter()
            .find(|(_, msg)| msg.contains("scan-result evaluated"))
            .expect("expected scan-result info log");
        let msg = &scan_event.1;
        assert!(
            msg.contains("correlation_id"),
            "record_scan_result info log must carry correlation_id (AUDIT-info-2): {msg}"
        );
    }

    // -- score-projection wiring tests ------------------------------------------

    #[tokio::test]
    async fn quarantine_artifact_threads_score_delta_to_lifecycle() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::None);
        let until = Utc::now() + chrono::Duration::hours(24);
        uc.quarantine_artifact(artifact_id, until, Actor::Api(api_actor()))
            .await
            .unwrap();

        let deltas = lifecycle.score_deltas();
        assert_eq!(deltas.len(), 1);
        let (repo_id, delta) = &deltas[0];
        assert_eq!(
            *repo_id,
            artifacts
                .find_by_id(artifact_id)
                .await
                .unwrap()
                .repository_id
        );
        assert_eq!(delta.quarantined_delta, 1);
        assert_eq!(delta.released_delta, 0);
        assert_eq!(delta.rejected_delta, 0);
        assert!(delta.last_scan_at.is_none());
    }

    #[tokio::test]
    async fn admin_release_threads_released_delta_with_prior_quarantined() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        uc.admin_release(
            artifact_id,
            api_actor(),
            admin_privileges(),
            "ok by ops".into(),
        )
        .await
        .unwrap();

        let deltas = lifecycle.score_deltas();
        assert_eq!(deltas.len(), 1);
        let (_repo, delta) = &deltas[0];
        assert_eq!(delta.quarantined_delta, -1);
        assert_eq!(delta.released_delta, 1);
        assert_eq!(delta.rejected_delta, 0);
    }

    /// Fail-closed: a candidate with no authority
    /// (no `ScanCompleted`, no `scan_backends:[]` policy) is not
    /// released, so no score delta is threaded. The released path's
    /// delta is covered by `release_expired_releases_via_scan_succeeded`
    /// / `admin_release_threads_released_delta_with_prior_quarantined`.
    #[tokio::test]
    async fn release_expired_fail_closed_threads_no_delta() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        uc.release_expired(vec![artifact_id]).await.unwrap();

        assert!(lifecycle.score_deltas().is_empty());
    }

    #[tokio::test]
    async fn record_scan_result_clean_threads_severity_only_delta() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let severity = SeveritySummary {
            critical: 0,
            high: 5,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let deltas = lifecycle.score_deltas();
        assert_eq!(deltas.len(), 1);
        let (_repo, delta) = &deltas[0];
        // Clean scan, no status transition.
        assert_eq!(delta.quarantined_delta, 0);
        assert_eq!(delta.rejected_delta, 0);
        assert_eq!(delta.high_delta, 5);
        assert_eq!(delta.critical_delta, 0);
        assert!(delta.last_scan_at.is_some());
    }

    #[tokio::test]
    async fn record_scan_result_reject_threads_quarantined_to_rejected_delta() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
        let severity = SeveritySummary {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        let deltas = lifecycle.score_deltas();
        assert_eq!(deltas.len(), 1);
        let (_repo, delta) = &deltas[0];
        // Quarantined → Rejected: -1 quarantined, +1 rejected, severity counts bump.
        assert_eq!(delta.quarantined_delta, -1);
        assert_eq!(delta.rejected_delta, 1);
        assert_eq!(delta.released_delta, 0);
        assert_eq!(delta.critical_delta, 1);
        assert!(delta.last_scan_at.is_some());
    }

    /// A re-scan that re-derives a `Reject` on an artifact already in the
    /// terminal `Rejected` state must (a) return Ok — no churn, no
    /// `cannot reject artifact in state rejected` error — AND (b) RECORD the
    /// fresh `ScanCompleted` + findings so a manual rescan refreshes the stored
    /// result, while skipping the duplicate `ArtifactRejected` event and the
    /// score re-count. The earlier pure-skip recorded nothing, which left the
    /// operator unable to see the current scan result without a release; this
    /// test pins that a rescan now updates findings.
    #[tokio::test]
    async fn record_scan_result_reject_on_already_rejected_records_findings_no_duplicate_reject() {
        let (uc, artifacts, _events, lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Rejected);
        let severity = SeveritySummary {
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        };

        // Returns Ok — a recoverable re-scan, not the hard
        // `cannot reject artifact in state rejected` error that looped the job.
        uc.record_scan_result(
            artifact_id,
            "trivy".into(),
            findings_from_summary(&severity),
            None,
        )
        .await
        .unwrap();

        // The fresh scan IS recorded (the dual-write fired) so a rescan
        // refreshes the stored result — not a silent no-op.
        let txns = lifecycle.committed_transitions();
        assert_eq!(
            txns.len(),
            1,
            "the fresh scan must be recorded so a rescan refreshes findings"
        );
        let (saved, batch, _) = &txns[0];
        assert_eq!(
            saved.quarantine_status,
            QuarantineStatus::Rejected,
            "artifact stays terminal"
        );
        assert!(
            batch
                .events
                .iter()
                .any(|e| matches!(&e.event, DomainEvent::ScanCompleted(_))),
            "fresh ScanCompleted recorded"
        );
        // ... but NOT a duplicate ArtifactRejected, and no score re-count.
        assert!(
            !batch
                .events
                .iter()
                .any(|e| matches!(&e.event, DomainEvent::ArtifactRejected(_))),
            "no duplicate ArtifactRejected on an already-rejected artifact"
        );
        assert!(
            lifecycle.score_deltas().is_empty(),
            "no score re-count on a terminal re-scan"
        );
    }

    /// Fail-closed: when no authority is constructible
    /// (no `ScanCompleted`, no `scan_backends:[]` waiver), the timer
    /// sweep skips the artifact and logs a fail-closed skip line — it
    /// does NOT log the "released expired artifact" success line. The
    /// success-line + correlation_id assertions are covered by
    /// `release_expired_info_log_carries_resolved_authority_kind`.
    #[test]
    fn release_expired_fail_closed_logs_skip() {
        install_audit_passthrough_subscriber();
        let _serial = AUDIT_TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = AuditCapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (uc, artifacts, _events, _lifecycle, repositories, _projections) = make_use_case();
            let artifact_id =
                seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);
            uc.release_expired(vec![artifact_id]).await.unwrap();
        });

        let records = captured.lock().unwrap();
        assert!(
            records
                .iter()
                .any(|(_, msg)| msg.contains("skipping: no release authority")),
            "fail-closed: timer sweep must log the no-authority skip arm, not a release"
        );
        assert!(
            !records
                .iter()
                .any(|(_, msg)| msg.contains("released expired artifact")),
            "fail-closed: timer sweep must NOT log a release"
        );
    }

    /// `record_scan_result` is the single
    /// CAS write site for the findings blob (the orchestrator-side
    /// duplicate write was removed). The 8 MiB cap from
    /// `FINDINGS_BLOB_MAX_BYTES` enforces here, in `persist_findings_blob`.
    /// This test pins the cap path: a finding set whose JSON-serialised
    /// representation exceeds the cap returns `DomainError::Validation`
    /// rather than persisting the oversize blob.
    ///
    /// Migrated from `scan_orchestration_tests::run_scan_returns_failed_when_blob_exceeds_size_cap`,
    /// which exercised an orchestrator-side cap that no longer exists.
    #[tokio::test]
    async fn record_scan_result_returns_validation_error_when_findings_blob_exceeds_size_cap() {
        let (uc, artifacts, _events, _lifecycle, repositories, _projections) = make_use_case();
        let artifact_id =
            seed_artifact_with_repo(&artifacts, &repositories, QuarantineStatus::Quarantined);

        // Build ~1000 max-size findings. Each finding carries a 1024-byte
        // title, a 512-byte purl, a 128-byte vulnerability_id, 32 references
        // of 256 bytes, and 32 fixed_versions of 32 bytes. JSON-serialised
        // size is well over 9 KiB per finding, so 1000 entries clear the
        // 8 MiB cap with margin.
        let max_purl = "p".repeat(512);
        let max_vuln = "v".repeat(128);
        let max_title = "t".repeat(1024);
        let mut refs = Vec::with_capacity(32);
        for _ in 0..32 {
            refs.push("r".repeat(256));
        }
        let mut fixed = Vec::with_capacity(32);
        for _ in 0..32 {
            fixed.push("f".repeat(32));
        }
        let mut findings: Vec<Finding> = Vec::with_capacity(1000);
        for i in 0..1000u32 {
            findings.push(Finding {
                purl: format!("{max_purl}{i:04}")[..512].to_string(),
                vulnerability_id: format!("{max_vuln}{i:04}")[..128].to_string(),
                severity: SeverityThreshold::High,
                cvss_score: Some(7.5),
                title: max_title.clone(),
                fixed_versions: fixed.clone(),
                source_scanner: "trivy".into(),
                references: refs.clone(),
                aliases: vec![],
                informational_class: None,
            });
        }
        // Sanity: confirm we cleared the cap before invoking the use case.
        let serialised_len = serde_json::to_vec(&findings).unwrap().len();
        assert!(
            serialised_len > FINDINGS_BLOB_MAX_BYTES,
            "test fixture must exceed the 8 MiB cap; got {serialised_len} bytes"
        );

        let err = uc
            .record_scan_result(artifact_id, "trivy".into(), findings, None)
            .await
            .expect_err("oversize findings blob must surface as an error");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("findings_blob"),
                    "validation message must mention findings_blob; got: {msg}"
                );
                assert!(
                    msg.contains("byte cap"),
                    "validation message must mention 'byte cap'; got: {msg}"
                );
            }
            other => panic!("expected Domain(Validation), got {other:?}"),
        }
    }
}
