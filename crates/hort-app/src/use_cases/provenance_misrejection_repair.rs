//! `ProvenanceMisrejectionRepairUseCase` — the corrective path for the
//! artifacts stranded by the defect ADR 0039's 2026-09-12 amendment
//! removed.
//!
//! # Why this exists at all
//!
//! The amendment stops the defect recurring — a missing signature now
//! holds indefinitely instead of rejecting. It does nothing for the
//! artifacts already stranded by the old behaviour, and those are not
//! reachable by any existing operator action:
//!
//! - `POST /admin/curation/quarantine/:id/reevaluate` answers
//!   `still_rejected` and writes nothing.
//!   [`Artifact::re_evaluate`](hort_domain::entities::artifact::Artifact::re_evaluate)'s
//!   eligibility guard admits only a **scan-clearable** rejection, and a
//!   provenance rejection leaves `rejection_reason = None`, which is
//!   fail-closed ineligible. That refusal is *correct* (ADR 0041
//!   invariant #6(a)): a scan re-judgement must never clear a provenance
//!   rejection.
//! - `release` / `waive` never applies — the source-state guard admits
//!   only `Quarantined` / `ScanIndeterminate`.
//! - Re-pushing produces no ingest: the content is already present, so
//!   the push is a no-op.
//!
//! So the only named exit from `Rejected` leads to the one check that
//! structurally excludes this rejection kind. This module is the missing
//! exit.
//!
//! # Shape: an admin-invoked, dry-run-by-default, one-shot repair
//!
//! Deliberately **not** a startup reconciliation and **not** a periodic
//! task handler. The population is bounded and historical — every
//! artifact in it was stranded by code that no longer exists — so
//! anything that runs forever would outlive its purpose and become a path
//! nobody remembers can fire. An operator-triggered surface also means
//! the repair happens when someone has read what it will touch, which is
//! what the dry-run exists for: [`RepairRequest::dry_run`] defaults to
//! *true* at the HTTP edge, so the report is the default outcome and
//! mutation is the opt-in.
//!
//! Authority is `Permission::Admin` (the HTTP route sits under the
//! `AdminPrincipal` gate, not the curator gate that protects
//! `/admin/curation/*`). That is a deliberate consequence of ADR 0038 —
//! service accounts are strictly non-admin — so this cannot be wired into
//! a pipeline; a human operator with an IdP-assumed admin session runs it.
//! It is not a curation decision: no verdict is being made about the
//! artifact, a structurally invalid one is being withdrawn.
//!
//! # The predicate
//!
//! Exactly three conjuncts, each load-bearing — see
//! [`Artifact::repair_provenance_misrejection`](hort_domain::entities::artifact::Artifact::repair_provenance_misrejection)
//! for why. This module's job is to resolve the two stream-derived ones
//! and hand them to the domain as verified facts:
//!
//! 1. `quarantine_status = Rejected` — the listing filter, re-checked by
//!    the domain's source-state guard.
//! 2. nothing terminal on the stream — resolved via
//!    [`TerminalRejectionRecord::from_events`], which *calls* the same
//!    `has_terminal_rejection_event` predicate the D6 structural guard
//!    (`hort-domain/tests/rejected_requires_terminal_event.rs`) applies to
//!    the emitting side. One definition, two consumers. It also
//!    classifies a **historical CAS corruption tombstone** separately:
//!    that path now writes the `ArtifactRejected` D6 requires, but every
//!    stream written before it does not, and the event store is
//!    append-only. Without that second classification an
//!    `ArtifactRejected`-only test would let one of those
//!    verified-then-corrupted artifacts through and hand corrupt bytes
//!    back to the release sweep.
//! 3. a `ProvenanceVerified` on the stream — resolved via
//!    [`resolve_provenance_clearance`], the single-source release-gate
//!    helper. Called with `ProvenanceMode::Required` **literally**, not
//!    with the repository's currently-active mode: the question is "does
//!    this artifact's stream contradict its rejection?", which is a fact
//!    about the stream. An operator loosening the policy afterwards must
//!    not change whether the artifact was wrongly condemned — and under
//!    any other mode the helper answers `NotRequired` without reading the
//!    stream at all, which would prove nothing.
//!
//! Conjunct 2 is evaluated first because it is the cheap, highly
//! selective one: almost every `Rejected` artifact has a terminal event,
//! so the clearance read is reached only by the few that do not.
//!
//! # Exit
//!
//! `Rejected → Quarantined`, never straight to `Released`. The repair
//! withdraws an illegal terminalisation; it does not decide servability.
//! The original observation-window anchor rides the emitted
//! `ArtifactQuarantined`, so the artifact lands back in front of the
//! ordinary release sweep with an already-elapsed window, and the sweep
//! applies the live scan / curation / provenance gates. For this
//! population `resolve_provenance_clearance` already answers `Cleared`
//! (conjunct 3 is exactly its input), so the next sweep tick releases it.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::artifact::{
    ProvenanceClearance, QuarantineStatus, TerminalRejectionRecord,
};
use hort_domain::entities::scan_policy::ProvenanceMode;
use hort_domain::events::{
    Actor, ApiActor, ArtifactReEvaluated, DomainEvent, ReEvaluationTrigger, StreamId, NO_POLICY,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::curation_queue_repository::{CurationQueueFilter, CurationQueueRepository};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ReadFrom};

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::projectors::repo_security_score::RepoSecurityScoreProjector;
use crate::use_cases::release_clearance::resolve_provenance_clearance;
use crate::use_cases::{read_expected_version, STREAM_EVENT_CAP};

/// Hard cap on how many `Rejected` rows one call examines. Mirrors the
/// curation queue's own `MAX_QUEUE_LIMIT`, which is the listing this
/// scans. The bound is reported rather than applied silently — see
/// [`RepairReport::scan_cap_hit`].
pub const MAX_SCAN_LIMIT: u32 = 500;

/// Default scan bound when the caller supplies none.
pub const DEFAULT_SCAN_LIMIT: u32 = 100;

/// One call's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRequest {
    /// Narrow the scan to one repository. `None` scans every repository,
    /// newest-rejected first (the curation queue's own ordering).
    pub repository_id: Option<Uuid>,
    /// How many `Rejected` rows to examine. Clamped to
    /// [`MAX_SCAN_LIMIT`].
    pub limit: u32,
    /// When `true` (the HTTP default) the call reports the affected set
    /// and writes nothing — no event, no status, no projection delta.
    pub dry_run: bool,
}

impl Default for RepairRequest {
    fn default() -> Self {
        Self {
            repository_id: None,
            limit: DEFAULT_SCAN_LIMIT,
            dry_run: true,
        }
    }
}

/// One artifact the predicate matched — enough for an operator to
/// recognise it without a second lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedArtifact {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub package_name: String,
    pub version: Option<String>,
}

/// What one call did (or, on a dry run, would do).
#[derive(Debug)]
pub struct RepairReport {
    /// Echoes the request — a report is worthless if the reader cannot
    /// tell whether it describes a plan or a change.
    pub dry_run: bool,
    /// How many `Rejected` rows the listing returned and this call
    /// examined.
    pub scanned: usize,
    /// The listing filled its limit, so there may be more `Rejected` rows
    /// beyond it. **Never silently truncated** — also logged at `warn!`.
    pub scan_cap_hit: bool,
    /// Artifacts matching all three conjuncts. On a dry run these are the
    /// artifacts a non-dry run would repair; otherwise they are the ones
    /// it did repair.
    pub affected: Vec<AffectedArtifact>,
    /// Per-artifact failures. Continue-on-error, mirroring
    /// `CurationUseCase::block`: successful repairs are not rolled back
    /// (events are immutable).
    pub failed: Vec<(Uuid, String)>,
}

/// See the module docs.
pub struct ProvenanceMisrejectionRepairUseCase {
    events: Arc<dyn EventStore>,
    artifacts: Arc<dyn ArtifactRepository>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    curation_queue: Arc<dyn CurationQueueRepository>,
}

impl ProvenanceMisrejectionRepairUseCase {
    pub fn new(
        events: Arc<EventStorePublisher>,
        artifacts: Arc<dyn ArtifactRepository>,
        lifecycle: Arc<dyn ArtifactLifecyclePort>,
        curation_queue: Arc<dyn CurationQueueRepository>,
    ) -> Self {
        Self {
            events,
            artifacts,
            lifecycle,
            curation_queue,
        }
    }

    /// Scan the `Rejected` population for artifacts in D6's illegal state
    /// whose stream contradicts the rejection, and (unless
    /// [`RepairRequest::dry_run`]) return each to `Quarantined`.
    #[tracing::instrument(skip(self), fields(actor_id = %actor.user_id))]
    pub async fn run(&self, request: RepairRequest, actor: ApiActor) -> AppResult<RepairReport> {
        let limit = request.limit.clamp(1, MAX_SCAN_LIMIT);
        let candidates = self
            .curation_queue
            .list_queue(CurationQueueFilter {
                repository_id: request.repository_id,
                status: Some(QuarantineStatus::Rejected),
                // Deliberately unfiltered: the discriminator the queue
                // projects is derived from the very `ArtifactRejected`
                // conjunct 2 asserts is ABSENT, so these rows carry no
                // kind at all. Filtering on it here would also be a
                // second place the predicate lives. The listing supplies
                // candidates; the stream decides.
                rejection_reason_kind: None,
                limit,
            })
            .await?;

        let scan_cap_hit = candidates.len() as u32 >= limit;
        if scan_cap_hit {
            tracing::warn!(
                limit,
                "provenance-misrejection repair filled its scan limit — there may be \
                 further Rejected artifacts beyond it; re-run (optionally per repository) \
                 until the scan returns fewer rows than the limit"
            );
        }

        let mut report = RepairReport {
            dry_run: request.dry_run,
            scanned: candidates.len(),
            scan_cap_hit,
            affected: Vec::new(),
            failed: Vec::new(),
        };

        for entry in candidates {
            let artifact_id = entry.artifact_id;
            match self.repair_one(artifact_id, request.dry_run, &actor).await {
                Ok(true) => report.affected.push(AffectedArtifact {
                    artifact_id,
                    repository_id: entry.repository_id,
                    repository_key: entry.repository_key,
                    package_name: entry.package_name,
                    version: entry.version,
                }),
                // The predicate did not match — the overwhelmingly common
                // case (every genuinely rejected artifact). Not a
                // failure, and deliberately not logged per row.
                Ok(false) => {}
                Err(e) => report.failed.push((artifact_id, e.to_string())),
            }
        }

        tracing::info!(
            actor_id = %actor.user_id,
            dry_run = request.dry_run,
            scanned = report.scanned,
            affected = report.affected.len(),
            failed = report.failed.len(),
            scan_cap_hit = report.scan_cap_hit,
            "provenance-misrejection repair completed"
        );
        Ok(report)
    }

    /// Evaluate the predicate for one artifact and, on a match and a
    /// non-dry run, commit the repair. `Ok(true)` means "matched";
    /// `Ok(false)` means "not in the illegal state, left alone".
    async fn repair_one(
        &self,
        artifact_id: Uuid,
        dry_run: bool,
        actor: &ApiActor,
    ) -> AppResult<bool> {
        let mut artifact = self
            .artifacts
            .find_by_id(artifact_id)
            .await
            .map_err(AppError::Domain)?;

        // Conjunct 1. Checked here, not left to the domain guard, so that
        // "this artifact is not in the illegal state" is one uniform
        // answer across all three conjuncts rather than a refusal for two
        // of them and an error for the third. The domain's source-state
        // guard stays as defence-in-depth and, reached through this path,
        // can no longer fire.
        if artifact.quarantine_status != QuarantineStatus::Rejected {
            return Ok(false);
        }

        let stream_id = StreamId::artifact(artifact_id);
        let persisted = self
            .events
            .read_stream(&stream_id, ReadFrom::Start, STREAM_EVENT_CAP + 1)
            .await?;

        // Conjunct 2 — cheap and highly selective, so it runs first and
        // short-circuits the clearance read for every genuine rejection.
        // Only `Absent` continues: `Present` is a recorded verdict and
        // `CorruptionTombstone` is a CAS integrity failure recorded before
        // that axis wrote its companion — both genuine.
        let terminal_record =
            TerminalRejectionRecord::from_events(persisted.iter().map(|p| &p.event));
        if terminal_record != TerminalRejectionRecord::Absent {
            return Ok(false);
        }

        // Conjunct 3 — see the module docs on why `Required` is passed
        // literally rather than resolved from the repository's policy.
        let provenance =
            resolve_provenance_clearance(&*self.events, artifact_id, ProvenanceMode::Required)
                .await?;
        if provenance != ProvenanceClearance::Cleared {
            return Ok(false);
        }

        if dry_run {
            // The domain guard is still consulted — a dry run that
            // reports a set the real run would refuse is worse than no
            // report. `repair_provenance_misrejection` takes `&mut self`,
            // so this runs against a throwaway clone and the loaded
            // artifact is discarded either way.
            let mut probe = artifact.clone();
            probe.repair_provenance_misrejection(terminal_record, provenance, Utc::now())?;
            return Ok(true);
        }

        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;
        let previous_status = artifact.quarantine_status;
        let quarantined = artifact
            .repair_provenance_misrejection(terminal_record, provenance, Utc::now())
            .map_err(AppError::Domain)?;
        let new_status = artifact.quarantine_status;

        let re_evaluated = ArtifactReEvaluated {
            artifact_id,
            // No policy was consulted — the repair is a structural
            // correction, not a re-derivation of a policy verdict.
            policy_id: NO_POLICY,
            trigger: ReEvaluationTrigger::ProvenanceMisrejectionRepair,
            previous_status,
            new_status,
        };
        let score_delta =
            RepoSecurityScoreProjector::compute_re_evaluated_delta(previous_status, new_status);
        let correlation_id = Uuid::new_v4();

        self.lifecycle
            .commit_transition_with_score(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![
                        EventToAppend::new(DomainEvent::ArtifactReEvaluated(re_evaluated)),
                        EventToAppend::new(DomainEvent::ArtifactQuarantined(quarantined)),
                    ],
                    correlation_id,
                    causation_id: None,
                    actor: Actor::Api(actor.clone()),
                },
                None,
                Some((artifact.repository_id, score_delta)),
            )
            .await
            .map_err(AppError::Domain)?;

        tracing::info!(
            artifact_id = %artifact_id,
            actor_id = %actor.user_id,
            correlation_id = %correlation_id,
            "repaired a provenance misrejection: Rejected with no ArtifactRejected on the \
             stream, contradicted by a ProvenanceVerified — returned to Quarantined for the \
             ordinary release sweep"
        );
        Ok(true)
    }
}

#[cfg(test)]
#[path = "provenance_misrejection_repair_tests.rs"]
mod tests;
