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
//! - `release` / `waive` does not reach them either. `Rejected` *is* a
//!   release source state, for the curator's manual waive alone, and
//!   that waive reaches the provenance axis
//!   ([`is_curator_overridable`](hort_domain::entities::artifact::is_curator_overridable)).
//!   But these rows carry no recorded reason at all — a provenance
//!   rejection left `rejection_reason = None`, as above — and the axis
//!   conjunct refuses a reason-less rejection fail-closed: a release that
//!   guessed from an absent reason would override whatever actually
//!   condemned the artifact.
//! - Re-pushing produces no ingest: the content is already present, so
//!   the push is a no-op.
//!
//! So every named exit from `Rejected` runs into a check that
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
//! 3. provenance evidence on the stream that this terminalisation was
//!    never valid — resolved by [`provenance_rejection_evidence`] into
//!    the domain's [`ProvenanceRejectionEvidence`]. **A disjunction of
//!    two proofs**, because a provenance rejection can be entitled to no
//!    terminal state for either of two reasons:
//!
//!    - a `ProvenanceVerified` is on the stream, which contradicts the
//!      rejection outright. Resolved via [`provenance_clearance_from`],
//!      the single-source release-gate helper, with
//!      `ProvenanceMode::Required` passed **literally**, not with the
//!      repository's currently-active mode: the question is "does this
//!      artifact's stream contradict its rejection?", which is a fact
//!      about the stream. An operator loosening the policy afterwards
//!      must not change whether the artifact was wrongly condemned — and
//!      under any other mode the helper answers `NotRequired` without
//!      reading the stream at all, which would prove nothing.
//!    - the stream's only provenance verdict is a
//!      `ProvenanceRejected{Unsigned}`. That verdict is a statement about
//!      a point in time and ADR 0039 D1 forbids it from ever being
//!      terminal, so it needs no contradiction — it is invalid on its own
//!      terms. This is the arm that reaches a descriptor which can never
//!      carry a signature of its own, and for which the first arm's proof
//!      can therefore never arrive.
//!
//!    Both refusals are load-bearing: a **positive disproof** on the
//!    stream (a signature present and wrong) is terminal by D1/D4, and a
//!    stream with no provenance verdict at all establishes nothing about
//!    why the artifact is `Rejected`. See [`ProvenanceRejectionEvidence`].
//!
//! Conjunct 2 is evaluated first because it is the cheap, highly
//! selective one: almost every `Rejected` artifact has a terminal event,
//! so the evidence scan is reached only by the few that do not.
//!
//! # Exit
//!
//! `Rejected → Quarantined`, never straight to `Released`. The repair
//! withdraws an illegal terminalisation; it does not decide servability.
//! The original observation-window anchor rides the emitted
//! `ArtifactQuarantined`, so the artifact lands back in front of the
//! ordinary release sweep with an already-elapsed window, and the sweep
//! applies the live scan / curation / provenance gates. **What happens
//! next differs per arm, and both outcomes are the sweep's to decide:**
//!
//! - a contradicted rejection already resolves `Cleared` at the
//!   provenance leg (the first arm's proof is exactly that helper's
//!   input), so the next sweep tick releases it;
//! - a never-terminal one resolves `Pending`, which denies the timer arm
//!   of `Artifact::release` — so the sweep **holds** it indefinitely,
//!   neither releasing nor re-rejecting, which is precisely D1's
//!   prescribed treatment of an unsigned artifact. It can still leave the
//!   hold the way D1 intends: its own verify, or the parent's
//!   provenance-clearance cascade, which
//!   `Artifact::cascade_provenance_clearance` refuses from `Rejected` and
//!   admits from `Quarantined`. For a signature's own constituents that
//!   cascade is the only exit there is, and the illegal terminal state was
//!   what blocked it.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::artifact::{
    ProvenanceClearance, ProvenanceRejectionEvidence, QuarantineStatus, TerminalRejectionRecord,
};
use hort_domain::entities::scan_policy::ProvenanceMode;
use hort_domain::events::{
    Actor, ApiActor, ArtifactReEvaluated, DomainEvent, PersistedEvent, ReEvaluationTrigger,
    NO_POLICY,
};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::curation_queue_repository::{CurationQueueFilter, CurationQueueRepository};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend};
use hort_domain::ports::provenance::ProvenanceRejectReason;

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::projectors::repo_security_score::RepoSecurityScoreProjector;
use crate::use_cases::release_clearance::provenance_clearance_from;
use crate::use_cases::{ArtifactAtVersion, OverCapStream};

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
    /// Narrow the scan to one artifact — the way to reach a known
    /// artifact directly rather than paging towards it, since the scan
    /// has no cursor and `None` always returns the same newest rows.
    ///
    /// A **conjunction** with `repository_id`, not an alternative: a
    /// mismatched pair returns empty. No precedence rule, no silent
    /// widening.
    pub artifact_id: Option<Uuid>,
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
            artifact_id: None,
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

/// Resolve conjunct 3 over a stream the caller already holds: does this
/// artifact's provenance evidence establish that its `Rejected` status
/// records a verdict that was never entitled to be terminal?
///
/// The two accepting arms are the module docs' disjunction. The order is
/// load-bearing in both directions:
///
/// - **The contradiction is tested first**, through
///   [`provenance_clearance_from`] so this path cannot drift from the
///   release gate's own reading of `Cleared`. A stream carrying both a
///   verification and a disproof therefore classifies `Contradicted`,
///   exactly as the release gate classifies it `Cleared` — and is refused
///   at conjunct 2 regardless, because a disproof writes the
///   `ArtifactRejected` companion.
/// - **A positive disproof then wins over an `Unsigned`.** The scan
///   returns on the first non-`Unsigned` reason rather than accumulating,
///   which is what makes "`Unsigned` and nothing else" the condition:
///   an `Unsigned` followed by a later disproof is a disproven artifact,
///   not a misrejected one.
///
/// Binding the reason rather than enumerating it is deliberate here, and
/// is the fail-closed direction: [`ProvenanceRejectReason`]'s own
/// contract is that every variant is a positive disproof, with
/// `Unsigned` the single exception ADR 0039 D1 carved out of it. A future
/// variant is therefore a disproof by construction, and classifying it
/// as one refuses the repair.
fn provenance_rejection_evidence(stream: &[PersistedEvent]) -> ProvenanceRejectionEvidence {
    if provenance_clearance_from(stream, ProvenanceMode::Required) == ProvenanceClearance::Cleared {
        return ProvenanceRejectionEvidence::Contradicted;
    }

    // No verification on the stream, so the rejection's own reason is the
    // only thing left that can disprove its terminality.
    let mut unsigned_seen = false;
    for persisted in stream {
        if let DomainEvent::ProvenanceRejected(rejected) = &persisted.event {
            match rejected.reason {
                ProvenanceRejectReason::Unsigned => unsigned_seen = true,
                disproof => return ProvenanceRejectionEvidence::Disproved(disproof),
            }
        }
    }

    if unsigned_seen {
        ProvenanceRejectionEvidence::NeverTerminal
    } else {
        ProvenanceRejectionEvidence::NoVerdict
    }
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
                artifact_id: request.artifact_id,
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
            // Narrowing is what reaches the rest, not repetition. The
            // listing is `ORDER BY created_at DESC LIMIT n` with no
            // cursor, so an identical re-run returns the identical newest
            // n rows for as long as the population is unchanged — and a
            // dry run changes nothing by construction.
            tracing::warn!(
                limit,
                "provenance-misrejection repair filled its scan limit — there may be \
                 further Rejected artifacts beyond it. The scan has no cursor, so \
                 re-running the same request returns the same rows; narrow it by \
                 repository or by artifact to reach the rest"
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
        // The artifact, its stream and the version the repair's append
        // will carry — one observation. Both conjuncts below are decided
        // from that stream; a version read after them would already
        // contain whatever committed in between, so the repair would not
        // conflict with it.
        let mut paired = ArtifactAtVersion::load(
            &*self.artifacts,
            &*self.events,
            artifact_id,
            OverCapStream::Tolerate,
        )
        .await?;

        // Conjunct 1. Checked here, not left to the domain guard, so that
        // "this artifact is not in the illegal state" is one uniform
        // answer across all three conjuncts rather than a refusal for two
        // of them and an error for the third. The domain's source-state
        // guard stays as defence-in-depth and, reached through this path,
        // can no longer fire.
        if paired.artifact().quarantine_status != QuarantineStatus::Rejected {
            return Ok(false);
        }

        let persisted = paired.evidence()?;

        // Conjunct 2 — cheap and highly selective, so it runs first and
        // short-circuits the clearance check for every genuine rejection.
        // Only `Absent` continues: `Present` is a recorded verdict and
        // `CorruptionTombstone` is a CAS integrity failure recorded before
        // that axis wrote its companion — both genuine.
        let terminal_record =
            TerminalRejectionRecord::from_events(persisted.iter().map(|p| &p.event));
        if terminal_record != TerminalRejectionRecord::Absent {
            return Ok(false);
        }

        // Conjunct 3 — a disjunction of two proofs. See the module docs
        // for both arms, and on why `Required` is passed literally
        // rather than resolved from the repository's policy.
        let provenance = provenance_rejection_evidence(persisted);
        if !provenance.disproves_terminality() {
            return Ok(false);
        }

        if dry_run {
            // The domain guard is still consulted — a dry run that
            // reports a set the real run would refuse is worse than no
            // report. `repair_provenance_misrejection` takes `&mut self`,
            // so this runs against a throwaway clone and the loaded
            // artifact is discarded either way.
            let mut probe = paired.artifact().clone();
            probe.repair_provenance_misrejection(terminal_record, provenance, Utc::now())?;
            return Ok(true);
        }

        let stream_id = paired.stream_id().clone();
        let expected_version = paired.expected_version();
        let previous_status = paired.artifact().quarantine_status;
        let quarantined = paired
            .artifact_mut()
            .repair_provenance_misrejection(terminal_record, provenance, Utc::now())
            .map_err(AppError::Domain)?;
        let new_status = paired.artifact().quarantine_status;
        let artifact = paired.into_artifact();

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
            evidence = ?provenance,
            "repaired a provenance misrejection: Rejected with no ArtifactRejected on the \
             stream, and provenance evidence that the rejection was never entitled to be \
             terminal — returned to Quarantined for the ordinary release sweep"
        );
        Ok(true)
    }
}

#[cfg(test)]
#[path = "provenance_misrejection_repair_tests.rs"]
mod tests;
