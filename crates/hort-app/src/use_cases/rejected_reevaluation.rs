//! Shared "derive the verdict from the paired evidence" path for a
//! `Rejected` artifact re-evaluation over stored findings under a
//! resolved scan policy.
//!
//! Used by both the loosen direction of the policy-mutation population
//! pass ([`PolicyUseCase::re_evaluate_one_rejected`](crate::use_cases::policy_use_case))
//! and the curator-invoked single-artifact endpoint
//! ([`CurationUseCase::reevaluate`](crate::use_cases::curation_use_case)).
//! Both callers read identical evidence and delegate to the same pure
//! domain derivation
//! ([`hort_domain::policy::decide_rejected_transition`]); this module is
//! the single source of that derivation block so the two call sites
//! cannot drift.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use hort_domain::entities::artifact::{is_scan_clearable, ProvenanceClearance};
use hort_domain::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection};
use hort_domain::events::RejectionReason;
use hort_domain::policy::{
    decide_rejected_transition, effective_quarantine_deadline, ReEvaluationOutcome,
};
use hort_domain::ports::storage::StoragePort;

use crate::error::AppResult;
use crate::use_cases::release_clearance::provenance_clearance_from;
use crate::use_cases::{scan_history, ArtifactAtVersion};

/// Outcome of [`derive_rejected_outcome`] — either a determined verdict
/// or the reason a verdict could not be derived (both are terminal,
/// non-error results: the artifact stays `Rejected` untouched).
pub(crate) enum RejectedDerivation {
    /// The artifact's current rejection reason is not scan-clearable
    /// (ADR 0041 invariant #6(a)): a scan re-judgement does not apply to
    /// a provenance-, curation-, or admin-rejected artifact. No scan
    /// evidence is consulted.
    Ineligible { reason: Option<RejectionReason> },
    /// No `ScanCompleted` event exists on the artifact's stream — there
    /// is no scan evidence to recompute a verdict from.
    NoScanCompleted,
    /// A verdict was derived from stored evidence. `quarantine_deadline`
    /// is the **computed** deadline (never the bare anchor) the caller
    /// must hydrate onto the artifact before invoking
    /// [`Artifact::re_evaluate`](hort_domain::entities::artifact::Artifact::re_evaluate)
    /// so the two decisions agree on boundary semantics; `rejection_reason`
    /// is the hydrated reason the caller must likewise set on the
    /// artifact before that call (the entity's own eligibility guard
    /// reads it, and `find_by_id` never populates it).
    Determined {
        outcome: ReEvaluationOutcome,
        quarantine_deadline: Option<DateTime<Utc>>,
        rejection_reason: Option<RejectionReason>,
        /// The provenance leg of the cross-axis release conjunction
        /// (ADR 0041 invariant #6), resolved from the same evidence as
        /// the verdict.
        ///
        /// Returned from here rather than resolved by the caller
        /// afterwards for two reasons. It is the same answer for both
        /// callers off the same stream, so computing it twice is the
        /// drift risk [`provenance_clearance_from`] exists to remove;
        /// and the caller would have to ask the pairing for the evidence
        /// a second time, which can only fail in a way this function has
        /// already ruled out — an unreachable error arm nobody can test.
        ///
        /// Only the release arm consults it. Computing it on every arm
        /// costs a pure scan of a slice already in hand.
        provenance: ProvenanceClearance,
    },
}

/// Derive a `Rejected` artifact's re-evaluation verdict from the evidence
/// its pairing already observed. See module docs — this is the single
/// derive path shared by every `Rejected`-artifact re-evaluation caller.
///
/// Every answer comes out of `paired`: the rejection reason, the latest
/// scan summary and the per-finding blob hash all come from the one
/// stream read that also fixed the `ExpectedVersion` the caller's append
/// will carry. That is what makes a verdict committed since the pairing
/// fail that append rather than be overwritten by this derivation — see
/// [`ArtifactAtVersion`]'s contract.
///
/// `Err` only when the paired stream breached the event cap, so the
/// evidence cannot be read to its tail and no verdict may be derived
/// from the prefix.
pub(crate) async fn derive_rejected_outcome(
    paired: &ArtifactAtVersion,
    storage: &Arc<dyn StoragePort>,
    policy: Option<&ScanPolicyProjection>,
    exclusions: &[ExclusionProjection],
    now: DateTime<Utc>,
) -> AppResult<RejectedDerivation> {
    let artifact = paired.artifact();
    let stream = paired.evidence()?;

    let reason = scan_history::last_rejection_reason(stream);
    if !is_scan_clearable(reason.as_ref()) {
        return Ok(RejectedDerivation::Ineligible { reason });
    }

    let Some(last_snapshot) = scan_history::last_scan_completed(stream) else {
        return Ok(RejectedDerivation::NoScanCompleted);
    };

    let last_findings = scan_history::last_findings(stream, storage, artifact.id).await;

    let quarantine_deadline = policy.and_then(|p| {
        artifact.quarantine_window_start.map(|anchor| {
            effective_quarantine_deadline(
                anchor,
                chrono::Duration::seconds(p.quarantine_duration_secs),
            )
        })
    });

    let outcome = decide_rejected_transition(
        artifact,
        &last_snapshot.summary,
        last_findings.as_deref(),
        policy,
        exclusions,
        quarantine_deadline,
        now,
    );

    Ok(RejectedDerivation::Determined {
        outcome,
        quarantine_deadline,
        rejection_reason: reason,
        provenance: provenance_clearance_from(
            stream,
            policy.map(|p| p.provenance_mode).unwrap_or_default(),
        ),
    })
}
