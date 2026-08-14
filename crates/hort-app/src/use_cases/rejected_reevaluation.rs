//! Shared "load evidence, derive verdict" path for a `Rejected` artifact
//! re-evaluation over stored findings under a resolved scan policy.
//!
//! Used by both the loosen direction of the policy-mutation population
//! pass ([`PolicyUseCase::re_evaluate_one_rejected`](crate::use_cases::policy_use_case))
//! and the curator-invoked single-artifact endpoint
//! ([`CurationUseCase::reevaluate`](crate::use_cases::curation_use_case)).
//! Both callers load identical evidence and delegate to the same pure
//! domain derivation
//! ([`hort_domain::policy::decide_rejected_transition`]); this module is
//! the single source of that load-and-derive block so the two call sites
//! cannot drift.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use hort_domain::entities::artifact::{is_scan_clearable, Artifact};
use hort_domain::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection};
use hort_domain::events::RejectionReason;
use hort_domain::policy::{
    decide_rejected_transition, effective_quarantine_deadline, ReEvaluationOutcome,
};
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::storage::StoragePort;

use crate::error::AppResult;
use crate::use_cases::scan_history;

/// Outcome of [`derive_rejected_outcome`] — either a determined verdict
/// or the reason a verdict could not be derived (both are terminal,
/// non-error results: the artifact stays `Rejected` untouched).
pub(crate) enum RejectedDerivation {
    /// The artifact's current rejection reason is not scan-clearable
    /// (ADR 0041 invariant #6(a)): a scan re-judgement does not apply to
    /// a provenance-, curation-, or admin-rejected artifact. No scan
    /// evidence is loaded.
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
    },
}

/// Load a `Rejected` artifact's re-evaluation evidence and derive its
/// verdict. See module docs — this is the single load-and-derive path
/// shared by every `Rejected`-artifact re-evaluation caller.
///
/// Read order (both callers' infrastructure-failure tests pin the exact
/// sequence): rejection-reason hydration, then — only if scan-clearable
/// — the last `ScanCompleted` summary, then the per-finding rows.
pub(crate) async fn derive_rejected_outcome(
    events: &dyn EventStore,
    storage: &Arc<dyn StoragePort>,
    artifact: &Artifact,
    policy: Option<&ScanPolicyProjection>,
    exclusions: &[ExclusionProjection],
    now: DateTime<Utc>,
) -> AppResult<RejectedDerivation> {
    let artifact_id = artifact.id;

    let reason = scan_history::read_last_rejection_reason(events, artifact_id).await?;
    if !is_scan_clearable(reason.as_ref()) {
        return Ok(RejectedDerivation::Ineligible { reason });
    }

    let Some(last_snapshot) = scan_history::read_last_scan_completed(events, artifact_id).await?
    else {
        return Ok(RejectedDerivation::NoScanCompleted);
    };

    // Re-scans the stream for the same `ScanCompleted` snapshot already
    // read above — existing behavior carried over unchanged; see
    // `read_last_findings`'s own doc for the best-effort fallback
    // contract on a missing/malformed blob.
    let last_findings = scan_history::read_last_findings(events, storage, artifact_id).await?;

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
    })
}
