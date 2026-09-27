//! Single-source computation of the two **transient, non-persisted** hold
//! fields a `503` read path renders:
//! [`Artifact::quarantine_deadline`](hort_domain::entities::artifact::Artifact::quarantine_deadline)
//! and
//! [`Artifact::provenance_hold_indefinite`](hort_domain::entities::artifact::Artifact::provenance_hold_indefinite).
//!
//! The schema stores only the immutable window **anchor**
//! (`quarantine_window_start`); the deadline is derived live so a later
//! `quarantineDuration` edit takes effect with no backfill (ADR 0007), and
//! the Postgres mapper therefore hands every freshly-loaded row out with
//! the pair at its `None` / `false` defaults. Whoever returns an artifact
//! to a format crate has to fill them in — the format crates cannot, since
//! resolving a `ScanPolicy` or reading an event stream from there would
//! reach past the use case (ADR 0008).
//!
//! Two layers need the answer and must not compute it differently:
//!
//! - the read path
//!   ([`ArtifactUseCase::hydrate_quarantine_deadline`](crate::use_cases::artifact_use_case::ArtifactUseCase)),
//!   which resolves the window from the matched policy per artifact; and
//! - the two **mint** paths in
//!   [`IngestUseCase`](crate::use_cases::ingest_use_case::IngestUseCase),
//!   which already hold the derived anchor and the effective duration at
//!   the instant they stamp the window — so the artifact they hand back
//!   can carry the pair for free.
//!
//! Before this module the mint paths carried neither, and a pull-through
//! `GET` that ingested and quarantined in the same request answered `503`
//! with the consuming handler's "deadline unknown" fallback (a flat one
//! hour) while a later read of the same row reported the real remaining
//! window. Sharing the expression is what keeps the two answers identical.
//!
//! Pure orchestration: no state mutation, no metric emission, no event
//! append. The caller owns the guard — see [`resolve_transient_hold`].

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::ProvenanceClearance;
use hort_domain::entities::scan_policy::ProvenanceMode;
use hort_domain::policy::effective_quarantine_deadline;
use hort_domain::ports::event_store::EventStore;

use crate::error::AppResult;
use crate::use_cases::release_clearance::resolve_provenance_clearance;

/// The transient hold pair for one artifact, as
/// [`resolve_transient_hold`] computes it.
pub(crate) struct TransientHold {
    /// The instant the observation window elapses — `anchor + duration`.
    pub deadline: DateTime<Utc>,
    /// `true` iff the window has already elapsed AND the artifact's
    /// `Required`-mode provenance clearance is still
    /// [`ProvenanceClearance::Pending`], i.e. the hold is waiting on an
    /// external event rather than on the passage of time (ADR 0039's
    /// 2026-09-12 amendment, D5).
    pub hold_indefinite: bool,
}

/// Compute the transient hold pair for an artifact the caller has already
/// established is `Quarantined` with a resolved window `anchor`.
///
/// The guard is deliberately the **caller's**: the read path needs it
/// before resolving a policy at all (a non-quarantined row must cost zero
/// policy-port calls), and the mint paths satisfy it by construction —
/// they are inside the branch that just stamped the window. Putting the
/// guard here would either force the read path's policy resolution onto
/// every happy-path read or hand this function a duration it had no reason
/// to resolve.
///
/// `duration` is the resolved observation-window length (matched
/// `ScanPolicy.quarantineDuration`, else
/// [`DefaultPolicy::quarantine_duration_secs`](hort_domain::policy::DefaultPolicy::quarantine_duration_secs)).
/// The deadline is `anchor + duration` through the one domain helper every
/// consumer shares — **never** `now + duration`: the anchor may legitimately
/// predate this moment (ADR 0054 derives it as the minimum over the age
/// sources, so content Hort first saw eight hours ago inherits an
/// eight-hour-old anchor), and reporting the full duration would advertise a
/// window that is already partly spent.
///
/// The provenance read is gated on the deadline having **already elapsed**
/// — the only state in which the deadline is not the whole story — and
/// short-circuits inside [`resolve_provenance_clearance`] for every mode
/// but `Required`. `clearance_events: None` (an unwired event store; a
/// test-only state in the read path) leaves `hold_indefinite` false, which
/// is the safe default: the computed deadline is advertised as-is.
pub(crate) async fn resolve_transient_hold(
    artifact_id: Uuid,
    anchor: DateTime<Utc>,
    duration: chrono::Duration,
    provenance_mode: ProvenanceMode,
    clearance_events: Option<&dyn EventStore>,
) -> AppResult<TransientHold> {
    let deadline = effective_quarantine_deadline(anchor, duration);
    let hold_indefinite = match clearance_events {
        Some(events) if deadline <= Utc::now() => matches!(
            resolve_provenance_clearance(events, artifact_id, provenance_mode).await?,
            ProvenanceClearance::Pending
        ),
        _ => false,
    };
    Ok(TransientHold {
        deadline,
        hold_indefinite,
    })
}
