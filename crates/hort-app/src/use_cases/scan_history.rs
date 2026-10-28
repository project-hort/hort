//! Shared readers for the questions an artifact's **already-read** event
//! stream answers about its scan history.
//!
//! Shared so every caller that re-derives a verdict — the policy-mutation
//! re-evaluation pass, the curator-invoked single-artifact endpoint, the
//! promotion gate — asks the same question of the same evidence and
//! cannot drift on how "the latest scan" is found.
//!
//! The surface is a [`ScanCompletedSnapshot`] carrying both the cached
//! aggregate AND the `findings_blob` hash so a caller can either run
//! aggregate-summary evaluation cheaply or hydrate the per-finding
//! `Vec<Finding>` from CAS and use exact CVE-ID matching (avoiding the
//! "one exclusion drops one count" limitation called out in
//! `crates/hort-domain/src/policy/exclusion.rs`).
//!
//! Beside that, [`latest_scan_standing`] answers the one question the
//! release gate asks of the same evidence — "does the latest scan
//! verdict block?" — for both the `release_expired` sweep and the
//! scan-time inline fast path. It takes an event *iterator* rather than
//! a `&[PersistedEvent]` slice precisely so the fast path can ask it of
//! the batch it is about to append, which is the same evidence one
//! commit later.
//!
//! **These readers take the stream, they do not read it.** The stream a
//! decision rests on arrives from
//! [`ArtifactAtVersion`](crate::use_cases::ArtifactAtVersion), paired in
//! one observation with the `ExpectedVersion` the committing append will
//! carry — see that type's contract for why a reader that fetched the
//! stream for itself would reopen the window the pairing closes. Pure
//! scans over that slice: no I/O apart from the CAS fetch in
//! [`last_findings`], no state mutation, no metric emission.

use std::sync::Arc;

use tokio::io::AsyncReadExt;
use uuid::Uuid;

use hort_domain::entities::artifact::ReleaseOrigin;
use hort_domain::events::{
    DomainEvent, PersistedEvent, PolicyResult, RejectionReason, ScanCompleted, SeveritySummary,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{ContentHash, Finding};

/// Snapshot of the artifact's most recent `ScanCompleted` event,
/// surfaced by [`last_scan_completed`]. Carries both the cached
/// aggregate (`summary`) and the `findings_blob` hash so callers can
/// either run aggregate-summary evaluation cheaply or
/// hydrate per-finding detail from CAS for exact CVE-ID matching.
///
/// `findings_blob` is `None` iff the latest scan was clean (no
/// findings) — the `ScanCompleted` invariant
/// (`finding_count == 0 ⇔ findings_blob.is_none()`) carries through
/// here unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanCompletedSnapshot {
    pub summary: SeveritySummary,
    pub findings_blob: Option<ContentHash>,
}

/// Scan `stream` in reverse and return the most recent [`ScanCompleted`]
/// payload as a [`ScanCompletedSnapshot`].
///
/// `None` means the stream carries no `ScanCompleted` (never scanned).
/// Callers treat that as a clean baseline — see
/// [`crate::use_cases::promotion_use_case::PromotionUseCase::evaluate_and_promote`]
/// for the "missing scan summary == empty findings" rule and the
/// `Rejected`-re-evaluation callers for the "skip artifact" rule.
///
/// The reverse scan is only an answer about "the latest" if `stream` is
/// the whole stream, which is exactly what
/// [`ArtifactAtVersion::evidence`](crate::use_cases::ArtifactAtVersion::evidence)
/// guarantees and refuses to fake: over an oldest-prefix of a stream
/// that breached the event cap, the first `ScanCompleted` found walking
/// back is a *superseded* one, and the rejection that superseded it is
/// past the end of the slice.
pub(crate) fn last_scan_completed(stream: &[PersistedEvent]) -> Option<ScanCompletedSnapshot> {
    // Iterate in reverse — `ScanCompleted` is typically near the end
    // (post-quarantine, pre-rejection on the same stream).
    stream.iter().rev().find_map(|event| match &event.event {
        DomainEvent::ScanCompleted(ScanCompleted {
            severity_summary,
            findings_blob,
            ..
        }) => Some(ScanCompletedSnapshot {
            summary: severity_summary.clone(),
            findings_blob: findings_blob.clone(),
        }),
        _ => None,
    })
}

/// Scan `stream` in reverse and return the most recent
/// `ArtifactRejected.rejected_by` reason, `None` if the artifact has
/// never been rejected.
///
/// Shared by every caller that re-derives a `Rejected` artifact's
/// verdict — the eligibility guard downstream
/// ([`hort_domain::entities::artifact::is_scan_clearable`]) reads this
/// value, and the artifact entity loaded via
/// `ArtifactRepository::find_by_id` does not carry it (rejection reason
/// is not a stored column; it is reconstructed from the event log on
/// demand).
pub(crate) fn last_rejection_reason(stream: &[PersistedEvent]) -> Option<RejectionReason> {
    stream.iter().rev().find_map(|e| match &e.event {
        DomainEvent::ArtifactRejected(r) => Some(r.rejected_by.clone()),
        _ => None,
    })
}

/// Scan `stream` in reverse and classify **who** last released the
/// artifact — the verified fact
/// [`Artifact::reject_from_scan`](hort_domain::entities::artifact::Artifact::reject_from_scan)
/// takes as its precondition for re-blocking a `Released` artifact.
///
/// The reverse scan is what makes this an answer about the LATEST
/// release: an artifact the timer released, a curation rule re-blocked
/// and an admin then released again is protected by the admin's
/// decision, and a forward scan would have found the timer's.
///
/// No `ArtifactReleased` anywhere on the stream is
/// [`ReleaseOrigin::NeverReleased`] — the ordinary answer for every
/// artifact that has never been released, and (paired with a `Released`
/// status) the release-side mirror of D6's illegal state. See
/// [`ReleaseOrigin::permits_scan_reblock`] for which way that falls.
///
/// **Completeness is load-bearing**, exactly as in
/// [`last_scan_completed`]: over an oldest-prefix of a stream that
/// breached the event cap the latest release is not necessarily in
/// view, and an `Admin` release that scrolled out of the window would
/// read as the `Timer` release that preceded it. Callers pass evidence
/// from
/// [`ArtifactAtVersion::evidence`](crate::use_cases::ArtifactAtVersion::evidence),
/// which refuses an over-cap stream rather than answering from a
/// prefix.
pub(crate) fn latest_release_origin(stream: &[PersistedEvent]) -> ReleaseOrigin {
    stream
        .iter()
        .rev()
        .find_map(|e| match &e.event {
            DomainEvent::ArtifactReleased(r) => Some(ReleaseOrigin::Released(r.released_by)),
            _ => None,
        })
        .unwrap_or(ReleaseOrigin::NeverReleased)
}

/// What the artifact's **latest** scan observation says about releasing
/// it on the scan axis of the release gate (ADR 0007). Produced by
/// [`latest_scan_standing`].
///
/// Four answers rather than a boolean, because the release ladder has to
/// tell "the verdict blocked" apart from the two reasons there is no
/// verdict to read at all: quarantine invariant 2 (a
/// never-successfully-scanned artifact never releases on the timer
/// alone) and the rule that a scan-axis authority never lifts a
/// rejection from another axis are both distinctions a boolean loses.
///
/// The clearing answer carries one bit beside it — whether the scan
/// found anything — because the release authority it justifies depends
/// on that and on nothing else; see [`Self::Clears`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanStanding {
    /// No `ScanCompleted` in the evidence at all: the artifact has never
    /// been scanned, so there is no verdict. Deliberately NOT
    /// [`Self::Holds`] — `enforcement: record` un-gates a blocking
    /// verdict and must never un-gate a missing observation.
    Unobserved,
    /// An `ArtifactRejected` sits LATER in the evidence than the latest
    /// `ScanCompleted`. Whatever that scan decided has been superseded
    /// by a rejection — scanner, curator or provenance — and no
    /// scan-axis authority may lift it.
    Superseded,
    /// The scan ran, the verdict reached on it does NOT block, and
    /// nothing has rejected the artifact since.
    ///
    /// `findings_present` is the latest `ScanCompleted`'s
    /// `finding_count > 0` — the one extra fact the release gate needs
    /// AFTER it knows the artifact clears, because the two authorities
    /// a clearing standing justifies claim different things:
    /// `ScanSucceeded` asserts an empty finding list, `ScanCleared`
    /// asserts a verdict that permitted what the scan found. It rides
    /// the variant rather than being re-read from the stream so the
    /// token can never disagree with the standing it was resolved
    /// alongside. `false` here is also the only shape the legacy
    /// no-verdict satisfier below can produce, which is what makes
    /// `findings_present: true` provably a recorded `Pass`.
    Clears { findings_present: bool },
    /// The scan ran, nothing has rejected the artifact since, and the
    /// verdict either BLOCKS or cannot be read.
    ///
    /// The unreadable case is the pre-verdict-event population: a
    /// `ScanCompleted` carrying findings, written before the scan path
    /// appended its verdict unconditionally. That verdict is not
    /// recoverable from the stream — `finding_count` says how many
    /// findings there were, never whether they blocked — so the gate
    /// treats it as it treats any verdict it cannot read: one it must
    /// not act on. Such an artifact clears once it is rescanned, which
    /// the rescan sweep does on the policy's `rescan_interval_hours`.
    Holds,
}

impl ScanStanding {
    /// Did a scan run, with nothing rejecting the artifact since?
    ///
    /// The `enforcement: record` arm's question, and the reason this is
    /// an enum and not a boolean: that mode un-gates the *verdict*,
    /// never the *observation*, so it needs [`Self::Clears`] and
    /// [`Self::Holds`] folded together while keeping both apart from
    /// the two no-observation answers. It is the same computation read
    /// differently, not a second derivation.
    ///
    /// The scan-axis release question — "does the latest verdict clear
    /// the artifact, and under which authority?" — is the OTHER
    /// projection of the same value, and it lives in
    /// `quarantine_use_case`'s `scan_axis_release_authority` (step 1,
    /// via `clearing_scan_authority`) rather than here, because its
    /// answer is a `ReleaseAuthorization`, not a fact about the stream.
    /// Both projections of this standing are read by that one ladder,
    /// which both release paths call — this method is its step 2.
    pub(crate) fn observation_stands(self) -> bool {
        matches!(self, ScanStanding::Clears { .. } | ScanStanding::Holds)
    }
}

/// Where the artifact's latest scan leaves the scan axis of the release
/// gate — **the one definition of "does the latest scan verdict block?"**
///
/// `events` is the artifact's domain events in stream order. Both release
/// paths call this, which is the whole reason it exists:
///
/// - the `release_expired` sweep passes the candidate's complete
///   persisted stream;
/// - the scan-time inline fast path passes the batch it is about to
///   append, which after the commit IS the tail of that stream.
///
/// They used to derive the answer from two different facts — the sweep
/// from `ScanCompleted.finding_count == 0` ("did the scanner find
/// anything?"), the fast path from its own `violations` ("did the policy
/// block?") — so one artifact released or stayed quarantined
/// indefinitely depending on whether its scan finished after or inside
/// its observation window. No document described that, because it was
/// not a rule; it was the arithmetic of a divergence.
///
/// **Completeness is load-bearing**, for the same reason it is in
/// [`last_scan_completed`]: over an oldest-prefix of a stream that
/// breached the event cap, "the latest `ScanCompleted`" is a superseded
/// verdict and the `ArtifactRejected` that condemned the artifact sits
/// past the end of the slice. Callers pass evidence from
/// [`ArtifactAtVersion::evidence`](crate::use_cases::ArtifactAtVersion::evidence),
/// which refuses to fake it.
///
/// **Which `PolicyEvaluated` is the scan's verdict:** the FIRST one
/// after the latest `ScanCompleted`. The scan path appends its verdict
/// in the same atomic batch as the `ScanCompleted` it was reached on, so
/// nothing can be interposed between the two; the promotion gate — the
/// only other producer of `PolicyEvaluated` on an artifact stream — can
/// only land in a later append. Taking the first one is therefore what
/// keeps a promotion verdict from being read as a scan verdict, and
/// position is the only thing that can: the event carries no
/// decision-point discriminator, and a promotion `Warn` /
/// `RequireApproval` is recorded as `Pass`.
///
/// On a `ScanCompleted` that recorded no verdict of its own — the
/// pre-verdict-event population — "the first one after it" can reach a
/// promotion verdict instead, and that borrowing is sound rather than
/// merely harmless: **a BLOCKING scan verdict has always written its
/// `PolicyEvaluated(Fail)` beside its own `ScanCompleted`.** The
/// rejecting path appended that `Fail` unconditionally (and still
/// appends it when the artifact was already terminal and the
/// `ArtifactRejected` is withheld), and `enforcement: record` appended
/// the identical `Fail` for the verdict it declined to act on. Only the
/// NON-blocking verdict went unrecorded. So a legacy `ScanCompleted`
/// with no verdict adjacent to it cannot be a blocking one, and nothing
/// a later append says about it can open a gate that the true verdict
/// would have held shut.
///
/// Passing the fast path's batch rather than the whole post-commit
/// stream is sound for the same reason the suffix check is: the batch
/// carries the latest `ScanCompleted` and everything after it, and an
/// `ArtifactRejected` already on the stream is EARLIER than that scan —
/// exactly the case the "later than" clause excludes.
pub(crate) fn latest_scan_standing<'a>(
    events: impl IntoIterator<Item = &'a DomainEvent>,
) -> ScanStanding {
    /// The latest `ScanCompleted` seen so far by the pass below, and
    /// what has landed since it.
    struct LatestScan {
        /// `ScanCompleted.finding_count == 0` — the legacy satisfier's
        /// only input.
        clean_count: bool,
        /// The verdict reached on this scan; `None` until one is seen.
        verdict: Option<PolicyResult>,
        /// An `ArtifactRejected` landed after this scan.
        rejected_after: bool,
    }

    // Forward pass. Every `ScanCompleted` discards whatever the previous
    // one established, so what survives the walk describes the LATEST
    // scan and only the events after it — which is what makes "no
    // rejection later than the latest scan" fall out without a second
    // pass over a suffix.
    let mut latest: Option<LatestScan> = None;
    for event in events {
        match event {
            DomainEvent::ScanCompleted(sc) => {
                latest = Some(LatestScan {
                    clean_count: sc.finding_count == 0,
                    verdict: None,
                    rejected_after: false,
                });
            }
            DomainEvent::PolicyEvaluated(p) => {
                if let Some(scan) = latest.as_mut() {
                    // First verdict after the scan wins — see the
                    // promotion-gate note above.
                    if scan.verdict.is_none() {
                        scan.verdict = Some(p.result);
                    }
                }
            }
            DomainEvent::ArtifactRejected(_) => {
                if let Some(scan) = latest.as_mut() {
                    scan.rejected_after = true;
                }
            }
            _ => {}
        }
    }

    match latest {
        None => ScanStanding::Unobserved,
        Some(scan) if scan.rejected_after => ScanStanding::Superseded,
        Some(LatestScan {
            verdict: Some(PolicyResult::Pass),
            clean_count,
            ..
        }) => ScanStanding::Clears {
            findings_present: !clean_count,
        },
        Some(LatestScan {
            verdict: Some(PolicyResult::Fail),
            ..
        }) => ScanStanding::Holds,
        // SECOND SATISFIER — for the pre-verdict-event population ONLY.
        // A `ScanCompleted` with no verdict beside it was written before
        // the scan path appended one unconditionally. A zero finding
        // count is then the only evidence left that nothing blocked, and
        // it is sufficient evidence: no threshold in any policy blocks on
        // an empty finding list. There is no backfill and none is needed
        // — the leg retires itself as those artifacts are rescanned.
        //
        // Checked AFTER the verdict, deliberately, so a recorded verdict
        // always beats the count. That ordering is what keeps a
        // zero-finding `Fail` — a license rule can produce one — from
        // reading as a pass, which is how the count alone would have
        // read it.
        //
        // `findings_present: false` is not a choice here — this leg
        // fires only on a zero finding count, so the clearing authority
        // it justifies is the finding-free one by construction.
        Some(LatestScan {
            clean_count: true, ..
        }) => ScanStanding::Clears {
            findings_present: false,
        },
        Some(_) => ScanStanding::Holds,
    }
}

/// Resolve the stream's most recent `ScanCompleted.findings_blob` to the
/// underlying `Vec<Finding>` via [`StoragePort::get`] and JSON decode.
/// The `Rejected`-re-evaluation callers use this to enable exact CVE-ID
/// matching via
/// [`hort_domain::policy::exclusion::filter_excluded_findings`].
///
/// Returns `None` for any best-effort failure mode (no `ScanCompleted`
/// on the stream, clean scan with no blob, missing CAS object, or
/// deserialise failure). The caller falls back to the aggregate-summary
/// path on `None`.
///
/// Failure modes (missing blob, malformed blob) log a
/// `tracing::warn!` so operators can correlate a silent fallback with
/// CAS rot. The aggregate-summary fallback is still safe — it
/// preserves the highest-tier-first decrement semantics — so
/// degrading gracefully here is the right tradeoff (the alternative
/// would be skipping the artifact entirely, which is worse from an
/// operator's perspective).
pub(crate) async fn last_findings(
    stream: &[PersistedEvent],
    storage: &Arc<dyn StoragePort>,
    artifact_id: Uuid,
) -> Option<Vec<Finding>> {
    let blob_hash = last_scan_completed(stream)?.findings_blob?;

    let mut reader = match storage.get(&blob_hash).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                artifact_id = %artifact_id,
                findings_blob = %blob_hash,
                error = %e,
                "findings_blob absent from CAS; falling back to aggregate-summary re-evaluation",
            );
            return None;
        }
    };

    let mut buf = Vec::new();
    if let Err(e) = reader.read_to_end(&mut buf).await {
        tracing::warn!(
            artifact_id = %artifact_id,
            findings_blob = %blob_hash,
            error = %e,
            "findings_blob read failed; falling back to aggregate-summary re-evaluation",
        );
        return None;
    }

    match serde_json::from_slice::<Vec<Finding>>(&buf) {
        Ok(findings) => Some(findings),
        Err(e) => {
            tracing::warn!(
                artifact_id = %artifact_id,
                findings_blob = %blob_hash,
                error = %e,
                "findings_blob malformed; falling back to aggregate-summary re-evaluation",
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use hort_domain::entities::scan_policy::SeverityThreshold;
    use hort_domain::events::{
        Actor, ApprovalDecided, ApprovalDecision, ArtifactQuarantined, ArtifactRejected,
        ArtifactReleased, DomainEvent, PersistedEvent, RejectionReason, ReleaseReason,
        ScanAssessment, ScanCompleted, SeveritySummary, StreamId,
    };
    use hort_domain::ports::storage::StoragePort;
    use hort_domain::types::{ComponentRelation, ContentHash, Finding};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    /// Non-clean `ScanCompleted` carries a `ContentHash`
    /// referencing the per-finding blob in CAS. The placeholder used
    /// here (SHA-256 of empty input) is sufficient — these tests never
    /// dereference the hash.
    fn placeholder_findings_blob() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("static valid SHA-256 hex")
    }

    use super::*;
    use crate::use_cases::test_support::*;

    fn persisted(stream_id: &StreamId, position: u64, event: DomainEvent) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream_id.clone(),
            stream_position: position,
            global_position: position + 1,
            event,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(api_actor()),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    fn finding(vuln: &str, sev: SeverityThreshold) -> Finding {
        Finding {
            purl: "pkg:npm/lodash@4.17.20".into(),
            vulnerability_id: vuln.into(),
            severity: sev,
            cvss_score: None,
            title: "test finding".into(),
            fixed_versions: vec![],
            source_scanner: "osv".into(),
            references: vec![],
            aliases: vec![],
            informational_class: None,
            severity_basis: hort_domain::types::SeverityBasis::Assessed,
            component_relation: ComponentRelation::NotEstablished,
            statement: hort_domain::types::FindingStatement::Unstated,
            advisory_published_at: None,
        }
    }

    #[test]
    fn returns_none_when_stream_empty() {
        assert!(last_scan_completed(&[]).is_none());
    }

    #[test]
    fn returns_none_when_stream_has_no_scan_completed() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id,
                quarantine_window_start: Utc::now(),
            }),
        )];

        assert!(last_scan_completed(&stream).is_none());
    }

    // ---- latest_scan_standing ---------------------------------------------
    //
    // The one definition of "does the latest scan verdict block?", read by
    // both release paths. The cases below are the whole decision table: the
    // two verdict answers, the two no-verdict-to-read answers, the
    // positional rule that tells a scan verdict from a promotion one, and
    // the legacy satisfier that keeps pre-verdict-event clean scans
    // releasing.

    /// A `ScanCompleted` at `position` carrying `severity`. The
    /// per-tier counts are the input and `finding_count` is their sum,
    /// which is what [`ScanCompleted::validate`] requires.
    ///
    /// The tier is stated at the call site because the cases below turn
    /// on it: a scan with `High` findings and a `PolicyEvaluated(Pass)`
    /// beside it is the production shape this function has to answer
    /// `Clears { findings_present: true }` for, and a fixture that put
    /// every finding in `critical` described a stream no producer can
    /// append under a `Critical` threshold — it merely happened not to
    /// change the answer, because this function reads the count and the
    /// verdict rather than the summary.
    fn scan_completed(
        artifact_id: Uuid,
        position: u64,
        severity: SeveritySummary,
    ) -> PersistedEvent {
        let stream_id = StreamId::artifact(artifact_id);
        let finding_count = severity.critical
            + severity.high
            + severity.medium
            + severity.low
            + severity.negligible;
        persisted(
            &stream_id,
            position,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "trivy".into(),
                finding_count,
                severity_summary: severity,
                findings_blob: if finding_count > 0 {
                    Some(placeholder_findings_blob())
                } else {
                    None
                },
                assessment: ScanAssessment::Analysed,
            }),
        )
    }

    fn verdict(artifact_id: Uuid, position: u64, result: PolicyResult) -> PersistedEvent {
        let stream_id = StreamId::artifact(artifact_id);
        persisted(
            &stream_id,
            position,
            DomainEvent::PolicyEvaluated(hort_domain::events::PolicyEvaluated {
                artifact_id,
                policy_id: Uuid::new_v4(),
                result,
                violations: Vec::new(),
            }),
        )
    }

    fn rejected(artifact_id: Uuid, position: u64) -> PersistedEvent {
        let stream_id = StreamId::artifact(artifact_id);
        persisted(
            &stream_id,
            position,
            DomainEvent::ArtifactRejected(ArtifactRejected {
                artifact_id,
                rejected_by: RejectionReason::Scanner,
                reason: "critical finding".into(),
            }),
        )
    }

    fn standing_of(stream: &[PersistedEvent]) -> ScanStanding {
        latest_scan_standing(stream.iter().map(|e| &e.event))
    }

    #[test]
    fn unobserved_when_nothing_was_scanned() {
        assert_eq!(standing_of(&[]), ScanStanding::Unobserved);

        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id,
                quarantine_window_start: Utc::now(),
            }),
        )];
        assert_eq!(standing_of(&stream), ScanStanding::Unobserved);
    }

    /// A `PolicyEvaluated(Pass)` with no `ScanCompleted` anywhere is NOT a
    /// release authority. The promotion gate writes exactly this event to
    /// the artifact's own stream, and it says nothing about whether the
    /// artifact was ever scanned — the whole point of the `Unobserved`
    /// answer being distinct from `Clears`.
    #[test]
    fn a_verdict_without_a_scan_is_not_an_observation() {
        let artifact_id = Uuid::new_v4();
        let stream = vec![verdict(artifact_id, 0, PolicyResult::Pass)];
        assert_eq!(standing_of(&stream), ScanStanding::Unobserved);
    }

    #[test]
    fn clears_on_a_passing_verdict_beside_the_scan() {
        let artifact_id = Uuid::new_v4();
        // Findings present — none of them blocked. This is the shape the
        // sweep used to refuse because it read the count, not the verdict.
        let stream = vec![
            scan_completed(
                artifact_id,
                0,
                findings_in_tier(13, SeverityThreshold::High),
            ),
            verdict(artifact_id, 1, PolicyResult::Pass),
        ];
        assert_eq!(
            standing_of(&stream),
            ScanStanding::Clears {
                findings_present: true
            }
        );
    }

    #[test]
    fn holds_on_a_blocking_verdict() {
        let artifact_id = Uuid::new_v4();
        let stream = vec![
            scan_completed(
                artifact_id,
                0,
                findings_in_tier(13, SeverityThreshold::Critical),
            ),
            verdict(artifact_id, 1, PolicyResult::Fail),
        ];
        assert_eq!(standing_of(&stream), ScanStanding::Holds);
    }

    #[test]
    fn superseded_by_a_rejection_after_the_latest_scan() {
        let artifact_id = Uuid::new_v4();
        let stream = vec![
            scan_completed(artifact_id, 0, no_findings()),
            verdict(artifact_id, 1, PolicyResult::Pass),
            rejected(artifact_id, 2),
        ];
        assert_eq!(standing_of(&stream), ScanStanding::Superseded);
    }

    /// A rejection EARLIER than the latest scan is not a supersession: the
    /// later scan is the current observation and a clean rescan is how a
    /// rejected artifact gets its verdict re-derived.
    #[test]
    fn a_rejection_before_the_latest_scan_does_not_supersede_it() {
        let artifact_id = Uuid::new_v4();
        let stream = vec![
            scan_completed(
                artifact_id,
                0,
                findings_in_tier(3, SeverityThreshold::Critical),
            ),
            verdict(artifact_id, 1, PolicyResult::Fail),
            rejected(artifact_id, 2),
            scan_completed(artifact_id, 3, no_findings()),
            verdict(artifact_id, 4, PolicyResult::Pass),
        ];
        assert_eq!(
            standing_of(&stream),
            ScanStanding::Clears {
                findings_present: false
            }
        );
    }

    /// The scan's verdict is the FIRST `PolicyEvaluated` after its
    /// `ScanCompleted`, never a later one. A promotion decision — the only
    /// other producer of this event on an artifact stream, and one that
    /// records `Warn` / `RequireApproval` as `Pass` — must not be able to
    /// overwrite a blocking scan verdict.
    #[test]
    fn the_first_verdict_after_the_scan_wins() {
        let artifact_id = Uuid::new_v4();
        let stream = vec![
            scan_completed(
                artifact_id,
                0,
                findings_in_tier(3, SeverityThreshold::Critical),
            ),
            verdict(artifact_id, 1, PolicyResult::Fail),
            verdict(artifact_id, 2, PolicyResult::Pass),
        ];
        assert_eq!(standing_of(&stream), ScanStanding::Holds);
    }

    /// The legacy satisfier: a `ScanCompleted` written before the scan
    /// path appended its verdict unconditionally. A zero finding count is
    /// the only evidence left that nothing blocked, and it is enough.
    #[test]
    fn a_legacy_clean_scan_with_no_recorded_verdict_clears() {
        let artifact_id = Uuid::new_v4();
        let stream = vec![scan_completed(artifact_id, 0, no_findings())];
        assert_eq!(
            standing_of(&stream),
            ScanStanding::Clears {
                findings_present: false
            }
        );
    }

    /// The other half of the legacy population: findings and no verdict.
    /// The count cannot say whether they blocked, so the gate holds the
    /// artifact until a rescan records one.
    ///
    /// The findings are deliberately in the `High` tier — under the
    /// `Critical` threshold a verdict would have permitted them. That
    /// is the cost of having no backfill, stated as evidence rather
    /// than as prose: this artifact is held not because anything
    /// decided against it, but because the one fact left on its stream
    /// cannot say either way.
    #[test]
    fn a_legacy_dirty_scan_with_no_recorded_verdict_holds() {
        let artifact_id = Uuid::new_v4();
        let stream = vec![scan_completed(
            artifact_id,
            0,
            findings_in_tier(3, SeverityThreshold::High),
        )];
        assert_eq!(standing_of(&stream), ScanStanding::Holds);
    }

    /// A legacy scan that recorded no verdict of its own borrows the
    /// next `PolicyEvaluated` on the stream — which can be a promotion
    /// decision. Pinned because it is the one place the
    /// first-verdict-after rule is approximate, and because what makes
    /// it sound is a property of the WRITERS rather than of this
    /// function: a blocking scan verdict has always written its `Fail`
    /// beside its own `ScanCompleted`, on both the rejecting and the
    /// `record` path, so a legacy scan with no adjacent verdict was
    /// provably non-blocking and the borrowed `Pass` agrees with the
    /// verdict it stands in for. Should a future writer start emitting a
    /// `ScanCompleted` whose blocking verdict is NOT beside it, this
    /// test is the one that has to be revisited.
    #[test]
    fn a_later_verdict_fills_in_for_a_legacy_scan_that_recorded_none() {
        let artifact_id = Uuid::new_v4();
        let stream = vec![
            scan_completed(artifact_id, 0, findings_in_tier(3, SeverityThreshold::High)),
            // A promotion decision, several appends later.
            verdict(artifact_id, 7, PolicyResult::Pass),
        ];
        assert_eq!(
            standing_of(&stream),
            ScanStanding::Clears {
                findings_present: true
            }
        );
    }

    /// A recorded verdict beats the count, both directions. The blocking
    /// direction is the one that matters: a license rule can fail with an
    /// empty finding list, and reading the count first would have called
    /// that a pass.
    #[test]
    fn a_recorded_verdict_beats_the_finding_count() {
        let artifact_id = Uuid::new_v4();
        let blocking_but_countless = vec![
            scan_completed(artifact_id, 0, no_findings()),
            verdict(artifact_id, 1, PolicyResult::Fail),
        ];
        assert_eq!(standing_of(&blocking_but_countless), ScanStanding::Holds);

        let passing_with_findings = vec![
            scan_completed(artifact_id, 0, findings_in_tier(7, SeverityThreshold::High)),
            verdict(artifact_id, 1, PolicyResult::Pass),
        ];
        assert_eq!(
            standing_of(&passing_with_findings),
            ScanStanding::Clears {
                findings_present: true
            }
        );
    }

    /// `observation_stands()` over every standing — the
    /// `enforcement: record` arm's question, which folds in a blocking
    /// verdict and nothing else. Both shapes of the clearing answer are
    /// listed: the finding bit it carries decides which release
    /// authority applies, never whether the observation stands.
    ///
    /// The standing's OTHER projection — which `ReleaseAuthorization` a
    /// clearing answer justifies — is pinned over the same four
    /// standings by
    /// `quarantine_use_case::tests::clearing_scan_authority_maps_every_standing`,
    /// beside the one ladder both release paths call.
    #[test]
    fn observation_stands_is_exhaustive_over_every_standing() {
        for (standing, stands) in [
            (ScanStanding::Unobserved, false),
            (ScanStanding::Superseded, false),
            (
                ScanStanding::Clears {
                    findings_present: false,
                },
                true,
            ),
            (
                ScanStanding::Clears {
                    findings_present: true,
                },
                true,
            ),
            (ScanStanding::Holds, true),
        ] {
            assert_eq!(
                standing.observation_stands(),
                stands,
                "observation_stands() on {standing:?}"
            );
        }
    }

    // -- last_rejection_reason -----------------------------------------------

    #[test]
    fn last_rejection_reason_none_when_stream_has_no_rejection() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id,
                quarantine_window_start: Utc::now(),
            }),
        )];

        assert!(last_rejection_reason(&stream).is_none());
    }

    #[test]
    fn last_rejection_reason_returns_most_recent() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![
            persisted(
                &stream_id,
                0,
                DomainEvent::ArtifactRejected(ArtifactRejected {
                    artifact_id,
                    rejected_by: RejectionReason::Curator {
                        curator_id: Uuid::new_v4(),
                    },
                    reason: "stale".into(),
                }),
            ),
            persisted(
                &stream_id,
                1,
                DomainEvent::ArtifactRejected(ArtifactRejected {
                    artifact_id,
                    rejected_by: RejectionReason::Scanner,
                    reason: "current".into(),
                }),
            ),
        ];

        assert_eq!(
            last_rejection_reason(&stream),
            Some(RejectionReason::Scanner)
        );
    }

    // -- latest_release_origin -----------------------------------------------

    fn released(stream_id: &StreamId, position: u64, reason: ReleaseReason) -> PersistedEvent {
        let operator = matches!(reason, ReleaseReason::Admin | ReleaseReason::Curator);
        persisted(
            stream_id,
            position,
            DomainEvent::ArtifactReleased(ArtifactReleased {
                artifact_id: Uuid::new_v4(),
                released_by: reason,
                // The `ArtifactReleased` variant invariant: an operator
                // release carries attribution, a system-driven one must
                // not.
                released_by_user_id: operator.then(Uuid::new_v4),
                justification: operator.then(|| "operator override".to_string()),
            }),
        )
    }

    #[test]
    fn latest_release_origin_never_released_on_a_stream_with_no_release() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id,
                quarantine_window_start: Utc::now(),
            }),
        )];

        assert_eq!(latest_release_origin(&stream), ReleaseOrigin::NeverReleased);
        assert_eq!(latest_release_origin(&[]), ReleaseOrigin::NeverReleased);
    }

    #[test]
    fn latest_release_origin_reads_the_sole_release() {
        let stream_id = StreamId::artifact(Uuid::new_v4());
        for reason in [
            ReleaseReason::Timer,
            ReleaseReason::Admin,
            ReleaseReason::PolicyReEvaluation,
            ReleaseReason::Curator,
        ] {
            let stream = vec![released(&stream_id, 0, reason)];
            assert_eq!(
                latest_release_origin(&stream),
                ReleaseOrigin::Released(reason)
            );
        }
    }

    /// The LATEST release decides, in both directions. An admin release
    /// after a timer release protects the artifact; a timer release after
    /// an admin release (the artifact was re-held and the window elapsed
    /// again) does not — the admin's decision was about the state the
    /// re-hold replaced.
    #[test]
    fn latest_release_origin_takes_the_most_recent_release() {
        let stream_id = StreamId::artifact(Uuid::new_v4());

        let timer_then_admin = vec![
            released(&stream_id, 0, ReleaseReason::Timer),
            released(&stream_id, 1, ReleaseReason::Admin),
        ];
        assert_eq!(
            latest_release_origin(&timer_then_admin),
            ReleaseOrigin::Released(ReleaseReason::Admin)
        );

        let admin_then_timer = vec![
            released(&stream_id, 0, ReleaseReason::Admin),
            released(&stream_id, 1, ReleaseReason::Timer),
        ];
        assert_eq!(
            latest_release_origin(&admin_then_timer),
            ReleaseOrigin::Released(ReleaseReason::Timer)
        );
    }

    /// Events after the release do not hide it: the reader is looking
    /// for the latest `ArtifactReleased`, not for the stream's tail.
    #[test]
    fn latest_release_origin_sees_past_later_events() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![
            released(&stream_id, 0, ReleaseReason::Curator),
            persisted(
                &stream_id,
                1,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "osv".into(),
                    finding_count: 1,
                    severity_summary: findings_in_tier(1, SeverityThreshold::Critical),
                    findings_blob: Some(placeholder_findings_blob()),
                    assessment: ScanAssessment::Analysed,
                }),
            ),
        ];

        assert_eq!(
            latest_release_origin(&stream),
            ReleaseOrigin::Released(ReleaseReason::Curator)
        );
    }

    #[test]
    fn returns_summary_and_blob_from_only_scan_completed() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let blob = placeholder_findings_blob();

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "trivy".into(),
                finding_count: 3,
                severity_summary: findings_in_tier(3, SeverityThreshold::Critical),
                findings_blob: Some(blob.clone()),
                assessment: ScanAssessment::Analysed,
            }),
        )];

        let snapshot = last_scan_completed(&stream).expect("ScanCompleted on stream");
        assert_eq!(snapshot.summary.critical, 3);
        assert_eq!(snapshot.findings_blob, Some(blob));
    }

    #[test]
    fn returns_most_recent_scan_completed_when_multiple() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let stream = vec![
            persisted(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 1,
                    severity_summary: findings_in_tier(1, SeverityThreshold::Critical),
                    findings_blob: Some(placeholder_findings_blob()),
                    assessment: ScanAssessment::Analysed,
                }),
            ),
            persisted(
                &stream_id,
                1,
                DomainEvent::ApprovalDecided(ApprovalDecided {
                    artifact_id,
                    decision: ApprovalDecision::Approved,
                    notes: None,
                }),
            ),
            persisted(
                &stream_id,
                2,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 5,
                    severity_summary: findings_in_tier(5, SeverityThreshold::Critical),
                    findings_blob: Some(placeholder_findings_blob()),
                    assessment: ScanAssessment::Analysed,
                }),
            ),
        ];

        let snapshot = last_scan_completed(&stream).expect("ScanCompleted on stream");
        // The reverse-scan must pick the second (latest) ScanCompleted.
        assert_eq!(snapshot.summary.critical, 5);
    }

    #[test]
    fn ignores_non_scan_events_after_a_scan_completed() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let stream = vec![
            persisted(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 7,
                    severity_summary: findings_in_tier(7, SeverityThreshold::Critical),
                    findings_blob: Some(placeholder_findings_blob()),
                    assessment: ScanAssessment::Analysed,
                }),
            ),
            persisted(
                &stream_id,
                1,
                DomainEvent::ApprovalDecided(ApprovalDecided {
                    artifact_id,
                    decision: ApprovalDecision::Rejected,
                    notes: None,
                }),
            ),
        ];

        let snapshot = last_scan_completed(&stream).expect("ScanCompleted on stream");
        assert_eq!(snapshot.summary.critical, 7);
    }

    // ---- last_findings -----------------------------------------------------

    #[tokio::test]
    async fn last_findings_returns_none_when_no_scan_completed() {
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        assert!(last_findings(&[], &storage, Uuid::new_v4()).await.is_none());
    }

    #[tokio::test]
    async fn last_findings_returns_none_when_scan_was_clean() {
        // Clean scan: `findings_blob = None`. Caller falls back to
        // aggregate-summary path (which sees an empty summary).
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "osv".into(),
                finding_count: 0,
                severity_summary: no_findings(),
                findings_blob: None,
                assessment: ScanAssessment::Analysed,
            }),
        )];

        assert!(last_findings(&stream, &storage, artifact_id)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn last_findings_hydrates_blob_from_storage() {
        let mock_storage = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        // Seed CAS with a serialised Vec<Finding>.
        let findings = vec![
            finding("CVE-2021-23337", SeverityThreshold::High),
            finding("CVE-OTHER", SeverityThreshold::Medium),
        ];
        let bytes = serde_json::to_vec(&findings).unwrap();
        let hash_hex = hex::encode(Sha256::digest(&bytes));
        let blob_hash: ContentHash = hash_hex.parse().unwrap();
        mock_storage.insert_content(blob_hash.clone(), bytes);

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "osv".into(),
                finding_count: 2,
                severity_summary: SeveritySummary {
                    critical: 0,
                    high: 1,
                    medium: 1,
                    low: 0,
                    negligible: 0,
                },
                findings_blob: Some(blob_hash),
                assessment: ScanAssessment::Analysed,
            }),
        )];

        let storage: Arc<dyn StoragePort> = mock_storage;
        let hydrated = last_findings(&stream, &storage, artifact_id)
            .await
            .expect("findings hydrated from CAS");
        assert_eq!(hydrated.len(), 2);
        assert_eq!(hydrated[0].vulnerability_id, "CVE-2021-23337");
        assert_eq!(hydrated[1].vulnerability_id, "CVE-OTHER");
    }

    #[tokio::test]
    async fn last_findings_returns_none_when_blob_missing_from_storage() {
        // The `ScanCompleted` event references a hash that is NOT in
        // CAS — best-effort: log warn, return None, caller falls back.
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "osv".into(),
                finding_count: 1,
                severity_summary: findings_in_tier(1, SeverityThreshold::Critical),
                findings_blob: Some(placeholder_findings_blob()),
                assessment: ScanAssessment::Analysed,
            }),
        )];

        assert!(last_findings(&stream, &storage, artifact_id)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn last_findings_returns_none_when_blob_is_malformed_json() {
        // The blob bytes are present but don't deserialise as
        // `Vec<Finding>` — best-effort: log warn, return None.
        let mock_storage = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        // Inject garbage at a fabricated hash. We have to fabricate the
        // hash explicitly because the production path always writes
        // hash(content) → content; here we want hash X to map to
        // garbage Y. MockStoragePort's `insert_content` does not enforce
        // the CAS invariant, exactly so tests can stage this kind of
        // failure mode.
        let blob_hash = placeholder_findings_blob();
        mock_storage.insert_content(blob_hash.clone(), b"not valid JSON".to_vec());

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "osv".into(),
                finding_count: 1,
                severity_summary: findings_in_tier(1, SeverityThreshold::Critical),
                findings_blob: Some(blob_hash),
                assessment: ScanAssessment::Analysed,
            }),
        )];

        let storage: Arc<dyn StoragePort> = mock_storage;
        assert!(last_findings(&stream, &storage, artifact_id)
            .await
            .is_none());
    }
}
