//! Structural guard: `quarantine_status = Rejected` must never be reached
//! without a terminal event on the artifact's stream (ADR 0039's
//! 2026-09-12 amendment, D6, echoing ADR 0002's event-sourcing invariant).
//!
//! `quarantine_status` is a **projection**; the event stream is the
//! record. A status with no event behind it cannot be audited, cannot be
//! re-derived by replaying the stream, and is invisible to anyone reading
//! the stream to find out what happened — the stream would say the
//! artifact is still whatever it last was, while the projection says
//! `Rejected`, with nothing connecting the two.
//!
//! DB-free, network-free, sub-second — in the spirit of the sibling
//! structural guards (`no_bcrypt`, `retention_registration_guard`,
//! `ephemeral_keyspace_exhaustive`, `streaming_metadata_port`).
//!
//! ## Why this isn't a source-text scan
//!
//! A grep for `QuarantineStatus::Rejected` is defeated by any refactor
//! that renames or indirects the assignment. This guard drives the domain
//! instead: it enumerates every [`QuarantineEvent`] whose declared
//! transition table
//! ([`quarantine_transitions::classify`]) can reach `Rejected` from some
//! source state, actually calls the [`Artifact`] entity method that event
//! represents, and inspects the *emitted events* for a terminal companion.
//!
//! ## The exhaustiveness mechanism
//!
//! [`classify`] (this file's, not to be confused with
//! [`quarantine_transitions::classify`]) is a `match` over every
//! [`QuarantineEvent`] variant — **no wildcard arm**. `QuarantineEvent` is
//! not `#[non_exhaustive]`, so a future variant fails this file to
//! COMPILE until it is consciously classified `Unreachable`, `Compliant`,
//! or `KnownGap`. That is the same compile-forcing pattern
//! `retention_permitted` uses for `StreamCategory` in
//! `hort-app/tests/retention_registration_guard.rs`.
//!
//! A change to [`quarantine_transitions::QUARANTINE_TRANSITIONS`] itself
//! (widening which states an existing event can reach) does not touch the
//! `QuarantineEvent` enum, so it would NOT be caught by the compile-forced
//! match alone. `classification_matches_the_declared_transition_table`
//! closes that gap: it cross-checks this file's per-event verdict against
//! [`quarantine_transitions::classify`] for every `(event, state)` cell,
//! so a table edit that makes a previously-safe event newly reach
//! `Rejected` fails that test until this file's classification is updated
//! to match.
//!
//! ## Verdicts
//!
//! - `Compliant` — the event reaches `Rejected` and its
//!   emitted event set is asserted, by actually calling the method, to
//!   contain an `ArtifactRejected`.
//! - `Unreachable` — the event's declared table never targets
//!   `Rejected` from any source state; nothing to exercise.
//! - `KnownGap` — the event reaches `Rejected` but its
//!   emitted event set is asserted NOT to contain an `ArtifactRejected`.
//!   This is not a legitimate exemption from D6 — see
//!   [`QuarantineEvent::TombstoneFromCorruption`]'s arm below for the one
//!   member of this category and why it is pinned rather than silently
//!   passing: pinning a known-bad behaviour as an explicit, named,
//!   commented arm is the only way a reader can tell "the guard checked
//!   this and it currently fails" apart from "the guard never looked."

use hort_domain::entities::artifact::{has_terminal_rejection_event, Artifact, QuarantineStatus};
use hort_domain::entities::quarantine_transitions::{self, QuarantineEvent};
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::events::{ArtifactCorrupted, DomainEvent, PolicyViolation, RejectionReason};
use hort_domain::policy::ScanOutcome;
use hort_domain::ports::provenance::{ProvenanceRejectReason, ProvenanceVerdict};
use hort_domain::types::ContentHash;
use uuid::Uuid;

const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn fixed_hash() -> ContentHash {
    VALID_SHA256.parse().expect("fixture sha256 must parse")
}

fn quarantined_artifact() -> Artifact {
    Artifact {
        id: Uuid::from_u128(1),
        repository_id: Uuid::from_u128(2),
        name: "pkg".into(),
        name_as_published: "pkg".into(),
        version: Some("1.0.0".into()),
        path: "pkg/1.0.0/pkg-1.0.0.tar.gz".into(),
        size_bytes: 1024,
        sha256_checksum: fixed_hash(),
        sha1_checksum: None,
        md5_checksum: None,
        content_type: "application/octet-stream".into(),
        quarantine_status: QuarantineStatus::Quarantined,
        rejection_reason: None,
        quarantine_window_start: Some(chrono::Utc::now()),
        quarantine_deadline: None,
        provenance_hold_indefinite: false,
        deleted_at: None,
        upstream_published_at: None,
        uploaded_by: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn reject_violation() -> ScanOutcome {
    ScanOutcome::Reject(vec![PolicyViolation {
        rule: "cve-severity-threshold".into(),
        severity: SeverityThreshold::Critical,
        message: "fixture violation".into(),
        details: serde_json::Value::Null,
    }])
}

// ---------------------------------------------------------------------------
// Classification — the compile-enforced source of truth for this guard
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectedArmVerdict {
    /// No `(event, state)` cell in the declared table targets `Rejected`.
    Unreachable,
    /// Reaches `Rejected`, and the entity method is proven (below) to emit
    /// an `ArtifactRejected` alongside its own axis event — D6-compliant.
    Compliant,
    /// Reaches `Rejected` WITHOUT an `ArtifactRejected` companion. Not a
    /// legitimate design exemption — see the arm's own comment for why it
    /// exists and what closes it.
    KnownGap,
}

/// Classify every [`QuarantineEvent`] for the Rejected-terminal-event
/// invariant. Exhaustive, **no wildcard arm** — see the module doc for
/// what that buys.
#[allow(clippy::match_same_arms)]
fn classify(event: QuarantineEvent) -> RejectedArmVerdict {
    use RejectedArmVerdict::{Compliant, KnownGap, Unreachable};

    match event {
        // ── never reach Rejected (see quarantine_transitions::classify) ──
        QuarantineEvent::Quarantine => Unreachable,
        QuarantineEvent::RecordCleanScan => Unreachable,
        QuarantineEvent::ReleaseCuratorWaiver => Unreachable,
        QuarantineEvent::ReleaseGeneral => Unreachable,
        QuarantineEvent::CascadeProvenanceClearance => Unreachable,
        QuarantineEvent::FailScanIndeterminate => Unreachable,
        // Leaves Rejected (Quarantined/Released), never reaches it.
        QuarantineEvent::ReEvaluate => Unreachable,
        // The corrective path out of D6's illegal state. Leaves
        // `Rejected` for `Quarantined` and reaches no other state, so it
        // can never *create* the condition this guard polices. Its own
        // safety — that it cannot reach a genuine terminal rejection —
        // is the inverse property, enforced by the
        // `TerminalRejectionRecord::Present` refusal in
        // `Artifact::repair_provenance_misrejection` (which asks the same
        // `has_terminal_rejection_event` predicate this file does).
        QuarantineEvent::RepairProvenanceMisrejection => Unreachable,

        // ── reach Rejected, and append ArtifactRejected ──────────────────
        // The scan axis (`QuarantineUseCase`).
        QuarantineEvent::RejectFromScan => Compliant,
        // The curation axis (`CurationUseCase`).
        QuarantineEvent::RejectFromRetroactiveCuration => Compliant,
        // The retroactive scan-policy axis (`PolicyUseCase`) — only its
        // `ScanOutcome::Reject` arm reaches Rejected; `Clean` /
        // `FindingsRecorded` are no-ops (`quarantine_transitions::classify`
        // still lists the cell `Allowed` because the *state* accepts the
        // event, independent of which outcome fires).
        QuarantineEvent::RejectFromScanPolicyRetroactive => Compliant,
        // The curator axis (`CurationUseCase::block`).
        QuarantineEvent::BlockByCurator => Compliant,
        // The provenance axis (`Artifact::complete_provenance`). This is
        // the arm ADR 0039's 2026-09-12 amendment D6 closed: a positive
        // disproof now appends `ArtifactRejected` alongside
        // `ProvenanceRejected` (the unsigned-at-expiry arm that used to be
        // the OTHER offender no longer reaches Rejected at all — it holds,
        // per D1/D4 — so it is not a member of this match's
        // "reaches Rejected" set to begin with).
        QuarantineEvent::CompleteProvenance => Compliant,

        // ── reaches Rejected, but WITHOUT an ArtifactRejected companion ──
        //
        // `Artifact::tombstone_from_corruption` transitions
        // `{None, Quarantined, Released, ScanIndeterminate} -> Rejected`
        // but appends only `ArtifactCorrupted` — never `ArtifactRejected`.
        // This is the guard finding a genuine, pre-existing D6 violation,
        // not a legitimate design choice: `RejectionReason` has no
        // corruption-shaped variant to carry (the entity method leaves
        // `rejection_reason = None`), and
        // `crates/hort-adapters-postgres/src/curation_queue_repository.rs`'s
        // rejection-reason LATERAL JOIN resolves only `event_type =
        // 'ArtifactRejected'` rows — its own doc comment already flags
        // that a corruption-tombstoned artifact's rejection reason is
        // "sourced separately if a future schema change adds it", i.e.
        // today it resolves to nothing. A corruption-tombstoned artifact
        // is therefore exactly the state D6 forbids: `Rejected` with no
        // `ArtifactRejected` on the stream, unauditable via the query path
        // every other Rejected axis uses.
        //
        // Pinned here as a NAMED arm — not silently passed — so
        // `every_transition_reaching_rejected_is_checked_for_its_terminal_event`
        // fails loudly the moment someone closes it, forcing a conscious
        // promotion to `Compliant` instead of the fix going unnoticed.
        QuarantineEvent::TombstoneFromCorruption => KnownGap,
    }
}

// ---------------------------------------------------------------------------
// Cross-check: this file's classification vs. the declared transition table
// ---------------------------------------------------------------------------

const ALL_STATUSES: &[QuarantineStatus] = &[
    QuarantineStatus::None,
    QuarantineStatus::Quarantined,
    QuarantineStatus::Released,
    QuarantineStatus::Rejected,
    QuarantineStatus::ScanIndeterminate,
];

/// Whether ANY `(event, state)` cell in
/// [`quarantine_transitions::classify`] targets `Rejected` — the ground
/// truth this file's [`classify`] must agree with.
fn table_reaches_rejected(event: QuarantineEvent) -> bool {
    ALL_STATUSES.iter().any(|&from| {
        matches!(
            quarantine_transitions::classify(event, from),
            quarantine_transitions::Cell::Allowed(targets)
                if targets.contains(&QuarantineStatus::Rejected)
        )
    })
}

#[test]
fn classification_matches_the_declared_transition_table() {
    for &event in QuarantineEvent::ALL {
        let this_file_says_reaches = classify(event) != RejectedArmVerdict::Unreachable;
        let table_says_reaches = table_reaches_rejected(event);
        assert_eq!(
            this_file_says_reaches, table_says_reaches,
            "classify({event:?}) here says reaches-Rejected={this_file_says_reaches}, but \
             quarantine_transitions::classify says {table_says_reaches} — the declared \
             transition table changed which states {event:?} can reach without a matching \
             update here. Update this file's `classify` to agree."
        );
    }
}

// ---------------------------------------------------------------------------
// Exercise — actually call the entity method each Rejected-reaching event
// represents, and collect the events it emits.
// ---------------------------------------------------------------------------

fn exercise(event: QuarantineEvent) -> Vec<DomainEvent> {
    match event {
        QuarantineEvent::RejectFromScan => {
            let mut a = quarantined_artifact();
            let ev = a
                .reject_from_scan("scan finding".into())
                .expect("Quarantined -> RejectFromScan is an allowed transition");
            vec![DomainEvent::ArtifactRejected(ev)]
        }
        QuarantineEvent::RejectFromRetroactiveCuration => {
            let mut a = quarantined_artifact();
            let ev = a
                .reject_from_retroactive_curation(Uuid::from_u128(0xEE), "curation hit".into())
                .expect("Quarantined -> RejectFromRetroactiveCuration is an allowed transition");
            vec![DomainEvent::ArtifactRejected(ev)]
        }
        QuarantineEvent::RejectFromScanPolicyRetroactive => {
            let mut a = quarantined_artifact();
            let ev = a
                .reject_from_scan_policy_retroactive(&reject_violation(), "policy re-derive".into())
                .expect("Quarantined -> RejectFromScanPolicyRetroactive(Reject) is allowed")
                .expect("a ScanOutcome::Reject verdict must produce Some(ArtifactRejected)");
            vec![DomainEvent::ArtifactRejected(ev)]
        }
        QuarantineEvent::BlockByCurator => {
            let mut a = quarantined_artifact();
            let ev = a
                .block_by_curator(Uuid::from_u128(0xC0), "curator block".into())
                .expect("Quarantined -> BlockByCurator is an allowed transition");
            vec![DomainEvent::ArtifactRejected(ev)]
        }
        QuarantineEvent::CompleteProvenance => {
            let mut a = quarantined_artifact();
            a.complete_provenance(
                ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
                "cosign",
            )
            .expect("Quarantined -> CompleteProvenance(Rejected) is an allowed transition")
        }
        QuarantineEvent::TombstoneFromCorruption => {
            let mut a = quarantined_artifact();
            let ev = a
                .tombstone_from_corruption(fixed_hash(), chrono::Utc::now())
                .expect("Quarantined -> TombstoneFromCorruption is an allowed transition");
            vec![DomainEvent::ArtifactCorrupted(ev)]
        }
        QuarantineEvent::Quarantine
        | QuarantineEvent::RecordCleanScan
        | QuarantineEvent::ReleaseCuratorWaiver
        | QuarantineEvent::ReleaseGeneral
        | QuarantineEvent::CascadeProvenanceClearance
        | QuarantineEvent::FailScanIndeterminate
        | QuarantineEvent::ReEvaluate
        | QuarantineEvent::RepairProvenanceMisrejection => {
            unreachable!(
                "exercise({event:?}) called for an event classified Unreachable — \
                 the main test only calls exercise() for the other two verdicts"
            )
        }
    }
}

/// The D6 terminal-event predicate. Thin alias over the **domain's own**
/// [`has_terminal_rejection_event`] rather than a second implementation:
/// the corrective path
/// ([`Artifact::repair_provenance_misrejection`]) asks the identical
/// question of a stranded artifact's persisted stream, and two copies of
/// a safety predicate is precisely the drift `release_clearance.rs`
/// exists to prevent. If this guard's notion of "carries a terminal
/// event" and the repair's ever diverge, the repair could reach a real
/// rejection — so they share one definition by construction.
fn contains_artifact_rejected(events: &[DomainEvent]) -> bool {
    has_terminal_rejection_event(events)
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

#[test]
fn every_transition_reaching_rejected_is_checked_for_its_terminal_event() {
    for &event in QuarantineEvent::ALL {
        match classify(event) {
            RejectedArmVerdict::Unreachable => {
                // Nothing to exercise — table_reaches_rejected(event) is
                // false, proven by the cross-check test above.
            }
            RejectedArmVerdict::Compliant => {
                let events = exercise(event);
                assert!(
                    contains_artifact_rejected(&events),
                    "{event:?} reaches QuarantineStatus::Rejected but its emitted event set \
                     {events:?} carries no ArtifactRejected. This is the illegal state ADR \
                     0039's 2026-09-12 amendment (D6) forbids — a terminal status the stream \
                     cannot audit or re-derive. If this regression is intentional, reclassify \
                     the arm KnownGap with a named, commented reason instead \
                     of silently letting this assertion fail."
                );
            }
            RejectedArmVerdict::KnownGap => {
                let events = exercise(event);
                assert!(
                    !contains_artifact_rejected(&events),
                    "{event:?} is classified KnownGap but its emitted event \
                     set {events:?} now DOES carry an ArtifactRejected — the gap has been \
                     closed; promote this arm to Compliant."
                );
            }
        }
    }
}

/// Proves the guard's own predicate actually distinguishes compliant from
/// illegal event sets — a guard nobody has watched fail is a guard nobody
/// knows works. Constructs the exact illegal shape D6 forbids: a
/// transition to `Rejected` (stood in for by an `ArtifactCorrupted`
/// companion, exactly what `TombstoneFromCorruption` above emits for
/// real) whose event set omits `ArtifactRejected`.
#[test]
fn predicate_rejects_a_fabricated_event_set_with_no_terminal_companion() {
    let illegal_state_events = vec![DomainEvent::ArtifactCorrupted(ArtifactCorrupted {
        artifact_id: Uuid::from_u128(9),
        computed_hash: fixed_hash(),
        expected_hash: fixed_hash(),
        detected_at: chrono::Utc::now(),
    })];
    assert!(
        !contains_artifact_rejected(&illegal_state_events),
        "predicate must flag an event set with no ArtifactRejected as non-compliant"
    );

    // And the positive case: a compliant event set is correctly accepted.
    let compliant_events = vec![DomainEvent::ArtifactRejected(
        hort_domain::events::ArtifactRejected {
            artifact_id: Uuid::from_u128(9),
            rejected_by: RejectionReason::Scanner,
            reason: "fixture".into(),
        },
    )];
    assert!(
        contains_artifact_rejected(&compliant_events),
        "predicate must accept an event set that does carry an ArtifactRejected"
    );
}
