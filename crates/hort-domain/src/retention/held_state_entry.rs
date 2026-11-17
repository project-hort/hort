//! The **state-entry anchor** — when the artifact entered the held state
//! it is in *now*.
//!
//! A span over a held artifact measures how long it has been in that
//! state, never how old its content is. This module resolves the only
//! anchor that answers the first question, and its entire reason for
//! existing is that the codebase already ships a plausible-looking
//! anchor that answers the second.
//!
//! ## Why [`Artifact::quarantine_window_start`] is the wrong anchor
//!
//! [`Artifact::quarantine_window_start`](crate::entities::artifact::Artifact::quarantine_window_start)
//! is the *earliest content anchor* — the minimum over the mint instant,
//! the earliest moment hort observed this content in any of its
//! repositories, a trusted upstream publish time, and the
//! referenced-tree-descendant carve-out (ADR 0054, which describes it in
//! as many words as an approximation of elapsed ecosystem exposure). It
//! is correct for what it is: the input to the observation-window
//! deadline the release gate uses.
//!
//! It is **not** a statement about the artifact's current state, and a
//! retroactive rejection keeps it unchanged
//! ([`Artifact::reject_from_scan_policy_retroactive`](crate::entities::artifact::Artifact::reject_from_scan_policy_retroactive),
//! [`Artifact::reject_from_retroactive_curation`](crate::entities::artifact::Artifact::reject_from_retroactive_curation)).
//! So a two-year-old artifact rejected five minutes ago is **instantly
//! past any span expressed against it**: under a 30-day span it would be
//! purged the same afternoon it was first judged. That is invisible in
//! any test whose fixture creates the artifact and rejects it in the same
//! second, which is what a hand-written fixture naturally does — hence
//! `state_entry_is_the_state_entry_not_the_content_anchor`, which puts a
//! year between the two.
//!
//! ## The trap one level down: the entry event carries the other number
//!
//! [`ArtifactQuarantined`](crate::events::ArtifactQuarantined) — the
//! entry event for [`HeldState::Quarantined`] — carries a
//! `quarantine_window_start` field in its own payload, because that is
//! the anchor the quarantine transition sets. Reading the entry event and
//! then taking the timestamp *out of it* therefore lands on the content
//! anchor again, by a route that looks like it consulted the stream.
//!
//! The entry instant is [`PersistedEvent::stored_at`] — when the store
//! recorded the transition — and **never a payload field**. The other two
//! entry events carry no timestamp at all, so `stored_at` is also the
//! only thing available for them; `ArtifactQuarantined` is the one event
//! where a wrong answer is reachable, and it is the one the year-apart
//! test is written against.
//!
//! ## Which event marks entry, per state
//!
//! | State | Entry event | Transitions that emit it |
//! |---|---|---|
//! | [`Quarantined`](HeldState::Quarantined) | [`ArtifactQuarantined`](crate::events::ArtifactQuarantined) | `quarantine`, `supersede_absent_verdict`, `re_evaluate` (in-window arm), `repair_provenance_misrejection` |
//! | [`Rejected`](HeldState::Rejected) | [`ArtifactRejected`](crate::events::ArtifactRejected) | `reject_from_scan`, `reject_from_retroactive_curation`, `reject_from_scan_policy_retroactive`, `block_by_curator`, `tombstone_from_corruption` (beside its `ArtifactCorrupted`), `complete_provenance` (beside its `ProvenanceRejected`) |
//! | [`ScanIndeterminate`](HeldState::ScanIndeterminate) | [`ScanIndeterminate`](crate::events::ScanIndeterminate) | `fail_scan_indeterminate` |
//!
//! Each state's entry is **one** event type. For `Rejected` that is a
//! property worth naming rather than assuming: two of its six
//! transitions reach the status while emitting a second, axis-specific
//! event beside the terminal one (`ArtifactCorrupted`,
//! `ProvenanceRejected`), and it is ADR 0039's 2026-09-12 amendment (D6)
//! — "a `Rejected` status must have an `ArtifactRejected` behind it",
//! single-sourced as
//! [`has_terminal_rejection_event`](crate::entities::artifact::has_terminal_rejection_event)
//! — that makes `ArtifactRejected` the common companion. Keying on the
//! axis event instead would miss four transitions out of six; a
//! diagnostic query built from a hand-enumerated lifecycle table was
//! blind to `ProvenanceRejected` for exactly the mirror-image reason.
//!
//! ## The *latest* entry event, because all three states are re-enterable
//!
//! Checked against the declared transition table
//! ([`crate::entities::quarantine_transitions`]) rather than inferred
//! from the event list:
//!
//! - `Rejected` → `Released` (the curator's manual release) → `Rejected`
//!   again (`reject_from_scan` / `reject_from_retroactive_curation` /
//!   `block_by_curator` all admit `Released` as a source state);
//! - `Rejected` → `Quarantined` (`re_evaluate` in-window,
//!   `repair_provenance_misrejection`) and `ScanIndeterminate` →
//!   `Quarantined` (`supersede_absent_verdict`), so a stream can carry
//!   several `ArtifactQuarantined`;
//! - `ScanIndeterminate` → `Quarantined` → `ScanIndeterminate` again
//!   (`fail_scan_indeterminate` admits `Quarantined`).
//!
//! So a held artifact's stream may carry several entry events for the
//! state it is in now, and only the last one dates the *current*
//! occupancy. A reverse scan takes it. Earlier occupancies of the same
//! state are history, and a span measured from one of them would count
//! time the artifact spent elsewhere.
//!
//! ## No entry event ⇒ **no span**, and never a fallback
//!
//! [`resolve_held_state_entry`] answers `None` when the stream carries no
//! entry event for the state, and a `None` means the artifact has no span
//! and therefore never expires on one. It does **not** fall back to
//! [`Artifact::quarantine_window_start`](crate::entities::artifact::Artifact::quarantine_window_start),
//! and it does not substitute the oldest available date.
//!
//! The fallback is the thing that looks harmless and is not, because the
//! absent event and the old content **coincide exactly in the population
//! at risk**: the streams that predate an entry event being written are
//! the oldest streams in the system. A fallback would therefore fire
//! first, and hardest, on precisely the artifacts whose content anchor is
//! furthest in the past. The known instance is a **historical** CAS
//! corruption tombstone: before D6 the tombstone appended
//! `ArtifactCorrupted` alone, the event store is append-only so those
//! streams cannot gain the companion, and they are `Rejected` with no
//! `ArtifactRejected`
//! ([`TerminalRejectionRecord::CorruptionTombstone`](crate::entities::artifact::TerminalRejectionRecord::CorruptionTombstone)).
//! Each of them is a genuine terminal condemnation of bytes that do not
//! match their hash; answering `None` keeps them exactly where they are.
//!
//! ## Clock skew
//!
//! [`PersistedEvent::stored_at`] is informational — `global_position` is
//! the authoritative ordering and `stored_at` may be non-monotonic under
//! clock skew. This resolver therefore picks the entry event by **stream
//! position** (the reverse scan) and reports that event's `stored_at` as
//! the value. A skewed-forward `stored_at` yields a negative elapsed span
//! at the consumer, which is the safe direction: not elapsed, so no
//! expiry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::artifact::QuarantineStatus;
use crate::events::{DomainEvent, PersistedEvent};

/// A [`QuarantineStatus`] in which an artifact is **held** — retained as
/// evidence or awaiting a decision, and today protected from retention
/// collection at four independent places.
///
/// A deliberately narrower type than [`QuarantineStatus`]: it makes
/// "which event marks entry?" a **total** question. Asking that of
/// [`Released`](QuarantineStatus::Released) or
/// [`None`](QuarantineStatus::None) has no answer, and a resolver that
/// took the wider type would have to return the same `None` for "this
/// artifact is not held" as for "this artifact is held and its entry
/// event is missing" — two answers a consumer must never conflate: the
/// first means the ordinary retention rules apply, the second means
/// nothing may expire this artifact at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HeldState {
    /// [`QuarantineStatus::Quarantined`] — the observation hold.
    Quarantined,
    /// [`QuarantineStatus::Rejected`] — a verdict was rendered against
    /// the bytes.
    Rejected,
    /// [`QuarantineStatus::ScanIndeterminate`] — ADR 0007's fail-closed
    /// terminal scan failure.
    ScanIndeterminate,
}

impl HeldState {
    /// Every held state, so a consumer that has to enumerate them —
    /// the operator-facing opt-in, the status/event-type arrays an
    /// adapter binds — iterates this instead of re-listing the
    /// variants. Asserted complete against
    /// [`Self::from_status`] over every [`QuarantineStatus`], so a
    /// fourth held state cannot be added to the enum and left out of
    /// here.
    pub const ALL: [Self; 3] = [Self::Quarantined, Self::Rejected, Self::ScanIndeterminate];

    /// The [`QuarantineStatus`] this held state *is* — the inverse of
    /// [`Self::from_status`], total in this direction because every
    /// held state is a status while only three statuses are held.
    ///
    /// Exists so a consumer that has to name the status (an adapter
    /// binding the stored spelling, a comparison against an artifact's
    /// current status) derives it from the one mapping rather than
    /// carrying a second copy. Exhaustive with no wildcard arm.
    #[must_use]
    pub fn status(self) -> QuarantineStatus {
        match self {
            Self::Quarantined => QuarantineStatus::Quarantined,
            Self::Rejected => QuarantineStatus::Rejected,
            Self::ScanIndeterminate => QuarantineStatus::ScanIndeterminate,
        }
    }

    /// The `event_type` string of this state's entry event — the same
    /// value [`DomainEvent::event_type`] returns for it.
    ///
    /// The one place the state → entry-event mapping becomes a string,
    /// for a consumer that must ask the question in SQL. It is derived
    /// from [`DomainEvent::event_type`] rather than written out, so a
    /// renamed event type cannot leave a stale literal here, and
    /// `entry_event_type_matches_the_event_the_resolver_scans_for`
    /// pins it against [`Self::is_entry_event`] — the two must name
    /// one event or a SQL consumer and the resolver would be asking
    /// about different occupancies.
    ///
    /// A payload is needed to call `event_type()` and none of its
    /// fields reach the answer, so each arm builds the cheapest
    /// well-formed one.
    #[must_use]
    pub fn entry_event_type(self) -> &'static str {
        let probe = match self {
            Self::Quarantined => {
                DomainEvent::ArtifactQuarantined(crate::events::ArtifactQuarantined {
                    artifact_id: uuid::Uuid::nil(),
                    quarantine_window_start: DateTime::<Utc>::UNIX_EPOCH,
                })
            }
            Self::Rejected => DomainEvent::ArtifactRejected(crate::events::ArtifactRejected {
                artifact_id: uuid::Uuid::nil(),
                rejected_by: crate::events::RejectionReason::Scanner,
                reason: String::new(),
            }),
            Self::ScanIndeterminate => {
                DomainEvent::ScanIndeterminate(crate::events::ScanIndeterminate {
                    artifact_id: uuid::Uuid::nil(),
                    scanner: String::new(),
                    reason: String::new(),
                    attempts: 0,
                })
            }
        };
        probe.event_type()
    }

    /// Is this status a held state, and which one?
    ///
    /// The `None` arm is "not held", never "held, entry unknown" — see
    /// the type's own doc for why those two stay separate answers.
    ///
    /// Exhaustive with no wildcard arm, so a sixth [`QuarantineStatus`]
    /// variant is a compile error here rather than silently classifying
    /// as not-held.
    #[must_use]
    pub fn from_status(status: QuarantineStatus) -> Option<Self> {
        match status {
            QuarantineStatus::Quarantined => Some(Self::Quarantined),
            QuarantineStatus::Rejected => Some(Self::Rejected),
            QuarantineStatus::ScanIndeterminate => Some(Self::ScanIndeterminate),
            QuarantineStatus::None | QuarantineStatus::Released => None,
        }
    }

    /// Does this event mark entry into this state?
    ///
    /// The single definition of the state → entry-event mapping the
    /// module docs table states. Exhaustive over [`Self`] with no
    /// wildcard arm, so a fourth held state is a compile error here
    /// rather than an entry event nobody chose.
    fn is_entry_event(self, event: &DomainEvent) -> bool {
        match self {
            Self::Quarantined => matches!(event, DomainEvent::ArtifactQuarantined(_)),
            Self::Rejected => matches!(event, DomainEvent::ArtifactRejected(_)),
            Self::ScanIndeterminate => matches!(event, DomainEvent::ScanIndeterminate(_)),
        }
    }
}

/// When an artifact entered the held state it is in now.
///
/// A distinct type rather than a bare `DateTime<Utc>` so the two time
/// quantities in play cannot be exchanged by accident: handing
/// [`Artifact::quarantine_window_start`](crate::entities::artifact::Artifact::quarantine_window_start)
/// where this is expected is a type error, and every call site that
/// reaches the instant spells [`Self::entered_at`] to get there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldStateEntry {
    /// The held state this entry is about — carried so the value is
    /// self-describing wherever it is logged or asserted, and so a
    /// consumer reading one of these never has to look back at which
    /// state it asked about.
    pub state: HeldState,
    /// The instant the store recorded the entry transition:
    /// [`PersistedEvent::stored_at`] of the **latest** entry event for
    /// [`Self::state`]. Never a payload field — see the module docs on
    /// [`ArtifactQuarantined`](crate::events::ArtifactQuarantined)
    /// carrying the *other* number.
    pub entered_at: DateTime<Utc>,
    /// [`PersistedEvent::stream_position`] of that entry event — the
    /// identity of **this occupancy** of [`Self::state`].
    ///
    /// The state and the instant together do not identify an
    /// occupancy, and that is not a nicety. All three held states are
    /// re-enterable (see the module docs), so a decision recorded
    /// about one occupancy must not be readable as a decision about a
    /// later one: an artifact rejected in March, expired by a policy
    /// whose span had run, released by a curator and rejected again in
    /// September is in the *same state* with the *same name*, and the
    /// March decision says nothing about the September occupancy. The
    /// position is what a consumer compares against the stream's
    /// latest entry event to tell the two apart.
    ///
    /// Positions are per-stream and monotonic, and the event store is
    /// append-only, so a position already issued cannot be re-issued —
    /// which is what makes the comparison conclusive rather than
    /// merely suggestive. `entered_at` cannot do this job: it is
    /// [`PersistedEvent::stored_at`], which is informational and may
    /// repeat or go backwards under clock skew.
    pub entry_stream_position: u64,
}

/// When did this artifact enter `state`?
///
/// `stream` is the artifact's own event stream in stream-position order,
/// read **in full** — the reverse scan answers about the latest entry
/// event among the events it is given, so a truncated prefix would date
/// an earlier occupancy of the state as the current one. The `hort-app`
/// callers get that guarantee from `read_artifact_stream`, which refuses
/// a stream it cannot prove it read to the tail (ADR 0007's event cap).
///
/// `state` must be the held state of the artifact whose stream this is —
/// [`HeldState::from_status`] applied to that artifact's own
/// `quarantine_status`.
///
/// `None` ⇒ **no span**: the stream carries no entry event for `state`,
/// so nothing dates the current occupancy and no span may be computed
/// against anything else. See the module docs for why a fallback to the
/// content anchor is the defect this signature exists to prevent.
#[must_use]
pub fn resolve_held_state_entry(
    state: HeldState,
    stream: &[PersistedEvent],
) -> Option<HeldStateEntry> {
    stream
        .iter()
        .rev()
        .find(|persisted| state.is_entry_event(&persisted.event))
        .map(|persisted| HeldStateEntry {
            state,
            // The store's own record of when the transition landed. The
            // payload is deliberately unread: `ArtifactQuarantined`
            // carries `quarantine_window_start`, which is the content
            // anchor and the wrong number by a year or more.
            entered_at: persisted.stored_at,
            // Which occupancy this is. Taken from the same event the
            // instant comes from, so the two cannot describe different
            // entries.
            entry_stream_position: persisted.stream_position,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;
    use uuid::Uuid;

    use crate::entities::artifact::QuarantineStatus;
    use crate::events::{
        Actor, ArtifactCorrupted, ArtifactQuarantined, ArtifactRejected, ArtifactReleased,
        InternalActor, ProvenanceRejected, RejectionReason, ReleaseReason, ScanIndeterminate,
        StreamId,
    };
    use crate::ports::provenance::ProvenanceRejectReason;
    use crate::types::ContentHash;

    fn ts(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0)
            .single()
            .expect("unambiguous test timestamp")
    }

    /// A stream event at `position`, recorded by the store at `stored_at`.
    ///
    /// `stored_at` is the only timestamp the resolver may read, so every
    /// test below sets it explicitly and independently of whatever the
    /// payload carries.
    fn persisted(
        artifact_id: Uuid,
        position: u64,
        event: DomainEvent,
        stored_at: DateTime<Utc>,
    ) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(artifact_id),
            stream_position: position,
            global_position: position,
            event,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Internal(InternalActor::System),
            event_version: 1,
            stored_at,
        }
    }

    fn quarantined(artifact_id: Uuid, window_start: DateTime<Utc>) -> DomainEvent {
        DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
            artifact_id,
            quarantine_window_start: window_start,
        })
    }

    fn rejected(artifact_id: Uuid) -> DomainEvent {
        DomainEvent::ArtifactRejected(ArtifactRejected {
            artifact_id,
            rejected_by: RejectionReason::Scanner,
            reason: "blocking findings".to_owned(),
        })
    }

    fn scan_indeterminate(artifact_id: Uuid) -> DomainEvent {
        DomainEvent::ScanIndeterminate(ScanIndeterminate {
            artifact_id,
            scanner: "trivy".to_owned(),
            reason: "every backend errored".to_owned(),
            attempts: 3,
        })
    }

    fn released(artifact_id: Uuid) -> DomainEvent {
        DomainEvent::ArtifactReleased(ArtifactReleased {
            artifact_id,
            released_by: ReleaseReason::Curator,
            released_by_user_id: Some(Uuid::from_u128(0xC0DE)),
            justification: Some("reviewed and accepted".to_owned()),
        })
    }

    fn hash(byte: char) -> ContentHash {
        String::from_iter(std::iter::repeat_n(byte, 64))
            .parse()
            .expect("64 hex chars")
    }

    fn corrupted(artifact_id: Uuid, detected_at: DateTime<Utc>) -> DomainEvent {
        DomainEvent::ArtifactCorrupted(ArtifactCorrupted {
            artifact_id,
            computed_hash: hash('b'),
            expected_hash: hash('a'),
            detected_at,
        })
    }

    fn provenance_rejected(artifact_id: Uuid) -> DomainEvent {
        DomainEvent::ProvenanceRejected(ProvenanceRejected {
            artifact_id,
            content_hash: hash('a'),
            backend: "cosign".to_owned(),
            reason: ProvenanceRejectReason::Unsigned,
        })
    }

    // -----------------------------------------------------------------
    // The test that decides whether the span exists at all
    // -----------------------------------------------------------------

    /// **The year-apart test.** Content anchor and state entry are
    /// deliberately a year apart: a 2025-01-01 artifact rejected on
    /// 2026-01-01. The resolver must answer with the *rejection*, not
    /// with the content's age.
    ///
    /// If this test's assertion were `ts(2025, 1, 1)`, a 30-day span over
    /// such an artifact would be elapsed the instant the rejection landed
    /// and the artifact would be purged the same afternoon it was first
    /// judged. That failure is invisible to any fixture that ingests and
    /// rejects in the same second, which is why the gap is a year.
    #[test]
    fn state_entry_is_the_state_entry_not_the_content_anchor() {
        let id = Uuid::new_v4();
        let content_anchor = ts(2025, 1, 1);
        let rejected_at = ts(2026, 1, 1);

        // The quarantine carries the year-old content anchor in BOTH
        // places it can be carried: the event payload and (in production)
        // the artifact row. The rejection five minutes ago carries none —
        // only the store's `stored_at` dates it.
        let stream = vec![
            persisted(id, 0, quarantined(id, content_anchor), content_anchor),
            persisted(id, 1, rejected(id), rejected_at),
        ];

        let entry = resolve_held_state_entry(HeldState::Rejected, &stream)
            .expect("the stream carries an ArtifactRejected");

        assert_eq!(
            entry,
            HeldStateEntry {
                state: HeldState::Rejected,
                entered_at: rejected_at,
                entry_stream_position: 1,
            },
            "a retroactive rejection dates from the rejection, never from the content"
        );
        assert_ne!(
            entry.entered_at, content_anchor,
            "the content anchor is a year earlier and must not be the answer"
        );
    }

    /// The same year-apart gap on the one state whose entry event carries
    /// the wrong number **inside its own payload**.
    ///
    /// `ArtifactQuarantined.quarantine_window_start` is the content
    /// anchor (ADR 0054). A resolver that found the right event and then
    /// read the timestamp out of it would be wrong by a year while
    /// looking like it had consulted the stream — the one reachable wrong
    /// answer for this state.
    #[test]
    fn quarantined_entry_ignores_the_window_start_in_its_own_payload() {
        let id = Uuid::new_v4();
        let content_anchor = ts(2025, 1, 1);
        let quarantined_at = ts(2026, 1, 1);

        let stream = vec![persisted(
            id,
            0,
            quarantined(id, content_anchor),
            quarantined_at,
        )];

        let entry = resolve_held_state_entry(HeldState::Quarantined, &stream)
            .expect("the stream carries an ArtifactQuarantined");

        assert_eq!(entry.entered_at, quarantined_at);
        assert_ne!(
            entry.entered_at, content_anchor,
            "the payload's quarantine_window_start is the content anchor, not the state entry"
        );
    }

    // -----------------------------------------------------------------
    // One entry event per state; a status change moves the answer
    // -----------------------------------------------------------------

    /// Each of the three held states finds the event its own transition
    /// emits, over one stream that carries all three.
    #[test]
    fn each_held_state_finds_its_own_entry_event() {
        let id = Uuid::new_v4();
        let quarantined_at = ts(2026, 1, 1);
        let indeterminate_at = ts(2026, 2, 1);
        let rejected_at = ts(2026, 3, 1);

        let stream = vec![
            persisted(id, 0, quarantined(id, ts(2025, 1, 1)), quarantined_at),
            persisted(id, 1, scan_indeterminate(id), indeterminate_at),
            persisted(id, 2, rejected(id), rejected_at),
        ];

        for (state, expected, expected_position) in [
            (HeldState::Quarantined, quarantined_at, 0),
            (HeldState::ScanIndeterminate, indeterminate_at, 1),
            (HeldState::Rejected, rejected_at, 2),
        ] {
            // One eagerly-evaluated comparison over the whole `Option`:
            // it asserts presence, the state tag and the instant at
            // once, and the `Debug` output names the state on failure
            // without a closure that a passing run never enters.
            assert_eq!(
                resolve_held_state_entry(state, &stream),
                Some(HeldStateEntry {
                    state,
                    entered_at: expected,
                    entry_stream_position: expected_position,
                }),
                "each held state must date from its own entry event"
            );
        }
    }

    /// A status change moves the answer: the same stream, asked about the
    /// state the artifact is in *now*, yields that state's entry — so an
    /// artifact that left `quarantined` for `rejected` stops being dated
    /// from the quarantine.
    #[test]
    fn a_status_change_moves_the_answer() {
        let id = Uuid::new_v4();
        let quarantined_at = ts(2026, 1, 1);
        let rejected_at = ts(2026, 6, 1);

        let stream = vec![
            persisted(id, 0, quarantined(id, ts(2025, 1, 1)), quarantined_at),
            persisted(id, 1, rejected(id), rejected_at),
        ];

        let while_quarantined = resolve_held_state_entry(HeldState::Quarantined, &stream)
            .expect("quarantine entry present");
        let after_rejection =
            resolve_held_state_entry(HeldState::Rejected, &stream).expect("rejection present");

        assert_eq!(while_quarantined.entered_at, quarantined_at);
        assert_eq!(after_rejection.entered_at, rejected_at);
        assert_ne!(while_quarantined.entered_at, after_rejection.entered_at);
    }

    /// The `Rejected` entry is the terminal `ArtifactRejected` companion,
    /// not the axis event beside it. Two of the six `Rejected`-reaching
    /// transitions emit an axis event as well
    /// (`tombstone_from_corruption` → `ArtifactCorrupted`,
    /// `complete_provenance` → `ProvenanceRejected`); keying on either
    /// would miss the other four, and here the axis events are
    /// deliberately stored a month before their companions.
    #[test]
    fn rejected_entry_is_the_terminal_companion_not_the_axis_event() {
        let id = Uuid::new_v4();
        let axis_at = ts(2026, 1, 1);
        let companion_at = ts(2026, 2, 1);

        let provenance_stream = vec![
            persisted(id, 0, provenance_rejected(id), axis_at),
            persisted(id, 1, rejected(id), companion_at),
        ];
        assert_eq!(
            resolve_held_state_entry(HeldState::Rejected, &provenance_stream)
                .expect("the D6 companion is on the stream")
                .entered_at,
            companion_at
        );

        let corruption_stream = vec![
            persisted(id, 0, corrupted(id, axis_at), axis_at),
            persisted(id, 1, rejected(id), companion_at),
        ];
        assert_eq!(
            resolve_held_state_entry(HeldState::Rejected, &corruption_stream)
                .expect("the D6 companion is on the stream")
                .entered_at,
            companion_at
        );
    }

    // -----------------------------------------------------------------
    // Re-entry: the latest occupancy, not the first
    // -----------------------------------------------------------------

    /// All three states are re-enterable (see the module docs' walk of
    /// the transition table), so the resolver takes the **latest** entry
    /// event. A span measured from the first would count time the
    /// artifact spent in another state.
    #[test]
    fn re_entry_dates_from_the_latest_entry_event() {
        let id = Uuid::new_v4();
        let first_rejection = ts(2026, 1, 1);
        let waiver = ts(2026, 2, 1);
        let second_rejection = ts(2026, 3, 1);

        // Rejected → Released (curator waiver) → Rejected again: every
        // one of `reject_from_scan`, `reject_from_retroactive_curation`
        // and `block_by_curator` admits `Released` as a source state.
        let stream = vec![
            persisted(id, 0, rejected(id), first_rejection),
            persisted(id, 1, released(id), waiver),
            persisted(id, 2, rejected(id), second_rejection),
        ];

        assert_eq!(
            resolve_held_state_entry(HeldState::Rejected, &stream)
                .expect("rejections present")
                .entered_at,
            second_rejection,
            "the current occupancy began at the second rejection"
        );
    }

    /// The same, for a re-quarantine: `re_evaluate`'s in-window arm and
    /// `repair_provenance_misrejection` both emit a second
    /// `ArtifactQuarantined` on a stream that already carries one.
    #[test]
    fn re_quarantine_dates_from_the_latest_quarantine_event() {
        let id = Uuid::new_v4();
        let content_anchor = ts(2025, 1, 1);
        let first_quarantine = ts(2026, 1, 1);
        let re_quarantine = ts(2026, 5, 1);

        // Both events carry the SAME preserved content anchor — the
        // re-quarantine restores the window rather than restarting it —
        // so the payload cannot distinguish them and only `stored_at`
        // can.
        let stream = vec![
            persisted(id, 0, quarantined(id, content_anchor), first_quarantine),
            persisted(id, 1, rejected(id), ts(2026, 2, 1)),
            persisted(id, 2, quarantined(id, content_anchor), re_quarantine),
        ];

        assert_eq!(
            resolve_held_state_entry(HeldState::Quarantined, &stream)
                .expect("quarantine entries present")
                .entered_at,
            re_quarantine
        );
    }

    /// And for `scan_indeterminate`, which `supersede_absent_verdict`
    /// exits to `Quarantined` and `fail_scan_indeterminate` can re-enter
    /// from there.
    #[test]
    fn re_entered_scan_indeterminate_dates_from_the_latest_failure() {
        let id = Uuid::new_v4();
        let first_failure = ts(2026, 1, 1);
        let second_failure = ts(2026, 4, 1);

        let stream = vec![
            persisted(id, 0, scan_indeterminate(id), first_failure),
            persisted(id, 1, quarantined(id, ts(2025, 1, 1)), ts(2026, 2, 1)),
            persisted(id, 2, scan_indeterminate(id), second_failure),
        ];

        assert_eq!(
            resolve_held_state_entry(HeldState::ScanIndeterminate, &stream)
                .expect("failures present")
                .entered_at,
            second_failure
        );
    }

    // -----------------------------------------------------------------
    // No entry event ⇒ no span (the absence, asserted as an absence)
    // -----------------------------------------------------------------

    /// An empty stream yields **no span**. Asserted as an absence: there
    /// is no value to compare against, because a fallback value is
    /// exactly the defect.
    #[test]
    fn empty_stream_yields_no_span() {
        assert!(resolve_held_state_entry(HeldState::Rejected, &[]).is_none());
        assert!(resolve_held_state_entry(HeldState::Quarantined, &[]).is_none());
        assert!(resolve_held_state_entry(HeldState::ScanIndeterminate, &[]).is_none());
    }

    /// The population at risk, concretely: a **historical** CAS
    /// corruption tombstone. Before ADR 0039's D6 companion existed the
    /// tombstone appended `ArtifactCorrupted` alone, and the event store
    /// is append-only so those streams can never gain the companion —
    /// they are `Rejected` with no `ArtifactRejected`.
    ///
    /// The stream still carries a year-old `ArtifactQuarantined` whose
    /// payload holds a content anchor, and the whole point is that the
    /// resolver reaches for **neither** it nor any other date: no entry
    /// event, no span, so nothing may ever expire this artifact.
    #[test]
    fn historical_corruption_tombstone_yields_no_span_not_a_fallback() {
        let id = Uuid::new_v4();
        let stream = vec![
            persisted(id, 0, quarantined(id, ts(2024, 1, 1)), ts(2024, 1, 1)),
            persisted(id, 1, corrupted(id, ts(2026, 1, 1)), ts(2026, 1, 1)),
        ];

        assert!(
            resolve_held_state_entry(HeldState::Rejected, &stream).is_none(),
            "a pre-D6 tombstone has no ArtifactRejected, so it has no span — \
             not the quarantine's anchor, not the ArtifactCorrupted's stored_at"
        );
    }

    /// A stream with events but none of them this state's entry event:
    /// the resolver does not settle for the nearest available timestamp.
    #[test]
    fn a_stream_without_this_states_entry_event_yields_no_span() {
        let id = Uuid::new_v4();
        let stream = vec![
            persisted(id, 0, quarantined(id, ts(2025, 1, 1)), ts(2025, 1, 1)),
            persisted(id, 1, released(id), ts(2026, 1, 1)),
        ];

        assert!(resolve_held_state_entry(HeldState::Rejected, &stream).is_none());
        assert!(resolve_held_state_entry(HeldState::ScanIndeterminate, &stream).is_none());
        // The one state that IS on this stream still answers.
        assert!(resolve_held_state_entry(HeldState::Quarantined, &stream).is_some());
    }

    // -----------------------------------------------------------------
    // HeldState::from_status
    // -----------------------------------------------------------------

    /// The three held statuses classify, and the two that are not held
    /// classify as not-held rather than as "held, entry unknown".
    #[test]
    fn from_status_classifies_every_quarantine_status() {
        assert_eq!(
            HeldState::from_status(QuarantineStatus::Quarantined),
            Some(HeldState::Quarantined)
        );
        assert_eq!(
            HeldState::from_status(QuarantineStatus::Rejected),
            Some(HeldState::Rejected)
        );
        assert_eq!(
            HeldState::from_status(QuarantineStatus::ScanIndeterminate),
            Some(HeldState::ScanIndeterminate)
        );
        assert_eq!(HeldState::from_status(QuarantineStatus::None), None);
        assert_eq!(HeldState::from_status(QuarantineStatus::Released), None);
    }

    /// Every [`QuarantineStatus`] variant is classified — so a sixth
    /// variant cannot be added and left out of this decision silently.
    /// `QuarantineStatus::ALL` is the vocabulary's single list and
    /// `from_status` is wildcard-free, so the two together make the
    /// omission a compile error rather than a quiet "not held".
    #[test]
    fn from_status_covers_the_whole_status_vocabulary() {
        let classified = QuarantineStatus::ALL
            .iter()
            .filter(|s| HeldState::from_status(**s).is_some())
            .count();
        // Both halves eagerly, so the statement says "three of the five"
        // rather than deferring the total into an assertion message that
        // only a failing run would ever evaluate.
        assert_eq!(
            (classified, QuarantineStatus::ALL.len()),
            (3, 5),
            "exactly three of the five quarantine statuses are held states"
        );
    }

    // -----------------------------------------------------------------
    // The occupancy identity
    // -----------------------------------------------------------------

    /// The position names the **latest** occupancy, not the first.
    ///
    /// This is the decisive property for the consumer that compares a
    /// recorded decision against the stream: a stream carrying two
    /// rejections must date — and identify — the second one, or an
    /// authority recorded for the first would read as current.
    #[test]
    fn the_position_names_the_latest_occupancy() {
        let id = Uuid::new_v4();
        let first_rejection = ts(2026, 3, 1);
        let second_rejection = ts(2026, 9, 1);

        let stream = vec![
            persisted(id, 0, quarantined(id, ts(2025, 1, 1)), ts(2025, 1, 1)),
            persisted(id, 1, rejected(id), first_rejection),
            persisted(id, 2, released(id), ts(2026, 6, 1)),
            persisted(id, 3, rejected(id), second_rejection),
        ];

        assert_eq!(
            resolve_held_state_entry(HeldState::Rejected, &stream),
            Some(HeldStateEntry {
                state: HeldState::Rejected,
                entered_at: second_rejection,
                entry_stream_position: 3,
            }),
            "the current occupancy is the September rejection at position 3"
        );
    }

    /// The position is the entry event's own, not the stream's length
    /// or the position of whatever happens to be last.
    #[test]
    fn the_position_is_the_entry_events_own_not_the_streams_tail() {
        let id = Uuid::new_v4();
        let rejected_at = ts(2026, 1, 1);
        let stream = vec![
            persisted(id, 0, quarantined(id, ts(2025, 1, 1)), ts(2025, 1, 1)),
            persisted(id, 1, rejected(id), rejected_at),
            // Two later events that are not entry events for `Rejected`.
            persisted(id, 2, corrupted(id, ts(2026, 2, 1)), ts(2026, 2, 1)),
            persisted(id, 3, provenance_rejected(id), ts(2026, 3, 1)),
        ];

        let entry = resolve_held_state_entry(HeldState::Rejected, &stream)
            .expect("the stream carries an ArtifactRejected");
        assert_eq!(entry.entry_stream_position, 1);
    }

    // -----------------------------------------------------------------
    // The derived mappings
    // -----------------------------------------------------------------

    /// `status()` is the inverse of `from_status` on every held state —
    /// so a consumer that converts in one direction and compares in the
    /// other cannot be reading two mappings.
    #[test]
    fn status_round_trips_through_from_status() {
        for state in HeldState::ALL {
            assert_eq!(
                HeldState::from_status(state.status()),
                Some(state),
                "status() and from_status must be one mapping"
            );
        }
    }

    /// `ALL` is complete: it holds exactly the states `from_status`
    /// classifies over the whole status vocabulary. A fourth held state
    /// added to the enum but not to `ALL` fails here, which is what
    /// keeps every enumerate-the-states consumer (the opt-in surface,
    /// the arrays an adapter binds) from quietly covering two of three.
    #[test]
    fn all_holds_every_state_from_status_classifies() {
        let mut classified: Vec<HeldState> = QuarantineStatus::ALL
            .iter()
            .filter_map(|s| HeldState::from_status(*s))
            .collect();
        classified.sort_unstable();
        let mut listed = HeldState::ALL.to_vec();
        listed.sort_unstable();
        assert_eq!(classified, listed);
    }

    /// `entry_event_type()` names the event `is_entry_event` scans for.
    ///
    /// The two are the same mapping seen from two sides — a typed match
    /// for the resolver, a string for a SQL consumer — and the whole
    /// point of the string is to ask about the same occupancy the
    /// resolver answers about. A divergence would let a consumer compute
    /// "the latest entry event" over a different event type than the one
    /// the recorded position came from, and the comparison would then
    /// refuse every authority (or accept a stale one) with nothing
    /// failing.
    #[test]
    fn entry_event_type_matches_the_event_the_resolver_scans_for() {
        let id = Uuid::new_v4();
        let candidates = [
            quarantined(id, ts(2025, 1, 1)),
            rejected(id),
            scan_indeterminate(id),
            released(id),
            corrupted(id, ts(2026, 1, 1)),
            provenance_rejected(id),
        ];
        for state in HeldState::ALL {
            let by_type: Vec<&str> = candidates
                .iter()
                .filter(|ev| ev.event_type() == state.entry_event_type())
                .map(DomainEvent::event_type)
                .collect();
            let by_predicate: Vec<&str> = candidates
                .iter()
                .filter(|ev| state.is_entry_event(ev))
                .map(DomainEvent::event_type)
                .collect();
            assert_eq!(
                (state, by_type),
                (state, by_predicate),
                "the string and the typed match must select the same event"
            );
        }
    }

    /// The three entry event types are distinct, so the string cannot
    /// make two states share an occupancy.
    #[test]
    fn each_state_has_its_own_entry_event_type() {
        let mut types: Vec<&str> = HeldState::ALL
            .iter()
            .map(|s| s.entry_event_type())
            .collect();
        types.sort_unstable();
        types.dedup();
        assert_eq!(types.len(), HeldState::ALL.len());
    }

    /// The entry carries its occupancy through `serde`, because it is
    /// the authority snapshot `ArtifactExpired` persists. A position
    /// lost in the round trip would make every stored authority
    /// unverifiable.
    #[test]
    fn the_entry_round_trips_through_serde() {
        let entry = HeldStateEntry {
            state: HeldState::ScanIndeterminate,
            entered_at: ts(2026, 4, 5),
            entry_stream_position: 42,
        };
        let json = serde_json::to_value(entry).expect("serialises");
        assert_eq!(json["state"], "ScanIndeterminate");
        assert_eq!(json["entry_stream_position"], 42);
        assert_eq!(
            serde_json::from_value::<HeldStateEntry>(json).expect("deserialises"),
            entry
        );
    }
}
