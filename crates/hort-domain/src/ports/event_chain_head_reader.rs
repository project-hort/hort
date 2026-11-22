//! Outbound port for snapshotting the live event-chain heads
//! (the external-anchor *emission* half of tamper evidence).
//!
//! **Pure boundary, zero I/O.** This module only *defines* the read
//! contract the `eventstore-checkpoint` `TaskHandler` needs to assemble
//! a checkpoint: every live stream's
//! `(stream_id, final_stream_position, head_event_hash)` plus the
//! consistent-cut `max_global_position`, and the `StreamSealed` records
//! on the `StreamId::eventstore_retention()` audit-meta stream (the
//! derived `admin-<v5-uuid>` id) since the previous **anchored**
//! checkpoint.
//!
//! ## The seal read is a delta, and the boundary is a parameter
//!
//! The seal set is scoped to what no checkpoint has anchored yet, so
//! the caller supplies the boundary: the audit-meta stream position an
//! anchored checkpoint already covered
//! (`hort_domain::events::anchored_retention_position`, derived from the
//! signed witness the emission cycle has already read). Carrying the
//! whole seal history in every checkpoint would re-anchor every seal on
//! every tick, growing each anchor object with the seal count and the
//! anchor store with seals x ticks.
//!
//! **Why that boundary and not the previous tick.** A failed emission
//! writes no anchor, so the boundary does not advance and the next run
//! reads the same seals again: catch-up is structural rather than a
//! property of re-reading everything. The windows tile without gaps
//! because the boundary is the *same snapshot's* head of the stream the
//! seals are read from.
//!
//! **This is the emission half only.** The verification half
//! (`EventChainReaderPort::read_sealed_records`) stays unwindowed: it
//! justifies a now-absent anchored stream, which needs the full seal
//! history permanently.
//!
//! ## Why a new sibling port (not `EventStore`)
//!
//! `EventStore::read_stream`/`read_category` return `PersistedEvent`,
//! which by design does **not** carry the `prev_event_hash`/`event_hash`
//! chain columns the checkpoint emitter needs. The checkpoint emitter
//! needs the head `event_hash` per stream, which `PersistedEvent` cannot
//! express. Widening `EventStore` is explicitly forbidden. This is
//! therefore an **additive sibling port**, mirroring the verifier's own
//! decision to issue its bounded chain-column `SELECT` rather than widen
//! `EventStore` (`crates/hort-server/src/cli/verify_event_chain.rs`).
//! The adapter reuses the *same* runtime-DML-DSN bounded read shape
//! (`list_stream_ids` / per-stream head row) — `SELECT`-only on the
//! runtime pool, never DDL, never a write to `events`.
//!
//! The trait is intentionally minimal (one snapshot op); the read posture
//! (runtime DML DSN, `SELECT` only) is an adapter concern documented on
//! the implementation.
//!
//! ## A failed snapshot has two classes, and they are distinguished here
//!
//! A snapshot can fail because the store could not be reached — and
//! because the **stored chain evidence cannot be read back**: a chain
//! hash column that is not 32 bytes wide, a `StreamSealed` payload that
//! does not decode. The second class is the thing this whole anchor
//! mechanism exists to surface, and re-reading the same bytes returns
//! the same verdict, so retrying only spends the caller's attempt budget
//! before reaching the same end.
//!
//! [`ChainSnapshotError`] therefore carries the two classes as separate
//! variants, with the corrupt-evidence half as a dedicated
//! port-boundary payload ([`CorruptChainEvidence`]) — the shape
//! [`CasIntegrityFailure`](super::storage::CasIntegrityFailure) already
//! uses for at-rest corruption, and deliberately **not** a
//! [`DomainError`] variant: the condition has no HTTP surface, so a new
//! variant would reach every exhaustive match and the HTTP error mapping
//! for a caller that does not exist.

use core::fmt;

use crate::error::DomainError;
use crate::events::{SealedStreamRecord, StreamHead};

use super::BoxFuture;

/// A consistent-cut snapshot of the live event store, sufficient to
/// assemble a checkpoint. Pure data — the adapter populates it from a
/// bounded runtime-DSN `SELECT`; this type does no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveChainSnapshot {
    /// Every live stream's head: `(stream_id, final_stream_position,
    /// head_event_hash)`. Order is unspecified — the pure builder sorts
    /// by `stream_id` for the Merkle root + witness.
    pub heads: Vec<StreamHead>,
    /// The max `events.global_position` the snapshot covers — the
    /// consistent-cut marker (a *marker*, not a chain link). `0` when
    /// the table is empty.
    pub max_global_position: u64,
    /// `StreamSealed` records read from the never-deleted
    /// `StreamId::eventstore_retention()` audit-meta stream (the derived
    /// `admin-<v5-uuid>` id) since the previous **anchored** checkpoint —
    /// the records at a stream position past the boundary
    /// `snapshot_live_chain` was handed. **Empty is valid and expected**
    /// when nothing has been sealed since that cut — the emitter handles
    /// an empty set cleanly.
    pub sealed_since_previous: Vec<SealedStreamRecord>,
}

impl LiveChainSnapshot {
    /// A convenience constructor used by tests / adapters that have the
    /// three parts already. Pure.
    pub fn new(
        heads: Vec<StreamHead>,
        max_global_position: u64,
        sealed_since_previous: Vec<SealedStreamRecord>,
    ) -> Self {
        Self {
            heads,
            max_global_position,
            sealed_since_previous,
        }
    }
}

/// Where an unreadable stored datum sits.
///
/// A closed, stable set, used as the value of the structured log field
/// an operator alerts on — so the alert keys on a field rather than on a
/// substring of a message. It names **the datum**, not the call site
/// that noticed it: two code paths that find the same stored value
/// unreadable report the same locus, and the free-text detail says which
/// way it was unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainEvidenceLocus {
    /// A stored 32-byte `bytea` chain-hash column (`event_hash` /
    /// `prev_event_hash`) is not 32 bytes wide.
    ChainHashColumn,
    /// The audit-meta stream position an anchored checkpoint already
    /// covered, as recovered from that checkpoint's signed witness, does
    /// not fit the column it is compared against.
    AnchoredRetentionPosition,
    /// A stored `StreamSealed` payload on the audit-meta stream does not
    /// decode into the record the checkpoint binds.
    SealedRecordPayload,
    /// A row read as a seal on the audit-meta stream decoded as some
    /// other event.
    SealedRecordEventType,
}

impl ChainEvidenceLocus {
    /// The stable wire form — the log/alert field value. Changing one of
    /// these strings breaks every operator alert keyed on it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChainHashColumn => "chain_hash_column",
            Self::AnchoredRetentionPosition => "anchored_retention_position",
            Self::SealedRecordPayload => "sealed_record_payload",
            Self::SealedRecordEventType => "sealed_record_event_type",
        }
    }
}

impl fmt::Display for ChainEvidenceLocus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The stored event-chain evidence a checkpoint is assembled from could
/// not be read back as the chain format requires.
///
/// Carried as a typed port-boundary payload — the shape
/// [`CasIntegrityFailure`](super::storage::CasIntegrityFailure) uses for
/// the same question one layer down — because a caller has to tell this
/// apart from the store being unreachable, and a message-only error
/// cannot answer that without substring matching.
///
/// Locating the bad datum is the whole payload: `locus` + `subject` say
/// *which* stored value, `detail` says what reading it produced.
/// **Never the datum itself** — no raw bytes, no key material: a
/// consumer logs this, and the bytes of a corrupt hash column are of no
/// use to an operator who has to go and look at the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptChainEvidence {
    /// Which stored value class is unreadable — the stable alert field.
    pub locus: ChainEvidenceLocus,
    /// Which instance of it: the column name, or the stream the row sits
    /// on.
    pub subject: String,
    /// What reading it produced — a width, a decoder message. No raw
    /// bytes.
    pub detail: String,
}

impl CorruptChainEvidence {
    /// A convenience constructor for the three parts. Pure.
    pub fn new(
        locus: ChainEvidenceLocus,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            locus,
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for CorruptChainEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "corrupt event-chain evidence [{}] at {}: {}",
            self.locus, self.subject, self.detail
        )
    }
}

impl std::error::Error for CorruptChainEvidence {}

/// Why a live-chain snapshot did not happen.
///
/// The two variants are the two classes, and keeping them apart **in the
/// type** is the point: the consumer's correct response differs, and a
/// single message-carrying error made tamper evidence indistinguishable
/// from an outage.
#[derive(Debug, Clone)]
pub enum ChainSnapshotError {
    /// The snapshot could not be taken: the store was unreachable, a
    /// read transaction could not be opened or committed, a query
    /// failed. An operational failure **of this cycle** that a later
    /// cycle can still complete, so the consumer retries it.
    Unavailable(DomainError),
    /// The store answered, and what it holds cannot be read as chain
    /// evidence. Not an outage: re-reading the same bytes returns the
    /// same verdict, so a consumer must fail terminally rather than
    /// spend an attempt budget reaching the same end.
    CorruptEvidence(CorruptChainEvidence),
}

impl ChainSnapshotError {
    /// The transient half: an infrastructure step of the snapshot
    /// failed. Naming the class at every construction site is what keeps
    /// the classification a decision rather than a default — there is
    /// deliberately no `From<DomainError>`, so no `?` can classify a
    /// failure as retryable without saying so.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(DomainError::Invariant(message.into()))
    }

    /// The corrupt-evidence verdict, if this is one.
    ///
    /// `None` for every infrastructure failure — which is precisely the
    /// distinction a consumer must preserve, and the reason this travels
    /// as a typed payload rather than as text to match on (mirrors
    /// [`CasIntegrityFailure::from_io_error`](super::storage::CasIntegrityFailure::from_io_error)).
    pub fn corrupt_evidence(&self) -> Option<&CorruptChainEvidence> {
        match self {
            Self::Unavailable(_) => None,
            Self::CorruptEvidence(c) => Some(c),
        }
    }
}

impl fmt::Display for ChainSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "{e}"),
            Self::CorruptEvidence(c) => write!(f, "{c}"),
        }
    }
}

impl std::error::Error for ChainSnapshotError {}

impl From<CorruptChainEvidence> for ChainSnapshotError {
    fn from(c: CorruptChainEvidence) -> Self {
        Self::CorruptEvidence(c)
    }
}

/// Outbound port: snapshot the live chain heads for checkpoint emission.
///
/// Read-only and side-effect-free: the emitter never writes `events`
/// (the runtime DML DSN holds only `SELECT`/`INSERT`; this path only
/// `SELECT`s). `Err` is never a silently-skipped checkpoint; which of
/// the two [`ChainSnapshotError`] classes it carries decides whether the
/// consumer retries the cycle.
pub trait EventChainHeadReaderPort: Send + Sync {
    /// Snapshot every live stream's head + the consistent-cut
    /// `max_global_position` + the `StreamSealed` records past
    /// `anchored_retention_position`. A single consistent read (the id
    /// set is small — thousands of streams).
    ///
    /// `anchored_retention_position` is the audit-meta stream position an
    /// anchored checkpoint already covered, as
    /// `hort_domain::events::anchored_retention_position` derives it from
    /// the signed witness. `None` means no checkpoint has anchored that
    /// stream, so no seal is anchored yet and the whole seal history is
    /// returned; because the position is 0-based, `Some(0)` is a real
    /// boundary and an implementation must not collapse the two.
    fn snapshot_live_chain(
        &self,
        anchored_retention_position: Option<u64>,
    ) -> BoxFuture<'_, Result<LiveChainSnapshot, ChainSnapshotError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_chain_head_reader_port_is_dyn_compatible() {
        let _ = size_of::<&dyn EventChainHeadReaderPort>();
    }

    #[test]
    fn event_chain_head_reader_port_can_be_boxed() {
        let _: Option<Box<dyn EventChainHeadReaderPort>> = None;
    }

    fn corrupt(locus: ChainEvidenceLocus) -> CorruptChainEvidence {
        CorruptChainEvidence::new(locus, "event_hash", "16 bytes, expected 32")
    }

    #[test]
    fn every_locus_has_a_distinct_stable_wire_form() {
        // The log field an operator alerts on. Two loci sharing a string
        // would merge two conditions into one alert; a renamed string
        // breaks the alert silently.
        let all = [
            ChainEvidenceLocus::ChainHashColumn,
            ChainEvidenceLocus::AnchoredRetentionPosition,
            ChainEvidenceLocus::SealedRecordPayload,
            ChainEvidenceLocus::SealedRecordEventType,
        ];
        let names: Vec<&str> = all.iter().map(|l| l.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "chain_hash_column",
                "anchored_retention_position",
                "sealed_record_payload",
                "sealed_record_event_type",
            ]
        );
        for l in all {
            assert_eq!(l.to_string(), l.as_str());
        }
    }

    #[test]
    fn corrupt_evidence_locates_the_datum_in_its_display() {
        let c = corrupt(ChainEvidenceLocus::ChainHashColumn);
        assert_eq!(c.locus, ChainEvidenceLocus::ChainHashColumn);
        assert_eq!(c.subject, "event_hash");
        let shown = c.to_string();
        assert!(shown.contains("chain_hash_column"), "{shown}");
        assert!(shown.contains("event_hash"), "{shown}");
        assert!(shown.contains("16 bytes, expected 32"), "{shown}");
        assert_eq!(c.clone(), c);
        let _: &dyn std::error::Error = &c;
    }

    #[test]
    fn the_two_classes_are_distinguishable_without_reading_a_message() {
        // The defect this type exists to close: a consumer must be able
        // to tell corrupt stored evidence from an unreachable store
        // without substring-matching free text.
        let transient = ChainSnapshotError::unavailable("begin snapshot tx failed: closed");
        assert!(transient.corrupt_evidence().is_none());
        assert!(transient.to_string().contains("begin snapshot tx failed"));

        let evidence = corrupt(ChainEvidenceLocus::SealedRecordPayload);
        let corrupted: ChainSnapshotError = evidence.clone().into();
        assert_eq!(corrupted.corrupt_evidence(), Some(&evidence));
        assert_eq!(corrupted.to_string(), evidence.to_string());
        let _: &dyn std::error::Error = &corrupted;
        let _ = format!("{:?}", corrupted.clone());
    }

    #[test]
    fn live_chain_snapshot_new_and_traits() {
        let s = LiveChainSnapshot::new(vec![], 0, vec![]);
        assert_eq!(s.clone(), s);
        let _ = format!("{s:?}");
        assert!(s.heads.is_empty());
        assert_eq!(s.max_global_position, 0);
        assert!(s.sealed_since_previous.is_empty());
    }
}
