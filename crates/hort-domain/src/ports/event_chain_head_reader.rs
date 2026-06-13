//! Outbound port for snapshotting the live event-chain heads
//! (the external-anchor *emission* half of tamper evidence).
//!
//! **Pure boundary, zero I/O.** This module only *defines* the read
//! contract the `eventstore-checkpoint` `TaskHandler` needs to assemble
//! a §6.2 checkpoint: every live stream's
//! `(stream_id, final_stream_position, head_event_hash)` plus the
//! consistent-cut `max_global_position`, and the `StreamSealed` records
//! on the `StreamId::eventstore_retention()` audit-meta stream (the
//! derived `admin-<v5-uuid>` id; B8 decision a2) since the previous
//! checkpoint.
//!
//! ## Why a new sibling port (not `EventStore`)
//!
//! `EventStore::read_stream`/`read_category` return `PersistedEvent`,
//! which by design does **not** carry the `prev_event_hash`/`event_hash`
//! chain columns (spec §8.2 / §14 R4 — "reuse the existing read ports;
//! do **not** widen the port"). The checkpoint emitter needs the head
//! `event_hash` per stream, which `PersistedEvent` cannot express.
//! Widening `EventStore` is explicitly forbidden (governance + §14 R4).
//! This is therefore an **additive sibling port**, exactly mirroring the
//! Item-3 verifier's own decision to issue its bounded chain-column
//! `SELECT` rather than widen `EventStore`
//! (`crates/hort-server/src/cli/verify_event_chain.rs` doc). The adapter
//! reuses the *same* runtime-DML-DSN bounded read shape
//! (`list_stream_ids` / per-stream head row) — `SELECT`-only on the
//! runtime pool, never DDL, never a write to `events`.
//!
//! The trait is intentionally minimal (one snapshot op); the read posture
//! (runtime DML DSN, `SELECT` only) is an adapter concern documented on
//! the implementation.

use crate::error::DomainResult;
use crate::events::{SealedStreamRecord, StreamHead};

use super::BoxFuture;

/// A consistent-cut snapshot of the live event store, sufficient to
/// assemble a spec §6.2 checkpoint. Pure data — the adapter populates
/// it from a bounded runtime-DSN `SELECT`; this type does no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveChainSnapshot {
    /// Every live stream's head: `(stream_id, final_stream_position,
    /// head_event_hash)`. Order is unspecified — the pure builder sorts
    /// by `stream_id` for the Merkle root + witness.
    pub heads: Vec<StreamHead>,
    /// The max `events.global_position` the snapshot covers — the
    /// consistent-cut marker (spec §6.2; §13 divergence 6 — a *marker*,
    /// not a chain link). `0` when the table is empty.
    pub max_global_position: u64,
    /// `StreamSealed` records read from the never-deleted
    /// `StreamId::eventstore_retention()` audit-meta stream (the derived
    /// `admin-<v5-uuid>` id) since the previous
    /// checkpoint. **Empty is valid and
    /// expected** when nothing has been sealed since the previous
    /// checkpoint — the emitter handles an empty set cleanly (spec §6.3
    /// / backlog Item-3b acceptance).
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

/// Outbound port: snapshot the live chain heads for checkpoint emission
/// (spec §6.2/§9).
///
/// Read-only and side-effect-free: the emitter never writes `events`
/// (spec §8.2 read posture — the runtime DML DSN holds only
/// `SELECT`/`INSERT`; this path only `SELECT`s). `Err` is an
/// *operational* failure for this emission cycle (DB unreachable) — the
/// task maps it to a `Failed { retry: true }` outcome, never a
/// silently-skipped checkpoint.
pub trait EventChainHeadReaderPort: Send + Sync {
    /// Snapshot every live stream's head + the consistent-cut
    /// `max_global_position` + the `StreamSealed` records since the
    /// previous checkpoint. A single consistent read (the id set is
    /// small — thousands of streams, spec §6.2).
    fn snapshot_live_chain(&self) -> BoxFuture<'_, DomainResult<LiveChainSnapshot>>;
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
