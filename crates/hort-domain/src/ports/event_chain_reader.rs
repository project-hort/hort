//! Outbound port for the offline event-chain **verifier's** reads.
//!
//! **Pure boundary, zero I/O.** This module only *defines* the read
//! contract the `hort-server verify-event-chain` subcommand needs to
//! recompute every stream's hash chain and cross-check the anchored
//! checkpoints: the set of stream ids to verify, each stream's rows from
//! genesis (carrying the stored chain columns), and every `StreamSealed`
//! record on the `StreamId::eventstore_retention()` audit-meta stream.
//!
//! ## Why a new sibling port (not `EventStore`, not raw `sqlx`)
//!
//! `EventStore::read_stream`/`read_category` return [`PersistedEvent`],
//! which by design does **not** carry the `prev_event_hash`/`event_hash`
//! chain columns the verifier's §7/§8.1 model needs to localize a tamper
//! to an exact `Broken { at_position }`. An earlier rule said
//! "reuse the existing read ports; do not widen the port" — but that is
//! not implementable through `PersistedEvent`. The correct
//! resolution: a dedicated,
//! additive read port — implemented by `PgEventChainReader` in
//! `hort-adapters-postgres` — exactly mirroring the emitter half's
//! [`EventChainHeadReaderPort`](super::event_chain_head_reader). This
//! keeps **all** `sqlx` in the Postgres adapter (the verifier no longer
//! issues raw `SELECT`s from the `hort-server` binary) and keeps the
//! verifier backend-agnostic: it depends on `Arc<dyn EventChainReaderPort>`,
//! so an EventStoreDB/KurrentDB backend implements the same port. The
//! `EventStore` trait is **neither used nor widened** (governance +
//! `feedback_no_port_contract_changes`: this is a *new* port, not a
//! widening of the well-designed `EventStore` trait).
//!
//! ## Read posture (adapter concern)
//!
//! `SELECT`-only on the **runtime DML DSN** (the `hort_app_role` equivalent
//! that holds only `SELECT`/`INSERT` on `events`) — never DDL, never a
//! write to `events`. Each method is bounded; per-stream reads page
//! internally so the verifier never buffers the whole table (spec §8.2).

use crate::error::DomainResult;
use crate::events::{ChainRow, SealedStreamRecord};

use super::BoxFuture;

/// Outbound port: the reads the offline chain verifier performs.
///
/// Read-only and side-effect-free. `Err` is an *operational* failure
/// (store unreachable, a row that does not deserialize) — the subcommand
/// maps it to exit code 1, distinct from a chain-break *verdict* (which
/// is a value the pure core returns, never an `Err`).
pub trait EventChainReaderPort: Send + Sync {
    /// The distinct stream ids to verify, ordered ascending.
    ///
    /// `since_global` is a **stream-selection** filter: `Some(n)` selects
    /// every stream with any activity at `global_position >= n`; `None`
    /// selects all streams. It never restricts which rows *within* a
    /// selected stream are read — [`read_stream_chain`] always reads from
    /// genesis (spec §8.2). The explicit `--stream` allow-list is applied
    /// by the caller before reaching the port (no DB read needed).
    ///
    /// [`read_stream_chain`]: EventChainReaderPort::read_stream_chain
    fn list_stream_ids(
        &self,
        since_global: Option<u64>,
    ) -> BoxFuture<'_, DomainResult<Vec<String>>>;

    /// One stream's rows ordered by `stream_position` ascending, from
    /// genesis, each carrying the stored `prev_event_hash`/`event_hash`
    /// chain columns. The adapter pages internally (bounded memory).
    fn read_stream_chain<'a>(
        &'a self,
        stream_id: &'a str,
    ) -> BoxFuture<'a, DomainResult<Vec<ChainRow>>>;

    /// Every `StreamSealed` record on the `StreamId::eventstore_retention()`
    /// audit-meta stream (ordered). Empty is valid and expected on a store
    /// where nothing has ever been sealed. Feeds the anchor cross-check
    /// (`verify_against_checkpoint`) so a sealed-then-removed stream
    /// resolves to `SealedGap`, not `Broken`.
    fn read_sealed_records(&self) -> BoxFuture<'_, DomainResult<Vec<SealedStreamRecord>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_chain_reader_port_is_dyn_compatible() {
        // Compile-time proof the trait is object-safe (used as
        // `Arc<dyn EventChainReaderPort>` in composition + the verifier).
        let _ = size_of::<&dyn EventChainReaderPort>();
        let _: Option<Box<dyn EventChainReaderPort>> = None;
    }
}
