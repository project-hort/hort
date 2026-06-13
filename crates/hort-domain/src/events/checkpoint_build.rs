//! Pure checkpoint-assembly core — the external-anchor *emission* half
//! of the event-chain tamper-evidence design (ADR 0002).
//!
//! Zero-I/O, zero-`tracing` `hort-domain` logic that turns a consistent
//! cut of the live event store into the spec §6.2 signed-checkpoint
//! *body shape*: the `stream_id`-sorted flat witness list
//! `(stream_id, final_stream_position, head_event_hash)`, the next
//! monotonic `checkpoint_seq`, and the §5 `backfill_baseline`
//! first-checkpoint honesty caveat.
//!
//! **What the v1 signature covers (precisely).** The shipped v1
//! `SignedBody` (`hort-evchain/v1`) signs the **flat sorted
//! `stream_heads` witness list directly** — there is **no signed Merkle
//! root in v1** and **the reader does not recompute one**. Binding the
//! full sorted witness list is at least as strong as signing a Merkle
//! root over the same tuples (the root is just a hash of a hash of the
//! list) and has no Merkle-malleability surface since no tree is
//! ever materialised on the verification path. Tightening the contract
//! to a signed Merkle root would be a coordinated reader+emitter
//! `SignedBody` bump (a future `hort-evchain/v2`-style change) — a
//! forward decision, recorded here so the residual is explicit (same
//! framing as the `backfill_baseline`/`max_global_position` advisory
//! note in `hort-adapters-checkpoint-anchor`).
//!
//! This module does **not** sign, serialize to the wire JSON, or write
//! to the anchor store — that I/O lives in the
//! `hort-adapters-checkpoint-anchor` write path (which owns the single
//! shared `SignedBody` shape, the verifier↔emitter contract pin). This
//! module only computes the *pure* parts so they are exhaustively
//! unit-testable at the `hort-domain` 100%-coverage tier (CLAUDE.md Test
//! Coverage Tiers): the witness sorting, the seq derivation, and the
//! backfill-baseline first-only rule.
//!
//! Reuses the Item-2 [`Checkpoint`](super::Checkpoint) /
//! [`EventHash`](super::EventHash) / [`SealedStreamRecord`](super::SealedStreamRecord)
//! types — no parallel struct that could drift.

use super::{Checkpoint, EventHash, SealedStreamRecord};

/// One live stream's head, as the emitter snapshots it from the runtime
/// `events` table (the §6.2 leaf tuple). Pure data — the adapter builds
/// these from a `SELECT`; this module never does I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHead {
    /// Wire-form stream id, exactly as persisted in `events.stream_id`.
    pub stream_id: String,
    /// The stream's final (head) `stream_position` — 0-based.
    pub final_stream_position: u64,
    /// The stream's chain head `event_hash` (32 bytes).
    pub head_event_hash: EventHash,
}

/// The §5 backfill-baseline honesty caveat, set **only** on the first
/// post-migration checkpoint. Carries the proof that "tamper-evident
/// from `<migration_timestamp>`" is honest: the max `global_position`
/// the in-migration backfill covered and the migration timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillBaseline {
    /// The max `events.global_position` the in-migration backfill
    /// chained at trust-on-migrate (spec §5).
    pub baseline_max_global_position: u64,
    /// The migration timestamp — the boundary the compliance wording
    /// ("tamper-evident from `<this>`") refers to.
    pub migration_timestamp: chrono::DateTime<chrono::Utc>,
}

/// The fully-assembled, *not-yet-signed* checkpoint the emitter will
/// sign + anchor (spec §6.2). The pure builder produces this; the
/// adapter wraps it into the shared `SignedBody`, signs, and writes.
///
/// The v1 `SignedBody` (`hort-evchain/v1`) signs the **flat sorted
/// `stream_heads` witness list directly** — there is no intermediate
/// Merkle root field here or in the wire type. The adapter constructs
/// `SignedBody` from `stream_heads` (already sorted by the builder) and
/// signs exactly those bytes. See the module doc for the forward-decision
/// note on a future signed-root bump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointToEmit {
    /// `"hort-evchain/v1"` (selects the canonicalizer, §3.3).
    pub chain_format_version: String,
    /// Monotonic, gap-free sequence (next = prev max + 1, §6.4).
    pub checkpoint_seq: u64,
    /// Store-supplied emit time (RFC3339 UTC on the wire).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The `global_position` this checkpoint covers up to — a
    /// consistent cut marker (§6.2; §13 divergence 6: a *marker*, not
    /// a chain link).
    pub max_global_position: u64,
    /// The flat, `stream_id`-sorted witness list — the v1 signature
    /// covers these entries directly (no Merkle root intermediary;
    /// see module doc).
    pub stream_heads: Vec<StreamHead>,
    /// `StreamSealed` records covered since the previous checkpoint
    /// (may be empty when no stream was sealed since the previous
    /// checkpoint — valid).
    pub sealed_streams: Vec<SealedStreamRecord>,
    /// The §5 honesty caveat — `Some` **only** on the first
    /// post-migration checkpoint.
    pub backfill_baseline: Option<BackfillBaseline>,
}

/// Return the witness list sorted by `stream_id` (the on-wire order
/// §6.2 mandates so the v1 reader reconstructs the same sorted sequence
/// the emitter signed).
pub fn sorted_witness(heads: &[StreamHead]) -> Vec<StreamHead> {
    let mut v = heads.to_vec();
    v.sort_by(|a, b| a.stream_id.cmp(&b.stream_id));
    v
}

/// Derive the next monotonic `checkpoint_seq` from the checkpoints
/// already in the anchor store (spec §6.4 — gap-free; the reader treats
/// a gap as `missing_checkpoint`). First checkpoint is seq `1`;
/// otherwise `max(existing) + 1`. Pure.
pub fn next_checkpoint_seq(existing: &[Checkpoint]) -> u64 {
    existing
        .iter()
        .map(|c| c.checkpoint_seq)
        .max()
        .map_or(1, |m| m + 1)
}

/// `true` iff this is the first post-migration checkpoint — i.e. the
/// anchor store has no prior checkpoint (spec §5: "Determine 'is this
/// the first checkpoint' deterministically — no prior `checkpoint_seq`
/// in the anchor store"). The §5 `backfill_baseline` is attached
/// **only** when this is `true`.
pub fn is_first_checkpoint(existing: &[Checkpoint]) -> bool {
    existing.is_empty()
}

/// Assemble the pure §6.2 checkpoint body from a consistent cut.
///
/// * `existing` — every checkpoint already in the anchor store (drives
///   `checkpoint_seq` monotonicity + the first-checkpoint test).
/// * `heads` — the live `(stream_id, final_position, head_hash)` set.
/// * `sealed` — `StreamSealed` records since the previous checkpoint
///   (may be empty when no stream was sealed since the previous
///   checkpoint — valid).
/// * `max_global_position` — the consistent-cut marker.
/// * `created_at` — store-supplied emit time.
/// * `backfill` — the §5 caveat; attached **only** on the first
///   checkpoint. Passing `Some` on a non-first checkpoint is ignored
///   (the §5 rule is "first post-migration checkpoint **only**"); the
///   caller is expected to gate this, and the builder enforces it
///   defensively so a mis-wired caller cannot stamp every checkpoint
///   with a baseline (which would corrupt the honesty semantics).
///
/// Pure. The returned `stream_heads` are already sorted by `stream_id`
/// (the order the v1 `SignedBody` signs directly).
#[allow(clippy::too_many_arguments)]
pub fn build_checkpoint(
    chain_format_version: &str,
    existing: &[Checkpoint],
    heads: &[StreamHead],
    sealed: &[SealedStreamRecord],
    max_global_position: u64,
    created_at: chrono::DateTime<chrono::Utc>,
    backfill: Option<BackfillBaseline>,
) -> CheckpointToEmit {
    let witness = sorted_witness(heads);
    let first = is_first_checkpoint(existing);
    CheckpointToEmit {
        chain_format_version: chain_format_version.to_string(),
        checkpoint_seq: next_checkpoint_seq(existing),
        created_at,
        max_global_position,
        stream_heads: witness,
        sealed_streams: sealed.to_vec(),
        // §5: backfill_baseline is set ONLY on the first post-migration
        // checkpoint. Defensive: drop it on any non-first checkpoint
        // even if the caller passed Some.
        backfill_baseline: if first { backfill } else { None },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn head(id: &str, pos: u64, b: u8) -> StreamHead {
        StreamHead {
            stream_id: id.to_string(),
            final_stream_position: pos,
            head_event_hash: EventHash([b; 32]),
        }
    }

    fn cp(seq: u64) -> Checkpoint {
        Checkpoint {
            chain_format_version: "hort-evchain/v1".into(),
            checkpoint_seq: seq,
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            stream_heads: vec![],
            sealed_streams: vec![],
        }
    }

    // ---- sorted_witness -------------------------------------------------

    #[test]
    fn witness_is_sorted_by_stream_id() {
        let w = sorted_witness(&[head("z", 0, 1), head("a", 0, 2), head("m", 0, 3)]);
        let ids: Vec<&str> = w.iter().map(|h| h.stream_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "m", "z"]);
    }

    #[test]
    fn witness_empty_in_empty_out() {
        assert!(sorted_witness(&[]).is_empty());
    }

    // ---- next_checkpoint_seq / is_first_checkpoint ----------------------

    #[test]
    fn first_seq_is_one_when_no_existing() {
        assert_eq!(next_checkpoint_seq(&[]), 1);
        assert!(is_first_checkpoint(&[]));
    }

    #[test]
    fn next_seq_is_max_plus_one() {
        let ex = vec![cp(1), cp(3), cp(2)];
        assert_eq!(next_checkpoint_seq(&ex), 4);
        assert!(!is_first_checkpoint(&ex));
    }

    #[test]
    fn next_seq_strictly_increments_across_repeated_builds() {
        let mut ex: Vec<Checkpoint> = vec![];
        let mut last = 0;
        for _ in 0..5 {
            let s = next_checkpoint_seq(&ex);
            assert_eq!(s, last + 1, "seq must strictly increment by 1");
            last = s;
            ex.push(cp(s));
        }
    }

    // ---- build_checkpoint ----------------------------------------------

    fn baseline() -> BackfillBaseline {
        BackfillBaseline {
            baseline_max_global_position: 4242,
            migration_timestamp: Utc.timestamp_opt(1_699_000_000, 0).unwrap(),
        }
    }

    #[test]
    fn build_first_checkpoint_carries_backfill_baseline_and_seq_1() {
        let now = Utc.timestamp_opt(1_700_000_500, 0).unwrap();
        let c = build_checkpoint(
            "hort-evchain/v1",
            &[],
            &[head("admin-a", 2, 9)],
            &[],
            777,
            now,
            Some(baseline()),
        );
        assert_eq!(c.checkpoint_seq, 1);
        assert_eq!(c.chain_format_version, "hort-evchain/v1");
        assert_eq!(c.max_global_position, 777);
        assert_eq!(c.created_at, now);
        assert_eq!(c.backfill_baseline, Some(baseline()));
        // The v1 SignedBody signs the flat sorted witness list directly.
        assert_eq!(c.stream_heads.len(), 1);
    }

    #[test]
    fn build_second_checkpoint_has_no_backfill_baseline_even_if_passed() {
        // §5 enforcement: a mis-wired caller passing Some on a non-first
        // checkpoint must NOT stamp a baseline (honesty-semantics guard).
        let now = Utc.timestamp_opt(1_700_001_000, 0).unwrap();
        let c = build_checkpoint(
            "hort-evchain/v1",
            &[cp(1)],
            &[head("admin-a", 3, 9)],
            &[],
            900,
            now,
            Some(baseline()),
        );
        assert_eq!(c.checkpoint_seq, 2);
        assert_eq!(
            c.backfill_baseline, None,
            "backfill_baseline is first-checkpoint-only (§5)"
        );
    }

    #[test]
    fn build_first_checkpoint_without_baseline_is_none() {
        let now = Utc.timestamp_opt(1_700_000_500, 0).unwrap();
        let c = build_checkpoint("hort-evchain/v1", &[], &[], &[], 0, now, None);
        assert_eq!(c.checkpoint_seq, 1);
        assert_eq!(c.backfill_baseline, None);
        assert!(c.stream_heads.is_empty());
    }

    #[test]
    fn build_checkpoint_sorts_witness_and_carries_sealed() {
        let now = Utc.timestamp_opt(1_700_000_500, 0).unwrap();
        let sealed = vec![SealedStreamRecord {
            sealed_stream_id: "admin-gone".into(),
            final_event_hash: EventHash([0xcd; 32]),
        }];
        let c = build_checkpoint(
            "hort-evchain/v1",
            &[cp(7)],
            &[head("z", 0, 1), head("a", 0, 2)],
            &sealed,
            10,
            now,
            None,
        );
        assert_eq!(c.checkpoint_seq, 8);
        let ids: Vec<&str> = c
            .stream_heads
            .iter()
            .map(|h| h.stream_id.as_str())
            .collect();
        assert_eq!(ids, vec!["a", "z"], "witness must be stream_id-sorted");
        assert_eq!(c.sealed_streams, sealed);
    }

    #[test]
    fn stream_head_and_backfill_traits() {
        let h = head("s", 1, 2);
        assert_eq!(h.clone(), h);
        let _ = format!("{h:?}");
        let b = baseline();
        assert_eq!(b.clone(), b);
        let _ = format!("{b:?}");
        let c = build_checkpoint("hort-evchain/v1", &[], &[], &[], 0, Utc::now(), None);
        let _ = format!("{c:?}");
        assert_eq!(c.clone(), c);
    }
}
