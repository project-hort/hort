//! Outbound port for **writing** an externally-anchored, signed
//! event-chain checkpoint (the external-anchor *emission* half of
//! tamper evidence).
//!
//! **Pure boundary, zero I/O.** This module only *defines* the
//! emission contract; it performs no I/O, no `tracing`, no signing.
//! The S3 Object-Lock **write** adapter
//! (`hort-adapters-checkpoint-anchor`, the same crate as the Item-3
//! *read* adapter so the `SignedBody` signature shape is a single
//! shared source of truth — the verifier↔emitter contract pin) implements
//! it; the `eventstore-checkpoint` `TaskHandler`
//! (`hort_app::task_handlers`) composes it with the live stream-head read.
//!
//! ## Why a *sibling* port, not a method on `CheckpointAnchorPort`
//!
//! `CheckpointAnchorPort` (the Item-3 *read* trait) is **shipped** and
//! its surface is byte-frozen (governance: no existing port signature
//! change without confirmation). Adding a `write`/`emit` method to it
//! would change every implementor's required surface. The capability
//! is therefore **additive**: a new, independent one-method port. The
//! verifier-side read path (`read_all`) stays exactly as shipped; the
//! transparency-log alternative (§14 R5) remains a drop-in behind both
//! thin boundaries.
//!
//! ## What the adapter does (the I/O this port forbids)
//!
//! Given the pure, builder-assembled
//! [`CheckpointToEmit`](crate::events::CheckpointToEmit) (the §6.2
//! body: Merkle root + sorted witness + monotonic seq + the §5
//! first-checkpoint `backfill_baseline`), the adapter:
//!
//! 1. wraps it in the **shared `SignedBody`** shape the Item-3 reader
//!    verifies (Ed25519 over `serde_json::to_vec(&SignedBody)`, exactly
//!    those fields — the contract pin),
//! 2. signs that with the **operator-provisioned** anchor signing key
//!    (spec §14 R2 — a file under the existing `HORT_*` posture, the
//!    private counterpart of the SPKI PEM the reader verifies;
//!    **distinct from any runtime credential**, never embedded /
//!    derived / generated-at-runtime; a missing/malformed key fails the
//!    task, never a silent unsigned checkpoint),
//! 3. writes `<bucket>/hort-event-chain-checkpoints/<RFC3339-utc>-<seq>.json`
//!    into the operator-provisioned **S3 Object-Lock** bucket (WORM —
//!    see the adapter's hardening note for the exact guarantee + the
//!    required bucket provisioning).
//!
//! `Err` is an *operational* failure for that emission cycle (sign
//! failure, anchor-store write failure) — the task records it and the
//! external CronJob retries on the next tick. It is **never** swallowed
//! into a silently-unsigned or skipped checkpoint.

use crate::error::DomainResult;
use crate::events::CheckpointToEmit;

use super::BoxFuture;

/// Outbound port: sign + WORM-anchor one assembled checkpoint
/// (spec §6/§9).
///
/// The adapter owns the verifier↔emitter signature contract: it MUST
/// sign exactly the bytes the shipped Item-3 reader verifies
/// (`serde_json::to_vec(&SignedBody)` over the shared `SignedBody`
/// fields) so a checkpoint this port emits round-trips to
/// `AnchorVerdict::Ok` through the existing read adapter. A divergence
/// makes every emitted checkpoint read as a signature failure ⇒ a
/// permanent `missing_checkpoint` verdict.
///
/// Read-only verification stays the separate, byte-unchanged
/// [`CheckpointAnchorPort`](super::checkpoint_anchor::CheckpointAnchorPort);
/// this port never reads or verifies — it only emits.
pub trait CheckpointEmitterPort: Send + Sync {
    /// Sign and anchor `checkpoint`. `Ok(())` ⇒ the signed object is
    /// durably written to the WORM store. `Err` ⇒ this emission cycle
    /// failed (sign or anchor-store write) — surfaced to the task layer
    /// (which maps it to the distinct `hort_event_chain_checkpoint_total`
    /// failure result + an `error!`); never a silently-skipped or
    /// unsigned checkpoint.
    fn emit<'a>(&'a self, checkpoint: &'a CheckpointToEmit) -> BoxFuture<'a, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CheckpointEmitterPort` is dyn-compatible (the composition root
    /// stores the S3 write adapter as `Arc<dyn CheckpointEmitterPort>`).
    /// Mirrors every other port's dyn-compat guard in this module,
    /// including the sibling `CheckpointAnchorPort`.
    #[test]
    fn checkpoint_emitter_port_is_dyn_compatible() {
        let _ = size_of::<&dyn CheckpointEmitterPort>();
    }

    /// `Box<dyn CheckpointEmitterPort>` resolves — proves the trait can
    /// be type-erased into an owned trait object the way the worker
    /// composition root will store the S3 write adapter.
    #[test]
    fn checkpoint_emitter_port_can_be_boxed() {
        let _: Option<Box<dyn CheckpointEmitterPort>> = None;
    }
}
