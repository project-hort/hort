//! Outbound port for reading externally-anchored, signed event-chain
//! checkpoints.
//!
//! **Pure boundary, zero I/O.** This module only *defines* the contract;
//! it performs no I/O, no `tracing`, no signature math. The S3
//! Object-Lock read adapter (`hort-adapters-checkpoint-anchor`) implements
//! it and is wired by the `hort-server` composition root; the
//! `verify-event-chain` subcommand consumes anchored checkpoints through
//! this trait and feeds them to the pure
//! [`verify_against_checkpoint`](crate::events::verify_against_checkpoint)
//! core.
//!
//! Per spec §6.1 the port is deliberately thin: the only operation the
//! verifier needs is "give me every signature-verified checkpoint from
//! the anchor store" — a *read*. Checkpoint *emission* (the S3
//! Object-Lock **write** adapter + the `eventstore-checkpoint`
//! `TaskHandler`, spec §6/§12) is a separate, not-yet-scheduled item; it
//! is NOT part of this port's v1 surface. With no emitter deployed the
//! store is legitimately empty and the verifier resolves the anchor
//! verdict to `missing_checkpoint` — a correct, spec-defined verdict
//! (§6.4(a)), not an error.
//!
//! `#[non_exhaustive]` is not needed on the trait (traits are extended
//! by adding methods with default impls); keeping the surface minimal
//! (one read method) matches spec §14 R5 — the transparency-log
//! alternative stays a drop-in adapter behind this same boundary.

use crate::error::DomainResult;
use crate::events::Checkpoint;

use super::BoxFuture;

/// Outbound port: read signature-verified, externally-anchored
/// checkpoints (spec §6.1/§6.2).
///
/// The adapter is responsible for the I/O the verifier core forbids:
/// listing the WORM-locked object-store prefix
/// (`<bucket>/hort-event-chain-checkpoints/…`), fetching each object,
/// deserializing the JSON to a [`Checkpoint`], and **verifying the
/// detached signature** against the operator-provisioned anchor public
/// key (spec §6.2 `signature`, §14 R2 — key is an operator-provisioned
/// file under the existing `HORT_*` posture). A checkpoint whose signature
/// does not verify MUST NOT be returned (a forged checkpoint is
/// indistinguishable from no checkpoint as far as the integrity
/// attestation is concerned — surfacing it would let an attacker who can
/// write the object store but not forge the key fabricate a passing
/// anchor verdict).
///
/// Returns the verified checkpoints in no particular order; the pure
/// core [`verify_against_checkpoint`](crate::events::verify_against_checkpoint)
/// selects the newest by `checkpoint_seq` and checks the sequence is
/// gap-free, so the adapter need not sort. An **empty `Vec`** is a
/// valid, expected result (no emitter deployed yet, or the cron never
/// ran) — the core maps it to
/// [`MissingReason::NoCheckpoint`](crate::events::MissingReason::NoCheckpoint).
/// `Err` is reserved for an *operational* failure (anchor store
/// unreachable, credentials rejected, a malformed object that is not
/// attributable to tampering) — the subcommand maps that to exit code 1
/// ("the verifier could not run"), distinct from a detected integrity
/// violation (exit 2) or a coverage gap (exit 3).
pub trait CheckpointAnchorPort: Send + Sync {
    /// Read and signature-verify every checkpoint in the anchor store.
    ///
    /// Read-only and side-effect-free: the verifier never writes the
    /// anchor store (spec §8.2 — "does not touch the anchor store for
    /// writes"). Verified-checkpoints-only contract: see the trait doc.
    fn read_all(&self) -> BoxFuture<'_, DomainResult<Vec<Checkpoint>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `CheckpointAnchorPort` is
    /// dyn-compatible (the composition root stores it as
    /// `Arc<dyn CheckpointAnchorPort>`). Runtime: `size_of` executes in
    /// the test body for coverage. Mirrors every other port's
    /// dyn-compat guard in this module.
    #[test]
    fn checkpoint_anchor_port_is_dyn_compatible() {
        let _ = size_of::<&dyn CheckpointAnchorPort>();
    }

    /// `Box<dyn CheckpointAnchorPort>` resolves — proves the trait can
    /// be type-erased into an owned trait object the way the `hort-server`
    /// composition root will store the S3 adapter.
    #[test]
    fn checkpoint_anchor_port_can_be_boxed() {
        let _: Option<Box<dyn CheckpointAnchorPort>> = None;
    }
}
