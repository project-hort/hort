# hort-adapters-checkpoint-anchor — Event-Chain Checkpoint Anchor Adapter

## Layer

Outbound adapter — takes an injected `Arc<dyn ObjectStore>` rather than
constructing its own client, and deliberately does not depend on
`hort-adapters-storage` or `hort-config`. No `hort-app` dependency (leaf
adapter over `hort-domain` + crypto + `object_store`). Requires >= 85%
coverage.

## Responsibility

Reads **and writes** externally-anchored, Ed25519-signed event-chain
checkpoints from a WORM/Object-Lock object-store prefix, feeding verified
`Checkpoint` values to the pure verify-event-chain core in `hort-domain`
(ADR 0002). Note: the crate's own `Cargo.toml` description calls this a
"read adapter", but the write path (`ObjectStoreCheckpointEmitter`) lives
in this same crate and shares one `SignedBody` struct with the reader as
the single source of truth — the one-line description is stale relative
to the code; treat this README, not the Cargo.toml description, as
authoritative on scope.

## Ports

- **Implements:** `CheckpointAnchorPort` (`ObjectStoreCheckpointAnchor`),
  `CheckpointEmitterPort` (`ObjectStoreCheckpointEmitter`).
- **Consumes:** none — leaf adapter.

## Key types

- `ObjectStoreCheckpointAnchor`, `ObjectStoreCheckpointEmitter`.
- `AnchorAdapterError`, `EmitterAdapterError`.
- `CHECKPOINT_PREFIX`.

## Rules

- No `reqwest::Client` is built anywhere in this crate — the injected
  `ObjectStore` handle is the only network path, so ADR 0010's
  builder-vs-`new()` rule doesn't apply here (there is no client to build).
