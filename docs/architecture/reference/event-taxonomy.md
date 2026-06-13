# Public event taxonomy

Information-oriented catalog of the domain events that external consumers
may subscribe to, kept in lockstep with `crates/hort-domain/src/events/`.

> **Scope.** This page is **not** the full event vocabulary — the
> complete set lives in `crates/hort-domain/src/events/` and is summarised
> conceptually in [../explanation/domain-model.md](../explanation/domain-model.md)
> ("Events — overview") and [../explanation/event-sourcing.md](../explanation/event-sourcing.md).
> A name is listed here only once an external consumer is expected to
> subscribe to it and its payload + stream + stability contract are
> being committed to. Retention is the first
> subsystem to require that commitment — `ArtifactPurged` must be
> documented here before any
> external consumer subscribes to artifact-lifecycle streams. Other
> events graduate onto this page as their consumer contracts are
> committed; absence here means "no external-consumer contract yet",
> not "no such event".

## Stability contract

For every event on this page:

- **Payload fields are append-only.** New optional fields may be added;
  existing fields are never removed or repurposed within a major
  version. The event enum is `#[non_exhaustive]`, so consumers must
  tolerate unknown variants.
- **`stored_at` is the event-store record time; the in-payload
  timestamp is the decision time.** They are deliberately distinct (see
  per-event notes). Consumers ordering by causality use the per-stream
  `stream_position` / cross-stream `global_position`, not wall-clock.
- **Replay-safe.** Events are immutable and may be re-delivered after a
  projector restart; consumers must apply them idempotently.

## Retention events

Both events land on the **artifact** stream — wire-form id
`artifact-{uuid}`, where `{uuid}` is the artifact id
(`StreamCategory::Artifact`). They are the two-stage retention split:
`ArtifactExpired` records the policy decision; `ArtifactPurged`
terminates that work item once storage has been reconciled. Source:
`crates/hort-domain/src/events/artifact_events.rs`.

### `ArtifactExpired`

Emitted when a retention policy predicate matches an artifact and marks
it eligible for purge. Recorded **before** any storage deletion so the
policy decision is auditable independently of purge success. An
`ArtifactExpired` with no following `ArtifactPurged` on the same stream
is the pending-purge work item the GC walk consumes.

| Field | Type | Meaning |
|---|---|---|
| `artifact_id` | `Uuid` | The artifact this expiry applies to; equals the artifact stream's `entity_id`. |
| `policy_id` | `Uuid` | Retention policy whose predicate matched (foreign key into the CRUD retention-policy store). |
| `policy_name` | `String` | Policy name denormalised at decision time — the policy row may be archived or renamed before an auditor reads this event. |
| `reason` | `ExpirationReason` | Discriminated reason the policy marked the artifact eligible, snapshotting the inputs that drove the decision (incl. the security-finding snapshot for security-driven expiry). |
| `eligible_at` | `DateTime<Utc>` | Policy-evaluation wall-clock — when the artifact *became* eligible. Distinct from the event store's `stored_at` (when the audit log recorded it). |

### `ArtifactPurged`

Emitted when the storage delete completes, or the blob is confirmed
already absent, terminating an `ArtifactExpired` work item. Re-emitting
on an already-absent blob is **correct, not an error** (idempotent — §6
invariant 4): re-applying to an already-purged artifact is a no-op that
does not corrupt projected state.

| Field | Type | Meaning |
|---|---|---|
| `artifact_id` | `Uuid` | The artifact whose reference was removed; equals the artifact stream's `entity_id`. |
| `content_hash` | `ContentHash` | CAS content hash whose reference this purge removed (64 lowercase hex chars by construction). |
| `refs_remaining` | `u32` | Cross-`kind` `content_references` count for `content_hash` **after** this artifact's reference was removed. `0` ⇒ the blob itself was deleted; `> 0` ⇒ a still-live reference keeps the blob and only this artifact's reference is gone. |
| `purged_at` | `DateTime<Utc>` | Wall-clock at which the purge (or already-absent confirmation) completed. Distinct from the event store's `stored_at`. |

**Consumer contract.** A consumer reconstructing retention state keys on
`(artifact_id)` within the `artifact-{uuid}` stream: an `ArtifactExpired`
is "pending purge" until a subsequent `ArtifactPurged` on the same
stream terminates it. Because `ArtifactPurged` is idempotent, a consumer
that sees it more than once (replay, or a retried already-absent purge)
must treat the second and later occurrences as no-ops. `refs_remaining`
is observational — it tells a consumer whether the underlying blob
survived deduplication, not whether this artifact's purge succeeded
(it always did, by the time the event is emitted).
