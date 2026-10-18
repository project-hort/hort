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
- **The two positions carry different guarantees, and a consumer that
  needs completeness has to know which.** `stream_position` is 0-based
  and **gapless** within its `stream_id` — the store derives it as that
  stream's tail plus one inside the appending transaction, and a unique
  index on `(stream_id, stream_position)` holds it there — so a hole in
  it is a genuinely skipped event. `global_position` is a total order
  across streams but is **not** gapless and is **not** a completeness
  guarantee: it comes from a sequence, so a rolled-back append burns its
  number permanently, and the number is drawn at INSERT while the row
  becomes visible at COMMIT, so a cursor that is a bare high-water mark
  can step over a transaction that commits late. That is accepted
  behaviour, and it is detectable; the detectors are in
  [../explanation/event-notifications.md](../explanation/event-notifications.md#detecting-a-late-commit-skip).
- **Replay-safe.** Events are immutable and may be re-delivered after a
  projector restart; consumers must apply them idempotently.

## Retention events

Both events land on the **artifact** stream — wire-form id
`artifact-{uuid}`, where `{uuid}` is the artifact id
(`StreamCategory::Artifact`). They are the two-stage retention split:
`ArtifactExpired` records the policy decision; `ArtifactPurged`
terminates that work item once storage has been reconciled. Source:
`crates/hort-domain/src/events/artifact_events.rs`.

`ArtifactPurged` also terminates an `ArtifactDeleted` (see
[Deletion](#deletion) below): one storage-GC sweep releases the bytes of
every retired artifact, whether a policy or a caller retired it.

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
already absent, terminating a byte-release work item — an
`ArtifactExpired` or an `ArtifactDeleted`. Re-emitting
on an already-absent blob is **correct, not an error** (idempotent — §6
invariant 4): re-applying to an already-purged artifact is a no-op that
does not corrupt projected state.

| Field | Type | Meaning |
|---|---|---|
| `artifact_id` | `Uuid` | The artifact whose reference was removed; equals the artifact stream's `entity_id`. |
| `content_hash` | `ContentHash` | CAS content hash whose reference this purge removed (64 lowercase hex chars by construction). |
| `refs_remaining` | `u32` | **Claims on `content_hash`** observed under the hash-scoped blob-reclamation lock immediately before the storage decision — not the count the sweep's preparation transaction recorded earlier, which a re-reference landing in between corrects here. `0` ⇒ the blob itself was deleted; `> 0` ⇒ something still holds those bytes and only this artifact's reference is gone. A claim is either a cross-`kind` `content_references` row still targeting the hash, or — when there is no such row — a non-deleted artifact in a GC-protected quarantine state (`quarantined` / `rejected` / `scan_indeterminate`) whose primary content or metadata blob is this hash. The second kind exists because retained scan evidence deliberately carries no reference edge (the refcount repair mints none for it) while CAS shares its bytes with every artifact of the same content: a row count alone would read `0` for bytes that are being kept, and `0` has to mean "deleted" on every path that emits this field. |
| `purged_at` | `DateTime<Utc>` | Wall-clock at which the purge (or already-absent confirmation) completed. Distinct from the event store's `stored_at`. |

**Consumer contract.** A consumer reconstructing retention state keys on
`(artifact_id)` within the `artifact-{uuid}` stream: an `ArtifactExpired`
— or an `ArtifactDeleted` — is "pending purge" until a subsequent
`ArtifactPurged` on the same
stream terminates it. Because `ArtifactPurged` is idempotent, a consumer
that sees it more than once (replay, or a retried already-absent purge)
must treat the second and later occurrences as no-ops. `refs_remaining`
is observational — it tells a consumer whether the underlying blob
survived, not whether this artifact's purge succeeded
(it always did, by the time the event is emitted). A consumer may read
`refs_remaining > 0` as "the bytes are still there" but not as "some
other artifact serves them": a protected claimant is quarantined
evidence, which no read path serves.

**Byte reclamation does not gate this event's meaning.** An artifact is
externally gone once `ArtifactPurged` is on its stream; the bytes behind
it are reclaimed by a best-effort sweep that declines to act whenever it
cannot prove, under the blob lock, that nothing claims them. A blob
whose reclamation was deferred keeps its durable worklist row and is
retried by the next run, so `refs_remaining` is a statement about what
the sweep observed, never a promise about disk.

## Deletion

### `ArtifactDeleted`

Emitted when an artifact is deleted from its repository — today reachable
through the OCI manifest `DELETE` by digest. Lands on the **artifact**
stream (`artifact-{uuid}`, `StreamCategory::Artifact`), so a replay of
that stream terminates here and never reconstructs a deleted artifact as
live. Attribution (who deleted it) and record time ride the persisted-event
envelope's `actor` / `stored_at`, not the payload. Source:
`crates/hort-domain/src/events/artifact_events.rs`.

Deletion is a **soft delete**: the `artifacts` projection row is retained
with `deleted_at` set, and the CAS blob is untouched *at this transition*
— blob lifetime stays refcount-gated GC, because another artifact may
reference the same bytes.
A deleted artifact is excluded from every live read, and its path is
released: the `(repository_id, path)` unique index is predicated on
`deleted_at IS NULL`, so a later ingest at the same path mints a **new**
artifact with a new id and its own stream rather than resurrecting this
one.

`ArtifactDeleted` is **also the byte-release work item** that makes that
refcount-gated GC fire. The storage-GC sweep enumerates every artifact
stream carrying an `ArtifactExpired` *or* an `ArtifactDeleted` with no
following `ArtifactPurged`; the sweep — not the delete — removes the
artifact's `content_references` source edges and deletes the blob once
its cross-kind refcount reaches zero. The event is emitted in the same
transaction as `deleted_at`, so the work item is exactly as durable as
the retirement it authorises. A caller-deleted artifact whose bytes were
also GC-eligible therefore acquires an `ArtifactPurged` on a later sweep;
byte release is asynchronous by design, bounded by the sweep interval.

Deletion is orthogonal to the quarantine axis. The event does not change
`quarantine_status`, and there is no `Deleted` status value: a `Released`
artifact and a `Rejected` one are both deletable, and the pre-deletion
status is exactly what an audit reader needs preserved.

| Field | Type | Meaning |
|---|---|---|
| `artifact_id` | `Uuid` | The deleted artifact; equals the artifact stream's `entity_id`. |
| `repository_id` | `Uuid` | Repository the artifact was deleted from. Denormalised so an audit query ("everything deleted from repository R") never has to join a projection row that is itself deletable. |
| `path` | `String` | Repository-relative path the artifact occupied. Free for re-ingest after this event. |
| `content_hash` | `ContentHash` | CAS content hash the artifact pointed at (64 lowercase hex chars by construction), so its content identity survives independently of the projection row. |

**Consumer contract.** `ArtifactDeleted` is terminal for the artifact on
the operator/registry-API axis: at most one appears per stream, and no
further **catalog**-lifecycle event follows it (the retention events above
are a separate axis — they decide the blob's fate, not the catalog's, and
may still appear on the stream afterwards). A consumer projecting a live
catalog removes the artifact on this event and must not reinstate it — a later
artifact at the same `path` arrives under a *different* `artifact_id` and
a different stream. It is not itself a purge *confirmation*:
`content_hash` may still be referenced by other artifacts, and whether
the blob was actually removed is reported only by the `ArtifactPurged`
that later terminates this work item (`refs_remaining = 0` ⇒ the bytes
are gone).
