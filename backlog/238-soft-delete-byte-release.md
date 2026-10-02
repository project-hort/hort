# 238 — A soft delete never releases the content reference

**Issue:** #295 · **Branch:** `agent/295-soft-delete-byte-release`
**Governing decisions:** ADR 0003 (CAS) · ADR 0054 (CAS-shared bytes: rows are
not bytes) · ADR 0007 (Invariant 1 — protected artifacts stay uncollectable) ·
#284 (the `deleted_at` exclusion in the candidate reader) · #286 (the atomic
binding of terminal event and projection retirement — the shape to mirror).

## The finding

`ArtifactUseCase::delete` is an event-sourced soft delete. The adapter
(`crates/hort-adapters-postgres/src/artifact_repo.rs`, `fn delete`) does
exactly three things in one transaction: read the row, `append_in_tx` an
`ArtifactDeleted`, and

```sql
UPDATE artifacts SET deleted_at = $2, updated_at = $2
 WHERE id = $1 AND deleted_at IS NULL
```

**The `content_references` source edge is left standing.** The use case's own
doc comment states the intent:

> The CAS blob is untouched: blob lifetime stays **refcount-gated GC**, because
> another artifact may reference the same bytes.

The intent is right and the mechanism never fires: while the source edge
stands, the refcount does not fall, so the refcount-gated collector never sees
the blob. The bytes of a user-deleted artifact have **no release path at all** —
no predicate reaches them, no policy selects them, no configuration changes it.

Compare the rejection path, which does the opposite: `quarantine_use_case.rs`
deletes the `content_references` on reject and logs a failure explicitly
(*"refcount row not deleted"*).

## The part that is simpler than it looks — check it first

It is tempting to read this as a conflict with #284: the candidate reader now
excludes `deleted_at IS NOT NULL`, so retention can no longer see these rows.
**That exclusion is not in the way.** It lives in the *candidate reader*, which
decides what to **expire**. The purge — which decides what to **collect** —
reads `list_pending_purge` (`crates/hort-adapters-postgres/src/purge_gc.rs`),
and that query filters on:

- an `ArtifactExpired` exists on the artifact's stream,
- no `ArtifactPurged` does,
- the status is not GC-protected.

**It does not filter `deleted_at`.** So a soft-deleted artifact that carries a
work item the purge understands is already collectable by the machinery as it
stands, and `complete_artifact_purge`'s `deleted_at` write is already
`COALESCE`-idempotent (#286), so a second write over an existing timestamp is a
no-op.

Verify this for yourself before designing around it — if it holds, the question
narrows sharply.

## The question this item must answer

**What work item does a user delete produce, and is `ArtifactExpired` the right
carrier?**

Reusing it means the whole purge path — edge deletion, the persisted hash
worklist, cross-kind refcounting, `StoragePort::delete` at count zero, the
terminal `ArtifactPurged` — works unchanged. But `ArtifactExpired` carries an
`ExpirationReason`, which is retention vocabulary: a deletion did not *expire*.
Adding a reason variant for it makes the event say something slightly untrue in
exchange for reusing everything.

The alternatives are a distinct work-item event the purge also accepts, or
releasing the edges inside the delete transaction and leaving the blob to a
collector that would then have to exist. Each has a cost; name them and argue
the choice. **Do not add a second collector** without establishing that the
existing one genuinely cannot serve — one purge path is the reason #286's
invariants hold at all.

Whatever the carrier, the write belongs in the **same transaction** as
`deleted_at` and `ArtifactDeleted`, mirroring #286: a deletion that is durable
while its byte-release work item is not is the same class of defect #286 closed.

## Also to settle

**The recovery path.** #281 D1 already requires that after a purge, a re-ingest
of the same content makes the artifact whole again — the ingest dedup is keyed
on `(hash, path)` and the blob write sits behind it, so a re-push can skip the
write and leave the row alive with its bytes gone. Whether that trap closes on
this path too is to be **tested, not assumed**.

## Read first

- `crates/hort-app/src/use_cases/artifact_use_case.rs` — `delete`, and its doc
  comment's claim about refcount-gated GC.
- `crates/hort-adapters-postgres/src/artifact_repo.rs` — `fn delete`.
- `crates/hort-app/src/use_cases/purge_use_case.rs` — the module doc's GC
  algorithm, and `process_expired`.
- `crates/hort-adapters-postgres/src/purge_gc.rs` — `list_pending_purge`,
  `complete_artifact_purge`, the worklist.
- `crates/hort-app/src/use_cases/quarantine_use_case.rs` — the reject path's
  edge deletion, as the precedent for doing this correctly.
- `crates/hort-domain/src/retention/reason.rs` — `ExpirationReason`, if you
  consider extending it.

## Acceptance

- After a soft delete, the content's refcount falls by the deleted artifact's
  edge.
- If that was the last reference, the blob is collected through a named,
  tested path — and the choice of path is argued, not improvised.
- If another artifact references the same bytes, the blob is untouched. A test
  with two artifacts over one content.
- The `deleted_at` exclusion in the candidate reader keeps its effect: a
  retired row acquires no `ArtifactExpired` through the *retention* path.
- A GC-protected artifact that is soft-deleted is still not collected
  (Invariant 1 does not bend here).
- Purge → re-push of the same content serves bytes again, with a test that
  walks exactly that sequence.
- Gate green, `#[serial(hort_pg_db)]` on every test that acquires a connection.

## Explicitly not in this item

No change to what the retention candidate reader enumerates. No relaxation of
Invariant 1. No new CLI or HTTP surface.
