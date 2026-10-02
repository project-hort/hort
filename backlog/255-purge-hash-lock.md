# 255 — The purge locks the artifact; the blob is what it destroys

**Issue:** #320 · **Branch:** `agent/320-purge-hash-lock`
**Governing decisions:** ADR 0003 (enforced CAS, `put(stream) → ContentHash`) ·
ADR 0020 (eventstore single-flight) · the human's event-model decision of
2026-09-28, quoted below · #297 (the finding).

## Why

The purge is the only path that reclaims storage. For every `ArtifactExpired`
with no following `ArtifactPurged` it decrements `content_references`, deletes
the CAS blob when the cross-`kind` refcount reaches zero, and appends
`ArtifactPurged`.

**The lock it holds protects the wrong thing.** `purge_gc.rs` takes
`SELECT checksum_sha256 FROM artifacts WHERE id = $1 FOR UPDATE` — a lock on the
**artifact row**. What it destroys is the **blob**, and the same hash can belong
to several artifacts; CAS deduplicates precisely so that it does. A lock on one
artifact says nothing about the other owners of that hash.

So there is a window. `remaining_refs` counts zero; before `finish_one_ref`
deletes the bytes, a concurrent ingest deduplicates onto the same hash
(`exists(hash)` is true, so nothing is written) and records a reference. The new
artifact now points at bytes that no longer exist.

## What makes the small answer sufficient

The human decided the event model on 2026-09-28:

> `ArtifactPurged` is permitted once the system behaves that way externally. The
> actual physical delete can then be best-effort housekeeping. The goal is
> reclaiming storage — it should happen in the short to medium term via a sweep,
> but it need not be synchronous or just-in-time.

That changes the requirement at the root. **We do not need certainty that a
delete happens — only certainty that nothing live is deleted.** A sweep that
skips when in doubt and retries next time is safe and still reclaims space.
Which is why the generation-addressed-blob and fencing-token design is not
built here: it existed to make deletion safe *and* prompt.

## What to build

1. **A hash-scoped lock** spanning both the decision and the act: count the
   references for the hash → delete the bytes only if zero. Held across both
   steps, not just the count.
2. **The same lock on the ingest's dedup path** — where `exists(hash)` is true
   and a reference to existing bytes is recorded. That serializes deletion
   against re-referencing.
3. **Skip when in doubt.** If the lock cannot be taken, or the count is not
   zero, leave the bytes and leave the worklist row; the next sweep retries.
   This is the mechanism that already exists — `finish_one_ref` leaves a
   transient `StoragePort::delete` failure standing exactly this way today.
4. **`ArtifactPurged` does not wait on byte reclamation.** External behaviour
   and housekeeping are separate; an artifact can be externally gone while its
   bytes wait for a later sweep.

`hort-adapters-storage` has no database access and gets none. The lock lives in
the application / Postgres layer and the storage call happens underneath it.

## The first run (folded in from the issue formerly tracked separately)

The first purge run after a deployment is unbounded — the set is only known once
it is fully loaded. Retention-evaluate already has a cap for this
(`MAX_BATCHES_PER_TICK * BATCH_SIZE`); the same shape applies here. A capped run
that leaves the rest to the next tick fits "best effort" anyway.

## Acceptance

- A test demonstrates the race: a purge that has reached zero references, and a
  concurrent ingest deduplicating onto the same hash. Without the fix the new
  artifact loses its bytes; with it, it does not. Against a real database.
- The ingest dedup path and the byte GC demonstrably take the same lock —
  shown, not asserted.
- Skipping is observable: a skipped blob leaves its worklist row and is retried
  by the next run.
- The first run is capped, in the same shape as retention-evaluate.
- Gate green, `#[serial(hort_pg_db)]` on every test that opens a real Postgres
  connection.

## Explicitly not in this item

- No generation model, no fencing tokens, no change to `cas_path` or to how
  blobs are addressed.
- No change to the `StoragePort` contract beyond what point 1 forces.
- No new operator surface, no new knob.
- No change to ADR 0003 or ADR 0043 as long as the fix does not need one. If it
  does, that is a finding for the report and a separate decision.
