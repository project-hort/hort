# 383 — Membership edges on a dedup hit

**Issue:** #410 · **Branch:** `agent/410-edges-on-a-dedup-hit` · single item.

**Governing decisions:** ADR 0030 (retention / GC) and the constituent
deliverability work from #342. **No ADR change** — the edge is already defined
as the GC keepalive; one path does not write it.

## The defect

An ingest that takes the dedup short-circuit **discards the membership edges
its caller passed**, and the caller then counts them as written.

The path, verified against `develop` `8faaf380`:

1. `oci-index-child-ingest` derives the edges and passes them as
   `claimed_edges` to `IngestUseCase::ingest_verified`
   (`crates/hort-app/src/task_handlers/oci_index_child_ingest.rs:811-820`).
2. `ingest_verified` routes `ProtocolNative` to `ingest_verified_sha256`, i.e.
   onto "the existing `ingest_inner` declared-hash path"
   (`crates/hort-app/src/use_cases/ingest_use_case.rs:1452-1480`).
3. Step 3 of that path is `find_existing_and_check_declared_dedup`
   (`:2619-2672`). When the path **and** the declared hash match an existing
   row, it breaks out through `dedup_ok` with `ControlFlow::Break`.
4. `dedup_ok` (`:2583-2595`) runs the upstream comparisons and returns
   `(existing, true, repo_key, uuid)`. **It touches no edge.**
   `Self::ingest_edges` (`:3249`) is reached only from the commit paths
   (`:1732`, `:4116`, `:5053`).
5. The handler then sets
   `summary.membership_edges_written = claims.edges.len()`
   (`oci_index_child_ingest.rs:838`), justified by *"The transition committed,
   so every edge it carried is durable — there is no per-edge outcome left to
   count."* On a dedup hit **no transition happened**, so the count is wrong.

## Why it matters

The handler states the stake itself (`oci_index_child_ingest.rs:805-810`):

> *"The edge is the claim that keeps a constituent's bytes alive under the
> storage GC, and nothing re-derives one for a manifest that committed
> without it — `artifacts` records a manifest's own hash, not what it
> references, which is exactly why `oci_membership_edge_backfill` has to
> re-read manifest bodies to repair this."*

So: the edge is the GC keepalive, nothing derives it later, and a repair tool
already exists because this gap has occurred before. The ingest path keeps
producing it on the dedup branch.

The branch is reached whenever the row already exists at that path with that
hash — a repeated index-child ingest after a partial success, a child that
arrived earlier through a client pull, or a re-run of the same task. **The
repeat that would repair a missing edge is the one that does not write it.**

**What this is not:** not #410's sibling #312. There the handler path writes
the edges and does not fetch the blobs; here the edge itself is not written.
The consequences differ — an extra round plus scan latency there, a
constituent the GC may collect while an index still names it here.

## What to build

The dedup hit **reconciles** the claimed edges instead of discarding them:
insert what is missing, touch nothing that is already there. That is the
operation `ingest_edges` performs on the commit path, and it needs no artifact
transition here, because the row does not change.

Two things must not happen:

- **No success that reports edges which are not there.**
  `membership_edges_written` must be the result of the write, not the length
  of the input list.
- **No rework of the dedup decision itself.** That a same-path-same-hash
  request is a `Duplicate` stays correct; only the edge half is missing.

Read `ingest_edges` before writing the reconcile: it is the definition of what
an edge for a claim looks like, and a second spelling of that is how the two
halves drift.

## Acceptance

1. A second index-child ingest against an already-present row installs the
   missing membership edges — shown by a test that produces the first round
   **without** edges and reads the edges after the second.
2. Edges already present are neither duplicated nor rewritten.
3. `membership_edges_written` counts what was written. A dedup hit with no
   missing edge reports `0`, not the length of the list.
4. The dedup path is otherwise unchanged: same return value, same upstream
   comparisons, no extra CAS access. The existing dedup tests pass
   **unmodified** — if one has to change, say so and stop.
5. A test shows the property, not just the row: with the edge reconciled, the
   GC may no longer collect the constituent.

## Read first

- `crates/hort-app/src/task_handlers/oci_index_child_ingest.rs:770-850` — the
  caller, its claim derivation, and the comment that states the stake.
- `crates/hort-app/src/use_cases/ingest_use_case.rs:2556-2672` — `dedup_ok`
  and the declared-hash short-circuit, with the doc comments explaining why
  the short-circuit exists at all.
- `crates/hort-app/src/use_cases/ingest_use_case.rs:3249-3300` —
  `ingest_edges`, the definition to reuse.
- The `oci_membership_edge_backfill` task — the existing repair path, and the
  evidence that this gap has been seen before.
