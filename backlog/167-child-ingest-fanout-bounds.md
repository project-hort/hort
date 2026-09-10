# 167 — bound and observe the eager-child-ingest fan-out

**Issue:** #229 · **Branch:** `agent/229-eager-child-ingest` · Item 4 of 4
(depends on items 161 and 162; one MR carries all four).

## Problem

Three gaps surfaced when item 1's handler was reviewed. All three concern what
happens at the edges of the fan-out rather than its happy path, and none is
visible from the handler's own tests.

**1 — The recursion is bounded per digest, not per tree.** A child that is
itself an index enqueues its own children. Re-visits are bounded twice over
(the target-repository presence check, and the fact that
`jobs_idempotency_key_uq` is unique over all non-`NULL` keys rather than live
rows only), so each distinct digest runs at most once per repository. But
`MAX_INDEX_CHILDREN = 1024` bounds one *level*. A chain of distinct nested
indexes fans out as 1024ⁿ, so a single client pull of a hostile or merely
pathological upstream tree can enqueue an arbitrarily large job tree. Priority
0 and concurrency 1 limit the damage rate, not the size.

**2 — Terminal rows accumulate forever.** `prefetch-row-retention-sweep` is
scoped `kind LIKE 'prefetch%'` and the scan sweep to `kind = 'scan'`, so no
sweep covers `oci-index-child-ingest`. One terminal row per child manifest per
repository is retained permanently.

**3 — Two rules decide index-versus-image, and they can disagree.**
`register_membership_edges_from_pull` decides on the manifest's *declared
media type*; the enqueue added in item 2 decides on the *body structure*
(`is_image_index`). In practice they agree. Where they disagree — an upstream
serving a structurally-index body under an image-manifest media type — the
edges follow one rule and the enqueue follows the other, so children are
ingested while the index's `oci_index_member` membership rows are never
written. That is the same class of incomplete-membership defect
`oci_membership_edge_backfill` exists to repair, and digest verification does
not help: the bytes match their digest, the `Content-Type` is what lies.

The pre-existing rule was not wrong on its own. It became a defect the moment
a second rule was placed beside it, which item 2 did.

**4 — A failed grandchild enqueue is invisible at log level.** A run with
`grandchildren_failed > 0` still completes at normal severity; the count
reaches `result_summary` JSON only. Those grandchildren silently fall back to
the lazy path, which is the correct behaviour but not a silent one.

## Governing decisions

- **Issue #229 D10 is amended by this item.** D10 said nested indexes recurse
  without a depth knob. That remains right about *operator-visible* knobs — no
  `PrefetchPolicy` field, nothing configurable. It was wrong to read it as
  "no bound at all": a hard internal cap is the same shape as
  `MAX_INDEX_CHILDREN`, which bounds breadth and which the issue already
  endorses. Breadth is capped; depth must be too.
- **ADR 0007** — unchanged. Nothing here touches the release predicate, and a
  child that is not eagerly ingested still reaches the repository through the
  lazy pull path with its own full window.
- **ADR 0054** — unchanged. Sweeping a terminal jobs row does not touch an
  artifact row or its anchor.

## Read first

- `crates/hort-app/src/task_handlers/oci_index_child_ingest.rs` — the
  `register_and_recurse` path, the `ChildSummary` counters, the params struct.
- `crates/hort-app/src/task_handlers/prefetch_row_retention_sweep.rs` and the
  scan-row retention sweep — the two existing per-kind sweep precedents, their
  scoping predicates and their retention parameters.
- `crates/hort-domain/src/oci.rs` — `MAX_INDEX_CHILDREN`, for the shape a hard
  internal cap takes in this codebase.
- `migrations/009_scan_jobs_and_findings.sql` — `jobs_idempotency_key_uq`, for
  why sweeping a terminal row is safe.

## What to build

**A depth bound.** Carry a recursion depth in the task params, defaulting to
the root level when absent so rows enqueued by item 2 need no change, and
refuse to enqueue past a small hard constant. Real-world OCI trees nest one
level; a cap of four costs nothing legitimate. This is a constant in the code,
not a config field, not a `PrefetchPolicy` entry, and not operator-visible.
Refusing at the cap is a completion with an explicit outcome label and a
`warn!`, not a failure — the deeper children remain reachable lazily.

**Retention.** Bring terminal `oci-index-child-ingest` rows under an existing
retention sweep. Choose whichever of the two existing sweeps is the right
home and justify the choice in the commit body rather than adding a third
sweep handler for one kind.

Sweeping is safe and the reason must be stated in the code as an invariant: the
jobs row is the *second* dedupe layer, not the only one. Once a child is held
in the target repository, the presence check short-circuits any re-enqueued
row before it touches the network, so a swept row that is later re-enqueued is
a cheap no-op rather than a re-fetch.

**One rule for index-versus-image.** Make
`register_membership_edges_from_pull` decide on the body, the same way the
enqueue and the handler already do, so the whole feature has exactly one
answer to the question. The declared media type stays worth cross-checking and
logging on disagreement — it is a useful signal about the upstream — but it
must not be the thing that decides which edges get written. The bytes that
were hashed and stored are the artifact; a `Content-Type` header is not.

Check the hosted PUT path while you are there and say in the report whether it
shares the same divergence or already decides on the body. Do not change it in
this item if it differs — report it.

**Observability.** A run that ends with `grandchildren_failed > 0` logs at
`warn!`, naming the count. The run still completes — the fallback is correct —
but an operator watching severity must be able to see that eager ingest
degraded.

**One test tightening.** The assertion pinning the anchor invariant currently
uses an `is_none_or` shape that passes vacuously when the anchor is `None`.
Since the preceding assertion already establishes the row is `Quarantined`,
the anchor is necessarily `Some`; assert that, so the "not backdated" claim is
actually load-bearing. This test is the one that pins the ADR 0054 invariant
for this whole feature and must not be able to pass for the wrong reason.

## Explicitly not in this item

- Any operator-visible knob, field, or config surface. The depth cap is a
  constant.
- A third retention-sweep handler.
- Any change to the presence check, the dedupe key, or the failure-shape split
  item 1 settled.
- Any change to `MAX_INDEX_CHILDREN` itself.

## Acceptance

- A nested-index chain stops enqueueing at the cap, with a `warn!` and an
  explicit outcome label; the run completes rather than failing.
- A structurally-index body declaring an image-manifest media type gets its
  `oci_index_member` edges written and its children enqueued — one rule, one
  outcome — with the disagreement logged.
- A root-level row enqueued without a depth param behaves exactly as today.
- Terminal `oci-index-child-ingest` rows fall within a retention sweep's
  scope, with the "the presence check is the real dedupe" invariant written
  down where a future reader will find it.
- `grandchildren_failed > 0` produces a `warn!` naming the count.
- The anchor-invariant test fails if the anchor is `None`.
- `hort-app` coverage contract: 100%.
- Full local gate green per the pre-push checklist, `cargo test --workspace`.
