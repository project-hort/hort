# 376 — The cascade root is not client-waited

**Issue:** #399 · **Branch:** `agent/399-reassignment` · item between 373 and 374.

Opened by unit 373's flag 1, which reported the symptom and correctly refused
to fix it in the write face. This unit is the classification decision, taken by
the architect.

## What holds after 373

`('prefetch-dependencies', 'ingest')` — the transitive dependency cascade a
push spawns — classifies **`Interactive`**, because `TaskTier::classify` reads
the trigger source and an ingest caused the row. After 373 derived the ordinal
from the class, that row therefore carries `INTERACTIVE_BAND`: the **top** band,
above an operator's manual rescan.

Before 373 it shared the schema default with the ingest-time gates — the
**bottom** of the old layout. So the re-ranking promoted it from the floor to
the ceiling, and with prefetch-on-ingest enabled a bulk push run produces one
such row per artifact: a flood in the top band that preempts the operator work
it used to drain behind. That is the defect class ADR 0066 exists to remove,
reappearing in a new place, and it is why this closes before the branch's MR
rather than after.

## Why `Bulk` is the right answer

ADR 0066 D1's test is *who is waiting on this right now*. Nobody is waiting on
the cascade:

- the push that caused it has already answered `201`; the cascade contributes
  nothing to that response;
- the handler is a warm-up walk — it reads the ingested artifact's manifest and
  prefetches the dependencies it declares so that *later* pulls are warm
  (`crates/hort-app/src/task_handlers/prefetch_dependencies.rs`, module header);
- and the recovery path proves nobody is blocked: *"a failed walk leaves a
  terminal row … and the next pull of any dependent re-derives the missing
  subtree from the `artifacts` projection"*. A pull that needs a dependency
  fetches it on demand, on its own path. If the cascade never ran, nothing
  waits — something else does the work when someone actually asks.

**This is D3 read in the other direction, not an exception to it.** D3 says
that a piece of work running on a timer is not therefore unwaited-on: *"That a
piece of work runs on a timer says how it is triggered, never that nobody is
waiting for its effect."* The converse is the same rule: that a piece of work
was triggered by a client's push says how it was triggered, never that a client
is waiting for its effect. The trigger source is the *cause*; the class is
*who waits*; D2 keys the class on the cause only because the cause usually
determines who waits. The cascade is the case where it does not.

`TaskTier`'s own module doc already lists "the prefetch cascade" under `Bulk`,
while `classify` has filed its ingest-triggered root under `Interactive` since
unit 363. One of the two is wrong, and it is not the doc.

## The outcome

**`TaskTier::classify` gains a kind carve-out for `prefetch-dependencies` →
`Bulk`**, read **before** the trigger source — structurally identical to the
`quarantine-release-sweep` carve-out already there (D3), and justified by the
same rule in the opposite direction.

Keyed on the **kind alone**, not on `(kind, trigger_source)`:

- the cascade's own child rows already carry `trigger_source = 'prefetch'`
  (that file's `PREFETCH_TRIGGER_SOURCE`, used at `:1082` and `:1112`) and so
  already classify `Bulk` — the carve-out makes the root agree with its
  children instead of outranking them by two whole bands;
- there is no `(prefetch-dependencies, *)` row anyone waits on, so a
  source-keyed carve-out would be a narrower rule with no case to distinguish.

**It must be in `classify`, not in `queue_priority`.** A kind-keyed exception
in the write face that the read face does not share is exactly the
two-lists-disagreeing defect this module was built to end, and 373 made the
write face a function of the read face precisely so that this is impossible.

## Acceptance

1. `classify("prefetch-dependencies", s) == Bulk` for **every** `s` in
   `TriggerSource::ALL`, asserted over the set rather than for `'ingest'` —
   the carve-out is read before the parse, like the sweep's.
2. `queue_priority("prefetch-dependencies", "ingest") == BULK_BAND`, and a test
   that states the relation the unit exists for: the cascade root does **not**
   outrank the manual rescan, the admin invoke, or the ingest-time gates.
3. The root ranks **with its own children** — equal to
   `queue_priority(prefetch-ingest, 'prefetch')` — asserted as an equality, so
   a later band change cannot silently separate them again.
4. `the_ordinal_order_agrees_with_the_tier_order` stays green without an edit.
   If it needs one, stop: that means the carve-out broke the agreement rather
   than restoring it.
5. The counter-assertion the sweep's carve-out carries gets its sibling: the
   two kind carve-outs are the only ones, and each is asserted to be that
   kind's alone.
6. `TaskTier`'s module doc stops being contradicted — check the "prefetch
   cascade" sentence reads true afterwards rather than leaving it to a reader.
7. Both producers' tests (`ingest_use_case.rs` at the ingest-time hook and at
   the register-by-hash hook) assert the band through the table.
8. `CHANGELOG.md`: **no new entry.** Fold into the existing `#399` `### Changed`
   entry if anything needs saying; the ranking statement there already covers
   "ranked by who waits", and this unit makes that sentence true for one more
   kind rather than changing what an operator must do.

## Not in this item

- Non-displacement (374) and the observability half (375).
- Any other kind's classification. If a second kind looks misfiled, report it —
  the whole point of this unit is that the decision is taken once, with the
  reasoning written down, not patched at a call site.
