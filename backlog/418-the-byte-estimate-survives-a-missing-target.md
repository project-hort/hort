# 418 — The byte estimate survives a missing target

**Issue:** #281 · **Branch:** `agent/281-the-byte-estimate-survives-a-missing-target` ·
the only item. **No ADR change, no migration.**

**Governing decisions:** none. `freed_bytes` is a purely informational value
and this does not change what retention decides.

**Maintainer decision (2026-11-09):** cut it in the **minimal** form. An
earlier proposal distinguished two incomplete statuses; he asked whether the
complexity was justified for the use case and the answer was no. What is
built is one status and one counter.

## The property

**An informational estimate must degrade, not vanish.**

Measured on staging, the first real retention dry run: 3 647 expiring rows
over 3 608 distinct contents, and **no byte estimate at all** —

```
freed_bytes: {"status":"omitted","reason":"reclaimable target 00cdd796… is missing from storage"}
```

`sum_target_sizes` (`crates/hort-app/src/task_handlers/retention_evaluate.rs:868-895`)
probes `storage.size_of()` for every reclaimable content and returns `Err` on
the **first** failure; the caller turns that into `status: "omitted"`
(`:711-737`). **One missing object out of 3 608 suppressed the whole
number.**

## Why "at least" is the honest label, and why one status is enough

The sum over the targets that resolved is a **lower bound in every failure
mode**, so one label covers all of them:

- a target that is **`NotFound`** frees nothing when purged anyway — the
  purge treats an absent blob as a clean no-op, in its own words
  *"already-absent blob is a clean no-op (`delete` is success-on-missing)"*
  (`crates/hort-app/src/use_cases/purge_use_case.rs:176-177`, and the
  `NotFound` arm at `:849-873`). So the sum is in fact **exact** for what
  would really be freed;
- any **other storage error** leaves the size unknown and the object possibly
  present, so the sum is a genuine floor.

"At least X" is therefore true in both, and distinguishing them would buy
precision that nothing consumes: `freed_bytes` is produced only in the
dry-run branch and read only by the CLI's renderers and its baseline-versus-
fresh delta table. **Collapsing loses precision, never truth** — which is
what makes the simple version correct rather than merely cheaper.

**And the integrity half is not lost by simplifying, because it was never
this number's job.** A reclaimable target absent from storage means an
artifact row references content that is not there; that belongs to the CAS
scrub. This estimate's duty is to make it **visible** — which the counter
does — not to characterise it.

## What to build

1. **`sum_target_sizes` stops aborting.** Accumulate the sizes that
   resolved, count the targets that did not, and return both.
2. **A third status, `at_least`**, carrying the summed `bytes` and
   `unresolved_targets`. `exact` keeps its current meaning and shape for the
   all-resolved case — **the common case must not change on the wire** — and
   the bound-exceeded path keeps `omitted` with its existing reason
   (`RetentionContentSimulation::Omitted`).
3. **The count replaces the hash in the summary.** Today's reason names
   whichever probe failed **first** under `buffer_unordered` — an arbitrary,
   unstable choice that cannot distinguish one missing object from a
   thousand. That is the actual defect in the current output.
   **Keep the per-failure `tracing::warn!` that names each hash**
   (`retention_evaluate.rs:881`): the log is where an operator finds *which*
   objects, the summary says *how many*. Do not put a hash list in the
   summary.
4. **The CLI learns the variant.** `FreedBytes`
   (`crates/hort-cli/src/admin/retention/dto.rs`) gains it, and
   `bytes_phrase` / `bytes_cell` (`render.rs:90-108`) render it as a floor
   with the count. Note the forward-compatibility affordance that already
   exists and must be preserved: `FreedBytes::Unrecognised` means an **older
   CLI against a newer server degrades gracefully** rather than failing, so
   adding a status is safe — keep that arm working.

## Explicitly not in scope

No change to what retention evaluates, expires or purges. No CAS-integrity
handling, no scrub trigger, no new metric. No hash list on the wire. No
second incomplete status.

## Acceptance

- **All targets resolve → `exact`, byte-identical to today** on the wire.
  Asserted, because the common case regressing would be the one real cost.
- **One target unresolved →** `at_least` with the bytes summed over the
  others and `unresolved_targets: 1`.
- **Several unresolved → the count is the count** — not `1`, and not the
  first failure. This is the assertion that pins the actual defect.
- The bound-exceeded path is unchanged.
- Each failed probe still emits its own `warn` naming the hash.
- The CLI renders the new variant as a floor with the count, and an
  unrecognised status still renders through the existing `Unrecognised` arm.
- Gate green; no uncovered added lines; no ticket numbers in code comments.
