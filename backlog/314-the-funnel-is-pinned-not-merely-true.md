# 314 — The funnel is pinned, not merely true

**Issue:** #346 · **Branch:** `agent/346-pullthrough-weaker-than-its-proof`
**Governing decisions:** ADR 0006 (mandatory upstream verification), and the
project's structural-guard idiom (`cas_reads_are_verified`,
`capped_stream_reads`, `status_decode_fails_closed`,
`db_tests_are_serialized`).

**Depends on item 313**, which created the property this unit pins.

## What is true today

Item 313 made `dedup_ok` (`crates/hort-app/src/use_cases/ingest_use_case.rs`)
the **single construction site** of a deduplicated `ingest_inner` success: it
runs the request's upstream comparison and only then builds the 4-tuple, so a
success carrying `was_duplicate = true` cannot come into existence without the
comparison having run. That is what discharges "impossible to reach silently".

**Nothing enforces that it stays the only site.** A future author adding a
third dedup exit can hand-build the tuple and the comparison is skipped again —
silently, with every test still green, because the tests assert the behaviour
of the paths that exist rather than the shape of the ones that could.

This is the same hazard class the project already pins four times over, and
each of those guards exists because convention alone did not hold the
invariant: the `VerifyingReader` wrap was hand-written at two sites with
nothing holding it; ten capped-read sites got the budget wrong; the serial key
was missing from 29 tests that fell through a crate-scoped wording.

## What to do

1. **Add a DB-free source-scan guard** under `crates/hort-app/tests/`, in the
   family named above and following their shape: sub-second, no database, no
   allow-list, and it runs automatically because `cargo test --workspace` runs
   every `tests/` target.
2. **What it asserts:** every construction of a deduplicated-success value in
   `ingest_use_case.rs` — the `was_duplicate = true` shape — occurs inside
   `fn dedup_ok`. Derive the predicate from the source rather than from a list
   of line numbers, so it survives the file moving.
3. **Carry a counter-assertion**, as its siblings do: the scan must prove the
   corpus is real — that `dedup_ok` still exists, that it still contains the
   comparison calls, and that the scan still finds the construction it is
   meant to police. A rename must not be able to make the guard vacuously
   green; that failure mode is precisely why `cas_reads_are_verified` pins its
   two known implementations by type and file.
4. **Name the blind spot in the guard's own module doc**, the way its siblings
   do — a construction assembled through a macro, or moved to a helper in
   another file, is not visible to a source scan, and the review check survives
   alongside it.

## Explicitly out of scope

- Any production-code change. If the guard goes red on the tree as it stands,
  that is a finding to report, not a thing to fix here.
- Pinning anything else about the ingest path.
- Adding the guard to a gate list: a `tests/` target needs no entry, which is
  the point of putting it there.

## Acceptance

- The guard exists under `crates/hort-app/tests/`, is DB-free, runs in under a
  second, and has **no allow-list**.
- It is green on the tree as it stands.
- **Non-vacuity, both directions:** (a) hand-build a deduplicated success
  outside `dedup_ok` in a scratch edit → the guard goes **red**; (b) rename
  `dedup_ok` → the counter-assertion goes **red** rather than the scan passing
  vacuously. Both outputs in the report, both edits reverted.
- The module doc states what the guard cannot see.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p hort-app` — judge by the output, not the rc,
  and quote the totals. Do **not** run `cargo test --workspace`, `cargo audit`,
  `cargo deny` or the attribution script; the architect runs the full gate on
  the same tree before any MR.
