# 075 — #131 item 2: S4 in-flight guard matches its own rows + S4 hoisted before the authority guard (F2+F3)

**Issue:** #131. Dispatched AFTER item 074's report (the claim-side fix changes the
runtime behavior these fixes are verified against). Both defects here are already
PROVEN by the live evidence — no investigation phase.

**Read first:** #131 evidence comments;
`crates/hort-app/src/use_cases/quarantine_use_case.rs` — `release_expired` (the
authority `continue` at ~:1400, the S4 block :1415-1437,
`enqueue_final_provenance_verify` :1491+ and its in-flight guard via
`find_active_provenance_for_artifact`);
`crates/hort-adapters-postgres/src/jobs_repository.rs::find_active_provenance_for_artifact`
(compare its matching predicate against the exact row shape
`enqueue_provenance_verify_in_tx` writes — the live stack re-enqueued every tick
DESPITE pending rows, so the predicate demonstrably misses them);
item 074's report (claim-side changes this builds on).

## Proven defects

- **F2:** the S4 guard re-enqueued a final `provenance-verify` for the same
  artifacts on every sweep tick although their prior jobs sat `pending` — ~1450
  rows in 33 minutes, unbounded jobs-table growth. The guard's lookup does not
  match the rows its own enqueue writes (params shape / status set / kind — find
  the actual mismatch and pin it in a test).
- **F3:** S4 sits AFTER the release-authority `continue` in `release_expired`, so
  any candidate whose release authority is not constructible never receives its
  terminal provenance decision. The terminal-decision enqueue must not depend on
  release-authority constructibility: hoist the S4 block (Required + Pending +
  past-deadline check) ahead of the authority guard, preserving the existing
  best-effort/warn-and-continue semantics and the (fixed) in-flight guard.

## Work

1. Fix `find_active_provenance_for_artifact` (or the guard's use of it) so a
   pending OR running `provenance-verify` row for the artifact suppresses
   re-enqueue. DB-gated test: seed artifact + pending verify job → sweep tick →
   assert NO second row; complete the job → next tick → assert exactly one new
   row.
2. Hoist S4 before the authority `continue`; unit tests in `hort-app` (mock
   ports): candidate with unconstructible authority + Required + Pending + past
   deadline → final verify enqueued; authority present → unchanged behavior.
3. Jobs-table-growth regression: the 074 reproduction shape extended — N sweep
   ticks over a held Required artifact produce at most 1 active final-verify row.
4. **Acceptance vehicle (F4):** the E2E negative case
   (`quarantine/provenance-push-then-sign` [6/6]) is expected to pass UNCHANGED
   after 074+075 — state this in the report for the human's local run; do not
   modify the scenario.

## Scope / acceptance

- `hort-app` 100% tier on changed branches; adapter tests `#[serial(hort_pg_db)]`.
- No E2E/harness changes; no dispatcher changes beyond what 074 landed.
- Gate: full pre-push suite (fmt, clippy -D warnings, test --workspace with and
  without DATABASE_URL, audit, deny).

**Model hint:** sonnet (both defects proven and precisely located; mechanical with
a clear test matrix).
