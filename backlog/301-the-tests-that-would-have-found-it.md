# 301 — The fixture can express a non-blocking finding, and the two paths are cross-tabled

**Issue:** #344 · **Branch:** `agent/344-scan-verdict-release-authority`
**Governing decisions:** CLAUDE.md's coverage contract for `hort-app` (100%,
"every match arm, every error path, and every boundary condition — not just
happy paths"). **Last of five; it is the structural close, not the garnish.**

## What is true today

Nothing pins the defect — no test asserts that an artifact with non-blocking
findings must stay quarantined. **But the case cannot be written** with the
fixture the authority tests use. `scan_completed_event`
(`crates/hort-app/src/use_cases/quarantine_use_case.rs:2630`) builds the
severity summary as:

```rust
severity_summary: SeveritySummary {
    critical: u32::from(finding_count > 0),
    high: 0, medium: 0, low: 0, negligible: 0,
},
```

In that fixture **"has findings" means "has a CRITICAL"**. All five call sites
that pass a non-zero count (`:5058`, `:5255`, `:5333`, `:5376`, `:5431`)
therefore exercise a **blocking** finding, and the production case — findings
present, none above the threshold — has no representation in the corpus.

That is why the divergence between the two authority derivations survived: in
every test the two agree **because the fixture makes them agree**. The module
is called the authority-derivation matrix and looks exhaustive; it never
separates "the scanner found something" from "the policy blocks". The 100 %
line-coverage target was satisfied the whole time — the condition's line runs,
just never with this decision.

## What to do

1. **The fixture takes the severity as an argument**, so "n findings, none
   above the threshold" is expressible. Keep a thin helper for the common
   clean/blocking shapes if it reduces churn, but the severity must be
   *statable* at the call site. Until this exists, no new test can reach the
   case — which is why this item is not optional.
2. **Cross-table both paths.** For each combination of (finding count ×
   severity relative to the threshold × `enforcement` mode × window elapsed or
   not at scan time), assert that the fast path and the sweep reach the **same**
   verdict about releasing. This table cannot go green while two
   implementations of the question exist, which is exactly the property worth
   pinning: it fails on a future re-divergence, not merely on today's symptom.
3. **Pin the authority's meaning, not only the outcome**: for each row, assert
   *which* authority the release carries (item 299), so a correct release under
   a dishonest label is still a failure.
4. **Cover item 300's partition in the same table** where it applies: a
   re-scan above the threshold against a `Timer`-released and an
   `Admin`-released artifact.
5. **Report the decision coverage, not the line coverage.** The report names
   which boundary each row crosses and states explicitly that the
   `finding_count` condition is now exercised in both directions from inside
   the `if let` — the gap that the previous corpus left.

## Explicitly out of scope

- Rewriting unrelated tests that happen to use the fixture: adapt call sites
  mechanically, and say in the report how many were touched and that none
  changed meaning.
- Adding an allow-list or a skip for any existing test. If an existing test
  encodes the old behaviour, it is a review conversation, named in the report.

## Acceptance

- The fixture can express a non-blocking finding, and at least one test uses it
  with a `high`/`medium` severity and a `critical` threshold.
- The cross-table exists, covers both paths, and **fails** when either path's
  predicate is reverted — demonstrate both directions with captured output.
- Every row asserts the authority value as well as the release outcome.
- `release_expired_fail_closed_does_not_release_unscanned` and the
  `enforcement: record` / `scan_backends: []` tests pass unchanged.
- The report states, per row, which boundary it crosses.
- Gate: `bash handover/gate-unit.sh` — check, fmt, clippy and the
  `hort-domain` + `hort-app` tests. The full workspace suite, `cargo audit`,
  `cargo deny` and the attribution check are the **architect's** to run on the
  same tree before any MR: together they outlive a worker's foreground tool
  window, so the harness backgrounds them and the turn ends while they run,
  which killed four runs in thirteen. Commit, then write the report.
