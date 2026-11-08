# 402 — The window outlasts the budget

**Issue:** #420 · **Branch:** `agent/420-the-window-outlasts-the-budget` ·
single item. **Test harness only — no Rust, no product change.**

**Governing decisions:** none govern a scenario's timeout budget. ADR 0007 is
the reason the wait exists at all (the quarantine window is the gate, and the
index carries the full one), and nothing about it changes here.

## The property

**A scenario's budget for a wait is derived from what it is waiting for, not
from how long the steps before it happened to take.**
`scripts/native-tests/scenarios/quarantine/proxy-required-multilayer.sh`
violates this at step 9b, and the violation makes the scenario fail *when the
runner is fast*.

## The defect, measured

The index is deliberately anchored to the **full** quarantine window — step 7
asserts `quarantine_window_start == created_at` — and
`deploy/compose/example-config/policies/oci-provenance-proxy-e2e-required.yaml`
sets `quarantineDuration: 120s`. Step 9b therefore waits on that window.
`ANON_PULL_WAIT_SECS` gives it **90 s**. From the `v0.17.3-beta.2` run, both
lanes:

| | base lane | native-tokens lane |
|---|---|---|
| step 0, cold ingest (= `quarantine_window_start`) | 06:29:09.83 | 06:29:13.32 |
| window closes (+120 s) | 06:31:09.83 | 06:31:13.32 |
| step 9b starts | 06:29:25.82 | 06:29:28.23 |
| 90 s budget ends | **06:30:55.82** | **06:30:58.23** |

The budget runs out 14.0 s and 15.1 s **before the window closes**, and the
release then needs the next sweep tick (15 s) plus job-claim/release
processing on top. Deterministic in both lanes, not flaky.

**Faster is worse.** Only the elapsed time between step 0 and step 9b eats
into the window; it was 16.0 s / 14.9 s here. For 90 s to suffice that gap
must be ≥ 30 s, realistically ~45–55 s once the tick and processing are
counted. The lanes of the previous, green `v0.17.3-beta.1` run took 14:33 and
14:39; these took ~10:20. Same commit, green on a slower machine, red on a
faster one.

**The two budgets sit swapped.** `WINDOW_WAIT_SECS` (default 240 s, line 124)
does the window arithmetic correctly in its own comment and guards step 8
(`await ProvenanceVerified`), which completed in ~6 s. `ANON_PULL_WAIT_SECS`
(default 90 s, line 132) guards the step that actually waits, and its comment
states the premise that is wrong: that 9b waits *"only on clearance + the
release sweep tick"*. That is true of the constituents and false of the index,
which is the thing being pulled.

## What to build

**Split step 9b into two waits, each with an honest budget and an honest
failure message.**

1. **9b-i — await the index row's release.** Poll the index artifact's
   `quarantine_status` via psql until it is `released`, the way steps 5 and 7
   already reach the database. Budget: the full window plus a sweep tick plus
   processing — reuse the 240 s that `WINDOW_WAIT_SECS` already justifies, or
   a sibling constant with the same arithmetic written out. Failure message:
   the index never released, naming the window as the thing waited on.
2. **9b-ii — the anonymous `--all` pull.** Unchanged command, short budget
   (60 s is ample once the row is released — this leg is a pull, not a wait).
   Failure message: keep the existing cascade / late-joiner / clearance
   wording, which is then *true*, because the window has provably closed.

Why the split rather than simply raising `ANON_PULL_WAIT_SECS` to 240: it
removes the faster-is-worse property instead of hiding it behind a larger
constant, it survives a future change to `quarantineDuration` without
re-tuning, and it makes the two failure modes distinguishable — today a
window-not-closed timeout is reported as a cascade or clearance problem,
which is what sent the first reading of this failure down the wrong path.

If the split turns out to fight the harness's helpers, raising
`ANON_PULL_WAIT_SECS` to 240 with a corrected comment is an acceptable
fallback — **say so in the report** rather than doing it silently.

**Correct the comment at lines 125-132 either way**, and state the
faster-is-worse property there: the scenario needs the elapsed time between
step 0 and step 9b *not* to be assumed, so that the next person to speed up
the early steps does not quietly re-break it.

## Out of scope

- Any product change. Hort behaved correctly: the index was held because its
  quarantine window had not elapsed.
- The four children that missed the sign-time cascade (*"provenance cascade:
  child manifest CAS read failed — its config/layer blobs are not
  cascaded"*). That is the expected late-joiner case step 9a collects, and 9a
  passed. The FAIL-LOG dump ends at the timeout, before the window closed, so
  this run says nothing about whether every late-joining blob was released in
  the end — the next run with a correct budget will. **Do not chase this
  while fixing the budget; report it if the fixed scenario still fails.**
- Other scenarios' budgets. A sweep for the same mistake elsewhere is worth
  doing, but not inside this change.

## Acceptance

- Step 9b's wait is sized against the window, not against an assumption about
  the preceding steps, and the file says so.
- `./scripts/native-tests/run.sh --hort=compose --scenario quarantine/proxy-required-multilayer`
  passes. Report the elapsed time between step 0 and step 9b for the run, so
  the margin is on the record.
- A window-not-closed timeout and a clearance failure produce **different**
  failure messages.
- No product file is touched. The diff is the scenario script (and, if the
  default moves, nothing else).

## Gate

Shell only: `bash scripts/run-shell-guards.sh`, plus the scenario run above.
`cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings`
as a no-op confirmation that nothing Rust moved. A full `cargo test
--workspace` is not warranted for a change that touches no Rust — say so in
the report instead of running it.
