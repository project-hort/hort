# 258 — Make the artifact load and its expected stream version inseparable

**Issue:** #334 · **Branch:** `agent/334-struktur-332`
**Governing decisions:** ADR 0007 (bounded stream reads) · the project rule
that N call sites with N ad-hoc answers means a missing base concept.

## Why

Three call sites decide an artifact's lifecycle outcome from stored evidence
and then commit it behind an optimistic append. The correct order is: read
the expected stream version **beside** the artifact load, then read the
evidence, then decide, then append. When the version is read *after* the
decision, a verdict that committed in between is already contained in the
version just read — the append does not conflict, and the stale decision is
committed over the newer one.

One site has the correct order, and its comment is in effect the
specification that never became a contract
(`crates/hort-app/src/use_cases/quarantine_use_case.rs:909-934`): it
explains that the read is paired with the load, what the old order cost, and
why the append now fails `Conflict` instead.

The other two are the audit's S4C-3 and S8-4:

| Site | Shape |
|---|---|
| `curation_use_case.rs::reevaluate` (:742) | load :764 → evidence → decision → version :994 |
| `policy_use_case.rs::re_evaluate_one_rejected` (:1670) → `commit_re_evaluation` | evidence → decision → version :1929, under a comment calling the read "up-front" |

**A fourth site has the same shape and was not in the audit:**
`policy_use_case.rs::re_evaluate_one_active` (:1441) hydrates the stored
findings at :1458, decides via `evaluate_scan_result`, and
`commit_tighten` (:1572) reads the version at :1583. It commits a tighten
rather than a release, so a stale decision there overwrites a *newer* clean
verdict instead of releasing on a stale clean one — the same defect, the
other direction.

That fourth site is the argument for this item. Two more point fixes would
reproduce exactly the situation in which a fifth site gets it wrong.

## What to do

Build a primitive that makes the two reads **inseparable** — the artifact and
its expected stream version come back from one call — so the order cannot be
got wrong per call site. Then adopt it.

1. **Inventory first.** There are 22 `read_expected_version(` call sites
   across 8 files (`curation_use_case`, `ingest_use_case`, `policy_use_case`,
   `promotion_use_case`, `provenance_misrejection_repair`,
   `provenance_orchestration`, `quarantine_use_case`,
   `apply_config_use_case/curation.rs`). Classify every one as either
   *load-paired* (a decision is derived from state read after the load, and
   the primitive applies) or *not* (e.g. the version is read before anything
   is loaded, or there is no decision between). Record the classification in
   the commit body — it is the evidence that the adoption is complete, and
   the next reader needs it more than the diff.
2. **Adopt it at every load-paired site**, including the already-correct
   `record_scan_result`, so no fourth variant survives.
3. **Leave the explanatory comment**, but rewrite it as the contract rather
   than a site-local story, and drop the `issue #108 H2a` reference — code
   comments state the invariant, never the provenance.

The strength of the correction is that the wrong order becomes
**inexpressible**, not that it is avoided in three or four places. If the
chosen shape still lets a caller read evidence before the version without
going around the primitive, it is the wrong shape.

## Explicitly out of scope

- No change to what any of these sites *decides* — only to when the version
  is read.
- No new event, no schema change, no migration.
- No change to `read_expected_version`'s error semantics per caller: the
  single-artifact job still propagates and the bulk pass still skips. That
  difference is deliberate and documented at both sites.
- The structural guard below is optional, not required.

## Acceptance

- A caller cannot read the evidence before the version without bypassing the
  primitive.
- Every load-paired site uses it, `record_scan_result` included, and the
  commit body carries the 22-site classification.
- A test that actually builds the interleaving: a decision derived from old
  evidence, a blocking scan committed in between, and the append must return
  `Conflict`. The existing tests are serial and cannot construct the case —
  this one has to drive the two in a controlled order.
- The same test exists for the tighten direction (`re_evaluate_one_active`),
  where the stale decision would overwrite a newer clean verdict.
- A structural guard is welcome but not a condition: if the primitive makes
  the wrong order inexpressible, none is needed.
- No comment anywhere still describes the version read as "up-front" where
  it is not.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo-audit audit
  -D warnings`, `cargo-deny check`.
