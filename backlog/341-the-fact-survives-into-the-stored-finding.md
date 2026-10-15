# 341 — The second verdict function consults the predicate

**Issue:** #351 · **Branch:** `agent/351-a-finding-condemns-only-its-own-artifact`
**Governing decisions:** ADR 0056 (as amended 2026-10-15) · ADR 0041
(re-evaluation reads the stored findings) · ADR 0007 (fail-closed, preserved).

**Depends on units 338-340.** Last of four.

> **This item was rewritten on 2026-10-15 after unit 340's report.** Its
> original subject was a `scan_findings` column, on the premise that
> re-evaluation would otherwise be blind to the relation. **That premise is
> false and the column is dropped** — see §1. What actually needs closing is
> a second verdict function, which unit 340 found and did not touch.

## 1. Why the original premise was wrong

`policy-reevaluation` does **not** read the `scan_findings` projection. It
hydrates the per-finding list from the **CAS findings blob**:
`scan_history::last_findings` (`crates/hort-app/src/use_cases/scan_history.rs:388`)
takes the last `ScanCompleted`'s `findings_blob` hash, reads it through
`StoragePort::get`, and deserialises `Vec<Finding>` — the full struct,
`component_relation` included, because serde carries it.

So the relation already survives onto the re-evaluation path. A migration
would add a column that no verdict reads: the projection's only
finding-reconstructing consumer is
`crates/hort-adapters-postgres/src/retention_scan_reader.rs:98`, which feeds
**retention** evaluation, not the release gate. Adding schema for that is
scope this issue does not need, and an unused column is a maintenance claim
nobody is paying.

**No file under `migrations/` changes in this item.**

## 2. What actually needs closing

`decide_rejected_transition`
(`crates/hort-domain/src/policy/re_evaluation.rs`) is the **second** function
in the workspace that computes a blocking verdict from a finding list. Unit
340 narrowed `evaluate_scan_result` and left this one alone, so the two now
disagree — and the function's own module rustdoc states the invariant that
breaks:

> *the enforcement check is applied to the SAME `action` the CVE +
> negligible evaluators produce, so this decision point and
> `evaluate_scan_result` cannot disagree about which verdicts block.*

**The tighten direction is already fine** — `policy_use_case.rs:1583` re-runs
`evaluate_scan_result` itself and inherits the narrowing. **The loosen
direction is not.** The reachable sequence, from unit 340's report:

1. an artifact is rejected over a Critical on its **own subject**, and also
   carries a `NotContained` Critical;
2. an operator adds an exclusion for the subject one;
3. `decide_rejected_transition` filters the excluded finding out, reads the
   leftover `NotContained` Critical as blocking, and returns `StillRejected`;
4. a fresh scan of the identical findings returns `Clean`.

Fail-closed, so not a security hole — but it is an artifact stuck on a
verdict no scan would reach, clearable only by a rescan. That is the same
"stuck on a verdict nothing reached" shape ADR 0059 was written for, and
this issue exists to stop producing.

**So: consult `Finding::may_condemn_artifact` there too**, on the same
findings, before the threshold walk — the narrowing unit 340 applied at step
1b of `evaluate_scan_result`, applied at the equivalent point here.

## 3. This makes a second consumer — pin it deliberately

Unit 340's guard (§6 of item 340) asserts that `component_relation` is read
only where it is allowed to be read, via an `EXPECTED_CALL_SITES` census.
Adding this consumer **will turn that guard red, by design**. Add the row.
That is the conversation the guard exists to force: a second reader is
permitted here because it is the second verdict function and the invariant
above requires the two to agree — not because the guard was in the way.

Do not add a third. If a fourth verdict-computing site ever appears, the
right answer is to collapse them, not to extend the census again.

## 4. The residual this item names and does not close

When the CAS findings blob cannot be hydrated — absent or malformed —
`last_findings` returns `None` and re-evaluation degrades to the
**aggregate-summary** path (`filter_excluded_summary` in the same function),
which has per-tier counts and no per-finding data at all. It therefore cannot
consult the relation, and keeps today's condemning behaviour.

That is a genuine residual, not an oversight, and it is fail-closed: a
non-carried finding keeps its authority on a degraded path that already loses
`severity_basis` the same way. **Write it into the function's rustdoc** so the
next reader does not mistake it for an inconsistency, and state in the report
that it is accepted rather than missed.

## 5. Constraints

- `hort-domain` requires **100 % coverage**.
- **ADR 0007 preserved**: no release authority added, removed or
  reinterpreted. This narrows what counts as a blocking finding on the second
  path, exactly as unit 340 did on the first.
- The **unassessed-severity floor** stays untouched and is not routed around.
- No `migrations/` change, and no `CHANGELOG.md` entry — the architect stamps
  the issue's entry at MR time.
- No issue, MR or backlog reference in any code comment.

## Acceptance

- `decide_rejected_transition` consults the predicate, and the two verdict
  functions agree: a finding list containing only non-carried findings yields
  a non-blocking outcome from **both**.
- The reachable sequence in §2 is pinned as a test: subject Critical plus
  `NotContained` Critical, exclusion added for the subject one, re-evaluation
  returns the released/non-blocking transition rather than `StillRejected`.
- The subject-still-condemns direction is pinned here too — the regression
  that matters is the same one unit 340 guards.
- The guard's `EXPECTED_CALL_SITES` carries the new row and the census is
  green again, with its counter-assertions intact.
- The aggregate-summary residual is documented in the rustdoc and named in
  the report.
