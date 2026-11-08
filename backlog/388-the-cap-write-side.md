# 388 — The cap's write side

**Issue:** #412 · **Branch:** `agent/412-the-cap-write-side` · single item,
one census and two corrections.

**Governing decisions:** ADR 0007 and its two-sided cap-enforcement amendment
(**#329 is open for the ADR side — this item does not pre-empt it**: it enforces
the invariant where it already holds and names the guard. If #329 changes the
*form* of enforcement, that is the ADR side of the same question and is decided
there).

## The finding

`STREAM_EVENT_CAP` is declared *"an enforced, fail-closed bound, not an
estimate of how long a stream gets"* (`crates/hort-app/src/use_cases/mod.rs`).

**The read side is pinned.** The guard `capped_stream_reads` permits a bounded
`read_stream` in exactly one production file and checks every call in the
workspace.

**The write side has no counterpart.** Refusal *before* appending exists at
exactly two sites:

- `crates/hort-app/src/use_cases/retention_use_case.rs` — `stream_len + 1 >
  STREAM_EVENT_CAP`
- `crates/hort-app/src/use_cases/quarantine_use_case.rs` —
  `stream_len + appended > STREAM_EVENT_CAP` (from #406, and stricter than that
  item specified: it counts the batch's events rather than one)

Every other production path that appends to an artifact stream has no such
check.

**The census is part of this item and is not asserted here.**
`StreamId::artifact(` appears in more than a dozen files under `crates/*/src`,
most of them reading or helping. What is needed is an enumeration of the
**append** sites and, for each, the answer to one question: *can this path be
repeated?* A once-per-artifact write cannot breach the cap; a repeatable one
can, and that was #406's defect exactly.

**Impact.** A repeatable writer without the check freezes the artifact
permanently on crossing — the shape #406 fixed for the scan path. Raising the
cap from 200 to 1000 moved the threshold; it did not remove it.

## What to build

1. **The census**, per append site, with the repeatable-or-not verdict and its
   reason.
2. **The check** where a path is repeatable, in the same shape as the two that
   have it.
3. **A guard for the write side**, as `capped_stream_reads` is for the read
   side. This is the real conclusion: a convention applied correctly twice and
   not applied N times does not hold itself. An append path should either carry
   the check, or declare itself once-only **with its reason at the site**, or
   go red.

The guard needs what its siblings have: a counter-assertion that it can still
fail (strip the predicate from a corrected site and watch it go red), and the
cap named in one place — no guard and no test spelling the number a second
time.

## Two residues from the same scoping — confirm or discard first

Both come from the #406 refinement and are **not re-verified**. The first step
per point is: confirm or discard with the reason, and report it either way. A
discarded point is a result.

1. **The additive score delta per rescan is computed in the write path.** To
   settle: whether that is where it belongs, and whether it still does what it
   should for a rescan with an unchanged verdict — which since #406 appends no
   event.
2. **The ordering of `previously_clean_at`.** To settle: against which time
   base the value is set, and whether two rescans in quick succession can
   produce an order the release path reads differently from the write path.

What must not happen is a correction without a prior confirmation: both sit in
the path #406 just changed.

## Acceptance

1. The census exists, per append site, with "repeatable: yes/no" and the
   reason.
2. Every repeatable site refuses before crossing, with a message naming the
   stream and the cap.
3. A guard turns a new append site red unless it carries the check or declares
   its reason; it carries a counter-assertion that it can fail.
4. The cap stays defined in one place; no second literal.
5. Both residues are confirmed and fixed, or discarded with reasons.
6. No test green today has to be rewritten; if one does, that is a finding.

## Read first

- `crates/hort-app/src/use_cases/mod.rs` — the cap, its contract, and the
  bounded read it is paired with.
- `crates/hort-app/src/use_cases/retention_use_case.rs` and
  `.../quarantine_use_case.rs` — the two sites that already refuse, and the
  shape to follow.
- `crates/hort-app/tests/` — `capped_stream_reads` as the model for a
  structural guard with a counter-assertion.
