# 175 — the rollback floor must predict the refusal, not contradict it

**Issue:** #226 · **Branch:** `agent/226-schema-compat` · Item 6 of 6
(depends on item 174).

## Problem

Two parts of this feature answer the same question — *what does this schema
require of a binary?* — with **opposite** rules for the same input.

The **refusal** side, `SchemaRollbackBound::required_binary_version`, is
explicit in its own doc: it returns `None` "when at least one of them is
unregistered and the answer is therefore unknown", and its test says why —
*one unregistered blocker makes the whole requirement unknown, even alongside
registered ones: the unknown one could require more.*

The **inspection** side, `schema_rollback_floor`, does the reverse: a recorded
minimum wins over an unregistered sibling, so it reports a version where the
refusal would report unknown.

The consequence is the exact failure the inspection answer exists to prevent.
An operator reads `tolerates_binaries_from=0.13.0`, rolls back to 0.13.0, and
is refused anyway — by a message telling them the requirement is unknown. The
report does not merely fail to help there; it actively misleads, in the one
situation it was added for.

Item 5 preserved this because it was the pre-existing behaviour and its
directive forbade predicate changes. That was the right instinct and the wrong
conclusion: `schema_rollback_floor` is the *report*, not the predicate. No gate
reads it. Aligning it changes nothing about what is refused.

## Governing decisions

- **Issue #226** — the inspection answer exists so an operator can ask how far
  back a database rolls *before* attempting it. An answer that contradicts the
  gate is worse than no answer, because it will be acted on.
- The fail-closed posture already chosen on the refusal side: an unknown could
  require more, so unknown dominates. The report must say the same.

## Read first

- `crates/hort-config/src/schema_compat.rs` — `schema_rollback_floor`'s final
  `match`, and `SchemaRollbackBound::required_binary_version` with its doc and
  its `one_unregistered_blocker_makes_the_requirement_unknown` test. The second
  is the rule the first must adopt.
- `rollback_floor_prefers_a_recorded_minimum_over_an_unregistered_sibling` —
  item 5 added this to lock in the behaviour being changed. It is replaced by
  its inverse, named for what it now asserts.

## What to change

In `schema_rollback_floor`, an unregistered applied migration makes the answer
`Indeterminate` **regardless** of what any other applied migration records. The
priority inverts: unknown dominates a recorded minimum, exactly as it already
does on the refusal side.

`Unconstrained` and `Version` are otherwise unchanged, and so is everything
about which migrations are inspected.

Say in `schema_rollback_floor`'s doc comment that it deliberately mirrors the
refusal side's unknown-dominates rule, and why — a report that disagrees with
the gate it predicts is worse than silence. That sentence is the thing stopping
someone from "optimising" it back.

## Explicitly not in this item

- Any change to the gates, the predicate, the refusal wordings, the register's
  contents, or `required_binary_version`. The refusal side is already correct;
  this item moves the report to match it.
- Any change to `Unconstrained`, to `Version`, or to the variant names item 5
  chose.
- Any new inspection surface.

## Acceptance

- An applied set containing both a recorded minimum and an unregistered
  migration reports `Indeterminate`.
- All-expansions still reports `Unconstrained`; a recorded minimum with
  everything else registered still reports its version.
- `rollback_floor_prefers_a_recorded_minimum_over_an_unregistered_sibling` is
  replaced by its inverse under a name describing the new rule.
- A test asserts the report and the refusal agree on the same input — the
  property this item exists to establish, not merely the branch it changes.
- No gate's behaviour changes; the refusal wordings are untouched.
- Full local gate green per the pre-push checklist, `cargo test --workspace`,
  with `DATABASE_URL` set and the skipped-for-no-database count reported.
