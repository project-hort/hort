# 391 — The permissive strand is a third kind, and the repair path has never met it

**Issue:** #252 · **Branch:** `agent/252-the-permissive-strand-is-a-third-kind`
· single item. **No production code change.**

**Governing decisions:** ADR 0007 (the time gate) · ADR 0039 D6 (the illegal
`Rejected` state the repair path exists for) · #250 (the `secs > 0` guard whose
removal made the repair path's own promise true again).

## What is verified, and one wording I am correcting

Verified against `origin/develop` before this item was written:

- **`recover-stranded-artifacts.md` names two strands.** §1–§4 are the
  scanner-execution strand; §5 is *"A different strand: artifacts wrongly
  `rejected` on the provenance axis"*. The permissive strand is not a named
  third kind anywhere in the file.
- **`curator-workflow.md` does not list `quarantineDuration` among the
  re-evaluation triggers.** The list is `severityThreshold`, the blocked-class
  set, `negligibleAction` and exclusions (around `:636`–`:643`). The file *does*
  already carry a §5 on the `quarantineDuration: 0` opt-out, so the gap is the
  **connection** between the two, not the opt-out itself: because the duration
  is not a re-evaluation trigger, the sweep is the only way out, and that
  sentence exists in neither place.
- **The repair path's own promise.** `Artifact::repair_provenance_misrejection`
  (`crates/hort-domain/src/entities/artifact.rs:2215`) inherits the original
  anchor, and its module doc promises the artifact *"lands back in front of the
  ordinary release sweep with an already-elapsed window… the next sweep tick
  releases it."*

**The correction:** the issue calls the transition "unconditional". It is not —
the function refuses on the transition table and on two terminal-record shapes
(`TerminalRejectionRecord::Present`, `::CorruptionTombstone`,
`artifact.rs:2235`–`:2252`), each with its own reason. What is unconditional is
the **anchor inheritance**, which is the part the promise rests on. Do not
repeat the issue's wording in a comment or a test name.

## The property to show

**A repaired artifact in a permissive repository is actually released.** Under
#250's removed `secs > 0` guard that sentence was false for *every* permissive
repository — the repair would have re-stranded exactly the artifacts it was
written to un-strand. It is true again, and nothing holds it: the connection
between the repair population and the permissive window is covered today only
by the candidate selection, not by a test that touches both paths.

## The test is green on arrival, so it needs a second half

This is a confirmation test, not a red-to-green one. A test that passes the
moment it is written proves the property **and nothing about its own
sensitivity** — it would pass just as happily if the thing it asserts were
unreachable.

So pair it, the way `#415`'s observation tests were paired: either two
assertions over one constellation that could not both hold if the wiring were
wrong, or a mutation check that shows the assertion can fail. State in the
report which you chose and why it is sensitive — "it passes" is not the
deliverable.

Keep it DB-free if the harness allows; if it needs a database, every DB-bound
test carries `#[serial(hort_pg_db)]`.

## The two documentation additions

**`recover-stranded-artifacts.md`** gains the third strand: its recognition
shape (`quarantined`, `release_attempt_at = NULL`, a repository whose window is
`0`), that it is **self-healing** since the guard came off, and that a
pre-existing population heals the same way — **no backfill is needed**. That
last clause is the operationally valuable one: without it an operator reads
"fixed in a later version" and starts looking for a migration.

**`curator-workflow.md`** gains the sentence the two halves are missing: why
`quarantineDuration` is not in the re-evaluation trigger list, and what follows
— that a change to it does not re-evaluate anything, so the sweep tick is the
only way out.

Neither file is *wrong* today; both are incomplete. Do not rewrite either
beyond what the gap needs.

## Acceptance

- A test shows a repaired artifact in a permissive repository is released, with
  its sensitivity established rather than assumed.
- `recover-stranded-artifacts.md` names the third strand, its recognition shape,
  that it self-heals, and that no backfill is needed.
- `curator-workflow.md` states why `quarantineDuration` is absent from the
  re-evaluation list and what that means for the way out.
- **No production code change.** If the test cannot be written without one,
  stop and report — that is a finding about the harness or about the property,
  and either way it is mine to rule on.
- No issue, MR or backlog reference in any code comment; the two docs are
  `docs/` prose and may cite ADRs and paths freely.
- Gate green.
