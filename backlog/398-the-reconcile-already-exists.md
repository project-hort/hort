# 398 — The reconcile already exists

**Issue:** #256 · **Branch:** `agent/256-the-reconcile-already-exists` · single
item. **Message text only** — no behaviour, no signature, no migration.

**Governing decisions:** none govern a log message. ADR 0030 is the home of the
refcount projection the messages describe, and it is not amended here.

## The property

**No message in the codebase tells an operator that the refcount reconcile is
future work, because it is not.** The sweep exists, it repairs exactly the
drift these messages report, and it runs at worker and server boot over every
repository.

**It is not unconditional, and the message must not claim a schedule.** Both
boot sites gate it on `HORT_REFCOUNT_RECONCILE_ON_STARTUP` — default `true`,
with a documented upgrade-install opt-out — and on the worker the opt-out path
returns `ReconcileGateState::Open`, so with the flag `false` the sweep does not
run *and* the purge GC gate is not held. So state the **capability** ("the
sweep removes it"), never "on the next boot": the capability claim is true in
both configurations, and in both the right operator action is still never a
hand edit of a refcount row — it is to run the sweep.

## The census has moved since the issue was written — read this, not the issue

The issue names `crates/hort-app/src/use_cases/ingest_use_case.rs` and the
`primary_content` insert warning. **That site no longer carries the phrase.**
It was corrected in the meantime, and its doc comment now names the sweep and
even states its limit — it derives `primary_content` / `metadata_blob` from the
artifact row and mints no tree edge, so an edge onto foreign bytes is *not*
repaired. That half of the issue is done; do not go looking for it.

What survives is the same false clause on a **different** drift: a
`content_references` row that was *not deleted* when its artifact was
rejected. Four sites, and the grep that finds all four is
`git grep -n 'reconcile is future work' -- crates/`:

1. `crates/hort-app/src/use_cases/quarantine_use_case.rs` — the scan-driven
   reject path's post-commit sweep warn (`stage =
   "content_references_delete_on_reject"`).
2. `crates/hort-app/src/use_cases/apply_config_use_case/curation.rs` — the
   retroactive-curation reject path's identical warn.
3. `crates/hort-app/src/use_cases/quarantine_use_case.rs` — a test's assertion
   message, *"warn-on-fail must leave the seeded row in place; reconcile is
   future work"*.
4. `crates/hort-app/src/use_cases/apply_config_use_case/curation.rs` — the
   same assertion message.

In 3 and 4 the **assertion is correct** and stays exactly as it is: a
warn-on-fail does leave the row in place, because the use case does not retry.
Only the trailing clause is false. Do not weaken either assertion while
rewording its message.

## Why the clause is false for this drift too

`RefcountRepair` (`crates/hort-domain/src/ports/refcount_reconcile.rs`) carries
a variant for precisely this case:
`DeleteRejectedSourceRows { source_artifact_id, kind }` — *"A
`content_references` row exists whose source artifact is `quarantine_status =
'rejected'` — delete every row for that source (the warn-on-fail
`ArtifactRejected` cascade did not land)"*. The sweep's own doc names the
warn-on-fail path these two messages are logged from.

And the contradiction is already in the file: three lines above site 2 the
comment says *"The refcount reconcile sweep heals any drift."* The comment and
the log line in the same block disagree, and the log line is the half an
operator reads at 03:00.

## Why this is not a typo

An operator who finds the warning reads: *something went wrong here and no
mechanism cleans it up.* The reaction that invites is a hand edit of a
projection that repairs itself on the next boot — and hand-editing refcount
rows is exactly the intervention that can corrupt a retention decision. The
message should say what is true, so that **doing nothing** is recognisably the
right action.

## The rewording

Say three things and stop: the delete failed, the row is eventual, and the
refcount-reconcile sweep removes it. Name the mechanism by a **durable
anchor** — `RefcountRepair::DeleteRejectedSourceRows`, or the sweep's type name
— not by prose like "the boot sweep", which is what let the claim rot in the
first place. The structured fields (`artifact_id`, `error`, `stage`) stay
exactly as they are: something may already alert on them.

## Out of scope

- No behaviour change. The warn-on-fail posture is correct and stays: the
  reject itself has committed, and failing the call would undo nothing.
- No change to the sweep, its variants, or its scheduling.
- No sweep of other stale "future work" comments elsewhere in the workspace
  (four other files carry the phrase about unrelated things). Legacy wording is
  not swept opportunistically.
- No `CHANGELOG.md` entry. A log message an operator reads differently is not
  an observable change to running or upgrading hort, and the changelog carries
  only what is.

## Acceptance

- `git grep -n 'reconcile is future work' -- crates/` returns **nothing**.
- The two production warns name the repairing mechanism by type or function
  name, not by prose.
- The two test assertions still assert the row survives a warn-on-fail; only
  their messages changed.
- `git diff --stat` touches exactly two files, and no line outside a string
  literal or a comment.
- Gate green, workspace suite run **once**.
