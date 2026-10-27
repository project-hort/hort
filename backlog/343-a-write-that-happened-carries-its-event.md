# 343 — A write that happened carries its event

**Issue:** #352 · **Branch:** `agent/352-integrity-verifier-verdict`
**Governing decisions:** ADR 0002 (event-sourced lifecycle: every state
transition produces an immutable domain event) · ADR 0060 (append-conflict
reaction contract).

**Confirmed by the maintainer 2026-10-18** (#352 moved to `ready`). This is
the keystone finding of the block: it is the path that *produces* the
projection-vs-log divergence nothing in the verifier looks for.

## What is true today

`crates/hort-adapters-postgres/src/artifact_group_lifecycle.rs`, one
transaction, four steps:

1. `:151-174` — when `change.primary_role_assigned` is `Some`:
   `UPDATE artifact_groups SET primary_role = $1, updated_at = NOW()
    WHERE id = $2 AND primary_role = ''`.
   `rows_affected == 0` means the race was lost → `drop(uow)` (rollback) +
   `Conflict`. `rows_affected == 1` means **the group's primary role has
   just been written** and execution continues.
2. `:184-197` — `INSERT INTO artifact_group_members … ON CONFLICT
   (group_id, artifact_id) DO NOTHING`.
3. `:199-236` — when the insert affected no rows, the stored role is read
   back. **If it equals the requested role**, the code logs
   `idempotent same-role re-add; no event emitted`, commits at `:221` and
   returns `Committed`.
4. `:242` — `append_in_tx(batch)`, never reached on that branch.

The comment above the commit (`:218-220`) states:

> *"Commit releases the row lock from the INSERT attempt; nothing else was
> written, so the txn is semantically a no-op."*

**That sentence is false in exactly one combination**, and the combination is
reachable: the group has no primary role yet (so step 1's `WHERE primary_role
= ''` matches and the UPDATE *succeeds*), the artifact is already a member
with the same role (so step 2 affects no rows), and the caller asked for the
primary role on this call. Step 1 wrote. Step 3 commits it. The event batch is
discarded.

The result is a durable projection change with no event behind it — the
precise divergence class the chain verifier has no check for.

## What to build

**Establish the caller first, do not assume it.** Before changing behaviour,
determine whether a production caller actually produces
`primary_role_assigned = Some(role)` together with an existing same-role
membership. The reconcile path is the candidate. Record the answer in the
commit body either way: it decides whether this is a latent trap or a live
data-integrity bug, and the fix is the same, but the report must not guess.

The correction belongs at the branch, not at the call sites: the early return
must not be reachable while an earlier step in the same transaction has
written. Two shapes are acceptable and the choice is the implementer's, with
the reasoning in the commit body:

- make the branch conditional on nothing having been written in this
  transaction, and otherwise fall through to the event append; or
- make "did step 1 write?" a value the branch must consume, so a future step
  that writes cannot silently bypass the append.

What is **not** acceptable is a comment correction. The comment is accurate
about the intent and wrong about the state; the fix is to make the state match
the intent.

## Acceptance

1. A re-add of an existing same-role member that also assigns a
   previously-unset primary role **either** appends its event batch **or**
   writes nothing at all. A committed role change with no event is impossible.
2. The pre-existing idempotent case — same-role re-add with **no**
   `primary_role_assigned` — still commits, still emits no event, still
   returns `Committed`. No new event on a genuine no-op.
3. The race-lost path (`rows_affected == 0` on the UPDATE) still rolls back
   and still surfaces `Conflict`.
4. The different-role case still rolls back and still surfaces `Conflict`.
5. A test drives the reachable combination directly against the database and
   asserts the group's `primary_role` and the stream's event count move
   together — not one without the other.
6. The misleading comment is gone, replaced by one that states the invariant
   the code now holds.
