# 334 — A compensating delete removes only what it inserted

**Issue:** #349 · **Branch:** `agent/349-the-predicate-of-the-purpose`
**Governing decisions:** ADR 0028 (durable single-flight idempotency for
destructive task kinds — the key this delete destroys) · ADR 0020 (the
single-flight stack ADR 0028 adds a layer to) · ADR 0002 (event-sourced
lifecycle: the audit event is the record) · ADR 0008.

**Depends on nothing.** One adapter statement, one port contract, one
use-case branch, three pieces of prose.

## 1. The statement has no status predicate

`crates/hort-adapters-postgres/src/jobs_repository.rs:1119`:

```rust
sqlx::query("DELETE FROM public.jobs WHERE id = $1")
```

Its one caller is `crates/hort-app/src/use_cases/task_use_case.rs:445`, inside
`if is_fresh_enqueue`, after a failed `TaskInvoked` append.

**The predicate of the purpose** is in the port contract itself
(`crates/hort-domain/src/ports/jobs_repository.rs:751-759`): *"Used as a
compensating action by `TaskUseCase::enqueue` when the event-store append
fails after a successful insert"* and *"**Rollback-only.** Do not call from
any path other than compensating-delete sequences."* What it is meant to
remove is **the row this same call just inserted and that nobody has claimed
yet**. `enqueue_task` inserts with `status = 'pending'`
(`jobs_repository.rs:988`); the claim flips `pending → running`
(`CLAIM_PENDING_BY_KINDS_SQL`, `:134-164` — `WHERE status = 'pending'`,
`SET status = 'running'`). So the predicate is `AND status = 'pending'`, and
it is already written verbatim twenty lines above in the same file.

**What happens instead.** Between the `INSERT` and the compensating `DELETE`
lies a failed event-store append — a network round-trip. A worker can claim
the row in that window and begin executing it. The `DELETE` removes it anyway,
**together with its single-flight idempotency key** (the per-UTC-day key ADR
0028 made durable precisely so a destructive kind cannot run twice). A second
authorised POST then inserts afresh under the same key, and two destructive
executions can run on separate replicas while **no `TaskInvoked` exists for
the first**.

Preconditions: an append failure and a worker claiming inside that window.
Infrastructure bad luck, not a permission.

## 2. Zero rows affected is not success

After the narrowing, the `DELETE` matches **no rows** when the worker won the
race. That must not pass as a rollback. The row is executing with no audit
event — exactly the state the module doc already describes for the *failed*
compensation (`task_use_case.rs:435-436`: *"the `jobs` row exists without an
audit event"*).

So the port method stops returning `DomainResult<()>` and returns a named
two-valued outcome. Add to `hort-domain`'s jobs-repository port:

```rust
/// What a compensating delete observed. The variants name what the
/// statement saw, not a cause inferred from it.
pub enum CompensatingDelete {
    /// The row was still `pending` and is gone: the insert is rolled back.
    RolledBack,
    /// The row was no longer `pending` when the delete reached it. A worker
    /// claimed it and is executing it, and no `TaskInvoked` was appended —
    /// so the execution has no audit record and the row must be inspected.
    NoLongerPending,
}
```

Name the variants for the observation, not the cause: the statement cannot
distinguish "claimed" from "already gone", and a variant promising the former
would be a claim the SQL does not support. The rustdoc says which it means in
practice and why.

`NoLongerPending` goes on the **same operator-visible path** as today's
`del_err` branch (`task_use_case.rs:445-452`), with a message that states the
difference: not "compensating delete failed" but *the row was already claimed —
it is executing without an audit event*. Keep the existing `del_err` branch for
a genuine infrastructure error; this is a third outcome beside it, not a
replacement.

## 3. Four pieces of prose the finding falsifies

- **The port contract** (`jobs_repository.rs:754-755`) says *"Returns `Ok(())`
  if the row was deleted or did not exist"*. That promise is the defect
  written down; it changes with the signature.
- **The module doc** (`task_use_case.rs:27-29`) says of the orphaned row:
  *"the row will idle as `pending` and an operator can purge it manually"*.
  For the case this finding names that is false — the row is `running` and
  being executed. It does not idle, and purging it does not undo what it did.
  The recovery guidance misleads the operator exactly where they need it.
- **The inline comment** at `task_use_case.rs:434-436` carries the same
  "Limitation" wording and gains the second shape.
- **The `TaskFailed` emission-source doc**
  (`crates/hort-domain/src/events/authorization_events.rs:921-929`) tells the
  operator to find orphaned rows by *"looking for `status='pending'` jobs with
  no corresponding `TaskInvoked` event"*. The row this finding strands is
  `running`, so that query does not find it — the one recovery instruction the
  domain gives misses precisely the case that matters.

## Acceptance

- A DB-backed test that **kills the wrong predicate**: insert, claim the row
  (`status = 'running'`), call the compensating delete, and assert the row
  **survives** and the outcome is `NoLongerPending`. It carries
  `#[serial(hort_pg_db)]` like every other test that opens a Postgres
  connection.
- A DB-backed test that a still-`pending` row is deleted and the outcome is
  `RolledBack` — the regression guard for the narrowing.
- A `hort-app` test over the mock jobs repository for each of the three
  branches in `enqueue`'s failure path (`RolledBack`, `NoLongerPending`,
  infrastructure error), since `hort-app` is a 100 %-coverage crate.
- All four prose sites — the port contract, the module doc, the inline
  comment and the `TaskFailed` emission-source doc — say what the code does,
  and the recovery guidance names both row states.
- No file under `migrations/` is changed.
- Full gate green (`CHECK/FMT/CLIPPY/TEST/AUDIT/DENY/ATTR`). No issue/MR
  references in code comments.

## Out of scope

- The two other findings on this issue (items 335 and 336).
- Any change to the claim statement, the retention sweep's bulk delete
  (`jobs_repository.rs:3550`), or the idempotency key's derivation.
- Making the enqueue a real two-phase commit. The port deliberately has no
  shared transaction (`task_use_case.rs` § *Transaction semantics*); this unit
  narrows a compensation, it does not replace the model.
