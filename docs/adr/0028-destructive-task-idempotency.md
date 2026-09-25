# 0028 — Durable single-flight idempotency for destructive task kinds

- **Status:** Accepted
- **Enforced by:** the `jobs_idempotency_key_uq` partial unique index
  (`migrations/009_scan_jobs_and_findings.sql:356-358`) + the adapter test suite
  `crates/hort-adapters-postgres/tests/idempotency_key.rs` (dedup, distinct-key,
  None-path, and schema-CHECK cases); the closed-set guard
  `crates/hort-http-admin-tasks/tests/destructive_kinds_carry_db_idempotency.rs`
  (walks `DESTRUCTIVE_TASK_KINDS`, asserts the default invocation of every kind
  reaches `enqueue` with `Some(key)` and that a retention dry run reaches it
  with none); the operator-visible pin
  `crates/hort-http-admin-tasks/tests/retention_dry_run_is_repeatable.rs`
  (two previews are two `202`s, a second execution is still a `200` dedup hit,
  and the claim gate and key derivation cannot disagree); the post-failure pin
  `crates/hort-server/tests/destructive_kind_idempotency_post_failure.rs`.
- **Supersedes:** — (adds a layer to ADR 0020's single-flight stack; does not
  supersede it)

## Context

The destructive task kinds — `retention-evaluate`, `retention-purge`,
`eventstore-archive` (`DESTRUCTIVE_TASK_KINDS`,
`crates/hort-domain/src/events/authorization_events.rs:475-480`) — execute
irreversible work, and `eventstore-archive`'s seal path performs an unbounded
`StreamSealed` append that is safe **only** under cluster-wide single-flight
(ADR 0020). One of ADR 0020's layers is the per-UTC-day idempotency key.

As first built, that layer was **best-effort ephemeral**: the admin-tasks
invoke handler checked an `idem-task:<key>` entry in the ephemeral durable
store (Redis-backed `ctx.ephemeral_durable`,
`crates/hort-http-admin-tasks/src/handlers/invoke.rs`) with a 300 s TTL. The
check is fail-closed against the store being *unreachable*, but a
flush/failover that clears the entry while the store stays up returns a clean
miss — dedup silently doesn't fire. Combined with a CronJob-controller restart
inside the TTL window, two concurrent `eventstore-archive` invocations were
possible, violating the single-flight precondition. The key was also
client-supplied (`Idempotency-Key` header, derived by the CLI's
`--idempotency-key-window` flag, `crates/hort-cli/src/admin/task_invoke.rs`) —
present only when the operator remembered to send it, so an ad-hoc
`hort-cli admin task invoke retention-purge` bypassed the layer entirely.

## Decision

For every **destructive invocation**, the server derives a per-UTC-day
idempotency key itself and the database enforces its uniqueness durably:

- **Server-derived, always.** The invoke handler computes
  `cron:<kind>:<YYYY-MM-DD>` for `retention-purge` and
  `eventstore-archive`, and `cron:retention-evaluate:execute:<YYYY-MM-DD>`
  for a retention execution
  (`crates/hort-http-admin-tasks/src/handlers/invoke.rs`, Step 4b), regardless
  of any operator-supplied `Idempotency-Key` header. There is no branch where
  a destructive invocation reaches `enqueue` with no key — the invariant
  "destructive ⇒ key present" is structural, not operator discipline.
- **Per invocation, not per kind.** The gate is
  `hort_domain::events::task_invocation_is_destructive(kind, params)` — the
  same domain answer that decides whether the caller needs the
  `DESTRUCTIVE_TASK_CLAIM` (`TaskUseCase::authorize_kind`), so the authority
  an invocation needs and the single-flight claim it takes cannot come apart.
  The coarser `task_kind_is_destructive(kind)` remains correct for audit
  routing (`TaskUseCase::task_audit_stream`: a dry run's `TaskInvoked` still
  belongs on the never-deleted destructive-kind stream) and is deliberately
  not the predicate here. The practical difference is
  `retention-evaluate` in `dry_run` mode: it appends nothing, takes **no**
  durable key, and is therefore repeatable within a UTC day. Denying a repeat
  of an observation buys nothing this decision is about — a restart cannot
  make an observation destroy anything — and costs the one thing a preview
  has to support, which is looking again. The mode segment stays in the
  execute key even though no other mode now reaches that branch: it names the
  dimension the key separates on, so a second kind gaining a mode cannot
  silently collapse two invocations onto one key.
- **Persisted and DB-enforced.** The key threads through
  `TaskUseCase::enqueue` (`crates/hort-app/src/use_cases/task_use_case.rs:259`)
  to `JobsRepository::enqueue_task`
  (`idempotency_key: Option<&IdempotencyKey>`,
  `crates/hort-domain/src/ports/jobs_repository.rs:440-448`) and lands on the
  `jobs` row. The partial unique index (`WHERE idempotency_key IS NOT NULL`)
  rejects a second row; the Postgres adapter's
  `INSERT … ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO
  NOTHING` CTE (`crates/hort-adapters-postgres/src/jobs_repository.rs:658`)
  resolves the conflict to `EnqueueOutcome::Duplicate { existing_job_id }`.
- **Duplicate is not an error and never a second run.** The handler maps
  `Duplicate` to HTTP 200 with the existing `task_job_id` (same shape as the
  ephemeral fast-path hit), and the `TaskInvoked` audit event carries
  `duplicate_of: Option<Uuid>`
  (`crates/hort-domain/src/events/authorization_events.rs:546`,
  `#[serde(default)]` for replay safety) so dedup decisions are
  reconstructable from the audit stream.
- **Strictly at most one destructive enqueue per key per UTC day, including
  after failure.** The key is never cleared on terminal worker failure — the
  cron schedule *is* the retry mechanism. Same-day recovery is an explicit, audited
  operator action (delete the failed `jobs` row). Pinned by
  `destructive_kind_idempotency_post_failure.rs`.
- **Non-destructive invocations are untouched.** They pass `None`; the
  partial-index predicate is inert and the insert always proceeds. That
  covers every non-destructive kind and every retention dry run.
- **Validated end-to-end.** The `IdempotencyKey` newtype
  (`crates/hort-domain/src/types/idempotency_key.rs`) validates charset and
  length (1..=256), matched 1:1 by the schema CHECKs
  (`jobs_idempotency_key_charset_chk` / `jobs_idempotency_key_length_chk`,
  `migrations/009_scan_jobs_and_findings.sql:260-264`) as defence in depth
  against domain-bypass writes.

The ephemeral `idem-task:` fast-path remains in the handler as a cheap
additional layer for header-bearing calls. Its cached value records the job,
kind, and complete typed params, and only an exact match is a hit; the former
16-byte raw UUID representation is an unverified miss. The CLI includes the
retention mode in its window-derived header key. The DB index is the durable
layer.
This ADR records the layer that **promotes ADR 0020's per-UTC-day key from
best-effort-ephemeral to durable-DB** — the other ADR 0020 layers (CronJob
`concurrencyPolicy: Forbid`, worker per-kind semaphore, sequential seal await,
`lock_timeout` backstop) are unchanged, and relaxing any of them remains a hard
block per ADR 0020.

## Consequences

- The per-UTC-day single-flight layer survives ephemeral-store flush/failover
  and CronJob-controller restarts — the dedup decision lives in the same
  database transaction domain as the job row itself.
- Retention preview and execution are independent same-day jobs at both
  idempotency layers. A preview cannot suppress a later execution, and a
  preview cannot suppress a later preview: `hort-cli admin retention apply
  --from-preview <A>` re-measures immediately before executing and that fresh
  sweep is genuinely fresh, so the delta it renders is the proposal against
  the world as it now is rather than the proposal against itself.
- Ad-hoc CLI invocations of destructive kinds get the layer with no
  operator-supplied key; nothing depends on the `--idempotency-key-window`
  flag being present.
- A failed destructive run blocks same-day re-enqueue by design. Failures are
  persistently operator-visible (failed `jobs` row, audit event); recovery
  inside the same UTC day requires deliberately deleting the failed row.
- A future destructive kind on a sub-day schedule would be silently collapsed
  to the day's first run by the `cron:<kind>:<date>` key shape — adding one
  requires revisiting the per-UTC-day granularity in a new ADR, not a silent
  extension.
- Every `enqueue_task` / `enqueue` call site makes an explicit
  `Option<&IdempotencyKey>` decision; the compiler forces new enqueuers to
  consider idempotency.
- Adding a kind to `DESTRUCTIVE_TASK_KINDS` automatically extends both the
  server-side derivation (via `task_invocation_is_destructive`, which is built
  on `task_kind_is_destructive`) and the closed-set guard test — no second list
  to update. A kind that needs a *mode* dimension extends
  `task_invocation_is_destructive`, and the claim gate and the key follow
  together because both read it.

## Alternatives considered

- **Client-supplied key + `debug_assert!` that destructive kinds carry one.**
  Rejected: fails closed in debug builds but silently in release — exactly
  where it matters.
- **Reject destructive invocations lacking an `Idempotency-Key` header
  (400).** Rejected: breaks ad-hoc operator invocations, and still leaves the
  key's *shape* to the client.
- **Clear the key on terminal worker failure (same-day retry).** Rejected: a
  retry-within-the-day path defeats the per-day bound that keeps the unbounded
  seal append safe, and hand-rolls a retry mechanism the cron schedule already
  provides.
- **Table-level unique constraint on `jobs.idempotency_key`.** Rejected: would
  require a key on every job; the partial index leaves the majority
  (non-destructive, `NULL`-key) enqueues completely untouched.
- **Relocating the ephemeral fast-path into the use case.** Rejected: the
  handler is where the `Idempotency-Key` header arrives and where the
  destructive-invocation classification gates RBAC; moving the fast-path would
  add a port nothing else needs. The two layers coexist at their natural
  boundaries.
- **Keeping the key per *kind* and letting the CLI report the dedup.** The
  shipped CLI detects a deduplicated preview exactly (`200` versus `202` from
  the server, not a clock comparison) and says so in the header, the delta
  section, the JSON and the confirmation question. Rejected as the resting
  state: it is an honest report of a wrong answer. The delta an operator is
  being asked to authorise would still be empty by construction on every day
  the intended preview-then-apply workflow is followed. The messaging stays —
  a second *execution* in one day is still deduplicated by design, and saying
  so is then exactly right.

## References

- ADR 0020 — single-flight backstop for the unbounded seal/retention append
  (this ADR durably enforces its third layer).
- ADR 0022 — the schema change landed as an in-place edit of the original
  `jobs` migration.
- `crates/hort-domain/src/types/idempotency_key.rs` (newtype);
  `crates/hort-domain/src/ports/jobs_repository.rs:440` (`enqueue_task` +
  `EnqueueOutcome`); `crates/hort-app/src/use_cases/task_use_case.rs`
  (`enqueue`, `authorize_kind`);
  `crates/hort-http-admin-tasks/src/handlers/invoke.rs` (Step 4b server-side
  derivation); `crates/hort-adapters-postgres/src/jobs_repository.rs`
  (`ON CONFLICT` CTE); `migrations/009_scan_jobs_and_findings.sql:260-264,356-358`
  (column, CHECKs, partial unique index);
  `crates/hort-domain/src/events/authorization_events.rs`
  (`DESTRUCTIVE_TASK_KINDS`, `task_kind_is_destructive`,
  `task_invocation_is_destructive`, `retention_evaluate_mode`);
  `crates/hort-domain/src/retention/mode.rs` (`RetentionEvaluationMode`).
- Tests: `crates/hort-adapters-postgres/tests/idempotency_key.rs`;
  `crates/hort-http-admin-tasks/tests/destructive_kinds_carry_db_idempotency.rs`;
  `crates/hort-http-admin-tasks/tests/retention_dry_run_is_repeatable.rs`;
  `crates/hort-server/tests/destructive_kind_idempotency_post_failure.rs`.
