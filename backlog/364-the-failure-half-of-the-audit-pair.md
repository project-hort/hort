# 364 — The failure half of the task audit pair

**Issue:** #331, entry **E53** · **Branch:** `agent/331-e53-taskfailed-emit` · single item.

**Maintainer decision (2026-11-02):** build the emit site. The alternative —
pulling ADR 0028 and the two doc sites back to the as-built state — was
declined.

## Why

`DomainEvent::TaskFailed` exists, is mapped for subscriptions, and has a
`validate()`. **No production code constructs or appends it.** Three places
say otherwise, and one of them is a standing decision:

- `docs/adr/0028-destructive-task-idempotency.md:130-131`: *"A failed
  destructive run blocks same-day re-enqueue by design. Failures are
  persistently operator-visible (failed `jobs` row, **audit event**);
  recovery inside the same UTC day requires deliberately deleting the failed
  row."*
- `crates/hort-domain/src/events/authorization_events.rs`, the `TaskFailed`
  docstring: *"the worker dispatcher **emits** `TaskFailed` when a
  `TaskHandler` returns a terminal error"*.
- `crates/hort-app/src/use_cases/task_use_case.rs`, which contradicts itself
  inside one paragraph: *"the `TaskFailed` audit record **is emitted** by the
  worker dispatcher"* alongside *"the single reuse point a **future**
  `TaskFailed` emit-site is expected to call"*.

Two places are honest: `task_dispatcher.rs` carries
`#[allow(dead_code)] event_store`, and `jobs_row_retention_sweep.rs` states
the `jobs` row is *"the only durable record of a failure … a column update
with no event-store append to fall back on"*.

**What is actually missing is one half of a pair, and the asymmetry runs the
wrong way for an audit trail.** A task's *invocation* is recorded durably:
`TaskUseCase::enqueue` appends `TaskInvoked` on the stream
`task_audit_stream(kind)` returns, and for a destructive kind that is
`StreamId::eventstore_retention()` — the never-deleted stream. Its *failure*
is recorded nowhere but a `jobs` row the retention sweep removes after seven
days (`jobs_row_retention_sweep.rs:145`). So a refused or failed destructive
run — the case ADR 0028's re-check exists for — is the more interesting
record and the only one that expires.

**The recovery procedure is not broken, and the item should not claim it is.**
ADR 0028 requires the operator to find and deliberately delete the failed row
within the same UTC day; the seven-day horizon comfortably exceeds that, so
the row is present when it is needed. The gap is the durable trail, not the
recovery.

**The metric is not a substitute either.** The dispatcher emits
`hort_admin_tasks_completed_total{kind, result="failed_terminal"}`, but it
lives on the worker's registry, which is opt-in and off by default
(`worker.metrics.enabled`, chart default `false`), and a counter names no
job, no reason, no time and no authority.

## What to build

**The emit site is the dispatcher**, which is where the row's result state is
written and the only writer of it (the `jobs_row_has_one_owner` guard pins
that). It already holds the `event_store` it needs, marked
`#[allow(dead_code)]`.

**Use the reuse point the code already names.** `TaskUseCase::task_audit_stream(kind)`
is documented as *"the single reuse point a future `TaskFailed` emit-site is
expected to call so both records land on the same exempt stream."* Do not
re-derive the routing; call it. Destructive kinds must land on the
never-deleted stream beside their `TaskInvoked`, or the pair is split across
two streams and neither half is readable as one trail.

**Both failure paths, distinguished by `final_attempt`.** The dispatcher has
two: `reschedule` (retryable, `attempts < attempt_cap`) and `mark_failed`
(terminal). Emit on both — `final_attempt: false` and `true` respectively.
The field exists to carry exactly this distinction, and the volume is bounded
by the attempt cap, which is one configured number
(`HORT_SCANNER_MAX_ATTEMPTS`, default 6); a destructive kind runs at most once
per UTC day per kind, so the never-deleted stream grows by at most the attempt
cap per kind per day.

## The constraint that would bite a naive implementation

`TaskFailed::validate()` **rejects a kind outside `ADMIN_INVOKABLE_TASK_KINDS`**
(`authorization_events.rs:981`), and the production adapter calls
`validate()` on every append. The dispatcher, however, runs kinds that are
deliberately *not* in that set — `scan` is the documented example, absent on
purpose because a scan row is only well-formed carrying four scan-typed
columns.

So an unconditional emit produces a rejected append for exactly those kinds.
That is correct behaviour from `validate()` and must be respected rather than
worked around: `TaskFailed` is the counterpart of `TaskInvoked`, which only
ever exists for an allowlisted kind, so the pair is symmetric by
construction.

**Required: a census, reported untruncated** — which kinds the dispatcher can
run that are **not** in `ADMIN_INVOKABLE_TASK_KINDS`, and for each, what does
record its failure instead (a scan has its own vocabulary). Then skip the
append for those, with the reason stated where the skip stands, naming no
issue number.

**Do not widen `validate()`** to admit every `jobs.kind`. That weakens a
domain validation to fit a call site, and the call site is the thing that
should narrow.

## Two further constraints

**Emit only when the result write actually landed.** Both write paths go
through `surface_attempted_result_write`, and the write can be *refused* — the
fence is `AND attempts = $2`, and a refusal means this execution lost the row
to a later one. An audit record for a row another execution now owns is a
false record. Condition the append on the outcome saying the write landed.

**The append must never change the task's outcome.** The `jobs` row is the
operational record and the event is the audit record; an event-store failure
is logged and nothing else. Append after the result write, never before.

## Not in this unit

- **No ADR change.** ADR 0028 becomes *true* when this ships; that is the
  point. Do not edit it.
- **No new metric**, and no change to the worker's metrics listener.
- **No change to the subscription mapping** — it already knows the kind.

## Acceptance

- A production path constructs and appends `TaskFailed`; the
  `#[allow(dead_code)]` on the dispatcher's `event_store` is gone.
- Routing goes through `task_audit_stream`, with a test proving a destructive
  kind's `TaskFailed` lands on the same stream as its `TaskInvoked`.
- Both paths emit, with `final_attempt` correct for each, proven by test.
- A refused result write emits nothing, proven by test.
- An event-store failure leaves the task's outcome and the `jobs` row
  unchanged, proven by test.
- The kinds outside `ADMIN_INVOKABLE_TASK_KINDS` are censused untruncated in
  the report, and the skip is tested for at least one of them.
- The two doc sites that describe the emit as existing or future are corrected
  to the as-built state; `jobs_row_retention_sweep.rs`'s "only durable record"
  sentence is no longer true and is corrected too.
- `CHANGELOG.md` gets one entry: a failed admin task now writes an audit
  event, which subscribers to the task event types will begin receiving.
