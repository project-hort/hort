# 416 — One retry for both halves of the audit trail

**Issue:** #426 · **Branch:** `agent/426-one-retry-for-both-halves` ·
the only item. **No ADR change, no migration.**

**Governing decisions:** ADR 0002 (the stream is the record), ADR 0028
(durable per-UTC-day idempotency for destructive kinds — why the loss window
is narrow), ADR 0008 (the helper belongs where both callers can reach it
without inverting the layering). No new decision.

## The property

**A pair of events deliberately written to one stream must have one
durability promise, not two.**

`TaskInvoked` and `TaskFailed` are placed on the **same** stream on purpose,
so the two halves read as a single trail — and they resolve it through the
same helper: `TaskUseCase::task_audit_stream(kind)`
(`crates/hort-app/src/use_cases/task_use_case.rs:276-282`) routes a
destructive kind to `StreamId::eventstore_retention()` and every other kind
to `StreamId::authorization()`. Both append with `ExpectedVersion::Any`.

**Only one of them retries.** Verified on `develop` 2026-11-09:

- `TaskInvoked` wraps its append in a bounded CAS retry —
  `TASK_AUDIT_APPEND_RETRY_ATTEMPTS = 5`
  (`task_use_case.rs:99`), the loop at `:430-462`, which retries on
  `DomainError::Conflict` and logs a distinct warning when the budget is
  exhausted.
- `TaskFailed` has none: the dispatcher's append is a bare
  `if let Err(e) = self.event_store.append(append).await`
  (`crates/hort-app/src/task_dispatcher.rs`, the `TaskFailed` append in the
  audit-record helper), and a conflict is a log line.

`ExpectedVersion::Any` is **not** a guarantee of success — it is why the
retry exists at all: an append can still lose a race at the stream tail. So
under contention a `TaskFailed` can be lost where its paired `TaskInvoked`
would have been retried, and the loss appears **only as a log line**.

## Why this is a unit and not a two-line patch

The finding was reported rather than fixed, deliberately, and its reasoning
is the item's shape: **a second copy of the loop is the wrong answer.** It
would be a duplication finding on its own, and it would put the same promise
in two places where a later change can move one and not the other.

So: **one shared helper, used by both call sites.** Then both halves carry
the same promise and there is exactly one place where the retry budget is
stated. That is also what makes the budget reviewable — today the number
lives next to one caller and is invisible from the other.

**Placement.** `TaskFailed`'s append is in `hort-app`'s dispatcher and
`TaskInvoked`'s in a `hort-app` use case, so a shared helper stays inside
`hort-app` and needs no port and no layering change. Do **not** reach for the
stream helper's home as the automatic answer — `task_audit_stream` is an
associated function on `TaskUseCase`, and making the dispatcher depend on the
use case for a retry loop would couple a dispatcher to a use case for no
reason. Put the helper where both can call it without either depending on the
other, and say in the report where that was and why.

## What this is not

**Not a widening of the loss window's significance.** The honest size, from
the finding itself: contention on these streams is low (an admin-task
failure, not a request-path append), and a destructive kind runs at most once
per UTC day per kind under ADR 0028. The reason it still counts is the
**promise**, not the frequency: one half that can vanish under load while the
other is retried undermines "both halves are one trail", and it undermines it
silently.

Do not use this item to add retries elsewhere, to change
`ExpectedVersion::Any` on either append, or to introduce a general
append-retry policy. One helper, two callers, same promise.

## Acceptance

- Both appends go through **one** helper; `TASK_AUDIT_APPEND_RETRY_ATTEMPTS`
  (or its successor) is stated in exactly one place, asserted by a test or a
  grep whose result the report quotes.
- A conflict on the `TaskFailed` append is retried and then succeeds — driven
  by a double whose first N appends return `Conflict`, so the retry is
  observed rather than inferred.
- The exhausted-budget path on `TaskFailed` logs and does not panic, and the
  dispatcher's outcome is unchanged by it: a lost audit append must not change
  the job's result state. Asserted, because that is the one way this change
  could make things worse.
- `TaskInvoked`'s existing behaviour is unchanged — same budget, same
  exhausted-budget warning. Its existing tests pass untouched.
- Neither append's `ExpectedVersion` changes.
- Gate green; no uncovered added lines; no ticket numbers in code comments.
