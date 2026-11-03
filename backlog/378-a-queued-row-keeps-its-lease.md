# 378 — A queued row keeps its lease

**Issue:** #399 · **Branch:** `agent/399-reassignment` · between 374 and 375.

Opened by unit 374's flag (a), which reported it rather than quietly shipping
the edge, and proposed the fix it did not take because it is a decision. This
is that decision, taken by the architect.

## What holds

The concurrency permit is granted in the dispatch loop
(`crates/hort-app/src/task_dispatcher.rs:620`, `pending_permit.granted().await`)
**before** `dispatch_one` is entered, and the lease renewal is started inside
it (`:984`, `spawn_lease_renewal`). So a row that has been **claimed** —
`status = 'running'`, `attempts` already incremented by the claim UPDATE, one
`locked_until` written at claim time — and is waiting for a permit holds a
lease that **nobody renews**.

`sweep_abandoned_leases` then requeues it after `lock_duration ×
(1 + LEASE_EXPIRY_GRACE_MULTIPLE)` — **30 minutes** at the defaults
(`HORT_SCANNER_LOCK_DURATION_SECS = 900`, multiple `1`). Each sweep costs the
row one attempt, and `HORT_SCANNER_MAX_ATTEMPTS` (default 6) makes the sixth
one a terminal `failed` row.

**It pre-exists**: the claim takes `batch_size` rows per poll regardless of how
many permits are free, and the shipped compose default is `batch_size = 4`
against a `scan` concurrency of **1** — so three of every four claimed rows
begin by waiting. What unit 374 changes is that the waiting is now
**systematic and concentrated**: the class-fair floor means that under
sustained waited-on load at a concurrency of one, the rows that wait are the
`Bulk` ones, by design rather than by luck.

## Why that is the wrong outcome

**An attempt budget bounds failing work.** A permit wait is not evidence about
the job — nothing was attempted, nothing was read, nothing failed. Spending the
budget on a scheduling delay condemns work for a scheduling reason, which is
the shape this project rejects elsewhere: only material that proved something
about the work may condemn it, and a queue position proves nothing.

For a scan row the consequence is not cosmetic. A terminal `failed` scan leaves
the artifact without the verdict that run was owed — and for the stranded-
artifact recovery the rescan tick drives (`quarantine_status IS NULL`), the
recovery itself is what goes terminal.

And it is not the trade ADR 0066 states. That decision's own consequence
section says bulk work "drains measurably slower, by construction" — **latency**
is the agreed cost. A permanent failure is not slower draining; it is a
different outcome.

## The decision

**The lease renewal starts when the row is claimed, not when the handler
starts.** `locked_until` means *a live worker owns this row*, not *a handler is
executing it*.

That is what the lease is actually for. `sweep_abandoned_leases` exists to
recover a row whose **worker died** holding the claim; a row waiting for a
permit is owned by a live worker that intends to run it, so renewing its lease
is truthful about the only thing the mechanism tests. Letting it lapse reports
a death that did not happen.

**What the change costs, and where that is paid.** From `locked_until` alone,
*queued* and *executing* become indistinguishable. That is an **observability**
distinction and not a recovery one — the sweep only needs "is the owner alive"
— and it belongs to the next unit (ADR 0066 D5), which has to surface
permit-waiting rows anyway: a row waiting for a permit is already `running`, so
it is invisible in the claim-eligible backlog by construction. #400's E111
entry records the same gap from the other side: the task-duration metric
measures `handler.run` only, so the wait time is in no metric today.

## Acceptance

1. **A claimed row waiting for a permit keeps its lease.** Withhold the permit
   past `lock_duration × (1 + grace)`, and assert the row is **not** requeued
   and its `attempts` did not move. Red before the change.
2. **Worker death is still detected.** With the renewal stopped — the guard
   dropped, the task gone — the sweep still requeues. The lease must not become
   unconditional; this is the test that keeps the fix from disabling the
   recovery path.
3. **The renewal still stops where it stops today.** `dispatch_one`'s property
   at `:980-983` — *"stop holding it the instant `run` returns … a renewal
   landing after it would be writing a lease onto a row that is no longer
   running"* — survives, and `lost_the_row()` is still read before the outcome
   write.
4. No change to `max_attempts`, to `LEASE_EXPIRY_GRACE_MULTIPLE`, or to the
   sweep's own predicate. The fix is **where the renewal starts**, nothing else.
5. The meaning of `locked_until` is written down where it is set and where the
   sweep reads it, including what it no longer distinguishes and which unit
   pays that back.
6. Every DB-backed test carries `#[serial(hort_pg_db)]`.
7. `CHANGELOG.md`: extend the existing `#399` `### Changed` entry with the
   operator-visible half — a queued task no longer spends an attempt while it
   waits for capacity. No second entry.

## Not in this item

- The queued-vs-executing observability (unit 375 / ADR 0066 D5).
- Aging, deadline ordering, and the shares themselves.
- The dispatcher's shape: claiming no more rows than there are free permits
  would also remove the wait, and it is a different design — the batch claim is
  *meant* to claim more than it runs at once (`batch_size = 4` against a
  concurrency of 1 is the shipped default). Not reopened here.
