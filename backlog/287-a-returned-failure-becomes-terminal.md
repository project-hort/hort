# 287 — A returned failure becomes terminal

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** ADR 0028 (destructive-task idempotency: the cron
schedule is the retry mechanism, and a failed row is **persistent and
operator-visible**).

## What is true today

`TaskDispatcher` calls `reschedule` for **every** `TaskOutcome::Failed { retry:
true }` and every handler `Err`, with no reference to `job.attempts` and no
reference to the kind (`crates/hort-app/src/task_dispatcher.rs`, the
`TaskOutcome::Failed { retry: true }` arm). `compute_backoff(job.attempts)`
bounds the *delay* at 24 hours; it bounds nothing else. So a job that fails the
same way forever is re-driven forever and **never becomes the terminal failed
row ADR 0028 describes to the operator.**

The one attempt cap in the system's job plumbing is
`LEASE_REQUEUE_ATTEMPT_CAP` (`task_dispatcher.rs:212`, value `5`), passed to
`job_repo.requeue_abandoned(...)`. That path only ever sees rows whose worker
died — and the constant's own docstring says so:

> It has to live here because the sweep is the only code that runs for such a
> row: the scan orchestrator's `attempts >= max_attempts` branch and the
> dispatcher's `TaskOutcome::Failed` arms both require the handler to return,
> which is precisely what did not happen.

The comment is correct about the sweep and names the gap in the same breath.
That is this block's lens: the knowledge is present, accurate and local.

Three destructive handlers return `retry: true` on a top-level failure —
`task_handlers/retention_purge.rs`, `eventstore_archive.rs`, and retention
evaluation on page-selection or evaluation failure. Purge can fail on a later
page *after earlier pages have already done work*, so the same accepted
destructive job can run again the same day. The daily unique key prevents a
second **enqueue**; it does not limit executions of the row that already
exists.

## The decisions, so the unit is not open-ended

1. **Reuse the existing number, do not invent one.** The cap is `5`, the value
   `LEASE_REQUEUE_ATTEMPT_CAP` already carries because it was set to the scan
   pipeline's own default (`HORT_SCANNER_MAX_ATTEMPTS`). A third budget would
   be the "N sites, N answers" smell this project rejects; after this change
   the scan orchestrator's branch and the dispatcher's agree instead of
   disagreeing. **No new configuration knob** — ADR 0016's rule, and the
   operator surface for scan attempts already exists.
2. **The cap is uniform across kinds. Do not add a kind list.**
   `REQUEUE_ON_LEASE_EXPIRY_KINDS` exists for a different question — which
   kinds are safe to re-drive after a *crash*, where a concurrent second
   execution is absorbed by nothing. A returned failure has no in-flight
   duplicate to fear, because the handler returned. Carrying that list over
   would answer the wrong question and create an exemption table nobody can
   audit.
3. **At the cap, the row becomes terminal the same way the sweep's cap path
   makes it terminal.** One behaviour, two triggers. Establish what that path
   does (`requeue_abandoned`'s over-cap arm) and reuse it, rather than writing
   a second terminal transition; name it in the report.
4. **The constant stops being about the sweep.** Rename it for what it now
   governs and rewrite the docstring — the sentence quoted above becomes false
   the moment the dispatcher consults it, and leaving it would be exactly the
   stale-comment shape this block is clearing up.

## Explicitly out of scope

- `retry: false` outcomes, which are already terminal.
- The scan pipeline's own `max_attempts` surface and its env var.
- The backoff curve, the 24-hour ceiling, the lease duration, the sweep's kind
  list.
- Per-item purge/archive failures handled inside their own sweeps — the claim
  is about the *job* outcome, not about per-artifact errors.
- Any new configuration.

## Behaviour change to surface in the report

A persistently failing job of **any** kind now stops being re-driven after the
fifth attempt and becomes a terminal `failed` row with its last error — where
it previously retried until someone noticed. That is ADR 0028's described
model, and it is a change an operator watching the job table will see.

## Acceptance

- A test that a handler returning `Failed { retry: true }` on a row already at
  the cap is **not** rescheduled and the row is terminal with its last error.
- A test that the same handler below the cap **is** still rescheduled, with the
  existing backoff — the fix must not turn the first failure into a dead row.
- A test for at least one of the three destructive kinds specifically, since
  they are the reason the finding is rated as it is.
- No comment still claims the dispatcher's `Failed` arms cannot reach an
  attempt cap.
- The diff adds no uncovered lines.
- Gate green, one-shot capture, exit codes separate from the output.
  `cargo test --workspace` as **one** invocation with `DATABASE_URL` set:
  background it, then wait in your own turn until the exit code is in hand, and
  touch no source file between launch and completion.
