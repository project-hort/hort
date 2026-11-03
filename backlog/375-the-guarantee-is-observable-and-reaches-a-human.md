# 375 — The guarantee is observable, and the observation reaches a human

**Issue:** #399 · **Branch:** `agent/399-reassignment` · item 4 of 4, depends on 374.

ADR 0066 D5: *"Every class is guaranteed service; the guarantee is observable;
and the observation reaches a human."* The ADR argues the last clause from the
evidence: both instances of this defect were found by a human noticing
latency, which is what makes an instrumented guarantee nobody is alerted on
documentation rather than a guarantee.

## What exists, and what it cannot see

`TaskDispatcher::audit_starvation`
(`crates/hort-app/src/task_dispatcher.rs:605`) already reads the
claim-eligible backlog for every kind, emits a per-kind gauge, and turns each
`detect_starvation` finding into an ERROR log plus a counter, with three
reasons — `unregistered`, `not_claimed`, `oldest_row_stalled`. That is a real
instrument and the starting point, not something to replace.

Two gaps, both consequences of 374's two points:

1. **It is per kind, and the guarantee is per class.** A kind that is being
   claimed steadily while one of its classes never is reads as healthy.
   `oldest_row_stalled` approximates this by age, which is the same wrong axis
   the reservation just stopped using.
2. **It cannot see point two at all.** A row waiting for a permit is already
   `running`, so it is not in the claim-eligible backlog by construction. The
   starvation 374 closes at the permit is invisible to the only instrument
   that would show it coming back.

## The third gap: the observation does not reach a human

The audit's output is a worker-side log line, an ERROR-level one, plus
worker-process metrics. Two facts about this deployment make that a dead end:

- the worker exposes **no HTTP surface** — a deliberate decision, not an
  omission — and `worker.metrics` is opt-in and off by default, so a
  worker-process gauge is not scrapeable in the default deployment;
- a process-local counter is lost on restart, which is exactly when a stall is
  being investigated.

**The precedent for the way out is in the tree and was built for the same
problem:** `emit_staging_sweep_liveness_signal`
(`crates/hort-server/src/composition.rs:406`) has `hort-server` sample a
durable fact out of the database on its own schedule — a last-completed
timestamp — evaluate it against a domain predicate
(`evaluate_staging_sweep_liveness`), and emit the verdict as a gauge on the
**server's** `/metrics`, where an operator's scrape already points. The
liveness decision is a pure domain function; the sampler is the composition
root's.

So: the per-class service guarantee is evaluated from a fact the database
already holds, and the verdict is emitted where a human's scrape reaches it.

## The outcome

1. **Per-class observability.** The audit reports, per class, whether the class
   is being served — and it is the same `TaskTier` definition that decides
   which class a row belongs to (ADR 0066 D6: one definition). Per-kind
   reporting stays; it answers a different question.
2. **Point two is visible.** A row that holds a claim and is waiting for a
   permit is counted somewhere, so permit starvation is observable rather than
   inferred from end-to-end latency.

   **This unit owes a debt from 378.** Once the lease renewal starts at the
   claim, `locked_until` alone no longer separates *queued* from *executing* —
   a deliberate trade, taken because the sweep only tests whether the owner is
   alive, and paid back here. So "counted somewhere" is not optional
   decoration: after 378 it is the **only** way to tell a row waiting for
   capacity from a row running a slow handler. #400's E111 entry records the
   same gap from the other side — the task-duration metric measures
   `handler.run` only, so the wait time appears in no metric today.
3. **The verdict reaches a scrape an operator already has**, following the
   sampler precedent: a durable fact in the database, a pure predicate, a
   gauge on `hort-server`'s `/metrics`. The worker-side log and counter stay
   as the local trail.
4. **The threshold is configuration with a default**, and the ADR already
   states the direction to err in: *"The guarantee in (5) will fire falsely
   the first time its threshold is set too low. That is the intended
   direction: a false alarm is recoverable, a silent stall is the failure
   being removed."* Do not tune it quiet.

## Acceptance

1. The service verdict is a **pure domain function** of the sampled facts,
   unit-tested without a database or a composed application —
   `evaluate_staging_sweep_liveness` is the shape to mirror.
2. A test per gap: a kind that is claimed steadily while one of its classes is
   not produces a finding; a class whose rows wait for permits produces one.
   Both red against the pre-change instrument.
3. The metrics catalog gains the new series with a description that matches
   what is measured. **Check it against the code rather than against the
   intent** — a catalog sentence that describes a different measurement than
   the code takes is a live defect in this tree (#400, item 2c), and this unit
   must not add a second one.
4. Nothing in this unit requires `worker.metrics` to be enabled to reach the
   operator. If some part does, say so plainly rather than describing the
   signal as available.
5. Every DB-backed test carries `#[serial(hort_pg_db)]`.
6. `CHANGELOG.md`: one entry — per-class queue service is observable on the
   server's metrics, with the knob named.

## Not in this item

- The reservation itself (374).
- Aging as a safety net, and deadline ordering.
- A notification channel. "Reaches a human" here means the signal is on a
  surface an operator already scrapes; routing it into an alert is the
  operator's own configuration, and the notification system's own staging
  verification is a separate open item (#331, E6).
