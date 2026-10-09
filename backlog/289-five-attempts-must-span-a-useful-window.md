# 289 — Five attempts must span a window in which exhaustion means something

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** ADR 0028 (a failed job row is persistent and
operator-visible; the cron schedule is the retry mechanism) · ADR 0016 (no new
configuration as the close).

Item 287 bounded the dispatcher's retries at five attempts, reusing the number
the abandoned-lease sweep and the scan orchestrator already share. That was
right. It also, without saying so, shortened the outage a job can survive from
**over a day to seven and a half minutes** — and this item is the other half of
that change.

## The arithmetic, measured

`compute_backoff(attempts)` in `task_dispatcher.rs` is
`DEFAULT_BACKOFF_SECS << (attempts - 1)`, with `DEFAULT_BACKOFF_SECS = 30` and
a `24 * 3600` ceiling:

| attempt | delay before the next one |
|---|---|
| 1 | 30 s |
| 2 | 60 s |
| 3 | 120 s |
| 4 | 240 s |

Five executions, four waits: **450 s — 7 m 30 s** from first failure to
terminal row. The scan orchestrator spends the *same five attempts* over
`60 + 300 + 1800 + 3600 s` = **96 minutes**.

Two consequences follow, and the second is the sharper one:

1. **A job whose failure mode outlasts eight minutes now dies terminally where
   it previously kept retrying.** For the tick kinds and the prefetch family
   that is harmless — a terminal row is the designed state there and the next
   tick or the next pull re-derives. For the destructive kinds it is the
   intent. It bites the **one-shot** kinds, which nothing re-enqueues:
   `seed-import`, `wheel-metadata-backfill`,
   `oci-membership-edge-backfill`, `service-account-rotation`,
   `eventstore-checkpoint`. A ten-minute database or upstream hiccup ends those
   permanently until an operator notices.
2. **The 24-hour ceiling in `compute_backoff` is now unreachable.** Reaching it
   needs about twelve attempts; the budget stops at five, so the largest delay
   the function can ever return is 240 s. A bound that cannot be reached is a
   stale mechanism of exactly the kind this block is clearing out — and it is
   also the evidence that the curve was written for an unbounded chain and was
   never revisited when the chain became bounded.

## The decision

**Adopt the scan orchestrator's curve shape, so the number and the window mean
the same thing wherever the number is used.** `1 min, 5 min, 30 min, 60 min`,
giving the same ~96-minute window for the same five attempts.

Why this rather than the alternatives:

- **Not a longer base with continued doubling** (e.g. 5 min → 75 min). It
  reaches a similar window but leaves two differently-shaped curves behind one
  shared constant, which is the thing that made this gap invisible in the first
  place.
- **Not a per-kind curve.** That is the kind table item 287 deliberately
  refused, for the same reason: an exemption surface nobody can audit.
- **Not a bigger cap.** The three budgets agreeing on five is a property item
  287 won; spending it to buy a window is the wrong trade when the curve is
  free.
- **No new configuration** (ADR 0016). The scan pipeline's window is already
  the house number for "how long do we tolerate a failing dependency"; this
  adopts it rather than inventing an operator surface.

The first retry moving from 30 s to 60 s is the whole cost, and it falls on a
job that has already failed once.

## What to do

1. Replace `compute_backoff`'s body with the four-step curve. Keep it a
   function of `attempts` with the same signature.
2. **Decide what happens to the 24-hour ceiling and say why.** It is
   unreachable either way; either drop it as dead, or keep it as an explicit
   guard with a comment stating that the budget, not the ceiling, is what
   bounds the chain. Do not leave it unexplained.
3. **Say where the shape now lives.** Two identical curves in two crates is the
   next stale-divergence waiting to happen. Either share one definition, or
   state in both docstrings that they are deliberately the same number and
   shape and must move together. Prefer sharing if it costs nothing structural;
   if sharing would make `hort-app` depend on something it should not, say so
   and take the documented-twin option.
4. Rewrite the docstring: what the window is, why it matches the scan
   pipeline's, and that five attempts spanning ~96 minutes is what makes an
   exhausted budget mean "persistently broken" rather than "unlucky for eight
   minutes".

## Explicitly out of scope

- The cap itself (five, shared, uniform across kinds — item 287's decisions
  stand).
- Any new configuration knob or per-kind curve.
- `return_to_pending` charging an attempt without executing a handler —
  recorded separately as a found defect with impact and triage.
- The scan orchestrator's own curve, which is the reference, not the subject.

## Behaviour change to surface in the report

The window a failing job survives moves from 7 m 30 s to ~96 minutes; the
number of executions does not change. An operator watching the job table sees a
row stay `pending` with a growing `locked_until`/retry delay for an hour and a
half before it goes `failed`, where it previously went `failed` in under ten
minutes.

## Acceptance

- A test pinning each of the four delays by value, so the window is a fact in
  the suite and not an inference from a shift expression.
- A test that the exhaustion point is still the fifth execution (the cap is
  untouched).
- Whatever you decide about the ceiling is pinned by a test or removed.
- The diff adds no uncovered lines.
- Gate green, one-shot capture, exit codes separate from the output.
  `cargo test --workspace` as one invocation with `DATABASE_URL` set:
  background it, wait in your own turn until the exit code is in hand, and
  touch no source file between launch and completion.
