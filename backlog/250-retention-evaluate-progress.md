# 250 — the evaluation restarts at the beginning of the keyset every run

**Issue:** #322 · **Branch:** `agent/322-retention-evaluate-progress`
**Governing decisions:** none found that governs per-tick progress over a
large table; the cron-rescan single-shot cap is the cited precedent and is
what the current code copied.

## Why

`RetentionEvaluateHandler` walks at most `MAX_BATCHES_PER_TICK * BATCH_SIZE`
= 64 × 1000 = **64,000** rows per tick
(`crates/hort-app/src/task_handlers/retention_evaluate.rs:63,70`). The cursor
is re-initialised to `None` on **every** invocation (`:268`), and
`list_candidates` is keyset-paginated by `artifacts.id` with
`($3::uuid IS NULL OR a.id > $3)` and `ORDER BY a.id`
(`crates/hort-adapters-postgres/src/retention_candidate_reader.rs:268-269`),
selecting live rows without excluding ones already evaluated.

So every tick walks the same first 64,000 ids and stops. The comment at
`:67` claims *"subsequent daily ticks drain the rest"*. That is only true if
the candidate set shrinks — which requires the leading rows to expire **and**
be purged. With purge disabled (the shipped default) the set never shrinks and
the tail is never reached.

**Failure scenario.** The 64,000 lowest eligible ids are too young for
`AgeExceeds`; artifact 64,001 is old enough. Every daily run re-reads the same
prefix, reports `partial` coverage, and never evaluates 64,001. The policy is
permanently inert for the tail of the registry, with no error signal — the run
reports success.

This matters independently of physical byte deletion: it breaks **logical**
retirement, which ships regardless of the CAS-ownership work.

The existing test (`:1584`,
`batch_ceiling_is_reported_as_partial_coverage`) asserts only that *one* run
reports `partial`. It cannot see this defect.

## What has to hold

- Progress **survives the run**: consecutive ticks advance rather than repeat.
- Over successive ticks every eligible artifact is eventually evaluated, and a
  full pass wraps back to the beginning rather than stopping at the end.
- The per-tick bound stays — one tick must still not walk the whole table.
- The comment describes what the code does.

The mechanism is the implementer's call, argued in the report. A persisted
cursor is the obvious candidate; excluding already-evaluated rows via a
per-artifact watermark is the other, and it costs a write per artifact.
Note that `artifacts.id` ordering is UUID order, so "resume where we stopped"
walks UUID space, not time — a new artifact may sort before or after the saved
cursor. Coverage therefore comes from the wrap, not from ordering.

State explicitly what happens when the candidate set changes between ticks:
keyset pagination over a mutable set can skip or repeat a row. Skipping is
acceptable here (the next pass catches it) but must be a stated property, not
an accident.

## Acceptance

- A test that drives **two** ticks and asserts the second sees rows the first
  did not. The existing single-run cap test stays.
- A test for the wrap: after the last page, the next tick starts again.
- The stale comment is corrected.
- Gate green.
