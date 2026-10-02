# 230 — The preview's simulation bound is guessed, and it sits under the case that motivated it

**Issue:** #290 · **Branch:** `agent/290-simulation-bound`
**Depends on:** #283 (merged) — it introduced the bound.
**Governing decisions:** the concept's D2 · ADR 0054 (rows are not bytes) ·
#283's rule that a byte figure is simulated or omitted, never estimated.

## Why

`MAX_SIMULATION_ARTIFACTS = 10_000` and `MAX_SIMULATION_TARGETS = 10_000`
(`crates/hort-app/src/task_handlers/retention_evaluate.rs:74-75`) bound the byte
simulation; beyond either, the figure is reported as `omitted`.

Omitting is the right direction — a plausible wrong number against 142 GB is
worse than none. Three things about the bound are not right:

1. **It sits under the motivating case.** `KeepLastN(20)` over a repository with
   36 894 artifacts is why the preview exists at all. The first real preview
   against that repository reports `omitted`, so the preview does not deliver
   there what it was built for.
2. **It was chosen without measurement.** Both constants are `10_000` — a round
   number, not an established one. The cost plausibly scales with the number of
   target edges rather than with the artifact count, but that too is currently
   a guess.
3. **The omission is not actionable.** It says the figure was omitted, not
   *which* bound was exceeded, how high it stands, or what was counted. An
   operator holding 36 894 artifacts in scope cannot tell whether narrowing the
   scope brings the number back.

## Read first

- `crates/hort-app/src/task_handlers/retention_evaluate.rs:60-90` — the
  constants and where they are passed.
- `crates/hort-adapters-postgres/src/retention_preview.rs` — the statement whose
  cost is being bounded, and the shape it returns.
- `crates/hort-domain/src/ports/retention_preview.rs` — the port, including the
  `Omitted` variant and its reason.
- `crates/hort-adapters-postgres/src/purge_gc.rs` — the edge set the simulation
  mirrors, so you can judge which dimension actually drives the cost.

## Scope

1. **Measure, do not guess.** Run `reclaimable_content` against a realistic
   corpus — the order of magnitude of the largest production repository, so
   roughly 40 000 artifacts with their edges — and report the wall time. Build
   the corpus in a throwaway database the way the existing DB tests do. The new
   bounds are derived from that measurement, and the measured figure goes into
   the constants' doc comment as the justification.
2. **Establish which bound is the load-bearing one.** If the cost tracks target
   edges rather than artifact count, the tight bound belongs there and the
   artifact bound can be generous. Decide this from the measurement, not from
   the shape of the query.
3. **The omission names the bound it hit**, its configured value, and the
   observed count. Without that an operator cannot tell whether a narrower scope
   helps.
4. **A ceiling stays.** This is not about removing the bound: an unbounded run
   can tie up the database, and a preview that disturbs production is not worth
   its price. It is about the bound being established and placed where it does
   something.

## Acceptance

- The measurement is in the report: corpus size, edge count, wall time, and the
  bounds derived from it.
- The constants carry their justification in code, with the measured order of
  magnitude — not "seems reasonable".
- A preview over the order of magnitude of the largest production repository
  returns a byte figure rather than `omitted`, **or** the report argues from the
  measurement why it should not.
- The omission names the bound, its value and the observed count; a test pins the
  message.
- No estimated byte figure is introduced. Omission stays the honest outcome — it
  just becomes rarer and more informative.
- Gate green; DB-backed tests carry `#[serial(hort_pg_db)]`; no issue, MR or
  backlog numbers in code comments.

## Explicitly not in this item

No change to *what* is simulated — #283's edge set stands. No runtime
configurability: a constant with an established value is enough until something
measured says otherwise. No CLI rendering changes beyond what the new omission
message carries (#289 owns the surface).
