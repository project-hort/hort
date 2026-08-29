# 143 — Verify cron_rescan_tick under persistent scan failure

Issue: #213. **This is a verification item** — it closes with evidence, or
its findings spawn fix issues. Deliverable: a findings report (handover
report; the architect transfers it to the issue), plus DB-free tests ONLY
where they pin down semantics cheaply. No speculative fixes in this item.

Two questions on `crates/hort-app/src/task_handlers/cron_rescan_tick.rs` +
`crates/hort-adapters-postgres/src/rescan_candidates.rs`:

## Q1 — does a FAILED scan advance `last_scan_at`?

If not, a permanently-failing artifact re-qualifies immediately every tick.
Combined with the candidacy query having **no ORDER BY** (arbitrary but
in-practice heap-order-stable selection), a > batch-size persistently-failing
subset can probabilistically monopolize the 1000-row selection — the soft
cousin of the quarantine-sweep starvation. Establish the actual
projection-update semantics: does a scan failure produce a `ScanCompleted`
event (updating the projection) or a job-level failure with no event?
Follow the full path: tick → enqueue → scan job handler → event → projection.

## Q2 — scanner-outage accumulation

Candidacy excludes artifacts with `pending`/`running` scan jobs; a failed
job releases the artifact back into candidacy. With a dead scanner, does the
tick re-enqueue up to `BATCH_SIZE` fresh job rows every 5 minutes (unbounded
`jobs`-table growth), or does job-level retry/backoff hold rows in
`pending`? Establish the real job lifecycle (state machine of a failed scan
job, retry policy, terminal handling) and its growth bound.

## Also (low-risk note from the audit)

`staging_sweep` `MAX_PER_TICK = 1000` is self-consuming and only jams if the
same head-of-list deletions fail persistently — confirm deletion-failure
handling logs loudly. Nothing more.

## Read first

- `crates/hort-app/src/task_handlers/cron_rescan_tick.rs`
- `crates/hort-adapters-postgres/src/rescan_candidates.rs`
- The scan job handler + its failure path (follow the enqueue kind)
- `crates/hort-app/src/task_handlers/staging_sweep.rs` (the side note)

## Acceptance

- Per question: a verdict — "sound, here's why" with code-path evidence
  (file/function chain), or "defect, here's the failure scenario" with the
  concrete starvation/growth mechanism, each backed by the actual event/
  projection/job-lifecycle behavior (not inference from names).
- Where a DB-free unit test can pin the load-bearing semantics (e.g. "failed
  scan does/does not update the projection"), add it; skip tests that would
  need a live scanner.
- Report the verdicts in the handover report; do NOT open issues yourself
  (no GitLab access) — the architect spawns any fix issues from the report.
