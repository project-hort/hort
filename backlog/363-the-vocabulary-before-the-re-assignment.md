# 363 — The tier vocabulary, before anything re-ranks

**Issue:** #399 · **Branch:** `agent/399-task-tiers` · first of five units, no behaviour change.

**Governing decision:** [ADR 0066](../docs/adr/0066-background-work-never-outranks-a-waiting-client.md)
— D1, D2, D3, D7, D8. This unit builds the vocabulary and nothing else. D9 is
explicit that introducing the vocabulary and changing which class a path
belongs to are two changes and ship separately, so that a rollback of the fix
does not roll back the vocabulary.

## Why

The rank a queued task carries is retyped at each producer. Measured on
`cd6a35b6`, twelve named constants, with no shared type and no shared module:

```
ADVISORY_PRIORITY: i16 = 5                  advisory_watch_tick.rs
CRON_RESCAN_PRIORITY: i16 = 10              cron_rescan_tick.rs
CLEARANCE_VERIFY_PRIORITY: i16 = 10         ingest_use_case.rs
CRON_PRIORITY: i16 = 10                     enqueue_jobs_row_retention_sweep.rs
CRON_PRIORITY: i16 = 10                     enqueue_prefetch_row_retention_sweep.rs
CRON_PRIORITY: i16 = 10                     enqueue_prefetch_tick.rs
CRON_PRIORITY: i16 = 10                     enqueue_quarantine_release_sweep.rs
CRON_PRIORITY: i16 = 10                     enqueue_scan_row_retention_sweep.rs
CRON_PRIORITY: i16 = 10                     enqueue_wheel_metadata_backfill.rs
MANUAL_RESCAN_PRIORITY: i16 = 20            manual_rescan_use_case.rs
MANUAL_PRIORITY: i16 = 20                   seed_import.rs
CHILD_INGEST_ENQUEUE_PRIORITY: i16 = 0      oci_index_child_ingest.rs
```

plus roughly a dozen bare `priority: 0` literals at enqueue sites.

Nothing exists for a reviewer to check an assignment against. That is how
"maintenance outranks publishing" came to be written in several places
without ever reading as wrong: ingest scans sit at `0`, the lowest rank in
the system, while the cron rescans that nobody waits on sit at `10`.

## What this unit does

**Adds `TaskTier` to `hort-domain` and derives it from the row.** Per D2 the
tier is a property of the work item, derived from `(kind, trigger_source)` —
both already on the row, so there is no migration, no backfill and no new
column (D8). `trigger_source` is already constrained to
`('manual','cron','advisory','ingest')`
(`crates/hort-domain/src/ports/jobs_repository.rs:179`).

**Routes every producer through it.** No enqueue site names a number after
this unit (D7). The numeric column keeps existing and is written in exactly
one place, from a tier.

## The hard constraint: the numbers written do not change

This is what makes the unit behaviour-neutral and it is the part to get right.

The tier order and today's numeric order **do not agree** — that disagreement
*is* the defect ADR 0066 names, and fixing it is unit 367, not this one. An
ingest scan is `Interactive` and carries `0`; a cron rescan is `Bulk` and
carries `10`. So the single write site must map each
`(kind, trigger_source)` to **the number that site writes today**, not to a
number derived from its tier.

Concretely: after this unit, `SELECT kind, trigger_source, priority FROM jobs`
for newly enqueued rows is byte-identical to before. The tier is computed and
available; nothing consumes it yet.

**Acceptance for that constraint:** a test that pins, per producer, the
number written against the constant it writes today — so unit 367 has to
delete an assertion to change a rank, rather than changing one silently.

## Explicitly not in this unit

- **Reserved claim capacity** (D4) — unit 364.
- **The tier-aware execution permit** (D5) — unit 365.
- **The starvation guarantee's two corollaries** (D6) — unit 366.
- **The re-assignment** (D9) — unit 367, and the only one that changes a rank.
- **The band values and the weights.** ADR 0066 leaves both open, and with a
  single worker replica the share is the whole control surface, so they are a
  per-deployment concern rather than a constant. Nothing here needs them: this
  unit writes today's numbers.
- **The per-kind tier assignment for every kind.** Settled so far, by
  measurement: `advisory` is `Bulk`; `policy-reevaluation`,
  `replay-seen-prune` and `scanner-registry-prune` are `Normal`;
  `verify-event-chain` has **no tier at all**, rather than an unknown one — it
  is not dispatcher-runnable: there is no `TaskHandler` for it and no worker
  registration, and its `jobs` row is a liveness breadcrumb written directly
  by the `hort-server verify-event-chain` CLI subcommand
  (`hort-adapters-postgres/src/jobs_repository.rs:1226` calls it a
  "non-worker-dispatched run"). A tier is a property of work the dispatcher
  schedules, so this kind is outside the vocabulary rather than unassigned
  within it, and whoever writes unit 367 should not go looking for its
  runtime. The rest follow from runtime and from what
  waits on them, and the runtime half is
  `hort_admin_tasks_duration_seconds{kind}` — which is emitted on the
  **worker's** registry and therefore needs `worker.metrics.enabled` in the
  measuring deployment. That is a config change to propose, and it is a
  prerequisite for unit 364's weights, not for this unit.

## Acceptance

- `TaskTier` lives in `hort-domain` and is the only definition of a tier.
- Every enqueue site names a tier; `grep -rn "priority: " crates/*/src
  --include='*.rs'` finds no producer supplying a number, and the census is
  reported untruncated.
- The numeric column is written in exactly one place, from a tier.
- A test pins, per producer, that the number written equals the constant that
  site writes today — twelve named constants plus the bare-`0` sites.
- An exhaustiveness match over `trigger_source` with no wildcard arm, so a
  future value cannot silently acquire a tier.
- A row written by a binary that predates this unit still classifies: the
  derivation reads `(kind, trigger_source)` and never requires a value only a
  new writer would produce.
- `CHANGELOG.md` gets no entry — nothing an operator can observe changes.
