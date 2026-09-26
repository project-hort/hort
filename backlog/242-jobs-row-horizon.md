# 242 — `public.jobs` grows without bound, and the newest terminal row per kind is state

**Issue:** #297 · **Branch:** `agent/297-jobs-row-horizon`
**Governing decisions:** ADR 0020 (eventstore retention — the `events` half,
deliberately **not** built here) · #280 (the measurements) · #281 (the finding:
"accounting, not artifacts").

## Why

`public.jobs` has no general horizon. #280 counted **~83,000 terminal rows** on
the production instance. Two kind-specific sweeps exist and cover three kinds
between them:

- `delete_terminal_prefetch_rows_older_than` — `kind LIKE 'prefetch%' OR kind =
  'oci-index-child-ingest'`, `status IN ('completed','failed')`, `updated_at <
  now() - interval`.
- `delete_terminal_scan_rows_older_than` — `kind = 'scan'`, same shape.

The `jobs_kind_check` constraint in `migrations/024_…` admits **26 kinds**. The
other ~22 accumulate forever. This is neither CAS nor evidence under Invariant
1 — it is accounting, and accounting needs a horizon, not a policy vocabulary.

## The trap a naive horizon springs

**The newest terminal row per `kind` is state, not garbage.**
`JobsRepository::record_run_completion`
(`crates/hort-adapters-postgres/src/jobs_repository.rs:899`) writes a terminal
row purely as a liveness breadcrumb for recurring, non-worker-dispatched runs,
and `last_completed_at_by_kind` (:843) reads the newest one back.

**There are two such gauges, not one.** The issue named only the second:

| kind | gauge | default expected interval |
|---|---|---|
| `staging-sweep` | `hort_staging_sweep_overdue` | **300 s** (`HORT_STAGING_SWEEP_EXPECTED_INTERVAL_SECS`) |
| `verify-event-chain` | `hort_event_chain_verify_overdue` | 86400 s (`HORT_EVENT_CHAIN_VERIFY_EXPECTED_INTERVAL_SECS`) |

Both read through `run_staging_sweep_liveness_check` /
the event-chain equivalent in `crates/hort-server/src/composition.rs` (:1199,
:1242), both at boot, both with a staleness multiplier of 3.

The 300-second one is the sharper case, and it inverts the intuition: while the
sweep is **healthy** its newest row is minutes old and nowhere near any
horizon. The newest row only ages past a horizon **during an outage** — which
is exactly when the gauge has to fire. A horizon that collects it turns a
long outage into a *quieter* signal than a short one. Establish what
`evaluate_staging_sweep_liveness` does with `None` before choosing anything;
that answer decides how bad the naive version is.

So: **"keep the newest per `kind`" is not a refinement — it is the condition
under which this unit may be built at all.**

## What to do

1. **Enumerate the consumers of `jobs`-as-state, completely.** Two are verified
   above. #280 additionally names the keyset cursor for `prefetch-tick`. The
   list is to be **compiled, not inherited** — an incomplete list here is the
   same as no list. Look for two shapes, not one:
   - `last_completed_at_by_kind`-style reads of the newest terminal row;
   - any `ORDER BY … LIMIT 1` over `jobs`. The exemplar is
     `crates/hort-adapters-postgres/src/rescan_candidates.rs:232`, whose
     `LEFT JOIN LATERAL (… ORDER BY j.created_at DESC LIMIT 1) last_job` makes
     the *latest* terminal `scan` row decide whether an artifact is a rescan
     candidate. That one is outside this unit's kinds, but it is the read shape
     to hunt for — and it shows the failure mode: deleting the newest
     `completed` row while an older `failed` row survives silently flips the
     predicate.
2. **Build a generic horizon** that does not duplicate the two kind-specific
   sweeps, closes the gap for the remaining kinds, and carries the clause from
   point 1.
3. **Abandoned `staging-sweep` runs** (carried from #281). Note what this is and
   is not: the `.staging` *directory* (`<root>/.staging/`, `.tmp.<uuid>`
   orphans in the filesystem storage adapter) is already swept — that is what
   the `staging-sweep` task itself does, via `StatefulUploadStagingPort`. What
   is **not** handled is a `staging-sweep` **job row** left non-terminal after a
   crash. At a 5-minute cadence this kind is also the highest-churn unswept kind
   in the table (~288 rows/day). Both existing sweeps key on
   `status IN ('completed','failed')`, so **no terminal-row horizon reaches an
   abandoned `running` row** — and no reaper for those exists in any kind today.
   Deleting a `running` row is not symmetric with deleting a terminal one: it
   may be genuinely running. Say how you tell the difference, or say why you are
   not touching them.

## To decide

- **The horizon.** The two existing sweeps stand at 7 days. The same value is
  the obvious choice and still needs an argument — these rows are the only trace
  of a run that went wrong.
- **Where it runs.** Another CronJob in the established family, or an extension
  of an existing sweep. The family is established; deviating needs a reason.
  A new kind means a new `jobs_kind_check` migration — check whether the
  chosen shape needs one before assuming it does not.
- **Whether `events` belongs here.** It does not. #280 names 302 MB and
  +150–180k/month, and the machinery already exists
  (`eventstore_retention_use_case`, ADR 0020) — it is simply not configured on
  that instance. **A configuration task, not a build task.** Named here only so
  it is not lost.

## Acceptance

- The consumer list is compiled and in the report, with the query per consumer.
- The sweep keeps the newest terminal row per `kind`, with a test that checks it
  **through the consumer** (`last_completed_at_by_kind`), not merely by row
  count.
- A test showing **both** liveness gauges are unchanged across a sweep, not just
  the event-chain one.
- The horizon is argued, not copied from the neighbours.
- Abandoned `staging-sweep` rows are either handled or explicitly and
  argumentatively excluded.
- Gate green; `#[serial(hort_pg_db)]` on every DB-backed test.

## Explicitly not in this item

- No `events` retention work, and no configuration change for it.
- No change to the two existing kind-specific sweeps' predicates or horizons.
- No reaper for abandoned rows of kinds other than `staging-sweep`, unless the
  enumeration shows the same mechanism covers them for free — in which case say
  so rather than widening quietly.
