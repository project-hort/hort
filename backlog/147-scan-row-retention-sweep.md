# 147 — scan-row-retention-sweep: GC terminal `kind='scan'` jobs rows

Issue: #216 (finding from the #213 verification).

Terminal `kind='scan'` rows accumulate unbounded: each stranded-requeue
exhaustion cycle leaves a permanent `failed` row (~1 per artifact per
96 min during a scanner outage), and every successful scan — including
every periodic rescan — leaves a `completed` row forever. The only jobs
sweep is scoped `kind LIKE 'prefetch%'`.

**Governing decisions:** `prefetch_row_retention_sweep` precedent
(mirrored, not generalized) · ADR 0030 (eventstore-retention allowlist
untouched — jobs-table sweeps are a separate mechanism; say so in the
module doc) · the #213 Q1 verdict (stranded self-healing is deliberate —
no churn bound; the horizon bounds outage accumulation).

## Read first

- `crates/hort-app/src/task_handlers/prefetch_row_retention_sweep.rs` —
  the handler to mirror exactly (params shape, default horizon, posture
  rationale in the module doc).
- The adapter method behind it
  (`delete_terminal_prefetch_rows_older_than` in
  `crates/hort-adapters-postgres/src/jobs_repository.rs`) — the deletion
  SQL shape to mirror.
- `crates/hort-adapters-postgres/src/rescan_candidates.rs` — the candidacy
  queries whose neutrality you re-verify (see Acceptance).
- The Helm CronJob template for the prefetch sweep
  (`deploy/helm/hort-server/templates/`) — the chart shape to mirror.
- `migrations/009_scan_jobs_and_findings.sql` (the status CHECK and the
  verify-event-chain checkpoint comment — why the kind scope is exact).

## Confirmed design

New `scan-row-retention-sweep` TaskHandler + port method + Helm CronJob,
mirroring the prefetch sweep exactly:

```sql
DELETE FROM public.jobs
 WHERE kind = 'scan'
   AND status IN ('completed', 'failed')
   AND updated_at < now() - $horizon
```

- Params `{"horizon_seconds": N}`, optional, default 7 days (same
  constant-and-field pattern as the precedent).
- **`kind = 'scan'` exactly** — other kinds keep their newest terminal row
  as durable state (verify-event-chain's chain checkpoint); the module doc
  states this invariant.
- Both terminal statuses; `pending`/`running` never touched.
- No churn bound, no behavior change to scan/candidacy semantics.
- Helm CronJob mirroring the prefetch sweep's (schedule knob in the
  `scheduledTasks.*` values block, default enabled, values.schema.json
  entry).

## Acceptance

- DB-gated integration test (`#[serial(hort_pg_db)]` — mandatory): seeds
  aged + fresh terminal scan rows, a pending and a running scan row, an
  aged terminal `verify-event-chain` row, an aged terminal prefetch row ⇒
  exactly the aged terminal `scan` rows are deleted; foreign kinds and
  non-terminal rows untouched.
- Handler unit tests (mock port): params parsing, default horizon,
  summary shape — mirroring the precedent's suite.
- **Candidacy-neutrality re-verified in the report**: deleting a stranded
  artifact's terminal failed row flips `select_stranded`'s predicate from
  `status='failed'` to `IS NULL` — same selection; `select_eligible` reads
  only pending/running existence + `artifacts.last_scan_at`. Confirm
  against the current queries and state the file/line evidence.
- Chart: template renders with defaults, disable knob works
  (helm-template-test rows).
- Comment discipline: invariants (esp. the exact-kind scope), no issue
  refs.
