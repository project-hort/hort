# 254 — The sweep family: ten false route claims, an invented index, a missing timer, one shared horizon

**Issue:** #308 · **Branch:** `agent/308-sweep-family-corrections`
**Governing decisions:** ADR 0009 (DB-only subcommands parse `MinimalConfig`, not the
serve surface) · ADR 0028 (per-UTC-day idempotency for destructive kinds) · #297 (all
findings, flags F3/F4/F6/F7).

## Why these belong in one unit

Four defects plus one carried-in fifth, all in the same two file pairs
(`scan_row_retention_sweep` / `prefetch_row_retention_sweep` and their CLI and chart
files). They touch the same lines; three separate passes would cost more than one.

## A — `horizon_seconds` is a parameter no supported path can set

Ten places claim a way to set the retention horizon. None of them works.

Nine claim `hort-cli admin task invoke <kind>`. `hort-http-admin-tasks::router()`
enumerates its invoke routes one by one and there are **11** (`noop`,
`cron-rescan-tick`, `advisory-watch-tick`, `retention-evaluate`, `retention-purge`,
`eventstore-archive`, `staging-sweep`, `service-account-rotation`,
`eventstore-checkpoint`, `replay-seen-prune`, `scanner-registry-prune`).
`ADMIN_INVOKABLE_TASK_KINDS` has 23 members; for the other 12,
`POST /api/v1/admin/tasks/<kind>` answers 404. The nine:

- `crates/hort-server/src/cli/enqueue_scan_row_retention_sweep.rs`
- `crates/hort-server/src/cli/enqueue_prefetch_row_retention_sweep.rs`
- `deploy/helm/hort-server/templates/cronjob-scan-row-retention-sweep.yaml`
- `deploy/helm/hort-server/templates/cronjob-prefetch-row-retention-sweep.yaml`
- `deploy/helm/hort-server/values.yaml`, five `scheduledTasks` blocks
  (`quarantineReleaseSweep`, `prefetchTick`, `prefetchRowRetentionSweep`,
  `scanRowRetentionSweep`, `wheelMetadataBackfill`)

The tenth is `crates/hort-app/src/task_handlers/scan_row_retention_sweep.rs:39` —
"The Helm CronJob writes the value the operator chose". The CronJob runs
`hort-server enqueue-scan-row-retention-sweep`, which writes `params` unconditionally
empty. There is no chart value and no flag behind it.

So `horizon_seconds` cannot be set, and `MAX_HORIZON` caps a value nothing moves.

**Note that `ADMIN_INVOKABLE_TASK_KINDS` is NOT the router's list** and must not be
narrowed to match it. It is the set of kinds an admin may enqueue at all, including
the DSN-direct path; it is consumed by event validation and by handler-level
assertions (`jobs_row_retention_sweep.rs:320`,
`oci_membership_edge_backfill.rs:675`). The router being a subset is legitimate.

### Decided — correct the claims, add nothing

All ten places state the truth: **there is no supported way to set the retention
horizon per invocation today.** Every supported path — the Helm CronJob, the systemd
timer, a bare `hort-server enqueue-*` run — enqueues with empty `params`, so
`DEFAULT_HORIZON` is the horizon in force, always.

No HTTP invoke routes, and **no `--horizon-seconds` flag either.** An earlier draft of
this item added one, with a chart value behind it. That was requirement expansion
dressed as a bug fix: the defect is ten comments that lie, and making them honest
costs ten edits. Whether an operator ever needs a per-invocation horizon is a
question for an operator who has it, not for this unit.

`horizon_seconds` and `MAX_HORIZON` stay as they are. The param is reachable by the
handler and no supported path supplies it; say that where the param is defined,
rather than removing a mechanism nothing is hurting.

## B — Both handlers justify `MAX_HORIZON` with an index that does not exist

`prefetch_row_retention_sweep.rs` and `scan_row_retention_sweep.rs` both say a wider
horizon "falls out of the `updated_at` index". **No migration creates an index on
`jobs.updated_at`.** What exists: `jobs_scan_unique`, `jobs_claim_idx`,
`jobs_prefetch_unique`, `jobs_prefetch_dependencies_unique`, `jobs_idempotency_key_uq`
(009), `idx_jobs_scan_artifact_created_at` (015). All three sweeps are sequential
scans, which at this table size and daily cadence is the right shape; the 365-day cap
stands on its other stated reasons. Only the justification is invented, and an
invented justification is worse than none.

## C — The non-k8s deploy has no scan-row sweep at all

`deploy/ansible/roles/hort_timers/defaults/main.yml` lists seventeen timers after
#297 — including `quarantine-release-sweep`, `prefetch-row-retention-sweep`,
`jobs-row-retention-sweep` and `staging-sweep` — but **not
`scan-row-retention-sweep`**. It is the only default-on chart CronJob with no systemd
equivalent. This is a functional gap, not a documentation gap: on a non-k8s deploy,
terminal `scan` rows are never reclaimed.

## D — The sweep handler body stands three times

Params parse, horizon resolve and cap check are near-verbatim in three handlers. In
#297 that was correct — the instruction was to mirror the established family, and that
change added only the second copy. At three, extract
`resolve_sweep_horizon(kind, params, default, max) -> Result<Duration, TaskOutcome>`
and use it from all three.

## E — The `prefetch-tick` rotation cursor sits in the cascade sweep with no keep-newest clause

`delete_terminal_prefetch_rows_older_than` matches `kind LIKE 'prefetch%'`, which also
catches **`prefetch-tick`**. That kind's keyset rotation cursor lives in the
`result_summary` of its newest `completed` row and is read back through
`last_result_summary_by_kind` (`WHERE … status = 'completed' ORDER BY completed_at
DESC LIMIT 1`) by `PrefetchTickHandler::read_cursor`. The cascade sweep deletes
terminal `prefetch-tick` rows with no keep-newest clause.

An instance whose `prefetch-tick` CronJob was off longer than the horizon — it is
disabled by default — or failing loses the cursor, and rotation restarts from the
beginning. On a large instance the tail packages then come up rarely or never.

The degradation is graceful and `read_cursor` documents it as such, so this is a wart,
not an outage — which is why it rides here rather than carrying its own ticket.

**Two ways, choose with an argument:** exempt `prefetch-tick` from the cascade
predicate so the kind falls to the generic sweep, which already carries the clause —
one rule in one place, but the kind moves to a different horizon and the generic
sweep's exclusion list grows; or give the cascade sweep its own keep-newest clause —
the horizon stays put, but the rule is then written twice.

## Acceptance

- No comment in the repository claims a route that does not exist. All ten places,
  the tenth included, say what is actually true: the default horizon is the only one
  any supported path produces.
- Nothing new is added to reach the horizon — no route, no flag, no chart value.
- The index justification in both handlers is gone or replaced by the true one.
- `scan-row-retention-sweep` has a systemd timer.
- A test or check holds the chart CronJobs and the Ansible timers against each other,
  so the next gap of this kind surfaces instead of standing for years. If that is
  disproportionate, say why and say what carries the parity instead.
- `resolve_sweep_horizon` is extracted and used by all three handlers.
- E is decided with an argument and implemented.
- Gate green. Chart changes verified with `scripts/test-helm-templates.sh` against the
  Helm version pinned in CI (`alpine/helm:3.22.0`) — a newer Helm major fails the
  golden fixtures on blank lines.

## Explicitly not in this item

- No new HTTP invoke routes.
- No new CLI flag or chart value for the horizon.
- No narrowing of `ADMIN_INVOKABLE_TASK_KINDS`.
- No change to any sweep's default horizon or to the 365-day cap.
- No removal of `horizon_seconds` or `MAX_HORIZON`.
