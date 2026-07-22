# hort-http-admin-tasks — Admin Task Invocation HTTP Adapter

## Layer

Inbound HTTP — per-format-style adapter crate for an internal admin/ops
surface (ADR 0028). No `hort-adapters-*`, `sqlx`, or `reqwest` dependency
(ADR 0008); the crate's own module doc gives the exact verification command
(`cargo tree -p hort-http-admin-tasks --edges normal --prefix none`).
Requires >= 85% coverage.

## Responsibility

Serves the admin-task invoke/list/get REST surface for every registered
task kind: `noop`, `scan`, `cron-rescan-tick`, `advisory-watch-tick`,
`retention-evaluate`/`retention-purge`, `eventstore-archive`/
`eventstore-checkpoint`, `staging-sweep`, `service-account-rotation`,
`replay-seen-prune`, `scanner-registry-prune`.

## Ports

- **Implements:** none — an inbound HTTP adapter.
- **Consumes:** `TaskUseCase` (every route invokes a task kind through this
  single use case, per ADR 0028).

## Key types

- `router()` — mounted at `/api/v1/admin/tasks`.
- Per-kind param types: `NoopParams`, `ScanRawParams`,
  `CronRescanTickRawParams`, and the rest of the task-kind family.
- `dto`, `handlers`, `params` — public modules.

## Rules

- ADR 0008, self-documented with a verification command in the crate's own
  module doc.
- Every task kind this crate exposes must be a registered `TaskHandler` in
  `hort-app`/`hort-worker` — there is no ad hoc dispatch outside that
  registry.
