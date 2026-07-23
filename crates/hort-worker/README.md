# hort-worker — Background Task Worker Binary

## What this binary IS

- A separate process from `hort-server` (ADR 0001 topology): a multi-kind
  job dispatcher pulling rows from the shared `jobs` table via
  `hort_app::task_dispatcher::TaskDispatcher` under
  `FOR UPDATE SKIP LOCKED`.
- The process that instantiates scanner adapters (Trivy, OSV-scanner) and
  the advisory/provenance/retention/prefetch/gitops-sweep task handlers —
  `hort-server` does not depend on any of those.
- Its own composition root: `hort_worker::composition::build_app_context`,
  with its own `WorkerConfig` (parallel-by-construction to
  `hort-server`'s config, not shared with it).

## What it is NOT

- Not an HTTP edge for any registry protocol — it has no `hort-http-*`
  dependency.
- Not sharing a composition root with `hort-server` — the two binaries
  build `AppContext` independently, even though both ultimately wire the
  same `hort-app` use cases and `hort-adapters-postgres` types.

## Task kinds it processes

Every registered `TaskHandler` in `crates/hort-app/src/task_handlers/`:
`scan`, `cron-rescan-tick`, `advisory-watch-tick`, `noop`,
`eventstore-archive`, `scanner-registry-prune`, `quarantine-release-sweep`,
`retention-evaluate`, `eventstore-checkpoint`, `retention-purge`,
`provenance-verify`, `policy-reevaluation`,
`prefetch-row-retention-sweep`, `seed-import`, `wheel-metadata-backfill`,
`prefetch-ingest`, `prefetch-dependencies`, `staging-sweep`,
`service-account-rotation`, `prefetch-tick`, `replay-seen-prune`.

## Entrypoint

`Cli::parse()` (`src/main.rs`) dispatches to `run_dispatcher()` (default: config
parse -> tracing/metrics init -> extra-CA read -> `build_app_context` ->
spawn dispatcher poll loop + heartbeat loop + optional metrics listener,
joined on SIGTERM/SIGINT), `run_healthcheck()` (k8s livenessProbe exec
gate), and the shared `license`/`attribution` subcommands (via
`hort-attribution`).

## Required environment variables (selected — see `src/config.rs` for the
full, authoritative list)

`HORT_DATABASE_URL` (or `DATABASE_URL`), `HORT_REDIS_URL_EVICTABLE`,
`HORT_SCANNER_TRIVY_ENABLED`, `HORT_SCANNER_OSV_ENABLED`,
`HORT_PROVENANCE_COSIGN_ENABLED`, `HORT_PROVENANCE_TRUSTED_ROOT_FILE`,
`HORT_PROVENANCE_COSIGN_PUBLIC_KEYS_FILE`,
`HORT_ROTATION_TARGET_NAMESPACES`, `HORT_PUBLIC_REGISTRY_HOST`,
`HORT_REFCOUNT_RECONCILE_ON_STARTUP`, `HORT_RETENTION_STREAM_MODE`,
`HORT_LOG_FORMAT`, `HORT_WORKER_METRICS_BIND`,
`HORT_STATEFUL_UPLOAD_STAGING_DIR`.

## Local-dev quickstart

```bash
HORT_DATABASE_URL='postgres://registry:registry@localhost:5432/artifact_registry' \
cargo run -p hort-worker
```

Kill with `Ctrl+C` — graceful shutdown on SIGTERM/SIGINT.
