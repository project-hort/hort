//! TaskHandler implementations for the worker dispatcher.
//!
//! This module contains all task handler types registered in the worker's
//! dispatch table. Each handler is keyed by its `kind()` identifier and
//! invoked with per-job request parameters.

pub mod advisory_watch_tick;
pub mod cron_rescan_tick;
// Periodic quarantine release sweep (kind `quarantine-release-sweep`).
// Triggered by a Helm CronJob that runs the `hort-server enqueue-
// quarantine-release-sweep` subcommand via the runtime DSN —
// deliberately bypasses the svc-token / `hort-cli` HTTP admin-task
// path.
pub mod quarantine_release_sweep;
// Audit-log tamper-detection checkpoint emission (external anchor).
pub mod eventstore_checkpoint;
pub mod noop;
// Federated-JWT replay-guard seen-set TTL cleanup
// (default-ENABLED CronJob).
pub mod replay_seen_prune;
// `provenance-verify` TaskHandler wrapping
// `ProvenanceOrchestrationUseCase` (ADR 0027). Dispatched for the
// ingest-enqueued `kind = 'provenance-verify'` row (gate: mode != Off
// AND a registered verifier applies_to the format).
pub mod provenance_verify;
pub mod scan;
// The three retention TaskHandlers:
// event-sourced retention evaluate (`RetentionUseCase`), destructive
// storage-GC purge (`PurgeUseCase`), and the
// audit-retention stream archive (`EventStoreRetentionUseCase`,
// seal-and-remove chokepoint).
pub mod eventstore_archive;
pub mod retention_evaluate;
pub mod retention_purge;
// Fallback PAT rotation reconciler (ADR 0018).
pub mod service_account_rotation;
// Seed-import cutover (kind `seed-import`).
// Wraps `SeedImportUseCase`; bulk-registers an operator-supplied
// dependency set with backdated `quarantine_window_start` anchors.
pub mod seed_import;
// Scheduled prefetch trigger (kind
// `prefetch-tick`). Walks every repository whose `prefetch_policy` opts
// into the `Scheduled` trigger and invokes the `PrefetchUseCase`
// planner per tracked package. Delivery mirrors the quarantine-release
// sweep: a Helm CronJob runs `hort-server enqueue-prefetch-tick` via
// the runtime DSN.
pub mod prefetch_tick;
// Transitive prefetch cascade (kind
// `prefetch-dependencies`). Reads an ingested artifact's manifest via
// `FormatHandler::extract_dependency_specs`, resolves each declared
// runtime-dep range via `resolve_range_max`, and enqueues a `prefetch`
// ingest row + a child `prefetch-dependencies` row (bounded by
// `prefetch_policy.transitive_depth`) per not-already-held dep. Dedup
// is the L3 partial unique index on `jobs.target_key` (migration 009).
pub mod prefetch_dependencies;
// Leaf-ingest kind (`prefetch`) the cascade
// enqueues per `(repo, package, version)` coordinate; performs the
// pull-through ingest for that coordinate.
pub mod prefetch_ingest;
// `jobs`-row retention sweep
// (`prefetch-row-retention-sweep`). Periodically deletes terminal
// `prefetch%` rows older than a configurable horizon (default 7d) so
// the high-churn `jobs` table does not grow unbounded under cascade
// load.
pub mod prefetch_row_retention_sweep;
// Scanner-worker registry housekeeping (kind
// `scanner-registry-prune`). Deletes `scanner_registry` rows whose
// `last_heartbeat` is older than the retention horizon so pod churn does
// not grow the worker-coordination table without bound. Helm CronJob
// ships default-enabled.
pub mod scanner_registry_prune;
pub mod staging_sweep;
// PEP 658 wheel-metadata backfill (kind
// `wheel-metadata-backfill`). Operator-opt-in retrofit: walks PyPI
// wheels without a `wheel_metadata` ContentReference and runs the
// extract+persist sequence per artifact. Helm CronJob ships
// default-disabled (the backfill is a one-shot post-upgrade
// remediation, not a steady-state sweep).
pub mod wheel_metadata_backfill;

pub use advisory_watch_tick::AdvisoryWatchTickHandler;
pub use cron_rescan_tick::CronRescanTickHandler;
pub use eventstore_archive::EventStoreArchiveHandler;
pub use eventstore_checkpoint::{
    CheckpointEmissionHook, CheckpointEmitterHookAdapter, EventstoreCheckpointHandler,
};
pub use noop::NoopTaskHandler;
pub use prefetch_dependencies::{target_key as prefetch_target_key, PrefetchDependenciesHandler};
pub use prefetch_ingest::PrefetchIngestHandler;
pub use prefetch_row_retention_sweep::PrefetchRowRetentionSweepHandler;
pub use prefetch_tick::PrefetchTickHandler;
pub use provenance_verify::ProvenanceVerifyHandler;
pub use quarantine_release_sweep::QuarantineReleaseSweepHandler;
pub use replay_seen_prune::ReplaySeenPruneHandler;
pub use retention_evaluate::RetentionEvaluateHandler;
pub use retention_purge::RetentionPurgeHandler;
pub use scan::ScanTaskHandler;
pub use scanner_registry_prune::ScannerRegistryPruneHandler;
pub use seed_import::SeedImportHandler;
pub use service_account_rotation::ServiceAccountRotationHandler;
pub use staging_sweep::StagingSweepHandler;
pub use wheel_metadata_backfill::WheelMetadataBackfillHandler;
