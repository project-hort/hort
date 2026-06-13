//! `hort-worker` — multi-kind job dispatcher (scan, cron-rescan-tick,
//! advisory-watch-tick, staging-sweep, noop, and more).
//!
//! The worker is a separate process from `hort-server` (see ADR 0001 topology):
//!
//! - It pulls `kind='scan'` rows from the shared `jobs` table via the
//!   generalised [`hort_app::task_dispatcher::TaskDispatcher`]
//!   using [`hort_app::task_handlers::ScanTaskHandler`] wrapping
//!   [`hort_app::use_cases::scan_orchestration::ScanOrchestrationUseCase`]
//!   under `FOR UPDATE SKIP LOCKED`.
//! - It instantiates the scanner adapters (Trivy, OSV-scanner) and the
//!   advisory adapter (OSV.dev) — `hort-server` does NOT depend on these
//!   crates.
//! - It hands findings to
//!   [`hort_app::use_cases::quarantine_use_case::QuarantineUseCase::record_scan_result`]
//!   for atomic event-store + projection persistence.
//! - It registers itself in `scanner_registry` on startup and refreshes
//!   `last_heartbeat` every 60 seconds.
//!
//! The worker connects with the `hort_app_role` Postgres role (ADR 0009):
//! it asserts the schema is current via [`hort_adapters_postgres`]'s
//! migration set but never runs migrations. Operators ship migrations via
//! `hort-server migrate` (the existing pre-install Helm Job).
//!
//! The `poll_loop` module retains the M12 alerting metric helper
//! (`emit_failed_branch_alert`) and its unit tests; the scan-specific
//! `run` / `process_one_batch` / `run_with_drain_deadline` functions
//! have been removed in favour of the generalised `TaskDispatcher`
//! (see `how-to/using-hort-cli-with-admin-ops.md`).

pub mod cli;
pub mod composition;
pub mod config;
pub mod extra_ca;
pub mod healthcheck;
pub mod heartbeat;
pub mod metrics_server;
pub mod poll_loop;
pub mod telemetry;
