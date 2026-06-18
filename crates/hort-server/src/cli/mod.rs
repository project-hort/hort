//! CLI surface for `hort-server`.
//!
//! The binary is a multi-subcommand tool built with `clap`. The default
//! (no subcommand) is [`Command::Serve`]:
//! `hort-server` run with zero arguments starts the HTTP
//! service.
//!
//! - [`Command::Serve`] — start the HTTP service (current behaviour).
//! - [`Command::Migrate`] — apply database migrations and exit. Useful
//!   for init-container patterns where a sidecar runs migrations before
//!   the main server pod starts.
//! - [`Command::Scrub`] — CAS integrity scrubber.
//! - [`Command::Admin`] — service-account token management;
//!   `issue-svc-token` is the only nested subcommand (there is no
//!   `bootstrap` — the local-admin identity path it seeded was
//!   removed).
//!
//! Every subcommand module is an inbound adapter:
//! it parses CLI arguments, calls an `hort-app` use case, and maps the
//! result to a process exit code. No business logic lives here.

use std::future::Future;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

pub mod admin;
// DB-only enqueue subcommand the Helm
// CronJob runs to schedule the prefetch tick. Runtime DSN; no
// svc-token. The
// `FormatHandler::extract_upstream_versions` wiring makes the
// per-tick walk produce non-zero results. Mirrors
// `enqueue_quarantine_release_sweep` verbatim.
pub mod enqueue_prefetch_tick;
// DB-only enqueue subcommand the Helm
// CronJob runs to schedule the prefetch-row retention sweep.
// Runtime DSN; no svc-token. Same delivery contract
// as `enqueue-quarantine-release-sweep` and `enqueue-prefetch-tick`.
pub mod enqueue_prefetch_row_retention_sweep;
// DB-only enqueue subcommand the Helm CronJob
// runs to schedule the quarantine release sweep. Runtime DSN; no
// svc-token. See module docstring for the design rationale
// (avoid dragging the svc-token-bootstrap chain to
// default-on).
pub mod enqueue_quarantine_release_sweep;
// DB-only enqueue subcommand the Helm CronJob
// runs to retrofit older PyPI wheels with their PEP 658 metadata
// blob. Runtime DSN; no svc-token. Same delivery contract as
// `enqueue-quarantine-release-sweep` and
// `enqueue-prefetch-tick` — same
// rationale (avoid the svc-token-bootstrap chain on a
// default-shipped, default-disabled CronJob).
pub mod enqueue_wheel_metadata_backfill;
pub mod migrate;
pub mod rbac_refresh;
pub mod reconcile_groups;
pub mod scrub;
// DB-only enqueue subcommand for the seed-import
// cutover path. Operator-invoked once per deployment; parses an
// operator-supplied TSV file and enqueues one `seed-import` job. The
// worker (with the full ingest stack) does the actual bulk-register
// with backdated `quarantine_window_start` anchors. Runtime DSN; no
// svc-token. Mirrors `enqueue-quarantine-release-sweep` verbatim.
pub mod seed_import;
pub mod serve;
// The config-invalid **park**
// server. When boot-time gitops apply fails with a provably-pre-write
// error (`GitopsBootError::Parse | Read | Walk`), `serve::run_async`
// tails into `serve_config_invalid_park` instead of crashing: it binds
// the public API listener and serves a minimal not-ready router
// (`/healthz`=200, `/readyz`=503 status-only, fallback=503) until
// SIGTERM, removing the `CrashLoopBackOff` while keeping the rollout
// loud-failing (readiness never flips). `Validate | Apply` still crash.
pub mod serve_parked;
// The offline `validate-config` subcommand. Runs
// the pure `StaticConfigValidator` over a gitops config tree, DSN-free
// (no `Config::from_env`, no `MinimalConfig`, no `DATABASE_URL`). Reads
// `HORT_CONFIG_DIR` + `HORT_STORAGE_BACKEND` from the env (the same
// deployment env server boot reads); the only flag is `--strict`.
pub mod validate_config;
pub mod verify_event_chain;

/// Shared Tokio-runtime + result-to-exit-code bootstrap used by every
/// subcommand's synchronous `run` entry point.
///
/// Each subcommand (`serve`, `migrate`, `scrub`, `admin`) is a tiny
/// clap-facing wrapper that:
/// 1. builds a multi-thread Tokio runtime,
/// 2. `block_on`s an async body returning `anyhow::Result<T>`,
/// 3. maps `Ok(T)` to an [`ExitCode`] (via the caller-supplied
///    `on_ok` closure — unit-returning bodies pass `|_| ExitCode::SUCCESS`;
///    the scrub passes a mapper from `ScrubReport` to either SUCCESS or
///    `ExitCode::from(1)`),
/// 4. maps `Err(anyhow::Error)` to [`ExitCode::FAILURE`], printing the
///    full context chain via the `Debug` impl (matches the earlier behaviour
///    of a `main() -> anyhow::Result<()>`).
///
/// Runtime-build failure prints `error: building tokio runtime: {err}`
/// on stderr and returns `ExitCode::FAILURE`. The prefix matches the
/// pre-refactor shape in all four subcommands.
///
/// Factored out of the per-subcommand modules
/// so the four call sites stay 2-3 lines each and the
/// runtime-build boilerplate lives in one place. Zero behaviour change:
/// exit-code semantics and stderr prefixes are preserved verbatim.
pub(crate) fn run_with_runtime<F, Fut, T>(f: F, on_ok: impl FnOnce(&T) -> ExitCode) -> ExitCode
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("error: building tokio runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(f()) {
        Ok(value) => on_ok(&value),
        Err(err) => {
            // anyhow::Error's Debug impl prints the full context chain —
            // matches the pre-refactor behaviour of
            // `main() -> anyhow::Result<()>` exiting with code 1 on Err.
            eprintln!("Error: {err:?}");
            ExitCode::FAILURE
        }
    }
}

/// Top-level `hort-server` CLI parser.
///
/// `command` is optional so that the bare `hort-server` invocation
/// (current behaviour, used by `deploy/compose/docker-compose.yml`) still
/// works — `None` dispatches to [`Command::Serve`].
#[derive(Debug, Parser)]
#[command(name = "hort-server", version, about = "hort service binary")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the HTTP service (default when no subcommand is given).
    Serve,
    /// Apply database migrations and exit.
    ///
    /// Useful for k8s init-container patterns where migrations are
    /// applied once before the serving replicas roll out.
    Migrate,
    /// CAS integrity scrubber.
    Scrub(scrub::ScrubArgs),
    /// Service-account token management. There is no `bootstrap`
    /// subcommand; `issue-svc-token` is the only nested subcommand.
    Admin(admin::AdminCommand),
    /// Group-membership reconciliation sweep.
    ///
    /// Heals artifacts whose ingest-path group commit dropped between
    /// the `ArtifactIngested` transaction and the subsequent
    /// `ArtifactGroupMemberAdded` transaction. Operator-triggered;
    /// mirrors the `Scrub` subcommand's shape.
    ReconcileGroups(reconcile_groups::ReconcileGroupsArgs),
    /// Offline tamper-evident event-chain verifier (ADR 0002).
    ///
    /// Recomputes every per-stream hash chain and cross-checks live
    /// heads against the externally-anchored signed checkpoints, then
    /// emits `hort_event_chain_verify_total{result}` and exits with a
    /// deterministic code (0=ok, 2=broken, 3=missing_checkpoint,
    /// 1=operational error). Read-only: connects with the runtime DML
    /// DSN and never writes or migrates.
    VerifyEventChain(verify_event_chain::VerifyEventChainArgs),
    /// Enqueue one `quarantine-release-sweep`
    /// job and exit. The Helm CronJob runs this every 5 minutes
    /// (operator-tunable) using the runtime DSN (no svc-token; no
    /// `cronJobs.enabled` umbrella dependency).
    /// The always-on worker picks the row up and dispatches to
    /// `QuarantineReleaseSweepHandler`, which feeds the fail-closed
    /// `release_expired` (ADR 0007).
    EnqueueQuarantineReleaseSweep(
        enqueue_quarantine_release_sweep::EnqueueQuarantineReleaseSweepArgs,
    ),
    /// Parse an operator-supplied TSV file
    /// describing a dependency cutover set, then enqueue one
    /// `seed-import` job carrying the items. The worker dispatches
    /// `SeedImportHandler` → `SeedImportUseCase`, which bulk-registers
    /// each item with a backdated `quarantine_window_start` anchor so
    /// the *time* gate is already elapsed at import. Operator-invoked
    /// once per deployment for the one-shot cutover. NOT `ScanWaived`:
    /// a dirty scan still rejects (the scan gate is unchanged).
    SeedImport(seed_import::SeedImportArgs),
    /// Enqueue one `prefetch-tick` job
    /// and exit. The Helm CronJob runs this every 15 minutes
    /// (operator-tunable) using the runtime DSN (no svc-token; no
    /// `cronJobs.enabled` umbrella dependency).
    /// The always-on worker picks the row up and dispatches to
    /// `PrefetchTickHandler`, which walks every
    /// Scheduled-eligible repo + tracked-package, fetches the
    /// upstream catalog, extracts the version set via the format
    /// handler's `extract_upstream_versions` method, and invokes the
    /// prefetch planner with the real upstream-vs-held divergence —
    /// emitting `hort_prefetch_enqueued_total{trigger="scheduled"}`.
    EnqueuePrefetchTick(enqueue_prefetch_tick::EnqueuePrefetchTickArgs),
    /// Enqueue one
    /// `prefetch-row-retention-sweep` job and exit. The Helm CronJob
    /// runs this daily (operator-tunable) using the runtime DSN (no
    /// svc-token; no `cronJobs.enabled` umbrella
    /// dependency). The always-on worker picks the row up and
    /// dispatches to `PrefetchRowRetentionSweepHandler`, which
    /// deletes terminal (`status IN ('completed', 'failed')`)
    /// `kind LIKE 'prefetch%'` rows older than a configurable horizon
    /// (default 7 days). Pairs with the per-table
    /// autovacuum tuning on `public.jobs` (migration 009) so the
    /// transitive-cascade churn does not grow the table unbounded.
    EnqueuePrefetchRowRetentionSweep(
        enqueue_prefetch_row_retention_sweep::EnqueuePrefetchRowRetentionSweepArgs,
    ),
    /// Enqueue one `wheel-metadata-backfill`
    /// job and exit. The Helm CronJob runs this on the operator's
    /// chosen schedule (default-disabled — backfill is a one-shot
    /// retrofit, not steady-state) using the runtime DSN (no
    /// svc-token; no `cronJobs.enabled` umbrella dependency). The
    /// always-on worker picks the row up and dispatches to
    /// `WheelMetadataBackfillHandler`, which walks PyPI wheels
    /// without a `wheel_metadata` ContentReference, extracts the
    /// METADATA file from each wheel ZIP, persists it to CAS, and
    /// inserts the ContentReference row — retroactively enabling
    /// PEP 658 advertisement for wheels ingested before metadata
    /// extraction existed.
    EnqueueWheelMetadataBackfill(enqueue_wheel_metadata_backfill::EnqueueWheelMetadataBackfillArgs),
    /// Offline gitops-config validation. Runs the
    /// pure `StaticConfigValidator` (the snapshot-free subset of the
    /// apply-time validation/lint pass) over the gitops tree at
    /// `HORT_CONFIG_DIR`, with the storage backend kind from
    /// `HORT_STORAGE_BACKEND` (both required env vars — the same env
    /// server boot reads), DSN-free. Prints errors + warnings + an
    /// honesty footer; CI-friendly exit codes (0 clean, 1 validation
    /// error / strict-promoted warning, 2 missing/invalid env, 3
    /// operational). The only flag is `--strict` (warnings → failure).
    ValidateConfig(validate_config::ValidateConfigArgs),
}

/// Parse `std::env::args()` and dispatch to the selected subcommand.
///
/// Called from `main.rs`. Thin on purpose — every subcommand owns its
/// own process-exit translation.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    dispatch(cli.command.unwrap_or(Command::Serve))
}

/// Pure dispatch — factored out of [`run`] so it is exercised by unit
/// tests without going through `std::env::args()`.
fn dispatch(command: Command) -> ExitCode {
    match command {
        Command::Serve => serve::run(),
        Command::Migrate => migrate::run(),
        Command::Scrub(args) => scrub::run(args),
        Command::Admin(cmd) => admin::run(cmd),
        Command::ReconcileGroups(args) => reconcile_groups::run(args),
        Command::VerifyEventChain(args) => verify_event_chain::run(args),
        Command::EnqueueQuarantineReleaseSweep(args) => enqueue_quarantine_release_sweep::run(args),
        Command::SeedImport(args) => seed_import::run(args),
        Command::EnqueuePrefetchTick(args) => enqueue_prefetch_tick::run(args),
        Command::EnqueuePrefetchRowRetentionSweep(args) => {
            enqueue_prefetch_row_retention_sweep::run(args)
        }
        Command::EnqueueWheelMetadataBackfill(args) => enqueue_wheel_metadata_backfill::run(args),
        Command::ValidateConfig(args) => validate_config::run(&args),
    }
}

#[cfg(test)]
mod tests {
    //! Dispatcher tests — exercise clap parsing only. Subcommand
    //! exit-code behaviour is covered by the per-module tests.

    use super::*;

    // Bare `hort-server` (no subcommand) parses with `command: None` —
    // this is the invocation the docker-compose stack relies on.

    #[test]
    fn no_subcommand_parses_to_none() {
        let cli = Cli::try_parse_from(["hort-server"]).unwrap();
        assert!(cli.command.is_none());
    }

    // Explicit `serve` subcommand round-trips to `Command::Serve`.

    #[test]
    fn explicit_serve_parses() {
        let cli = Cli::try_parse_from(["hort-server", "serve"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Serve)));
    }

    // `migrate` subcommand parses to `Command::Migrate`.

    #[test]
    fn migrate_parses() {
        let cli = Cli::try_parse_from(["hort-server", "migrate"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Migrate)));
    }

    // `scrub` subcommand parses with empty args.

    #[test]
    fn scrub_parses() {
        let cli = Cli::try_parse_from(["hort-server", "scrub"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Scrub(_))));
    }

    // `reconcile-groups` subcommand parses.
    // Accepts bare invocation — `--since` is optional.

    #[test]
    fn reconcile_groups_parses() {
        let cli = Cli::try_parse_from(["hort-server", "reconcile-groups"]).unwrap();
        assert!(matches!(cli.command, Some(Command::ReconcileGroups(_))));
    }

    // `admin issue-svc-token` parses — nested subcommand form. The
    // dispatcher test only cares that the variant routes here, so we
    // pass the minimum args the clap schema requires.

    #[test]
    fn admin_issue_svc_token_parses() {
        let cli = Cli::try_parse_from([
            "hort-server",
            "admin",
            "issue-svc-token",
            "--name",
            "cronjob-tasks",
        ])
        .unwrap();
        let Some(Command::Admin(admin)) = cli.command else {
            panic!("expected Admin");
        };
        assert!(matches!(
            admin.command,
            admin::AdminSubcommand::IssueSvcToken(_)
        ));
    }

    // `admin` without a subcommand must fail — the nested enum is
    // required. Pins the shape so a future subcommand addition doesn't
    // drift. Clap reports this as `DisplayHelpOnMissingArgumentOrSubcommand`
    // by default (prints the subcommand's help + exits non-zero),
    // which is fine — the important property is that it doesn't
    // silently dispatch to a default.

    #[test]
    fn admin_without_subcommand_errors() {
        let err = Cli::try_parse_from(["hort-server", "admin"]).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    // `--help` is a clap-reported "error" from `try_parse_from` (stdout
    // is printed, but parse returns Err with kind == DisplayHelp).
    // Documents that --help works on the top-level command.

    #[test]
    fn top_level_help_renders() {
        let err = Cli::try_parse_from(["hort-server", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let rendered = err.to_string();
        assert!(rendered.contains("hort-server"));
        assert!(rendered.contains("serve"));
        assert!(rendered.contains("migrate"));
        assert!(rendered.contains("scrub"));
        assert!(rendered.contains("admin"));
        assert!(rendered.contains("reconcile-groups"));
        assert!(rendered.contains("verify-event-chain"));
        assert!(rendered.contains("enqueue-quarantine-release-sweep"));
        assert!(rendered.contains("seed-import"));
        assert!(rendered.contains("enqueue-prefetch-tick"));
        assert!(rendered.contains("enqueue-prefetch-row-retention-sweep"));
        assert!(rendered.contains("validate-config"));
    }

    // `validate-config` subcommand parses. Accepts
    // bare invocation — the only flag (`--strict`) is optional.

    #[test]
    fn validate_config_parses() {
        let cli = Cli::try_parse_from(["hort-server", "validate-config"]).unwrap();
        assert!(matches!(cli.command, Some(Command::ValidateConfig(_))));
    }

    // `seed-import` subcommand parses. Requires
    // the `--file` flag — the parser-level test in the seed_import
    // module covers the missing-flag case; here we only confirm the
    // dispatcher routes the variant.

    #[test]
    fn seed_import_parses_with_file_flag() {
        let cli =
            Cli::try_parse_from(["hort-server", "seed-import", "--file", "/tmp/seed.tsv"]).unwrap();
        assert!(matches!(cli.command, Some(Command::SeedImport(_))));
    }

    // `enqueue-prefetch-tick` subcommand parses.
    // Accepts bare invocation — the subcommand has no flags.

    #[test]
    fn enqueue_prefetch_tick_parses_bare_invocation() {
        let cli = Cli::try_parse_from(["hort-server", "enqueue-prefetch-tick"]).unwrap();
        assert!(matches!(cli.command, Some(Command::EnqueuePrefetchTick(_))));
    }

    // `enqueue-prefetch-row-retention-sweep` subcommand parses.
    // Accepts bare invocation — the
    // subcommand has no flags.

    #[test]
    fn enqueue_prefetch_row_retention_sweep_parses_bare_invocation() {
        let cli =
            Cli::try_parse_from(["hort-server", "enqueue-prefetch-row-retention-sweep"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::EnqueuePrefetchRowRetentionSweep(_))
        ));
    }

    // `verify-event-chain` subcommand parses.
    // Accepts bare invocation — every arg is optional / has a default.

    #[test]
    fn verify_event_chain_parses() {
        let cli = Cli::try_parse_from(["hort-server", "verify-event-chain"]).unwrap();
        assert!(matches!(cli.command, Some(Command::VerifyEventChain(_))));
    }

    // `--version` likewise — pinned so future refactors don't drop it.

    #[test]
    fn top_level_version_renders() {
        let err = Cli::try_parse_from(["hort-server", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    // `--help` on a subcommand also works (smoke check — clap gives
    // this for free when annotations are correct).

    #[test]
    fn subcommand_help_renders() {
        let err = Cli::try_parse_from(["hort-server", "migrate", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    // Unknown subcommand is rejected — guards against silent typos
    // slipping through (e.g. `hort-server serv` starting nothing).

    #[test]
    fn unknown_subcommand_errors() {
        let err = Cli::try_parse_from(["hort-server", "nosuch"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}
