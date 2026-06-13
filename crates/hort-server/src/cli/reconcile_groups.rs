//! `hort-server reconcile-groups` — group-membership reconciliation
//! sweep CLI.
//!
//! Inbound adapter for
//! [`hort_app::use_cases::group_reconcile_use_case::GroupReconcileUseCase`].
//! This module parses CLI arguments, builds the
//! composition (event store + read ports + group use case + wired
//! format handlers), invokes the use case, and maps the
//! [`ReconcileReport`] to a process exit code.
//!
//! **Exit codes (following the `scrub` precedent):**
//! - `0` on a successful sweep run regardless of per-event outcomes —
//!   the sweep is OBSERVABILITY-BY-METRIC, not gated. A run with
//!   `event_read_error > 0` exits `0` because the operator-visible
//!   signal is the metric on the dashboard + the `warn!` log line,
//!   not the exit code.
//! - `FAILURE` on config/connection errors — the sweep never ran.
//!
//! **Scope decision:** this is a one-shot operator-triggered job; we
//! use the native async runtime directly and share the same
//! `run_with_runtime` helper `scrub`/`migrate`/`admin` use.

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use clap::Args;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

use hort_adapters_postgres::artifact_group_lifecycle::PgArtifactGroupLifecycle;
use hort_adapters_postgres::artifact_group_repo::PgArtifactGroupRepository;
use hort_adapters_postgres::artifact_repo::PgArtifactRepository;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_adapters_postgres::repository_repo::PgRepositoryRepository;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
use hort_app::use_cases::group_reconcile_use_case::{GroupReconcileUseCase, ReconcileReport};
use hort_domain::ports::artifact_group_lifecycle::ArtifactGroupLifecyclePort;
use hort_domain::ports::artifact_group_repository::ArtifactGroupRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_formats::cargo::CargoFormatHandler;
use hort_formats::npm::NpmFormatHandler;
use hort_formats::pypi::PyPiFormatHandler;

use crate::config::MinimalConfig;
use crate::telemetry;

/// Arguments to `hort-server reconcile-groups`.
#[derive(Debug, Args)]
pub struct ReconcileGroupsArgs {
    /// Lower bound (RFC 3339) for `ArtifactIngested` events to
    /// consider. Omit to use the use case's default — the last 7
    /// days. Events stored before this cutoff are skipped silently
    /// (no counter increment, no log line).
    #[arg(long)]
    pub since: Option<DateTime<Utc>>,
}

/// Entry point. Delegates to [`super::run_with_runtime`] which builds
/// a Tokio runtime, runs [`run_async`], and maps the
/// [`ReconcileReport`] to a process exit code. Per module docstring,
/// the sweep always exits `0` on a successful run; per-event outcomes
/// are surfaced via the metric + tracing, not the exit code.
pub fn run(args: ReconcileGroupsArgs) -> ExitCode {
    super::run_with_runtime(move || run_async(args), report_to_exit_code)
}

async fn run_async(args: ReconcileGroupsArgs) -> anyhow::Result<ReconcileReport> {
    // `reconcile-groups` is a DB-only subcommand (ADR 0009),
    // so it parses `MinimalConfig`. The `include_repository_label`
    // field rides on `MinimalConfig` for exactly this callsite.
    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;

    info!(
        since = ?args.since,
        "hort-server reconcile-groups starting"
    );

    let pool = PgPoolOptions::new()
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres")?;

    // Hold the concrete `PgEventStore` Arc so we can pass it into
    // the Postgres lifecycle adapter (its `new` expects the concrete
    // type); the use case takes the trait-object clone below.
    let pg_event_store: Arc<PgEventStore> = Arc::new(
        PgEventStore::new(pool.clone())
            .await
            .context("constructing event store (is the immutability trigger installed?)")?,
    );
    let event_store: Arc<dyn EventStore> = pg_event_store.clone();
    // The reconcile-groups CLI is a one-shot dispatcher-free
    // path; wrap the event store in a no-broadcast publisher so the
    // `GroupReconcileUseCase` keeps its `Arc<EventStorePublisher>` shape.
    let event_publisher = Arc::new(EventStorePublisher::without_broadcast(event_store));
    let groups: Arc<dyn ArtifactGroupRepository> =
        Arc::new(PgArtifactGroupRepository::new(pool.clone()));
    let group_lifecycle: Arc<dyn ArtifactGroupLifecyclePort> =
        Arc::new(PgArtifactGroupLifecycle::new(pg_event_store));
    let artifacts: Arc<dyn ArtifactRepository> = Arc::new(PgArtifactRepository::new(pool.clone()));
    let repositories: Arc<dyn RepositoryRepository> =
        Arc::new(PgRepositoryRepository::new(pool.clone()));
    // Mirror the server's repository-label flag so dashboards line up
    // with serving-path emissions.
    let include_repository_label = cfg.include_repository_label;
    let group_use_case = Arc::new(ArtifactGroupUseCase::new(
        groups.clone(),
        group_lifecycle,
        include_repository_label,
    ));

    // Wire the three compiled-in handlers (pypi, cargo, npm); formats
    // without a wired handler silently skip.
    //
    // Deferred post-v1: the populated-from-`$WASM_PLUGIN_DIR` registry
    // is gated on the future WASM-format-modules work (ADR 0005). No
    // pre-v1 action expected.
    let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
    handlers.insert("pypi".into(), Arc::new(PyPiFormatHandler));
    handlers.insert("cargo".into(), Arc::new(CargoFormatHandler));
    handlers.insert("npm".into(), Arc::new(NpmFormatHandler));

    let use_case = GroupReconcileUseCase::new(
        event_publisher,
        groups,
        artifacts,
        repositories,
        group_use_case,
        handlers,
        include_repository_label,
    );

    let report = use_case
        .run(args.since)
        .await
        .context("running group-reconcile sweep")?;

    // One-line summary for shell capture. Operators parse the metric
    // + tracing for detail; this line is for humans running the
    // command interactively.
    println!(
        "reconcile-groups: healed={} already_linked={} handler_declined={} event_read_error={}",
        report.healed, report.already_linked, report.handler_declined, report.event_read_error
    );

    Ok(report)
}

/// Map a [`ReconcileReport`] to an [`ExitCode`].
///
/// Always [`ExitCode::SUCCESS`] on a successful run — see module
/// docstring for the rationale (observability-by-metric, not gated).
fn report_to_exit_code(_report: &ReconcileReport) -> ExitCode {
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: super::super::Command,
    }

    // -- CLI parsing --------------------------------------------------------

    #[test]
    fn reconcile_groups_parses_without_since() {
        let cli = TestCli::try_parse_from(["hort-server", "reconcile-groups"]).unwrap();
        let super::super::Command::ReconcileGroups(args) = cli.command else {
            panic!("expected ReconcileGroups");
        };
        assert!(args.since.is_none());
    }

    #[test]
    fn reconcile_groups_parses_with_since() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "reconcile-groups",
            "--since",
            "2026-04-01T00:00:00Z",
        ])
        .unwrap();
        let super::super::Command::ReconcileGroups(args) = cli.command else {
            panic!("expected ReconcileGroups");
        };
        let since = args.since.expect("since parsed");
        assert_eq!(since.to_rfc3339(), "2026-04-01T00:00:00+00:00");
    }

    #[test]
    fn reconcile_groups_rejects_invalid_since() {
        let err =
            TestCli::try_parse_from(["hort-server", "reconcile-groups", "--since", "not-a-date"])
                .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn reconcile_groups_help_renders() {
        let err =
            TestCli::try_parse_from(["hort-server", "reconcile-groups", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let rendered = err.to_string();
        assert!(rendered.contains("since"));
    }

    // -- Exit-code mapping --------------------------------------------------

    #[test]
    fn report_with_any_counts_maps_to_success() {
        // The sweep is observability-by-metric; per-event outcomes do
        // NOT gate the exit code. A non-zero event_read_error still
        // maps to SUCCESS — operators see the signal via the metric
        // dashboard, not the shell exit status.
        let r = ReconcileReport {
            healed: 1,
            already_linked: 2,
            handler_declined: 3,
            event_read_error: 4,
        };
        assert_eq!(
            format!("{:?}", report_to_exit_code(&r)),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    #[test]
    fn report_default_maps_to_success() {
        assert_eq!(
            format!("{:?}", report_to_exit_code(&ReconcileReport::default())),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }
}
