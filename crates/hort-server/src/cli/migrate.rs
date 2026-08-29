//! `hort-server migrate` — apply database migrations and exit.
//!
//! Intended for k8s init-container patterns where migrations run once
//! before the serving replicas roll out, and for local dev loops where
//! an operator wants to apply migrations without the full service
//! starting.
//!
//! Thin wrapper over [`crate::migrate::run`] (the primitive that
//! `serve` also uses). Reads the DSN the same way [`serve`] does — via
//! `MinimalConfig::from_env`, which prefers `HORT_DATABASE_URL` and falls
//! back to bare `DATABASE_URL` (ADR 0029) — so configuration
//! parity is automatic.
//!
//! Before applying, checks the runtime fleet fence
//! ([`crate::migrate::evaluate_fleet_fence`], ADR 0030 amendment (c)):
//! refuses when a pending migration is a declared
//! contraction (`migrations/CONTRACTIONS.toml`) AND an older or
//! unversioned hort-shaped client is still connected. The
//! `--allow-running-fleet` escape hatch applies anyway, loudly logged.
//!
//! This module is an inbound adapter: argument
//! parsing and exit-code translation only. The migration logic itself
//! lives in `crate::migrate` and is the same primitive `serve` calls.
//!
//! [`serve`]: super::serve

use std::process::ExitCode;

use anyhow::Context;
use clap::Args;
use sqlx::postgres::PgPoolOptions;
use tracing::{info, warn};

use crate::config::MinimalConfig;
use crate::{migrate, pg_identity, telemetry};

/// This binary's own version — the fence's "current" side of the
/// older/newer comparison. Identical to [`hort_config::pg_identity`]'s
/// stamped `application_name` version segment: both read
/// `CARGO_PKG_VERSION` from the same workspace-inherited `version.workspace
/// = true`.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Arguments to `hort-server migrate`.
#[derive(Debug, Args)]
pub struct MigrateArgs {
    /// Apply even when a pending contraction would run against an older
    /// (or unversioned) hort-shaped fleet still connected. Emergency
    /// escape hatch only — using it is loudly logged. Also settable via
    /// `HORT_ALLOW_RUNNING_FLEET` (the Helm pre-upgrade hook's env
    /// override, default off).
    #[arg(long, env = "HORT_ALLOW_RUNNING_FLEET")]
    pub allow_running_fleet: bool,
}

/// Synchronous entry point. Delegates to [`super::run_with_runtime`]
/// which builds a Tokio runtime, runs [`run_async`], and maps the
/// result to a process exit code.
pub fn run(args: MigrateArgs) -> ExitCode {
    super::run_with_runtime(move || run_async(args), |_| ExitCode::SUCCESS)
}

async fn run_async(args: MigrateArgs) -> anyhow::Result<()> {
    // `migrate` is a DB-only subcommand (ADR 0009), so it parses
    // `MinimalConfig` (DB + log + metric-flag + pg-pool tunables) and
    // skips storage / public-base-url / OIDC / proxy-trust parsing.
    // Operators running `hort-server migrate` do not need
    // HORT_STORAGE_FILESYSTEM_PATH or HORT_PUBLIC_BASE_URL set; the chart's migrate Job
    // env block needs one variable (HORT_DATABASE_URL, with bare
    // DATABASE_URL as the compat fallback — ADR 0029).
    // Behaviour loss: serve-relevant misconfig (wrong public-base-url,
    // missing storage) now surfaces ~10s later when serve boots
    // instead of when migrate runs. The serve pod fails loud either
    // way; no silent failure mode.
    let cfg = MinimalConfig::from_env().context("parsing environment")?;

    telemetry::init_tracing(cfg.log_format)?;
    info!("running migrations only");

    let pool = PgPoolOptions::new()
        .connect_with(pg_identity::connect_options(&cfg.database_url)?)
        .await
        .context("connecting to postgres")?;

    let fence = migrate::evaluate_fleet_fence(&pool, CURRENT_VERSION)
        .await
        .context("evaluating the runtime fleet fence")?;
    if fence.blocked && args.allow_running_fleet {
        warn!(
            offenders = ?fence.offenders,
            "HORT_ALLOW_RUNNING_FLEET active — applying a pending contraction while an \
             older fleet is still connected; this WILL break queries on the still-running \
             old clients the instant the migration commits"
        );
    }
    migrate::gate_on_fleet_fence(&fence, args.allow_running_fleet)
        .map_err(|msg| anyhow::anyhow!(msg))?;

    // `migrate::run` applies pending migrations AND re-asserts the
    // events role hardening (ADR 0009) — both errors carry their
    // own context, so no outer wrap here.
    migrate::run(&pool).await?;

    info!("migrations complete");
    Ok(())
}
