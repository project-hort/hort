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
//! This module is an inbound adapter: argument
//! parsing and exit-code translation only. The migration logic itself
//! lives in `crate::migrate` and is the same primitive `serve` calls.
//!
//! [`serve`]: super::serve

use std::process::ExitCode;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

use crate::config::MinimalConfig;
use crate::{migrate, telemetry};

/// Synchronous entry point. Delegates to [`super::run_with_runtime`]
/// which builds a Tokio runtime, runs [`run_async`], and maps the
/// result to a process exit code.
pub fn run() -> ExitCode {
    super::run_with_runtime(run_async, |_| ExitCode::SUCCESS)
}

async fn run_async() -> anyhow::Result<()> {
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
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres")?;

    // `migrate::run` applies pending migrations AND re-asserts the
    // events role hardening (ADR 0009) — both errors carry their
    // own context, so no outer wrap here.
    migrate::run(&pool).await?;

    info!("migrations complete");
    Ok(())
}
