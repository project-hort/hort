//! `hort-server enqueue-prefetch-row-retention-sweep` — scheduled
//! prefetch-row retention-sweep enqueue.
//!
//! A **DB-only** enqueue subcommand the Helm CronJob runs daily
//! (operator-tunable; default `0 2 * * *`). It inserts a single
//! `kind = 'prefetch-row-retention-sweep'` row into `public.jobs`
//! using the **runtime DSN** — the always-on worker (`hort-worker`)
//! then claims the row and dispatches to
//! [`PrefetchRowRetentionSweepHandler`](
//!     hort_app::task_handlers::PrefetchRowRetentionSweepHandler),
//! which deletes terminal `kind LIKE 'prefetch%'` rows older than a
//! configurable horizon (default 7 days).
//!
//! ## Why a DB-only subcommand instead of `hort-cli admin task invoke`
//!
//! Mirrors the `enqueue-quarantine-release-sweep`
//! and `enqueue-prefetch-tick` precedent:
//! an out-of-the-box schedulable tick
//! going through the `hort-cli` HTTP admin-task path would
//! drag the whole `svc-token-bootstrap` Job chain (and a standing
//! `admin_task_invoke` token mount) to default-on. The runtime DSN
//! is least-privilege — it can `INSERT INTO public.jobs` and read
//! the schema, full stop.
//!
//! The `hort-http-admin-tasks` HTTP route stays available for
//! **manual** operator invocation — `hort-cli admin task
//! invoke prefetch-row-retention-sweep` works for operators who
//! want to drive one ad-hoc; the default scheduled path bypasses it.
//!
//! ## Configuration
//!
//! Parses [`MinimalConfig`] (NOT `Config::from_env` — ADR 0009:
//! DB-only subcommands must not consume the full
//! serve-config surface). The env footprint shrinks to the DSN
//! (`HORT_DATABASE_URL`, falling back to bare `DATABASE_URL` —
//! ADR 0029) plus log/metric tunables; the CronJob template need set nothing
//! beyond what `hort-server.runtimeEnv` already populates.
//!
//! ## Idempotency
//!
//! The worker's claim query naturally short-circuits a duplicate
//! enqueue (two ticks back-to-back) — the first claim transitions
//! `pending → running`; subsequent ticks just queue more rows. The
//! DELETE itself is idempotent (re-running on already-deleted rows
//! is a no-op). No explicit dedup is needed at the CronJob layer.

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use uuid::Uuid;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::JobsRepository;

use crate::config::MinimalConfig;
use crate::telemetry;

/// `trigger_source` literal — must match the SQL CHECK constraint on
/// `jobs.trigger_source` (`'manual' | 'cron' | 'advisory' | 'ingest'`).
/// The scheduled CronJob is the `'cron'` trigger source.
const CRON_TRIGGER_SOURCE: &str = "cron";

/// `priority` for the enqueued row. The trigger-source
/// ranking is `ingest=0` → `advisory=5` → `cron=10` → `manual=20`.
/// Matches the release-sweep + prefetch-tick priority — the
/// three CronJobs in the cron tier drain together.
const CRON_PRIORITY: i16 = 10;

/// Arguments to `hort-server enqueue-prefetch-row-retention-sweep`.
///
/// No flags — the subcommand's single purpose is "enqueue one row."
/// Future tuning (priority, horizon override) would land as
/// `#[arg(long)]` here; pinning the v1 surface to argument-less
/// keeps the CronJob template idempotent and the unit-test parser
/// stable.
#[derive(Debug, Args)]
pub struct EnqueuePrefetchRowRetentionSweepArgs {}

/// Synchronous entry point. Delegates to [`super::run_with_runtime`]
/// which builds a Tokio runtime, runs [`run_async`], and maps the
/// result to a process exit code.
/// The CronJob's success criterion is **exit code only**: `0` on a
/// successful insert, non-zero on connect/insert failure (next cron
/// tick retries).
pub fn run(args: EnqueuePrefetchRowRetentionSweepArgs) -> ExitCode {
    super::run_with_runtime(move || run_async(args), |_| ExitCode::SUCCESS)
}

async fn run_async(_args: EnqueuePrefetchRowRetentionSweepArgs) -> anyhow::Result<()> {
    // DB-only subcommand → MinimalConfig, NOT Config::from_env
    // (ADR 0009). The CronJob pod's env block then needs only the
    // DB DSN + log format (via `hort-server.runtimeEnv` in the chart).
    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;
    info!("enqueueing prefetch-row-retention-sweep job");

    let pool = PgPoolOptions::new()
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres")?;

    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool));

    // The `params` jsonb is empty — the handler uses the default
    // retention horizon (7 days) when `horizon_seconds` is absent.
    // Operators wanting a custom horizon use the `hort-cli admin task
    // invoke prefetch-row-retention-sweep --params
    // '{"horizon_seconds": …}'` HTTP path instead. `actor_id` is
    // `None` because the scheduled path is system-driven (a CronJob
    // is not a human caller; the runtime DSN owns nothing
    // identity-wise).
    let outcome = jobs
        .enqueue_task(
            "prefetch-row-retention-sweep",
            &serde_json::json!({}),
            None, // actor_id — system-driven cron
            CRON_PRIORITY,
            CRON_TRIGGER_SOURCE,
            None, // non-destructive task kind — no DB-side idempotency key (ADR 0028)
        )
        .await
        .context("enqueueing prefetch-row-retention-sweep job")?;
    let id: Uuid = match outcome {
        hort_domain::ports::jobs_repository::EnqueueOutcome::Enqueued { job_id } => job_id,
        hort_domain::ports::jobs_repository::EnqueueOutcome::Duplicate { existing_job_id } => {
            existing_job_id
        }
    };

    info!(
        job_id = %id,
        kind = "prefetch-row-retention-sweep",
        priority = CRON_PRIORITY,
        trigger_source = CRON_TRIGGER_SOURCE,
        "prefetch-row-retention-sweep job enqueued"
    );
    // One-line summary on stdout for shell capture — operators tail
    // CronJob pod logs to confirm the enqueue happened; the job_id
    // makes the row trivially greppable in the events / jobs tables.
    println!("enqueue-prefetch-row-retention-sweep: job_id={id}");
    Ok(())
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

    /// Parses with zero positional/optional args — the subcommand has
    /// no surface beyond the bare invocation. Pins the v1 shape so a
    /// future `#[arg(long)]` addition is a deliberate change.
    #[test]
    fn enqueue_prefetch_row_retention_sweep_parses_bare_invocation() {
        let cli = TestCli::try_parse_from(["hort-server", "enqueue-prefetch-row-retention-sweep"])
            .expect("parse");
        let super::super::Command::EnqueuePrefetchRowRetentionSweep(_) = cli.command else {
            panic!("expected EnqueuePrefetchRowRetentionSweep variant");
        };
    }

    /// Unknown flag must fail — guards against typos in the CronJob
    /// template silently no-op'ing.
    #[test]
    fn enqueue_prefetch_row_retention_sweep_rejects_unknown_flag() {
        let err = TestCli::try_parse_from([
            "hort-server",
            "enqueue-prefetch-row-retention-sweep",
            "--bogus",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `--help` renders (clap-reported "error" via try_parse_from).
    #[test]
    fn enqueue_prefetch_row_retention_sweep_help_renders() {
        let err = TestCli::try_parse_from([
            "hort-server",
            "enqueue-prefetch-row-retention-sweep",
            "--help",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    /// Constants stay aligned with the release-sweep +
    /// prefetch-tick precedents (trigger-source ranking;
    /// CHECK constraint values). Same priority as the other cron-tier
    /// CronJobs so they drain in the same tier.
    #[test]
    fn constants_match_init33_trigger_source_ranking() {
        assert_eq!(CRON_TRIGGER_SOURCE, "cron");
        assert_eq!(
            CRON_PRIORITY, 10,
            "prefetch-row-retention-sweep must share priority with the other \
             cron-tier CronJobs (quarantine-release-sweep + prefetch-tick); \
             changing this skews the worker claim queue"
        );
    }
}
