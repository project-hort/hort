//! `hort-server enqueue-wheel-metadata-backfill` — scheduled PEP 658
//! metadata backfill enqueue.
//!
//! A **DB-only** enqueue subcommand the Helm CronJob runs to retrofit
//! older PyPI wheels with their PEP 658 metadata blob + the
//! `wheel_metadata` ContentReference row. Inserts a single
//! `kind = 'wheel-metadata-backfill'` row into `public.jobs` using the
//! **runtime DSN** — the always-on worker (`hort-worker`) then claims the
//! row and dispatches to
//! [`WheelMetadataBackfillHandler`](
//!     hort_app::task_handlers::WheelMetadataBackfillHandler).
//!
//! ## Why a DB-only subcommand instead of `hort-cli admin task invoke`
//!
//! Mirrors the release-sweep + prefetch-tick precedent:
//! a default-shipped CronJob going
//! through the `hort-cli` HTTP admin-task path would drag the
//! whole `svc-token-bootstrap` Job chain (and a standing
//! `admin_task_invoke` token mount) to default-on. The runtime DSN is
//! least-privilege — it can `INSERT INTO public.jobs` and read the
//! schema, full stop.
//!
//! The `hort-http-admin-tasks` HTTP route stays available for **manual**
//! operator invocation — `hort-cli admin task invoke
//! wheel-metadata-backfill` works for operators who want to drive one
//! ad-hoc; the default scheduled path bypasses it.
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
//! ## Params
//!
//! The enqueued row's `params` JSON is `{"batch_size": <int>}`. The
//! `--batch-size` flag is optional; omitted, the handler picks
//! [`WheelMetadataBackfillHandler`'s default = 100]. The handler caps
//! at 1000 regardless of operator input.
//!
//! ## Idempotency
//!
//! The worker's claim query naturally drains a duplicate enqueue (two
//! ticks back-to-back) — the first claim transitions `pending →
//! running`; subsequent ticks just queue more rows. The
//! `WheelMetadataBackfillHandler` is resumable by construction
//! ([`ArtifactRepository::find_pypi_wheels_without_kind`](
//!     hort_domain::ports::artifact_repository::ArtifactRepository)
//! re-derives the candidate set on every invocation), so two
//! concurrent runs would walk overlapping sets harmlessly. No
//! explicit dedup is needed at the CronJob layer.

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

/// `trigger_source` literal — `'cron'` mirrors the other scheduled
/// enqueue subcommands. Must match the SQL CHECK constraint on
/// `jobs.trigger_source` (`'manual' | 'cron' | 'advisory' | 'ingest'
/// | 'seed-import' | 'prefetch'`).
const CRON_TRIGGER_SOURCE: &str = "cron";

/// `priority` for the enqueued row. The trigger-source
/// ranking is `ingest=0 → advisory=5 → cron=10 → manual=20`. Matches the
/// release-sweep + prefetch-tick priority — backfill ticks are
/// co-equal with quarantine release sweeps in the cron tier. The
/// worker's claim query orders `priority DESC, created_at ASC`, so
/// this slots into the same drain tier.
const CRON_PRIORITY: i16 = 10;

/// Arguments to `hort-server enqueue-wheel-metadata-backfill`.
///
/// `--batch-size` is the only knob. Mirrors the design doc's per-tick
/// budget; operators tightening below the default 100 are explicitly
/// making the wall-clock vs memory tradeoff. The handler caps at 1000
/// regardless of input.
#[derive(Debug, Args)]
pub struct EnqueueWheelMetadataBackfillArgs {
    /// How many wheel artifacts to walk per invocation. Defaults to
    /// [`hort_app::task_handlers::wheel_metadata_backfill`]'s 100.
    /// Capped at 1000 by the handler.
    #[arg(long, value_name = "N")]
    pub batch_size: Option<u32>,
}

/// Synchronous entry point. Delegates to [`super::run_with_runtime`]
/// which builds a Tokio runtime, runs [`run_async`], and maps the
/// result to a process exit code.
/// The CronJob's success criterion is **exit code only**: `0` on a
/// successful insert, non-zero on connect/insert failure (next cron
/// tick retries).
pub fn run(args: EnqueueWheelMetadataBackfillArgs) -> ExitCode {
    super::run_with_runtime(move || run_async(args), |_| ExitCode::SUCCESS)
}

async fn run_async(args: EnqueueWheelMetadataBackfillArgs) -> anyhow::Result<()> {
    // DB-only subcommand → MinimalConfig, NOT Config::from_env
    // (ADR 0009). The CronJob pod's env block then needs only the
    // DB DSN + log format (via `hort-server.runtimeEnv` in the chart).
    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;
    info!("enqueueing wheel-metadata-backfill job");

    let pool = PgPoolOptions::new()
        .connect(&cfg.database_url)
        .await
        .context("connecting to postgres")?;

    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool));

    // Build the params JSON. Omitted batch-size → empty object; the
    // handler's `resolve_batch_size` falls back to the default.
    let params = match args.batch_size {
        Some(n) => serde_json::json!({ "batch_size": n }),
        None => serde_json::json!({}),
    };

    let outcome = jobs
        .enqueue_task(
            "wheel-metadata-backfill",
            &params,
            None, // actor_id — system-driven cron
            CRON_PRIORITY,
            CRON_TRIGGER_SOURCE,
            None, // non-destructive task kind — no DB-side idempotency key (ADR 0028)
        )
        .await
        .context("enqueueing wheel-metadata-backfill job")?;
    let id: Uuid = match outcome {
        hort_domain::ports::jobs_repository::EnqueueOutcome::Enqueued { job_id } => job_id,
        hort_domain::ports::jobs_repository::EnqueueOutcome::Duplicate { existing_job_id } => {
            existing_job_id
        }
    };

    info!(
        job_id = %id,
        kind = "wheel-metadata-backfill",
        priority = CRON_PRIORITY,
        trigger_source = CRON_TRIGGER_SOURCE,
        batch_size = ?args.batch_size,
        "wheel-metadata-backfill job enqueued"
    );
    // One-line summary on stdout for shell capture — operators tail
    // CronJob pod logs to confirm the enqueue happened; the job_id
    // makes the row trivially greppable in the events / jobs tables.
    println!("enqueue-wheel-metadata-backfill: job_id={id}");
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

    /// Parses with zero positional/optional args — the subcommand
    /// works without flags (the handler picks the default
    /// `batch_size`). Pins the v1 shape.
    #[test]
    fn enqueue_wheel_metadata_backfill_parses_bare_invocation() {
        let cli = TestCli::try_parse_from(["hort-server", "enqueue-wheel-metadata-backfill"])
            .expect("parse");
        let super::super::Command::EnqueueWheelMetadataBackfill(_) = cli.command else {
            panic!("expected EnqueueWheelMetadataBackfill variant");
        };
    }

    /// `--batch-size <N>` parses and round-trips. Operators tightening
    /// below the default invoke via this flag — pinning the flag name
    /// keeps the chart-template `args:` block stable.
    #[test]
    fn enqueue_wheel_metadata_backfill_parses_batch_size() {
        let cli = TestCli::try_parse_from([
            "hort-server",
            "enqueue-wheel-metadata-backfill",
            "--batch-size",
            "250",
        ])
        .expect("parse");
        let super::super::Command::EnqueueWheelMetadataBackfill(args) = cli.command else {
            panic!("expected EnqueueWheelMetadataBackfill variant");
        };
        assert_eq!(args.batch_size, Some(250));
    }

    /// Unknown flag must fail — guards against typos in the CronJob
    /// template silently no-op'ing.
    #[test]
    fn enqueue_wheel_metadata_backfill_rejects_unknown_flag() {
        let err =
            TestCli::try_parse_from(["hort-server", "enqueue-wheel-metadata-backfill", "--bogus"])
                .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `--help` renders (clap-reported "error" via try_parse_from).
    #[test]
    fn enqueue_wheel_metadata_backfill_help_renders() {
        let err =
            TestCli::try_parse_from(["hort-server", "enqueue-wheel-metadata-backfill", "--help"])
                .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    /// Constants stay aligned with the release-sweep + prefetch-tick
    /// precedent (trigger-source ranking; CHECK constraint
    /// values). Same priority as the other cron-tier enqueue
    /// subcommands so they drain in the same tier.
    #[test]
    fn constants_match_init33_trigger_source_ranking() {
        assert_eq!(CRON_TRIGGER_SOURCE, "cron");
        assert_eq!(
            CRON_PRIORITY, 10,
            "wheel-metadata-backfill must share priority with quarantine-release-sweep + \
             prefetch-tick (the cron tier); changing this skews the worker claim queue"
        );
    }
}
