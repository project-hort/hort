//! `hort-server enqueue-scan-row-retention-sweep` — scheduled
//! terminal-scan-row retention-sweep enqueue.
//!
//! A **DB-only** enqueue subcommand the Helm CronJob runs daily
//! (operator-tunable; default `0 3 * * *`). It inserts a single
//! `kind = 'scan-row-retention-sweep'` row into `public.jobs` using
//! the **runtime DSN** — the always-on worker (`hort-worker`) then
//! claims the row and dispatches to
//! [`ScanRowRetentionSweepHandler`](
//!     hort_app::task_handlers::ScanRowRetentionSweepHandler), which
//! deletes terminal (`status IN ('completed', 'failed')`)
//! `kind = 'scan'` rows older than a configurable horizon (default 7
//! days).
//!
//! ## Why a DB-only subcommand instead of `hort-cli admin task invoke`
//!
//! Mirrors the `enqueue-prefetch-row-retention-sweep` precedent: an
//! out-of-the-box schedulable tick going through the `hort-cli` HTTP
//! admin-task path would drag the whole `svc-token-bootstrap` Job chain
//! (and a standing `admin_task_invoke` token mount) to default-on. The
//! runtime DSN is least-privilege — it can `INSERT INTO public.jobs`
//! and read the schema, full stop.
//!
//! There is **no** HTTP invoke route for this kind, so there is no
//! ad-hoc path either. The kind IS in `ADMIN_INVOKABLE_TASK_KINDS` — an
//! operator-driven enqueue is authorised by the same model as any other
//! admin task — but that constant is the set of kinds an admin may
//! enqueue at all, not the router's list: `hort-http-admin-tasks::router()`
//! enumerates its invoke routes one by one and this kind is not among
//! them, so `POST /api/v1/admin/tasks/scan-row-retention-sweep`
//! answers 404. Running one off-schedule means running this
//! subcommand.
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
use hort_domain::ports::jobs_repository::{JobsRepository, TriggerSource};
use hort_domain::types::task_tier::queue_priority;

use crate::config::MinimalConfig;
use crate::{pg_identity, telemetry};

/// `trigger_source` literal for this scheduled CronJob enqueue, taken
/// from the one definition of the set
/// ([`hort_domain::ports::jobs_repository::TriggerSource`]) rather than
/// re-typed beside it — so CHECK membership is a property of the value
/// and this comment does not have to carry a copy of the list.
const CRON_TRIGGER_SOURCE: &str = TriggerSource::Cron.as_str();

/// `jobs.kind` of the row this subcommand enqueues. The ordinal it
/// carries is not named here: it is decided from `(kind,
/// trigger_source)` in `hort_domain::types::task_tier`, so every
/// cron-triggered row drains in the same tier by construction rather
/// than by six constants agreeing.
const KIND: &str = "scan-row-retention-sweep";

/// Arguments to `hort-server enqueue-scan-row-retention-sweep`.
///
/// No flags — the subcommand's single purpose is "enqueue one row."
/// Future tuning (priority, horizon override) would land as
/// `#[arg(long)]` here; pinning the v1 surface to argument-less
/// keeps the CronJob template idempotent and the unit-test parser
/// stable.
#[derive(Debug, Args)]
pub struct EnqueueScanRowRetentionSweepArgs {}

/// Synchronous entry point. Delegates to [`super::run_with_runtime`]
/// which builds a Tokio runtime, runs [`run_async`], and maps the
/// result to a process exit code.
/// The CronJob's success criterion is **exit code only**: `0` on a
/// successful insert, non-zero on connect/insert failure (next cron
/// tick retries).
pub fn run(args: EnqueueScanRowRetentionSweepArgs) -> ExitCode {
    super::run_with_runtime(move || run_async(args), |_| ExitCode::SUCCESS)
}

async fn run_async(_args: EnqueueScanRowRetentionSweepArgs) -> anyhow::Result<()> {
    // DB-only subcommand → MinimalConfig, NOT Config::from_env
    // (ADR 0009). The CronJob pod's env block then needs only the
    // DB DSN + log format (via `hort-server.runtimeEnv` in the chart).
    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;
    info!("enqueueing scan-row-retention-sweep job");

    let pool = PgPoolOptions::new()
        .connect_with(pg_identity::connect_options(&cfg.database_url)?)
        .await
        .context("connecting to postgres")?;

    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool));

    // The `params` jsonb is empty, unconditionally: this subcommand takes
    // no arguments and there is no HTTP invoke route for the kind, so the
    // handler's 7-day `DEFAULT_HORIZON` is the horizon in force on every
    // supported path. `actor_id` is `None` because the scheduled path is
    // system-driven (a CronJob is not a human caller; the runtime DSN
    // owns nothing identity-wise).
    let priority = queue_priority(KIND, CRON_TRIGGER_SOURCE);
    let outcome = jobs
        .enqueue_task(
            KIND,
            &serde_json::json!({}),
            None, // actor_id — system-driven cron
            priority,
            CRON_TRIGGER_SOURCE,
            None, // non-destructive task kind — no DB-side idempotency key (ADR 0028)
        )
        .await
        .context("enqueueing scan-row-retention-sweep job")?;
    let id: Uuid = match outcome {
        hort_domain::ports::jobs_repository::EnqueueOutcome::Enqueued { job_id } => job_id,
        hort_domain::ports::jobs_repository::EnqueueOutcome::Duplicate { existing_job_id } => {
            existing_job_id
        }
    };

    info!(
        job_id = %id,
        kind = KIND,
        priority,
        trigger_source = CRON_TRIGGER_SOURCE,
        "scan-row-retention-sweep job enqueued"
    );
    // One-line summary on stdout for shell capture — operators tail
    // CronJob pod logs to confirm the enqueue happened; the job_id
    // makes the row trivially greppable in the events / jobs tables.
    println!("enqueue-scan-row-retention-sweep: job_id={id}");
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
    fn enqueue_scan_row_retention_sweep_parses_bare_invocation() {
        let cli = TestCli::try_parse_from(["hort-server", "enqueue-scan-row-retention-sweep"])
            .expect("parse");
        let super::super::Command::EnqueueScanRowRetentionSweep(_) = cli.command else {
            panic!("expected EnqueueScanRowRetentionSweep variant");
        };
    }

    /// Unknown flag must fail — guards against typos in the CronJob
    /// template silently no-op'ing.
    #[test]
    fn enqueue_scan_row_retention_sweep_rejects_unknown_flag() {
        let err =
            TestCli::try_parse_from(["hort-server", "enqueue-scan-row-retention-sweep", "--bogus"])
                .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `--help` renders (clap-reported "error" via try_parse_from).
    #[test]
    fn enqueue_scan_row_retention_sweep_help_renders() {
        let err =
            TestCli::try_parse_from(["hort-server", "enqueue-scan-row-retention-sweep", "--help"])
                .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    /// Constants stay aligned with the trigger-source ranking and the
    /// CHECK constraint values. The CronJob template and the worker
    /// dispatch table both reference them implicitly through the
    /// inserted row; a silent drift here would break the claim
    /// ordering.
    ///
    /// The ordinal is asserted as relations rather than as a number by
    /// [`crate::cli::assert_scheduled_maintenance_ordinal`], which is
    /// where the reasoning for both of them lives.
    #[test]
    fn constants_match_cron_trigger_source_ranking() {
        assert_eq!(CRON_TRIGGER_SOURCE, "cron");
        crate::cli::assert_scheduled_maintenance_ordinal(KIND);
    }
}
