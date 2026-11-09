//! `hort-server enqueue-api-token-retention-sweep` — scheduled
//! credential-store retention-sweep enqueue.
//!
//! A **DB-only** enqueue subcommand the Helm CronJob (and the matching
//! systemd timer on the native deploy) runs daily. It inserts a single
//! `kind = 'api-token-retention-sweep'` row into `public.jobs` using the
//! **runtime DSN** — the always-on worker (`hort-worker`) then claims the
//! row and dispatches to
//! [`ApiTokenRetentionSweepHandler`](
//!     hort_app::task_handlers::ApiTokenRetentionSweepHandler), which
//! deletes a `public.api_tokens` row whose own `expires_at` is more than
//! the horizon (default 90 days) in the past, or whose own `revoked_at`
//! is.
//!
//! **A row with both marks NULL is a durable identity that never
//! expires, and it survives**: each disjunct of the predicate requires
//! that row's own mark to be present, so a both-NULL row matches
//! neither. That is the property worth knowing at this layer too,
//! because this is the surface an operator reaches for when they want the
//! sweep to run now — the sweep's reach is "credentials that have been
//! dead for 90 days", not "credentials".
//!
//! Unlike its three siblings, the `DELETE` behind this subcommand lands
//! outside the task queue, on the table that decides who may do what.
//! The 90-day window is also the decision that the deleted row's
//! `last_used_at` / `last_used_ip` / `last_used_user_agent` are not worth
//! keeping past it — those three live nowhere else in the system.
//!
//! ## Why a DB-only subcommand instead of `hort-cli admin task invoke`
//!
//! Mirrors the `enqueue-jobs-row-retention-sweep` /
//! `enqueue-scan-row-retention-sweep` /
//! `enqueue-prefetch-row-retention-sweep` precedent: an out-of-the-box
//! schedulable tick going through the `hort-cli` HTTP admin-task path
//! would drag the whole `svc-token-bootstrap` Job chain (and a standing
//! `admin_task_invoke` token mount) to default-on. The runtime DSN is
//! least-privilege — it can `INSERT INTO public.jobs` and read the
//! schema, full stop. Reversing that for the **credential store** of all
//! tables is the last place it would be worth doing.
//!
//! The kind is in `ADMIN_INVOKABLE_TASK_KINDS`, so an operator-driven
//! enqueue is authorised by the same model as any other admin task —
//! but that constant is the set of kinds an admin may enqueue at all,
//! not the router's list. There is **no per-kind HTTP invoke route**: the
//! `hort-http-admin-tasks` router enumerates its routes explicitly and
//! no retention kind is among them, so a `POST
//! /api/v1/admin/tasks/api-token-retention-sweep` reaches no invoke
//! handler — it falls through to that router's `GET /{id}` pattern, which
//! carries no `post` and therefore answers `405`. An ad-hoc run is this
//! subcommand, which — like the CronJob and the systemd timer that call
//! it — takes no arguments and writes `params` unconditionally empty. So
//! the handler's 90-day `DEFAULT_HORIZON` is the horizon in force on
//! every supported path; a different one needs a hand-written `INSERT`
//! into `public.jobs`, and the handler's 365-day cap is what keeps such a
//! row from becoming a year-wide window on the credential store.
//!
//! ## Configuration
//!
//! Parses [`MinimalConfig`] (NOT `Config::from_env` — ADR 0009: DB-only
//! subcommands must not consume the full serve-config surface). The env
//! footprint shrinks to the DSN (`HORT_DATABASE_URL`, falling back to
//! bare `DATABASE_URL` — ADR 0029) plus log/metric tunables; the CronJob
//! template need set nothing beyond what `hort-server.runtimeEnv` already
//! populates.
//!
//! ## Idempotency
//!
//! The worker's claim query naturally short-circuits a duplicate enqueue
//! (two ticks back-to-back) — the first claim transitions `pending →
//! running`; subsequent ticks just queue more rows. The DELETE itself is
//! idempotent: a second run finds the first run's rows already gone, so
//! it deletes nothing. No explicit dedup is needed at the CronJob layer,
//! and the kind is not an ADR 0028 destructive kind — a second run cannot
//! destroy more than the first.

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
/// than by seven constants agreeing.
const KIND: &str = "api-token-retention-sweep";

/// Arguments to `hort-server enqueue-api-token-retention-sweep`.
///
/// No flags — the subcommand's single purpose is "enqueue one row."
/// Deliberately argument-less rather than exposing the horizon: a
/// `--horizon-days` flag here would make the retention window on the
/// credential store settable per invocation, with no audit of who chose
/// what, which is the opposite of what the handler's single documented
/// default exists to guarantee.
#[derive(Debug, Args)]
pub struct EnqueueApiTokenRetentionSweepArgs {}

/// Synchronous entry point. Delegates to [`super::run_with_runtime`]
/// which builds a Tokio runtime, runs [`run_async`], and maps the result
/// to a process exit code. The CronJob's success criterion is **exit code
/// only**: `0` on a successful insert, non-zero on connect/insert failure
/// (next cron tick retries).
pub fn run(args: EnqueueApiTokenRetentionSweepArgs) -> ExitCode {
    super::run_with_runtime(move || run_async(args), |_| ExitCode::SUCCESS)
}

async fn run_async(_args: EnqueueApiTokenRetentionSweepArgs) -> anyhow::Result<()> {
    // DB-only subcommand → MinimalConfig, NOT Config::from_env
    // (ADR 0009). The CronJob pod's env block then needs only the DB DSN
    // + log format (via `hort-server.runtimeEnv` in the chart).
    let cfg = MinimalConfig::from_env().context("parsing environment")?;
    telemetry::init_tracing(cfg.log_format)?;
    info!("enqueueing api-token-retention-sweep job");

    let pool = PgPoolOptions::new()
        .connect_with(pg_identity::connect_options(&cfg.database_url)?)
        .await
        .context("connecting to postgres")?;

    let jobs: Arc<dyn JobsRepository> = Arc::new(PgJobsRepository::new(pool));

    // The `params` jsonb is empty — the handler uses the default
    // retention horizon (90 days) when `horizon_seconds` is absent.
    // `actor_id` is `None` because the scheduled path is system-driven (a
    // CronJob is not a human caller; the runtime DSN owns nothing
    // identity-wise).
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
        .context("enqueueing api-token-retention-sweep job")?;
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
        "api-token-retention-sweep job enqueued"
    );
    // One-line summary on stdout for shell capture — operators tail
    // CronJob pod logs to confirm the enqueue happened; the job_id makes
    // the row trivially greppable in the events / jobs tables.
    println!("enqueue-api-token-retention-sweep: job_id={id}");
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

    /// Parses with zero positional/optional args — the subcommand has no
    /// surface beyond the bare invocation. Pins the v1 shape so a future
    /// `#[arg(long)]` addition is a deliberate change, which for this
    /// subcommand specifically means a deliberate decision to make the
    /// credential store's retention window settable per invocation.
    #[test]
    fn enqueue_api_token_retention_sweep_parses_bare_invocation() {
        let cli = TestCli::try_parse_from(["hort-server", "enqueue-api-token-retention-sweep"])
            .expect("parse");
        let super::super::Command::EnqueueApiTokenRetentionSweep(_) = cli.command else {
            panic!("expected EnqueueApiTokenRetentionSweep variant");
        };
    }

    /// Unknown flag must fail — guards against typos in the CronJob
    /// template silently no-op'ing.
    #[test]
    fn enqueue_api_token_retention_sweep_rejects_unknown_flag() {
        let err = TestCli::try_parse_from([
            "hort-server",
            "enqueue-api-token-retention-sweep",
            "--bogus",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `--help` renders (clap-reported "error" via try_parse_from).
    #[test]
    fn enqueue_api_token_retention_sweep_help_renders() {
        let err =
            TestCli::try_parse_from(["hort-server", "enqueue-api-token-retention-sweep", "--help"])
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

    /// The kind this subcommand inserts is the kind the handler claims,
    /// read off the handler rather than re-typed.
    ///
    /// A `jobs` row whose `kind` no dispatcher recognises is not a
    /// compile error and not a failed enqueue: it sits `pending`
    /// forever, so the sweep silently stops running while the CronJob
    /// keeps reporting success. The two literals used to be able to
    /// drift; this is what stops them.
    #[test]
    fn the_enqueued_kind_is_the_one_the_handler_dispatches_on() {
        use hort_domain::ports::task_handler::TaskHandler;
        let handler = hort_app::task_handlers::ApiTokenRetentionSweepHandler::new(Arc::new(
            hort_app::use_cases::test_support::MockApiTokenRepository::new(),
        ));
        assert_eq!(KIND, handler.kind());
    }
}
