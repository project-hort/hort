//! `hort-worker healthcheck` subcommand body.
//!
//! Two checks, in order, both fast:
//!
//! 1. `WorkerConfig::from_env()` — proves the env is well-formed
//!    (DSN present and parseable, log-format selector valid, etc.).
//! 2. A single `SELECT 1` against the configured Postgres DSN —
//!    proves the network path + credentials reach the server. The
//!    worker's hot path is the `claim_pending_by_kinds` query; if
//!    `SELECT 1` fails, the worker has no useful work it can do.
//!
//! What it deliberately does NOT do:
//!   - **Start the dispatcher** — the k8s probe checks reachability, not
//!     liveness of the work loop. (Wedged-but-alive-worker detection via
//!     `scanner_registry.last_heartbeat` staleness is *operator-driven*, not
//!     automated: `hort admin workers list` / `GET /api/v1/admin/workers`
//!     surfaces each worker's `live` flag + last-heartbeat age, so an
//!     operator can spot a stale worker — but no probe/alert reads the
//!     staleness automatically yet. The probe here does not attempt it.)
//!     The probe's responsibility is "did the binary boot far enough that
//!     env + DB are reachable".
//!   - **Probe Trivy or osv-scanner** — those are scan-time concerns.
//!     A broken scanner binary makes scan jobs fail, but the worker
//!     process itself is still healthy in the k8s sense.
//!   - **Initialise tracing or Prometheus** — the probe runs every
//!     few seconds; subscriber init would emit a startup log line
//!     each time and bloat the audit trail.
//!
//! Returns `anyhow::Result<()>` so the caller (the `main` dispatch in
//! `cli`) can map `Ok` → `ExitCode::SUCCESS` and `Err` → `ExitCode::FAILURE`
//! while emitting a single human-readable diagnostic to stderr on
//! failure. The probe must complete inside the chart's
//! `livenessProbe.timeoutSeconds` budget (default 3s in the chart).

use std::time::Duration;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;

use crate::config::WorkerConfig;

/// Total wall-clock budget for the probe. Strictly below the chart's
/// default `livenessProbe.timeoutSeconds=3` so a slow DB doesn't push
/// the whole probe over the cliff.
const PROBE_BUDGET: Duration = Duration::from_millis(2_500);

/// Connect-acquire budget. The pool is built with `max_connections=1`
/// — there is no warm pool to draw from on each probe invocation.
/// Keep this strictly below `PROBE_BUDGET` so a non-routable DB host
/// fails the probe inside its own budget rather than at the parent
/// timeout.
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Run the healthcheck. Caller maps the result to a process exit code.
pub async fn run() -> anyhow::Result<()> {
    // 1. Parse env. Cheap, fully synchronous, no I/O.
    let cfg = WorkerConfig::from_env().context("parsing worker environment")?;

    // 2. Open a 1-connection pool, run `SELECT 1`, drop the pool. The
    //    pool deliberately uses `max_connections=1` so the probe
    //    doesn't briefly blow past the operator's pool sizing.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
        .connect(&cfg.minimal.database_url)
        .await
        .context("opening postgres connection")?;

    let probe = async {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&pool)
            .await
            .context("SELECT 1")?;
        Ok::<(), anyhow::Error>(())
    };

    // Belt-and-braces: outer timeout caps the whole future even if a
    // misbehaving driver swallows the inner pool-level deadline. The
    // probe runs from a k8s exec invocation; any drift past the
    // chart's `timeoutSeconds` looks like the probe failed and the
    // pod restarts unnecessarily.
    tokio::time::timeout(PROBE_BUDGET, probe)
        .await
        .context("healthcheck timed out")??;

    pool.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    // The healthcheck has two failure modes (env parse / DB reach)
    // and one success mode. The env-parse failure is exercised by
    // `crate::config::tests` (which already covers every required-var
    // missing case); the DB-reach success/failure paths require a
    // real Postgres, so they live in the workspace's DB-gated
    // integration suite.
    //
    // We pin the constants here so a casual edit doesn't push the
    // probe past the chart's `timeoutSeconds=3` default by accident.
    use super::*;

    #[test]
    fn probe_budget_strictly_below_chart_timeout() {
        // Chart default `livenessProbe.timeoutSeconds = 3`.
        assert!(
            PROBE_BUDGET < Duration::from_secs(3),
            "PROBE_BUDGET ({PROBE_BUDGET:?}) must stay below the chart's livenessProbe.timeoutSeconds=3"
        );
    }

    #[test]
    fn pool_acquire_timeout_strictly_below_probe_budget() {
        assert!(
            POOL_ACQUIRE_TIMEOUT < PROBE_BUDGET,
            "POOL_ACQUIRE_TIMEOUT ({POOL_ACQUIRE_TIMEOUT:?}) must stay below \
             PROBE_BUDGET ({PROBE_BUDGET:?}) so a non-routable DB fails inside \
             the probe's own budget"
        );
    }
}
