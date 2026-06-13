//! `hort-worker` binary entrypoint.
//!
//! Multi-kind worker. Claims jobs from the shared `jobs` table and
//! dispatches each row to the [`hort_app::task_handlers::TaskHandler`]
//! registered for its `kind` (scan, cron-rescan-tick,
//! advisory-watch-tick, staging-sweep, noop). The scan-specific poll
//! loop is replaced by the generalised [`TaskDispatcher`] driven by a
//! [`CancellationToken`]. The heartbeat loop retains its
//! `watch::channel` mechanism unchanged.
//!
//! Stays trivial — composition lives in
//! [`hort_worker::composition`]; the heartbeat loop lives in
//! [`hort_worker::heartbeat`].

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use hort_worker::cli::{Cli, Command};
use hort_worker::composition;
use hort_worker::config::WorkerConfig;
use hort_worker::{extra_ca, healthcheck, heartbeat, metrics_server, telemetry};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        // No subcommand → run the dispatcher (pre-follow-up default).
        None => run_dispatcher(),
        // k8s livenessProbe exec gate.
        Some(Command::Healthcheck) => run_healthcheck(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Mirror `hort-server`'s Debug-chain dump so the full
            // `anyhow::Context` stack reaches stderr even when the
            // tracing subscriber isn't installed yet (config parse
            // failures).
            eprintln!("hort-worker fatal: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// `hort-worker healthcheck` — k8s livenessProbe exec gate. Builds a
/// single-thread Tokio runtime (the dispatcher's multi-thread
/// runtime is overkill for two awaits) and runs the lightweight env
/// + DB reachability probe.
fn run_healthcheck() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building healthcheck tokio runtime")?;
    rt.block_on(healthcheck::run())
}

#[tokio::main(flavor = "multi_thread")]
async fn run_dispatcher() -> anyhow::Result<()> {
    // 0. Config parse — pre-tracing.
    let cfg = WorkerConfig::from_env().context("parsing environment")?;

    // 1. Tracing + metrics. After this point, tracing reaches stderr
    //    and Prometheus collects emissions.
    telemetry::init_tracing(cfg.minimal.log_format)?;
    // The recorder handle is also served by the worker `/metrics` listener
    // (spawned below once `cancel` exists), so the Prometheus snapshot is
    // scrapeable rather than write-only.
    let metrics_handle = std::sync::Arc::new(
        telemetry::install_prometheus().context("installing prometheus recorder")?,
    );

    tracing::info!(
        worker_id = %cfg.worker_id,
        poll_interval_secs = cfg.poll_interval.as_secs(),
        batch_size = cfg.batch_size,
        max_attempts = cfg.max_attempts,
        lock_duration_secs = cfg.lock_duration.as_secs(),
        "hort-worker starting",
    );

    // 2. Read HORT_EXTRA_CA_BUNDLE — propagate to spawned scanner
    //    subprocesses via SSL_CERT_FILE + capture parsed anchors for
    //    composition's reqwest-using adapters (ADR 0010).
    //    Failures abort boot (an extra-CA bundle that's been
    //    configured but is broken should fail fast at startup, not
    //    silently fall back to public-root-only TLS in a private-CA
    //    deployment).
    let extra_ca = extra_ca::read_and_propagate().context("reading HORT_EXTRA_CA_BUNDLE")?;

    // 3. Build composition. Anchors flow into the OSV advisory
    //    adapter (and any future reqwest-using adapter the worker
    //    constructs); the merged-bundle path flows into the scanner
    //    adapters' `SSL_CERT_FILE` Command env.
    let composition::BuildOutput { ctx, dispatcher } = composition::build_app_context(
        &cfg,
        extra_ca.anchors.as_ref(),
        extra_ca.subprocess_bundle_path.as_deref(),
    )
    .await
    .context("building worker app context")?;

    tracing::info!(
        scanners = ?ctx.scanners,
        worker_id = %ctx.worker_id,
        "hort-worker ready",
    );

    // 3. Shutdown signal.
    //
    // The dispatcher uses a `CancellationToken` for graceful shutdown.
    // The heartbeat loop retains the `watch::channel` mechanism it was
    // designed for; both are flipped from the same OS-signal handler.
    let cancel = CancellationToken::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    install_signal_handlers(cancel.clone(), shutdown_tx);

    // 3b. Spawn the worker `/metrics` listener so the Prometheus recorder
    //     installed above is scrapeable (`hort_provenance_*`, scan series,
    //     queue depth). Bound to `cfg.metrics_bind_addr` (disabled by
    //     default — opt-in; `HORT_WORKER_METRICS_BIND=<pod-addr>` enables,
    //     behind a mandatory NetworkPolicy). A bind failure is logged and
    //     the worker continues — the scrape surface is best-effort
    //     observability, never a hard dependency of job dispatch. Shares
    //     the same `CancellationToken` as the dispatcher, so one SIGTERM
    //     drains it too.
    let metrics = match cfg.metrics_bind_addr {
        Some(addr) => {
            let serve_cancel = cancel.clone();
            let handle = metrics_handle.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = metrics_server::serve(addr, handle, serve_cancel).await {
                    tracing::warn!(error = %e, %addr, "worker metrics listener failed");
                }
            }))
        }
        None => {
            tracing::info!("worker metrics listener disabled (HORT_WORKER_METRICS_BIND=off)");
            None
        }
    };

    // 4. Spawn the dispatcher poll loop + heartbeat loop.
    //
    // The dispatcher owns the `ScanTaskHandler` and drives all task
    // kinds registered with it. It shuts down when `cancel` fires.
    // The heartbeat loop retains its `watch::Receiver<bool>` mechanism.
    let poll_cancel = cancel.clone();
    let poll = tokio::spawn(async move { dispatcher.run(poll_cancel).await });

    let heart_ctx = ctx.clone();
    let heart_rx = shutdown_rx.clone();
    let heart = tokio::spawn(async move { heartbeat::run(heart_ctx, heart_rx).await });

    // 5. Wait for both loops to exit.
    let (poll_result, heart_result) = tokio::join!(poll, heart);

    if let Err(e) = poll_result {
        tracing::error!(error = %e, "poll loop join error");
    } else if let Err(inner) = poll_result.unwrap_or(Ok(())) {
        tracing::error!(error = %inner, "poll loop returned error");
    }
    if let Err(e) = heart_result {
        tracing::error!(error = %e, "heartbeat loop join error");
    }

    // Drain the metrics listener (if running) — it shut down on the same
    // `cancel` signal; join it so its graceful-shutdown completes before
    // the process exits.
    if let Some(metrics) = metrics {
        if let Err(e) = metrics.await {
            tracing::error!(error = %e, "metrics listener join error");
        }
    }

    tracing::info!("hort-worker shutdown complete");
    Ok(())
}

/// Install SIGTERM / SIGINT handlers that flip both the `CancellationToken`
/// (for the `TaskDispatcher`) and the `watch::Sender` (for the heartbeat
/// loop). Both receive the same shutdown signal from OS handlers.
fn install_signal_handlers(cancel: CancellationToken, tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        wait_for_signal().await;
        cancel.cancel();
        let _ = tx.send(true);
    });
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(%err, "failed to register SIGTERM handler — shutdown disabled");
                std::future::pending::<()>().await;
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(%err, "failed to register SIGINT handler — shutdown disabled");
                std::future::pending::<()>().await;
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM — beginning graceful shutdown"),
            _ = sigint.recv()  => tracing::info!("received SIGINT — beginning graceful shutdown"),
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "ctrl_c handler failed");
        } else {
            tracing::info!("received Ctrl+C — beginning graceful shutdown");
        }
    }
}
