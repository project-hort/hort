//! Tracing subscriber + Prometheus recorder install for the worker.
//!
//! Mirrors `hort-server::telemetry` shape verbatim — copy rather than
//! depend on `hort-server` because the worker binary intentionally does
//! NOT depend on the server crate (see lib.rs module doc). The two
//! init bodies stay parallel by construction; if `hort-server`'s
//! telemetry initialiser grows a third side-effect, the worker's must
//! be updated to match.

use anyhow::Context;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::LogFormat;

/// Install the global `tracing` subscriber.
///
/// Filter defaults come from `RUST_LOG` via [`EnvFilter::from_default_env`].
pub fn init_tracing(format: LogFormat) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Pretty => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().pretty())
            .try_init(),
        LogFormat::Json => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .try_init(),
    }
    .context("installing tracing subscriber")?;
    Ok(())
}

/// Install the global Prometheus recorder. The handle is held by the
/// caller for the lifetime of the worker; the heartbeat loop emits
/// `hort_scan_queue_depth` against this recorder.
///
/// Eagerly describe every scanning-pipeline metric so the worker's
/// `/metrics` endpoint carries the full catalog from the first scrape.
/// The metric set stays parallel with `hort-server::telemetry`; the same
/// names appear on both binaries (see `docs/metrics-catalog.md`). The
/// describe pattern is also load-bearing for the describe-defaulting tests
/// in `hort-app::metrics` — see the `register_scan_metrics` doc.
pub fn install_prometheus() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .context("installing prometheus recorder")?;
    hort_app::metrics::register_scan_metrics();
    Ok(handle)
}
