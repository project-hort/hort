//! Global `tracing` subscriber and Prometheus recorder install.
//!
//! Called exactly once from `main` before any other step. Any `tracing`
//! call made before [`init_tracing`] runs is silently dropped; any metric
//! emitted before [`install_prometheus`] is lost.

use anyhow::Context;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::LogFormat;

/// Install the global tracing subscriber.
///
/// Filter defaults come from `RUST_LOG` via [`EnvFilter::from_default_env`].
/// Format is selected by [`LogFormat`] — pretty for local dev, json for
/// production log-aggregation pipelines.
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

/// Install the global Prometheus recorder and return the scrape handle.
///
/// The returned handle is passed to
/// [`crate::composition::build_app_context`] so `GET /metrics` can render
/// the latest snapshot.
///
/// Immediately after install, eagerly describe every scan-pipeline
/// metric (see `docs/metrics-catalog.md`, ADR 0017) so /metrics
/// carries the catalog from the first
/// scrape, even for metrics whose increments fire only in the worker
/// (hort-server scrapes the /metrics surface; the worker emits
/// `hort_artifact_became_vulnerable_total` and friends). Without eager
/// registration the metric is absent from /metrics until something
/// fires it, which makes operator "is scanning wired up?" probes
/// fail on a healthy cold start.
pub fn install_prometheus() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .context("installing prometheus recorder")?;
    hort_app::metrics::register_scan_metrics();
    Ok(handle)
}
