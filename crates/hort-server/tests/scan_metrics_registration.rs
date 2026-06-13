//! Eager registration of the vulnerability-scanning metrics renders
//! `# TYPE` lines on /metrics from a cold start.
//!
//! Background: hort-server scrapes /metrics on port 9090; the worker
//! emits `hort_artifact_became_vulnerable_total` (and the rest of the
//! scan-pipeline catalog). Under purely lazy registration, a metric
//! that has never fired is absent from the Prometheus rendered body —
//! which makes operator "is scanning wired up?" probes fail on healthy
//! cold starts. The fix
//! ([`hort_app::metrics::register_scan_metrics`]) pairs each
//! `describe_*!` with a zero-binding `counter!`/`histogram!`/`gauge!`
//! so the Prometheus exporter's registry has every metric on the
//! first scrape. `scripts/native-tests/test-vulnerability-scan.sh`
//! phase 7 asserts exactly the surface this test asserts (the
//! `^# TYPE hort_artifact_became_vulnerable_total` line in
//! `GET /metrics`).
//!
//! The test lives in `hort-server/tests/` because
//! `metrics-exporter-prometheus` is a composition-root concern —
//! hort-app stays exporter-agnostic and exposes only the
//! `metrics::Recorder`-shaped registration helper. hort-server is the
//! crate that already declares `metrics-exporter-prometheus` (it's
//! the exporter we ship) so the rendered-text regression sits next
//! to the wiring it tests.

use metrics_exporter_prometheus::PrometheusBuilder;

/// Every vulnerability-scanning metric must appear on the rendered
/// `/metrics` surface after the eager-registration helper runs, even
/// before any producer has fired. Kept in sync with
/// `docs/metrics-catalog.md §Vulnerability scanning` and the body of
/// [`hort_app::metrics::register_scan_metrics`].
const SCAN_METRICS: &[&str] = &[
    "hort_scan_jobs_total",
    "hort_scan_findings_total",
    "hort_scan_duration_seconds",
    "hort_scan_queue_depth",
    "hort_advisory_query_total",
    "hort_sbom_extraction_total",
    "hort_artifact_became_vulnerable_total",
    "hort_scan_record_outcome_failures_total",
];

#[test]
fn eager_scan_metric_registration_renders_type_lines_on_prometheus_handle() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::with_local_recorder(&recorder, || {
        hort_app::metrics::register_scan_metrics();
    });
    let rendered = handle.render();

    for name in SCAN_METRICS {
        let needle = format!("# TYPE {name}");
        assert!(
            rendered.contains(&needle),
            "expected rendered /metrics body to contain `{needle}` after \
             eager registration. Rendered body:\n{rendered}",
        );
    }
}
