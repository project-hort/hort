//! The worker's internal-only `GET /metrics` Prometheus scrape listener.
//!
//! The worker installs a Prometheus recorder at boot ([`crate::telemetry::
//! install_prometheus`]) but had no scrape endpoint, leaving every worker
//! metric (`hort_provenance_verify_total`, `hort_provenance_reject_total`,
//! the scanning-pipeline series, queue depth) write-only. This module
//! stands up a single-route axum listener serving the recorder's snapshot,
//! mirroring `hort-server`'s admin-`/metrics` shape
//! (`hort_http_core::handlers::metrics::render_metrics`).
//! See `docs/metrics-catalog.md` for the full metric catalog.
//!
//! # Security posture (design §3.6 / M1)
//!
//! The endpoint reveals `repository` label values (repo names) and traffic
//! shape — the same reconnaissance surface the server's admin `/metrics`
//! carries. The protection is **the operator-chosen bind + a mandatory
//! NetworkPolicy**, not a new auth mechanism: the listener is **disabled by
//! default** (`HORT_WORKER_METRICS_BIND` unset → `None`,
//! [`crate::config::parse_metrics_bind_addr`]). Operators enabling scraping
//! set a pod-network address for a cluster Prometheus and restrict it with a
//! NetworkPolicy. Unlike the server's admin `/metrics`, there is **no
//! per-request auth** — the worker has no inbound-HTTP auth stack to reuse, so
//! the network is the control (a declared deviation from design M1; see the
//! `metrics_bind_addr` field doc). No new auth-catalog entry is introduced.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio_util::sync::CancellationToken;

/// Prometheus exposition content type — version 0.0.4 is the stable text
/// format emitted by [`PrometheusHandle::render`]. Mirrors
/// `hort_http_core::handlers::metrics`.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Render the current Prometheus snapshot held by the worker's
/// [`PrometheusHandle`]. Same body shape as the server's `render_metrics`
/// (which is bound to `AppContext` and so cannot be reused directly by the
/// non-HTTP-edge worker).
async fn render(State(handle): State<Arc<PrometheusHandle>>) -> impl IntoResponse {
    let body = handle.render();
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        body,
    )
}

/// Build the one-route metrics `Router` (`GET /metrics`). Separated from
/// [`serve`] so it is drivable in tests via `ServiceExt::oneshot` without
/// binding a socket.
pub fn router(handle: Arc<PrometheusHandle>) -> Router {
    Router::new()
        .route("/metrics", get(render))
        .with_state(handle)
}

/// Bind the worker metrics listener on `addr` and serve `GET /metrics` until
/// `cancel` fires (graceful shutdown). A bind failure is returned to the
/// caller — the worker logs it and continues (the scrape surface is
/// best-effort observability, not a hard dependency of job dispatch).
///
/// Boot `info!` "worker metrics listener bound on …" is emitted by the
/// caller (composition / main) once the listener is bound, per design §6.
pub async fn serve(
    addr: SocketAddr,
    handle: Arc<PrometheusHandle>,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "worker metrics listener bound on {addr}");
    axum::serve(listener, router(handle))
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    /// Emit a worker metric against a local recorder, then scrape the
    /// listener's router → the series is present in the rendered body. This
    /// is the H15 acceptance: a worker metric is no longer write-only.
    #[test]
    fn metrics_route_renders_emitted_series() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = Arc::new(recorder.handle());

        let body_text = metrics::with_local_recorder(&recorder, || {
            // Emit a provenance verdict counter — the exact series H15
            // makes observable.
            hort_app::metrics::emit_provenance_verify(
                "cosign",
                hort_domain::entities::scan_policy::ProvenanceMode::VerifyIfPresent,
                hort_app::metrics::ProvenanceVerifyResult::NoAttestation,
            );

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let response = router(handle.clone())
                        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                        .await
                        .expect("router responds");
                    assert_eq!(response.status(), StatusCode::OK);
                    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                    String::from_utf8(bytes.to_vec()).unwrap()
                })
        });

        assert!(
            body_text.contains("hort_provenance_verify_total"),
            "scrape body must expose the emitted provenance series; got:\n{body_text}"
        );
        assert!(
            body_text.contains("result=\"no_attestation\""),
            "scrape body must carry the result label; got:\n{body_text}"
        );
    }

    /// The render handler sets the Prometheus text content type.
    #[test]
    fn metrics_route_sets_prometheus_content_type() {
        let handle = Arc::new(PrometheusBuilder::new().build_recorder().handle());
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let response = router(handle)
                    .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                    .await
                    .expect("router responds");
                let ct = response
                    .headers()
                    .get(axum::http::header::CONTENT_TYPE)
                    .expect("content-type present")
                    .to_str()
                    .unwrap();
                assert_eq!(ct, PROMETHEUS_CONTENT_TYPE);
            });
    }

    /// `serve` binds, serves one scrape, and shuts down cleanly when the
    /// cancellation token fires — the real socket path + graceful-shutdown
    /// branch. Uses an ephemeral port (`:0`) so the test never collides.
    #[tokio::test]
    async fn serve_binds_and_scrapes_then_shuts_down() {
        let handle = Arc::new(PrometheusBuilder::new().build_recorder().handle());
        let cancel = CancellationToken::new();

        // Bind on an ephemeral port; discover the real addr by binding here
        // first then handing the addr to `serve` is racy, so instead bind a
        // throwaway to learn a free port, drop it, and reuse the addr.
        let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let serve_cancel = cancel.clone();
        let task = tokio::spawn(async move { serve(addr, handle, serve_cancel).await });

        // Poll the listener until it is accepting, then scrape it.
        let url = format!("http://{addr}/metrics");
        let mut last_err = None;
        let mut scraped = false;
        for _ in 0..50 {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(mut stream) => {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let req = format!(
                        "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
                    );
                    stream.write_all(req.as_bytes()).await.unwrap();
                    let mut buf = Vec::new();
                    stream.read_to_end(&mut buf).await.unwrap();
                    let text = String::from_utf8_lossy(&buf);
                    assert!(text.starts_with("HTTP/1.1 200"), "got: {text}");
                    scraped = true;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
        assert!(scraped, "listener never accepted: {last_err:?}; url={url}");

        // Trigger graceful shutdown and confirm the serve future returns Ok.
        cancel.cancel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("serve task joined within timeout")
            .expect("serve task did not panic");
        assert!(result.is_ok(), "serve returned error: {result:?}");
    }
}
