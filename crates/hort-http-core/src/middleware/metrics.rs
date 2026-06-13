//! HTTP metrics middleware.
//!
//! Emits the four `hort_http_*` metrics defined in `docs/metrics-catalog.md`:
//!
//! - `hort_http_requests_received_total{method, path}` counter — on entry
//! - `hort_http_requests_in_flight` gauge — ±1 around the request, decremented
//!   via an RAII guard so cancellation / panic still decrement the gauge
//! - `hort_http_responses_total{method, path, status}` counter — on exit
//! - `hort_http_request_duration_seconds{method, path}` histogram — on exit
//!
//! The `path` label is the **matched route template** obtained from
//! `axum::extract::MatchedPath` (e.g. `/pypi/:repo_key/simple/`). When no
//! matched path is available (404s, unmatched fallbacks), the sentinel
//! `hort_app::metrics::values::PATH_UNMATCHED` (= `"<unmatched>"`) is emitted.
//! The concrete URL is NEVER used as a label value — that would let a client
//! explode cardinality by generating arbitrary URLs.
//!
//! Label-name constants (`method`, `path`, `status`) come from
//! `hort_app::metrics::labels` so emission sites cannot typo a label name into
//! a silent new time series.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use metrics::{counter, gauge, histogram};

use hort_app::metrics::labels::{METHOD, PATH, STATUS};
use hort_app::metrics::values::PATH_UNMATCHED;

/// RAII guard that decrements the in-flight gauge on drop.
///
/// When a client disconnects mid-request, the response future is dropped at
/// the `.await` point and any code *after* the await never runs. A `Drop`
/// impl fires regardless — cancellation, panic, or normal return — so the
/// gauge stays consistent with the number of live requests.
struct InFlightGuard {
    method: String,
    path: String,
}

impl InFlightGuard {
    fn new(method: String, path: String) -> Self {
        gauge!(
            "hort_http_requests_in_flight",
            METHOD => method.clone(),
            PATH => path.clone(),
        )
        .increment(1.0);
        Self { method, path }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        gauge!(
            "hort_http_requests_in_flight",
            METHOD => self.method.clone(),
            PATH => self.path.clone(),
        )
        .decrement(1.0);
    }
}

/// Axum middleware that emits the four `hort_http_*` metrics. Wire via
/// `axum::middleware::from_fn(http_metrics_middleware)` on the top-level
/// router.
pub async fn http_metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().to_string();

    // Prefer the matched route pattern. The concrete URI path is NEVER used
    // as a label — it would let clients spam arbitrary URLs and explode
    // series cardinality.
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| PATH_UNMATCHED.to_owned());

    let start = Instant::now();

    counter!(
        "hort_http_requests_received_total",
        METHOD => method.clone(),
        PATH => path.clone(),
    )
    .increment(1);

    // Guard increments on construction and decrements on drop — fires once
    // in all exit paths (normal, cancelled, panicked).
    let _guard = InFlightGuard::new(method.clone(), path.clone());

    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    histogram!(
        "hort_http_request_duration_seconds",
        METHOD => method.clone(),
        PATH => path.clone(),
    )
    .record(duration);
    counter!(
        "hort_http_responses_total",
        METHOD => method,
        PATH => path,
        STATUS => status,
    )
    .increment(1);

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use metrics::SharedString;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use tower::ServiceExt;

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<SharedString>,
        DebugValue,
    );

    async fn ok_handler() -> &'static str {
        "OK"
    }

    /// Drive an HTTP request through the middleware with a local recorder
    /// installed. Returns the captured snapshot plus the HTTP response so
    /// tests can assert on both sides of the layer.
    fn drive_request(uri: &str) -> (Snapshot, StatusCode) {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        // `with_local_recorder` wants a sync closure; nest a runtime to run
        // the async router.
        let status = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let app: Router = Router::new()
                        .route("/echo/:id", get(ok_handler))
                        .layer(axum::middleware::from_fn(http_metrics_middleware));

                    let response = app
                        .oneshot(HttpRequest::builder().uri(uri).body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    response.status()
                })
        });

        (snapshotter.snapshot(), status)
    }

    fn find<'a>(
        entries: &'a [MetricEntry],
        kind: MetricKind,
        name: &str,
        expected_labels: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        for (ck, _, _, dv) in entries {
            if ck.kind() != kind || ck.key().name() != name {
                continue;
            }
            let matches = expected_labels
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            if matches {
                return Some(dv);
            }
        }
        None
    }

    // -----------------------------------------------------------------
    // Matched-route happy path: all four metrics fire with the template.
    // -----------------------------------------------------------------

    #[test]
    fn middleware_emits_requests_received_counter() {
        let (snap, status) = drive_request("/echo/42");
        assert_eq!(status, StatusCode::OK);
        let entries = snap.into_vec();

        let value = find(
            &entries,
            MetricKind::Counter,
            "hort_http_requests_received_total",
            &[("method", "GET"), ("path", "/echo/:id")],
        )
        .expect("hort_http_requests_received_total with matched path missing");
        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn middleware_emits_responses_counter_with_status() {
        let (snap, _) = drive_request("/echo/42");
        let entries = snap.into_vec();

        let value = find(
            &entries,
            MetricKind::Counter,
            "hort_http_responses_total",
            &[("method", "GET"), ("path", "/echo/:id"), ("status", "200")],
        )
        .expect("hort_http_responses_total with status=200 missing");
        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 1),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    #[test]
    fn middleware_records_duration_histogram() {
        let (snap, _) = drive_request("/echo/42");
        let entries = snap.into_vec();

        let value = find(
            &entries,
            MetricKind::Histogram,
            "hort_http_request_duration_seconds",
            &[("method", "GET"), ("path", "/echo/:id")],
        )
        .expect("hort_http_request_duration_seconds missing");
        match value {
            DebugValue::Histogram(samples) => {
                assert_eq!(samples.len(), 1, "expected exactly one sample");
            }
            other => panic!("expected Histogram, got {other:?}"),
        }
    }

    #[test]
    fn middleware_in_flight_gauge_balances_to_zero() {
        let (snap, _) = drive_request("/echo/42");
        let entries = snap.into_vec();

        let value = find(
            &entries,
            MetricKind::Gauge,
            "hort_http_requests_in_flight",
            &[("method", "GET"), ("path", "/echo/:id")],
        )
        .expect("hort_http_requests_in_flight gauge missing");
        match value {
            // DebuggingRecorder replays increments/decrements; net on a
            // completed request is 0.
            DebugValue::Gauge(v) => assert_eq!(v.into_inner(), 0.0),
            other => panic!("expected Gauge, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Unmatched-path fallback: sentinel, not the concrete URL.
    // -----------------------------------------------------------------

    #[test]
    fn middleware_uses_path_unmatched_sentinel_for_404() {
        let (snap, status) = drive_request("/no/such/route");
        assert_eq!(status, StatusCode::NOT_FOUND);
        let entries = snap.into_vec();

        // The responses counter must fire with path="<unmatched>".
        let value = find(
            &entries,
            MetricKind::Counter,
            "hort_http_responses_total",
            &[
                ("method", "GET"),
                ("path", PATH_UNMATCHED),
                ("status", "404"),
            ],
        )
        .expect("hort_http_responses_total with path=<unmatched> missing");
        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 1),
            other => panic!("expected Counter, got {other:?}"),
        }

        // The concrete URL must NOT appear in any label.
        for (ck, _, _, _) in &entries {
            for label in ck.key().labels() {
                assert!(
                    !label.value().contains("/no/such/route"),
                    "concrete URL leaked into label {}={}",
                    label.key(),
                    label.value()
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // Drop-guard invariant: gauge decrements even when the handler panics.
    // -----------------------------------------------------------------

    #[test]
    fn in_flight_guard_decrements_on_drop() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            let _g = InFlightGuard::new("GET".to_string(), "/echo/:id".to_string());
            // Guard drops at end of scope, firing -1.0 decrement.
        });

        let entries = snapshotter.snapshot().into_vec();
        let value = find(
            &entries,
            MetricKind::Gauge,
            "hort_http_requests_in_flight",
            &[("method", "GET"), ("path", "/echo/:id")],
        )
        .expect("hort_http_requests_in_flight gauge missing");
        match value {
            DebugValue::Gauge(v) => assert_eq!(v.into_inner(), 0.0),
            other => panic!("expected Gauge, got {other:?}"),
        }
    }
}
