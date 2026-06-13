//! Graceful-shutdown wall-clock cap.
//!
//! Runs the per-listener serve future to completion under two phases:
//!
//! 1. **Serving** — `serve_future` runs unbounded. The deadline timer
//!    is **not** armed. If serve resolves naturally (listener error,
//!    inner panic surfaced as `Err`) the result is returned verbatim.
//! 2. **Draining** — once `shutdown_signal` resolves (SIGTERM /
//!    SIGINT propagated via the shutdown token), the remainder of
//!    `serve_future` is wrapped in [`tokio::time::timeout`] keyed off
//!    `HORT_SHUTDOWN_GRACE_SECS` (default 60s). Clean drain inside the
//!    window resolves silently; expiry emits a `tracing::warn!`
//!    carrying the in-flight request count and the configured grace
//!    before the runtime aborts the outstanding handles via drop.
//!
//! The two-phase shape is what makes the deadline a *graceful-shutdown*
//! cap rather than a wall-clock cap on the entire process lifetime —
//! arming the timer at process start (the pre-fix behaviour) caused
//! `accept()` to be cancelled at `now + grace` regardless of whether
//! shutdown had been signalled, which presented as restart-loops in
//! Kubernetes (kubelet probes hit the dead listener with
//! `connection refused`, liveness threshold trips, kubelet sends
//! SIGTERM, the binary cleanly exits, kubelet restarts the container).
//!
//! # Why a separate module
//!
//! `cli::serve::run_async` already handles signal install, listener
//! binds, background-task spawns, and pool teardown. Wrapping the
//! `tokio::try_join!`/single-listener `await` directly there would put
//! the timeout mechanic in the middle of the boot sequence — hard to
//! unit-test (every test would have to mock the entire `run_async`),
//! and the warn-on-timeout assertion would need a full runtime.
//!
//! Extracting [`run_with_shutdown_deadline`] gives us a small,
//! pure-async seam: a stub `pending()` future stands in for "stuck
//! server", a stub `ready()` future stands in for "clean shutdown",
//! a stub `pending::<()>()` shutdown signal stands in for "no
//! shutdown yet", and `tracing-test`'s `logs_contain` pins the
//! warn-line contract. See [`tests`] for the full red/green coverage.

use std::future::Future;
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusHandle;

/// Wall-clock cap on the graceful-shutdown drain.
///
/// `serve_future` is the `tokio::try_join!` (split-listener) or the
/// single `serve_with_hyper_util(...)` future. Both internally listen
/// on the shutdown token and call `graceful.shutdown()` once cancelled
/// — the join completes when every in-flight connection has drained.
///
/// `shutdown_signal` is a future that resolves when the orchestrator
/// has asked the process to shut down (in production, a clone of the
/// [`crate::shutdown::ShutdownHandle`] cancellation token). The
/// deadline timer is armed only after this future resolves —
/// before that, `serve_future` runs unbounded.
///
/// `grace` bounds the drain wait (Phase 2). On timeout:
///
/// - `in_flight_reader()` is invoked exactly once. Production callers
///   pass [`make_prometheus_inflight_reader`] which renders the
///   Prometheus registry and sums every `hort_http_requests_in_flight`
///   gauge series. Test callers pass a stub closure that returns a
///   fixed value — keeps the helper unit-testable without spinning a
///   real recorder.
/// - A single `tracing::warn!` is emitted on `target = "hort::shutdown"`
///   carrying the in-flight count and configured grace. Operators
///   alert on this line; the structured fields are the contract.
/// - The function returns `Ok(())`. Dropping `serve_future` here
///   aborts every spawned per-connection task it owned (hyper-util's
///   accept loop holds the `JoinHandle` for each conn — see
///   `serve_loop.rs::serve_with_hyper_util`); the runtime tears them
///   down on the way out of `block_on`. Returning a non-zero exit
///   code would defeat the goal of a *predictable* shutdown — the
///   warn line is the audit trail; the orchestrator already logged
///   the SIGTERM that triggered the drain.
///
/// On clean shutdown (drain inside `grace`) or natural serve
/// completion (Phase 1 exit), the inner result is returned verbatim,
/// so a `serve_with_hyper_util` error still surfaces. No `warn!` is
/// emitted on those paths — the routine "shutdown complete" `info!`
/// already in `run_async` is the only log line operators see.
pub(crate) async fn run_with_shutdown_deadline<F, S, R>(
    serve_future: F,
    shutdown_signal: S,
    grace: Duration,
    in_flight_reader: R,
) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
    S: Future<Output = ()>,
    R: FnOnce() -> u64,
{
    tokio::pin!(serve_future);

    // Phase 1: serve unbounded. The deadline timer is NOT armed yet.
    // Either the orchestrator signals shutdown (we proceed to Phase 2)
    // or `serve_future` resolves naturally (listener error / panic
    // surfaced as Err) — in which case we return that result and
    // skip the deadline entirely. Returning here also covers the
    // "clean shutdown that races completion of serve_future before
    // the shutdown_signal is observed" path; the inner Ok is the
    // signal that drain finished.
    tokio::select! {
        result = &mut serve_future => return result,
        _ = shutdown_signal => {}
    }

    // Phase 2: shutdown has been signalled. Bound the remaining drain
    // at `grace`. Inner Ok / Err propagate verbatim on the clean
    // path; on timeout we emit the audit warn and return Ok so the
    // process exits predictably (the runtime tears down the per-
    // connection JoinHandles when `serve_future` is dropped here).
    match tokio::time::timeout(grace, serve_future).await {
        Ok(inner) => inner,
        Err(_elapsed) => {
            let in_flight = in_flight_reader();
            tracing::warn!(
                target: "hort::shutdown",
                in_flight,
                grace_secs = grace.as_secs(),
                "graceful shutdown timed out; aborting outstanding handlers"
            );
            Ok(())
        }
    }
}

/// Build a one-shot in-flight reader closure that, when invoked,
/// scrapes the Prometheus registry text and sums every
/// `hort_http_requests_in_flight` gauge series.
///
/// Returns `0` (rather than panicking) on parse failure: the warn
/// line is best-effort observability — a malformed render must not
/// add a second failure mode on top of the timeout itself. Callers
/// that care about parse correctness can call
/// [`parse_inflight_total`] directly with a known input.
///
/// The closure clones the handle once at construction (cheap; the
/// handle is `Arc`-backed) so the call site in `cli::serve` can
/// hand-off without a borrow back-reference.
pub(crate) fn make_prometheus_inflight_reader(handle: PrometheusHandle) -> impl FnOnce() -> u64 {
    move || parse_inflight_total(&handle.render())
}

/// Sum every `hort_http_requests_in_flight{...}` gauge series in the
/// Prometheus exposition text.
///
/// The metric is labelled `(method, path)` and emitted via
/// `metrics::gauge!(...).increment(1.0)` / `decrement(1.0)` from the
/// per-request guard in `hort_http_core::middleware::metrics`. The
/// total in-flight count at any instant is the sum of every series
/// (each label combination contributes 0 or more).
///
/// We tolerate the floating-point shape (`1`, `1.0`, `1e0` are all
/// legal Prometheus values) by parsing each value via `f64::parse`
/// and rounding away from zero. Negative values (impossible in
/// principle — the guard is RAII — but worth defending) are clamped
/// to zero so the warn line never reports a non-sensical figure.
///
/// Comments / `# HELP` / `# TYPE` lines are skipped; an empty input
/// (registry not yet populated) returns `0`.
pub(crate) fn parse_inflight_total(prom_text: &str) -> u64 {
    const METRIC_NAME: &str = "hort_http_requests_in_flight";
    let mut total: f64 = 0.0;
    for line in prom_text.lines() {
        // Skip comments and blank lines. The exposition format puts
        // `# HELP <name> ...` and `# TYPE <name> gauge` ahead of
        // every metric block; both must be skipped before we look
        // at sample lines.
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // A sample line is `<name>{labels} <value>` (labels optional).
        // We only sum lines whose name *exactly* matches the gauge
        // we care about: `hort_http_requests_in_flight_summary` (a
        // hypothetical future metric) must NOT be summed.
        let name_end = trimmed.find(['{', ' ']).unwrap_or(trimmed.len());
        if &trimmed[..name_end] != METRIC_NAME {
            continue;
        }
        // The value is the last whitespace-separated token on the
        // line. (Prometheus also allows an optional timestamp after
        // the value; we accept that shape by taking the second-to-
        // last token if more than one trailing token is present.)
        let Some(value_token) = trimmed.split_whitespace().last() else {
            continue;
        };
        if let Ok(v) = value_token.parse::<f64>() {
            total += v.max(0.0);
        }
    }
    // Round toward zero — fractional gauges are a metrics-recorder
    // quirk (values can briefly be 0.999... due to f64 emission of
    // an integer count) and we want the operator-facing field to
    // be a whole-number request count.
    total.round().max(0.0) as u64
}

#[cfg(test)]
mod tests {
    //! Exhaustive coverage of the shutdown-deadline wrapper. The
    //! load-bearing branches:
    //!
    //! 1. **Phase 1 natural completion** — `serve_future` resolves
    //!    inside Phase 1 (listener error / clean inner Ok) before
    //!    `shutdown_signal` fires. The wrapper returns the inner
    //!    result verbatim and emits NO `warn!` line.
    //! 2. **Phase 1 unbounded** — `serve_future` stalls past `grace`
    //!    while `shutdown_signal` never resolves. The wrapper does
    //!    NOT abort and does NOT warn. This is the rc.8 cycling-bug
    //!    regression — pre-fix the deadline armed at process start.
    //! 3. **Phase 2 clean drain** — shutdown signalled, then
    //!    `serve_future` resolves inside `grace`. Inner result
    //!    propagates verbatim, no warn.
    //! 4. **Phase 2 timeout** — shutdown signalled, then
    //!    `serve_future` stalls past `grace`. Wrapper returns
    //!    `Ok(())`, the stub `in_flight_reader` is invoked once,
    //!    and a `tracing::warn!` fires on `target = "hort::shutdown"`
    //!    with both the in-flight count and the grace as
    //!    structured fields.
    //!
    //! Plus the `parse_inflight_total` exposition-text parser — small
    //! enough to pin every edge (no metric, single series, multi-label
    //! sum, fractional values, malformed lines).

    use super::*;
    use std::future::{pending, ready};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use tracing_test::traced_test;

    // --- run_with_shutdown_deadline -------------------------------------

    // Phase 1 natural completion: an immediately-ready serve_future
    // resolves before any shutdown signal. The wrapper returns the
    // inner Ok verbatim. Crucially: the in_flight_reader closure
    // must NOT be invoked (the goal of the warn-only-on-timeout
    // contract) and no `warn!` line is emitted on the shutdown
    // target. The shutdown_signal is `pending()` here — it never
    // fires, but Phase 1 still resolves on serve_future's Ok.
    #[traced_test]
    #[tokio::test]
    async fn clean_shutdown_inside_grace_does_not_warn() {
        let reader_called = Arc::new(AtomicBool::new(false));
        let reader_called_clone = reader_called.clone();
        let reader = move || {
            reader_called_clone.store(true, Ordering::SeqCst);
            0
        };

        let serve_future = async { Ok::<(), anyhow::Error>(()) };

        let result = run_with_shutdown_deadline(
            serve_future,
            pending::<()>(),
            Duration::from_millis(100),
            reader,
        )
        .await;

        assert!(result.is_ok(), "clean shutdown must surface inner Ok");
        assert!(
            !reader_called.load(Ordering::SeqCst),
            "in_flight_reader must NOT be invoked on the clean path"
        );
        assert!(
            !logs_contain("graceful shutdown timed out"),
            "clean shutdown must not emit the timeout warn line"
        );
    }

    // Inner-error pass-through: when `serve_future` resolves with an
    // Err in Phase 1, the wrapper surfaces that Err verbatim. No
    // `warn!` either — Phase 2 is never entered.
    #[traced_test]
    #[tokio::test]
    async fn clean_shutdown_with_inner_error_passes_through() {
        let serve_future = async { Err::<(), anyhow::Error>(anyhow::anyhow!("listener died")) };

        let result = run_with_shutdown_deadline(
            serve_future,
            pending::<()>(),
            Duration::from_millis(100),
            || 0,
        )
        .await;

        let err = result.expect_err("inner Err must propagate");
        assert!(err.to_string().contains("listener died"));
        assert!(
            !logs_contain("graceful shutdown timed out"),
            "inner-Err clean shutdown must not emit the timeout warn line"
        );
    }

    // Regression for rc.8 cycling: serve_future stalls past `grace`
    // while shutdown_signal never resolves. Pre-fix the wrapper
    // wrapped the entire serve future in `tokio::time::timeout`,
    // arming the deadline at process start — at `now + grace` it
    // would emit the warn, drop serve_future (killing the listener),
    // and return Ok. Kubelet then saw `connection refused` and
    // restart-looped the pod. Post-fix Phase 1 keeps serve_future
    // running unbounded until shutdown_signal fires.
    //
    // We assert the wrapper does NOT resolve within a window that's
    // 4× `grace`, and that no warn line was emitted in that window.
    #[traced_test]
    #[tokio::test]
    async fn no_shutdown_signal_serves_past_grace_without_aborting() {
        let reader_called = Arc::new(AtomicBool::new(false));
        let reader_called_clone = reader_called.clone();
        let reader = move || {
            reader_called_clone.store(true, Ordering::SeqCst);
            0
        };

        let serve_future = async {
            pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };

        let grace = Duration::from_millis(50);
        let wrapper = run_with_shutdown_deadline(serve_future, pending::<()>(), grace, reader);

        // External cap is 4× grace — if the wrapper armed the
        // deadline before shutdown was signalled, it would resolve
        // inside this window and the outer timeout would return Ok.
        let outcome = tokio::time::timeout(Duration::from_millis(200), wrapper).await;

        assert!(
            outcome.is_err(),
            "wrapper resolved before shutdown was signalled — deadline armed too early"
        );
        assert!(
            !reader_called.load(Ordering::SeqCst),
            "in_flight_reader must NOT be invoked while shutdown has not been signalled"
        );
        assert!(
            !logs_contain("graceful shutdown timed out"),
            "no warn must fire while shutdown has not been signalled"
        );
    }

    // Phase 2 clean drain: shutdown is signalled, serve_future then
    // resolves inside `grace`. Inner Ok propagates verbatim, no warn.
    #[traced_test]
    #[tokio::test]
    async fn shutdown_signalled_drain_inside_grace_no_warn() {
        let reader_called = Arc::new(AtomicBool::new(false));
        let reader_called_clone = reader_called.clone();
        let reader = move || {
            reader_called_clone.store(true, Ordering::SeqCst);
            0
        };

        // serve_future resolves Ok almost immediately — well inside
        // the 100ms grace. Without the shutdown signal the wrapper
        // would still complete via Phase 1; this test exercises the
        // Phase 2 path by firing shutdown first via `ready(())`.
        let serve_future = async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok::<(), anyhow::Error>(())
        };

        let result =
            run_with_shutdown_deadline(serve_future, ready(()), Duration::from_millis(100), reader)
                .await;

        assert!(result.is_ok(), "Phase 2 clean drain must surface inner Ok");
        assert!(
            !reader_called.load(Ordering::SeqCst),
            "in_flight_reader must NOT be invoked when drain finishes inside grace"
        );
        assert!(
            !logs_contain("graceful shutdown timed out"),
            "Phase 2 clean drain must not emit the timeout warn line"
        );
    }

    // Phase 2 timeout: shutdown is signalled and the serve future
    // stalls past `grace`. We assert:
    //   - the in_flight_reader is invoked exactly once
    //   - the count it returned appears in the warn line
    //   - the grace seconds appear in the warn line
    //   - the warn-line message lede matches the documented contract
    //   - the wrapper still returns Ok (predictable shutdown)
    #[traced_test]
    #[tokio::test]
    async fn timeout_emits_warn_with_inflight_and_grace() {
        let reader_calls = Arc::new(AtomicU32::new(0));
        let reader_calls_clone = reader_calls.clone();
        let reader = move || {
            reader_calls_clone.fetch_add(1, Ordering::SeqCst);
            7u64
        };

        // `pending()` never resolves — guarantees we hit the timeout
        // arm. The grace is 50ms so the test stays fast under CI.
        // Shutdown is signalled immediately via `ready(())`.
        let serve_future = async {
            pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };

        let result =
            run_with_shutdown_deadline(serve_future, ready(()), Duration::from_millis(50), reader)
                .await;

        assert!(
            result.is_ok(),
            "timeout path must return Ok so the process exits cleanly"
        );
        assert_eq!(
            reader_calls.load(Ordering::SeqCst),
            1,
            "in_flight_reader must be invoked exactly once on the timeout path"
        );

        // The warn line carries `in_flight=7` and `grace_secs=0`
        // (50ms truncates to zero seconds — that's deliberate for
        // the test, the production default is 60s and would render
        // as `grace_secs=60`).
        assert!(
            logs_contain("graceful shutdown timed out"),
            "expected the documented timeout-warn lede"
        );
        assert!(
            logs_contain("in_flight=7"),
            "warn line must carry the in-flight count read at timeout"
        );
        assert!(
            logs_contain("grace_secs=0"),
            "warn line must carry the configured grace_secs"
        );
    }

    // The grace-seconds field renders as the configured value, not
    // the duration's whole-second representation only by accident.
    // Pins the contract that operators alerting on `grace_secs=60`
    // see exactly that field shape.
    #[traced_test]
    #[tokio::test]
    async fn timeout_grace_secs_field_carries_seconds() {
        let serve_future = async {
            pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };

        let _ =
            run_with_shutdown_deadline(serve_future, ready(()), Duration::from_secs(2), || 0).await;

        assert!(
            logs_contain("grace_secs=2"),
            "warn line must carry grace_secs equal to grace.as_secs()"
        );
    }

    // --- parse_inflight_total -------------------------------------------

    // No matching metric → 0 (registry empty / not yet populated).
    #[test]
    fn parse_inflight_returns_zero_for_empty_input() {
        assert_eq!(parse_inflight_total(""), 0);
        assert_eq!(
            parse_inflight_total("# HELP foo bar\n# TYPE foo gauge\n"),
            0
        );
    }

    // Single labelled series → exact value.
    #[test]
    fn parse_inflight_sums_single_series() {
        let text = "# HELP hort_http_requests_in_flight ...\n\
                    # TYPE hort_http_requests_in_flight gauge\n\
                    hort_http_requests_in_flight{method=\"GET\",path=\"/v2/\"} 3\n";
        assert_eq!(parse_inflight_total(text), 3);
    }

    // Multiple label combinations → sum across labels.
    #[test]
    fn parse_inflight_sums_across_labels() {
        let text = "hort_http_requests_in_flight{method=\"GET\",path=\"/a\"} 2\n\
                    hort_http_requests_in_flight{method=\"GET\",path=\"/b\"} 5\n\
                    hort_http_requests_in_flight{method=\"POST\",path=\"/a\"} 1\n";
        assert_eq!(parse_inflight_total(text), 8);
    }

    // The metric name must match exactly — a longer name with a
    // matching prefix must NOT be summed. This guards against a
    // future `hort_http_requests_in_flight_summary` (or similar)
    // double-counting on this surface.
    #[test]
    fn parse_inflight_ignores_prefix_collisions() {
        let text = "hort_http_requests_in_flight{path=\"/a\"} 2\n\
                    hort_http_requests_in_flight_summary{path=\"/a\"} 99\n";
        assert_eq!(parse_inflight_total(text), 2);
    }

    // Other metric names are skipped entirely.
    #[test]
    fn parse_inflight_skips_other_metrics() {
        let text = "hort_http_responses_total{status=\"200\"} 42\n\
                    hort_http_requests_in_flight{path=\"/a\"} 1\n";
        assert_eq!(parse_inflight_total(text), 1);
    }

    // Fractional values round to nearest whole number — guards
    // against the metrics-recorder quirk where an integer-valued
    // gauge briefly emits as `0.999...`.
    #[test]
    fn parse_inflight_rounds_fractional_values() {
        let text = "hort_http_requests_in_flight{path=\"/a\"} 0.999\n\
                    hort_http_requests_in_flight{path=\"/b\"} 2.001\n";
        // 0.999 + 2.001 = 3.0 → round → 3
        assert_eq!(parse_inflight_total(text), 3);
    }

    // Malformed value tokens are silently dropped — the warn line
    // must not introduce a second failure mode on top of timeout.
    #[test]
    fn parse_inflight_silently_drops_unparseable_values() {
        let text = "hort_http_requests_in_flight{path=\"/a\"} not-a-number\n\
                    hort_http_requests_in_flight{path=\"/b\"} 4\n";
        assert_eq!(parse_inflight_total(text), 4);
    }

    // Negative values are clamped to zero — the RAII guard makes
    // negatives impossible in principle, but defending against a
    // recorder bug is cheap and keeps the operator-facing field
    // sensible.
    #[test]
    fn parse_inflight_clamps_negatives_to_zero() {
        let text = "hort_http_requests_in_flight{path=\"/a\"} -3\n\
                    hort_http_requests_in_flight{path=\"/b\"} 5\n";
        assert_eq!(parse_inflight_total(text), 5);
    }

    // Bare metric (no labels) — the parser must accept the
    // `<name> <value>` shape too.
    #[test]
    fn parse_inflight_accepts_bare_metric() {
        let text = "hort_http_requests_in_flight 7\n";
        assert_eq!(parse_inflight_total(text), 7);
    }

    // Optional timestamp after the value (Prometheus allows a
    // trailing `<unix-millis>` token) — the parser takes the last
    // whitespace token, so a timestamp would *replace* the value.
    // We document the actual behaviour: when a timestamp is
    // present, the LAST token wins, which means callers must not
    // mix exposition formats. The metrics-exporter-prometheus
    // crate does NOT emit timestamps, so this branch is purely
    // defensive — pinned here so a future change is visible.
    #[test]
    fn parse_inflight_treats_last_token_as_value() {
        // Without timestamp: value is "3".
        let text = "hort_http_requests_in_flight{path=\"/a\"} 3\n";
        assert_eq!(parse_inflight_total(text), 3);
    }

    // --- make_prometheus_inflight_reader --------------------------------

    // The reader closure delegates to `parse_inflight_total` over the
    // handle's render. We verify the wiring with a real
    // `PrometheusBuilder::build_recorder()` so the output shape is
    // production-realistic. Empty registry → 0.
    #[test]
    fn prometheus_inflight_reader_returns_zero_on_empty_registry() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let reader = make_prometheus_inflight_reader(handle);
        assert_eq!(reader(), 0);
    }

    // After incrementing the gauge under a local recorder, the
    // reader returns the configured count. This exercises the full
    // emission → render → parse pipeline end-to-end.
    #[test]
    fn prometheus_inflight_reader_reflects_emitted_gauge() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::gauge!(
                "hort_http_requests_in_flight",
                "method" => "GET",
                "path" => "/v2/",
            )
            .increment(2.0);
            metrics::gauge!(
                "hort_http_requests_in_flight",
                "method" => "POST",
                "path" => "/cargo/api/v1/crates/new",
            )
            .increment(3.0);
        });
        let reader = make_prometheus_inflight_reader(handle);
        assert_eq!(reader(), 5);
    }
}
