//! Concurrency limit + load shed + per-IP cap.
//!
//! Two axum middleware functions, both attached at
//! [`crate::router::wrap_with_middleware`]:
//!
//! - [`global_load_shed_middleware`] — workspace-wide bound on
//!   in-flight requests. Backed by a single [`tokio::sync::Semaphore`]
//!   shared via `Arc`. Caller fills the bucket via `HORT_MAX_INFLIGHT`
//!   (default 512). When the bucket is full, the request is shed
//!   immediately with `503` plus the
//!   `hort_http_load_shed_total{result="shed"}` metric. No queueing —
//!   the goal is fast-fail under DDoS, not fairness.
//! - [`per_ip_load_shed_middleware`] — per-IP cap. Backed by a
//!   [`dashmap::DashMap`] of `IpAddr → Arc<Semaphore>`. Default 32
//!   in-flight per IP (`HORT_MAX_INFLIGHT_PER_IP`). Reads
//!   [`RequestTrust::client_ip`] from request extensions (populated by
//!   the request trust layer); a missing trust extension surfaces as a 500
//!   rather than silently bypassing the cap (mirrors
//!   [`crate::middleware::rate_limit::TrustAwareKeyExtractor`]).
//!
//! # Threat model
//!
//! tower-governor counts *requests*, not *in-flight work*. An attacker
//! who opens 10 000 long-running OCI blob upload sessions from one IP
//! pins every worker without exceeding the 300/min write bucket: each
//! upload is one request that simply takes minutes to complete. The
//! per-IP cap closes that vector by bounding *concurrent* requests per
//! IP.
//!
//! Defaults pre-approved by the architect skill:
//! - 512 workspace-wide (covers a healthy multi-CI-run environment).
//! - 32 per IP (covers a single CI run with parallel jobs while
//!   throttling botnet probes).
//!
//! # Why not `tower::limit::ConcurrencyLimitLayer` + `tower::load_shed::LoadShedLayer`?
//!
//! Those primitives operate on `Service::poll_ready`. axum 0.7 wraps the
//! `Router` such that each request is dispatched on a fresh `Clone` of
//! the inner service, and `LoadShed` reports `Ready` regardless — so
//! integration with axum's routing semantics requires care around the
//! per-request clone. Implementing the cap as plain axum
//! [`axum::middleware::from_fn`] middleware is structurally simpler and
//! easier to test (every test drives the router via
//! [`tower::ServiceExt::oneshot`]). The semantics — "if no permit,
//! short-circuit with 503" — are equivalent.
//!
//! # Observability
//!
//! - `hort_http_load_shed_total{result, path}` counter, where:
//!   - `result="shed"` — workspace-wide cap hit (the global cap has no
//!     headroom).
//!   - `result="per_ip_shed"` — per-IP cap hit (this IP has no
//!     headroom; other IPs are unaffected).
//!   - `path` — matched route template via
//!     [`axum::extract::MatchedPath`]. Falls back to `<unmatched>` for
//!     404 paths. Mirrors the rate-limit metric label shape.
//! - `tracing::warn!` on every shed event with `client_ip`, `scope`, and
//!   `path` span fields. Operators want to see this — defence-in-depth
//!   tripping is meaningful, not noise.
//! - The 503 response carries `Connection: close` so the kernel TCP
//!   queue drains on a flood instead of pinning the worker.
//!
//! # Hard constraint: cardinality
//!
//! `client_ip` is **never** a metric label — it would let an attacker
//! mint arbitrary series. The IP appears in the warn-log span fields
//! only.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use tokio::sync::Semaphore;

use crate::middleware::trust::RequestTrust;

// ---------------------------------------------------------------------------
// Constants — catalog-aligned label values + defaults
// ---------------------------------------------------------------------------

/// Metric name. Catalog: `docs/metrics-catalog.md`.
pub const HORT_HTTP_LOAD_SHED_TOTAL: &str = "hort_http_load_shed_total";

/// `result=shed` label value — workspace-wide cap rejection.
pub const RESULT_SHED: &str = "shed";

/// `result=per_ip_shed` label value — per-IP cap rejection.
pub const RESULT_PER_IP_SHED: &str = "per_ip_shed";

/// Sentinel `path` label when the request never matched a route template
/// (404s, unmatched fallbacks). Mirrors the rate-limit module's sentinel
/// so dashboards stay consistent.
const PATH_UNMATCHED: &str = "<unmatched>";

/// Default `HORT_MAX_INFLIGHT` — 512 concurrent requests workspace-wide.
pub const DEFAULT_MAX_INFLIGHT: usize = 512;

/// Default `HORT_MAX_INFLIGHT_PER_IP` — 32 concurrent requests per IP.
pub const DEFAULT_MAX_INFLIGHT_PER_IP: usize = 32;

// ---------------------------------------------------------------------------
// Config + state
// ---------------------------------------------------------------------------

/// Concurrency-limit configuration. Sourced from `hort-server::Config` so
/// operators tune without rebuilding. `NonZeroUsize` enforces the
/// non-zero invariant at the type level — config parsing in
/// `Config::from_env` rejects zero with `ConfigError::ValueNotPositive`,
/// and this carrier guarantees the invariant survives all the way to
/// the middleware constructor.
#[derive(Debug, Clone, Copy)]
pub struct ConcurrencyLimitConfig {
    /// Workspace-wide concurrent-request cap. `HORT_MAX_INFLIGHT`.
    pub max_inflight: NonZeroUsize,
    /// Per-IP concurrent-request cap. `HORT_MAX_INFLIGHT_PER_IP`.
    pub max_inflight_per_ip: NonZeroUsize,
}

impl ConcurrencyLimitConfig {
    /// New config with explicit caps.
    pub fn new(max_inflight: NonZeroUsize, max_inflight_per_ip: NonZeroUsize) -> Self {
        Self {
            max_inflight,
            max_inflight_per_ip,
        }
    }
}

impl Default for ConcurrencyLimitConfig {
    /// Production defaults (512 workspace, 32 per-IP). Used by tests
    /// that want the production posture without spelling each value;
    /// production callers always thread the operator-tuned values from
    /// `hort-server::Config`.
    fn default() -> Self {
        Self::new(
            NonZeroUsize::new(DEFAULT_MAX_INFLIGHT).expect("DEFAULT_MAX_INFLIGHT > 0"),
            NonZeroUsize::new(DEFAULT_MAX_INFLIGHT_PER_IP)
                .expect("DEFAULT_MAX_INFLIGHT_PER_IP > 0"),
        )
    }
}

/// Shared middleware state. Holds the workspace-wide semaphore plus the
/// per-IP semaphore map. Cheap to clone (one `Arc` per field).
#[derive(Clone)]
pub struct ConcurrencyLimitState {
    /// Single workspace-wide [`Semaphore`] with `max_inflight` permits.
    /// Each in-flight request holds one permit until the response future
    /// completes.
    global: Arc<Semaphore>,
    /// `IpAddr -> Arc<Semaphore>` with `max_inflight_per_ip` permits per
    /// IP. Lazily populated on first sight of an IP. Bounded memory:
    /// each entry is ~32 bytes plus a small Semaphore allocation; the
    /// theoretical IPv4 worst case is 2^32 entries, but we cap memory
    /// growth via the GC tick (see [`gc_tick`]).
    ///
    /// IPv6: keys are raw `IpAddr`. An attacker holding a routable /48 can mint up to
    /// 2^80 unique /128 source addresses and grow the map without bound. Operators
    /// deploying on IPv6 should put an L4 proxy in front that aggregates source IPs
    /// at /64 or /48, or bucket the keys here using the same /24 (IPv4) /48 (IPv6)
    /// pattern used for the EphemeralStore auth-events key. Track this as a
    /// follow-on if the IPv4-only bound is insufficient for the deployment.
    per_ip: Arc<DashMap<IpAddr, Arc<Semaphore>>>,
    /// Per-IP cap. Stored here (not just on the semaphores) so [`gc_tick`]
    /// can compare `available_permits()` against the cap to identify
    /// fully-drained-and-idle entries.
    per_ip_cap: usize,
}

impl ConcurrencyLimitState {
    /// Construct middleware state for the given config. Allocates the
    /// global semaphore eagerly (cheap) and an empty per-IP map.
    pub fn new(config: ConcurrencyLimitConfig) -> Self {
        Self {
            global: Arc::new(Semaphore::new(config.max_inflight.get())),
            per_ip: Arc::new(DashMap::new()),
            per_ip_cap: config.max_inflight_per_ip.get(),
        }
    }

    /// Test-only accessor — workspace-wide available permits.
    #[cfg(test)]
    pub(crate) fn global_available(&self) -> usize {
        self.global.available_permits()
    }

    /// Test-only accessor — per-IP map size.
    #[cfg(test)]
    pub(crate) fn per_ip_entry_count(&self) -> usize {
        self.per_ip.len()
    }

    /// Test-only accessor — available permits for a specific IP.
    /// Returns `None` if the IP has not been seen yet (no entry).
    #[cfg(test)]
    pub(crate) fn per_ip_available(&self, ip: IpAddr) -> Option<usize> {
        self.per_ip.get(&ip).map(|s| s.available_permits())
    }

    /// Idempotent reaping of fully-released per-IP entries.
    ///
    /// Currently NOT scheduled by `hort-server` — the function is exposed for future wire-up
    /// and is exercised by `gc_tick_removes_idle_entries_and_keeps_busy_ones`. A follow-on
    /// commit can either (a) refactor `wrap_with_middleware` to return the state so the
    /// composition root can spawn a `tokio::time::interval` ticker, or (b) accept an
    /// externally-constructed state. Until then, the per-IP map relies on the documented
    /// bound below; treat any growth pattern that approaches that bound as a signal to
    /// wire option (a) or (b).
    ///
    /// Drops per-IP entries whose semaphore is fully replenished
    /// (`available_permits() == cap`). Bounded by the map size so a
    /// single tick is `O(n)` where `n` is the number of distinct IPs
    /// seen — not the request count.
    ///
    /// Race tolerance: between the check and the remove, another request
    /// may acquire a permit. That's harmless: the worst case is we drop
    /// an entry that immediately gets re-created on the next request.
    /// `DashMap::remove_if` does the comparison + remove atomically per
    /// shard so we never delete a partially-drained entry.
    pub fn gc_tick(&self) {
        let cap = self.per_ip_cap;
        self.per_ip.retain(|_, sem| sem.available_permits() < cap);
    }
}

// ---------------------------------------------------------------------------
// Metric emission
// ---------------------------------------------------------------------------

/// Catalog: `hort_http_load_shed_total{result, path}`.
fn emit_shed_metric(path: String, result: &'static str) {
    metrics::counter!(
        HORT_HTTP_LOAD_SHED_TOTAL,
        "result" => result,
        "path" => path,
    )
    .increment(1);
}

/// Resolve the route template for metric emission. Mirrors the helper
/// in `rate_limit.rs` — extracted so tests can exercise the unmatched
/// branch without axum routing.
fn resolve_matched_path(req: &Request) -> String {
    req.extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| PATH_UNMATCHED.to_owned())
}

/// Build the canonical 503 response. No body — the shed event is a
/// transport-level signal, not an application error. `Connection: close`
/// is set so the kernel TCP queue drains on a flood instead of letting
/// the attacker pin the worker by holding the socket open.
fn shed_response() -> Response {
    let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

// ---------------------------------------------------------------------------
// Workspace-wide load-shed middleware
// ---------------------------------------------------------------------------

/// Workspace-wide concurrency cap with immediate load-shed on overflow.
///
/// Try-acquires one permit from the global semaphore on every request:
/// success means we're under the cap and the inner handler runs;
/// failure means every worker is busy and we shed the request with 503.
/// The permit is held by the future's stack frame, so dropping the
/// future (cancellation, panic, normal completion) releases it.
///
/// Wire via [`axum::middleware::from_fn_with_state`] in
/// [`crate::router::wrap_with_middleware`].
pub async fn global_load_shed_middleware(
    State(state): State<ConcurrencyLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(permit) = state.global.clone().try_acquire_owned() else {
        let path = resolve_matched_path(&request);
        let client_ip = request
            .extensions()
            .get::<RequestTrust>()
            .map(|t| t.client_ip.to_string());
        tracing::warn!(
            client_ip = client_ip.as_deref().unwrap_or("<unknown>"),
            scope = RESULT_SHED,
            path = %path,
            "workspace-wide concurrency cap reached; shedding request"
        );
        emit_shed_metric(path, RESULT_SHED);
        return shed_response();
    };

    // Permit held until the future returns; the inner handler can
    // freely await IO / DB / storage without us re-acquiring.
    // The permit is held across `next.run(request).await`, which resolves once the
    // inner handler produces `Response<Body>`. The response body then streams to the
    // client outside this middleware's stack frame, so the cap binds to request-body
    // consumption (the OCI blob upload threat), NOT to response-body
    // streaming. For response-body slowloris guards see request_timeout.
    let response = next.run(request).await;
    drop(permit);
    response
}

// ---------------------------------------------------------------------------
// Per-IP load-shed middleware
// ---------------------------------------------------------------------------

/// Per-IP concurrency cap with immediate load-shed on overflow.
///
/// Reads `client_ip` from [`RequestTrust`] (populated by the request
/// trust layer). On a missing extension surfaces 500 — same conservative
/// failure mode as [`crate::middleware::rate_limit::TrustAwareKeyExtractor`].
/// Get-or-inserts an `Arc<Semaphore>` for that IP and try-acquires one
/// permit; failure sheds with 503 and the
/// `result=per_ip_shed` metric label.
///
/// Memory bound: the [`DashMap`] grows with the number of distinct IPs
/// seen until [`ConcurrencyLimitState::gc_tick`] removes idle entries.
/// At 2^16 distinct IPv4 sources the per-IP table is ~2 MiB — bounded
/// even before GC.
pub async fn per_ip_load_shed_middleware(
    State(state): State<ConcurrencyLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(client_ip) = request
        .extensions()
        .get::<RequestTrust>()
        .map(|t| t.client_ip)
    else {
        // Composition bug — `RequestTrust` middleware did not run. 503 would mean
        // "too many requests"; this is a router-wiring failure, not a capacity event,
        // so 500 is the honest signal. Surface explicitly rather than silently
        // bypassing the cap.
        tracing::error!(
            "per-IP load-shed: RequestTrust missing from extensions; \
             router-wiring bug — refusing to bypass cap"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    // Get-or-insert the per-IP semaphore. `entry().or_insert_with` is
    // atomic per shard; concurrent first-sight requests for the same
    // IP race on the same Arc<Semaphore>, which is correct.
    let sem = state
        .per_ip
        .entry(client_ip)
        .or_insert_with(|| Arc::new(Semaphore::new(state.per_ip_cap)))
        .clone();

    let Ok(permit) = sem.try_acquire_owned() else {
        let path = resolve_matched_path(&request);
        tracing::warn!(
            client_ip = %client_ip,
            scope = RESULT_PER_IP_SHED,
            path = %path,
            "per-IP concurrency cap reached; shedding request"
        );
        emit_shed_metric(path, RESULT_PER_IP_SHED);
        return shed_response();
    };

    // Permit-release timing: same as `global_load_shed_middleware` — held across
    // `next.run(request).await` only, so the cap binds to request-body consumption,
    // not response-body streaming. See the comment at the global path for the full
    // rationale.
    let response = next.run(request).await;
    drop(permit);
    response
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::sync::Arc as StdArc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use axum::Router;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use crate::middleware::trust::RequestTrust;

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn trust_with_ip(ip: &str) -> RequestTrust {
        RequestTrust {
            client_ip: ip.parse().unwrap(),
            public_url: url::Url::parse("http://hort-server/").unwrap(),
        }
    }

    fn req_with_trust(uri: &str, t: RequestTrust) -> HttpRequest<Body> {
        let mut r = HttpRequest::get(uri).body(Body::empty()).unwrap();
        r.extensions_mut().insert(t);
        r
    }

    fn cfg(global: usize, per_ip: usize) -> ConcurrencyLimitConfig {
        ConcurrencyLimitConfig::new(
            NonZeroUsize::new(global).unwrap(),
            NonZeroUsize::new(per_ip).unwrap(),
        )
    }

    fn find_counter<'a>(
        entries: &'a [MetricEntry],
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != MetricKind::Counter || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    fn capture<T, F>(f: F) -> (Snapshot, T)
    where
        F: FnOnce() -> T,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let out = metrics::with_local_recorder(&recorder, f);
        (snapshotter.snapshot(), out)
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
    }

    /// Slow handler that blocks until released by a `Notify`. Used to
    /// pin permits while the test fires concurrent requests.
    async fn slow_handler(notify: StdArc<Notify>) -> &'static str {
        notify.notified().await;
        "ok"
    }

    /// Build a router with both load-shed layers attached. `notify` is
    /// the gate the slow_handler awaits — leaks of in-flight requests
    /// stay parked until `notify_waiters()` fires.
    fn build_test_router(state: ConcurrencyLimitState, notify: &StdArc<Notify>) -> Router {
        let n = notify.clone();
        Router::new()
            .route("/slow", get(move || slow_handler(n.clone())))
            // Order mirrors `wrap_with_middleware` (per-IP innermost,
            // global outermost) so the global cap fires first under
            // distributed flood; per-IP fires when a single attacker
            // pins all their slots regardless of global headroom.
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                per_ip_load_shed_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state,
                global_load_shed_middleware,
            ))
    }

    // ------------------------------------------------------------------
    // Config + state
    // ------------------------------------------------------------------

    #[test]
    fn config_default_matches_documented_defaults() {
        let c = ConcurrencyLimitConfig::default();
        assert_eq!(c.max_inflight.get(), DEFAULT_MAX_INFLIGHT);
        assert_eq!(c.max_inflight_per_ip.get(), DEFAULT_MAX_INFLIGHT_PER_IP);
    }

    #[test]
    fn state_initial_global_permits_match_config() {
        let state = ConcurrencyLimitState::new(cfg(8, 2));
        assert_eq!(state.global_available(), 8);
        assert_eq!(state.per_ip_entry_count(), 0);
    }

    // ------------------------------------------------------------------
    // resolve_matched_path — no axum routing required
    // ------------------------------------------------------------------

    #[test]
    fn resolve_matched_path_falls_back_to_unmatched_sentinel() {
        let req = HttpRequest::get("/anything").body(Body::empty()).unwrap();
        assert_eq!(resolve_matched_path(&req), PATH_UNMATCHED);
    }

    // ------------------------------------------------------------------
    // shed_response — body + headers
    // ------------------------------------------------------------------

    #[test]
    fn shed_response_is_503_with_connection_close_and_no_body() {
        let r = rt();
        let (status, conn, body) = r.block_on(async {
            let res = shed_response();
            let status = res.status();
            let conn = res
                .headers()
                .get(header::CONNECTION)
                .map(|v| v.to_str().unwrap().to_string());
            let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
            (status, conn, body)
        });
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(conn.as_deref(), Some("close"));
        assert_eq!(body.len(), 0, "shed response must carry no body");
    }

    // ------------------------------------------------------------------
    // Workspace-wide cap (acceptance test scaled to a tractable size)
    // ------------------------------------------------------------------

    /// The acceptance test asks for 600-concurrent / 512-cap. We exercise
    /// the same property with cap=8 / 12 concurrent — semantics are
    /// identical, runtime is much shorter. Per-IP cap is set high enough
    /// not to bind so the global cap is the binding constraint.
    ///
    /// Implementation note: we drive every request on a current-thread
    /// runtime via [`futures::future::join_all`] (no `tokio::spawn`) so
    /// the [`metrics::with_local_recorder`] thread-local stays in scope
    /// for the metric assertion. Spawned tasks would inherit a
    /// different recorder and the counter assertion would always
    /// observe zero increments.
    #[test]
    fn global_cap_admits_at_most_n_concurrent_remainder_shed() {
        let state = ConcurrencyLimitState::new(cfg(8, 100));
        let notify = StdArc::new(Notify::new());

        // Single-threaded runtime so `metrics::with_local_recorder`
        // covers every future polled by the executor (the recorder is
        // a thread-local).
        let r = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (snap, (success_count, shed_count)) = capture(|| {
            r.block_on(async {
                let router = build_test_router(state, &notify);

                // Build 12 oneshot futures (one per request), each from a
                // distinct IP so the per-IP cap never binds. The
                // futures are polled cooperatively on the current thread.
                let mut futures = Vec::new();
                for i in 0..12u8 {
                    let router = router.clone();
                    let trust = trust_with_ip(&format!("10.0.0.{i}"));
                    futures.push(async move {
                        router
                            .oneshot(req_with_trust("/slow", trust))
                            .await
                            .unwrap()
                            .status()
                    });
                }

                // Release the gate AFTER `join_all` has had a chance to
                // poll each future once: the 8 admitted requests park on
                // the `notified()` await, the 4 over-cap requests return
                // 503 from the load-shed middleware before reaching the
                // handler. Joining `notify_waiters` and `join_all` via
                // `tokio::join!` lets both progress cooperatively.
                let release = async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    notify.notify_waiters();
                };
                let (statuses, _) = tokio::join!(futures::future::join_all(futures), release,);

                let mut success_count = 0;
                let mut shed_count = 0;
                for status in statuses {
                    match status {
                        StatusCode::OK => success_count += 1,
                        StatusCode::SERVICE_UNAVAILABLE => shed_count += 1,
                        other => panic!("unexpected status {other}"),
                    }
                }
                (success_count, shed_count)
            })
        });

        assert_eq!(success_count, 8, "global cap must admit exactly 8");
        assert_eq!(shed_count, 4, "remaining 4 must shed");

        // Metric: exactly `shed_count` shed events (the workspace-wide
        // cap is the only binding constraint here, so every shed fires
        // `result=shed`).
        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            HORT_HTTP_LOAD_SHED_TOTAL,
            &[("result", RESULT_SHED), ("path", "/slow")],
        )
        .expect("hort_http_load_shed_total result=shed counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == shed_count as u64));
    }

    // ------------------------------------------------------------------
    // Per-IP cap: 33 concurrent from one IP → 32 succeed, 1 shed
    // ------------------------------------------------------------------

    #[test]
    fn per_ip_cap_admits_at_most_n_concurrent_per_ip_remainder_shed() {
        // Per-IP cap=4, global cap large enough to never bind.
        let state = ConcurrencyLimitState::new(cfg(100, 4));
        let notify = StdArc::new(Notify::new());

        let r = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (snap, (success, shed)) = capture(|| {
            r.block_on(async {
                let router = build_test_router(state, &notify);
                let mut futures = Vec::new();
                for _ in 0..5 {
                    let router = router.clone();
                    futures.push(async move {
                        router
                            .oneshot(req_with_trust("/slow", trust_with_ip("10.0.0.1")))
                            .await
                            .unwrap()
                            .status()
                    });
                }
                let release = async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    notify.notify_waiters();
                };
                let (statuses, _) = tokio::join!(futures::future::join_all(futures), release);

                let mut success = 0;
                let mut shed = 0;
                for status in statuses {
                    match status {
                        StatusCode::OK => success += 1,
                        StatusCode::SERVICE_UNAVAILABLE => shed += 1,
                        other => panic!("unexpected status {other}"),
                    }
                }
                (success, shed)
            })
        });

        assert_eq!(success, 4, "per-IP cap must admit exactly 4");
        assert_eq!(shed, 1, "remainder must shed");

        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            HORT_HTTP_LOAD_SHED_TOTAL,
            &[("result", RESULT_PER_IP_SHED), ("path", "/slow")],
        )
        .expect("hort_http_load_shed_total result=per_ip_shed counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // ------------------------------------------------------------------
    // Per-IP cap: distinct IPs have independent buckets
    // ------------------------------------------------------------------

    #[test]
    fn per_ip_cap_isolates_distinct_ips() {
        let state = ConcurrencyLimitState::new(cfg(100, 2));
        let notify = StdArc::new(Notify::new());

        let r = rt();
        let (success_a, success_b) = r.block_on(async {
            let router = build_test_router(state, &notify);
            let mut handles = Vec::new();
            // 2 from IP A and 2 from IP B — both should succeed.
            for ip in ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2"] {
                let router = router.clone();
                let ip = ip.to_string();
                let h = tokio::spawn(async move {
                    let trust = trust_with_ip(&ip);
                    let status = router
                        .oneshot(req_with_trust("/slow", trust))
                        .await
                        .unwrap()
                        .status();
                    (ip, status)
                });
                handles.push(h);
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
            notify.notify_waiters();

            let mut success_a = 0;
            let mut success_b = 0;
            for h in handles {
                let (ip, status) = h.await.unwrap();
                if status == StatusCode::OK {
                    if ip == "10.0.0.1" {
                        success_a += 1;
                    } else if ip == "10.0.0.2" {
                        success_b += 1;
                    }
                } else {
                    panic!("unexpected shed for {ip}: {status}");
                }
            }
            (success_a, success_b)
        });

        assert_eq!(success_a, 2, "all 2 from IP A admitted");
        assert_eq!(success_b, 2, "all 2 from IP B admitted");
    }

    // ------------------------------------------------------------------
    // Permit release: completed request frees the per-IP semaphore
    // ------------------------------------------------------------------

    #[test]
    fn completed_request_releases_per_ip_permit() {
        let state = ConcurrencyLimitState::new(cfg(100, 2));
        let notify = StdArc::new(Notify::new());
        let state_for_assert = state.clone();

        let r = rt();
        r.block_on(async {
            let router = build_test_router(state, &notify);
            // Drive a single request to completion.
            let trust = trust_with_ip("10.0.0.1");
            let h = tokio::spawn({
                let router = router.clone();
                async move {
                    router
                        .oneshot(req_with_trust("/slow", trust))
                        .await
                        .unwrap()
                        .status()
                }
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            notify.notify_waiters();
            assert_eq!(h.await.unwrap(), StatusCode::OK);
        });

        // After the request completes, the IP's semaphore is fully
        // replenished — its available_permits matches the per-IP cap.
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(state_for_assert.per_ip_available(ip), Some(2));
    }

    // ------------------------------------------------------------------
    // GC: idle entries are removed
    // ------------------------------------------------------------------

    #[test]
    fn gc_tick_removes_idle_entries_and_keeps_busy_ones() {
        let state = ConcurrencyLimitState::new(cfg(100, 4));
        let ip_idle: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_busy: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Manually populate two entries: idle (full) and busy (one
        // permit out). Shortcuts the request flow to keep the test
        // synchronous.
        state
            .per_ip
            .insert(ip_idle, Arc::new(Semaphore::new(state.per_ip_cap)));
        let busy = Arc::new(Semaphore::new(state.per_ip_cap));
        let _holding = busy.clone().try_acquire_owned().unwrap();
        state.per_ip.insert(ip_busy, busy);

        assert_eq!(state.per_ip_entry_count(), 2);
        state.gc_tick();
        assert_eq!(state.per_ip_entry_count(), 1, "idle entry must be removed");
        assert!(
            state.per_ip.contains_key(&ip_busy),
            "busy entry must be retained"
        );
    }

    // ------------------------------------------------------------------
    // Per-IP middleware on missing trust → 500 (no silent bypass)
    // ------------------------------------------------------------------

    #[test]
    fn per_ip_middleware_returns_500_when_trust_missing() {
        let state = ConcurrencyLimitState::new(cfg(100, 4));
        let notify = StdArc::new(Notify::new());
        let r = rt();
        let status = r.block_on(async {
            let n = notify.clone();
            let router: Router = Router::new()
                .route("/slow", get(move || slow_handler(n.clone())))
                .layer(axum::middleware::from_fn_with_state(
                    state,
                    per_ip_load_shed_middleware,
                ));
            // No RequestTrust inserted on this request.
            let req = HttpRequest::get("/slow").body(Body::empty()).unwrap();
            // Release the gate so a successful pass-through wouldn't park.
            notify.notify_waiters();
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
