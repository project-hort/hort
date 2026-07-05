//! Per-IP rate limiting (see `docs/auth-catalog.md` for the auth-surface
//! rate-limit/lockout posture).
//!
//! Two [`axum::middleware::from_fn_with_state`] layer builders, both
//! backed by a [`governor`] keyed rate limiter keyed on
//! [`RequestTrust::client_ip`] (read out of request extensions, populated
//! by [`request_trust_layer`]):
//!
//! - [`auth_rate_limit_layer`] — wraps [`require_principal`]. Per-IP
//!   token-bucket limiting auth attempts; bucket cap via
//!   `HORT_RATELIMIT_AUTH_PER_MIN` (default 60).
//! - [`write_rate_limit_layer`] — wraps the POST/PUT/DELETE sub-router.
//!   Per-IP token-bucket limiting write throughput; bucket cap via
//!   `HORT_RATELIMIT_WRITE_PER_MIN` (default 300).
//!
//! # CIDR exemption
//!
//! Traffic whose resolved `client_ip` is in `HORT_RATELIMIT_EXEMPT_CIDRS`
//! bypasses BOTH buckets entirely. First-party CI shares an egress IP (or
//! sits behind one ingress), so it collapses into a single per-IP bucket
//! and would otherwise 429 on legitimate publish bursts. The exemption is
//! an operator-declared allowlist of trusted source ranges; every other
//! IP stays per-IP limited.
//!
//! # Scope overlap (read before tuning defaults)
//!
//! Both layers are attached globally to the same router tree and both
//! apply only to write methods (`POST`/`PUT`/`DELETE`/`PATCH`; reads
//! bypass the governor entirely). A single write request therefore
//! consumes from BOTH buckets simultaneously. With the defaults
//! (auth=60/min, write=300/min) the auth bucket binds first for every
//! single-IP burst against a write route — `scope=write` rejections
//! are only expected when the two caps are configured independently
//! (e.g. `HORT_RATELIMIT_AUTH_PER_MIN=600`, `HORT_RATELIMIT_WRITE_PER_MIN=300`,
//! deliberately letting the write cap be the binding constraint).
//!
//! This is intentional. The two layers defend different threat models:
//!
//! - `scope=auth` fires on credential-stuffing floods (the attacker
//!   presents many tokens, each failing validation). The 60/min
//!   default targets that pattern.
//! - `scope=write` fires on sustained mutation throughput from an
//!   authenticated-or-otherwise attacker (e.g. a compromised CI
//!   token used to upload garbage). The 300/min default targets
//!   higher-throughput abuse that slips past the auth cap because
//!   the operator has deliberately raised it.
//!
//! Operators tuning caps should read both `HORT_RATELIMIT_*_PER_MIN`
//! together: the effective per-POST ceiling is `min(auth, write)`.
//! Narrowing `auth_rate_limit_layer` to a sub-tree that carries only
//! `require_principal` would decouple the two, but the current router
//! applies `require_principal` to the same write-method set via
//! `method_based_auth_dispatch` — so there's no sub-tree to narrow to
//! without a router re-architecture. If a future change splits admin
//! endpoints from format endpoints (different auth caps per surface),
//! revisit the attach points then.
//!
//! # Why key on `RequestTrust::client_ip`, not forwarded headers?
//!
//! Sniffing `X-Forwarded-For` / `X-Real-IP` / `Forwarded` directly —
//! without consulting a trusted-proxy allowlist — would silently bypass
//! the trust policy: an unauthenticated client could set
//! `X-Forwarded-For: 1.2.3.4` and escape their bucket. All peer-IP
//! evaluation lives in [`crate::middleware::trust`]; this module consumes
//! its [`RequestTrust::client_ip`] output and never looks at raw headers.
//! A request that reaches the limiter without `RequestTrust` in
//! extensions (router-wiring bug) surfaces `500` — never a silent
//! bucket-bypass.
//!
//! # Observability
//!
//! On reject: `429 Too Many Requests` with `Retry-After` (whole seconds,
//! floored at 1 so a client never hot-loops on `Retry-After: 0`), a
//! `Content-Type: application/json` `{"error":"too many requests"}` body,
//! plus the [`HORT_RATE_LIMIT_REJECTS_TOTAL`] metric with
//! `scope ∈ {auth, write}` and `path` = route template from
//! [`axum::extract::MatchedPath`] — NOT the concrete URI. Unmatched routes
//! (404 path) surface as `path="<unmatched>"`.
//!
//! [`RequestTrust::client_ip`]: crate::middleware::trust::RequestTrust::client_ip
//! [`request_trust_layer`]: crate::middleware::trust::request_trust_layer
//! [`require_principal`]: crate::middleware::auth::require_principal

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;

use crate::middleware::trust::{cidr_contains, RequestTrust};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Metric name (catalog: `docs/metrics-catalog.md`).
pub const HORT_RATE_LIMIT_REJECTS_TOTAL: &str = "hort_rate_limit_rejects_total";

/// `scope=auth` label value — auth rate-limit rejections.
pub const SCOPE_AUTH: &str = "auth";
/// `scope=write` label value — write-path rate-limit rejections.
pub const SCOPE_WRITE: &str = "write";

/// Sentinel `path` label when the request never matched a route template
/// (e.g. unmatched 404s). Matches the same sentinel used by
/// [`crate::middleware::metrics`] — dashboards stay consistent.
const PATH_UNMATCHED: &str = "<unmatched>";

/// Default `HORT_RATELIMIT_AUTH_PER_MIN` — 60 auth attempts / IP / minute.
pub const DEFAULT_AUTH_PER_MIN: u32 = 60;

/// Default `HORT_RATELIMIT_WRITE_PER_MIN` — 300 writes / IP / minute.
pub const DEFAULT_WRITE_PER_MIN: u32 = 300;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Per-scope rate-limit caps plus the shared CIDR exemption. Sourced from
/// `hort-server::Config` so operators tune without rebuilding. `u32`
/// matches `governor`'s burst type — larger caps would overflow the
/// underlying `NonZeroU32`; validation at parse-time in `Config::from_env`
/// ensures the values here are non-zero.
///
/// Not `Copy`: `exempt_cidrs` holds an `Arc<Vec<IpNet>>` so both layer
/// builders share one allocation of the operator's allowlist.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Auth attempts per IP per minute. Wraps `require_principal`.
    pub auth_per_min: u32,
    /// Writes per IP per minute. Wraps POST/PUT/DELETE routes.
    pub write_per_min: u32,
    /// Source ranges exempt from BOTH buckets. Parsed from
    /// `HORT_RATELIMIT_EXEMPT_CIDRS`; empty when unset. A resolved
    /// `client_ip` inside any of these ranges bypasses rate limiting.
    pub exempt_cidrs: Arc<Vec<IpNet>>,
}

impl RateLimitConfig {
    /// New config with explicit caps and exemption ranges. Callers
    /// (production `hort-server::Config`, tests) supply values; the
    /// non-zero cap invariant is enforced by [`build_keyed_limiter`]'s
    /// assert at construction time — zero would make `Quota` reject the
    /// burst and the builder panic at startup. Treat zero as an operator
    /// misconfiguration.
    pub fn new(auth_per_min: u32, write_per_min: u32, exempt_cidrs: Vec<IpNet>) -> Self {
        Self {
            auth_per_min,
            write_per_min,
            exempt_cidrs: Arc::new(exempt_cidrs),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::new(DEFAULT_AUTH_PER_MIN, DEFAULT_WRITE_PER_MIN, Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Keyed rate limiter construction
// ---------------------------------------------------------------------------

/// GCRA emission interval for a "`per_min` requests per minute" cap: one
/// token replenished every `60s / per_min`, so the bucket sustains exactly
/// `per_min` tokens per minute (with a burst of `per_min`).
///
/// This is the load-bearing detail behind the `*_PER_MIN` caps. `governor`'s
/// `Quota::with_period(d)` sets the interval to replenish ONE token — so a fixed
/// 60s interval sustains 1 token/min regardless of the cap. Dividing 60s by the
/// cap restores the intended per-minute rate.
///
/// `per_min` is guaranteed non-zero by `Config::from_env` (and the
/// [`build_keyed_limiter`] assert), so the division never panics.
fn emission_period(per_min: u32) -> Duration {
    Duration::from_secs(60) / per_min
}

/// Build a per-IP keyed [`governor`] rate limiter for `per_min` requests
/// per minute (sustained). Encoded as a token bucket: capacity = `per_min`,
/// one token replenished every [`emission_period`]`(per_min)` =
/// `60s / per_min`. A burst of `per_min` is admitted immediately;
/// sustained traffic is capped at `per_min`/minute; over-cap requests get
/// 429 + `Retry-After` in [`rate_limit_middleware`].
///
/// Panics on `per_min == 0` — operator would have fat-fingered the env var,
/// and `Config::from_env` in `hort-server` should have already rejected
/// zero values. Defensive panic here catches any accidental bypass.
fn build_keyed_limiter(per_min: u32) -> governor::DefaultKeyedRateLimiter<IpAddr> {
    assert!(
        per_min > 0,
        "rate_limit per_min must be > 0 — Config::from_env should have rejected zero"
    );
    // The token bucket is `per_min` = capacity and one token replenished
    // every `emission_period(per_min)` = `60s / per_min`. That makes the
    // SUSTAINED rate exactly `per_min` tokens per minute — matching the
    // `*_PER_MIN` semantics the caps carry — with a burst of `per_min`.
    // (A fixed 60s period would sustain only 1 token/min regardless of the
    // cap.)
    let quota = governor::Quota::with_period(emission_period(per_min))
        .expect("non-zero emission period")
        .allow_burst(NonZeroU32::new(per_min).expect("non-zero per_min"));
    governor::RateLimiter::keyed(quota)
}

// ---------------------------------------------------------------------------
// Metric emission
// ---------------------------------------------------------------------------

/// Catalog: `docs/metrics-catalog.md` — [`HORT_RATE_LIMIT_REJECTS_TOTAL`].
///
/// `path` is the route template (axum `MatchedPath`) — never the
/// concrete URL. `scope` is a static label value from [`SCOPE_AUTH`] /
/// [`SCOPE_WRITE`].
fn emit_reject_metric(path: String, scope: &'static str) {
    metrics::counter!(
        HORT_RATE_LIMIT_REJECTS_TOTAL,
        "path" => path,
        "scope" => scope,
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Reject observer — surfaces 429s as metric + audit log
// ---------------------------------------------------------------------------

/// Resolve the route template for metric emission. Extracted so the metric
/// call site is simple and the test harness can exercise the unmatched
/// branch independently of axum routing.
fn resolve_matched_path(req: &Request) -> String {
    req.extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| PATH_UNMATCHED.to_owned())
}

/// Canonical 429 JSON body. Mirrors the `{"error": …}` envelope the rest
/// of `hort-http-core` returns (see `crate::error`).
const RATE_LIMIT_BODY: &str = r#"{"error":"too many requests"}"#;

// ---------------------------------------------------------------------------
// Middleware state + entry point
// ---------------------------------------------------------------------------

/// Per-layer state shared across requests. Cheap to clone — the keyed
/// limiter and the exemption list are both behind an `Arc`. Public only
/// because it appears in the [`RateLimitLayer`] type alias returned by the
/// pub builders; its fields stay private, so callers can't construct it.
#[derive(Clone)]
pub struct RateLimitState {
    /// Keyed token bucket, one bucket per resolved `client_ip`.
    limiter: Arc<governor::DefaultKeyedRateLimiter<IpAddr>>,
    /// Source ranges exempt from this bucket (shared with the sibling
    /// scope's state via `Arc`).
    exempt_cidrs: Arc<Vec<IpNet>>,
    /// Metric/log label for this scope — [`SCOPE_AUTH`] or [`SCOPE_WRITE`].
    scope: &'static str,
}

/// Rate-limit middleware. Runs only on write methods; keys the bucket on
/// [`RequestTrust::client_ip`]; exempts operator-listed CIDRs; on reject
/// returns `429` with a floored `Retry-After` and the
/// [`HORT_RATE_LIMIT_REJECTS_TOTAL`] metric + audit log.
///
/// Boxed-future `fn` wrapper (not a bare `async fn`) so the
/// [`RateLimitLayer`] type alias can name the middleware function
/// pointer — same pattern as [`crate::middleware::trust`].
fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> RateLimitFuture {
    Box::pin(rate_limit_middleware_impl(state, req, next))
}

/// Policy body for [`rate_limit_middleware`]. Split out so the entry
/// point stays a nameable `fn` while the logic reads as a normal
/// `async fn`.
async fn rate_limit_middleware_impl(state: RateLimitState, req: Request, next: Next) -> Response {
    // (a) Method filter — GET/HEAD/OPTIONS are never rate-limited so
    // proxy-path reads (PyPI simple index, npm packuments, OCI blob
    // GETs) pass through untouched.
    if !write_methods().contains(req.method()) {
        return next.run(req).await;
    }

    // (b) Client IP. A missing `RequestTrust` means the trust layer did
    // not run before us (router-wiring bug). Surface 500 — never a
    // silent bucket-bypass. A `ConnectInfo` fallback would quietly defeat
    // the trust policy.
    let Some(client_ip) = req.extensions().get::<RequestTrust>().map(|t| t.client_ip) else {
        tracing::error!(
            scope = state.scope,
            "rate limit: RequestTrust missing from extensions; router-wiring bug — \
             refusing to bypass bucket"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    // (c) Exemption — operator-declared trusted ranges (e.g. first-party
    // CI egress) bypass BOTH buckets entirely.
    if cidr_contains(client_ip, &state.exempt_cidrs) {
        return next.run(req).await;
    }

    // (d) Limit.
    match state.limiter.check_key(&client_ip) {
        Ok(_) => next.run(req).await,
        Err(not_until) => {
            let wait = not_until.wait_time_from(governor::clock::Clock::now(
                &governor::clock::DefaultClock::default(),
            ));
            // Whole seconds, rounded up, floored at 1 so a client that
            // reads `Retry-After` never hot-loops on `Retry-After: 0`.
            let secs = (wait.as_millis().div_ceil(1000)).max(1) as u64;

            let path = resolve_matched_path(&req);
            // Audit evidence, not an error — info! lets fail2ban / SIEM
            // consume the line without triggering error-rate alerts.
            tracing::info!(
                client_ip = %client_ip,
                scope = state.scope,
                path = %path,
                "rate limit rejection"
            );
            emit_reject_metric(path, state.scope);
            rate_limit_response(secs)
        }
    }
}

/// Build the canonical 429 response: floored `Retry-After`,
/// `Content-Type: application/json`, and the [`RATE_LIMIT_BODY`] envelope.
fn rate_limit_response(retry_after_secs: u64) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        RATE_LIMIT_BODY,
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    response
}

// ---------------------------------------------------------------------------
// Public layer builders
// ---------------------------------------------------------------------------

/// Future returned by [`rate_limit_middleware`]. Boxed + pinned so the
/// `fn` pointer in [`RateLimitMiddlewareFn`] is nameable.
pub type RateLimitFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + 'static>>;

/// Signature of [`rate_limit_middleware`]. Captured as a type alias so the
/// `FromFnLayer` generics in [`RateLimitLayer`] stay legible. Mirrors the
/// `TrustMiddlewareFn` pattern in [`crate::middleware::trust`].
pub type RateLimitMiddlewareFn = fn(State<RateLimitState>, Request, Next) -> RateLimitFuture;

/// Axum tracks the middleware extractor tuple WITHOUT the trailing `Next`.
/// For `fn(State<_>, Request, Next)` the tuple is `(State<_>, Request)`.
pub type RateLimitMiddlewareArgs = (State<RateLimitState>, Request);

/// Layer type returned by the public builders — an
/// [`axum::middleware::from_fn_with_state`] wrapping
/// [`rate_limit_middleware`].
pub type RateLimitLayer =
    axum::middleware::FromFnLayer<RateLimitMiddlewareFn, RateLimitState, RateLimitMiddlewareArgs>;

/// Build the auth-scope rate-limit layer. Wraps the `require_principal`
/// middleware: a flood of failing auth attempts from one IP trips this
/// before reaching the IdP validation path.
///
/// `.layer()` this onto the route subtree that carries
/// [`crate::middleware::auth::require_principal`] — in the current
/// composition, that's wherever the method-dispatched auth layer attaches.
/// The middleware's own method filter skips GET/HEAD/OPTIONS, so only
/// write methods (which exercise the credential-validation path) tick the
/// bucket — a GET under an Enabled auth context is not an "auth attempt".
pub fn auth_rate_limit_layer(config: &RateLimitConfig) -> RateLimitLayer {
    let state = RateLimitState {
        limiter: Arc::new(build_keyed_limiter(config.auth_per_min)),
        exempt_cidrs: config.exempt_cidrs.clone(),
        scope: SCOPE_AUTH,
    };
    axum::middleware::from_fn_with_state(state, rate_limit_middleware as RateLimitMiddlewareFn)
}

/// Build the write-scope rate-limit layer. Applied globally but the
/// middleware's method filter skips GET/HEAD/OPTIONS — mutating methods
/// only. Reads stay unlimited so proxy-path GET traffic, PyPI simple index
/// lookups, and npm packument fetches are unaffected.
pub fn write_rate_limit_layer(config: &RateLimitConfig) -> RateLimitLayer {
    let state = RateLimitState {
        limiter: Arc::new(build_keyed_limiter(config.write_per_min)),
        exempt_cidrs: config.exempt_cidrs.clone(),
        scope: SCOPE_WRITE,
    };
    axum::middleware::from_fn_with_state(state, rate_limit_middleware as RateLimitMiddlewareFn)
}

/// HTTP methods the rate-limit layers engage on. Mirrors
/// `method_based_auth_dispatch`'s write-method set in
/// `crate::router` — keeps the two wrappers aligned.
fn write_methods() -> Vec<Method> {
    vec![Method::POST, Method::PUT, Method::DELETE, Method::PATCH]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{header, Request as HttpRequest, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use tower::ServiceExt;

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn trust(ip: &str) -> RequestTrust {
        RequestTrust {
            client_ip: ip.parse().unwrap(),
            public_url: url::Url::parse("http://hort-server/").unwrap(),
        }
    }

    // --- Root-cause regression: a `*_PER_MIN` cap must SUSTAIN that many
    // requests per minute, not collapse to 1/min after the initial burst.
    // The pre-fix `.per_second(60)` set a fixed 60s replenish interval,
    // sustaining 1 token/min regardless of the cap (~60-300x too tight). ---

    #[test]
    fn emission_period_encodes_per_minute_rate() {
        // One token every 60s/cap → `cap` tokens replenished per minute.
        assert_eq!(emission_period(60), Duration::from_secs(1));
        assert_eq!(emission_period(300), Duration::from_millis(200));
        // The degenerate cap=1 is the ONLY value for which a fixed 60s
        // interval was ever correct — proving the old constant was a
        // cap=1 special case, not the general rule.
        assert_eq!(emission_period(1), Duration::from_secs(60));
    }

    #[test]
    fn governor_config_sustains_cap_per_minute() {
        use governor::clock::FakeRelativeClock;
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        for cap in [60u32, 300] {
            let clock = FakeRelativeClock::default();
            // Same quota shape `build_keyed_limiter` produces:
            // `Quota::with_period(period).allow_burst(burst)`.
            let quota = Quota::with_period(emission_period(cap))
                .expect("non-zero period")
                .allow_burst(NonZeroU32::new(cap).expect("non-zero cap"));
            let lim = RateLimiter::direct_with_clock(quota, clock.clone());

            // Burst of `cap` admitted immediately; burst+1 rejects.
            let burst_ok = (0..cap).filter(|_| lim.check().is_ok()).count() as u32;
            assert_eq!(burst_ok, cap, "cap={cap}: full burst should pass");
            assert!(lim.check().is_err(), "cap={cap}: burst+1 must reject");

            // After one minute the bucket admits ~cap MORE (sustained
            // cap/min). The pre-fix fixed-60s-period bug refilled only 1.
            clock.advance(Duration::from_secs(60));
            let refilled = (0..cap * 2).filter(|_| lim.check().is_ok()).count() as u32;
            assert!(
                refilled >= cap - 1,
                "cap={cap}: expected ~{cap}/min sustained, only {refilled} refilled \
                 in a minute (the fixed-60s-period bug sustains 1/min)"
            );
        }
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    /// Inject a pre-built [`RequestTrust`] into a test request's extensions.
    /// The production composition populates this via
    /// `request_trust_layer`; tests fake it directly so each case has
    /// deterministic peer IPs.
    fn req_with_trust(uri: &str, t: RequestTrust) -> HttpRequest<Body> {
        let mut r = HttpRequest::get(uri).body(Body::empty()).unwrap();
        r.extensions_mut().insert(t);
        r
    }

    fn post_with_trust(uri: &str, t: RequestTrust) -> HttpRequest<Body> {
        let mut r = HttpRequest::post(uri).body(Body::empty()).unwrap();
        r.extensions_mut().insert(t);
        r
    }

    /// Locate a counter by name and exact label set. Returns the
    /// debug-value (whose inner `n` is the accumulated counter value), or
    /// `None` if no matching series was recorded.
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

    fn rt<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    // ------------------------------------------------------------------
    // resolve_matched_path — tested independently of axum routing
    // ------------------------------------------------------------------

    #[test]
    fn resolve_matched_path_falls_back_to_unmatched_sentinel_when_absent() {
        let req = HttpRequest::get("/anything").body(Body::empty()).unwrap();
        assert_eq!(resolve_matched_path(&req), PATH_UNMATCHED);
    }

    // ------------------------------------------------------------------
    // RateLimitConfig
    // ------------------------------------------------------------------

    #[test]
    fn config_default_matches_documented_caps() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.auth_per_min, DEFAULT_AUTH_PER_MIN);
        assert_eq!(cfg.write_per_min, DEFAULT_WRITE_PER_MIN);
    }

    #[test]
    fn config_new_stores_explicit_values() {
        let cfg = RateLimitConfig::new(10, 50, vec![]);
        assert_eq!(cfg.auth_per_min, 10);
        assert_eq!(cfg.write_per_min, 50);
    }

    // ------------------------------------------------------------------
    // Auth rate limit — exceeding the cap returns 429 + Retry-After
    // ------------------------------------------------------------------

    #[test]
    fn auth_layer_emits_429_and_retry_after_on_burst_exceeded() {
        // Burst of 2 — third same-IP request must 429. Using 2 instead of
        // 60 keeps the test fast; semantics are identical.
        //
        // POST, not GET: the auth layer's `methods` filter skips
        // GET/HEAD/OPTIONS (credential stuffing only exercises write
        // methods via `require_principal`). A GET would bypass the bucket
        // entirely and never 429.
        let cfg = RateLimitConfig::new(2, 10, vec![]);
        let (snap, (status_1, status_2, status_3, retry_after, content_type, body)) =
            capture(|| {
                rt(async {
                    let router = Router::new()
                        .route("/protected", post(ok_handler))
                        .layer(auth_rate_limit_layer(&cfg));
                    let s1 = router
                        .clone()
                        .oneshot(post_with_trust("/protected", trust("10.0.0.1")))
                        .await
                        .unwrap()
                        .status();
                    let s2 = router
                        .clone()
                        .oneshot(post_with_trust("/protected", trust("10.0.0.1")))
                        .await
                        .unwrap()
                        .status();
                    let r3 = router
                        .oneshot(post_with_trust("/protected", trust("10.0.0.1")))
                        .await
                        .unwrap();
                    let s3 = r3.status();
                    let retry_after = r3
                        .headers()
                        .get(header::RETRY_AFTER)
                        .map(|v| v.to_str().unwrap().to_owned());
                    let content_type = r3
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .map(|v| v.to_str().unwrap().to_owned());
                    let body = axum::body::to_bytes(r3.into_body(), 1024).await.unwrap();
                    (s1, s2, s3, retry_after, content_type, body)
                })
            });
        assert_eq!(status_1, StatusCode::OK);
        assert_eq!(status_2, StatusCode::OK);
        assert_eq!(status_3, StatusCode::TOO_MANY_REQUESTS);
        // The limiter always sets Retry-After on 429, floored at 1s.
        let retry_after = retry_after.expect("Retry-After header missing on 429 response");
        let retry_secs: u64 = retry_after
            .parse()
            .expect("Retry-After must be integer seconds");
        assert!(
            retry_secs >= 1,
            "Retry-After must be floored at 1s, got {retry_secs}"
        );
        // The new response construction: JSON envelope + content-type.
        assert_eq!(content_type.as_deref(), Some("application/json"));
        assert_eq!(&body[..], br#"{"error":"too many requests"}"#);

        // Metric assertion — exactly one increment for `scope=auth` on the
        // matched route template.
        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            HORT_RATE_LIMIT_REJECTS_TOTAL,
            &[("scope", SCOPE_AUTH), ("path", "/protected")],
        )
        .expect("rate-limit rejects counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // Auth layer bypasses GET/HEAD/OPTIONS: `require_principal` is only
    // attached on write methods (see `method_based_auth_dispatch`), so the
    // auth-rate-limit filter mirrors that split.
    #[test]
    fn auth_layer_skips_get_requests_regardless_of_burst() {
        let cfg = RateLimitConfig::new(1, 10, vec![]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/open", get(ok_handler))
                .layer(auth_rate_limit_layer(&cfg));
            let ip = trust("10.0.0.9");
            let mut seen = Vec::new();
            for _ in 0..5 {
                let s = router
                    .clone()
                    .oneshot(req_with_trust("/open", ip.clone()))
                    .await
                    .unwrap()
                    .status();
                seen.push(s);
            }
            seen
        });
        assert!(
            statuses.iter().all(|s| *s == StatusCode::OK),
            "GETs tripped the auth-rate-limit filter despite method carve-out: {statuses:?}"
        );
    }

    // ------------------------------------------------------------------
    // Write rate limit — same shape, different scope label
    // ------------------------------------------------------------------

    #[test]
    fn write_layer_emits_429_and_metric_on_burst_exceeded() {
        let cfg = RateLimitConfig::new(10, 1, vec![]);
        let (snap, (status_1, status_2)) = capture(|| {
            rt(async {
                let router = Router::new()
                    .route("/upload", post(ok_handler))
                    .layer(write_rate_limit_layer(&cfg));
                let s1 = router
                    .clone()
                    .oneshot(post_with_trust("/upload", trust("10.0.0.2")))
                    .await
                    .unwrap()
                    .status();
                let s2 = router
                    .oneshot(post_with_trust("/upload", trust("10.0.0.2")))
                    .await
                    .unwrap()
                    .status();
                (s1, s2)
            })
        });
        assert_eq!(status_1, StatusCode::OK);
        assert_eq!(status_2, StatusCode::TOO_MANY_REQUESTS);

        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            HORT_RATE_LIMIT_REJECTS_TOTAL,
            &[("scope", SCOPE_WRITE), ("path", "/upload")],
        )
        .expect("write-scope rejects counter absent");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
    }

    // ------------------------------------------------------------------
    // Distinct client IPs get distinct buckets (proves the trust layer feeds the key).
    // ------------------------------------------------------------------

    #[test]
    fn distinct_client_ips_have_independent_buckets() {
        let cfg = RateLimitConfig::new(1, 1, vec![]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/protected", post(ok_handler))
                .layer(auth_rate_limit_layer(&cfg));
            // IP A — first request consumes its token, second would 429.
            let a1 = router
                .clone()
                .oneshot(post_with_trust("/protected", trust("10.0.0.1")))
                .await
                .unwrap()
                .status();
            // IP B — its own bucket is still full, must succeed.
            let b1 = router
                .clone()
                .oneshot(post_with_trust("/protected", trust("10.0.0.2")))
                .await
                .unwrap()
                .status();
            // IP A again — bucket drained, must 429.
            let a2 = router
                .oneshot(post_with_trust("/protected", trust("10.0.0.1")))
                .await
                .unwrap()
                .status();
            (a1, b1, a2)
        });
        assert_eq!(statuses.0, StatusCode::OK, "first request from A");
        assert_eq!(statuses.1, StatusCode::OK, "first request from B");
        assert_eq!(
            statuses.2,
            StatusCode::TOO_MANY_REQUESTS,
            "A's bucket drained"
        );
    }

    // ------------------------------------------------------------------
    // Reads unaffected — the write-scope layer never trips on GET.
    // ------------------------------------------------------------------

    #[test]
    fn read_paths_are_untouched_by_write_layer() {
        // Cap the WRITE layer aggressively (burst=1) and verify GET traffic
        // against a route that does NOT have the layer attached stays 200
        // for >> burst requests from the same IP. Mirrors the production
        // sub-router split: reads live outside the write-layer scope.
        let cfg = RateLimitConfig::new(10, 1, vec![]);
        let all_200 = rt(async {
            let write_scope = Router::new()
                .route("/upload", post(ok_handler))
                .layer(write_rate_limit_layer(&cfg));
            let router = Router::new()
                .route("/read", get(ok_handler))
                .merge(write_scope);
            let mut outcomes = Vec::new();
            for _ in 0..10 {
                let s = router
                    .clone()
                    .oneshot(req_with_trust("/read", trust("10.0.0.3")))
                    .await
                    .unwrap()
                    .status();
                outcomes.push(s);
            }
            outcomes.into_iter().all(|s| s == StatusCode::OK)
        });
        assert!(
            all_200,
            "GET traffic was rate-limited by the write-scope layer"
        );
    }

    // ------------------------------------------------------------------
    // MatchedPath label MUST be route template, not concrete URI.
    // ------------------------------------------------------------------

    #[test]
    fn metric_path_label_is_route_template_not_concrete_uri() {
        // Route with a :param segment → MatchedPath carries the template;
        // concrete request carries the param value filled in. The metric
        // emission MUST use the template. Production emits things like
        // `/pypi/:repo_key/` — never `/pypi/test-repo/`.
        //
        // Uses POST because the methods filter skips GETs (see
        // `auth_layer_skips_get_requests_regardless_of_burst`).
        let cfg = RateLimitConfig::new(1, 10, vec![]);
        let snap = capture(|| {
            rt(async {
                let router = Router::new()
                    .route("/pypi/:repo_key/", post(ok_handler))
                    .layer(auth_rate_limit_layer(&cfg));
                let ip = trust("10.0.0.4");
                let _ = router
                    .clone()
                    .oneshot(post_with_trust("/pypi/concrete-repo/", ip.clone()))
                    .await
                    .unwrap();
                let _ = router
                    .oneshot(post_with_trust("/pypi/concrete-repo/", ip))
                    .await
                    .unwrap();
            })
        })
        .0;
        let entries = snap.into_vec();

        // Positive assertion: series tagged with the ROUTE TEMPLATE.
        let v = find_counter(
            &entries,
            HORT_RATE_LIMIT_REJECTS_TOTAL,
            &[("scope", SCOPE_AUTH), ("path", "/pypi/:repo_key/")],
        )
        .expect("expected series with route-template path label");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));

        // Negative assertion: NO series carries the concrete URI.
        let leaked = entries.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == HORT_RATE_LIMIT_REJECTS_TOTAL
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "path" && l.value() == "/pypi/concrete-repo/")
        });
        assert!(
            leaked.is_none(),
            "concrete URI leaked into metric path label — MatchedPath contract violated"
        );
    }

    // ------------------------------------------------------------------
    // Missing trust in extensions → 500 (safer than silent bypass)
    // ------------------------------------------------------------------

    #[test]
    fn missing_request_trust_yields_500_not_bucket_bypass() {
        // If the router is composed incorrectly (rate-limit attached
        // without the trust layer upstream), the extractor has no
        // client_ip to key on. Surfacing 500 makes the composition bug
        // immediately visible; a ConnectInfo fallback would silently
        // bypass the trust policy.
        //
        // POST to reach the rate-limiter's method filter; a GET would
        // bypass the limiter entirely and succeed with 200.
        let cfg = RateLimitConfig::new(1, 1, vec![]);
        let status = rt(async {
            let router = Router::new()
                .route("/protected", post(ok_handler))
                .layer(auth_rate_limit_layer(&cfg));
            // NOTE: no RequestTrust inserted.
            let req = HttpRequest::post("/protected").body(Body::empty()).unwrap();
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ------------------------------------------------------------------
    // CIDR exemption — an exempt client_ip bypasses BOTH buckets
    // ------------------------------------------------------------------

    #[test]
    fn exempt_cidr_bypasses_write_bucket() {
        // write cap = 1, but the caller's IP is in the exempt set →
        // every POST is admitted (200), no 429 regardless of burst.
        let cfg = RateLimitConfig::new(10, 1, vec!["10.0.0.0/8".parse().unwrap()]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/upload", post(ok_handler))
                .layer(write_rate_limit_layer(&cfg));
            let mut seen = Vec::new();
            for _ in 0..5 {
                let s = router
                    .clone()
                    .oneshot(post_with_trust("/upload", trust("10.1.2.3")))
                    .await
                    .unwrap()
                    .status();
                seen.push(s);
            }
            seen
        });
        assert!(
            statuses.iter().all(|s| *s == StatusCode::OK),
            "exempt IP must bypass the write bucket: {statuses:?}"
        );
    }

    #[test]
    fn exempt_cidr_bypasses_auth_bucket() {
        // auth cap = 1, caller in the exempt set → every POST 200.
        let cfg = RateLimitConfig::new(1, 10, vec!["10.0.0.0/8".parse().unwrap()]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/protected", post(ok_handler))
                .layer(auth_rate_limit_layer(&cfg));
            let mut seen = Vec::new();
            for _ in 0..5 {
                let s = router
                    .clone()
                    .oneshot(post_with_trust("/protected", trust("10.9.9.9")))
                    .await
                    .unwrap()
                    .status();
                seen.push(s);
            }
            seen
        });
        assert!(
            statuses.iter().all(|s| *s == StatusCode::OK),
            "exempt IP must bypass the auth bucket: {statuses:?}"
        );
    }

    #[test]
    fn non_exempt_ip_still_limited_when_exempt_set_nonempty() {
        // Exempt set covers 10.0.0.0/8; a caller from 203.0.113.7 is NOT
        // exempt and must still trip the burst=1 auth cap on its second
        // request. Proves the exemption is a targeted allowlist, not a
        // global off-switch.
        let cfg = RateLimitConfig::new(1, 10, vec!["10.0.0.0/8".parse().unwrap()]);
        let (s1, s2) = rt(async {
            let router = Router::new()
                .route("/protected", post(ok_handler))
                .layer(auth_rate_limit_layer(&cfg));
            let s1 = router
                .clone()
                .oneshot(post_with_trust("/protected", trust("203.0.113.7")))
                .await
                .unwrap()
                .status();
            let s2 = router
                .oneshot(post_with_trust("/protected", trust("203.0.113.7")))
                .await
                .unwrap()
                .status();
            (s1, s2)
        });
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(
            s2,
            StatusCode::TOO_MANY_REQUESTS,
            "non-exempt IP must still be limited when an exempt set is configured"
        );
    }
}
