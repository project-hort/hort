//! Per-IP rate limiting (see `docs/auth-catalog.md` for the auth-surface
//! rate-limit/lockout posture).
//!
//! Two tower layer builders, both backed by [`tower_governor`] with a
//! custom [`KeyExtractor`] that reads [`RequestTrust::client_ip`] out of
//! request extensions (populated by [`request_trust_layer`]):
//!
//! - [`auth_rate_limit_layer`] — wraps [`require_principal`]. Per-IP
//!   token-bucket limiting auth attempts; bucket cap via
//!   `HORT_RATELIMIT_AUTH_PER_MIN` (default 60).
//! - [`write_rate_limit_layer`] — wraps the POST/PUT/DELETE sub-router.
//!   Per-IP token-bucket limiting write throughput; bucket cap via
//!   `HORT_RATELIMIT_WRITE_PER_MIN` (default 300).
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
//! # Why not `SmartIpKeyExtractor`?
//!
//! `tower_governor` ships a `SmartIpKeyExtractor` that sniffs
//! `X-Forwarded-For` / `X-Real-IP` / `Forwarded` without consulting a
//! trusted-proxy allowlist. Using it here would silently bypass the
//! trust policy: an unauthenticated client could set
//! `X-Forwarded-For: 1.2.3.4` and escape their bucket. All peer-IP
//! evaluation lives in [`crate::middleware::trust`]; this module consumes
//! its output and never looks at raw headers.
//!
//! # Observability
//!
//! On reject: `429 Too Many Requests` with `Retry-After` (governor
//! builds the headers). The accompanying metric is
//! [`HORT_RATE_LIMIT_REJECTS_TOTAL`] with `scope ∈ {auth, write}` and
//! `path` = route template from [`axum::extract::MatchedPath`] — NOT the
//! concrete URI. Unmatched routes (404 path) surface as `path="<unmatched>"`.
//!
//! [`RequestTrust::client_ip`]: crate::middleware::trust::RequestTrust::client_ip
//! [`request_trust_layer`]: crate::middleware::trust::request_trust_layer
//! [`require_principal`]: crate::middleware::auth::require_principal
//! [`KeyExtractor`]: tower_governor::key_extractor::KeyExtractor

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{MatchedPath, Request};
use axum::http::{Method, Request as HttpRequest, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tower::layer::util::Stack;
use tower::ServiceBuilder;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::{GovernorError, GovernorLayer};

use crate::middleware::trust::RequestTrust;

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

/// Per-scope rate-limit caps. Sourced from `hort-server::Config` so operators
/// tune without rebuilding. `u32` matches `tower_governor`'s
/// `burst_size` type — larger caps would overflow the underlying
/// `NonZeroU32`; validation at parse-time in `Config::from_env` ensures
/// the values here are non-zero.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Auth attempts per IP per minute. Wraps `require_principal`.
    pub auth_per_min: u32,
    /// Writes per IP per minute. Wraps POST/PUT/DELETE routes.
    pub write_per_min: u32,
}

impl RateLimitConfig {
    /// New config with explicit caps. Callers (production `hort-server::Config`,
    /// tests) supply values; non-zero invariant enforced by the builder at
    /// `finish()` time — zero would cause `GovernorConfigBuilder::finish`
    /// to return `None` and this module's `build_governor_config` to panic
    /// at startup. Treat zero as an operator misconfiguration.
    pub fn new(auth_per_min: u32, write_per_min: u32) -> Self {
        Self {
            auth_per_min,
            write_per_min,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::new(DEFAULT_AUTH_PER_MIN, DEFAULT_WRITE_PER_MIN)
    }
}

// ---------------------------------------------------------------------------
// Key extractor
// ---------------------------------------------------------------------------

/// Custom [`KeyExtractor`] that pulls [`RequestTrust::client_ip`] out of
/// request extensions (populated by `request_trust_layer`); if the
/// extension is missing the extractor surfaces
/// [`GovernorError::UnableToExtractKey`] → `500 Internal Server Error`.
///
/// Why 500 instead of falling back to `ConnectInfo<SocketAddr>`: a
/// ConnectInfo fallback would silently bypass the trust policy whenever
/// the router is composed incorrectly (rate-limit layer attached before
/// the trust layer). 500 is the conservative failure — it surfaces the
/// composition bug immediately rather than hiding it behind a subtly-
/// different rate-limit behaviour. Tower-governor's default `From`
/// conversion maps `UnableToExtractKey` to 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustAwareKeyExtractor;

impl KeyExtractor for TrustAwareKeyExtractor {
    type Key = IpAddr;

    // NOTE: `name()` / `key_name()` on `KeyExtractor` are gated by
    // tower_governor's `tracing` cargo feature, which we do NOT enable
    // (see `hort-http-core`'s Cargo.toml: `default-features = false`). With that
    // feature off, the trait has no `name()` / `key_name()` method to
    // implement — adding stubs would fail to compile. Our own `tracing`
    // call site lives in [`observe_rejects`] instead.

    fn extract<T>(&self, req: &HttpRequest<T>) -> Result<Self::Key, GovernorError> {
        req.extensions()
            .get::<RequestTrust>()
            .map(|trust| trust.client_ip)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

// ---------------------------------------------------------------------------
// Governor layer construction
// ---------------------------------------------------------------------------

/// Build a [`GovernorConfig`] for N requests per 60s window, keyed by
/// [`TrustAwareKeyExtractor`]. "N per minute" is encoded as burst = N,
/// replenishment = 60s (1 token per minute, up to N tokens buffered). The
/// first N requests within a 60s window pass through; N+1 is rejected with
/// 429 + `Retry-After`.
///
/// Panics on `burst == 0` — operator would have fat-fingered the env var,
/// and `Config::from_env` in `hort-server` should have already rejected zero
/// values. Defensive panic here catches any accidental bypass.
fn build_governor_config(
    burst: u32,
    methods: Option<Vec<Method>>,
) -> Arc<GovernorConfig<TrustAwareKeyExtractor, governor::middleware::NoOpMiddleware>> {
    assert!(
        burst > 0,
        "rate_limit burst must be > 0 — Config::from_env should have rejected zero"
    );
    // `per_second(60)` here names the REPLENISHMENT INTERVAL (one token per
    // 60 seconds), not "per-second rate". tower_governor's API is the
    // `governor` crate's token-bucket: burst is the bucket capacity,
    // period is the cadence at which the bucket refills by one.
    //
    // `methods`: when set, the governor layer ONLY limits the listed
    // methods; everything else passes through. This is how we express
    // "write rate-limit applies only to POST/PUT/DELETE/PATCH" without
    // carving up the router into sibling sub-routers. Mirrors the
    // tower_governor `GovernorConfigBuilder::methods` API.
    // `key_extractor(...)` CONSUMES the PeerIp-typed builder and returns
    // a fresh builder parameterised on the new key type. Chain on that
    // return value — stashing it in a `mut` binding so the subsequent
    // `methods(...)` call (which takes `&mut Self`) lands on the right
    // generic instantiation.
    let mut builder = GovernorConfigBuilder::default()
        .per_second(60)
        .burst_size(burst)
        .key_extractor(TrustAwareKeyExtractor);
    if let Some(methods) = methods {
        builder.methods(methods);
    }
    let config = builder.finish().expect("non-zero burst and period");
    Arc::new(config)
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

/// Middleware that runs OUTSIDE the `GovernorLayer`: captures the matched
/// route template and the trust-evaluated `client_ip` on the way in,
/// detects a 429 on the way out, and emits the
/// [`HORT_RATE_LIMIT_REJECTS_TOTAL`] metric + a structured `info!` audit log.
///
/// Why out-of-band instead of inside `GovernorLayer::error_handler`:
/// the error handler closure only sees [`GovernorError`] — it doesn't
/// have access to the request (and thus no `MatchedPath`). The
/// per-scope closures below thread the `scope` label via a `&'static str`
/// captured by the closure; the per-scope layer pair is defined in
/// [`auth_rate_limit_layer`] / [`write_rate_limit_layer`].
async fn observe_rejects(req: Request, next: Next, scope: &'static str) -> Response {
    // Capture metadata pre-flight — on 429 the governor layer short-
    // circuits and `req` would no longer be readable from inside
    // `next.run(req)`'s body.
    let path = resolve_matched_path(&req);
    let client_ip = req
        .extensions()
        .get::<RequestTrust>()
        .map(|t| t.client_ip.to_string());

    let response = next.run(req).await;

    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        // Audit evidence, not an error — info! lets fail2ban / SIEM
        // consume the line without triggering error-rate alerts.
        tracing::info!(
            client_ip = client_ip.as_deref().unwrap_or("<unknown>"),
            scope,
            path = %path,
            "rate limit rejection"
        );
        emit_reject_metric(path, scope);
    }

    response
}

// ---------------------------------------------------------------------------
// Public layer builders
// ---------------------------------------------------------------------------

/// Scope-bound observer for auth rate-limit rejects. `async fn` — axum's
/// `from_fn` does the FromRequest-tuple inference directly from the
/// signature; no function-pointer cast required.
async fn auth_observer(req: Request, next: Next) -> Response {
    observe_rejects(req, next, SCOPE_AUTH).await
}

/// Scope-bound observer for write-path rate-limit rejects.
async fn write_observer(req: Request, next: Next) -> Response {
    observe_rejects(req, next, SCOPE_WRITE).await
}

/// Composed layer type returned by the public builders. Stacks an
/// [`axum::middleware::from_fn`] observer OUTSIDE a [`GovernorLayer`] so
/// the observer sees the 429 response produced by the inner governor.
///
/// The extractor tuple `(Request,)` in the middle of the
/// `FromFnLayer` generics matches axum's convention: the last tuple
/// element is the axum extractor (`Request` here, since the observer
/// takes the full request body), preceding elements are
/// `FromRequestParts` — none in our case.
pub type RateLimitLayer = Stack<
    GovernorLayer<TrustAwareKeyExtractor, governor::middleware::NoOpMiddleware>,
    Stack<
        axum::middleware::FromFnLayer<fn(Request, Next) -> ObserverFuture, (), (Request,)>,
        tower::layer::util::Identity,
    >,
>;

/// Future type for the observer `fn` pointers baked into the
/// [`RateLimitLayer`] alias. Boxed + pinned so the `fn` signatures the
/// stack type-alias references are nameable.
pub type ObserverFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + 'static>>;

/// Fn-pointer wrappers that hand `from_fn` a nameable function type. The
/// underlying `async fn` observers desugar to anonymous futures; casting
/// the wrappers to `fn(Request, Next) -> ObserverFuture` gives the type
/// alias [`RateLimitLayer`] a concrete middleware function type to quote.
fn auth_observer_fn(req: Request, next: Next) -> ObserverFuture {
    Box::pin(auth_observer(req, next))
}
fn write_observer_fn(req: Request, next: Next) -> ObserverFuture {
    Box::pin(write_observer(req, next))
}

/// Build the auth-scope rate-limit layer. Wraps the `require_principal`
/// middleware: a flood of failing auth attempts from one IP trips this
/// before reaching the IdP validation path.
///
/// `.layer()` this onto the route subtree that carries
/// [`crate::middleware::auth::require_principal`] — in the current
/// composition, that's wherever the method-dispatched auth layer attaches.
pub fn auth_rate_limit_layer(config: &RateLimitConfig) -> RateLimitLayer {
    // Auth-scope limit wraps `require_principal`. The existing
    // `method_based_auth_dispatch` already routes GET/HEAD/OPTIONS through
    // `extract_optional_principal` (never 401s), so only write methods
    // exercise the credential-validation path this layer defends.
    // Mirroring that shape keeps the auth-rate-limit metric bounded to
    // credential-stuffing traffic; a GET hitting the router under an
    // Enabled auth context is not an "auth attempt" — don't tick the
    // bucket for it.
    let governor = GovernorLayer {
        config: build_governor_config(config.auth_per_min, Some(write_methods())),
    };
    let observer: fn(Request, Next) -> ObserverFuture = auth_observer_fn;
    ServiceBuilder::new()
        .layer(axum::middleware::from_fn(observer))
        .layer(governor)
        .into_inner()
}

/// Build the write-scope rate-limit layer. Applied globally but
/// tower_governor's `methods` filter skips GET/HEAD/OPTIONS —
/// mutating methods only. Reads stay unlimited so proxy-path GET
/// traffic, PyPI simple index lookups, and npm packument fetches are
/// unaffected.
pub fn write_rate_limit_layer(config: &RateLimitConfig) -> RateLimitLayer {
    let governor = GovernorLayer {
        config: build_governor_config(config.write_per_min, Some(write_methods())),
    };
    let observer: fn(Request, Next) -> ObserverFuture = write_observer_fn;
    ServiceBuilder::new()
        .layer(axum::middleware::from_fn(observer))
        .layer(governor)
        .into_inner()
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

    use std::net::Ipv4Addr;

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
    // TrustAwareKeyExtractor — contract
    // ------------------------------------------------------------------

    #[test]
    fn key_extractor_returns_client_ip_from_request_trust() {
        let req = req_with_trust("/x", trust("10.0.0.5"));
        let key = TrustAwareKeyExtractor.extract(&req).unwrap();
        assert_eq!(key, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn key_extractor_errors_when_trust_missing_from_extensions() {
        // No RequestTrust in extensions → router-wiring bug → 500.
        let req = HttpRequest::get("/x").body(Body::empty()).unwrap();
        let err = TrustAwareKeyExtractor.extract(&req).unwrap_err();
        assert!(matches!(err, GovernorError::UnableToExtractKey));
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
        let cfg = RateLimitConfig::new(10, 50);
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
        let cfg = RateLimitConfig::new(2, 10);
        let (snap, (status_1, status_2, status_3, retry_after)) = capture(|| {
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
                (s1, s2, s3, retry_after)
            })
        });
        assert_eq!(status_1, StatusCode::OK);
        assert_eq!(status_2, StatusCode::OK);
        assert_eq!(status_3, StatusCode::TOO_MANY_REQUESTS);
        // tower_governor always sets Retry-After on 429.
        assert!(
            retry_after.is_some(),
            "Retry-After header missing on 429 response"
        );

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
        let cfg = RateLimitConfig::new(1, 10);
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
        let cfg = RateLimitConfig::new(10, 1);
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
        let cfg = RateLimitConfig::new(1, 1);
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
        let cfg = RateLimitConfig::new(10, 1);
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
        let cfg = RateLimitConfig::new(1, 10);
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
        let cfg = RateLimitConfig::new(1, 1);
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
}
