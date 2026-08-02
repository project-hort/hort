//! Per-IP rate limiting (see `docs/auth-catalog.md` for the auth-surface
//! rate-limit/lockout posture).
//!
//! Two [`axum::middleware::from_fn_with_state`] layer builders, keyed on
//! [`RequestTrust::client_ip`] (read out of request extensions, populated
//! by [`request_trust_layer`]) — but with **structurally different**
//! bucket-consumption models (issue #66):
//!
//! - [`write_rate_limit_layer`] — wraps the POST/PUT/DELETE sub-router.
//!   Backed by a [`governor`] keyed token bucket that CONSUMES on every
//!   write request, success or failure alike. Bucket cap via
//!   `HORT_RATELIMIT_WRITE_PER_MIN` (default 300). Bounds sustained
//!   mutation throughput regardless of auth outcome.
//! - [`auth_rate_limit_layer`] — attached over the same tree
//!   [`require_principal`] runs under (and over `POST
//!   /api/v1/auth/exchange`, which is anonymous — see below). Backed by
//!   [`AuthFailureWindow`], a bespoke per-IP fixed-window **failure**
//!   counter — NOT `governor` (see "Why not `governor` for the auth
//!   scope?" below). Counts only authentication **failures** (`401`
//!   responses), never successful writes by a valid principal. Cap via
//!   `HORT_RATELIMIT_AUTH_PER_MIN` (default 60 failures/minute/IP).
//!
//! # Why not `governor` for the auth scope?
//!
//! `governor`'s keyed limiter couples check+consume atomically in
//! `check_key` — there is no peek-without-consuming and no refund. The
//! auth scope needs exactly that: reject an over-budget IP **before**
//! `next.run` (so `require_principal`'s JWKS validation, or the
//! `/auth/exchange` handler's own credential-exchange work, never
//! executes for an IP that has already exhausted its failure budget —
//! this is the pre-validation throttle, the whole point of the scope),
//! but only ever CONSUME a slot after inspecting the downstream
//! response, and only when that response is `401`. A valid principal
//! that authenticates successfully and then gets `403`'d by a
//! downstream authorization check (insufficient RBAC for that
//! particular write) must not draw the bucket down either — `403` can
//! only be reached AFTER `require_principal` already accepted the
//! credential, so counting it here would penalize authenticated
//! clients for authorization decisions, not credential validity.
//! `AuthFailureWindow` therefore exposes two independent operations —
//! [`AuthFailureWindow::is_over_budget`] (peek, pure, never mutates) and
//! [`AuthFailureWindow::record_failure`] (the only mutator, called only
//! on a `401`) — which `governor`'s API cannot express.
//!
//! # The bug this replaced (issue #66)
//!
//! Before this change, `auth_rate_limit_layer` used the same
//! `governor`-backed, consume-on-every-write model as the write scope:
//! every authenticated write — success or failure — drew down BOTH the
//! auth bucket (60/min) and the write bucket (300/min) simultaneously,
//! so the effective ceiling for a valid, well-behaved authenticated
//! client was `min(auth, write) = 60/min`. A `cosign copy` bulk
//! multi-arch mirror push (far more than 60 authenticated blob/manifest
//! writes/min from one runner IP) hit that ceiling and 429'd even
//! though every credential presented was valid. The auth scope's threat
//! model — credential-stuffing, i.e. repeated presentation of a BAD
//! credential — never justified penalizing a stream of GOOD credentials
//! for being numerous. Counting failures only fixes this: a valid
//! principal's writes now fall under the write scope alone (300/min),
//! the control the doc always described as bounding "sustained mutation
//! throughput" (see "The two threat models" below) — while a
//! credential-stuffing flood (many `401`s from one IP) still trips the
//! auth scope, and still does so BEFORE the validation work each
//! attempt would otherwise burn.
//!
//! # The two threat models
//!
//! - `scope=auth` fires on credential-stuffing floods — repeated
//!   presentation of an invalid, missing, or replayed credential from
//!   one IP (60 FAILURES/min default). It does not fire on volume of
//!   successful, validly-authenticated writes.
//! - `scope=write` fires on sustained mutation throughput regardless of
//!   auth outcome — e.g. a compromised CI token used to upload garbage,
//!   or simply a very large legitimate bulk push (300/min default).
//!   This is now the ONLY scope a valid-principal write consumes from.
//!
//! Because the two scopes no longer double-consume on every write, the
//! `min(auth, write)` coupling this doc used to document as intentional
//! no longer applies — `write_per_min` is the real ceiling for
//! authenticated throughput; `auth_per_min` bounds only how many failed
//! credential presentations one IP gets per minute before the
//! pre-validation reject kicks in.
//!
//! # `POST /api/v1/auth/exchange` stays throttled
//!
//! `/auth/exchange` is anonymous — `method_based_auth_dispatch` routes
//! it around `require_principal` entirely (`crate::router::is_anonymous_path`)
//! — but it is the primary credential→token surface (ADR 0013) and a
//! prime credential-stuffing target. `auth_rate_limit_layer` is attached
//! over the whole router tree, method-filtered to write methods, not
//! specifically to `require_principal`'s call sites — so it still wraps
//! this route. The exchange handler's own `401 invalid_grant` responses
//! (bad/expired/replayed JWT, missing required `jti`) are indistinguishable
//! from a `require_principal` `401` at this layer and count identically.
//! A `403` from the exchange handler (`cap_exceeds_authority` — a VALID
//! JWT requesting more scope than its `ServiceAccount` holds) does not
//! count, for the same reason a downstream `403` never counts elsewhere:
//! the credential itself was accepted.
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

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
// Auth-scope failure-window counter (issue #66)
// ---------------------------------------------------------------------------

/// Per-IP fixed-window **failure** counter backing [`auth_rate_limit_layer`].
///
/// Deliberately NOT `governor` — see the module doc's "Why not `governor`
/// for the auth scope?" section. `governor::RateLimiter::check_key`
/// couples check+consume atomically with no peek and no refund, which
/// cannot express "reject on entry if over budget, but consume a slot
/// only when the eventual response turns out to be a failure." This
/// type exposes the two operations independently:
///
/// - [`is_over_budget`](Self::is_over_budget) — a pure peek, called on
///   EVERY write request before `next.run`. Never mutates state, so
///   merely checking never itself counts as a failure.
/// - [`record_failure`](Self::record_failure) — the only mutator,
///   called ONLY when the downstream response is a `401`.
///
/// Fixed (not sliding) window: a bucket's `count` resets to 0 the next
/// time `record_failure` observes the window has aged past `window`.
/// `is_over_budget` treats an aged-out window as empty without mutating
/// it — the actual roll-forward is lazy, on the next write.
///
/// Like `governor`'s keyed limiter (see its `retain_recent`/
/// `shrink_to_fit`, unused elsewhere in this module), entries are never
/// proactively evicted — an IP that fails once keeps a map entry
/// indefinitely. This mirrors the existing keyed-limiter's own
/// unbounded-growth characteristic in this codebase; out of scope for
/// issue #66 to newly solve.
struct AuthFailureWindow {
    /// Max failures per IP within `window` before `is_over_budget`
    /// returns `true`. Sourced from `RateLimitConfig::auth_per_min` —
    /// same config knob, reinterpreted as a failure cap rather than an
    /// attempt cap (issue #66).
    cap: u32,
    /// Window length. Always 60s in production (matching `*_PER_MIN`
    /// semantics); parameterized so tests can use a larger window and
    /// avoid real-time flakiness without changing the cap.
    window: Duration,
    buckets: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl AuthFailureWindow {
    fn new(cap: u32, window: Duration) -> Self {
        Self {
            cap,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Peek: is `ip` currently at or over the failure budget within its
    /// active window? Pure — never mutates `buckets`. An aged-out
    /// window (no failure recorded within the last `window`) always
    /// reads as under budget, regardless of the stale count still
    /// stored (the roll-forward happens lazily in
    /// [`record_failure`](Self::record_failure)).
    fn is_over_budget(&self, ip: IpAddr) -> bool {
        let buckets = self.buckets.lock().unwrap();
        match buckets.get(&ip) {
            Some((window_start, count)) if window_start.elapsed() < self.window => {
                *count >= self.cap
            }
            _ => false,
        }
    }

    /// Record one authentication failure for `ip`. Rolls the window
    /// forward (resets to `count = 1`) if the stored window has aged
    /// past `window`. The ONLY mutator on this type — callers MUST call
    /// this exclusively on the failure path (an HTTP `401` response),
    /// never on success and never speculatively on entry.
    fn record_failure(&self, ip: IpAddr) {
        let mut buckets = self.buckets.lock().unwrap();
        let entry = buckets.entry(ip).or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= self.window {
            *entry = (Instant::now(), 0);
        }
        entry.1 += 1;
    }

    /// Seconds remaining until `ip`'s current window resets, floored at
    /// 1 (matching [`rate_limit_response`]'s `Retry-After` contract —
    /// never advertise `Retry-After: 0`). Returns 1 for an IP with no
    /// stored bucket (defensive fallback; callers only reach this after
    /// [`is_over_budget`](Self::is_over_budget) already returned `true`
    /// for the same IP, so a bucket should always be present).
    fn retry_after_secs(&self, ip: IpAddr) -> u64 {
        let buckets = self.buckets.lock().unwrap();
        match buckets.get(&ip) {
            Some((window_start, _)) => self
                .window
                .saturating_sub(window_start.elapsed())
                .as_secs()
                .max(1),
            None => 1,
        }
    }
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

/// Per-layer state shared across requests, for the **write-scope**
/// layer specifically ([`write_rate_limit_layer`]). Despite the generic
/// name — kept to avoid churning the `RateLimitLayer`/
/// `RateLimitMiddlewareFn`/`RateLimitFuture` type-alias family for a
/// cosmetic rename — the auth scope no longer uses this type; see
/// [`AuthRateLimitState`] for its failure-counting sibling (issue #66).
/// Cheap to clone — the keyed limiter and the exemption list are both
/// behind an `Arc`. Public only because it appears in the
/// [`RateLimitLayer`] type alias returned by the pub builders; its
/// fields stay private, so callers can't construct it.
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
// Auth-scope middleware (failure-only counting — issue #66)
// ---------------------------------------------------------------------------

/// State for [`auth_rate_limit_layer`]. Deliberately NOT [`RateLimitState`]
/// — the auth scope's bucket-consumption model is structurally different
/// (peek-then-conditionally-consume vs. `governor`'s check-then-consume),
/// so it needs its own state shape. See the module doc's "Why not
/// `governor` for the auth scope?" section.
#[derive(Clone)]
pub struct AuthRateLimitState {
    /// Per-IP failure-window counter — NOT a `governor` token bucket.
    failures: Arc<AuthFailureWindow>,
    /// Source ranges exempt from this bucket (same semantics as
    /// [`RateLimitState::exempt_cidrs`]).
    exempt_cidrs: Arc<Vec<IpNet>>,
}

/// Auth-scope rate-limit middleware entry point. Boxed-future `fn`
/// wrapper, same pattern as [`rate_limit_middleware`].
fn auth_rate_limit_middleware(
    State(state): State<AuthRateLimitState>,
    req: Request,
    next: Next,
) -> RateLimitFuture {
    Box::pin(auth_rate_limit_middleware_impl(state, req, next))
}

/// Policy body for [`auth_rate_limit_middleware`].
///
/// Five steps — (a)-(c) mirror [`rate_limit_middleware_impl`] exactly
/// (method filter, `RequestTrust` extraction with the same 500-on-missing
/// safety net, CIDR exemption); (d)-(e) are new:
///
/// (d) **Pre-validation entry check — PEEK, never consumes.** An IP that
///     has already accumulated `auth_per_min` failures within the
///     current window is rejected HERE, before `next.run` — so
///     `require_principal`'s JWKS validation (or `/auth/exchange`'s own
///     credential-exchange work) never executes for it. This is
///     invariant 1 (pre-validation throttle).
/// (e) **Consume ONLY on failure.** After running downstream, a `401`
///     response — and only a `401` — records one failure. A successful
///     write by a valid principal, and a `403` from a downstream
///     authorization decision on an ALREADY-valid principal, never
///     touch the bucket (invariant 3).
async fn auth_rate_limit_middleware_impl(
    state: AuthRateLimitState,
    req: Request,
    next: Next,
) -> Response {
    // (a) Method filter.
    if !write_methods().contains(req.method()) {
        return next.run(req).await;
    }

    // (b) Client IP — same missing-trust safety net as the write scope.
    let Some(client_ip) = req.extensions().get::<RequestTrust>().map(|t| t.client_ip) else {
        tracing::error!(
            scope = SCOPE_AUTH,
            "rate limit: RequestTrust missing from extensions; router-wiring bug — \
             refusing to bypass bucket"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    // (c) Exemption.
    if cidr_contains(client_ip, &state.exempt_cidrs) {
        return next.run(req).await;
    }

    // (d) Pre-validation entry check — reject BEFORE next.run if this
    // IP is already over its failure budget. Peek only; does not
    // consume, so a request that turns out to be a valid-principal
    // write was never at risk of drawing the bucket down just by being
    // checked.
    if state.failures.is_over_budget(client_ip) {
        let path = resolve_matched_path(&req);
        tracing::info!(
            client_ip = %client_ip,
            scope = SCOPE_AUTH,
            path = %path,
            "rate limit rejection"
        );
        emit_reject_metric(path, SCOPE_AUTH);
        return rate_limit_response(state.failures.retry_after_secs(client_ip));
    }

    // (e) Run downstream, then consume ONLY on a 401. A 403 (valid
    // principal, insufficient authorization for THIS write) can only be
    // reached after require_principal already accepted the credential —
    // counting it here would penalize authenticated clients for
    // authorization outcomes, not credential validity (invariant 3).
    let response = next.run(req).await;
    if response.status() == StatusCode::UNAUTHORIZED {
        state.failures.record_failure(client_ip);
    }
    response
}

// ---------------------------------------------------------------------------
// Public layer builders
// ---------------------------------------------------------------------------

/// Future returned by [`rate_limit_middleware`] and
/// [`auth_rate_limit_middleware`]. Boxed + pinned so the `fn` pointers
/// in [`RateLimitMiddlewareFn`] / [`AuthRateLimitMiddlewareFn`] are
/// nameable. Shared between the two scopes — the alias itself carries
/// no state-type parameter, only `Response`.
pub type RateLimitFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + 'static>>;

/// Signature of [`rate_limit_middleware`]. Captured as a type alias so the
/// `FromFnLayer` generics in [`RateLimitLayer`] stay legible. Mirrors the
/// `TrustMiddlewareFn` pattern in [`crate::middleware::trust`].
pub type RateLimitMiddlewareFn = fn(State<RateLimitState>, Request, Next) -> RateLimitFuture;

/// Axum tracks the middleware extractor tuple WITHOUT the trailing `Next`.
/// For `fn(State<_>, Request, Next)` the tuple is `(State<_>, Request)`.
pub type RateLimitMiddlewareArgs = (State<RateLimitState>, Request);

/// Layer type returned by [`write_rate_limit_layer`] — an
/// [`axum::middleware::from_fn_with_state`] wrapping
/// [`rate_limit_middleware`].
pub type RateLimitLayer =
    axum::middleware::FromFnLayer<RateLimitMiddlewareFn, RateLimitState, RateLimitMiddlewareArgs>;

/// Signature of [`auth_rate_limit_middleware`]. Mirrors
/// [`RateLimitMiddlewareFn`]'s shape for the auth scope's distinct state
/// type.
pub type AuthRateLimitMiddlewareFn =
    fn(State<AuthRateLimitState>, Request, Next) -> RateLimitFuture;

/// Axum's middleware extractor tuple for [`AuthRateLimitMiddlewareFn`]
/// (WITHOUT the trailing `Next` — see [`RateLimitMiddlewareArgs`]).
pub type AuthRateLimitMiddlewareArgs = (State<AuthRateLimitState>, Request);

/// Layer type returned by [`auth_rate_limit_layer`] — an
/// [`axum::middleware::from_fn_with_state`] wrapping
/// [`auth_rate_limit_middleware`].
pub type AuthRateLimitLayer = axum::middleware::FromFnLayer<
    AuthRateLimitMiddlewareFn,
    AuthRateLimitState,
    AuthRateLimitMiddlewareArgs,
>;

/// Build the auth-scope rate-limit layer (issue #66). Attached over the
/// same tree [`crate::middleware::auth::require_principal`] runs under
/// — and over `POST /api/v1/auth/exchange`, which is anonymous but
/// still a credential-stuffing target (see the module doc). Counts only
/// authentication FAILURES (`401` responses); a valid principal's
/// writes never touch this bucket. The middleware's own method filter
/// skips GET/HEAD/OPTIONS — a GET is never a credential-presentation
/// attempt.
pub fn auth_rate_limit_layer(config: &RateLimitConfig) -> AuthRateLimitLayer {
    let state = AuthRateLimitState {
        failures: Arc::new(AuthFailureWindow::new(
            config.auth_per_min,
            Duration::from_secs(60),
        )),
        exempt_cidrs: config.exempt_cidrs.clone(),
    };
    axum::middleware::from_fn_with_state(
        state,
        auth_rate_limit_middleware as AuthRateLimitMiddlewareFn,
    )
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

    /// Stand-in for `require_principal` (or `/auth/exchange`) rejecting
    /// an invalid/missing/replayed credential — the ONLY status the
    /// auth-scope failure counter records against (issue #66).
    async fn unauthorized_handler() -> StatusCode {
        StatusCode::UNAUTHORIZED
    }

    /// Stand-in for a downstream authorization denial on an ALREADY
    /// valid principal (e.g. RBAC-insufficient for this specific
    /// write) — must NOT be counted as an auth-scope failure.
    async fn forbidden_handler() -> StatusCode {
        StatusCode::FORBIDDEN
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
    // AuthFailureWindow — direct unit tests (issue #66)
    //
    // The HTTP-level tests below exercise this type through the full
    // middleware, but the production window is a fixed 60s
    // (`auth_rate_limit_layer` hardcodes it) — too slow to exercise the
    // window-rollover branch in a fast test. These tests construct the
    // type directly with a short window instead.
    // ------------------------------------------------------------------

    #[test]
    fn auth_failure_window_is_over_budget_false_when_no_failures_recorded() {
        let w = AuthFailureWindow::new(2, Duration::from_secs(60));
        let ip: IpAddr = "10.9.0.1".parse().unwrap();
        assert!(!w.is_over_budget(ip));
    }

    #[test]
    fn auth_failure_window_over_budget_after_cap_failures() {
        let w = AuthFailureWindow::new(2, Duration::from_secs(60));
        let ip: IpAddr = "10.9.0.2".parse().unwrap();
        w.record_failure(ip);
        assert!(!w.is_over_budget(ip), "1 failure < cap=2");
        w.record_failure(ip);
        assert!(w.is_over_budget(ip), "2 failures >= cap=2");
    }

    #[test]
    fn auth_failure_window_is_over_budget_never_mutates() {
        // Peeking many times must not itself push the count toward the
        // cap — a request that turns out to be a valid-principal write
        // must never have consumed a slot just by being checked.
        let w = AuthFailureWindow::new(1, Duration::from_secs(60));
        let ip: IpAddr = "10.9.0.3".parse().unwrap();
        for _ in 0..10 {
            assert!(!w.is_over_budget(ip));
        }
    }

    #[test]
    fn auth_failure_window_rolls_forward_after_window_expires() {
        let w = AuthFailureWindow::new(1, Duration::from_millis(20));
        let ip: IpAddr = "10.9.0.4".parse().unwrap();
        w.record_failure(ip);
        assert!(w.is_over_budget(ip), "1 failure >= cap=1 within the window");
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            !w.is_over_budget(ip),
            "window expired — peek treats the stale count as fresh (0 failures)"
        );
        // Confirm record_failure ALSO rolls the window forward (not just
        // the peek path) — a fresh failure re-fills the cap=1 budget
        // rather than accumulating onto the stale count.
        w.record_failure(ip);
        assert!(
            w.is_over_budget(ip),
            "one fresh failure after rollover re-fills the cap=1 budget"
        );
    }

    #[test]
    fn auth_failure_window_retry_after_floors_at_one_second() {
        let w = AuthFailureWindow::new(1, Duration::from_millis(10));
        let ip: IpAddr = "10.9.0.5".parse().unwrap();
        w.record_failure(ip);
        // Window is only 10ms — remaining time truncates to 0 whole
        // seconds; must floor at 1 so Retry-After is never advertised
        // as 0 (a client would hot-loop on that).
        assert_eq!(w.retry_after_secs(ip), 1);
    }

    #[test]
    fn auth_failure_window_retry_after_defaults_to_one_when_ip_unknown() {
        let w = AuthFailureWindow::new(1, Duration::from_secs(60));
        let ip: IpAddr = "10.9.0.6".parse().unwrap();
        assert_eq!(w.retry_after_secs(ip), 1);
    }

    // ------------------------------------------------------------------
    // Auth rate limit — issue #66: counts FAILURES only
    // ------------------------------------------------------------------

    /// Invariant 1 (pre-validation throttle) + the core failures-only
    /// behavior: a flood of FAILING credential presentations from one
    /// IP still 429s once the failure budget is exhausted, with the
    /// canonical `Retry-After` + JSON envelope + metric — but the first
    /// `cap` failures DO reach the downstream handler (they must, to be
    /// counted), and only requests beyond the budget are rejected
    /// pre-validation.
    #[test]
    fn auth_layer_bad_credential_flood_429s_once_failure_budget_exhausted() {
        // Burst of 2 — third same-IP FAILED attempt must 429. Using 2
        // instead of 60 keeps the test fast; semantics are identical.
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
                        .route("/protected", post(unauthorized_handler))
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
        // First two FAILED attempts pass through to the downstream
        // handler (still 401 — they are genuinely bad credentials) and
        // are what fill the failure budget.
        assert_eq!(status_1, StatusCode::UNAUTHORIZED);
        assert_eq!(status_2, StatusCode::UNAUTHORIZED);
        // Third attempt is rejected PRE-VALIDATION — never reaches the
        // downstream handler at all.
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

    /// Invariant 1, made explicit: once the failure budget is
    /// exhausted, the downstream handler (standing in for
    /// `require_principal`'s JWKS validation) is NEVER invoked again —
    /// the reject happens strictly before `next.run`.
    #[test]
    fn auth_layer_stops_calling_downstream_once_failure_budget_exhausted() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = RateLimitConfig::new(2, 100, vec![]);
        let statuses = rt(async {
            let calls_for_handler = calls.clone();
            let router = Router::new()
                .route(
                    "/protected",
                    post(move || {
                        let calls = calls_for_handler.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            StatusCode::UNAUTHORIZED
                        }
                    }),
                )
                .layer(auth_rate_limit_layer(&cfg));
            let mut statuses = Vec::new();
            for _ in 0..5 {
                let s = router
                    .clone()
                    .oneshot(post_with_trust("/protected", trust("10.0.0.11")))
                    .await
                    .unwrap()
                    .status();
                statuses.push(s);
            }
            statuses
        });
        assert_eq!(
            statuses,
            vec![
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS,
            ]
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "downstream must not run once the failure budget is exhausted — \
             this IS the pre-validation throttle (invariant 1)"
        );
    }

    /// Invariant 3: an authenticated client whose writes ALL succeed
    /// (valid principal, 200 responses) never draws the auth bucket
    /// down, no matter how many writes it sends — the auth scope's cap
    /// is a FAILURE budget, not an attempt budget. This is the exact
    /// bug shape issue #66 reports: a `cosign copy` bulk mirror push
    /// far exceeding `auth_per_min` in valid, successfully-authenticated
    /// writes must never 429 at the auth scope.
    #[test]
    fn auth_layer_valid_principal_writes_never_consume_auth_bucket() {
        // auth cap = 2 (tiny) — if a 200-returning handler's successes
        // still consumed the auth bucket (the pre-fix behavior), the
        // 3rd of 10 requests would 429. It must not.
        let cfg = RateLimitConfig::new(2, 1000, vec![]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/protected", post(ok_handler))
                .layer(auth_rate_limit_layer(&cfg));
            let mut statuses = Vec::new();
            for _ in 0..10 {
                let s = router
                    .clone()
                    .oneshot(post_with_trust("/protected", trust("10.0.0.12")))
                    .await
                    .unwrap()
                    .status();
                statuses.push(s);
            }
            statuses
        });
        assert!(
            statuses.iter().all(|s| *s == StatusCode::OK),
            "valid-principal (200) writes must never be auth-429'd regardless \
             of volume: {statuses:?}"
        );
    }

    /// Invariant 3, the sharper edge: a `403` from a downstream
    /// authorization decision — reachable ONLY after `require_principal`
    /// already accepted the credential (RBAC-insufficient for this
    /// specific write, e.g.) — must not be mistaken for a credential
    /// failure and must not consume the auth bucket either.
    #[test]
    fn auth_layer_403_from_valid_principal_does_not_consume_bucket() {
        let cfg = RateLimitConfig::new(1, 1000, vec![]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/protected", post(forbidden_handler))
                .layer(auth_rate_limit_layer(&cfg));
            let mut statuses = Vec::new();
            for _ in 0..5 {
                let s = router
                    .clone()
                    .oneshot(post_with_trust("/protected", trust("10.0.0.13")))
                    .await
                    .unwrap()
                    .status();
                statuses.push(s);
            }
            statuses
        });
        assert!(
            statuses.iter().all(|s| *s == StatusCode::FORBIDDEN),
            "403 (valid principal, authz denial) must never draw the \
             auth-stuffing bucket down: {statuses:?}"
        );
    }

    /// Invariant 2: `POST /api/v1/auth/exchange` is anonymous
    /// (`method_based_auth_dispatch` routes it around
    /// `require_principal` — `crate::router::is_anonymous_path`), but
    /// `auth_rate_limit_layer` is attached over the whole tree,
    /// method-filtered rather than route-specific, so a flood of
    /// FAILING exchange attempts from one IP still trips the auth
    /// scope exactly like any other 401-returning write path.
    #[test]
    fn auth_layer_still_throttles_auth_exchange_path() {
        let cfg = RateLimitConfig::new(1, 100, vec![]);
        let (s1, s2) = rt(async {
            let router = Router::new()
                .route("/api/v1/auth/exchange", post(unauthorized_handler))
                .layer(auth_rate_limit_layer(&cfg));
            let s1 = router
                .clone()
                .oneshot(post_with_trust("/api/v1/auth/exchange", trust("10.0.0.14")))
                .await
                .unwrap()
                .status();
            let s2 = router
                .oneshot(post_with_trust("/api/v1/auth/exchange", trust("10.0.0.14")))
                .await
                .unwrap()
                .status();
            (s1, s2)
        });
        assert_eq!(
            s1,
            StatusCode::UNAUTHORIZED,
            "first bad-credential exchange fails normally"
        );
        assert_eq!(
            s2,
            StatusCode::TOO_MANY_REQUESTS,
            "second attempt from the same IP is pre-validation-throttled — \
             /auth/exchange bypasses require_principal but still trips the \
             auth scope"
        );
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

    /// Write-scope counterpart, same rationale as
    /// `write_layer_missing_request_trust_yields_500_not_bucket_bypass`
    /// — `write_rate_limit_layer`'s own method-filter early-return needs
    /// direct coverage now that it no longer shares an implementation
    /// with the auth scope.
    #[test]
    fn write_layer_skips_get_requests_regardless_of_burst() {
        let cfg = RateLimitConfig::new(10, 1, vec![]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/open", get(ok_handler))
                .layer(write_rate_limit_layer(&cfg));
            let ip = trust("10.0.0.10");
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
            "GETs tripped the write-rate-limit filter despite method carve-out: {statuses:?}"
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

    /// Write scope (unchanged, `governor`-backed) — distinct IPs get
    /// distinct buckets.
    #[test]
    fn write_layer_distinct_client_ips_have_independent_buckets() {
        let cfg = RateLimitConfig::new(1, 1, vec![]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/protected", post(ok_handler))
                .layer(write_rate_limit_layer(&cfg));
            // IP A — first request consumes its token, second would 429.
            let a1 = router
                .clone()
                .oneshot(post_with_trust("/protected", trust("10.0.1.1")))
                .await
                .unwrap()
                .status();
            // IP B — its own bucket is still full, must succeed.
            let b1 = router
                .clone()
                .oneshot(post_with_trust("/protected", trust("10.0.1.2")))
                .await
                .unwrap()
                .status();
            // IP A again — bucket drained, must 429.
            let a2 = router
                .oneshot(post_with_trust("/protected", trust("10.0.1.1")))
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

    /// Auth scope (the new [`AuthFailureWindow`]) — distinct IPs get
    /// distinct FAILURE buckets. Uses `unauthorized_handler` since the
    /// auth scope's bucket only moves on `401` (issue #66); this
    /// specifically proves the hand-rolled per-IP map isolates
    /// correctly, not just that the shared `governor` limiter does
    /// (already proven above for the write scope).
    #[test]
    fn auth_layer_distinct_client_ips_have_independent_failure_buckets() {
        let cfg = RateLimitConfig::new(1, 100, vec![]);
        let statuses = rt(async {
            let router = Router::new()
                .route("/protected", post(unauthorized_handler))
                .layer(auth_rate_limit_layer(&cfg));
            // IP A — first FAILED attempt records its one allowed
            // failure, second would be pre-validation-rejected.
            let a1 = router
                .clone()
                .oneshot(post_with_trust("/protected", trust("10.0.2.1")))
                .await
                .unwrap()
                .status();
            // IP B — its own failure bucket is still empty, must still
            // reach the handler (401, not 429).
            let b1 = router
                .clone()
                .oneshot(post_with_trust("/protected", trust("10.0.2.2")))
                .await
                .unwrap()
                .status();
            // IP A again — failure budget exhausted, must 429.
            let a2 = router
                .oneshot(post_with_trust("/protected", trust("10.0.2.1")))
                .await
                .unwrap()
                .status();
            (a1, b1, a2)
        });
        assert_eq!(
            statuses.0,
            StatusCode::UNAUTHORIZED,
            "first failed attempt from A reaches the handler"
        );
        assert_eq!(
            statuses.1,
            StatusCode::UNAUTHORIZED,
            "B's failure bucket is independent of A's"
        );
        assert_eq!(
            statuses.2,
            StatusCode::TOO_MANY_REQUESTS,
            "A's failure budget exhausted"
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
        // `auth_layer_skips_get_requests_regardless_of_burst`). Uses
        // `unauthorized_handler` — the auth scope's bucket only moves on
        // `401` (issue #66); an `ok_handler` (200) would never trip the
        // reject path this test exercises.
        let cfg = RateLimitConfig::new(1, 10, vec![]);
        let snap = capture(|| {
            rt(async {
                let router = Router::new()
                    .route("/pypi/{repo_key}/", post(unauthorized_handler))
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
            &[("scope", SCOPE_AUTH), ("path", "/pypi/{repo_key}/")],
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
    fn auth_layer_missing_request_trust_yields_500_not_bucket_bypass() {
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

    /// Write-scope counterpart. Before issue #66 split the two scopes
    /// into separate middleware implementations, this branch was shared
    /// with the auth-scope test above and implicitly covered by it; now
    /// that `write_rate_limit_layer` has its own
    /// `rate_limit_middleware_impl` instance, it needs its own direct
    /// coverage of the same missing-trust safety net.
    #[test]
    fn write_layer_missing_request_trust_yields_500_not_bucket_bypass() {
        let cfg = RateLimitConfig::new(1, 1, vec![]);
        let status = rt(async {
            let router = Router::new()
                .route("/protected", post(ok_handler))
                .layer(write_rate_limit_layer(&cfg));
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
        // exempt and must still trip the burst=1 auth FAILURE cap on its
        // second FAILED request. Proves the exemption is a targeted
        // allowlist, not a global off-switch. Uses `unauthorized_handler`
        // — the auth scope's bucket only moves on `401` (issue #66).
        let cfg = RateLimitConfig::new(1, 10, vec!["10.0.0.0/8".parse().unwrap()]);
        let (s1, s2) = rt(async {
            let router = Router::new()
                .route("/protected", post(unauthorized_handler))
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
        assert_eq!(s1, StatusCode::UNAUTHORIZED);
        assert_eq!(
            s2,
            StatusCode::TOO_MANY_REQUESTS,
            "non-exempt IP must still be limited when an exempt set is configured"
        );
    }
}
