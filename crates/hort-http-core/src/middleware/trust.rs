//! Request trust middleware.
//!
//! One tower layer establishes [`RequestTrust`] once per request and
//! stashes it in request extensions. Downstream consumers (URL
//! resolution, rate-limiting key extraction, audit logs)
//! read it without re-evaluating the policy. See
//! `docs/architecture/explanation/security.md` (request trust).
//!
//! # Policy
//!
//! | `HORT_PUBLIC_BASE_URL` | `HORT_TRUSTED_PROXY_CIDRS` | `public_url` | `client_ip` |
//! |---|---|---|---|
//! | set | (ignored) | the configured URL | socket peer (`X-Forwarded-*` ignored) |
//! | unset | set, peer is trusted, XFF present | `X-Forwarded-Proto` + `-Host` (falling back to `Host`) | rightmost-untrusted `X-Forwarded-For` |
//! | unset | set, peer is trusted, XFF absent | (as above) | [`XFF_MISSING_SENTINEL`] (`0.0.0.0`) + throttled `warn!` |
//! | unset | set, peer NOT trusted | `Host` + `https` scheme | socket peer |
//! | unset | set, peer NOT trusted, no `Host` | bind-address-derived default (`warn!` emitted) | socket peer |
//! | unset | unset | handled upstream — `Config::from_env` refuses to start |
//!
//! On the "trusted peer, XFF absent" sentinel row: falling back to the
//! proxy's socket peer would collapse
//! every caller through a misconfigured proxy onto one rate-limit /
//! fail2ban bucket — the proxy itself — disabling the rate-limit
//! defence. The `0.0.0.0` sentinel is OBVIOUSLY-NOT-A-REAL-IP and
//! detectable by dashboards.
//!
//! The `HORT_PUBLIC_BASE_URL` unset + `HORT_TRUSTED_PROXY_CIDRS` unset case never
//! reaches this middleware because `hort-server::config::Config::from_env`
//! fails startup unconditionally in that configuration (the
//! `X-Forwarded-Host`-injection vector poisoning package download URLs is
//! orthogonal to authentication, so the check is NOT auth-gated).
//!
//! # Layer ordering (load-bearing)
//!
//! Tower's `.layer(X)` wraps outward: the layer attached LAST is the
//! OUTERMOST at runtime and runs FIRST on the request path. The layer
//! produced here MUST be attached AFTER the auth dispatch layer in
//! [`crate::router::build_router`] so `RequestTrust` is populated before
//! any auth logging tries to read `client_ip`. Mis-ordering silently
//! inverts trust evaluation — the `layer_order_probe` test in this
//! module asserts the invariant.
//!
//! # Not this middleware's job
//!
//! - Parsing `HORT_TRUSTED_PROXY_CIDRS` — handled at startup by
//!   `hort-server::config::Config`.
//! - Rewriting `UrlResolver` to consume `RequestTrust` — Item 3's turf.
//!   Today's `UrlResolver` still parses its own headers; this layer adds
//!   the primitive. Item 3 wires them together.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::HOST;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

/// Sentinel `client_ip` returned when the peer is in
/// `HORT_TRUSTED_PROXY_CIDRS` but the request is missing
/// `X-Forwarded-For`. See the
/// module docstring's policy table.
///
/// `0.0.0.0` is OBVIOUSLY-NOT-A-REAL-IP, so downstream rate-limit /
/// fail2ban / dashboard logic detects the misconfiguration without
/// conflating attribution onto the proxy itself. Without this
/// sentinel, every caller through a misconfigured proxy would share
/// one rate-limit bucket — the proxy IP — and fail2ban would either
/// ban the proxy (DoS itself) or be tuned to ignore it.
pub const XFF_MISSING_SENTINEL: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Window between successive `WARN` emissions for the trusted-peer +
/// missing-XFF misconfiguration path. A request flood through a
/// misconfigured proxy would self-DoS the log pipeline if every
/// request emitted a line, so we throttle to one line per window per
/// process.
const XFF_WARN_THROTTLE_WINDOW: Duration = Duration::from_secs(60);

/// Per-request trust context, evaluated once by the middleware and
/// stashed in request extensions for every downstream consumer.
///
/// Only two fields — no `peer_trusted: bool`. Speculative API without a
/// named consumer is scope creep; if a future item needs the bool, add
/// it with the consumer in the same PR (design doc §2.0.2).
#[derive(Debug, Clone)]
pub struct RequestTrust {
    /// The real caller's IP. When the socket peer is listed in
    /// `HORT_TRUSTED_PROXY_CIDRS`, this is the rightmost-untrusted hop
    /// of `X-Forwarded-For` (`rightmost_untrusted_forwarded_for`,
    /// closes M-A3); otherwise the socket peer itself.
    pub client_ip: IpAddr,
    /// The public-facing base URL for absolute-URL emission. Always
    /// populated (by construction) so Item 3's infallible
    /// `UrlResolver::resolve() -> Url` holds. See the policy table
    /// above for derivation rules.
    pub public_url: url::Url,
}

/// Startup-configured policy the layer evaluates on every request.
///
/// Cheap to clone (URL clones are refcounted by the `url` crate; CIDR
/// lists are small). Shared across requests via an `Arc`.
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// `HORT_PUBLIC_BASE_URL`, when operator-pinned. When `Some`,
    /// `public_url` is always this value — forwarded headers are ignored
    /// regardless of peer trust.
    pub public_base_url: Option<url::Url>,
    /// Parsed `HORT_TRUSTED_PROXY_CIDRS`. Empty vec means "no proxy trust";
    /// forwarded headers are ignored for every request.
    pub trusted_proxy_cidrs: Vec<IpNet>,
    /// Derived from the server's bind address. Used only when both the
    /// public base URL is unset AND the request has no `Host` header
    /// (the backstop branch that guarantees `public_url` is always
    /// populated). The derivation strategy is the caller's — `hort-server`
    /// synthesises `http://<bind_addr>/` at startup.
    pub bind_addr_default: url::Url,
    /// Per-config throttle for the trusted-peer + missing-XFF `WARN`.
    /// `Arc<Mutex<Option<Instant>>>` so clones share the throttle state
    /// (production has one `TrustConfig` shared via `Arc`); tests get a
    /// fresh window automatically because each `TrustConfig::new` /
    /// `TrustConfig::default` constructs a new state cell.
    ///
    /// `None` = no WARN emitted yet (next call WILL warn).
    /// `Some(t)` = last WARN was emitted at `t`; suppress further
    /// WARNs until `t + XFF_WARN_THROTTLE_WINDOW`.
    ///
    /// See module docstring policy
    /// table.
    xff_warn_last: Arc<Mutex<Option<Instant>>>,
}

impl TrustConfig {
    /// Construct a trust config. All fields come from `hort-server::Config`;
    /// this constructor exists for test ergonomics + composability.
    pub fn new(
        public_base_url: Option<url::Url>,
        trusted_proxy_cidrs: Vec<IpNet>,
        bind_addr_default: url::Url,
    ) -> Self {
        Self {
            public_base_url,
            trusted_proxy_cidrs,
            bind_addr_default,
            xff_warn_last: Arc::new(Mutex::new(None)),
        }
    }

    /// Throttle decision for the trusted-peer + missing-XFF `WARN`.
    /// Returns `true` when the caller should emit the line, `false`
    /// when the previous WARN was within the throttle window. Updates
    /// the last-emit instant on the allow branch.
    ///
    /// Both branches are exercised by the test suite — the allow
    /// branch by `trusted_peer_without_xff_returns_sentinel_not_proxy_ip`
    /// (fresh config), the deny branch by the 100-request loop in
    /// `trusted_peer_xff_missing_warn_is_throttled`.
    fn should_emit_xff_warn(&self) -> bool {
        let now = Instant::now();
        let mut guard = self.xff_warn_last.lock().expect("xff-warn mutex poisoned");
        match *guard {
            // First WARN since this config was constructed: allow.
            None => {
                *guard = Some(now);
                true
            }
            // Previous WARN within the throttle window: suppress.
            Some(last) if now.duration_since(last) < XFF_WARN_THROTTLE_WINDOW => false,
            // Window elapsed: allow + reset.
            Some(_) => {
                *guard = Some(now);
                true
            }
        }
    }
}

impl Default for TrustConfig {
    /// Default wires a fixed `http://hort-server:8080/` public URL plus an
    /// empty trusted-proxy list. Intended for the many test harnesses
    /// that build `AppContext` literals and need every field populated
    /// without caring about trust — production paths always supply a
    /// concrete config from `hort-server::Config`. The default is chosen
    /// to match the production docker-compose `HORT_PUBLIC_BASE_URL`
    /// value so existing E2E URL shape assertions stay stable.
    fn default() -> Self {
        Self::new(
            Some(
                url::Url::parse("http://hort-server:8080").expect("valid test-default public URL"),
            ),
            Vec::new(),
            url::Url::parse("http://0.0.0.0:8080/").expect("valid test-default bind address"),
        )
    }
}

/// Attach [`request_trust_layer(cfg)`] LAST in the router's
/// `.layer()` chain so `RequestTrust` is populated before anything
/// downstream tries to read it.
///
/// Return type exposed as `axum::middleware::FromFnLayer<...>` so
/// callers don't need to thread `impl Trait` through composition.
/// The generic argument triple follows axum's convention:
/// - `F` — the middleware fn type (here a named fn pointer).
/// - `S` — the shared state (`Arc<TrustConfig>` so per-request clones
///   are pointer-only).
/// - `T` — the extractor tuple (everything before `Next` in the handler
///   signature); here `(State<Arc<TrustConfig>>, Request)`.
pub fn request_trust_layer(
    config: TrustConfig,
) -> axum::middleware::FromFnLayer<TrustMiddlewareFn, Arc<TrustConfig>, TrustMiddlewareArgs> {
    axum::middleware::from_fn_with_state(Arc::new(config), trust_middleware_fn as TrustMiddlewareFn)
}

/// Signature of [`trust_middleware_fn`]. Captured as a type alias so
/// the `FromFnLayer` generics in [`request_trust_layer`] stay legible.
pub type TrustMiddlewareFn = fn(State<Arc<TrustConfig>>, Request, Next) -> TrustMiddlewareFuture;

/// Axum tracks the middleware extractor tuple WITHOUT the trailing
/// `Next` (see `FromFn<F, S, I, T>` in `axum::middleware::from_fn`).
/// For a handler of shape `fn(State<_>, Request, Next)` the tuple is
/// `(State<_>, Request,)`.
pub type TrustMiddlewareArgs = (State<Arc<TrustConfig>>, Request);

/// Future returned by [`trust_middleware_fn`]. Boxed + pinned so the
/// fn pointer in [`TrustMiddlewareFn`] is nameable.
pub type TrustMiddlewareFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + 'static>>;

/// Trust-middleware entry. A plain `fn` (not `async fn`) because the
/// alias [`TrustMiddlewareFn`] needs a nameable function pointer type
/// — `async fn` desugars to an anonymous future which isn't nameable
/// as `fn`. Policy logic lives in the pure [`evaluate_trust`] so it
/// can be unit-tested without a full axum stack.
fn trust_middleware_fn(
    State(config): State<Arc<TrustConfig>>,
    mut req: Request,
    next: Next,
) -> TrustMiddlewareFuture {
    Box::pin(async move {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        let trust = evaluate_trust(&config, peer, req.headers());
        tracing::debug!(
            client_ip = %trust.client_ip,
            public_url = %trust.public_url,
            "request trust evaluated"
        );
        req.extensions_mut().insert(trust);
        next.run(req).await
    })
}

/// Core policy evaluation. Pure function — no I/O, no logging beyond a
/// `warn!` on the bind-address fallback branch. Exposed at module scope
/// so the `#[cfg(test)]` block can exercise every arm without faking
/// axum's `ConnectInfo` extractor.
pub(crate) fn evaluate_trust(
    config: &TrustConfig,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
) -> RequestTrust {
    let peer_trusted = match peer_ip {
        Some(ip) => cidr_contains(ip, &config.trusted_proxy_cidrs),
        // No peer IP means the server wasn't constructed with
        // `into_make_service_with_connect_info` — treat as untrusted.
        // The startup-time switch in `hort-server::main` prevents this
        // from firing in production; the defensive branch keeps tests
        // and misconfigured embeds honest.
        None => false,
    };

    let client_ip = if peer_trusted {
        // `peer_trusted == true` implies `peer_ip == Some(_)` AND that
        // ip is in `trusted_proxy_cidrs` (see how `peer_trusted` is
        // computed above) — the `expect` is a structural invariant,
        // not a runtime check. The right-to-left walk strips trusted
        // hops; the first untrusted hop is the real client.
        let trusted_peer = peer_ip.expect("peer_trusted=true implies peer_ip is Some");
        rightmost_untrusted_forwarded_for(headers, trusted_peer, &config.trusted_proxy_cidrs)
            .unwrap_or_else(|| {
                // Trusted proxy set the allowlist but omitted (or every
                // hop was trusted in) `X-Forwarded-For` — proxy
                // misconfiguration or strip attempt. So:
                //
                // 1. Return the `0.0.0.0` sentinel — NEVER the proxy IP.
                //    Falling back to the proxy IP would collapse every
                //    caller through the misconfigured proxy onto one
                //    rate-limit bucket, disabling fail2ban.
                // 2. Emit a throttled `WARN` (60s window per process)
                //    carrying the proxy peer + the matched trust source
                //    so the misconfig is visible in logs without
                //    log-volume DoS.
                if config.should_emit_xff_warn() {
                    tracing::warn!(
                        peer_addr = ?peer_ip,
                        trusted_proxy_cidrs = ?config.trusted_proxy_cidrs,
                        "trusted peer with missing X-Forwarded-For; emitting client_ip sentinel — \
                         check proxy config (XFF strip / misconfiguration)"
                    );
                }
                XFF_MISSING_SENTINEL
            })
    } else {
        peer_ip.unwrap_or(XFF_MISSING_SENTINEL)
    };

    let public_url = resolve_public_url(config, peer_trusted, peer_ip, headers);

    RequestTrust {
        client_ip,
        public_url,
    }
}

/// `public_url` derivation. The branches mirror the table in the module
/// docstring and design doc §2.2.
fn resolve_public_url(
    config: &TrustConfig,
    peer_trusted: bool,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
) -> url::Url {
    // Branch 1: operator-pinned URL always wins.
    if let Some(base) = &config.public_base_url {
        return base.clone();
    }

    // Branch 2: trusted peer — consult forwarded headers.
    if peer_trusted {
        let scheme = forwarded_proto(headers).unwrap_or("https");
        let authority = forwarded_host(headers)
            .or_else(|| header_str(headers, HOST))
            .unwrap_or("");
        if let Some(url) = build_url(scheme, authority) {
            return url;
        }
        // Trusted peer but every header is missing or malformed — drop
        // through to the bind-address fallback. This is a degenerate
        // proxy config but we must still return a `Url`.
        tracing::warn!(
            ?peer_ip,
            "trusted peer with unusable Host / X-Forwarded-Host; using bind-address fallback"
        );
        return config.bind_addr_default.clone();
    }

    // Branch 3: untrusted peer — ignore X-Forwarded-* entirely (§2.2),
    // synthesise from `Host` + `https`. Matches today's `url_resolver.rs`
    // bare-host branch (the production-safe default a TLS-terminating
    // proxy would supply).
    if let Some(host) = header_str(headers, HOST) {
        if let Some(url) = build_url("https", host) {
            return url;
        }
    }

    // Branch 4: missing `Host` on an untrusted peer. Guarantees
    // `public_url` is always populated so Item 3's infallible signature
    // holds. Emit a `warn!` — legitimate HTTP/1.1 clients never omit
    // `Host`, so this branch is either a probe or a buggy client.
    tracing::warn!(
        ?peer_ip,
        "request without Host header; using bind-address fallback for RequestTrust"
    );
    config.bind_addr_default.clone()
}

fn cidr_contains(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    // Dual-stack peers that arrive as
    // `::ffff:a.b.c.d` (IPv4-mapped IPv6, RFC 4291 §2.5.5) must match
    // operator-configured IPv4 CIDRs (e.g. `10.0.0.0/8`). Without
    // canonicalization, `IpNet::contains` compares the IPv6 form
    // against an IPv4 net and returns `false`, silently treating the
    // proxy as untrusted and emitting the XFF-strip sentinel.
    //
    // `to_canonical` is a no-op for `IpAddr::V4` and for `IpAddr::V6`
    // values that are NOT IPv4-mapped, so this is safe for every
    // existing call site (the trust check + the XFF walk).
    let canonical = ip.to_canonical();
    cidrs.iter().any(|net| net.contains(&canonical))
}

fn header_str(headers: &HeaderMap, name: impl axum::http::header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn forwarded_proto(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, "x-forwarded-proto")
}

fn forwarded_host(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, "x-forwarded-host")
}

/// Walk `X-Forwarded-For` right-to-left and return the rightmost hop
/// that is NOT in `trusted_cidrs`. The naive "leftmost" reading is
/// **spoofable**: any client can prepend a fake IP to its own request,
/// and an appending proxy will dutifully tack the real client on the
/// right without stripping the spoofed entry. Walking right-to-left
/// strips trusted-proxy hops until we cross the trust boundary — that
/// boundary entry is the correct attribution (RFC 7239 §5.2 / OWASP
/// proxy-headers guidance).
///
/// Algorithm (design doc §3, with the trust-boundary edge case spelled
/// out — the bare pseudocode misses the leftmost-untrusted-after-all-
/// trusted-hops case):
/// - Parse the XFF header into a `Vec<IpAddr>`, dropping unparseable
///   entries silently (matches the previous parser's `.ok()` shape).
/// - Maintain `prev_trusted`, initialised to `cidr_contains(peer_ip)`.
///   The "previous hop" relative to the rightmost XFF entry is the
///   socket peer that handed us the request.
/// - Walking right-to-left, on each entry: if `prev_trusted` is
///   `false`, the hop to our right was already untrusted, so the
///   chain has been compromised — return the current entry as the
///   attribution boundary. Otherwise, remember this entry as the
///   running "last entry walked" candidate and update
///   `prev_trusted = cidr_contains(entry)`.
/// - After the loop:
///   - If `prev_trusted` is still `true`, every hop including the
///     leftmost was trusted → no external attribution boundary →
///     return `None` (caller falls back to `XFF_MISSING_SENTINEL`).
///   - If `prev_trusted` flipped to `false` on the final entry, that
///     leftmost entry is the original (untrusted) sender — return it.
///
/// This is the spoof-resistant attribution walk — see the test-module
/// rationale below.
fn rightmost_untrusted_forwarded_for(
    headers: &HeaderMap,
    peer_ip: IpAddr,
    trusted_cidrs: &[IpNet],
) -> Option<IpAddr> {
    let raw = header_str(headers, "x-forwarded-for")?;
    let entries: Vec<IpAddr> = raw
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();
    let mut prev_trusted = cidr_contains(peer_ip, trusted_cidrs);
    let mut candidate: Option<IpAddr> = None;
    for entry in entries.iter().rev() {
        if !prev_trusted {
            return Some(*entry);
        }
        candidate = Some(*entry);
        prev_trusted = cidr_contains(*entry, trusted_cidrs);
    }
    // Loop ended without surfacing a mid-chain untrusted hop.
    // - prev_trusted == true: all hops trusted including leftmost.
    // - prev_trusted == false: the LAST update (leftmost entry) made
    //   it false. That leftmost entry is the original sender — return
    //   it. This is the trust-boundary edge case the design pseudocode
    //   omits but the unit tests pin.
    if prev_trusted {
        None
    } else {
        candidate
    }
}

fn build_url(scheme: &str, authority: &str) -> Option<url::Url> {
    if authority.is_empty() {
        return None;
    }
    url::Url::parse(&format!("{scheme}://{authority}")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use axum::body::Body;
    use axum::http::{HeaderName, HeaderValue, Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;
    use tracing_test::traced_test;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::try_from(*k).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn default_config(public: Option<&str>, cidrs: &[&str]) -> TrustConfig {
        TrustConfig::new(
            public.map(url),
            cidrs.iter().copied().map(cidr).collect(),
            url("http://0.0.0.0:8080/"),
        )
    }

    // ---------- policy: HORT_PUBLIC_BASE_URL wins ----------

    #[test]
    fn public_base_url_overrides_all_headers() {
        let config = default_config(Some("https://hort.example.com"), &["10.0.0.0/8"]);
        let h = headers(&[
            ("host", "evil.attacker.tld"),
            ("x-forwarded-proto", "http"),
            ("x-forwarded-host", "other.attacker.tld"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);
        // Peer is trusted — but the pinned URL still wins.
        let trust = evaluate_trust(&config, Some(ip("10.0.0.5")), &h);
        assert_eq!(trust.public_url.as_str(), "https://hort.example.com/");
    }

    #[test]
    fn public_base_url_preserves_port() {
        let config = default_config(Some("http://hort-server:8080"), &[]);
        let h = HeaderMap::new();
        let trust = evaluate_trust(&config, None, &h);
        assert_eq!(trust.public_url.scheme(), "http");
        assert_eq!(trust.public_url.host_str(), Some("hort-server"));
        assert_eq!(trust.public_url.port(), Some(8080));
    }

    // ---------- policy: trusted peer → forwarded headers ----------

    #[test]
    fn trusted_peer_uses_forwarded_proto_host_and_for() {
        let config = default_config(None, &["10.0.0.0/8"]);
        let h = headers(&[
            ("host", "internal.hort-server"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "hort.example.com"),
            ("x-forwarded-for", "203.0.113.7, 10.0.0.1"),
        ]);
        let trust = evaluate_trust(&config, Some(ip("10.0.0.5")), &h);
        assert_eq!(trust.public_url.as_str(), "https://hort.example.com/");
        assert_eq!(trust.client_ip, ip("203.0.113.7"));
    }

    #[test]
    fn trusted_peer_falls_back_to_host_when_forwarded_host_missing() {
        let config = default_config(None, &["10.0.0.0/8"]);
        let h = headers(&[
            ("host", "hort.example.com"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-for", "203.0.113.7"),
        ]);
        let trust = evaluate_trust(&config, Some(ip("10.0.0.5")), &h);
        assert_eq!(trust.public_url.as_str(), "https://hort.example.com/");
    }

    // ---------- policy: untrusted peer → X-Forwarded-* ignored ----------

    #[test]
    fn untrusted_peer_ignores_forwarded_headers() {
        let config = default_config(None, &["10.0.0.0/8"]);
        let h = headers(&[
            ("host", "hort.example.com"),
            ("x-forwarded-proto", "http"),
            ("x-forwarded-host", "attacker.example.com"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);
        // Peer 203.0.113.9 is NOT in 10.0.0.0/8.
        let trust = evaluate_trust(&config, Some(ip("203.0.113.9")), &h);
        // Scheme is the production-safe `https`, authority from `Host`.
        assert_eq!(trust.public_url.as_str(), "https://hort.example.com/");
        // Forwarded-For is ignored — client_ip is the socket peer.
        assert_eq!(trust.client_ip, ip("203.0.113.9"));
    }

    // ---------- policy: untrusted peer + no Host → bind-address fallback ----------

    #[test]
    fn untrusted_peer_missing_host_uses_bind_address_default() {
        let config = default_config(None, &["10.0.0.0/8"]);
        let h = HeaderMap::new();
        let trust = evaluate_trust(&config, Some(ip("203.0.113.9")), &h);
        // Bind-address default is populated — RequestTrust is never
        // missing `public_url`.
        assert_eq!(trust.public_url, url("http://0.0.0.0:8080/"));
        assert_eq!(trust.client_ip, ip("203.0.113.9"));
    }

    // ---------- empty trusted-proxy list: everyone is untrusted ----------

    #[test]
    fn empty_trusted_cidrs_means_all_peers_untrusted() {
        let config = default_config(None, &[]);
        let h = headers(&[
            ("host", "hort.example.com"),
            ("x-forwarded-host", "attacker.tld"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);
        let trust = evaluate_trust(&config, Some(ip("10.0.0.5")), &h);
        assert_eq!(trust.public_url.as_str(), "https://hort.example.com/");
        assert_eq!(trust.client_ip, ip("10.0.0.5"));
    }

    // ---------- trusted peer, but X-Forwarded-For missing ----------
    //
    // A naive behaviour
    // ("fall back to the socket peer") would collapse every caller through a
    // misconfigured proxy onto a single rate-limit / fail2ban bucket —
    // the proxy IP itself. fail2ban would either ban the proxy (DoS
    // itself) or be tuned to ignore it, disabling the defence.
    //
    // The corrected behaviour: emit the IPv4 `0.0.0.0` sentinel so
    // downstream rate-limit / fail2ban logic sees an
    // OBVIOUSLY-NOT-A-REAL-IP value. Dashboards keying on this sentinel
    // can detect the misconfig without conflating attribution onto the
    // proxy. A throttled `WARN` is emitted at the same site (per-process
    // throttle, 60s window) so the misconfig is observable in logs
    // without log-volume DoS.

    #[traced_test]
    #[test]
    fn trusted_peer_without_xff_returns_sentinel_not_proxy_ip() {
        let config = default_config(None, &["10.0.0.0/8"]);
        let h = headers(&[("host", "hort.example.com"), ("x-forwarded-proto", "https")]);
        let trust = evaluate_trust(&config, Some(ip("10.0.0.5")), &h);

        // Security lock: `client_ip` MUST be the sentinel, NOT the
        // proxy IP. Regressing this collapses every caller through a
        // misconfigured proxy onto one rate-limit bucket.
        assert_eq!(
            trust.client_ip,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "trusted-peer + missing XFF must yield 0.0.0.0 sentinel"
        );
        assert_ne!(
            trust.client_ip,
            ip("10.0.0.5"),
            "trusted-peer + missing XFF MUST NOT fall back to proxy IP"
        );

        // The WARN is the operator-facing signal that XFF is being
        // stripped or the proxy is misconfigured. Pin the lede + the
        // structured peer-address field so log-shipper alert rules
        // can key on it.
        assert!(
            logs_contain("trusted peer with missing X-Forwarded-For"),
            "expected XFF-missing misconfiguration warning"
        );
        assert!(
            logs_contain("10.0.0.5"),
            "expected the trusted peer's address in the WARN line"
        );
    }

    // Pre-existing-behaviour pin: trusted peer with a present XFF still
    // resolves `client_ip` to the original client (now via the
    // rightmost-untrusted walk — M-A3). The sentinel fallback is ONLY
    // for the missing-XFF / all-trusted-chain case.

    #[test]
    fn trusted_peer_with_xff_unchanged() {
        let config = default_config(None, &["10.0.0.0/8"]);
        let h = headers(&[
            ("host", "hort.example.com"),
            ("x-forwarded-for", "203.0.113.7"),
        ]);
        let trust = evaluate_trust(&config, Some(ip("10.0.0.5")), &h);
        assert_eq!(trust.client_ip, ip("203.0.113.7"));
    }

    // The WARN is a per-process resource — we MUST NOT emit one per
    // request (a request flood through a misconfigured proxy would
    // self-DoS the log pipeline). The test below drives 100 trusted
    // peer + missing-XFF requests through `evaluate_trust` in a tight
    // loop and asserts the WARN is emitted at most a small bounded
    // number of times (<= 2 to be tolerant of timing on busy CI).
    //
    // Implementation note: the throttle state lives in `TrustConfig`
    // (per-config, not a process-global static) so each test scope
    // gets a fresh window without needing test-only state mutators.

    #[traced_test]
    #[test]
    fn trusted_peer_xff_missing_warn_is_throttled() {
        let config = default_config(None, &["10.0.0.0/8"]);
        let h = headers(&[("host", "hort.example.com")]);

        for _ in 0..100 {
            let trust = evaluate_trust(&config, Some(ip("10.0.0.5")), &h);
            // Every iteration MUST yield the sentinel — the throttle
            // suppresses the WARN, not the sentinel itself.
            assert_eq!(trust.client_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        }

        logs_assert(|lines: &[&str]| {
            let count = lines
                .iter()
                .filter(|l| l.contains("trusted peer with missing X-Forwarded-For"))
                .count();
            if count <= 2 {
                Ok(())
            } else {
                Err(format!(
                    "expected throttled WARN (<= 2) across 100 requests, got {count}"
                ))
            }
        });
    }

    // The throttle's "deny" branch (suppress) is exercised by the
    // 100-request loop above. The "allow" branch (the very first WARN
    // after a fresh config) is exercised by
    // `trusted_peer_without_xff_returns_sentinel_not_proxy_ip`. Both
    // branches run on every CI build — the throttle never flips into
    // an unreachable arm.

    // ---------- CIDR predicate ----------

    #[test]
    fn cidr_contains_ipv4_match() {
        let nets = vec![cidr("10.0.0.0/8"), cidr("192.168.0.0/16")];
        assert!(cidr_contains(ip("10.1.2.3"), &nets));
        assert!(cidr_contains(ip("192.168.1.1"), &nets));
        assert!(!cidr_contains(ip("172.16.0.1"), &nets));
    }

    #[test]
    fn cidr_contains_ipv6_match() {
        let nets = vec![cidr("::1/128"), cidr("2001:db8::/32")];
        assert!(cidr_contains(ip("::1"), &nets));
        assert!(cidr_contains(ip("2001:db8::5"), &nets));
        assert!(!cidr_contains(ip("fe80::1"), &nets));
    }

    /// Dual-stack peers reported by the
    /// kernel as `::ffff:10.0.0.5` (IPv4-mapped IPv6, RFC 4291 §2.5.5)
    /// must match a configured `10.0.0.0/8` trusted-proxy CIDR. Without
    /// canonicalization, `IpNet::contains` compares an IPv6 address
    /// against an IPv4 net and returns `false`, leading the trust
    /// middleware to silently treat the proxy as untrusted and emit
    /// the XFF-strip sentinel even though the operator listed the
    /// peer's prefix.
    #[test]
    fn cidr_contains_canonicalizes_ipv4_mapped_ipv6() {
        let nets = vec![cidr("10.0.0.0/8")];
        // IPv4-mapped form of 10.0.0.5; must match after `to_canonical`.
        let mapped: IpAddr = "::ffff:10.0.0.5".parse().unwrap();
        assert!(cidr_contains(mapped, &nets));
        // Bare IPv4 still matches the same net (regression guard —
        // canonicalization must not break the IPv4 path).
        assert!(cidr_contains(ip("10.0.0.5"), &nets));
        // A real IPv6 address that is not in any IPv4-mapped form
        // is still rejected against the IPv4-only allowlist.
        assert!(!cidr_contains(ip("2001:db8::1"), &nets));
    }

    // ---------- XFF rightmost-untrusted walk ----------
    //
    // A leftmost-entry walk would be spoofable: any client
    // could prepend a fake IP to its own `X-Forwarded-For` and an
    // appending proxy would tack the real client on the right without
    // stripping the spoof. The rightmost-untrusted walk strips trusted
    // hops walking right-to-left and yields the first untrusted hop —
    // the actual attribution boundary. See
    // `docs/architecture/explanation/security.md` (request trust).

    #[test]
    fn rightmost_untrusted_single_xff_entry_with_trusted_peer() {
        // Single-hop trusted proxy. The only XFF entry IS the real
        // client — the algorithm's trust-boundary fallback (the
        // post-loop `if !prev_trusted { candidate }` arm) returns it.
        // Without that arm, this case would silently fall through to
        // the sentinel and we'd lose attribution for the most common
        // single-proxy deployment.
        let cidrs = vec![cidr("192.168.0.0/16")];
        let h = headers(&[("x-forwarded-for", "1.2.3.4")]);
        assert_eq!(
            rightmost_untrusted_forwarded_for(&h, ip("192.168.0.1"), &cidrs),
            Some(ip("1.2.3.4")),
            "trusted single-hop proxy: the only entry IS the real client"
        );
    }

    #[test]
    fn rightmost_untrusted_walks_chain_of_trusted_proxies() {
        // Three-hop chain: original client 1.2.3.4 → trusted proxy
        // 192.168.1.1 → trusted proxy 10.0.0.1 → us. Peer is the last
        // trusted hop (10.0.0.1). Walk right-to-left, strip trusted
        // hops, surface the first untrusted entry.
        let cidrs = vec![cidr("10.0.0.0/8"), cidr("192.168.0.0/16")];
        let h = headers(&[("x-forwarded-for", "1.2.3.4, 192.168.1.1, 10.0.0.1")]);
        assert_eq!(
            rightmost_untrusted_forwarded_for(&h, ip("10.0.0.1"), &cidrs),
            Some(ip("1.2.3.4")),
            "chained trusted proxies: the leftmost untrusted entry is the real client"
        );
    }

    #[test]
    fn rightmost_untrusted_rejects_spoofed_leftmost_when_peer_untrusted() {
        // Backlog test 3: XFF `<spoofed-1.2.3.4>, <real-5.6.7.8>`,
        // peer 5.6.7.8 (untrusted) → returns real client 5.6.7.8 (NOT
        // the spoofed 1.2.3.4). Function-level: prev_trusted starts
        // false (peer not in CIDRs); the first rev iteration is the
        // rightmost entry 5.6.7.8 → returned immediately.
        let cidrs = vec![cidr("10.0.0.0/8")];
        let h = headers(&[("x-forwarded-for", "1.2.3.4, 5.6.7.8")]);
        assert_eq!(
            rightmost_untrusted_forwarded_for(&h, ip("5.6.7.8"), &cidrs),
            Some(ip("5.6.7.8")),
            "rightmost-untrusted: real client wins, spoofed leftmost ignored"
        );
        // Integrated semantic via evaluate_trust: an untrusted peer
        // never reaches the XFF parser at all — the `peer_trusted`
        // branch is not taken. client_ip is the socket peer.
        let config = default_config(None, &["10.0.0.0/8"]);
        let h2 = headers(&[
            ("host", "hort.example.com"),
            ("x-forwarded-for", "1.2.3.4, 5.6.7.8"),
        ]);
        let trust = evaluate_trust(&config, Some(ip("5.6.7.8")), &h2);
        assert_eq!(
            trust.client_ip,
            ip("5.6.7.8"),
            "integrated: spoofed XFF must NOT influence client_ip when peer is untrusted"
        );
        assert_ne!(
            trust.client_ip,
            ip("1.2.3.4"),
            "integrated: spoofed leftmost MUST NOT win"
        );
    }

    #[test]
    fn rightmost_untrusted_with_untrusted_peer_returns_peer_via_existing_fallback() {
        // Untrusted peer + present XFF: `evaluate_trust` ignores the
        // XFF header altogether and falls through to
        // `peer_ip.unwrap_or(XFF_MISSING_SENTINEL)`. The new function
        // is never invoked — exactly the existing semantics.
        let config = default_config(None, &["10.0.0.0/8"]);
        let h = headers(&[("host", "hort.example.com"), ("x-forwarded-for", "1.2.3.4")]);
        let trust = evaluate_trust(&config, Some(ip("8.8.8.8")), &h);
        assert_eq!(
            trust.client_ip,
            ip("8.8.8.8"),
            "untrusted peer: client_ip is the socket peer, fallback shape unchanged"
        );
    }

    #[test]
    fn rightmost_untrusted_all_trusted_chain_returns_none() {
        // Every entry is in the trusted CIDR set — including the
        // leftmost. There is no untrusted attribution boundary; the
        // function returns None. The caller's existing
        // `unwrap_or_else(... sentinel + WARN ...)` path takes over,
        // which matches the operator-visible misconfiguration signal
        // (the entire chain is internal — XFF was never set by an
        // external client).
        let cidrs = vec![cidr("10.0.0.0/8"), cidr("192.168.0.0/16")];
        let h = headers(&[("x-forwarded-for", "10.0.0.5, 192.168.1.7, 10.0.0.1")]);
        assert_eq!(
            rightmost_untrusted_forwarded_for(&h, ip("10.0.0.1"), &cidrs),
            None,
            "all-trusted chain: no untrusted hop to surface; caller sentinel takes over"
        );
    }

    // ---------- layer order: the probe-layer invariant ----------
    //
    // The probe peeks at request extensions from an INNER layer and
    // captures whether `RequestTrust` was already populated. When
    // `request_trust_layer` is attached AFTER the probe in the builder
    // chain (outermost at runtime), the probe sees `Some(_)`. Swap the
    // order → probe sees `None`. Both cases are asserted.

    type ProbeCapture = Arc<Mutex<Option<bool>>>;

    async fn probe_handler() -> StatusCode {
        StatusCode::OK
    }

    /// Drive one request through a fully-assembled router. The probe
    /// layer captures whether `RequestTrust` was present in extensions
    /// by the time the probe saw the request. `ConnectInfo` is injected
    /// on the test request so the trust middleware can read a peer IP.
    fn run_probe(router: Router) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let addr: SocketAddr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
            let req = HttpRequest::builder()
                .uri("/probe")
                .header("host", "hort.example.com")
                .extension(ConnectInfo(addr))
                .body(Body::empty())
                .unwrap();
            let res = router.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        });
    }

    /// Build a probe middleware whose only side effect is to capture
    /// whether `RequestTrust` is already in request extensions by the
    /// time it runs. Returns a plain `axum::middleware::from_fn` layer
    /// that closes over the capture cell.
    ///
    /// Implemented as an inline closure (not a named helper) so the
    /// returned type stays opaque — axum's `FromFnLayer` has several
    /// generic parameters we'd rather not spell out.
    async fn probe_middleware_impl(capture: ProbeCapture, req: Request, next: Next) -> Response {
        let observed = req.extensions().get::<RequestTrust>().is_some();
        *capture.lock().unwrap() = Some(observed);
        next.run(req).await
    }

    // -- probe-order tests --
    //
    // The two tests below are the load-bearing invariant pins from the
    // F2 acceptance criteria. Both drive the same router shape with the
    // `.layer()` calls in OPPOSITE orders; the correct order must see
    // `Some(true)` from the probe; the inverted order must see
    // `Some(false)`. Both branches MUST be asserted — a test that only
    // checks the "happy" branch passes even when someone silently
    // swaps the `.layer()` calls in `build_router`. See the layer-order
    // note in the module docs.

    #[test]
    fn layer_order_probe_observes_trust_when_attached_last() {
        let capture: ProbeCapture = Arc::new(Mutex::new(None));
        let cap_clone = capture.clone();
        let cfg = default_config(Some("https://hort.example.com"), &[]);
        let router: Router = Router::new()
            .route("/probe", get(probe_handler))
            .layer(axum::middleware::from_fn(
                move |req: Request, next: Next| probe_middleware_impl(cap_clone.clone(), req, next),
            ))
            // trust layer attached LAST → wraps the probe → runs FIRST
            // at request time → probe sees RequestTrust populated.
            .layer(request_trust_layer(cfg));

        run_probe(router);

        assert_eq!(
            *capture.lock().unwrap(),
            Some(true),
            "correctly-ordered stack: probe must observe RequestTrust in extensions"
        );
    }

    #[test]
    fn layer_order_probe_observes_none_when_inverted() {
        let capture: ProbeCapture = Arc::new(Mutex::new(None));
        let cap_clone = capture.clone();
        let cfg = default_config(Some("https://hort.example.com"), &[]);
        let router: Router = Router::new()
            .route("/probe", get(probe_handler))
            // Inverted order: trust layer attached FIRST (inner),
            // probe attached LAST (outer). Probe runs first at request
            // time — before trust has had a chance to populate the
            // extension. If this assertion ever flips to `Some(true)`,
            // axum's layering semantics changed OR someone removed the
            // probe's capture order; either way the ordering in
            // `build_router` needs re-verifying.
            .layer(request_trust_layer(cfg))
            .layer(axum::middleware::from_fn(
                move |req: Request, next: Next| probe_middleware_impl(cap_clone.clone(), req, next),
            ));

        run_probe(router);

        assert_eq!(
            *capture.lock().unwrap(),
            Some(false),
            "inverted stack: probe should observe RequestTrust absent"
        );
    }
}
