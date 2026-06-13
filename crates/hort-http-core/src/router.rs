//! Router-assembly primitives shared by every inbound HTTP crate.
//!
//! Per-format crates (`hort-http-cargo`, `hort-http-npm`, `hort-http-pypi`,
//! `hort-http-oci`) build a per-format route tree and hand it to
//! [`wrap_with_middleware`] via the composition root (`hort-server`). This
//! module owns the cross-cutting concerns: optional `/metrics` mount,
//! the six-layer middleware chain, and the method-based auth dispatch
//! helper. The top-level assembly (nesting every per-format tree) lives
//! in `hort-server::http::build_router_with_oci_config`.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::Router;

use crate::context::AppContext;
use crate::handlers::metrics;
use crate::middleware;

/// Wrap a per-format route tree with the full middleware chain.
///
/// `inner` is the format-agnostic nested router (admin + each per-format
/// crate's routes). `include_metrics` toggles the `/metrics` scrape mount
/// on the main listener — production deployments usually set this to
/// `false` and expose `/metrics` on a dedicated admin listener so
/// network policy can keep scrape traffic off the public surface.
///
/// `metrics_require_auth` gates whether
/// the `/metrics` route mounted on the main listener (when
/// `include_metrics=true`) is treated as an authenticated path. When
/// `true` (the production default), the auth dispatch routes
/// `GET /metrics` through [`require_principal`] rather than
/// [`extract_optional_principal`] so anonymous scrapes return 401.
/// When `false` (legacy/operator escape hatch via
/// `HORT_METRICS_REQUIRE_AUTH=false`), `/metrics` keeps the read-path
/// optional-principal treatment and accepts anonymous scrapes.
///
/// The six layers are attached in the exact order that preserves the
/// pre-split runtime behaviour. Tower wraps outward: the layer attached
/// LAST is the OUTERMOST at runtime and runs FIRST on the request path.
/// The `layer_order_probe` tests in [`middleware::trust`] assert the
/// invariants.
///
/// [`require_principal`]: crate::middleware::auth::require_principal
/// [`extract_optional_principal`]: crate::middleware::auth::extract_optional_principal
pub fn wrap_with_middleware(
    ctx: Arc<AppContext>,
    inner: Router<Arc<AppContext>>,
    include_metrics: bool,
    metrics_require_auth: bool,
) -> Router {
    let mut router = inner;

    if include_metrics {
        router = router.route("/metrics", get(metrics::render_metrics));
    }

    // Write-path / read-path carve-out (ADR 0021).
    //
    // The auth middleware is split by HTTP method:
    // - Write methods (PUT / POST / DELETE / PATCH) go through
    //   `require_principal` — a missing / invalid bearer token is a 401.
    // - Read methods (GET / HEAD / OPTIONS) go through
    //   `extract_optional_principal` — the token is optional, handlers
    //   get `Option<CallerPrincipal>` in extensions for future
    //   private-repo toggles.
    //
    // The split lives in [`method_based_auth_dispatch`] (one layer wraps
    // the whole tree) rather than being expressed as two separate
    // sub-routers with different layer stacks. Splitting by sub-router
    // would require breaking each format's `*_routes()` builder into
    // read/write pairs and merging at the top level. That's viable but
    // churns the handler allowlist more than necessary — npm in
    // particular registers GET + PUT on the same route template
    // (`/:repo_key/:scope/:name` serves both `packument_scoped` and
    // `publish_scoped`), and router-merge with per-sub-router layers
    // stacks the layers oddly on shared route templates. A single
    // method-dispatching layer sidesteps that.
    //
    // When `AuthContext::Disabled` (no auth wired at all) we skip the
    // layer entirely — the router behaves bit-for-bit like a router
    // with no auth layer attached. Under `Enabled` (OIDC) and `BearerOnly`
    // (no-OIDC + `HORT_NATIVE_TOKENS_ENABLED=true`), the same dispatch
    // attaches so admin routes get an actual auth path.
    if ctx.auth.has_auth() {
        // Thread the metrics-auth flag
        // through to the dispatch via a small composite state. The
        // `/metrics` carve-out reads the flag to decide between
        // `require_principal` (default) and `extract_optional_principal`
        // (legacy bypass).
        let dispatch_state = AuthDispatchState {
            ctx: ctx.clone(),
            metrics_require_auth,
        };
        router = router.layer(axum::middleware::from_fn_with_state(
            dispatch_state,
            method_based_auth_dispatch,
        ));
    }

    // Per-IP rate limiting.
    //
    // Two layers, both attached HERE — AFTER (in builder order) the auth
    // dispatch, which makes them OUTER at runtime and gives them first
    // crack at each request. That ordering matters:
    //
    // - Auth rate-limit must reject a credential-stuffing flood BEFORE
    //   `require_principal` kicks off JWKS validation — otherwise the
    //   attacker still burns our IdP-facing reqwest path on every
    //   rejected token. Outer-than-auth = pre-auth enforcement.
    // - Write rate-limit must bound mutation throughput regardless of
    //   auth state (Disabled operators — e.g. local dev — still benefit).
    //   Applied globally; the layer's internal `methods` filter skips
    //   GET/HEAD/OPTIONS so reads pass through untouched.
    //
    // Both layers need `RequestTrust::client_ip`, populated by the
    // request-trust layer below. That layer is attached LAST in this chain — which
    // makes it the OUTERMOST at runtime — so by the time these two
    // read request extensions, trust is already present.
    //
    // Builder-chain order (LIFO at runtime):
    //   1. method_based_auth_dispatch  (innermost — attached first above)
    //   2. auth_rate_limit             (wraps 1)
    //   3. write_rate_limit            (wraps 2)
    //   4. http_metrics                (wraps 3)
    //   5. security_headers            (wraps 4)
    //   6. request_trust               (outermost — wraps 5)
    //
    // Auth rate-limit only attaches when the auth pipeline is wired
    // (Enabled or BearerOnly). Under `Disabled` there's no auth path
    // to protect and the layer would be pure overhead.
    if ctx.auth.has_auth() {
        router = router.layer(middleware::rate_limit::auth_rate_limit_layer(
            &ctx.rate_limit_config,
        ));
    }
    router = router.layer(middleware::rate_limit::write_rate_limit_layer(
        &ctx.rate_limit_config,
    ));

    // Request-trust layer.
    //
    // Attached LAST in the `.layer()` chain below — tower wraps outward,
    // so the final `.layer(...)` call is the OUTERMOST at runtime and
    // runs FIRST on the request path. That ordering is load-bearing:
    // every downstream consumer (auth logs, metrics, handlers, the
    // rate-limit key-extractor, `UrlResolver`)
    // reads `RequestTrust` from extensions. If this layer were attached
    // before the auth dispatch (i.e. wrapped inside it), auth would see
    // `None` when it tried to log `client_ip`. The
    // `layer_order_probe` tests in `middleware/trust.rs` assert both
    // orderings so swapping these calls fails CI.
    //
    // Per-request deadline.
    //
    // The deadline is NOT attached here. Tower wraps outward — a global
    // `Router::layer(TimeoutLayer)` at this point would wrap every
    // route, including the OCI blob upload subtree, defeating the
    // per-route ceiling that lets multi-GB pushes complete. Instead,
    // each per-format subtree owns its own timeout layer:
    //
    //   - `hort-http-oci::oci_routes_with_config` applies its long
    //     ceiling to the upload sub-router and the global default to
    //     the read/admin sub-router.
    //   - The composition root in `hort-server::http` applies the global
    //     default to the merged non-OCI subtrees (cargo / npm / pypi /
    //     admin) before merging with OCI.
    //
    // `Router::merge` preserves per-router layer stacks (verified by
    // `hort-server/tests/http_timeouts.rs`). See
    // `docs/operator/http-transport-timeouts.md` for the operator-
    // facing summary.

    // Concurrency limit + load shed + per-IP cap.
    //
    // Both layers are attached HERE — between the rate-limit layers
    // (which run inner of these at runtime) and the metrics layer
    // (which runs outer of these at runtime). Why this position:
    //
    // - The shed layers must wrap the rate-limit layers and the auth
    //   dispatch so that a flood beyond the workspace-wide cap is
    //   rejected BEFORE we burn cycles on token-bucket bookkeeping or
    //   IdP JWKS validation. tower-governor counts requests, not
    //   in-flight work — these layers close the long-running-upload
    //   pinning vector that bypasses the per-minute buckets.
    // - The shed layers must run INSIDE the metrics + security-headers
    //   layers so the 503 it emits picks up the standard hardening
    //   headers and the metrics middleware can count it as a response
    //   (under `status="503"`). Order matters here: metrics outer means
    //   sheds tick `hort_http_responses_total{status="503"}`; the dedicated
    //   shed metric `hort_http_load_shed_total{result, path}` is emitted
    //   from inside the shed middleware directly.
    //
    // Per-IP layer is attached FIRST in the builder chain (so it is
    // INNER at runtime). The global cap fires first under a
    // distributed flood; the per-IP cap binds when a single attacker
    // pins all their slots regardless of global headroom. Either order
    // is correct — the chosen ordering surfaces the global metric
    // first when both would trip on the same request, mirroring the
    // "wrap the cheaper check around the more expensive one" principle.
    let concurrency_state =
        middleware::load_shed::ConcurrencyLimitState::new(ctx.concurrency_limit_config);
    router = router
        .layer(axum::middleware::from_fn_with_state(
            concurrency_state.clone(),
            middleware::load_shed::per_ip_load_shed_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            concurrency_state,
            middleware::load_shed::global_load_shed_middleware,
        ));

    // Security-response-headers layer.
    //
    // Sits between `http_metrics_middleware` and `request_trust_layer`
    // in the builder chain. That places it OUTSIDE the metrics layer
    // at runtime — so every response emitted by any inner layer
    // (including 401s from the auth dispatch, 404s from unmatched
    // routes, and the Prometheus scrape itself) passes through on the
    // way out and picks up the hardening headers. Order does not
    // affect correctness of the header injection (this middleware only
    // mutates the response on the way out; it never reads trust or
    // emits metrics), but placing it outside metrics keeps metrics'
    // view of the response free of our injected headers and keeps
    // trust as the outermost primitive, as the trust design requires.
    router
        .layer(axum::middleware::from_fn(
            middleware::metrics::http_metrics_middleware,
        ))
        .layer(axum::middleware::from_fn(
            middleware::security_headers::security_headers_middleware,
        ))
        .layer(middleware::trust::request_trust_layer(
            ctx.trust_config.clone(),
        ))
        .with_state(ctx)
}

/// Composite middleware state for [`method_based_auth_dispatch`].
///
/// `Clone` is required by axum's `from_fn_with_state` (the state is
/// cloned per request); both fields are pointer-cheap (`Arc` clone +
/// `bool` copy).
#[derive(Clone)]
struct AuthDispatchState {
    ctx: Arc<AppContext>,
    /// When `true` (production default),
    /// `GET /metrics` on the main listener routes through
    /// `require_principal` rather than `extract_optional_principal`.
    metrics_require_auth: bool,
}

/// Route an incoming request to either `require_principal` (write methods)
/// or `extract_optional_principal` (read methods) based on the HTTP method.
///
/// Only attached when [`AuthContext::Enabled`]; otherwise both downstream
/// middleware functions assume the context supplies a live
/// [`hort_app::use_cases::authenticate_use_case::AuthenticateUseCase`].
///
/// Methods not enumerated in either branch (`CONNECT`, `TRACE`, custom
/// methods) fall through to `require_principal` — conservative default
/// since those methods do not exist in the v2 surface. If a future item
/// introduces genuine read-only support for `OPTIONS` (CORS preflight), it
/// already lives in the optional branch.
///
/// `/metrics` is a per-path carve-out:
/// regardless of method (it is always GET in practice), the request
/// goes through `require_principal` when
/// `state.metrics_require_auth == true`. This closes the dev-mode
/// (single-listener) anonymous-scrape vector without changing the
/// rest of the GET-read posture.
async fn method_based_auth_dispatch(
    State(state): State<AuthDispatchState>,
    req: Request,
    next: Next,
) -> Response {
    // The OCI subtree owns its own auth story
    // via `hort_http_oci::middleware::oci_auth::oci_bearer_auth`.
    // Short-circuit here so we don't run the IdP-bearer/Basic-fallback
    // pipeline on `/v2/*` requests — the OCI bearer middleware
    // attached on the OCI router will fire instead, validating the
    // hort-server-minted JWT from `/v2/token`.
    if is_oci_path(req.uri().path()) {
        return next.run(req).await;
    }
    // Anonymous endpoints (ADR 0013). RFC 8693 token-exchange
    // (`POST /api/v1/auth/exchange`) carries the credential as the
    // `subject_token` in the form body, NOT as a Bearer header. The
    // handler validates the JWT via `AuthenticateUseCase::authenticate_bearer`
    // itself; running the bearer-required middleware in front would
    // 401 every legitimate exchange request with "missing Authorization
    // header" before the handler ever sees the body. Skip the auth
    // pipeline for this exact path. Same posture as the OCI carve-out
    // above — the handler owns auth.
    if is_anonymous_path(req.uri().path()) {
        return next.run(req).await;
    }
    // `/metrics` carve-out. Always
    // require_principal under the default; falls through to the
    // method-based branches when `metrics_require_auth=false` so
    // the legacy anonymous-scrape escape hatch still works.
    if state.metrics_require_auth && req.uri().path() == "/metrics" {
        return middleware::auth::require_principal(State(state.ctx), req, next).await;
    }
    match *req.method() {
        Method::GET | Method::HEAD | Method::OPTIONS => {
            middleware::auth::extract_optional_principal(State(state.ctx), req, next).await
        }
        _ => middleware::auth::require_principal(State(state.ctx), req, next).await,
    }
}

/// Identical predicate to `crate::middleware::auth::is_oci_path` —
/// duplicated here because that one takes a `Request` reference
/// while we need to inspect the path string-only without forcing
/// callers to construct a `Request`.
fn is_oci_path(path: &str) -> bool {
    path == "/v2" || path == "/v2/" || path.starts_with("/v2/")
}

/// Paths that bypass the bearer-required / optional-principal auth
/// dispatch entirely. The handler at the path is responsible for any
/// auth validation it needs.
///
/// Currently:
/// - `/api/v1/auth/exchange` (ADR 0013) — RFC 8693 token-exchange. The
///   credential is `subject_token` in the form body; the handler
///   validates via `AuthenticateUseCase::authenticate_bearer`.
fn is_anonymous_path(path: &str) -> bool {
    path == "/api/v1/auth/exchange"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_anonymous_path_matches_exchange() {
        assert!(is_anonymous_path("/api/v1/auth/exchange"));
    }

    #[test]
    fn is_anonymous_path_rejects_neighbouring_routes() {
        // Native-token endpoints are NOT anonymous.
        assert!(!is_anonymous_path("/api/v1/users/me/tokens"));
        // whoami is NOT anonymous (uses extract_optional_principal
        // via the GET branch but doesn't bypass the dispatch).
        assert!(!is_anonymous_path("/api/v1/auth/whoami"));
        // Trailing-slash variant is NOT matched — axum normalises route
        // paths and `/api/v1/auth/exchange/` would 404 anyway.
        assert!(!is_anonymous_path("/api/v1/auth/exchange/"));
        // Sub-paths are NOT matched.
        assert!(!is_anonymous_path("/api/v1/auth/exchange/foo"));
        // Exchange path under a different (legacy) prefix is NOT matched —
        // the removed /api/v2 surface must never be anonymous.
        assert!(!is_anonymous_path("/api/v2/auth/exchange"));
    }

    #[test]
    fn is_anonymous_path_rejects_unrelated_paths() {
        assert!(!is_anonymous_path("/"));
        assert!(!is_anonymous_path("/v2/"));
        assert!(!is_anonymous_path("/metrics"));
        assert!(!is_anonymous_path("/.well-known/hort-client-config"));
    }
}
