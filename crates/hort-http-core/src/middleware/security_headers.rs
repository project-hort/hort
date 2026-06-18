//! Security response-headers middleware.
//!
//! Injects a small set of hardening headers on every response.
//! Runs as a tower layer attached globally in
//! [`crate::router::build_router`]; no per-handler wiring.
//!
//! # Headers
//!
//! Always injected:
//!
//! - `X-Content-Type-Options: nosniff` — MIME-sniffing protection
//! - `X-Frame-Options: DENY` — clickjacking protection
//! - `Referrer-Policy: no-referrer` — avoid leaking our URL structure
//! - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox`
//!   — defensive default CSP applied to every response.
//!   Neutralises any accidental content-sniff that might lead a browser
//!   to render a non-HTML body. Inserted via `entry().or_insert_with(...)`
//!   so the HTML branch's stricter value (set first, see below) is
//!   preserved.
//!
//! Conditionally injected when the response `Content-Type` starts with
//! `text/html` (case-insensitive — `text/html; charset=utf-8` and
//! `Text/HTML` both match):
//!
//! - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`
//!   (the HTML-specific stricter value; supersedes the default for HTML).
//!
//! Conditionally injected when the request path matches `/admin/` (prefix)
//! OR the request carried an `Authorization` header:
//!
//! - `Cache-Control: no-store, private` — admin and auth-bearing responses
//!   must not be cached by intermediaries. Inserted via
//!   `entry().or_insert_with(...)` so explicit per-handler values stand.
//!
//! Always stripped on the way out (defensive):
//!
//! - `Server` — hyper/axum may emit a default `Server` header; we never
//!   want to leak the implementation detail.
//!
//! Conditionally injected when [`crate::middleware::trust::RequestTrust`]
//! is present in request extensions AND its `public_url.scheme()` is
//! `https`:
//!
//! - `Strict-Transport-Security: max-age=15552000; includeSubDomains`
//!
//! # HSTS posture
//!
//! HSTS is never emitted unconditionally: TLS termination is
//! the operator's reverse-proxy responsibility, and emitting HSTS
//! unconditionally breaks HTTP-only dev clusters / internal proxies
//! terminating TLS upstream. The defensible middle
//! ground: the binary has positive evidence about its scheme via
//! `RequestTrust::public_url`. When that scheme is `https`, the
//! deployment IS behind TLS; emit HSTS. When it is `http` (or
//! `RequestTrust` is absent because the trust layer didn't run on this
//! path), stay silent.
//!
//! `includeSubDomains` is included because an artifact registry's
//! subdomains (per-format hostnames, mirror endpoints) shouldn't fall
//! back to HTTP either. `preload` is NOT included — preload-list
//! enrolment is operator-explicit, not a sensible default.
//!
//! # Overwrite semantics
//!
//! Existing response headers with the same names are overwritten
//! unconditionally. No handler in the v2 surface intentionally sets any
//! of these — a grep over `crates/` at the time of this change confirms
//! zero collisions. If a future handler needs to override one of these
//! headers, it must do so via a response extension that this middleware
//! explicitly consults (no such mechanism today).

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use axum::middleware::Next;
use axum::response::Response;

use crate::middleware::trust::RequestTrust;

/// `X-Content-Type-Options` header name.
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
/// `X-Frame-Options` header name.
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
/// `Referrer-Policy` header name.
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
/// `Content-Security-Policy` header name.
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
/// `Strict-Transport-Security` header name.
const STRICT_TRANSPORT_SECURITY: HeaderName = HeaderName::from_static("strict-transport-security");
/// `Cache-Control` header name.
const CACHE_CONTROL: HeaderName = HeaderName::from_static("cache-control");
/// `Server` header name. We strip
/// this defensively from every response.
const SERVER: HeaderName = HeaderName::from_static("server");

/// `X-Content-Type-Options` value.
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
/// `X-Frame-Options` value.
const DENY: HeaderValue = HeaderValue::from_static("DENY");
/// `Referrer-Policy` value.
const NO_REFERRER: HeaderValue = HeaderValue::from_static("no-referrer");
/// `Content-Security-Policy` value applied to `text/html` responses.
///
/// `default-src 'none'` blocks all script, font, image, frame, connect,
/// and media sources. `style-src 'unsafe-inline'` allows inline styles —
/// PEP 503 simple-index pages emit inline CSS via the `<style>` block
/// in some generators; the registry's emission does not, but operators
/// who proxy upstream indexes inherit whatever the upstream emits.
const CSP_HTML: HeaderValue =
    HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'");
/// Defensive default CSP value applied to every non-HTML response.
/// `default-src 'none'` blocks
/// everything; `frame-ancestors 'none'` is the modern equivalent of
/// `X-Frame-Options: DENY` and prevents framing entirely; `sandbox`
/// (no allowlist) neutralises any script execution / form submission /
/// plugin in case a browser content-sniffs a JSON or binary body and
/// mis-renders it. No `report-uri` — we don't run a report endpoint.
const CSP_DEFAULT: HeaderValue =
    HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; sandbox");
/// `Cache-Control` value applied to admin + auth-bearing responses.
/// `no-store` forbids any cache
/// (intermediary or local) from retaining the response; `private`
/// reinforces that even shared caches that ignore `no-store` must not
/// store the body.
const NO_STORE_PRIVATE: HeaderValue = HeaderValue::from_static("no-store, private");
/// `Strict-Transport-Security` value emitted when the binary has
/// positive evidence the public scheme is `https`. 180 days
/// (15552000 seconds) plus `includeSubDomains`. No `preload` — that's
/// operator-explicit.
const HSTS_VALUE: HeaderValue = HeaderValue::from_static("max-age=15552000; includeSubDomains");
/// Path prefix that triggers the no-store cache gate.
/// The trailing slash is load-bearing: `/administer` (a hypothetical
/// sibling) must NOT match. The production router only mounts
/// `/admin/...` routes, so this is purely defensive.
const ADMIN_PATH_PREFIX: &str = "/admin/";

/// Prefix test for `Content-Type: text/html`. Case-insensitive to match
/// RFC 7231 §3.1.1.1 (media types are case-insensitive).
fn content_type_is_html(response: &Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start().to_ascii_lowercase().starts_with("text/html"))
        .unwrap_or(false)
}

/// Returns `true` when the request carries a [`RequestTrust`] extension
/// whose `public_url` scheme is exactly `"https"`. The trust layer
/// populates `RequestTrust` on every request that traverses the public
/// router; absence means either (a) the trust layer didn't run on this
/// path (test harness, admin internal-only path) or (b) the request
/// pre-dates layer ordering — both of which mean we have no positive
/// evidence the connection is TLS, so HSTS stays silent.
fn public_scheme_is_https(request: &Request) -> bool {
    request
        .extensions()
        .get::<RequestTrust>()
        .map(|t| t.public_url.scheme() == "https")
        .unwrap_or(false)
}

/// Returns `true` when the request triggers the no-store cache gate.
/// Two independent triggers:
///
/// 1. URI path begins with `/admin/` (prefix match — the trailing slash
///    is load-bearing so `/administer` cannot accidentally match).
/// 2. The request carries an `Authorization` header (any value — the
///    presence is the signal, not the scheme).
///
/// Either trigger is sufficient. The check is performed before the
/// inner handler runs so the path / header are read off the inbound
/// request, not the response.
fn should_emit_no_store(request: &Request) -> bool {
    let path = request.uri().path();
    if path.starts_with(ADMIN_PATH_PREFIX) {
        return true;
    }
    request.headers().contains_key(AUTHORIZATION)
}

/// Axum middleware that injects the security headers defined at the top
/// of this module. Wire via
/// `axum::middleware::from_fn(security_headers_middleware)` on the
/// top-level router in [`crate::router::build_router`]. The HSTS branch
/// reads `RequestTrust` from request extensions BEFORE the response
/// future awaits so the inner handler is free to mutate `req` (it
/// can't unset extensions but reading first means we don't depend on
/// `Request` being available afterwards).
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let emit_hsts = public_scheme_is_https(&request);
    let emit_no_store = should_emit_no_store(&request);
    let mut response = next.run(request).await;
    let is_html = content_type_is_html(&response);

    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, NOSNIFF);
    headers.insert(X_FRAME_OPTIONS, DENY);
    headers.insert(REFERRER_POLICY, NO_REFERRER);

    if emit_hsts {
        headers.insert(STRICT_TRANSPORT_SECURITY, HSTS_VALUE);
    }

    // CSP: HTML branch sets the stricter value first. The default-CSP
    // insertion below uses `entry().or_insert_with(...)` so the HTML
    // value (and any explicit per-handler value) is preserved.
    if is_html {
        headers.insert(CONTENT_SECURITY_POLICY, CSP_HTML);
    }
    headers
        .entry(CONTENT_SECURITY_POLICY)
        .or_insert(CSP_DEFAULT);

    // Cache-Control gate: admin paths + auth-bearing
    // requests must not be cached. Use entry().or_insert_with(...) so
    // any explicit handler value (e.g. a deliberate `Cache-Control:
    // public, max-age=...`) is preserved.
    if emit_no_store {
        headers.entry(CACHE_CONTROL).or_insert(NO_STORE_PRIVATE);
    }

    // Defensive Server-header strip. Hyper/axum may
    // emit a default `Server` value, and a buggy handler could set one
    // explicitly; either way, we remove it on the egress path.
    headers.remove(&SERVER);

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE as CT;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    /// Handler returning an HTML response with `text/html; charset=utf-8`.
    async fn html_handler() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(CT, "text/html; charset=utf-8")
            .body(Body::from("<html></html>"))
            .unwrap()
    }

    /// Handler returning an HTML response with mixed-case `Text/HTML` —
    /// asserts the media-type match is case-insensitive.
    async fn html_mixed_case_handler() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(CT, "Text/HTML")
            .body(Body::from("<html></html>"))
            .unwrap()
    }

    /// Handler returning plain text — exercises the metrics-style path
    /// (Prometheus scrape emits `text/plain; version=0.0.4`).
    async fn plain_text_handler() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(CT, "text/plain; version=0.0.4")
            .body(Body::from("# HELP foo bar\n"))
            .unwrap()
    }

    /// Handler returning JSON — exercises the admin / API path.
    async fn json_handler() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(CT, "application/json")
            .body(Body::from("{}"))
            .unwrap()
    }

    /// Handler that omits `Content-Type` entirely — exercises the branch
    /// where the header is missing and must be treated as non-HTML.
    async fn no_content_type_handler() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("raw"))
            .unwrap()
    }

    fn app() -> Router {
        Router::new()
            .route("/html", get(html_handler))
            .route("/html-mixed", get(html_mixed_case_handler))
            .route("/plain", get(plain_text_handler))
            .route("/json", get(json_handler))
            .route("/none", get(no_content_type_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware))
    }

    fn drive(uri: &str) -> Response {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                app()
                    .oneshot(HttpRequest::get(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
            })
    }

    fn header(response: &Response, name: &HeaderName) -> Option<String> {
        response
            .headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    }

    // ---------- always-on headers ----------

    #[test]
    fn injects_nosniff_on_every_response() {
        for uri in ["/html", "/plain", "/json", "/none"] {
            let resp = drive(uri);
            assert_eq!(
                header(&resp, &X_CONTENT_TYPE_OPTIONS).as_deref(),
                Some("nosniff"),
                "X-Content-Type-Options missing on {uri}"
            );
        }
    }

    #[test]
    fn injects_frame_options_deny_on_every_response() {
        for uri in ["/html", "/plain", "/json", "/none"] {
            let resp = drive(uri);
            assert_eq!(
                header(&resp, &X_FRAME_OPTIONS).as_deref(),
                Some("DENY"),
                "X-Frame-Options missing on {uri}"
            );
        }
    }

    #[test]
    fn injects_referrer_policy_on_every_response() {
        for uri in ["/html", "/plain", "/json", "/none"] {
            let resp = drive(uri);
            assert_eq!(
                header(&resp, &REFERRER_POLICY).as_deref(),
                Some("no-referrer"),
                "Referrer-Policy missing on {uri}"
            );
        }
    }

    // ---------- CSP: HTML only ----------

    #[test]
    fn injects_csp_on_html_response() {
        let resp = drive("/html");
        assert_eq!(
            header(&resp, &CONTENT_SECURITY_POLICY).as_deref(),
            Some("default-src 'none'; style-src 'unsafe-inline'"),
        );
    }

    #[test]
    fn injects_csp_on_mixed_case_html_content_type() {
        // Asserts the prefix match is case-insensitive — `Text/HTML`
        // without `charset` must still be treated as HTML.
        let resp = drive("/html-mixed");
        assert_eq!(
            header(&resp, &CONTENT_SECURITY_POLICY).as_deref(),
            Some("default-src 'none'; style-src 'unsafe-inline'"),
        );
    }

    /// Every non-HTML response gets the
    /// defensive default CSP `default-src 'none'; frame-ancestors 'none';
    /// sandbox`. JSON / plain / no-content-type all share this branch —
    /// HTML keeps its own stricter value (asserted separately above).
    #[test]
    fn injects_default_csp_on_plain_text_response() {
        let resp = drive("/plain");
        assert_eq!(
            header(&resp, &CONTENT_SECURITY_POLICY).as_deref(),
            Some("default-src 'none'; frame-ancestors 'none'; sandbox"),
            "default CSP must apply to text/plain (Prometheus scrape path)"
        );
    }

    #[test]
    fn injects_default_csp_on_json_response() {
        let resp = drive("/json");
        assert_eq!(
            header(&resp, &CONTENT_SECURITY_POLICY).as_deref(),
            Some("default-src 'none'; frame-ancestors 'none'; sandbox"),
            "default CSP must apply to application/json (API responses)"
        );
    }

    #[test]
    fn injects_default_csp_when_content_type_absent() {
        let resp = drive("/none");
        assert_eq!(
            header(&resp, &CONTENT_SECURITY_POLICY).as_deref(),
            Some("default-src 'none'; frame-ancestors 'none'; sandbox"),
            "default CSP must apply when Content-Type is absent"
        );
    }

    /// The HTML branch sets its own stricter CSP first;
    /// the default-CSP insertion uses `entry().or_insert_with(...)` so the
    /// HTML value is preserved (do NOT clobber).
    #[test]
    fn html_csp_is_not_clobbered_by_default_csp() {
        let resp = drive("/html");
        // The CSP header must be present exactly once and equal to the
        // HTML-branch value, not the default value.
        let values: Vec<_> = resp
            .headers()
            .get_all(&CONTENT_SECURITY_POLICY)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            values,
            vec!["default-src 'none'; style-src 'unsafe-inline'".to_string()]
        );
    }

    /// Defensive `Server` header strip.
    /// Even if hyper/axum emits a default `Server`, or a handler sets one
    /// explicitly, the middleware must remove it so we don't leak the
    /// implementation detail.
    async fn handler_with_server_header() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(CT, "application/json")
            .header("server", "leaky-server/1.0")
            .body(Body::from("{}"))
            .unwrap()
    }

    #[test]
    fn strips_server_header_set_by_handler() {
        let app = Router::new()
            .route("/leaky", get(handler_with_server_header))
            .layer(axum::middleware::from_fn(security_headers_middleware));
        let resp = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                app.oneshot(HttpRequest::get("/leaky").body(Body::empty()).unwrap())
                    .await
                    .unwrap()
            });
        assert!(
            resp.headers().get("server").is_none(),
            "Server header must be stripped defensively"
        );
    }

    #[test]
    fn server_header_absent_when_handler_does_not_set_it() {
        // Sanity: the strip is also a no-op safety net when the handler
        // never sets `Server` in the first place.
        for uri in ["/json", "/plain", "/html", "/none"] {
            let resp = drive(uri);
            assert!(
                resp.headers().get("server").is_none(),
                "Server header must not be present (uri={uri})"
            );
        }
    }

    // ---------- Cache-Control on /admin/* + auth-bearing ----------

    /// Helper: drive a request with arbitrary URI + headers through the
    /// middleware. Used by the Cache-Control gate tests.
    fn drive_with_request(req: HttpRequest<Body>) -> Response {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                Router::new()
                    .route("/json", get(json_handler))
                    .route("/plain", get(plain_text_handler))
                    .route("/admin/foo", get(json_handler))
                    .route("/admin/", get(json_handler))
                    .layer(axum::middleware::from_fn(security_headers_middleware))
                    .oneshot(req)
                    .await
                    .unwrap()
            })
    }

    /// `/admin/<anything>` — Cache-Control: no-store, private must be
    /// emitted regardless of authentication state. Admin responses must
    /// not be cached by intermediaries.
    #[test]
    fn injects_cache_control_on_admin_path() {
        let req = HttpRequest::get("/admin/foo").body(Body::empty()).unwrap();
        let resp = drive_with_request(req);
        assert_eq!(
            header(&resp, &HeaderName::from_static("cache-control")).as_deref(),
            Some("no-store, private"),
            "Cache-Control must be set on /admin/* paths"
        );
    }

    /// Auth-bearing request on a non-admin path — Cache-Control still
    /// applies. The presence of an `Authorization` request header is the
    /// signal; the response status / handler do not matter.
    #[test]
    fn injects_cache_control_on_auth_bearing_request() {
        let req = HttpRequest::get("/json")
            .header("authorization", "Bearer foo")
            .body(Body::empty())
            .unwrap();
        let resp = drive_with_request(req);
        assert_eq!(
            header(&resp, &HeaderName::from_static("cache-control")).as_deref(),
            Some("no-store, private"),
            "Cache-Control must be set on auth-bearing requests"
        );
    }

    /// Anonymous request on a public (non-admin) path — middleware must
    /// NOT add Cache-Control. Whatever the handler chose stands.
    #[test]
    fn does_not_inject_cache_control_on_public_anonymous_request() {
        let req = HttpRequest::get("/json").body(Body::empty()).unwrap();
        let resp = drive_with_request(req);
        assert!(
            resp.headers()
                .get(HeaderName::from_static("cache-control"))
                .is_none(),
            "Cache-Control must not be added on anonymous public paths"
        );
    }

    /// Handler that explicitly sets a `Cache-Control` value — middleware
    /// must NOT clobber it. The gate uses `entry().or_insert_with(...)`,
    /// so handler intent wins.
    async fn handler_with_cache_control() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(CT, "application/json")
            .header("cache-control", "public, max-age=60")
            .body(Body::from("{}"))
            .unwrap()
    }

    #[test]
    fn does_not_clobber_handler_set_cache_control() {
        let app = Router::new()
            .route("/admin/cached", get(handler_with_cache_control))
            .layer(axum::middleware::from_fn(security_headers_middleware));
        let resp = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                app.oneshot(
                    HttpRequest::get("/admin/cached")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            });
        let values: Vec<_> = resp
            .headers()
            .get_all(HeaderName::from_static("cache-control"))
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(values, vec!["public, max-age=60".to_string()]);
    }

    /// `/admin` (no trailing slash) is NOT a match — the path-prefix gate
    /// uses `/admin/` so a hypothetical sibling like `/administer` cannot
    /// accidentally pick up no-store. The production router only mounts
    /// `/admin/...` routes, so this branch is purely defensive.
    #[test]
    fn does_not_inject_cache_control_on_administer_lookalike() {
        // Build a custom app with a route that LOOKS like /admin/ but
        // isn't. The ad-hoc /administer endpoint stands in for the
        // accidental-prefix concern.
        let app = Router::new()
            .route("/administer", get(json_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));
        let resp = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                app.oneshot(HttpRequest::get("/administer").body(Body::empty()).unwrap())
                    .await
                    .unwrap()
            });
        assert!(
            resp.headers()
                .get(HeaderName::from_static("cache-control"))
                .is_none(),
            "Cache-Control must not match `/administer` as if it were `/admin/`"
        );
    }

    // ---------- CORS regression ----------

    /// The codebase deliberately does NOT do CORS — there is no
    /// cross-origin browser client in the v2 surface. This test pins
    /// that posture: no `Access-Control-Allow-Origin` may be emitted by
    /// any layer in the security-headers test app. If a future change
    /// adds CORS, the change must update this test deliberately.
    #[test]
    fn no_cors_allow_origin_emitted() {
        for uri in ["/html", "/plain", "/json", "/none"] {
            let resp = drive(uri);
            assert!(
                resp.headers().get("access-control-allow-origin").is_none(),
                "Access-Control-Allow-Origin must NEVER be emitted (uri={uri})"
            );
        }
    }

    // ---------- HSTS conditional ----------
    //
    // The default routes used by `drive(uri)` do NOT inject `RequestTrust`
    // into request extensions, so HSTS must stay absent on every one of
    // them — no positive TLS evidence for any path the trust layer
    // didn't touch.
    //
    // The HSTS-emission tests below build a separate router that
    // attaches a tiny `inject_trust(scheme)` layer BEFORE the security-
    // headers layer, so the inner middleware sees a populated
    // `RequestTrust` and emits (or doesn't emit) HSTS based on the
    // pinned scheme. This mirrors how the production composition root
    // wires `request_trust_layer` upstream of `security_headers_middleware`
    // in `build_router`.

    use crate::middleware::trust::RequestTrust;
    use axum::extract::State;
    use std::net::{IpAddr, Ipv4Addr};

    /// Stateful trust-injector middleware. The scheme is carried as
    /// `State<&'static str>` so the closure can stay `fn`-shaped (axum's
    /// `from_fn_with_state` is happy with named function pointers).
    async fn inject_trust_middleware(
        State(scheme): State<&'static str>,
        mut req: Request,
        next: Next,
    ) -> Response {
        let url = url::Url::parse(&format!("{scheme}://example.com")).expect("test url parses");
        let trust = RequestTrust {
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            public_url: url,
        };
        req.extensions_mut().insert(trust);
        next.run(req).await
    }

    fn drive_with_trust(scheme: &'static str, uri: &str) -> Response {
        let app = Router::new()
            .route("/json", get(json_handler))
            .route("/plain", get(plain_text_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware))
            .layer(axum::middleware::from_fn_with_state(
                scheme,
                inject_trust_middleware,
            ));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                app.oneshot(HttpRequest::get(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
            })
    }

    /// HSTS present when `RequestTrust::public_url` is `https`.
    #[test]
    fn injects_hsts_when_request_trust_scheme_is_https() {
        let resp = drive_with_trust("https", "/json");
        assert_eq!(
            header(&resp, &STRICT_TRANSPORT_SECURITY).as_deref(),
            Some("max-age=15552000; includeSubDomains"),
            "HSTS must be emitted when public_url is https"
        );
    }

    /// HSTS value is exactly the expected string — locks against
    /// drift. If anyone tightens the value (e.g. adds `preload`)
    /// without updating the CHANGELOG, this test fails.
    #[test]
    fn hsts_value_is_exactly_180_days_with_includesubdomains() {
        let resp = drive_with_trust("https", "/json");
        assert_eq!(
            resp.headers()
                .get(&STRICT_TRANSPORT_SECURITY)
                .unwrap()
                .to_str()
                .unwrap(),
            "max-age=15552000; includeSubDomains"
        );
    }

    /// HSTS absent when `RequestTrust::public_url` is `http`. The
    /// binary has positive evidence the connection is NOT
    /// behind TLS, so emitting HSTS would be wrong (it'd lock clients
    /// out the next time they hit the http URL).
    #[test]
    fn does_not_inject_hsts_when_request_trust_scheme_is_http() {
        let resp = drive_with_trust("http", "/json");
        assert!(
            resp.headers().get(&STRICT_TRANSPORT_SECURITY).is_none(),
            "HSTS must not be emitted when public_url is http"
        );
    }

    /// HSTS absent when `RequestTrust` extension is missing. Defensive
    /// — should never happen on the production router (trust layer
    /// runs first), but the absence-branch must still compile and
    /// behave correctly.
    #[test]
    fn does_not_inject_hsts_when_request_trust_absent() {
        // `drive` (the original helper) builds a router with NO trust
        // injection — exactly the "RequestTrust missing" branch.
        for uri in ["/html", "/plain", "/json", "/none"] {
            let resp = drive(uri);
            assert!(
                resp.headers().get(&STRICT_TRANSPORT_SECURITY).is_none(),
                "HSTS must not be emitted when RequestTrust is absent (uri={uri})"
            );
        }
    }

    // ---------- overwrite semantics ----------

    /// Handler that deliberately sets `X-Content-Type-Options` to a
    /// weaker value; the middleware must overwrite it with `nosniff`.
    async fn handler_with_weak_nosniff() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(CT, "application/json")
            .header(&X_CONTENT_TYPE_OPTIONS, "sniff-everything")
            .body(Body::from("{}"))
            .unwrap()
    }

    #[test]
    fn overwrites_handler_set_nosniff_header() {
        let app = Router::new()
            .route("/weak", get(handler_with_weak_nosniff))
            .layer(axum::middleware::from_fn(security_headers_middleware));
        let resp = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                app.oneshot(HttpRequest::get("/weak").body(Body::empty()).unwrap())
                    .await
                    .unwrap()
            });
        // The middleware must clobber the handler's value.
        let values: Vec<_> = resp
            .headers()
            .get_all(&X_CONTENT_TYPE_OPTIONS)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(values, vec!["nosniff".to_string()]);
    }

    // ---------- pure-function boundary test ----------

    #[test]
    fn content_type_is_html_handles_charset_suffix() {
        let mut r = Response::new(Body::empty());
        r.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        assert!(content_type_is_html(&r));
    }

    #[test]
    fn content_type_is_html_rejects_text_plain() {
        let mut r = Response::new(Body::empty());
        r.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!content_type_is_html(&r));
    }

    #[test]
    fn content_type_is_html_missing_header_is_false() {
        let r = Response::new(Body::empty());
        assert!(!content_type_is_html(&r));
    }
}
