//! Shared building blocks for the OIDC JWKS-fetch path (single-issuer
//! adapter in `lib.rs` and multi-issuer adapter in `multi_issuer.rs`).
//!
//! # What lives here
//!
//! - [`build_http_client`] — the canonical `reqwest::Client` builder used
//!   by every OIDC outbound HTTP request. Centralises:
//!   - extra-CA-bundle layering (ADR 0010),
//!   - redirect cap of 3 hops (security.md §JWKS fetch hardening),
//!   - per-client timeout (security.md §JWKS fetch hardening),
//!   - TLS version pin: TLS 1.3 preferred, TLS 1.2 accepted
//!     (BSI TR-02102-2, ADR 0010).
//! - [`get_capped_body`] — streaming GET with a hard byte cap on the
//!   response body (closes the OOM vector where a malicious or
//!   misconfigured IdP returns an unbounded body).
//! - [`HTTP_DEFAULT_TIMEOUT`] / [`HTTP_MAX_REDIRECTS`] /
//!   [`OUTBOUND_TLS_MIN_VERSION`] / [`OUTBOUND_TLS_MAX_VERSION`] —
//!   constants shared across both adapters.
//!
//! # What does NOT live here
//!
//! `OidcProvider` keeps its own discovery+JWKS+`EventStore` audit flow
//! in `lib.rs`. The duplication budget for that path is the validation
//! pipeline, NOT the security-critical HTTP fetch — sharing the client
//! builder + body-cap helper is the minimum that ensures both adapters
//! layer the same TLS / redirect / timeout policy, which is the actual
//! rot risk. The full discovery + key-rotation audit flow stays inline
//! in `OidcProvider` because lifting it would force propagating the
//! optional `EventStore` dependency into the multi-issuer path, which
//! has no rotation audit (see ADR 0018 §machine-identity).

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use hort_config::ExtraTrustAnchors;

use crate::extra_ca::{self, ExtraCaApplyError};

/// Default per-request HTTP timeout for OIDC discovery + JWKS fetches.
///
/// 10 s matches the upstream-proxy default and is generous enough for a
/// real JWKS fetch on a healthy network. Kept here (rather than
/// re-exported from `lib.rs`) so the multi-issuer validator and the
/// single-issuer validator cannot drift on the policy without a visible
/// change to this file.
pub(crate) const HTTP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum redirect hops the OIDC fetch path will follow.
///
/// Three hops is enough for a legitimate proxy / canonicalising rewrite
/// at the IdP and tight enough to refuse a redirect-storm attack.
/// reqwest's default of 10 is too generous.
pub(crate) const HTTP_MAX_REDIRECTS: usize = 3;

/// Outbound TLS version floor — pinned to TLS 1.2 per BSI TR-02102-2 §3
/// Recommendation 1 (ADR 0010).
///
/// Without an explicit pin, reqwest defers to its implicit default
/// min-version (currently TLS 1.2 but not a guaranteed contract — a
/// future reqwest release could broaden the floor without our
/// involvement).
pub(crate) const OUTBOUND_TLS_MIN_VERSION: reqwest::tls::Version = reqwest::tls::Version::TLS_1_2;

/// Outbound TLS version ceiling — TLS 1.3.
pub(crate) const OUTBOUND_TLS_MAX_VERSION: reqwest::tls::Version = reqwest::tls::Version::TLS_1_3;

/// Build the canonical OIDC `reqwest::Client` with extra-CA, redirect cap,
/// timeout, and TLS-version pin all layered consistently. Used by both
/// the `OidcProvider` (single-issuer user-login) and the
/// `MultiIssuerJwksValidator` (workload federation).
///
/// `extra_trust_anchors`: when `Some`, every certificate in the bundle is
/// added to the underlying trust store via
/// [`extra_ca::apply_to_reqwest_builder`]. When `None`, the platform
/// default trust store is used unchanged.
///
/// # Errors
///
/// Returns [`ExtraCaApplyError`] if any certificate in
/// `extra_trust_anchors` is rejected by reqwest, or if
/// `ClientBuilder::build()` fails. Both are boot-time failures; the
/// process cannot run in a partially-trusted state.
///
/// # Anti-pattern avoidance
///
/// Built via `reqwest::Client::builder()` per the workspace-wide
/// architectural rule (no `reqwest::Client::new()` in adapters; ADR 0010).
pub(crate) fn build_http_client(
    extra_trust_anchors: Option<&ExtraTrustAnchors>,
) -> Result<reqwest::Client, ExtraCaApplyError> {
    let builder =
        extra_ca::apply_to_reqwest_builder(reqwest::Client::builder(), extra_trust_anchors)?;
    builder
        .timeout(HTTP_DEFAULT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(HTTP_MAX_REDIRECTS))
        .min_tls_version(OUTBOUND_TLS_MIN_VERSION)
        .max_tls_version(OUTBOUND_TLS_MAX_VERSION)
        .build()
        .map_err(ExtraCaApplyError::from)
}

/// Outcome of a [`get_capped_body`] call. The fine-grained taxonomy lets the
/// caller (`OidcProvider` or `MultiIssuerJwksValidator`) emit the right
/// `JwksRefreshResult` label without inspecting reqwest error strings.
#[derive(Debug)]
pub(crate) enum CappedBodyError {
    /// Transport failure (connect, DNS, TLS handshake, non-2xx HTTP, stream
    /// read error). Maps to `JwksRefreshResult::FetchFailed`.
    FetchFailed(String),
    /// Response body exceeded the configured byte cap. Maps to
    /// `JwksRefreshResult::BodyTooLarge`.
    BodyTooLarge { bytes_read: usize, cap: usize },
}

/// GET `url` and buffer the body up to `cap_bytes`.
///
/// Streams via [`reqwest::Response::bytes_stream`] and accumulates chunks
/// until either EOF or the running total exceeds the cap. `response.bytes()`
/// would buffer to EOF unconditionally — exactly the OOM vector this cap
/// closes (a malicious or misconfigured IdP returning an unbounded body).
///
/// The per-request `.timeout(HTTP_DEFAULT_TIMEOUT)` mirrors the per-client
/// timeout configured in [`build_http_client`]. Defence in depth: the
/// per-client timeout is the gate on slow-loris reads, but the per-request
/// override keeps the cap legible at the call site and survives any future
/// refactor that swaps in a shared `reqwest::Client` missing the per-client
/// timeout.
pub(crate) async fn get_capped_body(
    client: &reqwest::Client,
    url: &str,
    cap_bytes: usize,
) -> Result<Bytes, CappedBodyError> {
    let response = client
        .get(url)
        .timeout(HTTP_DEFAULT_TIMEOUT)
        .send()
        .await
        .map_err(|e| CappedBodyError::FetchFailed(format!("request failed: {e}")))?
        .error_for_status()
        .map_err(|e| CappedBodyError::FetchFailed(format!("non-2xx status: {e}")))?;

    let mut buf = BytesMut::with_capacity(cap_bytes.min(64 * 1024));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| CappedBodyError::FetchFailed(format!("stream read failed: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > cap_bytes {
            return Err(CappedBodyError::BodyTooLarge {
                bytes_read: buf.len() + chunk.len(),
                cap: cap_bytes,
            });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

/// Reason a discovery-supplied `jwks_uri` was rejected by
/// [`check_jwks_uri_bound`] before the JWKS fetch.
///
/// The variant carries no operator-supplied content beyond what the
/// adapter already logs — it exists so each caller can map the rejection
/// onto its OWN existing JWKS-fetch error classification (the
/// single-issuer `OidcProvider` path → `OidcValidationError::IdpUnavailable`;
/// the multi-issuer `MultiIssuerJwksValidator` path →
/// `FederationDenyReason::UnknownKid`). No NEW wire error / metric
/// variant is introduced — the design (§3.6) says "reject with the
/// existing JWKS-fetch error classification".
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JwksUriCheckError {
    /// `issuer_url` or `jwks_uri` failed to parse as an absolute URL, or
    /// had no host component. A discovery document whose `jwks_uri` is
    /// not a usable absolute URL is unusable regardless of the binding
    /// check.
    Unparsable(String),
    /// `jwks_uri` host does not equal the `issuer_url` host
    /// (case-insensitive). Same-host binding is the strongest,
    /// lowest-false-positive control for OIDC: a compromised /
    /// MITM'd discovery endpoint pointing `jwks_uri` off-origin is the
    /// SSRF vector F-48 closes.
    OffHost {
        issuer_host: String,
        jwks_host: String,
    },
}

/// Bind a discovery-supplied `jwks_uri` to the issuer origin BEFORE the
/// JWKS fetch. Amended after the post-E2E correction (routability leg
/// dropped; see below).
///
/// Shared by BOTH OIDC issuer paths — the single-issuer `OidcProvider`
/// (`lib.rs`) and the multi-issuer `MultiIssuerJwksValidator`
/// (`multi_issuer.rs`) — so the same-host guard cannot diverge between
/// them. There is exactly one
/// implementation; the two call sites map [`JwksUriCheckError`] onto
/// their own existing JWKS-fetch error classification.
///
/// The check is **additive** (§5): it runs in addition to — and does not
/// weaken — the TLS-version pin and redirect cap layered by
/// [`build_http_client`]. One control, before the fetch:
///
/// **Same-host binding.** `jwks_uri`'s HOST must equal `issuer_url`'s
/// HOST, compared case-insensitively per URL host semantics. We compare
/// the parsed `host_str()` values (hostnames), NOT the raw URL strings —
/// a discovery document legitimately serves `jwks_uri` on a different
/// scheme/port/path than the issuer URL, but a *different host* is the
/// SSRF vector. `url::Url::host_str` already lower-cases registered
/// domain names during parsing; we additionally `eq_ignore_ascii_case`
/// so an IDNA / mixed-case edge cannot slip a near-miss host through.
///
/// # Why no routability leg
///
/// An earlier revision ALSO resolved the `jwks_uri` host and rejected
/// any address that failed `hort_net_egress::is_routable`. That leg was
/// DROPPED after the E2E
/// proved it breaks the canonical OIDC deployment where the IdP is
/// internal (Keycloak in-cluster at an RFC 1918 address): the legitimate
/// issuer's own host resolves internally, so the routability leg rejected
/// every auth attempt with `idp_unavailable`. Given the same-host binding
/// — which pins the fetch to the issuer's own host, so a compromised
/// discovery document cannot redirect it to an arbitrary internal service
/// — `is_routable` only ever rejects the operator's own trusted issuer
/// host for negligible security benefit. Same-host binding is the
/// load-bearing SSRF control; routability is not. (User-approved post-E2E
/// correction; design §3.6 amended.)
///
/// The function does no I/O, so it is synchronous.
pub(crate) fn check_jwks_uri_bound(
    issuer_url: &str,
    jwks_uri: &str,
) -> Result<(), JwksUriCheckError> {
    let issuer_parsed = url::Url::parse(issuer_url)
        .map_err(|e| JwksUriCheckError::Unparsable(format!("issuer_url parse failed: {e}")))?;
    let jwks_parsed = url::Url::parse(jwks_uri)
        .map_err(|e| JwksUriCheckError::Unparsable(format!("jwks_uri parse failed: {e}")))?;

    let issuer_host = issuer_parsed
        .host_str()
        .ok_or_else(|| JwksUriCheckError::Unparsable("issuer_url has no host component".into()))?;
    let jwks_host = jwks_parsed
        .host_str()
        .ok_or_else(|| JwksUriCheckError::Unparsable("jwks_uri has no host component".into()))?;

    // ----- Same-host binding (the load-bearing SSRF control) ---------------
    if !issuer_host.eq_ignore_ascii_case(jwks_host) {
        return Err(JwksUriCheckError::OffHost {
            issuer_host: issuer_host.to_string(),
            jwks_host: jwks_host.to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_default_timeout_is_ten_seconds() {
        // Pin against accidental tightening that would 504 legitimate
        // JWKS fetches on healthy but slow networks.
        assert_eq!(HTTP_DEFAULT_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn http_max_redirects_is_three() {
        // Three hops accommodates a proxy + canonicalising rewrite at the
        // IdP; anything broader risks a redirect-storm attack.
        assert_eq!(HTTP_MAX_REDIRECTS, 3);
    }

    #[test]
    fn outbound_tls_versions_pin_to_12_then_13() {
        // BSI TR-02102-2 §3 Recommendation 1: TLS 1.3 + TLS 1.2 only.
        // Mirror tracked by the existing
        // `oidc_outbound_tls_version_pin_matches_outbound_policy`
        // regression in lib.rs.
        assert_eq!(OUTBOUND_TLS_MIN_VERSION, reqwest::tls::Version::TLS_1_2);
        assert_eq!(OUTBOUND_TLS_MAX_VERSION, reqwest::tls::Version::TLS_1_3);
    }

    #[test]
    fn build_http_client_succeeds_without_extra_anchors() {
        let _ = build_http_client(None).expect("default trust store must build");
    }

    #[tokio::test]
    async fn get_capped_body_returns_body_too_large_when_response_exceeds_cap() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Body is well over the 4-byte cap below.
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_string("xxxxxxxxx"))
            .mount(&server)
            .await;

        let client = build_http_client(None).expect("client builds");
        let err = get_capped_body(&client, &format!("{}/x", server.uri()), 4)
            .await
            .expect_err("body exceeds cap → BodyTooLarge");
        match err {
            CappedBodyError::BodyTooLarge { bytes_read, cap } => {
                assert!(bytes_read > cap, "bytes_read must exceed cap on overflow");
                assert_eq!(cap, 4);
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_capped_body_accepts_body_exactly_at_cap() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = "abcde";
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = build_http_client(None).expect("client builds");
        let out = get_capped_body(&client, &format!("{}/x", server.uri()), body.len())
            .await
            .expect("body at exact cap must succeed");
        assert_eq!(&out[..], body.as_bytes());
    }

    #[tokio::test]
    async fn get_capped_body_fetch_failed_on_non_2xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = build_http_client(None).expect("client builds");
        let err = get_capped_body(&client, &format!("{}/x", server.uri()), 1024)
            .await
            .expect_err("5xx must surface as FetchFailed");
        assert!(matches!(err, CappedBodyError::FetchFailed(_)));
    }

    // -----------------------------------------------------------------
    // `check_jwks_uri_bound`: bind the discovery-supplied `jwks_uri` to
    // the issuer origin (same-host binding only; the routability leg was
    // dropped post-E2E because it breaks internal IdPs — see the fn doc
    // comment).
    // -----------------------------------------------------------------

    #[test]
    fn jwks_uri_bound_accepts_same_host() {
        // Same host as the issuer → ACCEPTED. No DNS, no routability
        // dependency — same-host binding is the only control.
        check_jwks_uri_bound("https://idp.example.com", "https://idp.example.com/jwks")
            .expect("same-host jwks_uri must be accepted");
    }

    #[test]
    fn jwks_uri_bound_accepts_same_host_different_port_and_path() {
        // A legitimate discovery doc may serve `jwks_uri` on a different
        // port / path than the issuer URL — only a different HOST is the
        // SSRF vector.
        check_jwks_uri_bound(
            "https://idp.example.com/realms/x",
            "https://idp.example.com:8443/keys",
        )
        .expect("same-host different port/path must be accepted");
    }

    #[test]
    fn jwks_uri_bound_accepts_same_host_case_insensitive() {
        // Host comparison is case-insensitive per URL host semantics.
        check_jwks_uri_bound("https://IDP.EXAMPLE.COM", "https://idp.example.com/jwks")
            .expect("host match must be case-insensitive");
    }

    #[test]
    fn jwks_uri_bound_accepts_same_host_internal_rfc1918_literal_ip() {
        // Regression for the post-E2E correction: the canonical internal
        // IdP serves discovery + JWKS on an RFC 1918 / private address
        // (e.g. Keycloak in-cluster at 10.0.0.5). Same-host binding holds,
        // and there is NO routability leg, so this MUST be accepted — the
        // dropped routability leg had rejected exactly this case with
        // `idp_unavailable`, breaking all auth.
        check_jwks_uri_bound(
            "http://10.0.0.5:8080/realms/x",
            "http://10.0.0.5:8080/realms/x/certs",
        )
        .expect("same-host internal RFC1918 jwks_uri must be accepted (internal IdP case)");
    }

    #[test]
    fn jwks_uri_bound_rejects_off_host() {
        // `jwks_uri` on a DIFFERENT host than the issuer → REJECTED with
        // the off-host variant (the core SSRF vector: a compromised
        // discovery endpoint pointing the JWKS fetch off-origin). This is
        // the surviving control.
        let err = check_jwks_uri_bound("https://idp.example.com", "https://evil.example.net/jwks")
            .expect_err("off-host jwks_uri must be rejected");
        match err {
            JwksUriCheckError::OffHost {
                issuer_host,
                jwks_host,
            } => {
                assert_eq!(issuer_host, "idp.example.com");
                assert_eq!(jwks_host, "evil.example.net");
            }
            other => panic!("expected OffHost, got {other:?}"),
        }
    }

    #[test]
    fn jwks_uri_bound_rejects_unparsable_jwks_uri() {
        let err = check_jwks_uri_bound("https://example.com", "not a url")
            .expect_err("unparsable jwks_uri must be rejected");
        assert!(matches!(err, JwksUriCheckError::Unparsable(_)));
    }
}
