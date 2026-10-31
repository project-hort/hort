//! Shared building blocks for the OIDC JWKS-fetch path (single-issuer
//! adapter in `lib.rs` and multi-issuer adapter in `multi_issuer.rs`).
//!
//! # What lives here
//!
//! - [`build_http_client`] — the canonical `reqwest::Client` builder used
//!   by every OIDC outbound HTTP request. Centralises:
//!   - extra-CA-bundle layering (ADR 0010),
//!   - the redirect policy: every hop stays on the ORIGIN (scheme and
//!     host) of the URL the fetch was asked for, within a cap of 3 hops
//!     ([`same_origin_redirect_policy`]),
//!   - per-client timeout,
//!   - TLS version pin: TLS 1.3 preferred, TLS 1.2 accepted
//!     (BSI TR-02102-2, ADR 0010).
//! - [`get_capped_body`] — streaming GET with a hard byte cap on the
//!   response body (closes the OOM vector where a malicious or
//!   misconfigured IdP returns an unbounded body).
//! - [`hosts_match`] — the crate's single host-equality predicate, shared
//!   by the pre-fetch `jwks_uri` binding and the per-hop redirect binding.
//! - [`check_hop_bound_to_origin`] — the per-hop origin binding the
//!   redirect policy applies, as a pure predicate over two parsed URLs.
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
use tracing::warn;

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
///
/// The cap bounds *how many* hops; it says nothing about *where* they
/// point — that is [`same_origin_redirect_policy`]'s origin legs, which
/// the cap is nested inside. Neither property substitutes for the other.
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

/// The crate's single host-equality predicate.
///
/// Both OIDC origin bindings ask the same host question, so they are one
/// comparison with one rationale:
///
/// 1. [`check_jwks_uri_bound`] — does the discovery-declared `jwks_uri`
///    sit on the issuer's host?
/// 2. [`check_hop_bound_to_origin`] — does this redirect hop sit on the
///    host of the URL the fetch was asked for?
///
/// Two host comparisons with the same intent is how the two halves of one
/// property drift apart; there is exactly one here, with exactly two call
/// sites.
///
/// **Hosts, not URLs.** A legitimate discovery document, or an IdP's own
/// internal rewrite, may serve the same host on a different port or path,
/// and both bindings tolerate that. The **scheme** is not in that
/// tolerated set: each of those same two call sites binds it separately
/// and with equal force, because a transport change mid-fetch is authored
/// by the upstream whose `Location` header (or discovery document) is the
/// untrusted input the binding exists to contain. Callers therefore pass
/// parsed `Url::host_str()` values, never raw URL strings.
///
/// **Case-insensitive.** `url::Url` already lower-cases registered domain
/// names during parsing; `eq_ignore_ascii_case` on top means an IDNA /
/// mixed-case edge cannot slip a near-miss host through.
fn hosts_match(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Why a redirect hop was refused by [`same_origin_redirect_policy`].
///
/// Two refusals rather than one because the only thing that survives to
/// tell them apart — from each other and from the hop cap — is the text
/// that rides as the `source()` of reqwest's `Redirect`-kind error. The
/// split mirrors [`JwksUriCheckError`]'s on the pre-fetch side of the
/// same property: [`HopRefusal::OffHost`] ↔
/// [`JwksUriCheckError::OffHost`], [`HopRefusal::SchemeChanged`] ↔
/// [`JwksUriCheckError::SchemeMismatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopRefusal {
    /// The hop does not sit on the host of the URL the fetch was asked
    /// for — or one of the two URLs has no host component at all, which
    /// is the same refusal because a hop with nothing to bind to fails
    /// closed.
    OffHost,
    /// The hop sits on the requested host but does not speak the
    /// requested scheme. An `https` fetch that a `Location` header moves
    /// to `http` on the same host reads the keys that decide every
    /// token's validity in cleartext, on a path the issuer's own
    /// transport was chosen to rule out.
    SchemeChanged,
}

impl HopRefusal {
    /// The refusal text handed to `reqwest::redirect::Attempt::error`.
    /// Distinct per variant, and distinct from reqwest's own
    /// `too many redirects` cap text.
    fn as_str(self) -> &'static str {
        match self {
            Self::OffHost => "redirect target is not on the requested host",
            Self::SchemeChanged => "redirect target changes the scheme of the requested origin",
        }
    }
}

/// `scheme://host` of `url`, for a refusal log line. Path and query of an
/// upstream `Location` are upstream-controlled, so the line carries only
/// the two components the binding actually compares.
fn origin_for_log(url: &url::Url) -> String {
    format!(
        "{}://{}",
        url.scheme(),
        url.host_str().unwrap_or("<no-host>")
    )
}

/// Bind one redirect hop to the origin the fetch was asked for: the hop's
/// HOST and its SCHEME must both equal the requested URL's.
///
/// `requested` is `attempt.previous().first()` — the URL **this request**
/// was asked for (see [`same_origin_redirect_policy`] § Per request, not
/// per client). `None` fails closed: a chain with no origin to bind to is
/// refused.
///
/// # Origin here is (scheme, host) — deliberately not the port
///
/// RFC 6454's origin triple includes the port; this binding drops it,
/// because an IdP's own internal rewrite legitimately moves between ports
/// on one host (`https://idp/realms/x` → `https://idp:8443/keys`) and
/// refusing that rejects the operator's own issuer — the same reasoning
/// [`hosts_match`] records for the pre-fetch leg. The scheme is a
/// different matter: no legitimate deployment needs the transport to
/// change halfway through one fetch.
///
/// # Equality, not a no-downgrade test — and not `https_only`
///
/// A scheme change in EITHER direction leaves the origin that was bound,
/// so both are refused. `ClientBuilder::https_only(true)` would close the
/// HTTPS→HTTP downgrade but binds nothing to an origin, and it forbids the
/// plain-HTTP issuer that the canonical in-cluster deployment runs on and
/// that [`check_jwks_uri_bound`] deliberately permits. Equality in the
/// policy keeps both properties: an `http` issuer stays on `http`, an
/// `https` issuer stays on `https`, and neither can be moved by a
/// `Location` header.
fn check_hop_bound_to_origin(
    requested: Option<&url::Url>,
    next: &url::Url,
) -> Result<(), HopRefusal> {
    let Some(requested) = requested else {
        return Err(HopRefusal::OffHost);
    };
    match (requested.host_str(), next.host_str()) {
        (Some(from), Some(to)) if hosts_match(from, to) => {}
        _ => return Err(HopRefusal::OffHost),
    }
    // Same comparison and same rationale as `check_jwks_uri_bound`'s
    // scheme leg, on the hop instead of the declared URL: `Url::parse`
    // has already normalised both schemes to lower case.
    if requested.scheme() != next.scheme() {
        return Err(HopRefusal::SchemeChanged);
    }
    Ok(())
}

/// The OIDC redirect policy: **every hop stays on the origin — scheme and
/// host — of the URL the fetch was asked for**, within
/// [`HTTP_MAX_REDIRECTS`] hops.
///
/// # Why the hop cap alone was not enough
///
/// [`check_jwks_uri_bound`] binds the discovery-*declared* `jwks_uri` to
/// the issuer's origin, but it can only see a URL — it cannot see a
/// redirect. A bare `Policy::limited(n)` is the mirror image: it counts
/// hops and is blind to where they point. So a `302` from the issuer's own
/// host (or from anything that can answer for it) moved the fetch to any
/// host at all within the cap, and the keys that decide every token's
/// validity were then read from there. Neither half owned the property;
/// this policy owns it across the two.
///
/// # Both legs of the origin, because the host leg alone was not enough
///
/// Binding the host and leaving the scheme free left a hop from
/// `https://<issuer>/…` to `http://<issuer>/…` on the bound host, and it
/// was followed in cleartext. The client sets no `https_only`, and the
/// pre-fetch scheme binding in [`check_jwks_uri_bound`] runs *before* the
/// fetch, so a `Location` header arrives after the only control that had
/// ever compared schemes. [`check_hop_bound_to_origin`] carries that
/// comparison onto every hop.
///
/// # Both OIDC fetches are covered
///
/// Discovery *and* JWKS go out on the client built by
/// [`build_http_client`] — [`get_capped_body`] on the multi-issuer path,
/// `OidcProvider::get_capped_body` on the single-issuer one — so one
/// policy covers both, and that is deliberate rather than incidental.
/// Discovery matters as much as JWKS: the discovery document is what
/// *declares* `jwks_uri`, the token endpoint and the rest, so a discovery
/// response fetched from a foreign host is an attacker-authored
/// description of the issuer.
///
/// # Per request, not per client
///
/// The binding target is `attempt.previous().first()` — the URL **this
/// request** was asked for — not a host baked into the client at build
/// time. reqwest clones its redirect state per request (`tower_http`'s
/// `FollowRedirect::call` clones the policy, so the chain a closure sees
/// belongs to one request), which is what makes a single shared client
/// correct for many issuers: `MultiIssuerJwksValidator` holds ONE `http`
/// for every configured issuer, and issuer A's fetch is bound to A's own
/// host without A's identity ever reaching this closure. A client-level
/// or issuer-set-level binding could not express that — the issuer set is
/// all operator-configured, so a set-level binding would happily source
/// A's key material from B.
///
/// # Outcome shape
///
/// An off-origin attempt fails the redirect with [`reqwest::Error`] of
/// kind `Redirect`, so the caller's `send().await` returns `Err` and
/// [`get_capped_body`] classifies it as [`CappedBodyError::FetchFailed`] —
/// which both paths already map onto their existing JWKS-fetch rejection
/// (single-issuer → `OidcValidationError::IdpUnavailable`; multi-issuer →
/// `FederationDenyReason::UnknownKid`). No new error variant, no new
/// metric, no new wire shape.
///
/// Failing the redirect is load-bearing and NOT interchangeable with
/// `Attempt::stop()`: `stop()` hands the 3xx back as a successful
/// response, and `Response::error_for_status()` errors only on 4xx/5xx —
/// a 3xx passes it. The refusal would then reach the body parser, be
/// reported as a parse error rather than a fetch failure, and the
/// redirect response's own body would be read as if it were the discovery
/// document or the JWKS.
///
/// The hop cap is unchanged and still reqwest's own
/// `Policy::limited(HTTP_MAX_REDIRECTS)`, delegated to below via the
/// documented `Policy::redirect` wrapping hook — same construction, same
/// `TooManyRedirects` error. The three refusals are distinguishable two
/// ways: by the `source()` text ([`HopRefusal::as_str`] per leg, reqwest's
/// own `too many redirects` for the cap), and by how deep the chain got —
/// an origin refusal stops at the first hop, a cap breach only after
/// three were followed.
///
/// # No routability leg
///
/// A hop that stays on the issuer's origin is exactly as internal as the
/// issuer itself, and in the canonical deployment the IdP *is* internal
/// (Keycloak in-cluster on an RFC 1918 address) — so an address-based
/// control rejects the operator's own issuer and nothing else. See
/// [`check_jwks_uri_bound`]'s `# Why no routability leg`. A redirect to a
/// *different* internal service is precisely what the same-host binding
/// refuses, without consulting an address.
fn same_origin_redirect_policy() -> reqwest::redirect::Policy {
    let hop_cap = reqwest::redirect::Policy::limited(HTTP_MAX_REDIRECTS);
    reqwest::redirect::Policy::custom(move |attempt| {
        // `previous()[0]` is the URL the caller asked for; the entries
        // after it are the hops already taken.
        let requested = attempt.previous().first();
        if let Err(refusal) = check_hop_bound_to_origin(requested, attempt.url()) {
            // reqwest's `Display` for a redirect error prints only
            // "error following redirect for url (...)" — the cause lives
            // in `source()` — so without this line the operator cannot
            // tell one origin refusal from the other, or either from a cap
            // breach. Mirrors the `warn!` both call sites already emit for
            // the pre-fetch `jwks_uri` rejection. Scheme and host only, so
            // nothing upstream-controlled beyond an origin reaches the
            // log; no credential ever rides an OIDC discovery/JWKS fetch
            // in the first place.
            warn!(
                requested_origin = %requested
                    .map_or_else(|| "<none>".to_string(), origin_for_log),
                hop_origin = %origin_for_log(attempt.url()),
                refusal = refusal.as_str(),
                "oidc fetch refused a redirect off the requested origin"
            );
            // The cause rides as the `source()` of a `Redirect`-kind
            // `reqwest::Error`, the same place reqwest puts its own
            // `TooManyRedirects` — not as a new variant on any error type
            // this crate exposes.
            return attempt.error(refusal.as_str());
        }
        hop_cap.redirect(attempt)
    })
}

/// Build the canonical OIDC `reqwest::Client` with extra-CA, the
/// same-origin redirect policy (scheme + host binding + 3-hop cap),
/// timeout, and TLS-version pin all layered consistently. Used by both the `OidcProvider`
/// (single-issuer user-login) and the `MultiIssuerJwksValidator`
/// (workload federation).
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
        .redirect(same_origin_redirect_policy())
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
/// variant is introduced — each path rejects with its existing
/// JWKS-fetch error classification.
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
    /// SSRF vector this check closes.
    OffHost {
        issuer_host: String,
        jwks_host: String,
    },
    /// `jwks_uri` scheme does not equal the `issuer_url` scheme. An
    /// HTTPS issuer whose discovery document points `jwks_uri` at
    /// plain HTTP on the SAME host is a downgrade: the JWKS fetch (keys
    /// used to verify every subsequent token) would run unencrypted
    /// even though the issuer itself is TLS-protected, exposing it to
    /// on-path tampering the issuer's own transport was meant to rule
    /// out. Equality, not an HTTPS-only floor — the in-cluster
    /// http-issuer/http-jwks deployment (Keycloak) must keep working.
    SchemeMismatch {
        issuer_scheme: String,
        jwks_scheme: String,
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
/// The check is **additive**: it runs in addition to — and does not
/// weaken — the TLS-version pin and the same-host redirect policy layered
/// by [`build_http_client`]. One control, before the fetch:
///
/// **Same-host binding.** `jwks_uri`'s HOST must equal `issuer_url`'s
/// HOST, via the crate's one host predicate [`hosts_match`] — which
/// documents why port and path are tolerated and why the comparison is
/// case-insensitive, and is the same predicate
/// [`check_hop_bound_to_origin`] applies per hop.
///
/// **Scheme binding.** `jwks_uri`'s SCHEME must equal `issuer_url`'s, for
/// the reason recorded on [`JwksUriCheckError::SchemeMismatch`]. The
/// per-hop binding carries the same comparison onto every hop the fetch
/// then takes.
///
/// # What this check does and does not reach
///
/// It binds the *declared* URL. It cannot see a redirect — by the time a
/// `302` arrives the fetch is already in flight. The property "the JWKS
/// is read from the issuer's host" is therefore owned by two controls
/// together, and both are required:
///
/// 1. this function, on the URL the discovery document declares, and
/// 2. [`same_origin_redirect_policy`], on every hop of the fetch that
///    follows.
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
/// — which, together with the per-hop binding in
/// [`same_origin_redirect_policy`], pins the fetch to the issuer's own
/// origin so a compromised discovery document can redirect it neither by
/// declaration nor by `Location` header — `is_routable` only ever rejects
/// the operator's own trusted issuer host for negligible security
/// benefit. Same-host binding is the load-bearing SSRF control;
/// routability is not.
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
    // One predicate, shared with the per-hop redirect binding.
    if !hosts_match(issuer_host, jwks_host) {
        return Err(JwksUriCheckError::OffHost {
            issuer_host: issuer_host.to_string(),
            jwks_host: jwks_host.to_string(),
        });
    }

    // ----- Scheme binding (no same-host HTTPS→HTTP downgrade) --------------
    // Equality, not an HTTPS-only floor: http-issuer/http-jwks must keep
    // working for the canonical in-cluster Keycloak deployment.
    if issuer_parsed.scheme() != jwks_parsed.scheme() {
        return Err(JwksUriCheckError::SchemeMismatch {
            issuer_scheme: issuer_parsed.scheme().to_string(),
            jwks_scheme: jwks_parsed.scheme().to_string(),
        });
    }

    Ok(())
}

/// Test-only: stand up a wiremock on a loopback host literal DIFFERENT
/// from the `127.0.0.1` that `MockServer::start()` uses, so a redirect
/// across host literals has a genuinely LIVE target. Both suites'
/// hop-binding tests bind to it, which is why it lives here rather than
/// twice.
///
/// `127.0.0.2` is the same loopback interface as `127.0.0.1`, so a hop to
/// it would land; the only thing that refuses it is the host literal in
/// the `Location` header — exactly the thing an attacker controls. No DNS
/// is involved, so the test does not depend on how `localhost` resolves.
#[cfg(test)]
pub(crate) async fn start_server_on_foreign_loopback_host() -> wiremock::MockServer {
    let listener = std::net::TcpListener::bind("127.0.0.2:0")
        .expect("127.0.0.2 is loopback — binding it must succeed");
    wiremock::MockServer::builder()
        .listener(listener)
        .start()
        .await
}

/// Test-only: the host literal of a mock server's base URI, so a test can
/// assert that two servers differ (or agree) on the one thing the hop
/// binding looks at.
#[cfg(test)]
pub(crate) fn host_of(uri: &str) -> String {
    url::Url::parse(uri)
        .expect("mock server uri parses")
        .host_str()
        .expect("mock server uri has a host")
        .to_string()
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
    // `same_origin_redirect_policy`: every hop stays on the ORIGIN —
    // scheme and host — of the URL the fetch was asked for. Asserted at
    // the helper boundary, so the classification
    // (`CappedBodyError::FetchFailed`) is pinned where both adapters
    // consume it. The foreign target is a LIVE wiremock on `127.0.0.2`
    // carrying `.expect(0)`.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn get_capped_body_refuses_a_redirect_off_the_requested_host() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let foreign = start_server_on_foreign_loopback_host().await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_string("foreign-body"))
            .expect(0)
            .mount(&foreign)
            .await;

        let server = MockServer::start().await;
        assert_ne!(
            host_of(&server.uri()),
            host_of(&foreign.uri()),
            "the two mock servers must sit on different host literals"
        );
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/keys", foreign.uri()).as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = build_http_client(None).expect("client builds");
        let err = get_capped_body(&client, &format!("{}/keys", server.uri()), 1024)
            .await
            .expect_err("a hop off the requested host must be refused");
        match err {
            CappedBodyError::FetchFailed(detail) => {
                // The refusal FAILS the redirect, so it arrives on the
                // `send()` error path. It must not arrive as a response:
                // `error_for_status()` passes a 3xx, so an
                // `Attempt::stop()` here would hand the redirect's own
                // body to the JWKS/discovery parser and report the
                // refusal as a parse error.
                assert!(
                    detail.starts_with("request failed:"),
                    "off-host refusal must surface on the send() error path, got: {detail}"
                );
                assert!(
                    detail.contains("error following redirect"),
                    "the failure must be reqwest's redirect kind, got: {detail}"
                );
            }
            other => panic!("expected FetchFailed, got {other:?}"),
        }
        foreign.verify().await;
        server.verify().await;
    }

    #[tokio::test]
    async fn get_capped_body_follows_a_same_host_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/keys/live", server.uri()).as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/keys/live"))
            .respond_with(ResponseTemplate::new(200).set_body_string("same-host-body"))
            .expect(1)
            .mount(&server)
            .await;

        let client = build_http_client(None).expect("client builds");
        let out = get_capped_body(&client, &format!("{}/keys", server.uri()), 1024)
            .await
            .expect("a same-host redirect must still be followed");
        assert_eq!(&out[..], b"same-host-body");
        server.verify().await;
    }

    /// Walk the cause chain reqwest hung off the redirect error.
    ///
    /// reqwest's `Display` for a redirect error prints only
    /// "error following redirect for url (...)" and drops the cause, so
    /// the leg that refused — and the hop cap's own `too many redirects` —
    /// are readable only here. This is the mechanism the policy's refusal
    /// strings exist for.
    fn refusal_cause(err: &reqwest::Error) -> String {
        let mut causes = Vec::new();
        let mut next: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
        while let Some(cause) = next {
            causes.push(cause.to_string());
            next = cause.source();
        }
        causes.join(" | ")
    }

    #[tokio::test]
    async fn each_redirect_refusal_names_the_leg_that_refused() {
        // Three refusals from one client, asserted together because the
        // property is that they are TOLD APART: an operator reading a log
        // (and the assertions in this file) must be able to distinguish a
        // scheme change from an off-host hop and both from a hop-cap
        // breach, and the `source()` text is the only carrier that
        // survives. Driven through the client directly rather than
        // `get_capped_body`, which folds every send error into one
        // `FetchFailed(String)` built from reqwest's cause-less `Display`.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let foreign = start_server_on_foreign_loopback_host().await;
        let server = MockServer::start().await;
        let base = server.uri();
        assert_ne!(
            host_of(&base),
            host_of(&foreign.uri()),
            "the two mock servers must sit on different host literals"
        );

        // (1) off-host: same scheme, different host.
        Mock::given(method("GET"))
            .and(path("/off-host"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/keys", foreign.uri()).as_str()),
            )
            .mount(&server)
            .await;
        // (2) scheme change: the SAME host and the SAME port, `https`
        // instead of `http` — the host leg cannot refuse this, so if the
        // cause below names the scheme leg then the scheme leg is what
        // ran. (The target speaks plain HTTP, so a followed hop would
        // fail the TLS handshake instead and surface a connect-kind
        // cause — which is exactly why the assertion is on the cause and
        // not merely on "it errored".)
        let scheme_swapped = base.replacen("http://", "https://", 1);
        assert!(
            scheme_swapped.starts_with("https://") && base.starts_with("http://"),
            "the swap must actually change the scheme, or this leg silently \
             becomes a same-origin hop: {base} -> {scheme_swapped}"
        );
        Mock::given(method("GET"))
            .and(path("/scheme"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{scheme_swapped}/keys").as_str()),
            )
            .mount(&server)
            .await;
        // (3) hop cap: every hop on the requested origin, five deep.
        for i in 0..5 {
            Mock::given(method("GET"))
                .and(path(format!("/hop/{i}")))
                .respond_with(
                    ResponseTemplate::new(302)
                        .insert_header("Location", format!("{base}/hop/{}", i + 1).as_str()),
                )
                .mount(&server)
                .await;
        }

        let client = build_http_client(None).expect("client builds");
        let mut causes = Vec::new();
        for leg in ["off-host", "scheme", "hop/0"] {
            let err = client
                .get(format!("{base}/{leg}"))
                .send()
                .await
                .expect_err("every chain above must be refused");
            assert!(
                err.is_redirect(),
                "{leg}: refusal must be reqwest's redirect kind, got {err:?}"
            );
            causes.push(refusal_cause(&err));
        }

        assert!(
            causes[0].contains(HopRefusal::OffHost.as_str()),
            "off-host cause must name the host leg: {}",
            causes[0]
        );
        assert!(
            causes[1].contains(HopRefusal::SchemeChanged.as_str()),
            "same-host scheme change must name the scheme leg, not a TLS \
             or connect failure: {}",
            causes[1]
        );
        assert!(
            causes[2].contains("too many redirects"),
            "a same-origin chain past the cap must be cut by reqwest's own \
             cap, not by either origin leg: {}",
            causes[2]
        );
        assert_ne!(causes[0], causes[1], "the two origin legs must differ");
        assert_ne!(causes[1], causes[2], "a scheme refusal is not a cap breach");
    }

    // -----------------------------------------------------------------
    // `check_hop_bound_to_origin`: the per-hop binding as a pure
    // predicate. The live tests above drive it through reqwest, which can
    // only reach the scheme leg in one direction (wiremock speaks plain
    // HTTP, so an `https` *requested* URL needs the TLS harness in
    // `lib.rs`). Here both directions are stated directly, which is also
    // where the "equality, not no-downgrade" rule is written down.
    // -----------------------------------------------------------------

    /// Parse helper: every input below is a literal the test author
    /// controls, so a parse failure is a broken test, not a case.
    fn u(raw: &str) -> url::Url {
        url::Url::parse(raw).expect("test url literal parses")
    }

    #[test]
    fn hop_bound_to_origin_accepts_the_same_origin_on_another_port_and_path() {
        // The tolerated difference: an IdP's own rewrite may move between
        // ports and paths on one host. Refusing this rejects the
        // operator's own issuer, which is why the bound tuple is
        // (scheme, host) and not RFC 6454's full triple.
        check_hop_bound_to_origin(
            Some(&u("https://idp.example.com/realms/x")),
            &u("https://idp.example.com:8443/keys"),
        )
        .expect("same scheme + host on another port/path must be followed");
    }

    #[test]
    fn hop_bound_to_origin_accepts_a_case_differing_host() {
        // Host equality is the crate's one case-insensitive predicate.
        check_hop_bound_to_origin(
            Some(&u("https://IDP.EXAMPLE.COM/realms/x")),
            &u("https://idp.example.com/keys"),
        )
        .expect("host match must be case-insensitive");
    }

    #[test]
    fn hop_bound_to_origin_refuses_another_host() {
        assert_eq!(
            check_hop_bound_to_origin(
                Some(&u("https://idp.example.com/realms/x")),
                &u("https://attacker.example.net/keys"),
            ),
            Err(HopRefusal::OffHost)
        );
    }

    #[test]
    fn hop_bound_to_origin_refuses_an_https_to_http_downgrade_on_the_same_host() {
        // The hop stays on the bound host, so the host leg cannot refuse
        // it, and the keys that decide every token's validity would be
        // read in cleartext. The pre-fetch `jwks_uri` scheme binding
        // cannot reach this either — a `Location` header arrives after it
        // has run.
        assert_eq!(
            check_hop_bound_to_origin(
                Some(&u("https://idp.example.com/realms/x")),
                &u("http://idp.example.com/realms/x/certs"),
            ),
            Err(HopRefusal::SchemeChanged)
        );
    }

    #[test]
    fn hop_bound_to_origin_refuses_an_http_to_https_upgrade_on_the_same_host() {
        // Equality, not a no-downgrade test. An `http` issuer that a
        // `Location` header moves to `https` has also left the origin the
        // fetch was bound to, and the party that moved it is the upstream
        // whose header is the untrusted input. Refusing both directions is
        // what makes the rule a binding rather than a floor; a floor is
        // what `https_only(true)` would be, and it would reject the
        // canonical in-cluster plain-HTTP issuer outright.
        assert_eq!(
            check_hop_bound_to_origin(
                Some(&u("http://10.0.0.5:8080/realms/x")),
                &u("https://10.0.0.5:8080/realms/x/certs"),
            ),
            Err(HopRefusal::SchemeChanged)
        );
    }

    #[test]
    fn hop_bound_to_origin_fails_closed_with_no_requested_url() {
        // reqwest always supplies the requested URL as `previous()[0]`;
        // an empty chain would mean the binding has nothing to bind to,
        // and the refusal is the fail-closed answer.
        assert_eq!(
            check_hop_bound_to_origin(None, &u("https://idp.example.com/keys")),
            Err(HopRefusal::OffHost)
        );
    }

    #[test]
    fn hop_bound_to_origin_fails_closed_when_a_url_has_no_host() {
        // A host-less URL has no origin to compare, in either position.
        assert_eq!(
            check_hop_bound_to_origin(
                Some(&u("https://idp.example.com/realms/x")),
                &u("data:text/plain,keys"),
            ),
            Err(HopRefusal::OffHost)
        );
        assert_eq!(
            check_hop_bound_to_origin(
                Some(&u("data:text/plain,issuer")),
                &u("https://idp.example.com/keys"),
            ),
            Err(HopRefusal::OffHost)
        );
    }

    #[test]
    fn hop_refusal_texts_are_distinct_and_not_the_cap_text() {
        // The `source()` text is the only thing that survives to tell the
        // three refusals apart (reqwest's `Display` drops the cause), so
        // two legs collapsing onto one string — or onto reqwest's own cap
        // wording — would make the live assertions below vacuous.
        let off_host = HopRefusal::OffHost.as_str();
        let scheme = HopRefusal::SchemeChanged.as_str();
        assert_ne!(off_host, scheme);
        for text in [off_host, scheme] {
            assert!(
                !text.contains("too many redirects"),
                "a leg's text must not read as reqwest's hop-cap text: {text}"
            );
        }
    }

    #[test]
    fn origin_for_log_carries_scheme_and_host_only() {
        // Path and query of an upstream `Location` are upstream-controlled
        // and must not reach the log line.
        assert_eq!(
            origin_for_log(&u("https://idp.example.com:8443/realms/x?token=secret")),
            "https://idp.example.com"
        );
        assert_eq!(
            origin_for_log(&u("data:text/plain,x")),
            "data://<no-host>",
            "a host-less URL still logs legibly"
        );
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

    // -----------------------------------------------------------------
    // Scheme binding: `jwks_uri` scheme must equal `issuer_url` scheme.
    // Equality, not an HTTPS-only floor — same-host http/http (in-cluster
    // Keycloak) must keep working; only a scheme MISMATCH is rejected.
    // -----------------------------------------------------------------

    #[test]
    fn jwks_uri_bound_accepts_https_issuer_https_jwks() {
        check_jwks_uri_bound("https://idp.example.com", "https://idp.example.com/jwks")
            .expect("https issuer + https jwks_uri must be accepted");
    }

    #[test]
    fn jwks_uri_bound_accepts_http_issuer_http_jwks() {
        // In-cluster Keycloak: both issuer and jwks_uri are plain HTTP on
        // the same host. Equality holds, so this MUST keep working.
        check_jwks_uri_bound(
            "http://10.0.0.5:8080/realms/x",
            "http://10.0.0.5:8080/realms/x/certs",
        )
        .expect("http issuer + http jwks_uri (same host) must be accepted");
    }

    #[test]
    fn jwks_uri_bound_rejects_https_issuer_http_jwks_downgrade() {
        let err = check_jwks_uri_bound("https://idp.example.com", "http://idp.example.com/jwks")
            .expect_err("https issuer with an http jwks_uri must be rejected as a downgrade");
        match err {
            JwksUriCheckError::SchemeMismatch {
                issuer_scheme,
                jwks_scheme,
            } => {
                assert_eq!(issuer_scheme, "https");
                assert_eq!(jwks_scheme, "http");
            }
            other => panic!("expected SchemeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn jwks_uri_bound_rejects_http_issuer_https_jwks_mismatch() {
        // Not an HTTPS-only floor: the OTHER direction (http issuer,
        // https jwks_uri) is also a mismatch and must be rejected too —
        // equality is the rule, not "https is always fine".
        let err = check_jwks_uri_bound("http://idp.example.com", "https://idp.example.com/jwks")
            .expect_err("http issuer with an https jwks_uri must be rejected as a mismatch");
        match err {
            JwksUriCheckError::SchemeMismatch {
                issuer_scheme,
                jwks_scheme,
            } => {
                assert_eq!(issuer_scheme, "http");
                assert_eq!(jwks_scheme, "https");
            }
            other => panic!("expected SchemeMismatch, got {other:?}"),
        }
    }
}
