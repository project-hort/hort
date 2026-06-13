//! `AkClient` — thin reqwest wrapper for `hort-cli`.
//!
//! Pure HTTP client. Zero deps on `hort-domain`, `hort-app`, or
//! `hort-adapters-*`. The token is attached via `default_headers` so it
//! never appears in tracing output (our own `tracing::debug!` calls
//! never interpolate headers).
//!
//! # Token redaction
//!
//! `reqwest` may emit its own DEBUG-level logs (via the `log` facade)
//! that include request headers. Callers that need strict token
//! redaction should filter `reqwest` and `hyper` log targets below
//! `WARN`. Our own calls use URL-level context only — the token string
//! is never constructed inside a tracing macro argument.
//!
//! # HORT_EXTRA_CA_BUNDLE
//!
//! Mirrors the extra-CA-bundle helper present in `hort-net-egress`.
//! Because `hort-cli` has zero dependency on any `hort-*` crate, the
//! helper is inlined here (small — roughly 10 lines). The env var name
//! and semantics are identical.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, ClientBuilder};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

use crate::config::EffectiveConfig;

// -----------------------------------------------------------------
// Public types
// -----------------------------------------------------------------

/// Pure HTTP client — wraps `reqwest::Client` with bearer-token and
/// base-URL plumbing.
///
/// The client is cheaply `clone`-able (the inner `reqwest::Client`
/// uses an `Arc` over a shared connection pool).
#[derive(Clone)]
pub struct AkClient {
    http: Client,
    base_url: Url,
    // Stored so callers can write tests that verify the token is NOT
    // present in trace output. NEVER included in Debug output or
    // tracing events.
    #[allow(dead_code)]
    token: String,
}

impl std::fmt::Debug for AkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AkClient")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl AkClient {
    /// Build an `AkClient` from resolved configuration.
    ///
    /// Attaches `Authorization: Bearer <token>` via
    /// `default_headers` and applies `HORT_EXTRA_CA_BUNDLE` if the env
    /// var is set.
    pub fn new(cfg: &EffectiveConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();

        // SECURITY: token never logged — attached via default_headers so
        // reqwest carries it on every request. Our own tracing calls in
        // `get` / `post` log only the URL, not the headers map.
        let auth = HeaderValue::from_str(&format!("Bearer {}", cfg.token))
            .context("invalid characters in HORT_TOKEN — bearer token must be ASCII")?;
        headers.insert(AUTHORIZATION, auth);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let mut builder = ClientBuilder::new()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10));

        // Apply HORT_EXTRA_CA_BUNDLE (extra-CA-bundle helper mirror).
        builder = apply_extra_ca_bundle(builder)?;

        let http = builder.build().context("building reqwest client")?;

        Ok(Self {
            http,
            base_url: cfg.server.clone(),
            token: cfg.token.clone(),
        })
    }

    /// Issue a `GET` request to `path` (relative to `base_url`) and
    /// deserialise the response body as `T`.
    ///
    /// Returns `Err` for any non-2xx status or JSON deserialisation
    /// failure. The error message includes the HTTP status code and the
    /// raw response body on failure.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.base_url.join(path).context("joining URL path")?;
        // SECURITY: only the URL is traced — no headers, no body.
        tracing::debug!(method = "GET", url = %url, "request");
        let resp = self.http.get(url).send().await.context("HTTP GET")?;
        Self::handle_response(resp).await
    }

    /// Issue a `POST` request to `path` with `body` serialised as JSON
    /// and deserialise the response as `T`.
    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.post_with_headers(path, body, &[]).await
    }

    /// Issue a `POST` request with extra headers.
    ///
    /// Equivalent to [`post`](Self::post) but appends each `(name, value)`
    /// pair from `extra_headers` to the request. Used by call sites that
    /// need a request-scoped header (e.g. `Idempotency-Key`) without
    /// putting that header on the cloned default-headers map for every
    /// request.
    ///
    /// Header names and values must be ASCII; non-ASCII values produce an
    /// error before the request is sent.
    pub async fn post_with_headers<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        extra_headers: &[(&str, &str)],
    ) -> Result<T> {
        let url = self.base_url.join(path).context("joining URL path")?;
        // SECURITY: only the URL is traced (header *names* are safe to
        // log but we keep the URL-only convention for consistency).
        tracing::debug!(method = "POST", url = %url, "request");
        let mut req = self.http.post(url).json(body);
        for (name, value) in extra_headers {
            // Build a HeaderName/HeaderValue explicitly so non-ASCII bytes
            // surface as a clear error rather than a panic inside reqwest.
            let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("invalid header name: {name}"))?;
            let header_value = HeaderValue::from_str(value)
                .with_context(|| format!("invalid characters in {name} header value"))?;
            req = req.header(header_name, header_value);
        }
        let resp = req.send().await.context("HTTP POST")?;
        Self::handle_response(resp).await
    }

    /// POST to `path` with `body` serialised as JSON; succeed on any 2xx
    /// without attempting to deserialise the response body. Used by
    /// endpoints that return 204 No Content (e.g.
    /// `POST /admin/quarantine/:artifact_id/release`).
    ///
    /// On non-2xx, surfaces the same error shape as
    /// [`post`](Self::post): "HTTP <status>: <body text>".
    ///
    /// Distinct from [`post`](Self::post) because `post` calls
    /// `resp.json::<T>()` unconditionally, which fails on an empty body —
    /// the failure mode for 204-returning endpoints with the regular
    /// `post` path is "EOF while parsing a value", which is misleading.
    pub async fn post_no_response<B: Serialize>(&self, path: &str, body: &B) -> Result<()> {
        let url = self.base_url.join(path).context("joining URL path")?;
        // SECURITY: only the URL is traced — no headers, no body.
        tracing::debug!(method = "POST", url = %url, "request");
        let resp = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .context("HTTP POST")?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::response_to_error(resp).await)
        }
    }

    /// DELETE `path` with `body` serialised as JSON; succeed on any 2xx
    /// without attempting to deserialise the response body. Used by
    /// endpoints that return 204 No Content (e.g.
    /// `DELETE /admin/policies/:policy_id/exclusions/:cve_id`, which
    /// carries an audit `reason` in the request body per the curation
    /// wire contract).
    ///
    /// On non-2xx, surfaces the same error shape as
    /// [`post_no_response`](Self::post_no_response): "HTTP <status>:
    /// <body text>".
    pub async fn delete_no_response<B: Serialize>(&self, path: &str, body: &B) -> Result<()> {
        let url = self.base_url.join(path).context("joining URL path")?;
        // SECURITY: only the URL is traced — no headers, no body.
        tracing::debug!(method = "DELETE", url = %url, "request");
        let resp = self
            .http
            .delete(url)
            .json(body)
            .send()
            .await
            .context("HTTP DELETE")?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::response_to_error(resp).await)
        }
    }

    /// Return the configured base URL.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    async fn handle_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>().await.context("parsing JSON response body")
        } else {
            // Attempt to surface the project's standard error envelope:
            //   { "error": { "code": "...", "message": "..." } }
            // If the body isn't JSON the raw text is still useful for
            // diagnostics.
            Err(Self::response_to_error(resp).await)
        }
    }

    /// Convert a non-2xx response into a canonical `anyhow::Error` whose
    /// message is `"HTTP <status>: <body text>"`. Body text falls back to
    /// `"<no body>"` when reading the bytes fails (network blip, transcoding
    /// error). Used by both `handle_response` and `post_no_response` to keep
    /// the wire error shape consistent across all client methods.
    async fn response_to_error(resp: reqwest::Response) -> anyhow::Error {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        anyhow!("HTTP {status}: {text}")
    }
}

// -----------------------------------------------------------------
// CA bundle helper (extra-CA-bundle mirror — inlined, no shared-crate dep)
// -----------------------------------------------------------------

/// Heuristic — does this error chain indicate a TLS certificate
/// failure?
///
/// Walks `err.chain()` and matches on a short list of substrings that
/// appear in rustls / reqwest TLS-failure messages
/// (`certificate`, `unknown issuer`, `trust anchor`, `invalid peer`,
/// `self-signed`, `tls handshake`). Used so callers can produce
/// actionable error messages pointing at `HORT_EXTRA_CA_BUNDLE` when an
/// internal CA isn't trusted by the system roots — without forcing
/// every reqwest user to inspect the chain themselves.
///
/// False positives are possible in principle (an upstream service
/// returning a 4xx body literally containing the word "certificate"
/// could trip this) but unlikely in practice for the discovery /
/// openid-configuration calls the CLI makes.
pub(crate) fn is_tls_cert_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let msg = cause.to_string().to_lowercase();
        msg.contains("certificate")
            || msg.contains("unknownissuer")
            || msg.contains("unknown issuer")
            || msg.contains("trust anchor")
            || msg.contains("invalid peer")
            || msg.contains("self-signed")
            || msg.contains("self signed")
            || msg.contains("tls handshake")
    })
}

/// Apply `HORT_EXTRA_CA_BUNDLE` PEM file to the builder if the env var
/// is set.
///
/// `reqwest` 0.12 provides `Certificate::from_pem_bundle` which parses
/// a concatenated PEM file and returns a `Vec<Certificate>`. This
/// function iterates the returned vec and calls `add_root_certificate`
/// once per cert — same TLS trust semantics as the server-side adapter
/// helper in `hort-net-egress`.
///
/// If the variable is unset or empty, the builder is returned unmodified.
pub(crate) fn apply_extra_ca_bundle(builder: ClientBuilder) -> Result<ClientBuilder> {
    let path = match std::env::var("HORT_EXTRA_CA_BUNDLE") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(builder),
    };

    let pem =
        std::fs::read(&path).with_context(|| format!("reading HORT_EXTRA_CA_BUNDLE at {path}"))?;

    // `Certificate::from_pem_bundle` is available in reqwest 0.12.x
    // (confirmed against 0.12.28 source — src/tls.rs line 193).
    let certs = reqwest::Certificate::from_pem_bundle(&pem)
        .context("parsing HORT_EXTRA_CA_BUNDLE as PEM certificate bundle")?;

    let mut out = builder;
    for cert in certs {
        out = out.add_root_certificate(cert);
    }
    Ok(out)
}

// -----------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EffectiveConfig;
    use crate::config::OutputFormat;

    fn test_cfg(base_url: &str) -> EffectiveConfig {
        EffectiveConfig {
            server: Url::parse(base_url).expect("valid url"),
            token: "test-secret-token".to_string(),
            default_format: OutputFormat::Table,
        }
    }

    #[test]
    fn debug_output_redacts_token() {
        let cfg = test_cfg("https://example.com");
        let client = AkClient::new(&cfg).expect("builds");
        let debug = format!("{client:?}");
        assert!(
            !debug.contains("test-secret-token"),
            "token must not appear in Debug output: {debug}"
        );
        assert!(
            debug.contains("<redacted>"),
            "must show redacted placeholder: {debug}"
        );
    }

    #[test]
    fn base_url_accessor_matches_config() {
        let cfg = test_cfg("https://artifacts.example.com");
        let client = AkClient::new(&cfg).expect("builds");
        assert_eq!(client.base_url().as_str(), "https://artifacts.example.com/");
    }

    #[test]
    fn is_tls_cert_error_matches_certificate_keyword_in_chain() {
        let inner = anyhow::anyhow!("invalid peer certificate: UnknownIssuer");
        let err = inner.context("error sending request for url");
        assert!(is_tls_cert_error(&err));
    }

    #[test]
    fn is_tls_cert_error_matches_unknown_issuer() {
        let err = anyhow::anyhow!("rustls error: UnknownIssuer");
        assert!(is_tls_cert_error(&err));
    }

    #[test]
    fn is_tls_cert_error_matches_self_signed() {
        let err = anyhow::anyhow!("self-signed certificate not trusted");
        assert!(is_tls_cert_error(&err));
    }

    #[test]
    fn is_tls_cert_error_matches_top_level_message() {
        let err = anyhow::anyhow!("tls handshake failed");
        assert!(is_tls_cert_error(&err));
    }

    #[test]
    fn is_tls_cert_error_rejects_connection_refused() {
        let inner = anyhow::anyhow!("Connection refused (os error 111)");
        let err = inner.context("error sending request");
        assert!(!is_tls_cert_error(&err));
    }

    #[test]
    fn is_tls_cert_error_rejects_dns_failure() {
        let err = anyhow::anyhow!(
            "dns error: failed to lookup address information: \
             Name or service not known"
        );
        assert!(!is_tls_cert_error(&err));
    }
}
