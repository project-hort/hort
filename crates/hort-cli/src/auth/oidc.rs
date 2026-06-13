//! RFC 8628 device-flow client + RFC 8693 token-exchange client.
//!
//! This module runs the two-step OIDC login on behalf of `hort-cli`:
//! 1. Device-code flow (RFC 8628) against the external IdP.
//! 2. Token exchange (RFC 8693) against hort's `/api/v1/auth/exchange`.
//!
//! # Security invariants
//!
//! * The IdP JWT and the minted `hort_cli_*` token NEVER appear in tracing
//!   output, `Display` of error chains, or any printed string.
//! * The verification URL scheme is validated before any open attempt or
//!   URL print. A hostile IdP cannot smuggle `javascript:` or `file://`
//!   through to the user's browser.
//! * Print-then-open ordering: the URL is printed to stderr before the
//!   browser-open is attempted so the user can Ctrl-C if it looks wrong.
//! * The 15-minute wall-clock cap applies regardless of the IdP's
//!   `expires_in` field.
//!
//! # HTTP-client decision (locked)
//!
//! All calls in this module are anonymous. A fresh `reqwest::Client::builder()`
//! is used per call, piped through `crate::client::apply_extra_ca_bundle`.
//! `AkClient` is bearer-bound and intentionally not used here.
//! No `reqwest::Client::new()`.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use url::Url;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Endpoints from the IdP's `/.well-known/openid-configuration` needed for
/// RFC 8628 and RFC 8252 loopback.
///
/// - `device_authorization_endpoint`: RFC 8628 entry point.
/// - `authorization_endpoint`: RFC 6749 authorization endpoint, required by
///   OpenID Connect Discovery 1.0 §3 ("REQUIRED"). The RFC 8252 loopback
///   flow redirects the user to this URL.
/// - `token_endpoint`: shared by both flows.
#[derive(Debug)]
pub struct IdpEndpoints {
    pub device_authorization_endpoint: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
}

/// A `BrowserOpener` launches the verification URL in the user's browser.
///
/// # Contract
///
/// The caller MUST validate the URL scheme via [`validate_verification_uri`]
/// before passing the URL here. The opener does NOT re-validate -- double
/// validation would silently swallow a contract violation.
///
/// Failure to open is non-fatal: `run_device_flow` logs at `debug!` and
/// continues polling. The URL is already on screen.
pub trait BrowserOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<()>;
}

/// No-op opener -- for `--no-browser`, headless contexts, and tests.
pub struct NoopOpener;

impl BrowserOpener for NoopOpener {
    fn open(&self, _url: &str) -> Result<()> {
        Ok(())
    }
}

/// Validation errors for a verification URL returned by the IdP.
#[derive(Debug, thiserror::Error)]
pub enum VerificationUriError {
    #[error(
        "verification_uri uses plain HTTP; refusing to open. \
         Set HORT_OIDC_ALLOW_HTTP=1 to allow (dev only)."
    )]
    HttpDowngrade,
    #[error("verification_uri has scheme '{scheme}://' -- only http(s) is allowed")]
    ForbiddenScheme { scheme: String },
    #[error("verification_uri is not a URL: {0}")]
    Malformed(String),
}

/// Result of a successful device-code session -- the minted hort-cli token.
///
/// `requested_lifetime_secs` carries the value the operator supplied via
/// `--expires-in` (or `None` when the default was used). The post-login
/// output compares it against `expires_in` (the server-issued value)
/// to detect a server-side clamp and render a `note:` line; the
/// comparison logic lives in `login.rs::render_post_login_output`.
pub struct CliSessionToken {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub requested_lifetime_secs: Option<u64>,
    pub admin_requested: bool,
}

// SECURITY: access_token must never appear in Debug output.
impl std::fmt::Debug for CliSessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliSessionToken")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("requested_lifetime_secs", &self.requested_lifetime_secs)
            .field("admin_requested", &self.admin_requested)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DISCOVERY_TIMEOUT_SECS: u64 = 15;
const DEVICE_FLOW_SCOPE: &str = "openid profile email";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// RFC 8628 §3.5 -- default polling interval when IdP doesn't supply one.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
/// Defensive wall-clock ceiling for the polling loop.
const MAX_POLL_WALL_SECS: u64 = 900; // 15 minutes

// ---------------------------------------------------------------------------
// validate_verification_uri
// ---------------------------------------------------------------------------

/// Validate a raw verification URL returned by the IdP.
///
/// Scheme allow-list:
/// - `https://` always accepted.
/// - `http://` accepted only when `HORT_OIDC_ALLOW_HTTP` is set in the
///   environment (dev-only).
/// - Any other scheme hard-rejected before any open or print attempt.
///
/// `HORT_OIDC_ALLOW_HTTP` is NOT a TLS-trust knob; it only widens which
/// schemes the CLI will display and auto-launch for the verification URL.
pub fn validate_verification_uri(raw: &str) -> std::result::Result<Url, VerificationUriError> {
    let url = Url::parse(raw).map_err(|e| VerificationUriError::Malformed(e.to_string()))?;

    match url.scheme() {
        "https" => Ok(url),
        "http" => {
            if std::env::var("HORT_OIDC_ALLOW_HTTP").is_ok() {
                Ok(url)
            } else {
                info_scheme_rejected("http");
                Err(VerificationUriError::HttpDowngrade)
            }
        }
        other => {
            info_scheme_rejected(other);
            Err(VerificationUriError::ForbiddenScheme {
                scheme: other.to_string(),
            })
        }
    }
}

fn info_scheme_rejected(scheme: &str) {
    tracing::info!(
        scheme,
        "verification_uri scheme rejected -- refusing to open or display"
    );
}

// ---------------------------------------------------------------------------
// fetch_idp_endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OidcConfiguration {
    device_authorization_endpoint: Option<String>,
    /// Required by OIDC Discovery 1.0 §3; needed for the RFC 8252 loopback
    /// flow.
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
}

/// Fetch `<issuer>/.well-known/openid-configuration` and extract the two
/// endpoints needed for RFC 8628.
pub async fn fetch_idp_endpoints(issuer: &Url) -> Result<IdpEndpoints> {
    // Per OIDC Discovery 1.0 §4.1: "The Issuer Identifier ... is appended
    // with the URL `/.well-known/openid-configuration`" — i.e. string
    // concatenation, NOT RFC 3986 reference resolution. `Url::join`
    // resolves `.well-known/openid-configuration` against the issuer's
    // path and DROPS the final segment when there's no trailing slash:
    //   issuer `https://host/realms/kdp` (no slash) → join →
    //   `https://host/realms/.well-known/openid-configuration` (loses
    //   the realm name and 404s on Keycloak). Trim any trailing slash
    //   and string-append.
    let trimmed = issuer.as_str().trim_end_matches('/');
    let config_url_str = format!("{trimmed}/.well-known/openid-configuration");
    let config_url = Url::parse(&config_url_str).context("constructing IdP configuration URL")?;

    tracing::debug!(url = %config_url, "fetching IdP openid-configuration");

    let builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(DISCOVERY_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(10));
    let builder = crate::client::apply_extra_ca_bundle(builder)?;
    let client = builder
        .build()
        .context("building IdP discovery HTTP client")?;

    let resp = client
        .get(config_url)
        .send()
        .await
        .context("GET IdP openid-configuration")?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "IdP openid-configuration returned HTTP {}; contact your administrator",
            resp.status()
        );
    }

    let doc: OidcConfiguration = resp
        .json()
        .await
        .context("parsing IdP openid-configuration JSON")?;

    let device_authorization_endpoint = doc
        .device_authorization_endpoint
        .ok_or_else(|| {
            anyhow!(
                "IdP openid-configuration is missing 'device_authorization_endpoint'; \
                 the IdP may not support RFC 8628 device-code login"
            )
        })
        .and_then(|s| Url::parse(&s).context("parsing device_authorization_endpoint URL"))?;

    // OIDC Discovery 1.0 §3 marks `authorization_endpoint` as REQUIRED. The
    // RFC 8252 loopback flow is the consumer in hort-cli; if the IdP doc
    // omits it, every flow that relies on it (currently only loopback) will
    // fail closed.
    let authorization_endpoint = doc
        .authorization_endpoint
        .ok_or_else(|| {
            anyhow!(
                "IdP openid-configuration is missing 'authorization_endpoint' \
                 (REQUIRED by OIDC Discovery 1.0 §3)"
            )
        })
        .and_then(|s| Url::parse(&s).context("parsing authorization_endpoint URL"))?;

    let token_endpoint = doc
        .token_endpoint
        .ok_or_else(|| anyhow!("IdP openid-configuration is missing 'token_endpoint'"))
        .and_then(|s| Url::parse(&s).context("parsing token_endpoint URL"))?;

    Ok(IdpEndpoints {
        device_authorization_endpoint,
        authorization_endpoint,
        token_endpoint,
    })
}

// ---------------------------------------------------------------------------
// run_device_flow
// ---------------------------------------------------------------------------

/// Private DTO for the device authorisation response (RFC 8628 §3.2).
#[derive(Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    /// Seconds until device_code expires (RFC 8628 §3.2). Capped at 900 s.
    expires_in: Option<u64>,
    /// Polling interval in seconds. Defaults to 5 (RFC 8628 §3.5).
    interval: Option<u64>,
}

/// Private DTO for poll response errors (RFC 8628 §3.5).
#[derive(Deserialize)]
struct TokenErrorResponse {
    error: Option<String>,
}

/// IdP token response (RFC 6749 §5.1 + OIDC core §3.1.3.3).
///
/// The CLI sends the **access_token** (not the id_token) as the RFC 8693
/// `subject_token` to hort-server's `/api/v1/auth/exchange`. Rationale:
///
/// - `access_token` is OAuth's canonical "use this to call APIs"
///   credential (RFC 6749). Its audience semantics are unambiguous —
///   `aud = resource_server`, matching `HORT_OIDC_AUDIENCE` on the
///   server side.
/// - `id_token` is OIDC's "prove to the OAuth client that the user
///   authenticated" credential (OIDC Core §2) with `aud = client_id`.
///   Using it as `subject_token` mixes the two roles.
/// - When access_tokens are missing `sub` (e.g. Keycloak's optional
///   "lightweight access tokens" mode), the standards-shaped fix is
///   an IdP-side claim mapper to include `sub` on access_tokens. See
///   `docs/operator/idp-setup.md`.
#[derive(Deserialize)]
struct TokenSuccessResponse {
    access_token: Option<String>,
}

/// Run the full RFC 8628 device-code flow against `idp.device_authorization_endpoint`.
///
/// Returns the IdP-issued access_token on success. The token is never logged.
pub async fn run_device_flow(
    idp: &IdpEndpoints,
    client_id: &str,
    opener: &dyn BrowserOpener,
) -> Result<String> {
    let client = build_anon_client()?;
    run_device_flow_with_client(client, idp, client_id, opener).await
}

/// Inner implementation that accepts a pre-built client. Separated so tests
/// running under `tokio::time::pause()` can supply a no-timeout client (reqwest's
/// timer-based connect_timeout races with tokio's auto-advance during I/O polls).
async fn run_device_flow_with_client(
    client: reqwest::Client,
    idp: &IdpEndpoints,
    client_id: &str,
    opener: &dyn BrowserOpener,
) -> Result<String> {
    // Step 1 -- device authorisation request (RFC 8628 §3.2).
    let auth_resp: DeviceAuthResponse = client
        .post(idp.device_authorization_endpoint.as_str())
        .form(&[("client_id", client_id), ("scope", DEVICE_FLOW_SCOPE)])
        .send()
        .await
        .context("POST device_authorization_endpoint")?
        .error_for_status()
        .context("device_authorization_endpoint returned non-2xx")?
        .json()
        .await
        .context("parsing device authorisation response")?;

    // Step 2 -- choose and validate the URL the user will open.
    let validated_url = choose_and_validate_url(&auth_resp)?;

    // Step 3 -- print the URL and code to stderr BEFORE attempting to open.
    let mut stderr = std::io::stderr().lock();
    if let Err(e) = print_login_block(&mut stderr, validated_url.as_str(), &auth_resp.user_code) {
        tracing::debug!(error = %e, "stderr write failed (non-fatal)");
    }
    drop(stderr); // release the lock before the opener call

    // Step 4 -- attempt to open the URL. Failure is non-fatal.
    if let Err(e) = opener.open(validated_url.as_str()) {
        tracing::debug!(error = %e, "browser launch failed (non-fatal)");
    }

    // Step 5 -- poll the token endpoint.
    let mut interval_secs = auth_resp.interval.unwrap_or(DEFAULT_POLL_INTERVAL_SECS);
    // Edge case 1 -- honour the IdP's expires_in, capped at the 15-minute
    // defensive ceiling so a misbehaving IdP can't extend the session forever.
    let expires_in = auth_resp
        .expires_in
        .unwrap_or(MAX_POLL_WALL_SECS)
        .min(MAX_POLL_WALL_SECS);
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(expires_in);

    // Single Instant snapshot per check so elapsed and >= deadline are
    // consistent (two Instant::now() calls can disagree by microseconds).
    let check_deadline = |now: tokio::time::Instant| -> Result<()> {
        if now >= deadline {
            let elapsed = now.duration_since(start);
            tracing::info!(
                elapsed_secs = elapsed.as_secs(),
                "device flow timed out at 15-minute cap"
            );
            anyhow::bail!("login timed out after 15 minutes");
        }
        Ok(())
    };

    loop {
        check_deadline(tokio::time::Instant::now())?;

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        check_deadline(tokio::time::Instant::now())?;

        let poll_result = client
            .post(idp.token_endpoint.as_str())
            .form(&[
                ("grant_type", DEVICE_GRANT_TYPE),
                ("device_code", auth_resp.device_code.as_str()),
                ("client_id", client_id),
            ])
            .send()
            .await;

        let resp = match poll_result {
            Ok(r) => r,
            Err(e) => {
                // Edge case 10 -- single network failure retries on next interval.
                tracing::debug!(result_class = "network_error", error = %e, "poll network error, will retry");
                continue;
            }
        };

        let status = resp.status();

        if status.is_success() {
            let body: TokenSuccessResponse = resp.json().await.context("parsing token response")?;
            if let Some(token) = body.access_token {
                // SECURITY: token never logged -- only the result classification.
                tracing::info!(result_class = "success", "device flow completed");
                return Ok(token);
            }
            // The IdP returned 200 OK but the response body had no
            // `access_token`. The canonical fix is an IdP-side claim mapper
            // that includes `sub` on access_tokens; the operator guide
            // documents the recipe for Keycloak, Okta, Auth0, and
            // Microsoft Entra ID.
            anyhow::bail!(
                "IdP returned no access_token — verify that the OAuth client is configured \
                 to issue access_tokens with a `sub` claim. See docs/operator/idp-setup.md."
            );
        }

        // Non-200 -- parse the error field.
        let body: TokenErrorResponse = resp
            .json()
            .await
            .unwrap_or(TokenErrorResponse { error: None });
        let error_code = body.error.as_deref().unwrap_or("");

        match error_code {
            "authorization_pending" => {
                tracing::debug!(result_class = "pending", "authorization pending");
            }
            "slow_down" => {
                interval_secs += 5;
                tracing::debug!(
                    result_class = "slow_down",
                    new_interval = interval_secs,
                    "slow_down: extending interval"
                );
            }
            "access_denied" => {
                tracing::info!(result_class = "access_denied", "access denied by user");
                return Err(anyhow!("login cancelled by user"));
            }
            "expired_token" => {
                tracing::info!(result_class = "expired_token", "device code expired");
                return Err(anyhow!("login timed out"));
            }
            other => {
                tracing::debug!(
                    result_class = "network_error",
                    error_code = other,
                    "unexpected error code, will retry"
                );
            }
        }
    }
}

/// Validate the best available verification URL from the device auth response.
///
/// Preference: `verification_uri_complete` first (pre-filled code); fall back
/// to `verification_uri`. Per design §9 edge case 4: if `_complete` fails
/// validation but `verification_uri` is safe, use `verification_uri`
/// (the user must type the code). If both fail, propagate the `_complete`
/// error. If only `verification_uri` is available and it fails, propagate
/// that error.
fn choose_and_validate_url(resp: &DeviceAuthResponse) -> Result<Url> {
    match &resp.verification_uri_complete {
        Some(complete_raw) => match validate_verification_uri(complete_raw) {
            Ok(url) => Ok(url),
            Err(complete_err) => {
                // Fall back: try the plain verification_uri.
                match validate_verification_uri(&resp.verification_uri) {
                    Ok(fallback_url) => Ok(fallback_url),
                    Err(_) => {
                        // Both failed -- propagate the _complete error.
                        Err(anyhow!("verification URL rejected: {complete_err}"))
                    }
                }
            }
        },
        None => validate_verification_uri(&resp.verification_uri)
            .map_err(|e| anyhow!("verification URL rejected: {e}")),
    }
}

// ---------------------------------------------------------------------------
// exchange
// ---------------------------------------------------------------------------

/// Private DTO for successful token exchange response (RFC 8693 §2.2.1).
#[derive(Deserialize)]
struct ExchangeSuccessResponse {
    access_token: Option<String>,
    expires_in: Option<u64>,
}

/// RFC 6749 §5.2-shaped error body. hort's `/api/v1/auth/exchange` returns
/// `error_description` as a hardcoded English string (e.g. "subject_token
/// expired", "subject_token invalid") — never an echo of the JWT — so it
/// is safe to surface to the operator.
#[derive(Deserialize)]
struct ExchangeErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
}

/// POST the RFC 8693 token-exchange request to `server_endpoint` and return
/// the resulting `CliSessionToken`.
///
/// # Security
///
/// The response body is never logged -- it may contain the JWT in some error
/// shapes. The minted `hort_cli_*` token never appears in tracing output.
pub async fn exchange(
    server_endpoint: &Url,
    jwt: &str,
    client_id: &str,
    scope: Option<&str>,
    requested_lifetime_secs: Option<u64>,
) -> Result<CliSessionToken> {
    let client = build_anon_client()?;

    // SECURITY: jwt is placed in the form body only, never in a log macro.
    //
    // `subject_token_type` is `access_token` (the device flow's
    // access_token, see `TokenSuccessResponse`); `requested_token_type`
    // is also `access_token` because we want a session access token
    // (`hort_cli_*`) back from the server. RFC 8693 §2.1 — the two
    // URIs are independent; the server picks the resulting token shape
    // based on `requested_token_type`. The server side's accepted set
    // is the single-element closed set `[access_token]` (see
    // hort-http-core's `SUPPORTED_SUBJECT_TOKEN_TYPES`); sending
    // `id_token` would be rejected with HTTP 400 `invalid_request`.
    //
    // `scope` and `requested_token_lifetime` are optional RFC 8693
    // §2.1 form fields. We append them only when the caller supplies a
    // value.
    let lifetime_str;
    let mut form_pairs: Vec<(&str, &str)> = vec![
        ("grant_type", EXCHANGE_GRANT_TYPE),
        ("subject_token", jwt),
        ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
        ("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN),
        ("client_id", client_id),
    ];
    if let Some(s) = scope {
        form_pairs.push(("scope", s));
    }
    if let Some(secs) = requested_lifetime_secs {
        lifetime_str = secs.to_string();
        form_pairs.push(("requested_token_lifetime", &lifetime_str));
    }

    let admin_requested = scope
        .map(|s| {
            s.split_whitespace()
                .any(|t| t.eq_ignore_ascii_case("admin"))
        })
        .unwrap_or(false);

    let resp = client
        .post(server_endpoint.as_str())
        .form(&form_pairs)
        .send()
        .await
        .context("POST token exchange")?;

    let status = resp.status();

    if status.is_success() {
        let body: ExchangeSuccessResponse = resp
            .json()
            .await
            .context("parsing token exchange response")?;
        let access_token = body
            .access_token
            .ok_or_else(|| anyhow!("exchange response missing access_token"))?;
        tracing::info!("token exchange succeeded; cli session minted");
        Ok(CliSessionToken {
            access_token,
            expires_in: body.expires_in,
            requested_lifetime_secs,
            admin_requested,
        })
    } else {
        // Read the body and parse the RFC 6749 error shape. hort's exchange
        // handler returns hardcoded English `error_description` strings
        // ("subject_token expired", "subject_token invalid", etc.) — never
        // an echo of the JWT — so surfacing the description to the operator
        // is safe. We log only the structured `error` code (not the
        // description) at `info!` to avoid carrying server-supplied text
        // into the trace stream.
        let body_bytes = resp.bytes().await.unwrap_or_default();
        let oauth = serde_json::from_slice::<ExchangeErrorResponse>(&body_bytes).ok();

        let (err_code, err_desc) = match oauth {
            Some(e) => (e.error, e.error_description),
            None => (None, None),
        };

        if let Some(code) = err_code.as_deref() {
            tracing::info!(error = %code, http_status = %status, "token exchange refused");
        } else {
            tracing::warn!(http_status = %status, "token exchange failed (no OAuth error body)");
        }

        let msg = match (err_code, err_desc) {
            (Some(c), Some(d)) => format!("{c}: {d}"),
            (Some(c), None) => c,
            (None, _) => format!("HTTP {status}"),
        };
        Err(anyhow!("{msg}"))
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Extracted so tests can redirect output to a `Vec<u8>` and verify content
/// independently of the live stderr path.
fn print_login_block(
    out: &mut impl std::io::Write,
    url: &str,
    user_code: &str,
) -> std::io::Result<()> {
    writeln!(out, "Open this URL in your browser to log in:")?;
    writeln!(out)?;
    writeln!(out, "    {url}")?;
    writeln!(out)?;
    writeln!(out, "Then enter this code: {user_code}")?;
    writeln!(out)?;
    writeln!(out, "(Polling for completion \u{2014} Ctrl-C to cancel)")?;
    Ok(())
}

fn build_anon_client() -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10));
    let builder = crate::client::apply_extra_ca_bundle(builder)?;
    builder.build().context("building anonymous HTTP client")
}

/// No-timeout variant used by tests that call `tokio::time::pause()` /
/// `#[tokio::test(start_paused = true)]`. reqwest's timer-based timeouts
/// interact badly with paused tokio time (even plain HTTP I/O to a local
/// mockito server triggers the connect_timeout because hyper's internal
/// machinery uses tokio timers). Production code always uses
/// `build_anon_client()` (with timeouts).
#[cfg(test)]
fn build_anon_client_no_timeout() -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder();
    let builder = crate::client::apply_extra_ca_bundle(builder)?;
    builder
        .build()
        .context("building anonymous HTTP client (no-timeout, test-only)")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Env-lock helpers
    //
    // Process-global lock serialises all tests that mutate HORT_OIDC_ALLOW_HTTP.
    // tokio::sync::Mutex is used so async tests can hold the guard across
    // .await points without triggering the await_holding_lock lint.
    // -----------------------------------------------------------------------

    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn lock_env_sync() -> tokio::sync::MutexGuard<'static, ()> {
        ENV_LOCK.blocking_lock()
    }

    async fn lock_env_async() -> tokio::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().await
    }

    // -----------------------------------------------------------------------
    // Tracing capture helper
    //
    // A MakeWriter that writes all tracing output into a shared buffer.
    // Used by the "JWT/token never logged" tripwire tests.
    // -----------------------------------------------------------------------

    #[derive(Clone)]
    struct CapturingWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturingWriter {
        fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
            let buf = Arc::new(Mutex::new(Vec::new()));
            (Self { buf: buf.clone() }, buf)
        }
    }

    struct CapturingWriterGuard {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for CapturingWriterGuard {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.lock().unwrap().write(data)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
        type Writer = CapturingWriterGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CapturingWriterGuard {
                buf: self.buf.clone(),
            }
        }
    }

    fn captured_string(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // Recording opener spy
    // -----------------------------------------------------------------------

    struct RecordingOpener {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingOpener {
        fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl BrowserOpener for RecordingOpener {
        fn open(&self, url: &str) -> Result<()> {
            self.calls.lock().unwrap().push(url.to_string());
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Sync validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_verification_uri_accepts_https() {
        let _g = lock_env_sync();
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");
        let url = validate_verification_uri("https://idp.example.com/device")
            .expect("https must be accepted");
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn validate_verification_uri_rejects_http_by_default() {
        let _g = lock_env_sync();
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");
        let err = validate_verification_uri("http://idp.example.com/device")
            .expect_err("http must be rejected without HORT_OIDC_ALLOW_HTTP");
        assert!(
            matches!(err, VerificationUriError::HttpDowngrade),
            "expected HttpDowngrade, got {err:?}"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn validate_verification_uri_accepts_http_when_HORT_OIDC_ALLOW_HTTP_set() {
        let _g = lock_env_sync();
        std::env::set_var("HORT_OIDC_ALLOW_HTTP", "1");
        let result = validate_verification_uri("http://idp.example.com/device");
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");
        let url = result.expect("http must be accepted when HORT_OIDC_ALLOW_HTTP is set");
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn validate_verification_uri_rejects_javascript_scheme() {
        let _g = lock_env_sync();
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");
        let err = validate_verification_uri("javascript:alert(1)")
            .expect_err("javascript: must be rejected");
        assert!(
            matches!(err, VerificationUriError::ForbiddenScheme { .. }),
            "expected ForbiddenScheme, got {err:?}"
        );
    }

    #[test]
    fn validate_verification_uri_rejects_file_scheme() {
        let _g = lock_env_sync();
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");
        let err =
            validate_verification_uri("file:///etc/passwd").expect_err("file: must be rejected");
        assert!(
            matches!(err, VerificationUriError::ForbiddenScheme { .. }),
            "expected ForbiddenScheme, got {err:?}"
        );
    }

    #[test]
    fn validate_verification_uri_rejects_data_scheme() {
        let _g = lock_env_sync();
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");
        let err = validate_verification_uri("data:text/html,<h1>pwned</h1>")
            .expect_err("data: must be rejected");
        assert!(
            matches!(err, VerificationUriError::ForbiddenScheme { .. }),
            "expected ForbiddenScheme, got {err:?}"
        );
    }

    #[test]
    fn validate_verification_uri_rejects_malformed_url() {
        let _g = lock_env_sync();
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");
        let err = validate_verification_uri("not a url at all !!!")
            .expect_err("malformed URL must be rejected");
        assert!(
            matches!(err, VerificationUriError::Malformed(_)),
            "expected Malformed, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Async fetch_idp_endpoints tests
    // -----------------------------------------------------------------------

    fn idp_config_body(device_url: &str, token_url: &str) -> String {
        // Includes `authorization_endpoint` — it is REQUIRED by OIDC Discovery
        // 1.0 §3, so any realistic Keycloak/Okta/Auth0/Entra response will
        // carry it. Tests that exercise an IdP doc *missing*
        // `authorization_endpoint` build their bodies inline.
        let auth_url = device_url.replace("/device", "/auth");
        format!(
            r#"{{"device_authorization_endpoint":"{device_url}","authorization_endpoint":"{auth_url}","token_endpoint":"{token_url}"}}"#
        )
    }

    #[tokio::test]
    async fn fetch_idp_endpoints_returns_both_urls() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let device_url = format!("{base}/protocol/openid-connect/auth/device");
        let token_url = format!("{base}/protocol/openid-connect/token");

        let _m = server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(idp_config_body(&device_url, &token_url))
            .create_async()
            .await;

        let issuer = Url::parse(&base).unwrap();
        let endpoints = fetch_idp_endpoints(&issuer).await.expect("should succeed");

        assert_eq!(
            endpoints.device_authorization_endpoint.as_str(),
            &device_url
        );
        assert_eq!(endpoints.token_endpoint.as_str(), &token_url);
    }

    #[tokio::test]
    async fn fetch_idp_endpoints_handles_issuer_without_trailing_slash() {
        // Regression: issuer `https://host/realms/kdp` (no trailing slash) used
        // to drop the last path segment via Url::join, producing
        // `/realms/.well-known/openid-configuration` (404 on Keycloak).
        let mut server = mockito::Server::new_async().await;
        let base = server.url(); // e.g. http://127.0.0.1:NNNN
        let device_url = format!("{base}/realms/kdp/protocol/openid-connect/auth/device");
        let token_url = format!("{base}/realms/kdp/protocol/openid-connect/token");

        let _m = server
            .mock("GET", "/realms/kdp/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(idp_config_body(&device_url, &token_url))
            .create_async()
            .await;

        // Issuer WITHOUT trailing slash — the Keycloak shape.
        let issuer = Url::parse(&format!("{base}/realms/kdp")).unwrap();
        let endpoints = fetch_idp_endpoints(&issuer)
            .await
            .expect("string-append must preserve realm path");
        assert_eq!(
            endpoints.device_authorization_endpoint.as_str(),
            &device_url
        );
    }

    #[tokio::test]
    async fn fetch_idp_endpoints_handles_issuer_with_trailing_slash() {
        // Symmetry — both shapes must reach the same endpoint.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let device_url = format!("{base}/realms/kdp/protocol/openid-connect/auth/device");
        let token_url = format!("{base}/realms/kdp/protocol/openid-connect/token");

        let _m = server
            .mock("GET", "/realms/kdp/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(idp_config_body(&device_url, &token_url))
            .create_async()
            .await;

        let issuer = Url::parse(&format!("{base}/realms/kdp/")).unwrap();
        let endpoints = fetch_idp_endpoints(&issuer)
            .await
            .expect("trailing-slash issuer must also work");
        assert_eq!(
            endpoints.device_authorization_endpoint.as_str(),
            &device_url
        );
    }

    #[tokio::test]
    async fn fetch_idp_endpoints_rejects_missing_authorization_endpoint() {
        // OIDC Discovery 1.0 §3 marks `authorization_endpoint` REQUIRED; an
        // IdP doc that omits it cannot serve the loopback flow and must fail
        // fast at discovery time.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let device_url = format!("{base}/protocol/openid-connect/auth/device");
        let token_url = format!("{base}/protocol/openid-connect/token");

        let _m = server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"device_authorization_endpoint":"{device_url}","token_endpoint":"{token_url}"}}"#
            ))
            .create_async()
            .await;

        let issuer = Url::parse(&base).unwrap();
        let err = fetch_idp_endpoints(&issuer)
            .await
            .expect_err("missing authorization_endpoint must error");
        assert!(
            err.to_string().contains("authorization_endpoint"),
            "error must mention authorization_endpoint: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_idp_endpoints_rejects_missing_device_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let token_url = format!("{base}/protocol/openid-connect/token");

        let _m = server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(r#"{{"token_endpoint":"{token_url}"}}"#))
            .create_async()
            .await;

        let issuer = Url::parse(&base).unwrap();
        let err = fetch_idp_endpoints(&issuer)
            .await
            .expect_err("missing device_authorization_endpoint must error");
        assert!(
            err.to_string().contains("device_authorization_endpoint"),
            "error must mention device_authorization_endpoint: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Device flow test helpers
    // -----------------------------------------------------------------------

    /// Build a minimal device auth response JSON body.
    fn device_auth_body(
        device_code: &str,
        user_code: &str,
        verification_uri: &str,
        verification_uri_complete: Option<&str>,
        expires_in: Option<u64>,
        interval: Option<u64>,
    ) -> String {
        let mut s = format!(
            r#"{{"device_code":"{device_code}","user_code":"{user_code}","verification_uri":"{verification_uri}""#,
        );
        if let Some(vc) = verification_uri_complete {
            s.push_str(&format!(r#","verification_uri_complete":"{vc}""#));
        }
        if let Some(ei) = expires_in {
            s.push_str(&format!(r#","expires_in":{ei}"#));
        }
        if let Some(iv) = interval {
            s.push_str(&format!(r#","interval":{iv}"#));
        }
        s.push('}');
        s
    }

    fn pending_body() -> &'static str {
        r#"{"error":"authorization_pending"}"#
    }

    fn slow_down_body() -> &'static str {
        r#"{"error":"slow_down"}"#
    }

    fn access_denied_body() -> &'static str {
        r#"{"error":"access_denied"}"#
    }

    fn expired_token_body() -> &'static str {
        r#"{"error":"expired_token"}"#
    }

    fn success_token_body(token: &str) -> String {
        // The CLI extracts `access_token` (not `id_token`) from the IdP poll
        // response. The standards-shaped fix for missing-`sub`-on-
        // access_token is an IdP-side claim mapper, NOT a client-side
        // workaround switching to id_token; see
        // `docs/operator/idp-setup.md`. Mock responses include both fields
        // so the helper stays robust against an accidental contract revert,
        // but only `access_token` is required for the test to succeed.
        format!(r#"{{"access_token":"{token}","id_token":"unused-by-cli"}}"#)
    }

    /// Build IdpEndpoints pointing at a mockito server's /device and /token.
    fn mk_idp(base: &str) -> IdpEndpoints {
        IdpEndpoints {
            device_authorization_endpoint: Url::parse(&format!("{base}/device")).unwrap(),
            authorization_endpoint: Url::parse(&format!("{base}/auth")).unwrap(),
            token_endpoint: Url::parse(&format!("{base}/token")).unwrap(),
        }
    }

    // -----------------------------------------------------------------------
    // Device flow tests
    //
    // All verification URIs use static `https://` literals -- they are never
    // resolved (NoopOpener or RecordingOpener does not open URLs). Only the
    // device_authorization_endpoint and token_endpoint point at real mockito
    // servers. Tests that must control timing use tokio::time::pause() with
    // a select!/advance loop; tests that only care about error-code responses
    // use interval=0 so tokio::time::sleep(0) yields immediately.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn device_flow_returns_jwt_on_immediate_success() {
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let jwt = "eyJhbGciOiJSUzI1NiJ9.FAKE_JWT.signature";

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code_123",
                "USER-CODE",
                "https://idp.example.com/activate",
                Some("https://idp.example.com/activate?user_code=USER-CODE"),
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(success_token_body(jwt))
            .create_async()
            .await;

        let result = run_device_flow(&mk_idp(&base), "hort-cli", &NoopOpener)
            .await
            .expect("should succeed");
        assert_eq!(result, jwt);
    }

    #[tokio::test]
    async fn device_flow_polls_through_authorization_pending() {
        // interval=0 means tokio::time::sleep(0) completes on the first yield
        // without needing tokio::time::advance(); no time pausing required.
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let jwt = "eyJhbGci.POLLED_JWT.sig";

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "ABCD-1234",
                "https://idp.example.com/activate",
                None,
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        for _ in 0..3 {
            server
                .mock("POST", "/token")
                .with_status(400)
                .with_header("content-type", "application/json")
                .with_body(pending_body())
                .create_async()
                .await;
        }
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(success_token_body(jwt))
            .create_async()
            .await;

        let result = run_device_flow(&mk_idp(&base), "hort-cli", &NoopOpener)
            .await
            .expect("should succeed after polling");
        assert_eq!(result, jwt);
    }

    #[tokio::test(start_paused = true)]
    async fn device_flow_handles_slow_down_by_extending_interval() {
        // Start at interval=0; after slow_down the interval becomes 5 s.
        // start_paused=true lets tokio auto-advance through the 5-second sleep
        // without real wall-clock waiting, while still allowing HTTP I/O to
        // complete (auto-advance fires only when all futures are on timers).
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let jwt = "eyJhbGci.SLOW_DOWN_JWT.sig";

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "EFGH-5678",
                "https://idp.example.com/activate",
                None,
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(slow_down_body())
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(success_token_body(jwt))
            .create_async()
            .await;

        // Use the no-timeout client: reqwest's timer-based connect_timeout races
        // with tokio's auto-advance during the zero-duration I/O poll, causing
        // spurious timeouts. Production always uses build_anon_client() (with timeout).
        let client = build_anon_client_no_timeout().expect("builds");
        let noop = NoopOpener;
        let idp = mk_idp(&base);
        let result = run_device_flow_with_client(client, &idp, "hort-cli", &noop).await;
        assert_eq!(result.expect("should succeed after slow_down"), jwt);
    }

    #[tokio::test]
    async fn device_flow_returns_user_cancelled_on_access_denied() {
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "USER-CODE",
                "https://idp.example.com/activate",
                None,
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(access_denied_body())
            .create_async()
            .await;

        let err = run_device_flow(&mk_idp(&base), "hort-cli", &NoopOpener)
            .await
            .expect_err("access_denied must return Err");
        assert!(
            err.to_string().contains("cancelled"),
            "error must mention cancelled: {err}"
        );
    }

    #[tokio::test]
    async fn device_flow_returns_timed_out_on_expired_token() {
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "USER-CODE",
                "https://idp.example.com/activate",
                None,
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(expired_token_body())
            .create_async()
            .await;

        let err = run_device_flow(&mk_idp(&base), "hort-cli", &NoopOpener)
            .await
            .expect_err("expired_token must return Err");
        assert!(
            err.to_string().contains("timed out"),
            "error must mention timed out: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn device_flow_caps_total_wait_at_15_minutes() {
        // Uses start_paused=true so tokio auto-advances through each 10-second
        // sleep (fires when all futures are blocked on timers, not I/O).
        // After ~91 sleeps x 10 s = 910 s, the 900-second wall-clock cap fires.
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "ABCD",
                "https://idp.example.com/activate",
                None,
                Some(9000), // IdP claims 2.5 h; wall-clock cap is 15 min
                Some(10),   // 10-second interval
            ))
            .create_async()
            .await;
        // Always pending -- loop must exit via the 15-min cap.
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(pending_body())
            .expect_at_least(1)
            .create_async()
            .await;

        // Use the no-timeout client: reqwest's timer-based connect_timeout races
        // with tokio's auto-advance during the zero-duration I/O poll, causing
        // spurious timeouts. Production always uses build_anon_client() (with timeout).
        let client = build_anon_client_no_timeout().expect("builds");
        let noop = NoopOpener;
        let idp = mk_idp(&base);
        let err = run_device_flow_with_client(client, &idp, "hort-cli", &noop)
            .await
            .expect_err("must timeout at 15-min wall-clock cap");

        assert!(
            err.to_string().contains("timed out") || err.to_string().contains("15 minutes"),
            "error must mention timeout: {err}"
        );
    }

    #[test]
    fn print_login_block_writes_url_and_code() {
        let mut buf = Vec::new();
        print_login_block(
            &mut buf,
            "https://idp.example.com/device?code=ABC",
            "ABC-DEF",
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("https://idp.example.com/device?code=ABC"),
            "URL must appear: {out}"
        );
        assert!(out.contains("ABC-DEF"), "user code must appear: {out}");
        assert!(
            out.contains("Polling for completion"),
            "polling note must appear: {out}"
        );
        assert!(out.contains('\u{2014}'), "em-dash must appear: {out}");
    }

    #[tokio::test]
    async fn device_flow_calls_opener_with_verification_uri_complete_when_present() {
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        const PLAIN_URI: &str = "https://idp.example.com/activate";
        const COMPLETE_URI: &str = "https://idp.example.com/activate?user_code=XYZ-9999";
        let jwt = "eyJ.COMPLETE_URI_JWT.sig";

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "XYZ-9999",
                PLAIN_URI,
                Some(COMPLETE_URI),
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(success_token_body(jwt))
            .create_async()
            .await;

        let (recorder, calls) = RecordingOpener::new();
        run_device_flow(&mk_idp(&base), "hort-cli", &recorder)
            .await
            .expect("should succeed");

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1, "opener must be called exactly once");
        assert_eq!(
            recorded[0], COMPLETE_URI,
            "opener must be called with verification_uri_complete, not plain uri"
        );
    }

    #[tokio::test]
    async fn device_flow_aborts_when_verification_uri_has_forbidden_scheme() {
        // verification_uri_complete = javascript: (bad),
        // verification_uri = https:// (safe) => fallback succeeds; the opener
        // is called with the safe URI, never with the javascript: one.
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        const SAFE_URI: &str = "https://idp.example.com/activate";
        let jwt = "eyJ.FALLBACK_JWT.sig";

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "USER-CODE",
                SAFE_URI,
                Some("javascript:alert(1)"),
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(success_token_body(jwt))
            .create_async()
            .await;

        let (recorder, calls) = RecordingOpener::new();
        let result = run_device_flow(&mk_idp(&base), "hort-cli", &recorder).await;

        assert!(
            result.is_ok(),
            "should fall back to safe verification_uri: {result:?}"
        );
        let recorded = calls.lock().unwrap();
        if !recorded.is_empty() {
            assert_ne!(
                recorded[0], "javascript:alert(1)",
                "opener must never be called with javascript: URL"
            );
            assert_eq!(
                recorded[0], SAFE_URI,
                "opener must be called with the safe fallback URI"
            );
        }
    }

    #[tokio::test]
    async fn device_flow_aborts_when_both_verification_uris_have_forbidden_schemes() {
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "USER-CODE",
                "javascript:steal_plain()",
                Some("javascript:alert(1)"),
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;

        let (recorder, calls) = RecordingOpener::new();
        let err = run_device_flow(&mk_idp(&base), "hort-cli", &recorder)
            .await
            .expect_err("both bad schemes must cause Err");

        assert!(
            err.to_string().contains("rejected") || err.to_string().contains("scheme"),
            "error must mention rejection: {err}"
        );
        let recorded = calls.lock().unwrap();
        assert!(
            recorded.is_empty(),
            "opener must not be called when all URIs have bad schemes"
        );
    }

    #[tokio::test]
    async fn device_flow_does_not_log_jwt_at_any_level() {
        // Install a capturing subscriber via set_default (returns a scoped
        // guard). This is async-safe: set_default is per-thread and
        // #[tokio::test] is single-threaded, so the subscriber is active for
        // the entire async function body without blocking the runtime.
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        const SECRET_JWT: &str = "eyJhbGciOiJSUzI1NiJ9.SUPER_SECRET_JWT_NEVER_LOG_THIS.sig";

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "USER-CODE",
                "https://idp.example.com/activate",
                None,
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(success_token_body(SECRET_JWT))
            .create_async()
            .await;

        let (writer, buf) = CapturingWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_max_level(tracing::Level::TRACE)
            .finish();

        // set_default is scoped to this thread; works correctly in
        // single-threaded tokio::test without blocking the runtime.
        let _sub_guard = tracing::subscriber::set_default(subscriber);
        let result = run_device_flow(&mk_idp(&base), "hort-cli", &NoopOpener).await;
        drop(_sub_guard);

        assert!(result.is_ok(), "flow should succeed: {result:?}");
        let captured = captured_string(&buf);
        assert!(
            !captured.contains(SECRET_JWT),
            "JWT must never appear in tracing output. Captured:\n{captured}"
        );
    }

    // -----------------------------------------------------------------------
    // Exchange tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn exchange_posts_form_encoded_with_required_fields() {
        // Use mockito match_body to assert the exact form-encoded payload.
        // reqwest percent-encodes special chars; we use regex matchers so
        // field order and encoding variations don't matter.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        const TEST_JWT: &str = "eyJhbGci.TEST_JWT.sig";

        let _m = server
            .mock("POST", "/api/v1/auth/exchange")
            .match_header(
                "content-type",
                mockito::Matcher::Regex("application/x-www-form-urlencoded".to_string()),
            )
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("grant_type=".to_string()),
                mockito::Matcher::Regex("subject_token=".to_string()),
                mockito::Matcher::Regex("subject_token_type=".to_string()),
                mockito::Matcher::Regex("requested_token_type=".to_string()),
                mockito::Matcher::Regex("client_id=".to_string()),
                // Verify the grant_type URN is present (encoded)
                mockito::Matcher::Regex("token-exchange".to_string()),
                // Lock the wire shape: subject_token_type MUST be the RFC
                // 8693 access_token URI (percent-encoded `:` → `%3A`).
                // `id_token` was considered and rejected; the
                // standards-shaped fix for missing-`sub`-on-access_token
                // is an IdP-side claim mapper (see
                // `docs/operator/idp-setup.md`), NOT a client-side switch
                // to id_token. Switching back to id_token would
                // re-introduce audience-binding ambiguity (id_token's
                // `aud = client_id` vs access_token's
                // `aud = resource_server`); this assertion is the canary.
                mockito::Matcher::Regex(
                    "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
                        .to_string(),
                ),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"hort_cli_result_token","expires_in":2592000}"#)
            .create_async()
            .await;

        let endpoint = Url::parse(&format!("{base}/api/v1/auth/exchange")).unwrap();
        let token = exchange(&endpoint, TEST_JWT, "hort-cli/0.1.0", None, None)
            .await
            .expect("exchange should succeed");

        assert_eq!(token.access_token, "hort_cli_result_token");
        assert_eq!(token.expires_in, Some(2592000));
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn exchange_returns_cli_session_token_on_success() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _m = server
            .mock("POST", "/api/v1/auth/exchange")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"hort_cli_abc123","expires_in":86400}"#)
            .create_async()
            .await;

        let endpoint = Url::parse(&format!("{base}/api/v1/auth/exchange")).unwrap();
        let token = exchange(&endpoint, "eyJ.JWT.sig", "hort-cli/0.1.0", None, None)
            .await
            .expect("exchange should succeed");

        assert_eq!(token.access_token, "hort_cli_abc123");
        assert_eq!(token.expires_in, Some(86400));
    }

    #[tokio::test]
    async fn exchange_surfaces_oauth_error_response() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _m = server
            .mock("POST", "/api/v1/auth/exchange")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"invalid_grant","error_description":"JWT has expired"}"#)
            .create_async()
            .await;

        let endpoint = Url::parse(&format!("{base}/api/v1/auth/exchange")).unwrap();
        let err = exchange(&endpoint, "eyJ.EXPIRED.sig", "hort-cli/0.1.0", None, None)
            .await
            .expect_err("non-200 must return Err");

        let msg = err.to_string();
        assert!(
            msg.contains("invalid_grant"),
            "error must surface the OAuth error code: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // IdP response missing access_token
    //
    // The CLI extracts `access_token` (not `id_token`) from the device-flow
    // poll response. When the IdP returns 200 with only `id_token` (no
    // `access_token`) — typically because the OAuth client's `sub` claim
    // mapper is missing from access_tokens — the CLI surfaces a specific
    // operator-pointer error message pointing at
    // `docs/operator/idp-setup.md`. This test pins both the error path and
    // the exact message text.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn device_flow_surfaces_specific_error_when_idp_returns_only_id_token() {
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "USER-CODE",
                "https://idp.example.com/activate",
                None,
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        // IdP returns ONLY id_token; no access_token field at all.
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id_token":"eyJ.IDTOKEN_ONLY.sig"}"#)
            .create_async()
            .await;

        let err = run_device_flow(&mk_idp(&base), "hort-cli", &NoopOpener)
            .await
            .expect_err("missing access_token must return Err");

        let msg = err.to_string();
        assert!(
            msg.contains("IdP returned no access_token"),
            "error must mention 'IdP returned no access_token': {msg}"
        );
        assert!(
            msg.contains("`sub` claim"),
            "error must mention the `sub` claim requirement: {msg}"
        );
        assert!(
            msg.contains("docs/operator/idp-setup.md"),
            "error must point at docs/operator/idp-setup.md: {msg}"
        );
    }

    // Confirm the happy path: an IdP that returns access_token (with or
    // without id_token) succeeds and the CLI returns that access_token
    // as the subject_token for the downstream `/exchange` call. This
    // complements `device_flow_returns_jwt_on_immediate_success` (which
    // uses the test helper that also includes id_token); this test
    // pins the access_token-only variant explicitly.
    #[tokio::test]
    async fn device_flow_extracts_access_token_when_only_access_token_present() {
        let _g = lock_env_async().await;
        std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.ACCESS_TOKEN_ONLY.sig";

        server
            .mock("POST", "/device")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(device_auth_body(
                "dev_code",
                "USER-CODE",
                "https://idp.example.com/activate",
                None,
                Some(300),
                Some(0),
            ))
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(r#"{{"access_token":"{TOKEN}"}}"#))
            .create_async()
            .await;

        let result = run_device_flow(&mk_idp(&base), "hort-cli", &NoopOpener)
            .await
            .expect("access_token-only response must succeed");
        assert_eq!(result, TOKEN);
    }

    #[tokio::test]
    async fn exchange_does_not_log_token_at_any_level() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        const SECRET_TOKEN: &str = "hort_cli_SUPER_SECRET_TOKEN_NEVER_LOG";

        let _m = server
            .mock("POST", "/api/v1/auth/exchange")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"access_token":"{SECRET_TOKEN}","expires_in":2592000}}"#
            ))
            .create_async()
            .await;

        let endpoint = Url::parse(&format!("{base}/api/v1/auth/exchange")).unwrap();

        let (writer, buf) = CapturingWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_max_level(tracing::Level::TRACE)
            .finish();

        let _sub_guard = tracing::subscriber::set_default(subscriber);
        let result = exchange(&endpoint, "eyJ.JWT.sig", "hort-cli/0.1.0", None, None).await;
        drop(_sub_guard);

        assert!(result.is_ok(), "exchange should succeed: {result:?}");
        let captured = captured_string(&buf);
        assert!(
            !captured.contains(SECRET_TOKEN),
            "hort_cli_* token must never appear in tracing output. Captured:\n{captured}"
        );
    }
}
