//! `hort-cli auth login` — auto-detect OIDC vs paste, prompt, persist.
//!
//! # Behaviour
//!
//! Without flags, `run` GETs `/.well-known/hort-client-config`:
//! - 200 → RFC 8628 device flow + RFC 8693 exchange (OIDC branch).
//! - 404 → fall through to paste flow.
//! - Malformed → hard error (operator must fix the server config).
//! - Network error → hard error with retry hint.
//!
//! `--paste` forces paste flow, skipping discovery.
//! `--oidc` forces OIDC; hard errors if discovery returns 404 or Malformed.
//! `--no-browser` swaps the production `WebBrowserOpener` for `NoopOpener`.
//! `--paste` and `--oidc` are clap-level mutually exclusive.
//!
//! # Token redaction
//!
//! The token string is NEVER passed to a `tracing` macro. It flows only
//! through `read_token`, the `reqwest` default-header path (already
//! mirrored in `AkClient`), and the TOML serialise-to-disk path.

use std::io::{self, BufRead, IsTerminal};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use crate::auth::discovery::{AkClientConfig, DiscoveryOutcome};
use crate::auth::loopback::{self, LoopbackError};
use crate::auth::oidc::{BrowserOpener, NoopOpener};
use crate::auth::WhoamiResponse;
use crate::config::{config_file_path, load_effective_config};

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Explicit selector for the login flow.
///
/// `auto` is the default and consults `is_headless_environment` plus
/// loopback-bind availability. The other variants pin the flow regardless
/// of environment hints.
///
/// Migration matrix:
///
/// | flag combination              | resolved flow                                   |
/// |-------------------------------|-------------------------------------------------|
/// | (none)                        | `Auto` — decision tree picks loopback/device/paste |
/// | `--flow=loopback`             | `Loopback` (hard error if listener binding fails)  |
/// | `--flow=device`               | `Device` (force RFC 8628)                           |
/// | `--flow=paste` or `--paste`   | `Paste` (skip discovery)                            |
/// | `--oidc`                      | `Auto` restricted to {Loopback, Device} — paste forbidden |
/// | `--no-browser`                | `Device` (the URL-print-only path)                  |
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Flow {
    /// Pick a flow based on environment hints. Default.
    #[default]
    Auto,
    /// Force the RFC 8252 loopback flow (desktop default).
    Loopback,
    /// Force the RFC 8628 device flow.
    Device,
    /// Force the paste-the-token-yourself flow.
    Paste,
}

#[derive(clap::Args, Debug)]
pub struct LoginArgs {
    /// Validate the pasted token by calling GET /api/v1/auth/whoami.
    /// Warnings are emitted for svc_account / pat kinds; 401 aborts.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub validate: bool,

    /// Server base URL (overrides HORT_SERVER and config file).
    #[arg(long, env = "HORT_SERVER")]
    pub server: Option<String>,

    /// Skip discovery, force the paste-token flow.
    #[arg(long, conflicts_with = "oidc")]
    pub paste: bool,

    /// Force OIDC; error if discovery returns 404 or malformed.
    #[arg(long, conflicts_with = "paste")]
    pub oidc: bool,

    /// Skip the browser auto-open attempt; print URL only. Implies
    /// device-flow when set, since the loopback flow requires a browser.
    #[arg(long)]
    pub no_browser: bool,

    /// Explicit flow selector. Defaults to `auto`, which picks loopback on
    /// desktops, device on headless contexts, and paste when the server
    /// doesn't advertise OIDC.
    #[arg(long, value_enum, default_value_t = Flow::Auto)]
    pub flow: Flow,

    /// Request the `admin` permission scope. Requires the server to have
    /// HORT_TOKEN_ALLOW_ADMIN=true AND the caller to have admin authority.
    /// The resulting session is bounded to ≤1 h regardless of
    /// `--expires-in`. See
    /// docs/architecture/how-to/using-hort-cli-with-admin-ops.md.
    #[arg(long)]
    pub admin: bool,

    /// Requested session lifetime. Accepts go-style duration strings (1h,
    /// 30m, 4h, 24h). Defaults to 1 h. Server clamps to its per-cap
    /// maximum; hort-cli surfaces the actual issued lifetime in its
    /// post-login output.
    #[arg(long, value_parser = parse_duration_arg)]
    pub expires_in: Option<std::time::Duration>,
}

/// Parse `--expires-in` duration strings via humantime.
/// Returns a clap-friendly Result<Duration, String>; clap surfaces the
/// error verbatim in its usage hint when the operator passes an
/// unparseable value.
fn parse_duration_arg(s: &str) -> Result<std::time::Duration, String> {
    humantime::parse_duration(s)
        .map_err(|e| format!("invalid duration '{s}': {e} (expected e.g. 1h, 30m, 4h, 24h)"))
}

/// Caller-supplied scope + lifetime for the `/exchange` form body.
/// Constructed once in the top-level login entry point from [`LoginArgs`]
/// and threaded through to [`crate::auth::oidc::exchange`] via each
/// subflow.
#[derive(Debug, Clone, Default)]
pub struct SessionRequest {
    /// `scope` form-field value. `None` ⇒ omit the field; server applies
    /// its default `[Read, Write, Delete]`. `Some("admin read write
    /// delete")` requests admin scope.
    pub scope: Option<String>,
    /// `requested_token_lifetime` form-field value (seconds). `None` ⇒
    /// omit; server defaults to 1 h.
    pub requested_lifetime_secs: Option<u64>,
}

impl SessionRequest {
    /// Build from CLI flags. `--admin` widens the scope; `--expires-in`
    /// supplies the lifetime in seconds.
    pub fn from_login_args(args: &LoginArgs) -> Self {
        let scope = if args.admin {
            // Wire shape: space-separated.
            // Order doesn't matter to the server's parser; `admin`
            // first reads naturally for operators eyeballing logs.
            Some("admin read write delete".to_string())
        } else {
            None
        };
        let requested_lifetime_secs = args.expires_in.map(|d| d.as_secs());
        Self {
            scope,
            requested_lifetime_secs,
        }
    }

    /// True if either field is set — i.e. the caller deviated from the
    /// server's defaults. Used by the post-login output to decide
    /// whether to render the `note:` clamp line.
    pub fn deviates_from_defaults(&self) -> bool {
        self.scope.is_some() || self.requested_lifetime_secs.is_some()
    }
}

// ---------------------------------------------------------------------------
// Entry point (production)
// ---------------------------------------------------------------------------

pub async fn run(args: LoginArgs) -> Result<ExitCode> {
    run_with_opener_factory(args, default_opener_factory).await
}

fn default_opener_factory(no_browser: bool) -> Box<dyn BrowserOpener> {
    if no_browser || is_headless_environment() {
        Box::new(NoopOpener)
    } else {
        Box::new(WebBrowserOpener)
    }
}

/// Inner implementation — tested via `run_with_opener_factory`.
///
/// `opener_factory` receives the `no_browser` flag and returns the opener to
/// use. Integration tests inject a spy or `NoopOpener`; production passes
/// `default_opener_factory`.
pub async fn run_with_opener_factory<F>(args: LoginArgs, opener_factory: F) -> Result<ExitCode>
where
    F: Fn(bool) -> Box<dyn BrowserOpener>,
{
    run_with_opener_factory_and_reader(
        args,
        opener_factory,
        &mut io::stdin().lock(),
        io::stdin().is_terminal(),
    )
    .await
}

/// Testable variant of [`run_with_opener_factory`] that accepts an injectable
/// stdin reader and TTY flag for the paste flow.
///
/// `reader` is read from only when the paste flow is entered (either via
/// `--paste` or auto-detect 404 fall-through). `use_masked` controls whether
/// `rpassword` masking is used (`true` = TTY / production path) or the plain
/// reader is used (`false` = CI / test path).
pub async fn run_with_opener_factory_and_reader<F, R>(
    args: LoginArgs,
    opener_factory: F,
    reader: &mut R,
    use_masked: bool,
) -> Result<ExitCode>
where
    F: Fn(bool) -> Box<dyn BrowserOpener>,
    R: BufRead,
{
    let server_url = resolve_server_url(args.server.clone())?;

    // `--paste` (legacy) and `--flow=paste` both short-circuit before any
    // network I/O. The clap `conflicts_with` already excludes
    // `--paste && --oidc`; the explicit selector `Flow::Paste` is preserved
    // even alongside `--oidc` because the operator chose it explicitly.
    if args.paste || args.flow == Flow::Paste {
        return run_paste_flow(&server_url, args.validate, reader, use_masked).await;
    }

    let server_base = server_url
        .parse::<url::Url>()
        .context("parsing server URL")?;

    // Build the per-session request (scope + lifetime) once and thread it
    // through the subflows. Paste flow ignores it (the operator pastes a
    // long-lived PAT or whatever — no exchange call is made).
    let session_request = SessionRequest::from_login_args(&args);

    if args.oidc {
        // Forced OIDC — hard error if not available.
        return match crate::auth::discovery::fetch_client_config(&server_base).await {
            Ok(DiscoveryOutcome::Available(cfg)) => {
                dispatch_oidc(
                    &server_url,
                    &cfg,
                    args.no_browser,
                    args.flow,
                    &session_request,
                    &opener_factory,
                )
                .await
            }
            Ok(DiscoveryOutcome::NotEnabled) => {
                eprintln!("hort-cli: --oidc requested but server does not advertise OIDC login.");
                Ok(ExitCode::from(1))
            }
            Ok(DiscoveryOutcome::Malformed { reason }) => {
                eprintln!("hort-cli: discovery doc malformed: {reason}. Use --paste to skip OIDC.");
                Ok(ExitCode::from(1))
            }
            Err(e) => {
                report_discovery_error(&server_url, &e);
                Ok(ExitCode::from(1))
            }
        };
    }

    match crate::auth::discovery::fetch_client_config(&server_base).await {
        Ok(DiscoveryOutcome::Available(cfg)) => {
            dispatch_oidc(
                &server_url,
                &cfg,
                args.no_browser,
                args.flow,
                &session_request,
                &opener_factory,
            )
            .await
        }
        Ok(DiscoveryOutcome::NotEnabled) => {
            // Silent fall-through — paste is the configured v1 path.
            tracing::debug!("hort-client-config returned 404; falling through to paste flow");
            run_paste_flow(&server_url, args.validate, reader, use_masked).await
        }
        Ok(DiscoveryOutcome::Malformed { reason }) => {
            eprintln!("hort-cli: discovery doc malformed: {reason}. Use --paste to skip OIDC.");
            Ok(ExitCode::from(1))
        }
        Err(e) => {
            report_discovery_error(&server_url, &e);
            Ok(ExitCode::from(1))
        }
    }
}

/// Print a user-facing error for a failed discovery fetch. Distinguishes
/// TLS certificate failures (which need `HORT_EXTRA_CA_BUNDLE`) from
/// generic network errors so the operator gets an actionable message.
fn report_discovery_error(server_url: &str, err: &anyhow::Error) {
    if crate::client::is_tls_cert_error(err) {
        eprintln!("hort-cli: TLS error contacting hort server at {server_url}: {err}");
        eprintln!(
            "       If the server uses an internal CA, set \
             HORT_EXTRA_CA_BUNDLE=/path/to/ca.pem and retry."
        );
    } else {
        eprintln!("hort-cli: discovery network error: {err}. Retry, or use --paste.");
    }
}

// ---------------------------------------------------------------------------
// OIDC branch
// ---------------------------------------------------------------------------

async fn dispatch_oidc<F>(
    server_url: &str,
    cfg: &AkClientConfig,
    no_browser: bool,
    flow: Flow,
    session_request: &SessionRequest,
    opener_factory: &F,
) -> Result<ExitCode>
where
    F: Fn(bool) -> Box<dyn BrowserOpener>,
{
    let headless = is_headless_environment();
    if !no_browser && headless {
        tracing::info!(
            "hort-cli: headless environment detected; not auto-opening browser. \
             The login URL will be printed below."
        );
    }
    let opener = opener_factory(no_browser);

    // Pick the OIDC subflow. The dispatcher contract:
    //   - `--no-browser` always means device flow (the URL-print-only path).
    //   - `--flow=device` forces device flow regardless of other hints.
    //   - `--flow=loopback` forces loopback; bind failure is a hard error.
    //   - `Flow::Auto` consults the decision tree:
    //       headless                  → device
    //       loopback bind succeeds   → loopback
    //       loopback bind fails       → device (with info!)
    let resolved = resolve_oidc_subflow(flow, no_browser, headless);
    match resolved {
        OidcSubflow::Device => {
            tracing::info!(flow = "device", "running device flow");
            run_oidc_device_flow(server_url, cfg, session_request, opener.as_ref()).await
        }
        OidcSubflow::Loopback => {
            tracing::info!(flow = "loopback", "running loopback flow");
            run_oidc_loopback_flow(
                server_url,
                cfg,
                session_request,
                opener.as_ref(),
                /* loopback_forced */ flow == Flow::Loopback,
            )
            .await
        }
    }
}

/// Internal resolution result. `auto` is collapsed into one of two concrete
/// subflows (device or loopback); paste is handled earlier and never reaches
/// this resolver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OidcSubflow {
    Device,
    Loopback,
}

/// Decide between loopback and device. Pure — `headless` is the
/// `is_headless_environment()` result passed in by the caller.
fn resolve_oidc_subflow(flow: Flow, no_browser: bool, headless: bool) -> OidcSubflow {
    if no_browser {
        // No browser available → loopback is impossible (the user can never
        // reach the loopback callback). Force device flow.
        return OidcSubflow::Device;
    }
    match flow {
        Flow::Device => OidcSubflow::Device,
        Flow::Loopback => OidcSubflow::Loopback,
        Flow::Auto => {
            if headless {
                OidcSubflow::Device
            } else {
                // Try a bind probe; if it fails the caller will swap us back
                // to device with an info! log. The bind probe lives in the
                // run path because it consumes a port.
                OidcSubflow::Loopback
            }
        }
        // Paste is handled upstream; treat as Device for defence in depth.
        Flow::Paste => OidcSubflow::Device,
    }
}

/// Run the full OIDC device flow + exchange, then persist the token.
///
/// `opener` is either the production `WebBrowserOpener` or a test spy/`NoopOpener`.
async fn run_oidc_device_flow(
    server_url: &str,
    cfg: &AkClientConfig,
    session_request: &SessionRequest,
    opener: &dyn BrowserOpener,
) -> Result<ExitCode> {
    let endpoints = match crate::auth::oidc::fetch_idp_endpoints(&cfg.idp.issuer).await {
        Ok(ep) => ep,
        Err(e) => {
            if crate::client::is_tls_cert_error(&e) {
                eprintln!(
                    "hort-cli: TLS error contacting IdP at {}: {e}",
                    cfg.idp.issuer
                );
                eprintln!(
                    "       If the IdP uses an internal CA, set \
                     HORT_EXTRA_CA_BUNDLE=/path/to/ca.pem and retry."
                );
            } else {
                eprintln!(
                    "hort-cli: failed to fetch IdP configuration from {}: {e}",
                    cfg.idp.issuer
                );
                eprintln!("       Verify the IdP issuer URL with your administrator.");
            }
            // debug! (not info!) so the eprintln above isn't duplicated on
            // stderr under the default tracing-subscriber level.
            tracing::debug!(issuer = %cfg.idp.issuer, error = %e, "IdP endpoint fetch failed");
            return Ok(ExitCode::from(1));
        }
    };

    let jwt = match crate::auth::oidc::run_device_flow(&endpoints, &cfg.idp.client_id, opener).await
    {
        Ok(j) => j,
        Err(e) => {
            eprintln!("hort-cli: {e}");
            return Ok(ExitCode::from(1));
        }
    };

    let client_id = format!("hort-cli/{}", env!("CARGO_PKG_VERSION"));
    let token = match crate::auth::oidc::exchange(
        &cfg.exchange.endpoint,
        &jwt,
        &client_id,
        session_request.scope.as_deref(),
        session_request.requested_lifetime_secs,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hort-cli: server rejected exchange: {e}");
            return Ok(ExitCode::from(1));
        }
    };

    persist_token(server_url, &token.access_token).context("saving token to config file")?;
    tracing::info!("oidc login succeeded");

    print_post_login(server_url, &token, &mut io::stdout());

    Ok(ExitCode::SUCCESS)
}

/// Run the RFC 8252 loopback flow + RFC 8693 exchange.
///
/// `loopback_forced` is `true` when the operator explicitly chose
/// `--flow=loopback`; in that case `LoopbackUnavailable` is a hard error
/// rather than the fallback-to-device path.
async fn run_oidc_loopback_flow(
    server_url: &str,
    cfg: &AkClientConfig,
    session_request: &SessionRequest,
    opener: &dyn BrowserOpener,
    loopback_forced: bool,
) -> Result<ExitCode> {
    let endpoints = match crate::auth::oidc::fetch_idp_endpoints(&cfg.idp.issuer).await {
        Ok(ep) => ep,
        Err(e) => {
            if crate::client::is_tls_cert_error(&e) {
                eprintln!(
                    "hort-cli: TLS error contacting IdP at {}: {e}",
                    cfg.idp.issuer
                );
                eprintln!(
                    "       If the IdP uses an internal CA, set \
                     HORT_EXTRA_CA_BUNDLE=/path/to/ca.pem and retry."
                );
            } else {
                eprintln!(
                    "hort-cli: failed to fetch IdP configuration from {}: {e}",
                    cfg.idp.issuer
                );
                eprintln!("       Verify the IdP issuer URL with your administrator.");
            }
            tracing::debug!(issuer = %cfg.idp.issuer, error = %e, "IdP endpoint fetch failed");
            return Ok(ExitCode::from(1));
        }
    };

    // Pre-probe the listener bind so an unavoidable LoopbackUnavailable error
    // is reachable before we print the URL. Auto-mode falls back to device;
    // forced-mode hard-fails.
    if let Err(LoopbackError::LoopbackUnavailable {
        ipv4_reason,
        ipv6_reason,
    }) = loopback::bind_loopback_listener()
    {
        if loopback_forced {
            eprintln!(
                "hort-cli: loopback redirect failed: bind 127.0.0.1:0 ({ipv4_reason}) and [::1]:0 ({ipv6_reason}). \
                 See docs/operator/idp-setup.md#redirect-uris."
            );
            return Ok(ExitCode::from(1));
        }
        tracing::info!(
            ipv4_reason = %ipv4_reason,
            ipv6_reason = %ipv6_reason,
            "loopback bind failed; falling back to device flow"
        );
        return run_oidc_device_flow(server_url, cfg, session_request, opener).await;
    }

    let jwt = match loopback::run_loopback_flow(&endpoints, &cfg.idp.client_id, opener).await {
        Ok(j) => j,
        Err(e) => {
            // Decode the typed LoopbackError if present.
            match e.downcast_ref::<LoopbackError>() {
                Some(LoopbackError::UserCancelled) => {
                    eprintln!("hort-cli: login cancelled by user");
                    return Ok(ExitCode::from(1));
                }
                Some(LoopbackError::AuthorizationStateMismatch) => {
                    eprintln!("hort-cli: authorization state mismatch — possible CSRF attempt");
                    return Ok(ExitCode::from(1));
                }
                Some(LoopbackError::Timeout(secs)) => {
                    eprintln!("hort-cli: loopback callback timed out after {secs} seconds");
                    return Ok(ExitCode::from(1));
                }
                Some(LoopbackError::LoopbackUnavailable { .. }) => {
                    // Late-binding failure (race between probe and serve).
                    // Same policy as the pre-probe.
                    if !loopback_forced {
                        tracing::info!("loopback bind raced; falling back to device flow");
                        return run_oidc_device_flow(server_url, cfg, session_request, opener)
                            .await;
                    }
                    eprintln!("hort-cli: loopback redirect failed: {e}. See docs/operator/idp-setup.md#redirect-uris.");
                    return Ok(ExitCode::from(1));
                }
                Some(LoopbackError::AuthorizationError { .. })
                | Some(LoopbackError::InvalidHost)
                | Some(LoopbackError::Transport(_))
                | None => {
                    eprintln!("hort-cli: {e}");
                    return Ok(ExitCode::from(1));
                }
            }
        }
    };

    let client_id = format!("hort-cli/{}", env!("CARGO_PKG_VERSION"));
    let token = match crate::auth::oidc::exchange(
        &cfg.exchange.endpoint,
        &jwt,
        &client_id,
        session_request.scope.as_deref(),
        session_request.requested_lifetime_secs,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hort-cli: server rejected exchange: {e}");
            return Ok(ExitCode::from(1));
        }
    };

    persist_token(server_url, &token.access_token).context("saving token to config file")?;
    tracing::info!("oidc login (loopback) succeeded");

    print_post_login(server_url, &token, &mut io::stdout());

    Ok(ExitCode::SUCCESS)
}

/// Post-login output. Renders the actual issued lifetime (post-clamp) and,
/// when the operator supplied `--expires-in`/`--admin` that the server
/// clamped or narrowed, emits a `note:` line explaining the difference.
/// Operator-facing API: the format is pinned by integration tests.
fn print_post_login(
    server_url: &str,
    token: &crate::auth::oidc::CliSessionToken,
    out: &mut impl io::Write,
) {
    let issued_secs = token.expires_in.unwrap_or(0);
    let _ = match issued_secs {
        0 => writeln!(out, "Logged in to {server_url}."),
        n => writeln!(
            out,
            "Logged in to {server_url} (token expires in {}).",
            humanise_duration(n)
        ),
    };
    // Clamp detection: when the operator asked for a specific lifetime
    // and the server issued less, surface a `note:` line. Tolerance:
    // 5 s — accounts for the gap between issuance and response
    // assembly so a perfect-match 4 h request doesn't surface a
    // spurious note.
    if let (Some(requested), Some(issued)) = (token.requested_lifetime_secs, token.expires_in) {
        if requested > issued.saturating_add(5) {
            let _ = writeln!(
                out,
                "note: requested {} but server issued {}{} (session lifetime is capped per token shape)",
                humanise_duration(requested),
                humanise_duration(issued),
                if token.admin_requested {
                    " — admin sessions are bounded to ≤1 h"
                } else {
                    ""
                }
            );
        }
    }
}

fn humanise_duration(secs: u64) -> String {
    if secs >= 86400 {
        let days = secs / 86400;
        if days == 1 {
            "1 day".to_string()
        } else {
            format!("{days} days")
        }
    } else if secs >= 3600 {
        let hours = secs / 3600;
        if hours == 1 {
            "1 hour".to_string()
        } else {
            format!("{hours} hours")
        }
    } else if secs >= 60 {
        let mins = secs / 60;
        if mins == 1 {
            "1 minute".to_string()
        } else {
            format!("{mins} minutes")
        }
    } else if secs == 1 {
        "1 second".to_string()
    } else {
        format!("{secs} seconds")
    }
}

// ---------------------------------------------------------------------------
// Paste branch (extracted from original run())
// ---------------------------------------------------------------------------

async fn run_paste_flow<R: BufRead>(
    server_url: &str,
    validate: bool,
    reader: &mut R,
    use_masked: bool,
) -> Result<ExitCode> {
    // Read token — masked on TTY (rpassword), plain reader on non-TTY / tests.
    let token = if use_masked {
        read_token_masked()?
    } else {
        read_token_from_reader(reader)?
    };

    // Require a non-empty token.
    let token = token.trim().to_string();
    if token.is_empty() {
        eprintln!("hort-cli: error: token is empty");
        return Ok(ExitCode::from(1));
    }

    // Optionally validate by calling whoami.
    if validate {
        match validate_token(server_url, &token).await {
            Ok(whoami) => {
                // Warn if the token kind is probably wrong for a CLI login.
                match whoami.token_kind.as_deref() {
                    Some("svc_account") => {
                        eprintln!(
                            "hort-cli: warning: token kind is svc_account — \
                             you probably want an hort_cli_* or hort_pat_* token"
                        );
                    }
                    Some("pat") => {
                        eprintln!(
                            "hort-cli: warning: token kind is pat — \
                             consider using an hort_cli_* CLI-session token instead"
                        );
                    }
                    _ => {}
                }
                // Print success.
                let display_name = whoami
                    .username
                    .clone()
                    .unwrap_or_else(|| "<service account>".to_string());
                let kind_str = whoami.token_kind.as_deref().unwrap_or("oidc");
                println!("Logged in as {display_name} (kind={kind_str})");
            }
            Err(e) => {
                // Surface 401 as a hard abort; other errors also abort.
                eprintln!("hort-cli: login failed: {e}");
                return Ok(ExitCode::from(1));
            }
        }
    }

    // Persist to config file.
    persist_token(server_url, &token).context("saving token to config file")?;

    // If not validating, print a simpler confirmation.
    if !validate {
        println!("Token saved. Run `hort-cli auth status` to verify.");
    }

    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Production BrowserOpener — wraps webbrowser::open
// ---------------------------------------------------------------------------

/// Production [`BrowserOpener`] impl wrapping `webbrowser::open`.
///
/// SECURITY PRECONDITION: the URL must already have been validated by
/// `oidc::validate_verification_uri`. The opener does NOT re-validate
/// — adding double validation here would silently swallow a contract
/// violation in `run_device_flow`. The opener trusts the contract.
pub struct WebBrowserOpener;

impl BrowserOpener for WebBrowserOpener {
    fn open(&self, url: &str) -> Result<()> {
        webbrowser::open(url)
            .map(drop)
            .map_err(|e| anyhow::anyhow!("opening browser: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Headless environment detection
// ---------------------------------------------------------------------------

/// Abstraction over environment variable access, enabling pure tests.
pub(crate) trait EnvAccess {
    fn get(&self, key: &str) -> Option<String>;
}

pub(crate) struct LiveEnv;

impl EnvAccess for LiveEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Returns true if the environment looks headless: any of `CI`,
/// `SSH_CONNECTION`, or `SSH_CLIENT` is set (non-empty), OR stderr is not
/// a TTY.
pub fn is_headless_environment() -> bool {
    headless_signals_in(&LiveEnv, io::stderr().is_terminal())
}

/// Pure helper — testable without touching live stdio or process env.
///
/// `stderr_is_tty` must be `std::io::stderr().is_terminal()` in production;
/// pass an explicit value in tests.
pub(crate) fn headless_signals_in(env: &dyn EnvAccess, stderr_is_tty: bool) -> bool {
    if !stderr_is_tty {
        return true;
    }
    for k in ["CI", "SSH_CONNECTION", "SSH_CLIENT"] {
        if let Some(v) = env.get(k) {
            // Empty-string check: CI= (set but empty) does NOT count.
            if !v.is_empty() {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Token reading
// ---------------------------------------------------------------------------

/// Read a token from stdin with terminal masking (no echo).
///
/// Uses `rpassword::prompt_password` which handles both Unix (`termios`)
/// and Windows (`ReadConsole`) APIs for disabling echo.
pub(crate) fn read_token_masked() -> Result<String> {
    rpassword::prompt_password("Paste your hort_cli_* or hort_pat_* token: ")
        .context("reading token from terminal")
}

/// Read a token from an arbitrary `BufRead` (for CI / scripts / tests).
///
/// Reads one line, strips the trailing newline. This is the code path
/// that fires when stdin is not a TTY. Tests drive the login flow through
/// this function directly — `read_token_masked` is only tested manually
/// (we don't test `rpassword`'s own masking).
pub fn read_token_from_reader<R: BufRead>(reader: &mut R) -> Result<String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("reading token from stdin")?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Call `GET /api/v1/auth/whoami` with the candidate token and return
/// the parsed response. Returns `Err` for any non-2xx status.
pub async fn validate_token(server_url: &str, token: &str) -> Result<WhoamiResponse> {
    // Build a minimal reqwest client with just this token attached.
    let mut headers = reqwest::header::HeaderMap::new();
    // SECURITY: token never logged; attached via default_headers only.
    let auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .context("invalid token characters in Bearer header")?;
    headers.insert(reqwest::header::AUTHORIZATION, auth_value);

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building reqwest client for whoami")?;

    let url = format!("{}/api/v1/auth/whoami", server_url.trim_end_matches('/'));
    // SECURITY: URL only — token is in default_headers, not in the log.
    tracing::debug!(url = %url, "whoami request");

    let resp = client
        .get(&url)
        .send()
        .await
        .context("sending whoami request")?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!("server rejected the token (401 Unauthorized)");
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("whoami returned {status}: {body}");
    }

    resp.json::<WhoamiResponse>()
        .await
        .context("parsing whoami JSON response")
}

// ---------------------------------------------------------------------------
// Config persistence
// ---------------------------------------------------------------------------

/// Resolve the server URL from: flag > env HORT_SERVER > existing config file.
fn resolve_server_url(flag: Option<String>) -> Result<String> {
    if let Some(s) = flag {
        return Ok(s);
    }
    if let Ok(s) = std::env::var("HORT_SERVER") {
        if !s.is_empty() {
            return Ok(s);
        }
    }
    // Try reading from existing config file.
    match load_effective_config(None, None) {
        Ok(cfg) => Ok(cfg.server.to_string()),
        Err(_) => {
            bail!("server URL not specified — use --server or set HORT_SERVER")
        }
    }
}

/// Persist the server URL + token to `~/.hort/config.toml` at mode 0600.
///
/// Creates the parent directory if it does not exist. On Windows the
/// file is NOT chmod'd (NTFS ACLs on user-profile directories provide
/// equivalent protection; operator docs note this).
pub fn persist_token(server_url: &str, token: &str) -> Result<()> {
    let path =
        config_file_path().context("cannot determine config file path (HOME is not set?)")?;
    persist_token_to(&path, server_url, token)
}

/// Behaviour-preserving core of [`persist_token`] parameterised on the target
/// path so it is testable without driving `$HOME`.
///
/// Write-then-chmod TOCTOU fix. The previous implementation did
/// `fs::write` (creating the file at the process umask, commonly 0644,
/// containing the plaintext bearer token) and *then* `set_permissions(0600)`,
/// leaving a world-readable window on a multi-user host; on an existing file
/// `fs::write` truncated in place without resetting an attacker-pre-created
/// mode/symlink. The hardened path:
///
/// - `create_dir_all(parent)` then (Unix) tightens the parent to `0o700` —
///   it may have been created under the process umask.
/// - Writes a uniquely-named sibling temp file in the **same directory** via
///   `OpenOptions … create_new(true).mode(0o600)` — on Unix `create_new` +
///   `mode` is an atomic create at 0600 (no umask window — case (a)) that
///   *fails* if anything (file or symlink) already exists at the temp name
///   (case (c)).
/// - `sync_all()` then `std::fs::rename(temp, path)` — an atomic same-filesystem
///   replace, so the final file never inherits a stale mode from a
///   pre-existing target (case (b)) and a concurrent reader sees either the
///   old or the new file, never a partial/0644 one.
/// - The temp file is best-effort removed on every error path.
fn persist_token_to(path: &std::path::Path, server_url: &str, token: &str) -> Result<()> {
    // Ensure parent directory exists.
    let parent = path.parent();
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory {parent:?}"))?;
        // The dir may have been created under the process umask (e.g. 0755).
        // Tighten it so the 0600 file is not reachable via a loose parent.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("setting 0700 permissions on {parent:?}"))?;
        }
    }

    // Build the TOML content.
    let content = format!(
        "# hort-cli configuration — managed by `hort-cli auth login`\n\
         server = \"{server_url}\"\n\
         token  = \"{token}\"\n"
    );

    // Unique sibling temp name in the SAME directory (rename is only atomic
    // within one filesystem). pid + a counter avoids collisions between
    // concurrent `hort-cli auth login` invocations.
    let dir = parent.unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_path = dir.join(format!(".{file_name}.{}.{seq}.tmp", std::process::id()));

    let write_result = (|| -> Result<()> {
        // `create_new` ⇒ O_EXCL: fails if a file or symlink already exists at
        // the temp name (defeats symlink/file pre-creation, case (c)).
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Atomic create at 0600 — no umask-widened window (case (a)).
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp_path)
            .with_context(|| format!("creating temp config file {tmp_path:?}"))?;
        use std::io::Write;
        f.write_all(content.as_bytes())
            .with_context(|| format!("writing temp config file {tmp_path:?}"))?;
        f.sync_all()
            .with_context(|| format!("syncing temp config file {tmp_path:?}"))?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Atomic same-filesystem replace. A pre-existing target (any mode/symlink)
    // is replaced wholesale — the final inode is always our fresh 0600 file
    // (cases (b)/(c)), and a concurrent reader never observes a 0644 partial.
    if let Err(e) = std::fs::rename(&tmp_path, path)
        .with_context(|| format!("atomically replacing config file {path:?}"))
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // Stub env for headless_signals_in tests
    // -----------------------------------------------------------------------

    struct StubEnv(HashMap<&'static str, &'static str>);

    impl EnvAccess for StubEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).map(ToString::to_string)
        }
    }

    // -----------------------------------------------------------------------
    // read_token_from_reader tests (pre-existing)
    // -----------------------------------------------------------------------

    #[test]
    fn read_token_from_reader_strips_newline() {
        let input = b"my-secret-token\n";
        let tok = read_token_from_reader(&mut input.as_ref()).unwrap();
        assert_eq!(tok, "my-secret-token");
    }

    #[test]
    fn read_token_from_reader_handles_crlf() {
        let input = b"my-token\r\n";
        let tok = read_token_from_reader(&mut input.as_ref()).unwrap();
        assert_eq!(tok, "my-token");
    }

    #[test]
    fn read_token_from_reader_returns_empty_for_empty_line() {
        let input = b"\n";
        let tok = read_token_from_reader(&mut input.as_ref()).unwrap();
        assert_eq!(tok, "");
    }

    // -----------------------------------------------------------------------
    // headless_signals_in tests — driven by headless_returns_true_when_CI_set
    // -----------------------------------------------------------------------

    #[test]
    #[allow(non_snake_case)]
    fn headless_returns_true_when_CI_set() {
        let env = StubEnv([("CI", "true")].into_iter().collect());
        assert!(headless_signals_in(&env, true));
    }

    #[test]
    #[allow(non_snake_case)]
    fn headless_returns_true_when_SSH_CONNECTION_set() {
        let env = StubEnv(
            [("SSH_CONNECTION", "10.0.0.1 22 192.168.1.1 44321")]
                .into_iter()
                .collect(),
        );
        assert!(headless_signals_in(&env, true));
    }

    #[test]
    #[allow(non_snake_case)]
    fn headless_returns_true_when_SSH_CLIENT_set() {
        let env = StubEnv([("SSH_CLIENT", "10.0.0.1 22 22")].into_iter().collect());
        assert!(headless_signals_in(&env, true));
    }

    #[test]
    fn headless_returns_true_when_stderr_not_tty() {
        let env = StubEnv(Default::default());
        assert!(headless_signals_in(&env, false));
    }

    #[test]
    fn headless_returns_false_when_no_signals_and_tty() {
        let env = StubEnv(Default::default());
        assert!(!headless_signals_in(&env, true));
    }

    #[test]
    #[allow(non_snake_case)]
    fn headless_returns_false_when_CI_set_to_empty() {
        let env = StubEnv([("CI", "")].into_iter().collect());
        assert!(!headless_signals_in(&env, true));
    }

    // -----------------------------------------------------------------------
    // humanise_duration tests
    // -----------------------------------------------------------------------

    #[test]
    fn humanise_30_days() {
        assert_eq!(humanise_duration(2592000), "30 days");
    }

    #[test]
    fn humanise_1_day() {
        assert_eq!(humanise_duration(86400), "1 day");
    }

    #[test]
    fn humanise_15_minutes() {
        assert_eq!(humanise_duration(900), "15 minutes");
    }

    #[test]
    fn humanise_1_hour() {
        assert_eq!(humanise_duration(3600), "1 hour");
    }

    #[test]
    fn humanise_seconds() {
        assert_eq!(humanise_duration(45), "45 seconds");
    }

    #[test]
    fn humanise_1_second_is_singular() {
        assert_eq!(humanise_duration(1), "1 second");
    }

    #[test]
    fn humanise_1_minute_is_singular() {
        assert_eq!(humanise_duration(60), "1 minute");
    }

    // -----------------------------------------------------------------------
    // resolve_oidc_subflow — auto decision tree
    // -----------------------------------------------------------------------

    #[test]
    fn subflow_auto_picks_loopback_on_desktop() {
        assert_eq!(
            resolve_oidc_subflow(Flow::Auto, false, false),
            OidcSubflow::Loopback
        );
    }

    #[test]
    fn subflow_auto_picks_device_on_headless() {
        assert_eq!(
            resolve_oidc_subflow(Flow::Auto, false, true),
            OidcSubflow::Device
        );
    }

    #[test]
    fn subflow_no_browser_forces_device_regardless_of_flow() {
        assert_eq!(
            resolve_oidc_subflow(Flow::Auto, true, false),
            OidcSubflow::Device
        );
        assert_eq!(
            resolve_oidc_subflow(Flow::Loopback, true, false),
            OidcSubflow::Device
        );
    }

    #[test]
    fn subflow_explicit_device_always_picks_device() {
        assert_eq!(
            resolve_oidc_subflow(Flow::Device, false, false),
            OidcSubflow::Device
        );
        assert_eq!(
            resolve_oidc_subflow(Flow::Device, false, true),
            OidcSubflow::Device
        );
    }

    #[test]
    fn subflow_explicit_loopback_picks_loopback_when_browser_available() {
        // Headless + --flow=loopback still attempts loopback — the operator
        // asked for it explicitly. The dispatcher will hard-fail at bind
        // time if it can't make it work.
        assert_eq!(
            resolve_oidc_subflow(Flow::Loopback, false, false),
            OidcSubflow::Loopback
        );
        assert_eq!(
            resolve_oidc_subflow(Flow::Loopback, false, true),
            OidcSubflow::Loopback
        );
    }

    #[test]
    fn subflow_paste_treated_as_device_for_defence_in_depth() {
        // Paste is handled upstream and never reaches the OIDC dispatcher;
        // if it does (defence in depth), don't crash — fall back to device.
        assert_eq!(
            resolve_oidc_subflow(Flow::Paste, false, false),
            OidcSubflow::Device
        );
    }

    // -----------------------------------------------------------------------
    // --admin / --expires-in + post-login output
    // -----------------------------------------------------------------------

    #[test]
    fn parse_duration_arg_accepts_go_style_strings() {
        for (input, expected_secs) in [
            ("1h", 3_600),
            ("30m", 30 * 60),
            ("4h", 4 * 3_600),
            ("24h", 24 * 3_600),
            ("5min", 5 * 60),
        ] {
            let parsed = parse_duration_arg(input)
                .unwrap_or_else(|e| panic!("expected {input} to parse, got error: {e}"));
            assert_eq!(parsed.as_secs(), expected_secs);
        }
    }

    #[test]
    fn parse_duration_arg_rejects_unparseable_string_with_hint() {
        let err = parse_duration_arg("not-a-duration").unwrap_err();
        // Error message contains an actionable hint operators can see in
        // clap's usage rejection output.
        assert!(err.contains("not-a-duration"));
        assert!(err.contains("1h"), "hint should mention example formats");
    }

    fn login_args_with(admin: bool, expires_in: Option<std::time::Duration>) -> LoginArgs {
        LoginArgs {
            validate: false,
            server: None,
            paste: false,
            oidc: false,
            no_browser: false,
            flow: Flow::Auto,
            admin,
            expires_in,
        }
    }

    #[test]
    fn session_request_from_login_args_default_omits_scope_and_lifetime() {
        let req = SessionRequest::from_login_args(&login_args_with(false, None));
        assert!(req.scope.is_none());
        assert!(req.requested_lifetime_secs.is_none());
        assert!(!req.deviates_from_defaults());
    }

    #[test]
    fn session_request_from_login_args_admin_sets_admin_scope() {
        let req = SessionRequest::from_login_args(&login_args_with(true, None));
        let scope = req.scope.as_deref().expect("--admin must set scope");
        assert!(scope.split_whitespace().any(|t| t == "admin"));
        assert!(scope.split_whitespace().any(|t| t == "read"));
        assert!(scope.split_whitespace().any(|t| t == "write"));
        assert!(scope.split_whitespace().any(|t| t == "delete"));
        assert!(req.deviates_from_defaults());
    }

    #[test]
    fn session_request_from_login_args_expires_in_propagates() {
        let req = SessionRequest::from_login_args(&login_args_with(
            false,
            Some(std::time::Duration::from_secs(4 * 3_600)),
        ));
        assert!(req.scope.is_none()); // --admin not set
        assert_eq!(req.requested_lifetime_secs, Some(4 * 3_600));
        assert!(req.deviates_from_defaults());
    }

    fn cli_token(
        expires_in: Option<u64>,
        requested: Option<u64>,
        admin: bool,
    ) -> crate::auth::oidc::CliSessionToken {
        crate::auth::oidc::CliSessionToken {
            access_token: "hort_cli_test".into(),
            expires_in,
            requested_lifetime_secs: requested,
            admin_requested: admin,
        }
    }

    #[test]
    fn print_post_login_omits_note_when_requested_equals_issued() {
        let mut buf: Vec<u8> = Vec::new();
        print_post_login(
            "https://hort.example.com",
            &cli_token(Some(4 * 3_600), Some(4 * 3_600), false),
            &mut buf,
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Logged in to https://hort.example.com"));
        assert!(!out.contains("note:"), "no clamp note expected, got: {out}");
    }

    #[test]
    fn print_post_login_emits_clamp_note_when_server_issued_less() {
        let mut buf: Vec<u8> = Vec::new();
        // Operator asked for 4 h with --admin; server clamped to 1 h.
        print_post_login(
            "https://hort.example.com",
            &cli_token(Some(3_600), Some(4 * 3_600), true),
            &mut buf,
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("note:"),
            "expected clamp note in output: {out}"
        );
        assert!(
            out.contains("admin sessions are bounded"),
            "expected admin-clamp explanation: {out}"
        );
    }

    #[test]
    fn print_post_login_emits_clamp_note_for_non_admin_overshoot() {
        let mut buf: Vec<u8> = Vec::new();
        // Non-admin: 48 h requested; server caps at 24 h.
        print_post_login(
            "https://hort.example.com",
            &cli_token(Some(24 * 3_600), Some(48 * 3_600), false),
            &mut buf,
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("note:"), "expected clamp note: {out}");
        assert!(
            !out.contains("admin sessions"),
            "non-admin clamp should NOT mention admin lifetime, got: {out}"
        );
    }

    #[test]
    fn print_post_login_omits_note_when_no_expires_in_requested() {
        // Operator omitted --expires-in; server-issued lifetime is the
        // default. No note should appear because there's nothing to
        // compare against.
        let mut buf: Vec<u8> = Vec::new();
        print_post_login(
            "https://hort.example.com",
            &cli_token(Some(3_600), None, false),
            &mut buf,
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("note:"), "got: {out}");
    }

    // -----------------------------------------------------------------------
    // persist_token_to tests — write-then-chmod TOCTOU
    //
    // The atomic temp-file-in-same-dir + rename approach must close:
    //   (a) world-readable window between create and chmod,
    //   (b) stale attacker-pre-created mode on an existing target,
    //   (c) symlink/file pre-created at the target.
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    const EXPECTED_TOML: &str = "# hort-cli configuration — managed by `hort-cli auth login`\n\
         server = \"https://hort.example.com\"\n\
         token  = \"sekret-token-xyz\"\n";

    #[cfg(unix)]
    #[test]
    fn persist_token_to_fresh_file_is_0600_parent_0700_exact_content() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        // Mimic ~/.hort/config.toml: a nested parent dir that does not exist.
        let cfg_dir = tmp.path().join(".hort");
        let path = cfg_dir.join("config.toml");

        persist_token_to(&path, "https://hort.example.com", "sekret-token-xyz").unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "config file must be exactly 0600");

        let dir_mode = std::fs::metadata(&cfg_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "parent dir must be exactly 0700");

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, EXPECTED_TOML);
    }

    #[cfg(unix)]
    #[test]
    fn persist_token_to_resets_stale_attacker_mode_on_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg_dir = tmp.path().join(".hort");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let path = cfg_dir.join("config.toml");

        // Attacker pre-creates the target world-readable (case (b)).
        std::fs::write(&path, "stale attacker-controlled bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        persist_token_to(&path, "https://hort.example.com", "sekret-token-xyz").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "an existing 0644 file must end up 0600, not be truncated in place"
        );
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, EXPECTED_TOML, "stale content must be replaced");
    }

    #[cfg(unix)]
    #[test]
    fn persist_token_to_leaves_no_temp_and_is_repeatable() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg_dir = tmp.path().join(".hort");
        let path = cfg_dir.join("config.toml");

        persist_token_to(&path, "https://hort.example.com", "sekret-token-xyz").unwrap();
        // A second persist must succeed (atomic replace; temp name freed/cleaned).
        persist_token_to(&path, "https://hort.example.com", "sekret-token-xyz").unwrap();

        // Only the final config.toml may remain — no leftover temp sibling.
        let entries: Vec<_> = std::fs::read_dir(&cfg_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["config.toml".to_string()],
            "no temp file may survive a successful persist, got: {entries:?}"
        );

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, EXPECTED_TOML);
    }
}
