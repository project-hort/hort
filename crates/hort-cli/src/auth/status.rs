//! `hort-cli auth status` — show the current authentication state.
//!
//! # Behaviour
//!
//! `auth status` is a state query, not a configured-action. It
//! distinguishes four user-visible states:
//!
//! - **Authenticated** — `GET /api/v1/auth/whoami` returns 200 with a
//!   principal; render as table or JSON. Exit 0.
//! - **Not configured** — no server URL set in any source. Exit 1.
//! - **Not authenticated** — server set but no token. Exit 1.
//! - **Token rejected** — server + token, but whoami returned 401.
//!   Exit 1.
//!
//! Real config errors (malformed TOML, invalid URL) still surface as
//! exit 2 so scripts can distinguish them from the merely-not-configured
//! states above.

use std::process::ExitCode;

use anyhow::Result;
use serde_json::json;
use url::Url;

use crate::auth::WhoamiResponse;
use crate::client::AkClient;
use crate::config::{load_effective_config, load_server_only, ConfigError, OutputFormat};
use crate::output::{format_json, format_table_rows};

// ---------------------------------------------------------------------------
// AuthStatus — the discriminated union driving render + exit code
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) enum AuthStatus {
    Authenticated {
        server: Url,
        whoami: WhoamiResponse,
    },
    NotConfigured,
    NotAuthenticated {
        server: Url,
    },
    TokenRejected {
        server: Url,
        http_status: u16,
    },
    /// Real failures (malformed TOML, invalid URL). Exit 2.
    ConfigError {
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(output: OutputFormat) -> Result<ExitCode> {
    let status = compute_status().await?;
    let (rendered, exit) = render_status(&status, output);
    // Authenticated + JSON go to stdout (machine-readable). Everything
    // else still goes to stdout because callers may pipe — but the
    // exit code (1 / 2) carries the failure signal.
    print!("{rendered}");
    Ok(exit)
}

// ---------------------------------------------------------------------------
// compute_status — config + HTTP → AuthStatus
// ---------------------------------------------------------------------------

async fn compute_status() -> Result<AuthStatus> {
    let cfg = match load_effective_config(None, None) {
        Ok(c) => c,
        Err(ConfigError::Missing {
            field: "server", ..
        }) => {
            return Ok(AuthStatus::NotConfigured);
        }
        Err(ConfigError::Missing { field: "token", .. }) => {
            // Best-effort surface the configured server URL; falls
            // back to NotConfigured if the server resolution itself
            // hits an error.
            return Ok(match load_server_only(None) {
                Some(server) => AuthStatus::NotAuthenticated { server },
                None => AuthStatus::NotConfigured,
            });
        }
        Err(e) => {
            return Ok(AuthStatus::ConfigError {
                message: e.to_string(),
            });
        }
    };

    let server = cfg.server.clone();
    let client = AkClient::new(&cfg)?;
    match client.get::<WhoamiResponse>("/api/v1/auth/whoami").await {
        Ok(whoami) => Ok(AuthStatus::Authenticated { server, whoami }),
        Err(err) => {
            // The shared client raises non-2xx as `anyhow!("HTTP {status}: {body}")`.
            // 401 is the auth-rejected case; surface it structurally.
            // Other HTTP errors (5xx, network) propagate as a real Err
            // so the operator sees the failure.
            if let Some(code) = parse_http_status(&err) {
                if code == 401 {
                    return Ok(AuthStatus::TokenRejected {
                        server,
                        http_status: 401,
                    });
                }
            }
            Err(err)
        }
    }
}

/// Extract a HTTP status code out of an `anyhow::Error` whose message
/// starts with `"HTTP <code>"` (the shared client's error shape).
fn parse_http_status(err: &anyhow::Error) -> Option<u16> {
    let s = err.to_string();
    let rest = s.strip_prefix("HTTP ")?;
    let code = rest.split_whitespace().next()?;
    code.parse().ok()
}

// ---------------------------------------------------------------------------
// render_status — pure: AuthStatus + format → (text, exit code)
// ---------------------------------------------------------------------------

pub(crate) fn render_status(status: &AuthStatus, output: OutputFormat) -> (String, ExitCode) {
    match output {
        OutputFormat::Table => render_table(status),
        OutputFormat::Json => render_json(status),
    }
}

fn render_table(status: &AuthStatus) -> (String, ExitCode) {
    match status {
        AuthStatus::Authenticated { whoami, .. } => {
            let rows = whoami_to_table_rows(whoami);
            (
                format_table_rows(&["FIELD", "VALUE"], &rows),
                ExitCode::SUCCESS,
            )
        }
        AuthStatus::NotConfigured => (
            "hort-cli: not configured. \
             Run `hort-cli auth login --server <URL>` to set up credentials.\n"
                .to_string(),
            ExitCode::from(1),
        ),
        AuthStatus::NotAuthenticated { server } => (
            format!(
                "hort-cli: not authenticated to {server}. \
                 Run `hort-cli auth login` to authenticate.\n"
            ),
            ExitCode::from(1),
        ),
        AuthStatus::TokenRejected {
            server,
            http_status,
        } => (
            format!(
                "hort-cli: token rejected by {server} ({http_status}). \
                 Run `hort-cli auth login` to refresh credentials.\n"
            ),
            ExitCode::from(1),
        ),
        AuthStatus::ConfigError { message } => (
            format!(
                "hort-cli: config error: {message}\n\
                 Hint: run `hort-cli auth login` to set up credentials.\n"
            ),
            ExitCode::from(2),
        ),
    }
}

fn render_json(status: &AuthStatus) -> (String, ExitCode) {
    let (value, exit) = match status {
        AuthStatus::Authenticated { server, whoami } => (
            json!({
                "authenticated": true,
                "server": server.as_str(),
                "user_id": whoami.user_id,
                "username": whoami.username,
                "token_kind": whoami.token_kind,
                "permissions": whoami.permissions,
            }),
            ExitCode::SUCCESS,
        ),
        AuthStatus::NotConfigured => (
            json!({
                "authenticated": false,
                "reason": "not_configured",
            }),
            ExitCode::from(1),
        ),
        AuthStatus::NotAuthenticated { server } => (
            json!({
                "authenticated": false,
                "reason": "no_token",
                "server": server.as_str(),
            }),
            ExitCode::from(1),
        ),
        AuthStatus::TokenRejected {
            server,
            http_status,
        } => (
            json!({
                "authenticated": false,
                "reason": "token_rejected",
                "server": server.as_str(),
                "http_status": http_status,
            }),
            ExitCode::from(1),
        ),
        AuthStatus::ConfigError { message } => (
            json!({
                "authenticated": false,
                "reason": "config_error",
                "message": message,
            }),
            ExitCode::from(2),
        ),
    };
    let mut s = format_json(&value);
    if !s.ends_with('\n') {
        s.push('\n');
    }
    (s, exit)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn whoami_to_table_rows(whoami: &WhoamiResponse) -> Vec<Vec<String>> {
    vec![
        vec![
            "user_id".to_string(),
            whoami
                .user_id
                .clone()
                .unwrap_or_else(|| "<null>".to_string()),
        ],
        vec![
            "username".to_string(),
            whoami
                .username
                .clone()
                .unwrap_or_else(|| "<null>".to_string()),
        ],
        vec![
            "token_kind".to_string(),
            whoami
                .token_kind
                .clone()
                .unwrap_or_else(|| "<oidc>".to_string()),
        ],
        vec!["permissions".to_string(), whoami.permissions.join(", ")],
    ]
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn server() -> Url {
        Url::parse("https://hort.example.com").unwrap()
    }

    #[test]
    fn whoami_to_table_rows_renders_all_fields() {
        let whoami = WhoamiResponse {
            user_id: Some("abc-123".to_string()),
            username: Some("alice".to_string()),
            token_kind: Some("pat".to_string()),
            permissions: vec!["read".to_string(), "write".to_string()],
        };
        let rows = whoami_to_table_rows(&whoami);
        assert_eq!(rows[0][0], "user_id");
        assert_eq!(rows[0][1], "abc-123");
        assert_eq!(rows[1][1], "alice");
        assert_eq!(rows[2][1], "pat");
        assert!(rows[3][1].contains("read"));
        assert!(rows[3][1].contains("write"));
    }

    #[test]
    fn whoami_to_table_rows_handles_null_fields() {
        let whoami = WhoamiResponse {
            user_id: None,
            username: None,
            token_kind: Some("svc_account".to_string()),
            permissions: vec!["read".to_string()],
        };
        let rows = whoami_to_table_rows(&whoami);
        assert_eq!(rows[0][1], "<null>");
        assert_eq!(rows[1][1], "<null>");
    }

    // ----- render_status: state-aware messaging --------------------------
    //
    // The four AuthStatus variants below replace the old
    // "config error: required field missing" hard-fail with the
    // human-meaningful states a user actually wants from `auth status`.
    // Each test pins one variant × output combination so format drift is
    // caught.

    #[test]
    fn render_status_not_configured_table() {
        let (out, exit) = render_status(&AuthStatus::NotConfigured, OutputFormat::Table);
        assert!(
            out.to_lowercase().contains("not configured"),
            "expected 'not configured', got: {out}"
        );
        assert!(
            out.contains("hort-cli auth login"),
            "should hint login: {out}"
        );
        assert_eq!(exit_code_to_u8(exit), 1);
    }

    #[test]
    fn render_status_not_configured_json_signals_authenticated_false() {
        let (out, _exit) = render_status(&AuthStatus::NotConfigured, OutputFormat::Json);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(v["authenticated"], false);
        assert_eq!(v["reason"], "not_configured");
    }

    #[test]
    fn render_status_not_authenticated_table_includes_server() {
        let (out, exit) = render_status(
            &AuthStatus::NotAuthenticated { server: server() },
            OutputFormat::Table,
        );
        assert!(
            out.to_lowercase().contains("not authenticated"),
            "expected 'not authenticated', got: {out}"
        );
        assert!(
            out.contains("https://hort.example.com"),
            "should mention server: {out}"
        );
        assert!(out.contains("hort-cli auth login"));
        assert_eq!(exit_code_to_u8(exit), 1);
    }

    #[test]
    fn render_status_not_authenticated_json_carries_server() {
        let (out, _exit) = render_status(
            &AuthStatus::NotAuthenticated { server: server() },
            OutputFormat::Json,
        );
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(v["authenticated"], false);
        assert_eq!(v["reason"], "no_token");
        assert_eq!(v["server"], "https://hort.example.com/");
    }

    #[test]
    fn render_status_token_rejected_table_includes_status_code() {
        let (out, exit) = render_status(
            &AuthStatus::TokenRejected {
                server: server(),
                http_status: 401,
            },
            OutputFormat::Table,
        );
        assert!(
            out.to_lowercase().contains("rejected"),
            "expected 'rejected', got: {out}"
        );
        assert!(out.contains("401"), "expected status code in: {out}");
        assert!(out.contains("https://hort.example.com"));
        assert_eq!(exit_code_to_u8(exit), 1);
    }

    #[test]
    fn render_status_token_rejected_json_signals_authenticated_false() {
        let (out, _exit) = render_status(
            &AuthStatus::TokenRejected {
                server: server(),
                http_status: 401,
            },
            OutputFormat::Json,
        );
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(v["authenticated"], false);
        assert_eq!(v["reason"], "token_rejected");
        assert_eq!(v["http_status"], 401);
    }

    #[test]
    fn render_status_authenticated_table_keeps_existing_layout() {
        let whoami = WhoamiResponse {
            user_id: Some("u-1".to_string()),
            username: Some("alice".to_string()),
            token_kind: Some("pat".to_string()),
            permissions: vec!["read".to_string()],
        };
        let (out, exit) = render_status(
            &AuthStatus::Authenticated {
                server: server(),
                whoami,
            },
            OutputFormat::Table,
        );
        assert!(out.contains("alice"));
        assert!(out.contains("pat"));
        assert!(out.contains("FIELD") && out.contains("VALUE"));
        assert_eq!(exit_code_to_u8(exit), 0);
    }

    #[test]
    fn render_status_authenticated_json_signals_authenticated_true() {
        let whoami = WhoamiResponse {
            user_id: Some("u-1".to_string()),
            username: Some("alice".to_string()),
            token_kind: Some("pat".to_string()),
            permissions: vec!["read".to_string()],
        };
        let (out, _exit) = render_status(
            &AuthStatus::Authenticated {
                server: server(),
                whoami,
            },
            OutputFormat::Json,
        );
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(v["authenticated"], true);
        assert_eq!(v["server"], "https://hort.example.com/");
        assert_eq!(v["username"], "alice");
        assert_eq!(v["token_kind"], "pat");
    }

    #[test]
    fn render_status_config_error_table_shows_message() {
        let (out, exit) = render_status(
            &AuthStatus::ConfigError {
                message: "malformed config file at /tmp/x.toml: bad TOML".to_string(),
            },
            OutputFormat::Table,
        );
        assert!(out.contains("malformed config"));
        // Real config errors stay exit 2 so scripts can distinguish from
        // the merely-not-configured / not-authenticated states.
        assert_eq!(exit_code_to_u8(exit), 2);
    }

    /// Workaround: `ExitCode` does not implement `PartialEq` on stable.
    /// Compare via Debug printout, which is `ExitCode(unix_exit_status(N))`.
    /// A `#[cfg(test)]`-only stdlib-limitation shim; permanent until std
    /// stabilises `PartialEq` for `ExitCode`.
    fn exit_code_to_u8(c: ExitCode) -> u8 {
        let s = format!("{c:?}");
        // Pull the integer out of the Debug repr.
        let n = s.chars().filter(char::is_ascii_digit).collect::<String>();
        n.parse().unwrap_or(255)
    }
}
