//! `hort-cli admin cli-session revoke` / `revoke-user` — the two
//! CliSession emergency-revocation calls.
//!
//! # Wire DTO sync
//!
//! `RevokeCliSessionRequest` and `CliSessionCutoffResponse` mirror
//! `hort-http-core::handlers::api_tokens::{RevokeCliSessionRequestBody,
//! CliSessionCutoffResponse}` verbatim. Defined locally to keep
//! `hort-cli` adapter-free (no dep on workspace-internal HTTP/domain
//! crates). The wire JSON form is the contract.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;

use crate::client::AkClient;
use crate::config::OutputFormat;
use crate::output::format_json;

// ---------------------------------------------------------------------------
// Wire DTOs
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/admin/cli-sessions/revoke`.
///
/// **Sync-required**: mirrors `RevokeCliSessionRequestBody` in
/// `hort-http-core::handlers::api_tokens`.
#[derive(Debug, serde::Serialize)]
pub struct RevokeCliSessionRequest {
    pub jti: String,
    pub expires_at: String,
}

/// Response body for
/// `POST /api/v1/admin/users/<user_id>/cli-sessions/revoke`.
///
/// **Sync-required**: mirrors `CliSessionCutoffResponse` in
/// `hort-http-core::handlers::api_tokens`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct CliSessionCutoffResponse {
    pub user_id: String,
    pub cutoff: String,
    pub cutoff_expires_at: String,
}

// ---------------------------------------------------------------------------
// Clap args
// ---------------------------------------------------------------------------

/// Arguments for `hort-cli admin cli-session revoke`.
///
/// Either `--token` (the CLI reads `jti` and `exp` out of it locally)
/// or both of `--jti` / `--expires-at`. The two forms are mutually
/// exclusive: an operator who supplies a token AND a mismatched `jti`
/// has made a mistake worth an error rather than a silent precedence
/// rule.
#[derive(clap::Args, Debug)]
pub struct RevokeArgs {
    /// The CliSession JWT to revoke. `-` reads it from stdin, which
    /// keeps a live credential out of shell history.
    ///
    /// Only the payload is read, and only its `jti` and `exp` claims.
    /// No signature is checked and the token is never sent to the
    /// server.
    #[arg(long, conflicts_with_all = ["jti", "expires_at"])]
    pub token: Option<String>,

    /// The `jti` claim of the session to revoke.
    #[arg(long, requires = "expires_at")]
    pub jti: Option<String>,

    /// The `exp` claim of that same session, as RFC 3339 (e.g.
    /// `2026-10-27T18:45:00Z`) or as Unix seconds.
    #[arg(long, requires = "jti")]
    pub expires_at: Option<String>,
}

/// Arguments for `hort-cli admin cli-session revoke-user`.
///
/// `<user_id>` is passed through verbatim so the server's error is the
/// canonical one operators see (one error path, not two).
#[derive(clap::Args, Debug)]
pub struct RevokeUserArgs {
    /// UUID of the human whose sessions are cut off.
    pub user_id: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Dispatch path for `revoke`. Writes to stdout.
pub async fn run(client: AkClient, args: RevokeArgs, output: OutputFormat) -> Result<()> {
    run_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_with_output(
    client: AkClient,
    args: RevokeArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    let body = resolve_request(args, &mut std::io::stdin())?;
    client
        .post_no_response("/api/v1/admin/cli-sessions/revoke", &body)
        .await?;
    match output {
        OutputFormat::Json => writeln!(
            out,
            "{}",
            format_json(&serde_json::json!({
                "revoked_jti": body.jti,
                "denied_until": body.expires_at,
            }))
        )?,
        OutputFormat::Table => writeln!(
            out,
            "revoked_jti:  {}\ndenied_until: {}",
            body.jti, body.expires_at
        )?,
    }
    Ok(())
}

/// Dispatch path for `revoke-user`. Writes to stdout.
pub async fn run_user(client: AkClient, args: RevokeUserArgs, output: OutputFormat) -> Result<()> {
    run_user_with_output(client, args, output, &mut std::io::stdout()).await
}

/// Testable variant — writes to an arbitrary `Write` impl.
pub async fn run_user_with_output(
    client: AkClient,
    args: RevokeUserArgs,
    output: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    let path = format!(
        "/api/v1/admin/users/{}/cli-sessions/revoke",
        urlencoded(&args.user_id)
    );
    let resp: CliSessionCutoffResponse = client.post(&path, &serde_json::json!({})).await?;
    match output {
        OutputFormat::Json => writeln!(out, "{}", format_json(&resp))?,
        OutputFormat::Table => writeln!(
            out,
            "user_id:            {}\n\
             cutoff:             {}\n\
             cutoff_expires_at:  {}\n\
             \n\
             Every CliSession for this user issued at or before the cutoff is \
             now refused.\n\
             The user can run `hort-cli auth login` again right away; the new \
             session is admitted.",
            resp.user_id, resp.cutoff, resp.cutoff_expires_at
        )?,
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Request resolution
// ---------------------------------------------------------------------------

/// Turn the argument pair into the request body, reading the token
/// from `stdin` when `--token -` was given.
fn resolve_request(args: RevokeArgs, stdin: &mut impl Read) -> Result<RevokeCliSessionRequest> {
    match (args.token, args.jti, args.expires_at) {
        (Some(token), _, _) => {
            let raw = if token.trim() == "-" {
                let mut buf = String::new();
                stdin
                    .read_to_string(&mut buf)
                    .context("reading the token from stdin")?;
                buf
            } else {
                token
            };
            claims_from_token(raw.trim())
        }
        (None, Some(jti), Some(expires_at)) => Ok(RevokeCliSessionRequest {
            jti,
            expires_at: normalise_timestamp(&expires_at)?,
        }),
        // clap's `requires`/`conflicts_with_all` already reject the
        // partial forms, so this is the all-absent case.
        (None, _, _) => bail!(
            "supply either --token <JWT> (or --token - to read it from stdin) \
             or both --jti and --expires-at"
        ),
    }
}

/// Read `jti` and `exp` out of a CliSession JWT's payload.
///
/// No signature verification: this extracts two claims so the operator
/// does not have to run `base64 -d` by hand, and a forged token names
/// a `jti` nothing will ever present. The server is the authority on
/// what the revocation means.
fn claims_from_token(token: &str) -> Result<RevokeCliSessionRequest> {
    let payload_b64 = token
        .split('.')
        .nth(1)
        .filter(|_| token.split('.').count() == 3)
        .ok_or_else(|| anyhow!("not a JWT: expected three dot-separated segments"))?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("the JWT payload segment is not base64url")?;
    let json: serde_json::Value =
        serde_json::from_slice(&payload).context("the JWT payload is not JSON")?;

    let jti = json
        .get("jti")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("the token carries no `jti` claim — nothing to revoke by id"))?;
    let exp = json
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| anyhow!("the token carries no numeric `exp` claim"))?;

    Ok(RevokeCliSessionRequest {
        jti: jti.to_string(),
        expires_at: unix_seconds_to_rfc3339(exp)?,
    })
}

/// Accept either an RFC 3339 instant or Unix seconds and emit RFC 3339
/// — the form the server deserialises.
fn normalise_timestamp(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if let Ok(secs) = raw.parse::<i64>() {
        return unix_seconds_to_rfc3339(secs);
    }
    let parsed = raw
        .parse::<chrono::DateTime<chrono::Utc>>()
        .with_context(|| format!("`{raw}` is neither RFC 3339 nor Unix seconds"))?;
    Ok(parsed.to_rfc3339())
}

fn unix_seconds_to_rfc3339(secs: i64) -> Result<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339())
        .ok_or_else(|| anyhow!("`{secs}` is not a representable Unix timestamp"))
}

/// Percent-encode a single URL path segment. Mirrors the helper in
/// `admin/users/effective_permissions.rs`.
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0x0f) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt_with_payload(payload: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("header.{b64}.signature")
    }

    #[test]
    fn claims_are_read_out_of_the_token_payload() {
        let jwt =
            jwt_with_payload(r#"{"jti":"11111111-1111-1111-1111-111111111111","exp":1800000000}"#);
        let req = claims_from_token(&jwt).expect("decodes");
        assert_eq!(req.jti, "11111111-1111-1111-1111-111111111111");
        assert_eq!(req.expires_at, "2027-01-15T08:00:00+00:00");
    }

    #[test]
    fn a_token_without_a_jti_is_an_error_not_a_guess() {
        let jwt = jwt_with_payload(r#"{"exp":1800000000}"#);
        let err = claims_from_token(&jwt).expect_err("no jti");
        assert!(err.to_string().contains("no `jti` claim"), "{err}");
    }

    #[test]
    fn a_token_without_an_exp_is_an_error() {
        let jwt = jwt_with_payload(r#"{"jti":"abc"}"#);
        let err = claims_from_token(&jwt).expect_err("no exp");
        assert!(err.to_string().contains("no numeric `exp` claim"), "{err}");
    }

    #[test]
    fn a_non_jwt_is_rejected_before_any_request() {
        let err = claims_from_token("not-a-jwt").expect_err("not a jwt");
        assert!(err.to_string().contains("not a JWT"), "{err}");
        let err = claims_from_token("a.b.c.d").expect_err("four segments");
        assert!(err.to_string().contains("not a JWT"), "{err}");
    }

    #[test]
    fn a_payload_that_is_not_base64url_is_rejected() {
        let err = claims_from_token("header.!!!.sig").expect_err("bad base64");
        assert!(err.to_string().contains("base64url"), "{err}");
    }

    #[test]
    fn a_payload_that_is_not_json_is_rejected() {
        let jwt = jwt_with_payload("not json");
        let err = claims_from_token(&jwt).expect_err("bad json");
        assert!(err.to_string().contains("not JSON"), "{err}");
    }

    #[test]
    fn an_unrepresentable_exp_is_rejected() {
        let jwt = jwt_with_payload(r#"{"jti":"abc","exp":99999999999999999}"#);
        let err = claims_from_token(&jwt).expect_err("exp out of range");
        assert!(err.to_string().contains("not a representable"), "{err}");
    }

    #[test]
    fn explicit_jti_and_expires_at_accept_both_timestamp_forms() {
        let rfc = resolve_request(
            RevokeArgs {
                token: None,
                jti: Some("abc".into()),
                expires_at: Some("2027-01-15T08:00:00Z".into()),
            },
            &mut std::io::empty(),
        )
        .expect("rfc3339");
        let unix = resolve_request(
            RevokeArgs {
                token: None,
                jti: Some("abc".into()),
                expires_at: Some("1800000000".into()),
            },
            &mut std::io::empty(),
        )
        .expect("unix seconds");
        assert_eq!(rfc.expires_at, unix.expires_at);
    }

    #[test]
    fn an_unparseable_expires_at_is_rejected() {
        let err = resolve_request(
            RevokeArgs {
                token: None,
                jti: Some("abc".into()),
                expires_at: Some("tomorrow".into()),
            },
            &mut std::io::empty(),
        )
        .expect_err("not a timestamp");
        assert!(
            err.to_string()
                .contains("neither RFC 3339 nor Unix seconds"),
            "{err}"
        );
    }

    #[test]
    fn dash_token_reads_the_jwt_from_stdin() {
        let jwt =
            jwt_with_payload(r#"{"jti":"22222222-2222-2222-2222-222222222222","exp":1800000000}"#);
        // A trailing newline is what a `cat`/paste pipeline produces.
        let piped = format!("{jwt}\n");
        let req = resolve_request(
            RevokeArgs {
                token: Some("-".into()),
                jti: None,
                expires_at: None,
            },
            &mut piped.as_bytes(),
        )
        .expect("reads stdin");
        assert_eq!(req.jti, "22222222-2222-2222-2222-222222222222");
    }

    #[test]
    fn neither_form_supplied_is_an_error() {
        let err = resolve_request(
            RevokeArgs {
                token: None,
                jti: None,
                expires_at: None,
            },
            &mut std::io::empty(),
        )
        .expect_err("nothing supplied");
        assert!(err.to_string().contains("--token"), "{err}");
    }

    #[test]
    fn urlencoded_passes_through_uuid() {
        let uuid = "11111111-1111-1111-1111-111111111111";
        assert_eq!(urlencoded(uuid), uuid);
    }

    #[test]
    fn urlencoded_blocks_traversal() {
        assert_eq!(urlencoded("../x"), "..%2Fx");
    }
}
