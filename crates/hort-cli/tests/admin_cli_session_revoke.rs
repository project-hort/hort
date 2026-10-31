//! Integration tests for `hort-cli admin cli-session revoke` /
//! `revoke-user` — the wire contract against
//! `hort-http-core::handlers::api_tokens`'s two CliSession revocation
//! routes.
//!
//! What these pin that the unit tests cannot:
//!
//! 1. the single-session call POSTs `{jti, expires_at}` — and **not**
//!    the token — to `/api/v1/admin/cli-sessions/revoke`;
//! 2. the subject call POSTs to
//!    `/api/v1/admin/users/<id>/cli-sessions/revoke` and renders the
//!    cutoff window it gets back;
//! 3. a 403 from the admin gate surfaces as an error rather than a
//!    silent success — the failure mode that matters most on a
//!    revocation.
//!
//! Pattern mirrors `tests/admin_rescan.rs`: mockito server, env-lock
//! guard dropped before any await, `run_*_with_output` invoked with a
//! `Vec<u8>` buffer to capture stdout.

use std::sync::Mutex;

use base64::Engine;
use mockito::Server;

use hort_cli::admin::cli_session::revoke::{RevokeArgs, RevokeUserArgs};
use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

const ENV_SLOTS: &[&str] = &["HORT_SERVER", "HORT_TOKEN", "HORT_CONFIG_PATH"];

fn clear_env() {
    for s in ENV_SLOTS {
        std::env::remove_var(s);
    }
}

fn test_client(server_url: &str) -> AkClient {
    let cfg = EffectiveConfig {
        server: url::Url::parse(server_url).expect("valid url"),
        token: "test-token".to_string(),
        default_format: OutputFormat::Table,
    };
    AkClient::new(&cfg).expect("client builds")
}

const JTI: &str = "11111111-1111-1111-1111-111111111111";
const USER_ID: &str = "33333333-3333-3333-3333-333333333333";
/// `exp` = 2027-01-15T08:00:00Z.
const EXP_SECS: i64 = 1_800_000_000;

/// A CliSession-shaped JWT carrying only the two claims the CLI reads.
/// Unsigned on purpose — the decode checks no signature, and that is
/// the behaviour under test.
fn token() -> String {
    let payload = format!(r#"{{"jti":"{JTI}","exp":{EXP_SECS},"sub":"{USER_ID}"}}"#);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    format!("eyJhbGciOiJFZERTQSJ9.{b64}.c2ln")
}

// ---------------------------------------------------------------------------
// Single-session revocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_with_a_token_sends_the_claims_and_never_the_token() {
    {
        let _g = lock_env();
        clear_env();
    }

    let jwt = token();
    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", "/api/v1/admin/cli-sessions/revoke")
        .match_header("authorization", "Bearer test-token")
        // `Matcher::Json` is an EXACT JSON comparison, not a subset
        // one — which is the point. It asserts the body is the two
        // claims read out locally and *nothing else*, so the
        // credential itself provably does not travel; a body that
        // smuggled the token along would put it in the request log of
        // every hop on the way to revoking it. `PartialJson` here
        // would pass with the token attached.
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "jti": JTI,
            "expires_at": "2027-01-15T08:00:00+00:00",
        })))
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let mut out = Vec::new();
    hort_cli::admin::cli_session::revoke::run_with_output(
        client,
        RevokeArgs {
            token: Some(jwt.clone()),
            jti: None,
            expires_at: None,
        },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("revoke must succeed");

    m.assert_async().await;
    let rendered = String::from_utf8(out).expect("utf8");
    assert!(
        rendered.contains(JTI),
        "output must name the jti: {rendered}"
    );
    assert!(
        !rendered.contains(&jwt),
        "the CLI must not echo the credential back: {rendered}"
    );
}

#[tokio::test]
async fn revoke_with_explicit_jti_and_expiry_hits_the_same_route() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", "/api/v1/admin/cli-sessions/revoke")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "jti": JTI,
            "expires_at": "2027-01-15T08:00:00+00:00",
        })))
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let mut out = Vec::new();
    hort_cli::admin::cli_session::revoke::run_with_output(
        client,
        RevokeArgs {
            token: None,
            jti: Some(JTI.to_string()),
            expires_at: Some(EXP_SECS.to_string()),
        },
        OutputFormat::Json,
        &mut out,
    )
    .await
    .expect("revoke must succeed");

    m.assert_async().await;
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json output parses");
    assert_eq!(v["revoked_jti"], JTI);
}

#[tokio::test]
async fn revoke_refused_by_the_admin_gate_is_an_error_not_a_silent_success() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/api/v1/admin/cli-sessions/revoke")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"forbidden","message":"admin required"}}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let mut out = Vec::new();
    let err = hort_cli::admin::cli_session::revoke::run_with_output(
        client,
        RevokeArgs {
            token: Some(token()),
            jti: None,
            expires_at: None,
        },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect_err("a 403 must surface");
    assert!(
        err.to_string().to_lowercase().contains("403")
            || err.to_string().to_lowercase().contains("forbidden"),
        "unhelpful error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Subject-scoped revocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_user_reports_the_cutoff_and_its_window() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/users/{USER_ID}/cli-sessions/revoke");
    let body = format!(
        r#"{{"user_id":"{USER_ID}","cutoff":"2026-10-27T18:00:00Z",
             "cutoff_expires_at":"2026-10-27T18:15:00Z"}}"#
    );

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let mut out = Vec::new();
    hort_cli::admin::cli_session::revoke::run_user_with_output(
        client,
        RevokeUserArgs {
            user_id: USER_ID.to_string(),
        },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect("revoke-user must succeed");

    m.assert_async().await;
    let rendered = String::from_utf8(out).expect("utf8");
    assert!(rendered.contains(USER_ID), "{rendered}");
    assert!(rendered.contains("2026-10-27T18:00:00Z"), "{rendered}");
    assert!(rendered.contains("2026-10-27T18:15:00Z"), "{rendered}");
    // The operator is told this is not a lockout — the single most
    // likely misreading of "revoke every session".
    assert!(
        rendered.contains("auth login"),
        "the output must say the user can log in again: {rendered}"
    );
}

#[tokio::test]
async fn revoke_user_refused_by_the_admin_gate_is_an_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/users/{USER_ID}/cli-sessions/revoke");
    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"forbidden","message":"admin required"}}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let mut out = Vec::new();
    let err = hort_cli::admin::cli_session::revoke::run_user_with_output(
        client,
        RevokeUserArgs {
            user_id: USER_ID.to_string(),
        },
        OutputFormat::Table,
        &mut out,
    )
    .await
    .expect_err("a 403 must surface");
    assert!(
        err.to_string().to_lowercase().contains("403")
            || err.to_string().to_lowercase().contains("forbidden"),
        "unhelpful error: {err}"
    );
}
