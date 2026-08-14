//! Integration tests for `hort-cli curation reevaluate`.
//!
//! Mirrors the mockito test pattern from `tests/curation_waive.rs`:
//!
//! 1. `reevaluate_happy_path_table` — 200 OK → table prints the
//!    artifact id + outcome columns, exit 0.
//! 2. `reevaluate_happy_path_json` — `--output json` → parseable
//!    envelope with `outcome` / `previous_status` / `new_status`.
//! 3. `reevaluate_still_rejected_is_not_an_error` — `still_rejected`
//!    (idempotent, no-op) verdict is still a 200/Ok call, not an error.
//! 4. `reevaluate_conflict_409_returns_error` — the source-state guard
//!    (non-`Rejected` artifact) → Err, no panic, clean message.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::reevaluate::{run_with_output, ReevaluateArgs};

// ---------------------------------------------------------------------------
// Shared helpers (mirrors tests/curation_waive.rs)
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

const ARTIFACT_ID: &str = "11111111-1111-1111-1111-111111111111";

fn route() -> String {
    format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/reevaluate")
}

// ---------------------------------------------------------------------------
// Test 1 — happy path table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reevaluate_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route().as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"outcome":"reset_to_released","previous_status":"rejected","new_status":"released"}"#,
        )
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReevaluateArgs {
        artifact_id: ARTIFACT_ID.to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("reevaluate succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains(ARTIFACT_ID), "artifact id present: {out}");
    assert!(out.contains("reset_to_released"), "outcome present: {out}");
    assert!(out.contains("released"), "new status present: {out}");
}

// ---------------------------------------------------------------------------
// Test 2 — happy path JSON envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reevaluate_happy_path_json() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route().as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"outcome":"reset_to_quarantined","previous_status":"rejected","new_status":"quarantined"}"#,
        )
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReevaluateArgs {
        artifact_id: ARTIFACT_ID.to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("reevaluate succeeds in JSON mode");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("stdout parses as JSON");
    assert_eq!(parsed["outcome"], "reset_to_quarantined");
    assert_eq!(parsed["previous_status"], "rejected");
    assert_eq!(parsed["new_status"], "quarantined");
}

// ---------------------------------------------------------------------------
// Test 3 — `still_rejected` (idempotent no-op) is a successful call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reevaluate_still_rejected_is_not_an_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route().as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"outcome":"still_rejected","previous_status":"rejected","new_status":"rejected"}"#,
        )
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReevaluateArgs {
        artifact_id: ARTIFACT_ID.to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("still_rejected is Ok, not Err");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("stdout parses as JSON");
    assert_eq!(parsed["outcome"], "still_rejected");
}

// ---------------------------------------------------------------------------
// Test 4 — 409 source-state guard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reevaluate_conflict_409_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route().as_str())
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"cannot re-evaluate artifact in state quarantined"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReevaluateArgs {
        artifact_id: ARTIFACT_ID.to_string(),
    };

    let mut buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(result.is_err(), "409 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("409") || err.contains("Conflict") || err.contains("conflict"),
        "error references 409: {err}"
    );
}
