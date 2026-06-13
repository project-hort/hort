//! Integration tests for `hort-cli curation waive`.
//!
//! Four scenarios mirror the mockito test pattern from
//! `tests/admin_quarantine_release.rs`:
//!
//! 1. `waive_happy_path_table` — 200 OK → table prints "waived
//!    artifact <id>", exit 0.
//! 2. `waive_happy_path_json` — `--output json` → parseable
//!    `{"waived_artifact_id":"<uuid>"}` envelope.
//! 3. `waive_rbac_403_returns_error` — 403 → Err, no panic, clean
//!    message.
//! 4. `waive_oversize_justification_does_not_call_server` — 513-byte
//!    justification → CLI-side gate fires; mockito sees ZERO requests
//!    via `.expect(0)`.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::waive::{run_with_output, WaiveArgs};

// ---------------------------------------------------------------------------
// Shared helpers (mirrors tests/admin_quarantine_release.rs)
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

// ---------------------------------------------------------------------------
// Test 1 — happy path table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn waive_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/waive");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .with_status(200)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "CVE-2026-0001 false-positive".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("waive succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains("waived artifact"), "table label: {out}");
    assert!(out.contains(ARTIFACT_ID), "artifact id present: {out}");
}

// ---------------------------------------------------------------------------
// Test 2 — happy path JSON envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn waive_happy_path_json() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/waive");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .with_status(200)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("waive succeeds in JSON mode");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("stdout parses as JSON");
    let id = parsed
        .as_object()
        .expect("top-level object")
        .get("waived_artifact_id")
        .expect("waived_artifact_id field")
        .as_str()
        .expect("string");
    assert_eq!(id, ARTIFACT_ID);
}

// ---------------------------------------------------------------------------
// Test 3 — 403 RBAC denial
// ---------------------------------------------------------------------------

#[tokio::test]
async fn waive_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/waive");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"insufficient permissions"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = WaiveArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(result.is_err(), "403 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("403") || err.contains("Forbidden") || err.contains("forbidden"),
        "error references 403: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — > 512-byte justification → CLI-side gate, no HTTP call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn waive_oversize_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/waive");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .expect(0)
        .create_async()
        .await;

    let oversize = "a".repeat(513);
    let client = test_client(&server.url());
    let args = WaiveArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: oversize,
    };

    let mut buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(
        result.is_err(),
        "> 512-byte justification must return Err BEFORE the HTTP call"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("512") || err.contains("exceeds") || err.contains("justification"),
        "error references the cap: {err}"
    );
    m.assert_async().await;
}
