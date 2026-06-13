//! Integration tests for `hort-cli curation exclude-finding`.
//!
//! Four scenarios mirror the mockito test pattern from
//! `tests/admin_quarantine_release.rs`:
//!
//! 1. `exclude_finding_happy_path_table` — 201 Created → table prints
//!    "excluded <cve> on policy <id> (exclusion_id <uuid>)", exit 0.
//! 2. `exclude_finding_happy_path_json` — JSON envelope with the
//!    server-minted `exclusion_id`.
//! 3. `exclude_finding_rbac_403_returns_error` — 403 → Err.
//! 4. `exclude_finding_oversize_justification_does_not_call_server` —
//!    513-byte justification → CLI gate fires; ZERO HTTP calls.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::exclude_finding::{run_with_output, ExcludeFindingArgs};

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

const POLICY_ID: &str = "55555555-5555-5555-5555-555555555555";
const EXCLUSION_ID: &str = "66666666-6666-6666-6666-666666666666";
const CVE: &str = "CVE-2026-0001";

// ---------------------------------------------------------------------------
// Test 1 — happy path table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exclude_finding_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions");
    let body = format!(r#"{{"exclusion_id":"{EXCLUSION_ID}"}}"#);

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ExcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        justification: "false-positive — affects only test code paths".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("exclude-finding succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains("excluded"), "label present: {out}");
    assert!(out.contains(CVE), "cve rendered: {out}");
    assert!(out.contains(POLICY_ID), "policy id rendered: {out}");
    assert!(out.contains(EXCLUSION_ID), "exclusion id rendered: {out}");
}

// ---------------------------------------------------------------------------
// Test 2 — happy path JSON envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exclude_finding_happy_path_json() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions");
    let body = format!(r#"{{"exclusion_id":"{EXCLUSION_ID}"}}"#);

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ExcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(
        parsed.get("exclusion_id").and_then(|v| v.as_str()).unwrap(),
        EXCLUSION_ID
    );
}

// ---------------------------------------------------------------------------
// Test 3 — 403 → Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exclude_finding_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(403)
        .with_body(r#"{"error":"forbidden"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ExcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    let res = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(res.is_err(), "403 must propagate");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("403") || err.contains("orbidden"));
}

// ---------------------------------------------------------------------------
// Test 4 — > 512-byte justification → CLI gate fires; no HTTP call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exclude_finding_oversize_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ExcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        justification: "a".repeat(513),
    };

    let mut buf = Vec::new();
    let res = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(res.is_err(), "CLI gate must fire before HTTP");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("512") || err.contains("exceeds"),
        "error references the cap: {err}"
    );
    m.assert_async().await;
}
