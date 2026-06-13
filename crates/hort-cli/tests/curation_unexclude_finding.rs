//! Integration tests for `hort-cli curation unexclude-finding`.
//!
//! Four scenarios mirror the mockito pattern:
//!
//! 1. `unexclude_finding_happy_path_table` — 204 No Content → table
//!    prints "removed exclusion <cve> from policy <id>", exit 0.
//! 2. `unexclude_finding_happy_path_json` — JSON synthesised envelope
//!    `{"removed_exclusion_cve":"...","policy_id":"..."}`.
//! 3. `unexclude_finding_rbac_403_returns_error` — 403 → Err.
//! 4. `unexclude_finding_oversize_justification_does_not_call_server`
//!    — 513-byte justification → CLI gate fires; ZERO HTTP calls.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::unexclude_finding::{run_with_output, UnexcludeFindingArgs};

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

const POLICY_ID: &str = "77777777-7777-7777-7777-777777777777";
const CVE: &str = "CVE-2026-9999";

// ---------------------------------------------------------------------------
// Test 1 — happy path table (204 No Content)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexclude_finding_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
        policy: POLICY_ID.to_string(),
        cve: CVE.to_string(),
        justification: "false-positive reversed — re-arm CVE".to_string(),
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("unexclude-finding succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains("removed"), "label present: {out}");
    assert!(out.contains(CVE), "cve present: {out}");
    assert!(out.contains(POLICY_ID), "policy id present: {out}");
}

// ---------------------------------------------------------------------------
// Test 2 — happy path JSON synthesised envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexclude_finding_happy_path_json() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
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
    let obj = parsed.as_object().expect("top-level object");
    assert_eq!(
        obj.get("removed_exclusion_cve")
            .and_then(|v| v.as_str())
            .unwrap(),
        CVE
    );
    assert_eq!(
        obj.get("policy_id").and_then(|v| v.as_str()).unwrap(),
        POLICY_ID
    );
}

// ---------------------------------------------------------------------------
// Test 3 — 403 → Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexclude_finding_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("DELETE", route.as_str())
        .with_status(403)
        .with_body(r#"{"error":"forbidden"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
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
async fn unexclude_finding_oversize_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/policies/{POLICY_ID}/exclusions/{CVE}");

    let mut server = Server::new_async().await;
    let m = server
        .mock("DELETE", route.as_str())
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = UnexcludeFindingArgs {
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
        "error references cap: {err}"
    );
    m.assert_async().await;
}
