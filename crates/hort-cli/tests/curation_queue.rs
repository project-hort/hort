//! Integration tests for `hort-cli curation queue`.
//!
//! Two scenarios per the backlog (happy table + 403). Pattern mirrors
//! `tests/admin_quarantine_list.rs`: mockito server, env-lock guard
//! dropped before any await, `run_with_output` invoked with a `Vec<u8>`
//! buffer to capture stdout.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::queue::{run_with_output, QueueArgs};

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

const ROUTE: &str = "/api/v1/admin/curation/queue";

// ---------------------------------------------------------------------------
// Test 1 — happy path: table includes rejection_reason_kind column for
// a rejected row.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn queue_happy_path_table_includes_rejection_reason_kind() {
    {
        let _g = lock_env();
        clear_env();
    }

    // Two rows: one Quarantined (no reason kind), one Rejected with
    // `rejection_reason_kind = "curator"`. Asserts both the header and
    // the per-row projection of the discriminator.
    let body = r#"{
        "entries": [
            {
                "artifact_id": "11111111-1111-1111-1111-111111111111",
                "repository_id": "22222222-2222-2222-2222-222222222222",
                "repository_key": "npm-main",
                "format": "npm",
                "package_name": "evil-pkg",
                "version": "1.0.0",
                "quarantine_status": "quarantined",
                "quarantine_window_start": "2026-05-01T00:00:00Z",
                "quarantine_deadline": "2026-05-08T00:00:00Z",
                "finding_count": 3,
                "max_severity": "high",
                "rejection_reason_kind": null
            },
            {
                "artifact_id": "33333333-3333-3333-3333-333333333333",
                "repository_id": "22222222-2222-2222-2222-222222222222",
                "repository_key": "npm-main",
                "format": "npm",
                "package_name": "shadow-IT",
                "version": "2.0.0",
                "quarantine_status": "rejected",
                "quarantine_window_start": null,
                "quarantine_deadline": null,
                "finding_count": 0,
                "max_severity": null,
                "rejection_reason_kind": "curator"
            }
        ]
    }"#;

    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", ROUTE)
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = QueueArgs {
        repository: None,
        status: None,
        reason: None,
        limit: None,
    };

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("queue succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    // Header row.
    assert!(out.contains("ARTIFACT_ID"), "header present: {out}");
    assert!(
        out.contains("REJECT_REASON"),
        "REJECT_REASON column required: {out}"
    );
    // Both rows' package names appear.
    assert!(out.contains("evil-pkg"), "first row: {out}");
    assert!(out.contains("shadow-IT"), "second row: {out}");
    // Rejected row carries the discriminator.
    assert!(
        out.contains("curator"),
        "rejection_reason_kind rendered: {out}"
    );
    // Quarantine deadline rendered as ISO-8601 for the quarantined row.
    assert!(
        out.contains("2026-05-08T00:00:00Z"),
        "ISO-8601 deadline: {out}"
    );
    // Empty-result message MUST NOT appear when rows are present.
    assert!(!out.contains("No curation queue entries"));
}

// ---------------------------------------------------------------------------
// Test 2 — 403 RBAC denial surfaces as Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn queue_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", ROUTE)
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"insufficient permissions"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = QueueArgs {
        repository: None,
        status: None,
        reason: None,
        limit: None,
    };

    let mut buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(result.is_err(), "403 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("403") || err.contains("forbidden") || err.contains("Forbidden"),
        "error references 403 / forbidden: {err}"
    );
}
