//! Integration tests for `hort-cli curation block`.
//!
//! Covers both sub-subcommands:
//! - `block artifact <id>` → `POST /admin/curation/quarantine/:id/block`
//! - `block versions --repo ... --package ... --versions ...` →
//!   `POST /admin/curation/block-versions`
//!
//! Four tests per sub-subcommand (happy table, happy JSON, 403,
//! oversize-justification client-side reject). Plus one extra test on
//! `block versions`: partial-success response renders the `failed` and
//! `not_found_versions` sections in red so the operator sees them.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::block::{
    run_artifact_with_output, run_versions_with_output, BlockArtifactArgs, BlockVersionsArgs,
};

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

const ARTIFACT_ID: &str = "22222222-2222-2222-2222-222222222222";
const CORRELATION_ID: &str = "33333333-3333-3333-3333-333333333333";

/// Minimal "trivial envelope" the single-artifact endpoint returns —
/// at most one entry in any list.
fn trivial_envelope_blocked() -> String {
    format!(
        r#"{{
            "correlation_id": "{CORRELATION_ID}",
            "blocked_artifact_ids": ["{ARTIFACT_ID}"],
            "already_rejected_ids": [],
            "not_found_versions": [],
            "failed": []
        }}"#
    )
}

// ===========================================================================
// `block artifact` — 4 tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 1 — block artifact happy path (table)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_artifact_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/block");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(trivial_envelope_blocked())
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockArtifactArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "shadow-IT removal — operator-flagged".to_string(),
    };

    let mut buf = Vec::new();
    run_artifact_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("block artifact succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains("CORRELATION_ID"), "header: {out}");
    assert!(
        out.contains(CORRELATION_ID),
        "correlation id rendered: {out}"
    );
    assert!(out.contains("BLOCKED"), "BLOCKED header: {out}");
}

// ---------------------------------------------------------------------------
// Test 2 — block artifact happy path (JSON envelope)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_artifact_happy_path_json() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/block");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(trivial_envelope_blocked())
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockArtifactArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    run_artifact_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(
        parsed
            .get("correlation_id")
            .and_then(|v| v.as_str())
            .expect("correlation_id"),
        CORRELATION_ID
    );
    let blocked = parsed
        .get("blocked_artifact_ids")
        .and_then(|v| v.as_array())
        .expect("blocked_artifact_ids array");
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].as_str().unwrap(), ARTIFACT_ID);
}

// ---------------------------------------------------------------------------
// Test 3 — block artifact 403 → Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_artifact_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/block");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(403)
        .with_body(r#"{"error":"insufficient permissions"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockArtifactArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    let res = run_artifact_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(res.is_err(), "403 must propagate");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("403") || err.contains("orbidden"),
        "error references 403: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — block artifact > 512-byte justification → CLI gate, no HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_artifact_oversize_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/curation/quarantine/{ARTIFACT_ID}/block");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockArtifactArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "a".repeat(513),
    };

    let mut buf = Vec::new();
    let res = run_artifact_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(res.is_err(), "must short-circuit before HTTP call");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("512") || err.contains("exceeds"),
        "error references the cap: {err}"
    );
    m.assert_async().await;
}

// ===========================================================================
// `block versions` — 4 tests + 1 partial-success extra
// ===========================================================================

const BULK_ROUTE: &str = "/api/v1/admin/curation/block-versions";

// ---------------------------------------------------------------------------
// Test 5 — block versions happy path (table)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_versions_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let body = format!(
        r#"{{
            "correlation_id": "{CORRELATION_ID}",
            "blocked_artifact_ids": ["{ARTIFACT_ID}"],
            "already_rejected_ids": [],
            "not_found_versions": [],
            "failed": []
        }}"#
    );
    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", BULK_ROUTE)
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "lodash".to_string(),
        versions: vec!["4.17.20".to_string(), "4.17.21".to_string()],
        justification: "CVE-2026-0001 — bulk block".to_string(),
    };

    let mut buf = Vec::new();
    run_versions_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("block versions succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.contains("CORRELATION_ID"));
    assert!(out.contains(CORRELATION_ID));
    // No detail sections on the happy path — non_found_versions / failed empty.
    assert!(!out.contains("NOT_FOUND_VERSIONS ("));
    assert!(!out.contains("FAILED ("));
}

// ---------------------------------------------------------------------------
// Test 6 — block versions happy path (JSON)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_versions_happy_path_json() {
    {
        let _g = lock_env();
        clear_env();
    }

    let body = format!(
        r#"{{
            "correlation_id": "{CORRELATION_ID}",
            "blocked_artifact_ids": ["{ARTIFACT_ID}"],
            "already_rejected_ids": [],
            "not_found_versions": [],
            "failed": []
        }}"#
    );
    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", BULK_ROUTE)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "lodash".to_string(),
        versions: vec!["4.17.20".to_string()],
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    run_versions_with_output(client, args, OutputFormat::Json, &mut buf)
        .await
        .expect("succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(
        parsed
            .get("correlation_id")
            .and_then(|v| v.as_str())
            .unwrap(),
        CORRELATION_ID
    );
}

// ---------------------------------------------------------------------------
// Test 7 — block versions 403 → Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_versions_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", BULK_ROUTE)
        .with_status(403)
        .with_body(r#"{"error":"forbidden"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "lodash".to_string(),
        versions: vec!["1.0.0".to_string()],
        justification: "valid".to_string(),
    };

    let mut buf = Vec::new();
    let res = run_versions_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(res.is_err(), "403 must propagate");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("403") || err.contains("orbidden"));
}

// ---------------------------------------------------------------------------
// Test 8 — block versions > 512-byte justification → CLI gate, no HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_versions_oversize_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", BULK_ROUTE)
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "lodash".to_string(),
        versions: vec!["1.0.0".to_string()],
        justification: "a".repeat(513),
    };

    let mut buf = Vec::new();
    let res = run_versions_with_output(client, args, OutputFormat::Table, &mut buf).await;
    assert!(res.is_err(), "CLI gate must fire before HTTP");
    m.assert_async().await;
}

// ---------------------------------------------------------------------------
// Test 9 (extra per backlog Item 12) — partial-success response renders
// the FAILED + NOT_FOUND_VERSIONS sections in red. The operator must
// see which artifacts didn't land so they can retry the failed subset
// with the same correlation_id (continue-on-error per design §2.3).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_versions_partial_success_highlights_failed_in_red() {
    {
        let _g = lock_env();
        clear_env();
    }

    let failed_id = "44444444-4444-4444-4444-444444444444";
    let body = format!(
        r#"{{
            "correlation_id": "{CORRELATION_ID}",
            "blocked_artifact_ids": ["{ARTIFACT_ID}"],
            "already_rejected_ids": [],
            "not_found_versions": ["9.9.9"],
            "failed": [
                {{
                    "artifact_id": "{failed_id}",
                    "error_kind": "conflict",
                    "message": "event-store version conflict"
                }}
            ]
        }}"#
    );

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", BULK_ROUTE)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = BlockVersionsArgs {
        repository: "npm-proxy".to_string(),
        package: "lodash".to_string(),
        versions: vec![
            "4.17.20".to_string(),
            "9.9.9".to_string(),
            "4.17.21".to_string(),
        ],
        justification: "CVE-2026-0001".to_string(),
    };

    let mut buf = Vec::new();
    run_versions_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("partial-success is still a 200 — must succeed");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    // NOTE: ANSI escape bytes are NOT asserted here because the
    // production code TTY-gates them via `std::io::stdout().is_terminal()`
    // — under `cargo test` (and CI) stdout is typically piped, so no
    // escapes are emitted. The unit tests in `src/curation/block.rs`
    // assert the ANSI bytes directly by calling `highlight_if_nonzero` /
    // `render_outcome` with `use_ansi=true`. This integration test
    // instead pins the *structural* contract: section headers and per-row
    // details rendered correctly regardless of the surrounding TTY state.
    // See the function-level docstring for the ANSI-suppression behaviour.
    assert!(
        out.contains("FAILED (1)"),
        "failed section header present: {out}"
    );
    assert!(
        out.contains("NOT_FOUND_VERSIONS (1)"),
        "not_found section header present: {out}"
    );
    assert!(
        out.contains(failed_id),
        "failed artifact id rendered: {out}"
    );
    assert!(
        out.contains("event-store version conflict"),
        "failure message rendered: {out}"
    );
    assert!(out.contains("9.9.9"), "not_found version rendered: {out}");
    // The correlation_id should appear at least twice — once in the
    // header row, once in the FAILED retry hint line.
    let count = out.matches(CORRELATION_ID).count();
    assert!(
        count >= 2,
        "correlation_id appears in retry hint + header row (got {count}): {out}"
    );
}
