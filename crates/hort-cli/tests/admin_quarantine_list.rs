//! Integration tests for `hort-cli admin quarantine list-patch-candidates`.
//!
//! Four scenarios cover the wire contract from
//! `hort-http-core::handlers::admin`:
//!
//! 1. `list_patch_candidates_happy_path_renders_two_rows` — 200 + two rows
//!    → table output contains both packages, exit 0.
//! 2. `list_patch_candidates_empty_result_prints_no_candidates_message`
//!    — 200 + `{"candidates":[]}` → table prints "No patch candidates",
//!    exit 0.
//! 3. `list_patch_candidates_rbac_403_returns_error` — 403 → Err.
//! 4. `list_patch_candidates_limit_over_max_returns_error` — 400 → Err.
//!
//! Pattern mirrors `tests/admin_rescan.rs`: mockito server, env-lock
//! guard dropped before any await, `run_with_output` invoked with a
//! `Vec<u8>` buffer to capture stdout.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::admin::quarantine::list_patch_candidates::{
    run_with_output, ListPatchCandidatesArgs,
};
use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};

// ---------------------------------------------------------------------------
// Shared helpers (matches the pattern in tests/admin_rescan.rs)
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

const ROUTE: &str = "/api/v1/admin/quarantine/patch-candidates";

// ---------------------------------------------------------------------------
// Test 1 — happy path: two rows surface in the table output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_patch_candidates_happy_path_renders_two_rows() {
    {
        let _g = lock_env();
        clear_env();
    }

    // Two rows — distinct packages so we can assert both appear.
    let body = r#"{
      "candidates": [
        {
          "quarantined_artifact_id": "11111111-1111-1111-1111-111111111111",
          "quarantined_version": "4.17.21",
          "quarantined_status": "quarantined",
          "quarantined_until": "2030-01-01T00:00:00Z",
          "repository_id": "22222222-2222-2222-2222-222222222222",
          "repository_key": "npm-main",
          "format": "npm",
          "package_name": "lodash",
          "vulnerable_artifact_id": "33333333-3333-3333-3333-333333333333",
          "vulnerable_version": "4.17.20",
          "vulnerable_finding_count": 3,
          "vulnerable_max_severity": "high"
        },
        {
          "quarantined_artifact_id": "44444444-4444-4444-4444-444444444444",
          "quarantined_version": "2.0.0",
          "quarantined_status": "quarantined",
          "quarantined_until": null,
          "repository_id": "22222222-2222-2222-2222-222222222222",
          "repository_key": "pypi-main",
          "format": "pypi",
          "package_name": "requests",
          "vulnerable_artifact_id": "55555555-5555-5555-5555-555555555555",
          "vulnerable_version": "1.9.0",
          "vulnerable_finding_count": 1,
          "vulnerable_max_severity": "critical"
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
    let args = ListPatchCandidatesArgs {
        repository: None,
        limit: None,
    };

    let mut output_buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut output_buf)
        .await
        .expect("list must succeed");

    m.assert_async().await;

    let output = String::from_utf8(output_buf).expect("utf8");
    assert!(
        output.contains("lodash"),
        "first package name must appear: {output}"
    );
    assert!(
        output.contains("requests"),
        "second package name must appear: {output}"
    );
    assert!(
        output.contains("4.17.20 -> 4.17.21"),
        "version transition must appear: {output}"
    );
    assert!(
        output.contains("high"),
        "severity column must render: {output}"
    );
    assert!(
        output.contains("PACKAGE"),
        "header row must appear: {output}"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — empty result: "No patch candidates" line in table mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_patch_candidates_empty_result_prints_no_candidates_message() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", ROUTE)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"candidates":[]}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ListPatchCandidatesArgs {
        repository: None,
        limit: None,
    };

    let mut output_buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut output_buf)
        .await
        .expect("list must succeed on empty result");

    m.assert_async().await;

    let output = String::from_utf8(output_buf).expect("utf8");
    assert!(
        output.contains("No patch candidates"),
        "empty-result message required: {output}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — 403 RBAC denial: error message surfaces "403" / "forbidden"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_patch_candidates_rbac_403_returns_error() {
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
    let args = ListPatchCandidatesArgs {
        repository: None,
        limit: None,
    };

    let mut output_buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut output_buf).await;

    assert!(result.is_err(), "403 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("403") || err.contains("forbidden") || err.contains("Forbidden"),
        "error must reference 403 / forbidden: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — `--output json` happy path
//
// The existing tests in this file cover the table mode; this asserts that
// JSON mode emits parseable, round-trippable JSON whose top-level shape
// matches the documented `PatchCandidateListResponseDto`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_patch_candidates_json_output_round_trips_through_serde() {
    {
        let _g = lock_env();
        clear_env();
    }

    // Single-row body — enough to assert the field projection without
    // duplicating the two-row payload from Test 1.
    let body = r#"{
      "candidates": [
        {
          "quarantined_artifact_id": "11111111-1111-1111-1111-111111111111",
          "quarantined_version": "4.17.21",
          "quarantined_status": "quarantined",
          "quarantined_until": "2030-01-01T00:00:00Z",
          "repository_id": "22222222-2222-2222-2222-222222222222",
          "repository_key": "npm-main",
          "format": "npm",
          "package_name": "lodash",
          "vulnerable_artifact_id": "33333333-3333-3333-3333-333333333333",
          "vulnerable_version": "4.17.20",
          "vulnerable_finding_count": 3,
          "vulnerable_max_severity": "high"
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
    let args = ListPatchCandidatesArgs {
        repository: None,
        limit: None,
    };

    let mut output_buf = Vec::new();
    run_with_output(client, args, OutputFormat::Json, &mut output_buf)
        .await
        .expect("list must succeed in JSON mode");

    m.assert_async().await;

    let stdout = String::from_utf8(output_buf).expect("utf8");
    // Stdout MUST parse as valid JSON. A serde failure here means the CLI
    // emitted malformed or partial JSON — the load-bearing assertion for
    // operators piping `... --output json | jq`.
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout parses as valid JSON");
    // Top-level shape: `{ "candidates": [...] }`.
    let candidates = parsed
        .as_object()
        .expect("top-level is a JSON object")
        .get("candidates")
        .expect("candidates field is present")
        .as_array()
        .expect("candidates is an array");
    assert_eq!(candidates.len(), 1, "single-row body must round-trip");
    // Spot-check one server-side projection survived the round trip.
    assert_eq!(candidates[0]["package_name"], serde_json::json!("lodash"));
    assert_eq!(
        candidates[0]["vulnerable_max_severity"],
        serde_json::json!("high")
    );
}

// ---------------------------------------------------------------------------
// Test 5 — server 400 on limit > MAX (the use-case-side cap is 500)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_patch_candidates_limit_over_max_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", ROUTE)
        .match_query(mockito::Matcher::UrlEncoded("limit".into(), "501".into()))
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"error":{"code":"validation","message":"limit must be in 1..=500 (got 501)"}}"#,
        )
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ListPatchCandidatesArgs {
        repository: None,
        limit: Some(501),
    };

    let mut output_buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut output_buf).await;

    assert!(result.is_err(), "400 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("400") || err.contains("limit") || err.contains("validation"),
        "error must reference 400 / limit / validation: {err}"
    );
}
