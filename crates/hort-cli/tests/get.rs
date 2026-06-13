//! Integration tests for `hort-cli get repo-score` subcommand.
//!
//! Six test scenarios:
//!
//! 1. `repo_score_with_name_calls_single_endpoint` — `--name foo` calls
//!    `/api/v1/repositories/foo/security-score`
//! 2. `repo_score_without_name_calls_list_endpoint` — no `--name` calls
//!    `/api/v1/security-score?limit=...&cursor=...`
//! 3. `repo_score_table_format_for_single_includes_columns` — stdout
//!    contains expected columns
//! 4. `repo_score_json_format_pretty_prints` — `--output json` is valid
//!    JSON and round-trips
//! 5. `repo_score_list_pagination_hint` — stderr contains pagination hint
//!    when `next_cursor` present
//! 6. `repo_score_404_for_unknown_repo` — 404 response returns error exit
//!
//! # Env-lock discipline
//!
//! `lock_env` / `clear_env` protect process-global `HORT_*` env vars.
//! The guard is always dropped before the first `await` point in async
//! tests (same pattern as `auth.rs` and `admin.rs`).

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};

// ---------------------------------------------------------------------------
// Shared env-lock helpers
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

/// Build an `AkClient` pointing at the mockito server URL.
fn test_client(server_url: &str) -> AkClient {
    let cfg = EffectiveConfig {
        server: url::Url::parse(server_url).expect("valid url"),
        token: "test-token".to_string(),
        default_format: OutputFormat::Table,
    };
    AkClient::new(&cfg).expect("client builds")
}

/// Sample single security score response.
const SINGLE_SCORE_JSON: &str = r#"{
    "repository": "my-repo",
    "quarantined": 2,
    "rejected": 1,
    "released": 100,
    "severity_histogram": {
        "critical": 0,
        "high": 2,
        "medium": 5,
        "low": 10
    },
    "last_scan_at": "2026-05-08T14:30:00Z"
}"#;

/// Sample list response with two scores and a next cursor.
const LIST_WITH_CURSOR_JSON: &str = r#"{
    "scores": [
        {
            "repository": "repo-alpha",
            "quarantined": 1,
            "rejected": 0,
            "released": 50,
            "severity_histogram": {
                "critical": 1,
                "high": 0,
                "medium": 2,
                "low": 5
            },
            "last_scan_at": "2026-05-07T10:00:00Z"
        },
        {
            "repository": "repo-beta",
            "quarantined": 0,
            "rejected": 2,
            "released": 200,
            "severity_histogram": {
                "critical": 0,
                "high": 1,
                "medium": 3,
                "low": 8
            },
            "last_scan_at": null
        }
    ],
    "next_cursor": "abc123"
}"#;

/// Sample list response without cursor (last page).
#[allow(dead_code)]
const LIST_NO_CURSOR_JSON: &str = r#"{
    "scores": [],
    "next_cursor": null
}"#;

// ---------------------------------------------------------------------------
// Test 1 — repo_score_with_name_calls_single_endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repo_score_with_name_calls_single_endpoint() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", "/api/v1/repositories/my-repo/security-score")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(SINGLE_SCORE_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());

    // Call the repo_score function with a name.
    let result = hort_cli::get::repo_score::run_to_string(
        &client,
        Some("my-repo".to_string()),
        None,
        None,
        OutputFormat::Table,
    )
    .await;

    m.assert_async().await;
    assert!(result.is_ok(), "expect ok, got: {result:?}");
}

// ---------------------------------------------------------------------------
// Test 2 — repo_score_without_name_calls_list_endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repo_score_without_name_calls_list_endpoint() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;

    // Match the list endpoint with query string.
    let m = server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"^/api/v1/security-score\?.*".to_string()),
        )
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(LIST_WITH_CURSOR_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());

    // Call without name.
    let result = hort_cli::get::repo_score::run_to_string(
        &client,
        None,
        Some(10),
        Some("prev-cursor".to_string()),
        OutputFormat::Table,
    )
    .await;

    m.assert_async().await;
    assert!(result.is_ok(), "expect ok, got: {result:?}");
}

// ---------------------------------------------------------------------------
// Test 3 — repo_score_table_format_for_single_includes_columns
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repo_score_table_format_for_single_includes_columns() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/repositories/my-repo/security-score")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(SINGLE_SCORE_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());

    // Capture output by running the command.
    let output = hort_cli::get::repo_score::run_to_string(
        &client,
        Some("my-repo".to_string()),
        None,
        None,
        OutputFormat::Table,
    )
    .await
    .expect("run succeeded");

    // Check for expected columns in table.
    assert!(output.contains("REPOSITORY"), "expect REPOSITORY column");
    assert!(output.contains("my-repo"), "expect repo name");
    assert!(output.contains("QUARANTINED"), "expect QUARANTINED column");
    assert!(output.contains("RELEASED"), "expect RELEASED column");
    assert!(output.contains("CRITICAL"), "expect CRITICAL column");
}

// ---------------------------------------------------------------------------
// Test 4 — repo_score_json_format_pretty_prints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repo_score_json_format_pretty_prints() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/repositories/my-repo/security-score")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(SINGLE_SCORE_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());

    let output = hort_cli::get::repo_score::run_to_string(
        &client,
        Some("my-repo".to_string()),
        None,
        None,
        OutputFormat::Json,
    )
    .await
    .expect("run succeeded");

    // Round-trip the JSON to verify it's valid and has the right shape.
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("output is valid json");
    assert_eq!(parsed["repository"], "my-repo");
    assert_eq!(parsed["quarantined"], 2);
    assert_eq!(parsed["severity_histogram"]["critical"], 0);
}

// ---------------------------------------------------------------------------
// Test 5 — repo_score_list_pagination_hint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repo_score_list_pagination_hint() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"^/api/v1/security-score\?.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(LIST_WITH_CURSOR_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());

    // Capture stderr output (hint is written to stderr).
    let output = hort_cli::get::repo_score::run_to_string_with_stderr(
        &client,
        None,
        Some(10),
        None,
        OutputFormat::Table,
    )
    .await
    .expect("run succeeded");

    // The pagination hint should be in stderr.
    let (_stdout, stderr) = output;
    assert!(
        stderr.contains("--cursor") || stderr.contains("abc123"),
        "expect pagination hint in stderr, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — repo_score_404_for_unknown_repo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repo_score_404_for_unknown_repo() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/repositories/nonexistent/security-score")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"repository not found"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());

    let result = hort_cli::get::repo_score::run_to_string(
        &client,
        Some("nonexistent".to_string()),
        None,
        None,
        OutputFormat::Table,
    )
    .await;

    // Should error with 404.
    assert!(result.is_err(), "expect error for 404");
}
