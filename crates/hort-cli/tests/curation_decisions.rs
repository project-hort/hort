//! Integration tests for `hort-cli curation decisions`.
//!
//! Four scenarios per the backlog:
//! 1. `decisions_happy_path_table` — 200 OK with `events` populated →
//!    table renders header + a per-event row.
//! 2. `decisions_rbac_403_returns_error` — 403 → Err.
//! 3. `decisions_by_correlation_renders_groups` — `--by-correlation`
//!    causes the CLI to pass `by_correlation=true` AND render the
//!    `groups` shape (server returns `by_correlation:true` with
//!    non-empty `groups` and empty `events`).
//! 4. `decisions_empty_result_table_keeps_header` — empty events list
//!    still emits the header row + a "no entries" friendly message.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::decisions::{run_with_output, DecisionsArgs};

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

const ROUTE: &str = "/api/v1/admin/curation/decisions";

fn default_args() -> DecisionsArgs {
    DecisionsArgs {
        type_: None,
        actor: None,
        repository: None,
        package: None,
        since: None,
        limit: None,
        by_correlation: false,
    }
}

// ---------------------------------------------------------------------------
// Test 1 — happy path (events shape, default rendering)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decisions_happy_path_table() {
    {
        let _g = lock_env();
        clear_env();
    }

    let body = r#"{
        "by_correlation": false,
        "events": [
            {
                "event_id": "11111111-1111-1111-1111-111111111111",
                "kind": "waive",
                "actor_id": "22222222-2222-2222-2222-222222222222",
                "artifact_id": "33333333-3333-3333-3333-333333333333",
                "policy_id": null,
                "cve_id": null,
                "justification": "false-positive in container layer",
                "correlation_id": "44444444-4444-4444-4444-444444444444",
                "occurred_at": "2026-05-01T12:00:00Z"
            }
        ],
        "groups": []
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
    let mut buf = Vec::new();
    run_with_output(client, default_args(), OutputFormat::Table, &mut buf)
        .await
        .expect("decisions succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    // Events-shape header.
    assert!(out.contains("EVENT_ID"), "events header: {out}");
    assert!(out.contains("JUSTIFICATION"), "header complete: {out}");
    // Row content.
    assert!(out.contains("waive"));
    assert!(out.contains("false-positive in container layer"));
    // Must NOT render the groups-shape header.
    assert!(
        !out.contains("EVENT_COUNT"),
        "events mode must not show groups columns: {out}"
    );
    // Must NOT show the empty-result message.
    assert!(!out.contains("No curation decisions"));
}

// ---------------------------------------------------------------------------
// Test 2 — 403 RBAC denial surfaces as Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decisions_rbac_403_returns_error() {
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
    let mut buf = Vec::new();
    let result = run_with_output(client, default_args(), OutputFormat::Table, &mut buf).await;
    assert!(result.is_err(), "403 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("403") || err.contains("forbidden") || err.contains("Forbidden"),
        "error references 403: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — --by-correlation: CLI passes `by_correlation=true` AND
// renders the `groups` shape from the response.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decisions_by_correlation_renders_groups() {
    {
        let _g = lock_env();
        clear_env();
    }

    // Server returns a single group rolling up two events under the
    // same correlation_id. The CLI must:
    //   1. Send `?by_correlation=true` on the wire (mockito match_query
    //      asserts this).
    //   2. Render the groups-shape header (`EVENT_COUNT`, etc.) — NOT
    //      the events-shape header (`EVENT_ID`).
    let body = r#"{
        "by_correlation": true,
        "events": [],
        "groups": [
            {
                "correlation_id": "55555555-5555-5555-5555-555555555555",
                "kind": "block",
                "actor_id": "66666666-6666-6666-6666-666666666666",
                "event_count": 2,
                "first_occurred_at": "2026-05-01T12:00:00Z",
                "last_occurred_at": "2026-05-01T12:00:05Z",
                "justification": "supply-chain risk recognised manually"
            }
        ]
    }"#;

    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", ROUTE)
        .match_query(mockito::Matcher::UrlEncoded(
            "by_correlation".into(),
            "true".into(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let mut args = default_args();
    args.by_correlation = true;

    let mut buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut buf)
        .await
        .expect("decisions --by-correlation succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    // Groups-shape columns present.
    assert!(out.contains("CORRELATION"), "header: {out}");
    assert!(out.contains("EVENT_COUNT"), "header includes count: {out}");
    assert!(
        out.contains("FIRST_OCCURRED"),
        "header includes first_occurred: {out}"
    );
    // Must NOT render the events-shape header.
    assert!(
        !out.contains("EVENT_ID"),
        "groups mode must NOT show events columns: {out}"
    );
    // Row content from the rollup.
    assert!(out.contains("block"));
    assert!(out.contains("2"), "event_count value: {out}");
    assert!(out.contains("supply-chain risk recognised manually"));
}

// ---------------------------------------------------------------------------
// Test 4 — empty result keeps the header + emits friendly message
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decisions_empty_result_table_keeps_header() {
    {
        let _g = lock_env();
        clear_env();
    }

    let body = r#"{
        "by_correlation": false,
        "events": [],
        "groups": []
    }"#;

    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", ROUTE)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let mut buf = Vec::new();
    run_with_output(client, default_args(), OutputFormat::Table, &mut buf)
        .await
        .expect("empty result still succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    // Header still present.
    assert!(
        out.contains("EVENT_ID"),
        "header must appear on empty result: {out}"
    );
    // Friendly empty-result message.
    assert!(
        out.contains("No curation decisions"),
        "empty-result message: {out}"
    );
}
