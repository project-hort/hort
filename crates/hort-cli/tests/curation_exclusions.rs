//! Integration tests for `hort-cli curation exclusions`.
//!
//! Two scenarios per the backlog (happy table + 403). Pattern mirrors
//! `tests/curation_queue.rs`.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};
use hort_cli::curation::exclusions::{run_with_output, ExclusionsArgs};

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

const ROUTE: &str = "/api/v1/admin/curation/exclusions";

fn default_args() -> ExclusionsArgs {
    ExclusionsArgs {
        policy: None,
        cve: None,
        actor: None,
        limit: None,
    }
}

// ---------------------------------------------------------------------------
// Test 1 — happy path: table renders both global-scope and
// repository-scope rows with the expected projections.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exclusions_happy_path_table_renders_both_scope_arms() {
    {
        let _g = lock_env();
        clear_env();
    }

    // Two rows: one global-scope, one repository-scope. Asserts the
    // tagged-union `scope` field renders as `global` / `repo:<uuid>`
    // (the table projection from `render_scope`).
    let body = r#"{
        "entries": [
            {
                "exclusion_id": "11111111-1111-1111-1111-111111111111",
                "policy_id": "22222222-2222-2222-2222-222222222222",
                "cve_id": "CVE-2026-1234",
                "package_pattern": "xz-utils@<5.6.2",
                "added_by_actor_id": "33333333-3333-3333-3333-333333333333",
                "reason": "false positive in container layer",
                "scope": { "kind": "global" },
                "added_at": "2026-04-01T00:00:00Z",
                "expires_at": null
            },
            {
                "exclusion_id": "44444444-4444-4444-4444-444444444444",
                "policy_id": "22222222-2222-2222-2222-222222222222",
                "cve_id": "CVE-2026-5678",
                "package_pattern": null,
                "added_by_actor_id": "33333333-3333-3333-3333-333333333333",
                "reason": "vendor patched upstream — tracking",
                "scope": { "kind": "repository", "repository_id": "55555555-5555-5555-5555-555555555555" },
                "added_at": "2026-04-15T00:00:00Z",
                "expires_at": "2026-07-01T00:00:00Z"
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
    let mut buf = Vec::new();
    run_with_output(client, default_args(), OutputFormat::Table, &mut buf)
        .await
        .expect("exclusions succeeds");
    m.assert_async().await;

    let out = String::from_utf8(buf).expect("utf8");
    // Header.
    assert!(out.contains("EXCLUSION_ID"), "header: {out}");
    assert!(out.contains("SCOPE"), "header includes scope: {out}");
    // CVE columns.
    assert!(out.contains("CVE-2026-1234"));
    assert!(out.contains("CVE-2026-5678"));
    // Scope projections.
    assert!(out.contains("global"), "global scope: {out}");
    assert!(
        out.contains("repo:55555555-5555-5555-5555-555555555555"),
        "repository scope projection: {out}"
    );
    // Expires_at projection for the second row (ISO-8601).
    assert!(
        out.contains("2026-07-01T00:00:00Z"),
        "expires_at ISO-8601: {out}"
    );
    // Empty-result message MUST NOT appear when rows present.
    assert!(!out.contains("No exclusions"));
}

// ---------------------------------------------------------------------------
// Test 2 — 403 RBAC denial surfaces as Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exclusions_rbac_403_returns_error() {
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
