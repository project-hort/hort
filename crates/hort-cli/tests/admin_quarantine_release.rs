//! Integration tests for `hort-cli admin quarantine release`.
//!
//! Four scenarios cover the wire contract from
//! `hort-http-core::handlers::admin::post_quarantine_release`:
//!
//! 1. `release_happy_path_returns_204_and_prints_released` — 204
//!    No Content → table prints "released artifact <id>", exit 0. This
//!    is THE test that proves `post_no_response` does not choke on an
//!    empty body (where `post` would).
//! 2. `release_empty_justification_does_not_call_server` — empty
//!    `--justification` triggers the CLI-side gate; the mockito server
//!    sees ZERO requests. This is the load-bearing assertion that
//!    client-side validation fires before any HTTP round-trip.
//! 3. `release_404_unknown_artifact_returns_error` — 404 → Err.
//! 4. `release_rbac_403_returns_error` — 403 → Err.
//!
//! Pattern mirrors `tests/admin_rescan.rs`: mockito server, env-lock
//! guard dropped before any await, `run_with_output` invoked with a
//! `Vec<u8>` buffer to capture stdout.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::admin::quarantine::release::{run_with_output, ReleaseArgs};
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

const ARTIFACT_ID: &str = "11111111-1111-1111-1111-111111111111";

// ---------------------------------------------------------------------------
// Test 1 — happy path: 204 + table output "released artifact <id>"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_happy_path_returns_204_and_prints_released() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/quarantine/{ARTIFACT_ID}/release");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        // The server returns 204 with NO body — exercising the
        // `post_no_response` code path. If the CLI ever regresses to
        // `post::<T>()` against this endpoint, it would fail with an
        // "EOF while parsing a value" deserialise error and this test
        // would flip red.
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReleaseArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "CVE-2026-XXXX accepted: false-positive".to_string(),
    };

    let mut output_buf = Vec::new();
    run_with_output(client, args, OutputFormat::Table, &mut output_buf)
        .await
        .expect("release must succeed");

    m.assert_async().await;

    let output = String::from_utf8(output_buf).expect("utf8");
    assert!(
        output.contains("released artifact"),
        "table output must label release: {output}"
    );
    assert!(
        output.contains(ARTIFACT_ID),
        "table output must include the artifact id: {output}"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — empty justification → CLI-side rejection, NO HTTP call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_empty_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/quarantine/{ARTIFACT_ID}/release");

    // Set up the mockito server with a mock that asserts the endpoint
    // is NEVER called. `expect(0)` + `.assert_async()` is the load-bearing
    // pin: if the CLI ever sends the request despite the empty
    // justification, this trips.
    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .expect(0)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReleaseArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "".to_string(),
    };

    let mut output_buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut output_buf).await;

    assert!(
        result.is_err(),
        "empty justification must return Err BEFORE the HTTP call"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("empty") || err.contains("justification"),
        "error must reference the empty-justification check: {err}"
    );

    // `expect(0)` + `assert_async` is mockito's idiomatic "this route
    // must NOT have been called" assertion: if a request landed,
    // `assert_async` would panic with the mismatch. This is the
    // load-bearing pin that the client-side validation gate fires
    // BEFORE any HTTP round-trip.
    m.assert_async().await;

    // Whitespace-only also trips the gate.
    let mut server2 = Server::new_async().await;
    let m2 = server2
        .mock("POST", route.as_str())
        .expect(0)
        .create_async()
        .await;
    let client2 = test_client(&server2.url());
    let args2 = ReleaseArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "   \n\t  ".to_string(),
    };
    let mut buf2 = Vec::new();
    let res2 = run_with_output(client2, args2, OutputFormat::Table, &mut buf2).await;
    assert!(
        res2.is_err(),
        "whitespace-only justification must also short-circuit"
    );
    m2.assert_async().await;
}

// ---------------------------------------------------------------------------
// Test 3 — 404 unknown artifact → Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_404_unknown_artifact_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/quarantine/{ARTIFACT_ID}/release");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"not_found","message":"artifact not found"}}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReleaseArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
    };

    let mut output_buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut output_buf).await;

    assert!(result.is_err(), "404 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("404") || err.contains("not_found") || err.contains("not found"),
        "error must reference 404 / not_found: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — `--output json` happy path
//
// The existing happy-path test covers the table mode; this asserts that
// JSON mode emits parseable JSON with the documented synthetic envelope
// `{"released_artifact_id": "..."}` even though the server returned 204
// with no body.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_json_output_emits_synthesised_envelope() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/quarantine/{ARTIFACT_ID}/release");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .with_status(204)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReleaseArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
    };

    let mut output_buf = Vec::new();
    run_with_output(client, args, OutputFormat::Json, &mut output_buf)
        .await
        .expect("release must succeed in JSON mode");

    m.assert_async().await;

    let stdout = String::from_utf8(output_buf).expect("utf8");
    // Stdout MUST parse as valid JSON — `jq` consumers depend on this.
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout parses as valid JSON");
    // The synthetic envelope shape is the public CLI contract per the
    // module-level doc on `run_with_output`: operators script against
    // `jq '.released_artifact_id'`. Lock it in.
    let id = parsed
        .as_object()
        .expect("top-level is a JSON object")
        .get("released_artifact_id")
        .expect("released_artifact_id field is present")
        .as_str()
        .expect("released_artifact_id is a string");
    assert_eq!(id, ARTIFACT_ID);
}

// ---------------------------------------------------------------------------
// Test 5 — > 512-byte justification short-circuits client-side;
//           NO HTTP call lands.
//
// The unit test `max_justification_bytes_matches_server_cap` pins the
// constant; this integration test pins the END-TO-END behaviour: the
// CLI gate fires before any HTTP round-trip when the operator pastes an
// oversize justification (e.g. a commit message). Mirrors the
// architect-skill rationale: "CLI mirrors the requirement client-side so
// empty / oversize input fails fast rather than producing a 400".
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_oversize_justification_does_not_call_server() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/quarantine/{ARTIFACT_ID}/release");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        // `expect(0)` + `assert_async()` is the load-bearing pin: if any
        // request landed despite the > 512-byte justification, this trips.
        .expect(0)
        .create_async()
        .await;

    // 513 bytes of ASCII — exactly one byte over the cap. ASCII guarantees
    // byte-count == char-count so this length isn't sensitive to UTF-8
    // edge cases.
    let oversize = "a".repeat(513);
    assert_eq!(
        oversize.len(),
        513,
        "test fixture is exactly one byte over the 512 cap"
    );

    let client = test_client(&server.url());
    let args = ReleaseArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: oversize,
    };

    let mut output_buf = Vec::new();
    let result = run_with_output(client, args, OutputFormat::Table, &mut output_buf).await;

    assert!(
        result.is_err(),
        "> 512-byte justification must return Err BEFORE the HTTP call"
    );
    let err = result.unwrap_err().to_string();
    // The exact message wording is asserted loosely — what matters is
    // that the error references the size cap (the message is currently
    // "justification exceeds 512 bytes (got 513)").
    assert!(
        err.contains("512") || err.contains("exceeds") || err.contains("justification"),
        "error must reference the size cap: {err}"
    );

    // Confirms no HTTP request landed.
    m.assert_async().await;
}

// ---------------------------------------------------------------------------
// Test 6 — 403 RBAC denial → Err
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_rbac_403_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/admin/quarantine/{ARTIFACT_ID}/release");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"insufficient permissions"}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = ReleaseArgs {
        artifact_id: ARTIFACT_ID.to_string(),
        justification: "valid".to_string(),
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
