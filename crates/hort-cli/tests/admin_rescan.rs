//! Integration tests for `hort-cli admin rescan`.
//!
//! Four scenarios cover the wire contract from `hort-http-admin-security`:
//!
//! 1. `rescan_happy_path_prints_task_job_id` — 202 + uuid → exit 0
//! 2. `rescan_unknown_artifact_returns_error` — 404 → Err
//! 3. `rescan_in_flight_returns_error` — 409 → Err
//! 4. `rescan_no_write_permission_returns_error` — 403 → Err
//!
//! Pattern mirrors `tests/admin.rs`: mockito server, env-lock guard
//! dropped before any await, `run_with_output` invoked with a `Vec<u8>`
//! buffer to capture stdout.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::admin::rescan::RescanArgs;
use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};

// ---------------------------------------------------------------------------
// Shared helpers (matches the pattern in tests/admin.rs)
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
const NEW_JOB_ID: &str = "22222222-2222-2222-2222-222222222222";

// ---------------------------------------------------------------------------
// Test 1 — happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rescan_happy_path_prints_task_job_id() {
    {
        let _g = lock_env();
        clear_env();
    }

    let body = format!(r#"{{"task_job_id":"{NEW_JOB_ID}"}}"#);
    let route = format!("/api/v1/artifacts/{ARTIFACT_ID}/rescan");

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", route.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(202)
        .with_header("content-type", "application/json")
        .with_body(&body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = RescanArgs {
        artifact_id: ARTIFACT_ID.to_string(),
    };

    let mut output_buf = Vec::new();
    hort_cli::admin::rescan::run_with_output(client, args, OutputFormat::Table, &mut output_buf)
        .await
        .expect("rescan must succeed");

    m.assert_async().await;

    let output = String::from_utf8(output_buf).expect("utf8");
    assert!(
        output.contains("task_job_id"),
        "table output must label task_job_id: {output}"
    );
    assert!(
        output.contains(NEW_JOB_ID),
        "table output must contain the new jobs.id: {output}"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — 404 unknown artifact (or no Read — anti-enumeration)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rescan_unknown_artifact_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/artifacts/{ARTIFACT_ID}/rescan");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"not_found","message":"artifact not found"}}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = RescanArgs {
        artifact_id: ARTIFACT_ID.to_string(),
    };

    let mut output_buf = Vec::new();
    let result = hort_cli::admin::rescan::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await;

    assert!(result.is_err(), "404 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("404") || err.contains("not_found") || err.contains("not found"),
        "error must reference 404 or not_found: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — 409 in-flight scan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rescan_in_flight_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/artifacts/{ARTIFACT_ID}/rescan");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"error":{"code":"conflict","message":"a scan is already pending or running"}}"#,
        )
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = RescanArgs {
        artifact_id: ARTIFACT_ID.to_string(),
    };

    let mut output_buf = Vec::new();
    let result = hort_cli::admin::rescan::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await;

    assert!(result.is_err(), "409 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("409") || err.contains("conflict") || err.contains("already"),
        "error must reference 409 / conflict / 'already': {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — 403 RBAC fail (Read OK, no Write)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rescan_no_write_permission_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let route = format!("/api/v1/artifacts/{ARTIFACT_ID}/rescan");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", route.as_str())
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"forbidden","message":"write access required"}}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = RescanArgs {
        artifact_id: ARTIFACT_ID.to_string(),
    };

    let mut output_buf = Vec::new();
    let result = hort_cli::admin::rescan::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await;

    assert!(result.is_err(), "403 must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("403") || err.contains("forbidden") || err.contains("write"),
        "error must reference 403 / forbidden / write: {err}"
    );
}
