//! Integration tests for `hort-cli admin task` subcommands.
//!
//! Twelve test scenarios:
//!
//! 1. `task_invoke_posts_to_correct_url_for_kind`
//! 2. `task_invoke_with_params_file_sends_body`
//! 3. `task_invoke_returns_error_on_4xx`
//! 4. `task_invoke_with_output_json_prints_pretty`
//! 5. `task_list_passes_filters_to_query_string`
//! 6. `task_list_prints_paginated_hint_when_next_cursor_present`
//! 7. `task_list_table_columns`
//! 8. `task_get_for_known_id_prints_full_row`
//! 9. `task_get_for_unknown_id_returns_error`
//! 10. `task_invoke_with_invalid_params_file_returns_clear_error`
//! 11. `task_get_table_bounds_an_unbounded_result_summary`
//! 12. `task_get_json_stays_lossless_at_every_size`
//!
//! # Env-lock discipline
//!
//! `lock_env` / `clear_env` protect process-global `HORT_*` env vars.
//! The guard is always dropped before the first `await` point in async
//! tests (same pattern as `auth.rs`). Tests that don't mutate env vars
//! skip the lock entirely.

use std::sync::Mutex;

use mockito::Server;

use hort_cli::admin::task_get::TaskGetArgs;
use hort_cli::admin::task_invoke::TaskInvokeArgs;
use hort_cli::admin::task_list::TaskListArgs;
use hort_cli::client::AkClient;
use hort_cli::config::{EffectiveConfig, OutputFormat};

// ---------------------------------------------------------------------------
// Shared env-lock helpers (same pattern as auth.rs)
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

/// A sample task JSON row returned by GET endpoints.
const TASK_ROW_JSON: &str = r#"{
    "id": "11111111-1111-1111-1111-111111111111",
    "kind": "noop",
    "status": "completed",
    "priority": 0,
    "trigger_source": "manual",
    "attempts": 1,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:01:00Z"
}"#;

/// A sample invoke response JSON.
const INVOKE_RESP_JSON: &str = r#"{"task_job_id":"22222222-2222-2222-2222-222222222222"}"#;

// ---------------------------------------------------------------------------
// Test 1 — task_invoke_posts_to_correct_url_for_kind
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_invoke_posts_to_correct_url_for_kind() {
    // Drop guard before first await point.
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", "/api/v1/admin/tasks/noop")
        .match_header("authorization", "Bearer test-token")
        .with_status(202)
        .with_header("content-type", "application/json")
        .with_body(INVOKE_RESP_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskInvokeArgs {
        kind: "noop".to_string(),
        params_file: None,
        idempotency_key: None,
        idempotency_key_window: None,
    };

    let mut output_buf = Vec::new();
    hort_cli::admin::task_invoke::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await
    .expect("invoke must succeed");

    m.assert_async().await;

    let output = String::from_utf8(output_buf).expect("utf8");
    assert!(
        output.contains("22222222-2222-2222-2222-222222222222"),
        "output must contain the task_job_id: {output}"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — task_invoke_with_params_file_sends_body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_invoke_with_params_file_sends_body() {
    // Prepare params file before acquiring the env lock so the guard is
    // dropped before any await point.
    let dir = tempfile::tempdir().expect("tempdir");
    let params_path = dir.path().join("params.json");
    std::fs::write(&params_path, r#"{"repo_id":"abc-123","priority":5}"#).expect("write params");

    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("POST", "/api/v1/admin/tasks/retention-purge")
        .match_body(mockito::Matcher::JsonString(
            r#"{"repo_id":"abc-123","priority":5}"#.to_string(),
        ))
        .with_status(202)
        .with_header("content-type", "application/json")
        .with_body(INVOKE_RESP_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskInvokeArgs {
        kind: "retention-purge".to_string(),
        params_file: Some(params_path),
        idempotency_key: None,
        idempotency_key_window: None,
    };

    let mut output_buf = Vec::new();
    hort_cli::admin::task_invoke::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await
    .expect("invoke must succeed");

    m.assert_async().await;
}

// ---------------------------------------------------------------------------
// Test 3 — task_invoke_returns_error_on_4xx
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_invoke_returns_error_on_4xx() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/api/v1/admin/tasks/noop")
        .with_status(422)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"validation_error","message":"kind not in allowlist"}}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskInvokeArgs {
        kind: "noop".to_string(),
        params_file: None,
        idempotency_key: None,
        idempotency_key_window: None,
    };

    let mut output_buf = Vec::new();
    let result = hort_cli::admin::task_invoke::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await;

    // Must return Err on 4xx.
    assert!(result.is_err(), "4xx must propagate as Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("422") || err.contains("validation_error") || err.contains("not in allowlist"),
        "error must reference 4xx status or code/message: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — task_invoke_with_output_json_prints_pretty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_invoke_with_output_json_prints_pretty() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/api/v1/admin/tasks/noop")
        .with_status(202)
        .with_header("content-type", "application/json")
        .with_body(INVOKE_RESP_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskInvokeArgs {
        kind: "noop".to_string(),
        params_file: None,
        idempotency_key: None,
        idempotency_key_window: None,
    };

    let mut output_buf = Vec::new();
    hort_cli::admin::task_invoke::run_with_output(
        client,
        args,
        OutputFormat::Json,
        &mut output_buf,
    )
    .await
    .expect("invoke must succeed");

    let output = String::from_utf8(output_buf).expect("utf8");
    // Pretty JSON contains newlines.
    assert!(
        output.contains('\n'),
        "JSON output must be pretty-printed: {output}"
    );

    let parsed: serde_json::Value = serde_json::from_str(&output).expect("must be valid JSON");
    assert_eq!(
        parsed["task_job_id"], "22222222-2222-2222-2222-222222222222",
        "task_job_id must be present"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — task_list_passes_filters_to_query_string
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_list_passes_filters_to_query_string() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", "/api/v1/admin/tasks")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("kind".to_string(), "noop".to_string()),
            mockito::Matcher::UrlEncoded("status".to_string(), "pending".to_string()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"tasks":[],"next_cursor":null}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskListArgs {
        kind: Some("noop".to_string()),
        status: Some("pending".to_string()),
        limit: None,
        cursor: None,
    };

    let mut output_buf = Vec::new();
    let mut err_buf = Vec::new();
    hort_cli::admin::task_list::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
        &mut err_buf,
    )
    .await
    .expect("list must succeed");

    m.assert_async().await;
}

// ---------------------------------------------------------------------------
// Test 6 — task_list_prints_paginated_hint_when_next_cursor_present
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_list_prints_paginated_hint_when_next_cursor_present() {
    {
        let _g = lock_env();
        clear_env();
    }

    let next_cursor = "33333333-3333-3333-3333-333333333333";
    let body = format!(r#"{{"tasks":[{TASK_ROW_JSON}],"next_cursor":"{next_cursor}"}}"#);

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/admin/tasks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskListArgs {
        kind: None,
        status: None,
        limit: None,
        cursor: None,
    };

    let mut output_buf = Vec::new();
    let mut err_buf = Vec::new();
    hort_cli::admin::task_list::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
        &mut err_buf,
    )
    .await
    .expect("list must succeed");

    let stderr = String::from_utf8(err_buf).expect("utf8");
    assert!(
        stderr.contains(next_cursor),
        "stderr must include the next_cursor value for paging: {stderr}"
    );
    assert!(
        stderr.contains("--cursor"),
        "stderr must include '--cursor' hint: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — task_list_table_columns
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_list_table_columns() {
    {
        let _g = lock_env();
        clear_env();
    }

    let tasks_json = format!(
        r#"[{TASK_ROW_JSON},
        {{
            "id": "44444444-4444-4444-4444-444444444444",
            "kind": "scan",
            "status": "running",
            "priority": 1,
            "trigger_source": "cron",
            "attempts": 0,
            "created_at": "2026-01-02T00:00:00Z",
            "updated_at": "2026-01-02T00:01:00Z"
        }},
        {{
            "id": "55555555-5555-5555-5555-555555555555",
            "kind": "staging-sweep",
            "status": "failed",
            "priority": 0,
            "trigger_source": "manual",
            "attempts": 3,
            "created_at": "2026-01-03T00:00:00Z",
            "updated_at": "2026-01-03T00:05:00Z"
        }}]"#
    );
    let body = format!(r#"{{"tasks":{tasks_json},"next_cursor":null}}"#);

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/admin/tasks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&body)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskListArgs {
        kind: None,
        status: None,
        limit: None,
        cursor: None,
    };

    let mut output_buf = Vec::new();
    let mut err_buf = Vec::new();
    hort_cli::admin::task_list::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
        &mut err_buf,
    )
    .await
    .expect("list must succeed");

    let output = String::from_utf8(output_buf).expect("utf8");

    // Header must include the column names.
    assert!(output.contains("ID"), "table must have ID column: {output}");
    assert!(
        output.contains("KIND"),
        "table must have KIND column: {output}"
    );
    assert!(
        output.contains("STATUS"),
        "table must have STATUS column: {output}"
    );

    // Data must include the three rows.
    assert!(
        output.contains("noop"),
        "table must contain noop row: {output}"
    );
    assert!(
        output.contains("scan"),
        "table must contain scan row: {output}"
    );
    assert!(
        output.contains("staging-sweep"),
        "table must contain staging-sweep row: {output}"
    );
}

// ---------------------------------------------------------------------------
// Test 8 — task_get_for_known_id_prints_full_row
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_get_for_known_id_prints_full_row() {
    {
        let _g = lock_env();
        clear_env();
    }

    let task_id = "11111111-1111-1111-1111-111111111111";

    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", format!("/api/v1/admin/tasks/{task_id}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(TASK_ROW_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskGetArgs {
        task_job_id: task_id.to_string(),
    };

    let mut output_buf = Vec::new();
    hort_cli::admin::task_get::run_with_output(client, args, OutputFormat::Table, &mut output_buf)
        .await
        .expect("get must succeed");

    m.assert_async().await;

    let output = String::from_utf8(output_buf).expect("utf8");
    // The full row must contain at least the id and kind.
    assert!(
        output.contains(task_id) || output.contains("noop"),
        "output must contain row data: {output}"
    );
}

// ---------------------------------------------------------------------------
// Test 9 — task_get_for_unknown_id_returns_error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_get_for_unknown_id_returns_error() {
    {
        let _g = lock_env();
        clear_env();
    }

    let task_id = "99999999-9999-9999-9999-999999999999";

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", format!("/api/v1/admin/tasks/{task_id}").as_str())
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"not_found","message":"task not found"}}"#)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskGetArgs {
        task_job_id: task_id.to_string(),
    };

    let mut output_buf = Vec::new();
    let result = hort_cli::admin::task_get::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await;

    assert!(result.is_err(), "unknown id must return Err");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("404") || err.contains("not_found") || err.contains("not found"),
        "error must reference 404 or not_found: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 10 — task_invoke_with_invalid_params_file_returns_clear_error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_invoke_with_invalid_params_file_returns_clear_error() {
    // Write malformed JSON file before acquiring the env lock.
    let dir = tempfile::tempdir().expect("tempdir");
    let params_path = dir.path().join("bad-params.json");
    std::fs::write(&params_path, r#"{ "key": [not valid json"#).expect("write bad params");

    {
        let _g = lock_env();
        clear_env();
    }

    // No mock needed — the error should occur before any HTTP call.
    let server = Server::new_async().await;

    let client = test_client(&server.url());
    let args = TaskInvokeArgs {
        kind: "noop".to_string(),
        params_file: Some(params_path.clone()),
        idempotency_key: None,
        idempotency_key_window: None,
    };

    let mut output_buf = Vec::new();
    let result = hort_cli::admin::task_invoke::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await;

    assert!(result.is_err(), "invalid params file must return Err");
    let err = result.unwrap_err().to_string();
    // Error must mention the file path.
    let path_str = params_path.to_string_lossy();
    assert!(
        err.contains(path_str.as_ref())
            || err.contains("bad-params.json")
            || err.contains("params-file"),
        "error must mention the file path: {err}"
    );
}

// ---------------------------------------------------------------------------
// `--idempotency-key` flag → Idempotency-Key header
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_invoke_with_idempotency_key_sets_header() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    // The mock matches on the exact header value — if `--idempotency-key`
    // is wired through, the request hits this mock; if not, the request
    // hits no mock and `m.assert_async()` fails the test.
    let m = server
        .mock("POST", "/api/v1/admin/tasks/cron-rescan-tick")
        .match_header("idempotency-key", "2026-05-09T07:00:cron-rescan-tick")
        .with_status(202)
        .with_header("content-type", "application/json")
        .with_body(INVOKE_RESP_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskInvokeArgs {
        kind: "cron-rescan-tick".to_string(),
        params_file: None,
        idempotency_key: Some("2026-05-09T07:00:cron-rescan-tick".to_string()),
        idempotency_key_window: None,
    };

    let mut output_buf = Vec::new();
    hort_cli::admin::task_invoke::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await
    .expect("invoke must succeed");

    m.assert_async().await;
}

#[tokio::test]
async fn task_invoke_without_idempotency_key_omits_header() {
    {
        let _g = lock_env();
        clear_env();
    }

    let mut server = Server::new_async().await;
    // Mockito's `match_header(name, Missing)` requires the named header
    // to be absent on the request. If `--idempotency-key` is omitted,
    // the AkClient must not send the header at all.
    let m = server
        .mock("POST", "/api/v1/admin/tasks/noop")
        .match_header("idempotency-key", mockito::Matcher::Missing)
        .with_status(202)
        .with_header("content-type", "application/json")
        .with_body(INVOKE_RESP_JSON)
        .create_async()
        .await;

    let client = test_client(&server.url());
    let args = TaskInvokeArgs {
        kind: "noop".to_string(),
        params_file: None,
        idempotency_key: None,
        idempotency_key_window: None,
    };

    let mut output_buf = Vec::new();
    hort_cli::admin::task_invoke::run_with_output(
        client,
        args,
        OutputFormat::Table,
        &mut output_buf,
    )
    .await
    .expect("invoke must succeed");

    m.assert_async().await;
}

// ---------------------------------------------------------------------------
// Test 11 — task_get_table_bounds_an_unbounded_result_summary
// ---------------------------------------------------------------------------

/// A task row whose `result_summary` is a `retention-evaluate` dry-run
/// preview carrying `sample_rows` sample entries — the shape whose
/// `groups`/`sample` arrays have no bound.
fn task_row_json_with_summary(task_id: &str, sample_rows: usize) -> String {
    let sample: Vec<serde_json::Value> = (0..sample_rows)
        .map(|i| {
            serde_json::json!({
                "artifact_id": format!("11111111-0000-0000-0000-{i:012}"),
                "repository_key": "npm-proxy",
                "name": format!("some-package-{i}"),
                "version": "1.3.0",
                "age_seconds": 98_765 + i,
            })
        })
        .collect();
    serde_json::json!({
        "id": task_id,
        "kind": "retention-evaluate",
        "status": "completed",
        "priority": 0,
        "trigger_source": "api",
        "attempts": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:04:00Z",
        "completed_at": "2026-01-01T00:04:00Z",
        "result_summary": {
            "mode": "dry_run",
            "coverage": "complete",
            "evaluated": 1_200,
            "expired": 812,
            "preview": { "rows": 812, "sample": sample },
        },
    })
    .to_string()
}

/// Serve `body` as the task row for `task_id` and return what
/// `admin task get` wrote in `output` mode.
async fn task_get_output(task_id: &str, body: &str, output: OutputFormat) -> String {
    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", format!("/api/v1/admin/tasks/{task_id}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let mut output_buf = Vec::new();
    hort_cli::admin::task_get::run_with_output(
        test_client(&server.url()),
        TaskGetArgs {
            task_job_id: task_id.to_string(),
        },
        output,
        &mut output_buf,
    )
    .await
    .expect("task get must succeed at any payload size");

    m.assert_async().await;
    String::from_utf8(output_buf).expect("utf8")
}

/// The reported crash: `admin task get` on a finished dry run. The table
/// must render, bounded, and name the form that shows the whole value.
#[tokio::test]
async fn task_get_table_bounds_an_unbounded_result_summary() {
    {
        let _g = lock_env();
        clear_env();
    }

    let task_id = "33333333-3333-3333-3333-333333333333";
    let body = task_row_json_with_summary(task_id, 4_000);
    assert!(
        body.len() > 100_000,
        "the fixture must be the size the crash was reported at, got {}",
        body.len()
    );

    let output = task_get_output(task_id, &body, OutputFormat::Table).await;

    // Every bounded field is still there whole.
    assert!(output.contains(task_id), "{output}");
    assert!(output.contains("retention-evaluate"), "{output}");
    assert!(output.contains("2026-01-01T00:04:00Z"), "{output}");
    // The unbounded one is cut, says so, and says how to read the rest.
    assert!(
        output.contains("TRUNCATED"),
        "the cut must be unmissable:\n{output}"
    );
    assert!(
        output.contains(&format!("hort-cli admin task get {task_id} --output json")),
        "the cell must name the lossless command for this job:\n{output}"
    );
    assert!(
        output.len() < body.len() / 10,
        "the table must be readable output, not a transcription: {} bytes for a \
         {}-byte row",
        output.len(),
        body.len()
    );
}

// ---------------------------------------------------------------------------
// Test 12 — task_get_json_stays_lossless_at_every_size
// ---------------------------------------------------------------------------

/// `--output json` is the path the table points at, so it is never cut —
/// and is byte-for-byte what it always was: the pretty-printed row.
#[tokio::test]
async fn task_get_json_stays_lossless_at_every_size() {
    {
        let _g = lock_env();
        clear_env();
    }

    let task_id = "44444444-4444-4444-4444-444444444444";
    for sample_rows in [1_usize, 4_000] {
        let body = task_row_json_with_summary(task_id, sample_rows);
        let output = task_get_output(task_id, &body, OutputFormat::Json).await;

        // Byte-identical to the unchanged formula: the pretty-printed
        // row and a trailing newline, with no truncation anywhere in it.
        let row: hort_cli::admin::TaskRow =
            serde_json::from_str(&body).expect("the fixture is a task row");
        assert_eq!(
            output,
            format!("{}\n", hort_cli::output::format_json(&row)),
            "the json path is the pretty-printed row, unchanged \
             ({sample_rows} sample rows)"
        );
        assert!(
            !output.contains("TRUNCATED"),
            "the lossless path never cuts ({sample_rows} sample rows)"
        );

        // And it is lossless against the wire: the whole summary survives.
        let sent: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        let printed: serde_json::Value = serde_json::from_str(&output).expect("valid json");
        assert_eq!(
            printed["result_summary"], sent["result_summary"],
            "every byte of the summary is in the json output ({sample_rows} \
             sample rows)"
        );
    }
}
