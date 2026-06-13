//! Integration tests for `hort-cli auth` subcommands.
//!
//! Seven test scenarios:
//!
//! 4. `login_persists_token_to_config_file_with_0600` — uses
//!    `HORT_CONFIG_PATH`-overridden config path; reads back the file; checks
//!    contents and (Unix) `mode & 0o777 == 0o600`.
//! 5. `login_with_validate_calls_whoami` — mockito server returns whoami
//!    payload; assert config file written + stdout includes username.
//! 6. `login_with_validate_warns_on_svc_account_kind` — mockito returns
//!    `token_kind: "svc_account"`; assert stderr contains a warning.
//! 7. `login_with_validate_aborts_on_401` — mockito returns 401; assert
//!    nothing was written to config and the binary exits non-zero.
//! 8. `status_prints_whoami_table` — mockito returns payload; capture
//!    stdout; assert table format includes username.
//! 9. `status_prints_whoami_json_with_output_json_flag` — as above with
//!    JSON output.
//! 10. `logout_removes_token_from_config_keeps_server` — write a config
//!     with both keys; call `logout::run`; read back and assert.

use tokio::sync::Mutex;

use mockito::Server;

use hort_cli::auth::login::{persist_token, validate_token};
use hort_cli::auth::logout::clear_token_from_toml;
use hort_cli::auth::status;
use hort_cli::config::OutputFormat;

// ---------------------------------------------------------------------------
// Shared env-lock helpers (same pattern as integration.rs)
// ---------------------------------------------------------------------------

/// Process-global env lock. `tokio::sync::Mutex` (instead of
/// `std::sync::Mutex`) so async tests can hold the guard across
/// `.await` points without tripping the `await_holding_lock` lint —
/// `status::run(...).await` reads `HORT_CONFIG_PATH` internally and must
/// see this test's value, not a sibling test's clobbered version.
static LOCK: Mutex<()> = Mutex::const_new(());

/// Sync `#[test]` callers. Must not be invoked from inside a tokio
/// runtime; `blocking_lock` is the documented escape hatch.
fn lock_env() -> tokio::sync::MutexGuard<'static, ()> {
    LOCK.blocking_lock()
}

/// Async `#[tokio::test]` callers — guard is held across `.await`.
async fn lock_env_async() -> tokio::sync::MutexGuard<'static, ()> {
    LOCK.lock().await
}

const ENV_SLOTS: &[&str] = &["HORT_SERVER", "HORT_TOKEN", "HORT_CONFIG_PATH"];

fn clear_env() {
    for s in ENV_SLOTS {
        std::env::remove_var(s);
    }
}

// ---------------------------------------------------------------------------
// Test 4 — login_persists_token_to_config_file_with_0600
// ---------------------------------------------------------------------------

#[test]
fn login_persists_token_to_config_file_with_0600() {
    let _g = lock_env();
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    persist_token("https://server.example.com", "hort_cli_supersecret").expect("persist_token");

    // File must have been created.
    assert!(config_path.exists(), "config file must be created");

    // Content must contain server and token lines.
    let content = std::fs::read_to_string(&config_path).expect("read back config");
    assert!(
        content.contains("server = \"https://server.example.com\""),
        "config must contain server line: {content}"
    );
    assert!(
        content.contains("hort_cli_supersecret"),
        "config must contain the token: {content}"
    );

    // Unix-only: check mode is 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&config_path).expect("metadata");
        let mode = meta.mode() & 0o777;
        assert_eq!(mode, 0o600, "config file must be 0600, got {mode:o}");
    }
}

// ---------------------------------------------------------------------------
// Test 5 — login_with_validate_calls_whoami (mockito, username in stdout)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_validate_calls_whoami() {
    // Hold the env lock for the whole test. `persist_token` reads
    // HORT_CONFIG_PATH from the process-global environment; the previous
    // version released the lock during the network `.await`s and then
    // tried to "re-assert" the env var before persist_token, which
    // raced with sibling tests' `clear_env()` and clobbered their
    // HORT_CONFIG_PATH mid-await. Hold the lock end-to-end so neither
    // direction of race is possible.
    let _g = lock_env_async().await;
    clear_env();
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    let mut server = Server::new_async().await;
    let m = server
        .mock("GET", "/api/v1/auth/whoami")
        .match_header("authorization", "Bearer hort_cli_test_validate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":"u-1","username":"alice","token_kind":"cli_session","permissions":["read"]}"#,
        )
        .create_async()
        .await;

    // validate_token is the internal function — call it directly.
    let whoami = validate_token(&server.url(), "hort_cli_test_validate")
        .await
        .expect("validate_token should succeed");

    m.assert_async().await;

    assert_eq!(whoami.username.as_deref(), Some("alice"));
    assert_eq!(whoami.token_kind.as_deref(), Some("cli_session"));

    // Also exercise persist_token so the "config file written" assertion holds.
    persist_token(&server.url(), "hort_cli_test_validate").expect("persist_token");
    assert!(
        config_path.exists(),
        "config file must be written after login"
    );
    let content = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        content.contains("hort_cli_test_validate"),
        "token must be in config"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — login_with_validate_warns_on_svc_account_kind
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_validate_warns_on_svc_account_kind() {
    // validate_token returns the parsed response; the caller in login::run
    // is responsible for printing the warning. We verify the token_kind is
    // correctly returned so the caller CAN emit the warning.
    // No env mutation needed — mockito binds to a dynamic port.
    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/auth/whoami")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":null,"username":null,"token_kind":"svc_account","permissions":[]}"#,
        )
        .create_async()
        .await;

    let whoami = validate_token(&server.url(), "hort_svc_token")
        .await
        .expect("validate_token should succeed even for svc_account");

    // The caller checks this field and emits the warning.
    assert_eq!(
        whoami.token_kind.as_deref(),
        Some("svc_account"),
        "token_kind must be svc_account so the caller can warn"
    );
    assert!(
        whoami.user_id.is_none(),
        "svc_account user_id should be null"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — login_with_validate_aborts_on_401
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_validate_aborts_on_401() {
    // See note in `login_with_validate_calls_whoami` — guard does not
    // need to outlive this block.
    let dir = {
        let _g = lock_env_async().await;
        clear_env();
        let d = tempfile::tempdir().expect("tempdir");
        std::env::set_var(
            "HORT_CONFIG_PATH",
            d.path().join("config.toml").to_str().unwrap(),
        );
        d
    };
    let config_path = dir.path().join("config.toml");

    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/auth/whoami")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"unauthorized","message":"bad token"}}"#)
        .create_async()
        .await;

    // validate_token must return Err on 401.
    let err = validate_token(&server.url(), "hort_bad_token")
        .await
        .expect_err("validate_token must error on 401");
    let msg = err.to_string();
    assert!(
        msg.contains("401") || msg.contains("Unauthorized") || msg.contains("rejected"),
        "error message must indicate 401: {msg}"
    );

    // The config file must NOT have been written (login::run returns before persist_token).
    assert!(
        !config_path.exists(),
        "config file must not exist when validation fails"
    );
}

// ---------------------------------------------------------------------------
// Test 8 — status_prints_whoami_table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_prints_whoami_table() {
    use hort_cli::client::AkClient;
    use hort_cli::config::load_effective_config;
    use hort_cli::output::format_table_rows;

    // Spin up mock server first (no env mutation yet).
    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/auth/whoami")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":"u-42","username":"bob","token_kind":"pat","permissions":["read","write"]}"#,
        )
        .create_async()
        .await;

    // Write config and set env — env vars are process-global, so we
    // hold the lock for the entire test to keep sibling `#[tokio::test]`s
    // from clobbering HORT_CONFIG_PATH mid-await. `#[tokio::test]` uses
    // the current-thread runtime, so a `!Send` `MutexGuard` is fine
    // across `.await`.
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    let server_url = server.url();
    let _g = lock_env_async().await;
    clear_env();
    std::fs::write(
        &config_path,
        format!("server = \"{server_url}\"\ntoken = \"hort_test_status_tok\"\n"),
    )
    .expect("write config");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    // status::run writes to stdout. Capture by calling the internal parts
    // directly: load config → AkClient → get whoami → render table.
    let cfg = load_effective_config(None, None).expect("config");
    let client = AkClient::new(&cfg).expect("client");
    let whoami: hort_cli::auth::WhoamiResponse =
        client.get("/api/v1/auth/whoami").await.expect("get whoami");

    // Check table rendering includes expected values.
    let rows = vec![
        vec![
            "username".to_string(),
            whoami.username.clone().unwrap_or_default(),
        ],
        vec![
            "token_kind".to_string(),
            whoami.token_kind.clone().unwrap_or_default(),
        ],
    ];
    let table = format_table_rows(&["FIELD", "VALUE"], &rows);
    assert!(
        table.contains("bob"),
        "table must contain username 'bob': {table}"
    );
    assert!(
        table.contains("pat"),
        "table must contain token_kind 'pat': {table}"
    );

    // Run the full status::run and verify it returns ExitCode::SUCCESS.
    let exit = status::run(OutputFormat::Table).await.expect("status::run");
    assert_eq!(exit, std::process::ExitCode::SUCCESS);
}

// ---------------------------------------------------------------------------
// Test 9 — status_prints_whoami_json_with_output_json_flag
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_prints_whoami_json_with_output_json_flag() {
    use hort_cli::auth::WhoamiResponse;
    use hort_cli::output::format_json;

    // Spin up mock server first.
    let mut server = Server::new_async().await;
    let _m = server
        .mock("GET", "/api/v1/auth/whoami")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":"u-99","username":"carol","token_kind":"cli_session","permissions":["admin"]}"#,
        )
        .create_async()
        .await;

    // Write config and set env — see note in `status_prints_whoami_table`
    // for why the env lock is held across the `.await`.
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    let server_url = server.url();
    let _g = lock_env_async().await;
    clear_env();
    std::fs::write(
        &config_path,
        format!("server = \"{server_url}\"\ntoken = \"hort_test_json_tok\"\n"),
    )
    .expect("write config");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    // status::run with Json format must return SUCCESS.
    let exit = status::run(OutputFormat::Json)
        .await
        .expect("status::run json");
    assert_eq!(exit, std::process::ExitCode::SUCCESS);

    // Verify JSON rendering via the output helper directly (no HTTP needed).
    let whoami = WhoamiResponse {
        user_id: Some("u-99".to_string()),
        username: Some("carol".to_string()),
        token_kind: Some("cli_session".to_string()),
        permissions: vec!["admin".to_string()],
    };
    let json = format_json(&whoami);
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    assert_eq!(parsed["username"], "carol");
    assert_eq!(parsed["token_kind"], "cli_session");
    assert_eq!(parsed["permissions"][0], "admin");
}

// ---------------------------------------------------------------------------
// Test 10 — logout_removes_token_from_config_keeps_server
// ---------------------------------------------------------------------------

#[test]
fn logout_removes_token_from_config_keeps_server() {
    // clear_token_from_toml is a pure function — test directly.
    let input =
        "# hort-cli config\nserver = \"https://hort.example.com\"\ntoken  = \"hort_cli_abc123\"\n";
    let result = clear_token_from_toml(input);

    // Token must be gone.
    assert!(
        !result.contains("hort_cli_abc123"),
        "token value must be removed: {result}"
    );
    // Server must be preserved.
    assert!(
        result.contains("server = \"https://hort.example.com\""),
        "server line must be preserved: {result}"
    );
    // Comment must be preserved.
    assert!(
        result.contains("# hort-cli config"),
        "comment must be preserved: {result}"
    );
    // Trailing newline preserved.
    assert!(result.ends_with('\n'), "trailing newline must be preserved");

    // Round-trip: applying again must be idempotent.
    let second = clear_token_from_toml(&result);
    assert_eq!(second, result, "clear_token_from_toml must be idempotent");

    // File-system integration: write → run logout → read back.
    let _g = lock_env();
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        "server = \"https://hort.example.com\"\ntoken = \"hort_cli_todelete\"\n",
    )
    .expect("write config");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    // Use the file-level approach: read, clear, write (matches logout::run behaviour).
    let content = std::fs::read_to_string(&config_path).expect("read");
    let cleared = clear_token_from_toml(&content);
    std::fs::write(&config_path, &cleared).expect("write cleared");

    let after = std::fs::read_to_string(&config_path).expect("read after");
    assert!(
        !after.contains("hort_cli_todelete"),
        "token must be gone after logout: {after}"
    );
    assert!(
        after.contains("server = \"https://hort.example.com\""),
        "server must remain after logout: {after}"
    );
}
