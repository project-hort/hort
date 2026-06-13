//! Integration tests for `hort-cli` core modules.
//!
//! Eight test scenarios:
//!
//! 1. `mockito` server returning `200 { … }` → `AkClient::get` returns
//!    parsed value; `Authorization: Bearer <token>` was sent.
//! 2. `mockito` server returning `403` → `AkClient::get` returns `Err`;
//!    error message includes the status.
//! 3. Token redaction: trace output during a request does NOT contain
//!    the literal token string.
//! 4. `load_effective_config` precedence: CLI flag > env > config file
//!    (three test cases, each collapsed into one fn below for clarity).
//! 5. Missing token from all sources → `ConfigError::Missing { field: "token" }`.
//! 6. Malformed config file → `ConfigError::Toml`.
//! 7. `format_json` round-trip on a small struct.
//! 8. `format_table_rows` with sample data — assert column alignment.
//!
//! Tests 4–8 mirror the unit tests in `config.rs` and `output.rs` but
//! exercise them via the public API surface (`hort_cli::*`) so they serve
//! as contract tests for the lib re-exports.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use mockito::Server;
use serde::Deserialize;
use serde::Serialize;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use url::Url;

use hort_cli::client::AkClient;
use hort_cli::config::{load_effective_config, ConfigError, EffectiveConfig, OutputFormat};
use hort_cli::output::{format_json, format_table_rows};

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

fn make_cfg(base_url: &str, token: &str) -> EffectiveConfig {
    EffectiveConfig {
        server: Url::parse(base_url).expect("valid test url"),
        token: token.to_string(),
        default_format: OutputFormat::Table,
    }
}

/// All env-touching tests share one mutex.
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

// -----------------------------------------------------------------
// Test 1 — successful GET, token header sent
// -----------------------------------------------------------------

#[derive(Debug, Deserialize, PartialEq)]
struct Payload {
    id: u32,
    name: String,
}

#[tokio::test]
async fn get_200_parses_json_and_sends_auth_header() {
    let mut server = Server::new_async().await;

    let m = server
        .mock("GET", "/api/v1/foo")
        .match_header("authorization", "Bearer test-tok-xyz")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":1,"name":"alpha"}"#)
        .create_async()
        .await;

    let cfg = make_cfg(&server.url(), "test-tok-xyz");
    let client = AkClient::new(&cfg).expect("builds");
    let result: Payload = client.get("/api/v1/foo").await.expect("200 should succeed");

    assert_eq!(
        result,
        Payload {
            id: 1,
            name: "alpha".to_string()
        }
    );
    m.assert_async().await;
}

// -----------------------------------------------------------------
// Test 2 — 403 produces Err containing status
// -----------------------------------------------------------------

#[tokio::test]
async fn get_403_returns_err_with_status_in_message() {
    let mut server = Server::new_async().await;

    let _m = server
        .mock("GET", "/api/v1/protected")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"code":"forbidden","message":"access denied"}}"#)
        .create_async()
        .await;

    let cfg = make_cfg(&server.url(), "bad-token");
    let client = AkClient::new(&cfg).expect("builds");
    let result: Result<serde_json::Value, _> = client.get("/api/v1/protected").await;

    assert!(result.is_err(), "403 must return Err");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "error message must include HTTP status 403: {msg}"
    );
}

// -----------------------------------------------------------------
// Test 3 — token redaction in tracing output
// -----------------------------------------------------------------

/// A tracing subscriber that captures all log lines into a shared
/// `Vec<String>` so we can assert the token never appears.
struct CapturingSubscriber {
    lines: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturingSubscriber {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use tracing::field::{Field, Visit};

        struct Collector(String);
        impl Visit for Collector {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={:?}", field.name(), value));
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                self.0.push_str(&format!(" {}={}", field.name(), value));
            }
        }

        let mut c = Collector(format!("[{}]", event.metadata().target()));
        event.record(&mut c);
        self.lines.lock().unwrap().push(c.0);
    }
}

/// Token redaction test — run outside a tokio runtime so `with_default`
/// can install a fresh runtime via `block_on` without hitting the
/// "cannot start runtime from within runtime" panic.
///
/// Verifies that every `tracing::debug!` event emitted by `AkClient`
/// contains only URL-level data and not the bearer token literal.
#[test]
fn token_does_not_appear_in_tracing_output() {
    let secret_token = "VERY-SECRET-TOKEN-12345";

    let captured_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured_lines.clone();

    let subscriber = tracing_subscriber::registry().with(CapturingSubscriber {
        lines: captured_clone,
    });

    tracing::subscriber::with_default(subscriber, || {
        // Build a fresh single-threaded tokio runtime. This is valid
        // because we are NOT inside a tokio runtime here — the test
        // function is a plain `#[test]`, not `#[tokio::test]`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        rt.block_on(async {
            // Spin up a mockito server.
            let mut server = Server::new_async().await;
            let _m = server
                .mock("GET", "/api/v1/any")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"ok":true}"#)
                .create_async()
                .await;

            let cfg = make_cfg(&server.url(), secret_token);
            let client = AkClient::new(&cfg).expect("builds");
            let _ = client.get::<serde_json::Value>("/api/v1/any").await;
        });
    });

    // Assert the token never leaked into any log line produced by our code.
    let lines = captured_lines.lock().unwrap();
    for line in lines.iter() {
        assert!(
            !line.contains(secret_token),
            "token leaked into tracing output: {line}"
        );
    }

    // Also verify the AkClient's own Debug output redacts the token.
    let cfg = make_cfg("https://example.com", secret_token);
    let client = AkClient::new(&cfg).expect("builds");
    let debug = format!("{client:?}");
    assert!(
        !debug.contains(secret_token),
        "token leaked into Debug output: {debug}"
    );
}

// -----------------------------------------------------------------
// Test 4 — load_effective_config precedence (three sub-scenarios)
// -----------------------------------------------------------------

#[test]
fn config_precedence_cli_flag_beats_env() {
    let _g = lock_env();
    clear_env();
    std::env::set_var("HORT_SERVER", "https://env.example.com");
    std::env::set_var("HORT_TOKEN", "env-tok");

    let cfg = load_effective_config(
        Some("https://cli.example.com".to_string()),
        Some("cli-tok".to_string()),
    )
    .expect("parses");

    assert_eq!(cfg.server.host_str(), Some("cli.example.com"));
    assert_eq!(cfg.token, "cli-tok");
}

#[test]
fn config_precedence_env_beats_config_file() {
    let _g = lock_env();
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "server=\"https://file.example.com\"\ntoken=\"file-tok\"\n",
    )
    .expect("write");
    std::env::set_var("HORT_CONFIG_PATH", path.to_str().unwrap());
    std::env::set_var("HORT_SERVER", "https://env.example.com");
    std::env::set_var("HORT_TOKEN", "env-tok");

    let cfg = load_effective_config(None, None).expect("parses");
    assert_eq!(cfg.server.host_str(), Some("env.example.com"));
    assert_eq!(cfg.token, "env-tok");
}

#[test]
fn config_precedence_file_used_when_flag_and_env_absent() {
    let _g = lock_env();
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "server=\"https://file.example.com\"\ntoken=\"file-tok\"\n",
    )
    .expect("write");
    std::env::set_var("HORT_CONFIG_PATH", path.to_str().unwrap());

    let cfg = load_effective_config(None, None).expect("parses");
    assert_eq!(cfg.server.host_str(), Some("file.example.com"));
    assert_eq!(cfg.token, "file-tok");
}

// -----------------------------------------------------------------
// Test 5 — missing token returns ConfigError::Missing
// -----------------------------------------------------------------

#[test]
fn missing_token_from_all_sources_is_config_error() {
    let _g = lock_env();
    clear_env();
    // Server set, token absent everywhere.
    std::env::set_var("HORT_SERVER", "https://example.com");
    std::env::set_var("HORT_CONFIG_PATH", "/tmp/__hort_nonexistent_config.toml");

    let err = load_effective_config(None, None).expect_err("must error");
    assert!(
        matches!(err, ConfigError::Missing { field: "token", .. }),
        "expected Missing for token, got: {err:?}"
    );
}

// -----------------------------------------------------------------
// Test 6 — malformed config file returns ConfigError::Toml
// -----------------------------------------------------------------

#[test]
fn malformed_config_file_is_toml_error() {
    let _g = lock_env();
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "server = [broken\n").expect("write");
    std::env::set_var("HORT_CONFIG_PATH", path.to_str().unwrap());

    let err = load_effective_config(None, None).expect_err("malformed must error");
    assert!(
        matches!(err, ConfigError::Toml { .. }),
        "expected ConfigError::Toml, got: {err:?}"
    );
}

// -----------------------------------------------------------------
// Test 7 — format_json round-trip
// -----------------------------------------------------------------

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Small {
    repo: String,
    score: f64,
}

#[test]
fn format_json_round_trip_via_public_api() {
    let v = Small {
        repo: "npm-proxy".to_string(),
        score: 0.95,
    };
    let s = format_json(&v);
    let back: Small = serde_json::from_str(&s).expect("valid json");
    assert_eq!(v, back);
    assert!(s.contains('\n'), "must be pretty-printed");
}

// -----------------------------------------------------------------
// Test 8 — format_table_rows column alignment
// -----------------------------------------------------------------

#[test]
fn format_table_rows_column_alignment_via_public_api() {
    let headers = &["REPO", "SCORE", "STATE"];
    let rows = vec![
        vec![
            "npm-proxy".to_string(),
            "0.95".to_string(),
            "active".to_string(),
        ],
        vec![
            "a-very-long-repo-name".to_string(),
            "0.10".to_string(),
            "inactive".to_string(),
        ],
    ];
    let out = format_table_rows(headers, &rows);
    let lines: Vec<&str> = out.lines().collect();

    assert_eq!(lines.len(), 3);

    // "a-very-long-repo-name" is 21 chars; "REPO" is 4 chars.
    // Column 0 width == 21; header should be padded to 21.
    let header = lines[0];
    assert!(
        header.starts_with("REPO                 "),
        "REPO header padded to 21 chars: {header:?}"
    );

    // Second data row starts with the long name, unpadded beyond its own length.
    let second = lines[2];
    assert!(
        second.starts_with("a-very-long-repo-name"),
        "long name present in row 2: {second:?}"
    );

    // All column values from both rows present.
    let all: HashSet<&str> = out.split_whitespace().collect();
    for expected in &[
        "npm-proxy",
        "0.95",
        "active",
        "a-very-long-repo-name",
        "0.10",
        "inactive",
    ] {
        assert!(
            all.contains(expected),
            "expected {expected} in output:\n{out}"
        );
    }
}
