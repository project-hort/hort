//! Integration tests for `hort-cli auth login` OIDC dispatch.
//!
//! Nine test scenarios covering auto-detect dispatch,
//! explicit flags, headless detection, security invariants.
//!
//! Pattern mirrors `tests/auth.rs`: two mockito servers (IdP-shape + hort-shape),
//! `lock_env_async` for env serialisation, `tempfile::tempdir` + `HORT_CONFIG_PATH`
//! for token persistence, `run_with_opener_factory` for opener injection.

use std::sync::{Arc, Mutex};

use mockito::Server;
use tokio::sync::Mutex as AsyncMutex;

use hort_cli::auth::login::{
    run_with_opener_factory, run_with_opener_factory_and_reader, Flow, LoginArgs,
};
use hort_cli::auth::oidc::{BrowserOpener, NoopOpener};

// ---------------------------------------------------------------------------
// Env-lock helpers (copied from tests/auth.rs — cannot modify that file)
// ---------------------------------------------------------------------------

/// Process-global env lock. `tokio::sync::Mutex` so async tests can hold
/// the guard across `.await` points without the `await_holding_lock` lint.
static LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

async fn lock_env_async() -> tokio::sync::MutexGuard<'static, ()> {
    LOCK.lock().await
}

const ENV_SLOTS: &[&str] = &[
    "HORT_SERVER",
    "HORT_TOKEN",
    "HORT_CONFIG_PATH",
    "HORT_OIDC_ALLOW_HTTP",
    "CI",
    "SSH_CONNECTION",
    "SSH_CLIENT",
];

fn clear_env() {
    for s in ENV_SLOTS {
        std::env::remove_var(s);
    }
}

// ---------------------------------------------------------------------------
// Recording opener spy — records every URL it was called with.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct RecordingOpener {
    calls: Arc<Mutex<Vec<String>>>,
}

impl RecordingOpener {
    fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                calls: calls.clone(),
            },
            calls,
        )
    }
}

impl BrowserOpener for RecordingOpener {
    fn open(&self, url: &str) -> anyhow::Result<()> {
        self.calls.lock().unwrap().push(url.to_string());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test helpers — canonical mock bodies
// ---------------------------------------------------------------------------

/// Full v1 discovery document matching the server's well_known.rs shape.
fn hort_client_config_body(idp_base: &str, hort_base: &str) -> String {
    format!(
        r#"{{
            "version": 1,
            "idp": {{
                "issuer": "{idp_base}",
                "client_id": "hort-cli"
            }},
            "exchange": {{
                "endpoint": "{hort_base}/api/v1/auth/exchange",
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token"
                ]
            }}
        }}"#
    )
}

/// IdP openid-configuration pointing at the same mockito server.
///
/// Includes `authorization_endpoint` (required by OIDC Discovery 1.0 §3 and
/// consumed by the RFC 8252 loopback flow); the existing
/// device-flow tests don't read it, but `fetch_idp_endpoints` now treats it
/// as mandatory.
fn openid_configuration_body(idp_base: &str) -> String {
    format!(
        r#"{{
            "device_authorization_endpoint": "{idp_base}/device",
            "authorization_endpoint": "{idp_base}/auth",
            "token_endpoint": "{idp_base}/token"
        }}"#
    )
}

/// Device authorisation response (RFC 8628 §3.2).
fn device_auth_body(idp_base: &str) -> String {
    format!(
        r#"{{
            "device_code": "dev_code_it3",
            "user_code": "ABCD-1234",
            "verification_uri": "https://idp.example.com/activate",
            "verification_uri_complete": "{idp_base}/device?user_code=ABCD-1234",
            "expires_in": 300,
            "interval": 0
        }}"#
    )
}

fn device_auth_body_http(idp_base: &str) -> String {
    format!(
        r#"{{
            "device_code": "dev_code_it3",
            "user_code": "ABCD-1234",
            "verification_uri": "http://idp.example.com/activate",
            "verification_uri_complete": "{idp_base}/device?user_code=ABCD-1234",
            "expires_in": 300,
            "interval": 0
        }}"#
    )
}

fn device_auth_body_javascript() -> &'static str {
    r#"{
        "device_code": "dev_code_bad",
        "user_code": "ABCD-1234",
        "verification_uri": "javascript:alert(2)",
        "verification_uri_complete": "javascript:alert(1)",
        "expires_in": 300,
        "interval": 0
    }"#
}

fn success_token_body(jwt: &str) -> String {
    // hort-cli reads `id_token` (not `access_token`) from the device-flow
    // poll response — see `TokenSuccessResponse` in `auth/oidc.rs`. Both
    // fields are emitted so the fixture is robust to either side of the
    // contract being tightened later, but only `id_token` drives the
    // exchange.
    format!(r#"{{"id_token":"{jwt}","access_token":"unused-by-cli"}}"#)
}

fn exchange_response_body(token: &str) -> String {
    format!(r#"{{"access_token":"{token}","expires_in":2592000}}"#)
}

/// A `LoginArgs` with sensible defaults for OIDC tests.
fn oidc_args(server_url: &str, no_browser: bool) -> LoginArgs {
    LoginArgs {
        validate: false,
        server: Some(server_url.to_string()),
        paste: false,
        oidc: false,
        no_browser,
        // These tests mock the RFC 8628 device-flow path; with `flow = Auto`
        // plus `no_browser = true` the dispatcher resolves to device flow
        // (the same behaviour these tests have always exercised). Tests that
        // want loopback should construct LoginArgs inline with
        // `flow: Flow::Loopback`.
        flow: Flow::Auto,
        admin: false,
        expires_in: None,
    }
}

fn oidc_forced_args(server_url: &str) -> LoginArgs {
    LoginArgs {
        validate: false,
        server: Some(server_url.to_string()),
        paste: false,
        oidc: true,
        no_browser: true, // use NoopOpener in forced-OIDC tests
        flow: Flow::Auto,
        admin: false,
        expires_in: None,
    }
}

// ---------------------------------------------------------------------------
// Test 1 — login_oidc_happy_path_persists_hort_cli_token
//
// Drives: auto-detect → Available → device flow → exchange → persist.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_oidc_happy_path_persists_hort_cli_token() {
    let _g = lock_env_async().await;
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    let mut hort_server = Server::new_async().await;
    let mut idp_server = Server::new_async().await;
    let hort_base = hort_server.url();
    let idp_base = idp_server.url();

    // hort discovery endpoint.
    let _m_discovery = hort_server
        .mock("GET", "/.well-known/hort-client-config")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(hort_client_config_body(&idp_base, &hort_base))
        .create_async()
        .await;

    // IdP openid-configuration.
    let _m_idp_config = idp_server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(openid_configuration_body(&idp_base))
        .create_async()
        .await;

    // IdP device authorisation.
    let _m_device = idp_server
        .mock("POST", "/device")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(device_auth_body(&idp_base))
        .create_async()
        .await;

    // IdP token poll — immediate success.
    const FAKE_JWT: &str = "eyJhbGci.FAKE_JWT.sig";
    let _m_token = idp_server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(success_token_body(FAKE_JWT))
        .create_async()
        .await;

    // hort exchange endpoint.
    const HORT_CLI_TOKEN: &str = "hort_cli_integration_test_token";
    let _m_exchange = hort_server
        .mock("POST", "/api/v1/auth/exchange")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(exchange_response_body(HORT_CLI_TOKEN))
        .create_async()
        .await;

    let args = oidc_args(&hort_base, true); // no_browser=true → NoopOpener
    let result = run_with_opener_factory(args, |_| Box::new(NoopOpener))
        .await
        .expect("run should succeed");

    assert_eq!(
        result,
        std::process::ExitCode::SUCCESS,
        "OIDC happy path must exit 0"
    );

    // Token must be persisted.
    assert!(config_path.exists(), "config file must be created");
    let content = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        content.contains(HORT_CLI_TOKEN),
        "hort_cli_* token must be in config: {content}"
    );
    assert!(
        content.contains(&hort_base),
        "server URL must be in config: {content}"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — login_falls_back_to_paste_on_404_discovery
//
// Drives: auto-detect → NotEnabled (404) → paste flow.
// Verifies that discovery IS attempted (exactly one hit), then the token
// read from the injected cursor is persisted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_falls_back_to_paste_on_404_discovery() {
    let _g = lock_env_async().await;
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    let mut hort_server = Server::new_async().await;
    let hort_base = hort_server.url();

    // Discovery returns 404 → triggers paste fall-through.
    let discovery_mock = hort_server
        .mock("GET", "/.well-known/hort-client-config")
        .with_status(404)
        .expect(1) // exactly one hit — the dispatch DID try discovery
        .create_async()
        .await;

    // Whoami mock for validate=true post-paste validation.
    let _whoami_mock = hort_server
        .mock("GET", "/api/v1/auth/whoami")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"username":"alice","token_kind":"cli_session","permissions":[]}"#)
        .expect(1)
        .create_async()
        .await;

    let mut reader = std::io::Cursor::new(b"fallback-paste-token\n".to_vec());
    let exit = run_with_opener_factory_and_reader(
        LoginArgs {
            paste: false,
            oidc: false,
            no_browser: false,
            validate: true,
            server: Some(hort_base.clone()),
            flow: Flow::Auto,
            admin: false,
            expires_in: None,
        },
        |_| Box::new(NoopOpener),
        &mut reader,
        false, // non-TTY: use plain reader, not rpassword
    )
    .await
    .expect("run failed");

    assert_eq!(exit, std::process::ExitCode::SUCCESS);

    // Discovery was fetched exactly once (the 404).
    discovery_mock.assert_async().await;

    // The token read from the cursor was persisted.
    let content = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        content.contains("fallback-paste-token"),
        "persisted config should contain the fallback paste token: {content}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — login_oidc_flag_errors_when_discovery_404s
//
// Drives: --oidc + 404 discovery → exit 1 with clear message.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_oidc_flag_errors_when_discovery_404s() {
    let _g = lock_env_async().await;
    clear_env();

    let mut hort_server = Server::new_async().await;
    let hort_base = hort_server.url();

    let _m_discovery = hort_server
        .mock("GET", "/.well-known/hort-client-config")
        .with_status(404)
        .create_async()
        .await;

    let args = oidc_forced_args(&hort_base);
    let result = run_with_opener_factory(args, |_| Box::new(NoopOpener))
        .await
        .expect("run should return Ok");

    assert_ne!(
        result,
        std::process::ExitCode::SUCCESS,
        "--oidc with 404 must exit non-zero"
    );

    _m_discovery.assert_async().await;
}

// ---------------------------------------------------------------------------
// Test 4 — login_paste_flag_skips_discovery
//
// Drives: --paste → discovery endpoint never hit, token from reader persisted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_paste_flag_skips_discovery() {
    let _g = lock_env_async().await;
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    let mut hort_server = Server::new_async().await;
    let hort_base = hort_server.url();

    // Discovery mock with expect(0) — must NOT be hit when --paste is set.
    let discovery_mock = hort_server
        .mock("GET", "/.well-known/hort-client-config")
        .with_status(200)
        .with_body("{}")
        .expect(0)
        .create_async()
        .await;

    // Whoami mock for validate=true post-paste validation.
    let _whoami_mock = hort_server
        .mock("GET", "/api/v1/auth/whoami")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"username":"alice","token_kind":"cli_session","permissions":[]}"#)
        .expect(1)
        .create_async()
        .await;

    let mut reader = std::io::Cursor::new(b"my-paste-token\n".to_vec());
    let exit = run_with_opener_factory_and_reader(
        LoginArgs {
            paste: true,
            oidc: false,
            no_browser: false,
            validate: true,
            server: Some(hort_base.clone()),
            flow: Flow::Auto,
            admin: false,
            expires_in: None,
        },
        |_| Box::new(NoopOpener),
        &mut reader,
        false, // non-TTY: use plain reader, not rpassword
    )
    .await
    .expect("run failed");

    assert_eq!(exit, std::process::ExitCode::SUCCESS);

    // Critical: discovery was never hit (--paste skips it entirely).
    discovery_mock.assert_async().await;

    // The token read from the cursor was persisted.
    let content = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        content.contains("my-paste-token"),
        "persisted config should contain the token: {content}"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — login_no_browser_flag_skips_open_attempt
//
// Drives: --no-browser → opener never called.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_no_browser_flag_skips_open_attempt() {
    let _g = lock_env_async().await;
    clear_env();

    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    std::env::set_var("HORT_CONFIG_PATH", config_path.to_str().unwrap());

    let mut hort_server = Server::new_async().await;
    let mut idp_server = Server::new_async().await;
    let hort_base = hort_server.url();
    let idp_base = idp_server.url();

    setup_full_oidc_mocks(&mut hort_server, &mut idp_server, &hort_base, &idp_base).await;

    let (_, call_log) = RecordingOpener::new();
    let call_log_clone = call_log.clone();

    let args = oidc_args(&hort_base, true); // no_browser = true
                                            // When no_browser=true, the factory must return NoopOpener (or at least not call the opener).
                                            // We inject our recording factory to verify.
    let factory = move |no_browser: bool| -> Box<dyn BrowserOpener> {
        if no_browser {
            Box::new(NoopOpener)
        } else {
            Box::new(RecordingOpener {
                calls: call_log_clone.clone(),
            })
        }
    };

    let result = run_with_opener_factory(args, factory)
        .await
        .expect("run should succeed");

    assert_eq!(result, std::process::ExitCode::SUCCESS);
    // Since no_browser=true, the RecordingOpener was NOT returned by the factory,
    // so calls is empty.
    let recorded = call_log.lock().unwrap();
    assert!(
        recorded.is_empty(),
        "opener must not be called when --no-browser is set"
    );

    // Token must still be persisted.
    assert!(config_path.exists(), "config must be created");
}

// ---------------------------------------------------------------------------
// Test 6 — login_skips_open_when_CI_env_set
//
// Drives: CI=1 in env → opener receives NoopOpener from default_opener_factory.
// Verified via recording opener injected through run_with_opener_factory.
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(non_snake_case)]
async fn login_skips_open_when_CI_env_set() {
    let _g = lock_env_async().await;
    clear_env();
    std::env::set_var("CI", "true");

    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var(
        "HORT_CONFIG_PATH",
        dir.path().join("config.toml").to_str().unwrap(),
    );

    let mut hort_server = Server::new_async().await;
    let mut idp_server = Server::new_async().await;
    let hort_base = hort_server.url();
    let idp_base = idp_server.url();

    setup_full_oidc_mocks(&mut hort_server, &mut idp_server, &hort_base, &idp_base).await;

    let (_, call_log) = RecordingOpener::new();
    let call_log_clone = call_log.clone();

    let args = oidc_args(&hort_base, false); // no_browser=false — headless detection should kick in
                                             // Factory: when is_headless_environment() is true (CI=true), production code returns NoopOpener.
                                             // We replicate the headless check in the factory so we can assert call_log is empty.
    let factory = move |no_browser: bool| -> Box<dyn BrowserOpener> {
        if no_browser || hort_cli::auth::login::is_headless_environment() {
            Box::new(NoopOpener)
        } else {
            Box::new(RecordingOpener {
                calls: call_log_clone.clone(),
            })
        }
    };

    let result = run_with_opener_factory(args, factory)
        .await
        .expect("run should succeed");

    std::env::remove_var("CI");

    assert_eq!(result, std::process::ExitCode::SUCCESS);
    let recorded = call_log.lock().unwrap();
    assert!(
        recorded.is_empty(),
        "opener must not be called when CI env is set"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — login_skips_open_when_SSH_CONNECTION_set
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(non_snake_case)]
async fn login_skips_open_when_SSH_CONNECTION_set() {
    let _g = lock_env_async().await;
    clear_env();
    std::env::set_var("SSH_CONNECTION", "10.0.0.1 22 192.168.1.1 44321");

    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var(
        "HORT_CONFIG_PATH",
        dir.path().join("config.toml").to_str().unwrap(),
    );

    let mut hort_server = Server::new_async().await;
    let mut idp_server = Server::new_async().await;
    let hort_base = hort_server.url();
    let idp_base = idp_server.url();

    setup_full_oidc_mocks(&mut hort_server, &mut idp_server, &hort_base, &idp_base).await;

    let (_, call_log) = RecordingOpener::new();
    let call_log_clone = call_log.clone();

    let args = oidc_args(&hort_base, false);
    let factory = move |no_browser: bool| -> Box<dyn BrowserOpener> {
        if no_browser || hort_cli::auth::login::is_headless_environment() {
            Box::new(NoopOpener)
        } else {
            Box::new(RecordingOpener {
                calls: call_log_clone.clone(),
            })
        }
    };

    let result = run_with_opener_factory(args, factory)
        .await
        .expect("run should succeed");

    std::env::remove_var("SSH_CONNECTION");

    assert_eq!(result, std::process::ExitCode::SUCCESS);
    let recorded = call_log.lock().unwrap();
    assert!(
        recorded.is_empty(),
        "opener must not be called when SSH_CONNECTION env is set"
    );
}

// ---------------------------------------------------------------------------
// Test 8 — login_aborts_on_forbidden_verification_uri_scheme
//
// Drives: IdP returns javascript: URIs (both) → exit non-zero, opener not called.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_aborts_on_forbidden_verification_uri_scheme() {
    let _g = lock_env_async().await;
    clear_env();
    std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var(
        "HORT_CONFIG_PATH",
        dir.path().join("config.toml").to_str().unwrap(),
    );

    let mut hort_server = Server::new_async().await;
    let mut idp_server = Server::new_async().await;
    let hort_base = hort_server.url();
    let idp_base = idp_server.url();

    // hort discovery.
    let _m_discovery = hort_server
        .mock("GET", "/.well-known/hort-client-config")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(hort_client_config_body(&idp_base, &hort_base))
        .create_async()
        .await;

    // IdP openid-configuration.
    let _m_idp_config = idp_server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(openid_configuration_body(&idp_base))
        .create_async()
        .await;

    // IdP device auth — returns javascript: URIs.
    let _m_device = idp_server
        .mock("POST", "/device")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(device_auth_body_javascript())
        .create_async()
        .await;

    let (_, call_log) = RecordingOpener::new();
    let call_log_clone = call_log.clone();

    let args = oidc_args(&hort_base, false);
    let factory = move |_no_browser: bool| -> Box<dyn BrowserOpener> {
        Box::new(RecordingOpener {
            calls: call_log_clone.clone(),
        })
    };

    let result = run_with_opener_factory(args, factory)
        .await
        .expect("run should return Ok(ExitCode)");

    assert_ne!(
        result,
        std::process::ExitCode::SUCCESS,
        "javascript: scheme must cause non-zero exit"
    );

    let recorded = call_log.lock().unwrap();
    assert!(
        recorded.is_empty(),
        "opener must never be called with javascript: URL"
    );
}

// ---------------------------------------------------------------------------
// Test 9 — login_accepts_http_verification_uri_when_HORT_OIDC_ALLOW_HTTP_set
//
// Drives: HORT_OIDC_ALLOW_HTTP=1 → http:// verification URI accepted.
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(non_snake_case)]
async fn login_accepts_http_verification_uri_when_HORT_OIDC_ALLOW_HTTP_set() {
    let _g = lock_env_async().await;
    clear_env();
    std::env::set_var("HORT_OIDC_ALLOW_HTTP", "1");

    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var(
        "HORT_CONFIG_PATH",
        dir.path().join("config.toml").to_str().unwrap(),
    );

    let mut hort_server = Server::new_async().await;
    let mut idp_server = Server::new_async().await;
    let hort_base = hort_server.url();
    let idp_base = idp_server.url();

    // hort discovery.
    let _m_discovery = hort_server
        .mock("GET", "/.well-known/hort-client-config")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(hort_client_config_body(&idp_base, &hort_base))
        .create_async()
        .await;

    // IdP openid-configuration.
    let _m_idp_config = idp_server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(openid_configuration_body(&idp_base))
        .create_async()
        .await;

    // IdP device auth — verification_uri_complete is http:// (the idp_base is already http).
    let _m_device = idp_server
        .mock("POST", "/device")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(device_auth_body_http(&idp_base))
        .create_async()
        .await;

    // IdP token — immediate success.
    const FAKE_JWT: &str = "eyJhbGci.HTTP_ALLOW_JWT.sig";
    let _m_token = idp_server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(success_token_body(FAKE_JWT))
        .create_async()
        .await;

    // hort exchange.
    const HORT_CLI_TOKEN: &str = "hort_cli_http_allow_token";
    let _m_exchange = hort_server
        .mock("POST", "/api/v1/auth/exchange")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(exchange_response_body(HORT_CLI_TOKEN))
        .create_async()
        .await;

    let args = oidc_args(&hort_base, true); // no_browser
    let result = run_with_opener_factory(args, |_| Box::new(NoopOpener))
        .await
        .expect("run should succeed");

    std::env::remove_var("HORT_OIDC_ALLOW_HTTP");

    assert_eq!(
        result,
        std::process::ExitCode::SUCCESS,
        "http:// URI with HORT_OIDC_ALLOW_HTTP=1 must succeed"
    );

    let config_path = dir.path().join("config.toml");
    let content = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        content.contains(HORT_CLI_TOKEN),
        "hort_cli_* token must be persisted: {content}"
    );
}

// ---------------------------------------------------------------------------
// Shared helper — set up full OIDC mock stack on two servers.
// ---------------------------------------------------------------------------

async fn setup_full_oidc_mocks(
    hort_server: &mut Server,
    idp_server: &mut Server,
    hort_base: &str,
    idp_base: &str,
) {
    // hort discovery.
    hort_server
        .mock("GET", "/.well-known/hort-client-config")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(hort_client_config_body(idp_base, hort_base))
        .create_async()
        .await;

    // IdP openid-configuration.
    idp_server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(openid_configuration_body(idp_base))
        .create_async()
        .await;

    // IdP device auth.
    idp_server
        .mock("POST", "/device")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(device_auth_body(idp_base))
        .create_async()
        .await;

    // IdP token — immediate success.
    idp_server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(success_token_body("eyJhbGci.SETUP_JWT.sig"))
        .create_async()
        .await;

    // hort exchange.
    hort_server
        .mock("POST", "/api/v1/auth/exchange")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(exchange_response_body("hort_cli_setup_token"))
        .create_async()
        .await;
}
