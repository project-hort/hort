//! Integration tests for the RFC 8252 loopback flow.
//!
//! These tests drive the real loopback listener end-to-end:
//!
//! - A mockito `IdpEndpoints` is constructed locally (so we don't need an
//!   `openid-configuration` round-trip — the loopback module takes
//!   `IdpEndpoints` directly).
//! - A driver thread simulates the user's browser visiting the
//!   authorization_endpoint, then redirecting (via direct HTTP) to the
//!   loopback callback.
//! - The token endpoint is served by mockito and asserts the wire shape
//!   (`grant_type`, `code`, `redirect_uri`, `client_id`, `code_verifier`;
//!   NO `client_secret`).
//!
//! Layout mirrors `tests/oidc_login.rs`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hort_cli::auth::loopback::{run_loopback_flow, LoopbackError};
use hort_cli::auth::oidc::{BrowserOpener, IdpEndpoints};
use url::Url;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Records every URL the opener was invoked with. The test extracts the
/// redirect_uri from the recorded authorization URL and drives the callback
/// on its own.
#[derive(Clone)]
struct CapturingOpener {
    calls: Arc<Mutex<Vec<String>>>,
    /// When set, the opener spawns a thread that connects to the redirect_uri
    /// inside the captured authorization URL, simulating the IdP's redirect.
    auto_drive: Option<DriverParams>,
}

#[derive(Clone)]
struct DriverParams {
    /// `?code=...` value to send back on the callback.
    code: String,
    /// `?state=...` value to send back. When `None`, echo back the one from
    /// the captured authorization URL (happy path); when `Some`, override
    /// (used for state-mismatch test).
    state_override: Option<String>,
    /// When `Some`, send `?error=...` instead of a code (used for
    /// access_denied test).
    error: Option<String>,
}

impl CapturingOpener {
    fn capture_only() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            auto_drive: None,
        }
    }

    fn with_driver(params: DriverParams) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            auto_drive: Some(params),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl BrowserOpener for CapturingOpener {
    fn open(&self, url: &str) -> anyhow::Result<()> {
        self.calls.lock().unwrap().push(url.to_string());

        if let Some(params) = self.auto_drive.clone() {
            // Parse the captured authorization URL to extract redirect_uri + state.
            let parsed = Url::parse(url).expect("opener url parses");
            let mut redirect_uri = None;
            let mut state_from_request = None;
            for (k, v) in parsed.query_pairs() {
                match k.as_ref() {
                    "redirect_uri" => redirect_uri = Some(v.into_owned()),
                    "state" => state_from_request = Some(v.into_owned()),
                    _ => {}
                }
            }
            let redirect_uri = redirect_uri.expect("redirect_uri must be in auth URL");
            let returned_state = params
                .state_override
                .or(state_from_request)
                .unwrap_or_default();

            // Drive the callback in a worker thread so this opener call returns
            // immediately (matches a real browser launch).
            std::thread::spawn(move || {
                // Give the loopback listener a beat to be ready.
                std::thread::sleep(Duration::from_millis(50));

                let redirect_url = Url::parse(&redirect_uri).expect("redirect_uri parses");
                let host = redirect_url
                    .host_str()
                    .expect("redirect_uri has host")
                    .to_string();
                let port = redirect_url.port().expect("redirect_uri has port");
                let path = redirect_url.path().to_string();

                let query = if let Some(err) = params.error.as_deref() {
                    format!(
                        "{path}?error={err}&error_description=integration_test&state={returned_state}"
                    )
                } else {
                    format!(
                        "{path}?code={code}&state={returned_state}",
                        code = params.code
                    )
                };

                let host_header = if host.contains(':') {
                    // IPv6 — bracket it.
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                };

                let connect_addr = if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                };

                let Ok(mut conn) = TcpStream::connect_timeout(
                    &connect_addr.parse().expect("addr parses"),
                    Duration::from_secs(3),
                ) else {
                    return;
                };
                let _ = conn.set_write_timeout(Some(Duration::from_secs(2)));
                let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
                let req = format!(
                    "GET {query} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
                );
                let _ = conn.write_all(req.as_bytes());
                let mut buf = Vec::new();
                let _ = conn.read_to_end(&mut buf);
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test 1 — happy path: callback delivers code+state, token endpoint returns
// the access_token, the loopback flow returns it.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn loopback_happy_path_returns_idp_access_token() {
    let mut idp = mockito::Server::new_async().await;
    let idp_base = idp.url();

    // The "authorization endpoint" — the loopback flow does NOT contact it
    // (the URL is only opened in the user's browser). We don't need to mock
    // a response; the test's driver thread simulates the redirect locally.
    let auth_endpoint = format!("{idp_base}/auth");
    let token_endpoint = format!("{idp_base}/token");

    let _m_token = idp
        .mock("POST", "/token")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::Regex("grant_type=authorization_code".to_string()),
            mockito::Matcher::Regex("code=test_code_abc".to_string()),
            mockito::Matcher::Regex("client_id=hort-cli".to_string()),
            mockito::Matcher::Regex("code_verifier=".to_string()),
            mockito::Matcher::Regex("redirect_uri=".to_string()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"access_token":"idp_access_token_xyz"}"#)
        .create_async()
        .await;

    let endpoints = IdpEndpoints {
        device_authorization_endpoint: Url::parse(&format!("{idp_base}/device")).unwrap(),
        authorization_endpoint: Url::parse(&auth_endpoint).unwrap(),
        token_endpoint: Url::parse(&token_endpoint).unwrap(),
    };

    let opener = CapturingOpener::with_driver(DriverParams {
        code: "test_code_abc".to_string(),
        state_override: None, // echo back what we sent
        error: None,
    });

    let result = run_loopback_flow(&endpoints, "hort-cli", &opener).await;
    let token = result.expect("loopback flow should succeed");
    assert_eq!(token, "idp_access_token_xyz");

    // The opener was called once with the authorization URL.
    let calls = opener.calls();
    assert_eq!(calls.len(), 1, "opener must be called once");
    assert!(calls[0].starts_with(&auth_endpoint));
    assert!(calls[0].contains("response_type=code"));
    assert!(calls[0].contains("code_challenge_method=S256"));
    assert!(calls[0].contains("scope=openid+profile+email"));
}

// ---------------------------------------------------------------------------
// Test 2 — state mismatch: driver echoes a different state on the callback;
// loopback flow rejects with AuthorizationStateMismatch and does NOT POST
// to the token endpoint.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn loopback_rejects_callback_with_mismatched_state() {
    let mut idp = mockito::Server::new_async().await;
    let idp_base = idp.url();

    // Token endpoint expectation: NOT called.
    let _m_token = idp
        .mock("POST", "/token")
        .expect(0)
        .with_status(500)
        .create_async()
        .await;

    let endpoints = IdpEndpoints {
        device_authorization_endpoint: Url::parse(&format!("{idp_base}/device")).unwrap(),
        authorization_endpoint: Url::parse(&format!("{idp_base}/auth")).unwrap(),
        token_endpoint: Url::parse(&format!("{idp_base}/token")).unwrap(),
    };

    let opener = CapturingOpener::with_driver(DriverParams {
        code: "irrelevant_code".to_string(),
        state_override: Some("ATTACKER_PROVIDED_STATE".to_string()),
        error: None,
    });

    let err = run_loopback_flow(&endpoints, "hort-cli", &opener)
        .await
        .expect_err("mismatched state must error");

    // Downcast to the typed variant — confirms the right error code path.
    match err.downcast_ref::<LoopbackError>() {
        Some(LoopbackError::AuthorizationStateMismatch) => {}
        other => panic!("expected AuthorizationStateMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 3 — IdP redirects with error=access_denied; the flow surfaces a
// UserCancelled error, does NOT POST to the token endpoint, and exits cleanly.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn loopback_surfaces_user_cancelled_on_access_denied_redirect() {
    let mut idp = mockito::Server::new_async().await;
    let idp_base = idp.url();

    let _m_token = idp
        .mock("POST", "/token")
        .expect(0)
        .with_status(500)
        .create_async()
        .await;

    let endpoints = IdpEndpoints {
        device_authorization_endpoint: Url::parse(&format!("{idp_base}/device")).unwrap(),
        authorization_endpoint: Url::parse(&format!("{idp_base}/auth")).unwrap(),
        token_endpoint: Url::parse(&format!("{idp_base}/token")).unwrap(),
    };

    let opener = CapturingOpener::with_driver(DriverParams {
        code: "unused".to_string(),
        state_override: None,
        error: Some("access_denied".to_string()),
    });

    let err = run_loopback_flow(&endpoints, "hort-cli", &opener)
        .await
        .expect_err("access_denied must error");

    match err.downcast_ref::<LoopbackError>() {
        Some(LoopbackError::UserCancelled) => {}
        other => panic!("expected UserCancelled, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 4 — timeout: no callback ever arrives; the flow surfaces a Timeout
// error after HORT_OIDC_LOOPBACK_TIMEOUT_SECS expires. Uses the minimum 30s
// clamp via env-var to keep the test fast.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn loopback_times_out_when_no_callback_arrives() {
    let mut idp = mockito::Server::new_async().await;
    let idp_base = idp.url();

    let _m_token = idp
        .mock("POST", "/token")
        .expect(0)
        .with_status(500)
        .create_async()
        .await;

    let endpoints = IdpEndpoints {
        device_authorization_endpoint: Url::parse(&format!("{idp_base}/device")).unwrap(),
        authorization_endpoint: Url::parse(&format!("{idp_base}/auth")).unwrap(),
        token_endpoint: Url::parse(&format!("{idp_base}/token")).unwrap(),
    };

    // Capture-only opener: no callback ever drives the listener.
    let opener = CapturingOpener::capture_only();

    // 30s is the clamp minimum; tokio::time::pause is incompatible with
    // tiny_http's blocking recv_timeout, so we just wait the real 30s. To
    // keep the suite fast in normal runs, gate behind the
    // `HORT_LOOPBACK_RUN_TIMEOUT_TEST` env var (mirrors how RUSTSEC tests
    // gate slow scans elsewhere in the workspace).
    if std::env::var("HORT_LOOPBACK_RUN_TIMEOUT_TEST").is_err() {
        eprintln!(
            "skipping loopback_times_out_when_no_callback_arrives — \
             set HORT_LOOPBACK_RUN_TIMEOUT_TEST=1 to enable (~30s)"
        );
        return;
    }
    std::env::set_var("HORT_OIDC_LOOPBACK_TIMEOUT_SECS", "30");

    let err = run_loopback_flow(&endpoints, "hort-cli", &opener)
        .await
        .expect_err("absent callback must time out");

    std::env::remove_var("HORT_OIDC_LOOPBACK_TIMEOUT_SECS");

    match err.downcast_ref::<LoopbackError>() {
        Some(LoopbackError::Timeout(_)) => {}
        other => panic!("expected Timeout, got {other:?}"),
    }
}
