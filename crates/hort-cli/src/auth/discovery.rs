//! `/.well-known/hort-client-config` — client-bootstrap discovery fetcher.
//!
//! The server publishes a small JSON document when
//! `HORT_TOKEN_EXCHANGE_ENABLED=true`. This module fetches it, validates the
//! version and grant type, and returns a typed `DiscoveryOutcome` so the
//! caller never has to branch on raw HTTP status codes.
//!
//! # Design note — HTTP client
//!
//! The discovery call is **anonymous** (no `Authorization: Bearer` header).
//! `AkClient` is bearer-bound and intentionally not used here. A fresh
//! `reqwest::Client::builder()` is built per call. See design doc §3
//! "HTTP-client decision (locked)".

use anyhow::Result;
use serde::Deserialize;
use url::Url;

// ---------------------------------------------------------------------------
// DTOs — local types matching the server's wire shape exactly.
// Field names mirror `crates/hort-http-core/src/handlers/well_known.rs`.
//
// `url::Url` does not implement `serde::Deserialize` without the `url/serde`
// workspace feature. To keep Cargo.toml untouched (outside the two touchable
// paths for this item), we deserialise URL fields as `String` via a private
// helper and parse them at deserialisation time.
// ---------------------------------------------------------------------------

/// Full discovery document returned by `GET /.well-known/hort-client-config`.
#[derive(Debug, Deserialize)]
pub struct AkClientConfig {
    pub version: u32,
    pub idp: IdpConfig,
    pub exchange: ExchangeConfig,
}

/// IdP block within the discovery document.
#[derive(Debug, Deserialize)]
pub struct IdpConfig {
    #[serde(deserialize_with = "deserialize_url")]
    pub issuer: Url,
    pub client_id: String,
}

/// Exchange block within the discovery document.
#[derive(Debug, Deserialize)]
pub struct ExchangeConfig {
    #[serde(deserialize_with = "deserialize_url")]
    pub endpoint: Url,
    pub grant_type: String,
    pub subject_token_types_supported: Vec<String>,
}

// ---------------------------------------------------------------------------
// Private serde helper — parse a JSON string as a `url::Url`.
// ---------------------------------------------------------------------------

fn deserialize_url<'de, D>(deserializer: D) -> std::result::Result<Url, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Url::parse(&s).map_err(serde::de::Error::custom)
}

// ---------------------------------------------------------------------------
// DiscoveryOutcome
// ---------------------------------------------------------------------------

/// Tri-state result of `fetch_client_config`.
#[derive(Debug)]
pub enum DiscoveryOutcome {
    /// Server returned 200 and the body is a valid, version-1 document.
    /// Boxed to keep the enum compact (`AkClientConfig` is large).
    Available(Box<AkClientConfig>),
    /// Server returned 404 — OIDC is not enabled; fall back to paste.
    NotEnabled,
    /// Server returned 200 but the body was invalid, had `version != 1`,
    /// or had an unsupported `grant_type`. `reason` is operator-actionable.
    Malformed { reason: String },
}

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

const EXPECTED_VERSION: u32 = 1;
const EXPECTED_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const DISCOVERY_PATH: &str = "/.well-known/hort-client-config";
const REQUEST_TIMEOUT_SECS: u64 = 15;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch and parse `GET {server}/.well-known/hort-client-config`.
///
/// Returns:
/// - `Ok(Available(cfg))` — server is OIDC-capable and returned a valid doc.
/// - `Ok(NotEnabled)` — server returned 404 (feature is off).
/// - `Ok(Malformed { reason })` — 200 but the body is invalid, has the
///   wrong version, or has an unsupported grant_type.
/// - `Err(_)` — network error, timeout, or any non-(200|404) HTTP status.
pub async fn fetch_client_config(server: &Url) -> Result<DiscoveryOutcome> {
    let url = server.join(DISCOVERY_PATH)?;
    tracing::debug!(url = %url, "fetching hort-client-config discovery document");

    let builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .connect_timeout(std::time::Duration::from_secs(10));
    let builder = crate::client::apply_extra_ca_bundle(builder)?;
    let client = builder.build()?;

    let resp = client.get(url).send().await?;

    match resp.status().as_u16() {
        200 => {
            let text = resp.text().await?;
            validate_config_text(&text)
        }
        404 => {
            tracing::debug!(
                "hort-client-config returned 404 — OIDC not enabled; falling back to paste"
            );
            Ok(DiscoveryOutcome::NotEnabled)
        }
        status => {
            anyhow::bail!("unexpected HTTP {status} from discovery endpoint")
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn validate_config_text(text: &str) -> Result<DiscoveryOutcome> {
    let cfg: AkClientConfig = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            let reason =
                format!("discovery body is not valid JSON or missing required fields: {e}");
            tracing::warn!("{reason}");
            return Ok(DiscoveryOutcome::Malformed { reason });
        }
    };

    if cfg.version != EXPECTED_VERSION {
        let reason = format!(
            "discovery document has version {} (expected {EXPECTED_VERSION}); \
             upgrade hort-cli to support newer servers",
            cfg.version
        );
        tracing::warn!("{reason}");
        return Ok(DiscoveryOutcome::Malformed { reason });
    }

    if cfg.exchange.grant_type != EXPECTED_GRANT_TYPE {
        let reason = format!(
            "discovery document has unsupported grant_type '{}' (expected '{EXPECTED_GRANT_TYPE}')",
            cfg.exchange.grant_type
        );
        tracing::warn!("{reason}");
        return Ok(DiscoveryOutcome::Malformed { reason });
    }

    Ok(DiscoveryOutcome::Available(Box::new(cfg)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical exemplar JSON matching the server's well_known.rs sample
    // (crates/hort-http-core/src/handlers/well_known.rs).
    const VALID_V1_JSON: &str = r#"{
        "version": 1,
        "idp": {
            "issuer": "https://idp.example.com/realms/hort",
            "client_id": "hort-cli"
        },
        "exchange": {
            "endpoint": "https://hort.example.com/api/v1/auth/exchange",
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_types_supported": [
                "urn:ietf:params:oauth:token-type:access_token",
                "urn:ietf:params:oauth:token-type:id_token"
            ]
        }
    }"#;

    // -----------------------------------------------------------------------
    // Pure parse tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_valid_v1_config_round_trips() {
        let outcome = validate_config_text(VALID_V1_JSON).expect("no error");
        let DiscoveryOutcome::Available(cfg) = outcome else {
            panic!("expected Available, got {outcome:?}");
        };
        assert_eq!(cfg.version, 1);
        assert_eq!(
            cfg.idp.issuer.as_str(),
            "https://idp.example.com/realms/hort"
        );
        assert_eq!(cfg.idp.client_id, "hort-cli");
        assert_eq!(
            cfg.exchange.endpoint.as_str(),
            "https://hort.example.com/api/v1/auth/exchange"
        );
        assert_eq!(
            cfg.exchange.grant_type,
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        assert_eq!(cfg.exchange.subject_token_types_supported.len(), 2);
        assert!(cfg
            .exchange
            .subject_token_types_supported
            .contains(&"urn:ietf:params:oauth:token-type:access_token".to_string()));
        assert!(cfg
            .exchange
            .subject_token_types_supported
            .contains(&"urn:ietf:params:oauth:token-type:id_token".to_string()));
    }

    #[test]
    fn parse_rejects_version_other_than_1() {
        let json = r#"{
            "version": 2,
            "idp": {
                "issuer": "https://idp.example.com/realms/hort",
                "client_id": "hort-cli"
            },
            "exchange": {
                "endpoint": "https://hort.example.com/api/v1/auth/exchange",
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token"
                ]
            }
        }"#;
        let outcome = validate_config_text(json).expect("no error");
        let DiscoveryOutcome::Malformed { reason } = outcome else {
            panic!("expected Malformed, got {outcome:?}");
        };
        assert!(
            reason.contains("version"),
            "reason should mention version: {reason}"
        );
    }

    #[test]
    fn parse_rejects_unsupported_grant_type() {
        let json = r#"{
            "version": 1,
            "idp": {
                "issuer": "https://idp.example.com/realms/hort",
                "client_id": "hort-cli"
            },
            "exchange": {
                "endpoint": "https://hort.example.com/api/v1/auth/exchange",
                "grant_type": "password",
                "subject_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token"
                ]
            }
        }"#;
        let outcome = validate_config_text(json).expect("no error");
        let DiscoveryOutcome::Malformed { reason } = outcome else {
            panic!("expected Malformed, got {outcome:?}");
        };
        assert!(
            reason.contains("grant_type"),
            "reason should mention grant_type: {reason}"
        );
    }

    #[test]
    fn parse_rejects_missing_required_fields() {
        let cases: &[(&str, &str)] = &[
            (
                "missing version",
                r#"{"idp":{"issuer":"https://idp.example.com/realms/hort","client_id":"hort-cli"},"exchange":{"endpoint":"https://hort.example.com/api/v1/auth/exchange","grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_types_supported":[]}}"#,
            ),
            (
                "missing idp",
                r#"{"version":1,"exchange":{"endpoint":"https://hort.example.com/api/v1/auth/exchange","grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_types_supported":[]}}"#,
            ),
            (
                "missing exchange",
                r#"{"version":1,"idp":{"issuer":"https://idp.example.com/realms/hort","client_id":"hort-cli"}}"#,
            ),
            (
                "missing idp.issuer",
                r#"{"version":1,"idp":{"client_id":"hort-cli"},"exchange":{"endpoint":"https://hort.example.com/api/v1/auth/exchange","grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_types_supported":[]}}"#,
            ),
            (
                "missing idp.client_id",
                r#"{"version":1,"idp":{"issuer":"https://idp.example.com/realms/hort"},"exchange":{"endpoint":"https://hort.example.com/api/v1/auth/exchange","grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_types_supported":[]}}"#,
            ),
            (
                "missing exchange.endpoint",
                r#"{"version":1,"idp":{"issuer":"https://idp.example.com/realms/hort","client_id":"hort-cli"},"exchange":{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_types_supported":[]}}"#,
            ),
            (
                "missing exchange.grant_type",
                r#"{"version":1,"idp":{"issuer":"https://idp.example.com/realms/hort","client_id":"hort-cli"},"exchange":{"endpoint":"https://hort.example.com/api/v1/auth/exchange","subject_token_types_supported":[]}}"#,
            ),
            (
                "missing exchange.subject_token_types_supported",
                r#"{"version":1,"idp":{"issuer":"https://idp.example.com/realms/hort","client_id":"hort-cli"},"exchange":{"endpoint":"https://hort.example.com/api/v1/auth/exchange","grant_type":"urn:ietf:params:oauth:grant-type:token-exchange"}}"#,
            ),
        ];

        for (description, json) in cases {
            assert!(
                matches!(
                    validate_config_text(json).unwrap(),
                    DiscoveryOutcome::Malformed { .. }
                ),
                "{description} should be Malformed"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Async fetch tests (mockito)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fetch_client_config_returns_available_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/.well-known/hort-client-config")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(VALID_V1_JSON)
            .create_async()
            .await;

        let server_url = Url::parse(&server.url()).expect("valid url");
        let outcome = fetch_client_config(&server_url)
            .await
            .expect("no network error");

        assert!(
            matches!(outcome, DiscoveryOutcome::Available(_)),
            "expected Available on 200 with valid body, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn fetch_client_config_returns_not_enabled_on_404() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/.well-known/hort-client-config")
            .with_status(404)
            .create_async()
            .await;

        let server_url = Url::parse(&server.url()).expect("valid url");
        let outcome = fetch_client_config(&server_url)
            .await
            .expect("no network error");

        assert!(
            matches!(outcome, DiscoveryOutcome::NotEnabled),
            "expected NotEnabled on 404, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn fetch_client_config_returns_malformed_on_garbage_body() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/.well-known/hort-client-config")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create_async()
            .await;

        let server_url = Url::parse(&server.url()).expect("valid url");
        let outcome = fetch_client_config(&server_url)
            .await
            .expect("no network error");

        assert!(
            matches!(outcome, DiscoveryOutcome::Malformed { .. }),
            "expected Malformed on 200 with empty object body, got {outcome:?}"
        );
    }
}
