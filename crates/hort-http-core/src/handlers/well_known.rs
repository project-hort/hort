//! `/.well-known/hort-client-config` — anonymous client-bootstrap
//! document for `hort-cli`.
//!
//! Rationale (see ADR 0013 for the CLI-session model): hort is a
//! resource server with a token-exchange endpoint federating to an
//! upstream IdP, NOT an OAuth authorization server, so this is **not**
//! RFC 8414. The field names use hort-defined vocabulary
//! (`exchange.endpoint`, NOT `token_endpoint`) so a future RFC 8414
//! metadata document can coexist at
//! `/.well-known/oauth-authorization-server` without a name collision.
//!
//! ## Wire shape
//!
//! ```json
//! {
//!   "version": 1,
//!   "idp": {
//!     "issuer": "https://idp.example.com/realms/hort",
//!     "client_id": "hort-cli"
//!   },
//!   "exchange": {
//!     "endpoint": "https://hort.example.com/api/v1/auth/exchange",
//!     "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
//!     "subject_token_types_supported": [
//!       "urn:ietf:params:oauth:token-type:access_token"
//!     ]
//!   }
//! }
//! ```
//!
//! `subject_token_types_supported` deliberately excludes `id_token`
//! — accepting it would mix `aud = client_id` semantics into the
//! validator's single-audience matching. The standards-shaped fix for
//! IdPs that omit `sub` on access tokens is an IdP-side claim mapper;
//! see `docs/operator/idp-setup.md`.
//!
//! ## Mounting
//!
//! `well_known_routes()` is merged into the non-OCI subtree by
//! `hort-server::http::build_router` (around L148, inside the
//! `if enable_token_exchange { ... }` guard) BEFORE the subtree is
//! handed to `crate::router::wrap_with_middleware`. The wrapper
//! attaches `method_based_auth_dispatch`, which routes `GET` to
//! [`crate::middleware::auth::extract_optional_principal`] — that
//! middleware passes a request with no `Authorization` header through
//! to the handler with `Option<CallerPrincipal> = None`, so the
//! endpoint is anonymous in the same way every other GET on the
//! non-OCI subtree is anonymous.
//!
//! There is therefore no separate "skip auth on this path" carve-out —
//! anonymity comes from being a `GET` whose handler does not require a
//! principal, not from a dedicated bypass (ADR 0021). The route is
//! mounted at all only when `HORT_TOKEN_EXCHANGE_ENABLED=true`; off →
//! axum's default 404, no surface advertised. Same gate as
//! `/api/v1/auth/exchange`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::context::AppContext;
// `EXCHANGE_GRANT_TYPE` and `SUPPORTED_SUBJECT_TOKEN_TYPES` are the
// canonical RFC 8693 wire constants. Both this discovery doc and the
// `/exchange` handler (`crate::handlers::exchange`) read from the same
// module so the values published here match the values the handler
// accepts; the canonical gate is
// [`crate::handlers::token_exchange_common::is_supported_subject_token_type`].
use crate::handlers::token_exchange_common::{EXCHANGE_GRANT_TYPE, SUPPORTED_SUBJECT_TOKEN_TYPES};

/// Pre-rendered values that back the discovery document. Built once at
/// startup by `hort-server::composition` when
/// `HORT_TOKEN_EXCHANGE_ENABLED=true`. The composition root validates
/// that every field is non-empty before constructing this struct
/// (fail-closed boot rule in `hort-server::config`); the handler
/// can therefore borrow these as `&str` without re-checking.
#[derive(Clone, Debug)]
pub struct ClientBootstrapConfig {
    /// IdP issuer URL — published as `idp.issuer`. Source:
    /// `HORT_OIDC_ISSUER_URL`. The CLI runs OIDC discovery (then RFC
    /// 8628 device flow) against this URL.
    pub idp_issuer: String,
    /// OAuth public-client name `hort-cli` presents to the IdP —
    /// published as `idp.client_id`. Source: `HORT_OIDC_CLI_CLIENT_ID`.
    pub idp_cli_client_id: String,
    /// Absolute URL of `POST /api/v1/auth/exchange` — published as
    /// `exchange.endpoint`. Source: `HORT_PUBLIC_BASE_URL` joined with
    /// the exchange path. Stored as `String` (already validated as a
    /// `Url` at composition time) to keep the response builder
    /// allocation-free.
    pub exchange_endpoint: String,
}

#[derive(Serialize)]
struct ClientConfigResponse<'a> {
    version: u32,
    idp: IdpBlock<'a>,
    exchange: ExchangeBlock<'a>,
}

#[derive(Serialize)]
struct IdpBlock<'a> {
    issuer: &'a str,
    client_id: &'a str,
}

#[derive(Serialize)]
struct ExchangeBlock<'a> {
    endpoint: &'a str,
    grant_type: &'static str,
    subject_token_types_supported: &'static [&'static str],
}

/// `GET /.well-known/hort-client-config` — anonymous discovery
/// endpoint. Returns the static client-bootstrap JSON document
/// composed from `ctx.client_config`.
///
/// Returns `503 Service Unavailable` with a tiny JSON envelope when
/// `ctx.client_config` is `None` — that branch is reachable only via
/// a composition bug (the route shouldn't be mounted when the feature
/// is off), and 503 is the correct status for "the endpoint exists
/// but is currently misconfigured."
///
/// Tracing: `debug!` per request. This endpoint is anonymous and high
/// volume relative to `/exchange`; per-request `info!` would flood the
/// log. No `err` variant per the CLAUDE.md observability rules.
#[tracing::instrument(skip(ctx))]
pub async fn get_client_config(State(ctx): State<Arc<AppContext>>) -> Response {
    let Some(cfg) = ctx.client_config.as_ref() else {
        // Composition-bug guard. The route is only supposed to be
        // mounted when `client_config` is populated; if we somehow
        // reach the handler with `None`, surface it explicitly rather
        // than returning a half-formed document.
        tracing::warn!(
            "client_config endpoint hit with ctx.client_config = None — \
             likely a composition bug (route mounted without populating the field)"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (CONTENT_TYPE, "application/json"),
                (CACHE_CONTROL, "no-store"),
            ],
            Json(serde_json::json!({
                "error": "client_config_unavailable",
                "error_description": "discovery document is not configured on this server"
            })),
        )
            .into_response();
    };

    let body = ClientConfigResponse {
        version: 1,
        idp: IdpBlock {
            issuer: &cfg.idp_issuer,
            client_id: &cfg.idp_cli_client_id,
        },
        exchange: ExchangeBlock {
            endpoint: &cfg.exchange_endpoint,
            grant_type: EXCHANGE_GRANT_TYPE,
            subject_token_types_supported: SUPPORTED_SUBJECT_TOKEN_TYPES,
        },
    };

    tracing::debug!("client_config served");

    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/json"),
            // 5 minutes — field values are rotation-stable. Conservative
            // enough that an operator rotating `HORT_OIDC_CLI_CLIENT_ID`
            // sees clients re-fetch within one cache window.
            (CACHE_CONTROL, "public, max-age=300"),
        ],
        Json(body),
    )
        .into_response()
}

/// Build the well-known route subtree. Mounted by `hort-server::http`
/// only when `HORT_TOKEN_EXCHANGE_ENABLED=true`.
pub fn well_known_routes() -> Router<Arc<AppContext>> {
    Router::new().route("/.well-known/hort-client-config", get(get_client_config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use crate::test_support::{build_mock_ctx, with_client_config};

    fn ctx_with_config(cfg: Option<ClientBootstrapConfig>) -> Arc<AppContext> {
        let metrics_handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, _mocks) = build_mock_ctx(metrics_handle);
        with_client_config(&base, cfg)
    }

    fn sample_config() -> ClientBootstrapConfig {
        ClientBootstrapConfig {
            idp_issuer: "https://idp.example.com/realms/hort".into(),
            idp_cli_client_id: "hort-cli".into(),
            exchange_endpoint: "https://hort.example.com/api/v1/auth/exchange".into(),
        }
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn client_config_returns_200_with_correct_shape() {
        let ctx = ctx_with_config(Some(sample_config()));
        let app = well_known_routes().with_state(ctx);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/hort-client-config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/json"
        );
        assert_eq!(
            resp.headers().get(CACHE_CONTROL).unwrap().to_str().unwrap(),
            "public, max-age=300"
        );

        let json = body_json(resp).await;
        assert_eq!(json["version"], 1);
        assert_eq!(json["idp"]["issuer"], "https://idp.example.com/realms/hort");
        assert_eq!(json["idp"]["client_id"], "hort-cli");
        assert_eq!(
            json["exchange"]["endpoint"],
            "https://hort.example.com/api/v1/auth/exchange"
        );
        assert_eq!(
            json["exchange"]["grant_type"],
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        let types = json["exchange"]["subject_token_types_supported"]
            .as_array()
            .expect("subject_token_types_supported must be an array");
        // The closed set is `access_token` plus `jwt` (federation
        // branch). This two-element set is the wire contract;
        // `id_token` stays explicitly excluded.
        assert_eq!(types.len(), 2);
        assert!(types
            .iter()
            .any(|v| v == "urn:ietf:params:oauth:token-type:access_token"));
        assert!(types
            .iter()
            .any(|v| v == "urn:ietf:params:oauth:token-type:jwt"));
        assert!(
            !types
                .iter()
                .any(|v| v == "urn:ietf:params:oauth:token-type:id_token"),
            "id_token must NOT be published"
        );
    }

    #[tokio::test]
    async fn client_config_field_version_is_exactly_1() {
        // Hardcoded to `1`. A future schema bump must touch this
        // test — it is the dedicated regression anchor.
        let ctx = ctx_with_config(Some(sample_config()));
        let app = well_known_routes().with_state(ctx);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/hort-client-config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["version"], 1, "version is hardcoded to 1");
    }

    #[tokio::test]
    async fn client_config_returns_503_when_app_context_lacks_config() {
        // Composition-bug path: route mounted but `client_config = None`.
        // Should not happen because composition only mounts the route
        // when the field is populated, but the handler must surface the
        // bug rather than serve a half-formed document.
        let ctx = ctx_with_config(None);
        let app = well_known_routes().with_state(ctx);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/hort-client-config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "client_config_unavailable");
    }

    #[tokio::test]
    async fn client_config_anonymous_no_bearer_required() {
        // The route is built without any auth middleware in this test;
        // production puts it behind the per-method auth dispatch which
        // routes GET to `extract_optional_principal`. Both topologies
        // accept anonymous requests — this test pins the behaviour at
        // the route layer.
        let ctx = ctx_with_config(Some(sample_config()));
        let app = well_known_routes().with_state(ctx);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/hort-client-config")
                    // no Authorization header
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn client_config_route_absent_when_well_known_routes_not_mounted() {
        // When `enable_token_exchange = false`, hort-server::http does NOT
        // call `well_known_routes()` and the path falls through to
        // axum's default 404. We simulate the "feature off" topology by
        // building a router with NO well-known routes merged.
        let ctx = ctx_with_config(None);
        let app: Router<()> = Router::new().with_state(ctx);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/hort-client-config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
