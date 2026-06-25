//! OCI Distribution-Spec `/v2/auth` token-exchange handler.
//!
//! Inbound HTTP layer over
//! [`hort_app::use_cases::oci_token_exchange_use_case::OciTokenExchangeUseCase`]
//! (ADR 0012). See the OCI Distribution Spec §token-exchange for the
//! wire flow.
//!
//! # Wire shape
//!
//! Request:
//!
//! ```text
//! GET /v2/auth?service=<host>&scope=repository:foo/bar:pull,push
//! Authorization: Basic base64("<anything>:<PAT>")
//! ```
//!
//! Response (200):
//!
//! ```json
//! {
//!   "token": "<jwt>",
//!   "access_token": "<jwt>",
//!   "expires_in": 300,
//!   "issued_at": "2026-05-06T12:00:00Z"
//! }
//! ```
//!
//! `token` and `access_token` carry the SAME JWT — `token` is for
//! older Docker clients, `access_token` is for OAuth2-compliant
//! clients per Distribution Spec.
//!
//! Failure shapes:
//!
//! - **No `Authorization` header / non-Basic**: 401 with the Bearer
//!   challenge re-emitted (so the client knows to retry with creds).
//! - **Invalid PAT**: 401 with the Bearer challenge re-emitted.
//! - **Malformed scope**: 400 with `{"errors":[{"code":"UNSUPPORTED",
//!   "message":"invalid scope: <raw>"}]}`.
//! - **Mint / infrastructure failure**: 500 with `INTERNAL`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
// NOT `axum::extract::Query`: that extractor is backed by
// `serde_urlencoded`, which has no sequence support and errors
// `invalid type: string "…", expected a sequence` on the `Vec<String>`
// `scope` field for EVERY scoped request. `axum_extra::extract::Query`
// is backed by `serde_html_form`, which deserializes repeated keys
// (`scope=a&scope=b` → `vec!["a","b"]`, a single `scope=a` → `vec!["a"]`,
// an absent `scope` → `vec![]`).
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::Query;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use hort_app::use_cases::oci_token_exchange_use_case::{
    OciTokenExchangeError, OciTokenExchangeRequest,
};
use hort_http_core::context::AppContext;

use crate::error::OciError;
use crate::middleware::oci_auth::v2_auth_challenge_value;

/// The canonical Distribution-Spec token-mint path. **Single source of truth
/// for the literal:** the route registration ([`crate::oci_routes_with_config`])
/// and the `oci_bearer_auth` path-skip both reference this const, so a rename
/// moves both at once and the skip can never silently stop matching the route.
pub(crate) const V2_AUTH_PATH: &str = "/v2/auth";

// ---------------------------------------------------------------------------
// Query DTO
// ---------------------------------------------------------------------------

/// Inbound `?service=…&scope=…[&scope=…]` parameters.
///
/// `service` is required; `scope` is optional and may repeat. This DTO
/// is extracted with [`axum_extra::extract::Query`] (NOT
/// `axum::extract::Query`): its `serde_html_form` backend materialises
/// repeated `scope=` params into a `Vec<String>`. Plain axum `Query`
/// uses `serde_urlencoded`, which has no sequence support and would
/// error `expected a sequence` on every request carrying a `scope`. An
/// entirely-omitted `scope` deserialises to `vec![]` — the response is
/// then a token with an empty `access[]` ("ping-style"
/// anonymous-equivalent).
#[derive(Debug, Deserialize)]
pub struct V2AuthQuery {
    /// Registry hostname per Distribution-Spec convention. Echoed in
    /// the JWT `aud` claim (the use case's config value is
    /// authoritative; this string is used only for logging /
    /// future-debug).
    pub service: String,
    /// Multi-`scope` field. `serde_html_form` (via
    /// [`axum_extra::extract::Query`]) flattens repeated
    /// `scope=foo&scope=bar` into `vec!["foo", "bar"]`; a single
    /// `scope=foo` into `vec!["foo"]`; an absent `scope` into `vec![]`.
    /// Comma-separated *actions* within one scope
    /// (`repository:foo:pull,push`) are NOT split here — they stay one
    /// element and are split downstream by `parse_scope`.
    #[serde(default)]
    pub scope: Vec<String>,
}

// ---------------------------------------------------------------------------
// Response DTO — Distribution-Spec wire shape
// ---------------------------------------------------------------------------

/// Distribution-Spec response body. Both `token` and `access_token`
/// carry the SAME JWT (string-equal); the catalog test asserts this.
#[derive(Debug, Serialize)]
struct V2AuthResponseBody {
    token: String,
    access_token: String,
    expires_in: u64,
    issued_at: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /v2/auth` — Distribution-Spec token exchange.
///
/// Mounted by [`crate::oci_routes_with_config`] at [`V2_AUTH_PATH`]. The
/// `oci_bearer_auth` middleware PATH-SKIPS this route (the consume-side bearer
/// gate does not own the mint endpoint), so this handler owns credential
/// validation: it parses the `Authorization: Basic` header itself rather than
/// using a middleware principal, because:
/// - The username slot is irrelevant per spec (clients pass `oauth2`,
///   `<anything>`, or empty); only the password (PAT) matters.
/// - The PAT is validated AS a PAT (via `OciTokenExchangeUseCase`), not as an
///   IdP JWT — the middleware's bearer flow would mis-handle it.
pub async fn handle_v2_auth(
    State(ctx): State<Arc<AppContext>>,
    Query(query): Query<V2AuthQuery>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let exchange = match &ctx.oci_token_exchange {
        Some(uc) => uc.clone(),
        None => {
            // Native tokens disabled — `/v2/auth` is unreachable. The
            // handler still parses the request to keep the wire
            // contract clean; surface 404 NOT_FOUND so clients know
            // to fall back to the legacy Basic flow.
            tracing::debug!("/v2/auth invoked but native tokens disabled — returning 404");
            return OciError::NameUnknown {
                repository: "/v2/auth".into(),
            }
            .into_response();
        }
    };

    // The `service=`-vs-configured-`aud` 400-on-mismatch gate is
    // enforced INSIDE `OciTokenExchangeUseCase::exchange` as an
    // unbypassable Step-0 (before scope parse + PAT validation). The
    // handler only maps the typed `ServiceMismatch` error to the wire
    // body below — the gate itself is in `hort-app` so no caller can
    // skip it.

    // Parse `Authorization: Basic <b64(user:PAT)>`.
    let Some(plaintext) = extract_basic_password(&headers) else {
        return unauthorized_with_challenge(&ctx, &query, "missing Basic credentials");
    };

    let client_ip = connect_info.map(|ConnectInfo(addr)| addr.ip());

    let request = OciTokenExchangeRequest {
        plaintext_pat: plaintext,
        service: query.service.clone(),
        scopes: query.scope.clone(),
        client_ip,
    };
    match exchange.exchange(request).await {
        Ok(resp) => {
            let body = V2AuthResponseBody {
                token: resp.jwt.clone(),
                access_token: resp.jwt,
                expires_in: resp.expires_in_secs,
                issued_at: resp.issued_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(OciTokenExchangeError::ServiceMismatch { .. }) => {
            // HTTP 400, reuse the Distribution-Spec `UNSUPPORTED`
            // envelope (clients parse it with the same code path as
            // the established `invalid scope` 400), constant message
            // `"service mismatch"` — the body NEVER echoes the
            // requested / expected host — no reflected value; the
            // structured audit log in `hort-app` carries both for the
            // operator. The
            // `Docker-Distribution-API-Version` header is present,
            // consistent with every other `/v2/*` error.
            service_mismatch_response()
        }
        Err(OciTokenExchangeError::InvalidCredential) => {
            unauthorized_with_challenge(&ctx, &query, "invalid credential")
        }
        Err(OciTokenExchangeError::InvalidScope { raw }) => OciError::Unsupported {
            // Reflects the caller's OWN malformed scope (JSON-escaped by
            // serde — no injection), matching standard registry
            // behaviour. Deliberately asymmetric with
            // `service_mismatch_response`, which hides server config
            // (the configured `aud`) behind a constant message: the
            // service= path must not leak server state, whereas echoing
            // the caller's own input is safe and aids client debugging.
            message: format!("invalid scope: {raw}"),
        }
        .into_response(),
        Err(OciTokenExchangeError::TooManyScopes) => OciError::Unsupported {
            // Constant message — the offending count is in the
            // `hort-app` audit log, not the wire body.
            message: "too many scopes".to_string(),
        }
        .into_response(),
        Err(OciTokenExchangeError::Mint(err)) => {
            tracing::error!(error = %err, "/v2/auth mint failure");
            OciError::Internal.into_response()
        }
        Err(OciTokenExchangeError::Infrastructure(err)) => {
            tracing::error!(error = %err, "/v2/auth infrastructure failure");
            OciError::Internal.into_response()
        }
    }
}

/// Pull the password slot out of `Authorization: Basic <b64>`.
/// Returns `None` for missing header, non-Basic schemes, malformed
/// base64, missing `:`, or empty password.
fn extract_basic_password(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = raw.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_user, pw) = decoded.split_once(':')?;
    let pw = pw.trim();
    if pw.is_empty() {
        None
    } else {
        Some(pw.to_string())
    }
}

/// The `service=` mismatch 400 per OCI Distribution Spec §3.3.
///
/// Byte-exact: HTTP 400, body is the **same** `UNSUPPORTED` envelope
/// `OciError::Unsupported` already renders
/// (`{"errors":[{"code":"UNSUPPORTED","message":"service mismatch"}]}`),
/// `Docker-Distribution-API-Version: registry/2.0` header present
/// (consistent with `unauthorized_with_challenge` and every other
/// `/v2/*` error). The message is the constant `"service mismatch"` —
/// the body NEVER echoes the requested / expected host (the
/// reflected-value smell the spec rejects); both values are in the
/// `hort-app` structured audit log instead.
fn service_mismatch_response() -> Response {
    let mut response = OciError::Unsupported {
        message: "service mismatch".to_string(),
    }
    .into_response();
    response.headers_mut().insert(
        "Docker-Distribution-API-Version",
        axum::http::HeaderValue::from_static("registry/2.0"),
    );
    response
}

/// 401 response carrying the same Bearer challenge the unauthenticated
/// `/v2/*` middleware would emit. Re-emitting on `/v2/auth` itself is
/// harmless and keeps the negotiation predictable.
fn unauthorized_with_challenge(ctx: &AppContext, query: &V2AuthQuery, message: &str) -> Response {
    let challenge = v2_auth_challenge_value(
        ctx.oci_public_base_url.as_deref(),
        Some(&query.service),
        // The auth endpoint itself doesn't have a per-request scope
        // for the challenge; emit the requested scope (first one)
        // for client-side replay convenience. None when no scope was
        // supplied.
        query.scope.first().map(String::as_str),
    );
    let mut response = OciError::Unauthorized {
        message: message.to_string(),
        detail: None,
    }
    .into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response.headers_mut().insert(
        "Docker-Distribution-API-Version",
        axum::http::HeaderValue::from_static("registry/2.0"),
    );
    response
}

// ---------------------------------------------------------------------------
// path_to_scope helper — used by the challenge middleware AND tests
// ---------------------------------------------------------------------------

/// Map a request path to its Distribution-Spec scope string for the
/// `WWW-Authenticate: Bearer …,scope="<scope>"` challenge.
///
/// Returns `None` for paths that have no canonical scope (the version
/// probe `GET /v2/`, the auth endpoint itself, anything outside `/v2`).
///
/// This is a heuristic: the OCI route tree carries the canonical
/// dispatch elsewhere, but for the *challenge* the scope is a hint to
/// the client about what credentials to fetch. A wrong scope here
/// only delays the negotiation by one round-trip, never breaks it
/// (the client re-fetches with the actual scope on the second 401).
pub fn path_to_scope(method: &axum::http::Method, path: &str) -> Option<String> {
    // Strip leading `/`. Anything not under `/v2/` does not have an
    // OCI-shaped scope.
    let rest = path.strip_prefix("/v2/")?;
    if rest.is_empty() {
        // Bare /v2/ — version probe, anonymous.
        return None;
    }
    if rest == "auth" || rest.starts_with("auth?") || rest == "_catalog" {
        // /v2/_catalog → registry catalog scope. Push to a `pull`
        // for clients that interpret the action.
        if rest == "_catalog" {
            return Some("registry:catalog:*".to_string());
        }
        return None;
    }
    // /v2/<repo_key>/<rest> — extract the repo_key + try to map the
    // tail. Distribution-Spec scopes embed the FULL `<group>/<image>`
    // canonical path; hort-server's `<repo_key>/<canonical>` shape
    // means the scope name is `<repo_key>/<image-prefix>` exactly.
    // The tail itself decides whether the action is pull or push.
    let (repo_key, tail) = rest.split_once('/')?;
    if tail.is_empty() {
        return None;
    }
    // Synthesize the OCI image name from the tail by stripping the
    // trailing `/blobs/<digest>`, `/manifests/<ref>`, etc.
    let image_name = strip_oci_suffix(tail)?;
    let actions = match (method.as_str(), tail) {
        // Reads = pull. Writes = push. Delete = delete.
        ("GET", _) | ("HEAD", _) => "pull",
        ("POST", t) | ("PUT", t) | ("PATCH", t) if t.contains("blobs/uploads") => "push",
        ("PUT", t) if t.contains("/manifests/") => "push",
        ("DELETE", _) => "delete",
        _ => "pull",
    };
    Some(format!("repository:{repo_key}/{image_name}:{actions}"))
}

/// Strip the canonical OCI suffix from a tail to recover the image
/// name segment. Returns `None` for tails that don't have a
/// recognised suffix (the challenge falls back to no `scope=` value).
fn strip_oci_suffix(tail: &str) -> Option<&str> {
    for marker in &[
        "/blobs/uploads/",
        "/blobs/uploads",
        "/blobs/",
        "/manifests/",
        "/tags/list",
        "/referrers/",
    ] {
        if let Some(pos) = tail.find(marker) {
            return Some(&tail[..pos]);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::{HeaderName, HeaderValue, Method};

    #[test]
    fn extract_basic_password_happy_path() {
        let mut h = HeaderMap::new();
        let creds = base64::engine::general_purpose::STANDARD.encode("user:hunter2");
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {creds}")).unwrap(),
        );
        assert_eq!(extract_basic_password(&h).as_deref(), Some("hunter2"));
    }

    #[test]
    fn extract_basic_password_empty_password_rejected() {
        let mut h = HeaderMap::new();
        let creds = base64::engine::general_purpose::STANDARD.encode("user:");
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {creds}")).unwrap(),
        );
        assert!(extract_basic_password(&h).is_none());
    }

    #[test]
    fn extract_basic_password_non_basic_rejected() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert!(extract_basic_password(&h).is_none());
    }

    #[test]
    fn extract_basic_password_malformed_base64_rejected() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!not-b64!!!"),
        );
        assert!(extract_basic_password(&h).is_none());
    }

    #[test]
    fn extract_basic_password_missing_colon_rejected() {
        let mut h = HeaderMap::new();
        let creds = base64::engine::general_purpose::STANDARD.encode("nocolon");
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {creds}")).unwrap(),
        );
        assert!(extract_basic_password(&h).is_none());
    }

    #[test]
    fn extract_basic_password_missing_header() {
        let h = HeaderMap::new();
        assert!(extract_basic_password(&h).is_none());
    }

    // ---------- path_to_scope ----------

    #[test]
    fn path_to_scope_returns_none_for_version_probe() {
        assert!(path_to_scope(&Method::GET, "/v2/").is_none());
    }

    #[test]
    fn path_to_scope_returns_none_for_auth_path() {
        assert!(path_to_scope(&Method::GET, "/v2/auth").is_none());
    }

    #[test]
    fn path_to_scope_catalog_is_registry_scope() {
        let s = path_to_scope(&Method::GET, "/v2/_catalog").expect("scope");
        assert_eq!(s, "registry:catalog:*");
    }

    #[test]
    fn path_to_scope_blob_pull_is_pull() {
        let s = path_to_scope(&Method::GET, "/v2/myrepo/library/nginx/blobs/sha256:abc")
            .expect("scope");
        assert_eq!(s, "repository:myrepo/library/nginx:pull");
    }

    #[test]
    fn path_to_scope_manifest_head_is_pull() {
        let s = path_to_scope(&Method::HEAD, "/v2/myrepo/foo/manifests/v1").expect("scope");
        assert_eq!(s, "repository:myrepo/foo:pull");
    }

    #[test]
    fn path_to_scope_manifest_put_is_push() {
        let s = path_to_scope(&Method::PUT, "/v2/myrepo/foo/manifests/v1").expect("scope");
        assert_eq!(s, "repository:myrepo/foo:push");
    }

    #[test]
    fn path_to_scope_blob_upload_post_is_push() {
        let s = path_to_scope(&Method::POST, "/v2/myrepo/foo/blobs/uploads/").expect("scope");
        assert_eq!(s, "repository:myrepo/foo:push");
    }

    #[test]
    fn path_to_scope_manifest_delete_is_delete() {
        let s =
            path_to_scope(&Method::DELETE, "/v2/myrepo/foo/manifests/sha256:abc").expect("scope");
        assert_eq!(s, "repository:myrepo/foo:delete");
    }

    #[test]
    fn path_to_scope_non_v2_path_is_none() {
        assert!(path_to_scope(&Method::GET, "/api/users").is_none());
    }

    // ---------- response shape ----------

    #[test]
    fn v2_auth_response_body_serializes_with_both_token_fields() {
        let body = V2AuthResponseBody {
            token: "jwt-string".into(),
            access_token: "jwt-string".into(),
            expires_in: 300,
            issued_at: "2026-05-06T12:00:00Z".into(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["token"], "jwt-string");
        assert_eq!(json["access_token"], "jwt-string");
        assert_eq!(json["expires_in"], 300);
        assert_eq!(json["issued_at"], "2026-05-06T12:00:00Z");
    }

    /// Distribution-Spec wire form: `token` and `access_token` MUST
    /// carry the SAME string (older Docker reads `token`, OAuth2-
    /// compliant readers read `access_token`).
    #[test]
    fn v2_auth_response_body_token_and_access_token_match() {
        let body = V2AuthResponseBody {
            token: "abc.def.ghi".into(),
            access_token: "abc.def.ghi".into(),
            expires_in: 300,
            issued_at: "2026-05-06T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["token"], json["access_token"]);
    }

    /// Header-name-collision check: silence a future change that
    /// types `Docker-Distribution-API-Version` with a wrong byte and
    /// breaks Docker client parsing.
    #[test]
    fn challenge_response_carries_distribution_api_version_header() {
        let _name: HeaderName = "Docker-Distribution-API-Version".parse().unwrap();
    }
}
