//! OCI tags list — `GET /v2/<repo_key>/<name>/tags/list`.
//!
//! Drives [`hort_app::use_cases::ref_use_case::RefUseCase::list`] over
//! the `(repo_id, namespace=name)` pair. The cursor walk is byte-stable;
//! the handler forwards `?n=` / `?last=` query params unchanged.
//!
//! Response envelope (spec):
//! ```json
//! { "name": "library/nginx", "tags": ["v1", "v2", "latest"] }
//! ```
//!
//! `Link: </v2/<repo_key>/<name>/tags/list?n=&last=...>; rel="next"`
//! is emitted only when the page is saturated (a subsequent page
//! exists). Non-saturated terminal pages omit the header — clients
//! treat its absence as "end of enumeration".

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use urlencoding::encode as urlencode;

use hort_app::error::AppError;
use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::error::DomainError;

use super::error::OciError;
use hort_http_core::context::AppContext;

/// Query parameters for tags list + catalog endpoints. Both surfaces
/// use the same shape (`?n=<limit>&last=<cursor>`), so the struct is
/// shared via `super::` in `catalog.rs` and via the pull dispatcher
/// in `mod.rs`. Missing fields deserialize to `None` (axum's `Query`
/// extractor tolerates absent query strings when every field is
/// `Option<_>`).
#[derive(Debug, Deserialize, Default, Clone)]
pub struct PageQuery {
    /// Per-page limit. `None` or `0` falls through to the use-case
    /// default (100). Clamped to `[1, 1000]` by the use case.
    #[serde(default)]
    pub n: Option<u32>,
    /// Cursor — the last `ref_name` (or qualified group name) from
    /// the previous page. Pagination returns `> last` under byte
    /// ordering.
    #[serde(default)]
    pub last: Option<String>,
}

pub async fn serve(
    ctx: Arc<AppContext>,
    repo_key: &str,
    name: &str,
    query: PageQuery,
    actor: Option<&CallerPrincipal>,
) -> Response {
    // Visibility-checked repo resolve (ADR 0008). Missing or
    // invisible-to-actor private repo collapse to NAME_UNKNOWN
    // (anti-enumeration). The use case enforces Read on the repo
    // before the path lookup, closing anonymous read on private repos.
    let repo = match ctx
        .repository_access_use_case
        .resolve(repo_key, actor, AccessLevel::Read)
        .await
    {
        Ok(r) => r,
        Err(AppError::Domain(DomainError::NotFound { .. })) => {
            return OciError::NameUnknown {
                repository: repo_key.to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                error = %e,
                "repo lookup failed during OCI tags list"
            );
            return internal_error_response();
        }
    };

    let n = query.n.unwrap_or(0);
    let after = query.last.as_deref();

    let page = match ctx.ref_use_case.list(repo.id, name, after, n).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                namespace = %name,
                error = %e,
                "ref list failed"
            );
            return internal_error_response();
        }
    };

    let tags: Vec<String> = page.items.iter().map(|r| r.ref_name.clone()).collect();
    let body_value = serde_json::json!({
        "name": name,
        "tags": tags,
    });
    let body_bytes = serde_json::to_vec(&body_value).expect("static-shape JSON serialises");

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json");

    if page.saturated {
        if let Some(last_tag) = tags.last() {
            let link = format_next_link(repo_key, name, n, last_tag);
            // `Link` header values are ASCII; construction cannot
            // fail unless the inputs contain a CR/LF — which
            // `format_next_link`'s urlencode defence prevents.
            if let Ok(v) = HeaderValue::from_str(&link) {
                builder = builder.header("Link", v);
            }
        }
    }

    builder.body(Body::from(body_bytes)).unwrap()
}

/// Build the OCI spec Link header value for the next page of tags.
///
/// `last` is URL-encoded so tag names with `+`, `%`, or `/` don't break the Link syntax.
fn format_next_link(repo_key: &str, name: &str, n: u32, last: &str) -> String {
    let last_enc = urlencode(last);
    // `n = 0` is the "unspecified" shape upstream; preserve the same
    // shape on the `next` link so the client walks with the server's
    // default limit unless they originally passed `?n=`.
    if n == 0 {
        format!("</v2/{repo_key}/{name}/tags/list?last={last_enc}>; rel=\"next\"")
    } else {
        format!("</v2/{repo_key}/{name}/tags/list?n={n}&last={last_enc}>; rel=\"next\"")
    }
}

fn internal_error_response() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"errors":[{"code":"UNSUPPORTED","message":"internal error","detail":null}]}"#,
        ))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------- format_next_link ----------------

    #[test]
    fn link_format_with_n() {
        let l = format_next_link("myrepo", "library/nginx", 10, "v1.0");
        assert_eq!(
            l,
            "</v2/myrepo/library/nginx/tags/list?n=10&last=v1.0>; rel=\"next\""
        );
    }

    #[test]
    fn link_format_without_n_omits_n_param() {
        let l = format_next_link("myrepo", "library/nginx", 0, "v1.0");
        assert_eq!(
            l,
            "</v2/myrepo/library/nginx/tags/list?last=v1.0>; rel=\"next\""
        );
    }

    #[test]
    fn link_format_url_encodes_last() {
        // `+` and `/` in tag names must percent-encode. Otherwise the
        // Link header wouldn't round-trip through the client's
        // query-string parser.
        let l = format_next_link("myrepo", "nginx", 10, "v1.0+build");
        assert!(l.contains("last=v1.0%2Bbuild"), "unexpected encoding: {l}");
    }

    // ---------------- Handler-level ----------------
    //
    // The handler-level tests (happy path, saturated Link header,
    // missing repo → NAME_UNKNOWN) live alongside the router-level
    // tests in `handlers/oci/mod.rs::tests` after the dispatcher is
    // wired — they drive the `/v2/:repo_key/*tail` route end-to-end
    // via `oneshot`. Keeping them there prevents re-building the
    // `AppContext` harness in every submodule.
}
