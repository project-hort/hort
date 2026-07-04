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
use axum::response::Response;
use serde::Deserialize;
use urlencoding::encode as urlencode;

use hort_app::error::AppError;
use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::error::DomainError;

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
            // Repo-level read denial: 401 + mode-aware challenge for an
            // anonymous caller, NAME_UNKNOWN 404 anti-enumeration for an
            // authenticated one (D1/D2, ADR 0021).
            let path = format!("/v2/{repo_key}/{name}/tags/list");
            return crate::middleware::oci_auth::read_denied_response(
                &ctx,
                actor,
                &axum::http::Method::GET,
                &path,
                repo_key,
            );
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
    // The happy-path / saturated-Link-header / router-level tests live
    // alongside the dispatcher in `lib.rs::tests` (they drive the
    // `/v2/:repo_key/*tail` route end-to-end via `oneshot`). The
    // read-denial representation (D1/D2) is exercised here by calling
    // `serve` directly with an explicit `actor`.

    use metrics_exporter_prometheus::PrometheusBuilder;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_http_core::test_support::build_mock_ctx;

    fn run<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn oci_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r
    }

    /// Repo-level read denial (D1/D2, ADR 0021): an anonymous tags-list on
    /// a denied repo is challenged with 401 + the mode-aware
    /// `WWW-Authenticate` in BOTH signing-key states; an
    /// authenticated-but-unauthorized caller keeps the `NAME_UNKNOWN` 404
    /// anti-enumeration envelope.
    #[test]
    fn tags_read_denial_challenges_anonymous_and_404s_authenticated() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            // (1) anonymous, signing key UNWIRED → 401 Basic.
            crate::test_authz::assert_basic_challenge(
                &serve(
                    crate::test_authz::denied_ctx(&base, mocks.repositories.clone()),
                    "ghost",
                    "library/nginx",
                    PageQuery::default(),
                    None,
                )
                .await,
            );
            // (2) anonymous, signing key WIRED → 401 Bearer /v2/auth.
            crate::test_authz::assert_bearer_challenge(
                &serve(
                    crate::test_authz::denied_ctx_bearer(&base, mocks.repositories.clone()),
                    "ghost",
                    "library/nginx",
                    PageQuery::default(),
                    None,
                )
                .await,
                r#"scope="repository:ghost/library/nginx:pull""#,
            );
            // (3) authenticated but unauthorized → 404 NAME_UNKNOWN.
            let principal = crate::test_authz::grantless_principal();
            crate::test_authz::assert_name_unknown_404(
                serve(
                    crate::test_authz::denied_ctx(&base, mocks.repositories.clone()),
                    "ghost",
                    "library/nginx",
                    PageQuery::default(),
                    Some(&principal),
                )
                .await,
            )
            .await;
        });
    }

    /// Anti-enumeration equivalence (ADR 0021): anonymous denial for a
    /// NONEXISTENT repo is byte-identical to one for an EXISTING PRIVATE
    /// repo (Basic mode → no `scope=`).
    #[test]
    fn tags_anonymous_denial_uniform_nonexistent_vs_private() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let mut priv_repo = oci_repo("private-repo");
            priv_repo.is_public = false;
            mocks.repositories.insert(priv_repo);
            let ctx = crate::test_authz::denied_ctx(&base, mocks.repositories.clone());
            let nonexistent = serve(
                ctx.clone(),
                "ghost",
                "library/nginx",
                PageQuery::default(),
                None,
            )
            .await;
            let private = serve(
                ctx,
                "private-repo",
                "library/nginx",
                PageQuery::default(),
                None,
            )
            .await;
            assert_eq!(
                crate::test_authz::denial_snapshot(nonexistent).await,
                crate::test_authz::denial_snapshot(private).await,
                "anonymous nonexistent vs existing-private must be byte-identical"
            );
        });
    }
}
