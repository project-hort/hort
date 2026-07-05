//! OCI `_catalog` endpoints.
//!
//! Two distinct handlers share this file:
//!
//! - [`get_repo_catalog`] — `GET /v2/:repo_key/_catalog?n=&last=`.
//!   **Modern default.** Always mounted. Lists distinct manifest names
//!   inside one hort-repository. Names are unqualified (`library/nginx`,
//!   not `myrepo/library/nginx`).
//!
//! - [`get_global_catalog`] — `GET /v2/_catalog?n=&last=`.
//!   **Docker-legacy compat.** Conditionally mounted when
//!   [`super::config::OciHttpConfig::legacy_catalog_enabled`] is
//!   `true`. Aggregates fully-qualified names
//!   (`<repo_key>/<name>`) across every repo the caller can read. The
//!   "Docker repository" concept maps to hort's `<repo_key>/<name>` pair
//!   in this scheme.
//!
//! # Why two separate handlers, not one with a mode switch
//!
//! The modern per-repo endpoint has a `:repo_key` path parameter; the
//! legacy global endpoint doesn't. Their extractors are different —
//! `Path<String>` vs none. A single handler would force one side to
//! route through an unused extractor, so the file is already split at
//! the axum surface. The wire-shape response is the same
//! (`{"repositories":[...]}`) but the names inside differ.
//!
//! # Visibility
//!
//! Per-repo catalog: callers must already be able to read the repo
//! (enforced by a future RBAC check; currently anonymous-pass-through
//! under `AuthContext::Disabled`).
//!
//! Global catalog: the handler enumerates all repos, filters to those
//! the caller can read, and hands the visible-repo list to
//! [`ArtifactGroupUseCase::list_global_catalog`]. Anonymous callers
//! (`principal = None`) and callers under `AuthContext::Disabled` see
//! `is_public = true` repos only. Authenticated callers see public
//! repos plus any repo they have `Permission::Read` on.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::Extension;

use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::types::{PageRequest, StringPage};

use super::tags::PageQuery;
use hort_http_core::context::AppContext;
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

/// OCI `_catalog` JSON envelope — shared across per-repo + global
/// handlers. `repositories` holds unqualified names in the per-repo
/// case and qualified names (`<repo_key>/<name>`) in the global case;
/// the wire type is identical.
#[derive(serde::Serialize)]
struct CatalogEnvelope<'a> {
    repositories: &'a [String],
}

// ---------------------------------------------------------------------------
// Per-repo catalog
// ---------------------------------------------------------------------------

pub async fn get_repo_catalog(
    State(ctx): State<Arc<AppContext>>,
    Path(repo_key): Path<String>,
    Query(query): Query<PageQuery>,
    principal: Option<Extension<Option<AuthenticatedPrincipal>>>,
) -> Response {
    // Visibility-checked repo resolve (ADR 0008).
    // Anti-enumeration: a missing repo and a private-but-invisible
    // repo collapse to the same NAME_UNKNOWN envelope.
    //
    // The `AuthenticatedPrincipal` extension newtype is unwrapped to the
    // inner `CallerPrincipal` for the use-case API.
    let actor = principal
        .and_then(|Extension(p)| p)
        .map(AuthenticatedPrincipal::into_caller);
    let Ok(repo) = ctx
        .repository_access_use_case
        .resolve(&repo_key, actor.as_ref(), AccessLevel::Read)
        .await
    else {
        // Repo-level read denial: 401 + mode-aware challenge for an
        // anonymous caller, NAME_UNKNOWN 404 anti-enumeration for an
        // authenticated one (D1/D2, ADR 0021). `actor` here is an owned
        // `Option<CallerPrincipal>`; borrow it for the shared helper.
        let path = format!("/v2/{repo_key}/_catalog");
        return crate::middleware::oci_auth::read_denied_response(
            &ctx,
            actor.as_ref(),
            &axum::http::Method::GET,
            &path,
            &repo_key,
        );
    };

    let n = query.n.unwrap_or(0);
    let after = query.last.as_deref();

    let page = match ctx
        .artifact_group_use_case
        .list_repo_catalog(repo.id, "manifest", after, n)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                error = %e,
                "repo catalog enumeration failed"
            );
            return internal_error_response();
        }
    };

    respond(&page, |last| format_repo_next_link(&repo_key, n, last))
}

// ---------------------------------------------------------------------------
// Global (legacy) catalog
// ---------------------------------------------------------------------------

pub async fn get_global_catalog(
    State(ctx): State<Arc<AppContext>>,
    Query(query): Query<PageQuery>,
    principal: Option<Extension<Option<AuthenticatedPrincipal>>>,
) -> Response {
    // `Extension<Option<AuthenticatedPrincipal>>` is inserted by the
    // OCI bearer middleware (`oci_bearer_auth`); absent extension →
    // anonymous. The bare `CallerPrincipal` slot is no longer consulted.
    let principal = principal
        .and_then(|Extension(p)| p)
        .map(AuthenticatedPrincipal::into_caller);

    // `RepositoryAccessUseCase::list_visible` (ADR 0008) centralises
    // the visibility predicate. Scale is small (tens of repos per
    // deployment); the use case enumerates with a 1000-row max page
    // and filters in-memory.
    let page = PageRequest::new(0, 1000);
    let visible_repos = match ctx
        .repository_access_use_case
        .list_visible(principal.as_ref(), page)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                error = %e,
                "visible-repo enumeration for global catalog failed"
            );
            return internal_error_response();
        }
    };
    let visible: Vec<(uuid::Uuid, String)> = visible_repos
        .items
        .into_iter()
        .map(|r| (r.id, r.key))
        .collect();

    let n = query.n.unwrap_or(0);
    let after = query.last.as_deref();

    let page = match ctx
        .artifact_group_use_case
        .list_global_catalog(&visible, "manifest", after, n)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                error = %e,
                "global catalog enumeration failed"
            );
            return internal_error_response();
        }
    };

    respond(&page, |last| format_global_next_link(n, last))
}

// ---------------------------------------------------------------------------
// Shared response shape
// ---------------------------------------------------------------------------

fn respond(page: &StringPage<String>, build_link: impl Fn(&str) -> String) -> Response {
    let envelope = CatalogEnvelope {
        repositories: &page.items,
    };
    let body_bytes = serde_json::to_vec(&envelope).expect("static-shape JSON serialises");

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json");

    if page.saturated {
        if let Some(last) = page.items.last() {
            let link = build_link(last);
            if let Ok(v) = HeaderValue::from_str(&link) {
                builder = builder.header("Link", v);
            }
        }
    }

    builder.body(Body::from(body_bytes)).unwrap()
}

fn format_repo_next_link(repo_key: &str, n: u32, last: &str) -> String {
    let last_enc = urlencoding::encode(last);
    if n == 0 {
        format!("</v2/{repo_key}/_catalog?last={last_enc}>; rel=\"next\"")
    } else {
        format!("</v2/{repo_key}/_catalog?n={n}&last={last_enc}>; rel=\"next\"")
    }
}

fn format_global_next_link(n: u32, last: &str) -> String {
    let last_enc = urlencoding::encode(last);
    if n == 0 {
        format!("</v2/_catalog?last={last_enc}>; rel=\"next\"")
    } else {
        format!("</v2/_catalog?n={n}&last={last_enc}>; rel=\"next\"")
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

    use metrics_exporter_prometheus::PrometheusBuilder;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_http_core::middleware::auth::test_support::authenticated_principal;
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

    /// Per-repo `_catalog` read denial (D1/D2, ADR 0021): anonymous →
    /// 401 + mode-aware challenge (Basic when the signing key is unwired,
    /// Bearer `/v2/auth` when wired); authenticated-but-unauthorized →
    /// `NAME_UNKNOWN` 404. The per-repo catalog path has no canonical
    /// `scope=` (advisory, per the design), so the Bearer branch is
    /// asserted on realm + API-version only.
    #[test]
    fn repo_catalog_read_denial_challenges_anonymous_and_404s_authenticated() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);

            // (1) anonymous, signing key UNWIRED → 401 Basic.
            let ctx = crate::test_authz::denied_ctx(&base, mocks.repositories.clone());
            let resp = get_repo_catalog(
                State(ctx),
                Path("ghost".to_string()),
                Query(PageQuery::default()),
                None,
            )
            .await;
            crate::test_authz::assert_basic_challenge(&resp);

            // (2) anonymous, signing key WIRED → 401 Bearer /v2/auth.
            let ctx = crate::test_authz::denied_ctx_bearer(&base, mocks.repositories.clone());
            let resp = get_repo_catalog(
                State(ctx),
                Path("ghost".to_string()),
                Query(PageQuery::default()),
                None,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let www = resp
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap();
            assert!(www.starts_with("Bearer "), "{www}");
            assert!(
                www.contains(r#"realm="https://registry.example.com/v2/auth""#),
                "{www}"
            );
            assert_eq!(
                resp.headers()
                    .get("docker-distribution-api-version")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "registry/2.0"
            );

            // (3) authenticated but unauthorized → 404 NAME_UNKNOWN.
            let ctx = crate::test_authz::denied_ctx(&base, mocks.repositories.clone());
            let principal = authenticated_principal(crate::test_authz::grantless_principal());
            let resp = get_repo_catalog(
                State(ctx),
                Path("ghost".to_string()),
                Query(PageQuery::default()),
                Some(Extension(Some(principal))),
            )
            .await;
            crate::test_authz::assert_name_unknown_404(resp).await;
        });
    }

    /// Anti-enumeration equivalence (ADR 0021): anonymous denial for a
    /// NONEXISTENT repo is byte-identical to one for an EXISTING PRIVATE
    /// repo (Basic mode → no `scope=`).
    #[test]
    fn repo_catalog_anonymous_denial_uniform_nonexistent_vs_private() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let mut priv_repo = oci_repo("private-repo");
            priv_repo.is_public = false;
            mocks.repositories.insert(priv_repo);
            let ctx = crate::test_authz::denied_ctx(&base, mocks.repositories.clone());

            let nonexistent = get_repo_catalog(
                State(ctx.clone()),
                Path("ghost".to_string()),
                Query(PageQuery::default()),
                None,
            )
            .await;
            let private = get_repo_catalog(
                State(ctx),
                Path("private-repo".to_string()),
                Query(PageQuery::default()),
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

    #[test]
    fn repo_link_with_n_includes_n_param() {
        let l = format_repo_next_link("myrepo", 10, "library/nginx");
        assert!(l.contains("n=10"));
        assert!(l.contains("last=library%2Fnginx"));
    }

    #[test]
    fn repo_link_without_n_omits_n_param() {
        let l = format_repo_next_link("myrepo", 0, "nginx");
        assert_eq!(l, "</v2/myrepo/_catalog?last=nginx>; rel=\"next\"");
    }

    #[test]
    fn global_link_with_n() {
        let l = format_global_next_link(5, "mirror/alpine");
        assert!(l.contains("n=5"));
        assert!(l.contains("last=mirror%2Falpine"));
    }

    #[test]
    fn global_link_without_n() {
        let l = format_global_next_link(0, "a/b");
        assert_eq!(l, "</v2/_catalog?last=a%2Fb>; rel=\"next\"");
    }
}
