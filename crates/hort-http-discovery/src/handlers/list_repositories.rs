//! `GET /api/v1/repositories` — repositories visible to the caller.
//!
//! Read-endpoint pattern (ADR 0013): GET routes through
//! `extract_optional_principal`; visibility is enforced by
//! `RepositoryAccessUseCase::list_visible` (`can_see`), so an anonymous
//! caller sees only public repos. No new auth mechanism, no new outbound
//! port, no domain change, no metric.
//!
//! No pagination: a Hort deployment holds a small number of repositories
//! (tens, not thousands — RBAC and proxy/virtual fan-out are per-repo, not
//! per-package), so the listing returns all visible repositories under a
//! single fixed bound. See the design note in the shell-completions spec.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Serialize;

use hort_domain::types::PageRequest;
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Upper bound on repositories returned in a single listing. A Hort
/// deployment is not expected to approach this; it exists only to keep the
/// query bounded.
const MAX_REPOSITORIES: u64 = 1000;

/// Single-repository summary returned in the list.
#[derive(Debug, Serialize)]
pub struct RepoSummaryDto {
    pub key: String,
    pub format: String,
    pub kind: String,
}

/// Top-level response envelope.
///
/// Deliberately carries no `total` field. The listing is unpaginated (it
/// returns every visible repository under one fixed bound), so a count would
/// be exactly `repositories.len()` — and sourcing it from the use case's
/// `Page::total` would leak the *unfiltered* repository count (private repos
/// included) to anonymous callers, defeating the anti-enumeration property
/// the visibility filter exists to provide.
#[derive(Debug, Serialize)]
pub struct RepositoriesListDto {
    pub repositories: Vec<RepoSummaryDto>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /repositories` — list repositories visible to the (optional) caller.
///
/// Anonymous callers see only public repositories. Authenticated callers see
/// public repositories plus any private repository for which they hold at
/// least `Permission::Read` (enforced inside `list_visible` via `can_see`).
pub async fn list_repositories(
    State(ctx): State<Arc<AppContext>>,
    Extension(principal): Extension<Option<AuthenticatedPrincipal>>,
) -> Result<(StatusCode, Json<RepositoriesListDto>), ApiError> {
    let page = PageRequest::new(0, MAX_REPOSITORIES);
    // `as_caller()` returns `&CallerPrincipal`; `list_visible` takes
    // `Option<&CallerPrincipal>`. Mirror the borrow shape from
    // `list_versions.rs` (same crate, same pattern).
    let caller = principal.as_ref().map(AuthenticatedPrincipal::as_caller);
    let visible = ctx
        .repository_access_use_case
        .list_visible(caller, page)
        .await?;
    let dto = RepositoriesListDto {
        repositories: visible
            .items
            .into_iter()
            .map(|r| RepoSummaryDto {
                key: r.key,
                format: r.format.to_string(),
                kind: r.repo_type.to_string(),
            })
            .collect(),
    };
    Ok((StatusCode::OK, Json(dto)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use axum::body::to_bytes;
    use axum::http::{Method, Request, StatusCode};
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::api_token::TokenKind;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_http_core::middleware::auth::test_support as auth_test;
    use hort_http_core::test_support::{build_mock_ctx, with_repository_access};

    // ----- fixtures ---------------------------------------------------------

    fn public_repo(key: &str) -> hort_domain::entities::repository::Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.is_public = true;
        r
    }

    fn private_repo(key: &str) -> hort_domain::entities::repository::Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.is_public = false;
        r
    }

    fn rbac_with_read_on(repo_id: Uuid) -> RbacEvaluator {
        RbacEvaluator::new(vec![PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["reader".to_string()]),
            repository_id: Some(repo_id),
            permission: Permission::Read,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }])
    }

    fn caller_reader() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: vec!["reader".to_string()],
            token_kind: Some(TokenKind::CliSession),
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ----- tests ------------------------------------------------------------

    /// Anonymous callers (no Authorization header) see only public
    /// repositories; private repos are invisible (anti-enumeration).
    ///
    /// The test router does not attach the real auth middleware. Instead we
    /// inject `Option<AuthenticatedPrincipal> = None` via
    /// `auth_test::inject_optional_principal_none`, which is exactly the
    /// shape `extract_optional_principal` inserts when no token is present.
    #[tokio::test]
    async fn anonymous_sees_only_public_repos() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (base_ctx, mocks) = build_mock_ctx(handle);

        mocks.repositories.insert(public_repo("npm-public"));
        mocks.repositories.insert(private_repo("cargo-private"));

        // Rebuild with an RBAC-Enabled (empty) evaluator so that
        // `list_visible` enforces `is_public` for anonymous callers rather
        // than admitting everything (RbacAccess::Disabled admits all).
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(
                Vec::new(),
            )))),
            true,
        ));
        let ctx = with_repository_access(&base_ctx, access);

        let router = axum::Router::new()
            .nest("/api/v1", crate::routes())
            .with_state(ctx);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/repositories")
            .body(axum::body::Body::empty())
            .expect("request build");
        // Inject `None` — same shape `extract_optional_principal` writes
        // when no token is present (anonymous request).
        auth_test::inject_optional_principal_none(&mut req);

        let resp = router.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let repos = body["repositories"].as_array().expect("repositories array");
        let keys: Vec<&str> = repos
            .iter()
            .map(|r| r["key"].as_str().expect("key"))
            .collect();
        assert!(
            keys.contains(&"npm-public"),
            "public repo must appear; got {keys:?}"
        );
        assert!(
            !keys.contains(&"cargo-private"),
            "private repo must be hidden from anonymous; got {keys:?}"
        );
        // Exactly one repo is returned — and the envelope carries no separate
        // count, so the private repo cannot leak via a `total` field either.
        assert_eq!(
            keys.len(),
            1,
            "only the public repo is visible; got {keys:?}"
        );
        assert!(
            body.get("total").is_none(),
            "response must not expose a repository count; got {body}"
        );
    }

    /// An authenticated caller that holds `Permission::Read` on a private
    /// repository can see it in the listing.
    ///
    /// Uses `auth_test::inject_optional_principal_some` — the exact shape
    /// `extract_optional_principal` inserts when a valid token is present.
    #[tokio::test]
    async fn authed_with_read_grant_sees_private_repo() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (base_ctx, mocks) = build_mock_ctx(handle);

        mocks.repositories.insert(public_repo("npm-public"));
        let priv_repo = private_repo("cargo-private");
        let priv_id = priv_repo.id;
        mocks.repositories.insert(priv_repo);

        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(rbac_with_read_on(priv_id)))),
            true,
        ));
        let ctx = with_repository_access(&base_ctx, access);

        let router = axum::Router::new()
            .nest("/api/v1", crate::routes())
            .with_state(ctx);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/repositories")
            .body(axum::body::Body::empty())
            .expect("request build");
        // Inject `Some(alice)` — same shape `extract_optional_principal`
        // writes when a valid token bearing the "reader" claim is present.
        auth_test::inject_optional_principal_some(&mut req, caller_reader());

        let resp = router.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let repos = body["repositories"].as_array().expect("repositories array");
        let keys: Vec<&str> = repos
            .iter()
            .map(|r| r["key"].as_str().expect("key"))
            .collect();
        assert!(
            keys.contains(&"npm-public"),
            "public repo must appear; got {keys:?}"
        );
        assert!(
            keys.contains(&"cargo-private"),
            "private repo must be visible to caller with Read grant; got {keys:?}"
        );
        // Both repos visible to this caller, no more, no count field.
        assert_eq!(
            keys.len(),
            2,
            "public + granted-private are visible; got {keys:?}"
        );
        assert!(
            body.get("total").is_none(),
            "response must not expose a repository count; got {body}"
        );
    }
}
