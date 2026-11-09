//! `POST /api/v1/admin/curation/block-digests`.
//!
//! Bulk curator block addressed by content digest — the symmetric
//! sibling of `block-versions`, for OCI and every other format where
//! `artifacts.version` is `NULL` by construction and the bytes are the
//! only writable address. Wraps the
//! [`BlockTarget::DigestList`] arm of `CurationUseCase::block`, through
//! the same resolver `waive-digests` uses.
//!
//! **`block-versions`' contract is inherited unchanged**: continue-on-
//! error, the [`MAX_VERSIONS_PER_CALL`] cap, `200 OK` with the full
//! [`BlockOutcomeDto`] on any non-validation outcome, and
//! `not_found_digests` playing `not_found_versions`' part for digests
//! that match no live row. Blocking does not auto-block a future ingest
//! of those bytes.
//!
//! One case is **not** continue-on-error, and it is the one this route
//! shares with its waive sibling: a digest that matches more than one
//! live row in the repository is refused with `400`, naming the
//! candidate artifact ids, before the first append. Identical bytes can
//! be ingested at several paths, and which of those rows the curator
//! reviewed is not something the server may guess — while
//! `not_found_digests` would say the opposite of what happened, since
//! the bytes *were* found.
//!
//! Status-code mapping:
//! - `200 OK` with the full [`BlockOutcomeDto`] body on any
//!   non-validation outcome, partial success included
//! - `400 Bad Request` — empty / oversize justification; `digests` empty
//!   or over the cap; a digest that is not a bare 64-hex SHA-256 or a
//!   `sha256:`-prefixed one; a digest matching more than one live row
//! - `403 Forbidden` — principal lacks both Curate and Admin
//! - `404 Not Found` — the `repository` key does not resolve
//! - `500 Internal Server Error` — infrastructure failure on the
//!   repository-key resolution or the resolver itself

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use hort_app::use_cases::curation_use_case::BlockTarget;
use hort_domain::events::ApiActor;

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::block_versions::BlockOutcomeDto;
use super::{check_entry_count, check_justification, curator_privileges, MAX_VERSIONS_PER_CALL};

/// Request DTO for `POST /api/v1/admin/curation/block-digests`.
///
/// `repository` is the operator-facing **stable key**; a miss is a 404.
/// Each entry of `digests` is a bare 64-lowercase-hex SHA-256 or the same
/// value carrying a `sha256:` prefix — the two spellings are one address.
///
/// No `package` field: a digest is repository-scoped and names its bytes
/// outright, so the package the bytes happen to sit under is not part of
/// the address. And no `tags` field — a tag is a mutable pointer, and a
/// curation decision binds to the bytes that were reviewed.
#[derive(Debug, Deserialize)]
pub struct BlockDigestsRequestDto {
    repository: String,
    digests: Vec<String>,
    justification: String,
}

/// `POST /api/v1/admin/curation/block-digests`. See module docs.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn post_block_digests(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<BlockDigestsRequestDto>,
) -> Result<Response, ApiError> {
    // Boundary checks fire BEFORE the repository-key resolution so a
    // malformed body never spends a DB round-trip. The use case
    // re-checks every one of them.
    check_justification(&body.justification)?;
    check_entry_count("digests", body.digests.len(), MAX_VERSIONS_PER_CALL)?;

    let repository_id = ctx
        .repository_use_case
        .get_by_key(&body.repository)
        .await?
        .id;

    let outcome = ctx
        .curation_use_case
        .block(
            BlockTarget::DigestList {
                repository_id,
                digests: body.digests,
            },
            ApiActor {
                user_id: principal.0.user_id,
            },
            curator_privileges(),
            body.justification,
        )
        .await?;

    Ok((StatusCode::OK, Json(BlockOutcomeDto::from_domain(outcome))).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{
        dummy_persisted_event, sample_artifact, sample_repository, MockIdentityProvider,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::events::StreamId;
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_MISSING: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const REPO_KEY: &str = "curate-target";
    const ROUTE: &str = "/api/v1/admin/curation/block-digests";

    fn principal_with_claims(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "curator".into(),
            email: "curator@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn harness() -> (Router, MockPorts) {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics);
        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
            PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec!["curate".into()]),
                repository_id: None,
                permission: Permission::Curate,
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
                created_at: Utc::now(),
            },
        ])));
        let ctx = with_auth(
            &base,
            AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new()
            .nest("/api/v1/admin/curation", super::super::curation_routes())
            .with_state(ctx);
        (router, mocks)
    }

    fn post_json(body: &str, p: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post(ROUTE)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn seed_repo(mocks: &MockPorts) -> Uuid {
        let mut repo = sample_repository();
        repo.key = REPO_KEY.into();
        let repo_id = repo.id;
        mocks.repositories.insert(repo);
        repo_id
    }

    fn seed_digest(mocks: &MockPorts, repo_id: Uuid, digest: &str, path: &str) -> Uuid {
        let mut a = sample_artifact(QuarantineStatus::Quarantined);
        a.repository_id = repo_id;
        a.sha256_checksum = digest.parse().expect("64 lowercase hex");
        a.path = path.into();
        a.version = None;
        let id = a.id;
        let stream_id = StreamId::artifact(id);
        mocks
            .events
            .set_stream(&stream_id, vec![dummy_persisted_event(&stream_id, id, 0)]);
        mocks.artifacts.insert(a);
        id
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Happy path at the real route: 200, the block envelope, and
    /// `not_found_digests` carrying the entry nothing matched — echoed
    /// as the caller wrote it.
    #[tokio::test]
    async fn block_digests_happy_path_returns_200_with_the_digest_partition() {
        let (router, mocks) = harness();
        let repo_id = seed_repo(&mocks);
        let blocked = seed_digest(&mocks, repo_id, DIGEST_A, "blobs/a");

        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["sha256:{DIGEST_A}","{DIGEST_MISSING}"],"justification":"malware"}}"#
        );
        let resp = router
            .oneshot(post_json(
                body.as_str(),
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["blocked_artifact_ids"][0], blocked.to_string());
        assert_eq!(v["not_found_digests"][0], DIGEST_MISSING);
        assert!(v["not_found_versions"].as_array().unwrap().is_empty());
        assert!(v["failed"].as_array().unwrap().is_empty());
    }

    /// An ambiguous digest is a 400 naming the candidate rows, and
    /// nothing is blocked — the one case this route does not continue on.
    #[tokio::test]
    async fn block_digests_ambiguous_digest_returns_400_with_nothing_blocked() {
        let (router, mocks) = harness();
        let repo_id = seed_repo(&mocks);
        let twin_one = seed_digest(&mocks, repo_id, DIGEST_A, "blobs/a1");
        let twin_two = seed_digest(&mocks, repo_id, DIGEST_A, "blobs/a2");

        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"justification":"malware"}}"#
        );
        let resp = router
            .oneshot(post_json(
                body.as_str(),
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_json(resp).await;
        let message = v["error"].as_str().unwrap();
        assert!(message.contains(&twin_one.to_string()), "got: {message}");
        assert!(message.contains(&twin_two.to_string()), "got: {message}");
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// The boundary checks: empty list, over the 100-entry block cap,
    /// and the justification gate.
    #[tokio::test]
    async fn block_digests_boundary_failures_return_400() {
        let (router, mocks) = harness();
        seed_repo(&mocks);
        let oversize_list: Vec<String> = (0..=MAX_VERSIONS_PER_CALL)
            .map(|n| format!("\"{n:064x}\""))
            .collect();
        let oversize_justification = "x".repeat(513);
        for body in [
            format!(r#"{{"repository":"{REPO_KEY}","digests":[],"justification":"v"}}"#),
            format!(
                r#"{{"repository":"{REPO_KEY}","digests":[{}],"justification":"v"}}"#,
                oversize_list.join(",")
            ),
            format!(r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"justification":""}}"#),
            format!(
                r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"justification":"{oversize_justification}"}}"#
            ),
            format!(
                r#"{{"repository":"{REPO_KEY}","digests":["not-a-digest"],"justification":"v"}}"#
            ),
        ] {
            let resp = router
                .clone()
                .oneshot(post_json(
                    body.as_str(),
                    Some(principal_with_claims(&["curate"])),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "for body {body}");
        }
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Unknown repository key → 404; unprivileged caller → 403.
    #[tokio::test]
    async fn block_digests_unknown_repository_404_and_unprivileged_403() {
        let (router, mocks) = harness();
        seed_repo(&mocks);
        let body = format!(
            r#"{{"repository":"no-such-repo","digests":["{DIGEST_A}"],"justification":"v"}}"#
        );
        let resp = router
            .clone()
            .oneshot(post_json(
                body.as_str(),
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"justification":"v"}}"#
        );
        let resp = router
            .oneshot(post_json(
                body.as_str(),
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }
}
