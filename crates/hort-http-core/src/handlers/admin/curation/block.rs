//! `POST /api/v1/admin/curation/quarantine/:artifact_id/block`.
//!
//! Single-artifact curator block. The use case's [`BlockTarget::Artifact`]
//! arm pre-flights `find_by_id(artifact_id)` so an unknown id surfaces as
//! a top-level `Err(NotFound)` rather than landing in the
//! `outcome.failed` list — matching `waive`'s shape (per Item 5 amend).
//! The HTTP layer therefore maps a miss to **404**, not to 200 with
//! a failed-entry envelope.
//!
//! Status-code mapping (design §3 acceptance):
//! - `200 OK` with a trivial [`BlockOutcomeDto`] body — at most one of
//!   `blocked_artifact_ids` / `already_rejected_ids` / `failed` has
//!   a single entry; the others are empty
//! - `400 Bad Request` — empty / oversize justification (defence-in-depth
//!   at the handler boundary)
//! - `403 Forbidden` — principal lacks both Curate AND Admin
//! - `404 Not Found` — `artifact_id` does not resolve
//! - `409 Conflict` — `DomainError::Conflict` propagated from the
//!   event-store optimistic-concurrency check
//! - `500 Internal Server Error` — infrastructure failure

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::curation_use_case::BlockTarget;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::block_versions::BlockOutcomeDto;
use super::MAX_JUSTIFICATION_BYTES;

/// Request DTO for `POST /api/v1/admin/curation/quarantine/:artifact_id/block`.
///
/// `justification` is operator-supplied free text recorded in every
/// emitted `ArtifactRejected` event (one per attempted append for a
/// version-list target; one for the single-artifact target). MUST be
/// non-empty and ≤ 512 bytes — enforced at the boundary so the use
/// case never sees invalid input.
#[derive(Debug, Deserialize)]
pub struct BlockRequestDto {
    justification: String,
}

/// `POST /api/v1/admin/curation/quarantine/:artifact_id/block`.
///
/// See module docs for the full status-code map. Wraps the
/// [`BlockTarget::Artifact`] arm of [`CurationUseCase::block`] —
/// single-artifact target. The use case pre-flights `find_by_id`
/// (per Item 5 amend) so a stale id is a 404, NOT an envelope entry.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn post_block(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(artifact_id): Path<Uuid>,
    Json(body): Json<BlockRequestDto>,
) -> Result<Response, ApiError> {
    // Defence-in-depth justification cap. Use case re-checks via
    // `validate_justification`.
    let trimmed = body.justification.trim();
    if trimmed.is_empty() {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            "justification must not be empty".into(),
        ))));
    }
    if body.justification.len() > MAX_JUSTIFICATION_BYTES {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "justification exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
                body.justification.len()
            ),
        ))));
    }

    let actor = ApiActor {
        user_id: principal.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    };

    let outcome = ctx
        .curation_use_case
        .block(
            BlockTarget::Artifact(artifact_id),
            actor,
            privileges,
            body.justification,
        )
        .await?;

    // For single-artifact target, AT MOST one of the three lists has a
    // single entry. The DTO renders the trivial envelope verbatim
    // (operator tooling parses the same shape for both single and bulk
    // calls).
    Ok((StatusCode::OK, Json(BlockOutcomeDto::from_domain(outcome))).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockIdentityProvider,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

    fn curate_claim_grant() -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["curate".into()]),
            repository_id: None,
            permission: Permission::Curate,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

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
            curate_claim_grant(),
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
            .route(
                "/api/v1/admin/curation/quarantine/:artifact_id/block",
                post(post_block),
            )
            .with_state(ctx);
        (router, mocks)
    }

    fn block_post(artifact_id: Uuid, body: &str, p: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post(format!(
            "/api/v1/admin/curation/quarantine/{artifact_id}/block"
        ))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn seed_quarantined(mocks: &MockPorts) -> Uuid {
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let id = artifact.id;
        mocks.artifacts.insert(artifact);
        mocks.repositories.insert(repo);
        id
    }

    /// Happy path: curator + quarantined artifact → 200 with a trivial
    /// `BlockOutcome` (exactly one `blocked_artifact_ids` entry) and one
    /// `ArtifactRejected` commit on the lifecycle mock.
    #[tokio::test]
    async fn block_happy_path_returns_200_with_blocked_entry() {
        let (router, mocks) = harness();
        let artifact_id = seed_quarantined(&mocks);
        let principal = principal_with_claims(&["curate"]);
        let body = r#"{"justification":"manual block via curator"}"#;

        let resp = router
            .oneshot(block_post(artifact_id, body, Some(principal)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let blocked = v["blocked_artifact_ids"].as_array().unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0], artifact_id.to_string());
        assert!(v["already_rejected_ids"].as_array().unwrap().is_empty());
        assert!(v["not_found_versions"].as_array().unwrap().is_empty());
        assert!(v["failed"].as_array().unwrap().is_empty());

        let transitions = mocks.lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
    }

    /// Already-Rejected artifact → 200 with the trivial envelope
    /// reporting an `already_rejected_ids` entry. No event appended.
    #[tokio::test]
    async fn block_already_rejected_returns_200_with_idempotent_entry() {
        let (router, mocks) = harness();
        let artifact = sample_artifact(QuarantineStatus::Rejected);
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let id = artifact.id;
        mocks.artifacts.insert(artifact);
        mocks.repositories.insert(repo);

        let body = r#"{"justification":"valid"}"#;
        let resp = router
            .oneshot(block_post(
                id,
                body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["blocked_artifact_ids"].as_array().unwrap().is_empty());
        assert_eq!(
            v["already_rejected_ids"].as_array().unwrap()[0],
            id.to_string()
        );
        assert!(
            mocks.lifecycle.committed_transitions().is_empty(),
            "idempotent no-op must not emit an event"
        );
    }

    /// Admin caller (no explicit Curate) also accepted by the gate.
    #[tokio::test]
    async fn block_admin_caller_also_returns_200() {
        let (router, mocks) = harness();
        let id = seed_quarantined(&mocks);
        let body = r#"{"justification":"admin"}"#;
        let resp = router
            .oneshot(block_post(
                id,
                body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Empty justification → 400 at the handler boundary.
    #[tokio::test]
    async fn block_empty_justification_returns_400() {
        let (router, mocks) = harness();
        let id = seed_quarantined(&mocks);
        let body = r#"{"justification":""}"#;
        let resp = router
            .oneshot(block_post(
                id,
                body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Oversize justification → 400.
    #[tokio::test]
    async fn block_oversize_justification_returns_400() {
        let (router, mocks) = harness();
        let id = seed_quarantined(&mocks);
        let oversized = "x".repeat(513);
        let body = format!(r#"{{"justification":"{oversized}"}}"#);
        let resp = router
            .oneshot(block_post(
                id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Reader / unprivileged caller → 403.
    #[tokio::test]
    async fn block_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let id = seed_quarantined(&mocks);
        let body = r#"{"justification":"valid"}"#;
        let resp = router
            .oneshot(block_post(
                id,
                body,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Unknown artifact_id → 404 (single-artifact target preflight per
    /// Item 5 amend; the use case's `find_by_id` miss surfaces top-level
    /// `NotFound`, not an envelope entry).
    #[tokio::test]
    async fn block_unknown_artifact_returns_404() {
        let (router, _mocks) = harness();
        let body = r#"{"justification":"valid"}"#;
        let resp = router
            .oneshot(block_post(
                Uuid::new_v4(),
                body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// 409 / 500 wire-shape pins are covered by the `ApiError` unit
    /// tests in `error.rs`; the handler propagates `?` without
    /// transformation so the mapping is the same. See `waive.rs`'s
    /// equivalent `apierror_unit_tests` pin.
    #[tokio::test]
    async fn block_propagated_conflict_maps_to_409_via_apierror() {
        let api_err = ApiError(AppError::Domain(DomainError::Conflict(
            "stream version mismatch".into(),
        )));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
