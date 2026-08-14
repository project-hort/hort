//! `POST /api/v1/admin/curation/quarantine/:artifact_id/reevaluate`.
//!
//! Curator-invoked recompute of a `Rejected` artifact's verdict from its
//! stored findings under the currently active policy — no policy
//! mutation, no forced outcome. Mirrors the shape of
//! `POST /admin/curation/quarantine/:artifact_id/waive`: the
//! [`CurateOrAdminPrincipal`] gate, and `ArtifactReEvaluated` +
//! companion-event curator attribution via the append envelope's
//! `actor` (`Actor::Api`), rather than a payload field — the same
//! mechanism `waive`'s `ArtifactReleased` uses.
//!
//! No request body — this endpoint recomputes from stored evidence, it
//! does not accept an operator-supplied override or justification (that
//! is `waive` / `block`'s surface).
//!
//! Source-state guard is `Rejected` ONLY: every other state is a
//! caller-reachable precondition failure (ADR 0025), not a policy
//! mutation attempt.
//!
//! Status-code mapping:
//! - `200 OK` — a verdict was computed (including `StillRejected`,
//!   whether from the domain derivation, an ineligible rejection
//!   reason, or a cross-axis release-clearance hold — all are
//!   successful, idempotent outcomes, not errors), body is
//!   [`ReevaluateOutcomeDto`]
//! - `403 Forbidden` — principal lacks both `Permission::Curate` AND
//!   `Permission::Admin`
//! - `404 Not Found` — `artifact_id` does not resolve
//! - `409 Conflict` — source-state guard (non-`Rejected` artifact) via
//!   `DomainError::InvalidState`, OR an event-store optimistic-
//!   concurrency conflict
//! - `500 Internal Server Error` — no `ScanCompleted` evidence on the
//!   artifact's stream, or an infrastructure failure

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use uuid::Uuid;

use hort_app::use_cases::curation_use_case::ReevaluateOutcome;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::events::ApiActor;
use hort_domain::policy::ReEvaluationOutcome;

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

/// Response DTO for `POST /api/v1/admin/curation/quarantine/:artifact_id/reevaluate`.
///
/// `outcome` projects [`ReEvaluationOutcome`] as its wire string
/// (`still_rejected` | `reset_to_quarantined` | `reset_to_released`);
/// `previous_status` / `new_status` project [`QuarantineStatus`]'s
/// `Display` (mirrors [`super::queue::CurationQueueEntryDto`]).
#[derive(Debug, Serialize)]
pub struct ReevaluateOutcomeDto {
    pub outcome: &'static str,
    pub previous_status: String,
    pub new_status: String,
}

impl ReevaluateOutcomeDto {
    fn from_domain(outcome: ReevaluateOutcome) -> Self {
        let outcome_str = match outcome.outcome {
            ReEvaluationOutcome::StillRejected => "still_rejected",
            ReEvaluationOutcome::ResetToQuarantined => "reset_to_quarantined",
            ReEvaluationOutcome::ResetToReleased => "reset_to_released",
        };
        Self {
            outcome: outcome_str,
            previous_status: outcome.previous_status.to_string(),
            new_status: outcome.new_status.to_string(),
        }
    }
}

/// `POST /api/v1/admin/curation/quarantine/:artifact_id/reevaluate`.
///
/// See module docs for the full status-code map. Builds the
/// [`CallerPrivileges`] from the [`CurateOrAdminPrincipal`] payload
/// (`is_curator = true` is sufficient — the extractor already proved
/// the caller carries Curate OR Admin) and delegates to
/// `CurationUseCase::reevaluate`.
///
/// **`#[tracing::instrument]` deliberately WITHOUT `err`** — denial /
/// guard outcomes are info-level events (architect rule); promoting
/// them to `err` would surface every 4xx as ERROR in operator logs.
#[tracing::instrument(skip(ctx, principal))]
pub async fn post_reevaluate(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Response, ApiError> {
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
        .reevaluate(artifact_id, actor, privileges)
        .await?;

    Ok((
        StatusCode::OK,
        axum::Json(ReevaluateOutcomeDto::from_domain(outcome)),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    //! Handler-layer assertions for each status code. Tests use
    //! [`build_mock_ctx`] (mock harness from `test_support`) — the
    //! architect anti-pattern forbids hand-rolling `AppContext` here.

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
        persisted_artifact_rejected, persisted_scan_completed, sample_artifact, sample_repository,
        MockIdentityProvider,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::events::{RejectionReason, StreamId};
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
                "/api/v1/admin/curation/quarantine/{artifact_id}/reevaluate",
                post(post_reevaluate),
            )
            .with_state(ctx);
        (router, mocks)
    }

    fn reevaluate_post(artifact_id: Uuid, p: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post(format!(
            "/api/v1/admin/curation/quarantine/{artifact_id}/reevaluate"
        ))
        .body(Body::empty())
        .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// Seed a `Rejected` artifact whose stream carries a scan-clearable
    /// rejection followed by a `ScanCompleted` with `critical` findings
    /// (and no policy, so the default `block_on_critical` threshold
    /// applies and no per-finding blob is resolvable in this harness).
    fn seed_rejected_with_scan(mocks: &MockPorts, critical: u32) -> Uuid {
        let artifact = sample_artifact(QuarantineStatus::Rejected);
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        mocks.events.set_stream(
            &stream_id,
            vec![
                persisted_artifact_rejected(artifact_id, RejectionReason::Scanner, 0),
                persisted_scan_completed(artifact_id, critical, 1),
            ],
        );
        mocks.artifacts.insert(artifact);
        mocks.repositories.insert(repo);
        artifact_id
    }

    /// Happy path: a clean scan with no active policy resolves to
    /// `ResetToReleased` → 200 with the rendered outcome envelope, and
    /// the lifecycle mock records one curator-attributed transition.
    #[tokio::test]
    async fn reevaluate_clean_scan_returns_200_reset_to_released() {
        let (router, mocks) = harness();
        let artifact_id = seed_rejected_with_scan(&mocks, 0);
        let principal = principal_with_claims(&["curate"]);

        let resp = router
            .oneshot(reevaluate_post(artifact_id, Some(principal)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["outcome"], "reset_to_released");
        assert_eq!(body["previous_status"], "rejected");
        assert_eq!(body["new_status"], "released");

        let transitions = mocks.lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1, "exactly one transition committed");
    }

    /// A still-blocking finding → 200 with `still_rejected`, no commit.
    #[tokio::test]
    async fn reevaluate_still_blocking_returns_200_still_rejected() {
        let (router, mocks) = harness();
        let artifact_id = seed_rejected_with_scan(&mocks, 1);

        let resp = router
            .oneshot(reevaluate_post(
                artifact_id,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["outcome"], "still_rejected");
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Admin caller (no explicit Curate grant) is ALSO accepted by the
    /// curator-or-admin gate.
    #[tokio::test]
    async fn reevaluate_admin_caller_also_returns_200() {
        let (router, mocks) = harness();
        let artifact_id = seed_rejected_with_scan(&mocks, 0);

        let resp = router
            .oneshot(reevaluate_post(
                artifact_id,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Caller carrying neither `curate` nor `admin` claim → 403 via the
    /// `CurateOrAdminPrincipal` extractor short-circuit. Use case is
    /// never reached.
    #[tokio::test]
    async fn reevaluate_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let artifact_id = seed_rejected_with_scan(&mocks, 0);
        let resp = router
            .oneshot(reevaluate_post(
                artifact_id,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], br#"{"error":"insufficient permissions"}"#);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Bogus artifact_id (no seeded artifact) → 404 NOT FOUND surfaced
    /// from the use case's `find_by_id` miss.
    #[tokio::test]
    async fn reevaluate_unknown_artifact_returns_404() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(reevaluate_post(
                Uuid::new_v4(),
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Source-state guard: a non-`Rejected` artifact → 409 CONFLICT with
    /// the actionable message (ADR 0025), not an opaque 500.
    #[tokio::test]
    async fn reevaluate_non_rejected_artifact_returns_409_invalid_state() {
        let (router, mocks) = harness();
        let artifact = sample_artifact(QuarantineStatus::Quarantined);
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let id = artifact.id;
        mocks.artifacts.insert(artifact);
        mocks.repositories.insert(repo);

        let resp = router
            .oneshot(reevaluate_post(
                id,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let body_str = String::from_utf8_lossy(&bytes);
        assert!(
            body_str.contains("cannot re-evaluate artifact in state"),
            "409 body should carry the state-precondition message, got: {body_str}"
        );
    }

    /// No `ScanCompleted` evidence on the artifact's stream → 500 (no
    /// internal-detail leakage — the opaque-5xx contract).
    #[tokio::test]
    async fn reevaluate_no_scan_completed_returns_500() {
        let (router, mocks) = harness();
        let artifact = sample_artifact(QuarantineStatus::Rejected);
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let artifact_id = artifact.id;
        let stream_id = StreamId::artifact(artifact_id);
        mocks.events.set_stream(
            &stream_id,
            vec![persisted_artifact_rejected(
                artifact_id,
                RejectionReason::Scanner,
                0,
            )],
        );
        mocks.artifacts.insert(artifact);
        mocks.repositories.insert(repo);

        let resp = router
            .oneshot(reevaluate_post(
                artifact_id,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        crate::error::assert_no_internal_leakage(StatusCode::INTERNAL_SERVER_ERROR, &bytes);
    }

    /// Idempotence: re-invoking on a `StillRejected` artifact returns the
    /// outcome envelope again, no repeated events.
    #[tokio::test]
    async fn reevaluate_idempotent_re_invoke_returns_200_again() {
        let (router, mocks) = harness();
        let artifact_id = seed_rejected_with_scan(&mocks, 1);

        for _ in 0..2 {
            let resp = router
                .clone()
                .oneshot(reevaluate_post(
                    artifact_id,
                    Some(principal_with_claims(&["curate"])),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["outcome"], "still_rejected");
        }
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }
}
