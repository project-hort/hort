//! `POST /api/v1/admin/curation/quarantine/:artifact_id/waive`.
//!
//! Curator-driven release of a `Quarantined` artifact. Mirrors the
//! shape of `POST /admin/quarantine/:artifact_id/release`
//! (the admin override) but emits the curator-attributed
//! [`ArtifactReleased`](hort_domain::events::ArtifactReleased) variant
//! (`authority = CuratorWaiver`, `reason = Curator`) rather than the
//! admin variant. Source-state guard is `Quarantined` ONLY (design
//! §2.2 — curator does NOT clear `ScanIndeterminate` artifacts; that
//! authority stays admin-only).
//!
//! Status-code mapping (design §3):
//! - `200 OK` — success
//! - `400 Bad Request` — justification empty / oversize (handler enforces
//!   BEFORE the use-case call as defence-in-depth; use case re-checks),
//!   OR domain-rule validation (source-state mismatch, etc.) propagated
//!   via `AppError::Domain(DomainError::Validation(_))`
//! - `403 Forbidden` — principal lacks both `Permission::Curate` AND
//!   `Permission::Admin` (the [`CurateOrAdminPrincipal`] extractor
//!   short-circuits before the handler body runs)
//! - `404 Not Found` — `artifact_id` does not resolve (the use case's
//!   `find_by_id` returns `DomainError::NotFound`)
//! - `409 Conflict` — event-store optimistic-concurrency conflict
//!   (`DomainError::Conflict`) OR domain-state invariant
//!   (`DomainError::Invariant`) classified as a conflict-at-decision-
//!   time per `classify_append_error`
//! - `500 Internal Server Error` — infrastructure failure (Repository,
//!   Storage, EventStore, etc.)

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::MAX_JUSTIFICATION_BYTES;

/// Request DTO for `POST /api/v1/admin/curation/quarantine/:artifact_id/waive`.
///
/// `justification` is operator-supplied free text recorded in the emitted
/// `ArtifactReleased` event so audit consumers can reconstruct the
/// decision. MUST be non-empty and ≤ 512 bytes — enforced at the boundary
/// so the use case never sees invalid input. The handler-side gate is
/// defence-in-depth; the use-case-side `validate_justification` is the
/// canonical truth (mirror of the domain event validator).
///
/// Domain types (`ApiActor`, `ReleaseAuthorization`, etc.) are NEVER in
/// the request DTO — that's an architect anti-pattern. Only primitive
/// types serde can deserialise from request input.
#[derive(Debug, Deserialize)]
pub struct WaiveRequestDto {
    justification: String,
}

/// `POST /api/v1/admin/curation/quarantine/:artifact_id/waive`.
///
/// See module docs for the full status-code map. The handler validates
/// the justification at the boundary, builds the
/// [`CallerPrivileges`] from the [`CurateOrAdminPrincipal`] payload
/// (`is_curator = true` is sufficient — the extractor already proved
/// the caller carries Curate OR Admin), and delegates to
/// `CurationUseCase::waive`.
///
/// **`#[tracing::instrument]` deliberately WITHOUT `err`** — denial /
/// validation outcomes are info-level events (architect rule); promoting
/// them to `err` would surface every 4xx as ERROR in operator logs.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn post_waive(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(artifact_id): Path<Uuid>,
    Json(body): Json<WaiveRequestDto>,
) -> Result<Response, ApiError> {
    // Defence-in-depth boundary check. The use case also enforces the
    // same cap via `CurationUseCase::validate_justification`; the handler
    // fires first so an oversize body never reaches the application
    // layer. Trim mirrors `admin_release`'s handling — whitespace-only
    // input is the same UX failure as empty.
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

    // `CurateOrAdminPrincipal` already proved either Curate or Admin
    // satisfies the gate. Set `is_curator = true` so the use-case-side
    // `require_curate_or_admin()` is a no-op (defence in depth — the
    // use case is the canonical info-log + metric emission site, so
    // we keep its gate engaged for non-HTTP callers).
    let actor = ApiActor {
        user_id: principal.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    };

    ctx.curation_use_case
        .waive(artifact_id, actor, privileges, body.justification)
        .await?;

    Ok(StatusCode::OK.into_response())
}

#[cfg(test)]
mod tests {
    //! Item 9 acceptance: handler-layer assertions for each status code.
    //! Tests use [`build_mock_ctx`] (mock harness from `test_support`) —
    //! the architect anti-pattern forbids hand-rolling `AppContext` here.
    //!
    //! All tests run under `AuthContext::Enabled` and inject the
    //! principal via the existing `inject_principal` helper (same shape
    //! as `handlers::admin::tests`).

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

    /// Build a `PermissionGrant` that binds the `"curate"` claim to
    /// `Permission::Curate` globally (no repo scope). The tests use a
    /// caller carrying `claims = ["curate"]`; the evaluator's
    /// subset-match (claims ⊇ required) admits the caller for any
    /// `Permission::Curate` query.
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
                "/api/v1/admin/curation/quarantine/:artifact_id/waive",
                post(post_waive),
            )
            .with_state(ctx);
        (router, mocks)
    }

    fn waive_post(artifact_id: Uuid, body: &str, p: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post(format!(
            "/api/v1/admin/curation/quarantine/{artifact_id}/waive"
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

    /// Happy path: curator caller + valid body + quarantined artifact
    /// → 200 OK and the lifecycle mock records a single
    /// `ArtifactReleased(CuratorWaiver)` transition with the curator
    /// attribution.
    #[tokio::test]
    async fn waive_happy_path_returns_200() {
        let (router, mocks) = harness();
        let artifact_id = seed_quarantined(&mocks);
        let principal = principal_with_claims(&["curate"]);
        let curator_user_id = principal.user_id;
        let body = r#"{"justification":"upstream cleared the CVE"}"#;

        let resp = router
            .oneshot(waive_post(artifact_id, body, Some(principal)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let transitions = mocks.lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1, "exactly one transition committed");
        let (_saved, batch, _meta) = &transitions[0];
        match &batch.events[0].event {
            hort_domain::events::DomainEvent::ArtifactReleased(e) => {
                assert_eq!(e.released_by, hort_domain::events::ReleaseReason::Curator);
                assert_eq!(e.released_by_user_id, Some(curator_user_id));
                assert_eq!(e.justification.as_deref(), Some("upstream cleared the CVE"));
            }
            other => panic!("expected ArtifactReleased, got {other:?}"),
        }
    }

    /// Admin caller (no explicit Curate grant) is ALSO accepted by the
    /// curator-or-admin gate. Pins the "either-OR" semantics.
    #[tokio::test]
    async fn waive_admin_caller_also_returns_200() {
        let (router, mocks) = harness();
        let artifact_id = seed_quarantined(&mocks);
        let body = r#"{"justification":"admin override"}"#;

        let resp = router
            .oneshot(waive_post(
                artifact_id,
                body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Empty justification → 400 BAD REQUEST at the handler boundary;
    /// the use case is never reached (the lifecycle mock records no
    /// commit).
    #[tokio::test]
    async fn waive_empty_justification_returns_400() {
        let (router, mocks) = harness();
        let artifact_id = seed_quarantined(&mocks);
        let body = r#"{"justification":""}"#;
        let resp = router
            .oneshot(waive_post(
                artifact_id,
                body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Whitespace-only justification → 400 (same UX as empty).
    #[tokio::test]
    async fn waive_whitespace_justification_returns_400() {
        let (router, mocks) = harness();
        let artifact_id = seed_quarantined(&mocks);
        let body = r#"{"justification":"   \n  "}"#;
        let resp = router
            .oneshot(waive_post(
                artifact_id,
                body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// 513-byte justification → 400 (one over the 512 cap).
    #[tokio::test]
    async fn waive_oversize_justification_returns_400() {
        let (router, mocks) = harness();
        let artifact_id = seed_quarantined(&mocks);
        let oversized = "x".repeat(513);
        let body = format!(r#"{{"justification":"{oversized}"}}"#);
        let resp = router
            .oneshot(waive_post(
                artifact_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Caller carrying neither `curate` nor `admin` claim → 403 via the
    /// `CurateOrAdminPrincipal` extractor short-circuit. Use case is
    /// never reached.
    #[tokio::test]
    async fn waive_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let artifact_id = seed_quarantined(&mocks);
        let body = r#"{"justification":"valid"}"#;
        let resp = router
            .oneshot(waive_post(
                artifact_id,
                body,
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
    async fn waive_unknown_artifact_returns_404() {
        let (router, _mocks) = harness();
        let body = r#"{"justification":"valid"}"#;
        let resp = router
            .oneshot(waive_post(
                Uuid::new_v4(),
                body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// ADR 0025 — waiving a non-`Quarantined` artifact (the curator
    /// source-state guard inside `Artifact::release`) is a caller-reachable
    /// state precondition → **409 Conflict** carrying the real message, NOT
    /// an opaque 500. `DomainError::InvalidState` → 409 (see `error.rs`);
    /// the use case classifies it `conflict` for the metric label via
    /// `classify_append_error`. (Plain `Conflict`/409 still also covers
    /// event-store optimistic-concurrency version conflicts; the two are
    /// disambiguated by the response body, not the status code.)
    #[tokio::test]
    async fn waive_non_quarantined_artifact_returns_409_invalid_state() {
        let (router, mocks) = harness();
        // Seed an artifact already in `None` (released) state — the
        // source-state guard rejects every non-Quarantined.
        let artifact = sample_artifact(QuarantineStatus::None);
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let id = artifact.id;
        mocks.artifacts.insert(artifact);
        mocks.repositories.insert(repo);

        let body = r#"{"justification":"valid"}"#;
        let resp = router
            .oneshot(waive_post(
                id,
                body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        // ADR 0025: wrong-state → 409 with an actionable message, not 500.
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let body_str = String::from_utf8_lossy(&bytes);
        assert!(
            body_str.contains("cannot release artifact in state"),
            "409 body should carry the state-precondition message, got: {body_str}"
        );
    }

    /// Event-store optimistic-concurrency conflict → 409 CONFLICT.
    /// The mock event store has no real conflict mechanism, so we
    /// drive an `EventStore` error via the lifecycle mock to assert
    /// the wire shape.
    ///
    /// The default `MockArtifactLifecycle::commit_transition_with_score`
    /// returns `Ok(())`; to drive a 5xx path here would require a
    /// custom failing port. This test pins the wire-shape mapping for
    /// `DomainError::Conflict` directly via the `ApiError` path — the
    /// inline route handler can't synthesise the conflict otherwise.
    ///
    /// We rely on the `error.rs::tests::conflict_is_409` unit test as
    /// the canonical wire-shape pin for `DomainError::Conflict` → 409;
    /// reproducing it here would duplicate that coverage without
    /// adding handler-specific value. Re-route this assertion to the
    /// `ApiError::into_response` boundary, not the handler body.
    #[tokio::test]
    async fn waive_conflict_wire_shape_is_pinned_by_apierror_unit_tests() {
        // Pin: when a use case surfaces `Err(AppError::Domain(
        // DomainError::Conflict(_)))` from inside the handler, the
        // `ApiError::into_response` map yields 409. The handler body
        // does not transform the error shape (it propagates `?`).
        let api_err = ApiError(AppError::Domain(DomainError::Conflict(
            "stream version mismatch".into(),
        )));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    /// Repository (infrastructure) failure surfaces as 500.
    #[tokio::test]
    async fn waive_repository_error_wire_shape_is_500() {
        let api_err = ApiError(AppError::Repository("db down".into()));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
