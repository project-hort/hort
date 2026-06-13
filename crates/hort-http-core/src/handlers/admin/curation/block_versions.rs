//! `POST /api/v1/admin/curation/block-versions`.
//!
//! Bulk curator block by `(repository, package, versions[])`. Wraps the
//! [`BlockTarget::VersionList`] arm of [`CurationUseCase::block`].
//!
//! **Continue-on-error (design §2.3).** Per-version failures land in
//! `outcome.failed`; successful appends are NOT rolled back (event
//! sourcing — events are immutable). The wire response is therefore
//! `200 OK` with the FULL [`BlockOutcomeDto`] body (correlation_id +
//! four lists) on any non-validation outcome — partial success with
//! a non-empty `failed` list is STILL 200, NOT 5xx. Operators read the
//! envelope to discover which versions transitioned and which did not.
//!
//! Status-code mapping (design §3 acceptance):
//! - `200 OK` with full [`BlockOutcomeDto`] body on any non-validation
//!   outcome (including partial success — empty `failed` is the all-OK
//!   case, non-empty `failed` is the partial-success case)
//! - `400 Bad Request` — empty / oversize justification (handler
//!   boundary) OR `versions` empty OR `versions.len() > 100`
//! - `403 Forbidden` — principal lacks both Curate AND Admin
//! - `404 Not Found` — `repository` key does not resolve (the handler
//!   resolves key → id via `RepositoryUseCase::get_by_key`)
//! - `409 Conflict` — should not occur on `VersionList` (per-append
//!   conflicts land in `failed`); reserved for the resolver itself
//!   failing with an event-store conflict (defensive)
//! - `500 Internal Server Error` — infrastructure failure on the
//!   repository-key resolution or the resolver itself

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::curation_use_case::{BlockOutcome, BlockTarget};
use hort_app::use_cases::CallerPrivileges;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::{MAX_JUSTIFICATION_BYTES, MAX_VERSIONS_PER_CALL};

/// Request DTO for `POST /api/v1/admin/curation/block-versions`.
///
/// `repository` is the operator-facing **stable key** (UUIDs are an
/// internal detail). The handler resolves the key to a UUID
/// via `RepositoryUseCase::get_by_key`; a miss surfaces as 404.
///
/// `package` and `versions` are matched against `artifacts` rows via
/// `ArtifactRepository::find_by_name_in_repo`; unresolvable versions
/// land in `outcome.not_found_versions` (and the call still emits
/// `ArtifactRejected` for every version that DID resolve).
#[derive(Debug, Deserialize)]
pub struct BlockVersionsRequestDto {
    repository: String,
    package: String,
    versions: Vec<String>,
    justification: String,
}

/// HTTP-layer mirror of [`BlockOutcome`]. The domain envelope carries
/// `Vec<(Uuid, AppError)>` for `failed`, which is not serde-derived —
/// `AppError` is intentionally non-clonable and not `Serialize`. The
/// DTO projects each `(uuid, app_error)` pair to a stable wire shape
/// without leaking internal error details (mirrors the
/// `UPSTREAM_UNAVAILABLE_BODY` sanitisation precedent for
/// `External`/`Scanner`).
///
/// Fields:
/// - `correlation_id` — shared across every `ArtifactRejected` the call
///   emits; operator dashboards group decisions by this id
/// - `blocked_artifact_ids` — transitioned to `Rejected` on this call
/// - `already_rejected_ids` — idempotent no-op (no event appended)
/// - `not_found_versions` — strings in the request the resolver could
///   not match to an artifact_id; this surface does NOT auto-block
///   future ingests of these (deliberately out of scope)
/// - `failed` — per-(artifact, error) pairs that hit a continue-on-error
///   path (event-store conflict, repository error, etc.); see
///   [`FailedBlockEntryDto`] for the per-entry shape
#[derive(Debug, Serialize)]
pub(crate) struct BlockOutcomeDto {
    pub correlation_id: Uuid,
    pub blocked_artifact_ids: Vec<Uuid>,
    pub already_rejected_ids: Vec<Uuid>,
    pub not_found_versions: Vec<String>,
    pub failed: Vec<FailedBlockEntryDto>,
}

/// Per-entry projection of `(Uuid, AppError)` from
/// [`BlockOutcome::failed`].
///
/// `error_kind` is a stable discriminator drawn from the `AppError`
/// variant tree (operator tooling routes on this); `message` is a safe
/// human-readable summary — for the `External` / `Scanner` arms the
/// raw error string is REPLACED with an opaque "upstream unavailable"
/// sentinel (matches the
/// [`crate::error::ApiError::into_response`] sanitisation contract for
/// the same variants). For `Domain` / `Repository` / `Storage` /
/// `EventStore`, the variant's payload string is surfaced unmodified
/// — these don't carry the same exposure-risk shape `External` /
/// `Scanner` do.
#[derive(Debug, Serialize)]
pub(crate) struct FailedBlockEntryDto {
    pub artifact_id: Uuid,
    pub error_kind: &'static str,
    pub message: String,
}

impl FailedBlockEntryDto {
    fn from_app_error(artifact_id: Uuid, err: &AppError) -> Self {
        let (error_kind, message) = match err {
            AppError::Domain(DomainError::NotFound { entity, id }) => {
                ("not_found", format!("{entity} {id} not found"))
            }
            AppError::Domain(DomainError::Conflict(m)) => ("conflict", m.clone()),
            AppError::Domain(DomainError::Validation(m)) => ("validation", m.clone()),
            AppError::Domain(DomainError::Forbidden(m)) => ("forbidden", m.clone()),
            AppError::Domain(DomainError::Invariant(m)) => ("invariant", m.clone()),
            // ADR 0025 — caller-reachable state precondition (409 at the
            // single-resource boundary); per-version it's a labelled failure.
            AppError::Domain(DomainError::InvalidState(m)) => ("invalid_state", m.clone()),
            AppError::Domain(DomainError::ManagedByConfiguration { kind, name }) => (
                "managed_by_configuration",
                format!("{kind} {name} is gitops-managed"),
            ),
            AppError::Domain(DomainError::CurationBlocked { rule_name, .. }) => (
                "curation_blocked",
                format!("blocked by curation rule {rule_name}"),
            ),
            // Upstream body backstop trip (ADR 0026). Per-row failure
            // in the bulk curation-block surface is rare (the upstream
            // proxy is not on this code path); the arm exists for
            // exhaustive matching. Default-mapped to the same `external`
            // sanitised body as External / Scanner above.
            AppError::Domain(DomainError::UpstreamBodyTooLarge { .. }) => {
                ("upstream_body_too_large", err.to_string())
            }
            AppError::Repository(_) => ("repository", "internal error".into()),
            AppError::Storage(_) => ("storage", "internal error".into()),
            AppError::EventStore(_) => ("event_store", "internal error".into()),
            // Mirror the `ApiError::into_response` opaque-body
            // contract — `External` / `Scanner` carry infrastructure
            // details that must not surface on the wire.
            AppError::External(_) => ("external", "upstream unavailable".into()),
            AppError::Scanner(_) => ("scanner", "upstream unavailable".into()),
            AppError::OidcValidation(_) => ("oidc_validation", "invalid token".into()),
            AppError::Unauthorized(_) => ("unauthorized", "invalid or expired token".into()),
            AppError::ConcurrentModification(m) => ("concurrent_modification", m.clone()),
            AppError::RangeInvalid { .. } => ("range_invalid", err.to_string()),
            AppError::BodyLengthMismatch => ("body_length_mismatch", err.to_string()),
            AppError::SizeExceeded => ("size_exceeded", err.to_string()),
        };
        Self {
            artifact_id,
            error_kind,
            message,
        }
    }
}

impl BlockOutcomeDto {
    pub(crate) fn from_domain(o: BlockOutcome) -> Self {
        Self {
            correlation_id: o.correlation_id,
            blocked_artifact_ids: o.blocked_artifact_ids,
            already_rejected_ids: o.already_rejected_ids,
            not_found_versions: o.not_found_versions,
            failed: o
                .failed
                .iter()
                .map(|(id, e)| FailedBlockEntryDto::from_app_error(*id, e))
                .collect(),
        }
    }
}

/// `POST /api/v1/admin/curation/block-versions`.
///
/// Resolves `repository` (stable key) → `repository_id` (Uuid) via the
/// repository use case; dispatches the [`BlockTarget::VersionList`] arm;
/// returns the FULL `BlockOutcomeDto` body on any non-validation outcome
/// (continue-on-error per §2.3 — partial success is 200, NOT 5xx).
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn post_block_versions(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<BlockVersionsRequestDto>,
) -> Result<Response, ApiError> {
    // Boundary checks — fire BEFORE the repository-key resolution so
    // a malformed body never spends a DB round-trip.
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
    if body.versions.is_empty() {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            "versions must not be empty".into(),
        ))));
    }
    if body.versions.len() > MAX_VERSIONS_PER_CALL {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "versions length {} exceeds {MAX_VERSIONS_PER_CALL} cap",
                body.versions.len()
            ),
        ))));
    }

    // Resolve the operator-facing key → Uuid. A miss surfaces as 404
    // via the standard `AppError::Domain(DomainError::NotFound)` →
    // `ApiError` map. The lookup is bounded (single query) — not an
    // N+1 concern.
    let repository_id = ctx
        .repository_use_case
        .get_by_key(&body.repository)
        .await?
        .id;

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
            BlockTarget::VersionList {
                repository_id,
                package: body.package,
                versions: body.versions,
            },
            actor,
            privileges,
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
                "/api/v1/admin/curation/block-versions",
                post(post_block_versions),
            )
            .with_state(ctx);
        (router, mocks)
    }

    fn block_versions_post(body: &str, p: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post("/api/v1/admin/curation/block-versions")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// Seed a repo + a quarantined artifact under `package` /
    /// `version`. Returns `(repo_key, artifact_id)`.
    fn seed_repo_with_artifact(mocks: &MockPorts, package: &str, version: &str) -> (String, Uuid) {
        let mut repo = sample_repository();
        repo.key = "curate-target".into();
        let repo_id = repo.id;
        mocks.repositories.insert(repo);

        let mut artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.repository_id = repo_id;
        artifact.name = package.into();
        artifact.version = Some(version.into());
        let artifact_id = artifact.id;
        mocks.artifacts.insert(artifact);
        ("curate-target".to_string(), artifact_id)
    }

    /// Happy path: single resolvable version → 200 with the full
    /// envelope (`blocked_artifact_ids` carries the resolved id;
    /// `not_found_versions` and `failed` empty).
    #[tokio::test]
    async fn block_versions_happy_path_returns_200_with_full_envelope() {
        let (router, mocks) = harness();
        let (repo_key, artifact_id) = seed_repo_with_artifact(&mocks, "left-pad", "1.3.0");
        let body = format!(
            r#"{{"repository":"{repo_key}","package":"left-pad","versions":["1.3.0"],"justification":"manual block"}}"#
        );
        let resp = router
            .oneshot(block_versions_post(
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["correlation_id"].is_string());
        assert_eq!(v["blocked_artifact_ids"][0], artifact_id.to_string());
        assert!(v["already_rejected_ids"].as_array().unwrap().is_empty());
        assert!(v["not_found_versions"].as_array().unwrap().is_empty());
        assert!(v["failed"].as_array().unwrap().is_empty());
    }

    /// Partial success — one resolvable version + one unresolvable
    /// version. The wire shape is 200 with `not_found_versions`
    /// non-empty; the `failed` list is also empty (a name miss is NOT
    /// a failure per use-case semantics — it's the "did not exist at
    /// resolution time" partition).
    #[tokio::test]
    async fn block_versions_partial_success_returns_200_with_not_found_entry() {
        let (router, mocks) = harness();
        let (repo_key, _) = seed_repo_with_artifact(&mocks, "left-pad", "1.3.0");
        let body = format!(
            r#"{{"repository":"{repo_key}","package":"left-pad","versions":["1.3.0","9.9.9"],"justification":"valid"}}"#
        );
        let resp = router
            .oneshot(block_versions_post(
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "partial success must return 200 — continue-on-error per §2.3"
        );

        let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["blocked_artifact_ids"].as_array().unwrap().len(), 1);
        assert_eq!(v["not_found_versions"].as_array().unwrap()[0], "9.9.9");
    }

    /// Unknown repository key → 404.
    #[tokio::test]
    async fn block_versions_unknown_repository_returns_404() {
        let (router, _mocks) = harness();
        let body =
            r#"{"repository":"no-such-repo","package":"x","versions":["1"],"justification":"v"}"#;
        let resp = router
            .oneshot(block_versions_post(
                body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Empty `versions` → 400 at the handler boundary.
    #[tokio::test]
    async fn block_versions_empty_versions_returns_400() {
        let (router, mocks) = harness();
        let (repo_key, _) = seed_repo_with_artifact(&mocks, "left-pad", "1.3.0");
        let body = format!(
            r#"{{"repository":"{repo_key}","package":"x","versions":[],"justification":"valid"}}"#
        );
        let resp = router
            .oneshot(block_versions_post(
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 101 versions → 400 (>100 cap at the handler boundary).
    #[tokio::test]
    async fn block_versions_oversize_list_returns_400() {
        let (router, mocks) = harness();
        let (repo_key, _) = seed_repo_with_artifact(&mocks, "left-pad", "1.3.0");
        let versions: Vec<String> = (0..101).map(|n| format!("\"{n}.0\"")).collect();
        let body = format!(
            r#"{{"repository":"{repo_key}","package":"x","versions":[{}],"justification":"v"}}"#,
            versions.join(",")
        );
        let resp = router
            .oneshot(block_versions_post(
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Empty justification → 400.
    #[tokio::test]
    async fn block_versions_empty_justification_returns_400() {
        let (router, mocks) = harness();
        let (repo_key, _) = seed_repo_with_artifact(&mocks, "x", "1");
        let body = format!(
            r#"{{"repository":"{repo_key}","package":"x","versions":["1"],"justification":""}}"#
        );
        let resp = router
            .oneshot(block_versions_post(
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Oversize justification → 400.
    #[tokio::test]
    async fn block_versions_oversize_justification_returns_400() {
        let (router, mocks) = harness();
        let (repo_key, _) = seed_repo_with_artifact(&mocks, "x", "1");
        let oversized = "x".repeat(513);
        let body = format!(
            r#"{{"repository":"{repo_key}","package":"x","versions":["1"],"justification":"{oversized}"}}"#
        );
        let resp = router
            .oneshot(block_versions_post(
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Reader caller → 403.
    #[tokio::test]
    async fn block_versions_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let (repo_key, _) = seed_repo_with_artifact(&mocks, "x", "1");
        let body = format!(
            r#"{{"repository":"{repo_key}","package":"x","versions":["1"],"justification":"v"}}"#
        );
        let resp = router
            .oneshot(block_versions_post(
                &body,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// `BlockOutcomeDto::from_domain` round-trips a populated `failed`
    /// list — pins the AppError → wire-shape mapping for every variant
    /// that can show up on the continue-on-error path. The
    /// `External` / `Scanner` arms surface the opaque
    /// "upstream unavailable" sentinel (matches the
    /// `error::ApiError::into_response` sanitisation contract).
    #[test]
    fn block_outcome_dto_failed_entry_mapping() {
        let id = Uuid::new_v4();

        let dto = FailedBlockEntryDto::from_app_error(
            id,
            &AppError::Domain(DomainError::Conflict("vsn mismatch".into())),
        );
        assert_eq!(dto.error_kind, "conflict");
        assert_eq!(dto.message, "vsn mismatch");

        let dto = FailedBlockEntryDto::from_app_error(
            id,
            &AppError::External("postgres://internal".into()),
        );
        assert_eq!(dto.error_kind, "external");
        assert_eq!(dto.message, "upstream unavailable");
        assert!(!dto.message.contains("postgres"));
    }
}
