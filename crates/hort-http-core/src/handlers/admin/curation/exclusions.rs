//! `GET /api/v1/admin/curation/exclusions`.
//!
//! Paginated current-state listing of active CVE exclusions.
//! Reads `exclusion_projections` — the same projection
//! `QuarantineUseCase::record_scan_result` consults. Distinct from
//! `/decisions` because exclusions have **ongoing state** (active
//! until removed or expired); decisions are point-in-time.
//!
//! Query parameters:
//! - `policy` — UUID; invalid → 400.
//! - `cve` — string (CVE identifier); the use case forwards verbatim.
//! - `actor` — UUID; invalid → 400.
//! - `limit` — 1..=500. Default 100. Invalid range → 400.
//!
//! Status-code map:
//! - `200 OK` — body is [`CurationExclusionsResponseDto`]
//! - `400 Bad Request` — invalid UUID for `policy` / `actor`,
//!   oversize `limit`, or `limit = 0`
//! - `403 Forbidden` — caller lacks Curate AND Admin
//! - `500 Internal Server Error` — infrastructure failure
//!
//! **`#[tracing::instrument]` deliberately WITHOUT `err`** — same
//! rationale as `queue.rs`.

use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::error::DomainError;
use hort_domain::events::{ApiActor, PolicyScope};
use hort_domain::ports::curation_exclusions_repository::{
    CurationExclusionEntry, CurationExclusionFilter,
};

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::MAX_LIST_LIMIT;

/// Query parameters for `GET /api/v1/admin/curation/exclusions`.
#[derive(Debug, Deserialize)]
pub struct ExclusionsQueryParams {
    policy: Option<String>,
    cve: Option<String>,
    actor: Option<String>,
    limit: Option<u32>,
}

/// Response DTO for `GET /api/v1/admin/curation/exclusions`.
///
/// Domain [`CurationExclusionEntry`] type does NOT derive `Serialize`
/// (DTO discipline — no domain-type wire coupling).
#[derive(Debug, Serialize)]
pub struct CurationExclusionsResponseDto {
    pub entries: Vec<CurationExclusionEntryDto>,
}

/// Wire-format row for [`CurationExclusionsResponseDto`].
///
/// `scope` projects through a small ad-hoc shape — `{ "kind":
/// "global" }` or `{ "kind": "repository", "repository_id":
/// "<uuid>" }` — because [`PolicyScope`] derives `Serialize` but its
/// default serde shape leaks the Rust enum representation. The
/// projection here is the stable wire surface.
#[derive(Debug, Serialize)]
pub struct CurationExclusionEntryDto {
    pub exclusion_id: Uuid,
    pub policy_id: Uuid,
    pub cve_id: String,
    pub package_pattern: Option<String>,
    pub added_by_actor_id: Option<Uuid>,
    pub reason: String,
    pub scope: serde_json::Value,
    pub added_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl CurationExclusionEntryDto {
    fn from_domain(e: CurationExclusionEntry) -> Self {
        let scope = match e.scope {
            PolicyScope::Global => json!({ "kind": "global" }),
            PolicyScope::Repository(id) => json!({
                "kind": "repository",
                "repository_id": id.to_string(),
            }),
        };
        Self {
            exclusion_id: e.exclusion_id,
            policy_id: e.policy_id,
            cve_id: e.cve_id,
            package_pattern: e.package_pattern,
            added_by_actor_id: e.added_by_actor_id,
            reason: e.reason,
            scope,
            added_at: e.added_at,
            expires_at: e.expires_at,
        }
    }
}

/// `GET /api/v1/admin/curation/exclusions`.
#[tracing::instrument(skip(ctx, principal))]
pub async fn get_exclusions(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Query(query): Query<ExclusionsQueryParams>,
) -> Result<Response, ApiError> {
    let limit = match query.limit {
        None => CurationExclusionFilter::default().limit,
        Some(0) => {
            return Err(ApiError(AppError::Domain(DomainError::Validation(
                "limit must be >= 1".into(),
            ))));
        }
        Some(n) if n > MAX_LIST_LIMIT => {
            return Err(ApiError(AppError::Domain(DomainError::Validation(
                format!("limit {n} exceeds maximum {MAX_LIST_LIMIT}"),
            ))));
        }
        Some(n) => n,
    };

    let policy_id = match query.policy.as_deref() {
        None => None,
        Some(s) => Some(Uuid::from_str(s).map_err(|e| {
            ApiError(AppError::Domain(DomainError::Validation(format!(
                "invalid policy UUID {s:?}: {e}"
            ))))
        })?),
    };

    let actor_id = match query.actor.as_deref() {
        None => None,
        Some(s) => Some(Uuid::from_str(s).map_err(|e| {
            ApiError(AppError::Domain(DomainError::Validation(format!(
                "invalid actor UUID {s:?}: {e}"
            ))))
        })?),
    };

    let filter = CurationExclusionFilter {
        policy_id,
        cve_id: query.cve,
        actor_id,
        limit,
    };

    let actor = ApiActor {
        user_id: principal.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    };

    let entries = ctx
        .curation_use_case
        .list_exclusions(actor, privileges, filter)
        .await?;

    let body = CurationExclusionsResponseDto {
        entries: entries
            .into_iter()
            .map(CurationExclusionEntryDto::from_domain)
            .collect(),
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
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
            .route("/api/v1/admin/curation/exclusions", get(get_exclusions))
            .with_state(ctx);
        (router, mocks)
    }

    fn exclusions_get(query: &str, principal: Option<CallerPrincipal>) -> Request<Body> {
        let uri = if query.is_empty() {
            "/api/v1/admin/curation/exclusions".to_string()
        } else {
            format!("/api/v1/admin/curation/exclusions?{query}")
        };
        let mut req = Request::get(uri).body(Body::empty()).unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn sample_exclusion() -> CurationExclusionEntry {
        CurationExclusionEntry {
            exclusion_id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            cve_id: "CVE-2026-1234".into(),
            package_pattern: Some("xz-utils@<5.6.2".into()),
            added_by_actor_id: Some(Uuid::new_v4()),
            reason: "false positive in container layer".into(),
            scope: PolicyScope::Global,
            added_at: Utc::now(),
            expires_at: None,
        }
    }

    /// Happy path — curator + seeded exclusion → 200.
    #[tokio::test]
    async fn exclusions_happy_path_returns_200() {
        let (router, mocks) = harness();
        let entry = sample_exclusion();
        let expected_cve = entry.cve_id.clone();
        mocks.curation_exclusions.set_result(Ok(vec![entry]));

        let resp = router
            .oneshot(exclusions_get("", Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["entries"][0]["cve_id"], expected_cve);
        assert_eq!(body["entries"][0]["scope"]["kind"], "global");

        let recorded = mocks.curation_exclusions.recorded_filters();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].limit, 100);
    }

    /// 403 — caller lacks Curate AND Admin.
    #[tokio::test]
    async fn exclusions_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(exclusions_get("", Some(principal_with_claims(&["reader"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(mocks.curation_exclusions.recorded_filters().is_empty());
    }

    /// 400 — `?policy=not-a-uuid`.
    #[tokio::test]
    async fn exclusions_invalid_policy_uuid_returns_400() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(exclusions_get(
                "policy=not-a-uuid",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.curation_exclusions.recorded_filters().is_empty());
    }

    /// 400 — `?actor=not-a-uuid`.
    #[tokio::test]
    async fn exclusions_invalid_actor_uuid_returns_400() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(exclusions_get(
                "actor=not-a-uuid",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.curation_exclusions.recorded_filters().is_empty());
    }

    /// 200 — valid `?policy=<uuid>&actor=<uuid>&cve=CVE-…` all threaded.
    #[tokio::test]
    async fn exclusions_valid_uuids_threaded() {
        let (router, mocks) = harness();
        let policy = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let query = format!("policy={policy}&actor={actor}&cve=CVE-2026-1234");
        let resp = router
            .oneshot(exclusions_get(
                &query,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded = mocks.curation_exclusions.recorded_filters();
        assert_eq!(recorded[0].policy_id, Some(policy));
        assert_eq!(recorded[0].actor_id, Some(actor));
        assert_eq!(recorded[0].cve_id.as_deref(), Some("CVE-2026-1234"));
    }

    /// 400 — `?limit=501`.
    #[tokio::test]
    async fn exclusions_oversize_limit_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(exclusions_get(
                "limit=501",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 400 — `?limit=0`.
    #[tokio::test]
    async fn exclusions_zero_limit_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(exclusions_get(
                "limit=0",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 200 — `Repository(uuid)` scope renders as the
    /// `{ "kind": "repository", "repository_id": "..." }` wire shape.
    #[tokio::test]
    async fn exclusions_repository_scope_renders_correctly() {
        let (router, mocks) = harness();
        let repo_id = Uuid::new_v4();
        let mut entry = sample_exclusion();
        entry.scope = PolicyScope::Repository(repo_id);
        mocks.curation_exclusions.set_result(Ok(vec![entry]));

        let resp = router
            .oneshot(exclusions_get("", Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["entries"][0]["scope"]["kind"], "repository");
        assert_eq!(
            body["entries"][0]["scope"]["repository_id"],
            repo_id.to_string()
        );
    }

    /// 500 — adapter failure surfaces with no internal leakage.
    #[tokio::test]
    async fn exclusions_adapter_error_returns_500() {
        let (router, mocks) = harness();
        mocks
            .curation_exclusions
            .set_result(Err(DomainError::Invariant(
                "synthetic exclusions adapter failure".into(),
            )));
        let resp = router
            .oneshot(exclusions_get("", Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        crate::error::assert_no_internal_leakage(StatusCode::INTERNAL_SERVER_ERROR, &bytes);
    }
}
