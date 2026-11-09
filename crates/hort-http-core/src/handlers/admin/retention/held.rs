//! `GET /api/v1/admin/retention/held?bucket=…`.
//!
//! The drill-down: the list of held artifacts an operator actually acts
//! on. Unlike the aggregate beside it, every row here has been
//! re-decided through the one provenance authority in `hort-app`
//! (`provenance_clearance_from`), so this list is exact per row — a row
//! the aggregate counted and the authority clears does not appear.
//!
//! Query parameters:
//! - `bucket` — **required**, `constituent | in_own_right`. The two
//!   halves call for different operator action (a constituent is waiting
//!   on its *parent manifest's* signature and can never acquire one of
//!   its own), so there is no "both" shape and no default. Missing or
//!   invalid → `400`.
//! - `repository` — stable repository key (string); resolves to a UUID
//!   via `RepositoryUseCase::get_by_key`. A key that does not resolve →
//!   `404`.
//! - `after` — keyset cursor, the `next_cursor` of the previous page.
//!   Unparseable → `400`.
//! - `limit` — `1..=500`. Default 100. **Outside the range is refused,
//!   not clamped** (`400`), matching the curation queue: a clamp returns
//!   fewer rows than the caller asked for and says nothing about it.
//!
//! # Paging, and why a page can come back empty
//!
//! The adapter returns a keyset page of the aggregate's **superset**;
//! the use case then drops the rows the authority clears. So a response
//! can carry zero rows and a non-null `next_cursor` — that is a page
//! that was entirely stale, not an exhausted set. `next_cursor` is
//! derived from the last row *scanned*, never the last row kept, so
//! paging always advances. Keep requesting until `next_cursor` is
//! `null`.
//!
//! Status-code map:
//! - `200 OK` — success, body is [`HeldPageDto`]
//! - `400 Bad Request` — missing/invalid `bucket`, unparseable `after`,
//!   `limit = 0` or `limit > 500`
//! - `403 Forbidden` — caller holds neither `Permission::Curate` nor
//!   `Permission::Admin`
//! - `404 Not Found` — `repository` key does not resolve
//! - `500 Internal Server Error` — infrastructure failure
//!
//! **`#[tracing::instrument]` deliberately WITHOUT `err`** — a privilege
//! denial or a validation refusal is an audit fact, not an error.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::held_set_use_case::{
    HeldListRequest, HeldSetPage, DEFAULT_HELD_PAGE_LIMIT, MAX_HELD_PAGE_LIMIT,
};
use hort_app::use_cases::CallerPrivileges;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::ports::held_set_reader::{HeldBucket, HeldCandidateRow};

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

/// `GET /held` query string. Only handler-local DTOs are deserialized
/// from external input; the domain's `HeldBucket` is parsed from the
/// string below via its `FromStr` (ADR 0008).
#[derive(Debug, Deserialize)]
pub struct HeldQueryParams {
    pub bucket: Option<String>,
    pub repository: Option<String>,
    pub after: Option<String>,
    pub limit: Option<u32>,
}

/// One held artifact on the wire.
#[derive(Debug, Serialize)]
pub struct HeldArtifactDto {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub name: String,
    /// Absent for an OCI blob or manifest, which carries no version —
    /// `path` identifies those.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub path: String,
    /// Two rows sharing this value share their bytes (ADR 0054), which
    /// is why the aggregate counts distinct contents separately.
    pub content_hash: String,
    pub bucket: &'static str,
    pub held_since: DateTime<Utc>,
    /// How long this artifact has been held, at `measured_at`.
    pub age_secs: u64,
}

impl HeldArtifactDto {
    fn from_domain(row: &HeldCandidateRow, measured_at: DateTime<Utc>) -> Self {
        Self {
            artifact_id: row.artifact_id,
            repository_id: row.repository_id,
            repository_key: row.repository_key.clone(),
            name: row.name.clone(),
            version: row.version.clone(),
            path: row.path.clone(),
            content_hash: row.content_hash.clone(),
            bucket: row.bucket.as_str(),
            held_since: row.held_since,
            age_secs: row.age_secs(measured_at),
        }
    }
}

/// `GET /api/v1/admin/retention/held` response body.
#[derive(Debug, Serialize)]
pub struct HeldPageDto {
    /// The instant every `age_secs` in this body is relative to.
    pub measured_at: DateTime<Utc>,
    pub bucket: &'static str,
    /// The page, after the per-row authority. **May be empty while
    /// `next_cursor` is set** — see the module docs.
    pub held: Vec<HeldArtifactDto>,
    /// Pass back as `?after=` to continue. `null` means the bucket is
    /// exhausted.
    pub next_cursor: Option<Uuid>,
}

impl HeldPageDto {
    fn from_domain(page: &HeldSetPage, bucket: HeldBucket) -> Self {
        let measured_at = page.measured_at;
        Self {
            measured_at,
            bucket: bucket.as_str(),
            held: page
                .rows
                .iter()
                .map(|r| HeldArtifactDto::from_domain(r, measured_at))
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// `GET /api/v1/admin/retention/held`.
#[tracing::instrument(skip(ctx, principal))]
pub async fn get_held(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Query(query): Query<HeldQueryParams>,
) -> Result<Response, ApiError> {
    // `?bucket=` is required and has no default: the two halves are
    // different operator tasks, and guessing one for a caller who named
    // neither would answer a question they did not ask.
    let bucket = match query.bucket.as_deref() {
        None => {
            return Err(ApiError(AppError::Domain(DomainError::Validation(
                format!(
                    "bucket is required (expected one of {} | {})",
                    HeldBucket::Constituent.as_str(),
                    HeldBucket::InOwnRight.as_str(),
                ),
            ))));
        }
        Some(s) => s.parse::<HeldBucket>().map_err(ApiError::from)?,
    };

    // Validate `?limit=` BEFORE any database work; refuse rather than
    // clamp, against this view's own named bound.
    let limit = match query.limit {
        None => DEFAULT_HELD_PAGE_LIMIT,
        Some(0) => {
            return Err(ApiError(AppError::Domain(DomainError::Validation(
                "limit must be >= 1".into(),
            ))));
        }
        Some(n) if n > MAX_HELD_PAGE_LIMIT => {
            return Err(ApiError(AppError::Domain(DomainError::Validation(
                format!("limit {n} exceeds maximum {MAX_HELD_PAGE_LIMIT}"),
            ))));
        }
        Some(n) => n,
    };

    // The cursor is an artifact id. A malformed one is caller input, so
    // 400 — answering the first page instead would silently restart a
    // paging loop.
    let after = match query.after.as_deref() {
        None => None,
        Some(raw) => Some(Uuid::parse_str(raw).map_err(|_| {
            ApiError(AppError::Domain(DomainError::Validation(format!(
                "invalid after cursor {raw:?} (expected an artifact UUID)"
            ))))
        })?),
    };

    // Resolve `?repository=<key>` → Uuid. A miss surfaces as 404 via the
    // standard `DomainError::NotFound` map, matching the curation queue.
    let repository_id = match query.repository.as_deref() {
        None => None,
        Some(key) => Some(ctx.repository_use_case.get_by_key(key).await?.id),
    };

    // `CurateOrAdminPrincipal` proved the gate; `is_curator = true`
    // keeps the use-case gate engaged for non-HTTP callers while making
    // it a no-op here. Mirrors the curation queue handler.
    let actor = ApiActor {
        user_id: principal.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    };

    let page = ctx
        .held_set_use_case
        .list_held(
            actor,
            privileges,
            HeldListRequest {
                bucket,
                repository_id,
                after,
                limit,
            },
            Utc::now(),
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(HeldPageDto::from_domain(&page, bucket)),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    //! `GET /held` handler-layer assertions.

    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use chrono::Duration;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{sample_repository, MockIdentityProvider};
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
            .route("/api/v1/admin/retention/held", get(get_held))
            .with_state(ctx);
        (router, mocks)
    }

    fn held_get(query: &str, principal: Option<CallerPrincipal>) -> Request<Body> {
        let uri = if query.is_empty() {
            "/api/v1/admin/retention/held".to_string()
        } else {
            format!("/api/v1/admin/retention/held?{query}")
        };
        let mut req = Request::get(uri).body(Body::empty()).unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// A held row whose stream carries no `ProvenanceVerified`, under a
    /// repository policy that requires provenance — so the use case's
    /// per-row authority keeps it.
    fn seed_one_held_row(mocks: &MockPorts, bucket: HeldBucket) -> Uuid {
        let repo = sample_repository();
        mocks.policy_projections.insert(required_policy(repo.id));
        let artifact_id = Uuid::new_v4();
        mocks.held_set.set_page(Ok(vec![HeldCandidateRow {
            artifact_id,
            repository_id: repo.id,
            repository_key: "oci-main".into(),
            name: "library/nginx".into(),
            version: None,
            path: "library/nginx/blobs/sha256-dead".into(),
            content_hash: "a".repeat(64),
            bucket,
            held_since: Utc::now() - Duration::seconds(7_200),
        }]));
        artifact_id
    }

    fn required_policy(repo_id: Uuid) -> hort_domain::entities::scan_policy::ScanPolicyProjection {
        use hort_domain::entities::scan_policy::{
            CompositeVerdictMode, NegligibleAction, ProvenanceMode, ScanEnforcement,
            ScanPolicyProjection, SeverityThreshold,
        };
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: format!("held-{}", Uuid::new_v4()),
            scope: hort_domain::events::PolicyScope::Repository(repo_id),
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 60,
            require_approval: false,
            provenance_mode: ProvenanceMode::Required,
            provenance_backends: vec!["cosign".into()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".into()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            composite_verdict_mode: CompositeVerdictMode::Observed,
            stream_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn held_happy_path_returns_200_with_the_row_and_its_age() {
        let (router, mocks) = harness();
        let artifact_id = seed_one_held_row(&mocks, HeldBucket::InOwnRight);

        let resp = router
            .oneshot(held_get(
                "bucket=in_own_right",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["bucket"], "in_own_right");
        assert_eq!(body["held"][0]["artifact_id"], artifact_id.to_string());
        let age = body["held"][0]["age_secs"].as_u64().expect("age");
        assert!((7_000..7_400).contains(&age), "age was {age}");
        // An OCI blob carries no version; the field is omitted rather
        // than rendered as null.
        assert!(body["held"][0].get("version").is_none());
    }

    #[tokio::test]
    async fn held_forwards_the_requested_bucket() {
        let (router, mocks) = harness();
        seed_one_held_row(&mocks, HeldBucket::Constituent);
        let resp = router
            .oneshot(held_get(
                "bucket=constituent",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            mocks.held_set.recorded_page_queries()[0].bucket,
            HeldBucket::Constituent
        );
    }

    /// `?bucket=` is required: a caller who named neither half gets told
    /// so, rather than being answered about a half they did not pick.
    #[tokio::test]
    async fn held_without_a_bucket_returns_400() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(held_get("", Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.held_set.recorded_page_queries().is_empty());
    }

    #[tokio::test]
    async fn held_with_an_unknown_bucket_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(held_get(
                "bucket=both",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// **Refused, not clamped** — the whole point of matching the
    /// curation queue's behaviour here.
    #[tokio::test]
    async fn held_oversize_limit_returns_400_rather_than_clamping() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(held_get(
                &format!("bucket=in_own_right&limit={}", MAX_HELD_PAGE_LIMIT + 1),
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.held_set.recorded_page_queries().is_empty(),
            "a clamp would have reached the port with a smaller limit"
        );
    }

    #[tokio::test]
    async fn held_zero_limit_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(held_get(
                "bucket=in_own_right&limit=0",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn held_default_limit_is_the_documented_default() {
        let (router, mocks) = harness();
        router
            .oneshot(held_get(
                "bucket=in_own_right",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(
            mocks.held_set.recorded_page_queries()[0].limit,
            DEFAULT_HELD_PAGE_LIMIT
        );
    }

    /// A malformed cursor is caller input. Answering the first page
    /// instead would silently restart a paging loop that had been
    /// advancing.
    #[tokio::test]
    async fn held_malformed_cursor_returns_400() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(held_get(
                "bucket=in_own_right&after=not-a-uuid",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.held_set.recorded_page_queries().is_empty());
    }

    #[tokio::test]
    async fn held_forwards_a_well_formed_cursor() {
        let (router, mocks) = harness();
        let cursor = Uuid::new_v4();
        router
            .oneshot(held_get(
                &format!("bucket=in_own_right&after={cursor}"),
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(
            mocks.held_set.recorded_page_queries()[0].after,
            Some(cursor)
        );
    }

    /// A repository key that does not resolve is a 404, matching the
    /// curation queue.
    #[tokio::test]
    async fn held_unknown_repository_key_returns_404() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(held_get(
                "bucket=in_own_right&repository=no-such-repo",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(mocks.held_set.recorded_page_queries().is_empty());
    }

    #[tokio::test]
    async fn held_resolves_a_repository_key_to_its_id() {
        let (router, mocks) = harness();
        let repo = sample_repository();
        mocks.repositories.insert(repo.clone());
        router
            .oneshot(held_get(
                &format!("bucket=in_own_right&repository={}", repo.key),
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(
            mocks.held_set.recorded_page_queries()[0].repository_id,
            Some(repo.id),
            "the handler must forward the resolved id, not the key"
        );
    }

    #[tokio::test]
    async fn held_admin_caller_returns_200() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(held_get(
                "bucket=in_own_right",
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn held_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(held_get(
                "bucket=in_own_right",
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(mocks.held_set.recorded_page_queries().is_empty());
    }

    /// **The empty page.** A page the adapter filled and the authority
    /// emptied still carries a cursor, so a client keeps advancing. The
    /// wire has to be able to say that.
    #[tokio::test]
    async fn a_fully_dropped_page_is_empty_on_the_wire_but_still_advances() {
        let (router, mocks) = harness();
        let repo = sample_repository();
        mocks.policy_projections.insert(required_policy(repo.id));
        // No `ProvenanceVerified` is seeded, so instead make the mode
        // non-gating for a SECOND repository whose row shares the page:
        // the simplest fully-dropped page is one whose rows resolve to
        // `NotRequired`.
        let other = Uuid::new_v4();
        let last = Uuid::from_u128(9);
        mocks.held_set.set_page(Ok(vec![HeldCandidateRow {
            artifact_id: last,
            repository_id: other,
            repository_key: "npm-main".into(),
            name: "left-pad".into(),
            version: Some("1.0.0".into()),
            path: "left-pad/-/left-pad-1.0.0.tgz".into(),
            content_hash: "b".repeat(64),
            bucket: HeldBucket::InOwnRight,
            held_since: Utc::now(),
        }]));

        let resp = router
            .oneshot(held_get(
                "bucket=in_own_right&limit=1",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["held"], serde_json::json!([]));
        assert_eq!(
            body["next_cursor"],
            last.to_string(),
            "an emptied page must still advance, or a client loops forever"
        );
    }

    #[tokio::test]
    async fn held_port_failure_returns_500() {
        let (router, mocks) = harness();
        mocks
            .held_set
            .set_page(Err(DomainError::Invariant("db down".into())));
        let resp = router
            .oneshot(held_get(
                "bucket=in_own_right",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
