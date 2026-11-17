//! `GET /api/v1/admin/retention/overview`.
//!
//! The held-pending-signature aggregate: one cell per `(repository,
//! bucket)` carrying the artifact count, the **distinct-content** count
//! and the age of the oldest hold in that cell.
//!
//! The response field is `held_pending_signature_candidates`, and the
//! name is load-bearing. The query behind it resolves the quarantine
//! policy and the window expiry and stops: the provenance clearance
//! verdict is computed in exactly one place in `hort-app`, and an SQL
//! copy of it would be the second computation whose drift was once a
//! HIGH finding. So this number is a declared **superset** of the set
//! the gate is holding, and nothing on the wire claims otherwise. The
//! drill-down (`GET /held`) resolves each row through that one authority
//! and is exact.
//!
//! **An artifact count is not a byte count.** CAS shares content across
//! artifacts (ADR 0054), so `artifact_count` and
//! `distinct_content_count` genuinely differ — the first real retention
//! dry run reported 3 647 rows against 3 608 distinct contents. Both are
//! reported so nobody reads the row count as reclaimable storage. What a
//! disposal would actually free is a different question again, decided
//! by the CAS refcount.
//!
//! No query parameters.
//!
//! Status-code map:
//! - `200 OK` — success, body is [`HeldSetOverviewDto`]
//! - `403 Forbidden` — caller holds neither `Permission::Curate` nor
//!   `Permission::Admin` (the [`CurateOrAdminPrincipal`] extractor
//!   short-circuits before the handler body)
//! - `500 Internal Server Error` — infrastructure failure
//!
//! **`#[tracing::instrument]` deliberately WITHOUT `err`** — a privilege
//! denial is an audit fact, not an error (architect Observability rule).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use hort_app::use_cases::held_set_use_case::HeldSetOverview;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::events::ApiActor;
use hort_domain::ports::held_set_reader::HeldCandidateBucket;

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

/// One `(repository, bucket)` cell on the wire.
#[derive(Debug, Serialize)]
pub struct HeldBucketDto {
    pub repository_id: Uuid,
    pub repository_key: String,
    /// `constituent` — held because a parent manifest is unsigned, and a
    /// blob can never carry an attestation of its own — or
    /// `in_own_right`. The operator action differs, which is why the
    /// aggregate splits them.
    pub bucket: &'static str,
    /// `artifacts` rows in this cell.
    pub artifact_count: u64,
    /// Distinct `checksum_sha256` values across those rows. **Not** the
    /// same number as `artifact_count`, and not a byte figure — see the
    /// module docs.
    pub distinct_content_count: u64,
    /// The oldest hold anchor in this cell.
    pub oldest_held_since: DateTime<Utc>,
    /// How long that oldest row has been held, at `measured_at`. This is
    /// the number ADR 0039 D4's "no deadline" rests on.
    pub oldest_age_secs: u64,
}

impl HeldBucketDto {
    fn from_domain(bucket: &HeldCandidateBucket, measured_at: DateTime<Utc>) -> Self {
        Self {
            repository_id: bucket.repository_id,
            repository_key: bucket.repository_key.clone(),
            bucket: bucket.bucket.as_str(),
            artifact_count: bucket.artifact_count,
            distinct_content_count: bucket.distinct_content_count,
            oldest_held_since: bucket.oldest_held_since,
            oldest_age_secs: bucket.oldest_age_secs(measured_at),
        }
    }
}

/// `GET /api/v1/admin/retention/overview` response body.
#[derive(Debug, Serialize)]
pub struct HeldSetOverviewDto {
    /// The instant every `oldest_age_secs` in this body is relative to.
    pub measured_at: DateTime<Utc>,
    /// The aggregate. **Candidates**, not the gate's decision — see the
    /// module docs. An empty list means nothing is held.
    pub held_pending_signature_candidates: Vec<HeldBucketDto>,
}

impl HeldSetOverviewDto {
    fn from_domain(overview: &HeldSetOverview) -> Self {
        let measured_at = overview.measured_at;
        Self {
            measured_at,
            held_pending_signature_candidates: overview
                .buckets
                .iter()
                .map(|b| HeldBucketDto::from_domain(b, measured_at))
                .collect(),
        }
    }
}

/// `GET /api/v1/admin/retention/overview`.
#[tracing::instrument(skip(ctx, principal))]
pub async fn get_overview(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
) -> Result<Response, ApiError> {
    // `CurateOrAdminPrincipal` proved either Curate or Admin satisfies
    // the gate. `is_curator = true` makes the use-case-side
    // `require_curate_or_admin()` a no-op for this caller while keeping
    // its gate engaged for non-HTTP callers — the use case is the
    // canonical denial-log site. Mirrors the curation queue handler.
    let actor = ApiActor {
        user_id: principal.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    };

    // One `now` for the whole response: the window-expiry comparison in
    // the query and every age in the body describe the same instant.
    let overview = ctx
        .held_set_use_case
        .overview(actor, privileges, Utc::now())
        .await?;

    Ok((
        StatusCode::OK,
        Json(HeldSetOverviewDto::from_domain(&overview)),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    //! `GET /overview` handler-layer assertions.
    //!
    //! Uses [`build_mock_ctx`] (the anti-pattern checklist forbids
    //! hand-rolling `AppContext`); rows are seeded on
    //! `mocks.held_set`.

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
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::error::DomainError;
    use hort_domain::ports::held_set_reader::HeldBucket;
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

    pub(super) fn principal_with_claims(claims: &[&str]) -> CallerPrincipal {
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
            .route("/api/v1/admin/retention/overview", get(get_overview))
            .with_state(ctx);
        (router, mocks)
    }

    fn overview_get(principal: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::get("/api/v1/admin/retention/overview")
            .body(Body::empty())
            .unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn sample_bucket() -> HeldCandidateBucket {
        HeldCandidateBucket {
            repository_id: Uuid::new_v4(),
            repository_key: "oci-main".into(),
            bucket: HeldBucket::Constituent,
            artifact_count: 3_647,
            distinct_content_count: 3_608,
            oldest_held_since: Utc::now() - Duration::seconds(86_400),
        }
    }

    /// Happy path — curator + a seeded cell → 200, and the response
    /// field is named after what it measures.
    #[tokio::test]
    async fn overview_happy_path_names_the_aggregate_candidates() {
        let (router, mocks) = harness();
        mocks.held_set.set_aggregate(Ok(vec![sample_bucket()]));

        let resp = router
            .oneshot(overview_get(Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // The field says `candidates`, because the query behind it is a
        // superset of the gate's answer.
        assert!(
            body.get("held_pending_signature_candidates").is_some(),
            "the aggregate's wire name must say what it measures: {body}"
        );
        assert!(
            body.get("held_artifacts").is_none(),
            "no field may name the aggregate as if it were the gate's decision"
        );
        let cell = &body["held_pending_signature_candidates"][0];
        assert_eq!(cell["bucket"], "constituent");
        assert_eq!(cell["repository_key"], "oci-main");
    }

    /// Rows are not bytes: both counts reach the wire, and they differ.
    #[tokio::test]
    async fn overview_reports_rows_and_distinct_contents_on_the_wire() {
        let (router, mocks) = harness();
        mocks.held_set.set_aggregate(Ok(vec![sample_bucket()]));

        let resp = router
            .oneshot(overview_get(Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let cell = &body["held_pending_signature_candidates"][0];
        assert_eq!(cell["artifact_count"], 3_647);
        assert_eq!(cell["distinct_content_count"], 3_608);
    }

    /// The age is on the wire and is measured against `measured_at` —
    /// the number ADR 0039 D4's "no deadline" argument rests on.
    #[tokio::test]
    async fn overview_carries_the_age_of_the_oldest_hold() {
        let (router, mocks) = harness();
        mocks.held_set.set_aggregate(Ok(vec![sample_bucket()]));

        let resp = router
            .oneshot(overview_get(Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body.get("measured_at").is_some());
        let age = body["held_pending_signature_candidates"][0]["oldest_age_secs"]
            .as_u64()
            .expect("age is a number");
        assert!((86_000..87_000).contains(&age), "age was {age}");
    }

    /// An admin with no explicit Curate grant also passes the gate.
    #[tokio::test]
    async fn overview_admin_caller_returns_200() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(overview_get(Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A caller with neither permission → 403 from the extractor, and
    /// the port is never reached.
    #[tokio::test]
    async fn overview_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(overview_get(Some(principal_with_claims(&["reader"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            mocks.held_set.aggregate_calls(),
            0,
            "a forbidden caller must not reach the port"
        );
    }

    /// An empty held set is an empty list, not an absent field: an
    /// operator mid-incident must be able to tell "nothing is held" from
    /// "this endpoint told me nothing".
    #[tokio::test]
    async fn overview_of_an_empty_held_set_is_an_empty_list() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(overview_get(Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["held_pending_signature_candidates"],
            serde_json::json!([])
        );
    }

    /// An infrastructure failure is a 500, not an empty aggregate — an
    /// overview that answers "nothing is held" because the database is
    /// down is the worst available answer for this surface.
    #[tokio::test]
    async fn overview_port_failure_returns_500() {
        let (router, mocks) = harness();
        mocks
            .held_set
            .set_aggregate(Err(DomainError::Invariant("db down".into())));
        let resp = router
            .oneshot(overview_get(Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
