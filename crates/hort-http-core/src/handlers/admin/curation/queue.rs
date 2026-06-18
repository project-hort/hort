//! `GET /api/v1/admin/curation/queue`.
//!
//! Paginated read of curator-actionable artifacts. One
//! row per artifact currently in `Quarantined` / `Rejected` /
//! `ScanIndeterminate`, with per-row quarantine deadline resolved at
//! query time and a rejection-reason discriminator for rejected rows.
//!
//! Query parameters:
//! - `repository` — stable repository key (string). Resolves to a UUID
//!   via [`hort_app::use_cases::repository_use_case::RepositoryUseCase::get_by_key`];
//!   missing key → 404.
//! - `status` — one of `quarantined | rejected | scan_indeterminate`.
//!   Invalid value → 400.
//! - `reason` — rejection-reason discriminator, one of
//!   `scanner | curator | curation_retroactive` (closed set —
//!   `corruption` is NOT a curation-queue
//!   reason; corrupted artifacts surface via the separate
//!   `ArtifactCorrupted` stream, so `?reason=corruption` is rejected
//!   at the boundary). Invalid value → 400.
//! - `limit` — 1..=500. Default 100 when absent. Invalid range → 400.
//!
//! Status-code map:
//! - `200 OK` — success, body is [`CurationQueueResponseDto`]
//! - `400 Bad Request` — invalid `status` / `reason` value, oversize
//!   `limit`, or `limit = 0`
//! - `403 Forbidden` — caller lacks both `Permission::Curate` AND
//!   `Permission::Admin` (the [`CurateOrAdminPrincipal`] extractor
//!   short-circuits before the handler body)
//! - `404 Not Found` — `repository` key does not resolve (the use-case
//!   `get_by_key` miss propagates as `DomainError::NotFound`)
//! - `500 Internal Server Error` — infrastructure failure (Repository,
//!   EventStore, etc.)
//!
//! **`#[tracing::instrument]` deliberately WITHOUT `err`** — privilege
//! denial / validation outcomes are info-level events (architect rule);
//! promoting them to `err` would surface every 4xx as ERROR.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::ports::curation_queue_repository::{CurationQueueEntry, CurationQueueFilter};

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::MAX_LIST_LIMIT;

/// Closed set of accepted `?reason=` values for `GET /queue`.
///
/// `corruption` is deliberately not a queue discriminator: corruption
/// rides on the separate
/// `ArtifactCorrupted` event, and the queue's LATERAL JOIN
/// only reads `ArtifactRejected`, so a `?reason=corruption` filter
/// would always return empty. The handler rejects it with 400 so
/// operators
/// get a clear signal rather than a silent empty list.
const ACCEPTED_REASONS: &[&str] = &["scanner", "curator", "curation_retroactive"];

/// Query parameters for `GET /api/v1/admin/curation/queue`.
///
/// Every field is optional. Serde-deserialising `u32` from a
/// query-string value rejects non-integer input at extraction time,
/// producing a 400 from axum's `Query` extractor automatically — no
/// boundary check needed here for that case. The handler body still
/// re-validates the `1..=500` window because that's a domain rule,
/// not a parse rule.
#[derive(Debug, Deserialize)]
pub struct QueueQueryParams {
    repository: Option<String>,
    status: Option<String>,
    reason: Option<String>,
    limit: Option<u32>,
}

/// Response DTO for `GET /api/v1/admin/curation/queue`.
///
/// The domain [`CurationQueueEntry`] type does NOT derive `Serialize`
/// (DTO discipline — no domain-type wire coupling);
/// this DTO is the wire-format counterpart and is constructed via
/// [`CurationQueueEntryDto::from_domain`] in the handler body. Enum
/// fields are projected as their `Display` strings so the JSON
/// carries `"quarantined"` / `"npm"` / `"high"` rather than the
/// integer / variant-name shapes serde would produce.
#[derive(Debug, Serialize)]
pub struct CurationQueueResponseDto {
    pub entries: Vec<CurationQueueEntryDto>,
}

/// Wire-format row for [`CurationQueueResponseDto`].
///
/// Field set mirrors [`CurationQueueEntry`] one-to-one. `DateTime<Utc>`
/// serialises as ISO-8601 via the default chrono serde impl. The
/// `quarantine_status`, `format`, and `max_severity` enums project
/// through their `Display` strings so the operator sees stable wire
/// names.
#[derive(Debug, Serialize)]
pub struct CurationQueueEntryDto {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub format: String,
    pub package_name: String,
    pub version: Option<String>,
    pub quarantine_status: String,
    pub quarantine_window_start: Option<DateTime<Utc>>,
    pub quarantine_deadline: Option<DateTime<Utc>>,
    pub finding_count: u32,
    pub max_severity: Option<String>,
    pub rejection_reason_kind: Option<String>,
}

impl CurationQueueEntryDto {
    fn from_domain(e: CurationQueueEntry) -> Self {
        Self {
            artifact_id: e.artifact_id,
            repository_id: e.repository_id,
            repository_key: e.repository_key,
            format: e.format.to_string(),
            package_name: e.package_name,
            version: e.version,
            quarantine_status: e.quarantine_status.to_string(),
            quarantine_window_start: e.quarantine_window_start,
            quarantine_deadline: e.quarantine_deadline,
            finding_count: e.finding_count,
            max_severity: e.max_severity.map(|s| s.to_string()),
            rejection_reason_kind: e.rejection_reason_kind,
        }
    }
}

/// `GET /api/v1/admin/curation/queue`.
///
/// See module docs for the full status-code map. The handler validates
/// each query parameter at the boundary, resolves `repository` (key) →
/// `repository_id` (Uuid) via the repository use case, builds a
/// [`CurationQueueFilter`], and delegates to
/// [`hort_app::use_cases::curation_use_case::CurationUseCase::list_queue`].
#[tracing::instrument(skip(ctx, principal))]
pub async fn get_queue(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Query(query): Query<QueueQueryParams>,
) -> Result<Response, ApiError> {
    // Validate `?limit=` BEFORE any DB work; default to 100.
    let limit = match query.limit {
        None => CurationQueueFilter::default().limit,
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

    // Validate `?status=`. Lower-case lookup (the domain `FromStr` already
    // normalises) returns `DomainError::Validation` on miss, which maps
    // to 400 via `ApiError::into_response`.
    let status = match query.status.as_deref() {
        None => None,
        Some(s) => Some(s.parse::<QuarantineStatus>().map_err(ApiError::from)?),
    };

    // Validate `?reason=` against the closed set the adapter
    // actually emits (`scanner | curator | curation_retroactive`).
    // `corruption` is NOT a curation-queue reason (corrupted
    // artifacts surface via the separate
    // `ArtifactCorrupted` stream); reject with 400 rather than return
    // a silent empty list.
    let rejection_reason_kind = match query.reason {
        None => None,
        Some(r) => {
            if !ACCEPTED_REASONS.contains(&r.as_str()) {
                return Err(ApiError(AppError::Domain(DomainError::Validation(
                    format!(
                        "invalid reason {r:?} (expected one of {})",
                        ACCEPTED_REASONS.join(" | "),
                    ),
                ))));
            }
            Some(r)
        }
    };

    // Resolve `?repository=<key>` → Uuid. A miss surfaces as 404 via
    // the standard `AppError::Domain(DomainError::NotFound)` →
    // `ApiError` map (matches the block-versions handler).
    let repository_id = match query.repository.as_deref() {
        None => None,
        Some(key) => Some(ctx.repository_use_case.get_by_key(key).await?.id),
    };

    let filter = CurationQueueFilter {
        repository_id,
        status,
        rejection_reason_kind,
        limit,
    };

    // CurateOrAdminPrincipal proved either Curate or Admin satisfies
    // the gate. Set `is_curator = true` so the use-case-side
    // `require_curate_or_admin()` is a no-op (defence in depth — the
    // use case is the canonical info-log emission site, so we keep
    // its gate engaged for non-HTTP callers).
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
        .list_queue(actor, privileges, filter)
        .await?;

    let body = CurationQueueResponseDto {
        entries: entries
            .into_iter()
            .map(CurationQueueEntryDto::from_domain)
            .collect(),
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    //! `GET /queue` handler-layer assertions.
    //!
    //! Tests use [`build_mock_ctx`] (the anti-pattern checklist
    //! forbids hand-rolling `AppContext`). The recording
    //! [`MockCurationQueueRepository`] is exposed via
    //! `mocks.curation_queue`; tests seed a result Vec via
    //! `set_result(...)` then assert the filter the use case forwarded
    //! via `recorded_filters()`.

    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{sample_repository, MockIdentityProvider};
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::repository::RepositoryFormat;
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
            .route("/api/v1/admin/curation/queue", get(get_queue))
            .with_state(ctx);
        (router, mocks)
    }

    fn queue_get(query: &str, principal: Option<CallerPrincipal>) -> Request<Body> {
        let uri = if query.is_empty() {
            "/api/v1/admin/curation/queue".to_string()
        } else {
            format!("/api/v1/admin/curation/queue?{query}")
        };
        let mut req = Request::get(uri).body(Body::empty()).unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn sample_queue_entry() -> CurationQueueEntry {
        CurationQueueEntry {
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            repository_key: "npm-main".into(),
            format: RepositoryFormat::Npm,
            package_name: "evil-pkg".into(),
            version: Some("1.0.0".into()),
            quarantine_status: QuarantineStatus::Quarantined,
            quarantine_window_start: Some(Utc::now()),
            quarantine_deadline: Some(Utc::now()),
            finding_count: 3,
            max_severity: None,
            rejection_reason_kind: None,
        }
    }

    /// Happy path — curator + seeded entry → 200 with rendered DTO.
    #[tokio::test]
    async fn queue_happy_path_returns_200() {
        let (router, mocks) = harness();
        let entry = sample_queue_entry();
        let expected_artifact_id = entry.artifact_id;
        mocks.curation_queue.set_result(Ok(vec![entry]));

        let resp = router
            .oneshot(queue_get("", Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["entries"][0]["artifact_id"],
            expected_artifact_id.to_string()
        );
        assert_eq!(body["entries"][0]["quarantine_status"], "quarantined");
        assert_eq!(body["entries"][0]["format"], "npm");

        // The use case forwarded the default-shaped filter (no params on the URL).
        let recorded = mocks.curation_queue.recorded_filters();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].limit, 100);
        assert!(recorded[0].repository_id.is_none());
        assert!(recorded[0].status.is_none());
        assert!(recorded[0].rejection_reason_kind.is_none());
    }

    /// Admin caller (no explicit Curate grant) also passes the gate.
    #[tokio::test]
    async fn queue_admin_caller_also_returns_200() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(queue_get("", Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Unauthorized caller → 403 from the extractor; use case is
    /// never reached.
    #[tokio::test]
    async fn queue_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(queue_get("", Some(principal_with_claims(&["reader"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            mocks.curation_queue.recorded_filters().is_empty(),
            "forbidden caller must not reach the port"
        );
    }

    /// `?limit=501` → 400 at the handler boundary.
    #[tokio::test]
    async fn queue_oversize_limit_returns_400() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "limit=501",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.curation_queue.recorded_filters().is_empty(),
            "oversize limit must not reach the port"
        );
    }

    /// `?limit=0` → 400 at the handler boundary.
    #[tokio::test]
    async fn queue_zero_limit_returns_400() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "limit=0",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.curation_queue.recorded_filters().is_empty());
    }

    /// `?limit=500` (boundary) accepted; use case sees the value.
    #[tokio::test]
    async fn queue_boundary_limit_accepted() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "limit=500",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded = mocks.curation_queue.recorded_filters();
        assert_eq!(recorded[0].limit, 500);
    }

    /// `?reason=corruption` → 400 (pinned).
    #[tokio::test]
    async fn queue_reason_corruption_returns_400() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "reason=corruption",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.curation_queue.recorded_filters().is_empty(),
            "invalid reason must not reach the port"
        );
    }

    /// `?reason=bogus` (arbitrary string outside the closed set) → 400.
    #[tokio::test]
    async fn queue_reason_unknown_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "reason=bogus",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// `?reason=curator` (closed-set member) accepted and threaded into
    /// the filter.
    #[tokio::test]
    async fn queue_reason_curator_threaded_into_filter() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "reason=curator&status=rejected",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded = mocks.curation_queue.recorded_filters();
        assert_eq!(
            recorded[0].rejection_reason_kind.as_deref(),
            Some("curator")
        );
        assert_eq!(recorded[0].status, Some(QuarantineStatus::Rejected));
    }

    /// `?status=bogus` → 400.
    #[tokio::test]
    async fn queue_status_invalid_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "status=bogus",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// `?status=scan_indeterminate` accepted.
    #[tokio::test]
    async fn queue_status_scan_indeterminate_accepted() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "status=scan_indeterminate",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded = mocks.curation_queue.recorded_filters();
        assert_eq!(
            recorded[0].status,
            Some(QuarantineStatus::ScanIndeterminate)
        );
    }

    /// `?repository=<unknown-key>` → 404 NotFound from the
    /// repository use case.
    #[tokio::test]
    async fn queue_unknown_repository_returns_404() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(queue_get(
                "repository=does-not-exist",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            mocks.curation_queue.recorded_filters().is_empty(),
            "unknown repository must not reach the queue port"
        );
    }

    /// `?repository=<known-key>` resolves to the seeded UUID and is
    /// threaded into the filter.
    #[tokio::test]
    async fn queue_known_repository_threaded_into_filter() {
        let (router, mocks) = harness();
        let mut repo = sample_repository();
        repo.key = "npm-main".into();
        let expected_id = repo.id;
        mocks.repositories.insert(repo);

        let resp = router
            .oneshot(queue_get(
                "repository=npm-main",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded = mocks.curation_queue.recorded_filters();
        assert_eq!(recorded[0].repository_id, Some(expected_id));
    }

    /// Adapter (port-layer) infra failure → 500 with no internal leakage.
    #[tokio::test]
    async fn queue_adapter_error_returns_500() {
        let (router, mocks) = harness();
        mocks.curation_queue.set_result(Err(DomainError::Invariant(
            "synthetic adapter failure".into(),
        )));

        let resp = router
            .oneshot(queue_get("", Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        crate::error::assert_no_internal_leakage(StatusCode::INTERNAL_SERVER_ERROR, &bytes);
    }

    // NOTE: The "missing principal" path is exercised by the
    // `authz_scope_tests` module in `mod.rs` and by the unit tests
    // in `authz::extractors`. The minimal `harness()` here mounts the
    // route directly without the auth middleware (matching the shape
    // in `waive.rs::tests::harness`), so a request
    // with no injected principal surfaces as 500 from the extractor
    // composition-bug guard — not a useful wire-shape assertion for
    // this handler. The 403 path that DOES belong here is exercised
    // by [`queue_unauthorized_returns_403`] above (principal present
    // but lacking the required claim).
}
