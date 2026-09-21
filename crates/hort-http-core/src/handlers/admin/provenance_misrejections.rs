//! `POST /api/v1/admin/quarantine/provenance-misrejections/repair`.
//!
//! The operator surface for the one-shot corrective path described in
//! `hort_app::use_cases::provenance_misrejection_repair` — the artifacts
//! left `Rejected` with no `ArtifactRejected` behind them, contradicted by
//! a `ProvenanceVerified` on their own stream, by the defect ADR 0039's
//! 2026-09-12 amendment removed.
//!
//! ## Why this route and not the curation one
//!
//! Mounted in [`super::admin_routes`] behind [`AdminPrincipal`], NOT
//! under `/api/v1/admin/curation/*` behind `CurateOrAdminPrincipal`.
//! Two reasons, both deliberate:
//!
//! - It is not a curation decision. No verdict is being made about the
//!   artifact; a structurally invalid one is being withdrawn. `Curate` is
//!   day-to-day decision authority over held artifacts, which this is not.
//! - ADR 0038 makes service accounts strictly non-admin, so an admin gate
//!   is what decides that this cannot be wired into a pipeline. A human
//!   operator with an IdP-assumed admin session runs it, having read what
//!   it will touch.
//!
//! ## Dry run is the default
//!
//! `dry_run` defaults to **true**, including when the body is absent
//! entirely. Reporting is the default outcome and mutation is the
//! opt-in — an operator who fires this by accident gets a list, not a
//! state change. The response always echoes `dry_run` so the reader can
//! tell a plan from a change.
//!
//! Status-code mapping:
//! - `200 OK` — the scan ran; body is [`RepairReportDto`]. An empty
//!   `affected` list is a successful outcome (the expected steady state
//!   once the population is drained), not an error.
//! - `403 Forbidden` — principal lacks `Permission::Admin`.
//! - `422 Unprocessable Entity` — malformed body, or an unknown field
//!   (`deny_unknown_fields`: a typo'd `dryrun` must not silently become a
//!   dry run reported as a repair, or the reverse).
//! - `500 Internal Server Error` — the listing failed. Per-artifact
//!   failures do NOT fail the call; they surface in `failed`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::use_cases::provenance_misrejection_repair::{
    AffectedArtifact, RepairReport, RepairRequest, DEFAULT_SCAN_LIMIT,
};
use hort_domain::events::ApiActor;

use crate::authz::AdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

/// Request body. Every field is optional; an absent body is a dry run
/// over every repository with the default scan bound.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RepairRequestDto {
    /// Narrow the scan to one repository.
    pub repository_id: Option<Uuid>,
    /// How many `Rejected` rows to examine. Clamped by the use case to
    /// its `MAX_SCAN_LIMIT`; the response's `scan_cap_hit` says whether
    /// the bound actually bit.
    pub limit: Option<u32>,
    /// `false` performs the repair. Absent means **true** — see the
    /// module docs.
    pub dry_run: Option<bool>,
}

/// One artifact the predicate matched.
#[derive(Debug, Serialize)]
pub struct AffectedArtifactDto {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub package_name: String,
    pub version: Option<String>,
}

impl From<AffectedArtifact> for AffectedArtifactDto {
    fn from(a: AffectedArtifact) -> Self {
        Self {
            artifact_id: a.artifact_id,
            repository_id: a.repository_id,
            repository_key: a.repository_key,
            package_name: a.package_name,
            version: a.version,
        }
    }
}

/// One artifact the call could not process. Reported rather than failing
/// the whole run (continue-on-error).
#[derive(Debug, Serialize)]
pub struct RepairFailureDto {
    pub artifact_id: Uuid,
    pub error: String,
}

/// Response body.
#[derive(Debug, Serialize)]
pub struct RepairReportDto {
    /// `true` when nothing was written — the affected list is what a
    /// non-dry run **would** repair.
    pub dry_run: bool,
    /// `Rejected` rows examined.
    pub scanned: usize,
    /// The scan filled its limit, so there may be more rows beyond it.
    /// Re-run (optionally per repository) until this is `false`.
    pub scan_cap_hit: bool,
    pub affected: Vec<AffectedArtifactDto>,
    pub failed: Vec<RepairFailureDto>,
}

impl From<RepairReport> for RepairReportDto {
    fn from(r: RepairReport) -> Self {
        Self {
            dry_run: r.dry_run,
            scanned: r.scanned,
            scan_cap_hit: r.scan_cap_hit,
            affected: r.affected.into_iter().map(Into::into).collect(),
            failed: r
                .failed
                .into_iter()
                .map(|(artifact_id, error)| RepairFailureDto { artifact_id, error })
                .collect(),
        }
    }
}

/// `POST /api/v1/admin/quarantine/provenance-misrejections/repair`.
///
/// See the module docs for the status-code map and why the gate is
/// `AdminPrincipal`.
///
/// **`#[tracing::instrument]` deliberately WITHOUT `err`** — denial /
/// guard outcomes are info-level events (architect rule); promoting them
/// to `err` would surface every 4xx as ERROR in operator logs.
#[tracing::instrument(skip(ctx, principal))]
pub async fn post_repair_provenance_misrejections(
    principal: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    body: Option<axum::Json<RepairRequestDto>>,
) -> Result<Response, ApiError> {
    let dto = body.map(|axum::Json(b)| b).unwrap_or_default();
    let request = RepairRequest {
        repository_id: dto.repository_id,
        limit: dto.limit.unwrap_or(DEFAULT_SCAN_LIMIT),
        // Absent means dry run — mutation is the explicit opt-in.
        dry_run: dto.dry_run.unwrap_or(true),
    };
    let actor = ApiActor {
        user_id: principal.0.user_id,
    };

    let report = ctx
        .provenance_misrejection_repair_use_case
        .run(request, actor)
        .await?;

    Ok((StatusCode::OK, axum::Json(RepairReportDto::from(report))).into_response())
}

#[cfg(test)]
mod tests {
    //! Handler-layer assertions. Tests use [`build_mock_ctx`] (the
    //! `AppContext`-shaped mock harness) — hand-rolling an `AppContext`
    //! here is an architect anti-pattern.

    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::Router;
    use chrono::{Duration, Utc};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{
        queue_entry_for, sample_artifact, sample_repository, MockIdentityProvider,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::events::{DomainEvent, PersistedEvent, ProvenanceVerified, StreamId};
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::provenance::SignerIdentity;
    use hort_domain::ports::user_repository::UserRepository;
    use hort_domain::types::ContentHash;

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const ROUTE: &str = "/admin/quarantine/provenance-misrejections/repair";

    fn principal_with_claims(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
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
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        )));
        let ctx = with_auth(
            &base,
            AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new()
            .nest("/admin", super::super::admin_routes())
            .with_state(ctx);
        (router, mocks)
    }

    /// `body: None` sends no body at all — the shape an operator gets
    /// from a bare `curl -XPOST`.
    fn repair_post(body: Option<&str>, principal: Option<CallerPrincipal>) -> Request<Body> {
        let builder = Request::post(ROUTE);
        let mut req = match body {
            Some(b) => builder
                .header("content-type", "application/json")
                .body(Body::from(b.to_owned()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    /// Seed the exact three-conjunct stranded state and make it the one
    /// row the curation-queue listing returns.
    fn seed_stranded(mocks: &MockPorts) -> Uuid {
        let mut artifact = sample_artifact(QuarantineStatus::Rejected);
        artifact.rejection_reason = None;
        artifact.quarantine_window_start = Some(Utc::now() - Duration::hours(2));
        let mut repo = sample_repository();
        repo.id = artifact.repository_id;
        let id = artifact.id;
        mocks.events.set_stream(
            &StreamId::artifact(id),
            vec![PersistedEvent {
                event_id: Uuid::new_v4(),
                stream_id: StreamId::artifact(id),
                stream_position: 0,
                global_position: 0,
                event: DomainEvent::ProvenanceVerified(ProvenanceVerified {
                    artifact_id: id,
                    content_hash: VALID_SHA256.parse::<ContentHash>().unwrap(),
                    backend: "cosign".into(),
                    signer: SignerIdentity {
                        issuer: "iss".into(),
                        san: "san".into(),
                    },
                    predicate_type: None,
                    cascaded_from: None,
                }),
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::system_actor(),
                event_version: 1,
                stored_at: Utc::now(),
            }],
        );
        mocks
            .curation_queue
            .set_result(Ok(vec![queue_entry_for(&artifact, &repo.key)]));
        mocks.artifacts.insert(artifact);
        mocks.repositories.insert(repo);
        id
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// **The safety default.** A bare POST with no body is a DRY RUN:
    /// 200 with the affected set and nothing committed. An operator who
    /// fires this by accident gets a list, not a state change.
    #[tokio::test]
    async fn a_bodyless_post_is_a_dry_run() {
        let (router, mocks) = harness();
        let id = seed_stranded(&mocks);

        let resp = router
            .oneshot(repair_post(None, Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["dry_run"], true);
        assert_eq!(body["scanned"], 1);
        assert_eq!(body["affected"][0]["artifact_id"], id.to_string());
        assert!(
            mocks.lifecycle.committed_transitions().is_empty(),
            "the default must not mutate"
        );
    }

    /// A body that omits `dry_run` is also a dry run — the default lives
    /// in the absent-field path too, not only the absent-body one.
    #[tokio::test]
    async fn a_body_without_dry_run_is_a_dry_run() {
        let (router, mocks) = harness();
        seed_stranded(&mocks);
        let resp = router
            .oneshot(repair_post(
                Some(r#"{"limit": 10}"#),
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["dry_run"], true);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// `dry_run: false` performs the repair: one transition committed,
    /// and the report says it was not a dry run.
    #[tokio::test]
    async fn dry_run_false_performs_the_repair() {
        let (router, mocks) = harness();
        let id = seed_stranded(&mocks);

        let resp = router
            .oneshot(repair_post(
                Some(r#"{"dry_run": false}"#),
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["dry_run"], false);
        assert_eq!(body["affected"][0]["artifact_id"], id.to_string());
        assert_eq!(body["failed"].as_array().unwrap().len(), 0);

        let transitions = mocks.lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        assert_eq!(
            transitions[0].0.quarantine_status,
            QuarantineStatus::Quarantined
        );
    }

    /// The repository filter reaches the listing.
    #[tokio::test]
    async fn repository_id_is_threaded_into_the_listing_filter() {
        let (router, mocks) = harness();
        let repo = Uuid::new_v4();
        let resp = router
            .oneshot(repair_post(
                Some(&format!(r#"{{"repository_id": "{repo}"}}"#)),
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let filters = mocks.curation_queue.recorded_filters();
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].repository_id, Some(repo));
        assert_eq!(filters[0].status, Some(QuarantineStatus::Rejected));
    }

    /// **Authority.** A caller without `admin` is refused by the
    /// extractor before the handler body runs — and, per ADR 0038, a
    /// service account can never hold that claim, so this cannot be
    /// driven from a pipeline.
    #[tokio::test]
    async fn a_non_admin_caller_is_403_and_nothing_runs() {
        let (router, mocks) = harness();
        seed_stranded(&mocks);
        let resp = router
            .oneshot(repair_post(
                Some(r#"{"dry_run": false}"#),
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
        assert!(
            mocks.curation_queue.recorded_filters().is_empty(),
            "the use case must not even be reached"
        );
    }

    /// A `curate` claim is explicitly NOT enough — pinned separately
    /// from the generic denial above because the sibling curation
    /// endpoints DO accept it, and this route deliberately does not.
    #[tokio::test]
    async fn the_curator_gate_does_not_open_this_route() {
        let (router, _mocks) = harness();
        for claims in [&["curate"][..], &["reader"][..], &[][..]] {
            let resp = router
                .clone()
                .oneshot(repair_post(None, Some(principal_with_claims(claims))))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "claims {claims:?} must not open the repair route"
            );
        }
    }

    /// An unknown field is a 400, not a silently-ignored typo — an
    /// operator who writes `{"dryrun": false}` must not get a dry run
    /// reported as a repair or vice versa.
    #[tokio::test]
    async fn an_unknown_field_is_rejected() {
        let (router, mocks) = harness();
        seed_stranded(&mocks);
        let resp = router
            .oneshot(repair_post(
                Some(r#"{"dryrun": false}"#),
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// An empty population is a successful, reportable outcome — the
    /// expected steady state once the population has been drained.
    #[tokio::test]
    async fn an_empty_population_is_200_with_an_empty_set() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(repair_post(
                Some(r#"{"dry_run": false}"#),
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["scanned"], 0);
        assert_eq!(body["affected"].as_array().unwrap().len(), 0);
        assert_eq!(body["scan_cap_hit"], false);
    }

    /// A listing failure surfaces as an opaque 500 — no internal detail
    /// leakage.
    #[tokio::test]
    async fn a_listing_failure_is_an_opaque_500() {
        let (router, mocks) = harness();
        mocks
            .curation_queue
            .set_result(Err(hort_domain::error::DomainError::Invariant(
                "queue unavailable".into(),
            )));
        let resp = router
            .oneshot(repair_post(None, Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        crate::error::assert_no_internal_leakage(StatusCode::INTERNAL_SERVER_ERROR, &bytes);
    }
}
