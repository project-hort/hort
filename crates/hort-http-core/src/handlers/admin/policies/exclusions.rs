//! HTTP write surface for scan-policy
//! exclusions.
//!
//! Two endpoints, both gated by [`CurateOrAdminPrincipal`]:
//!
//! - `POST   /api/v1/admin/policies/:policy_id/exclusions`
//!   ([`post_exclusion`])
//! - `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`
//!   ([`delete_exclusion`])
//!
//! Both delegate to the existing
//! `PolicyUseCase::{add_exclusion, remove_exclusion}` methods. The
//! use-case signature is `(cmd, actor: Actor)` and contains NO
//! permission check — the gitops apply pipeline continues to call the
//! same methods with `Actor::Gitops`. The HTTP layer is the single
//! permission source of truth for the user-driven surface (see module
//! docs in the parent `mod.rs`).
//!
//! ## DELETE `:cve_id` resolution
//!
//! The URL carries `:cve_id` (e.g. `CVE-2026-0001`). The use case
//! takes an `exclusion_id` (UUID) — the
//! curator-facing identifier is the CVE, the internal projection-key
//! is the exclusion_id. The handler resolves CVE → exclusion_id by
//! reading `policy_projections.list_exclusions_for_policy(policy_id)`
//! and matching `cve_id`. A missing match surfaces as 404 BEFORE the
//! use case is touched; this also closes the otherwise-confusing
//! `Validation(policy not exist)` 400 (from the use case) that would
//! fire if a caller URL-encoded a stale policy id.
//!
//! Status-code mapping:
//! - **POST** — `201 Created` with `{ "exclusion_id": "<uuid>" }` on
//!   success; `400` (validation — empty reason / oversize / bad
//!   cve_id format / policy id mis-parsed); `403` (extractor); `404`
//!   (policy not found — note: the use case currently emits this as
//!   `Validation` so it would surface as 400; the handler runs a
//!   `policy_projections.find_by_id` pre-check that promotes the
//!   missing-policy case to 404 BEFORE the use case is touched);
//!   `409` (event-store conflict); `500` (infrastructure)
//! - **DELETE** — `204 No Content` on success; `400` / `403` / `404`
//!   / `409` / `500` (same shape)
//!
//! **`#[tracing::instrument]` deliberately WITHOUT `err`** — denial
//! and validation outcomes are info-level events (architect rule);
//! promoting them to `err` would surface every 4xx as ERROR in
//! operator logs. Mirrors the curation decision handlers.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::{AddExclusionCommand, RemoveExclusionCommand};
use hort_domain::error::DomainError;
use hort_domain::events::{Actor, ApiActor, PolicyScope};

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::MAX_JUSTIFICATION_BYTES;

// ---------------------------------------------------------------------------
// Wire-format DTOs
// ---------------------------------------------------------------------------

/// Wire-format `scope` discriminator for [`AddExclusionRequestDto`].
///
/// Maps onto the domain [`PolicyScope`] via `ScopeDto::into_domain`.
/// Defined as a handler-local DTO because the domain type's default
/// serde shape leaks the Rust enum representation
/// (`{"Repository":"<uuid>"}` etc.) — the stable wire surface uses a
/// tagged-union shape:
///
/// ```json
/// { "kind": "global" }
/// { "kind": "repository", "repository_id": "<uuid>" }
/// ```
///
/// Mirrors the `scope` projection in handlers/admin/curation/exclusions.rs
/// (`CurationExclusionEntryDto`), so the read and write surfaces are
/// byte-symmetric.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeDto {
    Global,
    Repository { repository_id: Uuid },
}

impl ScopeDto {
    fn into_domain(self) -> PolicyScope {
        match self {
            ScopeDto::Global => PolicyScope::Global,
            ScopeDto::Repository { repository_id } => PolicyScope::Repository(repository_id),
        }
    }
}

/// Request body for `POST /api/v1/admin/policies/:policy_id/exclusions`.
///
/// Domain types (`AddExclusionCommand`, `PolicyScope`) are NEVER
/// deserialised directly from request input (architect anti-pattern A
/// — DTO discipline). This struct carries only primitive types and
/// the [`ScopeDto`] wire-shape; the handler maps it into
/// [`AddExclusionCommand`] inside its body.
///
/// `reason` is the operator-supplied justification recorded on
/// `ExclusionAdded.reason`. MUST be non-empty and ≤ 512 bytes — the
/// handler enforces both gates before the use-case call.
#[derive(Debug, Deserialize)]
pub struct AddExclusionRequestDto {
    pub cve_id: String,
    #[serde(default)]
    pub package_pattern: Option<String>,
    pub scope: ScopeDto,
    pub reason: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response body for `POST /api/v1/admin/policies/:policy_id/exclusions`.
///
/// The exclusion_id is server-minted (see `PolicyUseCase::add_exclusion`
/// — `Uuid::new_v4()` inside the use case) and returned so the caller
/// can reference it on a follow-up DELETE if the projection-side CVE
/// lookup is undesirable.
#[derive(Debug, Serialize)]
pub struct AddExclusionResponseDto {
    pub exclusion_id: Uuid,
}

/// Optional request body for
/// `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`.
///
/// The DELETE is RESTfully body-optional; an absent body is treated
/// the same as `{ "reason": "" }` (which is then rejected as empty by
/// the same handler gate that catches an empty POST reason). The
/// reason rides the emitted `ExclusionRemoved.reason` payload — the
/// curator's audit anchor for the removal.
#[derive(Debug, Deserialize, Default)]
pub struct RemoveExclusionRequestDto {
    #[serde(default)]
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/admin/policies/:policy_id/exclusions`.
///
/// Validates the request body at the boundary, constructs an
/// [`AddExclusionCommand`] from the DTO + path parameter, builds the
/// [`Actor::Api`] from the validated principal, and delegates to
/// `PolicyUseCase::add_exclusion`. The use case mints the
/// `exclusion_id` server-side; the response body carries it back so
/// the caller doesn't need a follow-up GET to learn the value.
///
/// See module docs for the full status-code map.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn post_exclusion(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(policy_id): Path<Uuid>,
    Json(body): Json<AddExclusionRequestDto>,
) -> Result<Response, ApiError> {
    // Justification cap — 512-byte, same as the curation decision endpoints. The
    // domain `ExclusionAdded::validate` enforces a wider 4096-byte
    // cap on the underlying `reason`; this handler tightens the HTTP
    // bound to 512 to match every other curator-facing justification
    // field. Trim + empty check first so whitespace-only input is the
    // same UX failure as missing.
    let trimmed_reason = body.reason.trim();
    if trimmed_reason.is_empty() {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            "reason must not be empty".into(),
        ))));
    }
    if body.reason.len() > MAX_JUSTIFICATION_BYTES {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "reason exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
                body.reason.len()
            ),
        ))));
    }

    // Pre-check policy existence so the response surface is 404 (not
    // the use case's 400-via-Validation) for an unknown policy. This
    // is the same shape the curation read endpoints use for unknown
    // entities; matches operator expectations of REST semantics.
    let projection = ctx.policy_projections.find_by_id(policy_id).await?;
    if projection.is_none() {
        return Err(ApiError(AppError::Domain(DomainError::NotFound {
            entity: "ScanPolicy",
            id: policy_id.to_string(),
        })));
    }

    let cmd = AddExclusionCommand {
        policy_id,
        cve_id: body.cve_id,
        package_pattern: body.package_pattern,
        scope: body.scope.into_domain(),
        reason: body.reason,
        expires_at: body.expires_at,
    };

    let actor = Actor::Api(ApiActor {
        user_id: principal.0.user_id,
    });

    let exclusion_id = ctx.policy_use_case.add_exclusion(cmd, actor).await?;

    Ok((
        StatusCode::CREATED,
        Json(AddExclusionResponseDto { exclusion_id }),
    )
        .into_response())
}

/// `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`.
///
/// Resolves the CVE → exclusion_id by reading the policy's exclusion
/// projection, then delegates to `PolicyUseCase::remove_exclusion`.
/// A missing CVE surfaces as 404 BEFORE the use case is touched (so
/// the use-case's policy-existence guard is reached only when a
/// matching exclusion's `policy_id` lookup confirms the policy
/// exists).
///
/// See module docs for the full status-code map.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn delete_exclusion(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path((policy_id, cve_id)): Path<(Uuid, String)>,
    body: Option<Json<RemoveExclusionRequestDto>>,
) -> Result<Response, ApiError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let trimmed_reason = body.reason.trim();
    if trimmed_reason.is_empty() {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            "reason must not be empty".into(),
        ))));
    }
    if body.reason.len() > MAX_JUSTIFICATION_BYTES {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "reason exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
                body.reason.len()
            ),
        ))));
    }

    // Bounded CVE identifier — defence-in-depth so a pathological URL
    // doesn't bloat downstream logs / projection scans. Mirrors the
    // domain-layer `MAX_CVE_ID_LEN = 64` constant on
    // `ExclusionAdded::validate`. We don't try to parse CVE-XXXX-YYYY
    // structurally — operators sometimes use vendor advisory IDs that
    // don't match the canonical shape.
    if cve_id.is_empty() || cve_id.len() > 64 {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!("invalid cve_id length: {}", cve_id.len()),
        ))));
    }

    // Resolve CVE → exclusion_id via the projection. A missing match
    // is 404 (no exclusion with that CVE on this policy). The
    // projection port's contract is `list_exclusions_for_policy`
    // returns ONLY rows for `policy_id`, so the linear scan here is
    // bounded by the number of exclusions on the policy (typically
    // single digits in typical deployments).
    let exclusions = ctx
        .policy_projections
        .list_exclusions_for_policy(policy_id)
        .await?;
    let Some(found) = exclusions.into_iter().find(|e| e.cve_id == cve_id) else {
        return Err(ApiError(AppError::Domain(DomainError::NotFound {
            entity: "Exclusion",
            id: format!("policy={policy_id} cve={cve_id}"),
        })));
    };

    let cmd = RemoveExclusionCommand {
        policy_id,
        exclusion_id: found.exclusion_id,
        reason: body.reason,
    };

    let actor = Actor::Api(ApiActor {
        user_id: principal.0.user_id,
    });

    ctx.policy_use_case.remove_exclusion(cmd, actor).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    //! Handler-layer assertions for each status code on both endpoints,
    //! plus a regression test pinning that a curator-driven POST calls
    //! the use case with the same shape an admin-driven POST would (the
    //! use-case-side re-evaluation cascade is itself exercised by
    //! `policy_use_case.rs::tests`; the HTTP wiring just must not drop
    //! attribution).
    //!
    //! All tests use [`build_mock_ctx`] (architect rule — no
    //! hand-rolled `AppContext`).

    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::scan_policy::{
        ExclusionProjection, NegligibleAction, ProvenanceMode, ScanPolicyProjection,
        SeverityThreshold,
    };
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

    // -----------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------

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
            .nest("/api/v1/admin/policies", super::super::policies_routes())
            .with_state(ctx);
        (router, mocks)
    }

    /// Seed a non-archived scan policy onto the mock projections so
    /// the handler's `find_by_id` pre-check + the use-case's
    /// `find_by_id` lookup both succeed. Returns the seeded policy id.
    fn seed_policy(mocks: &MockPorts) -> Uuid {
        let policy_id = Uuid::new_v4();
        let now = Utc::now();
        mocks.policy_projections.insert(ScanPolicyProjection {
            policy_id,
            name: format!("test-policy-{policy_id}"),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 0,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".into()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        });
        policy_id
    }

    /// Seed an exclusion for the given policy → returns
    /// (exclusion_id, cve_id). Used by the DELETE tests.
    fn seed_exclusion(mocks: &MockPorts, policy_id: Uuid, cve: &str) -> (Uuid, String) {
        let exclusion_id = Uuid::new_v4();
        mocks
            .policy_projections
            .insert_exclusion(ExclusionProjection {
                exclusion_id,
                policy_id,
                cve_id: cve.to_string(),
                package_pattern: None,
                scope: PolicyScope::Global,
                reason: "seeded".into(),
                added_by_actor_id: None,
                expires_at: None,
            });
        (exclusion_id, cve.to_string())
    }

    fn post_req(policy_id: Uuid, body: &str, p: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post(format!("/api/v1/admin/policies/{policy_id}/exclusions"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn delete_req(
        policy_id: Uuid,
        cve: &str,
        body: &str,
        p: Option<CallerPrincipal>,
    ) -> Request<Body> {
        let mut req = Request::delete(format!(
            "/api/v1/admin/policies/{policy_id}/exclusions/{cve}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    // -----------------------------------------------------------------
    // POST /api/v1/admin/policies/:policy_id/exclusions
    // -----------------------------------------------------------------

    /// Happy path: curator caller + valid body + seeded policy → 201
    /// CREATED with `{exclusion_id}` body. The use case mints a fresh
    /// UUID and the response surface carries it back.
    #[tokio::test]
    async fn post_exclusion_happy_path_returns_201_with_exclusion_id() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);

        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": "upstream advisory withdrawn"
        })
        .to_string();

        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let returned = v["exclusion_id"]
            .as_str()
            .expect("exclusion_id must be present as a string");
        let returned = Uuid::parse_str(returned).expect("must parse as UUID");

        // Projection upsert confirms the use case ran with the
        // expected payload. The mock's `insert_exclusion` is also
        // exercised by the use-case-internal upsert.
        let upserts = mocks.policy_projections.exclusion_upserts();
        // The use case writes exactly one ExclusionProjection upsert
        // per add_exclusion call. We assert on the recorded upsert
        // because it's the cleanest signal the use case ran the full
        // happy path (event-store append + projection write).
        assert!(
            upserts.iter().any(|e| e.exclusion_id == returned
                && e.cve_id == "CVE-2026-1234"
                && e.reason == "upstream advisory withdrawn"),
            "expected upsert for newly-minted exclusion id, got: {upserts:?}",
        );
    }

    /// Admin caller (no Curate grant) also passes — confirms the
    /// either-OR gate semantics carry through to the POST surface.
    #[tokio::test]
    async fn post_exclusion_admin_caller_also_returns_201() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-9999",
            "scope": { "kind": "global" },
            "reason": "admin override"
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    /// Regression test — a curator-driven POST and an admin-driven POST
    /// produce the same use-case effect: one
    /// exclusion row appended to the projection, with the body's
    /// reason verbatim. The use-case-side re-evaluation cascade is
    /// exercised by `policy_use_case.rs::tests`; the HTTP wiring just
    /// must not drop attribution.
    ///
    /// Pins: (1) both paths reach the use case (no extractor
    /// short-circuit), (2) both produce one new projection row,
    /// (3) the row carries the reason text verbatim regardless of
    /// caller role.
    #[tokio::test]
    async fn curator_and_admin_drive_identical_use_case_call() {
        // Curator path
        let (router_c, mocks_c) = harness();
        let policy_c = seed_policy(&mocks_c);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-0001",
            "scope": { "kind": "global" },
            "reason": "re-eval cascade regression test"
        })
        .to_string();
        let resp = router_c
            .oneshot(post_req(
                policy_c,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let upserts_c = mocks_c.policy_projections.exclusion_upserts();
        assert_eq!(upserts_c.len(), 1);
        assert_eq!(upserts_c[0].cve_id, "CVE-2026-0001");
        assert_eq!(upserts_c[0].reason, "re-eval cascade regression test");

        // Admin path on a SEPARATE harness — same body, same outcome.
        let (router_a, mocks_a) = harness();
        let policy_a = seed_policy(&mocks_a);
        let resp = router_a
            .oneshot(post_req(
                policy_a,
                &body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let upserts_a = mocks_a.policy_projections.exclusion_upserts();
        assert_eq!(upserts_a.len(), 1);
        // The HTTP wiring drops nothing: cve_id, reason, scope all
        // arrive at the use case verbatim regardless of caller role.
        assert_eq!(upserts_a[0].cve_id, upserts_c[0].cve_id);
        assert_eq!(upserts_a[0].reason, upserts_c[0].reason);
        assert_eq!(upserts_a[0].scope, upserts_c[0].scope);
    }

    /// Empty `reason` → 400.
    #[tokio::test]
    async fn post_exclusion_empty_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": ""
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.policy_projections.exclusion_upserts().is_empty(),
            "validation must fire before the use case is called",
        );
    }

    /// Whitespace-only `reason` → 400 (same UX as empty).
    #[tokio::test]
    async fn post_exclusion_whitespace_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": "   \n\t  "
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 513-byte `reason` → 400. One byte over the 512-byte cap.
    #[tokio::test]
    async fn post_exclusion_oversize_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let oversize = "x".repeat(513);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": oversize
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Unauthorised caller (no curate, no admin) → 403 via the
    /// `CurateOrAdminPrincipal` extractor short-circuit; the use case
    /// is never reached. Body shape matches the extractor's 403 denial.
    #[tokio::test]
    async fn post_exclusion_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": "valid"
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], br#"{"error":"insufficient permissions"}"#);
        assert!(
            mocks.policy_projections.exclusion_upserts().is_empty(),
            "extractor short-circuit must not reach the use case",
        );
    }

    /// Unknown policy → 404. The handler's pre-check fires before the
    /// use case; the projection never grows.
    #[tokio::test]
    async fn post_exclusion_unknown_policy_returns_404() {
        let (router, mocks) = harness();
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": "valid"
        })
        .to_string();
        let unknown = Uuid::new_v4();
        let resp = router
            .oneshot(post_req(
                unknown,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            mocks.policy_projections.exclusion_upserts().is_empty(),
            "404 pre-check must not reach the use case",
        );
    }

    /// Path UUID parse failure → 400 (axum's `Path<Uuid>` extractor
    /// surfaces this before the handler body runs). Pins the URI
    /// shape rather than the response body — axum's extractor
    /// formatting is the canonical surface.
    #[tokio::test]
    async fn post_exclusion_malformed_policy_id_returns_400() {
        let (router, _mocks) = harness();
        let mut req = Request::post("/api/v1/admin/policies/not-a-uuid/exclusions")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"cve_id":"CVE-2026-1234","scope":{"kind":"global"},"reason":"v"}"#,
            ))
            .unwrap();
        crate::middleware::auth::test_support::inject_principal(
            &mut req,
            principal_with_claims(&["curate"]),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 409 — wire-shape pin. The mock event store doesn't synthesise
    /// concurrent-append conflicts; the `ApiError::into_response`
    /// unit tests (`error.rs::tests::conflict_is_409`) are the
    /// canonical pin for the `Conflict → 409` mapping. We mirror the
    /// curation handler's approach: pin the boundary here so a
    /// future regression that changes the conflict mapping is loud.
    #[tokio::test]
    async fn post_exclusion_conflict_wire_shape_is_pinned_by_apierror() {
        let api_err = ApiError(AppError::Domain(DomainError::Conflict(
            "stream version mismatch".into(),
        )));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    /// 500 — wire-shape pin for infrastructure failures. Same
    /// rationale as the conflict pin above.
    #[tokio::test]
    async fn post_exclusion_repository_error_wire_shape_is_500() {
        let api_err = ApiError(AppError::Repository("db down".into()));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Scope `kind: repository` round-trips through the DTO mapping
    /// and reaches the use case with the expected
    /// `PolicyScope::Repository(uuid)`. Pins the alternate scope
    /// projection so a regression that loses the variant trips here.
    #[tokio::test]
    async fn post_exclusion_repository_scope_threads_through() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let repo_id = Uuid::new_v4();
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "repository", "repository_id": repo_id },
            "reason": "valid"
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let upserts = mocks.policy_projections.exclusion_upserts();
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].scope, PolicyScope::Repository(repo_id));
    }

    // -----------------------------------------------------------------
    // DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id
    // -----------------------------------------------------------------

    /// Happy path: curator + seeded exclusion → 204 NO CONTENT and
    /// the projection records exactly one delete for the resolved
    /// exclusion_id (the use case's `remove_exclusion` invokes
    /// `delete_exclusion` on the projection port after the
    /// event-store append).
    #[tokio::test]
    async fn delete_exclusion_happy_path_returns_204() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-5678");

        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"superseded by upstream patch"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let deletes = mocks.policy_projections.exclusion_deletes();
        assert_eq!(deletes.len(), 1);
        assert_eq!(
            deletes[0], eid,
            "the CVE → exclusion_id resolution must drive the use case with the seeded id",
        );
    }

    /// Admin caller also passes the gate.
    #[tokio::test]
    async fn delete_exclusion_admin_caller_also_returns_204() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-1111");
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"admin override"}"#,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    /// Empty `reason` → 400.
    #[tokio::test]
    async fn delete_exclusion_empty_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-2222");
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":""}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.policy_projections.exclusion_deletes().is_empty(),
            "validation must fire BEFORE the use case runs (no delete recorded)",
        );
    }

    /// Missing body entirely → 400 (treated as empty reason).
    #[tokio::test]
    async fn delete_exclusion_no_body_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-3333");
        let mut req = Request::delete(format!(
            "/api/v1/admin/policies/{policy_id}/exclusions/{cve}"
        ))
        .body(Body::empty())
        .unwrap();
        crate::middleware::auth::test_support::inject_principal(
            &mut req,
            principal_with_claims(&["curate"]),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 513-byte reason → 400.
    #[tokio::test]
    async fn delete_exclusion_oversize_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-4444");
        let oversize = "x".repeat(513);
        let body = format!(r#"{{"reason":"{oversize}"}}"#);
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Unauthorised caller → 403 via the extractor.
    #[tokio::test]
    async fn delete_exclusion_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-5555");
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"valid"}"#,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], br#"{"error":"insufficient permissions"}"#);
    }

    /// Unknown CVE on a known policy → 404. The handler's
    /// `list_exclusions_for_policy` returns no match.
    #[tokio::test]
    async fn delete_exclusion_unknown_cve_returns_404() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let resp = router
            .oneshot(delete_req(
                policy_id,
                "CVE-2026-NONE",
                r#"{"reason":"valid"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Unknown policy → 404. With no exclusions on that policy_id,
    /// `list_exclusions_for_policy` returns empty and the handler
    /// surfaces 404.
    #[tokio::test]
    async fn delete_exclusion_unknown_policy_returns_404() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(delete_req(
                Uuid::new_v4(),
                "CVE-2026-1234",
                r#"{"reason":"valid"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Oversize CVE id (65 chars) → 400.
    #[tokio::test]
    async fn delete_exclusion_oversize_cve_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let cve = "C".repeat(65);
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"valid"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 409 / 500 wire-shape pins — same rationale as on POST.
    #[tokio::test]
    async fn delete_exclusion_conflict_wire_shape_is_pinned_by_apierror() {
        let api_err = ApiError(AppError::Domain(DomainError::Conflict(
            "stream version mismatch".into(),
        )));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn delete_exclusion_repository_error_wire_shape_is_500() {
        let api_err = ApiError(AppError::Repository("db down".into()));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
