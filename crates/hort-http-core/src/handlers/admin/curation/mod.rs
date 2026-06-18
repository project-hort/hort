//! HTTP endpoints for curator-driven
//! decisions on quarantined / non-terminal artifacts AND the matching
//! read surface.
//!
//! All routes mount under `/api/v1/admin/curation/` and gate via
//! [`CurateOrAdminPrincipal`](crate::authz::CurateOrAdminPrincipal)
//! (so EITHER `Permission::Curate` OR `Permission::Admin` satisfies
//! the gate). The existing `/admin/*` admin routes keep their
//! [`AdminPrincipal`](crate::authz::AdminPrincipal) gate unchanged —
//! the curate-or-admin expansion is scoped to this sub-router ONLY.
//!
//! Routes:
//! - **Decision endpoints:**
//!   - `POST /api/v1/admin/curation/quarantine/:artifact_id/waive`
//!     ([`waive::post_waive`])
//!   - `POST /api/v1/admin/curation/quarantine/:artifact_id/block`
//!     ([`block::post_block`])
//!   - `POST /api/v1/admin/curation/block-versions`
//!     ([`block_versions::post_block_versions`])
//! - **Read endpoints:**
//!   - `GET  /api/v1/admin/curation/queue`
//!     ([`queue::get_queue`])
//!   - `GET  /api/v1/admin/curation/decisions`
//!     ([`decisions::get_decisions`])
//!   - `GET  /api/v1/admin/curation/exclusions`
//!     ([`exclusions::get_exclusions`])
//!
//! Body shapes and status-code mappings: see each module's handler doc.
//!
//! See `docs/architecture/how-to/curator-workflow.md` for the operator
//! workflow and ADR 0007 for the release-gate posture this surface
//! participates in.
//!
//! ## Mounting
//!
//! `hort-server::http::control_plane_routes` is the canonical mount site
//! (mirrors `hort-http-admin-tasks::router()`). The
//! [`curation_routes`] function exposes the sub-router; mount with
//! `.nest("/api/v1/admin/curation", curation_routes())`.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::context::AppContext;

pub mod block;
pub mod block_versions;
pub mod decisions;
pub mod exclusions;
pub mod queue;
pub mod waive;

/// Build the curation sub-router.
///
/// Returns a `Router<Arc<AppContext>>` carrying the three decision
/// endpoints (POST) plus the three read endpoints
/// (GET); the caller mounts it at `/api/v1/admin/curation/` (see
/// module docs). Every route is gated by
/// [`CurateOrAdminPrincipal`](crate::authz::CurateOrAdminPrincipal)
/// declared as a handler-level extractor; forgetting the extractor
/// leaves the handler with no validated principal in scope (compile
/// error rather than a 403 at runtime).
pub fn curation_routes() -> Router<Arc<AppContext>> {
    Router::new()
        .route("/quarantine/:artifact_id/waive", post(waive::post_waive))
        .route("/quarantine/:artifact_id/block", post(block::post_block))
        .route("/block-versions", post(block_versions::post_block_versions))
        .route("/queue", get(queue::get_queue))
        .route("/decisions", get(decisions::get_decisions))
        .route("/exclusions", get(exclusions::get_exclusions))
}

/// Maximum `limit` accepted by the three list endpoints
/// (`/queue`, `/decisions`, `/exclusions`). Mirrors the use-case-side
/// `MAX_QUEUE_LIMIT` private constant in `hort_app::use_cases::curation_use_case`
/// — the handler boundary check fires FIRST so an oversize value never
/// reaches the use case (defence-in-depth; the use case re-checks).
///
/// Listings are capped at 500 (bounded per-call work).
pub(crate) const MAX_LIST_LIMIT: u32 = 500;

/// Maximum byte length of the operator-supplied justification on every
/// decision endpoint. Mirrors the 512-byte cap enforced by
/// `CurationUseCase::validate_justification` (also matched in the
/// `ArtifactReleased` / `ArtifactRejected` domain event validators).
///
/// The handler enforces this BEFORE the use-case call (defence in
/// depth). A bypass that reached the
/// use case would still surface 400 via the same `DomainError::Validation`
/// path, so the gate is fail-safe-by-construction at both layers.
pub(crate) const MAX_JUSTIFICATION_BYTES: usize = 512;

/// Maximum number of versions accepted per `POST /api/v1/admin/curation/block-versions`
/// call. Mirrors `CurationUseCase::MAX_VERSIONS_PER_CALL` (bounded
/// per-call work, same shape as the queue listing cap).
/// Empty `versions` is also rejected at the handler boundary (`< 1`).
pub(crate) const MAX_VERSIONS_PER_CALL: usize = 100;

#[cfg(test)]
mod authz_scope_tests {
    //! The curate-or-admin gate applies ONLY to the three curation
    //! routes; existing `/admin/*` routes keep their
    //! [`AdminPrincipal`] gate.
    //!
    //! These tests mount BOTH the curation sub-router (gated by
    //! `CurateOrAdminPrincipal`) AND an existing admin route (gated by
    //! `AdminPrincipal`) on the same harness, then assert each route
    //! enforces its own gate independently.

    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::AuthContext;
    use crate::handlers::admin::admin_routes;
    use crate::test_support::{build_mock_ctx, with_auth};

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

    /// Build a router that mounts BOTH the legacy admin tree (under
    /// `/admin`) AND the new curation sub-router (under
    /// `/api/v1/admin/curation`). Tests drive both surfaces with the
    /// same caller to assert per-route gate independence.
    fn harness_with_both_mounts() -> Router {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics);
        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        // Seed a global Curate-claim grant so a `claims = ["curate"]`
        // caller is admitted by the `CurateOrAdminPrincipal` extractor.
        // The `admin` claim still short-circuits the evaluator (no
        // grant needed) — those tests don't rely on this seed.
        let curate_grant = PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["curate".into()]),
            repository_id: None,
            permission: Permission::Curate,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        };
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
            curate_grant,
        ])));
        let ctx = with_auth(
            &base,
            AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        Router::new()
            .nest("/admin", admin_routes())
            .nest("/api/v1/admin/curation", super::curation_routes())
            .with_state(ctx)
    }

    fn inject(mut req: Request<Body>, principal: CallerPrincipal) -> Request<Body> {
        crate::middleware::auth::test_support::inject_principal(&mut req, principal);
        req
    }

    /// A Curate-only caller (no `admin` claim) hits the WAIVE route →
    /// reaches the handler body (the use case then 404s on the bogus
    /// id, but the gate is what we're asserting — anything ≠ 403
    /// proves the extractor admitted the caller).
    #[tokio::test]
    async fn curate_caller_passes_curation_gate_but_existing_admin_gate_denies() {
        let router = harness_with_both_mounts();

        // Curate-only caller hits the curation WAIVE route → NOT 403.
        let waive_req = inject(
            Request::post(format!(
                "/api/v1/admin/curation/quarantine/{id}/waive",
                id = Uuid::new_v4()
            ))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"justification":"valid"}"#))
            .unwrap(),
            principal_with_claims(&["curate"]),
        );
        let resp = router.clone().oneshot(waive_req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "CurateOrAdminPrincipal must admit a curate-only caller"
        );

        // Same caller hitting the existing admin route → 403 (the
        // AdminPrincipal extractor rejects). Pins that we did NOT
        // broaden the global admin gate.
        let admin_req = inject(
            Request::get("/admin/repositories/some-key")
                .body(Body::empty())
                .unwrap(),
            principal_with_claims(&["curate"]),
        );
        let resp = router.oneshot(admin_req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "existing admin gate must still reject a curate-only caller"
        );
    }

    /// Admin caller (no `curate` claim) passes BOTH gates — confirms
    /// the admin authority remains a strict superset.
    #[tokio::test]
    async fn admin_caller_passes_both_gates() {
        let router = harness_with_both_mounts();

        // Admin hits the curation route → admitted (anything ≠ 403).
        let waive_req = inject(
            Request::post(format!(
                "/api/v1/admin/curation/quarantine/{id}/waive",
                id = Uuid::new_v4()
            ))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"justification":"v"}"#))
            .unwrap(),
            principal_with_claims(&["admin"]),
        );
        let resp = router.clone().oneshot(waive_req).await.unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        // Admin hits the existing admin route → admitted.
        let admin_req = inject(
            Request::get("/admin/repositories/some-key")
                .body(Body::empty())
                .unwrap(),
            principal_with_claims(&["admin"]),
        );
        let resp = router.oneshot(admin_req).await.unwrap();
        // The admin handler returns 404 for the unseeded key, NOT 403.
        // Pin "not 403" so a future regression that demotes the
        // AdminPrincipal extractor to deny admins is loud.
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Caller with neither `curate` nor `admin` → 403 on the curation
    /// route. Pins the deny-by-default posture.
    #[tokio::test]
    async fn unprivileged_caller_denied_on_curation_gate() {
        let router = harness_with_both_mounts();

        let waive_req = inject(
            Request::post(format!(
                "/api/v1/admin/curation/quarantine/{id}/waive",
                id = Uuid::new_v4()
            ))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"justification":"v"}"#))
            .unwrap(),
            principal_with_claims(&["reader"]),
        );
        let resp = router.oneshot(waive_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
