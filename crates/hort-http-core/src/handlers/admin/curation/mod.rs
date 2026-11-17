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
//!   - `POST /api/v1/admin/curation/quarantine/:artifact_id/reevaluate`
//!     ([`reevaluate::post_reevaluate`])
//!   - `POST /api/v1/admin/curation/block-versions`
//!     ([`block_versions::post_block_versions`])
//!   - `POST /api/v1/admin/curation/block-digests`
//!     ([`block_digests::post_block_digests`])
//!   - `POST /api/v1/admin/curation/waive-versions`
//!     ([`waive_bulk::post_waive_versions`])
//!   - `POST /api/v1/admin/curation/waive-digests`
//!     ([`waive_bulk::post_waive_digests`])
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
//! ## The bulk verbs are not symmetric, and that is deliberate
//!
//! `block-versions` / `block-digests` are **fail-safe**: they cap at
//! [`MAX_VERSIONS_PER_CALL`] entries and continue on error, so a call
//! blocks what it resolved and reports what it did not.
//! `waive-versions` / `waive-digests` are **fail-open**: they cap at
//! [`MAX_WAIVE_ENTRIES_PER_CALL`] and are all-or-nothing, so one
//! unreadable entry aborts the whole batch with `409` and zero releases.
//!
//! The reason is `ArtifactReleased`: it is history that cannot be
//! retracted, while a block the curator did not mean is reversible by the
//! same curator a minute later. A future editor tidying the two
//! contracts into one shape would be removing the asymmetry on purpose
//! — do not.
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

use hort_app::error::AppError;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::error::DomainError;

use crate::context::AppContext;
use crate::error::ApiError;

pub mod block;
pub mod block_digests;
pub mod block_versions;
pub mod decisions;
pub mod exclusions;
pub mod queue;
pub mod reevaluate;
pub mod waive;
pub mod waive_bulk;

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
        .route("/quarantine/{artifact_id}/waive", post(waive::post_waive))
        .route("/quarantine/{artifact_id}/block", post(block::post_block))
        .route(
            "/quarantine/{artifact_id}/reevaluate",
            post(reevaluate::post_reevaluate),
        )
        .route("/block-versions", post(block_versions::post_block_versions))
        .route("/block-digests", post(block_digests::post_block_digests))
        .route("/waive-versions", post(waive_bulk::post_waive_versions))
        .route("/waive-digests", post(waive_bulk::post_waive_digests))
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

/// Maximum number of entries accepted per bulk **block** call
/// (`block-versions`, `block-digests`). Mirrors
/// `CurationUseCase::MAX_VERSIONS_PER_CALL` (bounded per-call work, same
/// shape as the queue listing cap). An empty list is also rejected at the
/// handler boundary (`< 1`).
pub(crate) const MAX_VERSIONS_PER_CALL: usize = 100;

/// Maximum number of entries accepted per bulk **waive** call
/// (`waive-versions`, `waive-digests`). Mirrors
/// `CurationUseCase::MAX_WAIVE_ENTRIES_PER_CALL`, and is deliberately a
/// quarter of the block cap above — see this module's docs for why the
/// two bulk verbs are not symmetric.
///
/// Enforced here *and* in the use case, exactly as the block cap is: a
/// cap that lived only at the handler would be bypassable by every other
/// caller of `CurationUseCase`.
pub(crate) const MAX_WAIVE_ENTRIES_PER_CALL: usize = 25;

/// The operator-supplied justification boundary check shared by every
/// decision endpoint: non-empty after trimming, and within
/// [`MAX_JUSTIFICATION_BYTES`].
///
/// Trimming is intentional — whitespace-only input is the same UX failure
/// as empty (an operator copy-pasting a stray newline), and an auditor
/// reading `"    "` as a justification is the same negative outcome as a
/// missing one. The length check is on the **untrimmed** bytes, because
/// that is the string the event carries.
pub(crate) fn check_justification(justification: &str) -> Result<(), ApiError> {
    if justification.trim().is_empty() {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            "justification must not be empty".into(),
        ))));
    }
    if justification.len() > MAX_JUSTIFICATION_BYTES {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "justification exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
                justification.len()
            ),
        ))));
    }
    Ok(())
}

/// The entry-count boundary check shared by every bulk endpoint:
/// non-empty, and within the verb's own `max`.
///
/// `field` names the request field in the message (`versions` /
/// `digests`) so the operator is told which list was wrong; `max` is
/// passed rather than read from a constant because the two bulk verbs
/// cap differently on purpose.
pub(crate) fn check_entry_count(field: &str, len: usize, max: usize) -> Result<(), ApiError> {
    if len == 0 {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!("{field} must not be empty"),
        ))));
    }
    if len > max {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!("{field} length {len} exceeds {max} cap"),
        ))));
    }
    Ok(())
}

/// The `CallerPrivileges` every curation handler hands the use case.
///
/// [`CurateOrAdminPrincipal`](crate::authz::CurateOrAdminPrincipal) has
/// already proved the caller carries Curate **or** Admin, so
/// `is_curator = true` makes the use case's own
/// `require_curate_or_admin()` a no-op. The use-case gate stays engaged
/// all the same: it is the canonical info-log and metric-emission site,
/// and it is what a non-HTTP caller meets.
pub(crate) fn curator_privileges() -> CallerPrivileges {
    CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    }
}

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
