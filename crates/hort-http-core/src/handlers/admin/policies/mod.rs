//! HTTP write surface for finding-exclusions
//! on a scan policy.
//!
//! All routes mount under `/api/v1/admin/policies/` and gate via
//! [`CurateOrAdminPrincipal`](crate::authz::CurateOrAdminPrincipal)
//! (so EITHER `Permission::Curate` OR `Permission::Admin` satisfies
//! the gate). The existing `/admin/*` admin routes keep their
//! [`AdminPrincipal`](crate::authz::AdminPrincipal) gate unchanged —
//! the curate-or-admin expansion is scoped to this sub-router ONLY
//! (mirrors the placement under `/api/v1/admin/curation/`).
//!
//! Routes:
//! - `POST   /api/v1/admin/policies/:policy_id/exclusions`
//!   ([`exclusions::post_exclusion`])
//! - `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`
//!   ([`exclusions::delete_exclusion`])
//!
//! Body shapes and status-code mappings: see each handler doc.
//!
//! ## Use-case signature is permission-neutral
//!
//! `PolicyUseCase::{add_exclusion, remove_exclusion}` take `(cmd,
//! actor: Actor)` and contain NO permission check. The gitops apply
//! pipeline (`apply_config_use_case.rs`) calls them with
//! `Actor::Gitops(...)` and bypasses the HTTP edge naturally. The
//! HTTP layer is therefore the single permission source of truth for
//! the user-driven exclusion surface: the `CurateOrAdminPrincipal`
//! extractor enforces curate-or-admin BEFORE the handler body runs,
//! then the handler constructs `Actor::Api(...)` from the validated
//! principal. This approach keeps `apply_config_use_case` working with
//! no port-contract change.
//!
//! See `docs/architecture/how-to/curator-workflow.md` for the operator
//! workflow.

use std::sync::Arc;

use axum::routing::{delete, post};
use axum::Router;

use crate::context::AppContext;

pub mod exclusions;

/// Build the policies sub-router.
///
/// Returns a `Router<Arc<AppContext>>` carrying the two HTTP
/// exclusion-write endpoints (POST add, DELETE remove). The caller
/// mounts it at `/api/v1/admin/policies/` (see module docs). Every
/// route is gated by
/// [`CurateOrAdminPrincipal`](crate::authz::CurateOrAdminPrincipal)
/// declared as a handler-level extractor; forgetting the extractor
/// leaves the handler with no validated principal in scope (compile
/// error rather than a 403 at runtime).
pub fn policies_routes() -> Router<Arc<AppContext>> {
    Router::new()
        .route("/:policy_id/exclusions", post(exclusions::post_exclusion))
        .route(
            "/:policy_id/exclusions/:cve_id",
            delete(exclusions::delete_exclusion),
        )
}

/// Maximum byte length of the operator-supplied justification on the
/// exclusion-write endpoints. Mirrors the 512-byte cap
/// enforced by the curation decision handlers (and the `ArtifactReleased`
/// / `ArtifactRejected` domain event validators).
///
/// The handler enforces this BEFORE the use-case call (defence in
/// depth). The use case itself
/// does not currently re-check this exact cap (the underlying
/// `ExclusionAdded::validate` enforces a wider 4096-byte cap on
/// `reason`), so the handler is the active gate at 512 bytes for the
/// HTTP surface — a tighter UX bound that aligns with every other
/// curator-facing justification field.
pub(crate) const MAX_JUSTIFICATION_BYTES: usize = 512;
