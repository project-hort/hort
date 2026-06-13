//! Route assembly for the security-score REST surface.
//!
//! Two routes mounted under no prefix — the caller (`hort-server::http`)
//! is responsible for nesting these under `/api/v1`. Keeping the path
//! prefix at the composition layer matches the per-format-crate
//! pattern (ADR 0008): the route shape lives with the handlers, the
//! absolute-URL contract lives with the binary.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use hort_http_core::context::AppContext;

use crate::handlers::{get_repo_score, list_repo_scores, rescan};

/// Build the security-score route subtree. Mount under `/api/v1`:
///
/// ```text
/// // in hort-server::http
/// router.nest("/api/v1", hort_http_admin_security::router::routes())
/// ```
///
/// Resulting absolute paths:
///
/// - `GET /api/v1/repositories/:name/security-score`
/// - `GET /api/v1/security-score`
/// - `POST /api/v1/artifacts/:id/rescan`
pub fn routes() -> Router<Arc<AppContext>> {
    Router::new()
        .route("/repositories/:name/security-score", get(get_repo_score))
        .route("/security-score", get(list_repo_scores))
        // Per-artifact "rescan now" trigger. Distinct from the admin-task
        // surface (`/api/v1/admin/tasks/{kind}`): this endpoint targets a
        // specific artifact and gates on `Permission::Write` against that
        // artifact's parent repo, NOT `Permission::AdminTaskInvoke`.
        .route("/artifacts/:id/rescan", post(rescan))
}
