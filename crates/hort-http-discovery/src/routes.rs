//! Route assembly for the discovery + self-service prefetch REST surface.
//! See `docs/architecture/explanation/prefetch-pipeline.md` and ADR 0013.
//!
//! Two routes mounted under no prefix; the caller (`hort-server::http`)
//! nests the fragment under `/api/v1` — mirroring the
//! `hort-http-admin-security` precedent exactly (ADR 0008 URL-composition
//! pattern):
//!
//! ```text
//! // in hort-server::http
//! router.nest("/api/v1", hort_http_discovery::routes())
//! ```
//!
//! Resulting absolute paths:
//!
//! - `GET  /api/v1/repositories/:repo_key/discovery/versions/:package_name`
//! - `POST /api/v1/repositories/:repo_key/prefetch`
//!
//! **NOT** in `hort_http_core::router::is_anonymous_path` — both routes
//! require an authenticated principal (the token-kind gate inside the
//! use case rejects anonymous-equivalent tokens before any port I/O,
//! but the structural defense-in-depth lives at the middleware edge:
//! the `require_principal` layer returns 401 to unauthenticated callers
//! before this handler runs).

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use hort_http_core::context::AppContext;

use crate::handlers::list_versions::list_versions;
use crate::handlers::prefetch::prefetch;

/// Build the discovery + self-service prefetch route subtree.
///
/// Mount under `/api/v1` in `hort-server::http`. The inner router
/// intentionally includes `/repositories/:repo_key/...` to match the
/// `hort-http-admin-security` shape — the path-prefix-at-composition
/// pattern is the ADR 0008 norm.
pub fn routes() -> Router<Arc<AppContext>> {
    Router::new()
        .route(
            "/repositories/:repo_key/discovery/versions/:package_name",
            get(list_versions),
        )
        .route("/repositories/:repo_key/prefetch", post(prefetch))
}
