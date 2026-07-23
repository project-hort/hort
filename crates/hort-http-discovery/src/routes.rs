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
//! - `GET  /api/v1/repositories`
//! - `GET  /api/v1/repositories/:repo_key/discovery/versions/:package_name`
//! - `POST /api/v1/repositories/:repo_key/prefetch`
//!
//! **Auth posture** — none of these routes appear in
//! `hort_http_core::router::is_anonymous_path`. The global router's
//! method-based dispatch sends every `GET` through
//! `extract_optional_principal` (principal is `Option<…>`), which is
//! exactly the read-endpoint pattern (ADR 0013): handlers receive `None`
//! for unauthenticated callers and enforce visibility themselves via the
//! use-case layer. `GET /repositories` has no token-kind restriction. The
//! other two routes additionally apply a token-kind gate inside their use
//! cases — NOT identical between them (issue #80): discovery-versions
//! requires `TokenKind::CliSession` alone (PATs rejected); prefetch
//! accepts `CliSession` **or** a `ServiceAccount` token whose resolved
//! grants include `Permission::Read ∧ Permission::Prefetch` on the target
//! repository (see `hort_app::use_cases::self_service_prefetch_use_case`'s
//! module docs and `docs/ci/hort-quarantine-integration.md` for why).

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use hort_http_core::context::AppContext;

use crate::handlers::list_repositories::list_repositories;
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
        .route("/repositories", get(list_repositories))
        .route(
            "/repositories/:repo_key/discovery/versions/:package_name",
            get(list_versions),
        )
        .route("/repositories/:repo_key/prefetch", post(prefetch))
}
