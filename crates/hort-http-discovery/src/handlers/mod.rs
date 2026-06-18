//! Axum handlers for the discovery + self-service prefetch endpoints.
//!
//! - [`list_versions`] — `GET /api/v1/repositories/:repo_key/discovery/versions/:package_name`
//! - [`prefetch`] — `POST /api/v1/repositories/:repo_key/prefetch`
//!
//! Both handlers are thin wrappers per the architect-doc pattern: extract
//! [`hort_http_core::middleware::auth::AuthenticatedPrincipal`], invoke the
//! corresponding use case, map `AppError` → `ApiError`. The token-kind
//! gate, RBAC gate, OCI rejection, and per-package orchestration all
//! live INSIDE the use cases.

pub mod list_versions;
pub mod prefetch;

pub use list_versions::list_versions as handle_list_versions;
pub use prefetch::prefetch as handle_prefetch;
