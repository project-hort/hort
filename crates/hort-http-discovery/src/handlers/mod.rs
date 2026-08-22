//! Axum handlers for the discovery + self-service prefetch endpoints.
//!
//! - [`list_versions`] — `GET /api/v1/repositories/:repo_key/discovery/versions/:package_name`
//! - [`prefetch`] — `POST /api/v1/repositories/:repo_key/prefetch`
//! - [`prefetch_job`] — `GET /api/v1/repositories/:repo_key/prefetch/jobs/:job_id`
//!
//! All three handlers are thin wrappers per the architect-doc pattern:
//! extract [`hort_http_core::middleware::auth::AuthenticatedPrincipal`],
//! invoke the corresponding use case, map `AppError` → `ApiError`. The
//! token-kind gate, RBAC gate, OCI rejection, and per-package/per-job
//! orchestration all live INSIDE the use cases.

pub mod list_repositories;
pub mod list_versions;
pub mod prefetch;
pub mod prefetch_job;

pub use list_versions::list_versions as handle_list_versions;
pub use prefetch::prefetch as handle_prefetch;
pub use prefetch_job::get_prefetch_job as handle_get_prefetch_job;
