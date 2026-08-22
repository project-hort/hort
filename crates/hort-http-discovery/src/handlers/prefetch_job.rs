//! Axum handler for `GET /api/v1/repositories/:repo_key/prefetch/jobs/:job_id`.
//!
//! Read-only, id-addressed lookup of a prefetch job's outcome. See
//! `hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase::get_prefetch_job_outcome`
//! for the authz + cross-repo-isolation contract this handler defers to
//! entirely.
//!
//! # Handler shape (thin wrapper)
//!
//! 1. Extract `Option<`[`AuthenticatedPrincipal`]`>` — this is a GET route,
//!    so it goes through `extract_optional_principal`
//!    (`hort-http-core::router.rs`'s method-based dispatch), exactly like
//!    [`super::list_versions`]. The handler does not enforce anonymous
//!    here; the use case rejects `None` with `AppError::Unauthorized`.
//! 2. Invoke
//!    [`SelfServicePrefetchUseCase::get_prefetch_job_outcome`](hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase::get_prefetch_job_outcome).
//! 3. Map `Err(AppError::_)` → `ApiError` (the existing
//!    [`hort_http_core::error::ApiError`] mapping handles `Unauthorized →
//!    401`, `Forbidden → 403`, `NotFound → 404` verbatim).
//!
//! # Status code rules
//!
//! - `200 OK` — the job exists, is of kind `prefetch` / `prefetch-dependencies`,
//!   and belongs to `repo_key`'s repository.
//! - `401 Unauthorized` — anonymous (no bearer token, or an unvalidatable one).
//! - `403 Forbidden` — token-kind denial (PAT / no `token_kind`), or
//!   missing `Permission::Read ∧ Permission::Prefetch` on the resolved repo
//!   — the SAME gate `POST .../prefetch` applies.
//! - `404 Not Found` — repo key unknown, job id unknown, job is not a
//!   prefetch-kind job, OR the job belongs to a DIFFERENT repository
//!   (anti-enumeration: indistinguishable from unknown).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use uuid::Uuid;

use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

use crate::dto::PrefetchJobOutcomeDto;

/// `GET /api/v1/repositories/:repo_key/prefetch/jobs/:job_id`.
pub async fn get_prefetch_job(
    State(ctx): State<Arc<AppContext>>,
    Path((repo_key, job_id)): Path<(String, Uuid)>,
    Extension(principal): Extension<Option<AuthenticatedPrincipal>>,
) -> Result<(StatusCode, Json<PrefetchJobOutcomeDto>), ApiError> {
    let use_case = ctx
        .self_service_prefetch_use_case
        .as_ref()
        .expect("self_service_prefetch_use_case wired by composition before router mount");

    let job = use_case
        .get_prefetch_job_outcome(
            &repo_key,
            job_id,
            principal.as_ref().map(AuthenticatedPrincipal::as_caller),
        )
        .await?;
    Ok((StatusCode::OK, Json(PrefetchJobOutcomeDto::from(job))))
}
