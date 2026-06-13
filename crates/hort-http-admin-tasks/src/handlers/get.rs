//! `GET /api/v1/admin/tasks/:id` — single task look-up.
//!
//! Returns the full `jobs` row projection for the given `id`. Returns
//! 404 when the row does not exist.
//!
//! # Authentication
//!
//! Requires `Permission::Admin` — same authz tier as [`super::list`].
//! A low-privilege principal cannot read a single job row (including
//! raw `params` / `last_error` / `result_summary`). The `AdminPrincipal`
//! extractor reads BOTH principal slots (the `require_principal` bare
//! slot AND the `extract_optional_principal` `Option<_>` slot) so the
//! handler cannot regress to the 2026-05-11 GET-only 403 bug.
//!
//! # Dep-graph invariant
//!
//! No `hort-adapters-*`, `sqlx`, or `reqwest` imports.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_domain::error::DomainError;

use hort_http_core::authz::extractors::AdminPrincipal;
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

use crate::dto::JobRowDto;

/// `GET /api/v1/admin/tasks/:id`
pub async fn get_task(
    State(ctx): State<Arc<AppContext>>,
    Path(id): Path<Uuid>,
    AdminPrincipal(_principal): AdminPrincipal,
) -> Result<(StatusCode, Json<JobRowDto>), ApiError> {
    let row = ctx.task_use_case.get_job(id).await?;
    match row {
        Some(row) => Ok((StatusCode::OK, Json(JobRowDto::from(row)))),
        None => Err(ApiError(AppError::Domain(DomainError::NotFound {
            entity: "task",
            id: id.to_string(),
        }))),
    }
}
