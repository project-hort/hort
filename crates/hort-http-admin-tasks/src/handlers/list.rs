//! `GET /api/v1/admin/tasks` — paginated task list.
//!
//! Returns a JSON page of `jobs` rows, most-recently-inserted first.
//! Optional query params:
//!
//! - `kind` — filter by task kind literal (e.g. `noop`, `scan`).
//! - `status` — filter by lifecycle status (`pending`, `running`,
//!   `completed`, `failed`).
//! - `cursor` — opaque UUID from the prior page's `next_cursor`.
//! - `limit` — max rows per page; clamped to [`MAX_LIMIT`]. `0` or
//!   absent selects [`DEFAULT_LIMIT`].
//!
//! # Authentication
//!
//! Requires `Permission::Admin`. The read tier matches the RBAC-gated
//! `POST /invoke` write tier — a low-privilege principal cannot read
//! the full job queue (including raw `params` / `last_error` /
//! `result_summary`). The `AdminPrincipal` extractor reads BOTH
//! principal slots (bare `AuthenticatedPrincipal` from
//! `require_principal`, plus `Option<AuthenticatedPrincipal>` from
//! `extract_optional_principal`) via the shared `extract_principal`
//! helper, so this handler cannot regress to the 2026-05-11 GET-only
//! 403 bug that was caused by reading only the bare slot.
//!
//! # Dep-graph invariant
//!
//! No `hort-adapters-*`, `sqlx`, or `reqwest` imports.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_domain::error::DomainError;
use hort_domain::ports::jobs_repository::{JobStatus, ListJobsFilter};

use hort_http_core::authz::extractors::AdminPrincipal;
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

use crate::dto::JobRowDto;

/// Maximum rows per page.
pub const MAX_LIMIT: u32 = 200;
/// Default rows per page when `limit` is absent or `0`.
pub const DEFAULT_LIMIT: u32 = 50;

/// Query-string parameters for `GET /api/v1/admin/tasks`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Restrict to rows matching this `kind` literal.
    pub kind: Option<String>,
    /// Restrict to rows matching this status string.
    pub status: Option<String>,
    /// Opaque continuation cursor from a prior page's `next_cursor`.
    pub cursor: Option<Uuid>,
    /// Max rows per page (clamped to `MAX_LIMIT`).
    pub limit: Option<u32>,
}

/// Wire response for `GET /api/v1/admin/tasks`.
#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub tasks: Vec<JobRowDto>,
    pub next_cursor: Option<Uuid>,
}

/// Parse a `status` string into a `JobStatus`. Returns `None` on unknown
/// values so the handler can surface a 400 rather than silently ignoring
/// the filter.
fn parse_status(s: &str) -> Option<JobStatus> {
    match s {
        "pending" => Some(JobStatus::Pending),
        "running" => Some(JobStatus::Running),
        "completed" => Some(JobStatus::Completed),
        "failed" => Some(JobStatus::Failed),
        _ => None,
    }
}

/// `GET /api/v1/admin/tasks`
pub async fn list_tasks(
    State(ctx): State<Arc<AppContext>>,
    Query(params): Query<ListQuery>,
    AdminPrincipal(_principal): AdminPrincipal,
) -> Result<(StatusCode, Json<ListResponse>), ApiError> {
    // Parse the optional `status` filter.
    let status_filter = match params.status.as_deref() {
        None => None,
        Some(s) => match parse_status(s) {
            Some(js) => Some(js),
            None => {
                return Err(ApiError(AppError::Domain(DomainError::Validation(
                    format!(
                        "unknown status {s:?}; expected one of pending, running, completed, failed"
                    ),
                ))))
            }
        },
    };

    let filter = ListJobsFilter {
        kind: params.kind,
        status: status_filter,
    };
    let limit = match params.limit.unwrap_or(0) {
        0 => DEFAULT_LIMIT,
        n => n.min(MAX_LIMIT),
    };

    let page = ctx
        .task_use_case
        .list_jobs(filter, limit, params.cursor)
        .await?;

    let tasks = page.items.into_iter().map(JobRowDto::from).collect();
    Ok((
        StatusCode::OK,
        Json(ListResponse {
            tasks,
            next_cursor: page.next_cursor,
        }),
    ))
}
