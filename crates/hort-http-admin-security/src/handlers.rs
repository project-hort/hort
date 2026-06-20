//! Axum handlers for the security-score REST surface.
//!
//! Two endpoints:
//!
//! - `GET /api/v1/repositories/:name/security-score` — single repo.
//! - `GET /api/v1/security-score?cursor=...&limit=...` — paginated.
//!
//! The handlers consult [`SecurityScoreUseCase`] for both the score
//! lookup and the visibility-filtered enumeration; they do NOT touch
//! any data port directly. Per the architect skill's "no business
//! logic in handlers" rule, the only adapter-side work is:
//!
//! 1. Extract the principal from `Extension<Option<AuthenticatedPrincipal>>`.
//! 2. Decode query / path params.
//! 3. Resolve `repository_id → name` via the use case for the wire shape.
//! 4. Map [`AppError`] → [`ApiError`] (`?` does this implicitly).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use axum::{http, Extension};
use serde::Deserialize;
use uuid::Uuid;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::ports::repo_security_score_repository::RepoSecurityScore;

use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

use crate::dto::{RescanResponse, SecurityScoreDto, SecurityScoreListDto};

/// Query-string knobs for `GET /api/v1/security-score`.
#[derive(Debug, Deserialize)]
pub struct ListParams {
    /// Opaque continuation token from a prior response's `next_cursor`.
    /// `None` requests the first page.
    pub cursor: Option<String>,
    /// Max rows per page. Use case clamps to
    /// [`hort_app::use_cases::security_score_use_case::MAX_LIST_LIMIT`];
    /// `None` defaults to `DEFAULT_LIST_LIMIT`.
    pub limit: Option<u32>,
}

/// `GET /api/v1/repositories/:name/security-score`.
///
/// Status mapping:
/// - `200 OK` — repo Read-visible to caller, score row served (or
///   synthesized zero row when the projection is absent).
/// - `404 Not Found` — repo missing OR invisible (anti-enumeration;
///   Read denial collapses to NotFound — ADR 0008).
/// - `403 Forbidden` — emitted only by the future Write-side surface;
///   Read denial collapses to 404. The handler still maps Forbidden →
///   403 for completeness (e.g. a future ACL extension that surfaces
///   it on Read paths).
pub async fn get_repo_score(
    State(ctx): State<Arc<AppContext>>,
    Path(name): Path<String>,
    // GET reads the `Option<AuthenticatedPrincipal>` slot that
    // `extract_optional_principal` writes (NOT the bare slot `require_principal`
    // writes on writes); the outer `Option` tolerates the no-auth-layer test
    // case → anonymous.
    principal: Option<Extension<Option<AuthenticatedPrincipal>>>,
) -> Result<(http::StatusCode, Json<SecurityScoreDto>), ApiError> {
    let principal = extract_caller(principal.as_deref().and_then(|opt| opt.as_ref()));
    let score = ctx
        .security_score_use_case
        .find_for_repo(&name, principal)
        .await?;
    let dto = render_score(&ctx, name, score).await?;
    Ok((http::StatusCode::OK, Json(dto)))
}

/// `GET /api/v1/security-score?cursor=...&limit=...`.
///
/// Lists score rows for repositories the caller can read, paginated.
/// Anonymous callers see public repos only.
pub async fn list_repo_scores(
    State(ctx): State<Arc<AppContext>>,
    Query(params): Query<ListParams>,
    // GET reads the `Option<AuthenticatedPrincipal>` slot that
    // `extract_optional_principal` writes; the outer `Option` tolerates the
    // no-auth-layer test case → anonymous.
    principal: Option<Extension<Option<AuthenticatedPrincipal>>>,
) -> Result<(http::StatusCode, Json<SecurityScoreListDto>), ApiError> {
    let principal = extract_caller(principal.as_deref().and_then(|opt| opt.as_ref()));
    let limit = params.limit.unwrap_or(0);
    let page = ctx
        .security_score_use_case
        .list_with_access(principal, params.cursor.as_deref(), limit)
        .await?;

    // Resolve names per row. The list path takes one extra repo lookup
    // per row — acceptable given the clamped page size (max 500).
    let mut scores = Vec::with_capacity(page.scores.len());
    for row in page.scores {
        let dto = render_score(&ctx, String::new(), row).await?;
        scores.push(dto);
    }

    Ok((
        http::StatusCode::OK,
        Json(SecurityScoreListDto {
            scores,
            next_cursor: page.next_cursor,
        }),
    ))
}

/// Render a single domain row into the wire DTO, resolving the
/// repository name. The `name_hint` argument is the path-supplied
/// name on the single-repo handler; the list handler passes `""` and
/// expects a fresh resolve. A repo whose row exists but whose name no
/// longer resolves (deleted between list and render) is rendered with
/// the empty string — the handler propagates the row rather than
/// 500'ing, since the score is genuine but the cosmetic name is gone.
async fn render_score(
    ctx: &AppContext,
    name_hint: String,
    score: RepoSecurityScore,
) -> Result<SecurityScoreDto, ApiError> {
    let resolved = if name_hint.is_empty() {
        ctx.security_score_use_case
            .resolve_repo_name(score.repository_id)
            .await?
            .unwrap_or_default()
    } else {
        name_hint
    };
    Ok(SecurityScoreDto::from_domain(resolved, &score))
}

/// Convert an `Option<&AuthenticatedPrincipal>` to the
/// `Option<&CallerPrincipal>` shape the use case wants. Trivial but
/// keeps the handler bodies short.
fn extract_caller(p: Option<&AuthenticatedPrincipal>) -> Option<&CallerPrincipal> {
    p.map(AuthenticatedPrincipal::as_caller)
}

/// `POST /api/v1/artifacts/:id/rescan`.
///
/// Triggers a manual rescan of a single artifact by inserting a
/// `kind='scan'` row in the `jobs` table with `trigger_source='manual'`,
/// `priority=20`. The wire response carries the **new `jobs.id`** so
/// the caller can poll `/api/v1/admin/tasks/<id>` for status — the
/// envelope shape (`{ "task_job_id": <uuid> }`) deliberately matches
/// the admin-task surface so downstream tooling reads the same field
/// on both surfaces.
///
/// Status mapping:
/// - `202 Accepted` — scan job enqueued, body carries `task_job_id`.
/// - `404 Not Found` — artifact missing OR caller cannot Read the
///   parent repo (anti-enumeration collapse, ADR 0008). The wire
///   envelope deliberately talks about the artifact, not the repo, so
///   the actor cannot probe for private repo membership through the
///   artifact-id surface.
/// - `403 Forbidden` — caller has Read on the parent repo but lacks
///   `Permission::Write` (ADR 0008).
/// - `409 Conflict` — a `kind='scan'` row with `status IN ('pending',
///   'running')` already exists for this artifact, OR the partial-
///   unique-index race surfaced via [`enqueue_scan`] returned the same
///   error after the use-case's pre-check. Both produce 409 so the
///   caller treats the two paths uniformly.
pub async fn rescan(
    State(ctx): State<Arc<AppContext>>,
    Path(artifact_id): Path<Uuid>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
) -> Result<(http::StatusCode, Json<RescanResponse>), ApiError> {
    let caller = extract_caller(principal.as_ref().map(|p| &p.0));
    let job_id = ctx
        .manual_rescan_use_case
        .trigger(caller, artifact_id)
        .await?;
    Ok((
        http::StatusCode::ACCEPTED,
        Json(RescanResponse {
            task_job_id: job_id,
        }),
    ))
}
