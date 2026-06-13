//! Axum route handlers for `/api/v1/subscriptions`.
//!
//! All handlers extract `CallerPrincipal` via the
//! [`hort_http_core::authz::extractors::AuthenticatedCaller`] /
//! [`hort_http_core::authz::extractors::AdminPrincipal`] extractors;
//! anonymous requests never reach this surface.
//!
//! Per the architect skill's "no business logic in handlers" rule, the
//! handler bodies are thin wrappers around
//! [`hort_app::use_cases::subscription_use_case::SubscriptionUseCase`]
//! calls. The two non-trivial pieces of HTTP logic that DO live in
//! this crate:
//!
//! 1. PATCH dispatch — a body of just `{"state": "Active"|"Paused"}`
//!    delegates to `pause()` / `resume()` (which emit dedicated
//!    `SubscriptionPaused` / `SubscriptionResumed` lifecycle events).
//!    Any other PATCH body falls through to `update()`.
//! 2. DTO ↔ domain mapping — handler-side DTOs derive `Deserialize`,
//!    domain types do not. See `dto.rs`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use hort_domain::entities::subscription::SubscriptionId;
use hort_domain::types::PageRequest;

use hort_http_core::authz::extractors::{AdminPrincipal, AuthenticatedCaller};
use hort_http_core::context::AppContext;

use crate::dto::{
    is_state_only_update, map_create_request_to_domain, map_subscription_to_response,
    map_update_request_to_domain, CreateSubscriptionRequest, PageResponse, SubscriptionResponse,
    SubscriptionStateDto, UpdateSubscriptionRequest,
};
use crate::error::{DtoHandlerError, SubscriptionHandlerError};

// ---------------------------------------------------------------------------
// Pagination query (shared by list_own / admin_list)
// ---------------------------------------------------------------------------

/// `?offset=<u64>&limit=<u64>` for `GET /api/v1/subscriptions` +
/// `GET /api/v1/admin/subscriptions`.
#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub offset: Option<u64>,
    pub limit: Option<u64>,
}

/// Default page size when `limit` is absent. Matches the use-case-level
/// `PageRequest::default()` of 20.
const DEFAULT_PAGE_LIMIT: u64 = 50;

fn page_request_from(q: &PageQuery) -> PageRequest {
    PageRequest::new(q.offset.unwrap_or(0), q.limit.unwrap_or(DEFAULT_PAGE_LIMIT))
}

// ---------------------------------------------------------------------------
// POST /api/v1/subscriptions
// ---------------------------------------------------------------------------

/// `POST /api/v1/subscriptions` — create a subscription owned by the
/// caller.
///
/// The request body's webhook target carries a `secret_ref` locator
/// (`{"source": "env_var" | "file", "location": "..."}`) referencing an
/// already-provisioned shared secret — exactly how upstream-mapping
/// credentials are referenced (`hort-config`'s `UpstreamMappingSpec`).
/// No secret material is accepted on the wire (only the `secret_ref` locator).
///
/// Returns `201 Created` with the canonical [`SubscriptionResponse`].
/// There is no one-shot plaintext field: the create path never handles
/// secret material, so there is nothing secret-derived to reveal.
pub async fn create_subscription(
    State(ctx): State<Arc<AppContext>>,
    AuthenticatedCaller(principal): AuthenticatedCaller,
    Json(req): Json<CreateSubscriptionRequest>,
) -> Result<(StatusCode, Json<SubscriptionResponse>), CreateError> {
    let domain_req = map_create_request_to_domain(req)?;
    let sub = ctx
        .subscription_use_case
        .create(&principal, domain_req)
        .await?;
    Ok((StatusCode::CREATED, Json(map_subscription_to_response(sub))))
}

// ---------------------------------------------------------------------------
// GET /api/v1/subscriptions
// ---------------------------------------------------------------------------

/// `GET /api/v1/subscriptions` — list subscriptions owned by the caller.
pub async fn list_own_subscriptions(
    State(ctx): State<Arc<AppContext>>,
    AuthenticatedCaller(principal): AuthenticatedCaller,
    Query(page): Query<PageQuery>,
) -> Result<Json<PageResponse<SubscriptionResponse>>, SubscriptionHandlerError> {
    let page_req = page_request_from(&page);
    let owner = principal.user_id;
    let result = ctx
        .subscription_use_case
        .list_for_owner(&principal, owner, page_req)
        .await?;
    Ok(Json(PageResponse {
        items: result
            .items
            .into_iter()
            .map(map_subscription_to_response)
            .collect(),
        total: result.total,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/v1/subscriptions/:id
// ---------------------------------------------------------------------------

/// `GET /api/v1/subscriptions/:id` — single subscription. Owner or admin.
pub async fn get_subscription(
    State(ctx): State<Arc<AppContext>>,
    AuthenticatedCaller(principal): AuthenticatedCaller,
    Path(id): Path<Uuid>,
) -> Result<Json<SubscriptionResponse>, SubscriptionHandlerError> {
    let sub = ctx
        .subscription_use_case
        .get_for_owner(&principal, SubscriptionId(id))
        .await?;
    Ok(Json(map_subscription_to_response(sub)))
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/subscriptions/:id
// ---------------------------------------------------------------------------

/// `PATCH /api/v1/subscriptions/:id` — update / pause / resume.
///
/// Dispatch:
/// - Body is exactly `{"state": "Active"|"Paused"}` and no other field is
///   present → dispatch to `pause()` / `resume()` so the lifecycle emits
///   the dedicated `SubscriptionPaused` / `SubscriptionResumed` events.
/// - Otherwise → call `update()`. Note that the use case's `update()`
///   accepts a `state` field but emits a single `SubscriptionUpdated`
///   event with `changed_fields = ["state"]` instead of the dedicated
///   pause/resume event; the dispatch above preserves the §5 audit
///   shape for the common operator surface.
pub async fn update_subscription(
    State(ctx): State<Arc<AppContext>>,
    AuthenticatedCaller(principal): AuthenticatedCaller,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, UpdateError> {
    let sub_id = SubscriptionId(id);

    if is_state_only_update(&req) {
        // SAFETY: `is_state_only_update` returned true ⇒ `state` is `Some(_)`.
        match req
            .state
            .expect("is_state_only_update guarantees state.is_some()")
        {
            SubscriptionStateDto::Active => {
                ctx.subscription_use_case.resume(&principal, sub_id).await?;
            }
            SubscriptionStateDto::Paused => {
                ctx.subscription_use_case.pause(&principal, sub_id).await?;
            }
        }
        // Echo back the latest row.
        let sub = ctx
            .subscription_use_case
            .get_for_owner(&principal, sub_id)
            .await?;
        return Ok(Json(map_subscription_to_response(sub)));
    }

    let domain_req = map_update_request_to_domain(req)?;
    let sub = ctx
        .subscription_use_case
        .update(&principal, sub_id, domain_req)
        .await?;
    Ok(Json(map_subscription_to_response(sub)))
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/subscriptions/:id
// ---------------------------------------------------------------------------

/// `DELETE /api/v1/subscriptions/:id` — `204 No Content` on success.
pub async fn delete_subscription(
    State(ctx): State<Arc<AppContext>>,
    AuthenticatedCaller(principal): AuthenticatedCaller,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, SubscriptionHandlerError> {
    ctx.subscription_use_case
        .delete(&principal, SubscriptionId(id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /api/v1/admin/subscriptions
// ---------------------------------------------------------------------------

/// `GET /api/v1/admin/subscriptions` — list every active subscription
/// across all owners. Admin-only — the [`AdminPrincipal`] extractor
/// rejects non-admin callers with `403`. The use case re-checks
/// `Permission::Admin` (defence in depth — same pattern as
/// `/admin/quarantine/patch-candidates`).
///
/// **Scope note.** v1 admin list returns *active* subscriptions only,
/// reflecting [`hort_domain::ports::subscription_repository::SubscriptionRepository::list_active`]
/// — the dispatcher's cache-refresh hot path. Paused / disabled rows
/// are excluded; a future PR may extend the repo port with a
/// `list_all` variant when an operator workflow surfaces demand
/// (the use case already accepts the `AdminPrincipal` gate so
/// extending the result set is a port-only change).
pub async fn admin_list_subscriptions(
    State(ctx): State<Arc<AppContext>>,
    AdminPrincipal(principal): AdminPrincipal,
    Query(_page): Query<PageQuery>,
) -> Result<Json<PageResponse<SubscriptionResponse>>, SubscriptionHandlerError> {
    let items = ctx.subscription_use_case.admin_list_all(&principal).await?;
    let total = items.len() as u64;
    Ok(Json(PageResponse {
        items: items
            .into_iter()
            .map(map_subscription_to_response)
            .collect(),
        total,
    }))
}

// ---------------------------------------------------------------------------
// Error wrappers — folded so handlers can `?` against both DTO mapping
// and use-case errors with one signature.
// ---------------------------------------------------------------------------

/// Combined error for `create_subscription`'s two failure surfaces:
/// DTO mapping and use-case rejection.
pub enum CreateError {
    Dto(DtoHandlerError),
    UseCase(SubscriptionHandlerError),
}

impl From<crate::dto::DtoMapError> for CreateError {
    fn from(e: crate::dto::DtoMapError) -> Self {
        Self::Dto(DtoHandlerError(e))
    }
}

impl From<hort_app::use_cases::subscription_use_case::SubscriptionError> for CreateError {
    fn from(e: hort_app::use_cases::subscription_use_case::SubscriptionError) -> Self {
        Self::UseCase(SubscriptionHandlerError(e))
    }
}

impl axum::response::IntoResponse for CreateError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Dto(e) => e.into_response(),
            Self::UseCase(e) => e.into_response(),
        }
    }
}

/// Combined error for `update_subscription`'s two failure surfaces.
pub enum UpdateError {
    Dto(DtoHandlerError),
    UseCase(SubscriptionHandlerError),
}

impl From<crate::dto::DtoMapError> for UpdateError {
    fn from(e: crate::dto::DtoMapError) -> Self {
        Self::Dto(DtoHandlerError(e))
    }
}

impl From<hort_app::use_cases::subscription_use_case::SubscriptionError> for UpdateError {
    fn from(e: hort_app::use_cases::subscription_use_case::SubscriptionError) -> Self {
        Self::UseCase(SubscriptionHandlerError(e))
    }
}

impl axum::response::IntoResponse for UpdateError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Dto(e) => e.into_response(),
            Self::UseCase(e) => e.into_response(),
        }
    }
}
