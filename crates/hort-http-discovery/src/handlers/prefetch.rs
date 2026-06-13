//! Axum handler for `POST /api/v1/repositories/:repo_key/prefetch`.
//! See `docs/architecture/explanation/prefetch-pipeline.md` and ADR 0013.
//!
//! The handler:
//!
//! 1. Decodes the JSON body into [`SelfServicePrefetchRequestDto`]
//!    (a deserialize-only DTO; the domain
//!    [`hort_domain::entities::discovery::PrefetchRequestItem`] is
//!    Deserialize-FREE per the architect-doc anti-pattern *"Domain type
//!    deserialization in API layer"*).
//! 2. Converts at the inbound boundary via
//!    `dto.items.into_iter().map(Into::into).collect::<Vec<PrefetchRequestItem>>()`.
//! 3. Invokes
//!    [`SelfServicePrefetchUseCase::enqueue_self_service`](hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase::enqueue_self_service).
//! 4. Renders the [`PrefetchOutcome`] envelope as JSON with status code
//!    `200 OK` (continue-on-error envelope — even a fully-failed batch
//!    returns 200 with the partition populated).
//!
//! The token-kind gate (§2.6), the `Permission::Read ∧ Permission::Prefetch`
//! gate (§2.5 Finding E), and the OCI rejection (§8) all live INSIDE the
//! use case. Per the architect-doc *"Emission by layer"* rule, business
//! metrics (`hort_prefetch_self_service_total`) emit at the `hort-app` layer.
//!
//! # Status code rules (§2.3 + acceptance #3)
//!
//! - **All items succeeded** → `200 OK`, empty `skipped` / `rejected` /
//!   `failed` arrays.
//! - **Some items failed but at least one enqueued** → `200 OK` with the
//!   envelope partitioned across all four buckets.
//! - **All items failed (per-item upstream / parse / network)** → `200 OK`
//!   with empty `enqueued_job_ids` and the failure arrays populated.
//! - **Malformed request body** → `400 Bad Request` (axum's `Json`
//!   extractor returns this before the handler runs).
//! - **Token-kind denial** → `403 Forbidden` (`AppError::Domain(Forbidden)`
//!   from the use case).
//! - **Anonymous** → `401 Unauthorized` (returned by `require_principal`
//!   before the handler runs).
//! - **OCI rejection** → `400 Bad Request` (`AppError::Domain(Validation)`
//!   from the use case via the §8 short-circuit).
//! - **Repo key unknown** → `404 Not Found` (anti-enumeration; the use
//!   case collapses `RepositoryRepository::find_by_key` `NotFound`).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};

use hort_domain::entities::discovery::{PrefetchOutcome, PrefetchRequestItem};

use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

use crate::dto::SelfServicePrefetchRequestDto;

/// `POST /api/v1/repositories/:repo_key/prefetch`.
///
/// See module-level doc for the status-code matrix.
pub async fn prefetch(
    State(ctx): State<Arc<AppContext>>,
    Path(repo_key): Path<String>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(dto): Json<SelfServicePrefetchRequestDto>,
) -> Result<(StatusCode, Json<PrefetchOutcome>), ApiError> {
    // The Item 7 → Item 8 split — see the matching `.expect` in
    // `list_versions.rs` for the rationale.
    let use_case = ctx
        .self_service_prefetch_use_case
        .as_ref()
        .expect("self_service_prefetch_use_case wired by composition before router mount");

    // Cross the inbound boundary: DTO → Vec<domain command>. The domain
    // `PrefetchRequestItem` is Deserialize-FREE (compile-time guard in
    // `hort_domain::entities::discovery` via `static_assertions`); only
    // the DTO accepts external bytes.
    let items: Vec<PrefetchRequestItem> = dto.items.into_iter().map(Into::into).collect();

    let outcome = use_case
        .enqueue_self_service(&repo_key, items, principal.as_caller())
        .await?;
    Ok((StatusCode::OK, Json(outcome)))
}
