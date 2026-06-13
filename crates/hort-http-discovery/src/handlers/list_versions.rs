//! Axum handler for `GET /api/v1/repositories/:repo_key/discovery/versions/:package_name`.
//!
//! The route is mounted under `/api/v1` by the composition root;
//! this crate's router fragment includes the
//! `/repositories/:repo_key/...` prefix verbatim, matching the
//! `hort-http-admin-security` precedent exactly (ADR 0008).
//!
//! # Handler shape (thin wrapper)
//!
//! 1. Extract `Option<`[`AuthenticatedPrincipal`]`>` (the F-25 read-endpoint
//!    shape). This GET routes through `extract_optional_principal`
//!    (`hort-http-core::router.rs:313-318` dispatches GET/HEAD/OPTIONS to the
//!    optional layer), so the principal arrives wrapped in `Option` —
//!    `Some(_)` on a valid token, `None` when absent or unvalidatable. The
//!    handler does NOT enforce anonymous here; it threads
//!    `Option<&CallerPrincipal>` into the use case, which rejects `None`
//!    with 401 (CliSession gate, ADR 0013).
//! 2. Invoke
//!    [`DiscoveryUseCase::list_versions`](hort_app::use_cases::discovery_use_case::DiscoveryUseCase::list_versions).
//! 3. Map `Err(AppError::Domain(_))` → `ApiError` (the existing
//!    [`hort_http_core::error::ApiError`] mapping handles `Forbidden →
//!    403`, `Validation → 400`, `NotFound → 404` verbatim).
//!
//! The token-kind gate (§2.6) and the `Permission::Read` gate live INSIDE
//! the use case, NOT here. Per the architect-doc *"Emission by layer"*
//! rule, business metrics (`hort_discovery_list_versions_total`) emit at
//! the `hort-app` layer; a handler-level short-circuit would either emit
//! from the wrong layer or duplicate the use case's check on the same
//! struct field with zero added defense.
//!
//! # Observability
//!
//! No tracing emission from this handler — per the architect-doc
//! Observability rules, handlers stay quiet and the use case carries
//! the audit trail.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};

use hort_domain::entities::discovery::DiscoveryListing;

use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;
use hort_http_core::middleware::auth::AuthenticatedPrincipal;

/// `GET /api/v1/repositories/:repo_key/discovery/versions/:package_name`.
///
/// Status mapping:
///
/// - `200 OK` — listing assembled (the use case folds upstream-fetch
///   failures into the listing envelope with an empty `unknown` set and
///   a non-`success` metric tick; the wire response is still 200).
/// - `400 Bad Request` — OCI format rejection
///   (`AppError::Domain(Validation)` from the use case's OCI short-circuit).
/// - `401 Unauthorized` — anonymous (the use case rejects a `None` caller;
///   GET routes through `extract_optional_principal`, NOT
///   `require_principal`, so the 401 is enforced one layer down, not by
///   the middleware — read-endpoint pattern, ADR 0013).
/// - `403 Forbidden` — token-kind denial (PAT / service-account / no
///   `token_kind`) OR `Permission::Read` denial.
/// - `404 Not Found` — repo key unknown (anti-enumeration; the use case
///   collapses `repository.find_by_key` `NotFound` to the same
///   envelope an invisible repo would produce).
pub async fn list_versions(
    State(ctx): State<Arc<AppContext>>,
    Path((repo_key, package_name)): Path<(String, String)>,
    Extension(principal): Extension<Option<AuthenticatedPrincipal>>,
) -> Result<(StatusCode, Json<DiscoveryListing>), ApiError> {
    // The Item 7 → Item 8 split: composition (Item 8) populates the
    // use case slot; the router is also mounted in Item 8. Until both
    // land, the slot is `None` in production. Test harness wires it
    // unconditionally via `AppContext::with_discovery_use_cases`. The
    // `.expect(_)` is a structural invariant — the only way to reach
    // this handler is through the (Item-8-mounted) router, which the
    // composition discipline guarantees is only mounted after the slot
    // is populated. A panic here would surface a composition bug, not
    // an operator-driven outage.
    let use_case = ctx
        .discovery_use_case
        .as_ref()
        .expect("discovery_use_case wired by composition before router mount");

    let listing = use_case
        .list_versions(
            &repo_key,
            &package_name,
            principal.as_ref().map(AuthenticatedPrincipal::as_caller),
        )
        .await?;
    Ok((StatusCode::OK, Json(listing)))
}
