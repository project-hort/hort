//! `hort-http-subscriptions` — inbound HTTP CRUD adapter for the
//! `/api/v1/subscriptions` surface.
//!
//! # Routes
//!
//! ```text
//! POST   /api/v1/subscriptions           → create_subscription
//! GET    /api/v1/subscriptions           → list_own_subscriptions
//! GET    /api/v1/subscriptions/:id       → get_subscription
//! PATCH  /api/v1/subscriptions/:id       → update_subscription
//!                                          (state-only body → pause/resume)
//! DELETE /api/v1/subscriptions/:id       → delete_subscription
//! GET    /api/v1/admin/subscriptions     → admin_list_subscriptions
//! ```
//!
//! # Dep-graph invariant (ADR 0008)
//!
//! This crate MUST NOT depend on `hort-adapters-*`, `sqlx`, or `reqwest`.
//! Run:
//!
//! ```text
//! cargo tree -p hort-http-subscriptions --edges normal --prefix none
//! ```
//!
//! and confirm none of those crates appear. The dep graph is
//! load-bearing: an adapter import is an unresolved-import compile
//! error, not a review finding.
//!
//! # Authentication / authorization
//!
//! - Every per-id and create / list-own route extracts the caller via
//!   [`hort_http_core::authz::extractors::AuthenticatedCaller`] (any
//!   authenticated user passes; the use case enforces owner-or-admin).
//! - The admin-list route uses
//!   [`hort_http_core::authz::extractors::AdminPrincipal`] (admin grant
//!   required at the extractor edge, re-checked by the use case).
//! - Anonymous callers never reach a handler body — both extractors
//!   short-circuit before the handler runs.
//!
//! # Composition wiring
//!
//! The crate exposes a single [`router`] function returning
//! `Router<Arc<AppContext>>`. Composition calls
//! `hort_http_subscriptions::router().with_state(ctx)` and nests / merges
//! the result onto the workspace router. The
//! `AppContext.subscription_use_case` field carrying the use case is
//! defined in `hort-http-core` so this crate stays adapter-free.

use std::sync::Arc;

use axum::routing::{delete, get, patch, post};
use axum::Router;
use hort_http_core::context::AppContext;

pub mod dto;
pub mod error;
pub mod handlers;

/// Build the subscriptions CRUD router. Path strings are absolute —
/// composition mounts the router via `Router::merge`, not `nest`, so
/// the per-route prefix lives in the same crate as the handler logic
/// (same pattern as `hort-http-admin-security`).
pub fn router() -> Router<Arc<AppContext>> {
    Router::new()
        .route("/api/v1/subscriptions", post(handlers::create_subscription))
        .route(
            "/api/v1/subscriptions",
            get(handlers::list_own_subscriptions),
        )
        .route("/api/v1/subscriptions/:id", get(handlers::get_subscription))
        .route(
            "/api/v1/subscriptions/:id",
            patch(handlers::update_subscription),
        )
        .route(
            "/api/v1/subscriptions/:id",
            delete(handlers::delete_subscription),
        )
        .route(
            "/api/v1/admin/subscriptions",
            get(handlers::admin_list_subscriptions),
        )
}
