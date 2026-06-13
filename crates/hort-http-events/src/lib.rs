//! `hort-http-events` — inbound HTTP adapter for `GET /api/v1/events`
//! pull-resync (design doc §9).
//!
//! # Route
//!
//! ```text
//! GET /api/v1/events?category=<cat>&after=<u64>&max=<u32>&wait_ms=<u32>
//!   → 200 OK { "events": [...], "next_after": u64, "has_more": bool }
//! ```
//!
//! # Dep-graph invariant (ADR 0008)
//!
//! This crate MUST NOT depend on `hort-adapters-*`, `sqlx`, or `reqwest`.
//! Run:
//!
//! ```text
//! cargo tree -p hort-http-events --edges normal --prefix none
//! ```
//!
//! and confirm none of those crates appear. The dep graph is
//! load-bearing: an adapter import is an unresolved-import compile
//! error, not a review finding.
//!
//! # Authn / authz
//!
//! - Every call extracts the caller via
//!   [`hort_http_core::authz::extractors::AuthenticatedCaller`] (any
//!   authenticated user passes; per-category authz happens inside the
//!   handler).
//! - Admin-only categories (`Policy`, `Authorization`, `User`, `Admin`,
//!   `AuthAttempts`) require `Permission::Admin`; everything else
//!   filters per-event.
//!
//! # Composition wiring
//!
//! [`router`] returns a `Router<Arc<AppContext>>`. Composition calls
//! `hort_http_events::router().with_state(ctx)` and merges the result
//! onto the workspace router. The existing
//! `event_store: Arc<EventStorePublisher>` is the only port this crate
//! reaches for.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use hort_http_core::context::AppContext;

pub mod dto;
pub mod handler;

/// Build the events pull-resync router. Path string is absolute —
/// composition mounts via `Router::merge` so the route prefix lives
/// next to the handler (same pattern as other per-subsystem crates).
pub fn router() -> Router<Arc<AppContext>> {
    Router::new().route("/api/v1/events", get(handler::get_events))
}
