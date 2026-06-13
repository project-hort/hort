//! `GET /metrics` — Prometheus scrape endpoint.
//!
//! Renders the current snapshot of the `PrometheusRecorder` held by the
//! `AppContext` in the standard Prometheus text exposition format
//! (`text/plain; version=0.0.4`).
//!
//! **Security:** This endpoint reveals repository names, package counts, and
//! error rates. It MUST NOT be exposed to the public internet. In production
//! the binary should bind this handler to a separate admin port via
//! `hort_server::http::build_admin_router` and restrict access at the network
//! layer (NetworkPolicy, firewall, mTLS on the proxy). See
//! `docs/metrics-catalog.md` (ADR 0017).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::context::AppContext;

/// Prometheus exposition content type. Version 0.0.4 is the stable text
/// format emitted by `PrometheusHandle::render`.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Render the current Prometheus metrics snapshot as text.
pub async fn render_metrics(State(ctx): State<Arc<AppContext>>) -> impl IntoResponse {
    let body = ctx.metrics_handle.render();
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        body,
    )
}
