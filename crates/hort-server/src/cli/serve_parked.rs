//! Config-invalid **park** server (Spec 076 §5.6).
//!
//! When boot-time gitops apply fails with a **provably-pre-write** error
//! (`GitopsBootError::Parse | Read | Walk | PreflightValidate` — see
//! [`crate::gitops_boot::is_park_eligible`]), the process does **not**
//! exit. Instead it binds the public API listener and serves this
//! minimal *config-invalid park* router until `SIGTERM`, so:
//!
//! - the pod stays **Running** (no `CrashLoopBackOff`) and is
//!   inspectable via `kubectl logs`;
//! - `helm upgrade --wait` still fails (readiness never flips to ready),
//!   so a silently-rejected config push can never masquerade as a
//!   successful rollout — loud failure preserved (§5.4);
//! - the operator sees the **exact** error in the logs (the full
//!   rendered `GitopsBootError` is logged by the caller; it is NOT echoed
//!   in any HTTP body — N1 / §5.5).
//!
//! Routes (everything fail-closed — no data/API routes are mounted):
//!
//! - `/healthz` → `200`  (process is alive; the kubelet must NOT restart
//!   — a restart cannot fix a bad config, and crashloop is exactly what
//!   we are removing).
//! - `/readyz`  → `503` with a **status-only** JSON body
//!   `{"status":"config_invalid"}` — no error detail (N1: the API
//!   listener is the unauthenticated public artifact tier; a serde parse
//!   error can echo the offending field value, so the body carries the
//!   status string only).
//! - any other route → `503`.
//!
//! Why crash on `Validate | Apply`: those are mid-write-capable, and
//! `ApplyConfigUseCase` ships no rollback on purpose — its safety rests
//! on "boot exits non-zero on a half-applied state" (Spec 076 §5.3). The
//! pre-write validation/lint that *can* be parked is run separately by
//! `apply_inner` (via `ApplyConfigUseCase::preflight_validate`) BEFORE
//! `apply()` and surfaces as the park-eligible `PreflightValidate` (H14);
//! `Validate` here is only the in-stage validation that survives into the
//! write stages. The caller in `cli/serve.rs` enforces the split via
//! `is_park_eligible`; this module only ever runs for the park-eligible
//! classes.

use std::net::SocketAddr;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::serve_loop::{serve_with_hyper_util, HttpTimeouts};

/// `/readyz` status string for a config-invalid parked pod. Status-only
/// by design — never an error detail (N1 / §5.5).
const CONFIG_INVALID_STATUS: &str = "config_invalid";

/// Liveness — the process is alive. Always `200`: a restart cannot fix a
/// bad config, so the kubelet must not loop the pod.
async fn park_healthz() -> impl IntoResponse {
    StatusCode::OK
}

/// Readiness — never ready while the config is invalid. `503` with a
/// **status-only** JSON body (no error detail — N1 / §5.5).
async fn park_readyz() -> impl IntoResponse {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "status": CONFIG_INVALID_STATUS })),
    )
}

/// Fallback — every other route is `503`. No data/API routes are mounted
/// (fail-closed; §5.5).
async fn park_fallback() -> impl IntoResponse {
    StatusCode::SERVICE_UNAVAILABLE
}

/// Build the minimal park router: `/healthz`→200, `/readyz`→503
/// (status-only body), everything else→503.
fn build_park_router() -> Router {
    Router::new()
        .route("/healthz", get(park_healthz))
        .route("/readyz", get(park_readyz))
        .fallback(park_fallback)
}

/// Bind the public API listener and serve the config-invalid park router
/// until `shutdown` fires (SIGTERM), then exit gracefully so a rollout
/// can replace the pod.
///
/// Reuses the existing serve machinery: the same
/// [`serve_with_hyper_util`] accept loop the live listeners use, driven
/// by the same [`CancellationToken`] the [`crate::shutdown::ShutdownHandle`]
/// produces. Returns `Ok(())` on a clean shutdown so the process exits
/// `0` (the rollout already failed via readiness; the exit code is moot,
/// but a clean exit keeps the kubelet from logging it as a crash).
///
/// `shutdown` is the codebase's shutdown signal — a `CancellationToken`
/// (see [`crate::shutdown::ShutdownHandle::token`]); the caller installs
/// a `ShutdownHandle` and passes its token clone.
pub async fn serve_config_invalid_park(
    api_bind_addr: SocketAddr,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(api_bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("binding park API listener on {api_bind_addr}: {e}"))?;
    info!(
        addr = %api_bind_addr,
        "config-invalid park: serving /healthz=200 /readyz=503 (status-only) until SIGTERM"
    );
    let router = build_park_router();
    serve_with_hyper_util(listener, router, HttpTimeouts::defaults(), shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    /// `/healthz` → 200 (process alive; kubelet must not restart).
    #[tokio::test]
    async fn park_healthz_returns_200() {
        let response = build_park_router()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// `/readyz` → 503 with a STATUS-ONLY body (N1 / §5.5): the body is
    /// exactly `{"status":"config_invalid"}` and carries NO error detail.
    #[tokio::test]
    async fn park_readyz_returns_503_status_only_body() {
        let response = build_park_router()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Exactly one field, status-only — no error detail leaked (N1).
        assert_eq!(value, json!({ "status": "config_invalid" }));
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 1, "readyz body must be status-only, got {value}");
        assert!(
            !obj.contains_key("error"),
            "readyz body must NOT carry an error detail (N1), got {value}"
        );
    }

    /// An arbitrary route → 503 (no data/API routes mounted; fail-closed).
    #[tokio::test]
    async fn park_arbitrary_route_returns_503() {
        let response = build_park_router()
            .oneshot(
                Request::get("/api/v1/artifacts/anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A non-probe POST also falls through to the 503 fallback.
    #[tokio::test]
    async fn park_post_to_root_returns_503() {
        let response = build_park_router()
            .oneshot(Request::post("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The serve loop exits gracefully when the shutdown token fires —
    /// pins that a rollout's SIGTERM lets the parked pod be replaced
    /// (§5.6). Bind to port 0 so the OS picks a free port (no fixed-port
    /// contention in the test suite).
    #[tokio::test]
    async fn serve_config_invalid_park_exits_on_shutdown() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let handle = tokio::spawn(async move { serve_config_invalid_park(addr, token).await });

        // Give the listener a moment to bind, then signal shutdown.
        tokio::task::yield_now().await;
        shutdown.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("park serve did not exit within 5s of shutdown")
            .expect("park serve task panicked");
        assert!(result.is_ok(), "park serve returned Err: {result:?}");
    }
}
