//! `/healthz` and `/readyz` — Kubernetes-style liveness + readiness probes
//! on the public listener, consumed by the kubelet.
//!
//! - **`/healthz`** returns 200 unconditionally. Process-liveness only;
//!   the kubelet `livenessProbe` uses this to decide whether to restart
//!   the pod. A successful HTTP response means the axum router is
//!   accepting traffic — no dependency check, by design (a flaky DB
//!   should not trigger a pod restart loop).
//! - **`/readyz`** returns 200 only when the event store responds to a
//!   trivial ping (the Postgres adapter implements this as `SELECT 1`
//!   on the same `PgPool` that backs every event-store operation, so a
//!   successful ping confirms both DB-pool acquisition and DB
//!   responsiveness in one call). Otherwise 503. Used by the kubelet
//!   `readinessProbe` to remove the pod from Service endpoints during
//!   transient infrastructure failures.
//!
//! Both endpoints are mounted on the **public** router in
//! `hort_server::http::build_router_with_oci_config` and bypass the
//! authentication middleware: kubelet probes do not carry credentials.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use hort_domain::ports::event_store::EventStore;

use crate::context::AppContext;

/// Liveness probe — process is alive and the HTTP router is serving.
///
/// No dependency check. If the request reaches this handler, the
/// process is responsive enough to satisfy livenessProbe; downstream
/// failures are the readiness probe's concern.
pub async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

/// Readiness probe — service is ready to accept traffic.
///
/// Pings the event store; the Postgres adapter implements this as a
/// `SELECT 1` round-trip on the `PgPool` that backs every other
/// event-store operation, so one ping covers both DB pool acquisition
/// and DB responsiveness. The mock event store's default impl returns
/// `Ok(())`, so router tests with the mock context observe the
/// happy-path branch unless they explicitly inject a failing store.
///
/// Returns 200 on success, 503 on failure. The failure path emits a
/// `tracing::warn!` with the underlying error reason so operators can
/// see *why* readiness flipped without scraping the event-store
/// adapter's own logs.
pub async fn readyz(State(ctx): State<Arc<AppContext>>) -> impl IntoResponse {
    match ctx.event_store.health_check().await {
        Ok(()) => StatusCode::OK,
        Err(err) => {
            tracing::warn!(error = %err, "readyz: event store health check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::events::{PersistedEvent, StreamCategory, StreamId};
    use hort_domain::ports::event_store::{
        AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
    };
    use hort_domain::ports::BoxFuture;

    use crate::test_support::{build_mock_ctx, with_event_store};

    /// Event store that always reports unhealthy. Used to drive the
    /// 503 branch of `readyz` without standing up Postgres.
    struct AlwaysFailingEventStore;

    impl EventStore for AlwaysFailingEventStore {
        fn append(&self, _batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "AlwaysFailingEventStore: append not used by /readyz tests".into(),
                ))
            })
        }

        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn read_category(
            &self,
            _category: StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "simulated event store outage".into(),
                ))
            })
        }

        // not exercised by /readyz tests
        fn delete_stream(&self, _stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!("not exercised by /readyz tests") })
        }

        // not exercised by /readyz tests
        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!("not exercised by /readyz tests") })
        }
    }

    fn build_router(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .with_state(ctx)
    }

    #[tokio::test]
    async fn healthz_returns_200_with_empty_body() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let (ctx, _mocks) = build_mock_ctx(handle);

        let response = build_router(ctx)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 64).await.unwrap();
        assert!(
            bytes.is_empty(),
            "healthz body should be empty, got {bytes:?}"
        );
    }

    #[tokio::test]
    async fn readyz_returns_200_when_event_store_healthy() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // Default `MockEventStore` inherits the trait's
        // `health_check` default (`Ok(())`), so this drives the
        // happy path without extra wiring.
        let (ctx, _mocks) = build_mock_ctx(handle);

        let response = build_router(ctx)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_event_store_unhealthy() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let (base, _mocks) = build_mock_ctx(handle);

        // Swap the event store for one that always fails. Every other
        // field carries forward from `base` via the `with_event_store`
        // helper — no inline AppContext wiring duplicated here.
        let ctx = with_event_store(&base, Arc::new(AlwaysFailingEventStore));

        let response = build_router(ctx)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
