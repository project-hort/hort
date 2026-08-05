//! `GET /metrics` — Prometheus scrape endpoint.
//!
//! Renders the current snapshot of the `PrometheusRecorder` held by the
//! `AppContext` in the standard Prometheus text exposition format
//! (`text/plain; version=0.0.4`).
//!
//! **Security:** This endpoint reveals repository names, package counts, and
//! error rates. It MUST NOT be exposed to the public internet. Network
//! position is defense-in-depth only, never the sole gate — the handler
//! itself requires `Permission::ReadMetrics` via
//! [`MetricsReaderPrincipal`](crate::authz::MetricsReaderPrincipal) (issue
//! #113). In production the binary should ALSO bind this handler to a
//! separate admin port via `hort_server::http::build_admin_router` and
//! restrict access at the network layer (NetworkPolicy, firewall, mTLS on
//! the proxy). See `docs/metrics-catalog.md` (ADR 0017).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::authz::MetricsReaderPrincipal;
use crate::context::AppContext;

/// Prometheus exposition content type. Version 0.0.4 is the stable text
/// format emitted by `PrometheusHandle::render`.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Render the current Prometheus metrics snapshot as text.
pub async fn render_metrics(
    _reader: MetricsReaderPrincipal,
    State(ctx): State<Arc<AppContext>>,
) -> impl IntoResponse {
    let body = ctx.metrics_handle.render();
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use chrono::Utc;
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::AuthContext;
    use crate::middleware::auth::AuthenticatedPrincipal;
    use crate::test_support::build_mock_ctx;

    fn principal(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Global (`repository_id = None`) `read_metrics` grant on the
    /// `scraper` claim — the scraper-`ServiceAccount` shape D3 describes.
    fn rbac_with_read_metrics_grant() -> RbacEvaluator {
        RbacEvaluator::new(vec![PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["scraper".into()]),
            repository_id: None,
            permission: Permission::ReadMetrics,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }])
    }

    fn enabled_ctx(rbac: RbacEvaluator) -> Arc<AppContext> {
        let (base, _mocks) = build_mock_ctx(prom_handle());
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(hort_app::use_cases::test_support::MockUserRepository::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            vec![],
        ));
        crate::test_support::with_auth(
            &base,
            AuthContext::Enabled {
                authenticate,
                rbac: Arc::new(arc_swap::ArcSwap::from_pointee(rbac)),
                issuer_url: None,
            },
        )
    }

    fn prom_handle() -> metrics_exporter_prometheus::PrometheusHandle {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle()
    }

    fn metrics_router(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route("/metrics", get(render_metrics))
            .with_state(ctx)
    }

    fn run_async<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Handler-level integration: gate is actually wired on the route, not
    /// just present in the function signature. Anonymous scrape → 401 (the
    /// pre-#113 behavior was a 200 leak of the repo-labelled exposition).
    #[test]
    fn render_metrics_returns_401_when_anonymous() {
        let status = run_async(async {
            let ctx = enabled_ctx(rbac_with_read_metrics_grant());
            let router = metrics_router(ctx);
            let mut req = Request::get("/metrics").body(Body::empty()).unwrap();
            req.extensions_mut()
                .insert::<Option<AuthenticatedPrincipal>>(None);
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// Authenticated but no `read_metrics` grant → 403 (the authz gap this
    /// item closes: previously any authenticated principal scraped).
    #[test]
    fn render_metrics_returns_403_without_grant() {
        let status = run_async(async {
            let ctx = enabled_ctx(rbac_with_read_metrics_grant());
            let router = metrics_router(ctx);
            let mut req = Request::get("/metrics").body(Body::empty()).unwrap();
            req.extensions_mut()
                .insert(AuthenticatedPrincipal::from_validated(principal(&[
                    "reader",
                ])));
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// `read_metrics`-granted caller reaches the handler and gets the
    /// Prometheus exposition back.
    #[test]
    fn render_metrics_returns_200_with_grant() {
        let (status, content_type) = run_async(async {
            let ctx = enabled_ctx(rbac_with_read_metrics_grant());
            let router = metrics_router(ctx);
            let mut req = Request::get("/metrics").body(Body::empty()).unwrap();
            req.extensions_mut()
                .insert(AuthenticatedPrincipal::from_validated(principal(&[
                    "scraper",
                ])));
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            (status, content_type)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some(PROMETHEUS_CONTENT_TYPE));
    }
}
