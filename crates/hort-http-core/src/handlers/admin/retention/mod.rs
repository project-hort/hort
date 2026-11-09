//! HTTP endpoints for retention's **held-set overview** — the
//! operator-facing view of the artifacts the release gate is holding
//! pending a signature.
//!
//! ADR 0039 D4 declines to put a deadline on an unsigned hold and argues
//! it on exactly one ground: an operator can see the held set *and its
//! age*. It names two surfaces — the admin curation queue, and "once it
//! exists, retention's overview, where disposal is operator-confirmed
//! and never decided automatically". This module is the second of those.
//!
//! Routes (both `GET`, both read-only):
//! - `GET /api/v1/admin/retention/overview` ([`overview::get_overview`])
//!   — the aggregate: row count, distinct-content count and oldest age
//!   per `(repository, bucket)`.
//! - `GET /api/v1/admin/retention/held?bucket=…` ([`held::get_held`]) —
//!   the drill-down an operator acts on, keyset-paginated.
//!
//! # The aggregate is named after what it measures
//!
//! The response field, the use case and the docs all say
//! **`held_pending_signature_candidates`** — not "held artifacts" and
//! not "artifacts the gate is holding". The aggregate resolves the
//! policy and the window expiry in SQL and deliberately stops short of
//! the provenance clearance verdict, which has exactly one computation
//! in `hort-app` (two independent ones drifted once, and the drift was a
//! HIGH finding). So it is a declared superset, and its name says so.
//! The drill-down resolves every row through that one authority and is
//! exact.
//!
//! # No new permission
//!
//! Both routes are gated by
//! [`CurateOrAdminPrincipal`](crate::authz::CurateOrAdminPrincipal) —
//! either `Permission::Curate` or `Permission::Admin` satisfies it, the
//! same gate as `/api/v1/admin/curation/*`. `Curate` is already the
//! decision authority over quarantined and rejected artifacts, which is
//! exactly the set this shows. A new `Permission` would cost a DB enum
//! migration, grant upkeep and a token rotation — the token cap is
//! frozen at issuance (ADR 0012) — without separating an authority that
//! should be separate.
//!
//! # Mounting
//!
//! `hort-server::http::control_plane_routes` is the mount site; mount
//! with `.nest("/api/v1/admin/retention", retention_routes())`. Mirrors
//! [`curation_routes`](super::curation::curation_routes), which sits
//! beside it under the same gate.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use crate::context::AppContext;

pub mod held;
pub mod overview;

/// Build the retention read sub-router.
///
/// Returns a `Router<Arc<AppContext>>` carrying the two read endpoints;
/// the caller mounts it at `/api/v1/admin/retention/`. Every route is
/// gated by [`CurateOrAdminPrincipal`](crate::authz::CurateOrAdminPrincipal)
/// declared as a handler-level extractor — forgetting it leaves the
/// handler with no validated principal in scope, which is a compile
/// error rather than a 403 at runtime.
pub fn retention_routes() -> Router<Arc<AppContext>> {
    Router::new()
        .route("/overview", get(overview::get_overview))
        .route("/held", get(held::get_held))
}

#[cfg(test)]
mod tests {
    //! Sub-router assertions: both paths are mounted where the module
    //! docs say, and the surface is read-only.

    use super::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use crate::test_support::build_mock_ctx;

    /// Mount the sub-router exactly as `control_plane_routes` does, so
    /// the asserted paths are the paths an operator reaches.
    fn router() -> Router {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, _mocks) = build_mock_ctx(metrics);
        Router::new()
            .nest("/api/v1/admin/retention", retention_routes())
            .with_state(ctx)
    }

    /// Both documented paths exist. An unmounted route would not 404
    /// here — axum falls through to the method-not-allowed / not-found
    /// fallback — so the discriminator is "not 404", which is what
    /// separates a mounted gated route from a missing one.
    #[tokio::test]
    async fn both_documented_paths_are_mounted() {
        for path in [
            "/api/v1/admin/retention/overview",
            "/api/v1/admin/retention/held",
        ] {
            let resp = router()
                .oneshot(Request::get(path).body(Body::empty()).expect("request"))
                .await
                .expect("response");
            assert_ne!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{path} is not mounted; the module docs promise it"
            );
        }
    }

    /// The surface is **read-only over the artifact set**: disposal of a
    /// held artifact is operator-confirmed (propose → confirm →
    /// execute) and deliberately does not exist here. A write verb
    /// appearing on either path is the regression.
    #[tokio::test]
    async fn neither_path_accepts_a_write_verb() {
        for path in [
            "/api/v1/admin/retention/overview",
            "/api/v1/admin/retention/held",
        ] {
            for method in ["POST", "DELETE", "PUT", "PATCH"] {
                let req = Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request");
                let resp = router().oneshot(req).await.expect("response");
                assert_eq!(
                    resp.status(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path} must not be routed"
                );
            }
        }
    }

    // The `CurateOrAdminPrincipal` gate itself is asserted where the
    // auth context is wired: `overview::tests::overview_unauthorized_returns_403`
    // and `held::tests::held_unauthorized_returns_403`, each also
    // checking that a refused caller never reaches the port. This module
    // asserts the routing, which needs no auth context.
}
