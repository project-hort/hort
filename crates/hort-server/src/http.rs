//! Top-level router assembly for the v2 service binary.
//!
//! Nests each `hort-http-<format>` crate under its path prefix, merges the
//! OCI `/v2/*` subtree (OCI Distribution spec mandates the exact path),
//! and hands the resulting tree to
//! [`hort_http_core::router::wrap_with_middleware`] for the shared
//! cross-cutting layers (trust, security headers, metrics, rate limit,
//! auth). The per-format route trees themselves live in their dedicated
//! `hort-http-<format>` crates (ADR 0008); routing authority and API
//! versioning are covered by ADR 0011.
//!
//! The assembly intentionally lives in the binary crate: it is the only
//! place in the workspace that knows the full catalogue of mounted
//! formats, and keeping it here means the compile-time adapter-free
//! property of `hort-http-core` + `hort-http-<format>` holds without a
//! separate enforcement crate.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use hort_http_core::context::AppContext;
use hort_http_core::handlers::admin;
use hort_http_core::handlers::health::{healthz, readyz};
use hort_http_core::handlers::metrics::render_metrics;
use hort_http_core::middleware;
use hort_http_core::router::wrap_with_middleware;
use hort_http_oci::OciHttpConfig;

/// Build the top-level axum router with every per-format handler mounted.
///
/// Test-only convenience: production callers in `cli::serve` go through
/// [`build_router_with_oci_config`] so they can thread the
/// `HORT_OCI_LEGACY_CATALOG_ENABLED` operator flag in.
///
/// When `include_metrics` is true, `GET /metrics` is mounted on the main
/// router — appropriate for developer/single-listener deployments. In
/// production, callers set this to `false` and expose `/metrics` on a
/// dedicated admin listener via [`build_admin_router`] so ingress rules can
/// keep scrape traffic off the public network. See
/// `docs/metrics-catalog.md` and ADR 0017.
///
/// `metrics_require_auth` gates whether the
/// `/metrics` route mounted here requires admin authentication. The
/// production default is `true`; operators with a legacy Prometheus
/// scrape config that cannot supply a bearer token may opt out via
/// `HORT_METRICS_REQUIRE_AUTH=false` (the binary emits a startup `WARN`
/// in that case). Test callers that don't care about the flag should
/// pass `true` to mirror production posture.
///
/// Default: token exchange (`POST /api/v1/auth/exchange`, ADR 0013) is
/// **OFF**. Tests that need the route mount go through
/// [`build_router_with_oci_config`] with `enable_token_exchange = true`.
pub fn build_router(
    ctx: Arc<AppContext>,
    include_metrics: bool,
    metrics_require_auth: bool,
) -> Router {
    build_router_with_oci_config(
        ctx,
        include_metrics,
        &OciHttpConfig::default(),
        metrics_require_auth,
        false,
        false,
    )
}

/// The internal-only control-plane route subtree.
///
/// Exactly the routes classified as the
/// internal-only **control plane**: the legacy repository-admin API
/// (`/admin/*`), the `/api/v1/admin/tasks` admin-task surface, and the
/// `/api/v1/subscriptions` subscription-*management* surface (including
/// the `/api/v1/admin/subscriptions` admin list). These are the routes
/// operators reasonably assume are internal but which today share the
/// public listener.
///
/// **Deliberately NOT here** (public by requirement — moving any of
/// these onto the internal tier is the anti-pattern this split exists
/// to avoid):
/// `/api/v1/auth/exchange`, `/api/v1/auth`, OCI `/v2/auth`, every
/// artifact-pull route, the `/api/v1/events` pull-resync read API, the
/// `/api/v1/...security-score` read surface, and the self-service
/// `/api/v1/users/me/tokens` token endpoints. The token-generation
/// plane is public *by requirement* — its only protections are
/// app-layer (rate limiting + credential hygiene), and that is
/// intentional.
///
/// Used by both [`build_control_router`] (when `HORT_CONTROL_BIND` is
/// set) and the main assembly (merged in when the split is OFF, so
/// behaviour is byte-identical to the unsplit layout).
fn control_plane_routes() -> Router<Arc<AppContext>> {
    Router::new()
        // Mounted at `/api/v1/admin`, matching every consumer —
        // hort-cli's admin subcommands request
        // `/api/v1/admin/{users,quarantine,rbac}/...`, the per-user
        // `claim_based_authority` hint points there, and the sibling
        // `/api/v1/admin/{curation,policies,tasks}` nests below share
        // the prefix.
        .nest("/api/v1/admin", admin::admin_routes())
        // Curator decision surface
        // (`POST /api/v1/admin/curation/quarantine/:id/{waive,block}` +
        // `POST /api/v1/admin/curation/block-versions`). The three
        // routes are gated by `CurateOrAdminPrincipal` (NOT the global
        // `AdminPrincipal` that protects `/admin/*`) so a non-admin
        // curator can drive the day-to-day decision surface without
        // elevating to admin.
        .nest("/api/v1/admin/curation", admin::curation::curation_routes())
        // Finding-exclusion write surface
        // (`POST/DELETE /api/v1/admin/policies/:policy_id/exclusions[/:cve_id]`).
        // Same `CurateOrAdminPrincipal` gate as `/api/v1/admin/curation/*`
        // — curator-driven exclusion-management does not require admin
        // elevation. The use case (`PolicyUseCase::{add,remove}_exclusion`)
        // signature is permission-neutral; the HTTP layer is the single
        // permission source of truth for this surface (gitops apply
        // continues to call the same use case with `Actor::Gitops`).
        .nest("/api/v1/admin/policies", admin::policies::policies_routes())
        // Admin-task REST surface
        // (`POST/GET /api/v1/admin/tasks...`).
        .nest("/api/v1/admin/tasks", hort_http_admin_tasks::router())
        // Admin native-API-token routes
        // (`POST /api/v1/admin/users/:user_id/tokens` service-account
        // mint, `DELETE /api/v1/admin/tokens/:id` admin-revoke). These
        // were factored out of `api_token_routes()` (which keeps the
        // public self-service `/users/me/tokens*` plane) so they move
        // to the control listener with the rest of `/api/v1/admin/*`.
        // `admin_token_routes()` returns `/api/v1`-relative paths, so
        // `.nest("/api/v1", ...)` (same shape as the public mount).
        .nest(
            "/api/v1",
            hort_http_core::handlers::api_tokens::admin_token_routes(),
        )
        // Subscription *management* surface.
        // The crate defines absolute `/api/v1/subscriptions...` (and
        // `/api/v1/admin/subscriptions`) paths inside `router()`, so we
        // `.merge` rather than `.nest` (same pattern as the other
        // absolute-path route trees).
        .merge(hort_http_subscriptions::router())
}

/// Extended variant of [`build_router`] that threads a per-handler
/// [`OciHttpConfig`] into the OCI route tree.
///
/// `cli::serve` parses the `HORT_OCI_*` environment variables into the
/// config and calls this function; tests call the default-config
/// [`build_router`] unless they specifically exercise a legacy-catalog
/// path. Per-handler config lives in the per-format crate (`hort-http-oci`)
/// to keep the shared [`AppContext`] OCI-agnostic.
///
/// `control_split`: when `false` (the default,
/// and the value `cli::serve` passes whenever `HORT_CONTROL_BIND` is
/// unset) the control-plane routes ([`control_plane_routes`]) are
/// merged into this public/main tree — **byte-identical to the
/// unsplit layout, no migration**. When `true`, those routes
/// are omitted here because they are served on the dedicated internal
/// control listener instead ([`build_control_router`]); the public
/// listener then genuinely cannot reach the admin / subscription-
/// management surface.
pub fn build_router_with_oci_config(
    ctx: Arc<AppContext>,
    include_metrics: bool,
    oci_http_config: &OciHttpConfig,
    metrics_require_auth: bool,
    enable_token_exchange: bool,
    control_split: bool,
) -> Router {
    // Per-publish body-size ceiling. PyPI and npm
    // share the same 300 MiB default (`DEFAULT_PUBLISH_BODY_LIMIT`);
    // operators can override both via `HORT_PUBLISH_BODY_MAX_SIZE`.
    // Cargo carries its own fixed 200 MiB ceiling — not threaded through
    // the env override (see `hort_http_core::limits::CARGO_PUBLISH_BODY_LIMIT`).
    let publish_limit = ctx
        .publish_body_limit_bytes
        .unwrap_or(hort_http_core::limits::DEFAULT_PUBLISH_BODY_LIMIT);

    // Per-request deadline.
    //
    // The non-OCI subtree (admin + cargo + npm + pypi) gets the global
    // default request deadline applied here before the merge with the
    // OCI subtree. The OCI subtree (`oci_routes_with_config`) applies
    // its own pair of timeout layers internally — the longer 60-minute
    // ceiling on POST/PATCH/PUT against `/v2/.../blobs/uploads/...`
    // and the global default on the metadata/pull routes.
    //
    // Why apply timeouts BEFORE the merge? `Router::merge` preserves
    // per-router layer stacks; if we instead applied a global timeout
    // post-merge via `Router::layer`, it would wrap the OCI uploads'
    // own override and the longer ceiling would never take effect.
    // The merge-then-don't-relayer pattern is the only structural way
    // to give merged subtrees independent per-request deadlines.
    // See `docs/operator/http-transport-timeouts.md` for the operator
    // summary.
    // When `HORT_TOKEN_EXCHANGE_ENABLED=true`, merge
    // the `/auth/exchange` route (ADR 0013) into the same `/api/v1`
    // subtree as the existing token endpoints. When `false`, the route
    // is not mounted and axum's default 404 fires (matches the
    // "no surface advertised" requirement). The `/exchange` route is
    // mounted regardless of `AuthConfig` variant — the federated-JWT
    // branch works without an interactive IdP configured.
    let mut api_v1: Router<Arc<AppContext>> =
        hort_http_core::handlers::api_tokens::api_token_routes();
    if enable_token_exchange {
        api_v1 = api_v1.merge(hort_http_core::handlers::exchange::token_exchange_routes());
    }
    let mut non_oci: Router<Arc<AppContext>> = Router::new()
        // PUBLIC self-service API token endpoints (ADR 0012).
        // Mounted under `/api/v1`:
        //   POST   /api/v1/users/me/tokens             — self-mint
        //   DELETE /api/v1/users/me/tokens/:id         — self-revoke
        //   GET    /api/v1/users/me/tokens             — list own
        // When token exchange is enabled, also:
        //   POST   /api/v1/auth/exchange               — RFC 8693 exchange
        // The two ADMIN token routes
        // (`POST /api/v1/admin/users/:user_id/tokens` admin-mint,
        // `DELETE /api/v1/admin/tokens/:id` admin-revoke) are NOT
        // here — they live in `admin_token_routes()` and
        // ride `control_plane_routes()` with the rest of
        // `/api/v1/admin/*`. `api_v1` is still a *mixed* nest
        // (self-service token mint + the public-by-requirement
        // `/auth/exchange`), so it stays on the public listener.
        .nest("/api/v1", api_v1)
        // Admin security-score REST surface.
        //   GET /api/v1/repositories/:name/security-score
        //   GET /api/v1/security-score?cursor=...&limit=...
        // No adapter imports in `hort-http-admin-security`; depends only
        // on `hort-app` use cases + `hort-http-core` AppContext.
        // Deliberately NOT under `/api/v1/admin/*` and not subscription
        // management — stays on the public listener (authz-gated).
        .nest("/api/v1", hort_http_admin_security::router::routes())
        // JWT-only discovery + self-service prefetch REST surface
        // (see `docs/architecture/explanation/prefetch-pipeline.md`).
        //   GET  /api/v1/repositories/:repo_key/discovery/versions/:package_name
        //   POST /api/v1/repositories/:repo_key/prefetch
        // No adapter imports in `hort-http-discovery`; depends only on
        // `hort-app` use cases + `hort-http-core` AppContext.
        // Deliberately NOT under `/api/v1/admin/*` and not subscription
        // management — stays on the public listener (token-kind +
        // RBAC gated by the use case). Mounted as a second
        // `.nest("/api/v1", ...)` alongside `hort-http-admin-security`
        // above (axum supports
        // two `.nest` calls at the same prefix as long as the inner
        // path sets don't collide; `/repositories/:repo_key/discovery/...`
        // and `/repositories/:repo_key/prefetch` do not collide with the
        // admin-security `/repositories/:name/security-score`).
        .nest("/api/v1", hort_http_discovery::routes())
        // Auth surface.
        //   GET /api/v1/auth/whoami  — return current principal
        .nest(
            "/api/v1/auth",
            hort_http_core::handlers::auth::auth_routes(),
        )
        // Event-notification *read* surface (see
        // `docs/architecture/explanation/event-notifications.md`).
        //   GET /api/v1/events?category=...&after=...  — pull resync
        // The subscription-*management* surface
        // (`POST/GET/PATCH/DELETE /api/v1/subscriptions`,
        // `/api/v1/admin/subscriptions`) is control-plane and lives in
        // `control_plane_routes()`; only the events pull-resync read
        // API stays here. When `HORT_NOTIFICATIONS_ENABLED=false`, the
        // routes stay mounted but the dispatcher is not spawned
        // ("flag-off short-circuits").
        .merge(hort_http_events::router())
        .nest("/cargo", hort_http_cargo::cargo_routes())
        .nest(
            "/npm",
            hort_http_npm::npm_routes_with_publish_limit(publish_limit),
        )
        .nest(
            "/pypi",
            hort_http_pypi::pypi_routes_with_publish_limit(publish_limit),
        )
        .nest("/maven", hort_http_maven::maven_routes());
    // Control-plane placement.
    //
    // When the control split is OFF (`HORT_CONTROL_BIND` unset — the
    // default), the admin / admin-task / subscription-management routes
    // are merged into this public/main tree,
    // so behaviour is byte-identical to the unsplit layout and no
    // migration is required. When ON, they are omitted here because
    // `build_control_router` serves them on the dedicated internal
    // listener — the public listener then genuinely cannot reach them.
    if !control_split {
        non_oci = non_oci.merge(control_plane_routes());
    }
    // Anonymous client-bootstrap discovery
    // doc at the absolute path `/.well-known/hort-client-config`
    // (ADR 0013). Only served when the interactive-OIDC path is fully
    // configured (`client_config` present in `AppContext`). Under
    // federation-only deployments (`AuthConfig::Disabled`),
    // `client_config` is `None` and the discovery doc is absent —
    // `hort-cli` device-flow is not supported and serving a half-formed
    // doc would be misleading.
    // `/exchange` itself is mounted unconditionally when
    // `enable_token_exchange=true` (the federated-JWT branch works
    // without the interactive config).
    if ctx.client_config.is_some() {
        non_oci = non_oci.merge(hort_http_core::handlers::well_known::well_known_routes());
    }
    let non_oci = non_oci.layer(middleware::request_timeout::request_timeout_layer(
        ctx.http_timeout_config.request_timeout,
    ));

    let inner: Router<Arc<AppContext>> = non_oci
        // OCI Distribution routes. Merged (not
        // nested) because axum 0.7's `Router::nest` refuses a nested
        // route at `/` — and the OCI spec mandates that the probe live
        // at the exact path `/v2/`. `oci_routes_with_config` registers
        // routes under `/v2/...` absolute and the outer router merges
        // them in. The OCI subtree carries its own per-request
        // deadline layers (long for uploads, short for reads), so the
        // merge intentionally inherits per-side layer stacks.
        .merge(hort_http_oci::oci_routes_with_config(
            oci_http_config,
            ctx.clone(),
        ));

    let wrapped = wrap_with_middleware(ctx.clone(), inner, include_metrics, metrics_require_auth);

    // `/healthz` + `/readyz` kubelet probes.
    //
    // Merged at the TOP level, AFTER `wrap_with_middleware` runs over
    // the rest of the tree, so the probe routes do NOT inherit the
    // auth-dispatch / rate-limit / load-shed / security-headers /
    // request-trust chain. kubelet probes do not carry credentials,
    // and a saturated workspace concurrency cap must not be allowed
    // to flip readiness to a false-positive 503: the whole point of
    // the readiness probe is to signal "ask the kubelet to drain me",
    // and that signal has to survive the very condition (overload)
    // it's trying to communicate.
    //
    // `Router::merge` preserves per-router layer stacks (the same
    // property the OCI subtree relies on for its per-route
    // timeouts), so the wrapped public tree stays wrapped while the
    // probes stay bare.
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(ctx)
        .merge(wrapped)
}

/// Admin-port router containing only `GET /metrics`.
///
/// Bind to a separate admin listener (e.g. via `HORT_METRICS_BIND=127.0.0.1:9090`)
/// so network policy can restrict scrape traffic to the Prometheus namespace
/// without touching the main API listener. The endpoint reveals repository
/// names, error ratios, and traffic volumes — it must never be exposed to
/// the public internet.
///
/// # Middleware stack
///
/// A bare `/metrics` route would be an open
/// reconnaissance surface even when ingress restricted the listener:
/// any attacker reaching the port would see repository names,
/// auth-failure rates, and traffic shape — exactly the signal that lets
/// them time probes around real traffic. The router therefore applies,
/// in builder-chain order (LIFO at runtime, OUTER wraps INNER):
///
/// 1. `require_principal` (innermost) — when `require_auth=true` AND
///    `AuthContext::Enabled`. Anonymous scrapes return 401.
/// 2. Write-rate-limit (skips on GET — `/metrics` is unaffected at
///    runtime but the layer is attached to mirror the public stack).
/// 3. `http_metrics` — counts the scrape requests themselves so
///    operators see meta-metrics on Prometheus health.
/// 4. `security_headers` — `X-Content-Type-Options`, `X-Frame-Options`,
///    `Referrer-Policy` injected on the scrape response.
/// 5. `request_trust` (outermost) — populates `RequestTrust` so the
///    auth layer's audit-log line carries `client_ip`.
///
/// `require_auth=false` is the legacy escape hatch
/// (`HORT_METRICS_REQUIRE_AUTH=false`); operators get the four other
/// hardening layers but anonymous scrape returns 200.
pub fn build_admin_router(ctx: Arc<AppContext>, require_auth: bool) -> Router {
    let mut router: Router<Arc<AppContext>> = Router::new().route("/metrics", get(render_metrics));

    // `require_principal` carve-out.
    //
    // Only attached when both `require_auth=true` AND auth is wired
    // (`AuthContext::Enabled`). The runtime-startup guard
    // (`ensure_auth_enabled`) refuses to boot under
    // `AUTH=disabled`, so the `Disabled` branch only fires from
    // mock-context tests; we mirror the public router's gate to keep
    // those tests' anonymous-pass-through behaviour intact.
    if require_auth && ctx.auth.has_auth() {
        router = router.layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            middleware::auth::require_principal,
        ));
    }

    // Same five-layer hardening stack the public router gets via
    // `wrap_with_middleware` (minus the auth-rate-limit layer — the
    // admin scrape path doesn't run the IdP-bearer pipeline that the
    // auth-rate-limit defends). Builder-chain order (LIFO at runtime):
    //
    //   1. require_principal     (innermost — attached above)
    //   2. write_rate_limit      (wraps 1)
    //   3. http_metrics          (wraps 2)
    //   4. security_headers      (wraps 3)
    //   5. request_trust         (outermost — wraps 4)
    //
    // `request_trust` MUST be outermost so `client_ip` is populated
    // before the auth layer's audit log reads it; same invariant as
    // the public router (see `wrap_with_middleware`).
    router
        .layer(middleware::rate_limit::write_rate_limit_layer(
            &ctx.rate_limit_config,
        ))
        .layer(axum::middleware::from_fn(
            middleware::metrics::http_metrics_middleware,
        ))
        .layer(axum::middleware::from_fn(
            middleware::security_headers::security_headers_middleware,
        ))
        .layer(middleware::trust::request_trust_layer(
            ctx.trust_config.clone(),
        ))
        .with_state(ctx)
}

/// Internal-only **control-plane** router.
///
/// Carries exactly the control-plane surface ([`control_plane_routes`]):
/// the `/admin` API, `/api/v1/admin/tasks`, and `/api/v1/subscriptions`
/// management. Bind it to a separate internal listener via
/// `HORT_CONTROL_BIND=127.0.0.1:9443` (or a concrete internal interface)
/// so a NetworkPolicy / firewall can restrict the admin + subscription-
/// management surface to the operator network without touching the
/// public artifact or token-generation planes. Mirrors the
/// `HORT_METRICS_BIND` / [`build_admin_router`] split exactly.
///
/// The token-generation plane (`/api/v1/auth/exchange`, `/api/v1/auth`,
/// OCI `/v2/auth`) and the artifact-pull plane are deliberately **not**
/// on this router — they are public *by requirement* (external push
/// clients / CI must reach them) and are hardened at the application
/// layer instead (anti-replay, audience binding, per-issuer
/// rate-limiting, short TTLs). This listener is **defense-in-depth on
/// top of — never instead of — the admin authorization gate (ADR 0012)
/// and the webhook allowlist**; network position is
/// never a substitute for authz.
///
/// # Middleware stack
///
/// The control routes get the **same** cross-cutting stack the main
/// router applies to them — `request_timeout` (mirroring the non-OCI
/// subtree) then [`wrap_with_middleware`] (auth dispatch, rate limits,
/// load shed, metrics-meta, security headers, request trust). Passing
/// `include_metrics = false` keeps `/metrics` off this listener (it is
/// the metrics/admin listener's job — `build_admin_router`).
/// `metrics_require_auth` is irrelevant here (no `/metrics` route) but
/// threaded through `wrap_with_middleware` as `true` to mirror the
/// production posture, exactly as `build_router`'s callers do.
pub fn build_control_router(ctx: Arc<AppContext>, require_auth: bool) -> Router {
    let control = control_plane_routes().layer(middleware::request_timeout::request_timeout_layer(
        ctx.http_timeout_config.request_timeout,
    ));

    // `require_auth` is consumed as the `metrics_require_auth` slot of
    // `wrap_with_middleware`: there is no `/metrics` route on the
    // control listener, so the value only affects a non-existent
    // carve-out. We forward it (rather than hard-coding `true`) so a
    // deployment running `HORT_METRICS_REQUIRE_AUTH=false` keeps a single
    // consistent auth posture across every listener.
    wrap_with_middleware(ctx, control, false, require_auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockUserRepository,
    };
    use hort_domain::entities::artifact::QuarantineStatus;

    use hort_http_core::context::AuthContext;
    use hort_http_core::test_support::{build_mock_ctx as build_base_ctx, with_auth};

    /// Seed a `pypi-test` repository + one downloadable artifact onto the
    /// shared mock context, so PyPI routes have something to serve.
    fn build_mock_ctx(handle: metrics_exporter_prometheus::PrometheusHandle) -> Arc<AppContext> {
        let (ctx, mocks) = build_base_ctx(handle);

        let mut repo = sample_repository();
        repo.key = "pypi-test".to_string();
        mocks.repositories.insert(repo.clone());

        let mut artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repo.id;
        artifact.name = "pkg".to_string();
        artifact.path = "simple/pkg/pkg-1.0.tar.gz".to_string();
        mocks.artifacts.insert(artifact.clone());
        mocks
            .storage
            .insert_content(artifact.sha256_checksum.clone(), b"payload".to_vec());

        ctx
    }

    /// End-to-end wiring check: drive a PyPI request through the real
    /// router, then scrape `/metrics` and assert the HTTP counters are
    /// present with the **matched route template** as the path label.
    #[test]
    fn build_router_mounts_metrics_and_middleware() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let body_text = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let ctx = build_mock_ctx(handle.clone());
                    let router = build_router(ctx, true, true);

                    let response = router
                        .clone()
                        .oneshot(
                            Request::get("/pypi/pypi-test/simple/pkg/pkg-1.0.tar.gz")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    let _ = to_bytes(response.into_body(), 1024).await.unwrap();

                    let scrape = router
                        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(scrape.status(), StatusCode::OK);
                    let ct = scrape
                        .headers()
                        .get(axum::http::header::CONTENT_TYPE)
                        .expect("Content-Type header missing")
                        .to_str()
                        .unwrap()
                        .to_string();
                    assert!(
                        ct.starts_with("text/plain"),
                        "unexpected content type: {ct}"
                    );
                    let bytes = to_bytes(scrape.into_body(), 64 * 1024).await.unwrap();
                    String::from_utf8(bytes.to_vec()).unwrap()
                })
        });

        assert!(
            body_text.contains("hort_http_responses_total{"),
            "hort_http_responses_total not present in scrape output:\n{body_text}"
        );
        assert!(
            body_text.contains("path=\"/pypi/:repo_key/simple/:project/:filename\""),
            "matched route template missing in scrape output:\n{body_text}"
        );
        assert!(
            !body_text.contains("pypi-test/simple/pkg/pkg-1.0.tar.gz"),
            "concrete URL leaked into /metrics output:\n{body_text}"
        );

        assert!(
            body_text.contains("hort_http_requests_in_flight"),
            "hort_http_requests_in_flight not present:\n{body_text}"
        );

        assert!(
            body_text.contains("hort_http_requests_received_total{"),
            "hort_http_requests_received_total not present:\n{body_text}"
        );
    }

    /// `/v2/` API-version probe is mounted on the
    /// main router and drives through the full middleware stack.
    #[test]
    fn build_router_mounts_oci_v2_version_probe() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let (status, header, body_bytes) = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let ctx = build_mock_ctx(handle.clone());
                    let router = build_router(ctx, false, true);

                    let response = router
                        .oneshot(Request::get("/v2/").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    let status = response.status();
                    let header = response
                        .headers()
                        .get("docker-distribution-api-version")
                        .map(|v| v.to_str().unwrap().to_string());
                    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
                    (status, header, bytes.to_vec())
                })
        });

        assert_eq!(status, StatusCode::OK);
        assert_eq!(header.as_deref(), Some("registry/2.0"));
        assert_eq!(body_bytes, b"{}");
    }

    /// Guard against a future `.layer()` chain
    /// rearrangement silently stripping hardening from the `/v2/` subtree.
    #[test]
    fn build_router_applies_security_headers_on_oci_v2() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let headers = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let ctx = build_mock_ctx(handle.clone());
                    let router = build_router(ctx, false, true);

                    let response = router
                        .oneshot(Request::get("/v2/").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    response.headers().clone()
                })
        });

        assert_eq!(
            headers
                .get("x-content-type-options")
                .map(|v| v.to_str().unwrap()),
            Some("nosniff"),
        );
        assert_eq!(
            headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
            Some("DENY"),
        );
    }

    #[test]
    fn build_admin_router_exposes_metrics_only() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let (metrics_status, pypi_status) = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let ctx = build_mock_ctx(handle.clone());
                    // `require_auth=true` is the production default; the
                    // mock context here is `AuthContext::Disabled`, so
                    // the `require_principal` layer is skipped (mirrors
                    // the public router's gate). Anonymous still 200s.
                    let router = build_admin_router(ctx, true);

                    let metrics_res = router
                        .clone()
                        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    let pypi_res = router
                        .oneshot(
                            Request::get("/pypi/pypi-test/simple/")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    (metrics_res.status(), pypi_res.status())
                })
        });

        assert_eq!(metrics_status, StatusCode::OK);
        assert_eq!(pypi_status, StatusCode::NOT_FOUND);
    }

    /// The internal-only control-plane
    /// listener split, mirroring `build_admin_router_exposes_metrics_only`.
    ///
    /// `build_control_router` carries the control-plane surface (`/admin`,
    /// `/api/v1/admin/tasks`, `/api/v1/subscriptions`) and NOT the public
    /// artifact plane. When the main router is built with the control
    /// split ON (`control_split=true`), `/admin` returns 404 there while
    /// a public PyPI route still serves — proving the admin surface is
    /// genuinely not reachable on the public listener.
    #[test]
    fn build_control_router_carries_control_plane_only_and_main_drops_it() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let (control_admin, control_pypi, main_admin, main_pypi) =
            metrics::with_local_recorder(&recorder, || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let ctx = build_mock_ctx(handle.clone());

                        // Control router: `require_auth=true` is the
                        // production default; mock ctx is
                        // `AuthContext::Disabled`, so `require_principal`
                        // is skipped (mirrors the admin-router gate).
                        let control = build_control_router(ctx.clone(), true);
                        // `/admin/repositories/:key` — the seeded
                        // `pypi-test` repo resolves under
                        // `AuthContext::Disabled` (AdminPrincipal grants
                        // unconditionally), so a routed request is 200.
                        let control_admin_res = control
                            .clone()
                            .oneshot(
                                Request::get("/api/v1/admin/repositories/pypi-test")
                                    .body(Body::empty())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        let control_pypi_res = control
                            .oneshot(
                                Request::get("/pypi/pypi-test/simple/")
                                    .body(Body::empty())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();

                        // Main router with the control split ON: the
                        // control surface is removed; the public artifact
                        // plane still serves.
                        let main = build_router_with_oci_config(
                            ctx,
                            false,
                            &OciHttpConfig::default(),
                            true,
                            false,
                            true,
                        );
                        let main_admin_res = main
                            .clone()
                            .oneshot(
                                Request::get("/api/v1/admin/repositories/pypi-test")
                                    .body(Body::empty())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        let main_pypi_res = main
                            .oneshot(
                                Request::get("/pypi/pypi-test/simple/pkg/pkg-1.0.tar.gz")
                                    .body(Body::empty())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();

                        (
                            control_admin_res.status(),
                            control_pypi_res.status(),
                            main_admin_res.status(),
                            main_pypi_res.status(),
                        )
                    })
            });

        // Control listener: admin route PRESENT (not the axum default
        // 404 — the handler is reached; its concrete status depends on
        // the mock use-case and is not what this test asserts), public
        // artifact NOT present. This mirrors
        // `build_admin_router_exposes_metrics_only`, which discriminates
        // routed-vs-absent by `OK`-vs-`NOT_FOUND` on a bare router.
        assert_ne!(
            control_admin,
            StatusCode::NOT_FOUND,
            "/admin must be routed on the control listener"
        );
        assert_eq!(
            control_pypi,
            StatusCode::NOT_FOUND,
            "public PyPI route must NOT be on the control listener"
        );
        // Public/main listener with split ON: admin gone, public served.
        assert_eq!(
            main_admin,
            StatusCode::NOT_FOUND,
            "/admin must be removed from the public listener when split is ON"
        );
        assert_eq!(
            main_pypi,
            StatusCode::OK,
            "public PyPI artifact pull must still serve on the main listener"
        );
    }

    /// The two ADMIN token routes
    /// (`POST /api/v1/admin/users/:user_id/tokens` admin-mint,
    /// `DELETE /api/v1/admin/tokens/:id` admin-revoke) must ride
    /// the control listener with the rest of `/api/v1/admin/*`, while
    /// the PUBLIC self-service `/api/v1/users/me/tokens*` routes stay on
    /// the public listener. If all five lived in
    /// `api_token_routes()`, the two admin routes would answer on the
    /// public listener even with `HORT_CONTROL_BIND` set — contradicting
    /// the hardening-checklist tier-(iii) `/api/v1/admin/*`-is-control
    /// claim.
    ///
    /// Discriminates routed-vs-absent by `NOT_FOUND`, exactly like
    /// `build_control_router_carries_control_plane_only_and_main_drops_it`
    /// (the mock ctx is `AuthContext::Disabled`, so `AdminPrincipal` /
    /// `AuthenticatedCaller` grant unconditionally and a routed request
    /// reaches the handler with a non-404 status; the concrete status is
    /// not what this test asserts).
    #[test]
    fn control_split_moves_admin_token_routes_off_the_public_listener() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let (
            control_admin_mint,
            control_admin_revoke,
            control_self_mint,
            main_admin_mint,
            main_admin_revoke,
            main_self_mint,
        ) = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let ctx = build_mock_ctx(handle.clone());
                    let target = uuid::Uuid::new_v4();
                    let token = uuid::Uuid::new_v4();

                    let control = build_control_router(ctx.clone(), true);
                    // Admin-mint and admin-revoke must be ROUTED here.
                    let control_admin_mint_res = control
                        .clone()
                        .oneshot(
                            Request::post(format!("/api/v1/admin/users/{target}/tokens"))
                                .header("content-type", "application/json")
                                .body(Body::from(
                                    r#"{"name":"ci","declared_permissions":["read"]}"#,
                                ))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    let control_admin_revoke_res = control
                        .clone()
                        .oneshot(
                            Request::delete(format!("/api/v1/admin/tokens/{token}"))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    // The public self-service mint must NOT be here.
                    let control_self_mint_res = control
                        .oneshot(
                            Request::post("/api/v1/users/me/tokens")
                                .header("content-type", "application/json")
                                .body(Body::from(
                                    r#"{"name":"ci","declared_permissions":["read"]}"#,
                                ))
                                .unwrap(),
                        )
                        .await
                        .unwrap();

                    // Main router with the control split ON.
                    let main = build_router_with_oci_config(
                        ctx,
                        false,
                        &OciHttpConfig::default(),
                        true,
                        false,
                        true,
                    );
                    // Both admin token routes must be GONE here.
                    let main_admin_mint_res = main
                        .clone()
                        .oneshot(
                            Request::post(format!("/api/v1/admin/users/{target}/tokens"))
                                .header("content-type", "application/json")
                                .body(Body::from(
                                    r#"{"name":"ci","declared_permissions":["read"]}"#,
                                ))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    let main_admin_revoke_res = main
                        .clone()
                        .oneshot(
                            Request::delete(format!("/api/v1/admin/tokens/{token}"))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    // The self-service mint must STILL serve here.
                    let main_self_mint_res = main
                        .oneshot(
                            Request::post("/api/v1/users/me/tokens")
                                .header("content-type", "application/json")
                                .body(Body::from(
                                    r#"{"name":"ci","declared_permissions":["read"]}"#,
                                ))
                                .unwrap(),
                        )
                        .await
                        .unwrap();

                    (
                        control_admin_mint_res.status(),
                        control_admin_revoke_res.status(),
                        control_self_mint_res.status(),
                        main_admin_mint_res.status(),
                        main_admin_revoke_res.status(),
                        main_self_mint_res.status(),
                    )
                })
        });

        // Control listener: both admin token routes PRESENT, self-service ABSENT.
        assert_ne!(
            control_admin_mint,
            StatusCode::NOT_FOUND,
            "POST /api/v1/admin/users/:id/tokens must be routed on the control listener"
        );
        assert_ne!(
            control_admin_revoke,
            StatusCode::NOT_FOUND,
            "DELETE /api/v1/admin/tokens/:id must be routed on the control listener"
        );
        assert_eq!(
            control_self_mint,
            StatusCode::NOT_FOUND,
            "self-service /api/v1/users/me/tokens must NOT be on the control listener"
        );
        // Public/main listener with split ON: admin token routes GONE, self-service served.
        assert_eq!(
            main_admin_mint,
            StatusCode::NOT_FOUND,
            "POST /api/v1/admin/users/:id/tokens must be removed from the public listener \
             when the control split is ON"
        );
        assert_eq!(
            main_admin_revoke,
            StatusCode::NOT_FOUND,
            "DELETE /api/v1/admin/tokens/:id must be removed from the public listener \
             when the control split is ON"
        );
        assert_ne!(
            main_self_mint,
            StatusCode::NOT_FOUND,
            "self-service POST /api/v1/users/me/tokens must STAY on the public listener"
        );
    }

    /// Split OFF (`control_split=false`, the
    /// default) is byte-identical to today: the control surface stays
    /// on the main listener. This is the zero-behaviour-change /
    /// no-migration guarantee.
    #[test]
    fn build_router_without_control_split_keeps_admin_on_main() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let main_admin = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let ctx = build_mock_ctx(handle.clone());
                    // `control_split=false` — the production/dev default
                    // when `HORT_CONTROL_BIND` is unset.
                    let router = build_router_with_oci_config(
                        ctx,
                        false,
                        &OciHttpConfig::default(),
                        true,
                        false,
                        false,
                    );
                    let res = router
                        .oneshot(
                            Request::get("/api/v1/admin/repositories/pypi-test")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    res.status()
                })
        });

        assert_ne!(
            main_admin,
            StatusCode::NOT_FOUND,
            "with control split OFF /admin must remain ROUTED on the main \
             listener (zero behaviour change when HORT_CONTROL_BIND is unset; \
             the handler is reached exactly as in the unsplit layout)"
        );
    }

    /// With `include_metrics = false`, the main router must NOT expose
    /// `/metrics` — the scrape endpoint is served exclusively from the
    /// admin listener in production.
    #[test]
    fn build_router_without_metrics_returns_404_for_scrape() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let metrics_status = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let ctx = build_mock_ctx(handle.clone());
                    let router = build_router(ctx, false, true);

                    let res = router
                        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    res.status()
                })
        });

        assert_eq!(metrics_status, StatusCode::NOT_FOUND);
    }

    /// Security-response-headers middleware is
    /// attached globally. Drive one HTML response (PyPI simple index) and
    /// one plain-text response (`/metrics`) through the real router and
    /// assert the presence / absence of each hardening header.
    #[test]
    fn build_router_attaches_security_headers_globally() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let (html_headers, plain_headers) = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let ctx = build_mock_ctx(handle.clone());
                    let router = build_router(ctx, true, true);

                    let html_res = router
                        .clone()
                        .oneshot(
                            Request::get("/pypi/pypi-test/simple/pkg/")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(html_res.status(), StatusCode::OK);
                    let html_ct = html_res
                        .headers()
                        .get(axum::http::header::CONTENT_TYPE)
                        .expect("html response missing Content-Type")
                        .to_str()
                        .unwrap()
                        .to_string();
                    assert!(
                        html_ct.starts_with("text/html"),
                        "expected text/html from simple index, got {html_ct}"
                    );
                    let html_headers = html_res.headers().clone();

                    let plain_res = router
                        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(plain_res.status(), StatusCode::OK);
                    let plain_ct = plain_res
                        .headers()
                        .get(axum::http::header::CONTENT_TYPE)
                        .expect("metrics response missing Content-Type")
                        .to_str()
                        .unwrap()
                        .to_string();
                    assert!(
                        plain_ct.starts_with("text/plain"),
                        "expected text/plain from /metrics, got {plain_ct}"
                    );
                    let plain_headers = plain_res.headers().clone();

                    (html_headers, plain_headers)
                })
        });

        assert_eq!(
            html_headers
                .get("x-content-type-options")
                .map(|v| v.to_str().unwrap()),
            Some("nosniff"),
        );
        assert_eq!(
            html_headers
                .get("x-frame-options")
                .map(|v| v.to_str().unwrap()),
            Some("DENY"),
        );
        assert_eq!(
            html_headers
                .get("referrer-policy")
                .map(|v| v.to_str().unwrap()),
            Some("no-referrer"),
        );
        assert_eq!(
            html_headers
                .get("content-security-policy")
                .map(|v| v.to_str().unwrap()),
            Some("default-src 'none'; style-src 'unsafe-inline'"),
        );
        assert!(
            html_headers.get("strict-transport-security").is_none(),
            "HSTS must not be injected (operator's reverse-proxy concern)"
        );

        assert_eq!(
            plain_headers
                .get("x-content-type-options")
                .map(|v| v.to_str().unwrap()),
            Some("nosniff"),
        );
        assert_eq!(
            plain_headers
                .get("x-frame-options")
                .map(|v| v.to_str().unwrap()),
            Some("DENY"),
        );
        assert_eq!(
            plain_headers
                .get("referrer-policy")
                .map(|v| v.to_str().unwrap()),
            Some("no-referrer"),
        );
        // The defensive default
        // CSP `default-src 'none'; frame-ancestors 'none'; sandbox`
        // applies to every non-HTML response, including the Prometheus
        // scrape output. The policy is deliberate and this assertion
        // locks it.
        assert_eq!(
            plain_headers
                .get("content-security-policy")
                .map(|v| v.to_str().unwrap()),
            Some("default-src 'none'; frame-ancestors 'none'; sandbox"),
            "default CSP must apply to text/plain scrape output"
        );
        assert!(
            plain_headers.get("strict-transport-security").is_none(),
            "HSTS must not be injected on /metrics either"
        );
    }

    /// Read-anonymous carve-out (ADR 0021): under `AuthContext::Enabled`, GET
    /// reads pass through `extract_optional_principal` (anonymous reads
    /// stay public), while write methods go through `require_principal`
    /// and return 401 without a bearer token.
    #[test]
    fn build_router_splits_auth_layers_by_method() {
        use chrono::Utc;
        use uuid::Uuid;

        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
        use hort_app::use_cases::test_support::MockIdentityProvider;
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
        use hort_domain::ports::identity_provider::IdentityProvider;
        use hort_domain::ports::user_repository::UserRepository;

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let (get_status, post_status) = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let base = build_mock_ctx(handle.clone());

                    let idp = Arc::new(MockIdentityProvider::new());
                    let users = Arc::new(MockUserRepository::new());
                    let authenticate = Arc::new(AuthenticateUseCase::new(
                        idp as Arc<dyn IdentityProvider>,
                        users as Arc<dyn UserRepository>,
                        Vec::new(),
                    ));
                    // Flat `GrantSubject::Claims` grant (ADR 0012 —
                    // the `developer` claim carries global Write);
                    // there is no role-keyed grant map.
                    let grant = PermissionGrant {
                        id: Uuid::new_v4(),
                        subject: GrantSubject::Claims(vec!["developer".into()]),
                        repository_id: None,
                        permission: Permission::Write,
                        created_at: Utc::now(),
                        managed_by: ManagedBy::Local,
                        managed_by_digest: None,
                    };
                    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
                        grant,
                    ])));

                    let ctx = with_auth(
                        &base,
                        AuthContext::Enabled {
                            authenticate,
                            rbac,
                            // http-router
                            // tests don't exercise the WWW-Authenticate
                            // selector.
                            issuer_url: None,
                        },
                    );

                    let router = build_router(ctx, false, true);

                    let get_res = router
                        .clone()
                        .oneshot(
                            Request::get("/pypi/pypi-test/simple/pkg/pkg-1.0.tar.gz")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();

                    let post_res = router
                        .oneshot(
                            Request::post("/pypi/pypi-test/")
                                .header("content-type", "multipart/form-data; boundary=x")
                                .body(Body::from("--x--\r\n"))
                                .unwrap(),
                        )
                        .await
                        .unwrap();

                    (get_res.status(), post_res.status())
                })
        });

        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(post_status, StatusCode::UNAUTHORIZED);
    }

    /// `/healthz` + `/readyz` are mounted on the
    /// public router and return 200 anonymously. Both probes survive
    /// `AuthContext::Enabled` because they are merged at the top level
    /// after `wrap_with_middleware` runs (so neither
    /// `require_principal` nor any other layer wraps them).
    #[test]
    fn build_router_mounts_anonymous_health_probes() {
        use chrono::Utc;
        use uuid::Uuid;

        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
        use hort_app::use_cases::test_support::MockIdentityProvider;
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
        use hort_domain::ports::identity_provider::IdentityProvider;
        use hort_domain::ports::user_repository::UserRepository;

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let (healthz_status, readyz_status) = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let base = build_mock_ctx(handle.clone());

                    // Flip auth ON so the test verifies the probes
                    // bypass `require_principal`. If the layer wrapped
                    // the probes, an anonymous request would 401.
                    let idp = Arc::new(MockIdentityProvider::new());
                    let users = Arc::new(MockUserRepository::new());
                    let authenticate = Arc::new(AuthenticateUseCase::new(
                        idp as Arc<dyn IdentityProvider>,
                        users as Arc<dyn UserRepository>,
                        Vec::new(),
                    ));
                    // Flat `GrantSubject::Claims` grant (ADR 0012 —
                    // the `developer` claim carries global Write);
                    // there is no role-keyed grant map.
                    let grant = PermissionGrant {
                        id: Uuid::new_v4(),
                        subject: GrantSubject::Claims(vec!["developer".into()]),
                        repository_id: None,
                        permission: Permission::Write,
                        created_at: Utc::now(),
                        managed_by: ManagedBy::Local,
                        managed_by_digest: None,
                    };
                    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
                        grant,
                    ])));

                    let ctx = with_auth(
                        &base,
                        AuthContext::Enabled {
                            authenticate,
                            rbac,
                            // http-router
                            // tests don't exercise the WWW-Authenticate
                            // selector.
                            issuer_url: None,
                        },
                    );

                    let router = build_router(ctx, false, true);

                    let healthz_res = router
                        .clone()
                        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    let readyz_res = router
                        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
                        .await
                        .unwrap();

                    (healthz_res.status(), readyz_res.status())
                })
        });

        assert_eq!(
            healthz_status,
            StatusCode::OK,
            "/healthz must return 200 anonymously even with AuthContext::Enabled"
        );
        assert_eq!(
            readyz_status,
            StatusCode::OK,
            "/readyz must return 200 anonymously when the mock event store is healthy"
        );
    }
}
