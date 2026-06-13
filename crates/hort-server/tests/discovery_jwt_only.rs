//! JWT-only invariant for the discovery endpoint (ADR 0013).
//!
//! Asserts the three security-load-bearing posture guarantees of the
//! JWT-only discovery surface:
//!
//! 1. `TokenKind::Pat` → `403 Forbidden` with the exact reason string
//!    *"this endpoint requires a CLI session token"*, AND the
//!    `hort_discovery_list_versions_total{result="token_kind_denied"}`
//!    counter ticks exactly once.
//! 2. `TokenKind::CliSession` + `Permission::Read` → `200 OK` with the
//!    `DiscoveryListing` JSON shape.
//! 3. Anonymous → `401 Unauthorized` from the use case's Gate 0. The GET
//!    routes through `extract_optional_principal` (not `require_principal`),
//!    which inserts `Option<AuthenticatedPrincipal> = None`; the handler
//!    threads that `None` into `list_versions`, whose read-endpoint
//!    principal guard rejects it with 401 BEFORE any emission, so the
//!    `hort_discovery_list_versions_total` counter does NOT tick — a future
//!    maintainer who starts emitting an `anonymous_denied`-shaped `result`
//!    label (which the catalog does not allow) would break this test.
//!
//! # `#[serial(hort_pg_db)]`
//!
//! These tests use the in-memory `build_mock_ctx` harness and DO NOT
//! touch the shared `hort_pg_db` Postgres pool. The `serial` key is
//! applied defensively — it costs
//! nothing on the fast path and protects against a future refactor that
//! adds DB seeding to the harness without dropping the key.
//!
//! # Test approach (router-fragment-against-mock-ctx)
//!
//! Integration tests fire requests against a synthetic axum router
//! built from the `hort_http_discovery::routes()` fragment nested under
//! `/api/v1`, backed by the shared `build_mock_ctx` test harness,
//! rather than the real `hort_server::http::build_router` production
//! middleware stack (the production mount lives in `crate::http`). The
//! synthetic router DOES exercise the `DiscoveryUseCase::list_versions`
//! gate matrix end-to-end (token-kind gate, RBAC gate,
//! anti-enumeration NotFound) — exactly the JWT-only invariant this
//! suite locks down.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use serial_test::serial;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::discovery_use_case::DiscoveryUseCase;
use hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase;
use hort_domain::entities::api_token::TokenKind;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::entities::repository::{Repository, RepositoryFormat};

use hort_http_core::context::AppContext;
use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_discovery_use_cases, MockPorts};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn npm_repo() -> Repository {
    use hort_app::use_cases::test_support::sample_repository;
    let mut r = sample_repository();
    r.format = RepositoryFormat::Npm;
    r.is_public = false;
    r
}

fn caller_with_token_kind(claims: &[&str], kind: Option<TokenKind>) -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "test:sub".into(),
        username: "alice".into(),
        email: "alice@example.com".into(),
        claims: claims.iter().map(|s| (*s).to_string()).collect(),
        token_kind: kind,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

fn evaluator_read(claim: &str, repo_id: Uuid) -> RbacEvaluator {
    RbacEvaluator::new(vec![PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec![claim.into()]),
        repository_id: Some(repo_id),
        permission: Permission::Read,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    }])
}

/// Build the synthetic test router + mock harness with the supplied
/// RBAC evaluator wired into both use cases. The discovery handler is
/// reached through the inner `/api/v1`-nested router fragment exposed
/// by `hort_http_discovery::routes()`.
fn build_router_with_rbac(
    rbac: RbacEvaluator,
    handle: metrics_exporter_prometheus::PrometheusHandle,
) -> (axum::Router, MockPorts) {
    let (base, mocks) = build_mock_ctx(handle);
    let rbac_arc = Arc::new(ArcSwap::from_pointee(rbac));
    let discovery = Arc::new(DiscoveryUseCase::new(
        mocks.repositories.clone(),
        mocks.artifacts.clone(),
        mocks.repository_upstream_mappings.clone(),
        mocks.upstream_metadata.clone(),
        rbac_arc.clone(),
        mocks.policy_projections.clone(),
    ));
    let self_service = Arc::new(SelfServicePrefetchUseCase::new(
        mocks.repositories.clone(),
        mocks.artifacts.clone(),
        mocks.repository_upstream_mappings.clone(),
        mocks.upstream_metadata.clone(),
        mocks.jobs.clone(),
        rbac_arc.clone(),
    ));
    let ctx: Arc<AppContext> = with_discovery_use_cases(&base, discovery, self_service);
    let router = axum::Router::new()
        .nest("/api/v1", hort_http_discovery::routes())
        .with_state(ctx);
    (router, mocks)
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ---------------------------------------------------------------------------
// 0. CLI-session claim-resolution footgun closure (headline, ADR 0013)
//    — a CliSession principal carrying the IdP-RESOLVED `developer`
//    claim authorizes a `Claims([developer])` Read grant on the
//    JWT-only discovery endpoint → 200. Previously the CliSession
//    principal carried `claims: []`, so a claim-subject grant could
//    never authorize it.
// ---------------------------------------------------------------------------

#[test]
#[serial(hort_pg_db)]
fn cli_session_with_developer_claim_grant_authorizes_discovery_200() {
    let prom_handle = PrometheusBuilder::new().build_recorder().handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let repo = npm_repo();
        let repo_id = repo.id;
        let key = repo.key.clone();
        // Grant keyed on the RESOLVED `developer` claim, repo-scoped.
        let (router, mocks) =
            build_router_with_rbac(evaluator_read("developer", repo_id), prom_handle);
        mocks.repositories.insert(repo);
        mocks.artifacts.seed_package_version_status(
            repo_id,
            "left-pad",
            vec![("1.0.0".into(), QuarantineStatus::Released)],
        );

        let url = format!("/api/v1/repositories/{}/discovery/versions/left-pad", key);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Body::empty())
            .unwrap();
        // CliSession carrying the resolved `developer` claim — the
        // Item-10 claims-carrying JWT validate-path output.
        auth_test::inject_optional_principal_some(
            &mut req,
            caller_with_token_kind(&["developer"], Some(TokenKind::CliSession)),
        );

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "CliSession + Claims([developer]) Read grant must authorize discovery (footgun closed)",
        );
    });
}

// ---------------------------------------------------------------------------
// 1. PAT → 403 + token_kind_denied tick exactly once
// ---------------------------------------------------------------------------

#[test]
#[serial(hort_pg_db)]
fn pat_principal_returns_403_with_exact_reason_and_ticks_token_kind_denied_once() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let prom_handle = PrometheusBuilder::new().build_recorder().handle();

    metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let repo = npm_repo();
            let repo_id = repo.id;
            let key = repo.key.clone();
            let (router, mocks) =
                build_router_with_rbac(evaluator_read("dev", repo_id), prom_handle);
            mocks.repositories.insert(repo);

            let url = format!("/api/v1/repositories/{}/discovery/versions/left-pad", key);
            let mut req = Request::builder()
                .method(Method::GET)
                .uri(url)
                .body(Body::empty())
                .unwrap();
            auth_test::inject_optional_principal_some(
                &mut req,
                caller_with_token_kind(&["dev"], Some(TokenKind::Pat)),
            );

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "PAT must be rejected with 403"
            );
            let body = body_string(resp).await;
            assert!(
                body.contains("this endpoint requires a CLI session token"),
                "exact reason string missing — body: {body}",
            );
        });
    });

    // The single `token_kind_denied` tick lives in the use case (the
    // metric-emission layer). Assert via the debugging snapshot.
    let snapshot = snapshotter.snapshot().into_vec();
    let token_kind_denied = snapshot
        .iter()
        .filter(|(key, _, _, _)| key.key().name() == "hort_discovery_list_versions_total")
        .filter(|(key, _, _, _)| {
            key.key()
                .labels()
                .any(|l| l.key() == "result" && l.value() == "token_kind_denied")
        })
        .filter_map(|(_, _, _, v)| match v {
            DebugValue::Counter(n) => Some(*n),
            _ => None,
        })
        .sum::<u64>();
    assert_eq!(
        token_kind_denied, 1,
        "expected exactly one hort_discovery_list_versions_total{{result=\"token_kind_denied\"}} tick",
    );
}

// ---------------------------------------------------------------------------
// 2. CliSession + Permission::Read → 200 with the right response shape
// ---------------------------------------------------------------------------

#[test]
#[serial(hort_pg_db)]
fn cli_session_with_read_returns_200_and_listing_shape_and_ticks_success() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let prom_handle = PrometheusBuilder::new().build_recorder().handle();

    metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let repo = npm_repo();
            let repo_id = repo.id;
            let key = repo.key.clone();
            let (router, mocks) =
                build_router_with_rbac(evaluator_read("dev", repo_id), prom_handle);
            mocks.repositories.insert(repo);
            mocks.artifacts.seed_package_version_status(
                repo_id,
                "left-pad",
                vec![("1.0.0".into(), QuarantineStatus::Released)],
            );

            let url = format!("/api/v1/repositories/{}/discovery/versions/left-pad", key);
            let mut req = Request::builder()
                .method(Method::GET)
                .uri(url)
                .body(Body::empty())
                .unwrap();
            auth_test::inject_optional_principal_some(
                &mut req,
                caller_with_token_kind(&["dev"], Some(TokenKind::CliSession)),
            );

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_string(resp).await;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["package"], "left-pad");
            assert_eq!(parsed["format"], "npm");
            assert!(parsed["versions"].is_array());
            assert_eq!(parsed["versions"].as_array().unwrap().len(), 1);
            assert_eq!(parsed["versions"][0]["status"]["kind"], "released");
        });
    });

    let snapshot = snapshotter.snapshot().into_vec();
    let success = snapshot
        .iter()
        .filter(|(key, _, _, _)| key.key().name() == "hort_discovery_list_versions_total")
        .filter(|(key, _, _, _)| {
            key.key()
                .labels()
                .any(|l| l.key() == "result" && l.value() == "success")
        })
        .filter_map(|(_, _, _, v)| match v {
            DebugValue::Counter(n) => Some(*n),
            _ => None,
        })
        .sum::<u64>();
    assert_eq!(success, 1, "expected one success tick");
}

// ---------------------------------------------------------------------------
// 3. Anonymous → 401 + NO metric tick (strict assertion)
// ---------------------------------------------------------------------------
//
// The discovery GET routes through `extract_optional_principal` in
// production (`hort-http-core::router.rs:313-318` dispatches GET/HEAD/OPTIONS
// to the optional layer, NOT `require_principal`). That layer ALWAYS
// inserts `Option<AuthenticatedPrincipal>` into the request extensions —
// `Some(_)` on a valid token, `None` when absent/unvalidatable. So the
// faithful model of an anonymous GET is `inject_optional_principal_none`
// (auth ran, no token), NOT "inject nothing". Injecting nothing would test
// a shape production never produces and let a missing-extension 500 pass as
// a "non-2xx" — exactly the mask that hid the bug where the handler
// extracted the bare `Extension<AuthenticatedPrincipal>` and 500'd for
// every caller (authenticated included).
//
// With that fixed, the handler threads `Option<&CallerPrincipal>` into
// the use case, whose Gate 0 rejects `None` with 401 BEFORE any metric
// emission. Both halves are now strict: the status is exactly 401, and the
// `hort_discovery_list_versions_total` counter does not tick at all.

#[test]
#[serial(hort_pg_db)]
fn anonymous_principal_returns_401_and_does_not_tick_metric() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let prom_handle = PrometheusBuilder::new().build_recorder().handle();

    metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let repo = npm_repo();
            let repo_id = repo.id;
            let key = repo.key.clone();
            let (router, mocks) =
                build_router_with_rbac(evaluator_read("dev", repo_id), prom_handle);
            mocks.repositories.insert(repo);

            let url = format!("/api/v1/repositories/{}/discovery/versions/left-pad", key);
            let mut req = Request::builder()
                .method(Method::GET)
                .uri(url)
                .body(Body::empty())
                .unwrap();
            // Model `extract_optional_principal`'s "auth ran, no token"
            // sentinel — the exact shape the production GET path inserts
            // for an anonymous request.
            auth_test::inject_optional_principal_none(&mut req);
            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "anonymous discovery must be a strict 401; got {}",
                resp.status(),
            );
        });
    });

    let snapshot = snapshotter.snapshot().into_vec();
    let any_tick: u64 = snapshot
        .iter()
        .filter(|(key, _, _, _)| key.key().name() == "hort_discovery_list_versions_total")
        .filter_map(|(_, _, _, v)| match v {
            DebugValue::Counter(n) => Some(*n),
            _ => None,
        })
        .sum();
    assert_eq!(
        any_tick, 0,
        "anonymous request must NOT reach the use case; no result-label tick is allowed",
    );
}
