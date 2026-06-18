//! Handler-layer integration tests for the discovery +
//! self-service prefetch REST surface.
//!
//! Drives the router fragment through `tower::ServiceExt::oneshot` —
//! same pattern as every other `hort-http-<crate>` integration suite.
//! The mock harness comes from `hort_http_core::test_support::build_mock_ctx`,
//! which wires `DiscoveryUseCase` + `SelfServicePrefetchUseCase` over the
//! in-memory port mocks and exposes the seeding handles on `MockPorts`.
//!
//! These tests are deliberately handler-shaped — they exercise the
//! status-code mapping, the DTO → domain boundary, and the response
//! envelope serialisation. The use-case-level coverage (token-kind
//! gate per-tick, RBAC denial per-tick, the status overlay, and the
//! per-item dispatch) lives in
//! `crates/hort-app/src/use_cases/{discovery,self_service_prefetch}_use_case.rs::tests`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
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
use hort_domain::entities::repository::{PrefetchTrigger, Repository, RepositoryFormat};
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, RepositoryUpstreamMappingRepository, UpstreamAuth,
};

use hort_http_core::context::AppContext;
use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_discovery_use_cases, MockPorts};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Build a mock `AppContext` AND rewire the discovery + self-service
/// prefetch use cases so they share the supplied RBAC evaluator. The
/// default `build_mock_ctx` wires an empty evaluator; tests asserting
/// the permission-passes path need to seed grants, which requires
/// rebuilding the two use cases via the `with_discovery_use_cases`
/// helper.
fn ctx_with_rbac(rbac: RbacEvaluator) -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    let (base_ctx, mocks) = build_mock_ctx(handle);
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
    let ctx = with_discovery_use_cases(&base_ctx, discovery, self_service);
    (ctx, mocks)
}

/// Wire the inner router's `routes()` fragment under `/api/v1` so
/// tests fire against real path strings.
fn build_test_router(ctx: Arc<AppContext>) -> axum::Router {
    axum::Router::new()
        .nest("/api/v1", hort_http_discovery::routes())
        .with_state(ctx)
}

fn caller_cli_session(claims: &[&str]) -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "test:sub".into(),
        username: "alice".into(),
        email: "alice@example.com".into(),
        claims: claims.iter().map(|s| (*s).to_string()).collect(),
        token_kind: Some(TokenKind::CliSession),
        issued_at: Utc::now(),
        token_cap: None,
    }
}

fn caller_with_token_kind(claims: &[&str], kind: Option<TokenKind>) -> CallerPrincipal {
    let mut c = caller_cli_session(claims);
    c.token_kind = kind;
    c
}

fn npm_repo() -> Repository {
    use hort_app::use_cases::test_support::sample_repository;
    let mut r = sample_repository();
    r.format = RepositoryFormat::Npm;
    r.is_public = false;
    r.prefetch_policy.enabled = true;
    r.prefetch_policy.depth = 4;
    r.prefetch_policy.triggers = vec![PrefetchTrigger::TransitiveDeps];
    r
}

fn oci_repo() -> Repository {
    use hort_app::use_cases::test_support::sample_repository;
    let mut r = sample_repository();
    r.format = RepositoryFormat::Oci;
    r.is_public = false;
    r
}

fn grant(subject_claim: &str, repo_id: Uuid, permission: Permission) -> PermissionGrant {
    PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec![subject_claim.to_string()]),
        repository_id: Some(repo_id),
        permission,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    }
}

fn evaluator_with_read_and_prefetch(claim: &str, repo_id: Uuid) -> RbacEvaluator {
    RbacEvaluator::new(vec![
        grant(claim, repo_id, Permission::Read),
        grant(claim, repo_id, Permission::Prefetch),
    ])
}

fn mapping(repo_id: Uuid) -> RepositoryUpstreamMapping {
    let now = Utc::now();
    RepositoryUpstreamMapping {
        id: Uuid::new_v4(),
        repository_id: repo_id,
        path_prefix: String::new(),
        upstream_url: "https://registry.example/".into(),
        upstream_name_prefix: None,
        upstream_auth: UpstreamAuth::Anonymous,
        secret_ref: None,
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
        insecure_upstream_url: false,
        trust_upstream_publish_time: false,
        mtls_cert_ref: None,
        mtls_key_ref: None,
        ca_bundle_ref: None,
        pinned_cert_sha256: None,
        created_at: now,
        updated_at: now,
    }
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// list_versions — status code matrix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_versions_pat_token_kind_returns_403() {
    let repo = npm_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    let router = build_test_router(ctx);

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
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert!(
        body["error"].as_str().unwrap_or("").contains("CLI session"),
        "envelope: {body}",
    );
}

#[tokio::test]
async fn list_versions_cli_session_succeeds_with_overlay() {
    let repo = npm_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    mocks
        .repository_upstream_mappings
        .upsert(mapping(repo_id))
        .await
        .unwrap();
    mocks.upstream_metadata.insert_versions(
        "npm",
        "left-pad",
        Ok(vec!["1.0.0".into(), "2.0.0".into()]),
    );
    mocks.artifacts.seed_package_version_status(
        repo_id,
        "left-pad",
        vec![("1.0.0".into(), QuarantineStatus::Released)],
    );
    let router = build_test_router(ctx);

    let url = format!("/api/v1/repositories/{}/discovery/versions/left-pad", key);
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["package"], "left-pad");
    assert_eq!(body["format"], "npm");
    let versions = body["versions"].as_array().expect("versions array");
    assert_eq!(versions.len(), 2);
    // 1.0.0 → released (AK-held); 2.0.0 → unknown (upstream-only)
    let released = versions
        .iter()
        .find(|v| v["version"] == "1.0.0")
        .expect("1.0.0 present");
    assert_eq!(released["status"]["kind"], "released");
    let unknown = versions
        .iter()
        .find(|v| v["version"] == "2.0.0")
        .expect("2.0.0 present");
    assert_eq!(unknown["status"]["kind"], "unknown");
}

#[tokio::test]
async fn list_versions_oci_returns_400_with_validation_message() {
    let repo = oci_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    // Seed catch-all mapping so the dispatch reaches the upstream port
    // and surfaces `UnsupportedFormat`.
    mocks
        .repository_upstream_mappings
        .upsert(mapping(repo_id))
        .await
        .unwrap();
    let router = build_test_router(ctx);

    let url = format!(
        "/api/v1/repositories/{}/discovery/versions/library%2Falpine",
        key,
    );
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    let msg = body["error"].as_str().unwrap_or("");
    assert!(msg.contains("OCI"), "envelope: {body}");
}

#[tokio::test]
async fn list_versions_unknown_repo_returns_404() {
    let (ctx, _mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", Uuid::new_v4()));
    let router = build_test_router(ctx);

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/repositories/does-not-exist/discovery/versions/left-pad")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_versions_missing_permission_read_returns_403() {
    // The caller carries a CliSession but no `Read` grant — the use
    // case ticks `permission_denied` and returns 403.
    let repo = npm_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    // Empty evaluator (no grants).
    let (ctx, mocks) = ctx_with_rbac(RbacEvaluator::new(Vec::new()));
    mocks.repositories.insert(repo);
    let router = build_test_router(ctx);

    let url = format!("/api/v1/repositories/{}/discovery/versions/left-pad", key);
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, caller_cli_session(&[]));
    let _ = repo_id;

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_versions_anonymous_returns_401() {
    // Anti-enumeration regression guard. The GET routes through
    // `extract_optional_principal` in production, which inserts
    // `Option<AuthenticatedPrincipal> = None` for an anonymous request.
    // The handler must thread that `None` into the use case, whose Gate 0
    // rejects it with 401. A handler that extracts the bare
    // `Extension<AuthenticatedPrincipal>` would 500 here instead — which is
    // exactly the bug this test locks down.
    let repo = npm_repo();
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo.id));
    mocks.repositories.insert(repo);
    let router = build_test_router(ctx);

    let url = format!("/api/v1/repositories/{}/discovery/versions/left-pad", key);
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_none(&mut req);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// prefetch — status code matrix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prefetch_pat_token_kind_returns_403() {
    let repo = npm_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    let router = build_test_router(ctx);

    let body = serde_json::json!({
        "items": [ { "package": "left-pad", "version": "1.0.0" } ],
    });
    let url = format!("/api/v1/repositories/{}/prefetch", key);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    auth_test::inject_principal(
        &mut req,
        caller_with_token_kind(&["dev"], Some(TokenKind::Pat)),
    );

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn prefetch_cli_session_all_success_returns_200_with_enqueued_ids() {
    let repo = npm_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    mocks
        .repository_upstream_mappings
        .upsert(mapping(repo_id))
        .await
        .unwrap();
    let router = build_test_router(ctx);

    let body = serde_json::json!({
        "items": [
            { "package": "a", "version": "1.0.0" },
            { "package": "b", "version": "2.0.0" },
        ],
    });
    let url = format!("/api/v1/repositories/{}/prefetch", key);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    auth_test::inject_principal(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["enqueued_job_ids"].as_array().unwrap().len(), 2);
    assert_eq!(body["skipped_already_held"].as_array().unwrap().len(), 0);
    assert_eq!(body["rejected_packages"].as_array().unwrap().len(), 0);
    assert_eq!(body["failed"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn prefetch_oci_returns_400_with_validation_message() {
    let repo = oci_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    let router = build_test_router(ctx);

    let body = serde_json::json!({
        "items": [ { "package": "library/alpine", "version": "3.18" } ],
    });
    let url = format!("/api/v1/repositories/{}/prefetch", key);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    auth_test::inject_principal(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn prefetch_malformed_body_returns_400() {
    let repo = npm_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    let router = build_test_router(ctx);

    let url = format!("/api/v1/repositories/{}/prefetch", key);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"not_items": []}"#))
        .unwrap();
    auth_test::inject_principal(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    // axum's `Json` extractor returns 422 (Unprocessable Entity) for
    // shape mismatches, NOT 400 — both are within the 4xx "client did
    // something wrong" envelope. We assert the broader 4xx class here.
    assert!(
        resp.status().is_client_error(),
        "expected 4xx, got {}",
        resp.status(),
    );
}

#[tokio::test]
async fn prefetch_empty_items_returns_200_with_empty_envelope() {
    let repo = npm_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    let router = build_test_router(ctx);

    let body = serde_json::json!({ "items": [] });
    let url = format!("/api/v1/repositories/{}/prefetch", key);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    auth_test::inject_principal(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["enqueued_job_ids"].as_array().unwrap().len(), 0);
    assert_eq!(body["skipped_already_held"].as_array().unwrap().len(), 0);
    assert_eq!(body["rejected_packages"].as_array().unwrap().len(), 0);
    assert_eq!(body["failed"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn prefetch_mixed_batch_partitions_into_envelope_buckets() {
    let repo = npm_repo();
    let repo_id = repo.id;
    let key = repo.key.clone();
    let (ctx, mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", repo_id));
    mocks.repositories.insert(repo);
    mocks
        .repository_upstream_mappings
        .upsert(mapping(repo_id))
        .await
        .unwrap();
    // success — fresh.
    // skipped — released held.
    // rejected (ScanRejected) — held Rejected.
    // failed — upstream Timeout.
    mocks.artifacts.seed_package_version_status(
        repo_id,
        "p_skipped",
        vec![("1.0.0".into(), QuarantineStatus::Released)],
    );
    mocks.artifacts.seed_package_version_status(
        repo_id,
        "p_rejected",
        vec![("1.0.0".into(), QuarantineStatus::Rejected)],
    );
    mocks.upstream_metadata.insert_versions(
        "npm",
        "p_failed",
        Err(hort_app::metrics::UpstreamFetchError::Timeout),
    );
    let router = build_test_router(ctx);

    let body = serde_json::json!({
        "items": [
            { "package": "p_success", "version": "1.0.0" },
            { "package": "p_skipped", "version": "1.0.0" },
            { "package": "p_rejected", "version": "1.0.0" },
            { "package": "p_failed" }, // version omitted → latest path
        ],
    });
    let url = format!("/api/v1/repositories/{}/prefetch", key);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    auth_test::inject_principal(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["enqueued_job_ids"].as_array().unwrap().len(), 1);
    assert_eq!(body["skipped_already_held"].as_array().unwrap().len(), 1);
    assert_eq!(body["rejected_packages"].as_array().unwrap().len(), 1);
    assert_eq!(body["failed"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["failed"][0]["error"], "timeout",
        "Timeout maps to `timeout` per the sanitised enum",
    );
}

#[tokio::test]
async fn prefetch_unknown_repo_returns_404() {
    let (ctx, _mocks) = ctx_with_rbac(evaluator_with_read_and_prefetch("dev", Uuid::new_v4()));
    let router = build_test_router(ctx);

    let body = serde_json::json!({ "items": [] });
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/repositories/does-not-exist/prefetch")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    auth_test::inject_principal(&mut req, caller_cli_session(&["dev"]));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
