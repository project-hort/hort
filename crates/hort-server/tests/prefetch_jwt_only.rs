//! JWT-only invariant for the self-service prefetch endpoint
//! (ADR 0013).
//!
//! Sibling of `discovery_jwt_only.rs`; same three security
//! guarantees on the `POST /api/v1/repositories/:repo_key/prefetch`
//! surface PLUS a mixed-batch envelope-partition assertion:
//!
//! 1. `TokenKind::Pat` → `403 Forbidden` with the exact reason string
//!    *"this endpoint requires a CLI session token"*, AND
//!    `hort_prefetch_self_service_total{result="token_kind_denied"}`
//!    ticks exactly once.
//! 2. `TokenKind::CliSession` + `Permission::Read ∧ Prefetch` → `200 OK`
//!    with the `PrefetchOutcome` envelope; the `success` label ticks
//!    PER-ITEM (not per call).
//! 3. Anonymous → no metric tick (the use case must not be reached).
//! 4. Mixed batch (success / skipped-already-held / rejected / failed
//!    upstream) → 200 with the four envelope buckets partitioned.
//!
//! # `#[serial(hort_pg_db)]`
//!
//! Same defensive rationale as the sibling discovery test — these
//! tests use `build_mock_ctx` (in-memory) and DO NOT touch the shared
//! Postgres pool. The key is applied defensively.

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

use hort_app::metrics::UpstreamFetchError;
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
// Harness
// ---------------------------------------------------------------------------

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

fn grant(claim: &str, repo_id: Uuid, permission: Permission) -> PermissionGrant {
    PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec![claim.into()]),
        repository_id: Some(repo_id),
        permission,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    }
}

fn evaluator_read_and_prefetch(claim: &str, repo_id: Uuid) -> RbacEvaluator {
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

fn counter_value(
    snapshot: &[(
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )],
    name: &str,
    result: &str,
) -> u64 {
    snapshot
        .iter()
        .filter(|(key, _, _, _)| key.key().name() == name)
        .filter(|(key, _, _, _)| {
            key.key()
                .labels()
                .any(|l| l.key() == "result" && l.value() == result)
        })
        .filter_map(|(_, _, _, v)| match v {
            DebugValue::Counter(n) => Some(*n),
            _ => None,
        })
        .sum()
}

// ---------------------------------------------------------------------------
// 0. CLI-session claim-resolution footgun closure (headline, ADR 0013)
//    — a CliSession principal carrying the IdP-RESOLVED `developer`
//    claim authorizes a `Claims([developer])` PermissionGrant on the
//    JWT-only prefetch endpoint → 200. Previously the CliSession
//    principal carried `claims: []` (it validated through
//    `authenticate_pat`), so a claim-subject grant could never
//    authorize it — the endpoint was only reachable by
//    `GrantSubject::User`/admin. The CliSession token is now a
//    claims-carrying signed JWT; this test pins the authorization axis
//    (the mint+validate axis lives in the hort-app unit tests; the
//    apply-linter axis is the real-linter test in
//    `alpha_fixture_linter.rs`).
// ---------------------------------------------------------------------------

#[test]
#[serial(hort_pg_db)]
fn cli_session_with_developer_claim_grant_authorizes_prefetch_200() {
    let prom_handle = PrometheusBuilder::new().build_recorder().handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let repo = npm_repo();
        let repo_id = repo.id;
        let key = repo.key.clone();
        // The grant is keyed on the `developer` claim (the resolved
        // claim a `test-developers` member carries post-ClaimMapping),
        // scoped to this repo — mirrors the alpha fixtures' shape.
        let (router, mocks) = build_router_with_rbac(
            evaluator_read_and_prefetch("developer", repo_id),
            prom_handle,
        );
        mocks.repositories.insert(repo);
        mocks
            .repository_upstream_mappings
            .upsert(mapping(repo_id))
            .await
            .unwrap();

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
        // A CliSession principal carrying the RESOLVED `developer` claim
        // — exactly what the Item-10 claims-carrying JWT validate path
        // now produces (was `claims: []` pre-Item-10).
        auth_test::inject_principal(
            &mut req,
            caller_with_token_kind(&["developer"], Some(TokenKind::CliSession)),
        );

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "CliSession + Claims([developer]) grant must authorize prefetch (footgun closed)",
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
                build_router_with_rbac(evaluator_read_and_prefetch("dev", repo_id), prom_handle);
            mocks.repositories.insert(repo);

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
            let body = body_string(resp).await;
            assert!(
                body.contains("this endpoint requires a CLI session token"),
                "exact reason string missing — body: {body}",
            );
        });
    });

    let snapshot = snapshotter.snapshot().into_vec();
    assert_eq!(
        counter_value(
            &snapshot,
            "hort_prefetch_self_service_total",
            "token_kind_denied"
        ),
        1,
        "expected exactly one token_kind_denied tick",
    );
}

// ---------------------------------------------------------------------------
// 2. CliSession + Read ∧ Prefetch → 200 with envelope + per-item success
// ---------------------------------------------------------------------------

#[test]
#[serial(hort_pg_db)]
fn cli_session_returns_200_envelope_and_ticks_success_per_item() {
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
                build_router_with_rbac(evaluator_read_and_prefetch("dev", repo_id), prom_handle);
            mocks.repositories.insert(repo);
            mocks
                .repository_upstream_mappings
                .upsert(mapping(repo_id))
                .await
                .unwrap();

            let body = serde_json::json!({
                "items": [
                    { "package": "a", "version": "1.0.0" },
                    { "package": "b", "version": "2.0.0" },
                    { "package": "c", "version": "3.0.0" },
                ],
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
                caller_with_token_kind(&["dev"], Some(TokenKind::CliSession)),
            );

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_string(resp).await;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["enqueued_job_ids"].as_array().unwrap().len(), 3);
            assert!(parsed["skipped_already_held"]
                .as_array()
                .unwrap()
                .is_empty());
            assert!(parsed["rejected_packages"].as_array().unwrap().is_empty());
            assert!(parsed["failed"].as_array().unwrap().is_empty());
        });
    });

    let snapshot = snapshotter.snapshot().into_vec();
    assert_eq!(
        counter_value(&snapshot, "hort_prefetch_self_service_total", "success"),
        3,
        "expected three per-item success ticks (one per enqueued item)",
    );
}

// ---------------------------------------------------------------------------
// 3. Anonymous → no metric tick (negative assert)
// ---------------------------------------------------------------------------

#[test]
#[serial(hort_pg_db)]
fn anonymous_principal_does_not_tick_metric_and_returns_non_2xx() {
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
                build_router_with_rbac(evaluator_read_and_prefetch("dev", repo_id), prom_handle);
            mocks.repositories.insert(repo);

            let body = serde_json::json!({ "items": [] });
            let url = format!("/api/v1/repositories/{}/prefetch", key);
            let req = Request::builder()
                .method(Method::POST)
                .uri(url)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            // No principal injected — models anonymous; the missing
            // `Extension<AuthenticatedPrincipal>` extractor short-circuits
            // before the use case runs.
            let resp = router.oneshot(req).await.unwrap();
            assert!(!resp.status().is_success(), "got {}", resp.status());
        });
    });

    let snapshot = snapshotter.snapshot().into_vec();
    // No tick across ANY result label.
    let total: u64 = snapshot
        .iter()
        .filter(|(key, _, _, _)| key.key().name() == "hort_prefetch_self_service_total")
        .filter_map(|(_, _, _, v)| match v {
            DebugValue::Counter(n) => Some(*n),
            _ => None,
        })
        .sum();
    assert_eq!(
        total, 0,
        "anonymous request must NOT reach the use case; no metric tick is allowed",
    );
}

// ---------------------------------------------------------------------------
// 4. Mixed batch partitions correctly + per-item ticks land in right buckets
// ---------------------------------------------------------------------------

#[test]
#[serial(hort_pg_db)]
fn mixed_batch_partitions_envelope_buckets_and_per_item_ticks() {
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
                build_router_with_rbac(evaluator_read_and_prefetch("dev", repo_id), prom_handle);
            mocks.repositories.insert(repo);
            mocks
                .repository_upstream_mappings
                .upsert(mapping(repo_id))
                .await
                .unwrap();
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
                Err(UpstreamFetchError::Timeout),
            );

            let body = serde_json::json!({
                "items": [
                    { "package": "p_success", "version": "1.0.0" },
                    { "package": "p_skipped", "version": "1.0.0" },
                    { "package": "p_rejected", "version": "1.0.0" },
                    { "package": "p_failed" },
                ],
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
                caller_with_token_kind(&["dev"], Some(TokenKind::CliSession)),
            );

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_string(resp).await;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["enqueued_job_ids"].as_array().unwrap().len(), 1);
            assert_eq!(parsed["skipped_already_held"].as_array().unwrap().len(), 1);
            assert_eq!(parsed["rejected_packages"].as_array().unwrap().len(), 1);
            assert_eq!(parsed["failed"].as_array().unwrap().len(), 1);
            assert_eq!(parsed["failed"][0]["error"], "timeout");
        });
    });

    let snapshot = snapshotter.snapshot().into_vec();
    assert_eq!(
        counter_value(&snapshot, "hort_prefetch_self_service_total", "success"),
        1,
    );
    assert_eq!(
        counter_value(
            &snapshot,
            "hort_prefetch_self_service_total",
            "rejected_version"
        ),
        1,
    );
    assert_eq!(
        counter_value(&snapshot, "hort_prefetch_self_service_total", "timeout"),
        1,
    );
}
