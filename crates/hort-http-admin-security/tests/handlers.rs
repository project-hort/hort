//! Integration tests for the security-score REST surface.
//!
//! Drive the router through `tower::ServiceExt::oneshot` — same pattern
//! every other per-format crate uses. The mock harness comes from
//! `hort_http_core::test_support::build_mock_ctx`, which wires the
//! `MockRepoSecurityScoreRepository` and exposes it via
//! `MockPorts.security_scores` for direct seeding.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::{TimeZone, Utc};
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::test_support::sample_repository;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::entities::repository::Repository;
use hort_domain::ports::repo_security_score_repository::RepoSecurityScore;

use hort_http_core::context::AppContext;
use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_repository_access, MockPorts};

/// Build the v2 security router with a 1:1 path prefix matching the
/// production composition (`/api/v1`). Tests fire requests against the
/// real path strings.
fn build_test_router(ctx: Arc<AppContext>) -> axum::Router {
    axum::Router::new()
        .nest("/api/v1", hort_http_admin_security::router::routes())
        .with_state(ctx)
}

fn new_ctx() -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    build_mock_ctx(handle)
}

fn public_repo(key: &str) -> Repository {
    let mut r = sample_repository();
    r.key = key.into();
    r.is_public = true;
    r
}

fn private_repo(key: &str) -> Repository {
    let mut r = sample_repository();
    r.key = key.into();
    r.is_public = false;
    r
}

fn sample_score(repo_id: Uuid) -> RepoSecurityScore {
    RepoSecurityScore {
        repository_id: repo_id,
        quarantined_count: 12,
        rejected_count: 3,
        released_count: 4521,
        critical_count: 1,
        high_count: 8,
        medium_count: 47,
        low_count: 123,
        last_scan_at: Some(Utc.with_ymd_and_hms(2026, 5, 8, 14, 23, 11).unwrap()),
        updated_at: Utc.with_ymd_and_hms(2026, 5, 8, 14, 23, 11).unwrap(),
    }
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// GET /api/v1/repositories/:name/security-score
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_repo_score_returns_200_with_score_when_authorised() {
    let (ctx, mocks) = new_ctx();

    let repo = public_repo("internal-pypi");
    let repo_id = repo.id;
    mocks.repositories.insert(repo);
    mocks.security_scores.seed(sample_score(repo_id));

    let app = build_test_router(ctx);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/repositories/internal-pypi/security-score")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp).await;
    assert_eq!(v["repository"], "internal-pypi");
    assert_eq!(v["quarantined"], 12);
    assert_eq!(v["rejected"], 3);
    assert_eq!(v["released"], 4521);
    assert_eq!(v["severity_histogram"]["critical"], 1);
    assert_eq!(v["severity_histogram"]["high"], 8);
    assert_eq!(v["severity_histogram"]["medium"], 47);
    assert_eq!(v["severity_histogram"]["low"], 123);
    assert!(v["last_scan_at"].is_string());
}

#[tokio::test]
async fn get_repo_score_returns_zero_row_when_projection_absent_but_repo_exists() {
    let (ctx, mocks) = new_ctx();

    // Repo exists, no score row seeded.
    mocks.repositories.insert(public_repo("fresh-repo"));

    let app = build_test_router(ctx);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/repositories/fresh-repo/security-score")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp).await;
    assert_eq!(v["repository"], "fresh-repo");
    assert_eq!(v["quarantined"], 0);
    assert_eq!(v["rejected"], 0);
    assert_eq!(v["released"], 0);
    assert_eq!(v["severity_histogram"]["critical"], 0);
    assert!(v["last_scan_at"].is_null());
}

#[tokio::test]
async fn get_repo_score_returns_404_when_repository_unknown() {
    let (ctx, _mocks) = new_ctx();
    let app = build_test_router(ctx);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/repositories/ghost/security-score")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Anti-enumeration: anonymous on a private repo gets 404 (NOT 403).
/// Read denial collapses to NotFound so the actor cannot probe for
/// private repo names (ADR 0008).
#[tokio::test]
async fn get_repo_score_returns_404_for_anonymous_on_private_repo() {
    let (ctx_base, mocks) = new_ctx();

    mocks.repositories.insert(private_repo("vault"));

    // Flip access to enabled-RBAC empty evaluator so anonymous
    // is denied.
    let access = Arc::new(RepositoryAccessUseCase::new(
        mocks.repositories.clone(),
        RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
            RbacEvaluator::new(Vec::new()),
        ))),
        true,
    ));
    let ctx = with_repository_access(&ctx_base, access);

    let app = build_test_router(ctx);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/repositories/vault/security-score")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 403 path: when the use case bubbles a `Forbidden` AppError up to
/// the handler, the response is 403. Read paths normally collapse to
/// 404 (anti-enumeration, ADR 0008), so we assert this by surfacing a
/// Forbidden through a constructed scenario — a private repo that the
/// principal can READ but where the underlying access evaluator returns
/// Forbidden via the resolver. The anti-enumeration contract emits
/// Forbidden ONLY on Write paths, but the API mapping is in place; this
/// test pins the mapping so a future use-case-side change to surface
/// Forbidden on Read for any reason (custom resource ACLs etc.)
/// renders 403.
#[tokio::test]
async fn get_repo_score_403_mapping_is_wired() {
    // Reuse the ApiError → status mapping. Building a Forbidden
    // through the use case would require a bespoke MockRepositoryAccess;
    // instead, drive the mapping directly through ApiError and trust
    // the per-format crate test harness for the end-to-end path.
    use axum::response::IntoResponse;
    use hort_app::error::AppError;
    use hort_domain::error::DomainError;
    use hort_http_core::error::ApiError;

    let err = ApiError(AppError::Domain(DomainError::Forbidden("denied".into())));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// GET /api/v1/security-score
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_repo_scores_returns_only_authorised_repos() {
    let (ctx_base, mocks) = new_ctx();

    let pub1 = public_repo("public-1");
    let priv1 = private_repo("private-1");
    let pub_id = pub1.id;
    let priv_id = priv1.id;
    mocks.repositories.insert(pub1);
    mocks.repositories.insert(priv1);
    mocks.security_scores.seed(sample_score(pub_id));
    mocks.security_scores.seed(sample_score(priv_id));

    // Anonymous-only visibility: enabled-RBAC empty evaluator means
    // anonymous sees only public repos.
    let access = Arc::new(RepositoryAccessUseCase::new(
        mocks.repositories.clone(),
        RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
            RbacEvaluator::new(Vec::new()),
        ))),
        true,
    ));
    let ctx = with_repository_access(&ctx_base, access);

    let app = build_test_router(ctx);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/security-score")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp).await;
    let scores = v["scores"].as_array().unwrap();
    assert_eq!(scores.len(), 1);
    assert_eq!(scores[0]["repository"], "public-1");
    assert!(v["next_cursor"].is_null());
}

/// Read-path principal-propagation regression for `list_repo_scores` (the
/// second changed GET handler). An authenticated caller holding a Read grant
/// must see a PRIVATE repo's score in the list — proving the GET-path
/// `Option<AuthenticatedPrincipal>` slot is threaded. A bare-slot read would
/// drop the principal → anonymous → the private repo would be filtered out and
/// the list would show only the public repo. Inject via
/// `inject_optional_principal_some` (the GET shape), NOT the bare slot.
#[tokio::test]
async fn list_repo_scores_authenticated_reader_sees_private_repo() {
    let (ctx_base, mocks) = new_ctx();

    let pub1 = public_repo("public-1");
    let priv1 = private_repo("private-1");
    let pub_id = pub1.id;
    let priv_id = priv1.id;
    mocks.repositories.insert(pub1);
    mocks.repositories.insert(priv1);
    mocks.security_scores.seed(sample_score(pub_id));
    mocks.security_scores.seed(sample_score(priv_id));

    // `reader` granted global Read → an authenticated reader sees BOTH the
    // public repo and the private repo it can read.
    let grants = vec![claims_grant("reader", None, Permission::Read)];
    let access = Arc::new(RepositoryAccessUseCase::new(
        mocks.repositories.clone(),
        RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
            RbacEvaluator::new(grants),
        ))),
        true,
    ));
    let ctx = with_repository_access(&ctx_base, access);

    let p = principal(&["reader"]);
    let app = build_test_router(ctx);
    let mut req = Request::builder()
        .uri("/api/v1/security-score")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, p);

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp).await;
    let mut repos: Vec<&str> = v["scores"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["repository"].as_str().unwrap())
        .collect();
    repos.sort_unstable();
    assert_eq!(
        repos,
        vec!["private-1", "public-1"],
        "authenticated reader must see the private repo's score, not just the public one"
    );
}

#[tokio::test]
async fn list_repo_scores_pagination_returns_next_cursor_when_more() {
    let (ctx, mocks) = new_ctx();

    let r1 = public_repo("alpha");
    let r2 = public_repo("beta");
    let r3 = public_repo("gamma");
    let r1_id = r1.id;
    let r2_id = r2.id;
    let r3_id = r3.id;
    mocks.repositories.insert(r1);
    mocks.repositories.insert(r2);
    mocks.repositories.insert(r3);
    mocks.security_scores.seed(sample_score(r1_id));
    mocks.security_scores.seed(sample_score(r2_id));
    mocks.security_scores.seed(sample_score(r3_id));

    let app = build_test_router(ctx);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/security-score?limit=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp).await;
    let scores = v["scores"].as_array().unwrap();
    assert_eq!(scores.len(), 1);
    assert!(
        v["next_cursor"].is_string(),
        "expected next_cursor on first page"
    );
}

#[tokio::test]
async fn list_repo_scores_pagination_returns_null_cursor_on_last_page() {
    let (ctx, mocks) = new_ctx();

    let r1 = public_repo("only-one");
    let r1_id = r1.id;
    mocks.repositories.insert(r1);
    mocks.security_scores.seed(sample_score(r1_id));

    let app = build_test_router(ctx);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/security-score?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp).await;
    let scores = v["scores"].as_array().unwrap();
    assert_eq!(scores.len(), 1);
    assert!(
        v["next_cursor"].is_null(),
        "expected null next_cursor on last page"
    );
}

/// End-to-end pagination across multiple calls: walking the cursor
/// returns every repo exactly once.
#[tokio::test]
async fn list_repo_scores_walking_cursor_covers_every_repo_exactly_once() {
    let (ctx, mocks) = new_ctx();

    let mut keys = Vec::new();
    for i in 0..5 {
        let r = public_repo(&format!("repo-{i:02}"));
        keys.push(r.id);
        mocks.security_scores.seed(sample_score(r.id));
        mocks.repositories.insert(r);
    }
    keys.sort();

    let app = build_test_router(ctx);

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;

    for _ in 0..10 {
        let uri = match cursor.as_deref() {
            Some(c) => format!("/api/v1/security-score?limit=2&cursor={c}"),
            None => "/api/v1/security-score?limit=2".to_string(),
        };
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        for s in v["scores"].as_array().unwrap() {
            seen.push(s["repository"].as_str().unwrap().to_string());
        }
        if v["next_cursor"].is_null() {
            break;
        }
        cursor = Some(v["next_cursor"].as_str().unwrap().to_string());
    }

    seen.sort();
    let mut expected: Vec<String> = (0..5).map(|i| format!("repo-{i:02}")).collect();
    expected.sort();
    assert_eq!(seen, expected);
}

#[tokio::test]
async fn list_repo_scores_empty_when_no_repos() {
    let (ctx, _mocks) = new_ctx();
    let app = build_test_router(ctx);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/security-score")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp).await;
    assert_eq!(v["scores"].as_array().unwrap().len(), 0);
    assert!(v["next_cursor"].is_null());
}

#[tokio::test]
async fn list_repo_scores_invalid_cursor_returns_400() {
    let (ctx, mocks) = new_ctx();
    let r = public_repo("alpha");
    let id = r.id;
    mocks.repositories.insert(r);
    mocks.security_scores.seed(sample_score(id));

    let app = build_test_router(ctx);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/security-score?cursor=not-a-cursor!!")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Authenticated principal on a private repo with grant → 200.
#[tokio::test]
async fn get_repo_score_returns_200_for_authenticated_reader_on_private_repo() {
    let (ctx_base, mocks) = new_ctx();

    let repo = private_repo("vault");
    let repo_id = repo.id;
    mocks.repositories.insert(repo);
    mocks.security_scores.seed(sample_score(repo_id));

    let grants = vec![claims_grant("reader", None, Permission::Read)];
    let access = Arc::new(RepositoryAccessUseCase::new(
        mocks.repositories.clone(),
        RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
            RbacEvaluator::new(grants),
        ))),
        true,
    ));
    let ctx = with_repository_access(&ctx_base, access);

    // GET routes through `extract_optional_principal`, which writes the
    // `Option<AuthenticatedPrincipal>` slot — inject THAT shape, not the bare
    // `authenticated_principal` slot (only the write path produces it).
    // Injecting the bare slot here would mask the handler's slot bug.
    let p = principal(&["reader"]);
    let app = build_test_router(ctx);
    let mut req = Request::builder()
        .uri("/api/v1/repositories/vault/security-score")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, p);

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp).await;
    assert_eq!(v["repository"], "vault");
}

/// Build a single flat grant whose subject is `Claims([claim])`, scoped
/// to `repo` (`None` = global), carrying `perm`. The claims-based
/// grant model is described in ADR 0012 + `operate/claim-based-rbac.md`.
fn claims_grant(claim: &str, repo: Option<Uuid>, perm: Permission) -> PermissionGrant {
    PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec![claim.into()]),
        repository_id: repo,
        permission: perm,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    }
}

/// Build a principal whose resolved claim set is `claims` (flat claims
/// model, ADR 0012; a `claims_grant`-seeded evaluator matches when the
/// required claim is present).
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

// ---------------------------------------------------------------------------
// POST /api/v1/artifacts/:id/rescan
// ---------------------------------------------------------------------------

mod rescan_tests {
    use super::*;

    use hort_app::use_cases::test_support::sample_artifact;
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};

    fn seed_artifact(repo_id: Uuid, mocks: &MockPorts) -> Artifact {
        let mut a = sample_artifact(QuarantineStatus::Released);
        a.repository_id = repo_id;
        mocks.artifacts.insert(a.clone());
        a
    }

    /// Happy path: caller has Write on the parent repo → 202 with
    /// `task_job_id`.
    #[tokio::test]
    async fn rescan_returns_202_with_task_job_id_when_authorised() {
        let (ctx_base, mocks) = new_ctx();

        let repo = private_repo("vault");
        let repo_id = repo.id;
        mocks.repositories.insert(repo);
        let artifact = seed_artifact(repo_id, &mocks);

        let grants = vec![claims_grant("dev", Some(repo_id), Permission::Write)];
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(grants),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx_base, access);

        let app = build_test_router(ctx);
        let p = principal(&["dev"]);
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/artifacts/{}/rescan", artifact.id))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(auth_test::authenticated_principal(p));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let v = body_json(resp).await;
        let id_str = v["task_job_id"]
            .as_str()
            .expect("task_job_id must be a string in the wire envelope");
        // Parses as a UUID — i.e., the use case returned the new
        // jobs.id, NOT the artifact id (we'd want to assert difference,
        // but the mock generates a fresh id per enqueue_scan call so a
        // parse + non-nil check is the load-bearing assertion).
        let parsed: Uuid = id_str.parse().expect("task_job_id must be a valid UUID");
        assert_ne!(parsed, Uuid::nil());
        assert_ne!(
            parsed, artifact.id,
            "task_job_id must be the new jobs.id, NOT the artifact id"
        );
    }

    /// 404: unknown artifact id.
    #[tokio::test]
    async fn rescan_returns_404_when_artifact_unknown() {
        let (ctx, _mocks) = new_ctx();
        let app = build_test_router(ctx);

        let unknown = Uuid::new_v4();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/artifacts/{unknown}/rescan"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// 404 (anti-enumeration): caller has no Read on the parent repo.
    /// Anti-enumeration collapses invisible to NotFound (ADR 0008);
    /// the use case further rewrites it to the Artifact entity so the
    /// wire envelope never leaks repo existence through the artifact-id
    /// surface.
    #[tokio::test]
    async fn rescan_returns_404_when_caller_cannot_read_parent_repo() {
        let (ctx_base, mocks) = new_ctx();

        let repo = private_repo("vault");
        let repo_id = repo.id;
        mocks.repositories.insert(repo);
        let artifact = seed_artifact(repo_id, &mocks);

        // Empty evaluator → the anonymous-ish caller has no grants;
        // anti-enumeration NotFound-collapses both "missing" and
        // "invisible" (ADR 0008) — and the use case maps the repo
        // NotFound back to "Artifact not found".
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(Vec::new()),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx_base, access);

        let app = build_test_router(ctx);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/artifacts/{}/rescan", artifact.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// 403: caller has Read on the parent repo but lacks Write.
    #[tokio::test]
    async fn rescan_returns_403_when_caller_has_read_but_not_write() {
        let (ctx_base, mocks) = new_ctx();

        let repo = private_repo("vault");
        let repo_id = repo.id;
        mocks.repositories.insert(repo);
        let artifact = seed_artifact(repo_id, &mocks);

        let grants = vec![claims_grant("reader", Some(repo_id), Permission::Read)];
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(grants),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx_base, access);

        let app = build_test_router(ctx);
        let p = principal(&["reader"]);
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/artifacts/{}/rescan", artifact.id))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(auth_test::authenticated_principal(p));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// 409: an in-flight scan exists for this artifact.
    #[tokio::test]
    async fn rescan_returns_409_when_in_flight_scan_exists() {
        let (ctx_base, mocks) = new_ctx();

        let repo = private_repo("vault");
        let repo_id = repo.id;
        mocks.repositories.insert(repo);
        let artifact = seed_artifact(repo_id, &mocks);

        // Seed an active scan BEFORE the access-rebuild so the shared
        // `MockJobsRepository` sees the seed under whatever wiring
        // `with_repository_access` lands on.
        let existing_job_id = Uuid::new_v4();
        mocks.jobs.seed_active_scan(artifact.id, existing_job_id);

        let grants = vec![claims_grant("dev", Some(repo_id), Permission::Write)];
        let access = Arc::new(RepositoryAccessUseCase::new(
            mocks.repositories.clone(),
            RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                RbacEvaluator::new(grants),
            ))),
            true,
        ));
        let ctx = with_repository_access(&ctx_base, access);

        let app = build_test_router(ctx);
        let p = principal(&["dev"]);
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/artifacts/{}/rescan", artifact.id))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(auth_test::authenticated_principal(p));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
