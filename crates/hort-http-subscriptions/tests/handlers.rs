//! Integration tests for the `/api/v1/subscriptions` REST surface.
//!
//! Drives the router through `tower::ServiceExt::oneshot` — same pattern
//! every other per-format / per-admin crate uses. The mock harness comes
//! from `hort_http_core::test_support::build_mock_ctx`; the new
//! `MockPorts.subscriptions` + `MockPorts.webhook_guard` handles let
//! tests seed rows and (in follow-on PRs) flip the SSRF guard.
//!
//! # Test coverage
//!
//! 1. `post_subscriptions_returns_201_with_secret_ref_and_no_plaintext_in_response`
//! 2. `post_subscriptions_returns_400_on_malformed_secret_ref`
//! 3. `post_subscriptions_returns_400_on_validation_failure` (empty name)
//! 4. `post_subscriptions_returns_400_on_plaintext_webhook_disallowed`
//! 5. `post_subscriptions_returns_403_on_repo_not_authorised`
//! 6. `post_subscriptions_returns_409_on_duplicate_name`
//! 7. `post_subscriptions_returns_400_on_unsupported_event_type`
//! 8. `get_subscriptions_returns_paginated_list`
//! 9. `get_subscription_by_id_returns_subscription_when_owner`
//! 10. `get_subscription_by_id_returns_403_when_not_owner_and_not_admin`
//! 11. `get_subscription_by_id_returns_404_when_unknown`
//! 12. `patch_subscription_with_state_paused_calls_pause`
//! 13. `patch_subscription_with_state_active_after_paused_calls_resume`
//! 14. `patch_subscription_with_filter_calls_update`
//! 15. `delete_subscription_returns_204`
//! 16. `admin_list_returns_subscriptions_across_owners_when_admin`
//! 17. `admin_list_returns_403_when_not_admin`
//! 18. `webhook_secret_ref_never_returned_on_get`

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::event_store_publisher::wrap_for_test;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::subscription_use_case::{SubscriptionUseCase, SubscriptionUseCaseConfig};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::entities::subscription::{
    EventTypeFilter, RepositoryScope, Subscription, SubscriptionFilter, SubscriptionId,
    SubscriptionState, SubscriptionTarget,
};
use hort_domain::ports::secret_port::{SecretRef, SecretSource};
use hort_http_core::context::AppContext;
use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_subscription_use_case, MockPorts};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn new_ctx() -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    build_mock_ctx(handle)
}

fn build_test_router(ctx: Arc<AppContext>) -> axum::Router {
    axum::Router::new()
        .merge(hort_http_subscriptions::router())
        .with_state(ctx)
}

fn user_principal(user_id: Uuid) -> CallerPrincipal {
    CallerPrincipal {
        user_id,
        external_id: "test-user".into(),
        username: "test-user".into(),
        email: "test@example.com".into(),
        // Single resolved `claims` set (ADR 0012); unprivileged caller
        // has no claims.
        claims: vec![],
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

fn admin_principal() -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "admin-user".into(),
        username: "admin-user".into(),
        email: "admin@example.com".into(),
        // The lowercase `"admin"` claim short-circuits the evaluator
        // (ADR 0012).
        claims: vec!["admin".into()],
        token_kind: None,
        issued_at: Utc::now(),
        token_cap: None,
    }
}

/// Build a `SubscriptionUseCase` whose RBAC evaluator grants
/// `Permission::Admin` (globally) to any caller whose resolved claims
/// contain `admin`. The lowercase-`admin` claim also short-circuits
/// `RbacEvaluator::authorize` directly (ADR 0012), so this explicit
/// `GrantSubject::Claims(["admin"])` grant is belt-and-braces fidelity.
fn subscription_use_case_with_admin_role(mocks: &MockPorts) -> Arc<SubscriptionUseCase> {
    let grant = PermissionGrant {
        id: Uuid::new_v4(),
        subject: GrantSubject::Claims(vec!["admin".into()]),
        repository_id: None,
        permission: Permission::Admin,
        created_at: Utc::now(),
        managed_by: ManagedBy::Local,
        managed_by_digest: None,
    };
    let evaluator = RbacEvaluator::new(vec![grant]);
    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(evaluator));
    let events = wrap_for_test(mocks.events.clone());
    Arc::new(SubscriptionUseCase::new(
        mocks.subscriptions.clone(),
        mocks.users.clone(),
        events,
        rbac,
        mocks.repositories.clone(),
        mocks.webhook_guard.clone(),
        SubscriptionUseCaseConfig::default(),
    ))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn create_body_webhook(name: &str) -> String {
    json!({
        "name": name,
        "target": {
            "kind": "webhook",
            "url": "https://example.com/hook",
            "secret_ref": { "source": "env_var", "location": "HORT_WEBHOOK_SECRET" }
        },
        "filter": {
            "categories": ["artifact"],
            "event_types": { "kind": "all" },
            "repositories": { "kind": "owned_by_actor" }
        }
    })
    .to_string()
}

fn seed_subscription(mocks: &MockPorts, owner: Uuid, name: &str) -> SubscriptionId {
    let id = SubscriptionId(Uuid::new_v4());
    let sub = Subscription {
        id,
        owner_user_id: owner,
        created_by_token_id: None,
        name: name.to_string(),
        description: None,
        target: SubscriptionTarget::NatsJetStream {
            subject: "events.test".into(),
        },
        filter: SubscriptionFilter {
            categories: vec![hort_domain::events::StreamCategory::Artifact],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: vec![],
        },
        // Authority-floor field (ADR 0012). A directly-seeded fixture row
        // (not driven through the create path) starts with the empty
        // floor; the dispatcher gate tests that need a populated floor
        // set it explicitly.
        snapshot_claims: Vec::new(),
        state: SubscriptionState::Active,
        last_delivered_position: None,
        last_failure: None,
        created_at: Utc::now(),
    };
    mocks.subscriptions.seed(sub);
    id
}

// ---------------------------------------------------------------------------
// Test 1 — POST returns 201; the request carries a secret_ref locator
// (mirrors upstream-mapping) and NO plaintext is echoed back (F-19).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_subscriptions_returns_201_with_secret_ref_and_no_plaintext_in_response() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let mut req = Request::post("/api/v1/subscriptions")
        .header("content-type", "application/json")
        .body(Body::from(create_body_webhook("primary")))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(Uuid::new_v4()));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = body_json(resp).await;
    assert!(body["id"].is_string());
    // F-19: no plaintext secret is handled anywhere in the create path —
    // the response carries NO `secret_plaintext` field at all.
    assert!(
        body.get("secret_plaintext").is_none(),
        "create response must not carry a plaintext secret (F-19): {body}"
    );
    // The webhook secret_ref / hash / plaintext never appear on the read
    // shape either.
    let target = &body["target"];
    assert_eq!(target["kind"], "webhook");
    assert!(target.get("secret_hash").is_none());
    assert!(target.get("secret").is_none());
    assert!(target.get("secret_ref").is_none());
}

// ---------------------------------------------------------------------------
// Test 1b — a malformed secret_ref (env_var location not POSIX-portable)
// is rejected at the wire boundary with 400 invalid_webhook_secret_ref
// (F-19; mirrors the upstream-mapping validate_secret_ref boundary rule).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_subscriptions_returns_400_on_malformed_secret_ref() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let body = json!({
        "name": "bad-secret-ref",
        "target": {
            "kind": "webhook",
            "url": "https://example.com/hook",
            // lowercase env-var name violates `^[A-Z_][A-Z0-9_]*$`
            "secret_ref": { "source": "env_var", "location": "not-portable" }
        },
        "filter": {
            "categories": ["artifact"],
            "event_types": { "kind": "all" },
            "repositories": { "kind": "owned_by_actor" }
        }
    })
    .to_string();

    let mut req = Request::post("/api/v1/subscriptions")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(Uuid::new_v4()));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "invalid_webhook_secret_ref");
}

// ---------------------------------------------------------------------------
// Test 2 — empty name → 400 validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_subscriptions_returns_400_on_validation_failure() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let body = json!({
        "name": "",
        "target": {
            "kind": "webhook",
            "url": "https://example.com/hook",
            "secret_ref": { "source": "env_var", "location": "HORT_WEBHOOK_SECRET" }
        },
        "filter": {
            "categories": ["artifact"],
            "event_types": { "kind": "all" },
            "repositories": { "kind": "owned_by_actor" }
        }
    });

    let mut req = Request::post("/api/v1/subscriptions")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(Uuid::new_v4()));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_json(resp).await;
    assert_eq!(body["error"], "validation");
}

// ---------------------------------------------------------------------------
// Test 3 — http:// URL when plaintext is disabled → 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_subscriptions_returns_400_on_plaintext_webhook_disallowed() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let body = json!({
        "name": "plain-http",
        "target": {
            "kind": "webhook",
            "url": "http://example.com/hook",
            "secret_ref": { "source": "env_var", "location": "HORT_WEBHOOK_SECRET" }
        },
        "filter": {
            "categories": ["artifact"],
            "event_types": { "kind": "all" },
            "repositories": { "kind": "owned_by_actor" }
        }
    });

    let mut req = Request::post("/api/v1/subscriptions")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(Uuid::new_v4()));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "plaintext_webhook_disallowed");
}

// ---------------------------------------------------------------------------
// Test 4 — Some([repo_id]) where caller has no Read → 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_subscriptions_returns_403_on_repo_not_authorised() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let unauthorized_repo = Uuid::new_v4();
    let body = json!({
        "name": "by-repo",
        "target": {
            "kind": "webhook",
            "url": "https://example.com/hook",
            "secret_ref": { "source": "env_var", "location": "HORT_WEBHOOK_SECRET" }
        },
        "filter": {
            "categories": ["artifact"],
            "event_types": { "kind": "all" },
            "repositories": {
                "kind": "some",
                "repository_ids": [unauthorized_repo.to_string()]
            }
        }
    });

    let mut req = Request::post("/api/v1/subscriptions")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(Uuid::new_v4()));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = body_json(resp).await;
    assert_eq!(body["error"], "repo_not_authorised");
    let unauthorized = body["unauthorized"].as_array().unwrap();
    assert_eq!(unauthorized.len(), 1);
}

// ---------------------------------------------------------------------------
// Test 5 — duplicate (owner, name) → 409
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_subscriptions_returns_409_on_duplicate_name() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx.clone());

    let user_id = Uuid::new_v4();

    // Seed an existing row with the same name first.
    seed_subscription(&mocks, user_id, "duplicate");

    let mut req = Request::post("/api/v1/subscriptions")
        .header("content-type", "application/json")
        .body(Body::from(create_body_webhook("duplicate")))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(user_id));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "duplicate_name");
}

// ---------------------------------------------------------------------------
// Test 6 — high-volume event type in filter → 400 unsupported_event_type
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_subscriptions_returns_400_on_unsupported_event_type() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let body = json!({
        "name": "high-vol",
        "target": {
            "kind": "webhook",
            "url": "https://example.com/hook",
            "secret_ref": { "source": "env_var", "location": "HORT_WEBHOOK_SECRET" }
        },
        // `artifact` is a NON-privileged category, so the privileged-
        // category admin gate (which would 403 a non-admin before the
        // high-volume check) does not fire — this test isolates the
        // high-volume-event-type 400 path it is named for.
        // `ArtifactDownloaded` is a high-volume kind in the `artifact`
        // category.
        "filter": {
            "categories": ["artifact"],
            "event_types": {
                "kind": "some",
                "kinds": ["ArtifactDownloaded"]
            },
            "repositories": { "kind": "owned_by_actor" }
        }
    });

    let mut req = Request::post("/api/v1/subscriptions")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(Uuid::new_v4()));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "unsupported_event_type");
}

// ---------------------------------------------------------------------------
// Test 7 — GET list returns paginated rows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_subscriptions_returns_paginated_list() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let owner = Uuid::new_v4();
    seed_subscription(&mocks, owner, "sub-a");
    seed_subscription(&mocks, owner, "sub-b");
    seed_subscription(&mocks, Uuid::new_v4(), "other-owners-sub");

    let mut req = Request::get("/api/v1/subscriptions")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, user_principal(owner));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "only the owner's two subs should appear");
    assert_eq!(body["total"], 2);
}

// ---------------------------------------------------------------------------
// Test 8 — GET by id, owner caller → 200
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_subscription_by_id_returns_subscription_when_owner() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let owner = Uuid::new_v4();
    let id = seed_subscription(&mocks, owner, "mine");

    let mut req = Request::get(format!("/api/v1/subscriptions/{}", id.0))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, user_principal(owner));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["name"], "mine");
    assert_eq!(body["owner_user_id"], owner.to_string());
}

// ---------------------------------------------------------------------------
// Test 9 — GET by id, not owner + not admin → 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_subscription_by_id_returns_403_when_not_owner_and_not_admin() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let owner = Uuid::new_v4();
    let other = Uuid::new_v4();
    let id = seed_subscription(&mocks, owner, "theirs");

    let mut req = Request::get(format!("/api/v1/subscriptions/{}", id.0))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, user_principal(other));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "not_authorized");
}

// ---------------------------------------------------------------------------
// Test 10 — GET by unknown id → 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_subscription_by_id_returns_404_when_unknown() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let mut req = Request::get(format!("/api/v1/subscriptions/{}", Uuid::new_v4()))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, user_principal(Uuid::new_v4()));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 11 — PATCH state=Paused on Active sub → pause()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_subscription_with_state_paused_calls_pause() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let owner = Uuid::new_v4();
    let id = seed_subscription(&mocks, owner, "to-pause");

    let body = json!({ "state": "Paused" }).to_string();
    let mut req = Request::patch(format!("/api/v1/subscriptions/{}", id.0))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(owner));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["state"], "Paused");
}

// ---------------------------------------------------------------------------
// Test 12 — PATCH state=Active on Paused sub → resume()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_subscription_with_state_active_after_paused_calls_resume() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let owner = Uuid::new_v4();
    let id = seed_subscription(&mocks, owner, "to-resume");

    // Seed a paused row directly so we can flip back to Active.
    {
        let mut existing = mocks
            .subscriptions
            .list_for_owner_blocking(owner)
            .into_iter()
            .next()
            .unwrap();
        existing.state = SubscriptionState::Paused;
        mocks.subscriptions.seed(existing);
    }

    let body = json!({ "state": "Active" }).to_string();
    let mut req = Request::patch(format!("/api/v1/subscriptions/{}", id.0))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(owner));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["state"], "Active");
}

// ---------------------------------------------------------------------------
// Test 13 — PATCH with `filter` field → update()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_subscription_with_filter_calls_update() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let owner = Uuid::new_v4();
    let id = seed_subscription(&mocks, owner, "to-rename");

    // Update the description (a non-state field).
    let body = json!({ "description": "now annotated" }).to_string();
    let mut req = Request::patch(format!("/api/v1/subscriptions/{}", id.0))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(owner));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["description"], "now annotated");
}

// ---------------------------------------------------------------------------
// Test 14 — DELETE returns 204
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_subscription_returns_204() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let owner = Uuid::new_v4();
    let id = seed_subscription(&mocks, owner, "to-delete");

    let mut req = Request::delete(format!("/api/v1/subscriptions/{}", id.0))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_principal(&mut req, user_principal(owner));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(mocks.subscriptions.count(), 0);
}

// ---------------------------------------------------------------------------
// Test 15 — admin list returns subs across owners
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_list_returns_subscriptions_across_owners_when_admin() {
    let (ctx, mocks) = new_ctx();
    // Replace the use case with one whose RBAC grants Admin to the `admin` role.
    let uc = subscription_use_case_with_admin_role(&mocks);
    let ctx = with_subscription_use_case(&ctx, uc);
    let router = build_test_router(ctx);

    seed_subscription(&mocks, Uuid::new_v4(), "by-owner-a");
    seed_subscription(&mocks, Uuid::new_v4(), "by-owner-b");

    let mut req = Request::get("/api/v1/admin/subscriptions")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, admin_principal());

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 16 — non-admin gets 403 on admin list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_list_returns_403_when_not_admin() {
    let (ctx, _mocks) = new_ctx();
    let router = build_test_router(ctx);

    let mut req = Request::get("/api/v1/admin/subscriptions")
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, user_principal(Uuid::new_v4()));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Test 17 — the webhook secret_ref locator is never echoed on GET (the
// read shape carries neither the locator, a hash, nor any plaintext).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_secret_ref_never_returned_on_get() {
    let (ctx, mocks) = new_ctx();
    let router = build_test_router(ctx);

    let owner = Uuid::new_v4();
    let id = seed_subscription(&mocks, owner, "no-echo");
    // Inject a webhook target carrying a SecretRef locator directly
    // (F-19: the row stores the locator, never the secret material).
    {
        let url = url::Url::parse("https://example.com/hook").unwrap();
        let secret_ref = SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        };
        let mut existing = mocks
            .subscriptions
            .list_for_owner_blocking(owner)
            .into_iter()
            .next()
            .unwrap();
        existing.target = SubscriptionTarget::Webhook { url, secret_ref };
        mocks.subscriptions.seed(existing);
    }

    let mut req = Request::get(format!("/api/v1/subscriptions/{}", id.0))
        .body(Body::empty())
        .unwrap();
    auth_test::inject_optional_principal_some(&mut req, user_principal(owner));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    // No plaintext, no hash on the read shape.
    assert!(body.get("secret_plaintext").is_none());
    let target = &body["target"];
    assert_eq!(target["kind"], "webhook");
    assert!(target.get("secret_hash").is_none());
    assert!(target.get("secret").is_none());
}
