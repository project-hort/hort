//! Integration tests for `GET /api/v1/events`.
//!
//! Drives the router through `tower::ServiceExt::oneshot`. The mock
//! harness comes from `hort_http_core::test_support::build_mock_ctx`;
//! the new `MockPorts.events` handle is the `MockEventStore` that the
//! `AppContext.event_store` publisher wraps. Per-event seeding goes
//! through `MockEventStore::set_category`.
//!
//! # Test coverage
//!
//! 1. Missing category → 400.
//! 2. Unknown category → 400.
//! 3. No matching events → 200 + empty list.
//! 4. Events returned in `global_position` order.
//! 5. `after` param skips prior events.
//! 6. `max` clamps to 1000.
//! 7. `wait_ms` clamps to 30000 (query-parse boundary).
//! 8. Admin-only category, non-admin caller → 403.
//! 9. Admin-only category, admin caller → 200.
//! 10. Per-event repo filter for `Artifact` category.
//! 11. `next_after` is the unfiltered last-seen position.
//! 12. `has_more=true` when response length equals `max`.
//! 13. Long-poll wait_ms=100ms with no events → empty within ~100ms.
//! 14. Long-poll wakes up on a published event.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::Value;
use tokio::sync::broadcast;
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
use hort_app::use_cases::test_support::MockIdentityProvider;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
use hort_domain::events::{
    Actor, ApiActor, ArtifactIngested, DomainEvent, IngestSource, PersistedEvent, PolicyCreated,
    PolicyScope, StreamCategory, StreamId,
};
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::identity_provider::IdentityProvider;
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::types::ContentHash;

use hort_http_core::context::{AppContext, AuthContext};
use hort_http_core::middleware::auth::test_support as auth_test;
use hort_http_core::test_support::{build_mock_ctx, with_auth, MockPorts};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn new_ctx() -> (Arc<AppContext>, MockPorts) {
    let handle = PrometheusBuilder::new().build_recorder().handle();
    build_mock_ctx(handle)
}

fn build_router(ctx: Arc<AppContext>) -> axum::Router {
    axum::Router::new()
        .merge(hort_http_events::router())
        .with_state(ctx)
}

fn user_principal() -> CallerPrincipal {
    CallerPrincipal {
        user_id: Uuid::new_v4(),
        external_id: "test-user".into(),
        username: "test-user".into(),
        email: "test@example.com".into(),
        // Single resolved `claims` set (ADR 0012); an unprivileged
        // caller starts with no claims.
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

/// Flip a mock context to `AuthContext::Enabled` so the handler's
/// admin / per-repo authz gates fire. The seeded `RbacEvaluator`
/// honours the lowercase `"admin"` role short-circuit
/// (`hort-app::rbac::RbacEvaluator::authorize`); fine-grained per-repo
/// grants are added by the `with_repo_grants` helper.
fn enable_auth(
    base: &Arc<AppContext>,
    mocks: &MockPorts,
    repo_grants: &[(Uuid, Uuid)],
) -> Arc<AppContext> {
    enable_auth_with(base, mocks, repo_grants, Permission::Read)
}

fn enable_auth_with(
    base: &Arc<AppContext>,
    mocks: &MockPorts,
    repo_grants: &[(Uuid, Uuid)], // (unused, repository_id) — the "test-role" claim resolves `permission` on repo_id
    permission: Permission,
) -> Arc<AppContext> {
    let idp = Arc::new(MockIdentityProvider::new());
    let users: Arc<dyn UserRepository> = mocks.users.clone();
    let authenticate = Arc::new(AuthenticateUseCase::new(
        idp as Arc<dyn IdentityProvider>,
        users,
        Vec::new(),
    ));

    // Build a per-test flat grant set (ADR 0012). Each grant's subject is
    // `Claims(["test-role"])`; a principal must carry `"test-role"` in
    // `principal.claims` to use the attached grants. Per
    // `RbacEvaluator::authorize`, the lowercase-`"admin"` claim
    // short-circuits regardless of the grant set — so
    // `admin_principal()` always passes admin-required categories
    // without any extra wiring.
    let grants: Vec<PermissionGrant> = repo_grants
        .iter()
        .map(|(_, repo_id)| PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["test-role".into()]),
            repository_id: Some(*repo_id),
            permission,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        })
        .collect();
    let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(grants)));

    with_auth(
        base,
        AuthContext::Enabled {
            authenticate,
            rbac,
            issuer_url: None,
        },
    )
}

fn artifact_event(repo_id: Uuid, global_pos: u64) -> PersistedEvent {
    let artifact_id = Uuid::new_v4();
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::artifact(artifact_id),
        stream_position: 0,
        global_position: global_pos,
        event: DomainEvent::ArtifactIngested(ArtifactIngested {
            artifact_id,
            repository_id: repo_id,
            name: "pkg".into(),
            version: Some("1.0.0".into()),
            sha256: "a".repeat(64).parse::<ContentHash>().unwrap(),
            size_bytes: 1,
            source: IngestSource::Direct,
            metadata: Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        }),
        event_version: 1,
        stored_at: Utc::now(),
    }
}

fn policy_event(global_pos: u64) -> PersistedEvent {
    let policy_id = Uuid::new_v4();
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::policy(policy_id),
        stream_position: 0,
        global_position: global_pos,
        event: DomainEvent::PolicyCreated(PolicyCreated {
            policy_id,
            name: "default".into(),
            scope: PolicyScope::Global,
            config_snapshot: serde_json::json!({}),
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        }),
        event_version: 1,
        stored_at: Utc::now(),
    }
}

/// Repo-scoped `PermissionGrantApplied` on the `StreamCategory::Repository`
/// stream — the audit F-39 read-path leak shape. The category is non-admin
/// and the payload carries `Some(repo)`, so without the type-not-category
/// gate a `Read`-on-repo caller would clear the upfront gate AND step 5's
/// per-repo `Read` filter and receive the grant topology.
fn repository_grant_event(repo_id: Uuid, global_pos: u64) -> PersistedEvent {
    use hort_domain::events::{GrantSubjectRecord, PermissionGrantApplied};
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::repository(repo_id),
        stream_position: 0,
        global_position: global_pos,
        event: DomainEvent::PermissionGrantApplied(PermissionGrantApplied {
            grant_id: Uuid::new_v4(),
            subject: GrantSubjectRecord::Claims {
                required: vec!["developer".into()],
            },
            permission: Permission::Read,
            repository_id: Some(repo_id),
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        }),
        event_version: 1,
        stored_at: Utc::now(),
    }
}

/// Ordinary (non-privileged) repo-scoped event on the
/// `StreamCategory::Repository` stream — `ChecksumMismatch` carries a direct
/// `repository_id` and is neither an authorization-model mutation nor a
/// privileged-audit, so it must still flow to a `Read`-on-repo caller (the
/// type gate is precise — no regression).
fn repository_checksum_mismatch_event(repo_id: Uuid, global_pos: u64) -> PersistedEvent {
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::events::ChecksumMismatch;
    use hort_domain::types::{ArtifactCoords, HashAlgorithm};
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::repository(repo_id),
        stream_position: 0,
        global_position: global_pos,
        event: DomainEvent::ChecksumMismatch(ChecksumMismatch {
            repository_id: repo_id,
            coords: ArtifactCoords {
                name: "pkg".into(),
                name_as_published: "pkg".into(),
                version: Some("1.0".into()),
                path: "pkg/1.0/pkg-1.0.tar.gz".into(),
                format: RepositoryFormat::Pypi,
                metadata: Value::Null,
            },
            format: "pypi".into(),
            algorithm: HashAlgorithm::Sha256,
            upstream_value: "a".repeat(64),
            computed_value: "b".repeat(64),
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        }),
        event_version: 1,
        stored_at: Utc::now(),
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    // 8 MiB ceiling: the `max=1000` test sends ~1000 events × ~700
    // bytes per event ≈ 700 KB. 8 MiB leaves plenty of headroom and
    // matches what the production handler emits.
    let bytes = to_bytes(resp.into_body(), 8 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn get(uri: &str, principal: CallerPrincipal) -> Request<Body> {
    let mut req = Request::get(uri).body(Body::empty()).unwrap();
    auth_test::inject_principal(&mut req, principal);
    req
}

// ---------------------------------------------------------------------------
// 1 — Missing category → 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_returns_400_when_category_missing() {
    let (ctx, _mocks) = new_ctx();
    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events", user_principal()))
        .await
        .unwrap();
    // Axum's Query extractor rejects with 400 when a required field is
    // absent — same shape every other Query-bearing handler uses.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// 2 — Unknown category → 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_returns_400_when_category_unknown() {
    let (ctx, _mocks) = new_ctx();
    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=bogus", user_principal()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "bad_request");
    assert!(body["message"].as_str().unwrap().contains("bogus"));
}

// ---------------------------------------------------------------------------
// 3 — No events → 200 + empty list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_returns_200_with_empty_list_when_no_events_match() {
    let (ctx, _mocks) = new_ctx();
    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=artifact", user_principal()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert!(events.is_empty(), "expected zero events, got {events:?}");
    // `next_after` defaults to `after` (0) when no events.
    assert_eq!(body["next_after"], 0);
    assert_eq!(body["has_more"], false);
}

// ---------------------------------------------------------------------------
// 4 — Returns events in global_position order
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_returns_events_in_global_position_order() {
    let (ctx, mocks) = new_ctx();
    let repo_id = Uuid::new_v4();
    let e1 = artifact_event(repo_id, 1);
    let e2 = artifact_event(repo_id, 2);
    let e3 = artifact_event(repo_id, 3);
    // Insert deliberately out-of-order; the mock sorts by position.
    mocks.events.set_category(
        StreamCategory::Artifact,
        vec![e3.clone(), e1.clone(), e2.clone()],
    );

    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=artifact", user_principal()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["global_position"], 1);
    assert_eq!(events[1]["global_position"], 2);
    assert_eq!(events[2]["global_position"], 3);
    assert_eq!(body["next_after"], 3);
    assert_eq!(body["has_more"], false);
    // event_type round-trips on the wire.
    assert_eq!(events[0]["event_type"], "ArtifactIngested");
    assert_eq!(events[0]["stream_category"], "artifact");
}

// ---------------------------------------------------------------------------
// 5 — `after` param filters out prior events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_respects_after_param() {
    let (ctx, mocks) = new_ctx();
    let repo_id = Uuid::new_v4();
    mocks.events.set_category(
        StreamCategory::Artifact,
        vec![
            artifact_event(repo_id, 1),
            artifact_event(repo_id, 2),
            artifact_event(repo_id, 3),
        ],
    );

    let router = build_router(ctx);
    let resp = router
        .oneshot(get(
            "/api/v1/events?category=artifact&after=1",
            user_principal(),
        ))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["global_position"], 2);
    assert_eq!(events[1]["global_position"], 3);
}

// ---------------------------------------------------------------------------
// 6 — max clamps to 1000
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_clamps_max_to_1000() {
    let (ctx, mocks) = new_ctx();
    let repo_id = Uuid::new_v4();
    // Seed 1005 events; max-clamping to 1000 means at most 1000 in the
    // page. The mock store sorts + truncates by max_count, so this
    // exercises the clamp.
    let seeded: Vec<PersistedEvent> = (1..=1005)
        .map(|i| artifact_event(repo_id, i as u64))
        .collect();
    mocks.events.set_category(StreamCategory::Artifact, seeded);

    let router = build_router(ctx);
    let resp = router
        .oneshot(get(
            "/api/v1/events?category=artifact&max=99999",
            user_principal(),
        ))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert!(
        events.len() <= 1000,
        "expected at most 1000 events, got {}",
        events.len()
    );
    // 1005 seeded, clamp at 1000 → exactly 1000 returned.
    assert_eq!(events.len(), 1000);
    assert_eq!(body["has_more"], true);
}

// ---------------------------------------------------------------------------
// 7 — wait_ms clamps at the query-parse boundary
// ---------------------------------------------------------------------------

#[test]
fn get_events_clamps_wait_ms_to_30000_at_query_parse_level() {
    use hort_http_events::dto::{EventsQuery, MAX_WAIT_MS};
    let q = EventsQuery {
        category: "artifact".into(),
        after: 0,
        max: None,
        wait_ms: Some(60_000),
    };
    assert_eq!(q.resolved_wait_ms(), MAX_WAIT_MS);
}

// ---------------------------------------------------------------------------
// 8 — Admin-only category, non-admin caller → 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_returns_403_for_admin_only_category_when_caller_not_admin() {
    let (base, mocks) = new_ctx();
    let ctx = enable_auth(&base, &mocks, &[]);
    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=policy", user_principal()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "forbidden");
}

// ---------------------------------------------------------------------------
// 9 — Admin-only category, admin caller → 200
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_returns_200_for_admin_only_category_when_caller_is_admin() {
    let (base, mocks) = new_ctx();
    mocks.events.set_category(
        StreamCategory::Policy,
        vec![policy_event(1), policy_event(2)],
    );

    let ctx = enable_auth(&base, &mocks, &[]);
    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=policy", admin_principal()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
}

// ---------------------------------------------------------------------------
// 10 — Per-event repo filter for Artifact category
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_filters_per_repo_for_artifact_category() {
    let (base, mocks) = new_ctx();
    let repo_a = Uuid::new_v4();
    let repo_b = Uuid::new_v4();
    // Caller has Read on repo_a only — the test-role grant table the
    // helper builds carries `(test-role, repo_a, Read)`. The caller
    // resolved via `user_principal_with_role` (below) lists
    // "test-role" so the grant applies.
    let ctx = enable_auth(&base, &mocks, &[(Uuid::new_v4(), repo_a)]);

    mocks.events.set_category(
        StreamCategory::Artifact,
        vec![artifact_event(repo_a, 1), artifact_event(repo_b, 2)],
    );

    // Principal carries the "test-role" role so the grant is in scope.
    let mut p = user_principal();
    p.claims = vec!["test-role".into()];

    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=artifact", p))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    // repo_a event passes; repo_b filtered out.
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["global_position"], 1);
}

// ---------------------------------------------------------------------------
// 11 — next_after is the unfiltered last-seen position
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_returns_next_after_as_unfiltered_max_position() {
    let (base, mocks) = new_ctx();
    let repo_a = Uuid::new_v4();
    let repo_b = Uuid::new_v4();
    let ctx = enable_auth(&base, &mocks, &[(Uuid::new_v4(), repo_a)]);

    // repo_a at position 5, repo_b at position 10. Caller has Read on
    // repo_a only, so only the position-5 event appears, but
    // `next_after` MUST be 10 (the unfiltered max) per design doc §9.
    mocks.events.set_category(
        StreamCategory::Artifact,
        vec![artifact_event(repo_a, 5), artifact_event(repo_b, 10)],
    );

    let mut p = user_principal();
    p.claims = vec!["test-role".into()];

    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=artifact", p))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["global_position"], 5);
    assert_eq!(body["next_after"], 10);
}

// ---------------------------------------------------------------------------
// 12 — has_more=true when response length equals max
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_returns_has_more_true_when_response_length_equals_max() {
    let (ctx, mocks) = new_ctx();
    let repo_id = Uuid::new_v4();
    mocks.events.set_category(
        StreamCategory::Artifact,
        vec![
            artifact_event(repo_id, 1),
            artifact_event(repo_id, 2),
            artifact_event(repo_id, 3),
        ],
    );

    let router = build_router(ctx);
    let resp = router
        .oneshot(get(
            "/api/v1/events?category=artifact&max=2",
            user_principal(),
        ))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(body["has_more"], true);
    assert_eq!(body["next_after"], 2);
}

// ---------------------------------------------------------------------------
// 13 — Long-poll returns empty within the wait window when nothing arrives
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_long_poll_returns_empty_when_no_events_published_within_window() {
    let (ctx, _mocks) = new_ctx();
    let router = build_router(ctx);

    let start = std::time::Instant::now();
    let resp = router
        .oneshot(get(
            "/api/v1/events?category=artifact&wait_ms=200",
            user_principal(),
        ))
        .await
        .unwrap();
    let elapsed = start.elapsed();

    // The mock publisher returned by `wrap_for_test` has no broadcast
    // sender — the slow path collapses to the empty initial read
    // immediately. Either branch is correct (empty → return), so the
    // assertion is "well under the wait window" rather than "at least
    // 200ms".
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["events"].as_array().unwrap().is_empty());
    assert!(
        elapsed < Duration::from_millis(2_000),
        "long-poll empty should return quickly, took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// 14 — Long-poll wakes up on a published event
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_long_poll_wakes_up_on_published_event() {
    // Build a base context, then swap in an EventStorePublisher that
    // actually has a broadcast sender (the mock harness wires
    // `wrap_for_test`, which is `without_broadcast`). The publisher's
    // inner store is the SAME `MockEventStore` instance the test
    // seeds via `set_category`, so a follow-up `read_category` after
    // wake-up observes the seeded row.
    let (base, mocks) = new_ctx();

    let inner: Arc<dyn EventStore> = mocks.events.clone();
    let (sender, _initial_rx) = broadcast::channel::<Arc<PersistedEvent>>(64);
    let publisher = Arc::new(EventStorePublisher::new(inner, sender.clone()));

    // Replace `ctx.event_store` via `Arc::get_mut` — the test owns the
    // sole strong ref at this point. Other use cases inside the
    // context retain the original `without_broadcast` publisher; the
    // handler reads `ctx.event_store` directly so the swap is
    // sufficient for this test.
    let mut owned = base;
    {
        let m = Arc::get_mut(&mut owned).expect("test owns the sole Arc<AppContext> at this point");
        m.event_store = publisher.clone();
    }
    let ctx = owned;

    // Spawn a task that publishes an event 50ms after the request
    // begins. The handler must wake up within the wait window.
    let repo_id = Uuid::new_v4();
    let event = Arc::new(artifact_event(repo_id, 7));
    // Pre-seed the event into the mock store so the post-wake-up
    // `read_category` returns it.
    mocks
        .events
        .set_category(StreamCategory::Artifact, vec![(*event).clone()]);

    let sender_for_task = sender.clone();
    let event_for_task = event.clone();
    let publish_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = sender_for_task.send(event_for_task);
    });

    let router = build_router(ctx);

    let start = std::time::Instant::now();
    let resp = router
        .oneshot(get(
            "/api/v1/events?category=artifact&after=0&wait_ms=5000",
            user_principal(),
        ))
        .await
        .unwrap();
    let elapsed = start.elapsed();

    // The publish task should have fired by now; wait for it to clean
    // up.
    publish_task.await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["global_position"], 7);
    assert!(
        elapsed < Duration::from_millis(2_500),
        "long-poll should have woken on the published event, took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// 15 — Disabled auth: admin-only category passes (no Enabled gate)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_under_disabled_auth_admin_only_category_passes() {
    // Default `build_mock_ctx` is `AuthContext::Disabled`; the handler
    // skips the admin gate under Disabled (same contract every other
    // F1 extractor uses). This pins that contract so a future
    // refactor doesn't tighten the gate without an explicit decision.
    let (ctx, mocks) = new_ctx();
    mocks
        .events
        .set_category(StreamCategory::Policy, vec![policy_event(1)]);

    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=policy", user_principal()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["events"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 16 — MockEventStore-backed long-poll: no broadcast sender → fast empty.
// (Exercises the `subscribe() -> None` branch explicitly so coverage
// hits the early-return arm of `long_poll_events`.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_long_poll_collapses_when_publisher_has_no_broadcast() {
    let (ctx, _mocks) = new_ctx();
    // `wrap_for_test` is `without_broadcast`; the handler's slow path
    // observes `subscribe() == None` and returns empty without
    // waiting for `wait_ms` to elapse.
    let router = build_router(ctx);
    let resp = router
        .oneshot(get(
            "/api/v1/events?category=artifact&wait_ms=10000",
            user_principal(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// 17 — Forbidden response carries `message` alongside `error`
// (consistency with `BadRequest`).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_forbidden_response_includes_message_field() {
    let (base, mocks) = new_ctx();
    let ctx = enable_auth(&base, &mocks, &[]);
    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=policy", user_principal()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "forbidden");
    assert!(
        body["message"].is_string(),
        "forbidden response must carry a `message` field for consistency \
         with the BadRequest envelope"
    );
}

// ---------------------------------------------------------------------------
// 18 — `hort_events_pull_total` fires with the expected labels on success.
// (design doc §12 metric.)
// ---------------------------------------------------------------------------

#[test]
fn get_events_emits_hort_events_pull_total_with_success_label() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    // Build a single-threaded runtime in a non-async test so the
    // metrics local recorder scope wraps the entire handler future.
    // `with_local_recorder` is sync and stack-scoped — using it from
    // inside a `#[tokio::test]` future panics (nested runtimes).
    let status = metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (ctx, mocks) = new_ctx();
            let repo_id = Uuid::new_v4();
            mocks
                .events
                .set_category(StreamCategory::Artifact, vec![artifact_event(repo_id, 1)]);
            let router = build_router(ctx);
            let resp = router
                .oneshot(get("/api/v1/events?category=artifact", user_principal()))
                .await
                .unwrap();
            resp.status()
        })
    });
    assert_eq!(status, StatusCode::OK);

    let entries: Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )> = snapshotter.snapshot().into_vec();
    let counter = entries
        .iter()
        .find(|(k, _, _, _)| {
            k.kind() == MetricKind::Counter
                && k.key().name() == "hort_events_pull_total"
                && k.key()
                    .labels()
                    .any(|l| l.key() == "category" && l.value() == "artifact")
                && k.key()
                    .labels()
                    .any(|l| l.key() == "result" && l.value() == "success")
        })
        .expect(
            "hort_events_pull_total{category=artifact,result=success} must fire on a happy-path call",
        );
    match &counter.3 {
        DebugValue::Counter(v) => assert_eq!(*v, 1),
        other => panic!("expected Counter, got {other:?}"),
    }
    // The duration histogram fires alongside.
    let histogram = entries.iter().find(|(k, _, _, _)| {
        k.kind() == MetricKind::Histogram
            && k.key().name() == "hort_events_pull_duration_seconds"
            && k.key()
                .labels()
                .any(|l| l.key() == "category" && l.value() == "artifact")
    });
    assert!(
        histogram.is_some(),
        "hort_events_pull_duration_seconds{{category=artifact}} histogram must also fire"
    );
}

// ---------------------------------------------------------------------------
// Authorization-model events gate on event TYPE, not stream CATEGORY.
// Read-path leg.
// ---------------------------------------------------------------------------

// F-39: a repo-scoped `PermissionGrantApplied` rides the NON-admin
// `Repository` category, so a `Read`-on-repo caller cleared the upfront
// admin-category gate AND step 5's per-repo `Read` filter — leaking RBAC
// topology. The type gate must now drop it for a non-admin caller.
#[tokio::test]
async fn get_events_denies_repo_scoped_permission_grant_to_read_only_caller() {
    let (base, mocks) = new_ctx();
    let repo_a = Uuid::new_v4();
    // Caller has Read on repo_a.
    let ctx = enable_auth(&base, &mocks, &[(Uuid::new_v4(), repo_a)]);

    mocks.events.set_category(
        StreamCategory::Repository,
        vec![repository_grant_event(repo_a, 1)],
    );

    let mut p = user_principal();
    p.claims = vec!["test-role".into()];

    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=repository", p))
        .await
        .unwrap();
    // Category-level gate is non-admin (Repository), so the request is 200;
    // the privileged TYPE must be filtered OUT of the page.
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert!(
        events.is_empty(),
        "Read-only caller must NOT see repo-scoped grant topology (F-39); got {events:?}"
    );
}

// F-39 no-regression: an admin caller IS served the repo-scoped
// `PermissionGrantApplied` (legitimate admin read).
#[tokio::test]
async fn get_events_serves_repo_scoped_permission_grant_to_admin_caller() {
    let (base, mocks) = new_ctx();
    let repo_a = Uuid::new_v4();
    let ctx = enable_auth(&base, &mocks, &[]);

    mocks.events.set_category(
        StreamCategory::Repository,
        vec![repository_grant_event(repo_a, 1)],
    );

    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=repository", admin_principal()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(
        events.len(),
        1,
        "admin caller must still read repo-scoped grant events (no regression)"
    );
}

// No-regression: an ordinary (non-privileged) repo-scoped event on the same
// non-admin `Repository` category — `ChecksumMismatch` — still flows to a
// `Read`-on-repo caller. The type gate is precise (only auth-model-mutation /
// privileged-audit types are blocked).
#[tokio::test]
async fn get_events_serves_ordinary_repository_event_to_read_only_caller() {
    let (base, mocks) = new_ctx();
    let repo_a = Uuid::new_v4();
    let ctx = enable_auth(&base, &mocks, &[(Uuid::new_v4(), repo_a)]);

    mocks.events.set_category(
        StreamCategory::Repository,
        vec![repository_checksum_mismatch_event(repo_a, 1)],
    );

    let mut p = user_principal();
    p.claims = vec!["test-role".into()];

    let router = build_router(ctx);
    let resp = router
        .oneshot(get("/api/v1/events?category=repository", p))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(
        events.len(),
        1,
        "ordinary repo events must still reach a Read caller (no regression)"
    );
}
