//! `PgSubscriptionRepository` integration tests.
//!
//! Asserts the schema / dispatcher cache-refresh hot path
//! contract the adapter ships with:
//!
//! 1. `insert_then_find_by_id_round_trips` — a webhook-target
//!    subscription round-trips through the adapter (`create` →
//!    `find_by_id`) without losing fields.
//! 2. `insert_then_find_by_id_round_trips_nats_target` — same for the
//!    `NatsJetStream` target variant.
//! 3. `find_by_name_returns_some_on_hit_none_on_miss` — adapter hands
//!    out `Option<Subscription>` for the use case's name-collision
//!    probe (called before issuing a `create`).
//! 4. `list_for_owner_orders_by_created_at_desc` — three rows surface
//!    in descending `created_at` order; `total` is 3.
//! 5. `list_active_returns_only_active_subscriptions` — partial index
//!    bounds the dispatcher's cache-refresh hot path.
//! 6. `unique_constraint_on_owner_user_id_and_name` — second insert
//!    surfaces as `DomainError::Conflict` via `map_sqlx_error`.
//! 7. `users_id_delete_cascades` — `users(id) ON DELETE CASCADE`
//!    drops the subscription row.
//! 8. `api_tokens_id_delete_sets_null_on_created_by_token_id` —
//!    `api_tokens(id) ON DELETE SET NULL` keeps the subscription
//!    alive (audit attribution only).
//! 9. `update_last_delivered_persists_position_and_failure` — the
//!    debounced dispatcher hot path writes only the two columns.
//! 10. `update_persists_state_and_disable_reason` — state transition
//!     (Active → Disabled) flips the row's `state`, `disable_reason`,
//!     `disabled_since` columns.
//!
//! Convention (mirrored from `api_token_repo.rs`): require
//! `DATABASE_URL` to be set; when unset, every test early-returns
//! silently so dev environments without a database keep the suite
//! green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test subscription_repo
//! ```

#![allow(clippy::expect_used)]

use std::env;

use chrono::{Duration, Utc};
use hort_adapters_postgres::subscription_repo::PgSubscriptionRepository;
use hort_domain::entities::subscription::{
    DisableReason, EventTypeFilter, EventTypeKind, RepositoryScope, Subscription,
    SubscriptionFailure, SubscriptionFilter, SubscriptionId, SubscriptionState, SubscriptionTarget,
};
use hort_domain::error::DomainError;
use hort_domain::events::StreamCategory;
use hort_domain::ports::event_notifier::NotifyFailureReason;
use hort_domain::ports::secret_port::{SecretRef, SecretSource};
use hort_domain::ports::subscription_repository::SubscriptionRepository;
use hort_domain::types::PageRequest;
use sqlx::PgPool;
use uuid::Uuid;

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Insert a minimal-but-valid `users` row and return the id. Mirrors
/// `tests/api_token_repo.rs::create_test_user`.
async fn create_test_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.users (id, username, email, auth_provider, is_active) \
         VALUES ($1, $2, $3, 'local', true)",
    )
    .bind(id)
    .bind(format!("subscription_i2_{}", id.simple()))
    .bind(format!("subscription_i2_{}@example.test", id.simple()))
    .execute(pool)
    .await
    .expect("seed test user");
    id
}

/// Insert a minimal-but-valid `api_tokens` row and return the id. Used
/// only by the `created_by_token_id` FK SET NULL test.
async fn create_test_api_token(pool: &PgPool, owner_user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    // 8-char token_prefix per the column's `character(8)` width.
    let prefix: String = id.simple().to_string().chars().take(8).collect();
    sqlx::query(
        "INSERT INTO public.api_tokens (\
            id, user_id, name, kind, token_hash, token_prefix, \
            declared_permissions, created_by_user_id\
         ) VALUES (\
            $1, $2, $3, 'pat', $4, $5, $6::text[], $2\
         )",
    )
    .bind(id)
    .bind(owner_user_id)
    .bind(format!("init35-tok-{}", &prefix[..4]))
    .bind("$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel")
    .bind(prefix)
    .bind(vec!["read".to_string()])
    .execute(pool)
    .await
    .expect("seed test api_token");
    id
}

fn sample_webhook_target() -> SubscriptionTarget {
    SubscriptionTarget::Webhook {
        url: "https://hooks.example.com/r/abc".parse().unwrap(),
        // The row carries a SecretRef locator, never the secret material.
        // The round-trip tests below assert this `(source, location)`
        // survives JSONB persistence intact.
        secret_ref: SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        },
    }
}

fn sample_nats_target() -> SubscriptionTarget {
    SubscriptionTarget::NatsJetStream {
        subject: "hort.events.artifact_promoted".into(),
    }
}

fn sample_filter(repo: Uuid) -> SubscriptionFilter {
    SubscriptionFilter {
        categories: vec![StreamCategory::Artifact],
        event_types: EventTypeFilter::Some(vec![EventTypeKind::ArtifactIngested]),
        repositories: RepositoryScope::Some(vec![repo]),
        named_predicates: Vec::new(),
    }
}

fn build_subscription(
    owner: Uuid,
    name: &str,
    target: SubscriptionTarget,
    filter: SubscriptionFilter,
) -> Subscription {
    Subscription {
        id: SubscriptionId(Uuid::new_v4()),
        owner_user_id: owner,
        created_by_token_id: None,
        name: name.to_string(),
        description: Some("subscription-round-trip test".into()),
        target,
        filter,
        // Authority floor captured at create (ADR 0012). Default to
        // empty here (the under-privileged PAT-created shape); the
        // dedicated snapshot round-trip test overrides it.
        snapshot_claims: Vec::new(),
        state: SubscriptionState::Active,
        last_delivered_position: None,
        last_failure: None,
        created_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Acceptance — insert + find_by_id round-trip (webhook).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn insert_then_find_by_id_round_trips() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let repo = Uuid::new_v4();
    let target = sample_webhook_target();
    let filter = sample_filter(repo);
    let sub = build_subscription(owner, "ci-replicator", target.clone(), filter.clone());

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&sub).await.expect("create succeeds");

    let fetched = repository
        .find_by_id(sub.id)
        .await
        .expect("find_by_id succeeds");
    assert_eq!(fetched.id, sub.id);
    assert_eq!(fetched.owner_user_id, owner);
    assert_eq!(fetched.name, "ci-replicator");
    assert_eq!(
        fetched.description.as_deref(),
        Some("subscription-round-trip test")
    );
    assert_eq!(fetched.target, target);
    assert_eq!(fetched.filter, filter);
    assert_eq!(fetched.state, SubscriptionState::Active);
    assert!(fetched.last_delivered_position.is_none());
    assert!(fetched.last_failure.is_none());
}

// ---------------------------------------------------------------------------
// Acceptance — snapshot_claims round-trips through create + find_by_id,
// and update full-replaces the authority floor (ADR 0012).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snapshot_claims_round_trips_and_update_full_replaces() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let repo = Uuid::new_v4();
    let target = sample_webhook_target();
    let filter = sample_filter(repo);
    let mut sub = build_subscription(owner, "claims-floor", target, filter);
    sub.snapshot_claims = vec!["developer".to_string(), "team-alpha".to_string()];

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&sub).await.expect("create succeeds");

    let fetched = repository
        .find_by_id(sub.id)
        .await
        .expect("find_by_id succeeds");
    assert_eq!(
        fetched.snapshot_claims,
        vec!["developer".to_string(), "team-alpha".to_string()],
        "snapshot_claims must round-trip through create + read"
    );

    // update re-captures the authority floor unconditionally,
    // fully replacing the prior value (full-replace semantics).
    let mut updated = fetched.clone();
    updated.snapshot_claims = vec!["admin".to_string()];
    repository.update(&updated).await.expect("update succeeds");

    let after = repository
        .find_by_id(sub.id)
        .await
        .expect("find_by_id after update");
    assert_eq!(
        after.snapshot_claims,
        vec!["admin".to_string()],
        "update must full-replace snapshot_claims, not merge"
    );

    // The under-privileged PAT-created shape is the empty set.
    let mut cleared = after.clone();
    cleared.snapshot_claims = Vec::new();
    repository.update(&cleared).await.expect("clear update");
    let bare = repository.find_by_id(sub.id).await.expect("find bare");
    assert!(bare.snapshot_claims.is_empty());
}

// ---------------------------------------------------------------------------
// Acceptance — insert + find_by_id round-trip (NATS variant).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn insert_then_find_by_id_round_trips_nats_target() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let target = sample_nats_target();
    let filter = SubscriptionFilter {
        categories: vec![StreamCategory::Artifact, StreamCategory::Repository],
        event_types: EventTypeFilter::All,
        repositories: RepositoryScope::OwnedByActor,
        named_predicates: Vec::new(),
    };
    let sub = build_subscription(owner, "siem-shipper", target.clone(), filter.clone());

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&sub).await.expect("create succeeds");

    let fetched = repository
        .find_by_id(sub.id)
        .await
        .expect("find_by_id succeeds");
    assert_eq!(fetched.target, target);
    assert_eq!(fetched.filter, filter);
}

// ---------------------------------------------------------------------------
// Acceptance — find_by_name returns Option<Subscription>.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn find_by_name_returns_some_on_hit_none_on_miss() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let target = sample_webhook_target();
    let filter = sample_filter(Uuid::new_v4());
    let sub = build_subscription(owner, "name-probe", target, filter);

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&sub).await.expect("create succeeds");

    let hit = repository
        .find_by_name(owner, "name-probe")
        .await
        .expect("find_by_name succeeds on hit");
    assert!(hit.is_some());
    assert_eq!(hit.unwrap().id, sub.id);

    let miss = repository
        .find_by_name(owner, "no-such-subscription")
        .await
        .expect("find_by_name succeeds on miss");
    assert!(miss.is_none());

    // Cross-owner: another user's same-name row is invisible to this owner.
    let other_owner = Uuid::new_v4();
    let cross = repository
        .find_by_name(other_owner, "name-probe")
        .await
        .expect("find_by_name succeeds across owners");
    assert!(cross.is_none());
}

// ---------------------------------------------------------------------------
// Acceptance — list_for_owner orders rows by created_at DESC.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_for_owner_orders_by_created_at_desc() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let now = Utc::now();
    let target = sample_webhook_target();
    let filter = sample_filter(Uuid::new_v4());

    let mut s1 = build_subscription(owner, "older", target.clone(), filter.clone());
    s1.created_at = now - Duration::seconds(20);
    let mut s2 = build_subscription(owner, "middle", target.clone(), filter.clone());
    s2.created_at = now - Duration::seconds(10);
    let mut s3 = build_subscription(owner, "newest", target, filter);
    s3.created_at = now;

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&s1).await.expect("insert s1");
    repository.create(&s2).await.expect("insert s2");
    repository.create(&s3).await.expect("insert s3");

    let page = repository
        .list_for_owner(owner, PageRequest::new(0, 10))
        .await
        .expect("list_for_owner succeeds");
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 3);
    assert_eq!(page.items[0].id, s3.id);
    assert_eq!(page.items[1].id, s2.id);
    assert_eq!(page.items[2].id, s1.id);
}

// ---------------------------------------------------------------------------
// Acceptance — list_active returns only state='active' rows.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_active_returns_only_active_subscriptions() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let target = sample_webhook_target();
    let filter = sample_filter(Uuid::new_v4());

    let active = build_subscription(owner, "active-sub", target.clone(), filter.clone());
    let mut disabled = build_subscription(owner, "disabled-sub", target, filter);
    disabled.state = SubscriptionState::Disabled {
        reason: DisableReason::OperatorDisabled,
        since: Utc::now(),
    };

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&active).await.expect("insert active");
    repository.create(&disabled).await.expect("insert disabled");

    let listed = repository
        .list_active()
        .await
        .expect("list_active succeeds");
    // Filter to our owner so a concurrently-running suite cannot leak
    // foreign rows into this assertion.
    let mine: Vec<_> = listed
        .into_iter()
        .filter(|s| s.owner_user_id == owner)
        .collect();
    assert_eq!(mine.len(), 1, "only the active subscription must surface");
    assert_eq!(mine[0].id, active.id);
}

// ---------------------------------------------------------------------------
// Acceptance — UNIQUE(owner_user_id, name) raises Conflict.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unique_constraint_on_owner_user_id_and_name() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let target = sample_webhook_target();
    let filter = sample_filter(Uuid::new_v4());

    let s1 = build_subscription(owner, "duplicate", target.clone(), filter.clone());
    let s2 = build_subscription(owner, "duplicate", target, filter);

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&s1).await.expect("first insert succeeds");
    let err = repository
        .create(&s2)
        .await
        .expect_err("second insert with same (owner, name) must conflict");
    assert!(
        matches!(err, DomainError::Conflict(_)),
        "unique-constraint violation must surface as DomainError::Conflict, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance — users(id) ON DELETE CASCADE drops the subscription.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn users_id_delete_cascades() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let target = sample_webhook_target();
    let filter = sample_filter(Uuid::new_v4());
    let sub = build_subscription(owner, "cascade-victim", target, filter);

    let repository = PgSubscriptionRepository::new(pool.clone());
    repository.create(&sub).await.expect("insert");

    // Hard-delete the owner row; subscription must vanish via CASCADE.
    sqlx::query("DELETE FROM public.users WHERE id = $1")
        .bind(owner)
        .execute(&pool)
        .await
        .expect("delete owner user");

    let err = repository
        .find_by_id(sub.id)
        .await
        .expect_err("CASCADE must have dropped the subscription");
    assert!(matches!(
        err,
        DomainError::NotFound {
            entity: "Subscription",
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Acceptance — api_tokens(id) ON DELETE SET NULL preserves the row.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_tokens_id_delete_sets_null_on_created_by_token_id() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let token_id = create_test_api_token(&pool, owner).await;
    let target = sample_webhook_target();
    let filter = sample_filter(Uuid::new_v4());
    let mut sub = build_subscription(owner, "token-attrib", target, filter);
    sub.created_by_token_id = Some(token_id);

    let repository = PgSubscriptionRepository::new(pool.clone());
    repository.create(&sub).await.expect("insert");

    let before = repository
        .find_by_id(sub.id)
        .await
        .expect("find before delete");
    assert_eq!(before.created_by_token_id, Some(token_id));

    sqlx::query("DELETE FROM public.api_tokens WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await
        .expect("delete authoring token");

    // Subscription stays alive — only the attribution column nulls out.
    let after = repository
        .find_by_id(sub.id)
        .await
        .expect("subscription survives token delete");
    assert_eq!(after.id, sub.id);
    assert_eq!(after.created_by_token_id, None);
}

// ---------------------------------------------------------------------------
// Acceptance — update_last_delivered writes only the two debounced columns.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_last_delivered_persists_position_and_failure() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let target = sample_webhook_target();
    let filter = sample_filter(Uuid::new_v4());
    let sub = build_subscription(owner, "debounce", target, filter);

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&sub).await.expect("insert");

    let failure = SubscriptionFailure {
        at: Utc::now(),
        reason: NotifyFailureReason::Http5xx { status: 503 },
        consecutive_failures: 7,
    };
    repository
        .update_last_delivered(sub.id, 12_891, Some(&failure))
        .await
        .expect("update_last_delivered succeeds");

    let fetched = repository.find_by_id(sub.id).await.expect("find_by_id");
    assert_eq!(fetched.last_delivered_position, Some(12_891));
    let lf = fetched.last_failure.expect("last_failure persisted");
    assert_eq!(lf.consecutive_failures, 7);
    assert_eq!(lf.reason, NotifyFailureReason::Http5xx { status: 503 });

    // Clearing the failure (first-success path) leaves position intact.
    repository
        .update_last_delivered(sub.id, 12_900, None)
        .await
        .expect("clear failure");
    let cleared = repository.find_by_id(sub.id).await.expect("find_by_id");
    assert_eq!(cleared.last_delivered_position, Some(12_900));
    assert!(cleared.last_failure.is_none());
}

// ---------------------------------------------------------------------------
// Acceptance — update persists Active → Disabled state transition.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_persists_state_and_disable_reason() {
    let Some(pool) = admin_pool().await else {
        return;
    };
    let owner = create_test_user(&pool).await;
    let target = sample_webhook_target();
    let filter = sample_filter(Uuid::new_v4());
    let mut sub = build_subscription(owner, "lifecycle", target, filter);

    let repository = PgSubscriptionRepository::new(pool);
    repository.create(&sub).await.expect("insert");

    let when = Utc::now();
    sub.state = SubscriptionState::Disabled {
        reason: DisableReason::DeliveryFailureBudgetExhausted,
        since: when,
    };
    repository
        .update(&sub)
        .await
        .expect("update Active → Disabled");

    let fetched = repository.find_by_id(sub.id).await.expect("find_by_id");
    match fetched.state {
        SubscriptionState::Disabled { reason, .. } => {
            assert_eq!(reason, DisableReason::DeliveryFailureBudgetExhausted);
        }
        other => panic!("expected Disabled state, got {other:?}"),
    }
}
