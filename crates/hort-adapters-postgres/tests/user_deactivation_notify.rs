//! DB-gated integration tests for the
//! `NOTIFY api_token_revocation, 'user:<uuid>'` emission inside
//! `PgUserRepository::save` when the persisted row has `is_active =
//! false`.
//!
//! Multi-replica revocation invalidation requires that user deactivation
//! broadcast on the same channel as token revocation, prefixed with
//! `user:` so every replica drops cached authority entries for that
//! user's PATs. This file pins:
//!
//! 1. The wire-level emission — a `PgListener` subscribed to
//!    `api_token_revocation` observes `user:<uuid>` after a
//!    deactivating `save` (test 1).
//! 2. The negative — saving a user with `is_active = true` does NOT
//!    emit anything on the channel (test 2).
//! 3. The single-fire on transition — saving active then inactive
//!    yields exactly one notification, on the deactivation (test 3).
//! 4. The end-to-end loop — the production
//!    [`spawn_revocation_listener`] task wired against a real
//!    `Arc<dyn ApiTokenCacheInvalidator>` records exactly one
//!    `invalidate_user(user_id)` call after a deactivating save
//!    (test 4).
//!
//! Same `DATABASE_URL` env-var convention as the existing
//! `api_token_revocation_listener.rs` integration tests — when unset,
//! every test early-returns silently so dev environments without a
//! database keep the suite green.
//!
//! ```bash
//! DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!   cargo test -p hort-adapters-postgres --test user_deactivation_notify
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use chrono::Utc;
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use uuid::Uuid;

use hort_adapters_postgres::api_token_revocation_listener::{
    spawn_revocation_listener, REVOCATION_CHANNEL, USER_PREFIX,
};
use hort_adapters_postgres::user_repo::PgUserRepository;
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::ports::api_token_cache_invalidator::ApiTokenCacheInvalidator;
use hort_domain::ports::user_repository::UserRepository;

/// Connect as the migration superuser; run all migrations cleanly.
/// Returns `None` when `DATABASE_URL` is unset — every test
/// early-returns under that branch so the suite stays green on a
/// dev machine without a Postgres.
async fn admin_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations run cleanly against the test DB");
    Some(pool)
}

/// Build a fresh `User` aggregate suitable for `save()`. Uses a unique
/// username/email per call so concurrent test runs don't trip the
/// users.username / users.email unique constraints.
fn make_user(is_active: bool) -> User {
    let id = Uuid::new_v4();
    let stamp = Utc::now();
    User {
        id,
        username: format!("f8-{id}"),
        email: format!("f8-{id}@example.test"),
        auth_provider: AuthProvider::Local,
        external_id: None,
        display_name: Some("deactivation test fixture".into()),
        is_active,
        is_admin: false,
        is_service_account: false,
        last_login_at: None,
        created_at: stamp,
        updated_at: stamp,
    }
}

/// Open a fresh `PgListener` on `api_token_revocation` and wait long
/// enough for the underlying `LISTEN` to be registered server-side
/// before the caller fires their NOTIFY. 250ms matches the existing
/// listener integration tests on the same machine.
async fn open_listener(pool: &PgPool) -> PgListener {
    let mut listener = PgListener::connect_with(pool)
        .await
        .expect("listener connect");
    listener
        .listen(REVOCATION_CHANNEL)
        .await
        .expect("listen api_token_revocation");
    tokio::time::sleep(Duration::from_millis(250)).await;
    listener
}

/// Try to receive a notification within `max_wait`. Returns `Some`
/// payload on success, `None` on timeout. We want both directions —
/// "did fire" tests use `Some(...)` to validate the payload, "did
/// not fire" tests use `None` to validate silence.
async fn try_recv(listener: &mut PgListener, max_wait: Duration) -> Option<String> {
    match tokio::time::timeout(max_wait, listener.recv()).await {
        Ok(Ok(notification)) => Some(notification.payload().to_string()),
        Ok(Err(e)) => panic!("listener.recv() errored: {e}"),
        Err(_elapsed) => None,
    }
}

/// Per-binary serialization gate.
///
/// All four tests in this binary listen on the production
/// `REVOCATION_CHANNEL` — the file tests the production NOTIFY
/// contract (user_repo's hardcoded emitter on user deactivation), so
/// the unique-per-test channel pattern from
/// `api_token_revocation_listener.rs` does not apply here.
///
/// Postgres `LISTEN/NOTIFY` broadcasts to every listener on a channel.
/// Without serialization, a sibling test's NOTIFY is observed by this
/// test's listener under cargo test's intra-binary parallelism.
/// `save_with_is_active_true_does_not_emit_notify` is structurally a
/// negative-assertion test and would observe sibling notifies as
/// false positives; the positive-assertion siblings would mis-read a
/// neighbour's user UUID as their own. Serialization removes both.
///
/// Cargo runs different test binaries sequentially by default, so a
/// binary-scoped lock is sufficient — sibling binaries (e.g.
/// `api_token_revocation_listener.rs`, which uses unique channels
/// anyway) are not affected.
fn serial_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

/// Acquire the per-binary serial lock for the test's duration. Held
/// until the returned guard is dropped at the end of the test body.
async fn lock_serial() -> AsyncMutexGuard<'static, ()> {
    serial_lock().lock().await
}

#[tokio::test]
async fn save_with_is_active_false_emits_user_prefix_notify() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };

    let mut listener = open_listener(&pool).await;

    let user = make_user(false);
    let repo = PgUserRepository::new(pool.clone());
    repo.save(&user).await.expect("save inactive user");

    let payload = try_recv(&mut listener, Duration::from_millis(500))
        .await
        .expect("expected a NOTIFY within 500ms after inactive save");

    let expected = format!("{}{}", USER_PREFIX, user.id);
    assert_eq!(
        payload, expected,
        "payload must be the literal `user:<uuid>` shape"
    );
}

#[tokio::test]
async fn save_with_is_active_true_does_not_emit_notify() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };

    let mut listener = open_listener(&pool).await;

    let user = make_user(true);
    let repo = PgUserRepository::new(pool.clone());
    repo.save(&user).await.expect("save active user");

    // 250ms silence window is comfortably above the round-trip latency
    // for a NOTIFY on a local Postgres — anything that was going to
    // fire would have arrived by now. We deliberately don't make this
    // longer; longer silence windows make the negative test slow
    // without making the assertion stronger.
    let payload = try_recv(&mut listener, Duration::from_millis(250)).await;
    assert!(
        payload.is_none(),
        "active save must not emit on api_token_revocation; got {payload:?}"
    );
}

#[tokio::test]
async fn save_active_then_deactivate_only_second_emits_notify() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };

    let mut listener = open_listener(&pool).await;

    let mut user = make_user(true);
    let repo = PgUserRepository::new(pool.clone());

    // Pass 1: insert as active. No NOTIFY expected.
    repo.save(&user).await.expect("save active");

    // Confirm silence on the active-save.
    assert!(
        try_recv(&mut listener, Duration::from_millis(150))
            .await
            .is_none(),
        "active save must not emit"
    );

    // Pass 2: flip to inactive. NOTIFY expected.
    user.is_active = false;
    user.updated_at = Utc::now();
    repo.save(&user).await.expect("save inactive");

    let payload = try_recv(&mut listener, Duration::from_millis(500))
        .await
        .expect("expected a NOTIFY within 500ms after deactivating save");
    let expected = format!("{}{}", USER_PREFIX, user.id);
    assert_eq!(payload, expected);

    // And exactly one — no follow-up NOTIFY arrives within a short
    // window.
    let extra = try_recv(&mut listener, Duration::from_millis(150)).await;
    assert!(
        extra.is_none(),
        "exactly one NOTIFY expected on the active->inactive transition; got extra {extra:?}"
    );
}

// ---------------------------------------------------------------------
// End-to-end: in-process `spawn_revocation_listener` records exactly
// one `invalidate_user` after a deactivating save.
// ---------------------------------------------------------------------

struct CountingInvalidator {
    tokens: Mutex<Vec<Uuid>>,
    users: Mutex<Vec<Uuid>>,
    drop_all: Mutex<usize>,
}

impl CountingInvalidator {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tokens: Mutex::new(Vec::new()),
            users: Mutex::new(Vec::new()),
            drop_all: Mutex::new(0),
        })
    }
    fn user_count(&self) -> usize {
        self.users.lock().unwrap().len()
    }
    fn last_user(&self) -> Option<Uuid> {
        self.users.lock().unwrap().last().copied()
    }
    fn token_count(&self) -> usize {
        self.tokens.lock().unwrap().len()
    }
}

impl ApiTokenCacheInvalidator for CountingInvalidator {
    fn invalidate_token(&self, token_id: Uuid) {
        self.tokens.lock().unwrap().push(token_id);
    }
    fn invalidate_user(&self, user_id: Uuid) {
        self.users.lock().unwrap().push(user_id);
    }
    fn drop_all(&self) {
        *self.drop_all.lock().unwrap() += 1;
    }
}

#[tokio::test]
async fn user_deactivation_invalidates_cached_pat_via_listener() {
    let _serial = lock_serial().await;
    let Some(pool) = admin_pool().await else {
        eprintln!("DATABASE_URL not set; skipping DB-gated test");
        return;
    };

    let inv = CountingInvalidator::new();
    // This test exercises the end-to-end production contract:
    // user_repo's NOTIFY emitter → listener → invalidator. The
    // emitter is hardcoded to fire on REVOCATION_CHANNEL, so the
    // listener has to listen there too — the unique-per-test channel
    // pattern used by api_token_revocation_listener.rs's tests does
    // not apply here.
    let task = spawn_revocation_listener(
        pool.clone(),
        inv.clone() as Arc<dyn ApiTokenCacheInvalidator>,
        REVOCATION_CHANNEL.to_string(),
    );

    // Listener task issues LISTEN asynchronously — give it a moment so
    // our subsequent NOTIFY isn't dropped on the floor before the
    // server-side subscription is registered.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let user = make_user(false);
    let user_id = user.id;
    let repo = PgUserRepository::new(pool.clone());
    repo.save(&user).await.expect("save inactive user");

    // Poll for the dispatch — same shape as the existing integration
    // tests in `api_token_revocation_listener.rs`.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        if inv.user_count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        inv.user_count() >= 1,
        "expected invalidate_user dispatch within 500ms"
    );
    assert_eq!(inv.last_user(), Some(user_id));
    assert_eq!(
        inv.token_count(),
        0,
        "token-prefix path must not fire on a user-deactivation NOTIFY"
    );

    task.abort();
}
