//! PostgreSQL `LISTEN`er for the `api_token_revocation` channel.
//!
//! This module wires the LISTEN side of the multi-replica cache-
//! invalidation contract (ADR 0012 §5 "Multi-replica revocation
//! invalidation"). The NOTIFY side lives on
//! `api_token_repo::PgApiTokenRepository::revoke` — it emits
//! `NOTIFY api_token_revocation, '<uuid>'` inside the same transaction
//! as the `revoked_at` column flip. The listener task spawned by
//! [`spawn_revocation_listener`] receives that payload on every replica
//! and dispatches it to the supplied [`ApiTokenCacheInvalidator`].
//!
//! # Wire format
//!
//! | Payload shape                      | Dispatch                               |
//! |------------------------------------|----------------------------------------|
//! | `<uuid>` (e.g. `01992c…`)          | `invalidate_token(token_id)`           |
//! | `user:<uuid>` (e.g. `user:01992c…`)| `invalidate_user(user_id)` (de-active) |
//! | anything else                      | `tracing::warn!` and ignore             |
//!
//! Distinguishing the two payload shapes by prefix lets the same
//! channel carry both per-token revocations and the future per-user
//! deactivation broadcast (a User entity
//! deactivation flips `is_active = false` AND fires `NOTIFY
//! api_token_revocation, 'user:<uuid>'` so every replica drops the
//! cache for THAT user's tokens). Per-user is documented here so the
//! listener's prefix-routing is forward-compatible.
//!
//! # Reconnection + backoff
//!
//! `PgListener::recv()` returns an error when the underlying
//! connection drops (network blip, server restart, statement_timeout
//! kill, etc.). On any such error the task:
//!
//! 1. Logs at `error!` carrying the failure cause.
//! 2. Calls [`ApiTokenCacheInvalidator::drop_all`] — we cannot prove
//!    the cache is consistent with the database after a missed
//!    notification window, so the safe outcome is a full flush. The
//!    rewarm cost is bounded by the cache TTL (5 min default).
//! 3. Sleeps with exponential backoff (1s → 2s → 4s … capped at 30s)
//!    before reconnecting.
//! 4. Re-issues `LISTEN api_token_revocation` on the new connection
//!    and resumes the receive loop. Successful reconnect resets the
//!    backoff to the floor.
//!
//! The task **never panics** — every error path is converted to a
//! `tracing::error!` plus a backoff-sleep. Composition is responsible
//! for holding the [`tokio::task::JoinHandle`] and aborting it on
//! shutdown.

use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use uuid::Uuid;

use hort_domain::ports::api_token_cache_invalidator::ApiTokenCacheInvalidator;

/// Postgres NOTIFY channel name. Matches the literal in
/// `PgApiTokenRepository::revoke` so a typo on either side breaks the
/// integration test deterministically (the `LISTEN/NOTIFY` channel is
/// scoped to the database and a name mismatch silently drops every
/// notification).
pub const REVOCATION_CHANNEL: &str = "api_token_revocation";

/// Initial reconnect-backoff delay. Doubles on every consecutive
/// failure up to [`RECONNECT_BACKOFF_CAP`].
const RECONNECT_BACKOFF_FLOOR: Duration = Duration::from_secs(1);

/// Maximum reconnect-backoff delay. The cap ensures a wedged
/// connection doesn't blow out to e.g. 30 minutes of dead time on a
/// long outage; we'd rather thrash at 30s and have the reconnect
/// metric carry the signal.
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// User-prefix discriminator for the `user:<uuid>` payload shape. Kept
/// as a `pub const` so the future user-deactivation NOTIFY emitter
/// can re-import the same
/// constant rather than duplicating the literal.
pub const USER_PREFIX: &str = "user:";

/// Spawn a `tokio` task that listens on `channel` forever, dispatching
/// every notification to `invalidator`. Returns the [`JoinHandle`] so
/// composition can abort the task on shutdown.
///
/// Production callers pass [`REVOCATION_CHANNEL`] — the contract pinned
/// against the revoke emitter and the user-deactivation NOTIFY in
/// `user_repo::PgUserRepository::save`. The channel is a parameter
/// rather than a hardcoded constant so DB-gated integration tests can
/// isolate each test's listener on a unique per-test channel — without
/// it, parallel `cargo test` runs cross-talk via the broadcast
/// semantics of `LISTEN/NOTIFY` (every listener on a channel sees
/// every notify, including those fired by sibling tests).
///
/// The task **never panics** — every error path falls through to the
/// reconnect loop with exponential backoff. See module docs for the
/// full lifecycle.
pub fn spawn_revocation_listener(
    pool: PgPool,
    invalidator: Arc<dyn ApiTokenCacheInvalidator>,
    channel: String,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_listener_loop(pool, invalidator, channel).await;
    })
}

/// Outer reconnect loop. Pulled out of the spawn so unit tests can
/// drive the dispatch path through [`dispatch_payload`] without
/// standing up a full PgListener.
async fn run_listener_loop(
    pool: PgPool,
    invalidator: Arc<dyn ApiTokenCacheInvalidator>,
    channel: String,
) {
    let mut backoff = RECONNECT_BACKOFF_FLOOR;
    loop {
        match connect_and_listen(&pool, &channel).await {
            Ok(listener) => {
                tracing::info!(
                    channel = %channel,
                    "api_token_revocation listener connected"
                );
                // Each successful (re)connect resets the backoff so a
                // long-running healthy connection doesn't carry stale
                // multi-second delays into the next outage.
                backoff = RECONNECT_BACKOFF_FLOOR;
                run_recv_loop(listener, invalidator.as_ref(), &channel).await;
                // `run_recv_loop` returned → connection dropped. Drop
                // the cache: we cannot prove consistency across the
                // missed window. Flush, back off, retry.
                tracing::error!(
                    channel = %channel,
                    "api_token_revocation listener connection lost; dropping cache and reconnecting"
                );
                invalidator.drop_all();
            }
            Err(e) => {
                tracing::error!(
                    channel = %channel,
                    error = %e,
                    "failed to (re)connect api_token_revocation listener; dropping cache and backing off"
                );
                invalidator.drop_all();
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = next_backoff(backoff);
    }
}

/// Open a new `PgListener` and issue `LISTEN <channel>`.
async fn connect_and_listen(pool: &PgPool, channel: &str) -> Result<PgListener, sqlx::Error> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(channel).await?;
    Ok(listener)
}

/// Inner receive loop — runs until `PgListener::recv()` errors. Each
/// successful `recv()` is dispatched to [`dispatch_payload`].
async fn run_recv_loop(
    mut listener: PgListener,
    invalidator: &dyn ApiTokenCacheInvalidator,
    channel: &str,
) {
    loop {
        match listener.recv().await {
            Ok(notification) => {
                let payload = notification.payload();
                dispatch_payload(payload, invalidator);
            }
            Err(e) => {
                tracing::error!(
                    channel = %channel,
                    error = %e,
                    "api_token_revocation recv() failed"
                );
                return;
            }
        }
    }
}

/// Dispatch a NOTIFY payload to the matching invalidator method.
///
/// Pure routing — no I/O — so unit tests exercise the prefix-routing
/// + UUID-parsing leaf logic without standing up a PgListener.
pub(crate) fn dispatch_payload(payload: &str, invalidator: &dyn ApiTokenCacheInvalidator) {
    if let Some(rest) = payload.strip_prefix(USER_PREFIX) {
        match Uuid::parse_str(rest.trim()) {
            Ok(user_id) => invalidator.invalidate_user(user_id),
            Err(e) => tracing::warn!(
                payload = %payload,
                error = %e,
                "api_token_revocation user payload not a uuid; ignoring"
            ),
        }
        return;
    }
    match Uuid::parse_str(payload.trim()) {
        Ok(token_id) => invalidator.invalidate_token(token_id),
        Err(e) => tracing::warn!(
            payload = %payload,
            error = %e,
            "api_token_revocation payload not a uuid; ignoring"
        ),
    }
}

/// Compute the next reconnect-backoff value, doubling and clamped at
/// [`RECONNECT_BACKOFF_CAP`]. Pure so the cap branch is unit-testable
/// without relying on wall-clock multiplication semantics.
fn next_backoff(current: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > RECONNECT_BACKOFF_CAP {
        RECONNECT_BACKOFF_CAP
    } else {
        doubled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-test invalidator that counts dispatches per method. The
    /// dispatch tests assert on the counts — no need for the full
    /// `PatCache` shape.
    struct CountingInvalidator {
        token_calls: Mutex<Vec<Uuid>>,
        user_calls: Mutex<Vec<Uuid>>,
        drop_all_calls: Mutex<usize>,
    }

    impl CountingInvalidator {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                token_calls: Mutex::new(Vec::new()),
                user_calls: Mutex::new(Vec::new()),
                drop_all_calls: Mutex::new(0),
            })
        }
    }

    impl ApiTokenCacheInvalidator for CountingInvalidator {
        fn invalidate_token(&self, token_id: Uuid) {
            self.token_calls.lock().unwrap().push(token_id);
        }
        fn invalidate_user(&self, user_id: Uuid) {
            self.user_calls.lock().unwrap().push(user_id);
        }
        fn drop_all(&self) {
            *self.drop_all_calls.lock().unwrap() += 1;
        }
    }

    #[test]
    fn dispatch_payload_uuid_invokes_invalidate_token() {
        let inv = CountingInvalidator::new();
        let token_id = Uuid::new_v4();
        dispatch_payload(&token_id.to_string(), inv.as_ref());
        let tokens = inv.token_calls.lock().unwrap();
        assert_eq!(*tokens, vec![token_id]);
        assert!(inv.user_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn dispatch_payload_user_prefix_invokes_invalidate_user() {
        let inv = CountingInvalidator::new();
        let user_id = Uuid::new_v4();
        dispatch_payload(&format!("user:{user_id}"), inv.as_ref());
        let users = inv.user_calls.lock().unwrap();
        assert_eq!(*users, vec![user_id]);
        assert!(inv.token_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn dispatch_payload_user_prefix_with_whitespace_is_trimmed() {
        // Some PG notification clients pad the payload — we trim
        // before parsing so the dispatch is robust.
        let inv = CountingInvalidator::new();
        let user_id = Uuid::new_v4();
        dispatch_payload(&format!("user:  {user_id}\n"), inv.as_ref());
        let users = inv.user_calls.lock().unwrap();
        assert_eq!(*users, vec![user_id]);
    }

    #[test]
    fn dispatch_payload_garbage_payload_is_logged_and_ignored() {
        let inv = CountingInvalidator::new();
        dispatch_payload("not-a-uuid", inv.as_ref());
        dispatch_payload("user:not-a-uuid", inv.as_ref());
        // No dispatch on either; the warn! emits but we don't assert
        // on log content here (the `tracing-test` machinery is heavy
        // for this leaf).
        assert!(inv.token_calls.lock().unwrap().is_empty());
        assert!(inv.user_calls.lock().unwrap().is_empty());
        assert_eq!(*inv.drop_all_calls.lock().unwrap(), 0);
    }

    #[test]
    fn next_backoff_doubles_until_cap() {
        assert_eq!(next_backoff(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(next_backoff(Duration::from_secs(2)), Duration::from_secs(4));
        assert_eq!(
            next_backoff(Duration::from_secs(16)),
            Duration::from_secs(30),
            "32s doubled would exceed cap; clamps"
        );
        // Cap is idempotent — already at cap, stays at cap.
        assert_eq!(next_backoff(RECONNECT_BACKOFF_CAP), RECONNECT_BACKOFF_CAP);
    }

    #[test]
    fn user_prefix_constant_matches_dispatch_assumption() {
        // Pinning the literal so a future emitter can re-import
        // `USER_PREFIX` without divergence.
        assert_eq!(USER_PREFIX, "user:");
    }

    #[test]
    fn revocation_channel_constant_matches_b4_emitter() {
        // Pinned literal — matches `PgApiTokenRepository::revoke`'s
        // `format!("NOTIFY api_token_revocation, …")` call site.
        assert_eq!(REVOCATION_CHANNEL, "api_token_revocation");
    }
}
