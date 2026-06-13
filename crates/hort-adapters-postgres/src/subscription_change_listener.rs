//! PostgreSQL `LISTEN`er for the `subscription_changes` channel.
//!
//! Implements [`hort_domain::ports::subscription_change_listener::SubscriptionChangeListener`].
//! The NOTIFY side lives on `subscription_repo::PgSubscriptionRepository::{create,
//! update, delete}` — each emits `NOTIFY subscription_changes, '<uuid>'`
//! inside the same transaction as the row write. The listener task spawned by
//! [`spawn_subscription_change_listener`] feeds an in-process mpsc channel; the
//! dispatcher (`hort_app::dispatcher::NotificationDispatcher`) consumes that
//! channel via `SubscriptionChangeListener::recv()`.
//!
//! # Wire format
//!
//! | Payload shape | Dispatch |
//! |---|---|
//! | `<uuid>` | `SubscriptionChangeEvent { subscription_id: Some(uuid) }` |
//! | empty / unparseable | `SubscriptionChangeEvent { subscription_id: None }` (reload-all signal) |
//!
//! On disconnect, the spawner emits a `None` event first so the
//! dispatcher's next reconcile sweeps the full active set rather than
//! relying on the missed-window NOTIFY payloads.
//!
//! # Template provenance
//!
//! Mirrors `api_token_revocation_listener.rs` line-by-line (channel
//! name + payload dispatch substituted). The reconnect/backoff
//! constants live alongside it; this module duplicates rather than
//! re-uses them to keep the API-token listener's `RECONNECT_BACKOFF_*`
//! constants private — cross-module `pub` exposure is intentionally
//! avoided. The shared values document parity in a comment.

use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::subscription_change_listener::{
    SubscriptionChangeEvent, SubscriptionChangeListener,
};
use hort_domain::ports::BoxFuture;

/// Postgres NOTIFY channel name. Matches the literal in
/// `PgSubscriptionRepository::{create, update, delete}` so a typo on
/// either side breaks the integration test deterministically.
pub const SUBSCRIPTION_CHANGES_CHANNEL: &str = "subscription_changes";

/// Initial reconnect-backoff delay. Doubles on every consecutive
/// failure up to [`RECONNECT_BACKOFF_CAP`]. Same values as the
/// API-token listener — cross-referenced here rather than imported to
/// avoid a `pub`-ification of the sibling crate's internal constants.
const RECONNECT_BACKOFF_FLOOR: Duration = Duration::from_secs(1);
/// Maximum reconnect-backoff delay.
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// In-process channel buffer size — bounded so a wedged dispatcher
/// can't accumulate unbounded change notifications. 64 is generous
/// for the expected create/update/delete rate.
const CHANNEL_BUFFER: usize = 64;

/// Postgres-backed implementation of [`SubscriptionChangeListener`].
///
/// Holds an mpsc receiver behind a tokio mutex. The spawned task feeds
/// it from `PgListener::recv()` and on disconnect emits a `None`
/// reload-all event before backing off.
pub struct PgSubscriptionChangeListener {
    rx: Mutex<mpsc::Receiver<SubscriptionChangeEvent>>,
}

impl PgSubscriptionChangeListener {
    fn new(rx: mpsc::Receiver<SubscriptionChangeEvent>) -> Self {
        Self { rx: Mutex::new(rx) }
    }
}

impl SubscriptionChangeListener for PgSubscriptionChangeListener {
    fn recv(&self) -> BoxFuture<'_, DomainResult<SubscriptionChangeEvent>> {
        Box::pin(async move {
            let mut rx = self.rx.lock().await;
            rx.recv().await.ok_or_else(|| {
                DomainError::Invariant("subscription_changes listener shutdown".to_string())
            })
        })
    }
}

/// Spawn a `tokio` task that listens on `channel` forever, feeding the
/// shared listener handle. Returns the listener handle for the
/// dispatcher and the [`JoinHandle`] for composition to abort on
/// shutdown.
pub fn spawn_subscription_change_listener(
    pool: PgPool,
    channel: String,
) -> (Arc<PgSubscriptionChangeListener>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(CHANNEL_BUFFER);
    let listener = Arc::new(PgSubscriptionChangeListener::new(rx));
    let handle = tokio::spawn(async move {
        run_listener_loop(pool, tx, channel).await;
    });
    (listener, handle)
}

/// Outer reconnect loop. Pulled out of the spawn so unit tests can
/// drive the dispatch path through [`dispatch_payload`] without
/// standing up a full PgListener.
async fn run_listener_loop(
    pool: PgPool,
    tx: mpsc::Sender<SubscriptionChangeEvent>,
    channel: String,
) {
    let mut backoff = RECONNECT_BACKOFF_FLOOR;
    loop {
        match connect_and_listen(&pool, &channel).await {
            Ok(listener) => {
                tracing::info!(
                    channel = %channel,
                    "subscription_changes listener connected"
                );
                backoff = RECONNECT_BACKOFF_FLOOR;
                run_recv_loop(listener, &tx, &channel).await;
                // `run_recv_loop` returned → connection dropped. Emit
                // a reload-all event so the dispatcher's next
                // reconcile sweeps the full active set; we cannot
                // prove consistency across the missed window.
                let _ = tx
                    .send(SubscriptionChangeEvent {
                        subscription_id: None,
                    })
                    .await;
                tracing::error!(
                    channel = %channel,
                    "subscription_changes listener connection lost; reconnecting"
                );
            }
            Err(e) => {
                tracing::error!(
                    channel = %channel,
                    error = %e,
                    "failed to (re)connect subscription_changes listener"
                );
                let _ = tx
                    .send(SubscriptionChangeEvent {
                        subscription_id: None,
                    })
                    .await;
            }
        }
        // If the receiver is gone the dispatcher has shut down — exit.
        if tx.is_closed() {
            return;
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
    tx: &mpsc::Sender<SubscriptionChangeEvent>,
    channel: &str,
) {
    loop {
        match listener.recv().await {
            Ok(notification) => {
                let event = dispatch_payload(notification.payload());
                if tx.send(event).await.is_err() {
                    // Receiver dropped — dispatcher shut down. Exit
                    // the recv loop; the outer loop's `tx.is_closed`
                    // check will exit cleanly.
                    return;
                }
            }
            Err(e) => {
                tracing::error!(
                    channel = %channel,
                    error = %e,
                    "subscription_changes recv() failed"
                );
                return;
            }
        }
    }
}

/// Map a NOTIFY payload string to a [`SubscriptionChangeEvent`].
///
/// Pure routing — no I/O — so unit tests exercise the UUID-parsing
/// leaf logic without standing up a PgListener.
///
/// - `<uuid>` → `subscription_id = Some(uuid)`
/// - Anything else (empty, garbage, leading/trailing whitespace
///   permitted) → `subscription_id = None` (reload-all signal). The
///   dispatcher's reconcile pass reloads from `list_active` and the
///   row state is reconciled.
pub(crate) fn dispatch_payload(payload: &str) -> SubscriptionChangeEvent {
    let trimmed = payload.trim();
    match Uuid::parse_str(trimmed) {
        Ok(id) => SubscriptionChangeEvent {
            subscription_id: Some(id),
        },
        Err(e) => {
            tracing::warn!(
                payload = %payload,
                error = %e,
                "subscription_changes payload not a uuid; emitting reload-all"
            );
            SubscriptionChangeEvent {
                subscription_id: None,
            }
        }
    }
}

/// Compute the next reconnect-backoff value, doubling and clamped at
/// [`RECONNECT_BACKOFF_CAP`].
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

    #[test]
    fn dispatch_payload_uuid_emits_some_id() {
        let id = Uuid::new_v4();
        let e = dispatch_payload(&id.to_string());
        assert_eq!(e.subscription_id, Some(id));
    }

    #[test]
    fn dispatch_payload_uuid_with_whitespace_is_trimmed() {
        let id = Uuid::new_v4();
        let e = dispatch_payload(&format!("  {id}\n"));
        assert_eq!(e.subscription_id, Some(id));
    }

    #[test]
    fn dispatch_payload_garbage_emits_none() {
        let e = dispatch_payload("not-a-uuid");
        assert_eq!(e.subscription_id, None);
    }

    #[test]
    fn dispatch_payload_empty_emits_none() {
        let e = dispatch_payload("");
        assert_eq!(e.subscription_id, None);
    }

    #[test]
    fn dispatch_payload_only_whitespace_emits_none() {
        let e = dispatch_payload("   ");
        assert_eq!(e.subscription_id, None);
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
        assert_eq!(next_backoff(RECONNECT_BACKOFF_CAP), RECONNECT_BACKOFF_CAP);
    }

    #[test]
    fn subscription_changes_channel_constant_matches_repo_emitters() {
        // Pinned literal — matches `PgSubscriptionRepository::{create, update,
        // delete}` `NOTIFY subscription_changes, …` call sites.
        assert_eq!(SUBSCRIPTION_CHANGES_CHANNEL, "subscription_changes");
    }

    #[tokio::test]
    async fn listener_recv_yields_pushed_event() {
        let (tx, rx) = mpsc::channel(8);
        let listener = PgSubscriptionChangeListener::new(rx);
        let id = Uuid::new_v4();
        tx.send(SubscriptionChangeEvent {
            subscription_id: Some(id),
        })
        .await
        .unwrap();
        let e = listener.recv().await.unwrap();
        assert_eq!(e.subscription_id, Some(id));
    }

    #[tokio::test]
    async fn listener_recv_errors_when_sender_dropped() {
        let (tx, rx) = mpsc::channel(8);
        let listener = PgSubscriptionChangeListener::new(rx);
        drop(tx);
        let r = listener.recv().await;
        assert!(matches!(r, Err(DomainError::Invariant(_))));
    }

    #[test]
    fn _assert_pg_listener_impls_port() {
        // Compile-time: `Arc<PgSubscriptionChangeListener>` must coerce to
        // `Arc<dyn SubscriptionChangeListener>` so composition wires it
        // through `hort-app::dispatcher::NotificationDispatcher::new`.
        let (_tx, rx) = mpsc::channel(1);
        let pg = Arc::new(PgSubscriptionChangeListener::new(rx));
        let _: Arc<dyn SubscriptionChangeListener> = pg;
    }
}
