//! Outbound port for subscription-row change notifications.
//!
//! See the subscription-cache section of
//! `docs/architecture/explanation/event-notifications.md`.
//! The dispatcher refreshes its
//! per-subscription task set every 30s via `list_active`; the change
//! listener accelerates that refresh by carrying create/update/delete
//! /pause/resume notifications from Postgres `NOTIFY` in near-real-time.
//!
//! # Backend-agnostic shape
//!
//! The Postgres adapter
//! (`crates/hort-adapters-postgres/src/subscription_change_listener.rs`) implements
//! this trait via `LISTEN subscription_changes`. A backend-agnostic
//! implementation (e.g. an EventStoreDB-driven change feed, or a no-op
//! adapter for deployments that disable notifications) plugs in here
//! without changing the dispatcher.
//!
//! The trait is intentionally minimal — the dispatcher consumes `recv()`
//! calls in a loop and tracks its own backoff / cancellation. Adapters
//! own their reconnect lifecycle internally.

use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// Notification of a subscription row change, carried over the
/// `subscription_changes` Postgres channel (or equivalent on other
/// backends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionChangeEvent {
    /// `Some(id)` carries the subscription that changed (the dispatcher
    /// reloads just that id from the repository). `None` is a "drop and
    /// reload everything" signal — emitted on listener reconnect when
    /// the missed-window cannot be reconstructed.
    pub subscription_id: Option<Uuid>,
}

/// Port for receiving subscription-row change notifications.
///
/// Implementation lives in `crates/hort-adapters-postgres/src/subscription_change_listener.rs`.
/// The dispatcher consumes `recv()` calls in a loop. Returning `Err` is
/// the signal to refresh from `SubscriptionRepository::list_active`
/// rather than reconnect — the adapter's own reconnect loop handles
/// transport recovery.
pub trait SubscriptionChangeListener: Send + Sync {
    /// Block until the next change event (or listener error).
    fn recv(&self) -> BoxFuture<'_, DomainResult<SubscriptionChangeEvent>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time + runtime assertion that
    /// [`SubscriptionChangeListener`] is dyn-compatible. The dispatcher
    /// wires it behind `Arc<dyn SubscriptionChangeListener>` in the
    /// composition root; a non-dyn-compatible signature would break that
    /// wiring at compile time.
    #[test]
    fn _assert_dyn_compat() {
        let _ = size_of::<&dyn SubscriptionChangeListener>();
    }

    #[test]
    fn subscription_change_event_clone_round_trip() {
        let e = SubscriptionChangeEvent {
            subscription_id: Some(Uuid::new_v4()),
        };
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn subscription_change_event_none_means_reload_all() {
        let e = SubscriptionChangeEvent {
            subscription_id: None,
        };
        assert_eq!(e.subscription_id, None);
    }

    #[test]
    fn subscription_change_event_eq_distinguishes_ids() {
        let a = SubscriptionChangeEvent {
            subscription_id: Some(Uuid::new_v4()),
        };
        let b = SubscriptionChangeEvent {
            subscription_id: Some(Uuid::new_v4()),
        };
        assert_ne!(a, b);
    }
}
