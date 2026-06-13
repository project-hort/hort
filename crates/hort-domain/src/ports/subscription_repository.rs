//! Outbound port for subscription persistence.
//!
//! See `docs/architecture/explanation/event-notifications.md`.
//!
//! # Adapter-side discipline (not enforced here)
//!
//! - `target` and `filter` JSONB columns deserialise via adapter-side
//!   DTOs (`crates/hort-adapters-postgres/src/subscription_repo.rs`) — the
//!   domain types do NOT derive `Deserialize`. Forging a [`Subscription`]
//!   with an arbitrary `secret_hash` from external input is the threat
//!   model; the wire boundary is the only place wire-shaped JSON is parsed.
//! - `update_last_delivered` is called by the dispatcher on a debounced
//!   schedule (5-minute floor, same pattern as the API-token
//!   `last_used_at` debounce).
//!   Implementations MUST NOT block the dispatcher on a slow write — the
//!   notifier is best-effort and the dispatcher is single-task per
//!   subscription (a load-bearing invariant).
//! - `list_active` is the dispatcher's cache-refresh hot path. Bound it
//!   to `state = 'active'` rows server-side; the index
//!   `idx_subscriptions_active` covers this access.

use uuid::Uuid;

use crate::entities::subscription::{Subscription, SubscriptionFailure, SubscriptionId};
use crate::error::DomainResult;
use crate::types::{Page, PageRequest};

use super::BoxFuture;

/// Outbound port for [`Subscription`] persistence + dispatcher updates.
pub trait SubscriptionRepository: Send + Sync {
    /// Insert a new subscription row.
    ///
    /// Returns `Err(DomainError::Conflict)` on
    /// `(owner_user_id, name)` unique-constraint violation. The use case
    /// maps that to [`crate::entities::subscription::SubscriptionDenialReason::DuplicateName`].
    fn create(&self, subscription: &Subscription) -> BoxFuture<'_, DomainResult<()>>;

    /// Look up by id.
    ///
    /// Returns `Err(DomainError::NotFound)` when the id is unknown.
    fn find_by_id(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<Subscription>>;

    /// Look up by `(owner_user_id, name)`. `Ok(None)` on miss; CRUD
    /// callers use this to detect name collisions before issuing a
    /// create.
    fn find_by_name(
        &self,
        owner: Uuid,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Subscription>>>;

    /// Paginated list of subscriptions owned by `owner` (descending by
    /// `created_at`).
    fn list_for_owner(
        &self,
        owner: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Subscription>>>;

    /// Every active subscription. Dispatcher cache-refresh hot path —
    /// bounded by the `idx_subscriptions_active` partial index.
    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<Subscription>>>;

    /// Update an existing row.
    ///
    /// The adapter persists every field on `subscription` verbatim;
    /// use-case-level invariants (state-transition gates, scope
    /// not-widening, etc.) are checked **before** calling here.
    fn update(&self, subscription: &Subscription) -> BoxFuture<'_, DomainResult<()>>;

    /// Hard-delete by id. Idempotent: returns `Ok(())` even when the row
    /// is already gone (delete-then-delete is a no-op).
    fn delete(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<()>>;

    /// Update only the debounced dispatcher columns
    /// (`last_delivered_position`, `last_failure`).
    ///
    /// Separate from [`Self::update`] so the dispatcher does not need
    /// the full `Subscription` row in scope and so the write touches only
    /// two columns. `last_failure = None` clears the row's failure marker
    /// (first success after a failure run).
    fn update_last_delivered(
        &self,
        id: SubscriptionId,
        position: u64,
        last_failure: Option<&SubscriptionFailure>,
    ) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time + runtime assertion that [`SubscriptionRepository`] is
    /// dyn-compatible — the composition root wires the adapter behind
    /// `Arc<dyn SubscriptionRepository>` in `AppContext`.
    #[test]
    fn _assert_dyn_compat() {
        let _ = size_of::<&dyn SubscriptionRepository>();
    }
}
