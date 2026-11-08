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
//! - **`last_delivered_position` has exactly one writer, and it only
//!   moves forward.** The writer is `update_last_delivered`, via
//!   [`advance_delivered_position`]; `update` leaves the column alone
//!   even though it is handed a whole [`Subscription`] carrying it
//!   ([`retained_delivered_position`]). The
//!   column is a delivery cursor, not a reported statistic — a read
//!   resumes strictly above it — so a value written backwards is
//!   re-delivery of everything between, and a value written forwards by
//!   mistake would be loss. Both halves are stated on the two methods
//!   below.

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
    /// The adapter persists every field on `subscription` verbatim
    /// **except `last_delivered_position`**, which it must leave
    /// untouched; use-case-level invariants (state-transition gates,
    /// scope not-widening, etc.) are checked **before** calling here.
    ///
    /// The exception is what makes the cursor have one writer. Every
    /// caller of this method reads the row, edits unrelated fields and
    /// writes it back, so the position it carries is whatever the read
    /// saw — and the dispatcher advances that column concurrently, on
    /// its own debounced schedule, from a different task and possibly a
    /// different process. Persisting it here would therefore write a
    /// value this caller never intended, taken from a read it has
    /// already outlived: a lost update whose effect is a rewound
    /// delivery cursor. Leaving the column alone is also what the
    /// callers mean — pausing, resuming, disabling or PATCHing a
    /// subscription all keep its progress — so there is no behaviour to
    /// trade for the guarantee.
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
    ///
    /// `position = None` means "record the failure, leave the position
    /// where it is". The dispatcher needs it because the position it
    /// persists alongside a failure is the position *before* the event
    /// that failed — reads have to resume at the failed event, not past
    /// it — and for a subscription whose first-ever delivery fails there
    /// is no such position. Implementations MUST leave the stored
    /// position untouched rather than writing NULL over it: a `None` here
    /// is the absence of an advance, never a rewind to the start of the
    /// log.
    ///
    /// **The write is monotonic, and a `position` below the stored one is
    /// the absence of an advance for the same reason a `None` is.**
    /// Implementations apply [`advance_delivered_position`] rather than
    /// assigning. The caller cannot enforce it: the position is flushed
    /// from an in-memory cursor held per task, one task per replica with
    /// no leader election, so two writers arrive out of order whenever a
    /// slower replica's flush lands after a faster one's. Taking the
    /// greater of the two is not merely "the newer one loses"; it is the
    /// correct reduction, because each writer's value is a watermark it
    /// has walked contiguously — everything at or below it was delivered
    /// or filtered by that writer — so the greatest of them is still such
    /// a watermark, and resuming from it neither skips an event nor
    /// re-delivers what the furthest writer already handled.
    fn update_last_delivered(
        &self,
        id: SubscriptionId,
        position: Option<u64>,
        last_failure: Option<&SubscriptionFailure>,
    ) -> BoxFuture<'_, DomainResult<()>>;
}

/// The stored delivery position after `incoming` is recorded over
/// `stored` — the one definition of "progress only moves forward".
///
/// `None` is "no position" on either side, and orders below every
/// `Some`, so the whole rule is one comparison: a `None` incoming leaves
/// the stored value alone, a lower incoming value leaves it alone, and a
/// higher one replaces it. That is exactly Postgres `GREATEST` over a
/// nullable column, which ignores NULL arguments and yields NULL only
/// when every argument is NULL — so the SQL adapter can express the rule
/// as one atomic statement with no read-modify-write, and this function
/// is the same rule for every other implementation of
/// [`SubscriptionRepository`].
///
/// It exists as one call rather than as a sentence each implementation
/// re-states, because the rule has two clauses and an implementation
/// that re-states it will state one of them. The `None` clause alone was
/// re-stated, in its own words, in every in-memory double of this port
/// that mirrors the write; adding the ordering clause to a sentence is
/// adding it once per double, and a double carrying half the rule lets a
/// test observe a rewound cursor no production writer can produce.
#[must_use]
pub fn advance_delivered_position(stored: Option<u64>, incoming: Option<u64>) -> Option<u64> {
    stored.max(incoming)
}

/// The delivery position an [`SubscriptionRepository::update`] must
/// persist: the one already stored, never the one its caller is
/// carrying. `stored` is `None` when there is no such row yet.
///
/// The other half of the one-writer rule, and one call for the same
/// reason [`advance_delivered_position`] is. The SQL adapter states it by
/// leaving the column out of its `SET` list, which no other
/// implementation can imitate — a map-backed one is handed the whole
/// [`Subscription`] and has to put the stored value back by hand, and a
/// "put it back" written per implementation is a rewind waiting for the
/// one that forgets.
#[must_use]
pub fn retained_delivered_position(
    stored: Option<&Subscription>,
    carried: Option<u64>,
) -> Option<u64> {
    stored.map_or(carried, |row| row.last_delivered_position)
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

    // -- advance_delivered_position -------------------------------------
    //
    // Every case below is also a case the Postgres statement must answer
    // identically, since `GREATEST` over the nullable column is the same
    // rule in SQL. `subscription_repo::a_late_writer_cannot_rewind_the_
    // delivery_cursor` is the live-database half.

    #[test]
    fn a_higher_incoming_position_advances_the_cursor() {
        assert_eq!(
            advance_delivered_position(Some(5_000), Some(9_000)),
            Some(9_000)
        );
    }

    #[test]
    fn a_lower_incoming_position_leaves_the_cursor_where_it_is() {
        assert_eq!(
            advance_delivered_position(Some(9_000), Some(4_000)),
            Some(9_000)
        );
    }

    #[test]
    fn an_equal_incoming_position_is_not_an_advance() {
        assert_eq!(
            advance_delivered_position(Some(9_000), Some(9_000)),
            Some(9_000)
        );
    }

    /// The failure path's `None`: record the failure, leave the position
    /// alone. Writing NULL here would rewind to the start of the log,
    /// which is the most expensive rewind available.
    #[test]
    fn no_incoming_position_leaves_the_cursor_where_it_is() {
        assert_eq!(advance_delivered_position(Some(9_000), None), Some(9_000));
    }

    /// A subscription that has never delivered takes the first position
    /// it is given — `None` is "no position", not "position zero", and
    /// `global_position` starts at 1 so zero would be unreachable anyway.
    #[test]
    fn a_first_position_lands_on_a_cursor_that_has_none() {
        assert_eq!(advance_delivered_position(None, Some(7)), Some(7));
    }

    /// A first-ever delivery that fails has neither side: nothing to
    /// record and nothing to keep.
    #[test]
    fn neither_side_having_a_position_leaves_the_cursor_unset() {
        assert_eq!(advance_delivered_position(None, None), None);
    }

    // -- retained_delivered_position ------------------------------------

    fn row_at(position: Option<u64>) -> Subscription {
        use crate::entities::subscription::{
            SubscriptionFilter, SubscriptionId, SubscriptionState, SubscriptionTarget,
        };
        use crate::events::StreamCategory;
        Subscription {
            id: SubscriptionId(Uuid::new_v4()),
            owner_user_id: Uuid::new_v4(),
            created_by_token_id: None,
            name: "s".into(),
            description: None,
            target: SubscriptionTarget::NatsJetStream {
                subject: "hort.events".into(),
            },
            filter: SubscriptionFilter {
                categories: vec![StreamCategory::Artifact],
                event_types: crate::entities::subscription::EventTypeFilter::All,
                repositories: crate::entities::subscription::RepositoryScope::OwnedByActor,
                named_predicates: Vec::new(),
            },
            snapshot_claims: Vec::new(),
            state: SubscriptionState::Active,
            last_delivered_position: position,
            last_failure: None,
            created_at: chrono::Utc::now(),
        }
    }

    /// The whole point: the caller's copy is discarded even when it names
    /// a position, because the caller is not a writer of this column.
    #[test]
    fn the_stored_position_wins_over_the_one_the_caller_carries() {
        let stored = row_at(Some(9_000));
        assert_eq!(
            retained_delivered_position(Some(&stored), Some(1_000)),
            Some(9_000)
        );
    }

    /// Including when the stored row has none — "never delivered" is a
    /// value, and a caller carrying a stale position must not invent one.
    #[test]
    fn an_unset_stored_position_stays_unset() {
        let stored = row_at(None);
        assert_eq!(
            retained_delivered_position(Some(&stored), Some(1_000)),
            None
        );
    }

    /// No row yet: there is nothing to retain, so the caller's value is
    /// all there is. Reached only by a double whose map misses; the
    /// adapter's `UPDATE` matches no row and writes nothing.
    #[test]
    fn with_no_stored_row_the_carried_position_is_all_there_is() {
        assert_eq!(retained_delivered_position(None, Some(1_000)), Some(1_000));
    }
}
