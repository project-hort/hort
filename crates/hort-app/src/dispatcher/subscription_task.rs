//! Per-subscription dispatcher task.
//!
//! Each active subscription is owned by one [`tokio::spawn`] task
//! running [`run`]. The task:
//!
//! 1. Performs a startup **catch-up**: one merged
//!    [`EventStore::read_categories`] walk across every category in the
//!    filter at once, starting `AfterGlobal(last_delivered_position)` and
//!    paging forward in 1000-event pages until a page comes back short
//!    (head reached).
//! 2. Enters the **delivery loop**. Every event is delivered by a
//!    catch-up pass; the loop only decides when to run one. A
//!    [`STORE_POLL_INTERVAL`] tick runs one, and so does a hint on the
//!    broadcast receiver whose category the filter subscribes to — the
//!    channel is a wake-up that removes the tick's latency, and its
//!    payload is never the thing delivered. Each event read is filtered
//!    against [`SubscriptionFilter`] and dispatched via the first
//!    [`EventNotifier`] that `supports` the target. Both the filter and
//!    the target come from the **live** row, not from the one the task
//!    was spawned with — see *The row is not fixed for the task's
//!    lifetime* below.
//! 3. [`broadcast::error::RecvError::Lagged`] is a third trigger for the
//!    same pass; overrunning the hint channel costs nothing but the
//!    counter that records it.
//! 4. Tracks a per-task [`FailureBudget`]. 100 consecutive failures in
//!    a 1h window → call `SubscriptionUseCase::disable` and exit.
//! 5. Persists `last_delivered_position` debounced (5-min floor); a
//!    failure flushes immediately.
//! 6. Honours a [`tokio_util::sync::CancellationToken`] for graceful
//!    shutdown.
//!
//! # The event store is the delivery path; the broadcast is a hint
//!
//! The broadcast channel cannot carry every persisted event, for two
//! structural reasons that no amount of extra `send` calls fixes:
//!
//! - **Transactional appends do not broadcast.** Events written inside
//!   a caller-owned transaction — the artifact, ref and artifact-group
//!   lifecycle ports, the artifact delete, the purge sweep — reach the
//!   `events` table through `PgEventStore::append_in_tx`, which sits
//!   below [`crate::event_store_publisher::EventStorePublisher`] and
//!   therefore below the `send`. Broadcasting from inside the
//!   transaction would announce a write that may still roll back;
//!   broadcasting from the adapter after commit would invert the
//!   dependency the publisher exists to express. So the whole artifact
//!   lifecycle — ingest, scan, release, promotion, deletion, purge —
//!   is silent on this channel by construction, bar the two kinds that
//!   reach an artifact stream through the publisher instead
//!   (`ArtifactExpired`, `CasIntegrityMismatch`).
//! - **The channel is per-process.** With more than one server replica,
//!   a replica's sender carries only that replica's own appends.
//!
//! Delivery is therefore driven by reads of the event store, which sees
//! every append from every process once it commits, and the broadcast
//! is kept for what it is good at: saying "something landed" sooner
//! than the next tick would. The hint's **category** is used as the wake
//! predicate — the same thing the pull surface (`GET /api/v1/events`)
//! does with it — so an append to a category nobody here subscribes to
//! does not cost a store read. The hint's **position** is discarded.
//!
//! Delivering the broadcast payload *directly* is the tempting
//! shortcut, and it is wrong for a reason worth stating: the payload
//! carries a `global_position`, so delivering it advances the cursor to
//! that position and the walk resumes above it — skipping every
//! transactional append below, which is exactly the set the channel
//! cannot carry. One cursor, advanced only by reads, is what keeps the
//! walk contiguous.
//!
//! # One ordered stream, one cursor
//!
//! A pass reads the filter's categories as a single
//! `global_position`-ordered stream, not one stream per category. That is
//! what makes the single persisted `last_delivered_position` scalar
//! *true*: every position at or below the mark has been read in every
//! subscribed category, so a restart that resumes from the mark cannot
//! step over anything. Walking the categories one at a time and
//! checkpointing one scalar cannot say that — an advance driven by the
//! first category carries the mark over the second category's unread
//! events below it, and a respawn seeds every category from the moved
//! mark. That is silent, permanent loss, and it is why the merged read
//! exists rather than being an optimisation.
//!
//! # A failed delivery is not checkpointed past
//!
//! When `notify` reports `Failed` / `DownstreamRejected`, the pass
//! **stops at that event**: the cursor is not advanced over it, the
//! position persisted alongside the failure is the position *before* it,
//! and the next pass re-reads it. One transport attempt per pass, retried
//! every [`STORE_POLL_INTERVAL`] until it succeeds or the failure budget
//! runs out — which is what bounds the head-of-line block the retry
//! creates, and what makes "at-least-once" a statement about deliveries
//! rather than about attempts.
//!
//! Residual: an event whose transaction commits *after* a concurrent
//! reader has already advanced this task's cursor past its
//! `global_position` is not re-read. `global_position` comes from a
//! sequence evaluated at INSERT while visibility arrives at COMMIT, so
//! the two orders can disagree. Closing that needs a cursor that is not
//! a bare high-water mark, which is a change to the position model
//! itself and not to this loop.
//!
//! # The row is not fixed for the task's lifetime
//!
//! A task is spawned with one `Subscription`, but it takes only that
//! row's **identity** and its **cursor seed** from it. What shapes
//! delivery — the filter and the target — is read per event from
//! [`SubscriptionTaskDeps::delivery_shape`], a [`DeliveryShape`] the
//! dispatcher's reconcile pass republishes from the row it just listed.
//! A target PATCHed away from a compromised webhook URL, and a filter
//! narrowed to drop a category or an event type, therefore take effect
//! for the next delivered event rather than at the next process
//! restart.
//!
//! The projection is narrow for one specific reason: the task owns its
//! own progress, and a republished `last_delivered_position` is behind
//! the in-memory `ReadCursor` by up to the `PROGRESS_DEBOUNCE` floor.
//! Re-seeding the cursor from a published row would re-deliver that
//! window on every reconcile tick, so the published value carries
//! neither the cursor nor the state column, the failure budget or the
//! debouncer.
//!
//! A filter change applies **from the cursor forward**. Narrowing takes
//! effect for everything the task has not yet walked; widening does not
//! retroactively deliver events the task already walked past under the
//! narrower filter, because those positions are below the mark and no
//! read starts below it. That is inherent to a cursor-driven walk
//! (ADR 0061), not a property of this republish.
//!

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::Utc;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::subscription::{
    DisableReason, Subscription, SubscriptionFailure, SubscriptionFilter, SubscriptionId,
    SubscriptionTarget,
};
use hort_domain::events::PersistedEvent;
use hort_domain::ports::event_notifier::{EventNotifier, NotifyOutcome};
use hort_domain::ports::event_store::{EventStore, SubscribeFrom};
use hort_domain::ports::repository_repository::RepositoryRepository;

use crate::dispatcher::failure_budget::FailureBudget;
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    emit_broadcast_lagged, emit_notify_delivery, emit_subscription_read_error,
    notify_outcome_label, target_kind_label,
};
use crate::rbac::RbacEvaluator;
use crate::use_cases::event_visibility::{EventRepositoryIndex, EventVisibilityUseCase};
use crate::use_cases::subscription_filter::{matches as filter_matches, FilterContext};
use crate::use_cases::subscription_use_case::SubscriptionUseCase;

/// Debounce floor for `update_last_delivered`. The dispatcher amortises
/// writes over a 5-minute window. Failure persists immediately and is
/// not debounced.
pub(crate) const PROGRESS_DEBOUNCE: Duration = Duration::from_secs(5 * 60);

/// Catch-up page size. We loop until `read_category` returns less than
/// `CATCHUP_PAGE`, signalling head reached.
pub(crate) const CATCHUP_PAGE: u64 = 1000;

/// Maximum events to fan in to one `notify` call. v1 dispatches one
/// event per notify call — batching a page's worth into one delivery is
/// a future optimisation.
pub(crate) const NOTIFY_BATCH_SIZE: usize = 1;

/// How long a committed event can wait before the task reads it out of
/// the event store.
///
/// This is the delivery latency on every path the broadcast does not
/// cover — the whole transactional artifact lifecycle, and every append
/// made by another server replica (see the module docs). Sized against
/// the dispatcher's own 30s reconcile: short enough that a supply-chain
/// reaction is not visibly late, long enough that the per-subscription
/// merged read stays negligible at realistic subscription counts.
///
/// What one tick costs is the shape of that read, not the tick rate.
/// `EventStore::read_categories` on Postgres is a `Merge Append` over one
/// keyset index scan per subscribed category, so a caught-up subscription
/// reads 3 shared buffers in ~4 µs regardless of how far the rest of the
/// log has moved on, and a subscription behind by a page reads that page
/// and nothing else. That is a property of the statement shape — see
/// `hort-adapters-postgres::merged_category_read` for the alternatives
/// that are not, one of which reads 160 000 rows to return none.
///
/// A subscription whose events do reach the broadcast is woken
/// immediately and does not wait for a tick; the tick is the floor, not
/// the norm.
pub(crate) const STORE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How far this task has **read** the merged category stream, whether or
/// not the filter matched what it read.
///
/// One mark over one ordered stream. Delivery walks this cursor and
/// nothing else, which is what makes the walk contiguous: every position
/// between the mark and the head is read, so an event the broadcast
/// channel could never carry cannot be stepped over by one it did. A
/// cursor the broadcast also advanced would reintroduce exactly the gap
/// this module exists to close — a live event at position 100 would carry
/// the mark past the transactional appends at 51..99 that no `send` ever
/// announced.
///
/// It is one mark rather than one per category because
/// `last_delivered_position` is one scalar, and the two have to agree.
/// Per-category marks over a single persisted scalar is a loss bug, not a
/// refinement: the scalar is seeded into every category at spawn, so a
/// mark that one category advanced becomes the floor for all of them
/// after a respawn. The merged read is what lets a single mark be exact.
///
/// Distinct from the persisted `last_delivered_position`, which moves
/// only on an actual delivery and lags it by up to
/// [`PROGRESS_DEBOUNCE`]. A subscription that matches nothing in a busy
/// category must still stop re-reading the same pages on every tick,
/// and the persisted position cannot do that job — it never advances for
/// such a subscription. The persisted position is the **seed**: reads
/// resume from it, so a restart re-reads (and may re-deliver) rather
/// than skipping. That asymmetry is deliberate — a duplicate is the
/// receiver's to drop (every delivery carries a fresh
/// `X-Hort-Delivery-Id` and a stable `global_position`), a gap is
/// recoverable by nobody.
#[derive(Debug)]
pub(crate) struct ReadCursor {
    /// `None` ⇒ nothing read and nothing ever delivered, so the walk
    /// starts at the head of the log.
    position: Option<u64>,
}

impl ReadCursor {
    /// Start at the subscription's persisted `last_delivered_position`.
    pub(crate) fn new(seed: Option<u64>) -> Self {
        Self { position: seed }
    }

    /// Where the next merged read should start.
    fn read_from(&self) -> SubscribeFrom {
        match self.position {
            Some(pos) => SubscribeFrom::AfterGlobal(pos),
            None => SubscribeFrom::Start,
        }
    }

    /// The mark itself — the position a restart may safely resume from,
    /// and therefore the position persisted alongside a delivery failure.
    fn mark(&self) -> Option<u64> {
        self.position
    }

    /// Record that `position` has been read. Monotonic: a page that comes
    /// back out of order cannot rewind the mark onto events this task has
    /// already walked.
    fn observe(&mut self, position: u64) {
        if self.position.is_none_or(|current| position > current) {
            self.position = Some(position);
        }
    }
}

/// The mutable part of a subscription row that shapes delivery: what
/// matches, and where it goes.
///
/// This is the value the dispatcher publishes into a running task on
/// every reconcile pass (see [`SubscriptionTaskDeps::delivery_shape`]),
/// and it is deliberately **not** the whole [`Subscription`].
///
/// # Why a projection and not the row
///
/// The task owns its own progress. `last_delivered_position` on a
/// freshly read row is whatever the last debounced write happened to
/// persist, which is up to the `PROGRESS_DEBOUNCE` floor behind the
/// task's own in-memory read cursor. A task that re-seeded its cursor
/// from a republished row would therefore re-deliver the window in
/// between on every reconcile tick, for as long as the debounce held
/// the write back. Publishing only these two fields makes that
/// impossible to write by accident rather than something a reader of
/// the task has to remember: the cursor, the `state` column, the
/// failure budget and the debouncer are not reachable from here.
///
/// `snapshot_claims` is absent for the same reason it is not *needed*:
/// the reconcile pass already folds it into the owner principal it
/// publishes alongside this value
/// ([`SubscriptionTaskDeps::owner_principal`]), so a second copy here
/// would be a second authority input ageing on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryShape {
    /// Where matching events go. Resolved per event, so the first
    /// delivery after a target PATCH already uses the new target.
    ///
    /// Not re-validated here: the create / update path validates a
    /// webhook target — plaintext rule, URL grammar and the SSRF /
    /// DNS guard — before it is persisted, so a row that reached the
    /// database was admitted. Re-checking would put a DNS round trip
    /// on the per-event path.
    pub target: SubscriptionTarget,
    /// What matches. Decides the categories a pass reads, the wake
    /// predicate for a broadcast hint, and the per-event filter walk.
    pub filter: SubscriptionFilter,
}

impl From<&Subscription> for DeliveryShape {
    fn from(row: &Subscription) -> Self {
        Self {
            target: row.target.clone(),
            filter: row.filter.clone(),
        }
    }
}

/// Wires the dependencies one [`run`] invocation needs.
///
/// Constructed once per spawn — the dispatcher (top-level) reads from
/// the repository, builds this struct, and spawns the task.
pub struct SubscriptionTaskDeps {
    /// Catch-up reads use `EventStore::read_category`. The publisher
    /// implements `EventStore` itself, so the dispatcher passes the
    /// same `Arc<EventStorePublisher>` every other use case already
    /// holds — no extra wiring.
    pub event_store: Arc<EventStorePublisher>,
    /// Use case for `disable` (budget exhaust) and
    /// `record_delivery_progress` (debounced position writes).
    pub use_case: Arc<SubscriptionUseCase>,
    /// Live RBAC snapshot — loaded once per processed event so revoking
    /// a grant takes effect within the auth cache TTL.
    pub rbac: Arc<ArcSwap<RbacEvaluator>>,
    /// Forward-compat hook for `NamedPredicate` variants that need
    /// repository metadata. v1 ships zero variants; the field is held
    /// but never consulted by the v1 filter.
    pub repositories: Arc<dyn RepositoryRepository>,
    /// Resolves the repository a catch-up page's events disclose. The
    /// post-ingest artifact lifecycle carries no repository column — the
    /// artifact aggregate does — so without this the filter cannot tell
    /// the owner's own repository's `ArtifactReleased` from another
    /// tenant's. Resolved ONCE per page in [`catch_up`], not per event.
    /// Shared with the `GET /api/v1/events` read gate.
    pub event_visibility: Arc<EventVisibilityUseCase>,
    /// Owner principal — synthesised from the owner's `User` row +
    /// `snapshot_claims` (the stale-`"admin"` strip + live-`is_admin`
    /// re-derivation; see [`crate::dispatcher::dispatcher`]
    /// `synthesise_principal`) and **re-published by the dispatcher on
    /// every reconcile pass**, for a running task as much as for a new
    /// one. The per-event filter walk `load()`s it, so the authority a
    /// delivery is decided under is at most one reconcile interval old.
    ///
    /// Mirroring the `rbac` field above is the substance of this type,
    /// not symmetry: both are inputs to the same `authorize` call in
    /// [`crate::use_cases::subscription_filter::matches`], and two
    /// inputs to one authorization decision have to age at the same
    /// rate. Each is bounded by one refresh cadence — the reconcile
    /// interval for this field, `HORT_RBAC_REFRESH_SECS` for the
    /// evaluator — which is why revoking `User.is_admin` stops a
    /// *running* task from delivering privileged-category events with
    /// no cancel-and-respawn needed.
    ///
    /// A principal that stops resolving at all (owner row gone,
    /// deactivated, or unreadable) is never published as a degraded
    /// value here; the reconcile cancels the task instead, so this
    /// field only ever holds authority the owner currently has.
    pub owner_principal: Arc<ArcSwap<CallerPrincipal>>,
    /// The live row's delivery-shaping fields — **re-published by the
    /// dispatcher on every reconcile pass**, for a running task as much
    /// as for a new one, from the row that pass listed.
    ///
    /// This is the third input to the same per-event decision the two
    /// fields above feed, and it is here for the same reason: an input
    /// to a per-event decision may not be older than the cadence the
    /// rest of that decision runs on. `PATCH
    /// /api/v1/subscriptions/:id` persists a new target and filter and
    /// notifies the dispatcher, so without this the acknowledged row
    /// would be visible through the API while delivery kept following
    /// the one the task was spawned with — a rotation away from a
    /// compromised webhook URL would keep feeding the old receiver, and
    /// a narrowed filter would keep delivering the categories and event
    /// types it removed, until the process restarted.
    ///
    /// See [`DeliveryShape`] for why this is a projection of the row
    /// rather than the row: a republished `last_delivered_position`
    /// would rewind a running task's cursor.
    pub delivery_shape: Arc<ArcSwap<DeliveryShape>>,
    /// First-match notifier registry — the task walks this and uses
    /// the first `supports(target) == true` adapter. Empty registry
    /// drops every event with a warning (degraded state, not a panic).
    pub notifiers: Vec<Arc<dyn EventNotifier>>,
    /// Per-task failure budget; constructed empty at spawn.
    pub budget: Arc<Mutex<FailureBudget>>,
    /// Per-task progress debouncer. Constructed at spawn with
    /// `last_persisted_at = Instant::now()` so the first 5 minutes
    /// after restart aren't a write-storm.
    pub progress: Arc<Mutex<ProgressDebouncer>>,
}

/// Tracks the timestamp of the last persisted
/// `update_last_delivered` call so the task can debounce writes.
///
/// Failures are NOT debounced (audit signal) — the debouncer is
/// consulted only on the success branch.
pub struct ProgressDebouncer {
    pub last_persisted_at: Instant,
    pub interval: Duration,
}

impl ProgressDebouncer {
    /// Construct a debouncer that will persist its first success
    /// `interval` after `now`.
    pub fn new(now: Instant, interval: Duration) -> Self {
        Self {
            last_persisted_at: now,
            interval,
        }
    }

    /// Returns `true` when the interval has elapsed since
    /// `last_persisted_at` (or this is the first call). Updates the
    /// timestamp so subsequent calls within the interval return
    /// `false`.
    pub fn should_persist(&mut self, now: Instant) -> bool {
        if now.duration_since(self.last_persisted_at) >= self.interval {
            self.last_persisted_at = now;
            true
        } else {
            false
        }
    }
}

/// Run a per-subscription task to completion.
///
/// Returns when either (a) the cancellation token fires, or (b) the
/// failure budget exhausts (we call `use_case.disable` then exit; the
/// dispatcher's next reconcile observes the disabled state and does
/// NOT respawn), or (c) the broadcast sender drops (publisher
/// shutdown).
pub async fn run(
    subscription: Subscription,
    deps: SubscriptionTaskDeps,
    mut receiver: broadcast::Receiver<Arc<PersistedEvent>>,
    cancel: CancellationToken,
) {
    // Destructured, not borrowed: what the task takes from the row it
    // was spawned with is its identity and its cursor seed, and nothing
    // else. `target` and `filter` change under a running task — the
    // reconcile pass republishes them into `deps.delivery_shape` and
    // every consumer below reads them from there — so a copy taken here
    // would be the stale value this task must not consult. Moving the
    // row out makes consulting it a compile error rather than a rule to
    // remember.
    let Subscription {
        id: sub_id,
        owner_user_id,
        last_delivered_position,
        ..
    } = subscription;
    tracing::info!(
        subscription_id = %sub_id.0,
        owner_user_id = %owner_user_id,
        "dispatcher task starting"
    );

    let mut cursor = ReadCursor::new(last_delivered_position);

    // Step 1: catch-up.
    if catch_up(sub_id, &deps, &cancel, &mut cursor).await {
        tracing::info!(subscription_id = %sub_id.0, "dispatcher task stopping after catch-up");
        return;
    }

    // Step 2: delivery loop. The tick is what makes delivery independent
    // of which write path and which process persisted the event; the
    // broadcast arm only removes the tick's latency where it can.
    let mut poll = tokio::time::interval(STORE_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval`'s first tick is immediate, and the startup catch-up
    // above just did that work.
    poll.tick().await;

    loop {
        // Every arm below says the same thing — go read the store — and
        // differs only in what prompted it. A relevant hint, an overrun
        // channel and an elapsed tick are one instruction with three
        // triggers; keeping one call site is what stops them drifting.
        let wake = tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(subscription_id = %sub_id.0, "dispatcher task cancelled");
                return;
            }
            _ = poll.tick() => Wake::Read,
            recv = receiver.recv() => match recv {
                Ok(event) => {
                    // The payload is not delivered, and its position is
                    // deliberately unused. Delivering it here would
                    // advance the cursor to that position and carry the
                    // walk past every transactional append below it — the
                    // gap this module exists to close. Its *category*, on
                    // the other hand, is exactly the predicate that says
                    // whether this subscription has anything to read: an
                    // append to a category outside the filter cannot
                    // produce an event this task would deliver, so waking
                    // for it buys a store read and nothing else.
                    //
                    // The predicate reads the **live** filter: a
                    // category a PATCH removed must stop buying store
                    // reads, and one it added must start waking the
                    // task rather than waiting for the next tick.
                    let shape = deps.delivery_shape.load();
                    let hinted = subscribes_to(&shape.filter, &event);
                    // Drained unconditionally, in its own binding: the
                    // queue has to be consumed whatever the first hint
                    // said, so this must never become the right-hand side
                    // of a short-circuiting `||`.
                    let drained = drain_pending_hints(&mut receiver, sub_id, &shape.filter);
                    if hinted || drained { Wake::Read } else { Wake::Skip }
                }
                // A lag is the one case where the categories that were
                // dropped are unknowable, so it always reads.
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    note_lagged(sub_id, skipped);
                    Wake::Read
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!(
                        subscription_id = %sub_id.0,
                        "broadcast sender dropped; task exiting"
                    );
                    return;
                }
            }
        };

        if matches!(wake, Wake::Skip) {
            continue;
        }

        if catch_up(sub_id, &deps, &cancel, &mut cursor).await {
            return;
        }
    }
}

/// What a trip round the delivery loop decided to do.
enum Wake {
    /// Run a catch-up pass.
    Read,
    /// Nothing this subscription could deliver has landed — go back to
    /// waiting without touching the store.
    Skip,
}

/// Does `event` belong to a category this subscription reads?
///
/// The category is the only part of a hint that is safe to act on. It is
/// also sufficient: the pass that follows re-derives everything else from
/// the store, and a hint for an unsubscribed category cannot change what
/// that pass would return.
///
/// `filter` is the caller's snapshot of the live
/// [`DeliveryShape::filter`], not a value captured at spawn — the
/// categories a subscription reads change under a running task.
fn subscribes_to(filter: &SubscriptionFilter, event: &PersistedEvent) -> bool {
    filter.categories.contains(&event.stream_id.category)
}

/// Consume every hint already queued, so a burst of appends costs one
/// store read rather than one per event. Returns whether any of them
/// named a category this subscription reads; the payloads are discarded
/// for the same reason the arm that called this discards its own. A lag
/// observed mid-drain counts as relevant, because what it dropped is
/// unknown.
fn drain_pending_hints(
    receiver: &mut broadcast::Receiver<Arc<PersistedEvent>>,
    sub_id: SubscriptionId,
    filter: &SubscriptionFilter,
) -> bool {
    let mut relevant = false;
    loop {
        match receiver.try_recv() {
            Ok(event) => relevant |= subscribes_to(filter, &event),
            Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                note_lagged(sub_id, skipped);
                relevant = true;
            }
            Err(broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed) => {
                return relevant
            }
        }
    }
}

/// Record that the hint channel overran. Overrunning it costs nothing
/// but the count: the store read that follows covers exactly what the
/// lost hints would have announced. The counter stays because it is the
/// signal that the channel is undersized for the append rate — and it is
/// recorded identically whether the lag surfaced on `recv` or mid-drain,
/// so the two cannot report differently.
fn note_lagged(sub_id: SubscriptionId, skipped: u64) {
    tracing::warn!(
        subscription_id = %sub_id.0,
        skipped = skipped,
        "broadcast channel lagged; the store read covers it"
    );
    emit_broadcast_lagged();
}

/// Catch-up walk of the filter's categories as one `global_position`-
/// ordered stream, paging forward from [`ReadCursor`]'s mark until a page
/// comes back short.
///
/// This is the delivery path, not a recovery path: it is what a
/// transactionally appended event — and an event appended by another
/// replica — is reached by, so it runs on every [`STORE_POLL_INTERVAL`]
/// tick and not only at startup.
///
/// One merged read rather than one read per category, because the mark it
/// advances is one scalar and the two have to describe the same stream
/// (see [`ReadCursor`]).
///
/// The pass ends early, with the mark left where it is, in two cases that
/// are not task-fatal: a failed read (the next tick retries the same page,
/// so a transient read failure costs latency and never an event) and a
/// failed delivery (the next tick retries the same event — see
/// [`process_event_for_subscription`]).
///
/// Returns `true` when the task must exit — the cancellation token
/// fired, or a delivery exhausted the failure budget and the
/// subscription is now disabled. A caller that ignored the budget half
/// would keep delivering to a subscription the dispatcher has already
/// given up on.
async fn catch_up(
    sub_id: SubscriptionId,
    deps: &SubscriptionTaskDeps,
    cancel: &CancellationToken,
    cursor: &mut ReadCursor,
) -> bool {
    loop {
        if cancel.is_cancelled() {
            return true;
        }
        let from = cursor.read_from();
        // The categories come from the live row, not from the one this
        // task was spawned with: a filter PATCH that adds a category has
        // to reach the read for that category's events to be reachable
        // at all, and one that removes a category must stop paying for
        // its pages. Taken as an owned list per page so the `ArcSwap`
        // guard is not held across the store round trip.
        let categories = deps.delivery_shape.load().filter.categories.clone();
        let events = match deps
            .event_store
            .read_categories(&categories, from, CATCHUP_PAGE)
            .await
        {
            Ok(evts) => evts,
            Err(e) => {
                // Fail closed: the mark does not move, so nothing is
                // skipped. A deterministic failure — one row this build
                // cannot decode, which is what a mixed-version rollout
                // produces — therefore stalls the subscription until an
                // operator intervenes, and the counter is how they find
                // out. `warn!` alone is not an alertable signal.
                emit_subscription_read_error();
                tracing::warn!(
                    subscription_id = %sub_id.0,
                    categories = ?categories,
                    error = %e,
                    "catch-up read failed; the pass stops and the next tick retries the same page"
                );
                return false;
            }
        };
        if events.is_empty() {
            return false;
        }
        let was_full_page = events.len() as u64 >= CATCHUP_PAGE;

        // Resolve, for the whole page in one round trip, the repository
        // every event discloses. This is the batch boundary the
        // visibility primitive is built around: the per-event walk below
        // consults the index without touching the database.
        //
        // Fail closed on a resolution failure the same way a failed read
        // does — end the pass with the mark where it is, so the next tick
        // retries this page. Continuing with an unresolved index would
        // silently degrade the page to admin-only and, because the
        // cursor would advance over it, drop the owner's own events for
        // good.
        let repository_index = match deps.event_visibility.index(&events).await {
            Ok(index) => index,
            Err(e) => {
                emit_subscription_read_error();
                tracing::warn!(
                    subscription_id = %sub_id.0,
                    error = %e,
                    "event repository resolution failed; the pass stops and the next \
                     tick retries the same page"
                );
                return false;
            }
        };

        for event in events {
            if cancel.is_cancelled() {
                return true;
            }
            // The mark before this event: where a restart would resume if
            // this event is not consumed here.
            let resume_from = cursor.mark();
            match process_event_for_subscription(
                &event,
                sub_id,
                deps,
                resume_from,
                &repository_index,
            )
            .await
            {
                Disposition::Consumed => {
                    // Advance only over an event this task is done with —
                    // delivered, filtered out, or dropped for want of a
                    // notifier. Recording the read is what stops the next
                    // tick re-reading the page forever.
                    cursor.observe(event.global_position);
                }
                // Not consumed, so not marked: the next pass reads this
                // same event again. That is the retry, and the failure
                // budget is what bounds the head-of-line block it creates.
                Disposition::Halt => return false,
                Disposition::ExitTask => return true,
            }
        }
        if !was_full_page {
            return false;
        }
    }
}

/// What the pass should do after handing one event to the notifier.
enum Disposition {
    /// This task is done with the event; advance the cursor over it.
    Consumed,
    /// Delivery failed. Leave the cursor where it is and end the pass;
    /// the next one retries this event.
    Halt,
    /// The failure budget exhausted and the subscription is now disabled.
    ExitTask,
}

/// Process a single event for the subscription.
///
/// `resume_from` is the cursor mark *before* this event — the position a
/// restart would resume from if this event is not consumed here. It is
/// what gets persisted alongside a delivery failure, and it is the whole
/// of the at-least-once guarantee: writing this event's own position
/// there instead would checkpoint the mark at an event nobody received,
/// and because reads resume with a strict `>` the next pass would start
/// above it. One transport attempt, ever, and a 30-second receiver outage
/// would silently swallow every event that arrived in it.
///
/// `repository_index` is the page-wide aggregate→repository resolution
/// [`catch_up`] built before the walk. Taking it as a parameter rather
/// than resolving here is what keeps the per-event path free of I/O.
async fn process_event_for_subscription(
    event: &PersistedEvent,
    sub_id: SubscriptionId,
    deps: &SubscriptionTaskDeps,
    resume_from: Option<u64>,
    repository_index: &EventRepositoryIndex,
) -> Disposition {
    // 1. Load the three inputs to this event's decision together — one
    //    `.load()` each per event. The evaluator carries the owner's
    //    grants, the principal carries the owner's live `is_admin` bit,
    //    and the delivery shape carries the live row's filter and
    //    target; steps 2 to 4 below decide one event against this one
    //    snapshot. Taking them in one place is what keeps the three the
    //    same age — any of them changing (a revoked grant, a revoked
    //    admin bit, a PATCHed filter or target) reaches this walk
    //    within its publisher's refresh cadence and no later.
    let evaluator_guard = deps.rbac.load();
    let evaluator = &**evaluator_guard;
    let owner_principal_guard = deps.owner_principal.load();
    let owner_principal = &**owner_principal_guard;
    let shape_guard = deps.delivery_shape.load();
    let shape = &**shape_guard;

    // 2. Filter via the pure subscription_filter helper.
    let ctx = FilterContext {
        rbac: evaluator,
        repositories: &deps.repositories,
        owner_principal,
        repository_index,
    };
    if !filter_matches(&shape.filter, event, &ctx).await {
        return Disposition::Consumed;
    }

    // 3. Find a notifier that supports the target. Resolved from the
    //    live shape, so the first delivery after a target PATCH already
    //    goes to the new target; the registry walk itself is unchanged,
    //    and a target no adapter supports keeps its degraded-state
    //    behaviour below.
    let notifier = deps.notifiers.iter().find(|n| n.supports(&shape.target));
    let Some(notifier) = notifier else {
        tracing::warn!(
            subscription_id = %sub_id.0,
            "no EventNotifier supports this target_kind; dropping event"
        );
        return Disposition::Consumed;
    };

    // 4. Send.
    let started = Instant::now();
    // One-event batch — multi-event batching is a future optimisation;
    // v1 keeps the per-event semantics simple.
    let _ = NOTIFY_BATCH_SIZE;
    let batch = std::slice::from_ref(event);
    let outcome = notifier.notify(&shape.target, sub_id, batch).await;
    let elapsed_secs = started.elapsed().as_secs_f64();

    // 5. Emit metrics (cardinality-safe closed labels).
    let target_kind = target_kind_label(&shape.target);
    let result = notify_outcome_label(&outcome);
    emit_notify_delivery(target_kind, result, elapsed_secs);

    // 6. Update budget and figure out whether to record a failure row.
    let now = Instant::now();
    let (failure_record, budget_exhausted) = match &outcome {
        NotifyOutcome::Delivered => {
            deps.budget.lock().unwrap().record_success();
            (None, false)
        }
        NotifyOutcome::DownstreamRejected { reason } | NotifyOutcome::Failed { reason } => {
            let mut b = deps.budget.lock().unwrap();
            let exhausted = b.record_failure(now);
            let consecutive = b.count_at(now);
            tracing::warn!(
                subscription_id = %sub_id.0,
                consecutive_failures = consecutive,
                "subscription delivery failure"
            );
            let failure = SubscriptionFailure {
                at: Utc::now(),
                reason: reason.clone(),
                consecutive_failures: consecutive as u32,
            };
            (Some(failure), exhausted)
        }
    };

    // 7. Persist progress.
    //
    // - On success: this event's own position, respecting the 5-min
    //   debounce floor; first persist on each interval boundary.
    // - On failure: `resume_from` — the position *before* this event —
    //   and immediately, because `last_failure` is an audit signal
    //   operators read live. `None` there means "record the failure, do
    //   not move the position"; the adapter leaves the column alone.
    let position = match &failure_record {
        Some(_) => resume_from,
        None => Some(event.global_position),
    };
    let should_persist = match &failure_record {
        Some(_) => true,
        None => deps.progress.lock().unwrap().should_persist(now),
    };
    if should_persist {
        if let Err(e) = deps
            .use_case
            .record_delivery_progress(sub_id, position, failure_record.as_ref())
            .await
        {
            tracing::warn!(
                subscription_id = %sub_id.0,
                error = %e,
                "record_delivery_progress failed"
            );
        }
    }

    // 8. Budget exhausted? Transition to Disabled and signal exit.
    if budget_exhausted {
        tracing::info!(
            subscription_id = %sub_id.0,
            reason = "DeliveryFailureBudgetExhausted",
            "subscription disabled by dispatcher (budget exhausted)"
        );
        if let Err(e) = deps
            .use_case
            .disable(sub_id, DisableReason::DeliveryFailureBudgetExhausted)
            .await
        {
            tracing::warn!(
                subscription_id = %sub_id.0,
                error = %e,
                "disable on budget-exhaust failed; task will still exit"
            );
        }
        return Disposition::ExitTask;
    }

    if failure_record.is_some() {
        Disposition::Halt
    } else {
        Disposition::Consumed
    }
}

/// Compile-time check: the unused-target case in the dispatch helper is
/// audit-only. Suppresses dead-code on `NOTIFY_BATCH_SIZE` / target
/// imports in the absence of the future batch-fan-in optimisation.
#[allow(dead_code)]
fn _check_target_kind_helper_compiles() {
    let target = SubscriptionTarget::NatsJetStream {
        subject: "hort.events".to_string(),
    };
    let _: &'static str = target_kind_label(&target);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use chrono::Utc;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::subscription::{
        EventTypeFilter, RepositoryScope, Subscription, SubscriptionFilter, SubscriptionId,
        SubscriptionState, SubscriptionTarget,
    };
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::events::{
        Actor, ApiActor, ArtifactIngested, DomainEvent, PersistedEvent, StreamCategory, StreamId,
    };
    use hort_domain::ports::event_notifier::{EventNotifier, NotifyFailureReason, NotifyOutcome};
    use hort_domain::ports::repository_repository::RepositoryRepository;
    use hort_domain::ports::subscription_repository::SubscriptionRepository;
    use hort_domain::ports::user_repository::UserRepository;
    use hort_domain::ports::webhook_target_guard::WebhookTargetGuard;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;
    use url::Url;
    use uuid::Uuid;

    use crate::event_store_publisher::EventStorePublisher;
    use crate::rbac::RbacEvaluator;
    use crate::use_cases::subscription_use_case::{SubscriptionUseCase, SubscriptionUseCaseConfig};
    use crate::use_cases::test_support::{
        MockArtifactGroupRepository, MockArtifactRepository, MockEventRepositoryResolver,
        MockEventStore, MockRepositoryRepository, MockUserRepository,
    };

    // ---- Recording EventNotifier --------------------------------------

    /// Notifier that records every `notify` call and returns a
    /// pre-canned outcome.
    pub(super) struct RecordingNotifier {
        outcome: NotifyOutcome,
        calls: Mutex<Vec<(SubscriptionTarget, Vec<PersistedEvent>)>>,
    }

    impl RecordingNotifier {
        pub fn new(outcome: NotifyOutcome) -> Self {
            Self {
                outcome,
                calls: Mutex::new(Vec::new()),
            }
        }

        pub fn calls(&self) -> Vec<(SubscriptionTarget, Vec<PersistedEvent>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl EventNotifier for RecordingNotifier {
        fn notify<'a>(
            &'a self,
            target: &'a SubscriptionTarget,
            _subscription_id: SubscriptionId,
            events: &'a [PersistedEvent],
        ) -> BoxFuture<'a, NotifyOutcome> {
            self.calls
                .lock()
                .unwrap()
                .push((target.clone(), events.to_vec()));
            let outcome = self.outcome.clone();
            Box::pin(async move { outcome })
        }

        fn supports(&self, target: &SubscriptionTarget) -> bool {
            matches!(target, SubscriptionTarget::Webhook { .. })
                || matches!(target, SubscriptionTarget::NatsJetStream { .. })
        }
    }

    /// Notifier that delivers successfully and then cancels the task,
    /// standing in for the process dying immediately after a delivery has
    /// been persisted. Records what it was handed, like
    /// [`RecordingNotifier`].
    pub(super) struct CancelAfterFirstDelivery {
        cancel: CancellationToken,
        calls: Mutex<Vec<u64>>,
    }

    impl CancelAfterFirstDelivery {
        fn new(cancel: CancellationToken) -> Self {
            Self {
                cancel,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn delivered(&self) -> Vec<u64> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl EventNotifier for CancelAfterFirstDelivery {
        fn notify<'a>(
            &'a self,
            _target: &'a SubscriptionTarget,
            _subscription_id: SubscriptionId,
            events: &'a [PersistedEvent],
        ) -> BoxFuture<'a, NotifyOutcome> {
            self.calls
                .lock()
                .unwrap()
                .extend(events.iter().map(|e| e.global_position));
            self.cancel.cancel();
            Box::pin(async { NotifyOutcome::Delivered })
        }

        fn supports(&self, target: &SubscriptionTarget) -> bool {
            matches!(target, SubscriptionTarget::Webhook { .. })
        }
    }

    /// Notifier that doesn't `supports` anything — used to test the
    /// empty-registry case.
    pub(super) struct UnsupportedNotifier;

    impl EventNotifier for UnsupportedNotifier {
        fn notify<'a>(
            &'a self,
            _t: &'a SubscriptionTarget,
            _subscription_id: SubscriptionId,
            _e: &'a [PersistedEvent],
        ) -> BoxFuture<'a, NotifyOutcome> {
            Box::pin(async { NotifyOutcome::Delivered })
        }

        fn supports(&self, _t: &SubscriptionTarget) -> bool {
            false
        }
    }

    // ---- Fixtures ----------------------------------------------------

    fn admin_principal(user_id: Uuid) -> CallerPrincipal {
        CallerPrincipal {
            user_id,
            external_id: "test:owner".into(),
            username: "owner".into(),
            email: "owner@example.com".into(),
            claims: vec!["admin".into()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn dev_principal(user_id: Uuid) -> CallerPrincipal {
        CallerPrincipal {
            user_id,
            external_id: "test:owner".into(),
            username: "owner".into(),
            email: "owner@example.com".into(),
            claims: vec!["dev".into()],
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn empty_eval() -> RbacEvaluator {
        RbacEvaluator::new(Vec::new())
    }

    /// Evaluator where a `Claims(["dev"])`-subject grant carries `Read`
    /// on `repo_id` (the claim-subject grant model, ADR 0012).
    fn eval_with_repo_read(repo_id: Uuid) -> RbacEvaluator {
        RbacEvaluator::new(vec![PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["dev".to_string()]),
            repository_id: Some(repo_id),
            permission: Permission::Read,
            created_at: Utc::now(),
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
        }])
    }

    fn make_subscription(owner_user_id: Uuid, scope: RepositoryScope) -> Subscription {
        Subscription {
            id: SubscriptionId(Uuid::new_v4()),
            owner_user_id,
            created_by_token_id: None,
            name: "test".into(),
            description: None,
            target: SubscriptionTarget::Webhook {
                url: "https://hooks.example.com/x".parse::<Url>().unwrap(),
                secret_ref: hort_domain::ports::secret_port::SecretRef {
                    source: hort_domain::ports::secret_port::SecretSource::EnvVar,
                    location: "HORT_WEBHOOK_SECRET".into(),
                },
            },
            filter: SubscriptionFilter {
                categories: vec![StreamCategory::Artifact],
                event_types: EventTypeFilter::All,
                repositories: scope,
                named_predicates: vec![],
            },
            // Per-subscription authority floor.
            snapshot_claims: Vec::new(),
            state: SubscriptionState::Active,
            last_delivered_position: None,
            last_failure: None,
            created_at: Utc::now(),
        }
    }

    fn ingested_event(repo_id: Uuid, global_pos: u64) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(Uuid::new_v4()),
            stream_position: 0,
            global_position: global_pos,
            event: DomainEvent::ArtifactIngested(ArtifactIngested {
                artifact_id: Uuid::new_v4(),
                repository_id: repo_id,
                name: "pkg".into(),
                version: Some("1.0.0".into()),
                sha256: "a".repeat(64).parse::<ContentHash>().unwrap(),
                size_bytes: 1,
                source: hort_domain::events::IngestSource::Direct,
                metadata: serde_json::Value::Null,
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

    // --- Test guard / mock implementations -----------------------------

    /// Webhook guard that accepts every URL — the use case requires
    /// the trait dyn but the dispatcher never calls it.
    struct PermissiveGuard;
    impl WebhookTargetGuard for PermissiveGuard {
        fn check<'a>(
            &'a self,
            _url: &'a Url,
        ) -> BoxFuture<'a, Result<(), hort_domain::entities::subscription::SsrfBlockReason>>
        {
            Box::pin(async { Ok(()) })
        }
    }

    /// One recorded `update_last_delivered` call: the subscription, the
    /// position it was asked to store (`None` = "do not move it") and the
    /// failure it carried.
    type ProgressCall = (SubscriptionId, Option<u64>, Option<SubscriptionFailure>);

    /// In-memory subscription repo with deterministic id-keyed lookups.
    struct MockSubRepo {
        rows: Mutex<HashMap<SubscriptionId, Subscription>>,
        progress_calls: Mutex<Vec<ProgressCall>>,
    }

    impl MockSubRepo {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                progress_calls: Mutex::new(Vec::new()),
            }
        }
        fn insert(&self, sub: Subscription) {
            self.rows.lock().unwrap().insert(sub.id, sub);
        }
        fn progress_calls(
            &self,
        ) -> Vec<(SubscriptionId, Option<u64>, Option<SubscriptionFailure>)> {
            self.progress_calls.lock().unwrap().clone()
        }
    }

    impl SubscriptionRepository for MockSubRepo {
        fn create(&self, sub: &Subscription) -> BoxFuture<'_, DomainResult<()>> {
            let sub = sub.clone();
            Box::pin(async move {
                self.rows.lock().unwrap().insert(sub.id, sub);
                Ok(())
            })
        }

        fn find_by_id(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<Subscription>> {
            let result =
                self.rows
                    .lock()
                    .unwrap()
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| DomainError::NotFound {
                        entity: "Subscription",
                        id: id.0.to_string(),
                    });
            Box::pin(async move { result })
        }

        fn find_by_name(
            &self,
            owner: Uuid,
            name: &str,
        ) -> BoxFuture<'_, DomainResult<Option<Subscription>>> {
            let name = name.to_string();
            let result = self
                .rows
                .lock()
                .unwrap()
                .values()
                .find(|s| s.owner_user_id == owner && s.name == name)
                .cloned();
            Box::pin(async move { Ok(result) })
        }

        fn list_for_owner(
            &self,
            owner: Uuid,
            _page: hort_domain::types::PageRequest,
        ) -> BoxFuture<'_, DomainResult<hort_domain::types::Page<Subscription>>> {
            let items: Vec<Subscription> = self
                .rows
                .lock()
                .unwrap()
                .values()
                .filter(|s| s.owner_user_id == owner)
                .cloned()
                .collect();
            let total = items.len() as u64;
            Box::pin(async move { Ok(hort_domain::types::Page { items, total }) })
        }

        fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<Subscription>>> {
            let items: Vec<Subscription> = self
                .rows
                .lock()
                .unwrap()
                .values()
                .filter(|s| matches!(s.state, SubscriptionState::Active))
                .cloned()
                .collect();
            Box::pin(async move { Ok(items) })
        }

        fn update(&self, sub: &Subscription) -> BoxFuture<'_, DomainResult<()>> {
            let sub = sub.clone();
            Box::pin(async move {
                self.rows.lock().unwrap().insert(sub.id, sub);
                Ok(())
            })
        }

        fn delete(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<()>> {
            self.rows.lock().unwrap().remove(&id);
            Box::pin(async { Ok(()) })
        }

        fn update_last_delivered(
            &self,
            id: SubscriptionId,
            position: Option<u64>,
            last_failure: Option<&SubscriptionFailure>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            self.progress_calls
                .lock()
                .unwrap()
                .push((id, position, last_failure.cloned()));
            // Also mirror into the row so subsequent reads see the
            // updated state. `None` leaves the position alone, mirroring
            // the adapter's COALESCE — a test must not be able to observe
            // a rewind the real store would never write.
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.get_mut(&id) {
                if let Some(position) = position {
                    row.last_delivered_position = Some(position);
                }
                row.last_failure = last_failure.cloned();
            }
            Box::pin(async { Ok(()) })
        }
    }

    // -- Helpers ----------------------------------------------------------

    /// Build a `SubscriptionUseCase` wired to the supplied
    /// `MockSubRepo`. Test rigging only — production composition wires
    /// the same shape.
    fn make_use_case(
        sub_repo: Arc<MockSubRepo>,
        event_store: Arc<EventStorePublisher>,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
    ) -> Arc<SubscriptionUseCase> {
        let users: Arc<dyn UserRepository> = Arc::new(MockUserRepository::new());
        let repos: Arc<dyn RepositoryRepository> = Arc::new(MockRepositoryRepository::new());
        let guard: Arc<dyn WebhookTargetGuard> = Arc::new(PermissiveGuard);
        Arc::new(SubscriptionUseCase::new(
            sub_repo,
            users,
            event_store,
            rbac,
            repos,
            guard,
            SubscriptionUseCaseConfig::default(),
        ))
    }

    /// `sub` seeds the published [`DeliveryShape`] — the task reads its
    /// filter and target from there, never from the row it is spawned
    /// with, so a test that wants a particular filter or target has to
    /// publish it here (which is exactly what the reconcile pass does).
    #[allow(clippy::needless_pass_by_value)]
    fn make_deps(
        sub: &Subscription,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
        notifier: Arc<dyn EventNotifier>,
        sub_repo: Arc<MockSubRepo>,
        mock_event_store: Arc<MockEventStore>,
        principal: CallerPrincipal,
    ) -> SubscriptionTaskDeps {
        let event_store_publisher =
            Arc::new(EventStorePublisher::without_broadcast(mock_event_store));
        let use_case = make_use_case(sub_repo, event_store_publisher.clone(), rbac.clone());
        let repos: Arc<dyn RepositoryRepository> = Arc::new(MockRepositoryRepository::new());
        SubscriptionTaskDeps {
            event_store: event_store_publisher,
            use_case,
            rbac,
            repositories: repos,
            // Empty artifact / group stores: every event these tests
            // drive is an `ArtifactIngested`, which carries its
            // repository in the payload and therefore needs no
            // resolution. The disclosure-resolving paths have their own
            // tests below, which seed the stores.
            event_visibility: Arc::new(EventVisibilityUseCase::new(Arc::new(
                MockEventRepositoryResolver::new(
                    Arc::new(MockArtifactRepository::new()),
                    Arc::new(MockArtifactGroupRepository::new()),
                ),
            ))),
            owner_principal: Arc::new(ArcSwap::from_pointee(principal)),
            delivery_shape: Arc::new(ArcSwap::from_pointee(DeliveryShape::from(sub))),
            notifiers: vec![notifier],
            budget: Arc::new(Mutex::new(FailureBudget::new())),
            progress: Arc::new(Mutex::new(ProgressDebouncer::new(
                Instant::now(),
                Duration::from_secs(0),
            ))),
        }
    }

    /// Fill a task's failure budget to one failure short of its
    /// threshold, so the next failed delivery is the one that exhausts it.
    ///
    /// Needed because a pass halts at its first failed delivery: a task
    /// starting from an empty budget takes 100 passes — 500 seconds of
    /// poll ticks — to reach the disable, which is the retry loop's
    /// property and not the property a `run`-level exit test is about.
    fn prime_budget_to_one_short_of_exhaustion(deps: &SubscriptionTaskDeps) {
        let now = Instant::now();
        let mut budget = deps.budget.lock().unwrap();
        for _ in 0..99 {
            assert!(
                !budget.record_failure(now),
                "99 failures must not exhaust a 100-failure budget"
            );
        }
    }

    // -- ProgressDebouncer unit tests ------------------------------------

    #[test]
    fn progress_debouncer_first_call_within_interval_returns_false() {
        let start = Instant::now();
        let mut d = ProgressDebouncer::new(start, Duration::from_secs(10));
        assert!(!d.should_persist(start + Duration::from_secs(5)));
    }

    #[test]
    fn progress_debouncer_after_interval_returns_true_then_resets() {
        let start = Instant::now();
        let mut d = ProgressDebouncer::new(start, Duration::from_secs(10));
        assert!(d.should_persist(start + Duration::from_secs(10)));
        // Immediately after persisting, next call within the new
        // interval returns false.
        assert!(!d.should_persist(start + Duration::from_secs(15)));
    }

    #[test]
    fn progress_debouncer_zero_interval_always_persists() {
        let start = Instant::now();
        let mut d = ProgressDebouncer::new(start, Duration::from_secs(0));
        assert!(d.should_persist(start));
        assert!(d.should_persist(start));
    }

    // -- task tests -------------------------------------------------------

    /// Filter mismatch (category not in filter) → notifier NOT called.
    #[tokio::test]
    async fn task_filters_out_event_not_matching_subscription_filter() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        // Subscription wants Policy category; event is on Artifact.
        let mut sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        sub.filter.categories = vec![StreamCategory::Policy];
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        let event = ingested_event(repo_id, 1);
        // No budget exhaustion possible — single event, mismatched filter.
        let disposition = process_event_for_subscription(
            &event,
            sub.id,
            &deps,
            None,
            &EventRepositoryIndex::empty(),
        )
        .await;
        assert!(
            matches!(disposition, Disposition::Consumed),
            "a filtered-out event is consumed, so the pass walks on past it"
        );
        assert!(notifier.calls().is_empty(), "notifier MUST NOT be called");
    }

    /// Filter passes → notifier called with the right target + events.
    #[tokio::test]
    async fn task_calls_notifier_when_filter_passes() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        let event = ingested_event(repo_id, 5);
        let disposition = process_event_for_subscription(
            &event,
            sub.id,
            &deps,
            None,
            &EventRepositoryIndex::empty(),
        )
        .await;
        assert!(matches!(disposition, Disposition::Consumed));
        let calls = notifier.calls();
        assert_eq!(calls.len(), 1, "exactly one notify call");
        assert_eq!(calls[0].1.len(), 1, "one event in the batch");
        assert_eq!(calls[0].1[0].global_position, 5);
    }

    /// Successful delivery → record_delivery_progress called with the
    /// event's global_position. (Debouncer is wired with zero interval
    /// in the test fixture so the first success persists.)
    #[tokio::test]
    async fn task_records_progress_on_successful_delivery() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier, sub_repo.clone(), mock_es, principal);
        // Zero-interval debouncer in make_deps → first success persists.
        let event = ingested_event(repo_id, 42);
        let _ = process_event_for_subscription(
            &event,
            sub.id,
            &deps,
            Some(41),
            &EventRepositoryIndex::empty(),
        )
        .await;
        let progress = sub_repo.progress_calls();
        assert_eq!(progress.len(), 1);
        assert_eq!(progress[0].0, sub.id);
        assert_eq!(
            progress[0].1,
            Some(42),
            "a delivered event checkpoints its own position"
        );
        assert!(progress[0].2.is_none(), "no failure on success");
    }

    /// Failed delivery → record_delivery_progress carries the failure
    /// record AND increments the budget counter.
    #[tokio::test]
    async fn task_records_progress_on_failed_delivery_with_failure_payload() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Failed {
            reason: NotifyFailureReason::Dns,
        }));
        let deps = make_deps(&sub, rbac, notifier, sub_repo.clone(), mock_es, principal);
        let event = ingested_event(repo_id, 7);
        let disposition = process_event_for_subscription(
            &event,
            sub.id,
            &deps,
            Some(6),
            &EventRepositoryIndex::empty(),
        )
        .await;
        assert!(
            matches!(disposition, Disposition::Halt),
            "a failed delivery halts the pass; a single failure does not exhaust the budget"
        );
        let progress = sub_repo.progress_calls();
        assert_eq!(progress.len(), 1);
        assert_eq!(
            progress[0].1,
            Some(6),
            "the position persisted alongside the failure is the one BEFORE the failed \
             event — reads must resume at it, not past it"
        );
        let failure = progress[0].2.as_ref().expect("failure payload present");
        assert_eq!(failure.reason, NotifyFailureReason::Dns);
        assert_eq!(failure.consecutive_failures, 1);
    }

    /// 100 consecutive failures → `disable` called and the function
    /// returns `true` (exit signal).
    #[tokio::test]
    async fn task_disables_subscription_on_budget_exhaustion() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Failed {
            reason: NotifyFailureReason::ConnectTimeout,
        }));
        let deps = make_deps(&sub, rbac, notifier, sub_repo.clone(), mock_es, principal);
        // Cycle 100 events. In production each of these is a separate
        // pass retrying the same event; here the positions differ only so
        // the assertion can tell the calls apart.
        let mut exhausted = false;
        for i in 1..=100u64 {
            let event = ingested_event(repo_id, i);
            let disposition = process_event_for_subscription(
                &event,
                sub.id,
                &deps,
                Some(i - 1),
                &EventRepositoryIndex::empty(),
            )
            .await;
            exhausted = matches!(disposition, Disposition::ExitTask);
            if exhausted {
                break;
            }
        }
        assert!(exhausted, "100th failure must signal budget exhaustion");
        let row = sub_repo.rows.lock().unwrap().get(&sub.id).cloned().unwrap();
        assert!(matches!(row.state, SubscriptionState::Disabled { .. }));
    }

    /// Empty notifier registry → task warns and drops (no panic).
    #[tokio::test]
    async fn task_with_no_supporting_notifier_drops_event() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let unsupported: Arc<dyn EventNotifier> = Arc::new(UnsupportedNotifier);
        let mut deps = make_deps(
            &sub,
            rbac,
            unsupported,
            sub_repo.clone(),
            mock_es,
            principal,
        );
        // Replace with empty registry to also exercise the empty branch.
        deps.notifiers = vec![];
        let event = ingested_event(repo_id, 1);
        let disposition = process_event_for_subscription(
            &event,
            sub.id,
            &deps,
            None,
            &EventRepositoryIndex::empty(),
        )
        .await;
        assert!(
            matches!(disposition, Disposition::Consumed),
            "an undeliverable target is not a delivery failure — it must not wedge the pass"
        );
        assert!(
            sub_repo.progress_calls().is_empty(),
            "no notifier called → no progress recorded"
        );
    }

    /// Admin scope event without repo → matches; this exercises the
    /// admin-principal branch through the filter.
    #[tokio::test]
    async fn task_dispatches_under_admin_scope_when_owner_is_admin() {
        let owner_user_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(empty_eval()));
        let principal = admin_principal(owner_user_id);
        let mut sub = make_subscription(owner_user_id, RepositoryScope::All);
        sub.filter.categories = vec![StreamCategory::Artifact];
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        let event = ingested_event(Uuid::new_v4(), 1);
        let _ = process_event_for_subscription(
            &event,
            sub.id,
            &deps,
            None,
            &EventRepositoryIndex::empty(),
        )
        .await;
        assert_eq!(notifier.calls().len(), 1);
    }

    // -- catch_up tests ---------------------------------------------------

    #[tokio::test]
    async fn catch_up_reads_seeded_events_and_dispatches() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(
            StreamCategory::Artifact,
            vec![ingested_event(repo_id, 1), ingested_event(repo_id, 2)],
        );
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        let cancel = CancellationToken::new();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);
        let exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;
        assert!(!exit, "healthy catch-up must not signal task exit");
        assert_eq!(
            notifier.calls().len(),
            2,
            "both seeded events delivered via catch-up"
        );
        assert!(
            matches!(cursor.read_from(), SubscribeFrom::AfterGlobal(2)),
            "the cursor must have advanced over everything the pass read"
        );
    }

    /// A counting resolver that answers from a fixed map and records
    /// how many times it was called. Lets a test assert the page-level
    /// batch boundary: ONE call for the whole page, never one per event.
    struct CountingResolver {
        artifacts: HashMap<Uuid, Uuid>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        fail: bool,
    }

    impl hort_domain::ports::event_repository_resolver::EventRepositoryResolver for CountingResolver {
        fn resolve_event_aggregates<'a>(
            &'a self,
            artifact_ids: &'a [Uuid],
            _artifact_group_ids: &'a [Uuid],
        ) -> BoxFuture<
            'a,
            DomainResult<hort_domain::ports::event_repository_resolver::EventAggregateRepositories>,
        > {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail {
                return Box::pin(async {
                    Err(DomainError::Invariant("database error: down".into()))
                });
            }
            let artifacts = artifact_ids
                .iter()
                .filter_map(|id| self.artifacts.get(id).map(|r| (*id, *r)))
                .collect();
            Box::pin(async move {
                Ok(
                    hort_domain::ports::event_repository_resolver::EventAggregateRepositories {
                        artifacts,
                        artifact_groups: HashMap::new(),
                    },
                )
            })
        }
    }

    /// `ArtifactQuarantined` on the artifact's own stream — payload
    /// names the artifact, not the repository.
    fn quarantined_event(artifact_id: Uuid, global_pos: u64) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(artifact_id),
            stream_position: 0,
            global_position: global_pos,
            event: DomainEvent::ArtifactQuarantined(hort_domain::events::ArtifactQuarantined {
                artifact_id,
                quarantine_window_start: Utc::now(),
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

    /// The catch-up pass resolves the whole page's repository
    /// disclosures in ONE round trip and delivers the events the owner
    /// holds `Read` on.
    ///
    /// Both halves matter: the delivery is the symmetry half of the fix
    /// (these events used to be dropped outright for a
    /// `RepositoryScope::Some` owner and delivered indiscriminately for
    /// an `OwnedByActor` one), and the call count is the hot-path
    /// constraint — a resolution per event would be four calls here.
    #[tokio::test]
    async fn catch_up_resolves_the_page_once_and_delivers_what_the_owner_may_read() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let artifact_a = Uuid::new_v4();
        let artifact_b = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::Some(vec![repo_id]));
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(
            StreamCategory::Artifact,
            vec![
                quarantined_event(artifact_a, 1),
                quarantined_event(artifact_b, 2),
                quarantined_event(artifact_a, 3),
                quarantined_event(artifact_b, 4),
            ],
        );
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        deps.event_visibility = Arc::new(EventVisibilityUseCase::new(Arc::new(CountingResolver {
            artifacts: HashMap::from([(artifact_a, repo_id), (artifact_b, repo_id)]),
            calls: calls.clone(),
            fail: false,
        })));

        let cancel = CancellationToken::new();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);
        let exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;

        assert!(!exit);
        assert_eq!(
            notifier.calls().len(),
            4,
            "an allow-list naming the artifacts' repository must receive that \
             repository's lifecycle events — the half the bypass fix must not lose"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the page must cost ONE resolution, not one per event"
        );
    }

    /// A failed resolution ends the pass with the cursor where it is, so
    /// the next tick retries the same page. Advancing over an unresolved
    /// page would drop the owner's own events permanently: the
    /// disclosure would read as unresolvable, the events would filter
    /// out as `Consumed`, and the mark would move past them.
    #[tokio::test]
    async fn catch_up_stops_without_advancing_when_resolution_fails() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let artifact = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(
            StreamCategory::Artifact,
            vec![
                quarantined_event(artifact, 1),
                quarantined_event(artifact, 2),
            ],
        );
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let mut deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        deps.event_visibility = Arc::new(EventVisibilityUseCase::new(Arc::new(CountingResolver {
            artifacts: HashMap::new(),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            fail: true,
        })));

        let cancel = CancellationToken::new();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);
        let exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;

        assert!(!exit, "a resolution failure is not task-fatal");
        assert!(notifier.calls().is_empty(), "nothing is delivered");
        assert!(
            matches!(cursor.read_from(), SubscribeFrom::Start),
            "the mark must not move, so the next tick retries the same page"
        );
    }

    #[tokio::test]
    async fn catch_up_with_empty_category_loop_exits_cleanly() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        // No category data seeded — read_category returns empty.
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        let cancel = CancellationToken::new();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);
        let exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;
        assert!(!exit);
        assert!(notifier.calls().is_empty());
    }

    #[tokio::test]
    async fn catch_up_cancellation_token_exits_early() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(StreamCategory::Artifact, vec![ingested_event(repo_id, 1)]);
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);
        let exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;
        assert!(exit, "cancellation must signal task exit");
        assert!(notifier.calls().is_empty());
    }

    // -- ReadCursor unit tests -------------------------------------------

    #[test]
    fn read_cursor_resumes_from_the_persisted_position() {
        let cursor = ReadCursor::new(Some(42));
        assert!(matches!(cursor.read_from(), SubscribeFrom::AfterGlobal(42)));
        assert_eq!(cursor.mark(), Some(42));
    }

    #[test]
    fn read_cursor_without_a_persisted_position_reads_from_the_start() {
        let mut cursor = ReadCursor::new(None);
        assert!(matches!(cursor.read_from(), SubscribeFrom::Start));
        assert_eq!(
            cursor.mark(),
            None,
            "nothing read and nothing delivered — there is no position to resume from"
        );
        cursor.observe(1);
        assert!(matches!(cursor.read_from(), SubscribeFrom::AfterGlobal(1)));
    }

    /// Monotonic: a page returned out of order cannot rewind the mark
    /// onto events this task has already walked.
    #[test]
    fn read_cursor_never_rewinds() {
        let mut cursor = ReadCursor::new(None);
        cursor.observe(10);
        cursor.observe(4);
        assert!(matches!(cursor.read_from(), SubscribeFrom::AfterGlobal(10)));
    }

    /// One mark over one merged stream — not one per category. This is
    /// what makes the single persisted `last_delivered_position` exact:
    /// the mark is a position in the same ordered stream the reads walk,
    /// so everything at or below it has been read in every subscribed
    /// category.
    #[test]
    fn read_cursor_is_one_mark_over_the_merged_stream() {
        let mut cursor = ReadCursor::new(None);
        // A merged page arrives in global order across categories; the
        // cursor records positions, not which category they came from.
        cursor.observe(10);
        cursor.observe(11);
        assert_eq!(cursor.mark(), Some(11));
        assert!(matches!(cursor.read_from(), SubscribeFrom::AfterGlobal(11)));
    }

    // -- hint-drain tests -------------------------------------------------

    /// Draining consumes everything already queued and stops at the end,
    /// so a burst of appends costs one store read rather than one per
    /// event. It must also survive the channel overrunning mid-drain,
    /// which is the one way this loop could fail to terminate.
    #[tokio::test]
    async fn drain_pending_hints_consumes_the_queue_including_a_lag() {
        let repo_id = Uuid::new_v4();
        let sub = make_subscription(Uuid::new_v4(), RepositoryScope::OwnedByActor);
        // Capacity 1 with three sends and no reads: the first
        // `try_recv` reports the overrun, the rest drain normally.
        let (sender, mut receiver) = broadcast::channel::<Arc<PersistedEvent>>(1);
        for pos in 1..=3u64 {
            sender
                .send(Arc::new(ingested_event(repo_id, pos)))
                .expect("receiver attached");
        }
        assert!(
            drain_pending_hints(&mut receiver, sub.id, &sub.filter),
            "a lag makes the drain relevant regardless of what it dropped"
        );
        assert!(
            matches!(
                receiver.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ),
            "the drain must leave the channel empty"
        );

        // And it returns on a closed channel rather than spinning.
        drop(sender);
        assert!(!drain_pending_hints(&mut receiver, sub.id, &sub.filter));
    }

    /// A drained hint for a category outside the filter is not a reason to
    /// read: the pass it would trigger cannot return anything this
    /// subscription would deliver.
    #[tokio::test]
    async fn drain_pending_hints_reports_only_subscribed_categories() {
        let repo_id = Uuid::new_v4();
        let mut sub = make_subscription(Uuid::new_v4(), RepositoryScope::OwnedByActor);
        sub.filter.categories = vec![StreamCategory::Policy];
        let (sender, mut receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        sender
            .send(Arc::new(ingested_event(repo_id, 1)))
            .expect("receiver attached");
        assert!(
            !drain_pending_hints(&mut receiver, sub.id, &sub.filter),
            "an Artifact hint says nothing to a Policy-only subscription"
        );

        let mut policy = ingested_event(repo_id, 2);
        policy.stream_id = StreamId {
            category: StreamCategory::Policy,
            entity_id: Uuid::new_v4(),
        };
        sender.send(Arc::new(policy)).expect("receiver attached");
        assert!(drain_pending_hints(&mut receiver, sub.id, &sub.filter));
    }

    // -- catch_up cursor / exit-signal tests ------------------------------

    /// A failed `read_category` must leave the mark where it was, so the
    /// next tick re-reads the page it could not read rather than
    /// stepping over it.
    #[tokio::test]
    async fn catch_up_read_error_does_not_advance_the_cursor() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let mut sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        sub.last_delivered_position = Some(5);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(StreamCategory::Artifact, vec![ingested_event(repo_id, 6)]);
        mock_es.inject_category_error_after_global_position(5);
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier.clone(), sub_repo, mock_es, principal);
        let cancel = CancellationToken::new();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);
        let exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;
        assert!(!exit, "a read error is not a reason to stop the task");
        assert!(
            notifier.calls().is_empty(),
            "nothing was read, nothing sent"
        );
        assert!(
            matches!(cursor.read_from(), SubscribeFrom::AfterGlobal(5)),
            "the next tick must retry the page this one could not read"
        );
    }

    /// A failed delivery stops the pass at the failed event, and the
    /// budget is what bounds the retry.
    ///
    /// The two halves are one mechanism: each pass re-reads the same
    /// event, so the 100 failures the budget allows are 100 *passes* and
    /// the subscription is disabled at the 100th rather than looping
    /// forever. Without the halt, one pass would burn the whole budget on
    /// 100 *different* events and checkpoint past every one of them.
    #[tokio::test]
    async fn a_failed_delivery_is_retried_by_every_pass_until_the_budget_runs_out() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let mut sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        sub.last_delivered_position = Some(40);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(
            StreamCategory::Artifact,
            vec![ingested_event(repo_id, 41), ingested_event(repo_id, 42)],
        );
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Failed {
            reason: NotifyFailureReason::Dns,
        }));
        let deps = make_deps(
            &sub,
            rbac,
            notifier.clone(),
            sub_repo.clone(),
            mock_es,
            principal,
        );
        let cancel = CancellationToken::new();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);

        // Pass 1: position 41 fails, the pass stops there, and position 42
        // is not touched.
        let exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;
        assert!(!exit, "one failure is not a reason to stop the task");
        assert_eq!(
            notifier
                .calls()
                .iter()
                .flat_map(|(_, evts)| evts.iter().map(|e| e.global_position))
                .collect::<Vec<_>>(),
            vec![41],
            "the pass must stop at the failed event, not walk on over it"
        );
        assert!(
            matches!(cursor.read_from(), SubscribeFrom::AfterGlobal(40)),
            "the cursor must not advance over an event nobody received"
        );
        let progress = sub_repo.progress_calls();
        assert_eq!(progress.last().unwrap().1, Some(40));

        // Passes 2..=100: the same event, every time, until the budget goes.
        let mut passes = 1;
        loop {
            passes += 1;
            if catch_up(sub.id, &deps, &cancel, &mut cursor).await {
                break;
            }
            assert!(passes < 200, "the budget must bound the retry");
        }
        assert_eq!(passes, 100, "the 100-in-1h budget is what ends the retry");
        let delivered: Vec<u64> = notifier
            .calls()
            .iter()
            .flat_map(|(_, evts)| evts.iter().map(|e| e.global_position))
            .collect();
        assert_eq!(delivered.len(), 100);
        assert!(
            delivered.iter().all(|p| *p == 41),
            "every attempt is the same event; got {delivered:?}"
        );
        let row = sub_repo.rows.lock().unwrap().get(&sub.id).cloned().unwrap();
        assert!(matches!(row.state, SubscriptionState::Disabled { .. }));
        assert_eq!(
            row.last_delivered_position,
            Some(40),
            "the persisted cursor never moved past the undelivered event"
        );
    }

    /// Budget exhaustion inside catch-up has to reach the caller. The
    /// pass now runs on every poll tick, so a task that kept looping
    /// would keep delivering to a subscription the dispatcher has
    /// already disabled.
    #[tokio::test]
    async fn catch_up_signals_exit_when_the_budget_exhausts() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(
            StreamCategory::Artifact,
            (1..=150u64).map(|i| ingested_event(repo_id, i)).collect(),
        );
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Failed {
            reason: NotifyFailureReason::Dns,
        }));
        let deps = make_deps(
            &sub,
            rbac,
            notifier.clone(),
            sub_repo.clone(),
            mock_es,
            principal,
        );
        let cancel = CancellationToken::new();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);
        // Each pass makes one attempt and halts, so the budget takes 100
        // of them; the 100th must reach the caller as an exit signal.
        let mut exit = false;
        for _ in 0..100 {
            exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;
            if exit {
                break;
            }
        }
        assert!(exit, "budget exhaustion must stop the task");
        assert_eq!(
            notifier.calls().len(),
            100,
            "one attempt per pass, and the budget ends it at 100"
        );
        let row = sub_repo.rows.lock().unwrap().get(&sub.id).cloned().unwrap();
        assert!(matches!(row.state, SubscriptionState::Disabled { .. }));
    }

    // -- run() integration tests -----------------------------------------

    /// The property the whole delivery loop exists for: an event that is
    /// in the event store but was never broadcast still reaches the
    /// subscriber. This is every transactionally appended event — the
    /// entire artifact lifecycle — and every event appended by another
    /// replica.
    #[tokio::test(start_paused = true)]
    async fn store_poll_delivers_an_event_the_broadcast_never_carried() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(
            &sub,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es.clone(),
            principal,
        );
        // A live sender that never sends: the task has a healthy
        // broadcast receiver and the event simply does not arrive on it.
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move { run(sub, deps, receiver, task_cancel).await });

        // Startup catch-up saw an empty store; the event lands after it.
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(notifier.calls().is_empty(), "nothing to deliver yet");
        mock_es.set_category(StreamCategory::Artifact, vec![ingested_event(repo_id, 1)]);

        tokio::time::sleep(STORE_POLL_INTERVAL * 2).await;
        assert_eq!(
            notifier.calls().len(),
            1,
            "the store poll must deliver an event the broadcast never carried"
        );

        cancel.cancel();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exits on cancel")
            .expect("task must not panic");
    }

    /// The publisher does both halves for an event it appends: the row
    /// lands in the store and the same event goes on the channel. The
    /// subscriber must see it once.
    #[tokio::test(start_paused = true)]
    async fn a_broadcast_wake_up_and_the_store_read_deliver_an_event_once() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(
            &sub,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es.clone(),
            principal,
        );
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move { run(sub, deps, receiver, task_cancel).await });
        tokio::time::sleep(Duration::from_millis(1)).await;

        // The publisher's two halves: the row lands in the store AND the
        // same event is broadcast.
        let event = ingested_event(repo_id, 1);
        mock_es.set_category(StreamCategory::Artifact, vec![event.clone()]);
        sender.send(Arc::new(event)).expect("receiver attached");

        tokio::time::sleep(STORE_POLL_INTERVAL * 3).await;
        assert_eq!(
            notifier.calls().len(),
            1,
            "position 1 delivered exactly once across both paths"
        );

        cancel.cancel();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exits on cancel")
            .expect("task must not panic");
    }

    /// The reverse order of the pair above: the tick gets there first,
    /// and the broadcast copy arrives afterwards. It wakes a read that
    /// starts above the position already delivered, so it sends nothing.
    #[tokio::test(start_paused = true)]
    async fn a_broadcast_copy_of_an_already_delivered_event_sends_nothing() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(
            &sub,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es.clone(),
            principal,
        );
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move { run(sub, deps, receiver, task_cancel).await });
        tokio::time::sleep(Duration::from_millis(1)).await;

        let event = ingested_event(repo_id, 1);
        mock_es.set_category(StreamCategory::Artifact, vec![event.clone()]);
        // Let the poll carry it first.
        tokio::time::sleep(STORE_POLL_INTERVAL * 2).await;
        assert_eq!(notifier.calls().len(), 1, "poll delivered it");

        sender.send(Arc::new(event)).expect("receiver attached");
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            notifier.calls().len(),
            1,
            "the late broadcast copy must be recognised, not re-sent"
        );

        cancel.cancel();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exits on cancel")
            .expect("task must not panic");
    }

    #[tokio::test]
    async fn run_exits_cleanly_on_cancellation() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(&sub, rbac, notifier, sub_repo, mock_es, principal);
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            run(sub, deps, receiver, cancel_clone).await;
        });
        cancel.cancel();
        // Drop sender to also exercise Closed branch eventually.
        drop(sender);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should exit on cancel")
            .expect("task should not panic");
    }

    #[tokio::test]
    async fn run_delivers_on_a_broadcast_wake_up_then_cancellation_stops_it() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let notifier_for_assert = notifier.clone();
        let deps = make_deps(&sub, rbac, notifier, sub_repo, mock_es.clone(), principal);
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            run(sub, deps, receiver, cancel_clone).await;
        });
        // Let the startup pass run against an empty store, so what
        // follows is attributable to the wake-up and not to it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let event = ingested_event(repo_id, 100);
        mock_es.set_category(StreamCategory::Artifact, vec![event.clone()]);
        sender.send(Arc::new(event)).expect("send ok");
        // Real time, and well inside STORE_POLL_INTERVAL: delivery this
        // soon can only have come from the broadcast wake-up.
        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should exit")
            .expect("task should not panic");
        assert_eq!(notifier_for_assert.calls().len(), 1);
    }

    #[tokio::test]
    async fn run_drops_to_catch_up_on_broadcast_lagged() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        // Seed the catch-up category with one event so the dispatch
        // path can be observed.
        mock_es.set_category(StreamCategory::Artifact, vec![ingested_event(repo_id, 99)]);
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let notifier_for_assert = notifier.clone();
        let deps = make_deps(&sub, rbac, notifier, sub_repo, mock_es, principal);
        // Capacity 1 + no consumer at spawn time → second send returns
        // SendError; first send + slow recv triggers Lagged on overflow.
        // We construct the channel, get a receiver, send 2 events without
        // recv, then start the task. The task's first recv returns
        // Lagged → catch-up.
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(1);
        // Send two before spawning so the second overflows the channel
        // — receiver sees `Lagged(1)` on its first recv.
        let _ = sender.send(Arc::new(ingested_event(repo_id, 50)));
        let _ = sender.send(Arc::new(ingested_event(repo_id, 51)));
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            run(sub, deps, receiver, cancel_clone).await;
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should exit on cancel")
            .expect("task should not panic");
        // The catch-up after Lagged must have dispatched the seeded
        // event. Plus the catch-up at startup also dispatched it once.
        let calls = notifier_for_assert.calls().len();
        assert!(
            calls >= 1,
            "Lagged → catch-up must dispatch at least once; got {calls}"
        );
    }

    /// The gap that makes the broadcast a wake-up and not a payload: a
    /// live event carries a `global_position`, and delivering it
    /// directly would advance the cursor to that position over the
    /// transactional appends sitting below it — which is precisely the
    /// set the channel never carries. The wake-up must make the task
    /// read *from its cursor*, not from the event it was handed.
    #[tokio::test(start_paused = true)]
    async fn a_broadcast_wake_up_does_not_carry_the_cursor_past_unbroadcast_events() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(
            &sub,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es.clone(),
            principal,
        );
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move { run(sub, deps, receiver, task_cancel).await });
        tokio::time::sleep(Duration::from_millis(1)).await;

        // Position 1 is a transactional append: in the store, never on
        // the channel. Position 2 went through the publisher, so it is
        // in the store AND broadcast.
        let silent = ingested_event(repo_id, 1);
        let announced = ingested_event(repo_id, 2);
        mock_es.set_category(
            StreamCategory::Artifact,
            vec![silent.clone(), announced.clone()],
        );
        sender.send(Arc::new(announced)).expect("receiver attached");
        tokio::time::sleep(Duration::from_millis(10)).await;

        let delivered: Vec<u64> = notifier
            .calls()
            .iter()
            .flat_map(|(_, events)| events.iter().map(|e| e.global_position))
            .collect();
        assert_eq!(
            delivered,
            vec![1, 2],
            "the wake-up must deliver the silent append below it, not skip to the announced one"
        );

        cancel.cancel();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exits on cancel")
            .expect("task must not panic");
    }

    /// An exhausted budget during the startup pass must stop the task
    /// before it ever enters the delivery loop — the subscription is
    /// already `Disabled` by then.
    ///
    /// The budget is pre-loaded to one short of its threshold because a
    /// pass now makes exactly ONE delivery attempt before halting: the
    /// 100 failures the budget allows are 100 passes, so exhausting it
    /// from empty would take 100 ticks and say nothing about this branch.
    #[tokio::test(start_paused = true)]
    async fn run_stops_when_the_startup_catch_up_exhausts_the_budget() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(
            StreamCategory::Artifact,
            (1..=150u64).map(|i| ingested_event(repo_id, i)).collect(),
        );
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Failed {
            reason: NotifyFailureReason::Dns,
        }));
        let deps = make_deps(&sub, rbac, notifier, sub_repo.clone(), mock_es, principal);
        prime_budget_to_one_short_of_exhaustion(&deps);
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        // Never cancelled: the task must stop on its own.
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(async move { run(sub.clone(), deps, receiver, cancel).await });
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exits without cancellation")
            .expect("task must not panic");
        drop(sender);
        let row = sub_repo
            .rows
            .lock()
            .unwrap()
            .values()
            .next()
            .cloned()
            .unwrap();
        assert!(matches!(row.state, SubscriptionState::Disabled { .. }));
    }

    /// Same, one tick later: the pass now runs repeatedly, so a task
    /// that ignored the exhaust signal would keep delivering to a
    /// disabled subscription every 5 seconds forever.
    #[tokio::test(start_paused = true)]
    async fn run_stops_when_a_poll_tick_exhausts_the_budget() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Failed {
            reason: NotifyFailureReason::Dns,
        }));
        let deps = make_deps(
            &sub,
            rbac,
            notifier,
            sub_repo.clone(),
            mock_es.clone(),
            principal,
        );
        prime_budget_to_one_short_of_exhaustion(&deps);
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(async move { run(sub.clone(), deps, receiver, cancel).await });
        // Startup pass sees an empty store; the failing events arrive after.
        tokio::time::sleep(Duration::from_millis(1)).await;
        mock_es.set_category(
            StreamCategory::Artifact,
            (1..=150u64).map(|i| ingested_event(repo_id, i)).collect(),
        );
        tokio::time::timeout(Duration::from_secs(60), handle)
            .await
            .expect("task exits without cancellation")
            .expect("task must not panic");
        drop(sender);
        let row = sub_repo
            .rows
            .lock()
            .unwrap()
            .values()
            .next()
            .cloned()
            .unwrap();
        assert!(matches!(row.state, SubscriptionState::Disabled { .. }));
    }

    // -- the two defects this module was rewritten to close ---------------

    /// **A restart mid-pass must not seed over an unread event.**
    ///
    /// The persisted `last_delivered_position` is one scalar. A pass that
    /// walked `filter.categories` one at a time would deliver the
    /// *Artifact* event at 11 first (list order), persist 11, and a task
    /// respawning from that scalar would seed every category at
    /// `AfterGlobal(11)` — so the *Ref* event at 10, which nothing had
    /// read, is below the mark and never revisited. Nothing recovers it:
    /// no later read starts below the cursor, and the receiver never heard
    /// of it.
    ///
    /// The merged walk is what closes it. Reading the categories as one
    /// ordered stream means the mark is always a position in that stream,
    /// so a persist at P asserts only that everything up to P was read —
    /// which, in global order, is true.
    #[tokio::test(start_paused = true)]
    async fn a_restart_mid_pass_does_not_seed_over_an_unread_event_of_another_category() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let mut sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        // Ref listed second, and holding the LOWER position — the shape
        // that loses the event under a per-category walk.
        sub.filter.categories = vec![StreamCategory::Artifact, StreamCategory::Ref];
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());

        let mock_es = Arc::new(MockEventStore::new());
        let mut ref_event = ingested_event(repo_id, 10);
        ref_event.stream_id = StreamId {
            category: StreamCategory::Ref,
            entity_id: Uuid::new_v4(),
        };
        mock_es.set_category(StreamCategory::Ref, vec![ref_event]);
        mock_es.set_category(StreamCategory::Artifact, vec![ingested_event(repo_id, 11)]);

        // Life 1: the process dies right after its first delivery is
        // persisted.
        let life1_cancel = CancellationToken::new();
        let life1_notifier = Arc::new(CancelAfterFirstDelivery::new(life1_cancel.clone()));
        let deps = make_deps(
            &sub,
            rbac.clone(),
            life1_notifier.clone(),
            sub_repo.clone(),
            mock_es.clone(),
            principal.clone(),
        );
        let (sender1, receiver1) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let sub_for_life1 = sub.clone();
        let handle = tokio::spawn(async move {
            run(sub_for_life1, deps, receiver1, life1_cancel).await;
        });
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("life 1 stops when its notifier cancels it")
            .expect("task must not panic");
        drop(sender1);

        let life1_delivered = life1_notifier.delivered();
        let seed = sub_repo
            .rows
            .lock()
            .unwrap()
            .get(&sub.id)
            .cloned()
            .unwrap()
            .last_delivered_position;
        assert_eq!(
            life1_delivered,
            vec![10],
            "the merged walk delivers in global order, so the FIRST delivery — and \
             therefore the persisted position — is the lowest unread position, not the \
             lowest unread position of whichever category happens to be listed first"
        );
        assert_eq!(seed, Some(10));

        // Life 2: respawn from the persisted seed.
        let mut sub2 = sub.clone();
        sub2.last_delivered_position = seed;
        let life2_notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps2 = make_deps(
            &sub2,
            rbac,
            life2_notifier.clone(),
            sub_repo.clone(),
            mock_es,
            principal,
        );
        let (sender2, receiver2) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel2 = CancellationToken::new();
        let task_cancel = cancel2.clone();
        let handle2 = tokio::spawn(async move { run(sub2, deps2, receiver2, task_cancel).await });
        tokio::time::sleep(Duration::from_millis(1)).await;
        cancel2.cancel();
        drop(sender2);
        tokio::time::timeout(Duration::from_secs(2), handle2)
            .await
            .expect("life 2 exits on cancel")
            .expect("task must not panic");

        let mut seen: Vec<u64> = life1_delivered;
        seen.extend(
            life2_notifier
                .calls()
                .iter()
                .flat_map(|(_, evts)| evts.iter().map(|e| e.global_position)),
        );
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen,
            vec![10, 11],
            "every event in the store must reach the subscriber across the restart; \
             a position missing here is a permanent gap"
        );
    }

    /// A subscription whose very first delivery fails has no earlier
    /// position to checkpoint, and must not invent one.
    ///
    /// `None` is the honest answer and the adapter treats it as "leave the
    /// column alone". Writing this event's position would be the F2 defect
    /// in its purest form; writing `0` would work only by the coincidence
    /// that `global_position` starts at 1.
    #[tokio::test]
    async fn a_failed_first_delivery_records_the_failure_without_inventing_a_position() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
        let principal = dev_principal(owner_user_id);
        let sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
        assert_eq!(sub.last_delivered_position, None, "fresh subscription");
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        mock_es.set_category(StreamCategory::Artifact, vec![ingested_event(repo_id, 7)]);
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Failed {
            reason: NotifyFailureReason::Dns,
        }));
        let deps = make_deps(&sub, rbac, notifier, sub_repo.clone(), mock_es, principal);
        let cancel = CancellationToken::new();
        let mut cursor = ReadCursor::new(sub.last_delivered_position);
        let exit = catch_up(sub.id, &deps, &cancel, &mut cursor).await;
        assert!(!exit);
        let progress = sub_repo.progress_calls();
        assert_eq!(progress.len(), 1, "a failure persists immediately");
        assert_eq!(
            progress[0].1, None,
            "there is no position before the first event, so none is written"
        );
        assert!(progress[0].2.is_some(), "the failure itself is recorded");
        let row = sub_repo.rows.lock().unwrap().get(&sub.id).cloned().unwrap();
        assert_eq!(row.last_delivered_position, None);
        assert!(matches!(cursor.read_from(), SubscribeFrom::Start));
    }

    /// A hint naming a category outside the filter must not cost a store
    /// read.
    ///
    /// Observable as latency: the store holds an event this subscription
    /// *would* deliver, and the unsubscribed hint must leave it there
    /// until the tick. The dispatcher subscribes one receiver per task to
    /// a channel every publisher-path append goes onto — throttled auth
    /// audit, per-download audit, token use, the retention sweep's bulk
    /// expiries — so an unfiltered wake-up turns one append into one read
    /// per subscription in the process.
    #[tokio::test(start_paused = true)]
    async fn a_hint_for_an_unsubscribed_category_does_not_trigger_a_store_read() {
        let owner_user_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let rbac = Arc::new(ArcSwap::from_pointee(empty_eval()));
        let principal = admin_principal(owner_user_id);
        let mut sub = make_subscription(owner_user_id, RepositoryScope::All);
        sub.filter.categories = vec![StreamCategory::Policy];
        let sub_repo = Arc::new(MockSubRepo::new());
        sub_repo.insert(sub.clone());
        let mock_es = Arc::new(MockEventStore::new());
        let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
        let deps = make_deps(
            &sub,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es.clone(),
            principal,
        );
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move { run(sub, deps, receiver, task_cancel).await });
        tokio::time::sleep(Duration::from_millis(1)).await;

        // A deliverable Policy event is waiting in the store.
        let mut policy = ingested_event(repo_id, 1);
        policy.stream_id = StreamId {
            category: StreamCategory::Policy,
            entity_id: Uuid::new_v4(),
        };
        mock_es.set_category(StreamCategory::Policy, vec![policy.clone()]);

        // An Artifact append announces itself. This subscription does not
        // read Artifact, so the hint says nothing about its stream.
        sender
            .send(Arc::new(ingested_event(repo_id, 2)))
            .expect("receiver attached");
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            notifier.calls().is_empty(),
            "an unsubscribed category's hint must not wake a read"
        );

        // A hint on a subscribed category does.
        sender.send(Arc::new(policy)).expect("receiver attached");
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            notifier.calls().len(),
            1,
            "a subscribed category's hint is still a wake-up"
        );

        cancel.cancel();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exits on cancel")
            .expect("task must not panic");
    }

    /// A failed read is fail-closed AND alertable.
    ///
    /// Leaving the mark put is the correct half — nothing is skipped. But
    /// a read that fails deterministically (one row this build cannot
    /// decode, which a mixed-version rollout produces) then retries the
    /// same page every tick forever, delivering nothing, and a `warn!` per
    /// tick is not something an operator can alert on.
    #[test]
    fn a_failed_catch_up_read_increments_the_alertable_counter() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    let owner_user_id = Uuid::new_v4();
                    let repo_id = Uuid::new_v4();
                    let rbac = Arc::new(ArcSwap::from_pointee(eval_with_repo_read(repo_id)));
                    let principal = dev_principal(owner_user_id);
                    let mut sub = make_subscription(owner_user_id, RepositoryScope::OwnedByActor);
                    sub.last_delivered_position = Some(5);
                    let sub_repo = Arc::new(MockSubRepo::new());
                    sub_repo.insert(sub.clone());
                    let mock_es = Arc::new(MockEventStore::new());
                    mock_es
                        .set_category(StreamCategory::Artifact, vec![ingested_event(repo_id, 6)]);
                    mock_es.inject_category_error_after_global_position(5);
                    let notifier = Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered));
                    let deps = make_deps(&sub, rbac, notifier, sub_repo, mock_es, principal);
                    let cancel = CancellationToken::new();
                    let mut cursor = ReadCursor::new(sub.last_delivered_position);
                    assert!(!catch_up(sub.id, &deps, &cancel, &mut cursor).await);
                });
        });

        let read_errors = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, _, _, _)| key.key().name() == "hort_notify_store_read_errors_total")
            .map(|(_, _, _, value)| value);
        assert!(
            matches!(read_errors, Some(DebugValue::Counter(1))),
            "a failed read must leave an alertable signal, not only a log line; got \
             {read_errors:?}"
        );
    }

    #[test]
    fn check_target_kind_helper_compiles() {
        // Smoke for the `_check_target_kind_helper_compiles` fn used as
        // a static-shape anchor.
        _check_target_kind_helper_compiles();
    }
}
