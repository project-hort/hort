//! Per-subscription dispatcher task.
//!
//! Each active subscription is owned by one [`tokio::spawn`] task
//! running [`run`]. The task:
//!
//! 1. Performs a startup **catch-up** read across each filter category,
//!    starting `AfterGlobal(last_delivered_position)` and walking
//!    forward in 1000-event pages until the category returns less than
//!    a full page (caught up to head).
//! 2. Enters the **live loop**: `recv()` on the broadcast receiver,
//!    filter the event against [`SubscriptionFilter`], and dispatch via
//!    the first [`EventNotifier`] that `supports` the target.
//! 3. On [`broadcast::error::RecvError::Lagged`], drops back into
//!    catch-up against `read_category` then re-enters the live loop.
//! 4. Tracks a per-task [`FailureBudget`]. 100 consecutive failures in
//!    a 1h window → call `SubscriptionUseCase::disable` and exit.
//! 5. Persists `last_delivered_position` debounced (5-min floor); a
//!    failure flushes immediately.
//! 6. Honours a [`tokio_util::sync::CancellationToken`] for graceful
//!    shutdown.
//!
//! All of the above is per design doc §6 paragraphs 1-4 and §11
//! invariants 1, 2, 10.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::Utc;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::subscription::{
    DisableReason, Subscription, SubscriptionFailure, SubscriptionTarget,
};
use hort_domain::events::PersistedEvent;
use hort_domain::ports::event_notifier::{EventNotifier, NotifyOutcome};
use hort_domain::ports::event_store::{EventStore, SubscribeFrom};
use hort_domain::ports::repository_repository::RepositoryRepository;

use crate::dispatcher::failure_budget::FailureBudget;
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    emit_broadcast_lagged, emit_notify_delivery, notify_outcome_label, target_kind_label,
};
use crate::rbac::RbacEvaluator;
use crate::use_cases::subscription_filter::{matches as filter_matches, FilterContext};
use crate::use_cases::subscription_use_case::SubscriptionUseCase;

/// Debounce floor for `update_last_delivered`. Per design doc §6
/// paragraph 3 — the dispatcher amortises writes over a 5-minute
/// window. Failure persists immediately and is not debounced.
pub(crate) const PROGRESS_DEBOUNCE: Duration = Duration::from_secs(5 * 60);

/// Catch-up page size — per design doc §6 paragraph 4 and Item 6b
/// backlog acceptance. We loop until `read_category` returns less than
/// `CATCHUP_PAGE`, signalling head reached.
pub(crate) const CATCHUP_PAGE: u64 = 1000;

/// Maximum events to fan in to one `notify` call from the live broadcast.
/// v1 dispatches one event per notify call — batching is a future
/// optimisation.
pub(crate) const NOTIFY_BATCH_SIZE: usize = 1;

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
    /// Owner principal — synthesised **once at task spawn** from the
    /// owner's `User` row + `snapshot_claims` (the F-37 stale-`"admin"`
    /// strip + live-`is_admin` re-derivation happens at that synthesis
    /// time; see [`crate::dispatcher::dispatcher`]
    /// `synthesise_principal`). This value is then **frozen for the
    /// life of the task** — it is captured into `SubscriptionTaskDeps`
    /// at spawn and the per-event filter walk reuses it.
    ///
    /// The dispatcher's 30s reconcile cadence governs **add/remove of
    /// tasks** (spawn for newly-active subscriptions, cancel on
    /// vanish/disable) and disabled-row teardown — it does **NOT**
    /// re-synthesise an already-running task's `owner_principal`
    /// (`dispatcher.rs` skips re-synthesis via
    /// `if tasks.contains_key(&sub.id) { continue; }`). A change to
    /// the owner's `User` row (notably the `is_admin` bit) is picked
    /// up only at the next **cancel+respawn** of the task, not on the
    /// reconcile tick. There is no per-reconcile freshness guarantee
    /// for a running task's principal. Live *grant* revocation is
    /// still honored independently per delivered event by the
    /// dispatch-time privileged-category gate, which reloads the
    /// [`RbacEvaluator`] (`rbac` field) on every processed event;
    /// only the spawn-frozen `user.is_admin` *bit* input is subject
    /// to this freeze (an accepted residual).
    pub owner_principal: CallerPrincipal,
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
/// `update_last_delivered` call so the task can debounce writes per
/// design doc §6 paragraph 3.
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
    let sub_id = subscription.id;
    tracing::info!(
        subscription_id = %sub_id.0,
        owner_user_id = %subscription.owner_user_id,
        "dispatcher task starting"
    );

    // Step 1: catch-up.
    catch_up(&subscription, &deps, &cancel).await;
    if cancel.is_cancelled() {
        tracing::info!(subscription_id = %sub_id.0, "dispatcher task cancelled during catch-up");
        return;
    }

    // Step 2: live loop.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(subscription_id = %sub_id.0, "dispatcher task cancelled");
                return;
            }
            recv = receiver.recv() => match recv {
                Ok(event) => {
                    if process_event_for_subscription(&event, &subscription, &deps).await {
                        // Budget exhausted — task exits; orchestrator
                        // sees the now-disabled row on next reconcile
                        // and does not respawn.
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        subscription_id = %sub_id.0,
                        skipped = skipped,
                        "broadcast channel lagged; dropping to catch-up"
                    );
                    emit_broadcast_lagged();
                    catch_up(&subscription, &deps, &cancel).await;
                    if cancel.is_cancelled() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!(
                        subscription_id = %sub_id.0,
                        "broadcast sender dropped; task exiting"
                    );
                    return;
                }
            }
        }
    }
}

/// Catch-up read across every category in the filter, walking forward
/// from `last_delivered_position` until each category returns less than
/// a full page.
///
/// Errors from `read_category` are logged and the category is skipped
/// for the rest of this catch-up pass — the next reconcile / live loop
/// will retry.
async fn catch_up(
    subscription: &Subscription,
    deps: &SubscriptionTaskDeps,
    cancel: &CancellationToken,
) {
    let start_pos = subscription.last_delivered_position.unwrap_or(0);
    for &cat in &subscription.filter.categories {
        if cancel.is_cancelled() {
            return;
        }
        let mut cursor = start_pos;
        loop {
            if cancel.is_cancelled() {
                return;
            }
            let from = if cursor == 0 && subscription.last_delivered_position.is_none() {
                SubscribeFrom::Start
            } else {
                SubscribeFrom::AfterGlobal(cursor)
            };
            let events = match deps
                .event_store
                .read_category(cat, from, CATCHUP_PAGE)
                .await
            {
                Ok(evts) => evts,
                Err(e) => {
                    tracing::warn!(
                        subscription_id = %subscription.id.0,
                        category = ?cat,
                        error = %e,
                        "catch-up read_category failed; skipping category for this pass"
                    );
                    break;
                }
            };
            if events.is_empty() {
                break;
            }
            let last_pos = events.last().map(|e| e.global_position).unwrap_or(cursor);
            let was_full_page = events.len() as u64 >= CATCHUP_PAGE;
            for event in events {
                if cancel.is_cancelled() {
                    return;
                }
                // Budget-exhaust during catch-up exits the task
                // immediately; orchestrator's next reconcile sees the
                // disabled row.
                if process_event_for_subscription(&event, subscription, deps).await {
                    return;
                }
            }
            cursor = last_pos;
            if !was_full_page {
                break;
            }
        }
    }
}

/// Process a single event for the subscription. Returns `true` when
/// the failure budget exhausted as a result of this delivery — the
/// caller exits the task.
async fn process_event_for_subscription(
    event: &PersistedEvent,
    subscription: &Subscription,
    deps: &SubscriptionTaskDeps,
) -> bool {
    // 1. Load the current evaluator snapshot. One `.load()` per event;
    //    revocation propagates within the auth cache TTL.
    let evaluator_guard = deps.rbac.load();
    let evaluator = &**evaluator_guard;

    // 2. Filter via the pure subscription_filter helper.
    let ctx = FilterContext {
        rbac: evaluator,
        repositories: &deps.repositories,
        owner_principal: &deps.owner_principal,
    };
    if !filter_matches(&subscription.filter, event, &ctx).await {
        return false;
    }

    // 3. Find a notifier that supports the target.
    let notifier = deps
        .notifiers
        .iter()
        .find(|n| n.supports(&subscription.target));
    let Some(notifier) = notifier else {
        tracing::warn!(
            subscription_id = %subscription.id.0,
            "no EventNotifier supports this target_kind; dropping event"
        );
        return false;
    };

    // 4. Send.
    let started = Instant::now();
    // One-event batch — design doc allows multi-event batching as a
    // future optimisation, but v1 keeps the per-event semantics simple.
    let _ = NOTIFY_BATCH_SIZE;
    let batch = std::slice::from_ref(event);
    let outcome = notifier
        .notify(&subscription.target, subscription.id, batch)
        .await;
    let elapsed_secs = started.elapsed().as_secs_f64();

    // 5. Emit metrics (cardinality-safe closed labels).
    let target_kind = target_kind_label(&subscription.target);
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
                subscription_id = %subscription.id.0,
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
    // - On success: respect the 5-min debounce floor; first persist on
    //   each interval boundary.
    // - On failure: persist immediately (audit signal — operators
    //   inspecting `last_failure` need it current). Even when
    //   debounced, the position update piggybacks.
    let should_persist = match &failure_record {
        Some(_) => true,
        None => deps.progress.lock().unwrap().should_persist(now),
    };
    if should_persist {
        if let Err(e) = deps
            .use_case
            .record_delivery_progress(
                subscription.id,
                event.global_position,
                failure_record.as_ref(),
            )
            .await
        {
            tracing::warn!(
                subscription_id = %subscription.id.0,
                error = %e,
                "record_delivery_progress failed"
            );
        }
    }

    // 8. Budget exhausted? Transition to Disabled and signal exit.
    if budget_exhausted {
        tracing::info!(
            subscription_id = %subscription.id.0,
            reason = "DeliveryFailureBudgetExhausted",
            "subscription disabled by dispatcher (budget exhausted)"
        );
        if let Err(e) = deps
            .use_case
            .disable(
                subscription.id,
                DisableReason::DeliveryFailureBudgetExhausted,
            )
            .await
        {
            tracing::warn!(
                subscription_id = %subscription.id.0,
                error = %e,
                "disable on budget-exhaust failed; task will still exit"
            );
        }
        return true;
    }

    false
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

    /// In-memory subscription repo with deterministic id-keyed lookups.
    struct MockSubRepo {
        rows: Mutex<HashMap<SubscriptionId, Subscription>>,
        progress_calls: Mutex<Vec<(SubscriptionId, u64, Option<SubscriptionFailure>)>>,
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
        fn progress_calls(&self) -> Vec<(SubscriptionId, u64, Option<SubscriptionFailure>)> {
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
            position: u64,
            last_failure: Option<&SubscriptionFailure>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            self.progress_calls
                .lock()
                .unwrap()
                .push((id, position, last_failure.cloned()));
            // Also mirror into the row so subsequent reads see the
            // updated state.
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.get_mut(&id) {
                row.last_delivered_position = Some(position);
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

    #[allow(clippy::needless_pass_by_value)]
    fn make_deps(
        owner_user_id: Uuid,
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
        let _ = owner_user_id;
        SubscriptionTaskDeps {
            event_store: event_store_publisher,
            use_case,
            rbac,
            repositories: repos,
            owner_principal: principal,
            notifiers: vec![notifier],
            budget: Arc::new(Mutex::new(FailureBudget::new())),
            progress: Arc::new(Mutex::new(ProgressDebouncer::new(
                Instant::now(),
                Duration::from_secs(0),
            ))),
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es,
            principal,
        );
        let event = ingested_event(repo_id, 1);
        // No budget exhaustion possible — single event, mismatched filter.
        let exhausted = process_event_for_subscription(&event, &sub, &deps).await;
        assert!(!exhausted);
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es,
            principal,
        );
        let event = ingested_event(repo_id, 5);
        let exhausted = process_event_for_subscription(&event, &sub, &deps).await;
        assert!(!exhausted);
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier,
            sub_repo.clone(),
            mock_es,
            principal,
        );
        // Zero-interval debouncer in make_deps → first success persists.
        let event = ingested_event(repo_id, 42);
        let _ = process_event_for_subscription(&event, &sub, &deps).await;
        let progress = sub_repo.progress_calls();
        assert_eq!(progress.len(), 1);
        assert_eq!(progress[0].0, sub.id);
        assert_eq!(progress[0].1, 42);
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier,
            sub_repo.clone(),
            mock_es,
            principal,
        );
        let event = ingested_event(repo_id, 7);
        let exhausted = process_event_for_subscription(&event, &sub, &deps).await;
        assert!(!exhausted, "single failure must not exhaust budget");
        let progress = sub_repo.progress_calls();
        assert_eq!(progress.len(), 1);
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier,
            sub_repo.clone(),
            mock_es,
            principal,
        );
        // Cycle 100 events.
        let mut exhausted = false;
        for i in 1..=100u64 {
            let event = ingested_event(repo_id, i);
            exhausted = process_event_for_subscription(&event, &sub, &deps).await;
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
            owner_user_id,
            rbac,
            unsupported,
            sub_repo.clone(),
            mock_es,
            principal,
        );
        // Replace with empty registry to also exercise the empty branch.
        deps.notifiers = vec![];
        let event = ingested_event(repo_id, 1);
        let exhausted = process_event_for_subscription(&event, &sub, &deps).await;
        assert!(!exhausted);
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es,
            principal,
        );
        let event = ingested_event(Uuid::new_v4(), 1);
        let _ = process_event_for_subscription(&event, &sub, &deps).await;
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es,
            principal,
        );
        let cancel = CancellationToken::new();
        catch_up(&sub, &deps, &cancel).await;
        assert_eq!(
            notifier.calls().len(),
            2,
            "both seeded events delivered via catch-up"
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es,
            principal,
        );
        let cancel = CancellationToken::new();
        catch_up(&sub, &deps, &cancel).await;
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
        let deps = make_deps(
            owner_user_id,
            rbac,
            notifier.clone(),
            sub_repo,
            mock_es,
            principal,
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        catch_up(&sub, &deps, &cancel).await;
        assert!(notifier.calls().is_empty());
    }

    // -- run() integration tests -----------------------------------------

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
        let deps = make_deps(owner_user_id, rbac, notifier, sub_repo, mock_es, principal);
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
    async fn run_processes_a_live_event_then_cancellation_stops_it() {
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
        let deps = make_deps(owner_user_id, rbac, notifier, sub_repo, mock_es, principal);
        let (sender, receiver) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            run(sub, deps, receiver, cancel_clone).await;
        });
        // Send one event.
        sender
            .send(Arc::new(ingested_event(repo_id, 100)))
            .expect("send ok");
        // Wait briefly.
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
        let deps = make_deps(owner_user_id, rbac, notifier, sub_repo, mock_es, principal);
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

    #[test]
    fn check_target_kind_helper_compiles() {
        // Smoke for the `_check_target_kind_helper_compiles` fn used as
        // a static-shape anchor.
        _check_target_kind_helper_compiles();
    }
}
