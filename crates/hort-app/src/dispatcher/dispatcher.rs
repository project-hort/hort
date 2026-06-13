//! Top-level `NotificationDispatcher`.
//!
//! Spawns one [`subscription_task::run`](crate::dispatcher::subscription_task::run)
//! task per active subscription. Refreshes the task set every 30s OR
//! on a [`SubscriptionChangeListener`] event. Per-task cancellation
//! tokens are children of the dispatcher's cancellation token so a
//! single `cancel.cancel()` propagates to every task on shutdown.
//!
//! See `docs/architecture/explanation/event-notifications.md`.
//!
//! # Wiring
//!
//! - The publisher's broadcast sender is the source of every live
//!   event delivered to a task. `EventStorePublisher::subscribe()`
//!   returns `None` when notifications are disabled — in that case the
//!   dispatcher should not be started. The defensive code path here
//!   spawns a task with a closed receiver so the task exits cleanly
//!   without dispatching anything.
//! - Subscription reconciliation runs against
//!   [`SubscriptionRepository::list_active`]; vanished subscriptions
//!   have their per-task cancellation token fired, and new ones get a
//!   spawn.
//! - Owner-principal synthesis happens once **at task spawn**, not
//!   every reconcile. The dispatcher loads the owner's `User` row via
//!   [`UserRepository::find_by_id`] and synthesises a
//!   [`CallerPrincipal`] from `subscription.snapshot_claims` with the
//!   stale-`"admin"` strip + live-`is_admin` re-derivation (ADR 0012).
//!   The 30s reconcile governs add/remove of tasks and
//!   disabled-row teardown — it does **not** re-synthesise an
//!   already-running task's principal. Live *grant* revocation is
//!   still honored per delivered event via the `RbacEvaluator`
//!   reload; only the spawn-frozen `is_admin`-bit input is not
//!   refreshed until cancel+respawn (bounded accepted residual).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::Utc;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::subscription::{Subscription, SubscriptionId, SubscriptionState};
use hort_domain::events::PersistedEvent;
use hort_domain::ports::event_notifier::EventNotifier;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::subscription_change_listener::SubscriptionChangeListener;
use hort_domain::ports::subscription_repository::SubscriptionRepository;
use hort_domain::ports::user_repository::UserRepository;

use crate::dispatcher::failure_budget::FailureBudget;
use crate::dispatcher::subscription_task::{
    self, ProgressDebouncer, SubscriptionTaskDeps, PROGRESS_DEBOUNCE,
};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    emit_dispatcher_principal_resolved, set_subscription_state_gauge, DispatcherPrincipalSource,
};
use crate::rbac::{add_admin_claim_if_admin, RbacEvaluator};
use crate::use_cases::subscription_use_case::SubscriptionUseCase;

/// Reconcile interval.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Initial backoff applied after a [`SubscriptionChangeListener::recv`]
/// failure. Doubles on each consecutive failure up to
/// [`LISTEN_BACKOFF_CAP`]; resets to the floor on the next successful
/// `recv`.
const LISTEN_BACKOFF_FLOOR: Duration = Duration::from_millis(200);

/// Cap on the listener-failure backoff. Mirrors [`RECONCILE_INTERVAL`]
/// — beyond that point the periodic reconcile catches the missed
/// change anyway, so longer waits are pointless.
const LISTEN_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Compute the next listener backoff value, doubling and clamped at
/// [`LISTEN_BACKOFF_CAP`]. Pure so the cap branch is unit-testable
/// without relying on wall-clock multiplication semantics. Mirrors
/// [`hort_adapters_postgres::api_token_revocation_listener::next_backoff`]'s
/// shape — same precedent the project already uses for LISTEN-loop
/// flap suppression.
fn next_backoff(current: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > LISTEN_BACKOFF_CAP {
        LISTEN_BACKOFF_CAP
    } else {
        doubled
    }
}

/// Top-level dispatcher. Owns the shared dependencies and the active
/// per-subscription task map.
pub struct NotificationDispatcher {
    publisher: Arc<EventStorePublisher>,
    use_case: Arc<SubscriptionUseCase>,
    rbac: Arc<ArcSwap<RbacEvaluator>>,
    user_repo: Arc<dyn UserRepository>,
    subscription_repo: Arc<dyn SubscriptionRepository>,
    repository_repo: Arc<dyn RepositoryRepository>,
    change_listener: Arc<dyn SubscriptionChangeListener>,
    notifiers: Vec<Arc<dyn EventNotifier>>,
}

impl NotificationDispatcher {
    /// Construct a dispatcher. Composition root wires this at startup
    /// when `HORT_NOTIFICATIONS_ENABLED=true`; with the flag off, do NOT
    /// construct one.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publisher: Arc<EventStorePublisher>,
        use_case: Arc<SubscriptionUseCase>,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
        user_repo: Arc<dyn UserRepository>,
        subscription_repo: Arc<dyn SubscriptionRepository>,
        repository_repo: Arc<dyn RepositoryRepository>,
        change_listener: Arc<dyn SubscriptionChangeListener>,
        notifiers: Vec<Arc<dyn EventNotifier>>,
    ) -> Self {
        Self {
            publisher,
            use_case,
            rbac,
            user_repo,
            subscription_repo,
            repository_repo,
            change_listener,
            notifiers,
        }
    }

    /// Run the dispatcher loop until `cancel` is triggered.
    ///
    /// Returns when the cancellation token fires. All per-subscription
    /// tasks are cancelled on shutdown (via child cancellation tokens).
    pub async fn run(self, cancel: CancellationToken) {
        let mut tasks: HashMap<SubscriptionId, TaskHandle> = HashMap::new();
        let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
        // The first `tick` fires immediately — that's the initial
        // reconcile pass.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Exponential backoff state for the `change_listener.recv()`
        // error branch. Starts at the floor;
        // doubles via `next_backoff` after each consecutive failure;
        // resets to the floor on a successful `recv`. The cap matches
        // the reconcile interval — beyond that the periodic tick
        // catches missed work anyway.
        let mut listen_backoff = LISTEN_BACKOFF_FLOOR;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("dispatcher shutdown; cancelling all subscription tasks");
                    for (_, handle) in tasks.drain() {
                        handle.cancel.cancel();
                    }
                    return;
                }
                _ = interval.tick() => {
                    self.reconcile(&mut tasks, &cancel).await;
                }
                change = self.change_listener.recv() => {
                    match change {
                        Ok(event) => {
                            tracing::debug!(
                                subscription_id = ?event.subscription_id,
                                "subscription_changes received; reconciling"
                            );
                            listen_backoff = LISTEN_BACKOFF_FLOOR;
                            self.reconcile(&mut tasks, &cancel).await;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                backoff_ms = %listen_backoff.as_millis(),
                                "change listener recv error; will retry after backoff (next reconcile tick still fires)"
                            );
                            // Avoid a hot error loop starving the
                            // cancel branch. The flat 200ms previously
                            // here thrashed at 5 Hz under a sustained
                            // outage; exponential backoff capped at
                            // the reconcile period suppresses the
                            // flap without delaying genuine recovery
                            // (the next reconcile tick catches up
                            // whatever the listener missed).
                            //
                            // Make the sleep cancellable so a shutdown
                            // during a long backoff returns promptly
                            // — biased to cancel so it always wins on
                            // race.
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => {
                                    tracing::info!("dispatcher shutdown during listen backoff");
                                    for (_, handle) in tasks.drain() {
                                        handle.cancel.cancel();
                                    }
                                    return;
                                }
                                _ = tokio::time::sleep(listen_backoff) => {}
                            }
                            listen_backoff = next_backoff(listen_backoff);
                        }
                    }
                }
            }
        }
    }

    /// Reconcile the per-subscription task map against the current
    /// `list_active` result. Spawn missing tasks, cancel vanished
    /// ones, leave the rest alone. Best-effort: a `list_active` error
    /// is logged and the current task set is kept; subsequent
    /// reconciles will retry.
    async fn reconcile(
        &self,
        tasks: &mut HashMap<SubscriptionId, TaskHandle>,
        parent_cancel: &CancellationToken,
    ) {
        let active = match self.subscription_repo.list_active().await {
            Ok(subs) => subs,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "list_active failed; keeping existing task set"
                );
                return;
            }
        };
        let active_ids: HashSet<SubscriptionId> = active.iter().map(|s| s.id).collect();

        // Cancel vanished.
        let vanished: Vec<SubscriptionId> = tasks
            .keys()
            .filter(|id| !active_ids.contains(id))
            .copied()
            .collect();
        for id in vanished {
            if let Some(handle) = tasks.remove(&id) {
                tracing::info!(
                    subscription_id = %id.0,
                    "subscription vanished; cancelling task"
                );
                handle.cancel.cancel();
            }
        }

        // Refresh the state gauge — even if list_active returned an
        // empty vec we still want to surface zero.
        emit_state_gauge(&active);

        // Spawn new.
        for sub in active {
            if tasks.contains_key(&sub.id) {
                continue;
            }
            let task_cancel = parent_cancel.child_token();
            let Some(principal) = self.synthesise_principal(&sub).await else {
                continue;
            };
            let deps = SubscriptionTaskDeps {
                event_store: self.publisher.clone(),
                use_case: self.use_case.clone(),
                rbac: self.rbac.clone(),
                repositories: self.repository_repo.clone(),
                owner_principal: principal,
                notifiers: self.notifiers.clone(),
                budget: Arc::new(Mutex::new(FailureBudget::new())),
                progress: Arc::new(Mutex::new(ProgressDebouncer::new(
                    Instant::now(),
                    PROGRESS_DEBOUNCE,
                ))),
            };
            let receiver = self.publisher.subscribe().unwrap_or_else(degraded_receiver);
            let sub_id = sub.id;
            let task_cancel_for_task = task_cancel.clone();
            let handle = tokio::spawn(async move {
                subscription_task::run(sub, deps, receiver, task_cancel_for_task).await;
            });
            tasks.insert(
                sub_id,
                TaskHandle {
                    join: handle,
                    cancel: task_cancel,
                },
            );
        }
    }

    /// Build the per-task `CallerPrincipal` from the owner's User row
    /// and the subscription's `snapshot_claims` authority floor.
    /// Returns `None` (skipping the task spawn) if the owner is
    /// unknown, the lookup fails, or the owner is deactivated — those
    /// signal stale state that the next reconcile will resolve.
    ///
    /// # Claim resolution
    ///
    /// The creator's resolved `principal.claims` are snapshotted onto
    /// the subscription at create / update time (`SubscriptionUseCase`);
    /// the dispatcher's job is purely **"apply the snapshot"**.
    /// Resolution happens once, at create / update, against
    /// `claim_mappings`; it is NOT re-resolved per event here. The
    /// dispatcher therefore holds no `Vec<ClaimMapping>` and does not
    /// consult `claim_mappings` — the snapshot is the source of truth
    /// at this layer (ADR 0012).
    ///
    /// The synthesised claim set is `sub.snapshot_claims` with the
    /// synthetic `"admin"` claim **re-derived from the live
    /// `user.is_admin` bit**, never trusted from the snapshot: any
    /// stale `"admin"` carried in `snapshot_claims` (e.g. a
    /// PATCH-via-PAT `["admin"]` replacement performed by a then-admin
    /// actor whose admin was later revoked) is stripped, then
    /// re-added iff the owner is *currently* admin
    /// ([`add_admin_claim_if_admin`]). This keeps the `User.is_admin`
    /// bit and the `"admin"` claim in sync by construction:
    /// combined with the dispatch-time privileged-category
    /// gate in [`crate::use_cases::subscription_filter::matches`] step
    /// 4, a snapshot elevated to `["admin"]`
    /// cannot retroactively unlock a privileged category against an
    /// owner who is not currently admin.
    async fn synthesise_principal(&self, sub: &Subscription) -> Option<CallerPrincipal> {
        match self.user_repo.find_by_id(sub.owner_user_id).await {
            Ok(user) => {
                if !user.is_active {
                    tracing::info!(
                        subscription_id = %sub.id.0,
                        owner_user_id = %sub.owner_user_id,
                        "owner deactivated; skipping task spawn"
                    );
                    return None;
                }
                // Apply the per-subscription
                // `snapshot_claims` authority floor resolved at
                // create/update time. The synthetic `"admin"` claim is
                // re-derived from the live `user.is_admin` bit (any
                // stale snapshot `"admin"` stripped first) — see fn doc.
                let snapshot_was_present = !sub.snapshot_claims.is_empty();
                let mut claims: Vec<String> = sub
                    .snapshot_claims
                    .iter()
                    .filter(|c| c.as_str() != "admin")
                    .cloned()
                    .collect();
                add_admin_claim_if_admin(&mut claims, user.is_admin);

                // Classify how the principal was resolved
                // (3-series counter; no per-subscription labels).
                let source = if snapshot_was_present {
                    DispatcherPrincipalSource::SnapshotPresent
                } else if user.is_admin {
                    DispatcherPrincipalSource::SnapshotEmptyAdmin
                } else {
                    DispatcherPrincipalSource::SnapshotEmptyNoAdmin
                };
                emit_dispatcher_principal_resolved(source);

                Some(CallerPrincipal {
                    user_id: user.id,
                    external_id: user
                        .external_id
                        .clone()
                        .unwrap_or_else(|| user.id.to_string()),
                    username: user.username.clone(),
                    email: user.email.clone(),
                    claims,
                    token_kind: None,
                    issued_at: Utc::now(),
                    token_cap: None,
                })
            }
            Err(e) => {
                tracing::warn!(
                    subscription_id = %sub.id.0,
                    owner_user_id = %sub.owner_user_id,
                    error = %e,
                    "owner user lookup failed; skipping task spawn"
                );
                None
            }
        }
    }
}

/// Per-task management handle.
struct TaskHandle {
    /// JoinHandle kept around for shutdown ordering; we do not await
    /// it here (the dispatcher's `cancel.cancel()` is the signal; the
    /// task body returns shortly thereafter).
    #[allow(dead_code)]
    join: JoinHandle<()>,
    cancel: CancellationToken,
}

/// Build a degraded-state broadcast receiver — a closed channel that
/// immediately yields `Err(Closed)`. Used when the publisher has no
/// broadcast sender (notifications disabled at composition root); the
/// task body sees Closed and exits cleanly.
fn degraded_receiver() -> broadcast::Receiver<Arc<PersistedEvent>> {
    let (tx, rx) = broadcast::channel(1);
    drop(tx);
    rx
}

/// Refresh `hort_subscription_total{state}` from the current
/// `list_active` snapshot. NOTE: `list_active` only returns active
/// rows — paused / disabled counts are zero from this perspective.
/// Operators that want a full breakdown either query SQL directly or
/// wait for the future per-state list method.
fn emit_state_gauge(active: &[Subscription]) {
    // For v1, list_active by definition only returns Active rows; the
    // gauge surfaces that explicit count. Paused / Disabled subscriptions
    // are not visible to this reconcile, so we don't fabricate zeros for
    // them — emitting only the active count keeps the gauge truthful.
    let active_count = active
        .iter()
        .filter(|s| matches!(s.state, SubscriptionState::Active))
        .count() as u64;
    set_subscription_state_gauge("active", active_count);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use chrono::Utc;
    use hort_domain::entities::subscription::{
        EventTypeFilter, RepositoryScope, SubscriptionFilter, SubscriptionState, SubscriptionTarget,
    };
    use hort_domain::entities::user::{AuthProvider, User};
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::events::PersistedEvent;
    use hort_domain::events::StreamCategory;
    use hort_domain::ports::event_notifier::{EventNotifier, NotifyOutcome};
    use hort_domain::ports::subscription_change_listener::SubscriptionChangeEvent;
    use hort_domain::ports::webhook_target_guard::WebhookTargetGuard;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::{Page, PageRequest};
    use url::Url;
    use uuid::Uuid;

    use crate::use_cases::subscription_use_case::{SubscriptionUseCase, SubscriptionUseCaseConfig};
    use crate::use_cases::test_support::{
        MockEventStore, MockRepositoryRepository, MockUserRepository,
    };

    // -- Local recording notifier (test-only) --------------------------

    struct RecordingNotifier {
        outcome: NotifyOutcome,
    }
    impl RecordingNotifier {
        fn new(outcome: NotifyOutcome) -> Self {
            Self { outcome }
        }
    }
    impl EventNotifier for RecordingNotifier {
        fn notify<'a>(
            &'a self,
            _t: &'a SubscriptionTarget,
            _subscription_id: SubscriptionId,
            _e: &'a [PersistedEvent],
        ) -> BoxFuture<'a, NotifyOutcome> {
            let outcome = self.outcome.clone();
            Box::pin(async move { outcome })
        }
        fn supports(&self, _t: &SubscriptionTarget) -> bool {
            true
        }
    }

    // -- Mock SubscriptionChangeListener --------------------------------

    /// Listener that never sends — every `recv()` is a pending future
    /// (the dispatcher only consults the listener when its other
    /// branches are quiet).
    struct NeverChangeListener;
    impl SubscriptionChangeListener for NeverChangeListener {
        fn recv(&self) -> BoxFuture<'_, DomainResult<SubscriptionChangeEvent>> {
            Box::pin(std::future::pending())
        }
    }

    /// Listener that errors on every recv — the dispatcher logs and
    /// falls back on the reconcile tick.
    struct FailingChangeListener;
    impl SubscriptionChangeListener for FailingChangeListener {
        fn recv(&self) -> BoxFuture<'_, DomainResult<SubscriptionChangeEvent>> {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "test: listener disconnected".to_string(),
                ))
            })
        }
    }

    // -- Mock SubscriptionRepository -------------------------------------

    struct MockSubRepo {
        active: Mutex<Vec<Subscription>>,
        list_active_should_fail: Mutex<bool>,
    }

    impl MockSubRepo {
        fn new() -> Self {
            Self {
                active: Mutex::new(Vec::new()),
                list_active_should_fail: Mutex::new(false),
            }
        }
        fn set_active(&self, subs: Vec<Subscription>) {
            *self.active.lock().unwrap() = subs;
        }
        fn fail_list_active(&self) {
            *self.list_active_should_fail.lock().unwrap() = true;
        }
    }

    impl SubscriptionRepository for MockSubRepo {
        fn create(&self, sub: &Subscription) -> BoxFuture<'_, DomainResult<()>> {
            let sub = sub.clone();
            Box::pin(async move {
                self.active.lock().unwrap().push(sub);
                Ok(())
            })
        }
        fn find_by_id(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<Subscription>> {
            let result = self
                .active
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.id == id)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "Subscription",
                    id: id.0.to_string(),
                });
            Box::pin(async move { result })
        }
        fn find_by_name(
            &self,
            _owner: Uuid,
            _name: &str,
        ) -> BoxFuture<'_, DomainResult<Option<Subscription>>> {
            Box::pin(async { Ok(None) })
        }
        fn list_for_owner(
            &self,
            _owner: Uuid,
            _page: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<Subscription>>> {
            Box::pin(async {
                Ok(Page {
                    items: Vec::new(),
                    total: 0,
                })
            })
        }
        fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<Subscription>>> {
            let fail = *self.list_active_should_fail.lock().unwrap();
            let active = self.active.lock().unwrap().clone();
            Box::pin(async move {
                if fail {
                    Err(DomainError::Invariant("forced failure".to_string()))
                } else {
                    Ok(active)
                }
            })
        }
        fn update(&self, sub: &Subscription) -> BoxFuture<'_, DomainResult<()>> {
            let sub = sub.clone();
            Box::pin(async move {
                let mut rows = self.active.lock().unwrap();
                if let Some(row) = rows.iter_mut().find(|s| s.id == sub.id) {
                    *row = sub;
                }
                Ok(())
            })
        }
        fn delete(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<()>> {
            self.active.lock().unwrap().retain(|s| s.id != id);
            Box::pin(async { Ok(()) })
        }
        fn update_last_delivered(
            &self,
            _id: SubscriptionId,
            _position: u64,
            _last_failure: Option<&hort_domain::entities::subscription::SubscriptionFailure>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -- Fixtures --------------------------------------------------------

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

    fn empty_eval() -> RbacEvaluator {
        RbacEvaluator::new(Vec::new())
    }

    fn admin_user(id: Uuid) -> User {
        User {
            id,
            username: format!("user-{id}"),
            email: "admin@example.com".into(),
            auth_provider: AuthProvider::Local,
            external_id: Some(format!("test:{id}")),
            display_name: None,
            is_active: true,
            is_admin: true,
            is_service_account: false,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn inactive_user(id: Uuid) -> User {
        let mut u = admin_user(id);
        u.is_active = false;
        u
    }

    /// Active, non-admin user — the F-3 / F-37 subject (an ordinary
    /// authenticated user who can create subscriptions).
    fn non_admin_user(id: Uuid) -> User {
        let mut u = admin_user(id);
        u.is_admin = false;
        u
    }

    fn sub_with_snapshot(owner_user_id: Uuid, snapshot_claims: Vec<String>) -> Subscription {
        let mut s = make_sub(owner_user_id);
        s.snapshot_claims = snapshot_claims;
        s
    }

    fn make_sub(owner_user_id: Uuid) -> Subscription {
        Subscription {
            id: SubscriptionId(Uuid::new_v4()),
            owner_user_id,
            created_by_token_id: None,
            name: format!("sub-{}", Uuid::new_v4()),
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
                repositories: RepositoryScope::All,
                named_predicates: vec![],
            },
            state: SubscriptionState::Active,
            // Per-subscription authority floor; the
            // dispatcher synthesises the owner principal from this set.
            snapshot_claims: Vec::new(),
            last_delivered_position: None,
            last_failure: None,
            created_at: Utc::now(),
        }
    }

    fn make_dispatcher(
        sub_repo: Arc<MockSubRepo>,
        user_repo: Arc<MockUserRepository>,
        change_listener: Arc<dyn SubscriptionChangeListener>,
    ) -> NotificationDispatcher {
        let mock_es = Arc::new(MockEventStore::new());
        let (sender, _rx) = broadcast::channel::<Arc<PersistedEvent>>(16);
        let publisher = Arc::new(EventStorePublisher::new(mock_es, sender));
        let rbac = Arc::new(ArcSwap::from_pointee(empty_eval()));
        let repos: Arc<dyn RepositoryRepository> = Arc::new(MockRepositoryRepository::new());
        let guard: Arc<dyn WebhookTargetGuard> = Arc::new(PermissiveGuard);
        let use_case = Arc::new(SubscriptionUseCase::new(
            sub_repo.clone(),
            user_repo.clone(),
            publisher.clone(),
            rbac.clone(),
            repos.clone(),
            guard,
            SubscriptionUseCaseConfig::default(),
        ));
        let notifiers: Vec<Arc<dyn EventNotifier>> =
            vec![Arc::new(RecordingNotifier::new(NotifyOutcome::Delivered))];
        NotificationDispatcher::new(
            publisher,
            use_case,
            rbac,
            user_repo,
            sub_repo,
            repos,
            change_listener,
            notifiers,
        )
    }

    // -- reconcile() tests -----------------------------------------------

    #[tokio::test]
    async fn reconcile_spawns_task_for_new_active_subscription() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(admin_user(owner));
        sub_repo.set_active(vec![make_sub(owner)]);
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(NeverChangeListener));
        let mut tasks: HashMap<SubscriptionId, TaskHandle> = HashMap::new();
        let parent = CancellationToken::new();
        dispatcher.reconcile(&mut tasks, &parent).await;
        assert_eq!(tasks.len(), 1);
        // Clean up.
        parent.cancel();
    }

    #[tokio::test]
    async fn reconcile_cancels_task_for_vanished_subscription() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(admin_user(owner));
        let s = make_sub(owner);
        sub_repo.set_active(vec![s.clone()]);
        let dispatcher =
            make_dispatcher(sub_repo.clone(), user_repo, Arc::new(NeverChangeListener));
        let mut tasks: HashMap<SubscriptionId, TaskHandle> = HashMap::new();
        let parent = CancellationToken::new();
        dispatcher.reconcile(&mut tasks, &parent).await;
        assert_eq!(tasks.len(), 1);
        // Now remove the subscription and reconcile again.
        sub_repo.set_active(vec![]);
        dispatcher.reconcile(&mut tasks, &parent).await;
        assert!(tasks.is_empty(), "vanished subscription must drop its task");
        parent.cancel();
    }

    #[tokio::test]
    async fn reconcile_leaves_existing_tasks_untouched_when_active_set_unchanged() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(admin_user(owner));
        let s = make_sub(owner);
        sub_repo.set_active(vec![s.clone()]);
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(NeverChangeListener));
        let mut tasks: HashMap<SubscriptionId, TaskHandle> = HashMap::new();
        let parent = CancellationToken::new();
        dispatcher.reconcile(&mut tasks, &parent).await;
        let original_count = tasks.len();
        // Reconcile again — the same subscription is still active.
        dispatcher.reconcile(&mut tasks, &parent).await;
        assert_eq!(tasks.len(), original_count);
        assert!(tasks.contains_key(&s.id));
        parent.cancel();
    }

    #[tokio::test]
    async fn reconcile_logs_and_continues_when_list_active_errors() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(admin_user(owner));
        let s = make_sub(owner);
        sub_repo.set_active(vec![s.clone()]);
        let dispatcher =
            make_dispatcher(sub_repo.clone(), user_repo, Arc::new(NeverChangeListener));
        let mut tasks: HashMap<SubscriptionId, TaskHandle> = HashMap::new();
        let parent = CancellationToken::new();
        dispatcher.reconcile(&mut tasks, &parent).await;
        assert_eq!(tasks.len(), 1);
        // Now make list_active fail; reconcile should be a no-op.
        sub_repo.fail_list_active();
        dispatcher.reconcile(&mut tasks, &parent).await;
        assert_eq!(tasks.len(), 1, "task set unchanged on list_active error");
        parent.cancel();
    }

    #[tokio::test]
    async fn reconcile_skips_task_spawn_when_owner_is_deactivated() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(inactive_user(owner));
        sub_repo.set_active(vec![make_sub(owner)]);
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(NeverChangeListener));
        let mut tasks: HashMap<SubscriptionId, TaskHandle> = HashMap::new();
        let parent = CancellationToken::new();
        dispatcher.reconcile(&mut tasks, &parent).await;
        assert!(tasks.is_empty(), "deactivated owner → no spawn");
        parent.cancel();
    }

    #[tokio::test]
    async fn reconcile_skips_task_spawn_when_owner_user_lookup_fails() {
        // Subscription owner_user_id has no row → synthesise_principal
        // returns None → no task spawned.
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new()); // empty
        sub_repo.set_active(vec![make_sub(owner)]);
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(NeverChangeListener));
        let mut tasks: HashMap<SubscriptionId, TaskHandle> = HashMap::new();
        let parent = CancellationToken::new();
        dispatcher.reconcile(&mut tasks, &parent).await;
        assert!(tasks.is_empty(), "missing user row → no spawn");
        parent.cancel();
    }

    // -- run() tests -----------------------------------------------------

    #[tokio::test]
    async fn run_exits_cleanly_on_cancellation() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(admin_user(owner));
        sub_repo.set_active(vec![make_sub(owner)]);
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(NeverChangeListener));
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            dispatcher.run(cancel_clone).await;
        });
        // Let the first reconcile fire.
        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run should exit on cancel")
            .expect("dispatcher should not panic");
    }

    #[tokio::test]
    async fn run_falls_back_to_reconcile_when_change_listener_errors() {
        // The failing listener returns Err immediately; the dispatcher
        // logs and continues. We let the scheduler iterate a few times
        // then cancel; the test passes if no panic / hang.
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(admin_user(owner));
        sub_repo.set_active(vec![make_sub(owner)]);
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(FailingChangeListener));
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            dispatcher.run(cancel_clone).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run should exit")
            .expect("dispatcher should not panic");
    }

    #[test]
    fn emit_state_gauge_counts_only_active() {
        // Pure unit test for the helper.
        let mut s_active = make_sub(Uuid::new_v4());
        s_active.state = SubscriptionState::Active;
        let mut s_paused = make_sub(Uuid::new_v4());
        s_paused.state = SubscriptionState::Paused;
        let list = vec![s_active, s_paused];
        // The helper sets a metrics gauge — we just ensure it doesn't
        // panic; the value emission is covered by metrics tests.
        emit_state_gauge(&list);
    }

    #[test]
    fn degraded_receiver_yields_closed_immediately() {
        let mut rx = degraded_receiver();
        // try_recv should be Closed (sender was dropped).
        let r = rx.try_recv();
        assert!(matches!(r, Err(broadcast::error::TryRecvError::Closed)));
    }

    /// LISTEN-error backoff is exponential, capped at the reconcile
    /// interval (not a flat 200ms retry).
    /// Mirrors the `next_backoff_doubles_until_cap` test in
    /// `hort_adapters_postgres::api_token_revocation_listener`.
    #[test]
    fn next_backoff_doubles_until_cap() {
        // Floor (200ms) → 400ms.
        assert_eq!(
            next_backoff(LISTEN_BACKOFF_FLOOR),
            Duration::from_millis(400)
        );
        // 400ms → 800ms.
        assert_eq!(
            next_backoff(Duration::from_millis(400)),
            Duration::from_millis(800)
        );
        // Just below the cap doubles into the cap.
        assert_eq!(
            next_backoff(Duration::from_secs(16)),
            Duration::from_secs(30),
            "32s doubled would exceed cap; clamps"
        );
        // Cap is idempotent — already at cap, stays at cap.
        assert_eq!(next_backoff(LISTEN_BACKOFF_CAP), LISTEN_BACKOFF_CAP);
    }

    // -- synthesise_principal reads snapshot_claims -----------------------

    /// A non-admin
    /// subscription with `snapshot_claims = ["developer",
    /// "team-alpha"]` synthesises a principal carrying exactly those
    /// claims (no synthetic `"admin"` — owner is not admin). The
    /// dispatcher applies the snapshot; it does not resolve.
    #[tokio::test]
    async fn synthesise_principal_reads_snapshot_claims_for_non_admin_owner() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(non_admin_user(owner));
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(NeverChangeListener));

        let sub = sub_with_snapshot(
            owner,
            vec!["developer".to_string(), "team-alpha".to_string()],
        );
        let principal = dispatcher
            .synthesise_principal(&sub)
            .await
            .expect("active non-admin owner → principal");

        assert_eq!(
            principal.claims,
            vec!["developer".to_string(), "team-alpha".to_string()],
            "snapshot_claims flow verbatim into the synthesised principal"
        );
        assert!(
            !principal.claims.iter().any(|c| c == "admin"),
            "non-admin owner gets no synthetic admin claim"
        );
        assert!(
            principal.token_kind.is_none(),
            "dispatcher principals are not native-token-kind discriminated"
        );
    }

    /// Base test 2 (backlog Item 9 acceptance). `snapshot_claims = []`
    /// + `user.is_admin = true` → `principal.claims = ["admin"]`
    /// (synthetic admin claim derived from the live bit; §6 invariant
    /// 3). Admin-owned subscriptions still authorise.
    #[tokio::test]
    async fn synthesise_principal_empty_snapshot_admin_owner_gets_admin_claim() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(admin_user(owner)); // is_admin = true
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(NeverChangeListener));

        let sub = sub_with_snapshot(owner, Vec::new());
        let principal = dispatcher
            .synthesise_principal(&sub)
            .await
            .expect("active admin owner → principal");

        assert_eq!(
            principal.claims,
            vec!["admin".to_string()],
            "empty snapshot + live is_admin=true → synthetic [\"admin\"]"
        );
        assert!(principal.token_kind.is_none());
    }

    /// **F-37 canonical closure (audit 2026-05-15 §4A).** Owner
    /// `is_admin = false`, but `snapshot_claims = ["admin"]` — the §5.5
    /// PATCH-via-PAT elevation persisted by a then-admin actor whose
    /// admin was later revoked. The synthesised principal MUST NOT
    /// carry `"admin"`: the stale snapshot string is neutralised and
    /// the `"admin"` claim is re-derived solely from the live
    /// `user.is_admin` bit (here `false`). With no `"admin"` claim the
    /// dispatch-time privileged-category gate (subscription_filter
    /// step 4) blocks every `ADMIN_CATEGORIES` event — snapshot
    /// elevation cannot retroactively unlock a privileged category
    /// against a non-admin owner. F-37 closed by construction.
    #[tokio::test]
    async fn f37_stale_snapshot_admin_does_not_elevate_non_admin_owner() {
        let owner = Uuid::new_v4();
        let sub_repo = Arc::new(MockSubRepo::new());
        let user_repo = Arc::new(MockUserRepository::new());
        user_repo.insert(non_admin_user(owner)); // is_admin = false NOW
        let dispatcher = make_dispatcher(sub_repo, user_repo, Arc::new(NeverChangeListener));

        // PATCH-via-PAT poisoned the snapshot to ["admin"].
        let sub = sub_with_snapshot(owner, vec!["admin".to_string()]);
        let principal = dispatcher
            .synthesise_principal(&sub)
            .await
            .expect("active owner → principal");

        assert!(
            !principal.claims.iter().any(|c| c == "admin"),
            "stale snapshot \"admin\" MUST be stripped for a \
             non-admin owner — F-37: snapshot elevation cannot unlock \
             privileged categories against a non-admin owner"
        );
        assert!(
            principal.claims.is_empty(),
            "the only snapshot claim was the stale \"admin\"; with it \
             stripped and the live is_admin=false the claim set is empty"
        );
    }
}
