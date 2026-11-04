//! Per-kind run-permit allocation that no class can be shut out of —
//! ADR 0066 D4 at the **second** of the two points where the system
//! allocates capacity.
//!
//! # The victim this exists for
//!
//! D4 says non-displacement holds wherever capacity is allocated, and
//! that the two points have different victims: at the claim, other
//! *kinds* of work; here, other *classes of the same kind*. The second
//! is invisible to the first, because a row that has been claimed is
//! already `running` — the claim's own reservation and the starvation
//! audit both look at `pending` rows and neither can see it.
//!
//! The kind it happens to is `scan`, which carries six trigger sources
//! across all three classes and runs at a per-worker concurrency of
//! one. A plain [`tokio::sync::Semaphore`] hands out permits strictly
//! in order of arrival, so a client-waited ingest scan that **won** the
//! claim still waited behind every scheduled rescan claimed in the same
//! batch for the capacity to run.
//!
//! # The rule
//!
//! A free permit is granted in three passes. The first two consider the
//! same classes: waited-on classes ([`TaskTier::is_waited_on`]) with a
//! queued row and fewer held permits than their
//! [`ClassFairPermits::reserved_per_class`] share.
//!
//! 1. among those past half the class-service audit threshold, to the
//!    class that has gone unserved longest;
//! 2. otherwise to the highest class among them in [`TaskTier::ALL`] order;
//! 3. otherwise to the **longest-waiting** row of any class.
//!
//! The share is a floor, not a priority order, and the difference is the
//! whole design. The first two passes guarantee a waited-on class its
//! share and nothing beyond it: once the class holds its share, a further
//! row cannot overtake another class below its share and otherwise
//! competes in arrival order. A waited-on flood cannot use an old grant
//! record to take a permit owed to a class still below its share. Pass
//! three is what makes
//! [`TaskTier::Bulk`] — which has no reserved share, because nobody is
//! waiting on it — served at all, and it is the same age-ordered
//! fallback the claim's priority-blind oldest slot is.
//!
//! **It is not preemption** (ADR 0066, "What this decision does not
//! say"). Nothing here interrupts running work or adds capacity: the
//! total stays the `max_concurrency` the kind was registered with, and
//! a waited-on row is only guaranteed not to be shut out. So the
//! guarantee is that it takes the *next* permit to come free, not that
//! it starts now.
//!
//! # What this does not bound
//!
//! At a capacity of one — the production setting for `scan` — the share
//! is the whole capacity, so pass three is reached only when no
//! waited-on class has a waiter. A worker whose waited-on arrivals
//! sustainedly exceed its capacity therefore runs no bulk work while
//! that lasts. That is ADR 0066's stated trade ("bulk work drains
//! measurably slower, by construction... that is the trade being made,
//! not a side effect") rather than an accident of this code, and the
//! two things that bound it are separate decisions by design: the
//! per-class service observation (D5) is what makes the state visible,
//! and aging is the safety net ADR 0066 places *beneath* D4 — "worth
//! having, not as a substitute". Neither is this module's, and a
//! deployment that needs arrival order back has
//! `HORT_SCANNER_RESERVED_SLOTS_PER_CLASS=0`.
//!
//! # Why the floor is also a time
//!
//! The share answers "does this class hold fewer permits than its
//! share *right now*", and at a capacity of one that question cannot
//! express a floor: a permit cannot be a third of itself, so after
//! every release **every** class holds fewer than any share and the
//! share pass always fires — for the first waited-on class in
//! [`TaskTier::ALL`], every time. The share pass alone is therefore
//! indistinguishable from strict class priority exactly where the
//! production configuration sits, and a lower waited-on class with a
//! sustained higher one above it is never served at all. A share of a
//! single server is a share of its **turns**, not of its seats.
//!
//! So the same below-share candidates need a second ordering by time.
//! That ordering uses the number the class-service audit already has
//! ([`hort_domain::policy::permit_service_interval`]): the guarantee,
//! its enforcement and its observation are one configured value rather
//! than three. Enforcement sits deliberately *below* the threshold the
//! audit reports on — a scheduler that acted at the same moment the
//! audit fired would make the alarm mean nothing, because the state it
//! reports would be the state the scheduler was about to leave.
//!
//! Holding a full share means a class is being served even if its last
//! grant is old; the time ordering cannot give it another permit ahead
//! of a class below its share. What the time floor buys is a **bound,
//! not a rate**: a below-share class that has been unserved longest
//! past the floor takes the next permit to come free, and then its
//! floor re-arms. It is not proportional fairness, which no decision
//! here asks for.
//!
//! # Why not a semaphore per class
//!
//! Splitting the capacity into per-class sub-semaphores is the obvious
//! shape and it cannot be built at a capacity of one: three classes
//! cannot each hold a dedicated permit out of a single one. A guarantee
//! at that capacity can only be about the *order* permits are granted
//! in, which is what this is. At higher capacities the same rule also
//! keeps a class that holds its full share out of both waited-on passes.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use hort_domain::types::task_tier::TaskTier;

/// How many classes there are, and therefore how many queues.
///
/// Read off [`TaskTier::ALL`] so a fourth class cannot arrive without a
/// queue of its own — which would otherwise silently share the lowest
/// class's.
const CLASS_COUNT: usize = TaskTier::ALL.len();

/// The queue index for `tier`, and for a row that does not classify.
///
/// `None` — a `trigger_source` this build cannot parse — is served as
/// [`TaskTier::Bulk`]. That is the same answer the ordinal table gives
/// such a row (it takes the schema default, the bottom of the layout),
/// and it is the safe direction: an unreadable row cannot acquire a
/// reserved share by being unreadable.
fn queue_index(tier: Option<TaskTier>) -> usize {
    let tier = tier.unwrap_or(TaskTier::Bulk);
    TaskTier::ALL
        .iter()
        .position(|candidate| *candidate == tier)
        .unwrap_or(CLASS_COUNT - 1)
}

/// One queued waiter: where to send its permit, and when it arrived.
struct Waiting {
    /// Arrival order across **all** classes — what pass three orders by.
    /// Per-queue position is not enough: the fallback is global arrival
    /// order, and three independently-ordered queues cannot answer it.
    seq: u64,
    arrived_at: Instant,
    tx: oneshot::Sender<Permit>,
}

/// Everything one kind's allocation decides from, under one lock.
///
/// A `std::sync::Mutex` rather than a `tokio` one, and nothing awaits
/// while it is held: every critical section here is a few queue
/// operations and a `oneshot::send`, none of which block.
struct State {
    /// Permits not currently held.
    free: usize,
    /// Permits held per class — both waited-on passes require a class below its share.
    held: [usize; CLASS_COUNT],
    /// Last delivered grant per class. An undelivered grant is rolled back.
    last_granted_at: [Option<Instant>; CLASS_COUNT],
    /// Waiters per class, each in arrival order.
    queues: [VecDeque<Waiting>; CLASS_COUNT],
    next_seq: u64,
}

/// Shared allocation state for one registered kind.
struct Inner {
    reserved_per_class: usize,
    service_interval: Duration,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    state: Mutex<State>,
}

impl Inner {
    /// The waiter the next free permit goes to and its class, or `None`
    /// when nobody is waiting.
    ///
    /// Both waited-on passes consider only queued classes below their
    /// reserved share. The first orders classes past the service time
    /// floor by how long they have gone unserved; the second uses
    /// [`TaskTier::ALL`] order. A class added later has to be given an
    /// `is_waited_on` answer before either pass can skip it.
    ///
    /// Pops rather than reporting an index, so there is no second
    /// "and is the queue still non-empty?" question for a caller to get
    /// wrong or for a reader to wonder about.
    fn take_next(&self, state: &mut State, now: Instant) -> Option<(usize, Waiting)> {
        let starved = (self.reserved_per_class > 0)
            .then(|| {
                TaskTier::ALL
                    .iter()
                    .enumerate()
                    .filter(|(_, tier)| tier.is_waited_on())
                    .filter(|(index, _)| state.held[*index] < self.reserved_per_class)
                    .filter_map(|(index, _)| {
                        let arrival = state.queues[index].front()?.arrived_at;
                        let reference = state.last_granted_at[index]
                            .map_or(arrival, |grant| grant.max(arrival));
                        (now.saturating_duration_since(reference) > self.service_interval)
                            .then_some((index, reference))
                    })
                    .min_by_key(|(index, reference)| (*reference, *index))
                    .map(|(index, _)| index)
            })
            .flatten();
        let index = starved
            .or_else(|| {
                TaskTier::ALL
                    .iter()
                    .enumerate()
                    .find(|(index, tier)| {
                        tier.is_waited_on()
                            && !state.queues[*index].is_empty()
                            && state.held[*index] < self.reserved_per_class
                    })
                    .map(|(index, _)| index)
            })
            .or_else(|| {
                (0..CLASS_COUNT)
                    .filter(|index| !state.queues[*index].is_empty())
                    .min_by_key(|index| {
                        state.queues[*index]
                            .front()
                            .map_or(u64::MAX, |waiting| waiting.seq)
                    })
            })?;
        state.queues[index].pop_front().map(|w| (index, w))
    }

    /// Hand out free permits until nothing is free or nobody is
    /// waiting.
    ///
    /// Called both on arrival and on release, which is what makes
    /// "free permit and a waiter at the same time" an unreachable
    /// state rather than one something has to poll for.
    fn pump(self: &Arc<Self>, state: &mut State) {
        let now = (self.clock)();
        while state.free > 0 {
            let Some((index, waiting)) = self.take_next(state, now) else {
                break;
            };
            state.free -= 1;
            state.held[index] += 1;
            let previous_grant = state.last_granted_at[index].replace(now);
            let permit = Permit {
                inner: Some(self.clone()),
                index,
            };
            if let Err(mut undelivered) = waiting.tx.send(permit) {
                // The waiter went away before its grant landed. Take
                // the capacity back here and defuse the permit —
                // letting its `Drop` do it would re-enter this lock.
                undelivered.inner = None;
                state.free += 1;
                state.held[index] -= 1;
                state.last_granted_at[index] = previous_grant;
            }
        }
    }

    /// Return a permit of class `index` to the pool and re-pump.
    fn release(self: &Arc<Self>, index: usize) {
        let mut state = self.lock();
        state.held[index] = state.held[index].saturating_sub(1);
        state.free += 1;
        self.pump(&mut state);
    }

    /// The lock, with the one panic message every caller shares.
    ///
    /// A poisoned lock means a previous holder panicked mid-critical-
    /// section, so the counts no longer describe the capacity. There is
    /// nothing a dispatcher can do with that, and continuing would hand
    /// out permits against bookkeeping known to be wrong — so this
    /// panics, exactly as the `tokio::sync::Semaphore` it replaced did
    /// on a closed semaphore.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("class-fair permit state poisoned by an earlier panic")
    }
}

/// One kind's run permits, allocated so that no class is shut out.
///
/// Built by `TaskDispatcher::register` from the kind's
/// `max_concurrency` and the deployment's per-class share. Replaces the
/// per-kind [`tokio::sync::Semaphore`], which could only hand out
/// permits in order of arrival.
pub(crate) struct ClassFairPermits {
    inner: Arc<Inner>,
}

impl ClassFairPermits {
    /// `capacity` permits, of which each waited-on class is guaranteed
    /// `reserved_per_class`.
    ///
    /// `capacity` is clamped to at least one: a kind registered with
    /// zero concurrency would otherwise never run, which is a
    /// composition mistake rather than a configuration the dispatcher
    /// should honour. `reserved_per_class` is **not** clamped to the
    /// capacity — a share larger than the capacity is the operator
    /// saying "the waited-on classes come first at this concurrency",
    /// which is a coherent thing to ask for and is what a capacity of
    /// one already means at the default.
    ///
    /// `reserved_per_class == 0` disables both waited-on passes, leaving
    /// the arrival order that predates ADR 0066.
    /// `service_interval` is derived from the configured class-service
    /// audit threshold by [`hort_domain::policy::permit_service_interval`].
    pub(crate) fn new_with_interval(
        capacity: usize,
        reserved_per_class: usize,
        service_interval: Duration,
    ) -> Self {
        let clock: Arc<dyn Fn() -> Instant + Send + Sync> = Arc::new(Instant::now);
        Self::build(capacity, reserved_per_class, service_interval, clock)
    }

    fn build(
        capacity: usize,
        reserved_per_class: usize,
        service_interval: Duration,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(Inner {
                reserved_per_class,
                service_interval,
                clock,
                state: Mutex::new(State {
                    free: capacity,
                    held: [0; CLASS_COUNT],
                    last_granted_at: [None; CLASS_COUNT],
                    queues: std::array::from_fn(|_| VecDeque::new()),
                    next_seq: 0,
                }),
            }),
        }
    }

    #[cfg(test)]
    fn new(capacity: usize, reserved_per_class: usize) -> Self {
        use hort_domain::policy::{permit_service_interval, DEFAULT_CLASS_SERVICE_THRESHOLD_SECS};

        let threshold = Duration::from_secs(DEFAULT_CLASS_SERVICE_THRESHOLD_SECS);
        Self::new_with_interval(
            capacity,
            reserved_per_class,
            permit_service_interval(threshold),
        )
    }

    #[cfg(test)]
    fn with_clock(
        capacity: usize,
        reserved_per_class: usize,
        service_interval: Duration,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        Self::build(capacity, reserved_per_class, service_interval, clock)
    }

    #[cfg(test)]
    pub(crate) fn service_interval(&self) -> Duration {
        self.inner.service_interval
    }

    /// Join the queue for `tier` **now**, and get back the handle to
    /// await the permit on.
    ///
    /// Deliberately not `async`: the enqueue has to happen at the call
    /// site, in the dispatcher's own loop, rather than whenever a
    /// spawned task first gets polled. The batch's arrival order is
    /// then the order the claim returned it in, which is a fact about
    /// the queue; if the enqueue happened inside the spawned task it
    /// would be a fact about the scheduler instead, and pass three's
    /// "longest-waiting" would mean something slightly different on
    /// every run.
    pub(crate) fn acquire(&self, tier: Option<TaskTier>) -> PermitHandle {
        let index = queue_index(tier);
        let (tx, rx) = oneshot::channel();
        {
            let mut state = self.inner.lock();
            let seq = state.next_seq;
            state.next_seq = state.next_seq.wrapping_add(1);
            let arrived_at = (self.inner.clock)();
            state.queues[index].push_back(Waiting {
                seq,
                arrived_at,
                tx,
            });
            self.inner.pump(&mut state);
        }
        PermitHandle {
            // Keeps the allocation alive for as long as a waiter
            // exists, which is what makes the `await` below unable to
            // observe a closed channel.
            _inner: self.inner.clone(),
            rx,
        }
    }
}

/// A queued claim on one of a kind's permits.
///
/// Returned by [`ClassFairPermits::acquire`] already enqueued — holding
/// one means a place in the queue, and dropping it gives that place up.
pub(crate) struct PermitHandle {
    _inner: Arc<Inner>,
    rx: oneshot::Receiver<Permit>,
}

impl PermitHandle {
    /// Wait for this handle's permit.
    ///
    /// Cannot fail: the sender lives in the allocation's queue, and
    /// this handle holds the allocation alive, so the channel outlives
    /// the wait.
    pub(crate) async fn granted(self) -> Permit {
        self.rx
            .await
            .expect("the grant channel outlives every handle that holds the allocation")
    }
}

/// Capacity held for as long as this value lives.
///
/// Dropping it returns the permit and immediately re-runs the
/// allocation, so the next grant is decided against the state the
/// release produced rather than the one before it.
pub(crate) struct Permit {
    /// `None` only on a permit [`Inner::pump`] could not deliver, which
    /// it has already accounted for — so `Drop` must not account for it
    /// again.
    inner: Option<Arc<Inner>>,
    index: usize,
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.release(self.index);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::*;

    /// Await a grant that must already be due, so a regression fails
    /// the test instead of hanging it.
    async fn granted_now(handle: PermitHandle) -> Permit {
        tokio::time::timeout(Duration::from_secs(2), handle.granted())
            .await
            .expect("the permit must already be free — waiting for it means it went elsewhere")
    }

    /// The permit `handle` has already been granted, if any.
    ///
    /// Reads the channel rather than waiting on a clock: `acquire`
    /// pumps synchronously, so a grant that was going to happen has
    /// already happened by the time this is called. The permit comes
    /// back by value and **must be bound** — dropping it releases the
    /// capacity and re-pumps, which is the next grant happening inside
    /// an assertion that was only meant to observe this one.
    fn try_take(handle: &mut PermitHandle) -> Option<Permit> {
        match handle.rx.try_recv() {
            Ok(permit) => Some(permit),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(e) => panic!("the grant channel must stay open while a handle lives: {e}"),
        }
    }

    /// True when `handle` has not been granted anything.
    ///
    /// Only sound where the expected answer is `true`: see
    /// [`try_take`] for why a `false` has to bind the permit instead.
    fn still_waiting(handle: &mut PermitHandle) -> bool {
        try_take(handle).is_none()
    }

    const INTERACTIVE: Option<TaskTier> = Some(TaskTier::Interactive);
    const NORMAL: Option<TaskTier> = Some(TaskTier::Normal);
    const BULK: Option<TaskTier> = Some(TaskTier::Bulk);

    fn clocked_permits(
        capacity: usize,
        reserved_per_class: usize,
    ) -> (ClassFairPermits, Arc<AtomicU64>) {
        let seconds = Arc::new(AtomicU64::new(0));
        let driven = seconds.clone();
        let start = Instant::now();
        let clock = Arc::new(move || start + Duration::from_secs(driven.load(Ordering::SeqCst)));
        (
            ClassFairPermits::with_clock(
                capacity,
                reserved_per_class,
                Duration::from_secs(150),
                clock,
            ),
            seconds,
        )
    }

    #[tokio::test]
    async fn sustained_interactive_stream_serves_normal_after_the_time_floor() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(BULK)).await;
        let mut normal = permits.acquire(NORMAL);
        let first_interactive = permits.acquire(INTERACTIVE);
        let second_interactive = permits.acquire(INTERACTIVE);
        let third_interactive = permits.acquire(INTERACTIVE);

        drop(running);
        let first = granted_now(first_interactive).await;
        assert!(still_waiting(&mut normal));

        seconds.store(150, Ordering::SeqCst);
        drop(first);
        let second = granted_now(second_interactive).await;
        assert!(
            still_waiting(&mut normal),
            "exactly at the floor is not starved"
        );

        seconds.store(151, Ordering::SeqCst);
        drop(second);
        let normal_run = try_take(&mut normal).expect("Normal must get the permit at 151 seconds");
        let mut third_interactive = third_interactive;
        assert!(still_waiting(&mut third_interactive));
        let fourth_interactive = permits.acquire(INTERACTIVE);

        drop(normal_run);
        let third = granted_now(third_interactive).await;
        drop(third);
        let _fourth = granted_now(fourth_interactive).await;
    }

    #[tokio::test]
    async fn the_longest_starved_class_wins_before_class_order() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(BULK)).await;
        let normal = permits.acquire(NORMAL);
        seconds.store(50, Ordering::SeqCst);
        let mut interactive = permits.acquire(INTERACTIVE);

        seconds.store(201, Ordering::SeqCst);
        drop(running);
        let _normal_run = granted_now(normal).await;
        assert!(still_waiting(&mut interactive));
    }

    #[tokio::test]
    async fn equally_starved_classes_follow_class_order() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(BULK)).await;
        let mut normal = permits.acquire(NORMAL);
        let interactive = permits.acquire(INTERACTIVE);

        seconds.store(151, Ordering::SeqCst);
        drop(running);
        let _interactive_run = granted_now(interactive).await;
        assert!(still_waiting(&mut normal));
    }

    #[tokio::test]
    async fn an_old_grant_does_not_make_a_new_waiter_starved() {
        let (permits, seconds) = clocked_permits(1, 1);
        drop(granted_now(permits.acquire(NORMAL)).await);
        seconds.store(1_000, Ordering::SeqCst);
        let running = granted_now(permits.acquire(BULK)).await;
        let mut normal = permits.acquire(NORMAL);
        let interactive = permits.acquire(INTERACTIVE);

        seconds.store(1_100, Ordering::SeqCst);
        drop(running);
        let _interactive_run = granted_now(interactive).await;
        assert!(still_waiting(&mut normal));
    }

    #[tokio::test]
    async fn a_first_waiter_is_judged_from_arrival_without_a_grant() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(BULK)).await;
        seconds.store(1_000, Ordering::SeqCst);
        let mut normal = permits.acquire(NORMAL);
        let interactive = permits.acquire(INTERACTIVE);

        seconds.store(1_100, Ordering::SeqCst);
        drop(running);
        let _interactive_run = granted_now(interactive).await;
        assert!(still_waiting(&mut normal));
    }

    #[tokio::test]
    async fn a_zero_share_skips_the_time_floor_even_after_it_expires() {
        let (permits, seconds) = clocked_permits(1, 0);
        let running = granted_now(permits.acquire(BULK)).await;
        let earlier_bulk = permits.acquire(BULK);
        let mut interactive = permits.acquire(INTERACTIVE);

        seconds.store(151, Ordering::SeqCst);
        drop(running);
        let _bulk_run = granted_now(earlier_bulk).await;
        assert!(still_waiting(&mut interactive));
    }

    #[tokio::test]
    async fn an_undelivered_grant_does_not_rearm_the_time_floor() {
        let (permits, seconds) = clocked_permits(1, 1);
        drop(granted_now(permits.acquire(NORMAL)).await);
        let running = granted_now(permits.acquire(BULK)).await;
        let abandoned = permits.acquire(NORMAL);
        let live_normal = permits.acquire(NORMAL);
        seconds.store(100, Ordering::SeqCst);
        let mut interactive = permits.acquire(INTERACTIVE);
        drop(abandoned);

        seconds.store(151, Ordering::SeqCst);
        drop(running);
        let _normal_run = granted_now(live_normal).await;
        assert!(still_waiting(&mut interactive));
    }

    /// An old grant does not make a class starved while it still holds
    /// its share and another waited-on class holds none.
    #[tokio::test]
    async fn an_old_grant_cannot_overtake_a_class_below_its_share() {
        let (permits, seconds) = clocked_permits(2, 1);
        let first_interactive = granted_now(permits.acquire(INTERACTIVE)).await;
        let _second_interactive = granted_now(permits.acquire(INTERACTIVE)).await;
        let mut third_interactive = permits.acquire(INTERACTIVE);

        seconds.store(300, Ordering::SeqCst);
        let mut normal = permits.acquire(NORMAL);

        seconds.store(400, Ordering::SeqCst);
        drop(first_interactive);
        let normal_run = try_take(&mut normal)
            .expect("Normal is still waiting despite holding none of its reserved share");
        assert!(
            still_waiting(&mut third_interactive),
            "Interactive already holds its reserved share"
        );

        drop(normal_run);
        let _third_interactive = granted_now(third_interactive).await;
    }

    /// The case the module exists for: a client-waited row queued
    /// behind a whole bulk batch takes the **first** permit to come
    /// free, not the last.
    #[tokio::test]
    async fn a_waited_on_class_takes_the_first_permit_to_come_free() {
        let permits = ClassFairPermits::new(1, 1);

        // The bulk row that is already running when the rest arrive —
        // nothing here interrupts it, so it keeps the permit.
        let running = granted_now(permits.acquire(BULK)).await;
        let mut queued: Vec<PermitHandle> = (0..3).map(|_| permits.acquire(BULK)).collect();
        let mut waited_on = permits.acquire(INTERACTIVE);
        assert!(
            queued.iter_mut().all(still_waiting) && still_waiting(&mut waited_on),
            "with the only permit held, every arrival must be queued"
        );

        drop(running);
        // Bound, not discarded: a dropped permit would release the
        // capacity and hand it straight to a bulk row, which is the
        // next assertion's subject.
        let _promoted = try_take(&mut waited_on).expect(
            "the freed permit must go to the client-waited row, not to the bulk backlog \
             it arrived behind",
        );
        assert!(
            queued.iter_mut().all(still_waiting),
            "the bulk rows must still be waiting — the grant above is the one permit, \
             not an extra one"
        );
    }

    /// The bulk rows are not starved by the row that overtook them:
    /// once the waited-on queue is empty they are granted in arrival
    /// order.
    #[tokio::test]
    async fn the_overtaken_rows_are_served_in_arrival_order_afterwards() {
        let permits = ClassFairPermits::new(1, 1);
        let running = granted_now(permits.acquire(BULK)).await;
        let first = permits.acquire(BULK);
        let second = permits.acquire(BULK);
        let waited_on = permits.acquire(INTERACTIVE);

        drop(running);
        let overtaking = granted_now(waited_on).await;
        drop(overtaking);
        // Arrival order among what is left, oldest first.
        let a = granted_now(first).await;
        drop(a);
        let b = granted_now(second).await;
        drop(b);
    }

    /// Pass one is a floor, not a priority order: a waited-on class
    /// that already holds its share competes in arrival order like
    /// everyone else.
    ///
    /// This is the assertion that separates this design from strict
    /// class priority. Without it the two are indistinguishable at the
    /// default share, and the difference is exactly what keeps a
    /// waited-on flood from taking capacity the arrival order would not
    /// have given it.
    #[tokio::test]
    async fn a_class_at_its_share_does_not_overtake_an_earlier_waiter() {
        let permits = ClassFairPermits::new(2, 1);

        // Interactive takes its reserved permit and keeps it.
        let reserved = granted_now(permits.acquire(INTERACTIVE)).await;
        // Bulk takes the other, through pass two.
        let other = granted_now(permits.acquire(BULK)).await;

        // Now a bulk row arrives, and a second interactive row after
        // it.
        let earlier_bulk = permits.acquire(BULK);
        let mut later_interactive = permits.acquire(INTERACTIVE);

        drop(other);
        let _bulk = granted_now(earlier_bulk).await;
        assert!(
            still_waiting(&mut later_interactive),
            "Interactive already holds its reserved permit, so the second row of that \
             class must not overtake a bulk row that arrived before it"
        );
        drop(reserved);
        let _promoted = granted_now(later_interactive).await;
    }

    /// Both waited-on classes get a share, and the higher one first
    /// when there is only capacity for one of them.
    ///
    /// The order is `TaskTier::ALL`'s, which is the same order the
    /// claim honours its band reservations in — so a deployment cannot
    /// see Normal served ahead of Interactive at one point and behind
    /// it at the other.
    #[tokio::test]
    async fn the_higher_waited_on_class_is_served_first_when_both_are_waiting() {
        let permits = ClassFairPermits::new(1, 1);
        let running = granted_now(permits.acquire(BULK)).await;
        let mut normal = permits.acquire(NORMAL);
        let interactive = permits.acquire(INTERACTIVE);

        drop(running);
        let first = granted_now(interactive).await;
        assert!(
            still_waiting(&mut normal),
            "Interactive outranks Normal in the reserved pass even though Normal \
             arrived first"
        );
        drop(first);
        let _second = granted_now(normal).await;
    }

    /// A share of zero is the arrival order that predates the decision
    /// — the knob's off position, and nothing else.
    #[tokio::test]
    async fn a_share_of_zero_leaves_pure_arrival_order() {
        let permits = ClassFairPermits::new(1, 0);
        let running = granted_now(permits.acquire(BULK)).await;
        let earlier_bulk = permits.acquire(BULK);
        let mut waited_on = permits.acquire(INTERACTIVE);

        drop(running);
        assert!(
            still_waiting(&mut waited_on),
            "with no reserved share the permit must go to the earliest waiter"
        );
        let _bulk = granted_now(earlier_bulk).await;
    }

    /// The capacity is the capacity: the reservation reorders grants
    /// and never adds one.
    ///
    /// "Nothing here... adds capacity" is the half of "not preemption"
    /// that a reservation implemented as extra permits would quietly
    /// break, and a scan concurrency of one exists because Trivy is
    /// heavy.
    #[tokio::test]
    async fn the_reservation_never_exceeds_the_registered_capacity() {
        let permits = ClassFairPermits::new(2, 1);
        let _a = granted_now(permits.acquire(INTERACTIVE)).await;
        let _b = granted_now(permits.acquire(NORMAL)).await;
        let mut third = permits.acquire(INTERACTIVE);
        assert!(
            still_waiting(&mut third),
            "a third row must wait at a capacity of two, whatever its class"
        );
        assert_eq!(
            permits.inner.lock().free,
            0,
            "both permits must be accounted as held"
        );
    }

    /// A row whose `trigger_source` this build cannot parse is served
    /// as the lowest class — the same answer the ordinal table gives
    /// it.
    #[tokio::test]
    async fn an_unclassifiable_row_is_served_as_the_lowest_class() {
        let permits = ClassFairPermits::new(1, 1);
        let running = granted_now(permits.acquire(None)).await;
        let mut unclassified = permits.acquire(None);
        let waited_on = permits.acquire(INTERACTIVE);

        drop(running);
        let _first = granted_now(waited_on).await;
        assert!(
            still_waiting(&mut unclassified),
            "an unreadable trigger source must not buy a reserved share"
        );
        assert_eq!(queue_index(None), queue_index(BULK));
    }

    /// A waiter that goes away before its grant lands does not take
    /// the permit with it.
    ///
    /// The grant is delivered by value, so the obvious implementation
    /// loses a permit for the lifetime of the worker whenever a
    /// spawned task is dropped between the pump and the receive — at
    /// shutdown, every time.
    #[tokio::test]
    async fn an_abandoned_waiter_does_not_leak_its_permit() {
        let permits = ClassFairPermits::new(1, 1);
        let running = granted_now(permits.acquire(BULK)).await;
        let abandoned = permits.acquire(INTERACTIVE);
        drop(abandoned);

        drop(running);
        assert_eq!(
            permits.inner.lock().free,
            1,
            "the permit the abandoned waiter would have taken must be back in the pool"
        );
        let _next = granted_now(permits.acquire(BULK)).await;
    }

    /// A capacity of zero is a composition mistake, not a
    /// configuration: it is clamped to one so the kind still runs.
    #[tokio::test]
    async fn a_capacity_of_zero_is_clamped_to_one() {
        let permits = ClassFairPermits::new(0, 1);
        let _only = granted_now(permits.acquire(BULK)).await;
        let mut next = permits.acquire(BULK);
        assert!(
            still_waiting(&mut next),
            "the clamp must be to one, not to many"
        );
    }

    /// There is a queue per class, so a fourth class cannot silently
    /// share the lowest one's.
    #[test]
    fn every_class_has_its_own_queue() {
        let indices: Vec<usize> = TaskTier::ALL
            .into_iter()
            .map(|tier| queue_index(Some(tier)))
            .collect();
        assert_eq!(indices, (0..CLASS_COUNT).collect::<Vec<_>>());
        assert_eq!(CLASS_COUNT, TaskTier::ALL.len());
    }
}
