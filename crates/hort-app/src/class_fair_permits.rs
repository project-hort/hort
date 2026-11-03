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
//! A free permit is granted in two passes:
//!
//! 1. to the highest **waited-on** class
//!    ([`TaskTier::is_waited_on`]) that has a waiter and currently holds
//!    fewer than [`ClassFairPermits::reserved_per_class`] permits;
//! 2. otherwise to the **longest-waiting** row of any class.
//!
//! That is a floor, not a priority order, and the difference is the
//! whole design. Pass one guarantees a waited-on class its share and
//! nothing beyond it: once the class holds its share, a further row of
//! that class takes its chances in arrival order against every other
//! waiter — so a waited-on flood cannot take capacity the arrival order
//! would not already have given it. Pass two is what makes
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
//! is the whole capacity, so pass two is reached only when no
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
//! # Why not a semaphore per class
//!
//! Splitting the capacity into per-class sub-semaphores is the obvious
//! shape and it cannot be built at a capacity of one: three classes
//! cannot each hold a dedicated permit out of a single one. A guarantee
//! at that capacity can only be about the *order* permits are granted
//! in, which is what this is, and the same rule then also reads
//! correctly at higher capacities — where holding a share and being
//! granted one coincide.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

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
    /// Arrival order across **all** classes — what pass two orders by.
    /// Per-queue position is not enough: the fallback is global arrival
    /// order, and three independently-ordered queues cannot answer it.
    seq: u64,
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
    /// Permits held per class — pass one's "has it got its share yet".
    held: [usize; CLASS_COUNT],
    /// Waiters per class, each in arrival order.
    queues: [VecDeque<Waiting>; CLASS_COUNT],
    next_seq: u64,
}

/// Shared allocation state for one registered kind.
struct Inner {
    reserved_per_class: usize,
    state: Mutex<State>,
}

impl Inner {
    /// The waiter the next free permit goes to and its class, or `None`
    /// when nobody is waiting.
    ///
    /// Pass one is wildcard-free over [`TaskTier::ALL`], so a class
    /// added later has to be given an `is_waited_on` answer before it
    /// can be skipped here.
    ///
    /// Pops rather than reporting an index, so there is no second
    /// "and is the queue still non-empty?" question for a caller to get
    /// wrong or for a reader to wonder about.
    fn take_next(&self, state: &mut State) -> Option<(usize, Waiting)> {
        let index = TaskTier::ALL
            .iter()
            .enumerate()
            .find(|(index, tier)| {
                tier.is_waited_on()
                    && !state.queues[*index].is_empty()
                    && state.held[*index] < self.reserved_per_class
            })
            .map(|(index, _)| index)
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
        while state.free > 0 {
            let Some((index, waiting)) = self.take_next(state) else {
                break;
            };
            state.free -= 1;
            state.held[index] += 1;
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
    /// `reserved_per_class == 0` disables pass one entirely, leaving
    /// the arrival order that predates ADR 0066.
    pub(crate) fn new(capacity: usize, reserved_per_class: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(Inner {
                reserved_per_class,
                state: Mutex::new(State {
                    free: capacity,
                    held: [0; CLASS_COUNT],
                    queues: std::array::from_fn(|_| VecDeque::new()),
                    next_seq: 0,
                }),
            }),
        }
    }

    /// Join the queue for `tier` **now**, and get back the handle to
    /// await the permit on.
    ///
    /// Deliberately not `async`: the enqueue has to happen at the call
    /// site, in the dispatcher's own loop, rather than whenever a
    /// spawned task first gets polled. The batch's arrival order is
    /// then the order the claim returned it in, which is a fact about
    /// the queue; if the enqueue happened inside the spawned task it
    /// would be a fact about the scheduler instead, and pass two's
    /// "longest-waiting" would mean something slightly different on
    /// every run.
    pub(crate) fn acquire(&self, tier: Option<TaskTier>) -> PermitHandle {
        let index = queue_index(tier);
        let (tx, rx) = oneshot::channel();
        {
            let mut state = self.inner.lock();
            let seq = state.next_seq;
            state.next_seq = state.next_seq.wrapping_add(1);
            state.queues[index].push_back(Waiting { seq, tx });
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
