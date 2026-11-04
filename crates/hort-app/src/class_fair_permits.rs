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
//! A free permit is granted in four passes. The middle two consider the
//! same classes: waited-on classes ([`TaskTier::is_waited_on`]) with a
//! queued row and fewer held permits than their
//! [`ClassFairPermits::reserved_per_class`] share.
//!
//! 1. to the **longest-waiting** row of any class, when it has waited
//!    past [`hort_domain::policy::permit_age_net_bound`] and the net
//!    has not already fired inside that bound;
//! 2. otherwise, among the below-share waited-on classes past half the
//!    class-service audit threshold, to the class that has gone
//!    unserved longest;
//! 3. otherwise to the highest class among them in [`TaskTier::ALL`] order;
//! 4. otherwise to the **longest-waiting** row of any class.
//!
//! Passes one and four choose the same row from the same selection —
//! one is the other brought forward — and differ only in what has to be
//! true to reach them: pass four needs every waited-on class to have no
//! eligible waiter, pass one needs a row to have waited past the bound.
//!
//! The share is a floor, not a priority order, and the difference is the
//! whole design. The two waited-on passes guarantee a waited-on class
//! its share and nothing beyond it: once the class holds its share, a
//! further row cannot overtake another class below its share and
//! otherwise competes in arrival order. A waited-on flood cannot use an
//! old grant record to take a permit owed to a class still below its
//! share. Passes one and four are what make
//! [`TaskTier::Bulk`] — which has no reserved share, because nobody is
//! waiting on it — served at all, and they are the same age-ordered
//! fallback the claim's priority-blind oldest slot is.
//!
//! **It is not preemption** (ADR 0066, "What this decision does not
//! say"). Nothing here interrupts running work or adds capacity: the
//! total stays the `max_concurrency` the kind was registered with, and
//! a waited-on row is only guaranteed not to be shut out. So the
//! guarantee is that it takes the *next* permit to come free, not that
//! it starts now.
//!
//! # What bounds the lowest class's wait
//!
//! At a capacity of one — the production setting for `scan` — the share
//! is the whole capacity, so the two waited-on passes match whenever
//! any waited-on class has a waiter and the arrival-order fallback is
//! reached only when none does. A worker whose waited-on arrivals
//! sustainedly exceed its capacity therefore never reaches pass four,
//! and before the age net above it that worker ran no bulk work at all
//! for as long as the stream lasted.
//!
//! "No bulk work while the stream lasts" is **not** the trade ADR 0066
//! makes. Its consequence is that bulk work "drains measurably slower,
//! by construction", and D5 guarantees service to every class
//! *including* the one with no reserved share — resting there "not on a
//! share but on a priority-blind age fallback beneath the reservation,
//! present at every point the reservation is". The other allocation
//! point already had one: the claim query's class-blind `oldest` CTE,
//! one row by `created_at ASC` per batch. Pass one is this point's
//! counterpart, and it sits *before* the waited-on passes because at a
//! capacity of one a waited-on pass always matches — after them the net
//! would be unreachable exactly where it is needed.
//!
//! **The bound is derived, not configured**
//! ([`hort_domain::policy::permit_age_net_bound`]): three quarters of
//! the class-service audit threshold, strictly above the time floor
//! below it and strictly below the window the audit reports on. One
//! operator number keeps ordering the three, and a second variable
//! could only reorder them into a state where one of them is dead.
//!
//! **The net fires at most once per bound, and never twice in a row**,
//! and that rate is what keeps it a net rather than a second ordering.
//! A permit queue holds rows that have already been claimed, and a
//! batch is claimed whether or not a permit is free, so a flood reaches
//! this point as a pile of waiters that age *together*. A net with no
//! rate would then match on every release for as long as the pile
//! lasted and hand it the whole capacity in age order — the
//! head-of-line blocking the reservation exists to remove, re-entered
//! through the floor beneath it. The claim's `oldest` slot is one row
//! of a batch for the same reason: aging is "a safety net beneath the
//! reservation rather than a second per-class allocation".
//!
//! The two halves of that rate are not redundant. The bound is
//! measured from the net's own last grant, so a single run **longer
//! than the bound** satisfies it again the moment that run releases —
//! and a `scan` run longer than three quarters of the audit threshold
//! is ordinary. "Never twice in a row" is what bounds the pile in that
//! regime: between two net grants some other pass is served, so the
//! net's reach degrades to every second permit rather than to all of
//! them. The net re-arms on its **own** grants and on nothing else, so
//! a run of ordinary grants cannot hold it shut; and when no waited-on
//! class is waiting, pass four still serves bulk work at full speed, so
//! the rate binds only under contention — the only state it is about.
//!
//! **It is not a share for [`TaskTier::Bulk`]** and not a second
//! per-class allocation: it is class-blind, so past the bound it may
//! serve a bulk row ahead of a younger `Normal` waiter. That is what
//! priority-blind means, and the claim point has done it since before
//! this module existed. Inside the bound it reorders nothing, so D1's
//! class order is untouched.
//!
//! What it buys is a **bound** where there was none, and the bound is
//! worth stating precisely: a row is served after the rows already
//! queued ahead of it, so its wait is the net's bound plus their run
//! time, and no later arrival — of any class, for any length of
//! stream — adds to it. It is *not* a function of the bound and the
//! class count alone: a deeper queue ahead of a row is a longer wait,
//! exactly as it is at the claim.
//!
//! `HORT_SCANNER_RESERVED_SLOTS_PER_CLASS=0` switches off all three
//! mechanisms together — the share, the time floor and this net — and
//! leaves the arrival order that predates ADR 0066. That is a
//! **permitted waiver** of the decision and not the off-switch of a
//! feature, and ADR 0066 attaches one condition to it: the deployment
//! states at startup which guarantee it has given up. The worker says
//! it from [`hort_domain::policy::class_reservation_waiver`].
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

use hort_domain::policy::{permit_age_net_bound, permit_service_interval};
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
    /// Last delivered grant the **age net** decided, and nothing else —
    /// the net's rate is one permit per [`Inner::age_net_bound`], so a
    /// grant any other pass made must not re-arm it. `None` until the
    /// net has fired, which is what lets a first aged waiter be served
    /// as soon as it crosses the bound.
    last_age_net_grant_at: Option<Instant>,
    /// Whether the last delivered grant was the net's.
    ///
    /// The second half of the net's rate, and not redundant with the
    /// first: the time rate is measured from the net's own last grant,
    /// so a run **longer than the bound** satisfies it again the moment
    /// that run releases, and a pile of aged rows would take every
    /// permit at a capacity of one. A `scan` run longer than three
    /// quarters of the audit threshold is ordinary, not exotic.
    age_net_took_the_last_grant: bool,
    /// Waiters per class, each in arrival order.
    queues: [VecDeque<Waiting>; CLASS_COUNT],
    next_seq: u64,
}

/// Shared allocation state for one registered kind.
struct Inner {
    reserved_per_class: usize,
    service_interval: Duration,
    age_net_bound: Duration,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    state: Mutex<State>,
}

/// Which pass decided a grant.
///
/// Only the age net needs naming: it is the one pass with a rate of its
/// own, so [`Inner::pump`] re-arms it on its own grants and on no
/// others. Returning it from [`Inner::take_next`] rather than
/// re-deriving it afterwards is what keeps "did the net decide this?"
/// from being a second, separately-wrong answer to a question the
/// decision already had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decider {
    /// Pass one — the class-blind age net.
    AgeNet,
    /// One of the other three passes, none of which has a rate.
    Other,
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
    fn take_next(&self, state: &mut State, now: Instant) -> Option<(usize, Waiting, Decider)> {
        if let Some(index) = self.age_net(state, now) {
            return state.queues[index]
                .pop_front()
                .map(|w| (index, w, Decider::AgeNet));
        }
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
            .or_else(|| Self::oldest_waiter(state))?;
        state.queues[index]
            .pop_front()
            .map(|w| (index, w, Decider::Other))
    }

    /// The longest-waiting row of any class — the arrival-order
    /// fallback's choice, and the age net's.
    ///
    /// Ordered by `seq` rather than by `arrived_at`: the sequence is
    /// assigned under the same lock that reads the clock, so the
    /// smallest `seq` among the queue fronts *is* the earliest arrival,
    /// with two arrivals inside one clock tick broken by the order they
    /// joined in. One selection shared by both passes is what makes the
    /// net the fallback brought forward rather than a second ordering
    /// that could answer differently.
    ///
    /// A queue's front is its own oldest row (`push_back` on arrival,
    /// `pop_front` on grant), so the fronts are the only candidates the
    /// global minimum can be among.
    fn oldest_waiter(state: &State) -> Option<usize> {
        (0..CLASS_COUNT)
            .filter(|index| !state.queues[*index].is_empty())
            .min_by_key(|index| {
                state.queues[*index]
                    .front()
                    .map_or(u64::MAX, |waiting| waiting.seq)
            })
    }

    /// Whether the net's one class-blind slot is open: not twice in a
    /// row, and not twice inside one bound.
    ///
    /// Both halves are needed and neither implies the other. The time
    /// rate is what keeps a pile of rows that aged together from being
    /// served all at once while runs are short; "not twice in a row" is
    /// what keeps the same pile bounded when a single run outlasts the
    /// bound, which satisfies the time rate at every release. Together
    /// they make the net one slot per bound *and* never more than every
    /// second grant — the claim's `oldest` slot is one row of a batch
    /// for the same reason.
    fn net_slot_is_open(&self, state: &State, now: Instant) -> bool {
        !state.age_net_took_the_last_grant
            && state
                .last_age_net_grant_at
                .is_none_or(|last| now.saturating_duration_since(last) > self.age_net_bound)
    }

    /// Pass one: the oldest waiter of any class once it has waited past
    /// [`Self::age_net_bound`], while the net's slot is open.
    ///
    /// Three conditions, each load-bearing:
    ///
    /// - **The share is on.** At `reserved_per_class == 0` the operator
    ///   has waived ADR 0066 and asked for arrival order, which is what
    ///   the fallback already is — so the net has nothing to add and is
    ///   switched off with the rest of the decision rather than left
    ///   running where the startup statement says it is gone.
    /// - **The slot is open** ([`Self::net_slot_is_open`]).
    /// - **The oldest waiter is past the bound**, strictly — the same
    ///   boundary the time floor uses, so "exactly at the bound" is not
    ///   yet late anywhere in this module.
    fn age_net(&self, state: &State, now: Instant) -> Option<usize> {
        if self.reserved_per_class == 0 || !self.net_slot_is_open(state, now) {
            return None;
        }
        let index = Self::oldest_waiter(state)?;
        let arrived_at = state.queues[index].front()?.arrived_at;
        (now.saturating_duration_since(arrived_at) > self.age_net_bound).then_some(index)
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
            let Some((index, waiting, decider)) = self.take_next(state, now) else {
                break;
            };
            state.free -= 1;
            state.held[index] += 1;
            let previous_grant = state.last_granted_at[index].replace(now);
            // The net re-arms on its own grants and on nothing else,
            // while "took the last grant" is set by every pass — a
            // grant the reservation made is precisely what re-opens the
            // net's slot. Both captured unconditionally so the rollback
            // below restores values rather than deciding again which to.
            let previous_age_net = state.last_age_net_grant_at;
            let previous_took_last = state.age_net_took_the_last_grant;
            state.age_net_took_the_last_grant = decider == Decider::AgeNet;
            if decider == Decider::AgeNet {
                state.last_age_net_grant_at = Some(now);
            }
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
                state.last_age_net_grant_at = previous_age_net;
                state.age_net_took_the_last_grant = previous_took_last;
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
    /// `reserved_per_class == 0` waives ADR 0066 at this point: both
    /// waited-on passes and the age net above them are off, leaving the
    /// arrival order that predates the decision.
    ///
    /// `audit_threshold` is the **configured class-service audit
    /// threshold** (`HORT_TASK_CLASS_SERVICE_THRESHOLD_SECS`) and not
    /// either of the times derived from it. Both derivations happen
    /// here, through the domain
    /// ([`permit_service_interval`] and [`permit_age_net_bound`]), so
    /// the two enforcement times cannot be threaded independently of
    /// each other or of the window the audit reports on — an ordering
    /// that retires a pass is not expressible rather than merely
    /// avoided.
    pub(crate) fn new_with_threshold(
        capacity: usize,
        reserved_per_class: usize,
        audit_threshold: Duration,
    ) -> Self {
        let clock: Arc<dyn Fn() -> Instant + Send + Sync> = Arc::new(Instant::now);
        Self::build(capacity, reserved_per_class, audit_threshold, clock)
    }

    fn build(
        capacity: usize,
        reserved_per_class: usize,
        audit_threshold: Duration,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(Inner {
                reserved_per_class,
                service_interval: permit_service_interval(audit_threshold),
                age_net_bound: permit_age_net_bound(audit_threshold),
                clock,
                state: Mutex::new(State {
                    free: capacity,
                    held: [0; CLASS_COUNT],
                    last_granted_at: [None; CLASS_COUNT],
                    last_age_net_grant_at: None,
                    age_net_took_the_last_grant: false,
                    queues: std::array::from_fn(|_| VecDeque::new()),
                    next_seq: 0,
                }),
            }),
        }
    }

    #[cfg(test)]
    fn new(capacity: usize, reserved_per_class: usize) -> Self {
        use hort_domain::policy::DEFAULT_CLASS_SERVICE_THRESHOLD_SECS;

        Self::new_with_threshold(
            capacity,
            reserved_per_class,
            Duration::from_secs(DEFAULT_CLASS_SERVICE_THRESHOLD_SECS),
        )
    }

    #[cfg(test)]
    fn with_clock(
        capacity: usize,
        reserved_per_class: usize,
        audit_threshold: Duration,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        Self::build(capacity, reserved_per_class, audit_threshold, clock)
    }

    #[cfg(test)]
    pub(crate) fn service_interval(&self) -> Duration {
        self.inner.service_interval
    }

    /// The age net's bound, for the composition-side assertion that the
    /// configured threshold reached it — the reason
    /// [`Self::service_interval`] is exposed, for the second number
    /// derived from the same knob.
    #[cfg(test)]
    pub(crate) fn age_net_bound(&self) -> Duration {
        self.inner.age_net_bound
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

    /// A driven-clock allocation at the shipped audit threshold.
    ///
    /// The argument is the threshold and not either time derived from
    /// it, because the allocation derives both: at the 300 s default
    /// that is a **150 s** service interval (half) and a **225 s** age
    /// net bound (three quarters), which are the numbers the second
    /// arguments below are chosen against. Nothing here sleeps — the
    /// clock is the `AtomicU64` the caller stores seconds into.
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
                Duration::from_secs(300),
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

    // ---- The class-blind age net ------------------------------------------

    /// The case the net exists for: a sustained client-waited stream at
    /// a capacity of one, and the bulk row queued behind it is still
    /// served.
    ///
    /// The loop is the sustained stream — one row joins for every row
    /// served, so the waited-on queue never empties and the
    /// arrival-order fallback is never reached. Before the net this
    /// test could not be written: it would hand every permit to the
    /// stream for as many iterations as it was given.
    #[tokio::test]
    async fn a_sustained_waited_on_stream_still_serves_bulk() {
        let (permits, seconds) = clocked_permits(1, 1);
        // The stream holds the permit from the start, so the bulk row
        // is a waiter rather than a holder by luck of arrival.
        let mut held = granted_now(permits.acquire(INTERACTIVE)).await;
        // `None` once it has been granted: a receiver that has already
        // yielded its permit is closed, and reading it again would
        // report the close rather than the grant.
        let mut bulk = Some(permits.acquire(BULK));
        let mut stream: VecDeque<PermitHandle> = VecDeque::new();
        stream.push_back(permits.acquire(INTERACTIVE));

        let mut granted = vec!["interactive"];
        for step in 1..=6u64 {
            seconds.store(step * 50, Ordering::SeqCst);
            drop(held);
            held = if let Some(permit) = bulk.as_mut().and_then(try_take) {
                bulk = None;
                granted.push("bulk");
                permit
            } else {
                let next = stream
                    .pop_front()
                    .expect("the stream keeps a waiter for every row it has served");
                granted.push("interactive");
                granted_now(next).await
            };
            stream.push_back(permits.acquire(INTERACTIVE));
        }
        drop(held);

        assert_eq!(
            granted,
            vec![
                "interactive",
                "interactive",
                "interactive",
                "interactive",
                "interactive",
                "bulk",
                "interactive",
            ],
            "the bulk row waits out the 225 s bound and then takes the first permit to \
             come free, and the stream has the capacity back on the next release"
        );
    }

    /// Past the bound the older waiter wins even when it is bulk work
    /// and the younger waiter belongs to a class with a reserved share.
    ///
    /// This is what priority-blind means, and the claim point's oldest
    /// slot has done it since before this module existed.
    #[tokio::test]
    async fn past_the_bound_the_older_bulk_row_beats_a_younger_normal_waiter() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(INTERACTIVE)).await;
        let mut bulk = permits.acquire(BULK);
        seconds.store(100, Ordering::SeqCst);
        let normal = permits.acquire(NORMAL);

        seconds.store(226, Ordering::SeqCst);
        drop(running);
        let bulk_run = try_take(&mut bulk).expect(
            "past the bound the oldest waiter is served whatever its class — Normal's \
             reserved share would otherwise have taken this permit",
        );

        // And the net yields immediately afterwards: it has fired
        // inside the bound, so the reservation decides the next one.
        drop(bulk_run);
        let _normal_run = granted_now(normal).await;
    }

    /// Exactly at the bound is not yet past it — the same boundary the
    /// time floor uses.
    #[tokio::test]
    async fn exactly_at_the_age_net_bound_the_reservation_still_decides() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(INTERACTIVE)).await;
        let mut bulk = permits.acquire(BULK);
        seconds.store(100, Ordering::SeqCst);
        let normal = permits.acquire(NORMAL);

        seconds.store(225, Ordering::SeqCst);
        drop(running);
        let _normal_run = granted_now(normal).await;
        assert!(
            still_waiting(&mut bulk),
            "a wait of exactly the bound has not passed it"
        );
    }

    /// The service pass still decides something: here it picks a class
    /// that neither of its neighbours would have.
    ///
    /// The three passes above the fallback would each answer
    /// differently at this instant — the net would serve the oldest row
    /// (`Bulk`), class order would serve the highest waiting class
    /// (`Interactive`), and the service pass serves the class that has
    /// gone unserved longest among those below their share (`Normal`,
    /// whose waiter is older than Interactive's). That the answer is
    /// `Normal` is the only observation that separates the three.
    #[tokio::test]
    async fn inside_the_bound_the_service_pass_decides_against_both_neighbours() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(BULK)).await;
        let mut oldest_bulk = permits.acquire(BULK);
        let mut normal = permits.acquire(NORMAL);
        seconds.store(100, Ordering::SeqCst);
        let interactive = permits.acquire(INTERACTIVE);

        seconds.store(200, Ordering::SeqCst);
        drop(running);
        let normal_run = try_take(&mut normal).expect(
            "the service pass must decide: 200 s is past the 150 s floor for Normal and \
             inside both the floor for Interactive and the 225 s age net bound",
        );
        assert!(
            still_waiting(&mut oldest_bulk),
            "inside the bound the net reorders nothing"
        );

        drop(normal_run);
        let _interactive_run = granted_now(interactive).await;
        assert!(
            still_waiting(&mut oldest_bulk),
            "and the reservation keeps deciding while the bound holds"
        );
    }

    /// The net fires once per bound and not once per release: a pile of
    /// rows that aged together does not take the capacity in age order.
    ///
    /// A claim batch is taken whether or not a permit is free, so this
    /// pile is the shape a flood actually arrives in. A net with no
    /// rate would match on every release until the pile cleared, which
    /// is the head-of-line blocking the reservation exists to remove.
    #[tokio::test]
    async fn the_net_serves_one_aged_row_per_bound() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(INTERACTIVE)).await;
        let mut first_bulk = permits.acquire(BULK);
        let mut second_bulk = permits.acquire(BULK);
        let mut stream: VecDeque<PermitHandle> = VecDeque::new();
        stream.push_back(permits.acquire(INTERACTIVE));
        stream.push_back(permits.acquire(INTERACTIVE));

        seconds.store(226, Ordering::SeqCst);
        drop(running);
        let first = try_take(&mut first_bulk).expect("the oldest aged row is served first");

        drop(first);
        assert!(
            still_waiting(&mut second_bulk),
            "the second aged row must not take the next permit too — the net has fired \
             inside its bound, so the waited-on stream gets it"
        );
        let stream_run = granted_now(
            stream
                .pop_front()
                .expect("the stream still has the waiter the net overtook"),
        )
        .await;

        // One bound after the net's own grant, the slot is open again.
        seconds.store(452, Ordering::SeqCst);
        drop(stream_run);
        let _second = try_take(&mut second_bulk)
            .expect("a bound after its last grant the net serves the next aged row");
    }

    /// A run longer than the bound does not let the net take every
    /// permit: it never fires twice in a row.
    ///
    /// The time rate alone would be satisfied again the instant such a
    /// run releases, so without this half an aged pile would hold a
    /// capacity of one for as long as it lasted — and a `scan` run
    /// longer than three quarters of the audit threshold is ordinary.
    #[tokio::test]
    async fn the_net_does_not_fire_twice_in_a_row() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(INTERACTIVE)).await;
        let mut first_bulk = permits.acquire(BULK);
        let mut second_bulk = permits.acquire(BULK);
        let interactive = permits.acquire(INTERACTIVE);

        seconds.store(226, Ordering::SeqCst);
        drop(running);
        let bulk_run = try_take(&mut first_bulk).expect("the oldest aged row is served first");

        // The run outlasts the bound, so the net's time rate is clear
        // again the moment it releases.
        seconds.store(600, Ordering::SeqCst);
        drop(bulk_run);
        assert!(
            still_waiting(&mut second_bulk),
            "the net must not take a second permit with no other grant between them, \
             however long its own run held the capacity"
        );
        let stream_run = granted_now(interactive).await;

        // With a grant in between and the bound long past, the slot is
        // open again — the rate bounds the pile without stranding it.
        seconds.store(900, Ordering::SeqCst);
        drop(stream_run);
        let _second = try_take(&mut second_bulk)
            .expect("one grant and one bound later, the next aged row is served");
    }

    /// A grant the net could not deliver leaves its slot open.
    ///
    /// Rolling the net's clock forward on an undelivered grant would
    /// cost the next aged row a whole bound for a permit nobody
    /// received — the same reason the per-class grant record is rolled
    /// back, and at shutdown an abandoned waiter is the normal case.
    #[tokio::test]
    async fn an_undelivered_net_grant_does_not_rearm_the_net() {
        let (permits, seconds) = clocked_permits(1, 1);
        let running = granted_now(permits.acquire(INTERACTIVE)).await;
        let abandoned = permits.acquire(BULK);
        let mut live_bulk = permits.acquire(BULK);
        let mut interactive = permits.acquire(INTERACTIVE);
        drop(abandoned);

        seconds.store(226, Ordering::SeqCst);
        drop(running);
        let _live = try_take(&mut live_bulk).expect(
            "the net's first pick went to an abandoned waiter, so its slot must still be \
             open for the next aged row",
        );
        assert!(
            still_waiting(&mut interactive),
            "the reservation would have taken this permit had the net been re-armed by a \
             grant nobody received"
        );
    }

    /// The waiver switches the net off with the rest of the decision:
    /// at a share of zero, past the bound is still the arrival order
    /// that predates ADR 0066.
    ///
    /// The net can only ever answer what the fallback answers — both
    /// pick the longest-waiting row from the same selection — so the
    /// observable promise of the waiver is this one: with the share at
    /// zero, no time and no class changes who is next.
    #[tokio::test]
    async fn a_zero_share_keeps_arrival_order_past_the_age_net_bound() {
        let (permits, seconds) = clocked_permits(1, 0);
        let running = granted_now(permits.acquire(BULK)).await;
        let earlier_bulk = permits.acquire(BULK);
        let mut waited_on = permits.acquire(INTERACTIVE);

        seconds.store(400, Ordering::SeqCst);
        drop(running);
        assert!(
            still_waiting(&mut waited_on),
            "with no reserved share the permit must go to the earliest waiter, however \
             long either of them has waited"
        );
        let _bulk = granted_now(earlier_bulk).await;
    }

    /// Both enforcement times come from the one configured threshold.
    #[test]
    fn both_enforcement_times_are_derived_from_the_audit_threshold() {
        use hort_domain::policy::{permit_age_net_bound, permit_service_interval};

        let threshold = Duration::from_secs(90);
        let permits = ClassFairPermits::new_with_threshold(1, 1, threshold);
        assert_eq!(
            permits.service_interval(),
            permit_service_interval(threshold)
        );
        assert_eq!(permits.age_net_bound(), permit_age_net_bound(threshold));
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
    ///
    /// The times are 150 s and 200 s so that both halves of the
    /// assertion are live at once: Interactive's grant is older than
    /// the 150 s service interval, so the time floor would consider it
    /// were the share check not excluding it, while its queued row is
    /// younger than the 225 s age net bound, so the net is not what
    /// decides here. Past that bound the net serves the oldest row
    /// whatever its share, which is
    /// `past_the_bound_the_older_bulk_row_beats_a_younger_normal_waiter`'s
    /// subject rather than this test's.
    #[tokio::test]
    async fn an_old_grant_cannot_overtake_a_class_below_its_share() {
        let (permits, seconds) = clocked_permits(2, 1);
        let first_interactive = granted_now(permits.acquire(INTERACTIVE)).await;
        let _second_interactive = granted_now(permits.acquire(INTERACTIVE)).await;
        let mut third_interactive = permits.acquire(INTERACTIVE);

        seconds.store(150, Ordering::SeqCst);
        let mut normal = permits.acquire(NORMAL);

        seconds.store(200, Ordering::SeqCst);
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
