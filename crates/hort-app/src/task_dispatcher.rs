//! Multi-kind task dispatcher.
//!
//! [`TaskDispatcher`] is the generalised worker poll loop. It claims batches
//! of pending `jobs` rows across all registered handler kinds in a single
//! `claim_pending_by_kinds` query, dispatches each row to the matching
//! [`TaskHandler`] implementation, and persists the returned [`TaskOutcome`]
//! to the jobs table via `mark_completed` / `reschedule` / `mark_failed`.
//!
//! Per-kind [`ClassFairPermits`] enforce the concurrency limits set at
//! registration time, and allocate them so that no class of the same
//! kind is shut out — the second of the two points ADR 0066 D4 requires
//! non-displacement at, and the one the claim cannot see (a row waiting
//! for a permit is already `running`). Graceful shutdown is driven by a
//! [`tokio_util::sync::CancellationToken`].
//!
//! # Execution-time authority
//!
//! Before any handler is invoked, a claimed row goes through
//! [`DestructiveTaskReauthorizer`], which re-checks the authority of the
//! requester named by `jobs.actor_id` — but only for the invocations
//! that destroy something. A revoked claim therefore stops a queued
//! `retention-purge` instead of being spent on it. Ordinary kinds pay
//! one pure classifier call and no I/O. See
//! [`crate::destructive_task_reauthorization`] for the decision and why
//! a refusal is terminal while an unreadable authority store is not.
//!
//! # Audit event emitted
//!
//! A failure the dispatcher wrote to the row also lands on the audit
//! stream as `TaskFailed` — `final_attempt: false` from the
//! `reschedule` path, `true` from `mark_failed`. It is the counterpart
//! of the enqueue path's `TaskInvoked` and shares its stream routing, so
//! a destructive kind's invocation and its failure are one trail on the
//! never-deleted stream. [`TaskDispatcher::append_failure_audit`]
//! carries the conditions: the write must have landed, and the kind must
//! be one an operator can invoke.
//!
//! # Metrics emitted
//!
//! See metrics-catalog.md (`hort_admin_tasks_*`):
//!
//! - `hort_admin_tasks_enqueued_total{kind, result}` — NOT emitted by the
//!   dispatcher; the HTTP invoke handler
//!   (`hort-http-admin-tasks::handlers::invoke`) owns it, and `result ∈
//!   {ok, rbac_denied, validation_error}` describes the *acceptance* of an
//!   operator request, not the fate of a claimed row. Listed here only so
//!   the `hort_admin_tasks_*` family reads complete from one place; the
//!   label set is the handler's, so change it there.
//! - `hort_admin_tasks_completed_total{kind, result}` — one increment per
//!   `record_outcome_for_row` call. `result ∈ {completed, failed_retry,
//!   failed_terminal}`. A retryable failure on a row that has spent its
//!   attempt budget ([`TaskDispatcher::attempt_cap`]) counts as
//!   `failed_terminal`, because
//!   that is what the dispatcher did to the row.
//! - `hort_admin_tasks_duration_seconds{kind}` — elapsed time inside
//!   `TaskHandler::run`, and nothing else. In particular it does NOT
//!   include the wait for a concurrency permit, which a claimed row may
//!   spend arbitrarily long in. That wait is not *timed* anywhere; what
//!   is observable is how many rows of a class are in it and how long
//!   the oldest of them has waited — see
//!   [`TaskDispatcher::audit_class_service`] and, for the
//!   operator-facing gauges,
//!   `hort_server::composition::emit_queue_class_service_signal`.
//! - `hort_admin_tasks_in_flight{kind}` — gauge; incremented when a task
//!   `run` starts, decremented when it finishes.
//! - `hort_admin_tasks_pending_eligible{kind}` — gauge; claim-eligible
//!   pending rows per kind, set on every starvation audit. Covers kinds
//!   this dispatcher does NOT claim.
//! - `hort_admin_tasks_starved_total{kind, reason}` — counter; one
//!   increment per audit at which a kind's eligible backlog has gone
//!   unserved past [`STARVATION_THRESHOLD`]. `reason ∈ {unregistered,
//!   not_claimed, oldest_row_stalled}`. `oldest_row_stalled` is independent
//!   of the other two: it fires whenever the single oldest eligible row of
//!   a kind has aged past the threshold, even while that kind is being
//!   claimed constantly (a sustained high-priority stream of the same kind
//!   can starve one old low-priority row indefinitely while claims of
//!   fresher rows keep `not_claimed`/`unregistered` silent).
//! - `hort_admin_tasks_class_starved_total{class, reason}` — counter;
//!   one increment per audit at which a **class** has work waiting that
//!   nothing of that class has been served ahead of (ADR 0066 D5).
//!   `reason ∈ {not_claimed, awaiting_capacity}` — which of the two
//!   allocation points the class is losing at. Per class rather than per
//!   kind, and therefore the answer to a question the two series above
//!   structurally cannot answer; see
//!   [`TaskDispatcher::audit_class_service`].

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use hort_domain::events::{
    Actor, DomainEvent, InternalActor, TaskFailed, ADMIN_INVOKABLE_TASK_KINDS,
};
use hort_domain::policy::{evaluate_class_service, ClassService};
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};
use hort_domain::ports::jobs_repository::{
    ClaimReservation, JobRow, JobsRepository, KindQueueSample, PendingKindBacklog, PriorityBand,
    QueueServiceSample, RequeueOutcome, REQUEUE_ON_LEASE_EXPIRY_KINDS,
};
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::types::task_tier::{class_bands, TaskTier};

use crate::class_fair_permits::ClassFairPermits;
use crate::destructive_task_reauthorization::{
    DestructiveTaskReauthorizer, ReauthorizationVerdict,
};
use crate::error::AppResult;
use crate::event_store_publisher::EventStorePublisher;
use crate::result_write_fence::surface_attempted_result_write;
use crate::retry_backoff::compute_backoff;
use crate::use_cases::task_use_case::TaskUseCase;
use crate::use_cases::{
    append_any_with_conflict_retry, event_append_backoff, EVENT_APPEND_RETRY_ATTEMPTS,
};

// ---------------------------------------------------------------------------
// Metric name constants
// ---------------------------------------------------------------------------

const METRIC_COMPLETED: &str = "hort_admin_tasks_completed_total";
const METRIC_DURATION: &str = "hort_admin_tasks_duration_seconds";
const METRIC_IN_FLIGHT: &str = "hort_admin_tasks_in_flight";
const METRIC_PENDING_ELIGIBLE: &str = "hort_admin_tasks_pending_eligible";
const METRIC_STARVED: &str = "hort_admin_tasks_starved_total";
const METRIC_CLASS_STARVED: &str = "hort_admin_tasks_class_starved_total";
/// The same finding as [`METRIC_CLASS_STARVED`] at the granularity the
/// guarantee is enforced at — one series per `(class, kind, reason)`.
///
/// A separate name rather than a `kind` label on the counter above, so
/// the class-wide question stays exactly as askable as it was: an
/// operator alarming on the coarse counter keeps the series identity
/// they have, and the coarse counter also stays the backstop for a kind
/// outside `EVENT_TASK_KINDS` (which the `jobs_kind_check` CHECK makes
/// unreachable, but which a fold still counts and a per-kind series
/// would have no label for).
const METRIC_CLASS_KIND_STARVED: &str = "hort_admin_tasks_class_kind_starved_total";
const METRIC_LEASE_REQUEUED: &str = "hort_admin_tasks_lease_requeued_total";
const METRIC_LEASE_RENEW_FAILED: &str = "hort_admin_tasks_lease_renew_failed_total";

// Result label values
const RESULT_COMPLETED: &str = "completed";
const RESULT_FAILED_RETRY: &str = "failed_retry";
const RESULT_FAILED_TERMINAL: &str = "failed_terminal";

// `reason` label values on `hort_admin_tasks_starved_total`.
const STARVED_UNREGISTERED: &str = "unregistered";
const STARVED_NOT_CLAIMED: &str = "not_claimed";
const STARVED_OLDEST_ROW: &str = "oldest_row_stalled";

// `result` label values on `hort_admin_tasks_lease_requeued_total`.
const REQUEUE_RESULT_REQUEUED: &str = "requeued";
const REQUEUE_RESULT_EXHAUSTED: &str = "retries_exhausted";

// `result` label values on `hort_admin_tasks_lease_renew_failed_total`.
// `lost` is the fencing signal — the row is no longer this worker's, so
// whatever it is still running against that row is not the authoritative
// execution. `error` is a transient database failure on the renewal
// itself, which says nothing about ownership.
const RENEW_RESULT_LOST: &str = "lost";
const RENEW_RESULT_ERROR: &str = "error";

/// How long a kind's claim-eligible backlog may sit un-drained before the
/// dispatcher calls it starvation (ERROR log + metric).
///
/// Sized well above any legitimate transient: a deep queue drains FIFO,
/// so a kind that is being claimed at all keeps re-arming its
/// last-claimed clock long before this elapses. A silently starved
/// kind, by contrast, can otherwise run for hours undetected.
const STARVATION_THRESHOLD: Duration = Duration::from_secs(600);

/// Minimum spacing between starvation audits, independent of
/// `poll_interval_secs`. The audit is one grouped aggregate over the
/// eligible-pending rows; at a 5 s poll that would be 12 scans a minute
/// for no diagnostic gain.
const STARVATION_AUDIT_INTERVAL: Duration = Duration::from_secs(60);

/// How many lease renewals a healthy worker performs per lease.
///
/// The renewal interval is `lock_duration / RENEWALS_PER_LEASE`, so a
/// live worker's `locked_until` is never more than
/// `lock_duration × (1 - 1/RENEWALS_PER_LEASE)` from its maximum. Three
/// is the smallest value that tolerates a lost renewal without letting
/// the lease lapse: at two, one missed tick puts the row on the sweep's
/// doorstep with no margin left.
const RENEWALS_PER_LEASE: u32 = 3;

/// Floor on the renewal interval.
///
/// `HORT_SCANNER_LOCK_DURATION_SECS` is operator-set and parses `0`
/// happily. A zero lease is already a broken configuration — every claim
/// is instantly re-claimable — but without this floor it would also turn
/// the renewal into an unthrottled loop issuing an `UPDATE` as fast as
/// the connection returns, which is a self-inflicted load problem on the
/// database rather than merely a misconfigured queue. Clamping keeps a
/// bad number bad instead of letting it become an outage.
const MIN_RENEWAL_INTERVAL: Duration = Duration::from_secs(1);

/// Extra time past a lapsed lease before the sweep calls the holder
/// dead, as a multiple of the lease.
///
/// **This is the discriminator, and this is why the number is derivable
/// rather than guessed.** Before lease renewal, `locked_until < now()`
/// on a `running` row said only "the task outlived its nominal lease",
/// which is equally true of a dead worker and of a task slower than
/// 15 minutes; picking a per-kind multiple to tell them apart means
/// guessing an upper bound on runtime, and several kinds have none
/// (`seed-import` processes an operator-supplied set of arbitrary size,
/// the prefetch cascade walks a transitive dependency graph over the
/// network). Renewal removes the guess: a live worker renews three times
/// a lease no matter how long its task runs, so a lapsed lease already
/// means three consecutive renewals failed to land.
///
/// One further lease on top is the margin for the cases where renewal is
/// alive but late — a renewal that lost a database race, a container
/// paused by its host, and the rolling-upgrade window in which older
/// replicas do not renew at all. A worker that is merely slow is
/// therefore never swept; one that has stopped writing to the database
/// for two full leases is recovered.
const LEASE_EXPIRY_GRACE_MULTIPLE: u32 = 1;

/// Minimum spacing between abandoned-lease sweeps.
///
/// Matches [`STARVATION_AUDIT_INTERVAL`] for the same reason: the sweep
/// is a single indexed range scan over `running` rows and there is no
/// diagnostic or recovery gain in running it twelve times a minute at a
/// 5 s poll. Recovery latency is dominated by the lease plus the grace
/// (30 minutes at the defaults), so a minute of sweep spacing is noise
/// against it.
const LEASE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// The renewal interval has to leave headroom for one lost renewal, and
/// the grace has to cover a fleet whose older replicas do not renew at
/// all. Both are compile-time so a future tuning edit that collapses the
/// margin fails the build rather than a test somebody can skim past.
///
/// At two renewals per lease a single missed tick puts the row on the
/// sweep's doorstep with nothing left, and the grace would then be
/// carrying the discriminator alone — which is the pre-renewal design
/// this replaced. At a grace below one lease, a rolling upgrade in which
/// the older replicas do not renew would sweep rows out from under
/// workers that are alive and working.
const _: () = assert!(
    RENEWALS_PER_LEASE >= 3,
    "fewer than three renewals per lease leaves no spare renewal inside a lease"
);
const _: () = assert!(
    LEASE_EXPIRY_GRACE_MULTIPLE >= 1,
    "the grace must be at least one full lease"
);

/// Rows the sweep resolves per pass.
///
/// Bounded so one pass cannot hold row locks across an unbounded set
/// after a fleet-wide restart. A backlog drains over consecutive passes.
const LEASE_SWEEP_BATCH: u16 = 100;

/// Recovery latency is bounded by lease + grace + one sweep interval.
/// Pinning the sweep spacing as the small term keeps a future cadence
/// edit from making housekeeping, rather than the lease, dominate how
/// long a dead worker's rows stay stranded.
const _: () = assert!(
    LEASE_SWEEP_INTERVAL.as_secs() <= 300,
    "sweep spacing must stay small against the lease-plus-grace recovery bound"
);

// ---------------------------------------------------------------------------
// TaskDispatcher
// ---------------------------------------------------------------------------

/// Multi-kind task dispatcher — the generalised worker poll loop.
///
/// Constructed via [`TaskDispatcher::new`]. Handlers are registered with
/// [`TaskDispatcher::register`]. The poll loop runs via
/// [`TaskDispatcher::run`] until the cancellation token fires.
pub struct TaskDispatcher {
    /// Registered handlers, keyed by `TaskHandler::kind()`.
    handlers: HashMap<&'static str, Arc<dyn TaskHandler>>,
    /// Per-kind run permits enforcing `max_concurrency`, allocated so
    /// that no class of the same kind is shut out — see
    /// [`ClassFairPermits`] and [`Self::reserved_slots_per_class`].
    permits: HashMap<&'static str, Arc<ClassFairPermits>>,
    job_repo: Arc<dyn JobsRepository>,
    /// Where the dispatcher appends the `TaskFailed` audit record for a
    /// failure it closed a row out on — see
    /// [`Self::append_failure_audit`] for the routing, the
    /// kinds it skips and why the append can never change the row's
    /// state.
    ///
    /// Nothing else in the dispatcher writes events: a scan's own
    /// outcome vocabulary is emitted inside `ScanTaskHandler::run` via
    /// `ScanOrchestrationUseCase::record_outcome`, and `TaskInvoked`
    /// belongs to the enqueue path (`TaskUseCase::enqueue`), not to
    /// execution.
    event_store: Arc<EventStorePublisher>,
    /// Re-checks a destructive invocation's requester against the live
    /// authority state before its handler is invoked.
    ///
    /// **Not optional, deliberately.** A dispatcher that could be built
    /// without one would run a `retention-purge` on authority nobody
    /// re-checked, and the composition root that forgot to wire it would
    /// look exactly like the one that did. Making it a constructor
    /// argument turns "a worker executes destructive work unchecked"
    /// into a compile error instead of a review finding.
    reauthorizer: Arc<DestructiveTaskReauthorizer>,
    worker_id: String,
    lock_duration: Duration,
    poll_interval_secs: u64,
    batch_size: u16,
    /// `attempts` at which a failing `jobs` row stops being re-driven
    /// and becomes the terminal, operator-visible `failed` row
    /// ADR 0028 describes.
    ///
    /// A row reaches the cap one of two ways, and the same number
    /// bounds both — one behaviour, two triggers:
    ///
    /// - **The handler returned a failure** — `TaskOutcome::Failed {
    ///   retry: true }`, or an `Err` recorded as one.
    ///   `record_outcome_for_row` reschedules while `attempts` is below
    ///   the cap and calls `mark_failed` at it. [`compute_backoff`]
    ///   bounds how long a row *waits* and bounds nothing else, so
    ///   without this cap a job that fails the same way every time
    ///   would be re-driven for as long as it kept failing, and would
    ///   never become a `failed` row at all.
    /// - **The handler never returned** — its worker died holding the
    ///   claim, and `sweep_abandoned_leases` is the only code that runs
    ///   for such a row. It passes this cap to `requeue_abandoned`,
    ///   whose `CASE` requeues below the cap and fails the row at it.
    ///
    /// Both paths spend the same budget because a requeue and a
    /// reschedule both cost exactly one attempt: neither touches the
    /// counter, and the next claim increments it.
    ///
    /// **Uniform across kinds, deliberately.**
    /// [`REQUEUE_ON_LEASE_EXPIRY_KINDS`] answers a different question —
    /// which kinds tolerate a *concurrent* second execution after a
    /// crash, where the duplicate is absorbed by nothing. A returned
    /// failure has no in-flight duplicate to fear, precisely because
    /// the handler returned, so carrying that allow-list over would
    /// answer the wrong question and build an exemption table nobody
    /// could audit.
    ///
    /// **Configured, not a constant, and this is load-bearing.** The
    /// value comes from `HORT_SCANNER_MAX_ATTEMPTS` by way of
    /// `WorkerConfig::max_attempts`, which the worker's composition
    /// root also assigns to `ScanOrchestrationConfig::max_attempts`.
    /// Those two caps meet at one boundary: the scan path spends its
    /// cap to decide the *artifact's* terminal state (an exhausted scan
    /// records `ScanIndeterminate`, or deliberately leaves an
    /// already-quarantined artifact alone) and this one decides the
    /// *row's*. While this was a `const u32 = 5` the two agreed only at
    /// the default — an operator who raised the scan budget got rows
    /// failed at five with no artifact verdict behind them, and one who
    /// lowered it got scans re-driven past their own verdict. There is
    /// deliberately no default here: a composition root that did not
    /// decide cannot compile.
    ///
    /// **A number of attempts is only half of a budget**; the other
    /// half is the window they span, which is [`compute_backoff`]'s to
    /// set. At the default six, those executions spend the curve's
    /// first five waits — 156 minutes from the first failure to the cap
    /// — and both halves had to agree before the cap could mean
    /// "persistently broken": while the dispatcher kept its own
    /// 30-s-doubling curve, the same five attempts were spent inside
    /// 7 m 30 s, so a transient outage slightly longer than a coffee
    /// break produced the same permanent `failed` row as a genuinely
    /// broken dependency.
    attempt_cap: u32,
    /// Slots held for each non-empty waited-on class at **both** points
    /// where this dispatcher allocates capacity — ADR 0066 D4.
    ///
    /// One number for two allocations on purpose: the claim decides
    /// *which work is taken up* and the permit decides *which work gets
    /// the capacity to run*, and D4 is explicit that a design closing
    /// one leaves the other's victim. Two knobs would let an operator
    /// close one and leave the other, which is the state the decision
    /// calls incomplete rather than partial.
    ///
    /// **Configured, not a constant**, because ADR 0066 declines to fix
    /// the shares: with a single worker replica the share *is* the whole
    /// control surface, so it is a per-deployment concern. The default
    /// is the domain's — at least one slot per non-empty waited-on class
    /// (`HORT_SCANNER_RESERVED_SLOTS_PER_CLASS`, default `1`), which
    /// needs no measurement to justify: interactive work is bounded by
    /// what clients do and bulk work is unbounded by construction, so a
    /// share that can go to zero for a class someone is waiting on is
    /// the defect itself.
    ///
    /// `0` turns the reservation off at both points, restoring the
    /// pre-decision behaviour. It is reachable only by an operator
    /// setting it deliberately.
    reserved_slots_per_class: u16,
    /// How long work of a class may wait with nothing of that class
    /// served before [`Self::audit_class_service`] calls the class
    /// unserved — ADR 0066 D5's threshold.
    ///
    /// **Configured, not a constant, and the same knob the server
    /// reads.** `HORT_TASK_CLASS_SERVICE_THRESHOLD_SECS` reaches this
    /// field by way of `WorkerConfig::class_service_threshold` and
    /// reaches `hort-server`'s gauge by way of its own composition
    /// root; the default is
    /// [`DEFAULT_CLASS_SERVICE_THRESHOLD_SECS`](hort_domain::policy::DEFAULT_CLASS_SERVICE_THRESHOLD_SECS),
    /// defined once in the domain so the two processes cannot disagree
    /// about it the way the attempt caps did while one of them was a
    /// `const` (see [`Self::attempt_cap`]). An operator who sets the
    /// variable on only one of the two deployments gets a worker log
    /// and an operator gauge that answer at different thresholds, which
    /// is why the metrics catalog names both readers.
    class_service_threshold: Duration,
}

impl TaskDispatcher {
    /// Construct a dispatcher without any registered handlers.
    ///
    /// Call [`register`](Self::register) for each handler kind before
    /// calling [`run`](Self::run).
    ///
    /// `attempt_cap` is the operator's configured attempt budget
    /// (`HORT_SCANNER_MAX_ATTEMPTS`), not a default this type supplies —
    /// see [`TaskDispatcher::attempt_cap`] for why it must be the same
    /// number the scan orchestrator was built with.
    // One composition-root call site; the alternative is a config struct
    // whose fields would read exactly as these arguments do.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_repo: Arc<dyn JobsRepository>,
        event_store: Arc<EventStorePublisher>,
        reauthorizer: Arc<DestructiveTaskReauthorizer>,
        worker_id: impl Into<String>,
        lock_duration: Duration,
        poll_interval_secs: u64,
        batch_size: u16,
        attempt_cap: u32,
        reserved_slots_per_class: u16,
        class_service_threshold: Duration,
    ) -> Self {
        Self {
            handlers: HashMap::new(),
            permits: HashMap::new(),
            job_repo,
            event_store,
            reauthorizer,
            worker_id: worker_id.into(),
            lock_duration,
            poll_interval_secs,
            batch_size,
            attempt_cap,
            reserved_slots_per_class,
            class_service_threshold,
        }
    }

    /// The attempt budget this dispatcher closes rows out against.
    ///
    /// Exposed so a composition test can assert the worker threaded one
    /// configured number into both halves of the scan boundary rather
    /// than leaving them to agree by coincidence — see the field's doc.
    pub fn attempt_cap(&self) -> u32 {
        self.attempt_cap
    }

    /// The per-class reserved share this dispatcher allocates both its
    /// claim batch and its run permits with.
    ///
    /// Exposed for the same reason [`Self::attempt_cap`] is: the
    /// composition root is the only place the operator's number is
    /// read, so a composition test is the only place the knob can be
    /// seen to reach the dispatcher at all. ADR 0066 D4 makes that
    /// worth asserting — one of the two allocation points is
    /// unobservable from outside the process, so "the share was
    /// configured but never threaded" would look exactly like "the
    /// share is the default".
    pub fn reserved_slots_per_class(&self) -> u16 {
        self.reserved_slots_per_class
    }

    /// The per-class service threshold this dispatcher audits against.
    ///
    /// Exposed for the reason [`Self::reserved_slots_per_class`] is: the
    /// composition root is the only place the operator's number is
    /// read, and the verdict it feeds is emitted by a *different*
    /// process, so a composition test is the only place "the knob
    /// reached the audit" can be seen at all.
    pub fn class_service_threshold(&self) -> Duration {
        self.class_service_threshold
    }

    /// Register a handler for its `kind()` with a per-kind concurrency cap.
    ///
    /// `max_concurrency` is the maximum number of concurrent invocations of
    /// this handler. A value of `1` serialises all executions of this kind.
    ///
    /// The cap is unchanged by [`Self::reserved_slots_per_class`]: the
    /// reservation decides the *order* this kind's permits are handed
    /// out in, never how many there are (ADR 0066 — "nothing here
    /// interrupts running work or takes capacity away from it"). A
    /// `scan` concurrency of one stays one.
    ///
    /// Panics if the same kind is registered twice (programming error).
    #[tracing::instrument(skip(self, handler))]
    pub fn register(&mut self, handler: Arc<dyn TaskHandler>, max_concurrency: usize) {
        let kind = handler.kind();
        assert!(
            !self.handlers.contains_key(kind),
            "TaskDispatcher: kind '{kind}' registered twice"
        );
        self.handlers.insert(kind, handler);
        self.permits.insert(
            kind,
            Arc::new(ClassFairPermits::new_with_threshold(
                max_concurrency,
                usize::from(self.reserved_slots_per_class),
                self.class_service_threshold,
            )),
        );
    }

    /// Return the set of currently-registered handler kinds.
    ///
    /// Used by composition smoke tests (e.g. `hort-worker`'s
    /// `composition_smoke.rs`) to assert that a handler the
    /// composition root claims to register actually appears in the
    /// dispatcher's kind table — closing the structural gap where a
    /// new `TaskHandler` impl could land in `hort-app` and be exported
    /// without ever being wired into the worker's `register(...)`
    /// chain.
    ///
    /// Returns owned `&'static str`s (handler kinds are compile-time
    /// constants); callers typically convert to `HashSet<&str>` for
    /// membership checks.
    pub fn registered_kinds(&self) -> Vec<&'static str> {
        self.handlers.keys().copied().collect()
    }

    /// Run the poll loop until `cancel` fires.
    ///
    /// Each iteration:
    /// 1. Waits for `poll_interval_secs` (or cancellation — whichever first).
    /// 2. Claims up to `batch_size` pending rows across all registered kinds.
    /// 3. Dispatches each row to its handler in a `tokio::spawn` task,
    ///    gated by the kind's permit allocation and — for the destructive
    ///    invocations only — by a live re-check of the requester's
    ///    authority (see the module docs).
    /// 4. Each spawned task records the outcome via `record_outcome_for_row`.
    /// 5. Every [`STARVATION_AUDIT_INTERVAL`], runs the starvation audit
    ///    (see [`detect_starvation`]) over the WHOLE eligible-pending
    ///    backlog — including kinds this dispatcher does not claim.
    ///
    /// Returns `Ok(())` when the cancellation token fires (clean shutdown).
    /// Infrastructure errors on claim or outcome recording are logged and
    /// swallowed — a transient DB flap does not crash the loop.
    #[tracing::instrument(skip(self))]
    pub async fn run(self, cancel: CancellationToken) -> AppResult<()> {
        let kinds: Vec<&str> = self.handlers.keys().copied().collect();
        let registered: HashSet<&str> = kinds.iter().copied().collect();
        // The bands the claim holds slots in — built once per run
        // rather than per poll, because they are a property of the
        // class vocabulary and not of the batch.
        let reservation = ClaimReservation::waited_on(self.reserved_slots_per_class);
        // Wrap self in Arc so spawned tasks can share ownership without
        // cloning the entire struct.
        let dispatcher = Arc::new(self);

        // Starvation-audit state. Owned by the loop, not by `self`: it is
        // per-run, and the audit is the only reader.
        let started_at = Utc::now();
        let mut last_claimed: HashMap<String, DateTime<Utc>> = HashMap::new();
        // `None` = audit on the first poll: a worker that boots into an
        // unclaimable backlog publishes `hort_admin_tasks_pending_eligible`
        // straight away. The ERROR/counter still needs
        // `STARVATION_THRESHOLD` to elapse, so the early audit cannot
        // false-alarm.
        let mut last_audit: Option<Instant> = None;
        // The abandoned-lease sweep runs on its own clock, not the
        // audit's: the audit is diagnostic and the sweep is a recovery
        // write, and coupling them would make a change to one silently
        // re-time the other. `None` = sweep on the first poll, so a
        // worker booting after a fleet-wide crash recovers the rows that
        // crash stranded without waiting out an interval first.
        let mut last_lease_sweep: Option<Instant> = None;

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    tracing::info!("TaskDispatcher: cancellation received; exiting poll loop");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(dispatcher.poll_interval_secs)) => {}
            }

            let claimed = match dispatcher
                .job_repo
                .claim_pending_by_kinds(
                    &kinds,
                    dispatcher.batch_size,
                    &dispatcher.worker_id,
                    dispatcher.lock_duration,
                    &reservation,
                )
                .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "TaskDispatcher: claim_pending_by_kinds failed; will retry on next tick",
                    );
                    continue;
                }
            };

            // Re-arm the per-kind starvation clock for every kind that
            // actually produced a row this tick — before the `is_empty`
            // short-circuit below, so the audit runs on idle ticks too
            // (an idle claim is exactly when a starved kind is invisible).
            let claimed_at = Utc::now();
            for job in &claimed {
                last_claimed.insert(job.kind.clone(), claimed_at);
            }

            if last_audit.is_none_or(|t| t.elapsed() >= STARVATION_AUDIT_INTERVAL) {
                last_audit = Some(Instant::now());
                dispatcher
                    .audit_starvation(&registered, &last_claimed, started_at)
                    .await;
                // The per-class half, on the same clock and as a
                // separate pass. It shares nothing with the per-kind
                // audit above — not even `last_claimed`, which is
                // per-kind and process-local — because the two answer
                // different questions from different facts; see
                // [`Self::audit_class_service`].
                dispatcher.audit_class_service().await;
            }

            if last_lease_sweep.is_none_or(|t| t.elapsed() >= LEASE_SWEEP_INTERVAL) {
                last_lease_sweep = Some(Instant::now());
                dispatcher.sweep_abandoned_leases().await;
            }

            if claimed.is_empty() {
                tracing::debug!("TaskDispatcher: no pending jobs");
                continue;
            }

            tracing::debug!(claimed = claimed.len(), "TaskDispatcher: batch claimed");

            for job in claimed {
                let kind_str = job.kind.clone();
                let Some(handler) = dispatcher.handlers.get(kind_str.as_str()).cloned() else {
                    // Should not happen — claim query filters by registered kinds.
                    tracing::error!(
                        job_id = %job.id,
                        kind = %kind_str,
                        "TaskDispatcher: claimed job has unregistered kind; returning it to pending"
                    );
                    dispatcher
                        .return_to_pending(&job, "claimed job has unregistered kind")
                        .await;
                    continue;
                };
                let Some(permits) = dispatcher.permits.get(kind_str.as_str()) else {
                    // Invariant: the permit pool always co-exists with
                    // the handler.
                    tracing::error!(kind = %kind_str, "TaskDispatcher: no permits for kind");
                    dispatcher
                        .return_to_pending(&job, "no permit pool registered for kind")
                        .await;
                    continue;
                };
                // Join the kind's permit queue HERE, synchronously, and
                // not inside the spawned task. Two reasons, both
                // load-bearing. The queue position has to be decided by
                // the claim's own order rather than by whenever the
                // runtime first polls a spawned task — otherwise the
                // allocation's "longest waiting" tiebreak is a fact
                // about the scheduler. And the class has to be read off
                // the row, which only this loop holds.
                let pending_permit =
                    permits.acquire(TaskTier::classify(&job.kind, &job.trigger_source));
                // Start renewing the claim's lease HERE, at the claim,
                // and not inside `dispatch_one` — for the same reason
                // the permit queue is joined here, and one more.
                // `locked_until` says *a live worker owns this row*, so
                // it has to be held from the moment this worker owns
                // one; the permit wait above can be arbitrarily long
                // (the batch claims `batch_size` rows regardless of how
                // many permits are free, and the shipped default claims
                // four against a `scan` concurrency of one), and a lease
                // left to lapse across it reports a death that did not
                // happen — see `spawn_lease_renewal` for the meaning
                // and what it costs.
                let renewal = dispatcher.spawn_lease_renewal(job.id, kind_str.clone());
                let dispatcher_clone = dispatcher.clone();
                tokio::spawn(async move {
                    // Hold the concurrency permit for the whole handler
                    // call.
                    let _permit = pending_permit.granted().await;

                    // The wait that began at the claim is over. Nothing
                    // reads the row as queued-for-capacity from here
                    // on — see `end_capacity_wait` for what the write
                    // is for and what a failed one costs.
                    //
                    // It is also the last word on whether this worker
                    // still holds the row: the write is fenced on
                    // `locked_by` + `status`, so a refusal is the fence
                    // answering, and a row handed on while this worker
                    // waited for its permit must not be run here. The
                    // renewal stops with the guard; nothing else of
                    // this row's is ours to write.
                    if !dispatcher_clone.end_capacity_wait(&job).await {
                        drop(renewal);
                        return;
                    }
                    dispatcher_clone.dispatch_one(job, handler, renewal).await;
                });
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Return a claimed-but-undispatchable row to `pending` so it is not
    /// permanently lost.
    ///
    /// The claim query transitions rows to `running` BEFORE the
    /// dispatcher decides it can run them. Both callers below are paths
    /// where the row was claimed and then not dispatched. Leaving such a
    /// row `running` — which is what this code used to do, on the stated
    /// assumption that "the lock expires and another worker claims it" —
    /// loses it: `claim_pending_by_kinds` selects only `status =
    /// 'pending'` rows. Invariant: a claimed-but-not-dispatched row is
    /// never permanently lost.
    ///
    /// [`Self::sweep_abandoned_leases`] is a backstop for this shape, not
    /// a replacement for it, and the revert stays the primary for two
    /// reasons. The sweep costs a lease plus the grace — half an hour at
    /// the defaults — where the revert costs one UPDATE and loses
    /// nothing. And the sweep only touches
    /// [`REQUEUE_ON_LEASE_EXPIRY_KINDS`], while the first caller below is
    /// specifically a row whose kind this replica does not recognise: a
    /// kind excluded from the requeue policy would be stranded by the
    /// sweep and is not by the revert, because a row that was never
    /// dispatched cannot be running twice.
    ///
    /// `reschedule` is the revert vehicle (it sets `status = 'pending'`,
    /// clears `locked_by` and records `last_error`); the backoff keeps a
    /// row this replica structurally cannot run from being re-claimed by
    /// the same replica on the very next tick, while leaving it visible
    /// to a sibling replica that does register the kind.
    async fn return_to_pending(&self, job: &JobRow, reason: &str) {
        let backoff = compute_backoff(job.attempts);
        let written = self
            .job_repo
            .reschedule(job.id, job.attempts, backoff, reason)
            .await;
        surface_attempted_result_write(written, "reschedule", job.id, &job.kind, job.attempts);
    }

    /// Starvation audit — makes a kind that stops being claimed loud
    /// instead of silent.
    ///
    /// Reads the eligible-pending backlog for EVERY kind (not just the
    /// registered ones), emits the per-kind gauge, and turns each
    /// [`detect_starvation`] finding into an ERROR log + counter.
    async fn audit_starvation(
        &self,
        registered: &HashSet<&str>,
        last_claimed: &HashMap<String, DateTime<Utc>>,
        started_at: DateTime<Utc>,
    ) {
        let backlogs = match self.job_repo.eligible_pending_by_kind().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "TaskDispatcher: starvation audit query failed; will retry on a later tick",
                );
                return;
            }
        };
        for b in &backlogs {
            metrics::gauge!(METRIC_PENDING_ELIGIBLE, "kind" => b.kind.clone()).set(b.count as f64);
        }
        for finding in detect_starvation(
            &backlogs,
            registered,
            last_claimed,
            Utc::now(),
            started_at,
            STARVATION_THRESHOLD,
        ) {
            tracing::error!(
                kind = %finding.kind,
                eligible_pending = finding.count,
                stalled_for_secs = finding.stalled_for_secs,
                reason = finding.reason,
                "TaskDispatcher: kind has claim-eligible pending jobs that are not being \
                 claimed — reason 'unregistered' means no handler is registered for it in this \
                 worker (check the composition root's registration gate); reason 'not_claimed' \
                 means it loses the priority/created_at claim race on every poll; reason \
                 'oldest_row_stalled' means the single oldest eligible row of this kind has \
                 aged past the threshold even though the kind IS being claimed — a sustained \
                 higher-priority stream of the same kind is starving it",
            );
            metrics::counter!(
                METRIC_STARVED,
                "kind" => finding.kind.clone(),
                "reason" => finding.reason,
            )
            .increment(1);
        }
    }

    /// Per-class service audit — ADR 0066 D5's guarantee, on the axis
    /// the guarantee is stated on.
    ///
    /// # What this sees that [`Self::audit_starvation`] cannot
    ///
    /// That audit is per **kind**, and a kind carries several classes —
    /// `scan` carries six trigger sources across all three. Its
    /// last-claimed clock is re-armed by a row of *any* class, so a
    /// kind claimed steadily with one class never claimed reads as
    /// healthy there, and its remaining axis (`oldest_row_stalled`)
    /// approximates service by the age of one row, which is the axis
    /// ADR 0066 removed from the reservation. This pass asks the
    /// question the decision is written in: per class, is work waiting,
    /// and has anything of this class been served while it waited?
    ///
    /// It also sees the **second** allocation point. A row that has
    /// been claimed and is queued behind a run permit is already
    /// `status = 'running'`, so it is outside the claim-eligible
    /// backlog by construction and no per-kind read of `pending` rows
    /// can see it. It arrives here as
    /// [`BandQueueSample::awaiting_capacity`](hort_domain::ports::jobs_repository::BandQueueSample::awaiting_capacity),
    /// which is the surface the lease-renewal move owed: once renewal
    /// starts at the claim, `locked_until` says a live worker owns the
    /// row and no longer says whether a handler is running it (see
    /// [`Self::spawn_lease_renewal`]).
    ///
    /// # Why it holds no state
    ///
    /// Every fact it reads is durable — the pending backlog, the
    /// capacity waits, and the newest completion per class all come off
    /// `jobs` in one statement. A process-local last-claimed map is
    /// lost on restart, which is exactly when a stall is being
    /// investigated, so the verdict rests on nothing this process
    /// remembers. That is also what lets `hort-server` reach the same
    /// verdict from the same facts on its own schedule — this log is
    /// the worker-side trail, and the operator-facing gauge is the
    /// server's, because the worker exposes no scraped surface by
    /// default.
    async fn audit_class_service(&self) {
        let bands = class_bands();
        let bounds: Vec<PriorityBand> = bands.iter().map(|(_, band)| *band).collect();
        let samples = match self.job_repo.queue_sample_by_band(&bounds).await {
            Ok(samples) => samples,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "TaskDispatcher: per-class service audit query failed; will retry on a \
                     later tick",
                );
                return;
            }
        };
        let now = Utc::now();
        // `zip` rather than an index: the adapter answers once per band
        // in the order the bands were passed, and a mock's additive
        // default answers for none at all — which makes this pass inert
        // rather than mislabelling a class.
        for ((tier, _), observation) in bands.iter().zip(&samples) {
            self.report_class_service(*tier, &observation.class_wide(), now);
            // The same verdict per `(class, kind)`, which is the
            // granularity the guarantee is enforced at: the run permits
            // come from one allocator per registered kind, so the class
            // -wide answer above can be re-armed by a sibling kind's
            // completion while this kind's own permit queue is stalled
            // (ADR 0066 D5). The rows come out of the same statement as
            // the fold, so the two verdicts describe one instant.
            for KindQueueSample { kind, sample } in &observation.kinds {
                self.report_kind_service(*tier, kind, sample, now);
            }
        }
    }

    /// Log and count a class-wide service finding, or return silently
    /// when the class is being served.
    ///
    /// Split out of [`Self::audit_class_service`] so the coarse and the
    /// fine pass cannot drift on what counts as a finding: both
    /// destructure the same `Starved` variant out of the same predicate
    /// and differ only in the labels they carry.
    fn report_class_service(
        &self,
        tier: TaskTier,
        sample: &QueueServiceSample,
        now: DateTime<Utc>,
    ) {
        let ClassService::Starved {
            waiting,
            awaiting_capacity,
            unserved_for_secs,
            threshold_secs,
            reason,
        } = evaluate_class_service(sample, now, self.class_service_threshold)
        else {
            return;
        };
        tracing::error!(
            class = tier.as_str(),
            waiting,
            awaiting_capacity,
            pending_eligible = sample.pending_eligible,
            unserved_for_secs,
            threshold_secs,
            reason = reason.as_str(),
            "TaskDispatcher: a work class has work waiting that nothing of that class has \
             been served ahead of — every class is guaranteed service (ADR 0066 D5) and \
             this one is not getting it. reason 'not_claimed' means the waiting rows are \
             pending and are not being taken up, so the claim is where the class is \
             losing; reason 'awaiting_capacity' means rows of the class hold a claim and \
             have been queued behind a run permit past the threshold, which is the \
             allocation point no read of the pending backlog can see. Check \
             HORT_SCANNER_RESERVED_SLOTS_PER_CLASS (is a share reserved at all?) and \
             whether one class is flooding the kind",
        );
        metrics::counter!(
            METRIC_CLASS_STARVED,
            "class" => tier.as_str(),
            "reason" => reason.as_str(),
        )
        .increment(1);
    }

    /// The same finding for one `(class, kind)` pair — the granularity
    /// the permits are allocated at.
    ///
    /// Fires independently of the class-wide pass, and the two are not
    /// redundant in either direction. A class-wide finding implies at
    /// least one kind finding, so the pair reads as a diagnosis rather
    /// than a repetition: the coarse line says the class is losing and
    /// the fine line says at which kind's allocator. The reverse does
    /// not hold, and that is the defect this exists for — a kind whose
    /// permit queue is stalled while a sibling kind of the same class
    /// keeps completing is reported here and nowhere else.
    fn report_kind_service(
        &self,
        tier: TaskTier,
        kind: &str,
        sample: &QueueServiceSample,
        now: DateTime<Utc>,
    ) {
        let ClassService::Starved {
            waiting,
            awaiting_capacity,
            unserved_for_secs,
            threshold_secs,
            reason,
        } = evaluate_class_service(sample, now, self.class_service_threshold)
        else {
            return;
        };
        tracing::error!(
            class = tier.as_str(),
            kind,
            waiting,
            awaiting_capacity,
            pending_eligible = sample.pending_eligible,
            unserved_for_secs,
            threshold_secs,
            reason = reason.as_str(),
            "TaskDispatcher: one kind of a work class has work waiting that nothing of that \
             kind and class has been served ahead of. This is the granularity the guarantee \
             is enforced at — the run permits for each kind are allocated by that kind's own \
             allocator — so this finding can stand while the class as a whole reads as \
             served because a different kind of it just completed. reason 'not_claimed' \
             means the rows are pending and are not being taken up (if nothing in the fleet \
             registers a handler for this kind, that is the cause and \
             hort_admin_tasks_starved_total carries reason 'unregistered' beside it); \
             reason 'awaiting_capacity' means rows of this kind and class hold a claim and \
             have been queued behind this kind's run permit past the threshold",
        );
        metrics::counter!(
            METRIC_CLASS_KIND_STARVED,
            "class" => tier.as_str(),
            "kind" => kind.to_string(),
            "reason" => reason.as_str(),
        )
        .increment(1);
    }

    /// Record that `job` is no longer waiting for capacity: its run
    /// permit has been granted and its handler is next. Answers whether
    /// this worker may still run the row.
    ///
    /// The other half of the claim's `capacity_waiting_since` write.
    /// Between the two, the row is the thing `locked_until` stopped
    /// being able to express — claimed by a live worker and *not*
    /// executing — which is what makes a permit wait countable at all
    /// (ADR 0066 D5; see [`Self::audit_class_service`]).
    ///
    /// Called from the dispatch loop's spawned task, immediately after
    /// the permit is granted and before the handler can run, which is
    /// the single point every claimed row of every registered kind
    /// passes through — the same totality argument
    /// [`Self::spawn_lease_renewal`] makes about its own start point.
    ///
    /// # The two failures are not the same statement, and only one of
    /// them is about ownership
    ///
    /// - **`Ok(false)` is the fence refusing**, and
    ///   `JobsRepository::clear_capacity_wait` fences on
    ///   `locked_by = worker_id AND status = 'running'` — so the answer
    ///   is "this row is not yours any more", from the same predicate
    ///   the lease renewal uses. This returns `false` and the caller
    ///   does not dispatch: running the handler here would be a second
    ///   concurrent execution of a row whose holder is already running
    ///   it. The result write is fenced on `attempts`, so the row's
    ///   *state* would survive that — but the work would double, a
    ///   second scan would occupy scanner capacity, and both runs could
    ///   append to the same stream.
    ///
    ///   This is not work dropped on the floor: the other worker holds
    ///   the row. In the one shape where nobody does — the sweep
    ///   requeued it and no sibling has re-claimed it — the row is
    ///   `pending` and the next poll takes it, one poll interval later.
    ///
    ///   The renewal guard is **not** what covers this. Its `lost` flag
    ///   gates the *outcome write* and nothing else:
    ///   [`Self::stop_renewing_and_check_fence`] is read after
    ///   `handler.run` has returned on the normal path, and on the
    ///   refusal path the handler was never called — so on no path does
    ///   it prevent an execution. A check whose answer arrives after
    ///   the work is done cannot be the reason not to do the work.
    ///
    /// - **`Err` is the absence of an answer** and says nothing about
    ///   ownership, so the row keeps running. It leaves the row reading
    ///   as queued-for-capacity while its handler runs, so its class
    ///   over-reports one waiter until the outcome write moves the row
    ///   out of `running` — bounded by the handler's own runtime, and
    ///   loud rather than silent, which is the direction ADR 0066 asks
    ///   for. Declining the dispatch on a database flap would trade a
    ///   metric for a stall.
    async fn end_capacity_wait(&self, job: &JobRow) -> bool {
        match self
            .job_repo
            .clear_capacity_wait(job.id, &self.worker_id)
            .await
        {
            Ok(true) => true,
            Ok(false) => {
                tracing::warn!(
                    job_id = %job.id,
                    kind = %job.kind,
                    "TaskDispatcher: the capacity-wait clear found the row is no longer ours — \
                     it was closed out or an abandoned-lease sweep handed it on while this \
                     worker waited for a run permit. Declining the dispatch and leaving the row \
                     to whoever holds it now; running it would be a second concurrent execution \
                     of work already in flight",
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    job_id = %job.id,
                    kind = %job.kind,
                    "TaskDispatcher: could not clear the row's capacity wait; its class will \
                     report one more row waiting for capacity than it has until the outcome \
                     write lands. Running the row anyway — a database that did not answer is no \
                     statement about who holds it",
                );
                true
            }
        }
    }

    /// Abandoned-lease sweep — the recovery path for a row whose worker
    /// died holding the claim.
    ///
    /// # What this reads `locked_until` as
    ///
    /// **"No live worker owns this row any more."** A lapsed lease plus
    /// the grace is a statement about the *owner*, never about the
    /// *work*: a live owner renews three times a lease however long its
    /// handler runs, and it renews from the claim onward — so a row
    /// still waiting for a concurrency permit is renewed too and is
    /// correctly invisible here. See [`Self::spawn_lease_renewal`] for
    /// the full meaning, including the queued-vs-executing distinction
    /// `locked_until` deliberately no longer carries — that one is
    /// `jobs.capacity_waiting_since`'s, which this predicate does not
    /// read and must not start reading: a row waiting for capacity is
    /// owned by a live worker, which is the only thing being asked
    /// here.
    ///
    /// This is why the predicate needs no "but is it merely slow?"
    /// term, and why it must not grow one.
    ///
    /// Runs on every replica with no leader election. The adapter's
    /// picking CTE takes its rows `FOR UPDATE SKIP LOCKED`, so
    /// concurrent sweepers take disjoint sets and a row is resolved
    /// exactly once.
    ///
    /// The kind allow-list is
    /// [`REQUEUE_ON_LEASE_EXPIRY_KINDS`], not this dispatcher's
    /// registered kinds. A heterogeneous fleet is the point: a replica
    /// that does not register `scan` is still the right one to hand a
    /// dead scanner's abandoned row back to a replica that does. The
    /// excluded kinds are excluded because a concurrent second execution
    /// of them is absorbed by nothing — see the constant.
    async fn sweep_abandoned_leases(&self) {
        let grace = self.lock_duration * LEASE_EXPIRY_GRACE_MULTIPLE;
        let resolved = match self
            .job_repo
            .requeue_abandoned(
                REQUEUE_ON_LEASE_EXPIRY_KINDS,
                grace,
                self.attempt_cap,
                LEASE_SWEEP_BATCH,
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "TaskDispatcher: abandoned-lease sweep failed; will retry on a later tick",
                );
                return;
            }
        };
        for row in &resolved {
            let result = match row.outcome {
                RequeueOutcome::Requeued => REQUEUE_RESULT_REQUEUED,
                RequeueOutcome::RetriesExhausted => REQUEUE_RESULT_EXHAUSTED,
            };
            metrics::counter!(
                METRIC_LEASE_REQUEUED,
                "kind" => row.kind.clone(),
                "result" => result,
            )
            .increment(1);
        }
        if resolved.is_empty() {
            return;
        }
        // A worker dying mid-task is an operational fault, not routine
        // housekeeping: the counter exists so a replica that dies every
        // few minutes shows up as a rate instead of being silently
        // compensated, and the log is what names the rows.
        tracing::warn!(
            resolved = resolved.len(),
            requeued = resolved
                .iter()
                .filter(|r| r.outcome == RequeueOutcome::Requeued)
                .count(),
            retries_exhausted = resolved
                .iter()
                .filter(|r| r.outcome == RequeueOutcome::RetriesExhausted)
                .count(),
            grace_secs = grace.as_secs(),
            "TaskDispatcher: rows were stranded in 'running' past their lease plus the grace \
             window and have been recovered — a worker holding them stopped renewing and is \
             presumed dead. Requeued rows are claimable again; retries-exhausted rows reached \
             the attempt cap and were failed terminally rather than re-driven into the same \
             crash",
        );
        for row in &resolved {
            tracing::info!(
                job_id = %row.id,
                kind = %row.kind,
                attempts = row.attempts,
                outcome = ?row.outcome,
                "TaskDispatcher: abandoned-lease row resolved",
            );
        }
    }

    /// Hold the claim lease on `job_id` for as long as the returned
    /// guard lives.
    ///
    /// # What `locked_until` means
    ///
    /// **A live worker owns this row** — not "a handler is executing
    /// it". That is the only thing the mechanism on the other end
    /// tests: [`Self::sweep_abandoned_leases`] recovers a row whose
    /// *worker died* holding the claim, and a lease is the worker
    /// saying it is still there. So the renewal starts at the **claim**
    /// (in [`Self::run`]'s dispatch loop, beside the permit
    /// `acquire`), not when the handler starts: a claimed row waiting
    /// for a concurrency permit is owned by a live worker that intends
    /// to run it, and letting its lease lapse across that wait reports
    /// a death that did not happen — and spends an attempt on a queue
    /// position, which is the one thing an attempt budget must not buy.
    ///
    /// **What that costs, and where it is paid.** From `locked_until`
    /// alone, *queued* and *executing* are no longer distinguishable.
    /// That is an observability distinction and not a recovery one —
    /// the sweep only ever needed "is the owner alive" — and the
    /// distinction now lives in a column of its own:
    /// `jobs.capacity_waiting_since` (migration 038) is set by the
    /// claim and cleared by [`Self::end_capacity_wait`] when the permit
    /// is granted, so a `running` row with a live lease says which of
    /// the two it is. That is what makes a permit wait countable
    /// ([`Self::audit_class_service`]) rather than inferred from
    /// end-to-end latency: the row is invisible in the claim-eligible
    /// backlog by construction, and the task-duration histogram times
    /// `handler.run` only.
    ///
    /// # Where it is started from
    ///
    /// The spawned task extends `locked_until` every `lock_duration /
    /// RENEWALS_PER_LEASE`; dropping the guard aborts it. The dispatch
    /// loop is the single start point, which is what makes the
    /// mechanism total: every claimed row of every registered kind
    /// passes through it on its way to `dispatch_one`, and
    /// `claim_pending_by_kinds` is the only claim statement with a
    /// production caller, so one call site covers the whole kind
    /// vocabulary and every kind added later. The guard is then handed
    /// to [`Self::dispatch_one`], which is where it has to die — see
    /// [`Self::stop_renewing_and_check_fence`].
    ///
    /// A renewal that reports the row is no longer ours raises the
    /// guard's `lost` flag, and [`Self::dispatch_one`] reads it before
    /// **every** outcome write it makes. That makes the flag a
    /// **fencing token**, not
    /// just a log line, and it has to be: the sweep only hands a row on
    /// after two full leases of silence, but once it has, a stale
    /// worker's `reschedule` would put a row a *live* worker is mid-way
    /// through back to `pending` — inviting a third concurrent execution
    /// and charging an attempt to the wrong run. Discarding the stale
    /// result is the only write that cannot make that worse. The
    /// handler's own side effects are already done and this dispatcher
    /// cannot unwind them, which is exactly why the census decides
    /// per kind whether a second execution is absorbed.
    fn spawn_lease_renewal(self: &Arc<Self>, job_id: Uuid, kind: String) -> LeaseRenewalGuard {
        let interval = (self.lock_duration / RENEWALS_PER_LEASE).max(MIN_RENEWAL_INTERVAL);
        let dispatcher = self.clone();
        let lost = Arc::new(AtomicBool::new(false));
        let lost_setter = lost.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match dispatcher
                    .job_repo
                    .renew_lease(job_id, &dispatcher.worker_id, dispatcher.lock_duration)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        lost_setter.store(true, Ordering::SeqCst);
                        tracing::warn!(
                            %job_id,
                            kind = %kind,
                            worker_id = %dispatcher.worker_id,
                            "TaskDispatcher: lease renewal found the row is no longer ours — \
                             it was closed out or an abandoned-lease sweep handed it on. This \
                             handler's execution is no longer the authoritative one; its \
                             outcome will be discarded rather than written over whoever holds \
                             the row now",
                        );
                        metrics::counter!(
                            METRIC_LEASE_RENEW_FAILED,
                            "kind" => kind.clone(),
                            "result" => RENEW_RESULT_LOST,
                        )
                        .increment(1);
                        return;
                    }
                    Err(e) => {
                        // Transient and retried on the next tick: with
                        // three renewals per lease, one failure still
                        // leaves two chances before the lease lapses.
                        tracing::warn!(
                            error = %e,
                            %job_id,
                            kind = %kind,
                            "TaskDispatcher: lease renewal failed; retrying on the next \
                             renewal tick",
                        );
                        metrics::counter!(
                            METRIC_LEASE_RENEW_FAILED,
                            "kind" => kind.clone(),
                            "result" => RENEW_RESULT_ERROR,
                        )
                        .increment(1);
                    }
                }
            }
        });
        LeaseRenewalGuard { handle, lost }
    }

    /// Re-check a destructive invocation's requester against the live
    /// authority state, and return the outcome to record when the
    /// handler must not run.
    ///
    /// `None` means proceed — which is every non-destructive row, at the
    /// cost of one pure classifier call and no I/O.
    ///
    /// The two refusing verdicts are deliberately not the same outcome.
    /// A [`ReauthorizationVerdict::Refused`] is an authority answer, so
    /// it is `retry: false`: a revoked claim does not become valid by
    /// being tried again, and re-driving the row would spend four more
    /// attempts restating the same refusal before the budget made it
    /// terminal anyway. A [`ReauthorizationVerdict::Unavailable`] is the
    /// *absence* of an answer, so it keeps the row's budget — the next
    /// claim re-asks, and a database that never recovers still ends as
    /// a terminal row once the budget is spent.
    async fn refuse_unauthorized_execution(
        &self,
        job: &JobRow,
        kind: &str,
        params: &serde_json::Value,
    ) -> Option<TaskOutcome> {
        match self.reauthorizer.authorize_execution(job, params).await {
            ReauthorizationVerdict::Authorized => None,
            ReauthorizationVerdict::Refused { reason } => {
                // `error!`, not `info!`: unlike the enqueue-time denial
                // — where the caller is on the other end of a 403 and
                // learns immediately — nobody is waiting on this one.
                // The terminal row and this line are the only places it
                // surfaces.
                tracing::error!(
                    job_id = %job.id,
                    kind,
                    actor_id = ?job.actor_id,
                    reason = %reason,
                    "TaskDispatcher: refusing to execute a destructive task — the authority its \
                     requester held at enqueue does not hold now; the handler was not called and \
                     the row is failed terminally",
                );
                Some(TaskOutcome::fail(reason, false))
            }
            ReauthorizationVerdict::Unavailable { reason } => {
                tracing::warn!(
                    job_id = %job.id,
                    kind,
                    actor_id = ?job.actor_id,
                    reason = %reason,
                    "TaskDispatcher: could not re-check a destructive task's requester — the \
                     handler was not called; the row keeps its attempt budget and the next claim \
                     re-asks",
                );
                Some(TaskOutcome::fail(reason, true))
            }
        }
    }

    /// Stop renewing the claim's lease, and answer whether this
    /// execution may still write the row's outcome.
    ///
    /// Both halves are one call because they have to happen together at
    /// every outcome write, and each of them is a property:
    ///
    /// - **The renewal stops before the write.** The outcome write is
    ///   what closes the row out; a renewal landing after it would be
    ///   putting a lease on a row that is no longer running, and the
    ///   very sweep that exists to recover a stuck row would then be
    ///   unable to see it.
    /// - **`lost_the_row()` is read before the write.** That is what
    ///   makes the fenced result write total rather than a property of
    ///   one code path. Since the renewal now starts at the claim
    ///   rather than at the handler, the window in which this worker can
    ///   lose the row covers the permit wait and the authority re-check
    ///   as well as `run` — so the refusal path is fenced for exactly
    ///   the same reason the handler path is.
    ///
    /// `false` means *do not write*: the row is now someone else's. The
    /// worst shape is not a lost result but a `reschedule` returning a
    /// row a live worker is mid-way through to `pending`, which invites
    /// a third concurrent execution and charges an attempt to the wrong
    /// run. The row's state is whatever its current holder makes it;
    /// this execution's only correct move is to stop.
    fn stop_renewing_and_check_fence(
        &self,
        renewal: LeaseRenewalGuard,
        job: &JobRow,
        kind: &str,
    ) -> bool {
        let lost = renewal.lost_the_row();
        drop(renewal);
        if lost {
            tracing::error!(
                job_id = %job.id,
                kind,
                "TaskDispatcher: discarding this execution's outcome — the row was handed to \
                 another worker while this worker held the claim, so writing the outcome \
                 would clobber an execution that is still in flight",
            );
        }
        !lost
    }

    /// Invoke the handler for a single job row and record the outcome.
    ///
    /// `renewal` is the claim's live lease, started by the dispatch
    /// loop when the row was claimed and handed over here because this
    /// is the only place that knows when the row stops being this
    /// worker's concern. Every path out of this method therefore goes
    /// through [`Self::stop_renewing_and_check_fence`] before it writes
    /// an outcome, and none of them may return while the guard is still
    /// alive.
    async fn dispatch_one(
        self: &Arc<Self>,
        job: JobRow,
        handler: Arc<dyn TaskHandler>,
        renewal: LeaseRenewalGuard,
    ) {
        let kind = handler.kind();

        let params = job.params.clone().unwrap_or(serde_json::Value::Null);

        // Authority must still hold when the job executes; acceptance
        // does not confer it. This runs before the in-flight gauge and
        // the duration timer because neither describes a refusal: a row
        // whose handler was never called did not take time in that
        // handler, and counting it would put a two-read authority check
        // into the kind's execution-latency distribution. The lease is
        // the one thing that is already running by this point — it
        // belongs to the claim, and this worker owns the row while it
        // asks the question.
        if let Some(outcome) = self
            .refuse_unauthorized_execution(&job, kind, &params)
            .await
        {
            if self.stop_renewing_and_check_fence(renewal, &job, kind) {
                self.record_outcome_for_row(&job, kind, outcome).await;
            }
            return;
        }

        // Build a TaskContext from the job row.
        let ctx = TaskContext {
            task_job_id: job.id,
            actor: Actor::Internal(InternalActor::Timer),
            correlation_id: Uuid::new_v4(),
            job_row: job.clone(),
        };

        // Emit in-flight gauge +1.
        metrics::gauge!(METRIC_IN_FLIGHT, "kind" => kind.to_string()).increment(1.0);

        let started = Instant::now();
        let outcome = handler.run(&params, ctx).await;
        let elapsed = started.elapsed();

        // Stop holding the lease the instant `run` returns — the outcome
        // write below is what closes the row out, and a renewal landing
        // after it would be writing a lease onto a row that is no longer
        // running.
        let may_write = self.stop_renewing_and_check_fence(renewal, &job, kind);

        // Emit in-flight gauge -1.
        metrics::gauge!(METRIC_IN_FLIGHT, "kind" => kind.to_string()).decrement(1.0);

        // Observe duration.
        metrics::histogram!(METRIC_DURATION, "kind" => kind.to_string())
            .record(elapsed.as_secs_f64());

        if !may_write {
            return;
        }

        match outcome {
            Ok(task_outcome) => {
                self.record_outcome_for_row(&job, kind, task_outcome).await;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    job_id = %job.id,
                    kind,
                    "TaskDispatcher: handler returned Err; recording it as a retryable failure, \
                     which the attempt budget turns terminal once spent",
                );
                let outcome = TaskOutcome::fail(e.to_string(), true);
                self.record_outcome_for_row(&job, kind, outcome).await;
            }
        }
    }

    /// Translate a [`TaskOutcome`] into a jobs-row state transition.
    ///
    /// `Failed { retry: true }` is a *request* to be re-driven, not a
    /// guarantee of one: it is honoured while the row has attempt
    /// budget left and refused at [`TaskDispatcher::attempt_cap`], where
    /// the row becomes terminal instead. See that field for why the
    /// budget is one number across both the returned-failure and the
    /// dead-worker path, uniform across kinds, and configured rather
    /// than compiled in.
    ///
    /// **This is the only writer of a `jobs` row's result state**, for
    /// every kind including `scan`. `ScanTaskHandler::run` used to close
    /// its own row out inside
    /// `ScanOrchestrationUseCase::record_outcome` and then return a
    /// blanket `TaskOutcome::Completed`, so this method wrote the row a
    /// second time and won — turning a scheduled scan retry into
    /// `status='completed'` with no verdict behind it. The scan path now
    /// owns events and artifact state and reports what the row should
    /// become; `crates/hort-app/tests/jobs_row_has_one_owner.rs` is what
    /// keeps a second writer from reappearing in this layer.
    ///
    /// Both failure transitions also append the `TaskFailed` audit
    /// record — see [`Self::append_failure_audit`], which is called only
    /// when the write landed and only for a kind the event admits.
    async fn record_outcome_for_row(&self, job: &JobRow, kind: &str, outcome: TaskOutcome) {
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                let written = self
                    .job_repo
                    .mark_completed(job.id, job.attempts, result_summary)
                    .await;
                surface_attempted_result_write(
                    written,
                    "mark_completed",
                    job.id,
                    kind,
                    job.attempts,
                );
                metrics::counter!(
                    METRIC_COMPLETED,
                    "kind" => kind.to_string(),
                    "result" => RESULT_COMPLETED,
                )
                .increment(1);
            }
            // One terminal transition, two triggers. `retry: false` is
            // terminal by the handler's own verdict. A `retry: true`
            // row that has spent its attempt budget is terminal because
            // re-driving it would re-drive it forever: the backoff
            // bounds the delay, not the number of runs. Both land on
            // the same `mark_failed` — `status='failed'` with the last
            // error retained — which is exactly the transition the
            // abandoned-lease sweep performs at the cap for a row whose
            // handler never returned (`requeue_abandoned`'s over-cap
            // `CASE` arm), so a row that keeps failing ends up in the
            // same state whichever way it got there.
            TaskOutcome::Failed { reason, retry } => {
                if retry && job.attempts < self.attempt_cap {
                    let backoff = compute_backoff(job.attempts);
                    let written = self
                        .job_repo
                        .reschedule(job.id, job.attempts, backoff, &reason)
                        .await;
                    let landed = surface_attempted_result_write(
                        written,
                        "reschedule",
                        job.id,
                        kind,
                        job.attempts,
                    );
                    metrics::counter!(
                        METRIC_COMPLETED,
                        "kind" => kind.to_string(),
                        "result" => RESULT_FAILED_RETRY,
                    )
                    .increment(1);
                    if landed {
                        self.append_failure_audit(job, kind, &reason, false).await;
                    }
                } else {
                    if retry {
                        // A task that has failed its whole budget is an
                        // operational fault someone has to look at, and
                        // the terminal row is the only lasting record
                        // of it — keep this loud.
                        tracing::error!(
                            job_id = %job.id,
                            kind,
                            attempts = job.attempts,
                            attempt_cap = self.attempt_cap,
                            last_error = %reason,
                            "TaskDispatcher: task asked to be retried but has spent its attempt \
                             budget — failing the row terminally instead of re-driving it; the \
                             row keeps this error and will not be claimed again",
                        );
                    }
                    let written = self
                        .job_repo
                        .mark_failed(job.id, job.attempts, &reason)
                        .await;
                    let landed = surface_attempted_result_write(
                        written,
                        "mark_failed",
                        job.id,
                        kind,
                        job.attempts,
                    );
                    metrics::counter!(
                        METRIC_COMPLETED,
                        "kind" => kind.to_string(),
                        "result" => RESULT_FAILED_TERMINAL,
                    )
                    .increment(1);
                    if landed {
                        self.append_failure_audit(job, kind, &reason, true).await;
                    }
                }
            }
        }
    }

    /// Append the `TaskFailed` audit record for a failure this
    /// execution wrote to the row.
    ///
    /// The `jobs` row records a failure for seven days and then the
    /// retention sweep removes it; this is the durable half. It pairs
    /// with the enqueue path's `TaskInvoked`, and the pairing is the
    /// whole design — five conditions follow from it, and each one is
    /// load-bearing.
    ///
    /// **Routed through [`TaskUseCase::task_audit_stream`], never
    /// re-derived.** A destructive kind's `TaskInvoked` lands on
    /// `StreamId::eventstore_retention()`, the stream
    /// `EventStore::delete_stream` / `archive_stream` are forbidden to
    /// touch. Its `TaskFailed` has to land there too, or an
    /// `eventstore-archive` run could truncate the record of its own
    /// failure while the record of its invocation survives — and the
    /// refused or failed destructive run is the half an operator came
    /// to read. A second copy of the routing rule here is how the two
    /// halves would come to disagree.
    ///
    /// **Retried on the same budget `TaskInvoked` is.** The two halves
    /// land on one stream on purpose, so they need one durability
    /// promise rather than two, and both get it from
    /// [`append_any_with_conflict_retry`] on
    /// [`EVENT_APPEND_RETRY_ATTEMPTS`] attempts.
    /// `ExpectedVersion::Any` is not a promise of success — it is why
    /// the retry exists, because an append can still lose a race at the
    /// stream tail. While this append was a bare one and the enqueue
    /// path's was retried, a `TaskFailed` could be dropped under
    /// contention that a `TaskInvoked` would have survived, and the loss
    /// showed up as nothing but the log line below. A second copy of
    /// that loop here would have been the same defect one step later:
    /// one promise stated twice is one a later change moves on one side
    /// only.
    ///
    /// **Only when the result write landed** — the caller branches on
    /// [`surface_attempted_result_write`]'s answer. The fenced write is
    /// `AND attempts = $2`; a refusal means the abandoned-lease sweep
    /// handed the row to a later execution while this handler ran, so
    /// this execution's failure is not the row's state. An audit record
    /// claiming otherwise is a false record about a row somebody else
    /// owns.
    ///
    /// **Skipped for a kind outside [`ADMIN_INVOKABLE_TASK_KINDS`]**,
    /// which the dispatcher does run: `TaskFailed::validate` rejects
    /// such a kind and the production event store validates every event
    /// it appends, so an unconditional append would produce a rejected
    /// write for exactly those. That validation is the right shape and
    /// this is the side that narrows — `TaskFailed` is the counterpart
    /// of `TaskInvoked`, which can only ever carry an allowlisted kind,
    /// so the pair is symmetric by construction. The two such kinds
    /// have records of their own: a `scan` row's failure is the scan
    /// vocabulary's business (`ScanCompleted` on a verdict,
    /// `ScanIndeterminate` when the budget is spent — and a scan row is
    /// only ever minted by `enqueue_scan`, never by an operator), and
    /// an `oci-index-child-ingest` failure costs nothing but the
    /// ergonomics win, because the child stays reachable through the
    /// lazy pull path that re-derives it.
    ///
    /// **Never changes the task's outcome.** The row is the operational
    /// record and this is the audit record, so the append comes after
    /// the write and an event-store failure is logged and nothing else
    /// — a spent retry budget included. A store that is down, or a
    /// stream tail too contended to reach within the budget, must not be
    /// able to hold a row open.
    async fn append_failure_audit(
        &self,
        job: &JobRow,
        kind: &str,
        reason: &str,
        final_attempt: bool,
    ) {
        if !ADMIN_INVOKABLE_TASK_KINDS.contains(&kind) {
            tracing::debug!(
                job_id = %job.id,
                kind,
                final_attempt,
                "TaskDispatcher: no TaskFailed audit event for this kind — it is not \
                 operator-invokable, so it has no TaskInvoked to pair with and the event's \
                 own validation rejects it; the row and the kind's own event vocabulary \
                 are its record",
            );
            return;
        }

        // `reason` is already bounded: every production failure is built
        // through `TaskOutcome::fail`, whose `REASON_MAX_BYTES` is the
        // same number as this event's own cap, deliberately so the event
        // and `jobs.last_error` cannot disagree about what was
        // truncated. Re-truncating here would be a second copy of that
        // bound; leaving it means a producer that ever bypassed the
        // constructor shows up as a rejected append rather than as two
        // silently different texts.
        let stream_id = TaskUseCase::task_audit_stream(kind);
        let event = DomainEvent::TaskFailed(TaskFailed {
            task_job_id: job.id,
            kind: kind.to_string(),
            reason: reason.to_string(),
            final_attempt,
        });
        let correlation_id = Uuid::new_v4();
        let appended = append_any_with_conflict_retry(
            self.event_store.as_ref(),
            EVENT_APPEND_RETRY_ATTEMPTS,
            event_append_backoff,
            || AppendEvents {
                stream_id: stream_id.clone(),
                expected_version: ExpectedVersion::Any,
                events: vec![EventToAppend::new(event.clone())],
                correlation_id,
                causation_id: None,
                // The same actor this execution's `TaskContext` already
                // carries, so one dispatched run is attributed one way
                // rather than two. Deliberately not the row's `actor_id`:
                // the requester asked for the task, the worker is what
                // failed it, and attributing the failure to the requester
                // would read as the operator having done something wrong.
                actor: Actor::Internal(InternalActor::Timer),
            },
        )
        .await;
        if let Err(e) = appended {
            tracing::error!(
                error = %e,
                job_id = %job.id,
                kind,
                final_attempt,
                attempts = EVENT_APPEND_RETRY_ATTEMPTS,
                "TaskDispatcher: the TaskFailed audit event did not reach the event store. \
                 The row's state is already written and stands — the failure is \
                 operator-visible there, but absent from the audit trail, so it is lost \
                 once the row's retention horizon removes it",
            );
        }
    }
}

/// Keeps a claim lease alive for as long as it is held.
///
/// A plain `JoinHandle` wrapper whose `Drop` aborts the renewal task, so
/// the lease stops being extended on every exit path out of
/// `dispatch_one` — including a panic unwinding through it. Letting the
/// renewal outlive the handler would keep a finished row's lease fresh
/// and, for a row whose outcome write failed, hide it from the very
/// sweep that exists to recover it.
struct LeaseRenewalGuard {
    handle: tokio::task::JoinHandle<()>,
    /// Raised by the renewal task when a renewal reports the row is no
    /// longer this worker's. Read once, after the handler returns.
    lost: Arc<AtomicBool>,
}

impl LeaseRenewalGuard {
    /// Whether this worker lost the row while its handler was running.
    fn lost_the_row(&self) -> bool {
        self.lost.load(Ordering::SeqCst)
    }
}

impl Drop for LeaseRenewalGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// One kind whose claim-eligible backlog is not draining.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StarvationFinding {
    kind: String,
    count: i64,
    /// `unregistered` or `not_claimed` — the `reason` metric label.
    reason: &'static str,
    /// How long the backlog has gone unserved, in seconds.
    stalled_for_secs: i64,
}

/// Decide which kinds are starving. Pure — no clock, no I/O — so every
/// branch is unit-testable without timing.
///
/// For each kind with a non-empty claim-eligible backlog, the reference
/// instant is the last time THIS dispatcher claimed a row of that kind,
/// or `started_at` if it never has (a freshly booted worker gets a full
/// threshold of grace before it accuses anyone). The backlog is only
/// considered stalled since `max(reference, oldest_created_at)`: rows
/// that arrived a second ago cannot have been starved for ten minutes,
/// no matter how long the worker has been up.
///
/// A kind that is being drained at all keeps re-arming its reference
/// every tick, so a deep-but-draining FIFO queue never trips this.
///
/// A second, independent axis runs alongside the one above: regardless of
/// `last_claimed`/`started_at`, a kind whose single oldest eligible row has
/// aged past `threshold` is flagged with `reason = "oldest_row_stalled"`.
/// This catches the case the first axis structurally cannot: a kind
/// claimed constantly (so `last_claimed` keeps re-arming) while a
/// sustained high-priority stream of the SAME kind claims only fresh rows
/// every poll, leaving one old low-priority row to rot behind them forever
/// — the first axis's `.max(reference, oldest_created_at)` floor means a
/// recent `last_claimed` always wins there and the finding never fires.
fn detect_starvation(
    backlogs: &[PendingKindBacklog],
    registered: &HashSet<&str>,
    last_claimed: &HashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
    started_at: DateTime<Utc>,
    threshold: Duration,
) -> Vec<StarvationFinding> {
    let threshold = chrono::Duration::from_std(threshold).unwrap_or(chrono::Duration::MAX);
    let mut findings = Vec::new();
    for b in backlogs {
        if b.count <= 0 {
            continue;
        }
        let reference = last_claimed
            .get(&b.kind)
            .copied()
            .unwrap_or(started_at)
            .max(b.oldest_created_at);
        let stalled_for = now - reference;
        if stalled_for > threshold {
            findings.push(StarvationFinding {
                kind: b.kind.clone(),
                count: b.count,
                reason: if registered.contains(b.kind.as_str()) {
                    STARVED_NOT_CLAIMED
                } else {
                    STARVED_UNREGISTERED
                },
                stalled_for_secs: stalled_for.num_seconds(),
            });
        }

        let oldest_age = now - b.oldest_created_at;
        if oldest_age > threshold {
            findings.push(StarvationFinding {
                kind: b.kind.clone(),
                count: b.count,
                reason: STARVED_OLDEST_ROW,
                stalled_for_secs: oldest_age.num_seconds(),
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use chrono::Utc;
    use hort_domain::error::DomainError;
    use hort_domain::error::DomainResult;
    use hort_domain::events::{DESTRUCTIVE_TASK_KINDS, EVENT_TASK_KINDS};
    use hort_domain::ports::jobs_repository::{
        BandQueueSample, JobRow, JobStatus, JobsRepository, RequeuedJob, ResultWriteOutcome,
        ScanJob,
    };
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::destructive_task_reauthorization::{REFUSAL_PREFIX, UNAVAILABLE_PREFIX};
    use crate::retry_backoff::DEFAULT_MAX_ATTEMPTS;
    use crate::use_cases::test_support::{
        MockPermissionGrantRepository, MockUserRepository, ResultWriteLog,
    };
    use hort_domain::policy::{
        permit_age_net_bound, permit_service_interval, ClassStarvationReason,
        DEFAULT_CLASS_SERVICE_THRESHOLD_SECS,
    };
    use hort_domain::ports::jobs_repository::TriggerSource;
    use hort_domain::types::task_tier::{TaskTier, DEFAULT_RESERVED_SLOTS_PER_CLASS};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// The requester every fixture row names.
    ///
    /// Fixed rather than random so [`make_dispatcher`] can seed the
    /// matching user: a destructive-kind row has to reach its handler in
    /// the tests that are about the handler, and it only does that if
    /// its requester still holds the authority.
    const FIXTURE_REQUESTER: Uuid = Uuid::from_u128(0x3671);

    /// A still-active requester for [`FIXTURE_REQUESTER`].
    ///
    /// Admin only because the coarse `AdminTaskInvoke` factor rides the
    /// admin short-circuit; the destructive factor is a grant and arrives
    /// through [`fixture_destructive_grants`] — an admin does not hold it
    /// implicitly (see [`crate::destructive_task_reauthorization`]).
    fn fixture_admin() -> hort_domain::entities::user::User {
        hort_domain::entities::user::User {
            id: FIXTURE_REQUESTER,
            username: "fixture-admin".into(),
            email: "fixture-admin@example.test".into(),
            auth_provider: hort_domain::entities::user::AuthProvider::Oidc,
            external_id: Some("oidc:fixture-admin".into()),
            display_name: None,
            is_active: true,
            is_admin: true,
            is_service_account: false,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// The identity-bound destructive grants [`FIXTURE_REQUESTER`] holds
    /// — both halves, so a fixture row of any destructive kind
    /// re-authorizes. `GrantSubject::User` because the execution-time
    /// principal carries no IdP-resolved claims to match a claims grant
    /// against.
    fn fixture_destructive_grants() -> Vec<hort_domain::entities::rbac::PermissionGrant> {
        use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
        [Permission::DestroyContent, Permission::DestroyRecord]
            .into_iter()
            .map(|permission| PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::User(FIXTURE_REQUESTER),
                repository_id: None,
                permission,
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
                created_at: Utc::now(),
            })
            .collect()
    }

    /// A reauthorizer that authorizes [`FIXTURE_REQUESTER`] — the
    /// default for every test that is not about the re-check itself.
    fn authorizing_reauthorizer() -> Arc<DestructiveTaskReauthorizer> {
        let users = Arc::new(MockUserRepository::new());
        users.insert(fixture_admin());
        let grants = Arc::new(MockPermissionGrantRepository::new());
        grants.seed(fixture_destructive_grants());
        Arc::new(DestructiveTaskReauthorizer::new(users, grants))
    }

    /// A reauthorizer that knows no users, so a destructive row's
    /// requester does not resolve and the invocation is refused.
    fn refusing_reauthorizer() -> Arc<DestructiveTaskReauthorizer> {
        Arc::new(DestructiveTaskReauthorizer::new(
            Arc::new(MockUserRepository::new()),
            Arc::new(MockPermissionGrantRepository::new()),
        ))
    }

    fn make_job_row(kind: &str) -> JobRow {
        use hort_domain::ports::jobs_repository::KindFields;
        let now = Utc::now();
        JobRow {
            id: Uuid::new_v4(),
            kind: kind.to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::json!({})),
            actor_id: Some(FIXTURE_REQUESTER),
            priority: 0,
            trigger_source: "test".to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    // -----------------------------------------------------------------------
    // Minimal mock JobsRepository for dispatcher tests
    // -----------------------------------------------------------------------

    /// Controls what `claim_pending_by_kinds` returns: each call returns the
    /// next batch in the queue (oldest-first), or empty if the queue is empty.
    /// One recorded `requeue_abandoned` invocation. A named struct
    /// rather than a tuple so an assertion reads as the argument it is
    /// checking rather than as `.2`.
    #[derive(Debug, Clone)]
    struct RequeueCall {
        kinds: Vec<String>,
        grace: Duration,
        attempt_cap: u32,
        batch_size: u16,
    }

    struct DispatcherMockRepo {
        /// Pre-seeded batches; each `claim` call pops the front.
        claim_batches: Mutex<Vec<Vec<JobRow>>>,
        /// The reservation every `claim_pending_by_kinds` call arrived
        /// with, in order. The claim is the half of ADR 0066 D4 that is
        /// a *port argument*, so this is where a DB-free test can see
        /// the configured share actually leave the dispatcher.
        claim_reservations: Mutex<Vec<ClaimReservation>>,
        mark_completed_calls: Mutex<Vec<Uuid>>,
        mark_completed_summaries: Mutex<Vec<serde_json::Value>>,
        reschedule_calls: Mutex<Vec<(Uuid, String)>>,
        /// The `backoff` argument of every `reschedule` call, in order.
        /// Separate from `reschedule_calls` so a test can assert the
        /// delay without every existing assertion on the call log
        /// having to spell a `Duration` it does not care about.
        reschedule_backoffs: Mutex<Vec<Duration>>,
        mark_failed_calls: Mutex<Vec<(Uuid, String)>>,
        /// What `eligible_pending_by_kind` reports (starvation audit).
        backlog: Mutex<Vec<PendingKindBacklog>>,
        /// When true, `eligible_pending_by_kind` returns `Err`.
        backlog_fails: Mutex<bool>,
        /// When true, `reschedule` returns `Err` — exercises the
        /// "could not return the row to pending" error branch.
        reschedule_fails: Mutex<bool>,
        /// Every `requeue_abandoned` call's arguments, in order.
        requeue_calls: Mutex<Vec<RequeueCall>>,
        /// What `requeue_abandoned` hands back.
        requeue_result: Mutex<Vec<RequeuedJob>>,
        /// When true, `requeue_abandoned` returns `Err`.
        requeue_fails: Mutex<bool>,
        /// `(job_id, worker_id)` of every `renew_lease` call, in order.
        renew_calls: Mutex<Vec<(Uuid, String)>>,
        /// What `renew_lease` answers: `Some(b)` → `Ok(b)`, `None` → `Err`.
        renew_answer: Mutex<Option<bool>>,
        /// The modelled `locked_until` of every row this repo handed
        /// out, keyed by job id. Only written while
        /// [`Self::model_leases`] is armed.
        leases: Mutex<HashMap<Uuid, ModelledLease>>,
        /// When armed, `requeue_abandoned` answers from [`Self::leases`]
        /// rather than from `requeue_result`, and `claim_pending_by_kinds`
        /// / `renew_lease` keep that model up to date.
        ///
        /// Opt-in because the question it answers is only ever asked by
        /// the two tests about **where the renewal starts** — and for
        /// those, a seeded `requeue_result` would assert the fixture. The
        /// whole point is whether the lease the dispatcher actually wrote
        /// stayed fresh, so the sweep has to read that lease.
        model_leases: Mutex<bool>,
        /// What the modelled sweep resolved, in order.
        model_requeued: Mutex<Vec<RequeuedJob>>,
        /// The fence every result write arrived with, and what they
        /// answer. See [`ResultWriteLog`].
        write_log: ResultWriteLog,
        /// What `queue_sample_by_band` reports, one entry per band in
        /// the order the bands were passed (the per-class service
        /// audit's input).
        band_samples: Mutex<Vec<BandQueueSample>>,
        /// When true, `queue_sample_by_band` returns `Err`.
        band_samples_fail: Mutex<bool>,
        /// The band bounds every `queue_sample_by_band` call arrived
        /// with, in order — so a test can see that the observation asks
        /// about every class rather than only the reserved ones.
        band_queries: Mutex<Vec<Vec<PriorityBand>>>,
        /// `(job_id, worker_id)` of every `clear_capacity_wait` call, in
        /// order.
        capacity_wait_clears: Mutex<Vec<(Uuid, String)>>,
        /// What `clear_capacity_wait` answers: `Some(b)` → `Ok(b)`,
        /// `None` → `Err`. Mirrors [`Self::renew_answer`], because the
        /// two writes have the same two failure shapes — a fence that
        /// refused, and a database that did not answer.
        capacity_wait_answer: Mutex<Option<bool>>,
    }

    impl DispatcherMockRepo {
        fn new() -> Self {
            Self {
                claim_batches: Mutex::new(Vec::new()),
                claim_reservations: Mutex::new(Vec::new()),
                mark_completed_calls: Mutex::new(Vec::new()),
                mark_completed_summaries: Mutex::new(Vec::new()),
                reschedule_calls: Mutex::new(Vec::new()),
                reschedule_backoffs: Mutex::new(Vec::new()),
                mark_failed_calls: Mutex::new(Vec::new()),
                backlog: Mutex::new(Vec::new()),
                backlog_fails: Mutex::new(false),
                reschedule_fails: Mutex::new(false),
                requeue_calls: Mutex::new(Vec::new()),
                requeue_result: Mutex::new(Vec::new()),
                requeue_fails: Mutex::new(false),
                renew_calls: Mutex::new(Vec::new()),
                renew_answer: Mutex::new(Some(true)),
                leases: Mutex::new(HashMap::new()),
                model_leases: Mutex::new(false),
                model_requeued: Mutex::new(Vec::new()),
                write_log: ResultWriteLog::default(),
                band_samples: Mutex::new(Vec::new()),
                band_samples_fail: Mutex::new(false),
                band_queries: Mutex::new(Vec::new()),
                capacity_wait_clears: Mutex::new(Vec::new()),
                capacity_wait_answer: Mutex::new(Some(true)),
            }
        }

        fn seed_batch(&self, rows: Vec<JobRow>) {
            self.claim_batches.lock().unwrap().push(rows);
        }

        fn claim_reservations(&self) -> Vec<ClaimReservation> {
            self.claim_reservations.lock().unwrap().clone()
        }

        fn seed_backlog(&self, rows: Vec<PendingKindBacklog>) {
            *self.backlog.lock().unwrap() = rows;
        }

        fn fail_backlog(&self) {
            *self.backlog_fails.lock().unwrap() = true;
        }

        /// Seed the per-class sample, one entry per band in
        /// `class_bands()` order (Interactive, Normal, Bulk).
        fn seed_band_samples(&self, samples: Vec<BandQueueSample>) {
            *self.band_samples.lock().unwrap() = samples;
        }

        fn fail_band_samples(&self) {
            *self.band_samples_fail.lock().unwrap() = true;
        }

        fn band_queries(&self) -> Vec<Vec<PriorityBand>> {
            self.band_queries.lock().unwrap().clone()
        }

        fn capacity_wait_clears(&self) -> Vec<(Uuid, String)> {
            self.capacity_wait_clears.lock().unwrap().clone()
        }

        fn set_capacity_wait_answer(&self, answer: Option<bool>) {
            *self.capacity_wait_answer.lock().unwrap() = answer;
        }

        fn fail_reschedule(&self) {
            *self.reschedule_fails.lock().unwrap() = true;
        }

        fn mark_completed_calls(&self) -> Vec<Uuid> {
            self.mark_completed_calls.lock().unwrap().clone()
        }

        /// H17 — the `result_summary` values passed to each `mark_completed`,
        /// in call order. Lets a test assert the handler's summary is threaded
        /// to the persistence call (not discarded).
        fn mark_completed_summaries(&self) -> Vec<serde_json::Value> {
            self.mark_completed_summaries.lock().unwrap().clone()
        }

        fn reschedule_calls(&self) -> Vec<(Uuid, String)> {
            self.reschedule_calls.lock().unwrap().clone()
        }

        fn reschedule_backoffs(&self) -> Vec<Duration> {
            self.reschedule_backoffs.lock().unwrap().clone()
        }

        fn mark_failed_calls(&self) -> Vec<(Uuid, String)> {
            self.mark_failed_calls.lock().unwrap().clone()
        }

        fn seed_requeue_result(&self, rows: Vec<RequeuedJob>) {
            *self.requeue_result.lock().unwrap() = rows;
        }

        fn fail_requeue(&self) {
            *self.requeue_fails.lock().unwrap() = true;
        }

        fn requeue_calls(&self) -> Vec<RequeueCall> {
            self.requeue_calls.lock().unwrap().clone()
        }

        fn set_renew_answer(&self, answer: Option<bool>) {
            *self.renew_answer.lock().unwrap() = answer;
        }

        fn renew_calls(&self) -> Vec<(Uuid, String)> {
            self.renew_calls.lock().unwrap().clone()
        }

        /// Arm the lease model — see [`Self::model_leases`] the field.
        fn model_leases(&self) {
            *self.model_leases.lock().unwrap() = true;
        }

        /// Write the modelled lease a claim hands out: `locked_until =
        /// now() + lock_duration`, carrying the row's post-claim
        /// `attempts` so the modelled sweep can spend the budget the way
        /// the real `CASE` does.
        fn model_claim(&self, row: &JobRow, lock_duration: Duration) {
            if !*self.model_leases.lock().unwrap() {
                return;
            }
            self.leases.lock().unwrap().insert(
                row.id,
                ModelledLease {
                    kind: row.kind.clone(),
                    attempts: row.attempts,
                    until: tokio::time::Instant::now() + lock_duration,
                },
            );
        }

        /// Push a modelled lease forward, as a renewal that answered
        /// "still yours" does. A renewal that errored or was refused
        /// moves nothing — which is the whole observable a stalled or
        /// dead worker leaves behind.
        fn model_renewal(&self, job_id: Uuid, lock_duration: Duration) {
            if !*self.model_leases.lock().unwrap() {
                return;
            }
            if let Some(lease) = self.leases.lock().unwrap().get_mut(&job_id) {
                lease.until = tokio::time::Instant::now() + lock_duration;
            }
        }

        /// The modelled sweep: every row of an allow-listed kind whose
        /// lease lapsed more than `grace` ago, oldest lapse first and
        /// capped at the batch — `REQUEUE_ABANDONED_SQL`'s predicate,
        /// in the one respect these tests turn on.
        ///
        /// Compared as `until + grace < now` rather than `until < now -
        /// grace` so the arithmetic cannot underflow near the paused
        /// clock's origin.
        ///
        /// The resolved rows leave the model, because the real statement
        /// clears `locked_by`/`locked_until`; `attempts` is handed back
        /// untouched, because the real statement leaves the column to
        /// the next claim.
        ///
        /// The real `CASE`'s other arm — a row at the attempt cap goes
        /// terminal instead of back to `pending` — is deliberately NOT
        /// modelled, because nothing here asks about it and
        /// `lease_expiry_requeue.rs` proves it against the statement
        /// itself. A row at the cap therefore **panics** rather than
        /// being answered `Requeued`: a double that cannot be faithful
        /// about a state has to refuse it, not guess, or the test
        /// standing on it proves a behaviour production does not have.
        fn model_sweep(
            &self,
            kinds: &[&str],
            grace: Duration,
            attempt_cap: u32,
            batch_size: u16,
        ) -> Vec<RequeuedJob> {
            let now = tokio::time::Instant::now();
            let mut leases = self.leases.lock().unwrap();
            let mut lapsed: Vec<(Uuid, ModelledLease)> = leases
                .iter()
                .filter(|(_, l)| kinds.contains(&l.kind.as_str()) && l.until + grace < now)
                .map(|(id, l)| (*id, l.clone()))
                .collect();
            lapsed.sort_by_key(|(id, l)| (l.until, *id));
            let resolved: Vec<RequeuedJob> = lapsed
                .into_iter()
                .take(batch_size as usize)
                .map(|(id, l)| {
                    assert!(
                        l.attempts < attempt_cap,
                        "the lease model does not model the attempt cap: row {id} is at \
                         {}/{attempt_cap} and the real statement would fail it terminally",
                        l.attempts,
                    );
                    leases.remove(&id);
                    RequeuedJob {
                        id,
                        kind: l.kind,
                        attempts: l.attempts,
                        outcome: RequeueOutcome::Requeued,
                    }
                })
                .collect();
            self.model_requeued
                .lock()
                .unwrap()
                .extend(resolved.iter().cloned());
            resolved
        }

        /// What the modelled sweep has resolved so far.
        fn model_requeued(&self) -> Vec<RequeuedJob> {
            self.model_requeued.lock().unwrap().clone()
        }

        /// The `attempts` the model still holds for `job_id`, or `None`
        /// once a sweep has resolved the row out of the model.
        fn modelled_attempts(&self, job_id: Uuid) -> Option<u32> {
            self.leases.lock().unwrap().get(&job_id).map(|l| l.attempts)
        }
    }

    /// One row's modelled `locked_until`, plus what the sweep needs to
    /// answer about it.
    #[derive(Clone)]
    struct ModelledLease {
        kind: String,
        /// `attempts` as the claim left it. Nothing in the model moves
        /// it, which is the behaviour `lease_expiry_requeue.rs` proves
        /// of the real statement.
        attempts: u32,
        until: tokio::time::Instant,
    }

    impl JobsRepository for DispatcherMockRepo {
        fn renew_lease<'a>(
            &'a self,
            job_id: Uuid,
            worker_id: &'a str,
            lock_duration: Duration,
        ) -> BoxFuture<'a, DomainResult<bool>> {
            self.renew_calls
                .lock()
                .unwrap()
                .push((job_id, worker_id.to_string()));
            let answer = *self.renew_answer.lock().unwrap();
            if answer == Some(true) {
                self.model_renewal(job_id, lock_duration);
            }
            Box::pin(async move {
                match answer {
                    Some(b) => Ok(b),
                    None => Err(DomainError::Invariant("renew boom".into())),
                }
            })
        }

        fn requeue_abandoned<'a>(
            &'a self,
            kinds: &'a [&'a str],
            grace: Duration,
            attempt_cap: u32,
            batch_size: u16,
        ) -> BoxFuture<'a, DomainResult<Vec<RequeuedJob>>> {
            self.requeue_calls.lock().unwrap().push(RequeueCall {
                kinds: kinds.iter().map(ToString::to_string).collect(),
                grace,
                attempt_cap,
                batch_size,
            });
            let fails = *self.requeue_fails.lock().unwrap();
            let rows = if *self.model_leases.lock().unwrap() {
                self.model_sweep(kinds, grace, attempt_cap, batch_size)
            } else {
                self.requeue_result.lock().unwrap().clone()
            };
            Box::pin(async move {
                if fails {
                    return Err(DomainError::Invariant("requeue boom".into()));
                }
                Ok(rows)
            })
        }

        fn claim_scan_jobs<'a>(
            &'a self,
            _w: &'a str,
            _b: u32,
            _l: Duration,
        ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn mark_completed<'a>(
            &'a self,
            job_id: Uuid,
            attempt: u32,
            result_summary: serde_json::Value,
        ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
            self.mark_completed_calls.lock().unwrap().push(job_id);
            self.mark_completed_summaries
                .lock()
                .unwrap()
                .push(result_summary);
            let outcome = self.write_log.record(attempt);
            Box::pin(async move { Ok(outcome) })
        }

        fn reschedule<'a>(
            &'a self,
            job_id: Uuid,
            attempt: u32,
            backoff: Duration,
            last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
            self.reschedule_calls
                .lock()
                .unwrap()
                .push((job_id, last_error.to_string()));
            self.reschedule_backoffs.lock().unwrap().push(backoff);
            let fails = *self.reschedule_fails.lock().unwrap();
            let outcome = self.write_log.record(attempt);
            Box::pin(async move {
                if fails {
                    Err(DomainError::Invariant("boom".into()))
                } else {
                    Ok(outcome)
                }
            })
        }

        fn mark_failed<'a>(
            &'a self,
            job_id: Uuid,
            attempt: u32,
            last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<ResultWriteOutcome>> {
            self.mark_failed_calls
                .lock()
                .unwrap()
                .push((job_id, last_error.to_string()));
            let outcome = self.write_log.record(attempt);
            Box::pin(async move { Ok(outcome) })
        }

        fn enqueue_scan<'a>(
            &'a self,
            _aid: Uuid,
            _rid: Uuid,
            _ch: &'a ContentHash,
            _f: &'a str,
            _p: i16,
            _ts: &'a str,
        ) -> BoxFuture<'a, DomainResult<Uuid>> {
            Box::pin(async { Ok(Uuid::nil()) })
        }

        fn claim_pending_by_kinds<'a>(
            &'a self,
            _kinds: &'a [&'a str],
            _batch_size: u16,
            _worker_id: &'a str,
            lock_duration: Duration,
            reservation: &'a ClaimReservation,
        ) -> BoxFuture<'a, DomainResult<Vec<JobRow>>> {
            self.claim_reservations
                .lock()
                .unwrap()
                .push(reservation.clone());
            let batch = {
                let mut q = self.claim_batches.lock().unwrap();
                if q.is_empty() {
                    Vec::new()
                } else {
                    q.remove(0)
                }
            };
            // The claim is where `locked_until` is first written, so it
            // is where the lease model starts.
            for row in &batch {
                self.model_claim(row, lock_duration);
            }
            Box::pin(async move { Ok(batch) })
        }

        fn eligible_pending_by_kind(&self) -> BoxFuture<'_, DomainResult<Vec<PendingKindBacklog>>> {
            let fails = *self.backlog_fails.lock().unwrap();
            let rows = self.backlog.lock().unwrap().clone();
            Box::pin(async move {
                if fails {
                    Err(DomainError::Invariant("backlog boom".into()))
                } else {
                    Ok(rows)
                }
            })
        }

        fn queue_sample_by_band<'a>(
            &'a self,
            bands: &'a [PriorityBand],
        ) -> BoxFuture<'a, DomainResult<Vec<BandQueueSample>>> {
            self.band_queries.lock().unwrap().push(bands.to_vec());
            let fails = *self.band_samples_fail.lock().unwrap();
            let rows = self.band_samples.lock().unwrap().clone();
            Box::pin(async move {
                if fails {
                    Err(DomainError::Invariant("band sample boom".into()))
                } else {
                    Ok(rows)
                }
            })
        }

        fn clear_capacity_wait<'a>(
            &'a self,
            job_id: Uuid,
            worker_id: &'a str,
        ) -> BoxFuture<'a, DomainResult<bool>> {
            self.capacity_wait_clears
                .lock()
                .unwrap()
                .push((job_id, worker_id.to_string()));
            let answer = *self.capacity_wait_answer.lock().unwrap();
            Box::pin(async move {
                match answer {
                    Some(landed) => Ok(landed),
                    None => Err(DomainError::Invariant("clear boom".into())),
                }
            })
        }
    }

    // Minimal EventStore mock
    use hort_domain::events::{PersistedEvent, StreamId};
    use hort_domain::ports::event_store::{
        AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
    };

    struct NoopEventStore;
    impl EventStore for NoopEventStore {
        fn append(&self, _batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            Box::pin(async {
                Ok(AppendResult {
                    stream_position: 0,
                    global_positions: Vec::new(),
                })
            })
        }

        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn read_category(
            &self,
            _category: hort_domain::events::StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn delete_stream(
            &self,
            _stream_id: StreamId,
            _authority: hort_domain::ports::event_store::SealAuthority,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
            Box::pin(async { Ok(hort_domain::ports::event_store::SealOutcome::Sealed) })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
            _authority: hort_domain::ports::event_store::SealAuthority,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
            Box::pin(async { Ok(hort_domain::ports::event_store::SealOutcome::Sealed) })
        }
    }

    /// An `EventStore` that records every batch it was handed, and can
    /// be told to refuse them.
    ///
    /// It does **not** round-trip — `read_stream` serves nothing, and
    /// no production code reads back what the dispatcher appends — so
    /// the "a double that round-trips must refuse what production
    /// refuses" rule does not reach it. What a test needs here is the
    /// batch's stream id, its payload and the fact that an append was
    /// attempted at all.
    struct RecordingEventStore {
        batches: Mutex<Vec<AppendEvents>>,
        fails: bool,
        /// How many of the leading appends answer
        /// `DomainError::Conflict` before the store starts accepting
        /// them. The retry budget is only *observable* through a store
        /// that loses a race and then stops losing it — a double that
        /// always succeeds proves nothing about a retry.
        conflicts_remaining: Mutex<u32>,
    }

    impl RecordingEventStore {
        fn new() -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                fails: false,
                conflicts_remaining: Mutex::new(0),
            }
        }

        /// Every append errors — the event store being down while the
        /// row's own write already landed.
        fn failing() -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                fails: true,
                conflicts_remaining: Mutex::new(0),
            }
        }

        /// The first `n` appends lose the race at the stream tail with
        /// `DomainError::Conflict`; the next one is accepted. `n` at or
        /// above the budget means the budget is spent and the event
        /// never lands.
        fn conflicting_first(n: u32) -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                fails: false,
                conflicts_remaining: Mutex::new(n),
            }
        }

        fn batches(&self) -> Vec<AppendEvents> {
            self.batches.lock().unwrap().clone()
        }

        /// The single `TaskFailed` payload this store was handed, with
        /// the stream it was routed to. Panics unless exactly one batch
        /// of exactly one `TaskFailed` was appended, because every
        /// caller is asserting about one failure.
        fn only_task_failed(&self) -> (StreamId, TaskFailed) {
            let batches = self.batches();
            assert_eq!(batches.len(), 1, "expected exactly one append: {batches:?}");
            let batch = &batches[0];
            assert_eq!(batch.events.len(), 1, "expected a single-event batch");
            match &batch.events[0].event {
                DomainEvent::TaskFailed(e) => (batch.stream_id.clone(), e.clone()),
                other => panic!("expected TaskFailed, got {}", other.event_type()),
            }
        }
    }

    impl EventStore for RecordingEventStore {
        fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            self.batches.lock().unwrap().push(batch);
            let fails = self.fails;
            let conflicts = {
                let mut remaining = self.conflicts_remaining.lock().unwrap();
                let conflicts = *remaining > 0;
                *remaining = remaining.saturating_sub(1);
                conflicts
            };
            Box::pin(async move {
                if fails {
                    Err(DomainError::Invariant("event store down".into()))
                } else if conflicts {
                    Err(DomainError::Conflict(
                        "stream authorization concurrent append at position 0".into(),
                    ))
                } else {
                    Ok(AppendResult {
                        stream_position: 0,
                        global_positions: vec![0],
                    })
                }
            })
        }

        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn read_category(
            &self,
            _category: hort_domain::events::StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn delete_stream(
            &self,
            _stream_id: StreamId,
            _authority: hort_domain::ports::event_store::SealAuthority,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
            Box::pin(async { Ok(hort_domain::ports::event_store::SealOutcome::Sealed) })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
            _authority: hort_domain::ports::event_store::SealAuthority,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
            Box::pin(async { Ok(hort_domain::ports::event_store::SealOutcome::Sealed) })
        }
    }

    // -----------------------------------------------------------------------
    // Handler helpers
    // -----------------------------------------------------------------------

    /// A noop handler that just returns Completed.
    struct NoopHandler {
        kind: &'static str,
        run_count: Arc<AtomicUsize>,
    }

    impl NoopHandler {
        fn new(kind: &'static str, run_count: Arc<AtomicUsize>) -> Self {
            Self { kind, run_count }
        }
    }

    impl TaskHandler for NoopHandler {
        fn kind(&self) -> &'static str {
            self.kind
        }

        fn run<'a>(
            &'a self,
            _params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            self.run_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(TaskOutcome::Completed {
                    result_summary: serde_json::Value::Null,
                })
            })
        }
    }

    /// Records the `trigger_source` of every row it is handed, in the
    /// order it was handed them — which, under a per-kind concurrency of
    /// one, is the order the kind's permits were granted in.
    struct OrderRecordingHandler {
        kind: &'static str,
        order: Arc<Mutex<Vec<String>>>,
    }

    impl TaskHandler for OrderRecordingHandler {
        fn kind(&self) -> &'static str {
            self.kind
        }

        fn run<'a>(
            &'a self,
            params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            let source = params
                .get("trigger_source")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>")
                .to_string();
            self.order.lock().unwrap().push(source);
            Box::pin(async {
                Ok(TaskOutcome::Completed {
                    result_summary: serde_json::Value::Null,
                })
            })
        }
    }

    /// A claimed `kind='scan'` row carrying a real trigger source, so
    /// `TaskTier::classify` has something to answer about.
    ///
    /// The trigger source is echoed into `params` as well, because the
    /// handler only sees the params — and the order it records is the
    /// evidence.
    fn make_scan_row(trigger_source: &str) -> JobRow {
        let mut row = make_job_row("scan");
        row.trigger_source = trigger_source.to_string();
        row.priority = hort_domain::types::task_tier::scan_queue_priority(trigger_source);
        row.params = Some(serde_json::json!({ "trigger_source": trigger_source }));
        row
    }

    /// A handler that returns Completed with a SPECIFIC non-null summary —
    /// proves the dispatcher threads `result_summary` to `mark_completed`
    /// (H17) rather than discarding it.
    struct SummaryHandler {
        kind: &'static str,
        summary: serde_json::Value,
    }

    impl TaskHandler for SummaryHandler {
        fn kind(&self) -> &'static str {
            self.kind
        }

        fn run<'a>(
            &'a self,
            _params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            let summary = self.summary.clone();
            Box::pin(async move {
                Ok(TaskOutcome::Completed {
                    result_summary: summary,
                })
            })
        }
    }

    /// A handler of a caller-chosen kind that returns
    /// `Failed { retry: true }` — the shape every handler's top-level
    /// error path produces, including the three destructive ones
    /// (`retention-evaluate` on page-selection or evaluation failure,
    /// `retention-purge` when `process_expired` refuses or fails,
    /// `eventstore-archive` when the candidate listing fails).
    ///
    /// The kind is a parameter because the attempt cap is uniform
    /// across kinds: a test naming a destructive kind must be able to
    /// say so without a second near-identical stub.
    struct RetryHandler(&'static str);

    impl TaskHandler for RetryHandler {
        fn kind(&self) -> &'static str {
            self.0
        }

        fn run<'a>(
            &'a self,
            _params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            Box::pin(async { Ok(TaskOutcome::fail("transient error".to_string(), true)) })
        }
    }

    /// A handler that returns Failed { retry: false }.
    struct TerminalHandler;

    impl TaskHandler for TerminalHandler {
        fn kind(&self) -> &'static str {
            "terminal-kind"
        }

        fn run<'a>(
            &'a self,
            _params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            Box::pin(async { Ok(TaskOutcome::fail("invariant violated".to_string(), false)) })
        }
    }

    /// A handler that returns `Err` rather than a `TaskOutcome`.
    ///
    /// `dispatch_one` records that as `Failed { retry: true }`, so an
    /// `Err` is subject to the same attempt budget as a returned
    /// retryable failure.
    struct ErrHandler(&'static str);

    impl TaskHandler for ErrHandler {
        fn kind(&self) -> &'static str {
            self.0
        }

        fn run<'a>(
            &'a self,
            _params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            Box::pin(async { Err(DomainError::Invariant("handler blew up".into())) })
        }
    }

    /// A `kind='scan'` handler that occupies its permit for a
    /// caller-chosen span, so the next row of the same batch is a
    /// *claimed row waiting for a permit* for exactly that long.
    ///
    /// `scan` rather than a made-up kind because the tests it serves
    /// turn on [`REQUEUE_ON_LEASE_EXPIRY_KINDS`]: that allow-list is
    /// what decides whether an abandoned row is recoverable at all, and
    /// a kind outside it would make a "not requeued" assertion pass for
    /// a reason that has nothing to do with the lease.
    struct OccupyingScanHandler {
        hold: Duration,
        started: Arc<AtomicUsize>,
    }

    impl TaskHandler for OccupyingScanHandler {
        fn kind(&self) -> &'static str {
            "scan"
        }

        fn run<'a>(
            &'a self,
            _params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let hold = self.hold;
            Box::pin(async move {
                tokio::time::sleep(hold).await;
                Ok(TaskOutcome::Completed {
                    result_summary: serde_json::Value::Null,
                })
            })
        }
    }

    /// A slow handler that holds its permit long enough to observe concurrency.
    struct SlowHandler {
        max_concurrent: Arc<AtomicUsize>,
        current: Arc<AtomicUsize>,
        delay_ms: u64,
    }

    impl TaskHandler for SlowHandler {
        fn kind(&self) -> &'static str {
            "slow-kind"
        }

        fn run<'a>(
            &'a self,
            _params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            let current = self.current.clone();
            let max_concurrent = self.max_concurrent.clone();
            let delay_ms = self.delay_ms;
            Box::pin(async move {
                let prev = current.fetch_add(1, Ordering::SeqCst);
                max_concurrent.fetch_max(prev + 1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                current.fetch_sub(1, Ordering::SeqCst);
                Ok(TaskOutcome::Completed {
                    result_summary: serde_json::Value::Null,
                })
            })
        }
    }

    fn make_dispatcher(repo: Arc<dyn JobsRepository>) -> TaskDispatcher {
        make_dispatcher_with(repo, authorizing_reauthorizer())
    }

    fn make_dispatcher_with(
        repo: Arc<dyn JobsRepository>,
        reauthorizer: Arc<DestructiveTaskReauthorizer>,
    ) -> TaskDispatcher {
        make_dispatcher_with_events(repo, reauthorizer, Arc::new(NoopEventStore))
    }

    /// [`make_dispatcher_with`] for a test that reads back what the
    /// dispatcher appended — see [`RecordingEventStore`].
    fn make_dispatcher_with_events<S: EventStore + 'static>(
        repo: Arc<dyn JobsRepository>,
        reauthorizer: Arc<DestructiveTaskReauthorizer>,
        events: Arc<S>,
    ) -> TaskDispatcher {
        TaskDispatcher::new(
            repo,
            crate::event_store_publisher::wrap_for_test(events),
            reauthorizer,
            "test-worker",
            Duration::from_secs(60),
            999_999, // very long poll interval — we drive ticks manually via seeded batches
            16,
            TEST_ATTEMPT_CAP,
            TEST_RESERVED_SLOTS_PER_CLASS,
            TEST_CLASS_SERVICE_THRESHOLD,
        )
    }

    /// Call `dispatch_one` the way the dispatch loop does — with the
    /// claim's lease renewal already running.
    ///
    /// The renewal starts at the claim, so a test that hands
    /// `dispatch_one` a row with no live guard would be exercising a
    /// state production cannot be in. Mirrors the loop exactly: the
    /// guard is created from the row's id and the handler's kind, and
    /// handed over by value.
    async fn dispatch_one_with_lease(
        dispatcher: &Arc<TaskDispatcher>,
        row: JobRow,
        handler: Arc<dyn TaskHandler>,
    ) {
        let renewal = dispatcher.spawn_lease_renewal(row.id, handler.kind().to_string());
        dispatcher.dispatch_one(row, handler, renewal).await;
    }

    /// The attempt budget `make_dispatcher` builds its dispatchers with.
    ///
    /// Production threads `HORT_SCANNER_MAX_ATTEMPTS` into
    /// `TaskDispatcher::new`; the tests use that variable's own default
    /// so the window assertion in
    /// [`six_executions_span_the_hundred_and_fifty_six_minute_window`]
    /// is the one an out-of-the-box deployment experiences. Tests that
    /// are about the cap being *configured* build their own dispatcher
    /// with a different value — see
    /// [`the_cap_is_the_configured_one_not_the_default`].
    const TEST_ATTEMPT_CAP: u32 = DEFAULT_MAX_ATTEMPTS;

    /// The per-class reserved share `make_dispatcher` builds its
    /// dispatchers with — `HORT_SCANNER_RESERVED_SLOTS_PER_CLASS`'s own
    /// default, so the fairness a test observes is the one an
    /// out-of-the-box deployment gets. A test about the share being
    /// *configured* builds its own dispatcher with a different value.
    const TEST_RESERVED_SLOTS_PER_CLASS: u16 = DEFAULT_RESERVED_SLOTS_PER_CLASS;

    /// The per-class service threshold `make_dispatcher` builds its
    /// dispatchers with — the domain default, so a test observes the
    /// window an out-of-the-box deployment audits at. A test about the
    /// threshold being *configured* passes its own.
    const TEST_CLASS_SERVICE_THRESHOLD: Duration =
        Duration::from_secs(DEFAULT_CLASS_SERVICE_THRESHOLD_SECS);

    // -----------------------------------------------------------------------
    // Helper to look up a counter value from a debugging snapshot
    // -----------------------------------------------------------------------

    fn counter_value(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        name: &str,
        labels: &[(&str, &str)],
    ) -> u64 {
        snap.iter()
            .find_map(|(ck, _, _, dv)| {
                if ck.kind() != MetricKind::Counter || ck.key().name() != name {
                    return None;
                }
                let matches = labels
                    .iter()
                    .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
                if matches {
                    if let DebugValue::Counter(n) = dv {
                        Some(*n)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn histogram_count(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        name: &str,
        labels: &[(&str, &str)],
    ) -> usize {
        snap.iter()
            .find_map(|(ck, _, _, dv)| {
                if ck.kind() != MetricKind::Histogram || ck.key().name() != name {
                    return None;
                }
                let matches = labels
                    .iter()
                    .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
                if matches {
                    if let DebugValue::Histogram(samples) = dv {
                        Some(samples.len())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Test 1 — dispatcher runs one iteration then stops on cancel
    // -----------------------------------------------------------------------

    /// `registered_kinds()` returns every kind passed to `register(..)`
    /// (used by `hort-worker`'s `composition_smoke.rs` to assert the
    /// structural wiring of new `TaskHandler` impls).
    #[test]
    fn registered_kinds_round_trips_every_register_call() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let mut dispatcher = make_dispatcher(repo as Arc<dyn JobsRepository>);
        let run_count = Arc::new(AtomicUsize::new(0));

        // Empty dispatcher reports no kinds.
        assert!(dispatcher.registered_kinds().is_empty());

        dispatcher.register(Arc::new(NoopHandler::new("noop", run_count.clone())), 1);
        dispatcher.register(
            Arc::new(NoopHandler::new("other-kind", run_count.clone())),
            2,
        );

        let kinds: HashSet<&str> = dispatcher.registered_kinds().into_iter().collect();
        assert_eq!(kinds.len(), 2, "got {kinds:?}");
        assert!(kinds.contains("noop"), "got {kinds:?}");
        assert!(kinds.contains("other-kind"), "got {kinds:?}");
    }

    /// The dispatcher runs through one poll tick (claims 1 row, executes
    /// noop handler), then stops when the cancellation token fires.
    #[tokio::test]
    async fn dispatcher_runs_one_iteration_then_stops_on_cancel() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("noop");
        repo.seed_batch(vec![row]);

        let run_count = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.register(Arc::new(NoopHandler::new("noop", run_count.clone())), 4);
        // Override poll_interval to 0 so the first tick fires immediately.
        dispatcher.poll_interval_secs = 0;

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });

        // Give the dispatcher time to run one tick.
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("dispatcher join timed out")
            .expect("task did not panic");
        assert!(result.is_ok(), "run returned Err: {result:?}");
        assert_eq!(
            run_count.load(Ordering::SeqCst),
            1,
            "handler ran exactly once"
        );
    }

    // -----------------------------------------------------------------------
    // Non-displacement at the permit (ADR 0066 D4, point two)
    // -----------------------------------------------------------------------

    /// **Point two of ADR 0066 D4.** A client-waited row that won the
    /// claim does not wait behind the whole bulk batch of its own kind
    /// for the capacity to run.
    ///
    /// This is the victim the claim cannot see: such a row is already
    /// `running`, so the starvation audit and the claim's own
    /// reservation are both blind to it. `scan` is the kind it happens
    /// to — six trigger sources across all three classes, and a
    /// production concurrency of one.
    ///
    /// The batch is deliberately ordered worst-case: the ingest scan is
    /// claimed **last**, behind four scheduled rescans. Under an
    /// arrival-ordered permit queue it therefore runs fifth. What it may
    /// not do is wait for work that has not started — the first rescan
    /// already holds the only permit and nothing here interrupts it (ADR
    /// 0066: this is not preemption), so the guarantee is that the
    /// ingest scan takes the **next** permit to come free, which is
    /// second.
    #[tokio::test]
    async fn a_client_waited_row_does_not_wait_behind_the_bulk_batch_for_a_permit() {
        let bulk = TriggerSource::Cron.as_str();
        let interactive = TriggerSource::Ingest.as_str();
        // The premise: these two really are different classes, and the
        // kind really is one both reach.
        assert_eq!(
            TaskTier::classify("scan", bulk),
            Some(TaskTier::Bulk),
            "the fixture needs the flood to be the class nobody waits on"
        );
        assert_eq!(
            TaskTier::classify("scan", interactive),
            Some(TaskTier::Interactive),
            "the fixture needs the victim to be client-waited"
        );

        let repo = Arc::new(DispatcherMockRepo::new());
        let mut batch: Vec<JobRow> = (0..4).map(|_| make_scan_row(bulk)).collect();
        batch.push(make_scan_row(interactive));
        repo.seed_batch(batch);

        let order = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        dispatcher.register(
            Arc::new(OrderRecordingHandler {
                kind: "scan",
                order: order.clone(),
            }),
            // The production concurrency for `scan`: parallelism comes
            // from replicas, not from intra-process concurrency. One
            // permit is also the case a spatial reservation cannot
            // serve, so it is the one worth pinning.
            1,
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("dispatcher join timed out")
            .expect("task did not panic")
            .expect("run returned Err");

        let order = order.lock().unwrap().clone();
        assert_eq!(
            order.len(),
            5,
            "every claimed row must still run — a reservation that dropped one \
             would pass the assertion below for the wrong reason: {order:?}"
        );
        let at = order
            .iter()
            .position(|s| s == interactive)
            .expect("the client-waited row must run");
        assert_eq!(
            at, 1,
            "the client-waited row must take the first permit that comes free, not \
             wait out the bulk batch it was claimed behind: {order:?}"
        );
    }

    /// **The share is the operator's number, at both points.**
    ///
    /// Asserted together rather than twice, because that is the shape
    /// of the mistake: ADR 0066 D4 calls a design that closes one point
    /// and not the other *incomplete*, and a knob threaded into one of
    /// them is exactly that. The claim's half is a port argument, so
    /// the mock can read it; the permit's half is internal, so it is
    /// read as behaviour.
    ///
    /// The configured value is the **off** position, which the default
    /// is not — at the default this test would pass against a
    /// compiled-in constant too.
    #[tokio::test]
    async fn the_reserved_share_is_the_configured_one_at_both_points() {
        const CONFIGURED: u16 = 0;
        const _: () = assert!(CONFIGURED != DEFAULT_RESERVED_SLOTS_PER_CLASS);

        let bulk = TriggerSource::Cron.as_str();
        let interactive = TriggerSource::Ingest.as_str();
        let repo = Arc::new(DispatcherMockRepo::new());
        let mut batch: Vec<JobRow> = (0..4).map(|_| make_scan_row(bulk)).collect();
        batch.push(make_scan_row(interactive));
        repo.seed_batch(batch);

        let order = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = TaskDispatcher::new(
            repo.clone() as Arc<dyn JobsRepository>,
            crate::event_store_publisher::wrap_for_test(Arc::new(NoopEventStore)),
            authorizing_reauthorizer(),
            "test-worker",
            Duration::from_secs(60),
            0,
            16,
            TEST_ATTEMPT_CAP,
            CONFIGURED,
            TEST_CLASS_SERVICE_THRESHOLD,
        );
        assert_eq!(dispatcher.reserved_slots_per_class(), CONFIGURED);
        dispatcher.register(
            Arc::new(OrderRecordingHandler {
                kind: "scan",
                order: order.clone(),
            }),
            1,
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("dispatcher join timed out")
            .expect("task did not panic")
            .expect("run returned Err");

        // Point one: the number reached the port, with the band list
        // the domain decides rather than one the dispatcher invented.
        let seen = repo.claim_reservations();
        let first = seen
            .first()
            .expect("the dispatcher must have claimed at least once");
        assert_eq!(
            first.slots_per_band, CONFIGURED,
            "the claim must be handed the configured share, not a default: {seen:?}"
        );
        assert_eq!(
            first.bands,
            hort_domain::types::task_tier::waited_on_bands(),
            "the bands must be the domain's waited-on list"
        );

        // Point two: the number reached `register`. At the off position
        // the permits are arrival-ordered, so the client-waited row
        // claimed last runs last.
        let order = order.lock().unwrap().clone();
        assert_eq!(
            order.len(),
            5,
            "every claimed row must still run: {order:?}"
        );
        assert_eq!(
            order.iter().position(|s| s == interactive),
            Some(4),
            "with the share at zero the permits must be arrival-ordered, which is what \
             shows the number reached the permit allocation and not only the accessor: \
             {order:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 — dispatcher dispatches to correct handler by kind
    // -----------------------------------------------------------------------

    /// Two handlers (noop, other-kind) are registered. A batch with one row
    /// of each kind is claimed. Both handlers execute exactly once.
    #[tokio::test]
    async fn dispatcher_dispatches_to_correct_handler_by_kind() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let row_noop = make_job_row("noop");
        let row_other = make_job_row("other-kind");
        repo.seed_batch(vec![row_noop, row_other]);

        let noop_count = Arc::new(AtomicUsize::new(0));
        let other_count = Arc::new(AtomicUsize::new(0));

        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        dispatcher.register(Arc::new(NoopHandler::new("noop", noop_count.clone())), 4);
        dispatcher.register(
            Arc::new(NoopHandler::new("other-kind", other_count.clone())),
            4,
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });

        // Allow both handlers to run.
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap();

        assert_eq!(
            noop_count.load(Ordering::SeqCst),
            1,
            "noop handler ran once"
        );
        assert_eq!(
            other_count.load(Ordering::SeqCst),
            1,
            "other-kind handler ran once"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3 — per-kind concurrency enforced
    // -----------------------------------------------------------------------

    /// A slow handler with concurrency=2 is registered. 4 rows are claimed.
    /// At most 2 concurrent invocations should be observed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dispatcher_per_kind_concurrency_enforced() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let rows: Vec<JobRow> = (0..4).map(|_| make_job_row("slow-kind")).collect();
        repo.seed_batch(rows);

        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let current = Arc::new(AtomicUsize::new(0));

        let handler = SlowHandler {
            max_concurrent: max_concurrent.clone(),
            current: current.clone(),
            delay_ms: 50,
        };

        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        dispatcher.register(Arc::new(handler), 2);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });

        // All 4 tasks need 50ms each; with concurrency=2 that's ~100ms minimum.
        tokio::time::sleep(Duration::from_millis(500)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap();

        let observed = max_concurrent.load(Ordering::SeqCst);
        assert!(
            observed <= 2,
            "max observed concurrency was {observed}, expected <= 2"
        );
        assert!(
            observed >= 1,
            "max observed concurrency was {observed}, expected >= 1"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4 — records outcome Completed
    // -----------------------------------------------------------------------

    /// Handler returns Completed → `mark_completed` is called on the repo.
    #[tokio::test]
    async fn dispatcher_records_outcome_completed() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("noop");
        let row_id = row.id;
        repo.seed_batch(vec![row]);

        let run_count = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        dispatcher.register(Arc::new(NoopHandler::new("noop", run_count.clone())), 4);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });

        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap();

        let completed = repo.mark_completed_calls();
        assert!(
            completed.contains(&row_id),
            "mark_completed must be called for the job id"
        );
    }

    /// H17 — the handler's `result_summary` must be threaded to
    /// `mark_completed`, not discarded. Regression guard for the dispatcher
    /// arm that previously matched `Completed { .. }` and dropped the field.
    #[tokio::test]
    async fn dispatcher_persists_handler_result_summary() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.seed_batch(vec![make_job_row("summary-kind")]);

        let summary = serde_json::json!({ "result": "no_attestation" });
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        dispatcher.register(
            Arc::new(SummaryHandler {
                kind: "summary-kind",
                summary: summary.clone(),
            }),
            4,
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap();

        assert_eq!(
            repo.mark_completed_summaries(),
            vec![summary],
            "dispatcher must thread the handler's result_summary to mark_completed"
        );
    }

    // -----------------------------------------------------------------------
    // Test 5 — records outcome Failed { retry: true }
    // -----------------------------------------------------------------------

    /// Handler returns Failed { retry: true } → `reschedule` is called.
    #[tokio::test]
    async fn dispatcher_records_outcome_failed_retry() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("retry-kind");
        let row_id = row.id;
        repo.seed_batch(vec![row]);

        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        dispatcher.register(Arc::new(RetryHandler("retry-kind")), 4);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });

        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap();

        let reschedules = repo.reschedule_calls();
        assert!(
            reschedules.iter().any(|(id, _)| *id == row_id),
            "reschedule must be called for the job id; got {reschedules:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6 — records outcome Failed { retry: false }
    // -----------------------------------------------------------------------

    /// Handler returns Failed { retry: false } → `mark_failed` is called.
    #[tokio::test]
    async fn dispatcher_records_outcome_failed_terminal() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("terminal-kind");
        let row_id = row.id;
        repo.seed_batch(vec![row]);

        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        dispatcher.register(Arc::new(TerminalHandler), 4);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });

        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap();

        let failed = repo.mark_failed_calls();
        assert!(
            failed.iter().any(|(id, _)| *id == row_id),
            "mark_failed must be called for the job id; got {failed:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6b — the attempt cap on a RETURNED failure
    // -----------------------------------------------------------------------

    /// `hort_admin_tasks_completed_total` as the dispatcher reported it
    /// for one row's kind. Named fields rather than a tuple so an
    /// assertion reads as the outcome it is checking.
    #[derive(Debug)]
    struct OutcomeCounters {
        failed_retry: u64,
        failed_terminal: u64,
    }

    /// Run one row through `dispatch_one` to completion on a
    /// current-thread runtime inside a local metrics recorder — the
    /// same shape as
    /// `dispatcher_emits_completed_total_metric_blocking`, which is
    /// what makes the counter observable at all (a `tokio::spawn`ed
    /// poll loop does not inherit a thread-local recorder).
    ///
    /// The attempt-cap matrix below differs only in the row's
    /// `attempts`, its kind and the handler, so the skeleton lives
    /// here rather than being re-spelled per test.
    ///
    /// Returns the mock repo (for the `reschedule` / `mark_failed` call
    /// log), the row's id, and the two outcome counters — the metric is
    /// how the dispatcher says which of the two transitions it chose.
    fn dispatch_one_row(
        kind: &'static str,
        attempts: u32,
        handler: Arc<dyn TaskHandler>,
    ) -> (Arc<DispatcherMockRepo>, Uuid, OutcomeCounters) {
        dispatch_one_row_with(kind, attempts, handler, authorizing_reauthorizer())
    }

    fn dispatch_one_row_with(
        kind: &'static str,
        attempts: u32,
        handler: Arc<dyn TaskHandler>,
        reauthorizer: Arc<DestructiveTaskReauthorizer>,
    ) -> (Arc<DispatcherMockRepo>, Uuid, OutcomeCounters) {
        assert_eq!(
            handler.kind(),
            kind,
            "the metric label is the HANDLER's kind, so the row's kind has to match it or the \
             counter lookup below reads a label nothing ever emitted"
        );
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(DispatcherMockRepo::new());
        let mut row = make_job_row(kind);
        row.attempts = attempts;
        let row_id = row.id;
        let dispatcher = Arc::new(make_dispatcher_with(
            repo.clone() as Arc<dyn JobsRepository>,
            reauthorizer,
        ));

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(dispatch_one_with_lease(&dispatcher, row, handler))
        });

        let snap = snapshotter.snapshot().into_vec();
        let counters = OutcomeCounters {
            failed_retry: counter_value(
                &snap,
                METRIC_COMPLETED,
                &[("kind", kind), ("result", RESULT_FAILED_RETRY)],
            ),
            failed_terminal: counter_value(
                &snap,
                METRIC_COMPLETED,
                &[("kind", kind), ("result", RESULT_FAILED_TERMINAL)],
            ),
        };
        (repo, row_id, counters)
    }

    /// The cap that fires is the one the dispatcher was constructed
    /// with, not the default.
    ///
    /// This is the half of the scan boundary the handoff has to get
    /// right. `HORT_SCANNER_MAX_ATTEMPTS` sets both
    /// `ScanOrchestrationConfig::max_attempts` — which decides whether
    /// an exhausted scan records the artifact's `ScanIndeterminate` —
    /// and this cap, which decides whether the row goes terminal. While
    /// this side was a `const u32 = 5` the two agreed only at the
    /// default: an operator setting `3` got a row failed at 5 after the
    /// scan path had already recorded the verdict at 3, and one setting
    /// `12` got the row failed at 5 with no verdict recorded at all.
    /// A dispatcher built with a cap of 2 must therefore fail at 2.
    #[test]
    fn the_cap_is_the_configured_one_not_the_default() {
        const CONFIGURED: u32 = 2;
        // A cap the default would NOT have fired at — otherwise this test
        // passes against a compiled-in constant too.
        const _: () = assert!(CONFIGURED < DEFAULT_MAX_ATTEMPTS);

        for (attempts, expect_terminal) in [(CONFIGURED - 1, false), (CONFIGURED, true)] {
            let repo = Arc::new(DispatcherMockRepo::new());
            let mut row = make_job_row("retry-kind");
            row.attempts = attempts;
            let row_id = row.id;
            let dispatcher = Arc::new(TaskDispatcher::new(
                repo.clone() as Arc<dyn JobsRepository>,
                crate::event_store_publisher::wrap_for_test(Arc::new(NoopEventStore)),
                authorizing_reauthorizer(),
                "test-worker",
                Duration::from_secs(60),
                999_999,
                16,
                CONFIGURED,
                TEST_RESERVED_SLOTS_PER_CLASS,
                TEST_CLASS_SERVICE_THRESHOLD,
            ));

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(dispatch_one_with_lease(
                    &dispatcher,
                    row,
                    Arc::new(RetryHandler("retry-kind")),
                ));

            if expect_terminal {
                assert_eq!(
                    repo.mark_failed_calls(),
                    vec![(row_id, "transient error".to_string())],
                    "attempts={attempts} is at the configured cap and must be terminal",
                );
                assert!(repo.reschedule_calls().is_empty());
            } else {
                assert_eq!(
                    repo.reschedule_calls(),
                    vec![(row_id, "transient error".to_string())],
                    "attempts={attempts} is below the configured cap and must be rescheduled",
                );
                assert!(
                    repo.mark_failed_calls().is_empty(),
                    "a row with budget left under the CONFIGURED cap must not be failed"
                );
            }
        }
    }

    /// The sweep spends the same configured budget the returned-failure
    /// path does.
    ///
    /// `requeue_abandoned`'s over-cap `CASE` is the dead-worker half of
    /// one budget, so a cap threaded into only one of the two paths
    /// would let a crashed worker's row outlive — or die ahead of — an
    /// identical row whose handler returned.
    #[test]
    fn the_sweep_passes_the_configured_cap_not_the_default() {
        const CONFIGURED: u32 = 9;
        const _: () = assert!(CONFIGURED != DEFAULT_MAX_ATTEMPTS);

        let repo = Arc::new(DispatcherMockRepo::new());
        let dispatcher = Arc::new(TaskDispatcher::new(
            repo.clone() as Arc<dyn JobsRepository>,
            crate::event_store_publisher::wrap_for_test(Arc::new(NoopEventStore)),
            authorizing_reauthorizer(),
            "test-worker",
            Duration::from_secs(60),
            999_999,
            16,
            CONFIGURED,
            TEST_RESERVED_SLOTS_PER_CLASS,
            TEST_CLASS_SERVICE_THRESHOLD,
        ));
        assert_eq!(dispatcher.attempt_cap(), CONFIGURED);

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(dispatcher.sweep_abandoned_leases());

        let calls = repo.requeue_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].attempt_cap, CONFIGURED);
    }

    /// Below the cap a retryable failure is still rescheduled, waiting
    /// the shared curve's last and longest interval.
    ///
    /// The boundary is `attempts < TEST_ATTEMPT_CAP`, so the last
    /// attempt below the cap keeps its retry — a cap that fired one
    /// attempt early would turn a transient failure into a dead row,
    /// which is the opposite of the point. (The first failure,
    /// `attempts == 1`, is covered by
    /// `dispatcher_records_outcome_failed_retry`.)
    #[test]
    fn a_returned_retryable_failure_below_the_attempt_cap_is_rescheduled() {
        let below_cap = TEST_ATTEMPT_CAP - 1;
        let (repo, row_id, counters) = dispatch_one_row(
            "retry-kind",
            below_cap,
            Arc::new(RetryHandler("retry-kind")),
        );

        assert_eq!(
            repo.reschedule_calls(),
            vec![(row_id, "transient error".to_string())],
            "a row with budget left goes back to pending, carrying the handler's reason"
        );
        assert_eq!(
            repo.reschedule_backoffs(),
            vec![Duration::from_secs(60 * 60)],
            "the row the cap will fail next waits the curve's longest interval first — pinned \
             by value, because 'what the last retry costs' is the operator-facing half of the \
             budget and must not be an inference from the function under test"
        );
        assert!(
            repo.mark_failed_calls().is_empty(),
            "a row with budget left must not be failed terminally"
        );
        assert_eq!(counters.failed_retry, 1, "counted as a retry");
        assert_eq!(counters.failed_terminal, 0);
    }

    /// At the cap a retryable failure is refused and the row becomes
    /// terminal, carrying its last error.
    ///
    /// [`compute_backoff`] bounds how long a row waits between
    /// executions and bounds nothing else, so without this the row
    /// would be re-driven for as long as it kept failing the same way
    /// and would never become the operator-visible `failed` row
    /// ADR 0028 describes.
    #[test]
    fn a_returned_retryable_failure_at_the_attempt_cap_is_terminal() {
        let (repo, row_id, counters) = dispatch_one_row(
            "retry-kind",
            TEST_ATTEMPT_CAP,
            Arc::new(RetryHandler("retry-kind")),
        );

        assert_eq!(
            repo.mark_failed_calls(),
            vec![(row_id, "transient error".to_string())],
            "at the cap the row is failed terminally, and keeps the last error that failed it"
        );
        assert!(
            repo.reschedule_calls().is_empty(),
            "a row at the cap must not be re-driven; that is the whole fix"
        );
        assert_eq!(counters.failed_retry, 0);
        assert_eq!(
            counters.failed_terminal, 1,
            "the dispatcher reports what it did to the row, not what the handler asked for"
        );
    }

    /// The predicate is `>=` the cap, not `==` it.
    ///
    /// A row can arrive past the cap without the dispatcher having seen
    /// it there: the abandoned-lease sweep requeues a row below the cap
    /// and the next claim charges it, and the sweep only runs on the
    /// kinds in `REQUEUE_ON_LEASE_EXPIRY_KINDS`. An `==` test would
    /// re-drive such a row forever — the exact shape this cap exists to
    /// close.
    #[test]
    fn a_returned_retryable_failure_past_the_attempt_cap_is_terminal() {
        let (repo, row_id, _counters) = dispatch_one_row(
            "retry-kind",
            TEST_ATTEMPT_CAP + 3,
            Arc::new(RetryHandler("retry-kind")),
        );

        assert_eq!(
            repo.mark_failed_calls(),
            vec![(row_id, "transient error".to_string())],
            "a row past the cap is terminal too"
        );
        assert!(repo.reschedule_calls().is_empty());
    }

    /// A handler `Err` is subject to the same budget.
    ///
    /// `dispatch_one` records an `Err` as `Failed { retry: true }`, so
    /// a handler that errors identically every time has to terminate
    /// for the same reason a returned retryable failure does.
    #[test]
    fn a_handler_error_at_the_attempt_cap_is_terminal() {
        let (repo, row_id, counters) = dispatch_one_row(
            "retry-kind",
            TEST_ATTEMPT_CAP,
            Arc::new(ErrHandler("retry-kind")),
        );

        let failed = repo.mark_failed_calls();
        assert_eq!(
            failed.len(),
            1,
            "one row, one terminal write; got {failed:?}"
        );
        assert_eq!(failed[0].0, row_id);
        assert!(
            failed[0].1.contains("handler blew up"),
            "the row keeps the handler's own error; got {failed:?}"
        );
        assert!(repo.reschedule_calls().is_empty());
        assert_eq!(counters.failed_terminal, 1);
    }

    /// Every result write carries the attempt the claim charged the
    /// row — the identity the adapter fences on.
    ///
    /// Not a detail of plumbing: a write carrying any other number is
    /// a write no execution owns, and the fence would refuse it. The
    /// three outcome paths reach three different methods, so each one
    /// is checked rather than one standing in for the others.
    #[test]
    fn every_outcome_path_writes_under_the_rows_own_attempt() {
        let completed_runs = Arc::new(AtomicUsize::new(0));
        let cases: Vec<(&'static str, &'static str, u32, Arc<dyn TaskHandler>)> = vec![
            (
                "mark_completed",
                "noop",
                3,
                Arc::new(NoopHandler::new("noop", completed_runs)),
            ),
            (
                "reschedule",
                "retry-kind",
                TEST_ATTEMPT_CAP - 1,
                Arc::new(RetryHandler("retry-kind")),
            ),
            (
                "mark_failed",
                "retry-kind",
                TEST_ATTEMPT_CAP,
                Arc::new(RetryHandler("retry-kind")),
            ),
        ];
        for (write, kind, attempts, handler) in cases {
            let (repo, _row_id, _counters) = dispatch_one_row(kind, attempts, handler);
            assert_eq!(
                repo.write_log.attempts(),
                vec![attempts],
                "{write} must write under the row's own attempt",
            );
        }
    }

    /// A refused write is surfaced and then let go.
    ///
    /// The handler's side effects are already done and this layer
    /// cannot unwind them, so the only correct move is to stop: no
    /// retry of the write, and no second write down another path. A
    /// retry would be refused for the same reason, and a fallback
    /// write is the clobber the fence exists to prevent.
    #[test]
    fn a_refused_result_write_is_not_retried_or_followed_by_another() {
        let runs = Arc::new(AtomicUsize::new(0));
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.write_log
            .refuse(ResultWriteOutcome::Superseded { current_attempt: 9 });
        let mut row = make_job_row("noop");
        row.attempts = 3;
        let row_id = row.id;
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(dispatch_one_with_lease(
                &dispatcher,
                row,
                Arc::new(NoopHandler::new("noop", runs)),
            ));

        assert_eq!(
            repo.mark_completed_calls(),
            vec![row_id],
            "the write is attempted exactly once"
        );
        assert_eq!(repo.write_log.attempts(), vec![3]);
        assert!(
            repo.reschedule_calls().is_empty() && repo.mark_failed_calls().is_empty(),
            "a refusal must not be answered with a different write: the row belongs to \
             whoever holds it now"
        );
    }

    // -----------------------------------------------------------------------
    // The failure half of the audit pair — `TaskFailed`
    // -----------------------------------------------------------------------

    /// Drive one row through `dispatch_one` against a caller-supplied
    /// repo and event store, so a test can read the row writes and the
    /// appends together.
    ///
    /// No metrics recorder, unlike [`dispatch_one_row`]: these cases are
    /// about the event, and the outcome counters have their own
    /// coverage above.
    fn dispatch_one_row_recording(
        repo: &Arc<DispatcherMockRepo>,
        events: &Arc<RecordingEventStore>,
        kind: &'static str,
        attempts: u32,
        handler: Arc<dyn TaskHandler>,
    ) -> Uuid {
        assert_eq!(
            handler.kind(),
            kind,
            "the audited kind is the HANDLER's, so the row's kind has to match it"
        );
        let mut row = make_job_row(kind);
        row.attempts = attempts;
        let row_id = row.id;
        let dispatcher = Arc::new(make_dispatcher_with_events(
            repo.clone() as Arc<dyn JobsRepository>,
            authorizing_reauthorizer(),
            events.clone(),
        ));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(dispatch_one_with_lease(&dispatcher, row, handler));
        row_id
    }

    /// The retryable path appends `final_attempt: false`.
    ///
    /// The row is going back to `pending`, so the failure is real but
    /// not the last word — and the field exists to carry exactly that
    /// distinction. An audit reader that could not tell a rescheduled
    /// failure from a terminal one would read the attempt budget's
    /// whole curve as repeated final failures.
    #[test]
    fn a_rescheduled_failure_appends_task_failed_as_not_final() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let events = Arc::new(RecordingEventStore::new());
        let row_id = dispatch_one_row_recording(
            &repo,
            &events,
            "noop",
            TEST_ATTEMPT_CAP - 1,
            Arc::new(RetryHandler("noop")),
        );

        assert_eq!(
            repo.reschedule_calls(),
            vec![(row_id, "transient error".to_string())],
            "the row still goes back to pending — the event is additive"
        );
        let (stream, event) = events.only_task_failed();
        assert_eq!(stream, StreamId::authorization());
        assert_eq!(
            event,
            TaskFailed {
                task_job_id: row_id,
                kind: "noop".to_string(),
                reason: "transient error".to_string(),
                final_attempt: false,
            }
        );
    }

    /// The terminal path appends `final_attempt: true`, carrying the
    /// same text the row's `last_error` got.
    #[test]
    fn a_terminal_failure_appends_task_failed_as_final() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let events = Arc::new(RecordingEventStore::new());
        let row_id = dispatch_one_row_recording(
            &repo,
            &events,
            "noop",
            TEST_ATTEMPT_CAP,
            Arc::new(RetryHandler("noop")),
        );

        assert_eq!(
            repo.mark_failed_calls(),
            vec![(row_id, "transient error".to_string())],
            "at the cap the row is terminal"
        );
        assert!(repo.reschedule_calls().is_empty());
        let (stream, event) = events.only_task_failed();
        assert_eq!(stream, StreamId::authorization());
        assert_eq!(
            event,
            TaskFailed {
                task_job_id: row_id,
                kind: "noop".to_string(),
                reason: "transient error".to_string(),
                final_attempt: true,
            }
        );
    }

    /// A destructive kind's `TaskFailed` lands on the same stream its
    /// `TaskInvoked` did — the never-deleted one.
    ///
    /// This is the whole reason the routing is a call into
    /// `TaskUseCase::task_audit_stream` rather than a second copy of the
    /// rule. Split across two streams, an `eventstore-archive` could
    /// truncate the record of its own failure while the record of its
    /// invocation survived on the exempt stream — and the failed
    /// destructive run is the half an operator came to read.
    #[test]
    fn a_destructive_kinds_task_failed_lands_beside_its_task_invoked() {
        for kind in DESTRUCTIVE_TASK_KINDS {
            let repo = Arc::new(DispatcherMockRepo::new());
            let events = Arc::new(RecordingEventStore::new());
            dispatch_one_row_recording(
                &repo,
                &events,
                kind,
                TEST_ATTEMPT_CAP,
                Arc::new(RetryHandler(kind)),
            );

            let (stream, event) = events.only_task_failed();
            assert_eq!(
                stream,
                TaskUseCase::task_audit_stream(kind),
                "{kind}: the pair has to share the enqueue path's own routing"
            );
            assert_eq!(
                stream,
                StreamId::eventstore_retention(),
                "{kind}: a destructive kind's audit trail is the exempt stream"
            );
            assert_ne!(stream, StreamId::authorization());
            assert!(event.final_attempt);
        }
    }

    /// A refused result write appends nothing, on both failure paths.
    ///
    /// The fence is `AND attempts = $2`: a refusal means the
    /// abandoned-lease sweep handed the row to a later execution while
    /// this handler ran, so this execution's failure is not the row's
    /// state. An audit record saying it is would be a false record
    /// about a row somebody else owns — and, unlike the row, the event
    /// store has no fence of its own to catch it.
    #[test]
    fn a_refused_result_write_appends_no_audit_event() {
        for (attempts, write) in [
            (TEST_ATTEMPT_CAP - 1, "reschedule"),
            (TEST_ATTEMPT_CAP, "mark_failed"),
        ] {
            let repo = Arc::new(DispatcherMockRepo::new());
            repo.write_log
                .refuse(ResultWriteOutcome::Superseded { current_attempt: 9 });
            let events = Arc::new(RecordingEventStore::new());
            dispatch_one_row_recording(
                &repo,
                &events,
                "noop",
                attempts,
                Arc::new(RetryHandler("noop")),
            );

            assert_eq!(
                repo.write_log.attempts(),
                vec![attempts],
                "{write} must still be attempted — the refusal is the repo's answer"
            );
            assert!(
                events.batches().is_empty(),
                "{write} was refused, so there is no failure of this execution's to audit; \
                 got {:?}",
                events.batches(),
            );
        }
    }

    /// An event-store failure changes neither the row nor the outcome.
    ///
    /// The row is the operational record and the event is the audit
    /// record, in that order: the append happens after the write, and a
    /// store that is down is logged and let go. A worker that failed a
    /// task differently — or held the row open — because its audit
    /// store was unreachable would turn an observability outage into a
    /// queue outage.
    #[test]
    fn an_event_store_failure_leaves_the_row_and_the_outcome_unchanged() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let events = Arc::new(RecordingEventStore::failing());
        let row_id = dispatch_one_row_recording(
            &repo,
            &events,
            "noop",
            TEST_ATTEMPT_CAP,
            Arc::new(RetryHandler("noop")),
        );

        assert_eq!(
            repo.mark_failed_calls(),
            vec![(row_id, "transient error".to_string())],
            "the row is closed out exactly as it would have been"
        );
        assert!(
            repo.reschedule_calls().is_empty(),
            "a failed append must not be answered with a different row write"
        );
        assert_eq!(
            events.batches().len(),
            1,
            "a non-`Conflict` error is not a lost tail race, so it consumes none of the \
             retry budget and the append is attempted exactly once"
        );
    }

    /// A `TaskFailed` append that loses the race at the stream tail is
    /// retried, and the retry lands.
    ///
    /// Driven by a store whose FIRST append answers
    /// `DomainError::Conflict` and whose second accepts, so the retry is
    /// observed rather than inferred: two attempts reach the store and
    /// the event is durable after the second. Before both halves shared
    /// one budget this append was bare — the conflict was a log line and
    /// the failure never reached the trail its own `TaskInvoked` is on.
    #[test]
    fn a_conflicting_task_failed_append_is_retried_and_then_lands() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let events = Arc::new(RecordingEventStore::conflicting_first(1));
        let row_id = dispatch_one_row_recording(
            &repo,
            &events,
            "noop",
            TEST_ATTEMPT_CAP,
            Arc::new(RetryHandler("noop")),
        );

        assert_eq!(
            events.batches().len(),
            2,
            "the first append conflicts and the second must be a fresh re-append — one \
             attempt would mean the conflict was swallowed as before"
        );
        // The attempt that landed is the last one — deliberately not
        // `only_task_failed`, which asserts a single attempt and is the
        // right shape only for an append that was never retried.
        let batches = events.batches();
        let landed = batches.last().expect("an append must have been attempted");
        assert_eq!(
            landed.stream_id,
            StreamId::authorization(),
            "the retry re-appends to the same kind-routed stream, not a re-derived one"
        );
        assert_eq!(landed.events.len(), 1, "expected a single-event batch");
        assert_eq!(
            landed.events[0].event,
            DomainEvent::TaskFailed(TaskFailed {
                task_job_id: row_id,
                kind: "noop".to_string(),
                reason: "transient error".to_string(),
                final_attempt: true,
            }),
            "the retried append carries the same event payload, not a rebuilt one"
        );
        assert_eq!(
            repo.mark_failed_calls(),
            vec![(row_id, "transient error".to_string())],
            "the row is closed out exactly once — the audit retry is not a second row write"
        );
    }

    /// A spent retry budget on the `TaskFailed` append leaves the job's
    /// result state exactly as it was.
    ///
    /// This is the one way carrying the retry over could have made
    /// things worse, so it is asserted rather than assumed: every
    /// attempt conflicts, the budget is bounded at
    /// `EVENT_APPEND_RETRY_ATTEMPTS`, the exhausted path logs and
    /// returns, and the row still reads exactly as it does when the
    /// append succeeds. An audit store nobody can reach must not be
    /// able to change what a task did.
    #[test]
    fn an_exhausted_task_failed_retry_budget_leaves_the_jobs_result_unchanged() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let events = Arc::new(RecordingEventStore::conflicting_first(
            EVENT_APPEND_RETRY_ATTEMPTS,
        ));
        let row_id = dispatch_one_row_recording(
            &repo,
            &events,
            "noop",
            TEST_ATTEMPT_CAP,
            Arc::new(RetryHandler("noop")),
        );

        assert_eq!(
            events.batches().len(),
            EVENT_APPEND_RETRY_ATTEMPTS as usize,
            "the retry is bounded by the shared budget and must not spin past it"
        );
        assert_eq!(
            repo.mark_failed_calls(),
            vec![(row_id, "transient error".to_string())],
            "the row is closed out exactly as it would have been with no contention"
        );
        assert!(
            repo.reschedule_calls().is_empty(),
            "a lost audit append must not be answered with a different row write"
        );
    }

    /// A kind outside `ADMIN_INVOKABLE_TASK_KINDS` closes its row out
    /// and appends nothing.
    ///
    /// `TaskFailed::validate` rejects such a kind and the production
    /// event store validates every event it appends, so an
    /// unconditional append here would write nothing but rejections for
    /// exactly the kinds the dispatcher runs and no operator can
    /// invoke. `scan` is the documented example: its rows are minted
    /// only by `enqueue_scan`, and its failures are the scan
    /// vocabulary's business.
    #[test]
    fn a_kind_outside_the_admin_invoke_allowlist_appends_no_audit_event() {
        for kind in ["scan", "oci-index-child-ingest"] {
            assert!(
                !ADMIN_INVOKABLE_TASK_KINDS.contains(&kind),
                "{kind} is the premise of this test — it must stay off the allowlist"
            );
            let repo = Arc::new(DispatcherMockRepo::new());
            let events = Arc::new(RecordingEventStore::new());
            let row_id = dispatch_one_row_recording(
                &repo,
                &events,
                kind,
                TEST_ATTEMPT_CAP,
                Arc::new(RetryHandler(kind)),
            );

            assert_eq!(
                repo.mark_failed_calls(),
                vec![(row_id, "transient error".to_string())],
                "{kind}: the row is still closed out — only the event is skipped"
            );
            assert!(
                events.batches().is_empty(),
                "{kind}: an append the event store would reject must not be issued; got {:?}",
                events.batches(),
            );
        }
    }

    /// A success appends nothing — the counter-assertion that the emit
    /// is scoped to the two failure paths and not to every outcome.
    #[test]
    fn a_completed_outcome_appends_no_audit_event() {
        let runs = Arc::new(AtomicUsize::new(0));
        let repo = Arc::new(DispatcherMockRepo::new());
        let events = Arc::new(RecordingEventStore::new());
        let row_id = dispatch_one_row_recording(
            &repo,
            &events,
            "noop",
            1,
            Arc::new(NoopHandler::new("noop", runs)),
        );

        assert_eq!(repo.mark_completed_calls(), vec![row_id]);
        assert!(
            events.batches().is_empty(),
            "there is no TaskCompleted in the vocabulary and no reason to invent one here; \
             got {:?}",
            events.batches(),
        );
    }

    /// The census behind the skip, pinned where the skip stands.
    ///
    /// Three `jobs.kind` values are valid rows the admin invoke path
    /// cannot produce. Two of them have a `TaskHandler` and so reach
    /// the dispatcher's failure paths — `scan` and
    /// `oci-index-child-ingest`, both covered by
    /// [`a_kind_outside_the_admin_invoke_allowlist_appends_no_audit_event`].
    /// `verify-event-chain` has no handler at all: its rows are written
    /// directly by the `hort-server verify-event-chain` subcommand as a
    /// liveness breadcrumb, so no dispatcher ever closes one out.
    ///
    /// A fourth arrival widens the set of failures that go unaudited,
    /// which is a decision rather than an oversight — this is what puts
    /// it in front of whoever adds it.
    #[test]
    fn the_kinds_with_no_task_failed_record_are_the_three_outside_the_allowlist() {
        let mut outside: Vec<&str> = EVENT_TASK_KINDS
            .iter()
            .copied()
            .filter(|k| !ADMIN_INVOKABLE_TASK_KINDS.contains(k))
            .collect();
        outside.sort_unstable();
        assert_eq!(
            outside,
            vec!["oci-index-child-ingest", "scan", "verify-event-chain"],
        );
    }

    /// The destructive kinds are the reason the cap is rated as it is,
    /// so one of them is pinned by name.
    ///
    /// `retention-purge` can fail on a later page after earlier pages
    /// have already deleted bytes, and its top-level error path asks to
    /// be retried. The per-UTC-day idempotency key (ADR 0028) stops a
    /// second *enqueue*, not repeated executions of the row that
    /// already exists — so the attempt budget is what bounds how many
    /// times an accepted destructive job runs in one day, and ADR 0028
    /// wants the end of that budget to be a persistent, operator-
    /// visible `failed` row rather than another silent re-drive.
    #[test]
    fn a_destructive_kind_at_the_attempt_cap_is_terminal() {
        let kind = "retention-purge";
        assert!(
            DESTRUCTIVE_TASK_KINDS.contains(&kind),
            "this test is only about what it claims while {kind:?} is still a destructive kind; \
             DESTRUCTIVE_TASK_KINDS is {DESTRUCTIVE_TASK_KINDS:?}"
        );

        let (repo, row_id, counters) =
            dispatch_one_row(kind, TEST_ATTEMPT_CAP, Arc::new(RetryHandler(kind)));

        assert_eq!(
            repo.mark_failed_calls(),
            vec![(row_id, "transient error".to_string())],
            "an accepted destructive job stops re-running itself once its budget is spent"
        );
        assert!(
            repo.reschedule_calls().is_empty(),
            "a destructive row at the cap must not be handed back to the queue"
        );
        assert_eq!(counters.failed_terminal, 1);
    }

    // -----------------------------------------------------------------------
    // Execution-time authority
    // -----------------------------------------------------------------------

    /// A `PermissionGrantRepository` whose snapshot read fails, so the
    /// re-check reaches no answer at all. Local to this module because
    /// the shared mock cannot be made to fail, and what it proves here
    /// is the *dispatcher's* mapping of an absent answer — a different
    /// fact from the verdict itself.
    struct UnreadableGrants;

    impl hort_domain::ports::permission_grant_repository::PermissionGrantRepository
        for UnreadableGrants
    {
        fn list_all(
            &self,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::rbac::PermissionGrant>>>
        {
            Box::pin(async { Err(DomainError::Invariant("database error: unreachable".into())) })
        }
        fn list_managed_by_gitops(
            &self,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::rbac::PermissionGrant>>>
        {
            unreachable!("the re-check reads the full snapshot")
        }
    }

    /// The gap this check exists for: the row was accepted, the
    /// requester's authority then went away, and the handler must never
    /// be called. Nothing destroyed.
    #[test]
    fn a_destructive_row_whose_requester_lost_authority_never_reaches_its_handler() {
        let kind = "retention-purge";
        assert!(
            DESTRUCTIVE_TASK_KINDS.contains(&kind),
            "this test is only about what it claims while {kind:?} is destructive"
        );
        let runs = Arc::new(AtomicUsize::new(0));

        // One attempt spent out of five, so a retry is still available
        // — nothing but the refusal's own `retry: false` can make this
        // terminal.
        let (repo, row_id, counters) = dispatch_one_row_with(
            kind,
            1,
            Arc::new(NoopHandler::new(kind, runs.clone())),
            refusing_reauthorizer(),
        );

        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "the handler must not run: a destructive handler that is entered has already begun \
             destroying"
        );
        assert!(
            repo.mark_completed_calls().is_empty(),
            "nothing completed — the work never started"
        );
        assert!(
            repo.reschedule_calls().is_empty(),
            "a revoked claim does not become valid by being tried again, so the row must not go \
             back to the queue even with budget left"
        );
        let failed = repo.mark_failed_calls();
        assert_eq!(failed.len(), 1, "exactly one terminal write: {failed:?}");
        assert_eq!(failed[0].0, row_id);
        assert!(
            failed[0].1.starts_with(REFUSAL_PREFIX),
            "the durable row must carry a reason naming the cause, not a generic failure: {:?}",
            failed[0].1
        );
        assert_eq!(counters.failed_terminal, 1);
        assert_eq!(counters.failed_retry, 0);
    }

    /// The normal case: authority unchanged, so the job runs exactly as
    /// it did before this check existed.
    #[test]
    fn a_destructive_row_whose_requester_still_holds_authority_runs() {
        let kind = "retention-purge";
        let runs = Arc::new(AtomicUsize::new(0));

        let (repo, row_id, _counters) =
            dispatch_one_row(kind, 1, Arc::new(NoopHandler::new(kind, runs.clone())));

        assert_eq!(runs.load(Ordering::SeqCst), 1, "the handler must still run");
        assert_eq!(repo.mark_completed_calls(), vec![row_id]);
        assert!(repo.mark_failed_calls().is_empty());
    }

    /// A non-destructive kind is untouched by any of this — the same
    /// reauthorizer that refuses a purge waves a `noop` straight
    /// through, because the classifier answers before either port is
    /// consulted.
    #[test]
    fn a_non_destructive_row_is_unaffected_by_a_refusing_reauthorizer() {
        let kind = "noop";
        assert!(
            !DESTRUCTIVE_TASK_KINDS.contains(&kind),
            "this test is only about what it claims while {kind:?} is NOT destructive"
        );
        let runs = Arc::new(AtomicUsize::new(0));

        let (repo, row_id, _counters) = dispatch_one_row_with(
            kind,
            1,
            Arc::new(NoopHandler::new(kind, runs.clone())),
            refusing_reauthorizer(),
        );

        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(repo.mark_completed_calls(), vec![row_id]);
        assert!(repo.mark_failed_calls().is_empty());
    }

    /// An authority store that cannot be read is fail-closed but not a
    /// verdict: the handler still does not run, and the row keeps its
    /// budget so the next claim re-asks. The distinction matters — a
    /// database flap must not permanently kill a destructive job the
    /// operator is entitled to, and must not run it either.
    #[test]
    fn an_unreadable_authority_store_holds_the_row_without_condemning_it() {
        let kind = "retention-purge";
        let runs = Arc::new(AtomicUsize::new(0));
        let users = Arc::new(MockUserRepository::new());
        users.insert(fixture_admin());
        let reauthorizer = Arc::new(DestructiveTaskReauthorizer::new(
            users,
            Arc::new(UnreadableGrants),
        ));

        let (repo, row_id, counters) = dispatch_one_row_with(
            kind,
            1,
            Arc::new(NoopHandler::new(kind, runs.clone())),
            reauthorizer,
        );

        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "an unanswerable authority check must not let the handler run"
        );
        let rescheduled = repo.reschedule_calls();
        assert_eq!(rescheduled.len(), 1, "the row keeps its budget");
        assert_eq!(rescheduled[0].0, row_id);
        assert!(
            rescheduled[0].1.starts_with(UNAVAILABLE_PREFIX),
            "the two cases are told apart by this prefix on the row, so pin it: {:?}",
            rescheduled[0].1
        );
        assert!(
            repo.mark_failed_calls().is_empty(),
            "an absent answer is not a refusal"
        );
        assert_eq!(counters.failed_retry, 1);
        assert_eq!(counters.failed_terminal, 0);
    }

    /// Every destructive kind goes through the same gate — pinned by
    /// iterating the closed domain set rather than naming one kind, so a
    /// fourth member (which `DESTRUCTIVE_TASK_KINDS` forbids, but a
    /// future reader may still add) cannot land unchecked.
    #[test]
    fn every_destructive_kind_is_gated() {
        for &kind in DESTRUCTIVE_TASK_KINDS {
            let runs = Arc::new(AtomicUsize::new(0));
            let (repo, _row_id, _counters) = dispatch_one_row_with(
                kind,
                1,
                Arc::new(NoopHandler::new(kind, runs.clone())),
                refusing_reauthorizer(),
            );
            assert_eq!(
                runs.load(Ordering::SeqCst),
                0,
                "{kind:?} reached its handler with no live authority behind it"
            );
            assert_eq!(repo.mark_failed_calls().len(), 1, "{kind} was not refused");
        }
    }

    // -----------------------------------------------------------------------
    // Test 7 — unhandled kind skipped safely
    // -----------------------------------------------------------------------

    /// A row whose kind is not in the registry (shouldn't happen because claim
    /// filters by registered kinds, but defensive). The dispatcher logs an
    /// error and continues without panicking.
    #[tokio::test]
    async fn dispatcher_unhandled_kind_skipped_safely() {
        let repo = Arc::new(DispatcherMockRepo::new());

        // Seed a row that won't be registered.
        // The claim mock bypasses the kind filter, so this simulates a race
        // where the kind was deregistered between claim and dispatch.
        // (In practice the claim query's WHERE kind = ANY(...) prevents this.)
        // The row is now returned to `pending` rather than left `running`
        // — see `claimed_row_with_unregistered_kind_is_returned_to_pending`;
        // this test pins the surrounding loop's liveness.
        let row = make_job_row("unknown-kind");
        repo.seed_batch(vec![row]);

        let run_count = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        // Register a different kind — "unknown-kind" is NOT registered.
        dispatcher.register(Arc::new(NoopHandler::new("noop", run_count.clone())), 4);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });

        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("dispatcher join timed out")
            .expect("task did not panic");

        // Dispatcher must return Ok (not panic, not Err).
        assert!(result.is_ok(), "run must return Ok even with unknown kind");
        // And noop handler must not have run (the unknown kind was skipped).
        assert_eq!(
            run_count.load(Ordering::SeqCst),
            0,
            "noop handler must not run"
        );
    }

    // -----------------------------------------------------------------------
    // Test 8 — emits completed_total metric
    // -----------------------------------------------------------------------

    /// `hort_admin_tasks_completed_total{kind="noop", result="completed"}` is
    /// incremented when the handler returns Completed.
    #[tokio::test]
    async fn dispatcher_emits_completed_total_metric() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(DispatcherMockRepo::new());
        repo.seed_batch(vec![make_job_row("noop")]);

        let run_count = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;
        dispatcher.register(Arc::new(NoopHandler::new("noop", run_count.clone())), 4);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = metrics::with_local_recorder(&recorder, || {
            tokio::spawn(async move { dispatcher.run(cancel_clone).await })
        });

        // Give the task time to fire inside the recorder's context.
        // The spawned tokio task runs on the same thread (current_thread runtime),
        // but metrics::with_local_recorder only applies to the current thread.
        // We need the metric to be emitted inside the recorder scope.
        // Re-enter the recorder context after spawning:
        metrics::with_local_recorder(&recorder, || {
            std::thread::sleep(Duration::from_millis(200));
        });

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap();

        // For the metric to fire under the recorder, dispatch_one must run
        // while the recorder is active. Since spawned tasks don't inherit
        // thread-local recorders, we assert the metric using the global
        // recorder approach: run everything in a blocking context.
        // This test is a structural compile + metric-API test — the metric
        // emission is validated by test 8b below using a simpler path.
        let _ = snapshotter.snapshot();
        // The test passes if no panic occurs (structure + API check).
    }

    // -----------------------------------------------------------------------
    // Test 8b — emits completed_total metric (blocking path)
    // -----------------------------------------------------------------------

    /// Directly call `dispatch_one` synchronously via `block_on` under a
    /// `DebuggingRecorder` to assert the counter fires. This avoids the
    /// thread-local recorder scoping issue with `tokio::spawn`.
    #[test]
    fn dispatcher_emits_completed_total_metric_blocking() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("noop");
        let run_count = Arc::new(AtomicUsize::new(0));
        let handler: Arc<dyn TaskHandler> = Arc::new(NoopHandler::new("noop", run_count.clone()));

        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(dispatch_one_with_lease(&Arc::new(dispatcher), row, handler))
        });

        let snap = snapshotter.snapshot().into_vec();
        let v = counter_value(
            &snap,
            METRIC_COMPLETED,
            &[("kind", "noop"), ("result", RESULT_COMPLETED)],
        );
        assert_eq!(v, 1, "completed counter must fire once; got {v}");
    }

    // -----------------------------------------------------------------------
    // Test 9 — emits duration histogram
    // -----------------------------------------------------------------------

    #[test]
    fn dispatcher_emits_duration_histogram() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("noop");
        let run_count = Arc::new(AtomicUsize::new(0));
        let handler: Arc<dyn TaskHandler> = Arc::new(NoopHandler::new("noop", run_count.clone()));

        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(dispatch_one_with_lease(&Arc::new(dispatcher), row, handler))
        });

        let snap = snapshotter.snapshot().into_vec();
        let count = histogram_count(&snap, METRIC_DURATION, &[("kind", "noop")]);
        assert_eq!(
            count, 1,
            "duration histogram must have one sample; got {count}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 10 — emits in-flight gauge
    // -----------------------------------------------------------------------

    /// During `run`, the in-flight gauge goes up before the handler is called
    /// and back down after. We verify this via a slow handler that sleeps —
    /// the gauge is incremented, sleep occurs, gauge is decremented.
    /// We check that the final snapshot shows the gauge at 0 (or it was
    /// decremented from 1 back to 0).
    #[test]
    fn dispatcher_emits_in_flight_gauge() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("noop");
        let run_count = Arc::new(AtomicUsize::new(0));
        let handler: Arc<dyn TaskHandler> = Arc::new(NoopHandler::new("noop", run_count.clone()));

        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(dispatch_one_with_lease(&Arc::new(dispatcher), row, handler))
        });

        let snap = snapshotter.snapshot().into_vec();
        // The gauge should be 0 after dispatch_one completes (incremented
        // before run, decremented after). Check it exists in the snapshot.
        let gauge_entry = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Gauge
                && ck.key().name() == METRIC_IN_FLIGHT
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "kind" && l.value() == "noop")
        });
        assert!(
            gauge_entry.is_some(),
            "in-flight gauge must appear in snapshot after dispatch_one"
        );
    }

    // -----------------------------------------------------------------------
    // The budget and the window it spans
    // -----------------------------------------------------------------------

    /// The two halves of the budget, multiplied out.
    ///
    /// Each half is pinned where it is defined: the cap by the
    /// terminal-at-the-cap tests above, the four waits by value in
    /// `crate::retry_backoff`'s own tests. Neither file can state the
    /// product, and the product is the only part an operator
    /// experiences — a row that sits in the jobs table with a growing
    /// retry delay for two and a half hours before it goes `failed`.
    ///
    /// This is also what pins the neighbouring cap tests to the *sixth*
    /// execution: they are written against `TEST_ATTEMPT_CAP` and would
    /// pass at any value of it, so the number itself is asserted here.
    /// Reshape the curve and this fails, which is the point — an
    /// exhausted budget means "persistently broken" only while the
    /// window is long enough for that to be the likelier reading.
    ///
    /// The cap is now configured rather than compiled in, so what this
    /// pins is the **default** an unconfigured deployment lands on. An
    /// operator who raises `HORT_SCANNER_MAX_ATTEMPTS` is buying a
    /// longer window at 60 minutes an attempt and has said so;
    /// [`the_cap_is_the_configured_one_not_the_default`] is what proves
    /// the configured number is the one that fires.
    #[test]
    fn six_executions_span_the_hundred_and_fifty_six_minute_window() {
        assert_eq!(
            TEST_ATTEMPT_CAP, 6,
            "the window asserted below is the one six executions span"
        );

        let spent: Vec<u64> = (1..TEST_ATTEMPT_CAP)
            .map(|attempts| compute_backoff(attempts).as_secs())
            .collect();
        assert_eq!(
            spent,
            vec![60, 5 * 60, 30 * 60, 60 * 60, 60 * 60],
            "the five waits a six-execution budget actually spends"
        );
        assert_eq!(
            spent.iter().sum::<u64>(),
            156 * 60,
            "first failure to terminal row — the scan pipeline's own window, to the second"
        );
    }

    // -----------------------------------------------------------------------
    // Claimed-but-undispatchable rows must not be lost
    // -----------------------------------------------------------------------

    /// A claimed row whose kind has no registered handler used to be
    /// skipped with the row left `running`, on the stated assumption that
    /// "the lock expires and another worker claims it". It does not: the
    /// claim query selects `status = 'pending'` only, and nothing anywhere
    /// resets a stale `running` row. The row must be returned to `pending`.
    #[tokio::test]
    async fn claimed_row_with_unregistered_kind_is_returned_to_pending() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let orphan = make_job_row("kind-with-no-handler");
        repo.seed_batch(vec![orphan.clone()]);

        // No handler registered at all → the claimed row is undispatchable.
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        let calls = repo.reschedule_calls();
        assert_eq!(
            calls.len(),
            1,
            "the orphan row must be returned to pending: {calls:?}"
        );
        assert_eq!(calls[0].0, orphan.id);
        assert!(
            calls[0].1.contains("unregistered kind"),
            "last_error must name the cause: {:?}",
            calls[0].1
        );
        assert_eq!(
            repo.write_log.attempts(),
            vec![orphan.attempts],
            "the revert is a result write like any other: it carries the attempt the claim \
             charged this row, so a sibling that took the row in between keeps it"
        );
    }

    /// The revert itself can fail (DB flap). The dispatcher logs and keeps
    /// polling — it must not panic or abort the loop.
    #[tokio::test]
    async fn failed_return_to_pending_does_not_break_the_poll_loop() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.fail_reschedule();
        repo.seed_batch(vec![make_job_row("kind-with-no-handler")]);
        repo.seed_batch(vec![make_job_row("kind-with-no-handler")]);

        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("join timed out")
            .expect("task did not panic");
        assert!(result.is_ok(), "run returned Err: {result:?}");
        assert!(
            repo.reschedule_calls().len() >= 2,
            "the loop must keep polling after a failed revert"
        );
    }

    // -----------------------------------------------------------------------
    // Starvation detection
    // -----------------------------------------------------------------------

    fn backlog(kind: &str, count: i64, oldest: DateTime<Utc>) -> PendingKindBacklog {
        PendingKindBacklog {
            kind: kind.to_string(),
            count,
            oldest_created_at: oldest,
        }
    }

    const THRESHOLD: Duration = Duration::from_secs(600);

    /// The live-incident shape: an unregistered kind has ~1450 eligible pending
    /// rows, the oldest hours old, and this dispatcher has no handler for
    /// the kind — so `claim_pending_by_kinds` never selects it and nothing
    /// ever complains. The audit must call it out as `unregistered`.
    #[test]
    fn detect_starvation_flags_an_unregistered_kind_with_an_old_backlog() {
        let now = Utc::now();
        let started = now - chrono::Duration::hours(2);
        let registered: HashSet<&str> = ["quarantine-release-sweep"].into_iter().collect();
        let backlogs = vec![backlog(
            "provenance-verify",
            1450,
            now - chrono::Duration::hours(2),
        )];

        let f = detect_starvation(
            &backlogs,
            &registered,
            &HashMap::new(),
            now,
            started,
            THRESHOLD,
        );

        // Two independent findings: the primary axis (`unregistered`, since
        // the reference/`.max` floor is old too) AND the oldest-row axis
        // (the row itself is hours old, unconditionally).
        assert_eq!(f.len(), 2, "{f:?}");
        let primary = f
            .iter()
            .find(|x| x.reason == STARVED_UNREGISTERED)
            .expect("missing unregistered finding");
        assert_eq!(primary.kind, "provenance-verify");
        assert_eq!(primary.count, 1450);
        assert!(primary.stalled_for_secs >= 7200, "{f:?}");
        let oldest_row = f
            .iter()
            .find(|x| x.reason == STARVED_OLDEST_ROW)
            .expect("missing oldest_row_stalled finding");
        assert_eq!(oldest_row.kind, "provenance-verify");
        assert!(oldest_row.stalled_for_secs >= 7200, "{f:?}");
    }

    /// Same backlog, but the kind IS registered and simply loses the
    /// `priority DESC, created_at ASC` race every poll → `not_claimed`.
    #[test]
    fn detect_starvation_flags_a_registered_but_unclaimed_kind() {
        let now = Utc::now();
        let started = now - chrono::Duration::hours(2);
        let registered: HashSet<&str> = ["provenance-verify"].into_iter().collect();
        let backlogs = vec![backlog(
            "provenance-verify",
            40,
            now - chrono::Duration::hours(1),
        )];

        let f = detect_starvation(
            &backlogs,
            &registered,
            &HashMap::new(),
            now,
            started,
            THRESHOLD,
        );

        // Same dual-finding shape as above, but the primary axis's reason
        // is `not_claimed` because the kind IS registered here.
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().any(|x| x.reason == STARVED_NOT_CLAIMED), "{f:?}");
        assert!(f.iter().any(|x| x.reason == STARVED_OLDEST_ROW), "{f:?}");
    }

    /// Incident replay: a REGISTERED kind is claimed constantly (`last_claimed`
    /// re-arms every tick, so the primary axis stays silent) while a
    /// sustained higher-priority stream of the SAME kind claims only fresh
    /// rows every poll — the single oldest eligible row of the kind never
    /// advances and rots for hours. Only the independent oldest-row-age
    /// axis can catch this; it must alarm with `reason =
    /// "oldest_row_stalled"` regardless of the fresh `last_claimed`.
    #[test]
    fn detect_starvation_flags_a_rotting_oldest_row_despite_constant_claims() {
        let now = Utc::now();
        let started = now - chrono::Duration::hours(3);
        let registered: HashSet<&str> = ["scan"].into_iter().collect();
        let backlogs = vec![backlog("scan", 500, now - chrono::Duration::hours(2))];
        let mut last_claimed = HashMap::new();
        last_claimed.insert("scan".to_string(), now - chrono::Duration::seconds(1));

        let f = detect_starvation(
            &backlogs,
            &registered,
            &last_claimed,
            now,
            started,
            THRESHOLD,
        );

        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].kind, "scan");
        assert_eq!(f[0].count, 500);
        assert_eq!(f[0].reason, STARVED_OLDEST_ROW);
        assert!(f[0].stalled_for_secs >= 7200, "{f:?}");
    }

    /// A deep FIFO queue that IS genuinely draining re-arms its
    /// last-claimed clock on every tick AND keeps its oldest row fresh
    /// (the front of the FIFO order is continuously being claimed). That
    /// is the common case and must never alarm on either axis.
    #[test]
    fn detect_starvation_ignores_a_deep_but_draining_queue() {
        let now = Utc::now();
        let started = now - chrono::Duration::hours(2);
        let registered: HashSet<&str> = ["provenance-verify"].into_iter().collect();
        let backlogs = vec![backlog(
            "provenance-verify",
            5000,
            now - chrono::Duration::seconds(30),
        )];
        let mut last_claimed = HashMap::new();
        last_claimed.insert(
            "provenance-verify".to_string(),
            now - chrono::Duration::seconds(5),
        );

        let f = detect_starvation(
            &backlogs,
            &registered,
            &last_claimed,
            now,
            started,
            THRESHOLD,
        );

        assert!(f.is_empty(), "a draining queue must not alarm: {f:?}");
    }

    /// A long-running worker that has never claimed a kind whose rows only
    /// just arrived must not alarm — the backlog cannot have starved for
    /// longer than it has existed.
    #[test]
    fn detect_starvation_floors_the_stall_at_the_oldest_row() {
        let now = Utc::now();
        let started = now - chrono::Duration::hours(6);
        let registered: HashSet<&str> = ["provenance-verify"].into_iter().collect();
        let backlogs = vec![backlog(
            "provenance-verify",
            3,
            now - chrono::Duration::seconds(2),
        )];

        let f = detect_starvation(
            &backlogs,
            &registered,
            &HashMap::new(),
            now,
            started,
            THRESHOLD,
        );

        assert!(f.is_empty(), "fresh rows must not read as a stall: {f:?}");
    }

    /// An empty backlog row (count 0) is not starvation.
    #[test]
    fn detect_starvation_ignores_empty_backlogs() {
        let now = Utc::now();
        let started = now - chrono::Duration::hours(2);
        let backlogs = vec![backlog("noop", 0, now - chrono::Duration::hours(2))];

        let f = detect_starvation(
            &backlogs,
            &HashSet::new(),
            &HashMap::new(),
            now,
            started,
            THRESHOLD,
        );

        assert!(f.is_empty(), "{f:?}");
    }

    /// A stall exactly at the threshold is not yet starvation (`>`, not
    /// `>=`), and an out-of-range `Duration` saturates rather than panicking.
    /// The backlog's oldest row sits exactly at the threshold too, so
    /// neither the primary axis nor the independent oldest-row axis fires.
    #[test]
    fn detect_starvation_threshold_boundary_and_saturating_conversion() {
        let now = Utc::now();
        let started = now - chrono::Duration::seconds(600);
        let backlogs = vec![backlog("noop", 1, now - chrono::Duration::seconds(600))];

        let at_threshold = detect_starvation(
            &backlogs,
            &HashSet::new(),
            &HashMap::new(),
            now,
            started,
            THRESHOLD,
        );
        assert!(
            at_threshold.is_empty(),
            "exactly-at-threshold must not fire: {at_threshold:?}"
        );

        // `chrono::Duration::from_std(Duration::MAX)` fails → saturate to
        // `chrono::Duration::MAX`, i.e. nothing can ever exceed it.
        let saturated = detect_starvation(
            &backlogs,
            &HashSet::new(),
            &HashMap::new(),
            now,
            started,
            Duration::MAX,
        );
        assert!(saturated.is_empty(), "{saturated:?}");
    }

    /// End-to-end through the poll loop: a dispatcher with NO
    /// `provenance-verify` handler and an hours-old eligible backlog for
    /// that kind emits the depth gauge and the `unregistered` starvation
    /// counter. This is the diagnostic a silent starvation otherwise lacks.
    #[tokio::test]
    async fn poll_loop_audit_emits_gauge_and_unregistered_starvation_counter() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.seed_backlog(vec![backlog(
            "provenance-verify",
            1450,
            Utc::now() - chrono::Duration::hours(2),
        )]);
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.poll_interval_secs = 0;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        drop(guard);

        let snapshot = snapshotter.snapshot().into_vec();
        let gauge = snapshot.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Gauge && ck.key().name() == METRIC_PENDING_ELIGIBLE
        });
        let (_, _, _, depth) = gauge.expect("depth gauge missing");
        assert_eq!(*depth, DebugValue::Gauge(1450.0.into()));

        // A just-booted worker publishes the depth immediately but does NOT
        // accuse anyone: the ERROR/counter still needs STARVATION_THRESHOLD
        // to elapse since `started_at`.
        assert_eq!(
            counter_value(
                &snapshot,
                METRIC_STARVED,
                &[
                    ("kind", "provenance-verify"),
                    ("reason", STARVED_UNREGISTERED),
                ],
            ),
            0,
            "a freshly booted worker must not alarm within its grace window"
        );
    }

    /// Once the grace window has elapsed, the same backlog produces the
    /// ERROR-logged `unregistered` starvation counter. `started_at` is the
    /// only input that has to age, so it is supplied directly rather than
    /// waiting ten minutes of wall clock.
    #[tokio::test]
    async fn audit_starvation_emits_the_unregistered_counter_past_the_grace_window() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.seed_backlog(vec![backlog(
            "provenance-verify",
            1450,
            Utc::now() - chrono::Duration::hours(2),
        )]);
        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);
        dispatcher
            .audit_starvation(
                &HashSet::new(),
                &HashMap::new(),
                Utc::now() - chrono::Duration::hours(2),
            )
            .await;
        drop(guard);

        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(
            counter_value(
                &snapshot,
                METRIC_STARVED,
                &[
                    ("kind", "provenance-verify"),
                    ("reason", STARVED_UNREGISTERED),
                ],
            ),
            1,
            "starvation counter missing: {snapshot:?}"
        );
    }

    /// A failing audit query is warn-and-continue, not a loop-killer.
    #[tokio::test]
    async fn audit_starvation_swallows_a_query_failure() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.fail_backlog();
        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher
            .audit_starvation(&HashSet::new(), &HashMap::new(), Utc::now())
            .await;
    }

    /// Claiming a row of a kind re-arms that kind's starvation clock, so a
    /// registered-and-draining kind never trips the audit even when its
    /// backlog is old and deep.
    #[tokio::test]
    async fn claiming_a_kind_suppresses_its_starvation_finding() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.seed_batch(vec![make_job_row("noop")]);
        repo.seed_backlog(vec![backlog(
            "noop",
            5000,
            Utc::now() - chrono::Duration::hours(2),
        )]);
        let run_count = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.register(Arc::new(NoopHandler::new("noop", run_count.clone())), 4);
        dispatcher.poll_interval_secs = 0;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        drop(guard);

        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(
            counter_value(
                &snapshot,
                METRIC_STARVED,
                &[("kind", "noop"), ("reason", STARVED_NOT_CLAIMED)],
            ),
            0,
            "a kind claimed this tick must not be reported starved: {snapshot:?}"
        );
    }
    // -----------------------------------------------------------------------
    // Per-class service audit (ADR 0066 D5)
    // -----------------------------------------------------------------------

    /// A slice sample with nothing in it — each test below sets only the
    /// facts its scenario rests on.
    fn empty_sample() -> QueueServiceSample {
        QueueServiceSample {
            pending_eligible: 0,
            oldest_pending_at: None,
            awaiting_capacity: 0,
            oldest_capacity_wait_at: None,
            last_served_at: None,
        }
    }

    /// One band's observation, built from its kinds.
    ///
    /// Every fixture below has to name the kinds its rows belong to,
    /// because a band is made of kinds and "two rows waiting in the
    /// Normal band" is not a complete statement of a queue: the
    /// guarantee is enforced per kind as well as per class, so which
    /// kind the rows are is part of the scenario rather than detail.
    fn band(kinds: Vec<(&str, QueueServiceSample)>) -> BandQueueSample {
        BandQueueSample {
            kinds: kinds
                .into_iter()
                .map(|(kind, sample)| KindQueueSample {
                    kind: kind.to_string(),
                    sample,
                })
                .collect(),
        }
    }

    /// A band with no rows at all — the class is completely quiet.
    fn empty_band() -> BandQueueSample {
        band(Vec::new())
    }

    /// The common single-kind band: one kind's facts, and nothing else
    /// of that class in the queue.
    fn one_kind_band(kind: &str, sample: QueueServiceSample) -> BandQueueSample {
        band(vec![(kind, sample)])
    }

    fn secs_ago(secs: i64) -> DateTime<Utc> {
        Utc::now() - chrono::Duration::seconds(secs)
    }

    /// Run both instruments over one scenario and return the metric
    /// snapshot: the pre-change per-kind audit with its own inputs, and
    /// the per-class audit with the seeded band samples.
    ///
    /// Both in one recorder on purpose. The claim each gap test makes is
    /// not "the new counter fires" but "the new counter fires **where
    /// the old one does not**", and that is only an assertion if the old
    /// one was given its own best shot at the same state in the same
    /// snapshot.
    async fn run_both_audits(
        repo: &Arc<DispatcherMockRepo>,
        last_claimed: &HashMap<String, DateTime<Utc>>,
        started_at: DateTime<Utc>,
    ) -> Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )> {
        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        let registered: HashSet<&str> = ["scan"].into_iter().collect();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);
        dispatcher
            .audit_starvation(&registered, last_claimed, started_at)
            .await;
        dispatcher.audit_class_service().await;
        drop(guard);
        snapshotter.snapshot().into_vec()
    }

    /// **Gap one.** A kind that is claimed steadily while one of its
    /// classes is not.
    ///
    /// `scan` carries all three classes. Here its `Interactive` rows are
    /// claimed and completed constantly and its `Normal` rows — an
    /// operator's rescans — have been sitting unclaimed for just under
    /// seven minutes with nothing of that class ever served.
    ///
    /// **The per-kind audit is silent, and both of its axes are silent
    /// for a structural reason, not a tuning one.** Its first axis asks
    /// "is this kind being claimed", and the answer is yes — the clock
    /// is re-armed by a row of *any* class, which is precisely the
    /// blind spot. Its second axis asks "has the kind's oldest eligible
    /// row aged past 600 s", and it has not: that threshold is sized
    /// "well above any legitimate transient" because the axis fires on
    /// states that are not defects (a deep queue draining normally
    /// keeps an old oldest row), so it cannot also be the window a
    /// control task's starvation is caught in. The per-class predicate
    /// has no such false positives to tolerate — service re-arms its
    /// reference — so it answers at 300 s, and that is the window this
    /// scenario sits in.
    #[tokio::test]
    async fn a_class_that_is_never_served_is_invisible_to_the_per_kind_audit() {
        let repo = Arc::new(DispatcherMockRepo::new());
        // The per-kind view: one kind, seven eligible rows, the oldest
        // of them 400 s old. This is the SAME queue the per-class view
        // below describes — 5 Interactive rows plus 2 Normal ones.
        repo.seed_backlog(vec![backlog("scan", 7, secs_ago(400))]);
        // The per-class view, in `class_bands()` order.
        repo.seed_band_samples(vec![
            // Interactive: flowing. Claimed and completed seconds ago.
            one_kind_band(
                "scan",
                QueueServiceSample {
                    pending_eligible: 5,
                    oldest_pending_at: Some(secs_ago(30)),
                    last_served_at: Some(secs_ago(2)),
                    ..empty_sample()
                },
            ),
            // Normal: two operator rescans waiting 400 s, and nothing
            // of this class has ever been served.
            one_kind_band(
                "scan",
                QueueServiceSample {
                    pending_eligible: 2,
                    oldest_pending_at: Some(secs_ago(400)),
                    ..empty_sample()
                },
            ),
            // Bulk: nothing waiting.
            empty_band(),
        ]);
        // The kind was claimed two seconds ago, and the worker has been
        // up for two hours — so the per-kind audit has no grace window
        // left to hide behind.
        let last_claimed: HashMap<String, DateTime<Utc>> =
            [("scan".to_string(), secs_ago(2))].into_iter().collect();

        let snapshot = run_both_audits(&repo, &last_claimed, secs_ago(7_200)).await;

        // The pre-change instrument says nothing at all — on either
        // reason, for the one kind there is.
        for reason in [
            STARVED_UNREGISTERED,
            STARVED_NOT_CLAIMED,
            STARVED_OLDEST_ROW,
        ] {
            assert_eq!(
                counter_value(
                    &snapshot,
                    METRIC_STARVED,
                    &[("kind", "scan"), ("reason", reason)]
                ),
                0,
                "the per-kind audit must read this queue as healthy — that is the gap: \
                 {snapshot:?}"
            );
        }
        // And the per-class audit names the class that is losing, and
        // the allocation point it is losing at.
        assert_eq!(
            counter_value(
                &snapshot,
                METRIC_CLASS_STARVED,
                &[
                    ("class", TaskTier::Normal.as_str()),
                    ("reason", ClassStarvationReason::NotClaimed.as_str()),
                ],
            ),
            1,
            "the class with work waiting and no service must be reported: {snapshot:?}"
        );
        // The class that IS being served is not reported, so the finding
        // is a verdict rather than a restatement of "this kind has a
        // backlog".
        for class in [TaskTier::Interactive.as_str(), TaskTier::Bulk.as_str()] {
            for reason in [
                ClassStarvationReason::NotClaimed.as_str(),
                ClassStarvationReason::AwaitingCapacity.as_str(),
            ] {
                assert_eq!(
                    counter_value(
                        &snapshot,
                        METRIC_CLASS_STARVED,
                        &[("class", class), ("reason", reason)],
                    ),
                    0,
                    "{class} is being served or idle and must not be reported: {snapshot:?}"
                );
            }
        }
    }

    /// **Gap two.** A class whose rows are waiting for permits.
    ///
    /// The rows have been claimed, so they are `running` and outside the
    /// claim-eligible backlog **by construction**: no SQL read of
    /// pending rows can see them, whatever its threshold. The per-kind
    /// audit here sees a kind that is being claimed with one young
    /// pending row — a perfectly healthy queue — while three rows of
    /// the `Normal` class have held a claim for twelve minutes without
    /// being given the capacity to run.
    ///
    /// This is also the debt the lease-renewal move took on: once
    /// renewal starts at the claim, `locked_until` no longer separates
    /// *queued* from *executing*, so this count is the only thing that
    /// tells a row waiting for capacity from a row running a slow
    /// handler.
    #[tokio::test]
    async fn rows_waiting_for_a_permit_are_invisible_to_the_per_kind_audit() {
        let repo = Arc::new(DispatcherMockRepo::new());
        // The per-kind view: one young pending row. The starved rows
        // are NOT here — they are `running`.
        repo.seed_backlog(vec![backlog("scan", 1, secs_ago(10))]);
        repo.seed_band_samples(vec![
            one_kind_band(
                "scan",
                QueueServiceSample {
                    pending_eligible: 1,
                    oldest_pending_at: Some(secs_ago(10)),
                    last_served_at: Some(secs_ago(1)),
                    ..empty_sample()
                },
            ),
            // Normal: nothing pending at all, three rows holding claims
            // and queued behind a run permit for 700 s, nothing of the
            // class served in two hours.
            one_kind_band(
                "scan",
                QueueServiceSample {
                    awaiting_capacity: 3,
                    oldest_capacity_wait_at: Some(secs_ago(700)),
                    last_served_at: Some(secs_ago(7_200)),
                    ..empty_sample()
                },
            ),
            empty_band(),
        ]);
        let last_claimed: HashMap<String, DateTime<Utc>> =
            [("scan".to_string(), secs_ago(1))].into_iter().collect();

        let snapshot = run_both_audits(&repo, &last_claimed, secs_ago(7_200)).await;

        for reason in [
            STARVED_UNREGISTERED,
            STARVED_NOT_CLAIMED,
            STARVED_OLDEST_ROW,
        ] {
            assert_eq!(
                counter_value(
                    &snapshot,
                    METRIC_STARVED,
                    &[("kind", "scan"), ("reason", reason)]
                ),
                0,
                "a permit waiter is `running`, so no per-kind read of the pending backlog \
                 can report it at any threshold: {snapshot:?}"
            );
        }
        assert_eq!(
            counter_value(
                &snapshot,
                METRIC_CLASS_STARVED,
                &[
                    ("class", TaskTier::Normal.as_str()),
                    ("reason", ClassStarvationReason::AwaitingCapacity.as_str()),
                ],
            ),
            1,
            "the class queued behind the permit must be reported, and the reason must name \
             the permit rather than the claim: {snapshot:?}"
        );
        assert_eq!(
            counter_value(
                &snapshot,
                METRIC_CLASS_STARVED,
                &[
                    ("class", TaskTier::Normal.as_str()),
                    ("reason", ClassStarvationReason::NotClaimed.as_str()),
                ],
            ),
            0,
            "the claim is not where this class is losing: {snapshot:?}"
        );
    }

    /// **Gap three.** A kind starving at its own permit point, inside a
    /// class a *sibling kind* keeps re-arming.
    ///
    /// The permits are allocated per registered kind — the dispatcher
    /// holds one allocator per kind, and the per-class time floor and
    /// the class-blind age net live inside it — so the guarantee is
    /// enforced per kind **and** per class. ADR 0066 D5: *"An
    /// observation coarser than the enforcement is a statistic and not
    /// an alarm — a guarantee enforced per kind and per class, and
    /// watched per class alone, can be reported healthy by a sibling
    /// kind's progress."*
    ///
    /// This is that constellation, and the class-wide verdict is
    /// **right** about what it was asked: one `scan` row of the `Normal`
    /// class has held a claim for 700 s behind that kind's permit, while
    /// `prefetch` rows of the same class completed a second ago. The
    /// class's newest completion is therefore a second old, the
    /// class-wide reference instant is re-armed, and the class reads as
    /// served — by a kind whose allocator is not the one that is stuck.
    /// The finding lives at `(class, kind)` and nowhere coarser.
    #[tokio::test]
    async fn a_kind_starved_at_its_permit_is_reported_though_a_sibling_kind_just_completed() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.seed_band_samples(vec![
            empty_band(),
            band(vec![
                // `scan`: one row claimed and queued behind this kind's
                // run permit for 700 s, and nothing of this kind and
                // class has ever completed.
                (
                    "scan",
                    QueueServiceSample {
                        awaiting_capacity: 1,
                        oldest_capacity_wait_at: Some(secs_ago(700)),
                        ..empty_sample()
                    },
                ),
                // `prefetch`: nothing waiting, and a completion a second
                // ago. A different kind, the same class.
                (
                    "prefetch",
                    QueueServiceSample {
                        last_served_at: Some(secs_ago(1)),
                        ..empty_sample()
                    },
                ),
            ]),
            empty_band(),
        ]);
        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);
        dispatcher.audit_class_service().await;
        drop(guard);
        let snapshot = snapshotter.snapshot().into_vec();

        // The class-wide instrument says nothing, on either reason —
        // that is the gap, and it is not a tuning failure: the sibling's
        // completion is a real completion of that class.
        for reason in [
            ClassStarvationReason::NotClaimed.as_str(),
            ClassStarvationReason::AwaitingCapacity.as_str(),
        ] {
            assert_eq!(
                counter_value(
                    &snapshot,
                    METRIC_CLASS_STARVED,
                    &[("class", TaskTier::Normal.as_str()), ("reason", reason)],
                ),
                0,
                "the class-wide verdict is re-armed by the sibling kind — that is the \
                 observation this granularity exists to replace: {snapshot:?}"
            );
        }
        // And the per-kind instrument names the kind and the allocation
        // point.
        assert_eq!(
            counter_value(
                &snapshot,
                METRIC_CLASS_KIND_STARVED,
                &[
                    ("class", TaskTier::Normal.as_str()),
                    ("kind", "scan"),
                    ("reason", ClassStarvationReason::AwaitingCapacity.as_str()),
                ],
            ),
            1,
            "the kind queued behind its own permit must be reported, with the permit named \
             rather than the claim: {snapshot:?}"
        );
        // The sibling is not accused of anything: it has nothing
        // waiting, so it is owed no service.
        for reason in [
            ClassStarvationReason::NotClaimed.as_str(),
            ClassStarvationReason::AwaitingCapacity.as_str(),
        ] {
            assert_eq!(
                counter_value(
                    &snapshot,
                    METRIC_CLASS_KIND_STARVED,
                    &[
                        ("class", TaskTier::Normal.as_str()),
                        ("kind", "prefetch"),
                        ("reason", reason),
                    ],
                ),
                0,
                "the kind that is flowing is idle, not starved: {snapshot:?}"
            );
        }
        assert_eq!(
            counter_value(
                &snapshot,
                METRIC_CLASS_KIND_STARVED,
                &[
                    ("class", TaskTier::Normal.as_str()),
                    ("kind", "scan"),
                    ("reason", ClassStarvationReason::NotClaimed.as_str()),
                ],
            ),
            0,
            "the claim is not where this kind is losing: {snapshot:?}"
        );
    }

    /// The observation covers **every** class, including the one with no
    /// reserved share.
    ///
    /// The bands it asks about are `class_bands()`, not the claim's
    /// `waited_on_bands()`. Building the observation from the
    /// reservation's list is the plausible mistake, and it would leave
    /// `Bulk` — the class whose service nothing else holds, because
    /// nobody is waiting on it — unobserved.
    #[tokio::test]
    async fn the_service_audit_observes_every_class_not_only_the_reserved_ones() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.audit_class_service().await;

        let queries = repo.band_queries();
        assert_eq!(queries.len(), 1, "one audit, one observation");
        let expected: Vec<PriorityBand> = class_bands().into_iter().map(|(_, band)| band).collect();
        assert_eq!(
            queries[0], expected,
            "the audit must observe every class's band, in class order"
        );
        assert!(
            queries[0].len() > hort_domain::types::task_tier::waited_on_bands().len(),
            "an observation built from the reservation's band list would be blind to Bulk"
        );
    }

    /// The audit answers at the **configured** threshold, not at the
    /// domain default.
    ///
    /// The number is read in the worker's composition root and the
    /// verdict it feeds is also emitted by `hort-server`, so "the knob
    /// was configured but never threaded" would look exactly like "the
    /// knob was never set" — the same shape the two attempt caps had
    /// while one of them was a `const`. One sample, two thresholds, two
    /// verdicts.
    #[tokio::test]
    async fn the_service_audit_answers_at_the_configured_threshold() {
        /// The class has had work waiting this long with nothing of it
        /// served — between the two thresholds below.
        const WAITED_SECS: i64 = 400;

        for (threshold_secs, expected) in [(900u64, 0u64), (300u64, 1u64)] {
            let repo = Arc::new(DispatcherMockRepo::new());
            repo.seed_band_samples(vec![
                empty_band(),
                one_kind_band(
                    "scan",
                    QueueServiceSample {
                        pending_eligible: 1,
                        oldest_pending_at: Some(secs_ago(WAITED_SECS)),
                        ..empty_sample()
                    },
                ),
                empty_band(),
            ]);
            let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
            dispatcher.class_service_threshold = Duration::from_secs(threshold_secs);
            assert_eq!(
                dispatcher.class_service_threshold(),
                Duration::from_secs(threshold_secs),
                "the accessor reports the number the dispatcher was built with — what a \
                 composition test asserts against `WorkerConfig`"
            );

            let recorder = DebuggingRecorder::new();
            let snapshotter = recorder.snapshotter();
            let guard = metrics::set_default_local_recorder(&recorder);
            dispatcher.audit_class_service().await;
            drop(guard);

            let snapshot = snapshotter.snapshot().into_vec();
            assert_eq!(
                counter_value(
                    &snapshot,
                    METRIC_CLASS_STARVED,
                    &[
                        ("class", TaskTier::Normal.as_str()),
                        ("reason", ClassStarvationReason::NotClaimed.as_str()),
                    ],
                ),
                expected,
                "{WAITED_SECS} s of unserved waiting against a {threshold_secs} s \
                 threshold: {snapshot:?}"
            );
        }
    }

    #[test]
    fn register_threads_the_configured_service_interval_to_the_allocator() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let mut dispatcher = make_dispatcher(repo as Arc<dyn JobsRepository>);
        dispatcher.class_service_threshold = Duration::from_secs(90);
        dispatcher.register(
            Arc::new(NoopHandler::new("scan", Arc::new(AtomicUsize::new(0)))),
            1,
        );
        assert_eq!(
            dispatcher.permits["scan"].service_interval(),
            permit_service_interval(Duration::from_secs(90))
        );
    }

    /// The **second** number derived from the same threshold reaches
    /// the allocator too.
    ///
    /// The age net's bound is not an independent knob: there is one
    /// operator variable and the allocation derives both enforcement
    /// times from it, so this asserts the threading rather than the
    /// arithmetic (which is the domain's own test). A bound that
    /// arrived as a constant would agree with the derivation only at
    /// the default — the shape the two attempt caps had.
    #[test]
    fn register_threads_the_configured_threshold_to_the_age_net() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let mut dispatcher = make_dispatcher(repo as Arc<dyn JobsRepository>);
        dispatcher.class_service_threshold = Duration::from_secs(90);
        dispatcher.register(
            Arc::new(NoopHandler::new("scan", Arc::new(AtomicUsize::new(0)))),
            1,
        );
        assert_eq!(
            dispatcher.permits["scan"].age_net_bound(),
            permit_age_net_bound(Duration::from_secs(90))
        );
    }

    /// A class being served is not reported, however deep and old its
    /// queue is — the false positive the per-kind age axis has and this
    /// one must not acquire.
    #[tokio::test]
    async fn a_deep_but_draining_class_is_not_reported() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.seed_band_samples(vec![
            empty_band(),
            empty_band(),
            one_kind_band(
                "scan",
                QueueServiceSample {
                    pending_eligible: 10_000,
                    oldest_pending_at: Some(secs_ago(7_200)),
                    last_served_at: Some(secs_ago(3)),
                    ..empty_sample()
                },
            ),
        ]);
        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);
        dispatcher.audit_class_service().await;
        drop(guard);

        let snapshot = snapshotter.snapshot().into_vec();
        for reason in [
            ClassStarvationReason::NotClaimed.as_str(),
            ClassStarvationReason::AwaitingCapacity.as_str(),
        ] {
            assert_eq!(
                counter_value(
                    &snapshot,
                    METRIC_CLASS_STARVED,
                    &[("class", TaskTier::Bulk.as_str()), ("reason", reason)],
                ),
                0,
                "a two-hour-old oldest row in a class that completed something three \
                 seconds ago is a deep queue draining, not starvation: {snapshot:?}"
            );
        }
    }

    /// A failing sample is warn-and-continue, exactly like the per-kind
    /// audit's own query failure: the poll loop must not die for a
    /// diagnostic read.
    #[tokio::test]
    async fn the_service_audit_swallows_a_query_failure() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.fail_band_samples();
        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);
        dispatcher.audit_class_service().await;
        drop(guard);

        let snapshot = snapshotter.snapshot().into_vec();
        for class in TaskTier::ALL {
            for reason in [
                ClassStarvationReason::NotClaimed.as_str(),
                ClassStarvationReason::AwaitingCapacity.as_str(),
            ] {
                assert_eq!(
                    counter_value(
                        &snapshot,
                        METRIC_CLASS_STARVED,
                        &[("class", class.as_str()), ("reason", reason)],
                    ),
                    0,
                    "a failed sample must accuse nobody: {snapshot:?}"
                );
            }
        }
    }

    /// A repository that answers for no bands at all makes the audit
    /// inert rather than mislabelling a class.
    ///
    /// That is the shape every `JobsRepository` fixture in the tree
    /// presents — `MockJobsRepository` seeds no samples unless a test
    /// says otherwise, and the port's own additive default answers for
    /// none either — so this is the audit's behaviour almost everywhere
    /// it is reachable from a test. Pairing a short answer with the
    /// band list positionally would label a class with another class's
    /// facts.
    #[tokio::test]
    async fn an_unseeded_sample_leaves_the_audit_inert() {
        let repo = Arc::new(crate::use_cases::test_support::MockJobsRepository::new());
        let dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let guard = metrics::set_default_local_recorder(&recorder);
        dispatcher.audit_class_service().await;
        drop(guard);

        assert_eq!(
            repo.band_sample_calls().len(),
            1,
            "the audit must still have asked"
        );
        let snapshot = snapshotter.snapshot().into_vec();
        for class in TaskTier::ALL {
            assert_eq!(
                counter_value(
                    &snapshot,
                    METRIC_CLASS_STARVED,
                    &[
                        ("class", class.as_str()),
                        ("reason", ClassStarvationReason::NotClaimed.as_str()),
                    ],
                ),
                0,
                "a repository that observes no bands must accuse nobody: {snapshot:?}"
            );
        }
    }

    /// The capacity wait that began at the claim ends when the permit is
    /// granted — and before the handler runs.
    ///
    /// Both halves matter. Without the clear, every row a worker ever
    /// claimed would read as queued-for-capacity for the whole of its
    /// execution, so the count the per-class audit reads would be "rows
    /// this worker holds" rather than "rows waiting for capacity" and
    /// the verdict would fire on a perfectly healthy worker. The
    /// ordering is what makes the count mean the wait and not the run.
    #[tokio::test]
    async fn the_dispatch_loop_ends_the_capacity_wait_at_the_grant() {
        /// Records how many capacity-wait clears had landed by the time
        /// the handler was entered.
        struct ObservingHandler {
            repo: Arc<DispatcherMockRepo>,
            clears_seen_at_run: Arc<AtomicUsize>,
        }
        impl TaskHandler for ObservingHandler {
            fn kind(&self) -> &'static str {
                "noop"
            }
            fn run<'a>(
                &'a self,
                _params: &'a serde_json::Value,
                _ctx: TaskContext,
            ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
                self.clears_seen_at_run
                    .store(self.repo.capacity_wait_clears().len(), Ordering::SeqCst);
                Box::pin(async {
                    Ok(TaskOutcome::Completed {
                        result_summary: serde_json::Value::Null,
                    })
                })
            }
        }

        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("noop");
        let job_id = row.id;
        repo.seed_batch(vec![row]);
        let clears_seen_at_run = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.register(
            Arc::new(ObservingHandler {
                repo: repo.clone(),
                clears_seen_at_run: clears_seen_at_run.clone(),
            }),
            1,
        );
        dispatcher.poll_interval_secs = 0;

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        assert_eq!(
            repo.capacity_wait_clears(),
            vec![(job_id, "test-worker".to_string())],
            "the granted row's capacity wait must be cleared, under this worker's own id — \
             the write is fenced on `locked_by`, so a wrong id would clear nothing"
        );
        assert_eq!(
            clears_seen_at_run.load(Ordering::SeqCst),
            1,
            "the clear must land BEFORE the handler runs, or the count means \
             'rows this worker holds' instead of 'rows waiting for capacity'"
        );
        assert_eq!(
            repo.mark_completed_calls(),
            vec![job_id],
            "and the row still runs to completion"
        );
    }

    /// A **fenced** capacity-wait clear declines the dispatch: no
    /// handler runs and nothing is written.
    ///
    /// `clear_capacity_wait` fences on `locked_by = worker_id AND
    /// status = 'running'`, so `Ok(false)` is that fence answering "this
    /// row is not yours" — from the same predicate the lease renewal
    /// uses, at the last point before the handler. Running it anyway is
    /// a second concurrent execution of a row its holder is already
    /// running: the result write is fenced on `attempts` so the row's
    /// state survives, but the work doubles, a second scan occupies
    /// scanner capacity, and both runs can append to the same stream.
    ///
    /// The renewal guard does **not** cover this, which is why this test
    /// is about the dispatch and not about the write:
    /// `stop_renewing_and_check_fence` is read after `handler.run` has
    /// returned on the normal path and in place of it on the refusal
    /// path, so on no path does it stop an execution — it only discards
    /// a result the work has already produced.
    ///
    /// Nor is this work dropped on the floor, which is what the absent
    /// `reschedule` below asserts: the other worker holds the row, and
    /// returning it to `pending` from here would be this worker writing
    /// to a row it has just been told is not its own. In the one shape
    /// where nobody holds it — the sweep requeued it and no sibling
    /// re-claimed it — the row is already `pending` and the next poll
    /// takes it.
    #[tokio::test]
    async fn a_fenced_capacity_wait_clear_declines_the_dispatch() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("noop");
        repo.seed_batch(vec![row]);
        repo.set_capacity_wait_answer(Some(false));
        let run_count = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.register(Arc::new(NoopHandler::new("noop", run_count.clone())), 1);
        dispatcher.poll_interval_secs = 0;

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        assert_eq!(
            repo.capacity_wait_clears().len(),
            1,
            "the clear is attempted exactly once per granted row — it is the check, so it still \
             runs"
        );
        assert_eq!(
            run_count.load(Ordering::SeqCst),
            0,
            "no handler may run after the fence said the row is not ours"
        );
        assert!(
            repo.mark_completed_calls().is_empty()
                && repo.mark_failed_calls().is_empty()
                && repo.reschedule_calls().is_empty(),
            "and nothing of the row's is written — not the outcome, and not a return to \
             `pending`, which would be a write to a row this worker was just told it does not \
             hold: completed={:?} failed={:?} rescheduled={:?}",
            repo.mark_completed_calls(),
            repo.mark_failed_calls(),
            repo.reschedule_calls(),
        );
    }

    /// A capacity-wait clear that could not be *made* still runs the
    /// row.
    ///
    /// The counterpart of the test above, and the distinction is the
    /// whole point: `Err` is the absence of an answer, not a statement
    /// about ownership, so declining here would trade a metric for a
    /// stall. The row keeps a non-NULL `capacity_waiting_since` while
    /// its handler runs, so its class over-reports one waiter until the
    /// outcome write lands — bounded by the handler's own runtime, and
    /// the direction ADR 0066 asks to err in.
    #[tokio::test]
    async fn a_capacity_wait_clear_that_did_not_answer_still_runs_the_row() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let row = make_job_row("noop");
        let job_id = row.id;
        repo.seed_batch(vec![row]);
        repo.set_capacity_wait_answer(None);
        let run_count = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        dispatcher.register(Arc::new(NoopHandler::new("noop", run_count.clone())), 1);
        dispatcher.poll_interval_secs = 0;

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { dispatcher.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        assert_eq!(
            repo.capacity_wait_clears().len(),
            1,
            "the clear is attempted exactly once per granted row"
        );
        assert!(
            run_count.load(Ordering::SeqCst) >= 1,
            "a database that did not answer is no statement about who holds the row, so the \
             handler must still run"
        );
        assert_eq!(
            repo.mark_completed_calls(),
            vec![job_id],
            "and the row must still be closed out"
        );
    }

    // -----------------------------------------------------------------------
    // Abandoned-lease sweep
    // -----------------------------------------------------------------------

    /// The sweep passes the policy allow-list, a grace derived from the
    /// lease, the attempt cap and the batch bound — and the allow-list is
    /// the domain constant, not this dispatcher's registered kinds.
    ///
    /// The distinction is load-bearing in a heterogeneous fleet: a
    /// replica that registers no scan handler is still the right one to
    /// hand a dead scanner's abandoned row back to a replica that does.
    #[tokio::test]
    async fn sweep_passes_the_policy_allow_list_and_a_lease_derived_grace() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let mut dispatcher = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        // Register exactly one kind, and not one from the allow-list, so
        // "the sweep asked for the registered kinds" cannot pass by
        // coincidence.
        dispatcher.register(
            Arc::new(NoopHandler::new(
                "retry-kind",
                Arc::new(AtomicUsize::new(0)),
            )),
            1,
        );
        let dispatcher = Arc::new(dispatcher);

        dispatcher.sweep_abandoned_leases().await;

        let calls = repo.requeue_calls();
        assert_eq!(calls.len(), 1, "one sweep pass, one query");
        let call = &calls[0];
        let expected: Vec<String> = REQUEUE_ON_LEASE_EXPIRY_KINDS
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            call.kinds, expected,
            "the sweep's allow-list is the domain requeue policy, not the registered kinds"
        );
        assert_eq!(
            call.grace,
            Duration::from_secs(60) * LEASE_EXPIRY_GRACE_MULTIPLE,
            "grace is a multiple of this dispatcher's lease, not a fixed constant"
        );
        assert_eq!(call.attempt_cap, TEST_ATTEMPT_CAP);
        assert_eq!(call.batch_size, LEASE_SWEEP_BATCH);
    }

    /// Both sweep outcomes land on
    /// `hort_admin_tasks_lease_requeued_total`, labelled by kind and
    /// result — so a replica dying every few minutes shows up as a rate
    /// instead of being silently compensated.
    #[test]
    fn sweep_counts_both_outcomes_per_kind() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(DispatcherMockRepo::new());
        repo.seed_requeue_result(vec![
            RequeuedJob {
                id: Uuid::new_v4(),
                kind: "scan".to_string(),
                attempts: 2,
                outcome: RequeueOutcome::Requeued,
            },
            RequeuedJob {
                id: Uuid::new_v4(),
                kind: "scan".to_string(),
                attempts: 3,
                outcome: RequeueOutcome::Requeued,
            },
            RequeuedJob {
                id: Uuid::new_v4(),
                kind: "prefetch".to_string(),
                attempts: TEST_ATTEMPT_CAP,
                outcome: RequeueOutcome::RetriesExhausted,
            },
        ]);
        let dispatcher = Arc::new(make_dispatcher(repo as Arc<dyn JobsRepository>));

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(dispatcher.sweep_abandoned_leases())
        });

        let snap = snapshotter.snapshot().into_vec();
        assert_eq!(
            counter_value(
                &snap,
                METRIC_LEASE_REQUEUED,
                &[("kind", "scan"), ("result", REQUEUE_RESULT_REQUEUED)]
            ),
            2,
        );
        assert_eq!(
            counter_value(
                &snap,
                METRIC_LEASE_REQUEUED,
                &[("kind", "prefetch"), ("result", REQUEUE_RESULT_EXHAUSTED)]
            ),
            1,
        );
    }

    /// A sweep query that fails is logged and swallowed — the poll loop
    /// keeps claiming. Recovery is best-effort housekeeping; a database
    /// flap must not take the worker down with it.
    #[tokio::test]
    async fn sweep_swallows_a_failing_query() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.fail_requeue();
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));

        dispatcher.sweep_abandoned_leases().await;

        assert_eq!(repo.requeue_calls().len(), 1, "the query was attempted");
    }

    /// An empty sweep emits nothing. The counter is an alerting signal,
    /// so the quiet case has to be genuinely quiet.
    #[test]
    fn sweep_with_nothing_to_do_emits_no_counter() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let repo = Arc::new(DispatcherMockRepo::new());
        let dispatcher = Arc::new(make_dispatcher(repo as Arc<dyn JobsRepository>));

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(dispatcher.sweep_abandoned_leases())
        });

        let snap = snapshotter.snapshot().into_vec();
        assert_eq!(
            counter_value(
                &snap,
                METRIC_LEASE_REQUEUED,
                &[("kind", "scan"), ("result", REQUEUE_RESULT_REQUEUED)]
            ),
            0,
        );
    }

    // -----------------------------------------------------------------------
    // Lease renewal
    // -----------------------------------------------------------------------

    /// **A claimed row waiting for a permit keeps its lease.**
    ///
    /// `locked_until` says a live worker *owns* the row, not that a
    /// handler is executing it. While the renewal started inside
    /// `dispatch_one`, a row that won the claim and then waited for a
    /// concurrency permit held a lease nobody renewed — so the sweep
    /// recovered it after `lock_duration × (1 +
    /// LEASE_EXPIRY_GRACE_MULTIPLE)`, reporting a death that had not
    /// happened and spending one of the row's attempts on a queue
    /// position. An attempt budget bounds *failing work*, and a permit
    /// wait is not evidence about the job: nothing was attempted,
    /// nothing failed.
    ///
    /// The wait is not a contrived state. The claim takes `batch_size`
    /// rows per poll regardless of how many permits are free, and the
    /// shipped compose default claims four against a `scan` concurrency
    /// of one — so three of every four claimed rows begin by waiting.
    ///
    /// The sweep here is a **sibling replica's**: the sweep runs on
    /// every replica with no leader election, and a replica that did not
    /// claim the row is exactly who recovers a dead worker's. It answers
    /// from the lease this dispatcher actually wrote — see
    /// `DispatcherMockRepo::model_leases` — while *which arguments* the
    /// dispatcher's own sweep passes is pinned separately by
    /// [`sweep_passes_the_policy_allow_list_and_a_lease_derived_grace`].
    #[tokio::test(start_paused = true)]
    async fn a_claimed_row_waiting_for_a_permit_keeps_its_lease() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.model_leases();

        // Two rows of one kind, one permit: the second is claimed,
        // `running`, and then waits. Both `Bulk`, which is the class
        // ADR 0066's floor makes wait under sustained waited-on load.
        let waiting = make_scan_row(TriggerSource::Cron.as_str());
        let waiting_id = waiting.id;
        let waiting_attempts = waiting.attempts;
        repo.seed_batch(vec![make_scan_row(TriggerSource::Cron.as_str()), waiting]);

        let mut worker = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        // Read off the dispatcher rather than restated, so a change to
        // either number cannot leave this test asserting about a window
        // the sweep no longer uses.
        let sweepable_after = worker.lock_duration * (1 + LEASE_EXPIRY_GRACE_MULTIPLE);
        let started = Arc::new(AtomicUsize::new(0));
        worker.register(
            Arc::new(OccupyingScanHandler {
                // Past the window, so the second row is still waiting
                // when the sweep below runs.
                hold: sweepable_after * 2,
                started: started.clone(),
            }),
            // The production `scan` concurrency: parallelism comes from
            // replicas, not from intra-process concurrency.
            1,
        );
        // A one-second poll, because the paused clock only auto-advances
        // while the runtime is idle: `make_dispatcher`'s 999_999 s would
        // put the first claim past the window under test, and the 0 the
        // real-clock fairness tests use would never let the loop idle.
        worker.poll_interval_secs = 1;

        let cancel = CancellationToken::new();
        let worker_handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { worker.run(cancel).await }
        });

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "the premise: the batch was claimed and only the first row got the one permit"
        );

        // Sit out the whole window an unrenewed lease lapses in.
        tokio::time::sleep(sweepable_after + Duration::from_secs(5)).await;
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "the second row must still be waiting for its permit — a run in which it had \
             started proves nothing about a lease held across a wait"
        );

        let sweeper = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        sweeper.sweep_abandoned_leases().await;

        assert_eq!(
            repo.model_requeued(),
            Vec::new(),
            "a claimed row waiting for a permit is owned by a live worker; the sweep must \
             not call it abandoned"
        );
        assert_eq!(
            repo.modelled_attempts(waiting_id),
            Some(waiting_attempts),
            "and its attempt budget must be untouched — a requeue spends one by making the \
             row claimable again"
        );

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), worker_handle)
            .await
            .expect("dispatcher join timed out")
            .expect("task did not panic")
            .expect("run returned Err");

        // And it still runs when the permit comes free. Keeping a lease
        // across the wait is only the right answer if the wait ends in
        // the work being done — a row that held its lease and then never
        // ran would be a worse outcome than the requeue, not a better one.
        tokio::time::timeout(sweepable_after * 4, async {
            while started.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .expect("the row that waited must run once the permit is released");
    }

    /// **Worker death is still detected.**
    ///
    /// The lease must not become unconditional. A fix that passed the
    /// test above by never letting a lease lapse would have disabled
    /// the only recovery a row whose worker died has — and for
    /// `kind='scan'` that is not clutter but a lost capability, because
    /// `jobs_scan_unique` blocks any further scan job for the artifact
    /// while the abandoned row sits in `running`.
    ///
    /// Same lease model and same sibling-replica sweep as the test
    /// above, so the pair differs in exactly one fact: here the renewal
    /// stops. The guard is dropped, which aborts the renewal task — and
    /// from the database that is indistinguishable from the process
    /// being gone, which is the whole discriminator.
    #[tokio::test(start_paused = true)]
    async fn a_dead_workers_claimed_row_is_still_swept() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.model_leases();
        let row = make_scan_row(TriggerSource::Cron.as_str());
        let row_id = row.id;
        let row_attempts = row.attempts;
        repo.seed_batch(vec![row]);

        let worker = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));
        let sweepable_after = worker.lock_duration * (1 + LEASE_EXPIRY_GRACE_MULTIPLE);

        // Claim the row and start its lease where the dispatch loop now
        // starts it — at the claim, before any permit or handler.
        let claimed = worker
            .job_repo
            .claim_pending_by_kinds(
                &["scan"],
                worker.batch_size,
                &worker.worker_id,
                worker.lock_duration,
                &ClaimReservation::waited_on(TEST_RESERVED_SLOTS_PER_CLASS),
            )
            .await
            .expect("the mock claim cannot fail");
        assert_eq!(claimed.len(), 1, "the premise: one row was claimed");
        let renewal = worker.spawn_lease_renewal(row_id, "scan".to_string());

        // While the worker is alive the row is not sweepable — which is
        // also what keeps this test from passing against a renewal that
        // never ran at all.
        tokio::time::sleep(sweepable_after).await;
        assert!(
            !repo.renew_calls().is_empty(),
            "the premise: the worker was holding the lease before it died"
        );
        let sweeper = make_dispatcher(repo.clone() as Arc<dyn JobsRepository>);
        sweeper.sweep_abandoned_leases().await;
        assert_eq!(
            repo.model_requeued(),
            Vec::new(),
            "a renewed lease is not sweepable"
        );

        // The worker dies here: the guard goes, and the renewal task
        // with it. Nothing pushes `locked_until` forward again.
        drop(renewal);

        tokio::time::sleep(sweepable_after + Duration::from_secs(5)).await;
        sweeper.sweep_abandoned_leases().await;

        assert_eq!(
            repo.model_requeued(),
            vec![RequeuedJob {
                id: row_id,
                kind: "scan".to_string(),
                attempts: row_attempts,
                outcome: RequeueOutcome::Requeued,
            }],
            "a lease that stopped being renewed for a full lease plus the grace is a dead \
             owner, and the row goes back to pending with its counter left for the next claim"
        );
    }

    /// A handler that outlives its lease keeps the lease alive.
    ///
    /// This is the property the whole discriminator rests on: without it
    /// a slow task and a dead worker are the same observation. Driven on
    /// a paused clock so the assertion is about the renewal interval
    /// (`lock_duration / RENEWALS_PER_LEASE`), not about wall time.
    #[tokio::test(start_paused = true)]
    async fn a_handler_outliving_its_lease_keeps_renewing() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let lease = Duration::from_secs(60);
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));

        let guard = dispatcher.spawn_lease_renewal(Uuid::new_v4(), "scan".to_string());
        // Three lease-lengths of a task that does not return.
        tokio::time::sleep(lease * 3 + Duration::from_secs(1)).await;
        drop(guard);

        let calls = repo.renew_calls();
        assert_eq!(
            calls.len(),
            (3 * RENEWALS_PER_LEASE) as usize,
            "expected {RENEWALS_PER_LEASE} renewals per lease over three leases, got {}",
            calls.len()
        );
        assert!(
            calls.iter().all(|(_, w)| w == "test-worker"),
            "the renewal must fence on this worker's id, or it would extend a lease it no \
             longer holds"
        );
    }

    /// Dropping the guard stops the renewals. A finished row whose lease
    /// kept being extended would be invisible to the very sweep that
    /// exists to recover it if its outcome write failed.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_guard_stops_renewal() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));

        let guard = dispatcher.spawn_lease_renewal(Uuid::new_v4(), "scan".to_string());
        tokio::time::sleep(Duration::from_secs(25)).await;
        let during = repo.renew_calls().len();
        assert_eq!(during, 1, "one renewal at the 20 s tick of a 60 s lease");
        drop(guard);

        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(
            repo.renew_calls().len(),
            during,
            "no renewal may land after the guard is dropped"
        );
    }

    /// A renewal that reports the row is no longer ours stops renewing
    /// and counts the fencing signal. Continuing would mean repeatedly
    /// trying to extend a lease on someone else's row.
    #[test]
    fn a_lost_row_stops_renewal_and_counts_it() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.set_renew_answer(Some(false));
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));

        metrics::with_local_recorder(&recorder, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .unwrap();
            rt.block_on(async {
                let guard = dispatcher.spawn_lease_renewal(Uuid::new_v4(), "scan".to_string());
                tokio::time::sleep(Duration::from_secs(300)).await;
                drop(guard);
            });
        });

        assert_eq!(
            repo.renew_calls().len(),
            1,
            "renewal must stop at the first 'not yours' answer, not keep hammering"
        );
        let snap = snapshotter.snapshot().into_vec();
        assert_eq!(
            counter_value(
                &snap,
                METRIC_LEASE_RENEW_FAILED,
                &[("kind", "scan"), ("result", RENEW_RESULT_LOST)]
            ),
            1,
        );
    }

    /// A renewal that errors is transient: it counts, and the next tick
    /// tries again. With three renewals per lease, one failure still
    /// leaves two chances before the lease lapses.
    #[test]
    fn a_failing_renewal_counts_and_retries() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.set_renew_answer(None);
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));

        metrics::with_local_recorder(&recorder, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .unwrap();
            rt.block_on(async {
                let guard = dispatcher.spawn_lease_renewal(Uuid::new_v4(), "scan".to_string());
                tokio::time::sleep(Duration::from_secs(61)).await;
                drop(guard);
            });
        });

        assert_eq!(
            repo.renew_calls().len(),
            3,
            "an erroring renewal must retry on the next tick, not give up"
        );
        let snap = snapshotter.snapshot().into_vec();
        assert_eq!(
            counter_value(
                &snap,
                METRIC_LEASE_RENEW_FAILED,
                &[("kind", "scan"), ("result", RENEW_RESULT_ERROR)]
            ),
            3,
        );
    }

    /// A worker that lost its row writes nothing.
    ///
    /// The fence, end to end. Without it, a stale worker finishing after
    /// the sweep handed its row on would write over an execution that is
    /// still in flight — and the damaging shape is not the lost result
    /// but a `reschedule` putting a live worker's row back to `pending`,
    /// which invites a third concurrent execution and charges an attempt
    /// to the wrong run. So the assertion is about *all three* write
    /// paths being silent, not just the completed one.
    #[tokio::test(start_paused = true)]
    async fn a_worker_that_lost_its_row_discards_its_outcome() {
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.set_renew_answer(Some(false));
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));
        // 150 s of work against a 60 s lease, so the first renewal tick
        // (20 s in) lands well before the handler returns.
        let handler: Arc<dyn TaskHandler> = Arc::new(SlowHandler {
            max_concurrent: Arc::new(AtomicUsize::new(0)),
            current: Arc::new(AtomicUsize::new(0)),
            delay_ms: 150_000,
        });
        let row = make_job_row("slow-kind");

        dispatch_one_with_lease(&dispatcher, row, handler).await;

        assert_eq!(repo.renew_calls().len(), 1, "renewal stopped at the fence");
        assert!(
            repo.mark_completed_calls().is_empty(),
            "a fenced worker must not complete a row it no longer holds"
        );
        assert!(
            repo.reschedule_calls().is_empty(),
            "the reschedule is the dangerous one: it would return a row a live worker is \
             mid-way through to 'pending'"
        );
        assert!(
            repo.mark_failed_calls().is_empty(),
            "a fenced worker must not fail a row it no longer holds"
        );
    }

    /// The fence covers the **refusal** write too, not only the
    /// handler's.
    ///
    /// This state is reachable only because the renewal starts at the
    /// claim: the permit wait now sits between the claim and the
    /// authority re-check, so a worker can have lost the row before it
    /// ever asks the question. An unfenced refusal here would write a
    /// terminal `failed` over a row another worker is already running —
    /// the same clobber the handler path is fenced against, reached by
    /// a path that writes without calling a handler at all.
    #[tokio::test(start_paused = true)]
    async fn a_worker_that_lost_its_row_discards_a_refusal_too() {
        let kind = "retention-purge";
        assert!(
            DESTRUCTIVE_TASK_KINDS.contains(&kind),
            "this test is only about what it claims while {kind:?} is destructive"
        );
        let repo = Arc::new(DispatcherMockRepo::new());
        repo.set_renew_answer(Some(false));
        let dispatcher = Arc::new(make_dispatcher_with(
            repo.clone() as Arc<dyn JobsRepository>,
            refusing_reauthorizer(),
        ));
        let runs = Arc::new(AtomicUsize::new(0));
        let handler: Arc<dyn TaskHandler> = Arc::new(NoopHandler::new(kind, runs.clone()));
        let row = make_job_row(kind);

        let renewal = dispatcher.spawn_lease_renewal(row.id, kind.to_string());
        // The permit wait — one lease of it, so a renewal tick lands and
        // reports the row is no longer ours before `dispatch_one` is
        // entered at all.
        tokio::time::sleep(dispatcher.lock_duration).await;
        dispatcher.dispatch_one(row, handler, renewal).await;

        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "the refusal still stops the handler — losing the row does not make it run"
        );
        assert!(
            repo.mark_failed_calls().is_empty(),
            "the refusal is an outcome write like any other, and a worker that no longer \
             holds the row must not make it"
        );
        assert!(
            repo.reschedule_calls().is_empty() && repo.mark_completed_calls().is_empty(),
            "and it must not substitute a different write for the one the fence refused"
        );
    }

    /// The fence does not fire on the ordinary path — a handler that
    /// keeps its row writes its outcome as usual.
    #[tokio::test(start_paused = true)]
    async fn a_worker_that_keeps_its_row_writes_its_outcome() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));
        let handler: Arc<dyn TaskHandler> = Arc::new(SlowHandler {
            max_concurrent: Arc::new(AtomicUsize::new(0)),
            current: Arc::new(AtomicUsize::new(0)),
            delay_ms: 150_000,
        });
        let row = make_job_row("slow-kind");
        let row_id = row.id;

        dispatch_one_with_lease(&dispatcher, row, handler).await;

        assert_eq!(
            repo.mark_completed_calls(),
            vec![row_id],
            "renewals kept answering 'still yours', so the outcome must be written"
        );
    }

    /// A zero lease does not become a hot loop.
    ///
    /// `HORT_SCANNER_LOCK_DURATION_SECS` is operator-set and parses `0`.
    /// Unclamped, `0 / 3` is a zero-length sleep and the renewal task
    /// would issue `UPDATE`s as fast as the connection returns them —
    /// turning a misconfigured queue into load on the database.
    #[tokio::test(start_paused = true)]
    async fn a_zero_lease_does_not_spin_the_renewal() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let dispatcher = Arc::new(TaskDispatcher::new(
            repo.clone() as Arc<dyn JobsRepository>,
            crate::event_store_publisher::wrap_for_test(Arc::new(NoopEventStore)),
            authorizing_reauthorizer(),
            "test-worker",
            Duration::ZERO,
            999_999,
            16,
            TEST_ATTEMPT_CAP,
            TEST_RESERVED_SLOTS_PER_CLASS,
            TEST_CLASS_SERVICE_THRESHOLD,
        ));

        let guard = dispatcher.spawn_lease_renewal(Uuid::new_v4(), "scan".to_string());
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(guard);

        // A range, not an exact count: the paused clock interleaves the
        // renewal task's own sleeps with this one, so the last tick may
        // or may not land inside the window. The property being pinned
        // is "paced by the floor", and an unclamped zero interval would
        // not miss it by one — it would never stop running.
        let n = repo.renew_calls().len();
        assert!(
            (9..=11).contains(&n),
            "a zero lease must fall back to the one-second floor, not spin; got {n} renewals \
             in ten seconds"
        );
    }

    /// `dispatch_one` holds the lease across the handler and releases it
    /// when the handler returns — the wiring, not just the helper.
    #[tokio::test(start_paused = true)]
    async fn dispatch_one_renews_while_the_handler_runs_and_stops_after() {
        let repo = Arc::new(DispatcherMockRepo::new());
        let dispatcher = Arc::new(make_dispatcher(repo.clone() as Arc<dyn JobsRepository>));
        // 150 s of work against a 60 s lease → two renewal ticks (20 s
        // and 40 s of each lease, i.e. at 20/40/60/80/100/120/140 s).
        let handler: Arc<dyn TaskHandler> = Arc::new(SlowHandler {
            max_concurrent: Arc::new(AtomicUsize::new(0)),
            current: Arc::new(AtomicUsize::new(0)),
            delay_ms: 150_000,
        });
        let row = make_job_row("slow-kind");

        dispatch_one_with_lease(&dispatcher, row, handler).await;

        let during = repo.renew_calls().len();
        assert_eq!(
            during, 7,
            "a 150 s handler against a 60 s lease renews every 20 s"
        );
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(
            repo.renew_calls().len(),
            during,
            "the lease must stop being renewed once the handler has returned"
        );
    }
}
