//! Multi-kind task dispatcher.
//!
//! [`TaskDispatcher`] is the generalised worker poll loop. It claims batches
//! of pending `jobs` rows across all registered handler kinds in a single
//! `claim_pending_by_kinds` query, dispatches each row to the matching
//! [`TaskHandler`] implementation, and persists the returned [`TaskOutcome`]
//! to the jobs table via `mark_completed` / `reschedule` / `mark_failed`.
//!
//! Per-kind [`tokio::sync::Semaphore`]s enforce concurrency limits set at
//! registration time. Graceful shutdown is driven by a
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
//! # Metrics emitted
//!
//! See metrics-catalog.md (`hort_admin_tasks_*`):
//!
//! - `hort_admin_tasks_enqueued_total{kind}` — currently unused by the
//!   dispatcher itself; enqueued events are emitted by the HTTP handler.
//!   Documented here for completeness.
//! - `hort_admin_tasks_completed_total{kind, result}` — one increment per
//!   `record_outcome_for_row` call. `result ∈ {completed, failed_retry,
//!   failed_terminal}`. A retryable failure on a row that has spent its
//!   [`JOB_ATTEMPT_CAP`] budget counts as `failed_terminal`, because
//!   that is what the dispatcher did to the row.
//! - `hort_admin_tasks_duration_seconds{kind}` — elapsed time from claim to
//!   `record_outcome_for_row`, wrapping `TaskHandler::run`.
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

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use hort_domain::events::{Actor, InternalActor};
use hort_domain::ports::jobs_repository::{
    JobRow, JobsRepository, PendingKindBacklog, RequeueOutcome, REQUEUE_ON_LEASE_EXPIRY_KINDS,
};
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};

use crate::destructive_task_reauthorization::{
    DestructiveTaskReauthorizer, ReauthorizationVerdict,
};
use crate::error::AppResult;
use crate::event_store_publisher::EventStorePublisher;
use crate::result_write_fence::surface_attempted_result_write;
use crate::retry_backoff::compute_backoff;

// ---------------------------------------------------------------------------
// Metric name constants
// ---------------------------------------------------------------------------

const METRIC_COMPLETED: &str = "hort_admin_tasks_completed_total";
const METRIC_DURATION: &str = "hort_admin_tasks_duration_seconds";
const METRIC_IN_FLIGHT: &str = "hort_admin_tasks_in_flight";
const METRIC_PENDING_ELIGIBLE: &str = "hort_admin_tasks_pending_eligible";
const METRIC_STARVED: &str = "hort_admin_tasks_starved_total";
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

/// `attempts` at which a failing `jobs` row stops being re-driven and
/// becomes the terminal, operator-visible `failed` row ADR 0028
/// describes.
///
/// A row reaches the cap one of two ways, and the same number bounds
/// both — one behaviour, two triggers:
///
/// - **The handler returned a failure** — `TaskOutcome::Failed { retry:
///   true }`, or an `Err` recorded as one. `record_outcome_for_row`
///   reschedules while `attempts` is below the cap and calls
///   `mark_failed` at it. [`compute_backoff`] bounds how long a row
///   *waits* and bounds nothing else, so without this cap a job that
///   fails the same way every time would be re-driven for as long as it
///   kept failing, and would never become a `failed` row at all.
/// - **The handler never returned** — its worker died holding the
///   claim, and `sweep_abandoned_leases` is the only code that runs for
///   such a row. It passes this cap to `requeue_abandoned`, whose
///   `CASE` requeues below the cap and fails the row at it.
///
/// Both paths spend the same budget because a requeue and a reschedule
/// both cost exactly one attempt: neither touches the counter, and the
/// next claim increments it.
///
/// **Uniform across kinds, deliberately.**
/// [`REQUEUE_ON_LEASE_EXPIRY_KINDS`] answers a different question —
/// which kinds tolerate a *concurrent* second execution after a crash,
/// where the duplicate is absorbed by nothing. A returned failure has
/// no in-flight duplicate to fear, precisely because the handler
/// returned, so carrying that allow-list over would answer the wrong
/// question and build an exemption table nobody could audit.
///
/// Set to the scan pipeline's own default (`HORT_SCANNER_MAX_ATTEMPTS`,
/// 5) so a scan row hits one budget rather than two disagreeing ones:
/// the scan orchestrator's `attempts >= max_attempts` branch in
/// `record_outcome` and this cap are the same number on purpose.
///
/// **A number of attempts is only half of a budget**; the other half is
/// the window they span, which is [`compute_backoff`]'s to set. Five
/// executions spend that curve's first four waits — 96 minutes from the
/// first failure to this cap — and both halves had to agree before the
/// cap could mean "persistently broken": while the dispatcher kept its
/// own 30-s-doubling curve, the same five attempts were spent inside
/// 7 m 30 s, so a transient outage slightly longer than a coffee break
/// produced the same permanent `failed` row as a genuinely broken
/// dependency.
const JOB_ATTEMPT_CAP: u32 = 5;

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
    /// Per-kind semaphore enforcing `max_concurrency`.
    semaphores: HashMap<&'static str, Arc<Semaphore>>,
    job_repo: Arc<dyn JobsRepository>,
    /// `EventStore` is held for future use (e.g. emitting `TaskInvoked`
    /// audit events). Currently unused by the dispatcher
    /// itself — scan-kind outcome events are emitted inside
    /// `ScanTaskHandler::run` via `ScanOrchestrationUseCase::record_outcome`.
    #[allow(dead_code)]
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
}

impl TaskDispatcher {
    /// Construct a dispatcher without any registered handlers.
    ///
    /// Call [`register`](Self::register) for each handler kind before
    /// calling [`run`](Self::run).
    pub fn new(
        job_repo: Arc<dyn JobsRepository>,
        event_store: Arc<EventStorePublisher>,
        reauthorizer: Arc<DestructiveTaskReauthorizer>,
        worker_id: impl Into<String>,
        lock_duration: Duration,
        poll_interval_secs: u64,
        batch_size: u16,
    ) -> Self {
        Self {
            handlers: HashMap::new(),
            semaphores: HashMap::new(),
            job_repo,
            event_store,
            reauthorizer,
            worker_id: worker_id.into(),
            lock_duration,
            poll_interval_secs,
            batch_size,
        }
    }

    /// Register a handler for its `kind()` with a per-kind concurrency cap.
    ///
    /// `max_concurrency` is the maximum number of concurrent invocations of
    /// this handler. A value of `1` serialises all executions of this kind.
    ///
    /// Panics if the same kind is registered twice (programming error).
    #[tracing::instrument(skip(self, handler))]
    pub fn register(&mut self, handler: Arc<dyn TaskHandler>, max_concurrency: usize) {
        let kind = handler.kind();
        assert!(
            !self.handlers.contains_key(kind),
            "TaskDispatcher: kind '{kind}' registered twice"
        );
        let concurrency = max_concurrency.max(1);
        self.handlers.insert(kind, handler);
        self.semaphores
            .insert(kind, Arc::new(Semaphore::new(concurrency)));
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
    ///    gated by the kind's semaphore and — for the destructive
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
                let Some(semaphore) = dispatcher.semaphores.get(kind_str.as_str()).cloned() else {
                    // Invariant: semaphore always co-exists with handler.
                    tracing::error!(kind = %kind_str, "TaskDispatcher: no semaphore for kind");
                    dispatcher
                        .return_to_pending(&job, "no semaphore registered for kind")
                        .await;
                    continue;
                };
                let dispatcher_clone = dispatcher.clone();
                tokio::spawn(async move {
                    // Acquire concurrency permit before calling the handler.
                    let _permit = semaphore
                        .acquire()
                        .await
                        .expect("semaphore never closed during run");

                    dispatcher_clone.dispatch_one(job, handler).await;
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

    /// Abandoned-lease sweep — the recovery path for a row whose worker
    /// died holding the claim.
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
                JOB_ATTEMPT_CAP,
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
    /// This is the half of the design that gives the sweep's
    /// discriminator a meaning. The spawned task extends `locked_until`
    /// every `lock_duration / RENEWALS_PER_LEASE`; dropping the guard
    /// aborts it. Placing it here rather than in the handlers is what
    /// makes the mechanism total: `dispatch_one` is the single point
    /// through which every registered kind runs, and
    /// `claim_pending_by_kinds` is the only claim statement with a
    /// production caller, so one call site covers the whole kind
    /// vocabulary and every kind added later.
    ///
    /// A renewal that reports the row is no longer ours raises the
    /// guard's `lost` flag, and [`Self::dispatch_one`] reads it before
    /// writing the outcome. That makes the flag a **fencing token**, not
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

    /// Invoke the handler for a single job row and record the outcome.
    async fn dispatch_one(self: &Arc<Self>, job: JobRow, handler: Arc<dyn TaskHandler>) {
        let kind = handler.kind();

        let params = job.params.clone().unwrap_or(serde_json::Value::Null);

        // Authority must still hold when the job executes; acceptance
        // does not confer it. This runs before the in-flight gauge, the
        // duration timer and the lease renewal because none of them
        // describe a refusal: a row whose handler was never called did
        // not take time in that handler, and counting it would put a
        // two-read authority check into the kind's execution-latency
        // distribution.
        if let Some(outcome) = self
            .refuse_unauthorized_execution(&job, kind, &params)
            .await
        {
            self.record_outcome_for_row(&job, kind, outcome).await;
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

        // Hold the lease for the whole of `run`, and stop holding it the
        // instant `run` returns — the outcome write below is what closes
        // the row out, and a renewal landing after it would be writing a
        // lease onto a row that is no longer running.
        let renewal = self.spawn_lease_renewal(job.id, kind.to_string());

        let started = Instant::now();
        let outcome = handler.run(&params, ctx).await;
        let elapsed = started.elapsed();

        let lost_the_row = renewal.lost_the_row();
        drop(renewal);

        // Emit in-flight gauge -1.
        metrics::gauge!(METRIC_IN_FLIGHT, "kind" => kind.to_string()).decrement(1.0);

        // Observe duration.
        metrics::histogram!(METRIC_DURATION, "kind" => kind.to_string())
            .record(elapsed.as_secs_f64());

        if lost_the_row {
            // The fence. Writing here would overwrite a row that is now
            // someone else's — and the worst shape is not a lost result
            // but a `reschedule` returning a row a live worker is
            // mid-way through to `pending`, which invites a third
            // concurrent execution and charges an attempt to the wrong
            // run. The row's state is whatever its current holder makes
            // it; this execution's only correct move is to stop.
            tracing::error!(
                job_id = %job.id,
                kind,
                "TaskDispatcher: discarding this handler's outcome — the row was handed to \
                 another worker while the handler ran, so writing the outcome would clobber \
                 an execution that is still in flight",
            );
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
    /// budget left and refused at [`JOB_ATTEMPT_CAP`], where the row
    /// becomes terminal instead. See that constant for why the budget
    /// is one number across both the returned-failure and the
    /// dead-worker path, and uniform across kinds.
    ///
    /// Decision on the "double record_outcome" problem for `kind="scan"`:
    ///
    /// `ScanTaskHandler::run` calls `ScanOrchestrationUseCase::record_outcome`
    /// internally and then returns `TaskOutcome::Completed`. This dispatcher
    /// then also calls `mark_completed`. The second `mark_completed` is an
    /// idempotent SQL UPDATE (sets an already-completed row to completed again)
    /// — harmless and simpler than adding a guard. The scan path is the only
    /// case where the handler owns the row-state transition, and the cost is
    /// one extra DB round-trip per scan job. This is acceptable for v1.
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
                if retry && job.attempts < JOB_ATTEMPT_CAP {
                    let backoff = compute_backoff(job.attempts);
                    let written = self
                        .job_repo
                        .reschedule(job.id, job.attempts, backoff, &reason)
                        .await;
                    surface_attempted_result_write(
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
                            attempt_cap = JOB_ATTEMPT_CAP,
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
                    surface_attempted_result_write(
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
                }
            }
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
    use hort_domain::events::DESTRUCTIVE_TASK_KINDS;
    use hort_domain::ports::jobs_repository::{
        JobRow, JobStatus, JobsRepository, RequeuedJob, ResultWriteOutcome, ScanJob,
    };
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::destructive_task_reauthorization::{REFUSAL_PREFIX, UNAVAILABLE_PREFIX};
    use crate::use_cases::test_support::{
        MockPermissionGrantRepository, MockUserRepository, ResultWriteLog,
    };

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

    /// A still-authorized requester for [`FIXTURE_REQUESTER`].
    ///
    /// Admin, because `users.is_admin` is the only destructive authority
    /// the registry persists — see
    /// [`crate::destructive_task_reauthorization`].
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

    /// A reauthorizer that authorizes [`FIXTURE_REQUESTER`] — the
    /// default for every test that is not about the re-check itself.
    fn authorizing_reauthorizer() -> Arc<DestructiveTaskReauthorizer> {
        let users = Arc::new(MockUserRepository::new());
        users.insert(fixture_admin());
        Arc::new(DestructiveTaskReauthorizer::new(
            users,
            Arc::new(MockPermissionGrantRepository::new()),
        ))
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
        /// The fence every result write arrived with, and what they
        /// answer. See [`ResultWriteLog`].
        write_log: ResultWriteLog,
    }

    impl DispatcherMockRepo {
        fn new() -> Self {
            Self {
                claim_batches: Mutex::new(Vec::new()),
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
                write_log: ResultWriteLog::default(),
            }
        }

        fn seed_batch(&self, rows: Vec<JobRow>) {
            self.claim_batches.lock().unwrap().push(rows);
        }

        fn seed_backlog(&self, rows: Vec<PendingKindBacklog>) {
            *self.backlog.lock().unwrap() = rows;
        }

        fn fail_backlog(&self) {
            *self.backlog_fails.lock().unwrap() = true;
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
    }

    impl JobsRepository for DispatcherMockRepo {
        fn renew_lease<'a>(
            &'a self,
            job_id: Uuid,
            worker_id: &'a str,
            _lock_duration: Duration,
        ) -> BoxFuture<'a, DomainResult<bool>> {
            self.renew_calls
                .lock()
                .unwrap()
                .push((job_id, worker_id.to_string()));
            let answer = *self.renew_answer.lock().unwrap();
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
            let rows = self.requeue_result.lock().unwrap().clone();
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
            _lock_duration: Duration,
        ) -> BoxFuture<'a, DomainResult<Vec<JobRow>>> {
            let batch = {
                let mut q = self.claim_batches.lock().unwrap();
                if q.is_empty() {
                    Vec::new()
                } else {
                    q.remove(0)
                }
            };
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

    /// A slow handler that holds a semaphore long enough to observe concurrency.
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
        TaskDispatcher::new(
            repo,
            crate::event_store_publisher::wrap_for_test(Arc::new(NoopEventStore)),
            reauthorizer,
            "test-worker",
            Duration::from_secs(60),
            999_999, // very long poll interval — we drive ticks manually via seeded batches
            16,
        )
    }

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
                .block_on(dispatcher.dispatch_one(row, handler))
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

    /// Below the cap a retryable failure is still rescheduled, waiting
    /// the shared curve's last and longest interval.
    ///
    /// The boundary is `attempts < JOB_ATTEMPT_CAP`, so the last
    /// attempt below the cap keeps its retry — a cap that fired one
    /// attempt early would turn a transient failure into a dead row,
    /// which is the opposite of the point. (The first failure,
    /// `attempts == 1`, is covered by
    /// `dispatcher_records_outcome_failed_retry`.)
    #[test]
    fn a_returned_retryable_failure_below_the_attempt_cap_is_rescheduled() {
        let below_cap = JOB_ATTEMPT_CAP - 1;
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
            JOB_ATTEMPT_CAP,
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
            JOB_ATTEMPT_CAP + 3,
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
            JOB_ATTEMPT_CAP,
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
                JOB_ATTEMPT_CAP - 1,
                Arc::new(RetryHandler("retry-kind")),
            ),
            (
                "mark_failed",
                "retry-kind",
                JOB_ATTEMPT_CAP,
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
            .block_on(dispatcher.dispatch_one(row, Arc::new(NoopHandler::new("noop", runs))));

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
            dispatch_one_row(kind, JOB_ATTEMPT_CAP, Arc::new(RetryHandler(kind)));

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
                .block_on(Arc::new(dispatcher).dispatch_one(row, handler))
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
                .block_on(Arc::new(dispatcher).dispatch_one(row, handler))
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
                .block_on(Arc::new(dispatcher).dispatch_one(row, handler))
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
    /// retry delay for an hour and a half before it goes `failed`.
    ///
    /// This is also what pins the neighbouring cap tests to the *fifth*
    /// execution: they are written against `JOB_ATTEMPT_CAP` and would
    /// pass at any value of it, so the number itself is asserted here.
    /// Raise the cap or reshape the curve and this fails, which is the
    /// point — an exhausted budget means "persistently broken" only
    /// while the window is long enough for that to be the likelier
    /// reading.
    #[test]
    fn five_executions_span_the_ninety_six_minute_window() {
        assert_eq!(
            JOB_ATTEMPT_CAP, 5,
            "the window asserted below is the one five executions span"
        );

        let spent: Vec<u64> = (1..JOB_ATTEMPT_CAP)
            .map(|attempts| compute_backoff(attempts).as_secs())
            .collect();
        assert_eq!(
            spent,
            vec![60, 5 * 60, 30 * 60, 60 * 60],
            "the four waits a five-execution budget actually spends"
        );
        assert_eq!(
            spent.iter().sum::<u64>(),
            96 * 60,
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
        assert_eq!(call.attempt_cap, JOB_ATTEMPT_CAP);
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
                attempts: JOB_ATTEMPT_CAP,
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

        dispatcher.dispatch_one(row, handler).await;

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

        dispatcher.dispatch_one(row, handler).await;

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

        dispatcher.dispatch_one(row, handler).await;

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
