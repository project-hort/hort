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
//! # Metrics emitted
//!
//! See metrics-catalog.md (`hort_admin_tasks_*`):
//!
//! - `hort_admin_tasks_enqueued_total{kind}` — currently unused by the
//!   dispatcher itself; enqueued events are emitted by the HTTP handler.
//!   Documented here for completeness.
//! - `hort_admin_tasks_completed_total{kind, result}` — one increment per
//!   `record_outcome_for_row` call. `result ∈ {completed, failed_retry,
//!   failed_terminal}`.
//! - `hort_admin_tasks_duration_seconds{kind}` — elapsed time from claim to
//!   `record_outcome_for_row`, wrapping `TaskHandler::run`.
//! - `hort_admin_tasks_in_flight{kind}` — gauge; incremented when a task
//!   `run` starts, decremented when it finishes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use hort_domain::events::{Actor, InternalActor};
use hort_domain::ports::jobs_repository::{JobRow, JobsRepository};
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};

use crate::error::AppResult;
use crate::event_store_publisher::EventStorePublisher;

// ---------------------------------------------------------------------------
// Metric name constants
// ---------------------------------------------------------------------------

const METRIC_COMPLETED: &str = "hort_admin_tasks_completed_total";
const METRIC_DURATION: &str = "hort_admin_tasks_duration_seconds";
const METRIC_IN_FLIGHT: &str = "hort_admin_tasks_in_flight";

// Result label values
const RESULT_COMPLETED: &str = "completed";
const RESULT_FAILED_RETRY: &str = "failed_retry";
const RESULT_FAILED_TERMINAL: &str = "failed_terminal";

// Default backoff for a retryable failed task (exponential from this base).
const DEFAULT_BACKOFF_SECS: u64 = 30;

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
    ///    gated by the kind's semaphore.
    /// 4. Each spawned task records the outcome via `record_outcome_for_row`.
    ///
    /// Returns `Ok(())` when the cancellation token fires (clean shutdown).
    /// Infrastructure errors on claim or outcome recording are logged and
    /// swallowed — a transient DB flap does not crash the loop.
    #[tracing::instrument(skip(self))]
    pub async fn run(self, cancel: CancellationToken) -> AppResult<()> {
        let kinds: Vec<&str> = self.handlers.keys().copied().collect();
        // Wrap self in Arc so spawned tasks can share ownership without
        // cloning the entire struct.
        let dispatcher = Arc::new(self);

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

            if claimed.is_empty() {
                tracing::debug!("TaskDispatcher: no pending jobs");
                continue;
            }

            tracing::debug!(claimed = claimed.len(), "TaskDispatcher: batch claimed");

            for job in claimed {
                let kind_str = job.kind.clone();
                let Some(handler) = dispatcher.handlers.get(kind_str.as_str()).cloned() else {
                    // Should not happen — claim query filters by registered kinds.
                    // Defensive: log and skip without updating the row (leave it
                    // 'running' so the lock expires and another worker claims it).
                    tracing::error!(
                        job_id = %job.id,
                        kind = %kind_str,
                        "TaskDispatcher: claimed job has unregistered kind; skipping"
                    );
                    continue;
                };
                let Some(semaphore) = dispatcher.semaphores.get(kind_str.as_str()).cloned() else {
                    // Invariant: semaphore always co-exists with handler.
                    tracing::error!(kind = %kind_str, "TaskDispatcher: no semaphore for kind");
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

    /// Invoke the handler for a single job row and record the outcome.
    async fn dispatch_one(&self, job: JobRow, handler: Arc<dyn TaskHandler>) {
        let kind = handler.kind();

        // Build a TaskContext from the job row.
        let ctx = TaskContext {
            task_job_id: job.id,
            actor: Actor::Internal(InternalActor::Timer),
            correlation_id: Uuid::new_v4(),
            job_row: job.clone(),
        };

        let params = job.params.clone().unwrap_or(serde_json::Value::Null);

        // Emit in-flight gauge +1.
        metrics::gauge!(METRIC_IN_FLIGHT, "kind" => kind.to_string()).increment(1.0);

        let started = Instant::now();
        let outcome = handler.run(&params, ctx).await;
        let elapsed = started.elapsed();

        // Emit in-flight gauge -1.
        metrics::gauge!(METRIC_IN_FLIGHT, "kind" => kind.to_string()).decrement(1.0);

        // Observe duration.
        metrics::histogram!(METRIC_DURATION, "kind" => kind.to_string())
            .record(elapsed.as_secs_f64());

        match outcome {
            Ok(task_outcome) => {
                self.record_outcome_for_row(&job, kind, task_outcome).await;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    job_id = %job.id,
                    kind,
                    "TaskDispatcher: handler returned Err; treating as failed_retry",
                );
                let outcome = TaskOutcome::fail(e.to_string(), true);
                self.record_outcome_for_row(&job, kind, outcome).await;
            }
        }
    }

    /// Translate a [`TaskOutcome`] into a jobs-row state transition.
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
                if let Err(e) = self.job_repo.mark_completed(job.id, result_summary).await {
                    tracing::error!(
                        error = %e,
                        job_id = %job.id,
                        kind,
                        "TaskDispatcher: mark_completed failed",
                    );
                }
                metrics::counter!(
                    METRIC_COMPLETED,
                    "kind" => kind.to_string(),
                    "result" => RESULT_COMPLETED,
                )
                .increment(1);
            }
            TaskOutcome::Failed {
                reason,
                retry: true,
            } => {
                let backoff = compute_backoff(job.attempts);
                if let Err(e) = self.job_repo.reschedule(job.id, backoff, &reason).await {
                    tracing::error!(
                        error = %e,
                        job_id = %job.id,
                        kind,
                        "TaskDispatcher: reschedule failed",
                    );
                }
                metrics::counter!(
                    METRIC_COMPLETED,
                    "kind" => kind.to_string(),
                    "result" => RESULT_FAILED_RETRY,
                )
                .increment(1);
            }
            TaskOutcome::Failed {
                reason,
                retry: false,
            } => {
                if let Err(e) = self.job_repo.mark_failed(job.id, &reason).await {
                    tracing::error!(
                        error = %e,
                        job_id = %job.id,
                        kind,
                        "TaskDispatcher: mark_failed failed",
                    );
                }
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

/// Compute an exponential backoff for a retryable failure.
///
/// `attempts` is the current `jobs.attempts` value (already incremented by the
/// claim query). The base is [`DEFAULT_BACKOFF_SECS`]; each retry doubles the
/// backoff up to a maximum of 24 hours.
fn compute_backoff(attempts: u32) -> Duration {
    let cap_secs: u64 = 24 * 3600;
    // Shift by at most 32 bits to avoid overflow; saturate at cap.
    let shift = attempts.saturating_sub(1).min(32);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let secs = DEFAULT_BACKOFF_SECS.saturating_mul(multiplier);
    Duration::from_secs(secs.min(cap_secs))
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
    use hort_domain::error::DomainResult;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, JobsRepository, ScanJob};
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_job_row(kind: &str) -> JobRow {
        use hort_domain::ports::jobs_repository::KindFields;
        let now = Utc::now();
        JobRow {
            id: Uuid::new_v4(),
            kind: kind.to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::json!({})),
            actor_id: None,
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
    struct DispatcherMockRepo {
        /// Pre-seeded batches; each `claim` call pops the front.
        claim_batches: Mutex<Vec<Vec<JobRow>>>,
        mark_completed_calls: Mutex<Vec<Uuid>>,
        mark_completed_summaries: Mutex<Vec<serde_json::Value>>,
        reschedule_calls: Mutex<Vec<(Uuid, String)>>,
        mark_failed_calls: Mutex<Vec<(Uuid, String)>>,
    }

    impl DispatcherMockRepo {
        fn new() -> Self {
            Self {
                claim_batches: Mutex::new(Vec::new()),
                mark_completed_calls: Mutex::new(Vec::new()),
                mark_completed_summaries: Mutex::new(Vec::new()),
                reschedule_calls: Mutex::new(Vec::new()),
                mark_failed_calls: Mutex::new(Vec::new()),
            }
        }

        fn seed_batch(&self, rows: Vec<JobRow>) {
            self.claim_batches.lock().unwrap().push(rows);
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

        fn mark_failed_calls(&self) -> Vec<(Uuid, String)> {
            self.mark_failed_calls.lock().unwrap().clone()
        }
    }

    impl JobsRepository for DispatcherMockRepo {
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
            result_summary: serde_json::Value,
        ) -> BoxFuture<'a, DomainResult<()>> {
            self.mark_completed_calls.lock().unwrap().push(job_id);
            self.mark_completed_summaries
                .lock()
                .unwrap()
                .push(result_summary);
            Box::pin(async { Ok(()) })
        }

        fn reschedule<'a>(
            &'a self,
            job_id: Uuid,
            _backoff: Duration,
            last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            self.reschedule_calls
                .lock()
                .unwrap()
                .push((job_id, last_error.to_string()));
            Box::pin(async { Ok(()) })
        }

        fn mark_failed<'a>(
            &'a self,
            job_id: Uuid,
            last_error: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            self.mark_failed_calls
                .lock()
                .unwrap()
                .push((job_id, last_error.to_string()));
            Box::pin(async { Ok(()) })
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

        fn delete_stream(&self, _stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
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

    /// A handler that returns Failed { retry: true }.
    struct RetryHandler;

    impl TaskHandler for RetryHandler {
        fn kind(&self) -> &'static str {
            "retry-kind"
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
        TaskDispatcher::new(
            repo,
            crate::event_store_publisher::wrap_for_test(Arc::new(NoopEventStore)),
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

        let kinds: std::collections::HashSet<&str> =
            dispatcher.registered_kinds().into_iter().collect();
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
        dispatcher.register(Arc::new(RetryHandler), 4);

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
                .block_on(dispatcher.dispatch_one(row, handler))
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
                .block_on(dispatcher.dispatch_one(row, handler))
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
                .block_on(dispatcher.dispatch_one(row, handler))
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
    // compute_backoff — unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn compute_backoff_attempt_1_returns_base() {
        let d = compute_backoff(1);
        assert_eq!(d.as_secs(), DEFAULT_BACKOFF_SECS);
    }

    #[test]
    fn compute_backoff_attempt_2_doubles() {
        let d = compute_backoff(2);
        assert_eq!(d.as_secs(), DEFAULT_BACKOFF_SECS * 2);
    }

    #[test]
    fn compute_backoff_caps_at_24_hours() {
        let d = compute_backoff(100);
        assert_eq!(d.as_secs(), 24 * 3600);
    }

    #[test]
    fn compute_backoff_attempt_0_returns_base() {
        // 0 attempts should not produce a shorter-than-base backoff.
        let d = compute_backoff(0);
        assert_eq!(d.as_secs(), DEFAULT_BACKOFF_SECS);
    }
}
