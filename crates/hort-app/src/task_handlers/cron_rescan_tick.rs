//! TaskHandler for the periodic cron-driven re-scan sweep.
//!
//! Triggered by the k8s CronJob (or operator host cron) hitting
//! `POST /api/v1/admin/tasks/cron-rescan-tick` (the admin-task
//! framework). Default schedule `*/5 * * * *`. The handler is a thin
//! orchestration step:
//!
//! 1. Capture `now`.
//! 2. Call [`RescanCandidatesRepository::select_eligible`] to fetch up
//!    to [`BATCH_SIZE`] artifacts whose policy-derived rescan interval
//!    has elapsed, that are `quarantine_status='released'`, and that
//!    have no in-flight `kind='scan'` job.
//! 3. For each candidate, call
//!    [`JobsRepository::enqueue_scan`] with `priority=10` and
//!    `trigger_source="cron"`.
//! 4. Return [`TaskOutcome::Completed`] with a result summary
//!    `{ eligible, enqueued }` so the framework's `result_summary`
//!    column captures per-tick load.
//!
//! Conflict detection is layered: the candidate SQL already filters
//! `NOT EXISTS (in-flight scan job)`, but a race against another
//! trigger source between SELECT and INSERT still surfaces as
//! `DomainError::Conflict` from the partial unique index
//! `(artifact_id) WHERE kind='scan'`. The handler swallows that
//! variant per row and continues — ON-CONFLICT-DO-NOTHING
//! semantics.
//!
//! Worker registration in the dispatch table lives in the
//! `hort-worker` composition root, not here.

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::jobs_repository::JobsRepository;
use hort_domain::ports::rescan_candidates::RescanCandidatesRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::metrics::{
    emit_scan_jobs_enqueued, set_cron_rescan_eligible_artifacts, TriggerSourceLabel,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Hard cap on candidates fetched per tick. Mirrors the `LIMIT 1000`
/// in the candidate SQL — a single tick cannot create more than this
/// many scan jobs. Subsequent CronJob runs drain any backlog.
///
/// Pinned as a `u32` constant (rather than wired through env): the
/// 1000-row batch cap prevents one invocation from creating an
/// enormous queue burst, and ENV-tuning is deliberately not offered.
const BATCH_SIZE: u32 = 1000;

/// Priority bucket for cron-enqueued scans.
///
/// Lower than manual (20), higher than advisory (5). The framework
/// orders claims `priority DESC, created_at ASC`.
const CRON_RESCAN_PRIORITY: i16 = 10;

/// `trigger_source` literal — must match the SQL CHECK constraint on
/// `jobs.trigger_source` (`'manual' | 'cron' | 'advisory' | 'ingest'`).
/// Mirrors [`hort_domain::ports::jobs_repository::TriggerSource::Cron`].
const CRON_TRIGGER_SOURCE: &str = "cron";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the periodic cron-rescan sweep. Constructed at
/// composition time with the two ports it touches.
pub struct CronRescanTickHandler {
    candidates: Arc<dyn RescanCandidatesRepository>,
    jobs: Arc<dyn JobsRepository>,
}

impl CronRescanTickHandler {
    /// Construct the handler from its two port dependencies.
    pub fn new(
        candidates: Arc<dyn RescanCandidatesRepository>,
        jobs: Arc<dyn JobsRepository>,
    ) -> Self {
        Self { candidates, jobs }
    }
}

impl TaskHandler for CronRescanTickHandler {
    fn kind(&self) -> &'static str {
        "cron-rescan-tick"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let now = Utc::now();
            let candidates = match self.candidates.select_eligible(BATCH_SIZE, now).await {
                Ok(rows) => rows,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "cron rescan tick: select_eligible failed; will retry on next tick",
                    );
                    return Ok(TaskOutcome::fail(
                        format!("select_eligible failed: {err}"),
                        true,
                    ));
                }
            };

            let eligible = candidates.len();
            // `hort_cron_rescan_eligible_artifacts` gauge.
            // Set once per tick; operator alarms on sustained > batch_size.
            set_cron_rescan_eligible_artifacts(eligible as u64);

            let mut enqueued: u32 = 0;

            for c in &candidates {
                match self
                    .jobs
                    .enqueue_scan(
                        c.artifact_id,
                        c.repository_id,
                        &c.content_hash,
                        &c.format,
                        CRON_RESCAN_PRIORITY,
                        CRON_TRIGGER_SOURCE,
                    )
                    .await
                {
                    Ok(_) => {
                        enqueued += 1;
                    }
                    Err(DomainError::Conflict(_)) => {
                        // ON CONFLICT (against the partial unique index
                        // `(artifact_id) WHERE kind='scan'`) DO NOTHING
                        // — a race against ingest, manual rescan, or
                        // advisory-watch resolves harmlessly.
                        tracing::debug!(
                            artifact_id = %c.artifact_id,
                            "cron rescan tick: enqueue conflict swallowed (race against another trigger source)",
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            artifact_id = %c.artifact_id,
                            error = %err,
                            "cron rescan tick: enqueue_scan failed; will retry on next tick",
                        );
                        return Ok(TaskOutcome::fail(
                            format!("enqueue_scan failed: {err}"),
                            true,
                        ));
                    }
                }
            }

            // `hort_scan_jobs_enqueued_total{trigger_source="cron"}`.
            // Conflict-on-enqueue rows do NOT count (the helper takes the
            // landed-rows count, not the attempted-rows count).
            if enqueued > 0 {
                emit_scan_jobs_enqueued(TriggerSourceLabel::Cron, u64::from(enqueued));
            }

            tracing::info!(eligible, enqueued, "cron rescan tick complete",);

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "eligible": eligible,
                    "enqueued": enqueued,
                }),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use chrono::DateTime;
    use uuid::Uuid;

    use hort_domain::error::DomainError;
    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{
        JobRow, JobStatus, JobsRepository, KindFields, ListJobsFilter, ListJobsPage, ScanJob,
    };
    use hort_domain::ports::rescan_candidates::{RescanCandidate, RescanCandidatesRepository};
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;

    // ---------- helpers ---------------------------------------------------

    fn test_hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("static valid SHA-256 hex")
    }

    fn make_candidate() -> RescanCandidate {
        RescanCandidate {
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            content_hash: test_hash(),
            format: "npm".into(),
            rescan_interval_hours: 24,
        }
    }

    fn test_job_row() -> JobRow {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        JobRow {
            id: Uuid::nil(),
            kind: "cron-rescan-tick".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
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

    fn make_context() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: test_job_row(),
        }
    }

    // ---------- mock RescanCandidatesRepository ---------------------------

    struct MockCandidates {
        rows: Mutex<Vec<RescanCandidate>>,
        err: Mutex<Option<DomainError>>,
        last_batch_size: Mutex<Option<u32>>,
    }

    impl MockCandidates {
        fn new(rows: Vec<RescanCandidate>) -> Self {
            Self {
                rows: Mutex::new(rows),
                err: Mutex::new(None),
                last_batch_size: Mutex::new(None),
            }
        }

        fn new_failing(err: DomainError) -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                err: Mutex::new(Some(err)),
                last_batch_size: Mutex::new(None),
            }
        }

        fn last_batch_size(&self) -> Option<u32> {
            *self.last_batch_size.lock().unwrap()
        }
    }

    impl RescanCandidatesRepository for MockCandidates {
        fn select_eligible<'a>(
            &'a self,
            batch_size: u32,
            _now: DateTime<Utc>,
        ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
            *self.last_batch_size.lock().unwrap() = Some(batch_size);
            let maybe_err = self.err.lock().unwrap().take();
            if let Some(err) = maybe_err {
                return Box::pin(async move { Err(err) });
            }
            let rows = self.rows.lock().unwrap().clone();
            Box::pin(async move { Ok(rows) })
        }
    }

    // ---------- mock JobsRepository (bare) -------------------------------

    /// Recorded `enqueue_scan` invocation.
    #[derive(Debug, Clone)]
    struct EnqueueCall {
        artifact_id: Uuid,
        repository_id: Uuid,
        format: String,
        priority: i16,
        trigger_source: String,
    }

    /// Per-call programmable response. `Conflict(N)` means the Nth
    /// `enqueue_scan` call (0-indexed) returns Conflict; `Internal(N)`
    /// means the Nth call returns an Internal-style error
    /// (`DomainError::Invariant`); other calls succeed.
    enum FailureMode {
        None,
        ConflictAt(usize),
        InternalAt(usize),
    }

    struct MockJobs {
        calls: Mutex<Vec<EnqueueCall>>,
        failure: Mutex<FailureMode>,
    }

    impl MockJobs {
        fn new(failure: FailureMode) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                failure: Mutex::new(failure),
            }
        }

        fn calls(&self) -> Vec<EnqueueCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl JobsRepository for MockJobs {
        fn claim_scan_jobs<'a>(
            &'a self,
            _w: &'a str,
            _b: u32,
            _l: std::time::Duration,
        ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn mark_completed<'a>(
            &'a self,
            _id: Uuid,
            _result_summary: serde_json::Value,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn reschedule<'a>(
            &'a self,
            _id: Uuid,
            _b: std::time::Duration,
            _e: &'a str,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn mark_failed<'a>(&'a self, _id: Uuid, _e: &'a str) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn enqueue_scan<'a>(
            &'a self,
            artifact_id: Uuid,
            repository_id: Uuid,
            _content_hash: &'a ContentHash,
            format: &'a str,
            priority: i16,
            trigger_source: &'a str,
        ) -> BoxFuture<'a, DomainResult<Uuid>> {
            let mut calls = self.calls.lock().unwrap();
            let idx = calls.len();
            calls.push(EnqueueCall {
                artifact_id,
                repository_id,
                format: format.to_string(),
                priority,
                trigger_source: trigger_source.to_string(),
            });
            drop(calls);
            let failure = self.failure.lock().unwrap();
            match &*failure {
                FailureMode::ConflictAt(n) if *n == idx => Box::pin(async move {
                    Err(DomainError::Conflict(format!(
                        "scan job already exists for artifact {artifact_id}"
                    )))
                }),
                FailureMode::InternalAt(n) if *n == idx => {
                    Box::pin(
                        async move { Err(DomainError::Invariant("simulated db error".into())) },
                    )
                }
                _ => Box::pin(async { Ok(Uuid::new_v4()) }),
            }
        }
        fn pending_scan_count<'a>(&'a self) -> BoxFuture<'a, DomainResult<i64>> {
            Box::pin(async { Ok(0) })
        }
        fn list_jobs<'a>(
            &'a self,
            _f: ListJobsFilter,
            _l: u32,
            _c: Option<Uuid>,
        ) -> BoxFuture<'a, DomainResult<ListJobsPage>> {
            Box::pin(async {
                Ok(ListJobsPage {
                    items: Vec::new(),
                    next_cursor: None,
                })
            })
        }
    }

    fn make_handler(candidates: Arc<MockCandidates>, jobs: Arc<MockJobs>) -> CronRescanTickHandler {
        CronRescanTickHandler::new(
            candidates as Arc<dyn RescanCandidatesRepository>,
            jobs as Arc<dyn JobsRepository>,
        )
    }

    // =====================================================================
    // kind() returns "cron-rescan-tick"
    // =====================================================================

    #[test]
    fn kind_returns_cron_rescan_tick() {
        let candidates = Arc::new(MockCandidates::new(Vec::new()));
        let jobs = Arc::new(MockJobs::new(FailureMode::None));
        let handler = make_handler(candidates, jobs);
        assert_eq!(handler.kind(), "cron-rescan-tick");
    }

    // =====================================================================
    // happy path: 3 eligible candidates → 3 enqueue_scan calls
    // =====================================================================

    #[tokio::test]
    async fn run_with_three_candidates_enqueues_each_with_cron_priority_and_trigger_source() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let c3 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![
            c1.clone(),
            c2.clone(),
            c3.clone(),
        ]));
        let jobs = Arc::new(MockJobs::new(FailureMode::None));

        let jobs_for_assert = jobs.clone();
        let handler = make_handler(candidates.clone(), jobs);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["eligible"], 3);
                assert_eq!(result_summary["enqueued"], 3);
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        let calls = jobs_for_assert.calls();
        assert_eq!(calls.len(), 3);
        for (call, c) in calls.iter().zip([&c1, &c2, &c3]) {
            assert_eq!(call.artifact_id, c.artifact_id);
            assert_eq!(call.repository_id, c.repository_id);
            assert_eq!(call.format, c.format);
            assert_eq!(call.priority, 10);
            assert_eq!(call.priority, CRON_RESCAN_PRIORITY);
            assert_eq!(call.trigger_source, "cron");
            assert_eq!(call.trigger_source, CRON_TRIGGER_SOURCE);
        }
    }

    // =====================================================================
    // empty: no candidates → result_summary {eligible:0, enqueued:0}
    // =====================================================================

    #[tokio::test]
    async fn run_with_empty_candidates_returns_zero_counts_and_skips_enqueue() {
        let candidates = Arc::new(MockCandidates::new(Vec::new()));
        let jobs = Arc::new(MockJobs::new(FailureMode::None));

        let jobs_for_assert = jobs.clone();
        let handler = make_handler(candidates, jobs);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["eligible"], 0);
                assert_eq!(result_summary["enqueued"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert_eq!(
            jobs_for_assert.calls().len(),
            0,
            "no candidates → no enqueue_scan calls"
        );
    }

    // =====================================================================
    // Conflict swallowed: 2 candidates, 1 returns Conflict → enqueued=1
    // =====================================================================

    #[tokio::test]
    async fn run_swallows_conflict_from_partial_unique_index_race() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![c1.clone(), c2.clone()]));
        // Second call (index 1) returns Conflict — first one succeeds.
        let jobs = Arc::new(MockJobs::new(FailureMode::ConflictAt(1)));

        let jobs_for_assert = jobs.clone();
        let handler = make_handler(candidates, jobs);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — Conflict is swallowed, not surfaced as Failed");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["eligible"], 2);
                assert_eq!(
                    result_summary["enqueued"], 1,
                    "Conflict on candidate 2 must NOT count toward enqueued",
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // Both candidates were attempted — Conflict does not abort the loop.
        assert_eq!(jobs_for_assert.calls().len(), 2);
    }

    // =====================================================================
    // fatal error: enqueue returns Invariant → TaskOutcome::Failed{retry:true}
    // =====================================================================

    #[tokio::test]
    async fn run_returns_failed_retry_when_enqueue_returns_non_conflict_error() {
        let c1 = make_candidate();
        let c2 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![c1, c2]));
        // First call (index 0) errors with a non-Conflict variant.
        let jobs = Arc::new(MockJobs::new(FailureMode::InternalAt(0)));

        let jobs_for_assert = jobs.clone();
        let handler = make_handler(candidates, jobs);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — non-Conflict errors are surfaced via TaskOutcome::Failed");

        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "non-Conflict enqueue error must retry");
                assert!(
                    reason.contains("enqueue_scan"),
                    "reason should mention enqueue_scan: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Loop aborted on the first failure — second candidate not attempted.
        assert_eq!(
            jobs_for_assert.calls().len(),
            1,
            "fatal error must abort the per-candidate loop"
        );
    }

    // =====================================================================
    // select_eligible returns error → TaskOutcome::Failed{retry:true}
    // =====================================================================

    #[tokio::test]
    async fn run_returns_failed_retry_when_select_eligible_errors() {
        let candidates = Arc::new(MockCandidates::new_failing(DomainError::Invariant(
            "simulated select failure".into(),
        )));
        let jobs = Arc::new(MockJobs::new(FailureMode::None));

        let jobs_for_assert = jobs.clone();
        let handler = make_handler(candidates, jobs);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — select_eligible errors are surfaced via TaskOutcome::Failed");

        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "select_eligible failure must retry");
                assert!(
                    reason.contains("select_eligible"),
                    "reason should mention select_eligible: {reason}",
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(
            jobs_for_assert.calls().len(),
            0,
            "select_eligible failure must short-circuit before any enqueue"
        );
    }

    // =====================================================================
    // BATCH_SIZE — handler asks select_eligible for exactly 1000
    // =====================================================================

    #[tokio::test]
    async fn run_asks_select_eligible_for_exactly_batch_size_1000() {
        let candidates = Arc::new(MockCandidates::new(Vec::new()));
        let jobs = Arc::new(MockJobs::new(FailureMode::None));

        let candidates_for_assert = candidates.clone();
        let handler = make_handler(candidates, jobs);

        let _ = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        assert_eq!(
            candidates_for_assert.last_batch_size(),
            Some(1000),
            "BATCH_SIZE constant must drive the candidate-SQL LIMIT — handler asks for 1000",
        );
        assert_eq!(BATCH_SIZE, 1000, "design pin: BATCH_SIZE = 1000");
    }

    // =====================================================================
    // Metric emission
    // =====================================================================

    /// Happy path emits `hort_scan_jobs_enqueued_total{trigger_source="cron"}`
    /// once with the landed-rows count, sets the
    /// `hort_cron_rescan_eligible_artifacts` gauge to the eligibility count,
    /// and exposes NO high-cardinality labels (artifact_id, purl, …).
    #[test]
    fn run_emits_scan_jobs_enqueued_and_eligible_gauge_metrics() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let c1 = make_candidate();
        let c2 = make_candidate();
        let c3 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![c1, c2, c3]));
        let jobs = Arc::new(MockJobs::new(FailureMode::None));
        let handler = make_handler(candidates, jobs);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(handler.run(&serde_json::Value::Null, make_context()))
                .expect("Ok");
        });

        let snap = snapshotter.snapshot().into_vec();

        // hort_scan_jobs_enqueued_total{trigger_source="cron"} == 3.
        let counter = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_scan_jobs_enqueued_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "trigger_source" && l.value() == "cron")
        });
        let (key, _, _, value) = counter.expect("scan_jobs_enqueued{trigger_source=cron}");
        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 3, "expected 3 enqueued increments"),
            other => panic!("expected Counter, got {other:?}"),
        }
        // High-cardinality labels MUST NOT appear.
        for forbidden in &["artifact_id", "purl", "vulnerability_id", "package_name"] {
            assert!(
                !key.key().labels().any(|l| l.key() == *forbidden),
                "forbidden label `{forbidden}` must not appear on hort_scan_jobs_enqueued_total",
            );
        }

        // hort_cron_rescan_eligible_artifacts == 3 (no labels).
        let gauge = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Gauge
                && ck.key().name() == "hort_cron_rescan_eligible_artifacts"
        });
        let (gkey, _, _, gvalue) = gauge.expect("hort_cron_rescan_eligible_artifacts gauge");
        assert_eq!(
            gkey.key().labels().count(),
            0,
            "hort_cron_rescan_eligible_artifacts must have no labels",
        );
        match gvalue {
            DebugValue::Gauge(v) => assert_eq!(*v, 3.0, "gauge must reflect eligibility count"),
            other => panic!("expected Gauge, got {other:?}"),
        }
    }

    /// Conflict-on-enqueue rows do NOT count toward
    /// `hort_scan_jobs_enqueued_total{trigger_source="cron"}` — the helper
    /// is called with the landed-rows count, not the attempted count.
    #[test]
    fn run_does_not_count_conflict_swallowed_rows_in_enqueued_metric() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let c1 = make_candidate();
        let c2 = make_candidate();
        let candidates = Arc::new(MockCandidates::new(vec![c1, c2]));
        // Second call returns Conflict; first one succeeds → enqueued=1.
        let jobs = Arc::new(MockJobs::new(FailureMode::ConflictAt(1)));
        let handler = make_handler(candidates, jobs);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(handler.run(&serde_json::Value::Null, make_context()))
                .expect("Ok");
        });

        let snap = snapshotter.snapshot().into_vec();
        let counter = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_scan_jobs_enqueued_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "trigger_source" && l.value() == "cron")
        });
        let (_, _, _, value) = counter.expect("scan_jobs_enqueued{trigger_source=cron}");
        match value {
            DebugValue::Counter(n) => assert_eq!(
                *n, 1,
                "Conflict-swallowed row must NOT count toward enqueued metric"
            ),
            other => panic!("expected Counter, got {other:?}"),
        }
    }
}
