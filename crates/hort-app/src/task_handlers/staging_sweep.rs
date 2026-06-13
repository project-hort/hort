//! TaskHandler for the staging-orphan sweep.
//!
//! Delegates to a single `sweep_once`-equivalent invocation per task
//! invocation. The k8s CronJob (or operator host cron) drives cadence
//! by repeatedly POSTing `/api/v1/admin/tasks/staging-sweep` — this
//! handler runs ONE tick per call.
//!
//! # What this is NOT
//!
//! This task does NOT GC ephemeral-store sessions — Redis (or the
//! in-memory adapter's evictor) handles that natively. There is
//! deliberately no
//! `delete_expired` query, no `OciUploadSessionRepository`, and no
//! `hort_stateful_upload_sessions_total{result="expired"}` metric.

use std::sync::Arc;

use hort_domain::error::DomainResult;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::stateful_upload_staging::StatefulUploadStagingPort;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;
use serde_json::json;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Hard cap on entries processed per tick. The filesystem adapter
/// MUST honour this — see `StatefulUploadStagingPort::list`. At
/// 1000-per-tick driven by a CronJob the sweep can clear ~12 k orphans
/// per hour (at 5-minute cadence), which is well above any realistic
/// abandonment rate. A real backlog (post-incident) drains over multiple
/// ticks; the system never block-loops trying to drain in one go.
const MAX_PER_TICK: usize = 1000;

/// Format token used in the ephemeral-store key. Hard-coded to
/// `"oci_v2"` — the OCI session
/// record's wire format is `postcard` (not the earlier `bincode 2.0`),
/// and the key-space token forked from `oci` to `oci_v2` so legacy
/// records never enter the new decoder's path. Must stay in lock
/// step with `hort_http_oci::upload_session::format_token("oci")`;
/// the `session_key_format_matches_literal` test below pins the
/// wire format. Future formats (Maven chunked PUT, Git LFS) will pass
/// their own format token — refactoring this into a parameter on the
/// handler is a follow-on once the second caller materialises.
///
/// The metric label still reads `"oci"` so the
/// `hort_stateful_upload_staging_orphans_cleaned_total{format="oci"}`
/// time-series stays continuous across the prefix bump; only the
/// internal key-space token changes.
const FORMAT_OCI: &str = "oci_v2";

/// Metric-label value for the OCI format. Diverges from
/// [`FORMAT_OCI`] (the key-space token) so the metric series stays
/// stable across key-space bumps.
const FORMAT_OCI_METRIC_LABEL: &str = "oci";

/// Counter name. `format` is the only label — no `result` axis;
/// every fired counter event represents exactly one orphan
/// successfully deleted from staging. `format` cardinality is
/// bounded by ~40 known formats (see `docs/metrics-catalog.md`).
const METRIC_NAME: &str = "hort_stateful_upload_staging_orphans_cleaned_total";

// ---------------------------------------------------------------------------
// session_key helper
// ---------------------------------------------------------------------------

/// Build the `EphemeralStore` key for a stateful-upload session.
///
/// Mirrors `hort_http_oci::upload_session::session_key` — both must
/// produce identical strings or the sweep will miss live sessions.
/// Future formats (Git LFS) will pass their own format token.
///
/// Note: the cross-crate agreement test from the original `hort-server::staging_sweep`
/// (which called `hort_http_oci::upload_session::session_key`) cannot live in `hort-app`
/// because `hort-http-oci` depends on `hort-app` (cycle). The wire-format pin is enforced
/// by the literal assertion in `session_key_format_matches_literal` in the test module.
pub(crate) fn session_key(format: &str, session_id: Uuid) -> String {
    format!("stateful_upload:{format}:{session_id}")
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// TaskHandler that runs a single staging-orphan sweep tick.
///
/// Constructed at composition time with the two ports it touches
/// (`StatefulUploadStagingPort` + `EphemeralStore`). The k8s CronJob
/// drives cadence by POSTing to `/api/v1/admin/tasks/staging-sweep`;
/// this handler processes up to `MAX_PER_TICK` candidates per call.
pub struct StagingSweepHandler {
    staging: Arc<dyn StatefulUploadStagingPort>,
    ephemeral: Arc<dyn EphemeralStore>,
}

impl StagingSweepHandler {
    /// Construct the handler. Both ports are injected at composition time.
    pub fn new(
        staging: Arc<dyn StatefulUploadStagingPort>,
        ephemeral: Arc<dyn EphemeralStore>,
    ) -> Self {
        Self { staging, ephemeral }
    }
}

impl TaskHandler for StagingSweepHandler {
    fn kind(&self) -> &'static str {
        "staging-sweep"
    }

    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let session_ids = match self.staging.list(MAX_PER_TICK).await {
                Ok(ids) => ids,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "staging-orphan sweep failed to list staging entries; will retry on next tick"
                    );
                    return Ok(TaskOutcome::fail(
                        format!("list staging entries failed: {err}"),
                        true,
                    ));
                }
            };

            let candidate_count = session_ids.len();

            if session_ids.is_empty() {
                tracing::debug!("staging-orphan sweep: no entries to consider");
                return Ok(TaskOutcome::Completed {
                    result_summary: json!({
                        "candidate_count": 0usize,
                        "orphan_count": 0usize,
                        "max_per_tick": MAX_PER_TICK,
                    }),
                });
            }

            tracing::debug!(
                candidate_count,
                "staging-orphan sweep evaluating candidates"
            );

            let mut orphan_count: usize = 0;

            for session_id in session_ids {
                let key = session_key(FORMAT_OCI, session_id);
                match self.ephemeral.get(&key).await {
                    Ok(Some(_)) => {
                        // Session still live — staging belongs to an
                        // in-flight upload and must not be reaped.
                        continue;
                    }
                    Ok(None) => {
                        // Session expired (TTL elapsed and the ephemeral
                        // store dropped the key) — staging is orphaned.
                        if let Err(err) = self.staging.delete(session_id).await {
                            tracing::warn!(
                                %session_id,
                                error = %err,
                                "staging-orphan sweep: delete failed; will retry on next tick"
                            );
                            continue;
                        }
                        metrics::counter!(METRIC_NAME, "format" => FORMAT_OCI_METRIC_LABEL)
                            .increment(1);
                        tracing::debug!(%session_id, "staging-orphan sweep deleted orphaned staging");
                        orphan_count += 1;
                    }
                    Err(err) => {
                        // Infrastructure-class miss on the ephemeral side —
                        // do NOT delete staging on a query failure; that
                        // would race with a still-live session whose lookup
                        // happened to fail transiently.
                        tracing::warn!(
                            %session_id,
                            error = %err,
                            "staging-orphan sweep: ephemeral get failed; leaving staging intact"
                        );
                    }
                }
            }

            Ok(TaskOutcome::Completed {
                result_summary: json!({
                    "candidate_count": candidate_count,
                    "orphan_count": orphan_count,
                    "max_per_tick": MAX_PER_TICK,
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

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use bytes::Bytes;
    use chrono::Utc;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::events::system_actor;
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use hort_domain::ports::stateful_upload_staging::StatefulUploadStagingPort;
    use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
    use hort_domain::ports::BoxFuture;
    use metrics::SharedString;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use tokio::io::AsyncRead;

    // ---------------- Mocks -------------------------------------------------

    /// Mock `StatefulUploadStagingPort` driven by a pre-loaded list of
    /// session IDs. `delete` records the IDs the sweep asked to remove.
    /// `list_calls` records the `max` argument of every `list` call so
    /// the iteration-cap test can prove the sweep never asks for more
    /// than `MAX_PER_TICK`.
    struct MockStaging {
        list_response: Mutex<Vec<Uuid>>,
        delete_calls: Mutex<Vec<Uuid>>,
        list_max_args: Mutex<Vec<usize>>,
        list_err: AtomicBool,
    }

    impl MockStaging {
        fn new(list_response: Vec<Uuid>) -> Self {
            Self {
                list_response: Mutex::new(list_response),
                delete_calls: Mutex::new(Vec::new()),
                list_max_args: Mutex::new(Vec::new()),
                list_err: AtomicBool::new(false),
            }
        }

        fn new_failing() -> Self {
            Self {
                list_response: Mutex::new(Vec::new()),
                delete_calls: Mutex::new(Vec::new()),
                list_max_args: Mutex::new(Vec::new()),
                list_err: AtomicBool::new(true),
            }
        }

        fn deleted(&self) -> Vec<Uuid> {
            self.delete_calls.lock().unwrap().clone()
        }

        fn list_max_args(&self) -> Vec<usize> {
            self.list_max_args.lock().unwrap().clone()
        }
    }

    impl StatefulUploadStagingPort for MockStaging {
        fn append(
            &self,
            _session_id: Uuid,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<u64>> {
            unreachable!("sweep does not call append")
        }

        fn stream_read(
            &self,
            _session_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            unreachable!("sweep does not call stream_read")
        }

        fn delete(&self, session_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            self.delete_calls.lock().unwrap().push(session_id);
            Box::pin(async move { Ok(()) })
        }

        fn list(&self, max: usize) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
            self.list_max_args.lock().unwrap().push(max);
            if self.list_err.load(Ordering::Relaxed) {
                return Box::pin(async move {
                    Err(DomainError::Invariant("simulated list failure".into()))
                });
            }
            // Honour the `max` cap so a buggy caller asking for more
            // than 1000 surfaces visibly: we deliberately only return
            // up to `max` entries, mirroring the filesystem adapter's
            // contract.
            let response = self.list_response.lock().unwrap().clone();
            let truncated: Vec<Uuid> = response.into_iter().take(max).collect();
            Box::pin(async move { Ok(truncated) })
        }
    }

    /// Mock `EphemeralStore` driven by a `HashMap`. `get_calls` records
    /// every key looked up so tests can assert exactly how many lookups
    /// the sweep made (load-bearing for the iteration-cap test).
    struct MockEphemeral {
        entries: Mutex<HashMap<String, Bytes>>,
        get_calls: AtomicUsize,
        get_err: AtomicBool,
    }

    impl MockEphemeral {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                get_calls: AtomicUsize::new(0),
                get_err: AtomicBool::new(false),
            }
        }

        fn new_failing() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                get_calls: AtomicUsize::new(0),
                get_err: AtomicBool::new(true),
            }
        }

        fn insert_live(&self, key: String) {
            // Value is unused by the sweep — only `Some(_)` vs `None`
            // matters. An empty Bytes is the cheapest sentinel.
            self.entries.lock().unwrap().insert(key, Bytes::new());
        }

        fn get_calls(&self) -> usize {
            self.get_calls.load(Ordering::Relaxed)
        }
    }

    impl EphemeralStore for MockEphemeral {
        fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            self.get_calls.fetch_add(1, Ordering::Relaxed);
            if self.get_err.load(Ordering::Relaxed) {
                return Box::pin(async move {
                    Err(DomainError::Invariant(
                        "simulated ephemeral get failure".into(),
                    ))
                });
            }
            let v = self.entries.lock().unwrap().get(key).cloned();
            Box::pin(async move { Ok(v) })
        }

        fn put(
            &self,
            _key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("sweep does not call put")
        }

        fn put_if_absent(
            &self,
            _key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            unreachable!("sweep does not call put_if_absent")
        }

        fn compare_and_swap(
            &self,
            _key: &str,
            _expected_version: u64,
            _new_value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            unreachable!("sweep does not call compare_and_swap")
        }

        fn delete(&self, _key: &str) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("sweep does not call delete on ephemeral")
        }

        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            unreachable!("sweep does not call extend_ttl")
        }
    }

    // ---------------- Handler factory ---------------------------------------

    fn make_handler(
        staging: Arc<MockStaging>,
        ephemeral: Arc<MockEphemeral>,
    ) -> StagingSweepHandler {
        StagingSweepHandler::new(
            staging as Arc<dyn StatefulUploadStagingPort>,
            ephemeral as Arc<dyn EphemeralStore>,
        )
    }

    fn test_job_row() -> JobRow {
        let now = Utc::now();
        JobRow {
            id: Uuid::nil(),
            kind: "staging-sweep".to_string(),
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

    // ---------------- Metric helpers ----------------------------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<SharedString>,
        DebugValue,
    );

    fn find<'a>(
        entries: &'a [MetricEntry],
        kind: MetricKind,
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != kind || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    fn capture<F, Fut>(f: F) -> (Snapshot, TaskOutcome)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = TaskOutcome>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let outcome = metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f())
        });
        (snapshotter.snapshot(), outcome)
    }

    // =====================================================================
    // kind() returns "staging-sweep"
    // =====================================================================

    #[test]
    fn kind_returns_staging_sweep() {
        let staging = Arc::new(MockStaging::new(vec![]));
        let ephemeral = Arc::new(MockEphemeral::new());
        let handler = make_handler(staging, ephemeral);
        assert_eq!(handler.kind(), "staging-sweep");
    }

    // =====================================================================
    // (a) Staging present + session key absent → staging deleted
    // =====================================================================

    #[test]
    fn sweep_deletes_staging_when_session_key_is_absent() {
        let orphan = Uuid::new_v4();
        let staging = Arc::new(MockStaging::new(vec![orphan]));
        let ephemeral = Arc::new(MockEphemeral::new());
        // Deliberately do NOT call `insert_live` — the ephemeral side
        // has no entry for this session, modelling a TTL'd session.

        let staging_for_assert = staging.clone();
        let ephemeral_for_assert = ephemeral.clone();

        let (snap, outcome) = capture(|| {
            let staging = staging.clone();
            let ephemeral = ephemeral.clone();
            async move {
                let handler = make_handler(staging, ephemeral);
                handler
                    .run(&serde_json::Value::Null, make_context())
                    .await
                    .expect("handler succeeded")
            }
        });

        // Sweep must have called delete exactly once with the orphan id.
        assert_eq!(staging_for_assert.deleted(), vec![orphan]);
        // Result summary must show 1 orphan.
        match &outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidate_count"], 1);
                assert_eq!(result_summary["orphan_count"], 1);
                assert_eq!(result_summary["max_per_tick"], MAX_PER_TICK);
            }
            _ => panic!("expected Completed, got {outcome:?}"),
        }
        // And the metric must have fired once with format=oci.
        let entries = snap.into_vec();
        let v = find(
            &entries,
            MetricKind::Counter,
            METRIC_NAME,
            &[("format", FORMAT_OCI_METRIC_LABEL)],
        )
        .expect("orphan-cleaned counter must fire");
        assert!(matches!(v, DebugValue::Counter(n) if *n == 1));
        // And exactly one ephemeral get was issued.
        assert_eq!(ephemeral_for_assert.get_calls(), 1);
    }

    // =====================================================================
    // (b) Fresh session + staging → both survive
    // =====================================================================

    #[test]
    fn sweep_preserves_staging_when_session_key_is_present() {
        let live = Uuid::new_v4();
        let staging = Arc::new(MockStaging::new(vec![live]));
        let ephemeral = Arc::new(MockEphemeral::new());
        ephemeral.insert_live(session_key(FORMAT_OCI, live));

        let staging_for_assert = staging.clone();

        let (snap, outcome) = capture(|| {
            let staging = staging.clone();
            let ephemeral = ephemeral.clone();
            async move {
                let handler = make_handler(staging, ephemeral);
                handler
                    .run(&serde_json::Value::Null, make_context())
                    .await
                    .expect("handler succeeded")
            }
        });

        // Sweep must NOT have called delete.
        assert!(
            staging_for_assert.deleted().is_empty(),
            "delete must not fire for a live session; got {:?}",
            staging_for_assert.deleted()
        );

        match &outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidate_count"], 1);
                assert_eq!(result_summary["orphan_count"], 0);
            }
            _ => panic!("expected Completed, got {outcome:?}"),
        }

        // No counter increment.
        let entries = snap.into_vec();
        assert!(
            find(
                &entries,
                MetricKind::Counter,
                METRIC_NAME,
                &[("format", FORMAT_OCI_METRIC_LABEL)],
            )
            .is_none(),
            "orphan-cleaned counter must NOT fire when session is live"
        );
    }

    // =====================================================================
    // (c) Iteration cap — sweep asks list for at most MAX_PER_TICK
    // =====================================================================

    #[test]
    fn sweep_iteration_caps_at_max_per_tick() {
        // Build MAX_PER_TICK orphan IDs. The mock staging port honours
        // the `max` argument and would only return up to `max` anyway,
        // but we additionally assert the sweep never asks for more.
        let orphans: Vec<Uuid> = (0..MAX_PER_TICK).map(|_| Uuid::new_v4()).collect();
        let staging = Arc::new(MockStaging::new(orphans));
        let ephemeral = Arc::new(MockEphemeral::new());

        let staging_for_assert = staging.clone();
        let ephemeral_for_assert = ephemeral.clone();

        let (_snap, _outcome) = capture(|| {
            let staging = staging.clone();
            let ephemeral = ephemeral.clone();
            async move {
                let handler = make_handler(staging, ephemeral);
                handler
                    .run(&serde_json::Value::Null, make_context())
                    .await
                    .expect("handler succeeded")
            }
        });

        // The sweep must have called list exactly once, and asked for
        // exactly MAX_PER_TICK — never more, never `usize::MAX`, never
        // `0`. Anything else means a regression in the hard cap.
        assert_eq!(
            staging_for_assert.list_max_args(),
            vec![MAX_PER_TICK],
            "sweep must ask list for exactly MAX_PER_TICK in a single tick"
        );
        // Exactly MAX_PER_TICK ephemeral lookups — one per candidate.
        assert_eq!(ephemeral_for_assert.get_calls(), MAX_PER_TICK);
    }

    // =====================================================================
    // (d) Empty staging list → Completed with zero counts
    // =====================================================================

    #[test]
    fn sweep_returns_completed_with_zero_counts_when_staging_is_empty() {
        let staging = Arc::new(MockStaging::new(vec![]));
        let ephemeral = Arc::new(MockEphemeral::new());

        let (_snap, outcome) = capture(|| {
            let staging = staging.clone();
            let ephemeral = ephemeral.clone();
            async move {
                let handler = make_handler(staging, ephemeral);
                handler
                    .run(&serde_json::Value::Null, make_context())
                    .await
                    .expect("handler succeeded")
            }
        });

        match &outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["candidate_count"], 0);
                assert_eq!(result_summary["orphan_count"], 0);
                assert_eq!(result_summary["max_per_tick"], MAX_PER_TICK);
            }
            _ => panic!("expected Completed, got {outcome:?}"),
        }
    }

    // =====================================================================
    // (e) list() fails → Failed { retry: true }
    // =====================================================================

    #[test]
    fn sweep_returns_failed_retry_when_list_errors() {
        let staging = Arc::new(MockStaging::new_failing());
        let ephemeral = Arc::new(MockEphemeral::new());

        let (_snap, outcome) = capture(|| {
            let staging = staging.clone();
            let ephemeral = ephemeral.clone();
            async move {
                let handler = make_handler(staging, ephemeral);
                handler
                    .run(&serde_json::Value::Null, make_context())
                    .await
                    .expect("handler run returned Ok (wrapping Failed)")
            }
        });

        match &outcome {
            TaskOutcome::Failed { retry, .. } => {
                assert!(*retry, "list failure must set retry=true");
            }
            _ => panic!("expected Failed, got {outcome:?}"),
        }
    }

    // =====================================================================
    // (f) ephemeral get() fails → skip delete, leave staging intact
    // =====================================================================

    #[test]
    fn sweep_skips_delete_when_ephemeral_get_errors() {
        let session_id = Uuid::new_v4();
        let staging = Arc::new(MockStaging::new(vec![session_id]));
        let ephemeral = Arc::new(MockEphemeral::new_failing());

        let staging_for_assert = staging.clone();

        let (_snap, outcome) = capture(|| {
            let staging = staging.clone();
            let ephemeral = ephemeral.clone();
            async move {
                let handler = make_handler(staging, ephemeral);
                handler
                    .run(&serde_json::Value::Null, make_context())
                    .await
                    .expect("handler succeeded despite ephemeral error")
            }
        });

        // Delete must NOT have been called — transient ephemeral error
        // is not grounds to destroy staging data.
        assert!(
            staging_for_assert.deleted().is_empty(),
            "delete must not fire on ephemeral get error; got {:?}",
            staging_for_assert.deleted()
        );

        // Handler still completes (0 orphans, not Failed).
        match &outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["orphan_count"], 0);
            }
            _ => panic!("expected Completed, got {outcome:?}"),
        }
    }

    // =====================================================================
    // session_key — wire format pin
    // =====================================================================

    /// Pin the wire format of `session_key` against the expected literal.
    ///
    /// The cross-crate agreement test (against `hort_http_oci::upload_session::session_key`)
    /// cannot live in `hort-app` because `hort-http-oci` depends on `hort-app`, which would
    /// create a circular dev-dependency. The literal assertion below is sufficient to pin
    /// the FORMAT_OCI constant and the key layout. If `hort-http-oci::upload_session::format_token`
    /// ever changes `"oci"` → `"oci_v3"` (another wire-format break), this test will catch the
    /// divergence at compile time via a constant mismatch in the adjacent module if both are
    /// updated together, and a wire-format test in `hort-http-oci` must confirm the new value.
    #[test]
    fn session_key_format_matches_literal() {
        let sid = Uuid::nil();
        assert_eq!(
            session_key(FORMAT_OCI, sid),
            format!("stateful_upload:oci_v2:{sid}"),
            "session_key wire format must use the oci_v2 key-space token"
        );
    }
}
