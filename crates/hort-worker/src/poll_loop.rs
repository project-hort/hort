//! M12 alerting metric — unit tests only.
//!
//! The `hort_scan_record_outcome_failures_total` counter is emitted when
//! `ScanOrchestrationUseCase::record_outcome` itself fails (i.e. the DB
//! write that transitions the job row to `completed` / `pending` / `failed`
//! returns an error). This is distinct from a job failing its scan — it
//! means the orchestrator could not persist the outcome of a scan that
//! already ran.
//!
//! The scan-specific poll loop (`run` / `process_one_batch` /
//! `run_with_drain_deadline`) is replaced by the generalised
//! [`hort_app::task_dispatcher::TaskDispatcher`] wired in `composition.rs`
//! and driven from `main.rs`
//! (see `how-to/using-hort-cli-with-admin-ops.md`). This module retains
//! only the M12 alerting helper (`emit_failed_branch_alert`) and its unit
//! tests.

#[cfg(test)]
mod tests {
    /// Metric name for the M12 alerting counter.
    /// See `docs/metrics-catalog.md`.
    const M12_RECORD_OUTCOME_FAILURES: &str = "hort_scan_record_outcome_failures_total";

    /// Sentinel for `scanner` label when M12 fires from the Failed-branch path.
    const M12_SCANNER_NONE: &str = "(none)";

    /// Sentinel for `result` label when M12 fires after a Failed-branch
    /// `record_outcome` invocation that itself errored.
    const M12_RESULT_FAILED_BRANCH: &str = "failed_branch";

    /// Log the failure and increment the M12 alerting counter when
    /// `record_outcome(&job, ScanRunOutcome::Failed(_))` itself returns
    /// `Err`.
    fn emit_failed_branch_alert<E: std::fmt::Display>(error: &E, job_id: Uuid, artifact_id: Uuid) {
        tracing::error!(
            error = %error,
            %job_id,
            %artifact_id,
            "record_outcome (Failed branch) failed",
        );
        metrics::counter!(
            M12_RECORD_OUTCOME_FAILURES,
            "result" => M12_RESULT_FAILED_BRANCH,
            "scanner" => M12_SCANNER_NONE,
        )
        .increment(1);
    }

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};
    use std::collections::HashMap;
    use uuid::Uuid;

    /// Walk a `DebuggingRecorder` snapshot and return the counter
    /// value for `(name, exact label-set)`. `0` when absent.
    fn counter_value(
        snap: &[(
            CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        metric_name: &str,
        label_kvs: &[(&str, &str)],
    ) -> u64 {
        for (key, _u, _d, value) in snap {
            if key.kind() != MetricKind::Counter {
                continue;
            }
            if key.key().name() != metric_name {
                continue;
            }
            let got: HashMap<String, String> = key
                .key()
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            let labels_match = label_kvs
                .iter()
                .all(|(k, v)| got.get(*k).is_some_and(|g| g == v))
                && got.len() == label_kvs.len();
            if labels_match {
                if let DebugValue::Counter(v) = value {
                    return *v;
                }
            }
        }
        0
    }

    /// M12: `emit_failed_branch_alert` increments
    /// `hort_scan_record_outcome_failures_total` with labels
    /// `{result="failed_branch", scanner="(none)"}` exactly once
    /// per call.
    #[test]
    fn emit_failed_branch_alert_increments_record_outcome_failures_total() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let err = "synthetic record_outcome failure";
            emit_failed_branch_alert(&err, Uuid::nil(), Uuid::nil());
        });
        let snap = snapshotter.snapshot().into_vec();
        let v = counter_value(
            &snap,
            M12_RECORD_OUTCOME_FAILURES,
            &[
                ("result", M12_RESULT_FAILED_BRANCH),
                ("scanner", M12_SCANNER_NONE),
            ],
        );
        assert_eq!(
            v, 1,
            "exactly one increment per failed-branch record_outcome error"
        );
    }

    /// M12: repeated calls accumulate — counter semantics, not gauge.
    #[test]
    fn emit_failed_branch_alert_accumulates_across_calls() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            for _ in 0..3 {
                emit_failed_branch_alert(&"err", Uuid::nil(), Uuid::nil());
            }
        });
        let snap = snapshotter.snapshot().into_vec();
        let v = counter_value(
            &snap,
            M12_RECORD_OUTCOME_FAILURES,
            &[
                ("result", M12_RESULT_FAILED_BRANCH),
                ("scanner", M12_SCANNER_NONE),
            ],
        );
        assert_eq!(v, 3, "three calls must produce a counter value of 3");
    }
}
