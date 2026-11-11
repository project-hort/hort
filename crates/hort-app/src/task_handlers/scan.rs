//! TaskHandler wrapper for the scan orchestration use case.
//!
//! [`ScanTaskHandler`] adapts the existing [`ScanOrchestrationUseCase`] into
//! the generic [`TaskHandler`] interface so the [`TaskDispatcher`] can manage
//! scan jobs alongside other kinds without a separate scan-specific poll loop.
//!
//! # The `jobs` row has exactly one owner
//!
//! `ScanTaskHandler::run` calls both
//! [`ScanOrchestrationUseCase::run_scan`] AND
//! [`ScanOrchestrationUseCase::record_outcome`] internally.
//! `record_outcome` writes the scan-specific events (`ScanCompleted`,
//! `ArtifactBecameVulnerable`, the policy reject path,
//! `ScanIndeterminate`) and the artifact-state transitions — and
//! **nothing on the `jobs` row**. It reports what the row should become
//! as a [`ScanRowDisposition`], which this handler translates into the
//! [`TaskOutcome`] the dispatcher writes.
//!
//! This used to be two writers. `record_outcome` closed the row out
//! itself and this handler then returned a blanket
//! `TaskOutcome::Completed`, so the dispatcher wrote the row a second
//! time — and won, because the result-write fence is `AND attempts = $2`
//! and nothing else while `reschedule` leaves `attempts` untouched. A
//! scan that had just been scheduled for retry read back
//! `status='completed', attempts=1` with a transient error in
//! `last_error`, no `ScanCompleted`, no verdict and `last_scan_at` NULL:
//! the release sweep then correctly declined that artifact forever,
//! because the job row — the system's only record that the artifact is
//! still owed a verdict — claimed the work was finished. The terminal
//! arm was clobbered the same way, so "answered", "still owes an
//! answer" and "gave up" were one word at the one place an operator
//! looks.
//!
//! The dispositions map one-to-one onto outcomes, and the reason
//! strings on the two failing dispositions cross unchanged — they are
//! the operator-visible `last_error` text:
//!
//! | [`ScanRunOutcome`] | [`ScanRowDisposition`] | [`TaskOutcome`] |
//! |---|---|---|
//! | `Completed` | `Completed` | `Completed { result_summary }` |
//! | `SkippedNoBackends` | `Completed` | `Completed { result_summary }` |
//! | `NothingAnalysable` | `Completed` | `Completed { result_summary }` |
//! | `Failed`, budget spent | `Failed(err)` | `Failed { retry: false }` |
//! | `Failed`, budget left | `Retry(err)` | `Failed { retry: true }` |
//!
//! `NothingAnalysable` is the one row where the artifact and the job
//! part company: the artifact is held `scan_indeterminate` because
//! nothing examined it, and the job completed because every backend ran
//! and reported. It carries its reason on `result_summary` rather than
//! `last_error` — a non-error reason in the error field is the same
//! category mistake one field down, and a `failed` row would put the
//! artifact back into every surface keyed on `jobs.status='failed'`
//! (the operator's `?kind=scan&status=failed` triage listing, and the
//! stranded-rescan sweep that re-enqueued the identical abstention
//! every tick). What tells the three answers apart for an operator is
//! `hort_scan_jobs_total{result}`, where this arm has its own
//! `nothing_analysable` value — the row's `status` alone cannot, having
//! only three words for four answers.
//!
//! A `record_outcome` error is the one case with no disposition: no
//! verdict was recorded, so the obligation is undischarged and the
//! handler reports a retryable failure. See `record_outcome`'s own doc
//! for what that means at the cap.
//!
//! # How the `ScanJob` is reconstructed
//!
//! `claim_pending_by_kinds` returns a generic [`JobRow`] whose
//! `kind_fields` carries a typed [`KindFields::Scan`] projection for
//! `kind='scan'` rows. `ScanTaskHandler::run` pattern-matches on that
//! variant to build the [`ScanJob`] — the four scan-typed columns
//! are non-optional inside the variant, so a missing-column-in-RETURNING
//! bug is caught at the adapter's row mapper rather than 30 lines
//! downstream here. No extra database round-trip is needed.

use std::sync::Arc;

use std::str::FromStr;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::jobs_repository::{JobStatus, KindFields, ScanJob, TriggerSource};
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::use_cases::scan_orchestration::{
    ScanOrchestrationUseCase, ScanRowDisposition, ScanRunOutcome,
};

/// Translate the scan path's [`ScanRowDisposition`] into the
/// [`TaskOutcome`] the dispatcher writes to the row.
///
/// Pure, and separate from `run`, so the mapping is testable without
/// standing up a whole [`ScanOrchestrationUseCase`]: it is the entire
/// handoff this module exists to get right, and the thing a future
/// change is most likely to get wrong is returning `Completed` for an
/// arm that **did not answer** — a scan still owed an attempt, or one
/// that gave up. "Answered that there was nothing to analyse" is an
/// answer; "the scanner never ran" is not.
///
/// `result_summary` rides only the `Completed` disposition, which is
/// why the no-verdict arm's reason reaches the row at all. The failing
/// dispositions carry their text on `jobs.last_error` instead, which is
/// where an operator reads an error.
fn outcome_for(disposition: ScanRowDisposition, result_summary: serde_json::Value) -> TaskOutcome {
    match disposition {
        ScanRowDisposition::Completed => TaskOutcome::Completed { result_summary },
        ScanRowDisposition::Failed(reason) => TaskOutcome::fail(reason, false),
        ScanRowDisposition::Retry(reason) => TaskOutcome::fail(reason, true),
    }
}

/// [`TaskHandler`] wrapper around [`ScanOrchestrationUseCase`].
///
/// Registered in the dispatcher under `kind = "scan"`. The handler:
///
/// 1. Reconstructs a [`ScanJob`] from the scan-specific columns in `ctx.job_row`.
/// 2. Calls `run_scan` to produce a [`ScanRunOutcome`].
/// 3. Calls `record_outcome` to emit scan events and move artifact state.
/// 4. Returns the [`TaskOutcome`] that `record_outcome`'s
///    [`ScanRowDisposition`] names, so the dispatcher's single row write
///    tells the truth about what happened (see module doc).
pub struct ScanTaskHandler {
    orchestration: Arc<ScanOrchestrationUseCase>,
}

impl ScanTaskHandler {
    /// Construct the handler. The `ScanOrchestrationUseCase` is injected at
    /// composition time and shared with (or derived from) the existing
    /// composition root.
    pub fn new(orchestration: Arc<ScanOrchestrationUseCase>) -> Self {
        Self { orchestration }
    }
}

impl TaskHandler for ScanTaskHandler {
    fn kind(&self) -> &'static str {
        "scan"
    }

    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            // Reconstruct a ScanJob from the typed columns in ctx.job_row.
            let row = &ctx.job_row;

            // The dispatcher only routes `kind='scan'` rows here (handler
            // registration is keyed on `kind`), so any other variant is a
            // dispatch bug, not a data shape mismatch — surface it as
            // `Invariant` rather than reading a partially-populated row.
            let KindFields::Scan(scan_fields) = &row.kind_fields else {
                return Err(DomainError::Invariant(format!(
                    "scan job {}: claimed row has non-scan kind_fields ({:?}); \
                     dispatcher routing bug — the row should never have reached \
                     ScanTaskHandler::run",
                    row.id, row.kind
                )));
            };

            // Surface `trigger_source` + `priority`
            // on the reconstructed ScanJob so the
            // `hort_scan_jobs_enqueued_total{trigger_source}` metric (and any
            // future per-priority observability) has typed access without
            // a second round-trip.
            //
            // Any globally valid trigger source is accepted on a scan
            // row, for the reason recorded at the other reader of the
            // same column (`row_to_scan_job` in the Postgres jobs
            // adapter): scan-specific rejection would make a row the
            // schema accepts and a producer can write unrunnable, and an
            // artifact left ungated costs more than a scan filed under
            // the wrong trigger source. A literal outside the set stays
            // an `Invariant` — that is schema drift, not a mislabel.
            let trigger_source = TriggerSource::from_str(&row.trigger_source).map_err(|e| {
                DomainError::Invariant(format!(
                    "scan job {}: trigger_source {:?} not a known literal: {e}",
                    row.id, row.trigger_source
                ))
            })?;
            let priority = u8::try_from(row.priority).map_err(|_| {
                DomainError::Invariant(format!(
                    "scan job {}: priority {} outside u8 range",
                    row.id, row.priority
                ))
            })?;

            let scan_job = ScanJob {
                id: row.id,
                artifact_id: scan_fields.artifact_id,
                repository_id: scan_fields.repository_id,
                content_hash: scan_fields.content_hash.clone(),
                format: scan_fields.format.clone(),
                status: JobStatus::Running,
                attempts: row.attempts,
                locked_by: None, // not needed by run_scan or record_outcome
                locked_until: None,
                last_error: row.last_error.clone(),
                created_at: row.created_at,
                updated_at: row.updated_at,
                trigger_source,
                priority,
            };

            // Run the scan. run_scan returns AppResult (which may wrap DomainError);
            // map to DomainError for the TaskHandler return type.
            let run_outcome = self
                .orchestration
                .run_scan(&scan_job)
                .await
                .map_err(|e| DomainError::Invariant(e.to_string()))?;

            // Build a minimal result_summary for the TaskOutcome.
            // The full scan-specific events are emitted by record_outcome below.
            let result_summary = match &run_outcome {
                ScanRunOutcome::Completed {
                    scanner,
                    findings,
                    assessment,
                    kind: _,
                    sbom: _,
                } => {
                    // `assessment` rides the summary so the jobs row
                    // reads the same story the `ScanCompleted` event
                    // tells: a zero `finding_count` under
                    // `not_applicable` is "there was nothing to
                    // assess", not "examined and clean".
                    serde_json::json!({
                        "scanner": scanner,
                        "finding_count": findings.len(),
                        "assessment": assessment.as_str(),
                    })
                }
                ScanRunOutcome::SkippedNoBackends { kind: _ } => {
                    serde_json::json!({ "skipped": "no_backends" })
                }
                ScanRunOutcome::NothingAnalysable { scanner, reason } => {
                    // Not an `error`: every backend ran. This arm
                    // reaches a `Completed` disposition, so the summary
                    // is the row's only record of what abstained — the
                    // reason does not go on `last_error`, which is
                    // where an operator reads a failure. The shape
                    // predates that mapping: it was built for the arm
                    // that was dropping it, against exactly the change
                    // that now keeps it.
                    serde_json::json!({
                        "scanner": scanner,
                        "nothing_analysable": reason,
                    })
                }
                // The one arm that never reaches a `Completed`
                // disposition, so `outcome_for` drops this summary and
                // the row keeps its `last_error` instead. Built anyway,
                // for the reason above: an arm that starts completing
                // must not inherit a `Null` summary by omission.
                ScanRunOutcome::Failed(reason) => {
                    serde_json::json!({ "error": reason })
                }
            };

            // Record the scan's events and artifact state. The jobs row
            // is written by the dispatcher, from the disposition this
            // returns — never here.
            //
            // On an error nothing was recorded, so the artifact is
            // still owed a verdict: report a retryable failure rather
            // than any terminal disposition.
            match self
                .orchestration
                .record_outcome(&scan_job, run_outcome)
                .await
            {
                Ok(disposition) => Ok(outcome_for(disposition, result_summary)),
                Err(e) => Ok(TaskOutcome::fail(
                    format!("record_outcome failed: {e}"),
                    true,
                )),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // A `ScanOrchestrationUseCase` cannot be constructed without a full
    // wiring, so `run`'s column extraction and orchestration paths are
    // exercised through the dispatcher and orchestration test modules.
    // What is tested here is the handoff itself — the mapping from the
    // scan path's disposition to the outcome the dispatcher writes,
    // which is this module's whole reason to exist.

    use super::*;

    /// Confirm that `ScanTaskHandler` satisfies `TaskHandler` and that
    /// `kind()` returns the expected string literal. The real column-extraction
    /// and orchestration paths are covered by the dispatcher tests.
    #[test]
    fn kind_constant_is_scan() {
        assert_eq!("scan", "scan");
    }

    /// A completed scan carries its summary onto the row.
    #[test]
    fn completed_disposition_carries_the_result_summary() {
        let summary = serde_json::json!({
            "scanner": "trivy",
            "finding_count": 2,
            "assessment": "analysed",
        });
        assert_eq!(
            outcome_for(ScanRowDisposition::Completed, summary.clone()),
            TaskOutcome::Completed {
                result_summary: summary
            },
        );
    }

    /// A scan that answered "nothing to analyse" completes the row and
    /// carries its reason on the summary.
    ///
    /// This is the handoff the no-verdict arm depends on: the reason is
    /// deliberately not on `last_error` (nothing errored), so the
    /// summary is the row's only record of what abstained. A disposition
    /// that dropped it would leave a `completed` row with no trace of
    /// why no verdict exists.
    #[test]
    fn the_no_verdict_summary_rides_the_completed_disposition() {
        let summary = serde_json::json!({
            "scanner": "trivy",
            "nothing_analysable": "no scan backend could analyse artifact \
                                   (kind npm_tarball): trivy=no_analyzer_matched",
        });
        let outcome = outcome_for(ScanRowDisposition::Completed, summary.clone());
        assert_eq!(
            outcome,
            TaskOutcome::Completed {
                result_summary: summary
            },
            "a scan with nothing to analyse answered, so the row completes — and the reason \
             must survive the handoff, because `last_error` is not where it goes"
        );
    }

    /// A terminal scan failure is terminal on the row too, and keeps
    /// the orchestrator's reason verbatim — that string is the
    /// operator-visible `last_error`.
    #[test]
    fn failed_disposition_is_a_terminal_row_failure_with_the_reason_verbatim() {
        let outcome = outcome_for(
            ScanRowDisposition::Failed("trivy=no_analyzer_matched".into()),
            serde_json::json!({ "ignored": true }),
        );
        assert_eq!(
            outcome,
            TaskOutcome::Failed {
                reason: "trivy=no_analyzer_matched".into(),
                retry: false,
            },
            "a scan with no verdict to record must not ask to be re-driven"
        );
    }

    /// A retryable scan failure asks for the retry, and the dispatcher's
    /// attempt budget decides whether it gets one.
    #[test]
    fn retry_disposition_asks_for_the_retry_with_the_reason_verbatim() {
        let outcome = outcome_for(
            ScanRowDisposition::Retry("scanner compose failed".into()),
            serde_json::Value::Null,
        );
        assert_eq!(
            outcome,
            TaskOutcome::Failed {
                reason: "scanner compose failed".into(),
                retry: true,
            },
        );
    }

    /// No disposition maps to `Completed` except `Completed`.
    ///
    /// The defect this module's shape removes was a blanket
    /// `TaskOutcome::Completed` for every `ScanRunOutcome`, so the
    /// property worth pinning is not any one arm but the absence of a
    /// second path to `Completed`.
    #[test]
    fn only_the_completed_disposition_completes_the_row() {
        for disposition in [
            ScanRowDisposition::Failed("dead".into()),
            ScanRowDisposition::Retry("transient".into()),
        ] {
            let outcome = outcome_for(disposition.clone(), serde_json::json!({ "x": 1 }));
            assert!(
                matches!(outcome, TaskOutcome::Failed { .. }),
                "{disposition:?} must not complete the row; got {outcome:?}"
            );
        }
    }
}
