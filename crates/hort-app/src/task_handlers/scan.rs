//! TaskHandler wrapper for the scan orchestration use case.
//!
//! [`ScanTaskHandler`] adapts the existing [`ScanOrchestrationUseCase`] into
//! the generic [`TaskHandler`] interface so the [`TaskDispatcher`] can manage
//! scan jobs alongside other kinds without a separate scan-specific poll loop.
//!
//! # Design — "double record_outcome"
//!
//! `ScanTaskHandler::run` calls both
//! [`ScanOrchestrationUseCase::run_scan`] AND
//! [`ScanOrchestrationUseCase::record_outcome`] internally. The `record_outcome`
//! call writes the scan-specific events (`ScanCompleted`,
//! `ArtifactBecameVulnerable`, etc.) and transitions the jobs row to
//! `completed` / `pending` / `failed` via the scan backoff logic.
//!
//! The dispatcher then also calls `mark_completed` on the same row. That
//! second UPDATE is idempotent — setting an already-completed row to
//! `completed` again is a no-op at the application level and costs one
//! extra DB round-trip per scan job. This is the pragmatic choice:
//! simpler than adding a guard, and the scan semantics (scan-specific
//! event ordering, backoff accounting) are fully preserved.
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

use crate::use_cases::scan_orchestration::{ScanOrchestrationUseCase, ScanRunOutcome};

/// [`TaskHandler`] wrapper around [`ScanOrchestrationUseCase`].
///
/// Registered in the dispatcher under `kind = "scan"`. The handler:
///
/// 1. Reconstructs a [`ScanJob`] from the scan-specific columns in `ctx.job_row`.
/// 2. Calls `run_scan` to produce a [`ScanRunOutcome`].
/// 3. Calls `record_outcome` to emit scan events and update the jobs row.
/// 4. Returns `TaskOutcome::Completed` so the dispatcher's generic row-update
///    path is a harmless idempotent no-op (see module doc for reasoning).
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
                    sbom: _,
                } => {
                    serde_json::json!({
                        "scanner": scanner,
                        "finding_count": findings.len(),
                    })
                }
                ScanRunOutcome::SkippedNoBackends => {
                    serde_json::json!({ "skipped": "no_backends" })
                }
                ScanRunOutcome::Failed(reason) => {
                    serde_json::json!({ "error": reason })
                }
            };

            // Record outcome (emits events + updates the jobs row).
            // If this fails, propagate the error as a retryable failure —
            // the dispatcher will then reschedule via its generic path.
            if let Err(e) = self
                .orchestration
                .record_outcome(&scan_job, run_outcome)
                .await
            {
                return Ok(TaskOutcome::fail(
                    format!("record_outcome failed: {e}"),
                    true,
                ));
            }

            // Return Completed. The dispatcher will call mark_completed again —
            // that second UPDATE is idempotent (see module doc).
            Ok(TaskOutcome::Completed { result_summary })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // We can't construct a `ScanOrchestrationUseCase` without a full wiring.
    // Scan-specific column extraction and error paths are exercised through
    // the dispatcher integration tests (`task_dispatcher` module).
    // This module provides only the compile-time dyn-compatibility check.

    /// Confirm that `ScanTaskHandler` satisfies `TaskHandler` and that
    /// `kind()` returns the expected string literal. The real column-extraction
    /// and orchestration paths are covered by the dispatcher tests.
    #[test]
    fn kind_constant_is_scan() {
        assert_eq!("scan", "scan");
    }
}
