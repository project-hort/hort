//! The one place a refused result write is surfaced.
//!
//! Two consumers close a `jobs` row out — [`crate::task_dispatcher`],
//! for every registered kind, and
//! [`crate::use_cases::scan_orchestration`]'s `record_outcome`, for
//! `kind='scan'` — and both reach the same three fenced writes
//! (`JobsRepository::{mark_completed, reschedule, mark_failed}`). Each
//! returns a [`ResultWriteOutcome`] rather than `()`, because a row can
//! be executed twice: the abandoned-lease sweep hands a stalled row on,
//! a sibling claims it, and the original worker may still come back
//! with a result. The fence refuses that result; this module is what
//! keeps the refusal from being silent, in one shape across the ten
//! call sites instead of ten hand-written log lines that drift.
//!
//! **No metric here.** A refusal is the tail of an event that is
//! already counted: the sweep's `hort_admin_tasks_lease_requeued_total`
//! records the handover, and
//! `hort_admin_tasks_lease_renew_failed_total{result="lost"}` records
//! the in-process early-out when a renewal happened to observe it
//! first. A third counter over the same incident gives an operator
//! nothing to do that those two do not already prompt. What the log
//! line adds is the pair of identities — which execution wrote and
//! which one holds the row — and that belongs in a record with the job
//! id on it, not in a counter's labels.

use hort_domain::error::DomainResult;
use hort_domain::ports::jobs_repository::ResultWriteOutcome;
use uuid::Uuid;

/// Log a result write the fence refused.
///
/// `write` names the method (`"mark_completed"` / `"reschedule"` /
/// `"mark_failed"`) and `attempt` is the identity the caller wrote
/// under, so the line names both ends of the fence.
///
/// Returns whether the result landed, so a caller with something to
/// decide can branch on it and a test can pin the classification
/// without standing up a `tracing` subscriber. Today's callers have
/// nothing to decide: the handler's side effects are already done, this
/// layer cannot unwind them, and the row's state belongs to whoever
/// holds it now.
pub(crate) fn surface_result_write(
    outcome: ResultWriteOutcome,
    write: &'static str,
    job_id: Uuid,
    kind: &str,
    attempt: u32,
) -> bool {
    match outcome {
        ResultWriteOutcome::Applied => true,
        ResultWriteOutcome::Superseded { current_attempt } => {
            tracing::warn!(
                %job_id,
                kind,
                write,
                attempt,
                current_attempt,
                "discarded this execution's result: the row has moved on to a later \
                 execution, so the write was refused rather than put over work that may \
                 still be in flight. The abandoned-lease sweep handed this row on while \
                 the handler was running",
            );
            false
        }
        ResultWriteOutcome::RowGone => {
            tracing::warn!(
                %job_id,
                kind,
                write,
                attempt,
                "discarded this execution's result: the row no longer exists, so there was \
                 nothing to write it to. Only a terminal row is ever deleted, and only past \
                 a retention horizon",
            );
            false
        }
    }
}

/// [`surface_result_write`] for a caller that logs a failed write
/// rather than propagating it — the dispatcher, whose poll loop has to
/// survive a database flap, where the scan orchestrator propagates so
/// the row stays retryable.
///
/// Folding the error arm in here is what keeps the dispatcher's four
/// write sites two lines each; written out per site it was the same
/// fourteen-line match four times over, three of whose error arms said
/// nothing beyond the method's own name.
pub(crate) fn surface_attempted_result_write(
    result: DomainResult<ResultWriteOutcome>,
    write: &'static str,
    job_id: Uuid,
    kind: &str,
    attempt: u32,
) -> bool {
    match result {
        Ok(outcome) => surface_result_write(outcome, write, job_id, kind, attempt),
        Err(e) => {
            tracing::error!(
                error = %e,
                %job_id,
                kind,
                write,
                attempt,
                "TaskDispatcher: the result write did not reach the database. The row keeps \
                 the state it has — it stays 'running' until the abandoned-lease sweep \
                 recovers it, and only for a kind that sweep covers",
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    fn job_id() -> Uuid {
        JOB.parse().expect("static valid uuid")
    }

    /// A write the row took is not a refusal: nothing is logged and the
    /// caller is told the result landed.
    #[test]
    fn an_applied_write_reports_that_the_result_landed() {
        assert!(surface_result_write(
            ResultWriteOutcome::Applied,
            "mark_completed",
            job_id(),
            "scan",
            2,
        ));
    }

    /// A write that never reached the database is not a landed result
    /// either — the row keeps whatever state it had.
    #[test]
    fn a_failed_write_reports_that_the_result_did_not_land() {
        assert!(!surface_attempted_result_write(
            Err(hort_domain::error::DomainError::Invariant("boom".into())),
            "mark_completed",
            job_id(),
            "scan",
            2,
        ));
        assert!(surface_attempted_result_write(
            Ok(ResultWriteOutcome::Applied),
            "mark_completed",
            job_id(),
            "scan",
            2,
        ));
    }

    /// Both refusals report the result as NOT landed. The distinction
    /// between them lives in the log line, not in the answer — a caller
    /// that branched differently on "someone else holds it" and "it is
    /// gone" would be unwinding work it cannot unwind either way.
    #[test]
    fn both_refusals_report_that_the_result_did_not_land() {
        assert!(!surface_result_write(
            ResultWriteOutcome::Superseded { current_attempt: 3 },
            "reschedule",
            job_id(),
            "scan",
            2,
        ));
        assert!(!surface_result_write(
            ResultWriteOutcome::RowGone,
            "mark_failed",
            job_id(),
            "staging-sweep",
            2,
        ));
    }
}
