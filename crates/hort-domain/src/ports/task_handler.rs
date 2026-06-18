//! Outbound port for the cross-kind task framework.
//!
//! A [`TaskHandler`] is a stateless strategy registered under a `kind()` literal
//! in the worker's dispatch table. The worker looks up the handler by kind, calls
//! [`TaskHandler::run`] with per-invocation request data, and persists the
//! returned [`TaskOutcome`] to the `jobs` table.
//!
//! Shared dependencies (use cases, other ports) are injected into each handler
//! at composition time via its constructor — they MUST NOT appear in
//! [`TaskContext`], which carries only per-invocation request data.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::events::Actor;
use crate::ports::jobs_repository::JobRow;

use super::BoxFuture;

/// Maximum byte length of `TaskOutcome::Failed.reason`.
///
/// The dispatcher writes `reason` to `jobs.result_summary JSONB`. A 4 KiB cap
/// prevents unbounded column growth from pathological error messages while
/// still accommodating full stack-trace summaries in practice.
pub const REASON_MAX_BYTES: usize = 4096;

/// Per-invocation request data passed to every [`TaskHandler::run`] call.
///
/// Handlers MUST NOT store this beyond the duration of `run()`. Shared
/// dependencies (use cases, ports) are injected at handler construction, not
/// here.
#[derive(Debug, Clone)]
pub struct TaskContext {
    /// The primary key of the `jobs` row for this invocation.
    pub task_job_id: Uuid,
    /// Actor who triggered the task (system timer, API user, CronJob, etc.).
    pub actor: Actor,
    /// Correlation ID for distributed tracing / log correlation.
    pub correlation_id: Uuid,
    /// The full `jobs` row as it was when the dispatcher claimed it.
    ///
    /// Handlers that need scan-specific typed columns (`artifact_id`,
    /// `repository_id`, `content_hash`, `format`) read them from this
    /// field rather than re-querying the database. The row is
    /// post-claim — `status = 'running'` and `attempts` is already
    /// incremented.
    pub job_row: JobRow,
}

/// Outcome of a single [`TaskHandler::run`] invocation.
///
/// Serialised to `jobs.result_summary JSONB` by the dispatcher.
/// The `#[serde(tag = "outcome")]` discriminant makes the DB row self-describing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TaskOutcome {
    /// The task completed successfully. `result_summary` is an arbitrary JSON
    /// object the handler populates (counts, file paths, metric deltas, etc.).
    Completed { result_summary: serde_json::Value },

    /// The task failed. `reason` is a human-readable description (capped at
    /// [`REASON_MAX_BYTES`]). `retry` signals whether the dispatcher should
    /// schedule a re-run; transient I/O errors set `retry = true`, invariant
    /// violations set `retry = false`.
    Failed { reason: String, retry: bool },
}

impl TaskOutcome {
    /// Construct a `Failed` variant, truncating `reason` to [`REASON_MAX_BYTES`]
    /// bytes if the input is longer.
    ///
    /// Truncation is byte-boundary-safe: the cap is applied to the UTF-8
    /// byte representation. If the cap falls inside a multi-byte codepoint, the
    /// truncation point is moved back to the nearest valid UTF-8 boundary, so
    /// the stored string is always valid UTF-8.
    pub fn fail(reason: impl Into<String>, retry: bool) -> Self {
        let r = reason.into();
        let truncated = if r.len() > REASON_MAX_BYTES {
            let mut boundary = REASON_MAX_BYTES;
            while boundary > 0 && !r.is_char_boundary(boundary) {
                boundary -= 1;
            }
            r[..boundary].to_owned()
        } else {
            r
        };
        Self::Failed {
            reason: truncated,
            retry,
        }
    }
}

/// Outbound port for a named, runnable task.
///
/// Implementations are registered in the worker's dispatch table keyed on
/// [`TaskHandler::kind`]. The kind string MUST be non-empty,
/// lowercase, and use hyphens as word separators (e.g. `"staging-sweep"`,
/// `"cron-rescan-tick"`).
///
/// # Dyn-compatibility
///
/// The trait is object-safe: `Arc<dyn TaskHandler>` is valid and is the
/// expected registration type in the dispatch table. The async `run` method
/// returns a [`BoxFuture`] (a pinned, boxed, `Send` future) rather than using
/// `async fn`, which would not be dyn-compatible.
pub trait TaskHandler: Send + Sync {
    /// Stable kind identifier for this handler (e.g. `"staging-sweep"`).
    ///
    /// Must be non-empty, lowercase, hyphen-separated. The worker dispatch
    /// table is keyed on this value; returning different values across calls
    /// is an invariant violation.
    fn kind(&self) -> &'static str;

    /// Execute the task.
    ///
    /// `params` is the raw JSON from `jobs.params` — handler-defined schema.
    /// `ctx` carries per-invocation request data.
    ///
    /// Returns [`TaskOutcome::Completed`] on success or
    /// [`TaskOutcome::Failed`] on recoverable / unrecoverable failure. Panics
    /// inside this method are caught by the worker and recorded as
    /// `Failed { retry: false }`.
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::events::{Actor, InternalActor, InternalActorToken};
    use crate::ports::jobs_repository::JobRow;

    // -----------------------------------------------------------------------
    // Dyn-compatibility compile check
    // -----------------------------------------------------------------------

    fn _task_handler_is_dyn_compatible() {
        let _: Option<Arc<dyn TaskHandler>> = None;
    }

    // -----------------------------------------------------------------------
    // TaskOutcome — Debug, Clone, PartialEq
    // -----------------------------------------------------------------------

    #[test]
    fn task_outcome_completed_debug_clone_partialeq() {
        let summary = serde_json::json!({ "deleted": 3 });
        let a = TaskOutcome::Completed {
            result_summary: summary.clone(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        // Debug must not panic
        let _ = format!("{a:?}");
    }

    #[test]
    fn task_outcome_failed_debug_clone_partialeq() {
        let a = TaskOutcome::Failed {
            reason: "disk full".into(),
            retry: true,
        };
        let b = a.clone();
        assert_eq!(a, b);
        let _ = format!("{a:?}");
    }

    #[test]
    fn task_outcome_completed_ne_failed() {
        let completed = TaskOutcome::Completed {
            result_summary: serde_json::Value::Null,
        };
        let failed = TaskOutcome::Failed {
            reason: String::new(),
            retry: false,
        };
        assert_ne!(completed, failed);
    }

    // -----------------------------------------------------------------------
    // TaskOutcome::fail — truncation behaviour
    // -----------------------------------------------------------------------

    #[test]
    fn fail_short_reason_preserved_verbatim() {
        let outcome = TaskOutcome::fail("short error", false);
        match outcome {
            TaskOutcome::Failed { reason, retry } => {
                assert_eq!(reason, "short error");
                assert!(!retry);
            }
            _ => panic!("expected Failed variant"),
        }
    }

    #[test]
    fn fail_reason_at_exact_cap_preserved_verbatim() {
        // A reason of exactly REASON_MAX_BYTES ASCII bytes must NOT be truncated.
        let at_cap = "x".repeat(REASON_MAX_BYTES);
        assert_eq!(at_cap.len(), REASON_MAX_BYTES);
        let outcome = TaskOutcome::fail(at_cap.clone(), false);
        match outcome {
            TaskOutcome::Failed { reason, retry: _ } => {
                assert_eq!(reason.len(), REASON_MAX_BYTES);
                assert_eq!(reason, at_cap);
            }
            _ => panic!("expected Failed variant"),
        }
    }

    #[test]
    fn fail_reason_one_over_cap_is_truncated_to_cap() {
        // A reason of REASON_MAX_BYTES + 1 ASCII bytes must be truncated to REASON_MAX_BYTES.
        let over = "x".repeat(REASON_MAX_BYTES + 1);
        let outcome = TaskOutcome::fail(over, true);
        match outcome {
            TaskOutcome::Failed { reason, retry } => {
                assert_eq!(reason.len(), REASON_MAX_BYTES);
                assert!(retry);
            }
            _ => panic!("expected Failed variant"),
        }
    }

    #[test]
    fn fail_truncation_is_valid_utf8() {
        // Build a string where the cap falls inside a multi-byte codepoint.
        // '€' is U+20AC encoded as 3 UTF-8 bytes (0xE2 0x82 0xAC).
        // Pad with ASCII 'a' up to REASON_MAX_BYTES - 1, then append '€'.
        // That pushes the total to REASON_MAX_BYTES + 2 bytes, straddling
        // the cap at byte REASON_MAX_BYTES - 1 (inside the 3-byte sequence).
        let mut s = "a".repeat(REASON_MAX_BYTES - 1);
        s.push('€'); // adds 3 bytes → total = REASON_MAX_BYTES + 2
        assert!(s.len() > REASON_MAX_BYTES);

        let outcome = TaskOutcome::fail(s, false);
        match outcome {
            TaskOutcome::Failed { reason, .. } => {
                // Must be strictly less than REASON_MAX_BYTES because the
                // boundary was retracted to avoid a mid-codepoint cut.
                assert!(reason.len() < REASON_MAX_BYTES);
            }
            _ => panic!("expected Failed variant"),
        }
    }

    // -----------------------------------------------------------------------
    // TaskOutcome — serde round-trip (both variants)
    // -----------------------------------------------------------------------

    #[test]
    fn task_outcome_completed_serde_round_trip() {
        let original = TaskOutcome::Completed {
            result_summary: serde_json::json!({ "count": 42, "ok": true }),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        // The `outcome` tag must appear in the JSON
        assert!(json.contains("\"outcome\":\"completed\""));
        let deserialized: TaskOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, deserialized);
    }

    #[test]
    fn task_outcome_failed_serde_round_trip() {
        let original = TaskOutcome::Failed {
            reason: "network timeout".into(),
            retry: true,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(json.contains("\"outcome\":\"failed\""));
        let deserialized: TaskOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, deserialized);
    }

    // -----------------------------------------------------------------------
    // TaskContext — Debug and Clone
    // -----------------------------------------------------------------------

    fn make_actor() -> Actor {
        Actor::Internal(InternalActor::system(InternalActorToken(())))
    }

    fn test_job_row(kind: &str) -> JobRow {
        use crate::ports::jobs_repository::{JobStatus, KindFields};
        use chrono::{DateTime, Utc};
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        JobRow {
            id: Uuid::new_v4(),
            kind: kind.to_string(),
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

    #[test]
    fn task_context_debug_and_clone() {
        let ctx = TaskContext {
            task_job_id: Uuid::new_v4(),
            actor: make_actor(),
            correlation_id: Uuid::new_v4(),
            job_row: test_job_row("noop-test"),
        };
        let cloned = ctx.clone();
        assert_eq!(ctx.task_job_id, cloned.task_job_id);
        assert_eq!(ctx.correlation_id, cloned.correlation_id);
        // Debug must not panic
        let _ = format!("{ctx:?}");
    }

    // -----------------------------------------------------------------------
    // Representative TaskHandler impl — dyn dispatch smoke test
    // -----------------------------------------------------------------------

    struct NoopTaskHandler;

    impl TaskHandler for NoopTaskHandler {
        fn kind(&self) -> &'static str {
            "noop-test"
        }

        fn run<'a>(
            &'a self,
            _params: &'a serde_json::Value,
            _ctx: TaskContext,
        ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
            Box::pin(async {
                Ok(TaskOutcome::Completed {
                    result_summary: serde_json::Value::Null,
                })
            })
        }
    }

    #[test]
    fn noop_handler_kind_is_nonempty() {
        let h = NoopTaskHandler;
        assert_eq!(h.kind(), "noop-test");
    }

    #[tokio::test]
    async fn noop_handler_run_through_dyn_ref_returns_completed() {
        let handler: Arc<dyn TaskHandler> = Arc::new(NoopTaskHandler);
        let ctx = TaskContext {
            task_job_id: Uuid::new_v4(),
            actor: make_actor(),
            correlation_id: Uuid::new_v4(),
            job_row: test_job_row("noop-test"),
        };
        let params = serde_json::Value::Null;
        let result = handler.run(&params, ctx).await.expect("run succeeded");
        assert!(matches!(result, TaskOutcome::Completed { .. }));
    }
}
