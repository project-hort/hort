//! Bounded, honest waiting for a task job to reach a terminal state.
//!
//! Reads the job the same way `hort-cli admin task get` does — `GET
//! /api/v1/admin/tasks/<id>`, deserialised into the shared
//! [`TaskRow`] — and polls until the job is terminal or the wait window
//! expires.
//!
//! The window expiring is **not** a failure of the job and must never be
//! reported as one, nor silently swallowed: the caller gets
//! [`WaitOutcome::TimedOut`] carrying the last status the CLI actually
//! observed, and tells the operator the job id to read later. The one
//! thing this module must never do is let a caller report a result the
//! CLI did not see.

use std::time::Duration;

use anyhow::Result;
use tokio::time::Instant;

use crate::admin::TaskRow;
use crate::client::AkClient;

/// Job statuses the task framework can still move out of. Everything
/// else — `completed`, `failed`, and any status a future server adds —
/// is treated as terminal, so an unknown terminal state surfaces
/// immediately instead of burning the whole wait window.
const NON_TERMINAL_STATUSES: &[&str] = &["pending", "running"];

/// How long to wait, and how often to look.
#[derive(Debug, Clone, Copy)]
pub struct WaitConfig {
    pub timeout: Duration,
    pub interval: Duration,
}

/// What the wait saw.
#[derive(Debug, Clone)]
pub enum WaitOutcome {
    /// The job reached a terminal state inside the window.
    Terminal(Box<TaskRow>),
    /// The window expired first. The job is still running server-side.
    TimedOut {
        job_id: String,
        /// The last status the CLI actually observed. A read that fails
        /// is an error, not a timeout, so by the time this is built at
        /// least one status has been seen.
        last_status: String,
    },
}

/// `true` when `status` is one the job can still leave.
pub fn is_non_terminal(status: &str) -> bool {
    NON_TERMINAL_STATUSES.contains(&status)
}

/// Poll `job_id` until it is terminal or `cfg.timeout` elapses.
///
/// Always performs at least one read, so a zero timeout still reports
/// what the job looked like rather than nothing at all.
pub async fn wait_for_terminal(
    client: &AkClient,
    job_id: &str,
    cfg: WaitConfig,
) -> Result<WaitOutcome> {
    let deadline = Instant::now() + cfg.timeout;
    let path = format!("/api/v1/admin/tasks/{job_id}");

    loop {
        let row: TaskRow = client.get(&path).await?;
        if !is_non_terminal(&row.status) {
            return Ok(WaitOutcome::Terminal(Box::new(row)));
        }

        let now = Instant::now();
        if now >= deadline {
            return Ok(WaitOutcome::TimedOut {
                job_id: job_id.to_string(),
                last_status: row.status,
            });
        }
        // Never sleep past the deadline: the last poll should land as
        // close to it as possible rather than one whole interval late.
        let remaining = deadline.saturating_duration_since(now);
        tokio::time::sleep(cfg.interval.min(remaining)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_and_running_are_the_only_non_terminal_statuses() {
        assert!(is_non_terminal("pending"));
        assert!(is_non_terminal("running"));
        assert!(!is_non_terminal("completed"));
        assert!(!is_non_terminal("failed"));
    }

    #[test]
    fn an_unknown_status_is_treated_as_terminal() {
        // A future server adding a terminal status must surface it, not
        // make the CLI spin out its whole wait window against a job that
        // is already finished.
        assert!(!is_non_terminal("cancelled"));
    }
}
