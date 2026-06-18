//! Sliding-window failure budget for one subscription.
//!
//! 100 consecutive failures across a 1h window → transition the
//! subscription to `Disabled { reason: DeliveryFailureBudgetExhausted }`.
//! First successful delivery resets the counter.
//!
//! Implemented as a small ring buffer of failure timestamps.
//! [`FailureBudget::record_failure`] appends and ages out entries older
//! than the window. [`FailureBudget::record_success`] clears the buffer
//! (mirrors the design's "budget resets on first successful delivery"
//! wording).
//!
//! # Test seam
//!
//! Both public methods take an explicit [`Instant`] so unit tests can
//! drive the time axis deterministically. Production callers pass
//! [`Instant::now()`]; tests pass `start + Duration::from_secs(_)`
//! arithmetic to exercise the eviction path without sleeping.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Window over which consecutive failures count toward the budget.
const WINDOW: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Threshold of failures within [`WINDOW`] that triggers
/// `DeliveryFailureBudgetExhausted`.
const THRESHOLD: usize = 100;

/// Sliding-window failure tracker for one subscription's dispatcher task.
///
/// The tracker is purely in-memory — failure history is per-task, not
/// persisted. Restarting the dispatcher resets every budget. This is
/// deliberate: the failure budget is a best-effort throttle, not a
/// durable SLA. Operators monitoring the disable signal see the
/// `SubscriptionDisabled` event in the audit stream regardless.
pub struct FailureBudget {
    /// Timestamps of consecutive failures within the current window.
    /// Bounded length = [`THRESHOLD`] — we don't care about more than
    /// 100 failures in a window; the 100th is the disable trigger and
    /// nothing past it is retained.
    failures: VecDeque<Instant>,
}

impl Default for FailureBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl FailureBudget {
    /// Construct an empty budget.
    pub fn new() -> Self {
        Self {
            failures: VecDeque::with_capacity(THRESHOLD + 1),
        }
    }

    /// Record a delivery failure observed at `now`. Returns `true` when
    /// the budget is exhausted — the caller transitions the
    /// subscription to `Disabled`.
    pub fn record_failure(&mut self, now: Instant) -> bool {
        self.evict_aged(now);
        self.failures.push_back(now);
        self.failures.len() >= THRESHOLD
    }

    /// Record a delivery success — clears the failure window.
    pub fn record_success(&mut self) {
        self.failures.clear();
    }

    /// Current count after eviction at `now`. Used by the dispatcher to
    /// populate [`SubscriptionFailure::consecutive_failures`] (the
    /// audit-visible counter on the row) and by tests to assert the
    /// eviction semantics.
    pub fn count_at(&mut self, now: Instant) -> usize {
        self.evict_aged(now);
        self.failures.len()
    }

    fn evict_aged(&mut self, now: Instant) {
        while let Some(front) = self.failures.front() {
            if now.duration_since(*front) > WINDOW {
                self.failures.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_budget_starts_empty() {
        let mut b = FailureBudget::new();
        assert_eq!(b.count_at(Instant::now()), 0);
    }

    #[test]
    fn default_budget_starts_empty() {
        let mut b = FailureBudget::default();
        assert_eq!(b.count_at(Instant::now()), 0);
    }

    #[test]
    fn single_failure_does_not_exhaust() {
        let mut b = FailureBudget::new();
        let now = Instant::now();
        assert!(!b.record_failure(now));
        assert_eq!(b.count_at(now), 1);
    }

    #[test]
    fn ninety_nine_failures_within_window_does_not_exhaust() {
        let mut b = FailureBudget::new();
        let start = Instant::now();
        for i in 0..99 {
            let t = start + Duration::from_secs(i);
            assert!(!b.record_failure(t), "failure {i} should not exhaust");
        }
        assert_eq!(b.count_at(start + Duration::from_secs(100)), 99);
    }

    #[test]
    fn one_hundred_failures_within_window_exhausts() {
        let mut b = FailureBudget::new();
        let start = Instant::now();
        let mut exhausted_at: Option<u64> = None;
        for i in 0..100 {
            let t = start + Duration::from_secs(i);
            if b.record_failure(t) {
                exhausted_at = Some(i);
                break;
            }
        }
        assert_eq!(
            exhausted_at,
            Some(99),
            "budget should exhaust at the 100th failure (index 99)"
        );
    }

    #[test]
    fn failures_outside_window_evicted() {
        let mut b = FailureBudget::new();
        let start = Instant::now();
        for _ in 0..50 {
            b.record_failure(start);
        }
        assert_eq!(b.count_at(start), 50);
        // Advance past the window — all 50 should age out.
        let after = start + Duration::from_secs(60 * 60 + 1);
        assert_eq!(b.count_at(after), 0);
    }

    #[test]
    fn boundary_at_exactly_window_does_not_evict() {
        // `duration_since > WINDOW` — at exactly `WINDOW`, the entry is
        // retained. Documents the strict-greater semantic.
        let mut b = FailureBudget::new();
        let start = Instant::now();
        b.record_failure(start);
        let at_boundary = start + Duration::from_secs(60 * 60);
        assert_eq!(b.count_at(at_boundary), 1);
    }

    #[test]
    fn success_clears_failures() {
        let mut b = FailureBudget::new();
        let start = Instant::now();
        for i in 0..50 {
            b.record_failure(start + Duration::from_secs(i));
        }
        assert_eq!(b.count_at(start + Duration::from_secs(100)), 50);
        b.record_success();
        assert_eq!(b.count_at(start + Duration::from_secs(100)), 0);
    }

    #[test]
    fn budget_resets_after_success_then_re_accumulates() {
        let mut b = FailureBudget::new();
        let start = Instant::now();
        // 99 failures.
        for i in 0..99 {
            assert!(!b.record_failure(start + Duration::from_secs(i)));
        }
        // Success clears.
        b.record_success();
        assert_eq!(b.count_at(start + Duration::from_secs(100)), 0);
        // Now a new burst: 99 more — none should exhaust because the
        // first batch was cleared.
        for i in 100..199 {
            assert!(!b.record_failure(start + Duration::from_secs(i)));
        }
        // 100th re-accumulated failure exhausts.
        assert!(b.record_failure(start + Duration::from_secs(199)));
    }

    #[test]
    fn partial_eviction_preserves_recent_entries() {
        let mut b = FailureBudget::new();
        let start = Instant::now();
        // Old entry at t=0 plus 5 recent at t=2h..2h+5s. The old one
        // ages out; the 5 stay.
        b.record_failure(start);
        for i in 0..5 {
            b.record_failure(start + Duration::from_secs(2 * 60 * 60 + i));
        }
        assert_eq!(b.count_at(start + Duration::from_secs(2 * 60 * 60 + 5)), 5);
    }
}
