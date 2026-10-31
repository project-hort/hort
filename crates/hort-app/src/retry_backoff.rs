//! The one retry-backoff curve a failing `jobs` row waits out, and the
//! one default for the budget that curve is spent against.
//!
//! Two consumers spend a row's attempt budget — the generalised
//! [`crate::task_dispatcher`] poll loop, for every registered kind, and
//! [`crate::use_cases::scan_orchestration`]'s `record_outcome`, for
//! `kind='scan'` — and both call [`compute_backoff`] here rather than
//! carrying a copy of it.
//!
//! A budget is two numbers, and both live here for the same reason:
//! [`DEFAULT_MAX_ATTEMPTS`] is how many executions a row gets and
//! [`compute_backoff`] is the window they span. Neither consumer
//! defines either one. The dispatcher is handed the *configured* cap at
//! construction and the scan orchestrator is handed it on
//! `ScanOrchestrationConfig`; this constant is only the value an
//! unconfigured deployment lands on, so there is no second cap for an
//! operator's setting to fail to reach.
//!
//! They used to carry two differently-shaped curves behind one agreed
//! number. Both stop re-driving a row after five executions, but the
//! dispatcher reached that point in 7 m 30 s (30 s, doubling) where the
//! scan orchestrator took 96 minutes: the same "five attempts" meant two
//! windows an order of magnitude apart, and nothing in either file made
//! the disagreement visible. One definition in one module is what keeps
//! that from happening again — a change to the shape now lands on both
//! consumers or on neither.

use std::time::Duration;

/// Default number of executions a `jobs` row gets before it becomes
/// terminal — the default of `HORT_SCANNER_MAX_ATTEMPTS`
/// (`hort-worker`'s `WorkerConfig::max_attempts`).
///
/// **This is a default, never a cap in its own right.** Both consumers
/// of the budget take the configured number: the dispatcher as a
/// `TaskDispatcher::new` argument, the scan orchestrator as
/// `ScanOrchestrationConfig::max_attempts`, and the worker's
/// composition root assigns both from the one `WorkerConfig` field. A
/// `const` used *as* a cap on either side is how an operator who sets
/// `HORT_SCANNER_MAX_ATTEMPTS=12` gets a row failed at five with no
/// artifact verdict behind it, so the only thing this value is allowed
/// to do is stand in when nothing was configured.
///
/// Five is the number [`compute_backoff`]'s window is rated for: it
/// spends the curve's first four waits, which is the 96 minutes that
/// doc describes. The two halves move together or not at all.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// How long a `jobs` row waits before its next execution, after an
/// attempt failed retryably.
///
/// `attempts` is the value already on the row when the failure is
/// observed: both claim statements increment it before any handler runs,
/// so the first failure arrives here as `attempts == 1`.
///
/// | `attempts` | wait before the next execution |
/// |---|---|
/// | 0, 1 | 1 min |
/// | 2 | 5 min |
/// | 3 | 30 min |
/// | 4 | 60 min |
/// | ≥ 5 | 60 min |
///
/// # The window, and why an exhausted budget means something
///
/// A five-execution budget spends the first four waits:
/// `60 + 300 + 1800 + 3600` seconds, so **96 minutes** separate the
/// first failure from the terminal row. That span is the point of the
/// curve, not a by-product of it. A spent budget is a permanent,
/// operator-visible `failed` row (ADR 0028), and for the one-shot kinds
/// — `seed-import`, `wheel-metadata-backfill`,
/// `oci-membership-edge-backfill`, `service-account-rotation`,
/// `eventstore-checkpoint` — nothing re-enqueues it: no tick comes
/// round, no later pull re-derives the work. An hour and a half of a
/// database or an upstream being unreachable is a fair description of
/// "persistently broken". Eight minutes is a description of "unlucky",
/// and the 30-s-doubling curve this replaced spent the entire budget
/// inside one of them.
///
/// The window is the scan pipeline's own, to the second, because that
/// pipeline already answers the same question for `kind='scan'` and
/// there is no reason for the house answer to "how long do we tolerate
/// a failing dependency" to depend on which kind is asking. Matching
/// the shape rather than merely the span is deliberate: a different
/// shape reaching a similar total is exactly how two curves hid behind
/// one shared number before.
///
/// # No delay ceiling, by construction
///
/// The last arm is flat, so 60 minutes is the largest value this can
/// return and there is nothing left for a ceiling to clamp. The 24-hour
/// ceiling this replaced belonged to an unbounded doubling chain; once
/// the chain was bounded at five executions, reaching it needed about
/// twelve attempts and it could never fire again. It is gone rather
/// than retained as a guard because it would guard nothing: **the
/// attempt budget, not a delay ceiling, is what ends a retry chain.**
/// A ceiling only ever shaped how far the waits grew, which this table
/// now states outright.
///
/// The `>= 5` arm is live, not defensive. The dispatcher's
/// `return_to_pending` backs off a claimed-but-undispatchable row
/// without consulting the attempt cap, so a row a replica structurally
/// cannot run can be charged past five; and the scan orchestrator's
/// budget is operator-set (`HORT_SCANNER_MAX_ATTEMPTS`, default 5) and
/// may be raised above it.
pub fn compute_backoff(attempts: u32) -> Duration {
    match attempts {
        // Defensive: both claim statements increment `attempts` before
        // the worker observes the row, so zero should not reach here.
        // Sharing the first wait keeps a bug from producing a
        // zero-duration retry storm.
        0 | 1 => Duration::from_secs(60),
        2 => Duration::from_secs(5 * 60),
        3 => Duration::from_secs(30 * 60),
        _ => Duration::from_secs(60 * 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four waits by value, and the window they add up to.
    ///
    /// Pinned as literals rather than derived from the function, so the
    /// 96-minute window is a fact the suite states instead of an
    /// inference a reader has to perform. The companion assertion — that
    /// the budget which spends exactly these four waits is five
    /// executions — lives with the cap, in
    /// `task_dispatcher::tests::five_executions_span_the_ninety_six_minute_window`.
    #[test]
    fn the_four_waits_a_five_execution_budget_spends_are_pinned_by_value() {
        assert_eq!(compute_backoff(1), Duration::from_secs(60));
        assert_eq!(compute_backoff(2), Duration::from_secs(5 * 60));
        assert_eq!(compute_backoff(3), Duration::from_secs(30 * 60));
        assert_eq!(compute_backoff(4), Duration::from_secs(60 * 60));

        let window: u64 = (1..5).map(|a| compute_backoff(a).as_secs()).sum();
        assert_eq!(
            window,
            96 * 60,
            "four waits separate the first failure from the fifth execution"
        );
    }

    /// Past the fourth wait the curve is flat — this is what replaced
    /// the unreachable 24-hour ceiling.
    ///
    /// The ceiling existed because the old curve grew without bound. A
    /// flat last arm needs no clamp: 60 minutes is the function's
    /// maximum for every input, including the ones no caller can
    /// produce, so an input this file did not anticipate cannot turn
    /// into a day-long wait.
    #[test]
    fn past_the_fourth_wait_the_curve_is_flat_at_sixty_minutes() {
        for attempts in [5, 6, 12, 100, u32::MAX] {
            assert_eq!(
                compute_backoff(attempts),
                Duration::from_secs(60 * 60),
                "attempts = {attempts}"
            );
        }
    }

    /// The budget's own half of the pairing, pinned by value.
    ///
    /// The window asserted above is rated for exactly five executions;
    /// a reader who changes this constant and not the curve has
    /// changed what "an exhausted budget" means without changing what
    /// it costs. The product of the two halves is pinned next to the
    /// dispatcher's cap, in
    /// `task_dispatcher::tests::five_executions_span_the_ninety_six_minute_window`.
    #[test]
    fn the_default_budget_is_the_one_the_window_is_rated_for() {
        assert_eq!(
            DEFAULT_MAX_ATTEMPTS, 5,
            "the window above spends this many executions' waits"
        );
        let spent: Vec<u64> = (1..DEFAULT_MAX_ATTEMPTS)
            .map(|a| compute_backoff(a).as_secs())
            .collect();
        assert_eq!(spent.iter().sum::<u64>(), 96 * 60);
    }

    /// `attempts == 0` gets the first wait, not a zero wait.
    ///
    /// Unreachable through either claim statement (both increment before
    /// the row is observed), so this pins the fallback rather than a
    /// behaviour: a zero-duration backoff would be a retry storm against
    /// whatever the row was already failing to reach.
    #[test]
    fn attempts_zero_waits_the_first_interval_rather_than_nothing() {
        assert_eq!(compute_backoff(0), Duration::from_secs(60));
    }
}
