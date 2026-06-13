//! Event-chain-verifier liveness predicate (ADR 0030).
//!
//! Background: the F-2 tamper-evidence verifier
//! (`hort-server verify-event-chain`) is correct crypto but ships
//! CLI-only — there is no in-cluster scheduler that runs it, and nothing
//! alerts when it stops running. Two
//! additive controls close that: (a) a **default-disabled**
//! `verify-event-chain`
//! CronJob, and (b) a boot-time liveness gauge
//! (`hort_event_chain_verify_overdue`) that flips to `1` when no
//! verify run has completed within the configured cadence window — so a
//! verifier that was enabled and then stopped is alarmable.
//!
//! This module is the **pure** half: a zero-I/O predicate the
//! composition root feeds with `(last_completed_at, now,
//! expected_interval, staleness_multiplier)`. It is a deliberate parallel
//! of [`super::staging_sweep_liveness`] (the precedent) — same
//! shape, same boundary semantics, same fail-safe-on-degenerate-config
//! direction — kept as its own type/fn (rather than generalising the
//! staging-sweep one) so that predicate stays untouched and each
//! signal carries its own documented remediation. It lives in
//! `hort-domain` (CLAUDE.md "domain layer: pure Rust, zero I/O") for the
//! same reason `policy::age` takes an explicit `now`: the wall-clock and
//! the port-fetched timestamp are caller-supplied so every branch is
//! unit-testable to the 100%-coverage `hort-domain` tier.
//!
//! **Boot-time emit, not a periodic loop.** A periodic in-process
//! re-check would re-introduce the `tokio::time` scheduler that was
//! deleted on purpose (the scheduler-free `hort-server` is load-bearing).
//! The gauge is set once at boot and scraped continuously; Prometheus
//! alarms on `max_over_time(hort_event_chain_verify_overdue[…]) > 0`,
//! the same shape the staging-sweep signal uses. Remediation is
//! operator-driven: enable the `cronJobs.verifyEventChain` CronJob or run
//! `hort-server verify-event-chain` out of band. See ADR 0030.

use chrono::{DateTime, Utc};

/// Outcome of [`evaluate_event_chain_verify_liveness`].
///
/// `Healthy` carries the observed age in whole seconds; `Overdue`
/// additionally carries the staleness threshold it exceeded so the
/// caller can put both in the `warn!` line without recomputing.
/// `NeverRan` is distinct from `Overdue` because the two have different
/// operator remediations: `Overdue` means the CronJob ran and stopped
/// (investigate the CronJob / the verifier's exit code), while `NeverRan`
/// means no verify run has *ever* completed on this deployment (the
/// canonical "verifier ships CLI-only and was never scheduled" case the
/// audit flags). Both set the gauge to `1` — both mean "no recent verify
/// run" — but the log line differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventChainVerifyLiveness {
    /// A `verify-event-chain` run completed within the staleness window.
    Healthy {
        /// Whole-second age of the most recent completed verify run.
        age_secs: i64,
    },
    /// A `verify-event-chain` run has completed before, but the most
    /// recent one is older than `staleness_multiplier × expected_interval`.
    Overdue {
        /// Whole-second age of the most recent completed verify run.
        age_secs: i64,
        /// The staleness threshold the age exceeded, in whole seconds.
        threshold_secs: i64,
    },
    /// No `verify-event-chain` run has ever completed on this deployment.
    /// Treated as overdue (gauge → 1) — the precise shape the audit calls
    /// out: a verifier that ships CLI-only and was never scheduled.
    NeverRan,
}

impl EventChainVerifyLiveness {
    /// `true` when the deployment should raise the staleness signal
    /// (gauge → `1`, emit `warn!`). `Overdue` and `NeverRan` are both
    /// overdue; only `Healthy` is not.
    pub fn is_overdue(&self) -> bool {
        !matches!(self, Self::Healthy { .. })
    }
}

/// Decide whether the event-chain verifier is overdue.
///
/// * `last_completed_at` — newest `jobs.completed_at` for a row with
///   `kind='verify-event-chain' AND status='completed'`, or `None` when
///   no such row exists. Supplied by the composition root via the
///   `JobsRepository` port; this function performs no I/O.
/// * `now` — caller-supplied wall-clock (the boot timestamp).
/// * `expected_interval` — the cadence the operator configured the
///   CronJob at (its `schedule:`). The composition root sources this
///   from an env knob with a sane default; the domain does not assume
///   a value.
/// * `staleness_multiplier` — how many intervals may elapse before the
///   verify run is "overdue". A multiplier of e.g. `3` tolerates two
///   missed ticks (jitter, a slow run, a brief controller restart)
///   before alarming, so a single skipped CronJob fire does not page.
///
/// Boundary semantics: the comparison is **strictly greater than** — an
/// age exactly equal to the threshold is still `Healthy`. A
/// `last_completed_at` in the future (clock skew between the DB and the
/// booting pod) yields a negative age, which is `< threshold` and
/// therefore `Healthy` (a future timestamp is not evidence of staleness).
/// A zero or negative effective threshold (operator set a nonsensically
/// small interval or multiplier) degrades to "anything with a non-future
/// timestamp is overdue", which is the safe direction — it over-alerts
/// rather than silently never-alerts.
pub fn evaluate_event_chain_verify_liveness(
    last_completed_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    expected_interval: std::time::Duration,
    staleness_multiplier: u32,
) -> EventChainVerifyLiveness {
    let Some(last) = last_completed_at else {
        return EventChainVerifyLiveness::NeverRan;
    };

    let age_secs = (now - last).num_seconds();

    // Saturating throughout — an absurd interval/multiplier must not
    // panic the boot path *and* must not silently wrap. `as i64` on a
    // `u64` seconds value would map `u64::MAX` → `-1` and flip the
    // predicate into permanent over-alert, so clamp the conversion at
    // `i64::MAX` first, then saturating-multiply.
    let interval_secs = i64::try_from(expected_interval.as_secs()).unwrap_or(i64::MAX);
    let threshold_secs = interval_secs.saturating_mul(i64::from(staleness_multiplier));

    if age_secs > threshold_secs {
        EventChainVerifyLiveness::Overdue {
            age_secs,
            threshold_secs,
        }
    } else {
        EventChainVerifyLiveness::Healthy { age_secs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    // ---- NeverRan ---------------------------------------------------------

    #[test]
    fn none_last_completed_is_never_ran() {
        let out = evaluate_event_chain_verify_liveness(
            None,
            ts(1_000_000),
            std::time::Duration::from_secs(3600),
            3,
        );
        assert_eq!(out, EventChainVerifyLiveness::NeverRan);
        assert!(out.is_overdue(), "NeverRan must be overdue");
    }

    // ---- Healthy ----------------------------------------------------------

    #[test]
    fn fresh_verify_run_is_healthy() {
        // Last run 100 s ago; interval 3600 s × 3 = 10800 s threshold.
        let out = evaluate_event_chain_verify_liveness(
            Some(ts(1_000_000 - 100)),
            ts(1_000_000),
            std::time::Duration::from_secs(3600),
            3,
        );
        assert_eq!(out, EventChainVerifyLiveness::Healthy { age_secs: 100 });
        assert!(!out.is_overdue());
    }

    #[test]
    fn age_exactly_at_threshold_is_healthy_not_overdue() {
        // age == threshold (10800 s). Strictly-greater-than means this is
        // still Healthy — pins the boundary.
        let out = evaluate_event_chain_verify_liveness(
            Some(ts(1_000_000 - 10_800)),
            ts(1_000_000),
            std::time::Duration::from_secs(3600),
            3,
        );
        assert_eq!(out, EventChainVerifyLiveness::Healthy { age_secs: 10_800 });
    }

    #[test]
    fn future_timestamp_clock_skew_is_healthy() {
        // last_completed_at is 50 s in the FUTURE (DB/pod clock skew).
        // Negative age < threshold → Healthy, not a false alarm.
        let out = evaluate_event_chain_verify_liveness(
            Some(ts(1_000_000 + 50)),
            ts(1_000_000),
            std::time::Duration::from_secs(3600),
            3,
        );
        assert_eq!(out, EventChainVerifyLiveness::Healthy { age_secs: -50 });
        assert!(!out.is_overdue());
    }

    // ---- Overdue ----------------------------------------------------------

    #[test]
    fn one_second_past_threshold_is_overdue() {
        // age = 10801 s, threshold = 10800 s → Overdue by 1 s.
        let out = evaluate_event_chain_verify_liveness(
            Some(ts(1_000_000 - 10_801)),
            ts(1_000_000),
            std::time::Duration::from_secs(3600),
            3,
        );
        assert_eq!(
            out,
            EventChainVerifyLiveness::Overdue {
                age_secs: 10_801,
                threshold_secs: 10_800,
            }
        );
        assert!(out.is_overdue());
    }

    #[test]
    fn far_overdue_reports_correct_age_and_threshold() {
        let out = evaluate_event_chain_verify_liveness(
            Some(ts(1_000_000 - 604_800)), // a week stale
            ts(1_000_000),
            std::time::Duration::from_secs(3600),
            2,
        );
        assert_eq!(
            out,
            EventChainVerifyLiveness::Overdue {
                age_secs: 604_800,
                threshold_secs: 7_200,
            }
        );
    }

    // ---- Degenerate config ------------------------------------------------

    #[test]
    fn zero_multiplier_makes_threshold_zero_and_over_alerts() {
        // multiplier 0 → threshold 0; any positive age is > 0 → Overdue.
        // Safe direction: over-alert rather than silently never alert.
        let out = evaluate_event_chain_verify_liveness(
            Some(ts(1_000_000 - 1)),
            ts(1_000_000),
            std::time::Duration::from_secs(3600),
            0,
        );
        assert_eq!(
            out,
            EventChainVerifyLiveness::Overdue {
                age_secs: 1,
                threshold_secs: 0,
            }
        );
    }

    #[test]
    fn zero_age_with_zero_threshold_is_healthy() {
        // age 0, threshold 0: 0 > 0 is false → Healthy. Pins the
        // exact-zero boundary on the degenerate path.
        let out = evaluate_event_chain_verify_liveness(
            Some(ts(1_000_000)),
            ts(1_000_000),
            std::time::Duration::from_secs(0),
            0,
        );
        assert_eq!(out, EventChainVerifyLiveness::Healthy { age_secs: 0 });
    }

    #[test]
    fn absurd_interval_multiplier_saturates_without_panic() {
        // u64::MAX-ish interval × large multiplier must saturate, not
        // overflow-panic the boot path.
        let out = evaluate_event_chain_verify_liveness(
            Some(ts(0)),
            ts(1_000_000),
            std::time::Duration::from_secs(u64::MAX),
            u32::MAX,
        );
        // Saturated threshold is i64::MAX; age 1_000_000 < that →
        // Healthy. The point of the test is "no panic".
        assert_eq!(
            out,
            EventChainVerifyLiveness::Healthy {
                age_secs: 1_000_000
            }
        );
    }
}
