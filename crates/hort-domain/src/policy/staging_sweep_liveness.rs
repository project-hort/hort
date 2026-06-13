//! Staging-sweep liveness predicate.
//!
//! Background: the admin-task framework removed the only in-process
//! scheduler from
//! `hort-server` and migrated `staging-sweep` to a worker `TaskHandler`
//! whose k8s CronJob is `cronJobs.enabled:false` by default. A
//! deployment that upgrades without enabling the CronJob (the
//! documented-safe default) or runs non-k8s gets **no staging sweep at
//! all** — orphaned `stateful_upload_staging` entries accumulate
//! unbounded until ingest fails on a full filesystem, and nothing
//! alerts. The close is a boot-time + scrape-time health
//! signal: a metric + `warn!` when no sweep has completed for longer
//! than `staleness_multiplier × expected_interval`.
//!
//! This module is the **pure** half: a zero-I/O predicate the
//! composition root feeds with `(last_completed_at, now,
//! expected_interval, staleness_multiplier)`. It lives in `hort-domain`
//! (CLAUDE.md "domain layer: pure Rust, zero I/O") for the same reason
//! `policy::age` takes an explicit `now` — the wall-clock and the
//! port-fetched timestamp are caller-supplied so every branch is unit
//! testable to the 100%-coverage `hort-domain` tier.
//!
//! A minimal in-process fallback sweep
//! is **out of scope and deliberately declined**: it
//! would re-introduce the in-process scheduler that was removed on
//! purpose (the scheduler-free `hort-server` is load-bearing). The
//! liveness signal is observation-only; remediation stays operator-
//! driven (enable the CronJob, or run `hort-cli admin task
//! staging-sweep`).

use chrono::{DateTime, Utc};

/// Outcome of [`evaluate_staging_sweep_liveness`].
///
/// `Healthy` carries no payload; `Overdue` carries the observed age in
/// whole seconds so the caller can put it in the `warn!` line without
/// recomputing. `NeverRan` is distinct from `Overdue` because the two
/// have different operator remediations: `Overdue` means the CronJob
/// was running and stopped (investigate the worker / CronJob); `NeverRan`
/// means the sweep has *never* completed on this deployment (the
/// canonical "upgraded without enabling the CronJob" case the audit
/// flags). Both set the gauge to `1` — both mean "no recent sweep" —
/// but the log line differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingSweepLiveness {
    /// A `staging-sweep` job completed within the staleness window.
    Healthy {
        /// Whole-second age of the most recent completed sweep.
        age_secs: i64,
    },
    /// A `staging-sweep` job has completed before, but the most recent
    /// one is older than `staleness_multiplier × expected_interval`.
    Overdue {
        /// Whole-second age of the most recent completed sweep.
        age_secs: i64,
        /// The staleness threshold the age exceeded, in whole seconds.
        threshold_secs: i64,
    },
    /// No `staging-sweep` job has ever completed on this deployment.
    /// Treated as overdue (gauge → 1) — this is the precise shape the
    /// audit calls out: an upgrade that never enabled the CronJob.
    NeverRan,
}

impl StagingSweepLiveness {
    /// `true` when the deployment should raise the staleness signal
    /// (gauge → `1`, emit `warn!`). `Overdue` and `NeverRan` are both
    /// overdue; only `Healthy` is not.
    pub fn is_overdue(&self) -> bool {
        !matches!(self, Self::Healthy { .. })
    }
}

/// Decide whether the staging sweep is overdue.
///
/// * `last_completed_at` — newest `jobs.completed_at` for a row with
///   `kind='staging-sweep' AND status='completed'`, or `None` when no
///   such row exists. Supplied by the composition root via the
///   `JobsRepository` port; this function performs no I/O.
/// * `now` — caller-supplied wall-clock (the boot timestamp).
/// * `expected_interval` — the cadence the operator configured the
///   CronJob at (its `schedule:`). The composition root sources this
///   from an env knob with a sane default; the domain does not assume
///   a value.
/// * `staleness_multiplier` — how many intervals may elapse before the
///   sweep is "overdue". A multiplier of e.g. `3` tolerates two missed
///   ticks (jitter, a slow drain, a brief worker restart) before
///   alarming, so a single skipped CronJob fire does not page.
///
/// Boundary semantics: the comparison is **strictly greater than** —
/// an age exactly equal to the threshold is still `Healthy`. A
/// `last_completed_at` in the future (clock skew between the DB and the
/// booting pod) yields a negative age, which is `< threshold` and
/// therefore `Healthy` (a future timestamp is not evidence of
/// staleness). A zero or negative effective threshold (operator set a
/// nonsensically small interval or multiplier) degrades to "anything
/// with a non-future timestamp is overdue", which is the safe
/// direction — it over-alerts rather than silently never-alerts.
pub fn evaluate_staging_sweep_liveness(
    last_completed_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    expected_interval: std::time::Duration,
    staleness_multiplier: u32,
) -> StagingSweepLiveness {
    let Some(last) = last_completed_at else {
        return StagingSweepLiveness::NeverRan;
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
        StagingSweepLiveness::Overdue {
            age_secs,
            threshold_secs,
        }
    } else {
        StagingSweepLiveness::Healthy { age_secs }
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
        let out = evaluate_staging_sweep_liveness(
            None,
            ts(1_000_000),
            std::time::Duration::from_secs(300),
            3,
        );
        assert_eq!(out, StagingSweepLiveness::NeverRan);
        assert!(out.is_overdue(), "NeverRan must be overdue");
    }

    // ---- Healthy ----------------------------------------------------------

    #[test]
    fn fresh_sweep_is_healthy() {
        // Last sweep 100 s ago; interval 300 s × 3 = 900 s threshold.
        let out = evaluate_staging_sweep_liveness(
            Some(ts(1_000_000 - 100)),
            ts(1_000_000),
            std::time::Duration::from_secs(300),
            3,
        );
        assert_eq!(out, StagingSweepLiveness::Healthy { age_secs: 100 });
        assert!(!out.is_overdue());
    }

    #[test]
    fn age_exactly_at_threshold_is_healthy_not_overdue() {
        // age == threshold (900 s). Strictly-greater-than means this is
        // still Healthy — pins the boundary.
        let out = evaluate_staging_sweep_liveness(
            Some(ts(1_000_000 - 900)),
            ts(1_000_000),
            std::time::Duration::from_secs(300),
            3,
        );
        assert_eq!(out, StagingSweepLiveness::Healthy { age_secs: 900 });
    }

    #[test]
    fn future_timestamp_clock_skew_is_healthy() {
        // last_completed_at is 50 s in the FUTURE (DB/pod clock skew).
        // Negative age < threshold → Healthy, not a false alarm.
        let out = evaluate_staging_sweep_liveness(
            Some(ts(1_000_000 + 50)),
            ts(1_000_000),
            std::time::Duration::from_secs(300),
            3,
        );
        assert_eq!(out, StagingSweepLiveness::Healthy { age_secs: -50 });
        assert!(!out.is_overdue());
    }

    // ---- Overdue ----------------------------------------------------------

    #[test]
    fn one_second_past_threshold_is_overdue() {
        // age = 901 s, threshold = 900 s → Overdue by 1 s.
        let out = evaluate_staging_sweep_liveness(
            Some(ts(1_000_000 - 901)),
            ts(1_000_000),
            std::time::Duration::from_secs(300),
            3,
        );
        assert_eq!(
            out,
            StagingSweepLiveness::Overdue {
                age_secs: 901,
                threshold_secs: 900,
            }
        );
        assert!(out.is_overdue());
    }

    #[test]
    fn far_overdue_reports_correct_age_and_threshold() {
        let out = evaluate_staging_sweep_liveness(
            Some(ts(1_000_000 - 86_400)), // a day stale
            ts(1_000_000),
            std::time::Duration::from_secs(600),
            2,
        );
        assert_eq!(
            out,
            StagingSweepLiveness::Overdue {
                age_secs: 86_400,
                threshold_secs: 1_200,
            }
        );
    }

    // ---- Degenerate config ------------------------------------------------

    #[test]
    fn zero_multiplier_makes_threshold_zero_and_over_alerts() {
        // multiplier 0 → threshold 0; any positive age is > 0 → Overdue.
        // Safe direction: over-alert rather than silently never alert.
        let out = evaluate_staging_sweep_liveness(
            Some(ts(1_000_000 - 1)),
            ts(1_000_000),
            std::time::Duration::from_secs(300),
            0,
        );
        assert_eq!(
            out,
            StagingSweepLiveness::Overdue {
                age_secs: 1,
                threshold_secs: 0,
            }
        );
    }

    #[test]
    fn zero_age_with_zero_threshold_is_healthy() {
        // age 0, threshold 0: 0 > 0 is false → Healthy. Pins the
        // exact-zero boundary on the degenerate path.
        let out = evaluate_staging_sweep_liveness(
            Some(ts(1_000_000)),
            ts(1_000_000),
            std::time::Duration::from_secs(0),
            0,
        );
        assert_eq!(out, StagingSweepLiveness::Healthy { age_secs: 0 });
    }

    #[test]
    fn absurd_interval_multiplier_saturates_without_panic() {
        // u64::MAX-ish interval × large multiplier must saturate, not
        // overflow-panic the boot path.
        let out = evaluate_staging_sweep_liveness(
            Some(ts(0)),
            ts(1_000_000),
            std::time::Duration::from_secs(u64::MAX),
            u32::MAX,
        );
        // Saturated threshold is i64::MAX; age 1_000_000 < that →
        // Healthy. The point of the test is "no panic".
        assert_eq!(
            out,
            StagingSweepLiveness::Healthy {
                age_secs: 1_000_000
            }
        );
    }
}
