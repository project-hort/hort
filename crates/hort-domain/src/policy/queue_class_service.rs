//! Per-class queue-service predicate — ADR 0066 D5, *"every class is
//! guaranteed service; the guarantee is observable"*.
//!
//! # The question this answers, and the two it replaces
//!
//! The dispatcher's existing starvation audit asks its question **per
//! kind**: does this kind have a claim-eligible backlog that is not
//! draining? That is the wrong granularity for the guarantee, because
//! the guarantee is per class (ADR 0066 D1/D4) and one kind carries
//! several classes — `scan` carries six trigger sources across all
//! three. A kind that is claimed steadily while one of its classes
//! never is reads as healthy there: the per-kind "last claimed" clock is
//! re-armed by a row of *any* class, and the one axis that can still
//! fire — the single oldest eligible row having aged past the threshold
//! — approximates service by **age**, which is the axis ADR 0066 says is
//! the wrong one to reserve on ("reserving part of each batch for the
//! oldest waiting item protects the oldest item, not the one that is
//! losing").
//!
//! So this predicate asks, per class: **is work of this class waiting,
//! and has anything of this class been served while it waited?** Age
//! enters only as "how long has work been waiting" — never as "which
//! row deserves to go next".
//!
//! # Why it is sharper than an age test, in both directions
//!
//! - It does not fire on a deep queue that is draining. A backlog's
//!   oldest *remaining* row can be hours old while the class is served
//!   every second; service re-arms the reference, so the verdict is
//!   `Served`.
//! - It fires on a class whose work is spread thinly across kinds. Five
//!   kinds with one waiting row each, none of them old enough to trip a
//!   per-kind age test, is one class that has had work waiting the whole
//!   time.
//! - It sees the second allocation point. A row that has been claimed
//!   and is waiting for a run permit is `status = 'running'`, so it is
//!   outside the claim-eligible backlog by construction; it reaches this
//!   predicate as [`BandQueueSample::awaiting_capacity`], which is what
//!   makes permit starvation observable rather than inferred from
//!   end-to-end latency.
//!
//! # Pure, like its siblings
//!
//! Zero I/O: the caller supplies the wall clock, the sampled facts and
//! the threshold, exactly as [`super::staging_sweep_liveness`] and
//! [`super::rescan_drive_liveness`] do, so every branch is unit-testable
//! without a database or a composed application. The sampling and the
//! emitting are the composition root's
//! (`hort_server::composition::emit_queue_class_service_signal`) and the
//! worker audit's (`hort_app::task_dispatcher`); both evaluate *this*
//! function, so the operator's gauge and the worker's log cannot
//! disagree about what starvation is.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::ports::jobs_repository::BandQueueSample;

/// How long work of a class may be waiting with nothing of that class
/// served before the class counts as unserved — the default of
/// `HORT_TASK_CLASS_SERVICE_THRESHOLD_SECS`.
///
/// **Five minutes, and deliberately tighter than the per-kind audit's
/// ten.** That constant is sized "well above any legitimate transient"
/// because its oldest-row axis fires on states that are not defects at
/// all (a deep queue draining normally keeps an old oldest row), and a
/// signal with false positives has to be slow to stay usable. This
/// predicate's conjunction removes that class of false positive —
/// service re-arms the reference — so it can afford to answer sooner,
/// and ADR 0066's victims need it sooner: the quarantine-release sweep
/// and an operator's rescan are "a control task that runs every few
/// minutes [and] needs it *soon*".
///
/// ADR 0066 also fixes the direction to err in: *"the guarantee in (5)
/// will fire falsely the first time its threshold is set too low. That
/// is the intended direction: a false alarm is recoverable, a silent
/// stall is the failure being removed."* So this is the loud default of
/// a knob, not a tuned number — and it is defined once, here, because
/// both `hort-server` (which emits the gauge) and `hort-worker` (which
/// logs the local trail) read the same knob and would otherwise agree
/// only by coincidence.
pub const DEFAULT_CLASS_SERVICE_THRESHOLD_SECS: u64 = 300;

/// Where a starved class's work is stuck — the `reason` label on the
/// per-class starvation counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassStarvationReason {
    /// The class has claim-eligible pending work that is not being
    /// taken up. The first of ADR 0066 D4's two allocation points.
    NotClaimed,
    /// The class holds claims it has not been given the capacity to run
    /// — rows that are `running` and queued behind a permit. The second
    /// allocation point, and the one no read of the pending backlog can
    /// see.
    AwaitingCapacity,
}

impl ClassStarvationReason {
    /// Stable metric/log label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotClaimed => "not_claimed",
            Self::AwaitingCapacity => "awaiting_capacity",
        }
    }
}

/// Outcome of [`evaluate_class_service`] for one class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassService {
    /// Nothing of this class is waiting, so the class is owed nothing
    /// and there is no verdict to make. Distinct from [`Self::Served`]
    /// because a quiet class and a flowing one are different operator
    /// pictures, and neither is a defect.
    Idle,
    /// Work of this class is waiting, and the class has been served
    /// within the threshold.
    Served {
        /// Rows of this class waiting at either allocation point.
        waiting: i64,
        /// How long the class has gone unserved while work waited, in
        /// whole seconds. Negative only under clock skew.
        unserved_for_secs: i64,
    },
    /// Work of this class has been waiting longer than the threshold
    /// and nothing of this class has been served in that window.
    Starved {
        /// Rows of this class waiting at either allocation point.
        waiting: i64,
        /// How many of those rows hold a claim and are waiting for a run
        /// permit (the subset no pending-backlog read can see).
        awaiting_capacity: i64,
        /// How long the class has gone unserved while work waited, in
        /// whole seconds.
        unserved_for_secs: i64,
        /// The threshold that was exceeded, in whole seconds.
        threshold_secs: i64,
        /// Which allocation point the work is stuck at.
        reason: ClassStarvationReason,
    },
}

impl ClassService {
    /// `true` when this class should raise the signal — the `0`/`1` the
    /// server's gauge carries, and the condition the worker's audit
    /// logs and counts.
    ///
    /// Both emitters go through this rather than matching the variants
    /// themselves, so "which verdicts are an alarm" is answered once:
    /// `Idle` and `Served` are not, and a fourth variant would have to
    /// be given an answer here before either emitter compiled.
    pub fn is_starved(&self) -> bool {
        matches!(self, Self::Starved { .. })
    }
}

/// Decide whether one class is being served.
///
/// * `sample` — the class's sampled queue facts, as
///   [`JobsRepository::queue_sample_by_band`](crate::ports::jobs_repository::JobsRepository::queue_sample_by_band)
///   returns them for the band that class occupies.
/// * `now` — caller-supplied wall clock.
/// * `threshold` — how long work may wait unserved before the class
///   counts as starved (`HORT_TASK_CLASS_SERVICE_THRESHOLD_SECS`,
///   defaulting to [`DEFAULT_CLASS_SERVICE_THRESHOLD_SECS`]).
///
/// # The decision
///
/// Nothing waiting is [`ClassService::Idle`] — a class with no work is
/// not being denied any.
///
/// Otherwise the reference instant is `max(last served, oldest waiting
/// item's arrival)`, and the class is starved when `now` is more than
/// `threshold` past it. Both halves of that `max` are load-bearing:
///
/// - **The last-served half** is what makes this a service test rather
///   than an age test. A class being served keeps re-arming it however
///   deep its queue is.
/// - **The arrival half** is what keeps a quiet deployment quiet. A
///   class nobody used for an hour has an hour-old last-served
///   timestamp; without this floor the first row to arrive would be
///   reported as an hour of starvation it did not experience. This is
///   the same floor the per-kind audit applies for the same reason.
///
/// A class with waiting work and **no** service on record at all
/// (`last_served_at: None` — nothing of it has ever completed) is
/// therefore judged on the arrival half alone, which is the honest
/// reading: there is no evidence of service, and the work has waited
/// however long it has waited.
///
/// Boundary semantics mirror the sibling liveness predicates: the
/// comparison is **strictly greater than**, so an age exactly equal to
/// the threshold is not yet starved; a future timestamp (clock skew
/// between the sampling process and the database) yields a negative
/// duration and is not evidence of a stall; and an absurd threshold
/// saturates rather than wrapping a nonsense value into permanent
/// alarm.
///
/// # The reason, and why the permit point wins the tie
///
/// A starved class that has rows waiting for a permit **past the
/// threshold** is reported as [`ClassStarvationReason::AwaitingCapacity`]
/// even when it also has old pending work. The permit point is the one
/// no SQL read of `jobs`'s pending backlog can see, so naming it first
/// is what lets a reader trust the other label: a class reported
/// `not_claimed` has been checked for a capacity shortage and does not
/// have one.
pub fn evaluate_class_service(
    sample: &BandQueueSample,
    now: DateTime<Utc>,
    threshold: Duration,
) -> ClassService {
    let waiting = sample
        .pending_eligible
        .max(0)
        .saturating_add(sample.awaiting_capacity.max(0));
    if waiting == 0 {
        return ClassService::Idle;
    }

    // A positive count with no timestamp beside it cannot happen from
    // the one producer — the adapter derives each count and each
    // timestamp from the same `FILTER` — and is resolved toward "waiting
    // since now", i.e. not starved: a finding whose stall has no
    // timestamp behind it names nothing an operator could go and look
    // at.
    let oldest_pending = waiting_since(sample.pending_eligible, sample.oldest_pending_at, now);
    let oldest_capacity = waiting_since(
        sample.awaiting_capacity,
        sample.oldest_capacity_wait_at,
        now,
    );
    // The `unwrap_or` is unreachable — `waiting > 0` means at least one
    // of the two counts is positive, and each positive count produces a
    // `Some` — and resolves the same way a missing timestamp does, for
    // the same reason.
    let oldest_waiting_at = oldest_pending
        .into_iter()
        .chain(oldest_capacity)
        .min()
        .unwrap_or(now);

    let reference = match sample.last_served_at {
        Some(served) => served.max(oldest_waiting_at),
        None => oldest_waiting_at,
    };
    let unserved_for_secs = (now - reference).num_seconds();
    let threshold_secs = i64::try_from(threshold.as_secs()).unwrap_or(i64::MAX);

    if unserved_for_secs > threshold_secs {
        let capacity_wait_secs = oldest_capacity.map_or(0, |at| (now - at).num_seconds());
        let reason = if sample.awaiting_capacity > 0 && capacity_wait_secs > threshold_secs {
            ClassStarvationReason::AwaitingCapacity
        } else {
            ClassStarvationReason::NotClaimed
        };
        ClassService::Starved {
            waiting,
            awaiting_capacity: sample.awaiting_capacity.max(0),
            unserved_for_secs,
            threshold_secs,
            reason,
        }
    } else {
        ClassService::Served {
            waiting,
            unserved_for_secs,
        }
    }
}

/// When work counted by `count` started waiting: the sampled timestamp
/// when there is work and a timestamp, `None` when there is no work,
/// and `now` when the sample is internally inconsistent (see
/// [`evaluate_class_service`]).
fn waiting_since(
    count: i64,
    sampled: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if count <= 0 {
        return None;
    }
    Some(sampled.unwrap_or(now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const NOW: i64 = 2_000_000;
    const THRESHOLD: Duration = Duration::from_secs(300);

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn now() -> DateTime<Utc> {
        ts(NOW)
    }

    /// A sample with nothing in it — each test sets only the fields it
    /// is about, so a reader can see which facts a verdict rests on.
    fn empty() -> BandQueueSample {
        BandQueueSample {
            pending_eligible: 0,
            oldest_pending_at: None,
            awaiting_capacity: 0,
            oldest_capacity_wait_at: None,
            last_served_at: None,
        }
    }

    // ---- Idle -------------------------------------------------------------

    #[test]
    fn a_class_with_no_waiting_work_is_idle() {
        let out = evaluate_class_service(&empty(), now(), THRESHOLD);
        assert_eq!(out, ClassService::Idle);
        assert!(!out.is_starved());
    }

    #[test]
    fn an_idle_class_stays_idle_however_old_its_last_service_is() {
        // The quiet-deployment shape: nothing of this class has
        // completed in a day, and nothing is waiting either. A class
        // nobody is asking anything of is not being starved.
        let sample = BandQueueSample {
            last_served_at: Some(ts(NOW - 86_400)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Idle
        );
    }

    #[test]
    fn negative_counts_are_treated_as_no_work() {
        // `count(*)` cannot return a negative, but the port's type is
        // signed; a negative must not become a positive `waiting`.
        let sample = BandQueueSample {
            pending_eligible: -5,
            awaiting_capacity: -1,
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Idle
        );
    }

    // ---- Served -----------------------------------------------------------

    #[test]
    fn work_waiting_inside_the_threshold_is_served() {
        let sample = BandQueueSample {
            pending_eligible: 3,
            oldest_pending_at: Some(ts(NOW - 100)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Served {
                waiting: 3,
                unserved_for_secs: 100,
            }
        );
    }

    #[test]
    fn recent_service_re_arms_the_reference_over_an_old_backlog() {
        // The deep-but-draining queue: the oldest remaining row is two
        // hours old because the queue is deep, and the class is being
        // served every few seconds. This is exactly the state the
        // per-kind `oldest_row_stalled` axis reports as starvation.
        let sample = BandQueueSample {
            pending_eligible: 10_000,
            oldest_pending_at: Some(ts(NOW - 7_200)),
            last_served_at: Some(ts(NOW - 5)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Served {
                waiting: 10_000,
                unserved_for_secs: 5,
            }
        );
    }

    #[test]
    fn an_arrival_newer_than_the_last_service_floors_the_reference() {
        // The quiet deployment: nothing of this class has completed for
        // an hour, and a row arrives now. Without the arrival floor the
        // very first row would be reported as an hour of starvation.
        let sample = BandQueueSample {
            pending_eligible: 1,
            oldest_pending_at: Some(ts(NOW - 2)),
            last_served_at: Some(ts(NOW - 3_600)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Served {
                waiting: 1,
                unserved_for_secs: 2,
            }
        );
    }

    #[test]
    fn a_wait_exactly_at_the_threshold_is_not_yet_starved() {
        let sample = BandQueueSample {
            pending_eligible: 1,
            oldest_pending_at: Some(ts(NOW - 300)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Served {
                waiting: 1,
                unserved_for_secs: 300,
            }
        );
    }

    #[test]
    fn a_future_timestamp_is_not_evidence_of_a_stall() {
        // Clock skew between the sampling process and the database.
        let sample = BandQueueSample {
            pending_eligible: 2,
            oldest_pending_at: Some(ts(NOW + 50)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Served {
                waiting: 2,
                unserved_for_secs: -50,
            }
        );
    }

    #[test]
    fn a_positive_count_with_no_timestamp_is_not_starved() {
        // Unreachable from the adapter (count and timestamp come from
        // one FILTER); resolved toward "waiting since now".
        let sample = BandQueueSample {
            pending_eligible: 4,
            awaiting_capacity: 2,
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Served {
                waiting: 6,
                unserved_for_secs: 0,
            }
        );
    }

    // ---- Starved: the claim point -----------------------------------------

    #[test]
    fn pending_work_waiting_past_the_threshold_with_no_service_is_starved() {
        let sample = BandQueueSample {
            pending_eligible: 2,
            oldest_pending_at: Some(ts(NOW - 400)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Starved {
                waiting: 2,
                awaiting_capacity: 0,
                unserved_for_secs: 400,
                threshold_secs: 300,
                reason: ClassStarvationReason::NotClaimed,
            }
        );
    }

    #[test]
    fn service_older_than_the_threshold_does_not_rescue_a_waiting_class() {
        // Served once, long ago, and the work has been waiting since
        // before that: the reference is the service, and it is stale.
        let sample = BandQueueSample {
            pending_eligible: 7,
            oldest_pending_at: Some(ts(NOW - 5_000)),
            last_served_at: Some(ts(NOW - 900)),
            ..empty()
        };
        let out = evaluate_class_service(&sample, now(), THRESHOLD);
        assert_eq!(
            out,
            ClassService::Starved {
                waiting: 7,
                awaiting_capacity: 0,
                unserved_for_secs: 900,
                threshold_secs: 300,
                reason: ClassStarvationReason::NotClaimed,
            }
        );
        assert!(out.is_starved());
    }

    // ---- Starved: the permit point ----------------------------------------

    #[test]
    fn rows_waiting_for_capacity_past_the_threshold_are_starved_at_the_permit() {
        // Nothing of this class is in the pending backlog at all — the
        // rows have been claimed and are queued behind a run permit, so
        // no read of `status = 'pending'` can see them.
        let sample = BandQueueSample {
            awaiting_capacity: 3,
            oldest_capacity_wait_at: Some(ts(NOW - 700)),
            last_served_at: Some(ts(NOW - 7_200)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Starved {
                waiting: 3,
                awaiting_capacity: 3,
                unserved_for_secs: 700,
                threshold_secs: 300,
                reason: ClassStarvationReason::AwaitingCapacity,
            }
        );
    }

    #[test]
    fn the_permit_point_is_named_even_when_pending_work_is_older() {
        // Both points are blocked. The permit point is reported because
        // it is the one a pending-backlog read cannot see.
        let sample = BandQueueSample {
            pending_eligible: 5,
            oldest_pending_at: Some(ts(NOW - 9_000)),
            awaiting_capacity: 1,
            oldest_capacity_wait_at: Some(ts(NOW - 400)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Starved {
                waiting: 6,
                awaiting_capacity: 1,
                unserved_for_secs: 9_000,
                threshold_secs: 300,
                reason: ClassStarvationReason::AwaitingCapacity,
            }
        );
    }

    #[test]
    fn a_young_capacity_wait_beside_old_pending_work_is_the_claim_point() {
        // The permit is not the holdup: that row has been waiting
        // seconds. The label has to point at the claim, or a reader
        // cannot tell the two points apart.
        let sample = BandQueueSample {
            pending_eligible: 5,
            oldest_pending_at: Some(ts(NOW - 9_000)),
            awaiting_capacity: 1,
            oldest_capacity_wait_at: Some(ts(NOW - 10)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Starved {
                waiting: 6,
                awaiting_capacity: 1,
                unserved_for_secs: 9_000,
                threshold_secs: 300,
                reason: ClassStarvationReason::NotClaimed,
            },
            "the permit is not the holdup when its wait is seconds old"
        );
    }

    #[test]
    fn a_long_capacity_wait_while_the_class_is_served_is_not_starvation() {
        // One row has waited twenty minutes for a permit while the
        // class completed something two seconds ago — the capacity is
        // busy with this very class, which is service, not starvation.
        let sample = BandQueueSample {
            awaiting_capacity: 1,
            oldest_capacity_wait_at: Some(ts(NOW - 1_200)),
            last_served_at: Some(ts(NOW - 2)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Served {
                waiting: 1,
                unserved_for_secs: 2,
            }
        );
    }

    // ---- Degenerate configuration -----------------------------------------

    #[test]
    fn a_zero_threshold_over_alerts_rather_than_never_alerting() {
        let sample = BandQueueSample {
            pending_eligible: 1,
            oldest_pending_at: Some(ts(NOW - 1)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), Duration::from_secs(0)),
            ClassService::Starved {
                waiting: 1,
                awaiting_capacity: 0,
                unserved_for_secs: 1,
                threshold_secs: 0,
                reason: ClassStarvationReason::NotClaimed,
            }
        );
    }

    #[test]
    fn a_zero_wait_at_a_zero_threshold_is_served() {
        let sample = BandQueueSample {
            pending_eligible: 1,
            oldest_pending_at: Some(now()),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), Duration::from_secs(0)),
            ClassService::Served {
                waiting: 1,
                unserved_for_secs: 0,
            }
        );
    }

    #[test]
    fn an_absurd_threshold_saturates_without_panicking() {
        let sample = BandQueueSample {
            pending_eligible: 1,
            oldest_pending_at: Some(ts(0)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), Duration::from_secs(u64::MAX)),
            ClassService::Served {
                waiting: 1,
                unserved_for_secs: NOW,
            }
        );
    }

    #[test]
    fn a_saturating_waiting_count_does_not_wrap() {
        let sample = BandQueueSample {
            pending_eligible: i64::MAX,
            oldest_pending_at: Some(ts(NOW - 10)),
            awaiting_capacity: 2,
            oldest_capacity_wait_at: Some(ts(NOW - 5)),
            ..empty()
        };
        assert_eq!(
            evaluate_class_service(&sample, now(), THRESHOLD),
            ClassService::Served {
                waiting: i64::MAX,
                unserved_for_secs: 10,
            },
            "the two counts must saturate rather than wrap into a negative depth"
        );
    }

    // ---- Labels -----------------------------------------------------------

    #[test]
    fn reason_labels_are_the_metric_values() {
        assert_eq!(ClassStarvationReason::NotClaimed.as_str(), "not_claimed");
        assert_eq!(
            ClassStarvationReason::AwaitingCapacity.as_str(),
            "awaiting_capacity"
        );
    }
}
