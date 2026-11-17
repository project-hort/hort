//! Rescan-drive liveness predicate.
//!
//! `ScanPolicy.rescanIntervalHours` is enforced correctly by its
//! consumer: the eligibility query in
//! `hort-adapters-postgres::rescan_candidates` reads
//! `COALESCE(p.rescan_interval_hours, $3)`, filters `> 0`, and compares
//! it against `artifacts.last_scan_at`. What the field needs in order
//! to mean anything is a **driver**, and that query runs only when the
//! `cron-rescan-tick` task runs — a worker `TaskHandler` fired by an
//! external CronJob whose chart value
//! `scheduledTasks.cronRescanTick.enabled` defaults to `false`.
//!
//! So an operator can declare a cadence, have it accepted and stored
//! verbatim, read it back from their own policy document, and make a
//! threat-model decision on it ("an advisory landing tomorrow is
//! matched against yesterday's artifacts") while nothing re-scans
//! anything. The same tick is also the only production caller of
//! `RescanCandidatesRepository::select_stranded`, so a scan left
//! stranded by a failed job has no automatic recovery either. This
//! predicate is the close: a boot-time statement that the declared
//! cadence is not reachable, naming the switch that makes it so.
//!
//! **It is not a verdict on the configuration.** Running without the
//! tick is supported and deliberate — the chart default is `false` on
//! purpose. An operator who chose it is not misconfigured; the signal
//! says what the choice costs, which is why the caller's log line
//! names `scheduledTasks.cronRescanTick.enabled` and the one-shot
//! `POST /api/v1/admin/tasks/cron-rescan-tick` rather than scolding.
//!
//! **Not an apply-time rejection** (contrast ADR 0015's `max_age_days`
//! exemplar, where the consumer does not exist). Here the consumer
//! exists and is correct, and the gap is in the *deployment*, which
//! gitops apply cannot see. Refusing `rescanIntervalHours` would break
//! configurations that are right.
//!
//! This module is the **pure** half — a zero-I/O predicate the
//! composition root feeds with `(active policies, last_completed_at,
//! now, staleness_multiplier)` — mirroring
//! [`crate::policy::staging_sweep_liveness`] and
//! [`crate::policy::event_chain_verify_liveness`], the two
//! boot-signal predicates it is modelled on. The wall-clock is
//! caller-supplied so every branch is unit testable to the
//! 100%-coverage `hort-domain` tier.
//!
//! **Scope: a *declared* cadence, not a resolved one.** A deployment
//! with zero `ScanPolicy` rows still resolves to
//! [`crate::policy::scan::DefaultPolicy::rescan_interval_hours`] (24 h)
//! inside the query's `COALESCE`, and that is equally undriven — but
//! no operator has read a cadence out of a policy document and relied
//! on it, so there is no promise to contradict. The signal keys off
//! what an operator declared, which is also why
//! `rescanIntervalHours: 0` produces nothing: it is a declaration that
//! this policy does not rescan, not a gap.

use chrono::{DateTime, Utc};

use crate::entities::scan_policy::ScanPolicyProjection;

/// The shortest rescan cadence any active `ScanPolicy` declares, and
/// the policy that declares it.
///
/// The *shortest* is the right one to report because it is the
/// tightest promise the configuration makes: a deployment whose
/// shortest declared cadence is already undriven has every longer one
/// undriven too, so one line covers the whole set. Naming the policy
/// is what makes the line actionable — a deployment can hold many
/// policies and an operator needs to know which document they were
/// reading when they formed the expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredCadence {
    /// The policy's `rescan_interval_hours`, always `> 0`.
    pub interval_hours: i32,
    /// `ScanPolicyProjection::name` of the policy carrying it.
    pub policy_name: String,
}

/// Outcome of [`evaluate_rescan_drive_liveness`].
///
/// `Stale` and `NeverDriven` are distinct because the operator
/// remediation differs in the same way it does for the staging-sweep
/// predicate: `Stale` means the tick was running and stopped
/// (investigate the CronJob / worker), `NeverDriven` means it has
/// never completed here — the canonical "the chart default is `false`
/// and nobody turned it on" case. Both are undriven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RescanDriveLiveness {
    /// No active policy declares a non-zero cadence, so nothing is
    /// owed. Either there are no policy rows at all, every row is
    /// archived, or every active row declares `rescanIntervalHours: 0`
    /// — which is an operator saying "do not rescan", not a gap.
    NoCadenceDeclared,
    /// A `cron-rescan-tick` completed inside the staleness window, so
    /// the declared cadence is actually being driven.
    Driven {
        /// Shortest declared cadence across active policies.
        cadence: DeclaredCadence,
        /// Whole-second age of the most recent completed tick.
        age_secs: i64,
        /// The staleness threshold the age stayed within.
        threshold_secs: i64,
    },
    /// A `cron-rescan-tick` has completed before, but the most recent
    /// one is older than `staleness_multiplier × shortest interval`.
    Stale {
        /// Shortest declared cadence across active policies.
        cadence: DeclaredCadence,
        /// Whole-second age of the most recent completed tick.
        age_secs: i64,
        /// The staleness threshold the age exceeded.
        threshold_secs: i64,
    },
    /// No `cron-rescan-tick` has ever completed on this deployment
    /// while a cadence is declared.
    NeverDriven {
        /// Shortest declared cadence across active policies.
        cadence: DeclaredCadence,
        /// The staleness threshold no completion exists to compare
        /// against — reported so the line states the window it judged.
        threshold_secs: i64,
    },
}

impl RescanDriveLiveness {
    /// `true` when a cadence is declared and not reachable — the caller
    /// raises the signal. `NoCadenceDeclared` and `Driven` are both
    /// `false`: nothing was promised, or the promise is kept.
    pub fn is_undriven(&self) -> bool {
        matches!(self, Self::Stale { .. } | Self::NeverDriven { .. })
    }

    /// The cadence this outcome is about, or `None` for
    /// [`Self::NoCadenceDeclared`].
    pub fn cadence(&self) -> Option<&DeclaredCadence> {
        match self {
            Self::NoCadenceDeclared => None,
            Self::Driven { cadence, .. }
            | Self::Stale { cadence, .. }
            | Self::NeverDriven { cadence, .. } => Some(cadence),
        }
    }
}

/// The shortest cadence any active policy declares.
///
/// `archived` rows survive in the projection (the reactivation path)
/// but are not active policy, so they are filtered out exactly as
/// `hort-server`'s quarantine-posture log filters them — the number
/// reported has to match what the eligibility query would actually
/// consult. `rescan_interval_hours <= 0` is filtered for the same
/// reason: the query's own predicate is `> 0`, so a `0` policy
/// contributes no cadence to be undriven. (Apply-time validation
/// rejects negatives; the `> 0` form means a row written before that
/// validation cannot invent a cadence here either.)
///
/// Ties break on `name` so the reported policy is stable across boots
/// regardless of the order the repository returned rows in — an
/// operator comparing two boot logs must not see the attribution move
/// on its own.
fn shortest_declared_cadence(policies: &[ScanPolicyProjection]) -> Option<DeclaredCadence> {
    policies
        .iter()
        .filter(|p| !p.archived && p.rescan_interval_hours > 0)
        .min_by(|a, b| {
            a.rescan_interval_hours
                .cmp(&b.rescan_interval_hours)
                .then_with(|| a.name.cmp(&b.name))
        })
        .map(|p| DeclaredCadence {
            interval_hours: p.rescan_interval_hours,
            policy_name: p.name.clone(),
        })
}

/// Decide whether a declared rescan cadence is actually being driven.
///
/// * `policies` — the active `ScanPolicy` projections
///   (`PolicyProjectionRepository::list_active`). Archived and
///   `rescanIntervalHours <= 0` rows are filtered here; the caller
///   hands over the list it already reads for the boot posture log and
///   performs no selection of its own.
/// * `last_completed_at` — newest `jobs.completed_at` for a row with
///   `kind='cron-rescan-tick' AND status='completed'`, or `None` when
///   no such row exists (`JobsRepository::last_completed_at_by_kind`).
/// * `now` — caller-supplied wall-clock (the boot timestamp).
/// * `staleness_multiplier` — how many shortest-intervals may elapse
///   before the cadence counts as undriven. This is deliberately
///   generous: the tick's own schedule (`*/5 * * * *` in the chart) is
///   far tighter than any sane rescan interval, so the window is sized
///   by the *promise* (24 h × 3 = 72 h at the default) and not by the
///   tick cadence. A deployment that drives rescans at all clears it by
///   orders of magnitude, which is what keeps the signal from firing on
///   a worker restart or a day of CronJob suspension.
///
/// Boundary semantics match the sibling liveness predicates: the
/// comparison is **strictly greater than**, so an age exactly equal to
/// the threshold is still `Driven`. A `last_completed_at` in the future
/// (clock skew between the database and the booting pod) yields a
/// negative age, which is `< threshold` and therefore `Driven` — a
/// future timestamp is not evidence of staleness. A zero
/// `staleness_multiplier` degrades to "any non-future completion is
/// stale", which over-alerts rather than silently never-alerting.
pub fn evaluate_rescan_drive_liveness(
    policies: &[ScanPolicyProjection],
    last_completed_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    staleness_multiplier: u32,
) -> RescanDriveLiveness {
    let Some(cadence) = shortest_declared_cadence(policies) else {
        return RescanDriveLiveness::NoCadenceDeclared;
    };

    // `interval_hours` is a positive `i32`, so the hours→seconds step
    // cannot overflow `i64`; the multiplier is operator-supplied and
    // saturates rather than wrapping a nonsense value into a negative
    // threshold (which would flip the predicate into permanent
    // over-alert).
    let threshold_secs = i64::from(cadence.interval_hours)
        .saturating_mul(3_600)
        .saturating_mul(i64::from(staleness_multiplier));

    let Some(last) = last_completed_at else {
        return RescanDriveLiveness::NeverDriven {
            cadence,
            threshold_secs,
        };
    };

    let age_secs = (now - last).num_seconds();

    if age_secs > threshold_secs {
        RescanDriveLiveness::Stale {
            cadence,
            age_secs,
            threshold_secs,
        }
    } else {
        RescanDriveLiveness::Driven {
            cadence,
            age_secs,
            threshold_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::scan_policy::{
        NegligibleAction, ProvenanceMode, ScanEnforcement, SeverityThreshold,
    };
    use crate::events::PolicyScope;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    /// A projection carrying only the three fields this predicate
    /// reads; every other field is a fixed filler so a test reads as
    /// "this policy declares N hours" and nothing else.
    fn policy(name: &str, rescan_interval_hours: i32, archived: bool) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id: Uuid::nil(),
            name: name.to_string(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 0,
            require_approval: false,
            provenance_mode: ProvenanceMode::Off,
            provenance_backends: Vec::new(),
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            stream_version: 0,
            created_at: ts(0),
            updated_at: ts(0),
        }
    }

    /// 24 h × 3 — the threshold every default-shaped case below judges
    /// against.
    const DEFAULT_THRESHOLD_SECS: i64 = 24 * 3_600 * 3;

    // ---- NoCadenceDeclared ------------------------------------------------

    #[test]
    fn no_policies_declares_no_cadence() {
        assert_eq!(
            evaluate_rescan_drive_liveness(&[], None, ts(1_000_000), 3),
            RescanDriveLiveness::NoCadenceDeclared,
            "zero policy rows promise nothing, so there is nothing to be undriven"
        );
    }

    #[test]
    fn only_archived_policies_declare_no_cadence() {
        let policies = [policy("retired", 24, true)];
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, None, ts(1_000_000), 3),
            RescanDriveLiveness::NoCadenceDeclared,
            "an archived row is not active policy and must not raise the signal"
        );
    }

    #[test]
    fn zero_interval_declares_no_cadence() {
        let policies = [policy("no-rescan", 0, false)];
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, None, ts(1_000_000), 3),
            RescanDriveLiveness::NoCadenceDeclared,
            "`rescanIntervalHours: 0` is a declaration that this policy does not \
             rescan — a gap would be the wrong reading of it"
        );
    }

    #[test]
    fn negative_interval_declares_no_cadence() {
        // Apply-time validation rejects negatives; the `> 0` filter
        // means a row written before that validation cannot invent a
        // cadence here either.
        let policies = [policy("corrupt", -5, false)];
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, None, ts(1_000_000), 3),
            RescanDriveLiveness::NoCadenceDeclared,
        );
    }

    // ---- NeverDriven ------------------------------------------------------

    #[test]
    fn declared_cadence_with_no_completed_tick_has_never_been_driven() {
        let policies = [policy("global", 24, false)];
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, None, ts(1_000_000), 3),
            RescanDriveLiveness::NeverDriven {
                cadence: DeclaredCadence {
                    interval_hours: 24,
                    policy_name: "global".to_string(),
                },
                threshold_secs: DEFAULT_THRESHOLD_SECS,
            },
        );
    }

    // ---- Stale ------------------------------------------------------------

    #[test]
    fn tick_older_than_threshold_is_stale() {
        let policies = [policy("global", 24, false)];
        let now = ts(1_000_000);
        let last = now - chrono::Duration::seconds(DEFAULT_THRESHOLD_SECS + 1);
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, Some(last), now, 3),
            RescanDriveLiveness::Stale {
                cadence: DeclaredCadence {
                    interval_hours: 24,
                    policy_name: "global".to_string(),
                },
                age_secs: DEFAULT_THRESHOLD_SECS + 1,
                threshold_secs: DEFAULT_THRESHOLD_SECS,
            },
        );
    }

    #[test]
    fn zero_multiplier_makes_any_past_completion_stale() {
        // Degenerate operator input: over-alerting is the safe
        // direction, silently never-alerting is not.
        let policies = [policy("global", 24, false)];
        let now = ts(1_000_000);
        assert_eq!(
            evaluate_rescan_drive_liveness(
                &policies,
                Some(now - chrono::Duration::seconds(1)),
                now,
                0
            ),
            RescanDriveLiveness::Stale {
                cadence: DeclaredCadence {
                    interval_hours: 24,
                    policy_name: "global".to_string(),
                },
                age_secs: 1,
                threshold_secs: 0,
            },
        );
    }

    // ---- Driven -----------------------------------------------------------

    #[test]
    fn tick_inside_window_is_driven() {
        let policies = [policy("global", 24, false)];
        let now = ts(1_000_000);
        let last = now - chrono::Duration::seconds(60);
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, Some(last), now, 3),
            RescanDriveLiveness::Driven {
                cadence: DeclaredCadence {
                    interval_hours: 24,
                    policy_name: "global".to_string(),
                },
                age_secs: 60,
                threshold_secs: DEFAULT_THRESHOLD_SECS,
            },
        );
    }

    #[test]
    fn age_exactly_at_threshold_is_still_driven() {
        // Strictly-greater-than boundary, matching the sibling
        // liveness predicates.
        let policies = [policy("global", 24, false)];
        let now = ts(1_000_000);
        let last = now - chrono::Duration::seconds(DEFAULT_THRESHOLD_SECS);
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, Some(last), now, 3),
            RescanDriveLiveness::Driven {
                cadence: DeclaredCadence {
                    interval_hours: 24,
                    policy_name: "global".to_string(),
                },
                age_secs: DEFAULT_THRESHOLD_SECS,
                threshold_secs: DEFAULT_THRESHOLD_SECS,
            },
        );
    }

    #[test]
    fn future_completion_timestamp_is_driven_not_stale() {
        // Clock skew between the database and the booting pod is not
        // evidence that nothing is rescanning.
        let policies = [policy("global", 24, false)];
        let now = ts(1_000_000);
        let last = now + chrono::Duration::seconds(600);
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, Some(last), now, 3),
            RescanDriveLiveness::Driven {
                cadence: DeclaredCadence {
                    interval_hours: 24,
                    policy_name: "global".to_string(),
                },
                age_secs: -600,
                threshold_secs: DEFAULT_THRESHOLD_SECS,
            },
        );
    }

    // ---- shortest-cadence selection ---------------------------------------

    #[test]
    fn shortest_declared_interval_wins() {
        let policies = [
            policy("weekly", 168, false),
            policy("hourly", 1, false),
            policy("daily", 24, false),
        ];
        let liveness = evaluate_rescan_drive_liveness(&policies, None, ts(1_000_000), 3);
        assert_eq!(
            liveness.cadence(),
            Some(&DeclaredCadence {
                interval_hours: 1,
                policy_name: "hourly".to_string(),
            }),
            "the tightest promise is the one to report — every longer cadence \
             is undriven too"
        );
        assert_eq!(
            liveness,
            RescanDriveLiveness::NeverDriven {
                cadence: DeclaredCadence {
                    interval_hours: 1,
                    policy_name: "hourly".to_string(),
                },
                // 1 h × 3 — the shortest declared cadence, not the
                // 24 h default any other policy here carries.
                threshold_secs: 3_600 * 3,
            },
        );
    }

    #[test]
    fn equal_shortest_intervals_break_on_name_independently_of_row_order() {
        let forward = [policy("zeta", 12, false), policy("alpha", 12, false)];
        let reversed = [policy("alpha", 12, false), policy("zeta", 12, false)];
        let expected = Some(DeclaredCadence {
            interval_hours: 12,
            policy_name: "alpha".to_string(),
        });
        assert_eq!(
            evaluate_rescan_drive_liveness(&forward, None, ts(0), 3)
                .cadence()
                .cloned(),
            expected,
        );
        assert_eq!(
            evaluate_rescan_drive_liveness(&reversed, None, ts(0), 3)
                .cadence()
                .cloned(),
            expected,
            "the attribution must not move between boots because the repository \
             returned rows in a different order"
        );
    }

    #[test]
    fn archived_shortest_row_does_not_shadow_the_active_cadence() {
        let policies = [
            policy("retired-hourly", 1, true),
            policy("active-daily", 24, false),
        ];
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, None, ts(0), 3).cadence(),
            Some(&DeclaredCadence {
                interval_hours: 24,
                policy_name: "active-daily".to_string(),
            }),
        );
    }

    #[test]
    fn zero_interval_row_does_not_shadow_the_active_cadence() {
        let policies = [
            policy("opted-out", 0, false),
            policy("active-daily", 24, false),
        ];
        assert_eq!(
            evaluate_rescan_drive_liveness(&policies, None, ts(0), 3).cadence(),
            Some(&DeclaredCadence {
                interval_hours: 24,
                policy_name: "active-daily".to_string(),
            }),
        );
    }

    #[test]
    fn absurd_multiplier_saturates_rather_than_wrapping_negative() {
        // An `i64` wrap would produce a negative threshold and flip the
        // predicate into permanent over-alert.
        let policies = [policy("global", i32::MAX, false)];
        let now = ts(1_000_000);
        let liveness = evaluate_rescan_drive_liveness(
            &policies,
            Some(now - chrono::Duration::seconds(1)),
            now,
            u32::MAX,
        );
        assert_eq!(
            liveness,
            RescanDriveLiveness::Driven {
                cadence: DeclaredCadence {
                    interval_hours: i32::MAX,
                    policy_name: "global".to_string(),
                },
                age_secs: 1,
                threshold_secs: i64::MAX,
            },
        );
    }

    // ---- accessors --------------------------------------------------------

    #[test]
    fn is_undriven_is_true_for_stale_and_never_driven_only() {
        let cadence = DeclaredCadence {
            interval_hours: 24,
            policy_name: "global".to_string(),
        };
        assert!(!RescanDriveLiveness::NoCadenceDeclared.is_undriven());
        assert!(!RescanDriveLiveness::Driven {
            cadence: cadence.clone(),
            age_secs: 0,
            threshold_secs: 1,
        }
        .is_undriven());
        assert!(RescanDriveLiveness::Stale {
            cadence: cadence.clone(),
            age_secs: 2,
            threshold_secs: 1,
        }
        .is_undriven());
        assert!(RescanDriveLiveness::NeverDriven {
            cadence,
            threshold_secs: 1,
        }
        .is_undriven());
    }

    #[test]
    fn cadence_is_none_only_for_no_cadence_declared() {
        let cadence = DeclaredCadence {
            interval_hours: 24,
            policy_name: "global".to_string(),
        };
        assert_eq!(RescanDriveLiveness::NoCadenceDeclared.cadence(), None);
        assert_eq!(
            RescanDriveLiveness::Driven {
                cadence: cadence.clone(),
                age_secs: 0,
                threshold_secs: 1,
            }
            .cadence(),
            Some(&cadence),
        );
        assert_eq!(
            RescanDriveLiveness::Stale {
                cadence: cadence.clone(),
                age_secs: 2,
                threshold_secs: 1,
            }
            .cadence(),
            Some(&cadence),
        );
        assert_eq!(
            RescanDriveLiveness::NeverDriven {
                cadence: cadence.clone(),
                threshold_secs: 1,
            }
            .cadence(),
            Some(&cadence),
        );
    }

    #[test]
    fn outcome_and_cadence_are_debug_clone_and_eq() {
        let cadence = DeclaredCadence {
            interval_hours: 24,
            policy_name: "global".to_string(),
        };
        assert_eq!(cadence.clone(), cadence);
        assert!(format!("{cadence:?}").contains("global"));
        let outcome = RescanDriveLiveness::NeverDriven {
            cadence,
            threshold_secs: 1,
        };
        assert_eq!(outcome.clone(), outcome);
        assert!(format!("{outcome:?}").contains("NeverDriven"));
        assert_ne!(outcome, RescanDriveLiveness::NoCadenceDeclared);
    }
}
