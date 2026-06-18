//! Retention predicate algebra (`PolicyPredicate`).
//!
//! The four security-driven variants consume scan projections
//! (`scan_findings.severity` / `.cvss_score` / advisory `fixed_versions`
//! / earliest `ScanCompleted`). Predicate *evaluation* against live
//! projection data is the use-case's job; this module owns only the pure
//! predicate value object, its structural validation, and the
//! `is_security_driven` classification that the §6-invariant-7
//! freshness gate and the §6-invariant-8 apply-time warning are keyed
//! off.
//!
//! ## Duration wire form
//!
//! `AgeExceeds` / `UnusedFor` / `HasFindingDetectedFor` carry a
//! `Duration`. The domain's established convention is integer seconds
//! (`quarantine_duration_secs: i64`, `Duration::from_secs(3600)`);
//! `chrono::Duration` has no first-class `serde` impl and `std::time::
//! Duration`'s default `serde` form is a `{secs,nanos}` struct that is
//! awkward to hand-author in operator YAML. The predicate therefore
//! stores `u64` seconds and exposes a typed
//! [`std::time::Duration`] accessor. Seconds is the smallest unit any
//! retention TTL is ever expressed in.

use serde::{Deserialize, Serialize};

use crate::entities::scan_policy::SeverityThreshold;
use crate::error::{DomainError, DomainResult};

/// Boolean combinator for [`PolicyPredicate::Composite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BooleanOp {
    /// All child predicates must match.
    And,
    /// At least one child predicate must match.
    Or,
}

/// Maximum nesting depth of a [`PolicyPredicate::Composite`] tree.
///
/// A retention predicate is operator-authored YAML; a pathologically
/// deep tree is a misconfiguration (and a stack-recursion hazard for
/// the evaluator). Three levels is far more than the canonical
/// single-level `Composite(And, [..])` operator pattern ever needs.
const MAX_COMPOSITE_DEPTH: usize = 8;

/// Maximum number of direct children in a single `Composite`.
const MAX_COMPOSITE_CHILDREN: usize = 64;

/// Maximum length of a CVSS score that is still meaningful (CVSS v3.1
/// caps at 10.0). Bounded so a malformed envelope cannot persist a
/// nonsense threshold that no finding could ever satisfy *or* that
/// would match every finding.
const MAX_CVSS: f32 = 10.0;

/// A retention match predicate.
///
/// `is_security_driven()` returns `true` for any tree that contains at
/// least one of the four scan-data variants — this is the boundary the
/// scan-freshness gate and the
/// direct-upload apply-warning are evaluated on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyPredicate {
    /// Match if the artifact is older than the given duration (seconds).
    AgeExceeds(u64),
    /// Match if the artifact has not been downloaded for the given
    /// duration (seconds).
    UnusedFor(u64),
    /// Keep only the most-recent `N` versions; older ones match.
    KeepLastN(u32),
    /// Boolean combination of child predicates.
    Composite(BooleanOp, Vec<PolicyPredicate>),

    // ---- security-driven (consume scan projections) ---------------------
    /// Match if any current finding's severity is at-or-above the
    /// threshold. Source: `scan_findings.severity`.
    HasFindingAboveSeverity(SeverityThreshold),
    /// Match if any current finding's CVSS score is at-or-above the
    /// value. Source: `scan_findings.cvss_score` (NULL counts as
    /// not-matched — some advisories carry no CVSS).
    HasFindingAboveCvss(f32),
    /// Match if any current finding has a non-empty `fixed_versions`
    /// array on its source advisory (an upgrade exists somewhere
    /// upstream — does NOT require the fix to be in this repository).
    HasFixAvailable,
    /// Match only after a finding has been present for the given
    /// duration (seconds). The grace-period anchor for
    /// "vulnerable for ≥ N days with a fix" composite policies.
    HasFindingDetectedFor(u64),
}

impl PolicyPredicate {
    /// `true` iff this predicate (or any descendant of a `Composite`)
    /// is one of the four scan-data variants.
    ///
    /// The scan-freshness gate skips artifacts whose most recent
    /// `ScanCompleted` is stale **only** for security-driven predicates;
    /// the apply warning fires **only** when a security-driven
    /// predicate's scope does not exclude `IngestSource(Direct)`. Both
    /// keys are this classification, so it lives in the domain (pure)
    /// even though the gate and the warning themselves live in the
    /// app/apply layers.
    pub fn is_security_driven(&self) -> bool {
        match self {
            Self::HasFindingAboveSeverity(_)
            | Self::HasFindingAboveCvss(_)
            | Self::HasFixAvailable
            | Self::HasFindingDetectedFor(_) => true,
            Self::Composite(_, children) => children.iter().any(Self::is_security_driven),
            Self::AgeExceeds(_) | Self::UnusedFor(_) | Self::KeepLastN(_) => false,
        }
    }

    /// Structural validation. Pure — no I/O, no projection access.
    ///
    /// - `Composite` must be non-empty, within child- and depth-bounds.
    /// - `HasFindingAboveCvss` must be a finite, in-range `[0.0, 10.0]`
    ///   score (a NaN / negative / >10 threshold is a misconfiguration
    ///   that would otherwise silently match nothing or everything).
    /// - `KeepLastN(0)` is rejected — "keep zero versions" is almost
    ///   never the operator's intent and would expire *every* artifact
    ///   in scope on the first sweep; the operator must say so via an
    ///   explicit age/manual policy instead.
    /// - The duration-bearing variants reject `0` seconds — a
    ///   zero-second TTL would expire artifacts the instant they are
    ///   ingested, which is a footgun, not a feature.
    pub fn validate(&self) -> DomainResult<()> {
        self.validate_at_depth(0)
    }

    fn validate_at_depth(&self, depth: usize) -> DomainResult<()> {
        match self {
            Self::AgeExceeds(secs) | Self::UnusedFor(secs) | Self::HasFindingDetectedFor(secs) => {
                if *secs == 0 {
                    return Err(DomainError::Validation(
                        "duration-bearing predicate must be > 0 seconds".into(),
                    ));
                }
                Ok(())
            }
            Self::KeepLastN(n) => {
                if *n == 0 {
                    return Err(DomainError::Validation(
                        "KeepLastN(0) would expire every artifact in scope; \
                         use an explicit age or manual policy instead"
                            .into(),
                    ));
                }
                Ok(())
            }
            Self::HasFindingAboveCvss(score) => {
                if !score.is_finite() {
                    return Err(DomainError::Validation(
                        "HasFindingAboveCvss threshold must be a finite number".into(),
                    ));
                }
                if *score < 0.0 || *score > MAX_CVSS {
                    return Err(DomainError::Validation(format!(
                        "HasFindingAboveCvss threshold must be within [0.0, {MAX_CVSS}] \
                         (got {score})"
                    )));
                }
                Ok(())
            }
            Self::Composite(_, children) => {
                if depth >= MAX_COMPOSITE_DEPTH {
                    return Err(DomainError::Validation(format!(
                        "Composite predicate nesting exceeds the maximum depth of \
                         {MAX_COMPOSITE_DEPTH}"
                    )));
                }
                if children.is_empty() {
                    return Err(DomainError::Validation(
                        "Composite predicate must have at least one child".into(),
                    ));
                }
                if children.len() > MAX_COMPOSITE_CHILDREN {
                    return Err(DomainError::Validation(format!(
                        "Composite predicate exceeds the maximum of \
                         {MAX_COMPOSITE_CHILDREN} children (got {})",
                        children.len()
                    )));
                }
                for child in children {
                    child.validate_at_depth(depth + 1)?;
                }
                Ok(())
            }
            Self::HasFindingAboveSeverity(_) | Self::HasFixAvailable => Ok(()),
        }
    }

    /// Typed accessor for the duration-bearing variants. `None` for any
    /// non-duration variant. Pure helper for the B3 evaluator so it
    /// never re-derives the seconds → `Duration` conversion ad hoc.
    pub fn as_duration(&self) -> Option<std::time::Duration> {
        match self {
            Self::AgeExceeds(s) | Self::UnusedFor(s) | Self::HasFindingDetectedFor(s) => {
                Some(std::time::Duration::from_secs(*s))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_security_driven --------------------------------------------------

    #[test]
    fn non_security_variants_are_not_security_driven() {
        assert!(!PolicyPredicate::AgeExceeds(60).is_security_driven());
        assert!(!PolicyPredicate::UnusedFor(60).is_security_driven());
        assert!(!PolicyPredicate::KeepLastN(3).is_security_driven());
    }

    #[test]
    fn each_security_variant_is_security_driven() {
        assert!(
            PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High).is_security_driven()
        );
        assert!(PolicyPredicate::HasFindingAboveCvss(9.0).is_security_driven());
        assert!(PolicyPredicate::HasFixAvailable.is_security_driven());
        assert!(PolicyPredicate::HasFindingDetectedFor(86_400).is_security_driven());
    }

    #[test]
    fn composite_is_security_driven_if_any_child_is() {
        let p = PolicyPredicate::Composite(
            BooleanOp::And,
            vec![
                PolicyPredicate::AgeExceeds(60),
                PolicyPredicate::HasFixAvailable,
            ],
        );
        assert!(p.is_security_driven());
    }

    #[test]
    fn composite_is_not_security_driven_if_no_child_is() {
        let p = PolicyPredicate::Composite(
            BooleanOp::Or,
            vec![
                PolicyPredicate::AgeExceeds(60),
                PolicyPredicate::KeepLastN(5),
            ],
        );
        assert!(!p.is_security_driven());
    }

    #[test]
    fn nested_composite_propagates_security_flag() {
        let p = PolicyPredicate::Composite(
            BooleanOp::And,
            vec![PolicyPredicate::Composite(
                BooleanOp::Or,
                vec![PolicyPredicate::HasFindingAboveCvss(7.5)],
            )],
        );
        assert!(p.is_security_driven());
    }

    // -- validate: duration-bearing -----------------------------------------

    #[test]
    fn age_exceeds_positive_ok() {
        PolicyPredicate::AgeExceeds(1).validate().unwrap();
    }

    #[test]
    fn age_exceeds_zero_rejected() {
        let err = PolicyPredicate::AgeExceeds(0).validate().unwrap_err();
        assert!(err.to_string().contains("> 0 seconds"));
    }

    #[test]
    fn unused_for_zero_rejected() {
        assert!(PolicyPredicate::UnusedFor(0).validate().is_err());
    }

    #[test]
    fn unused_for_positive_ok() {
        PolicyPredicate::UnusedFor(3600).validate().unwrap();
    }

    #[test]
    fn has_finding_detected_for_zero_rejected() {
        assert!(PolicyPredicate::HasFindingDetectedFor(0)
            .validate()
            .is_err());
    }

    #[test]
    fn has_finding_detected_for_positive_ok() {
        PolicyPredicate::HasFindingDetectedFor(604_800)
            .validate()
            .unwrap();
    }

    // -- validate: KeepLastN -------------------------------------------------

    #[test]
    fn keep_last_n_positive_ok() {
        PolicyPredicate::KeepLastN(1).validate().unwrap();
    }

    #[test]
    fn keep_last_n_zero_rejected() {
        let err = PolicyPredicate::KeepLastN(0).validate().unwrap_err();
        assert!(err.to_string().contains("every artifact"));
    }

    // -- validate: HasFindingAboveCvss --------------------------------------

    #[test]
    fn cvss_in_range_ok() {
        PolicyPredicate::HasFindingAboveCvss(0.0)
            .validate()
            .unwrap();
        PolicyPredicate::HasFindingAboveCvss(9.8)
            .validate()
            .unwrap();
        PolicyPredicate::HasFindingAboveCvss(10.0)
            .validate()
            .unwrap();
    }

    #[test]
    fn cvss_negative_rejected() {
        let err = PolicyPredicate::HasFindingAboveCvss(-0.1)
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("within"));
    }

    #[test]
    fn cvss_over_ten_rejected() {
        let err = PolicyPredicate::HasFindingAboveCvss(10.1)
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("within"));
    }

    #[test]
    fn cvss_nan_rejected() {
        let err = PolicyPredicate::HasFindingAboveCvss(f32::NAN)
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("finite"));
    }

    #[test]
    fn cvss_infinity_rejected() {
        assert!(PolicyPredicate::HasFindingAboveCvss(f32::INFINITY)
            .validate()
            .is_err());
    }

    // -- validate: severity / fix-available (always ok) ---------------------

    #[test]
    fn has_finding_above_severity_ok() {
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::Critical)
            .validate()
            .unwrap();
    }

    #[test]
    fn has_fix_available_ok() {
        PolicyPredicate::HasFixAvailable.validate().unwrap();
    }

    // -- validate: Composite -------------------------------------------------

    #[test]
    fn composite_non_empty_ok() {
        PolicyPredicate::Composite(BooleanOp::And, vec![PolicyPredicate::HasFixAvailable])
            .validate()
            .unwrap();
    }

    #[test]
    fn composite_empty_rejected() {
        let err = PolicyPredicate::Composite(BooleanOp::Or, vec![])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("at least one child"));
    }

    #[test]
    fn composite_propagates_child_validation_error() {
        // A child with a zero duration must fail the whole tree.
        let err = PolicyPredicate::Composite(BooleanOp::And, vec![PolicyPredicate::AgeExceeds(0)])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("> 0 seconds"));
    }

    #[test]
    fn composite_too_many_children_rejected() {
        let kids = vec![PolicyPredicate::HasFixAvailable; MAX_COMPOSITE_CHILDREN + 1];
        let err = PolicyPredicate::Composite(BooleanOp::And, kids)
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }

    #[test]
    fn composite_at_child_limit_ok() {
        let kids = vec![PolicyPredicate::HasFixAvailable; MAX_COMPOSITE_CHILDREN];
        PolicyPredicate::Composite(BooleanOp::And, kids)
            .validate()
            .unwrap();
    }

    #[test]
    fn composite_over_max_depth_rejected() {
        // Build a Composite chain one level deeper than the limit.
        let mut p = PolicyPredicate::HasFixAvailable;
        for _ in 0..=MAX_COMPOSITE_DEPTH {
            p = PolicyPredicate::Composite(BooleanOp::And, vec![p]);
        }
        let err = p.validate().unwrap_err();
        assert!(err.to_string().contains("depth"));
    }

    #[test]
    fn composite_at_max_depth_ok() {
        // Exactly MAX_COMPOSITE_DEPTH nested Composites is allowed; the
        // leaf at depth == MAX_COMPOSITE_DEPTH is a non-Composite.
        let mut p = PolicyPredicate::HasFixAvailable;
        for _ in 0..MAX_COMPOSITE_DEPTH {
            p = PolicyPredicate::Composite(BooleanOp::And, vec![p]);
        }
        p.validate().unwrap();
    }

    // -- as_duration ---------------------------------------------------------

    #[test]
    fn as_duration_for_duration_variants() {
        assert_eq!(
            PolicyPredicate::AgeExceeds(5).as_duration(),
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(
            PolicyPredicate::UnusedFor(7).as_duration(),
            Some(std::time::Duration::from_secs(7))
        );
        assert_eq!(
            PolicyPredicate::HasFindingDetectedFor(9).as_duration(),
            Some(std::time::Duration::from_secs(9))
        );
    }

    #[test]
    fn as_duration_none_for_non_duration_variants() {
        assert_eq!(PolicyPredicate::KeepLastN(3).as_duration(), None);
        assert_eq!(PolicyPredicate::HasFixAvailable.as_duration(), None);
        assert_eq!(
            PolicyPredicate::HasFindingAboveCvss(1.0).as_duration(),
            None
        );
        assert_eq!(
            PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::Low).as_duration(),
            None
        );
        assert_eq!(
            PolicyPredicate::Composite(BooleanOp::Or, vec![PolicyPredicate::HasFixAvailable])
                .as_duration(),
            None
        );
    }

    // -- BooleanOp -----------------------------------------------------------

    #[test]
    fn boolean_op_clone_copy_eq_debug() {
        let a = BooleanOp::And;
        let b = a;
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(BooleanOp::And, BooleanOp::Or);
        assert!(format!("{:?}", BooleanOp::Or).contains("Or"));
    }

    // -- serde round-trip (wire stability) ----------------------------------

    #[test]
    fn serde_round_trip_every_variant() {
        let variants = vec![
            PolicyPredicate::AgeExceeds(86_400),
            PolicyPredicate::UnusedFor(3600),
            PolicyPredicate::KeepLastN(10),
            PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
            PolicyPredicate::HasFindingAboveCvss(9.0),
            PolicyPredicate::HasFixAvailable,
            PolicyPredicate::HasFindingDetectedFor(604_800),
            PolicyPredicate::Composite(
                BooleanOp::And,
                vec![
                    PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                    PolicyPredicate::HasFixAvailable,
                    PolicyPredicate::HasFindingDetectedFor(604_800),
                ],
            ),
        ];
        for v in variants {
            let json = serde_json::to_value(&v).unwrap();
            let back: PolicyPredicate = serde_json::from_value(json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn clone_debug_eq_cover() {
        let a = PolicyPredicate::KeepLastN(5);
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, PolicyPredicate::KeepLastN(6));
        assert!(format!("{a:?}").contains("KeepLastN"));
    }
}
