//! CVE-severity-threshold evaluator.
//!
//! ## Mapping
//!
//! See [`crate::policy::threshold`] for the canonical
//! `SeverityThreshold → blocked-tiers` table. This module reads the
//! [`SeveritySummary`] tier counts and emits one violation per tier
//! that has any finding above the configured threshold:
//!
//! | Threshold | Tiers that produce violations            |
//! |-----------|------------------------------------------|
//! | Critical  | critical                                 |
//! | High      | critical, high                           |
//! | Medium    | critical, high, medium                   |
//! | Low       | critical, high, medium, low              |
//!
//! `negligible` never produces a violation under any threshold —
//! informational findings are not enforcement findings (see
//! `threshold` module rustdoc).

use crate::entities::scan_policy::SeverityThreshold;
use crate::events::{PolicyViolation, SeveritySummary};

use super::threshold::finding_exceeds_threshold;

/// Stable rule identifier emitted by every violation produced here.
pub const RULE: &str = "cve-severity-threshold";

/// Returns one violation per severity tier whose count is non-zero
/// AND whose tier exceeds the configured `threshold`.
///
/// `filtered` is the [`SeveritySummary`] **after** exclusions have
/// been applied (see [`crate::policy::exclusion::filter_excluded_findings`])
/// — this evaluator does no exclusion logic itself.
///
/// The `severity` field of each emitted [`PolicyViolation`] is the
/// tier's own [`SeverityThreshold`] (not the policy's threshold) — the
/// accumulator's
/// [`escalate_action_by_severity`](crate::policy::escalate_action_by_severity)
/// uses this to drive `Allow → Warn → Block` escalation.
pub fn evaluate_cve_thresholds(
    filtered: &SeveritySummary,
    threshold: SeverityThreshold,
) -> Vec<PolicyViolation> {
    // Per-tier walk in severity-descending order so the violation list
    // matches the operator's mental model ("critical first").
    let tiers: &[(SeverityThreshold, u32)] = &[
        (SeverityThreshold::Critical, filtered.critical),
        (SeverityThreshold::High, filtered.high),
        (SeverityThreshold::Medium, filtered.medium),
        (SeverityThreshold::Low, filtered.low),
    ];

    tiers
        .iter()
        .filter(|(tier, count)| *count > 0 && finding_exceeds_threshold(*tier, threshold))
        .map(|(tier, count)| PolicyViolation {
            rule: RULE.to_string(),
            severity: *tier,
            message: format!(
                "Found {count} {tier} severity vulnerabilities (threshold: {threshold})"
            ),
            details: serde_json::json!({
                "count": count,
                "tier": tier.to_string(),
                "threshold": threshold.to_string(),
            }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> SeveritySummary {
        SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        }
    }

    fn one_per_tier() -> SeveritySummary {
        SeveritySummary {
            critical: 1,
            high: 1,
            medium: 1,
            low: 1,
            negligible: 1,
        }
    }

    // ---- zero-finding fast path --------------------------------------------

    #[test]
    fn zero_findings_no_violations_under_critical() {
        let v = evaluate_cve_thresholds(&empty(), SeverityThreshold::Critical);
        assert!(v.is_empty());
    }

    #[test]
    fn zero_findings_no_violations_under_high() {
        let v = evaluate_cve_thresholds(&empty(), SeverityThreshold::High);
        assert!(v.is_empty());
    }

    #[test]
    fn zero_findings_no_violations_under_medium() {
        let v = evaluate_cve_thresholds(&empty(), SeverityThreshold::Medium);
        assert!(v.is_empty());
    }

    #[test]
    fn zero_findings_no_violations_under_low() {
        let v = evaluate_cve_thresholds(&empty(), SeverityThreshold::Low);
        assert!(v.is_empty());
    }

    // ---- threshold = Critical (only `critical` tier blocks) ----------------

    #[test]
    fn critical_threshold_critical_finding_one_violation() {
        let mut s = empty();
        s.critical = 3;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Critical);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::Critical);
        assert_eq!(v[0].rule, RULE);
        assert_eq!(v[0].details["count"].as_u64(), Some(3));
    }

    #[test]
    fn critical_threshold_high_finding_no_violation() {
        let mut s = empty();
        s.high = 5;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Critical);
        assert!(v.is_empty(), "high under critical threshold must not block");
    }

    #[test]
    fn critical_threshold_medium_finding_no_violation() {
        let mut s = empty();
        s.medium = 5;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Critical);
        assert!(v.is_empty());
    }

    #[test]
    fn critical_threshold_low_finding_no_violation() {
        let mut s = empty();
        s.low = 5;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Critical);
        assert!(v.is_empty());
    }

    // ---- threshold = High (critical + high block) --------------------------

    #[test]
    fn high_threshold_critical_finding_one_violation() {
        let mut s = empty();
        s.critical = 1;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::High);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::Critical);
    }

    #[test]
    fn high_threshold_high_finding_one_violation() {
        let mut s = empty();
        s.high = 2;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::High);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::High);
    }

    #[test]
    fn high_threshold_medium_finding_no_violation() {
        let mut s = empty();
        s.medium = 5;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::High);
        assert!(v.is_empty());
    }

    #[test]
    fn high_threshold_low_finding_no_violation() {
        let mut s = empty();
        s.low = 5;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::High);
        assert!(v.is_empty());
    }

    // ---- threshold = Medium (critical + high + medium block) ---------------

    #[test]
    fn medium_threshold_critical_finding_one_violation() {
        let mut s = empty();
        s.critical = 1;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Medium);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::Critical);
    }

    #[test]
    fn medium_threshold_high_finding_one_violation() {
        let mut s = empty();
        s.high = 1;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Medium);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::High);
    }

    #[test]
    fn medium_threshold_medium_finding_one_violation() {
        let mut s = empty();
        s.medium = 1;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Medium);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::Medium);
    }

    #[test]
    fn medium_threshold_low_finding_no_violation() {
        let mut s = empty();
        s.low = 5;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Medium);
        assert!(v.is_empty());
    }

    // ---- threshold = Low (every meaningful tier blocks) --------------------

    #[test]
    fn low_threshold_critical_finding_one_violation() {
        let mut s = empty();
        s.critical = 1;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Low);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::Critical);
    }

    #[test]
    fn low_threshold_high_finding_one_violation() {
        let mut s = empty();
        s.high = 1;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Low);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::High);
    }

    #[test]
    fn low_threshold_medium_finding_one_violation() {
        let mut s = empty();
        s.medium = 1;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Low);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::Medium);
    }

    #[test]
    fn low_threshold_low_finding_one_violation() {
        let mut s = empty();
        s.low = 1;
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Low);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, SeverityThreshold::Low);
    }

    // ---- multi-tier + ordering --------------------------------------------

    #[test]
    fn one_per_tier_under_low_threshold_four_violations_in_descending_order() {
        let s = one_per_tier();
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::Low);
        assert_eq!(v.len(), 4);
        assert_eq!(v[0].severity, SeverityThreshold::Critical);
        assert_eq!(v[1].severity, SeverityThreshold::High);
        assert_eq!(v[2].severity, SeverityThreshold::Medium);
        assert_eq!(v[3].severity, SeverityThreshold::Low);
    }

    #[test]
    fn one_per_tier_under_high_threshold_two_violations_critical_and_high_only() {
        let s = one_per_tier();
        let v = evaluate_cve_thresholds(&s, SeverityThreshold::High);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].severity, SeverityThreshold::Critical);
        assert_eq!(v[1].severity, SeverityThreshold::High);
    }

    #[test]
    fn negligible_count_never_produces_violation() {
        // Negligible has no SeverityThreshold variant; the tiers walk
        // skips it entirely. A negligible-only summary must produce
        // zero violations under every threshold.
        let mut s = empty();
        s.negligible = 100;
        for threshold in [
            SeverityThreshold::Critical,
            SeverityThreshold::High,
            SeverityThreshold::Medium,
            SeverityThreshold::Low,
        ] {
            let v = evaluate_cve_thresholds(&s, threshold);
            assert!(
                v.is_empty(),
                "threshold {threshold:?}: negligible-only summary must not violate"
            );
        }
    }

    #[test]
    fn produced_violations_validate_under_event_caps() {
        let s = SeveritySummary {
            critical: 10,
            high: 20,
            medium: 30,
            low: 40,
            negligible: 0,
        };
        for v in evaluate_cve_thresholds(&s, SeverityThreshold::Low) {
            v.validate().expect("produced violation must validate");
        }
    }
}
