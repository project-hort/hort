//! Severity-threshold mapping helpers for policy evaluation.
//!
//! These pure functions translate the operator-facing
//! [`SeverityThreshold`] (the *minimum* severity that should trigger
//! enforcement) into per-finding decisions and aggregate counts.
//!
//! Mapping:
//!
//! | Threshold | Severities that exceed it          |
//! |-----------|-------------------------------------|
//! | Critical  | critical only                       |
//! | High      | critical, high                      |
//! | Medium    | critical, high, medium              |
//! | Low       | critical, high, medium, low         |
//!
//! `negligible` never triggers enforcement under any threshold —
//! a `negligible` finding is informational only.

use crate::entities::scan_policy::SeverityThreshold;
use crate::events::SeveritySummary;

/// Returns true when a finding of `severity` exceeds the policy's
/// configured `threshold`.
///
/// Matches the table in this module's docstring: a `critical` policy
/// only blocks `critical`; `low` blocks every meaningful severity.
pub fn finding_exceeds_threshold(
    severity: SeverityThreshold,
    threshold: SeverityThreshold,
) -> bool {
    severity_rank(severity) >= severity_rank(threshold)
}

/// Sums the [`SeveritySummary`] counts whose severity tier exceeds
/// `threshold`. Callers that need the per-tier
/// breakdown construct violations from the original summary.
pub fn count_findings_above_threshold(
    summary: &SeveritySummary,
    threshold: SeverityThreshold,
) -> u32 {
    let tiers: &[(SeverityThreshold, u32)] = &[
        (SeverityThreshold::Critical, summary.critical),
        (SeverityThreshold::High, summary.high),
        (SeverityThreshold::Medium, summary.medium),
        (SeverityThreshold::Low, summary.low),
    ];
    tiers
        .iter()
        .filter(|(tier, _)| finding_exceeds_threshold(*tier, threshold))
        .map(|(_, count)| *count)
        .sum()
}

/// Internal numeric ranking — higher means "more severe." Critical is 4
/// (most severe), Low is 1. `negligible` has no [`SeverityThreshold`]
/// variant, by design — it never blocks.
fn severity_rank(s: SeverityThreshold) -> u8 {
    match s {
        SeverityThreshold::Critical => 4,
        SeverityThreshold::High => 3,
        SeverityThreshold::Medium => 2,
        SeverityThreshold::Low => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_summary() -> SeveritySummary {
        SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        }
    }

    // ---- finding_exceeds_threshold ----
    //
    // 16 input pairs total: 4 severities x 4 thresholds. Each on its own
    // test for clarity (per the backlog's "every SeverityThreshold mapping
    // pair" coverage requirement).

    // -- threshold = Critical (only critical blocks) --

    #[test]
    fn critical_finding_exceeds_critical_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::Critical,
            SeverityThreshold::Critical
        ));
    }

    #[test]
    fn high_finding_does_not_exceed_critical_threshold() {
        assert!(!finding_exceeds_threshold(
            SeverityThreshold::High,
            SeverityThreshold::Critical
        ));
    }

    #[test]
    fn medium_finding_does_not_exceed_critical_threshold() {
        assert!(!finding_exceeds_threshold(
            SeverityThreshold::Medium,
            SeverityThreshold::Critical
        ));
    }

    #[test]
    fn low_finding_does_not_exceed_critical_threshold() {
        assert!(!finding_exceeds_threshold(
            SeverityThreshold::Low,
            SeverityThreshold::Critical
        ));
    }

    // -- threshold = High (critical + high block) --

    #[test]
    fn critical_finding_exceeds_high_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::Critical,
            SeverityThreshold::High
        ));
    }

    #[test]
    fn high_finding_exceeds_high_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::High,
            SeverityThreshold::High
        ));
    }

    #[test]
    fn medium_finding_does_not_exceed_high_threshold() {
        assert!(!finding_exceeds_threshold(
            SeverityThreshold::Medium,
            SeverityThreshold::High
        ));
    }

    #[test]
    fn low_finding_does_not_exceed_high_threshold() {
        assert!(!finding_exceeds_threshold(
            SeverityThreshold::Low,
            SeverityThreshold::High
        ));
    }

    // -- threshold = Medium (critical + high + medium block) --

    #[test]
    fn critical_finding_exceeds_medium_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::Critical,
            SeverityThreshold::Medium
        ));
    }

    #[test]
    fn high_finding_exceeds_medium_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::High,
            SeverityThreshold::Medium
        ));
    }

    #[test]
    fn medium_finding_exceeds_medium_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::Medium,
            SeverityThreshold::Medium
        ));
    }

    #[test]
    fn low_finding_does_not_exceed_medium_threshold() {
        assert!(!finding_exceeds_threshold(
            SeverityThreshold::Low,
            SeverityThreshold::Medium
        ));
    }

    // -- threshold = Low (everything blocks) --

    #[test]
    fn critical_finding_exceeds_low_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::Critical,
            SeverityThreshold::Low
        ));
    }

    #[test]
    fn high_finding_exceeds_low_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::High,
            SeverityThreshold::Low
        ));
    }

    #[test]
    fn medium_finding_exceeds_low_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::Medium,
            SeverityThreshold::Low
        ));
    }

    #[test]
    fn low_finding_exceeds_low_threshold() {
        assert!(finding_exceeds_threshold(
            SeverityThreshold::Low,
            SeverityThreshold::Low
        ));
    }

    // ---- count_findings_above_threshold ----

    #[test]
    fn count_above_critical_threshold_counts_only_critical() {
        let summary = SeveritySummary {
            critical: 3,
            high: 5,
            medium: 7,
            low: 9,
            negligible: 100,
        };
        assert_eq!(
            count_findings_above_threshold(&summary, SeverityThreshold::Critical),
            3
        );
    }

    #[test]
    fn count_above_high_threshold_counts_critical_and_high() {
        let summary = SeveritySummary {
            critical: 3,
            high: 5,
            medium: 7,
            low: 9,
            negligible: 100,
        };
        assert_eq!(
            count_findings_above_threshold(&summary, SeverityThreshold::High),
            3 + 5
        );
    }

    #[test]
    fn count_above_medium_threshold_counts_critical_high_medium() {
        let summary = SeveritySummary {
            critical: 3,
            high: 5,
            medium: 7,
            low: 9,
            negligible: 100,
        };
        assert_eq!(
            count_findings_above_threshold(&summary, SeverityThreshold::Medium),
            3 + 5 + 7
        );
    }

    #[test]
    fn count_above_low_threshold_counts_all_meaningful_tiers() {
        // Negligible is not part of `SeverityThreshold` and never counted.
        let summary = SeveritySummary {
            critical: 3,
            high: 5,
            medium: 7,
            low: 9,
            negligible: 100,
        };
        assert_eq!(
            count_findings_above_threshold(&summary, SeverityThreshold::Low),
            3 + 5 + 7 + 9
        );
    }

    #[test]
    fn count_empty_summary_is_zero_under_every_threshold() {
        let summary = empty_summary();
        for threshold in [
            SeverityThreshold::Critical,
            SeverityThreshold::High,
            SeverityThreshold::Medium,
            SeverityThreshold::Low,
        ] {
            assert_eq!(
                count_findings_above_threshold(&summary, threshold),
                0,
                "threshold={threshold:?} expected zero on empty summary"
            );
        }
    }

    #[test]
    fn count_negligible_only_is_zero_under_every_threshold() {
        // A summary with only `negligible` findings must produce zero
        // under every threshold — informational findings don't enforce.
        let summary = SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 42,
        };
        for threshold in [
            SeverityThreshold::Critical,
            SeverityThreshold::High,
            SeverityThreshold::Medium,
            SeverityThreshold::Low,
        ] {
            assert_eq!(count_findings_above_threshold(&summary, threshold), 0);
        }
    }
}
