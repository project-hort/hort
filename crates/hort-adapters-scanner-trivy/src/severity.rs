//! Trivy severity string → [`SeverityThreshold`] mapping.
//!
//! Trivy reports one of five severity bands as an uppercase string:
//! `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`. The fifth band plus
//! any unrecognised string maps to the HIGHEST tier
//! [`SeverityThreshold::Critical`] — **fail-closed** (SUP-4). A finding
//! whose severity we cannot determine must still trip the default
//! Critical block threshold rather than slip under it; mapping unknowns
//! to a low tier (the prior `Low` default) was a fail-OPEN gap that let
//! an unparseable-severity finding pass the release gate. Unified with
//! the scanner-osv and advisory-osv adapters.
//!
//! The mapping is case-insensitive: `"critical"` and `"CRITICAL"` both
//! resolve to [`SeverityThreshold::Critical`]. Trivy spells the
//! upper-case form but the parser is lenient.

use hort_domain::entities::scan_policy::SeverityThreshold;

/// Map a Trivy severity string to a [`SeverityThreshold`].
///
/// Recognised inputs (case-insensitive):
/// - `CRITICAL` → [`SeverityThreshold::Critical`]
/// - `HIGH`     → [`SeverityThreshold::High`]
/// - `MEDIUM`   → [`SeverityThreshold::Medium`]
/// - `LOW`      → [`SeverityThreshold::Low`]
///
/// Anything else (including `UNKNOWN`, `NEGLIGIBLE`, empty) maps to the
/// highest tier [`SeverityThreshold::Critical`] (fail-closed, SUP-4).
pub(crate) fn trivy_severity_to_threshold(severity: &str) -> SeverityThreshold {
    match severity.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => SeverityThreshold::Critical,
        "HIGH" => SeverityThreshold::High,
        "MEDIUM" => SeverityThreshold::Medium,
        "LOW" => SeverityThreshold::Low,
        // UNKNOWN / NEGLIGIBLE / empty / anything else: fail-closed
        // fallback to the HIGHEST tier (`Critical`) so an
        // unparseable-severity finding still trips the default Critical
        // block threshold rather than slipping under it (SUP-4).
        _ => SeverityThreshold::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_maps_to_critical() {
        assert_eq!(
            trivy_severity_to_threshold("CRITICAL"),
            SeverityThreshold::Critical
        );
    }

    #[test]
    fn high_maps_to_high() {
        assert_eq!(trivy_severity_to_threshold("HIGH"), SeverityThreshold::High);
    }

    #[test]
    fn medium_maps_to_medium() {
        assert_eq!(
            trivy_severity_to_threshold("MEDIUM"),
            SeverityThreshold::Medium
        );
    }

    #[test]
    fn low_maps_to_low() {
        assert_eq!(trivy_severity_to_threshold("LOW"), SeverityThreshold::Low);
    }

    #[test]
    fn unknown_maps_to_critical_fail_closed() {
        // SUP-4: an unparseable severity must fail CLOSED to the highest
        // tier so it still trips the default Critical block threshold.
        assert_eq!(
            trivy_severity_to_threshold("UNKNOWN"),
            SeverityThreshold::Critical
        );
    }

    #[test]
    fn negligible_maps_to_critical_fail_closed() {
        assert_eq!(
            trivy_severity_to_threshold("NEGLIGIBLE"),
            SeverityThreshold::Critical
        );
    }

    #[test]
    fn empty_maps_to_critical_fail_closed() {
        assert_eq!(trivy_severity_to_threshold(""), SeverityThreshold::Critical);
    }

    #[test]
    fn lowercase_critical_maps_to_critical_case_insensitive() {
        assert_eq!(
            trivy_severity_to_threshold("critical"),
            SeverityThreshold::Critical
        );
    }

    #[test]
    fn mixed_case_high_maps_to_high_case_insensitive() {
        assert_eq!(trivy_severity_to_threshold("High"), SeverityThreshold::High);
    }

    #[test]
    fn whitespace_around_label_is_trimmed() {
        assert_eq!(
            trivy_severity_to_threshold("  CRITICAL  "),
            SeverityThreshold::Critical
        );
    }

    #[test]
    fn unrecognised_label_maps_to_critical_fail_closed() {
        // SUP-4: any unrecognised label fails CLOSED to the highest tier.
        assert_eq!(
            trivy_severity_to_threshold("nuclear"),
            SeverityThreshold::Critical
        );
    }
}
