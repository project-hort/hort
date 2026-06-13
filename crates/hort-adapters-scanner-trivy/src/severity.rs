//! Trivy severity string → [`SeverityThreshold`] mapping.
//!
//! Trivy reports one of five severity bands as an uppercase string:
//! `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`. The fifth band
//! plus any unrecognised string maps to [`SeverityThreshold::Low`] —
//! conservative because the orchestrator's policy evaluator gates on
//! threshold; mapping unknowns to anything higher would risk false
//! "block" decisions, mapping to anything lower would risk silently
//! dropping the finding from the policy view (the variant set has no
//! `Negligible`).
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
/// Anything else (including `UNKNOWN`, `NEGLIGIBLE`, empty) maps to
/// [`SeverityThreshold::Low`].
pub(crate) fn trivy_severity_to_threshold(severity: &str) -> SeverityThreshold {
    match severity.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => SeverityThreshold::Critical,
        "HIGH" => SeverityThreshold::High,
        "MEDIUM" => SeverityThreshold::Medium,
        "LOW" => SeverityThreshold::Low,
        // UNKNOWN / NEGLIGIBLE / empty / anything else: conservative
        // fallback to Low so the orchestrator still sees the finding
        // (the SeverityThreshold enum has no lower band).
        _ => SeverityThreshold::Low,
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
    fn unknown_maps_to_low_conservative_fallback() {
        assert_eq!(
            trivy_severity_to_threshold("UNKNOWN"),
            SeverityThreshold::Low
        );
    }

    #[test]
    fn negligible_maps_to_low_conservative_fallback() {
        assert_eq!(
            trivy_severity_to_threshold("NEGLIGIBLE"),
            SeverityThreshold::Low
        );
    }

    #[test]
    fn empty_maps_to_low_conservative_fallback() {
        assert_eq!(trivy_severity_to_threshold(""), SeverityThreshold::Low);
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
    fn unrecognised_label_maps_to_low_conservative_fallback() {
        assert_eq!(
            trivy_severity_to_threshold("nuclear"),
            SeverityThreshold::Low
        );
    }
}
