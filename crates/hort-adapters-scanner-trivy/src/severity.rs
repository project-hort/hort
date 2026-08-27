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
use hort_domain::types::SeverityBasis;

/// Map a Trivy severity string to a [`SeverityThreshold`] **and the basis
/// on which it was reached**.
///
/// Recognised inputs (case-insensitive), all
/// [`SeverityBasis::Assessed`]:
/// - `CRITICAL` → [`SeverityThreshold::Critical`]
/// - `HIGH`     → [`SeverityThreshold::High`]
/// - `MEDIUM`   → [`SeverityThreshold::Medium`]
/// - `LOW`      → [`SeverityThreshold::Low`]
///
/// Anything else (including `UNKNOWN`, `NEGLIGIBLE`, empty) maps to the
/// highest tier [`SeverityThreshold::Critical`] (fail-closed, SUP-4) with
/// [`SeverityBasis::Unassessed`]. The basis is what tells a downstream
/// consumer that this `Critical` is a floor rather than a reading — the
/// two are byte-identical on the `severity` field alone.
pub(crate) fn trivy_severity_to_threshold(severity: &str) -> (SeverityThreshold, SeverityBasis) {
    match severity.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => (SeverityThreshold::Critical, SeverityBasis::Assessed),
        "HIGH" => (SeverityThreshold::High, SeverityBasis::Assessed),
        "MEDIUM" => (SeverityThreshold::Medium, SeverityBasis::Assessed),
        "LOW" => (SeverityThreshold::Low, SeverityBasis::Assessed),
        // UNKNOWN / NEGLIGIBLE / empty / anything else: fail-closed
        // fallback to the HIGHEST tier (`Critical`) so an
        // unparseable-severity finding still trips the default Critical
        // block threshold rather than slipping under it (SUP-4). Marked
        // `Unassessed`: no severity was read, so the tier carries no
        // information about the advisory.
        _ => (SeverityThreshold::Critical, SeverityBasis::Unassessed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_maps_to_critical() {
        assert_eq!(
            trivy_severity_to_threshold("CRITICAL"),
            (SeverityThreshold::Critical, SeverityBasis::Assessed)
        );
    }

    #[test]
    fn high_maps_to_high() {
        assert_eq!(
            trivy_severity_to_threshold("HIGH"),
            (SeverityThreshold::High, SeverityBasis::Assessed)
        );
    }

    #[test]
    fn medium_maps_to_medium() {
        assert_eq!(
            trivy_severity_to_threshold("MEDIUM"),
            (SeverityThreshold::Medium, SeverityBasis::Assessed)
        );
    }

    #[test]
    fn low_maps_to_low() {
        assert_eq!(
            trivy_severity_to_threshold("LOW"),
            (SeverityThreshold::Low, SeverityBasis::Assessed)
        );
    }

    #[test]
    fn unknown_maps_to_critical_fail_closed_unassessed() {
        // SUP-4: an unparseable severity must fail CLOSED to the highest
        // tier so it still trips the default Critical block threshold —
        // and must say so, so the cross-backend merge can tell this
        // `Critical` from an assessed one.
        assert_eq!(
            trivy_severity_to_threshold("UNKNOWN"),
            (SeverityThreshold::Critical, SeverityBasis::Unassessed)
        );
    }

    #[test]
    fn negligible_maps_to_critical_fail_closed_unassessed() {
        assert_eq!(
            trivy_severity_to_threshold("NEGLIGIBLE"),
            (SeverityThreshold::Critical, SeverityBasis::Unassessed)
        );
    }

    #[test]
    fn empty_maps_to_critical_fail_closed_unassessed() {
        assert_eq!(
            trivy_severity_to_threshold(""),
            (SeverityThreshold::Critical, SeverityBasis::Unassessed)
        );
    }

    #[test]
    fn lowercase_critical_maps_to_critical_case_insensitive() {
        assert_eq!(
            trivy_severity_to_threshold("critical"),
            (SeverityThreshold::Critical, SeverityBasis::Assessed)
        );
    }

    #[test]
    fn mixed_case_high_maps_to_high_case_insensitive() {
        assert_eq!(
            trivy_severity_to_threshold("High"),
            (SeverityThreshold::High, SeverityBasis::Assessed)
        );
    }

    #[test]
    fn whitespace_around_label_is_trimmed() {
        assert_eq!(
            trivy_severity_to_threshold("  CRITICAL  "),
            (SeverityThreshold::Critical, SeverityBasis::Assessed)
        );
    }

    #[test]
    fn unrecognised_label_maps_to_critical_fail_closed_unassessed() {
        // SUP-4: any unrecognised label fails CLOSED to the highest tier.
        assert_eq!(
            trivy_severity_to_threshold("nuclear"),
            (SeverityThreshold::Critical, SeverityBasis::Unassessed)
        );
    }
}
