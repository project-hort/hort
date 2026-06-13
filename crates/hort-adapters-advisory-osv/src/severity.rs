//! CVSS / OSV severity → [`SeverityThreshold`] mapping. Pure function;
//! no I/O, no allocation beyond an optional fallback string parse.
//!
//! The OSV `vulns[]` entry exposes severity in two shapes:
//!
//! 1. A `severity` array of CVSS vectors (preferred, machine-readable).
//!    The vector encodes a `CVSS:<version>/AV:.../AC:.../...` tail; the
//!    full numeric base score requires a CVSS calculator. **For v1 we
//!    skip the per-vuln drill-down** — `querybatch` does not return
//!    base scores in-line, so the score fed to this mapper comes from
//!    `database_specific.severity` (a string label) when present, else
//!    `Medium` as the documented default.
//! 2. A `database_specific.severity` string label like `"HIGH"`, `"7.5"`,
//!    or `"7.5 HIGH"`. We accept either a parseable float or a known
//!    label.
//!
//! | Numeric score | Threshold |
//! |---|---|
//! | `>= 9.0`            | Critical |
//! | `>= 7.0` and `< 9.0` | High     |
//! | `>= 4.0` and `< 7.0` | Medium   |
//! | `>= 0.1` and `< 4.0` | Low      |
//! | otherwise           | (string fallback, else `Medium`) |
//!
//! Boundary tests cover each band edge in both directions (just-above /
//! exactly-at).

use hort_domain::entities::scan_policy::SeverityThreshold;

/// Map a CVSS base score to a [`SeverityThreshold`]. Returns `None` for
/// non-finite or out-of-range inputs (negative, > 10.0, NaN, infinity);
/// the caller falls back to the string label or to `Medium`.
pub(crate) fn cvss_score_to_severity(score: f32) -> Option<SeverityThreshold> {
    if !score.is_finite() {
        return None;
    }
    if !(0.0..=10.0).contains(&score) {
        return None;
    }
    if score >= 9.0 {
        Some(SeverityThreshold::Critical)
    } else if score >= 7.0 {
        Some(SeverityThreshold::High)
    } else if score >= 4.0 {
        Some(SeverityThreshold::Medium)
    } else if score >= 0.1 {
        Some(SeverityThreshold::Low)
    } else {
        // 0.0 ≤ score < 0.1 — CVSS spec calls this "None", but we have
        // no `Informational` variant. Treat as not-classifiable; caller
        // falls back to `Medium`.
        None
    }
}

/// Map an OSV severity label string to a [`SeverityThreshold`].
///
/// Accepts:
/// - well-known CVSS v3 labels: `critical`, `high`, `medium`,
///   `moderate` (GitHub Advisory's variant of `medium`), `low`;
/// - a bare numeric string like `"7.5"` (used in some
///   `database_specific.severity` fields);
/// - a label-prefixed numeric like `"7.5 HIGH"` — the leading number
///   wins.
///
/// Returns `None` when the input is unrecognised; the caller defaults
/// to [`SeverityThreshold::Medium`] — missing severity maps to Medium
/// as a conservative default for unknown advisory severity.
pub(crate) fn label_to_severity(label: &str) -> Option<SeverityThreshold> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Try parsing a leading float first; "7.5", "7.5 HIGH", "7.5/foo"
    // all fall into this branch. We only consume the leading numeric
    // prefix.
    let leading_numeric: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if let Ok(score) = leading_numeric.parse::<f32>() {
        if let Some(s) = cvss_score_to_severity(score) {
            return Some(s);
        }
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "critical" => Some(SeverityThreshold::Critical),
        "high" => Some(SeverityThreshold::High),
        "medium" | "moderate" => Some(SeverityThreshold::Medium),
        "low" => Some(SeverityThreshold::Low),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------- cvss_score_to_severity — band boundaries (just-above) ----------

    #[test]
    fn score_at_or_above_9_is_critical() {
        // exactly-at
        assert_eq!(
            cvss_score_to_severity(9.0),
            Some(SeverityThreshold::Critical)
        );
        // just-above
        assert_eq!(
            cvss_score_to_severity(9.5),
            Some(SeverityThreshold::Critical)
        );
        // ceiling
        assert_eq!(
            cvss_score_to_severity(10.0),
            Some(SeverityThreshold::Critical)
        );
    }

    #[test]
    fn score_just_below_9_is_high() {
        assert_eq!(cvss_score_to_severity(8.99), Some(SeverityThreshold::High));
    }

    #[test]
    fn score_at_or_above_7_below_9_is_high() {
        assert_eq!(cvss_score_to_severity(7.0), Some(SeverityThreshold::High));
        assert_eq!(cvss_score_to_severity(8.0), Some(SeverityThreshold::High));
    }

    #[test]
    fn score_just_below_7_is_medium() {
        assert_eq!(
            cvss_score_to_severity(6.99),
            Some(SeverityThreshold::Medium)
        );
    }

    #[test]
    fn score_at_or_above_4_below_7_is_medium() {
        assert_eq!(cvss_score_to_severity(4.0), Some(SeverityThreshold::Medium));
        assert_eq!(cvss_score_to_severity(5.5), Some(SeverityThreshold::Medium));
    }

    #[test]
    fn score_just_below_4_is_low() {
        assert_eq!(cvss_score_to_severity(3.99), Some(SeverityThreshold::Low));
    }

    #[test]
    fn score_at_or_above_0_1_below_4_is_low() {
        assert_eq!(cvss_score_to_severity(0.1), Some(SeverityThreshold::Low));
        assert_eq!(cvss_score_to_severity(2.0), Some(SeverityThreshold::Low));
    }

    #[test]
    fn score_below_0_1_is_none() {
        // CVSS "None" band — caller falls back to Medium.
        assert_eq!(cvss_score_to_severity(0.09), None);
        assert_eq!(cvss_score_to_severity(0.0), None);
    }

    // ------- cvss_score_to_severity — out-of-range / non-finite -------------

    #[test]
    fn negative_score_is_none() {
        assert_eq!(cvss_score_to_severity(-1.0), None);
    }

    #[test]
    fn over_max_score_is_none() {
        assert_eq!(cvss_score_to_severity(10.1), None);
    }

    #[test]
    fn nan_score_is_none() {
        assert_eq!(cvss_score_to_severity(f32::NAN), None);
    }

    #[test]
    fn infinity_score_is_none() {
        assert_eq!(cvss_score_to_severity(f32::INFINITY), None);
        assert_eq!(cvss_score_to_severity(f32::NEG_INFINITY), None);
    }

    // ------- label_to_severity — well-known labels --------------------------

    #[test]
    fn label_critical_maps_to_critical() {
        assert_eq!(
            label_to_severity("CRITICAL"),
            Some(SeverityThreshold::Critical)
        );
        assert_eq!(
            label_to_severity("critical"),
            Some(SeverityThreshold::Critical)
        );
    }

    #[test]
    fn label_high_maps_to_high() {
        assert_eq!(label_to_severity("HIGH"), Some(SeverityThreshold::High));
    }

    #[test]
    fn label_medium_and_moderate_both_map_to_medium() {
        assert_eq!(label_to_severity("MEDIUM"), Some(SeverityThreshold::Medium));
        // GitHub Advisory uses "moderate" instead of "medium".
        assert_eq!(
            label_to_severity("moderate"),
            Some(SeverityThreshold::Medium)
        );
    }

    #[test]
    fn label_low_maps_to_low() {
        assert_eq!(label_to_severity("LOW"), Some(SeverityThreshold::Low));
    }

    #[test]
    fn unknown_label_returns_none() {
        assert_eq!(label_to_severity("nuclear"), None);
        assert_eq!(label_to_severity(""), None);
        assert_eq!(label_to_severity("   "), None);
    }

    // ------- label_to_severity — numeric strings ----------------------------

    #[test]
    fn label_numeric_string_uses_band() {
        assert_eq!(label_to_severity("7.5"), Some(SeverityThreshold::High));
        assert_eq!(label_to_severity("9.0"), Some(SeverityThreshold::Critical));
        assert_eq!(label_to_severity("4.0"), Some(SeverityThreshold::Medium));
    }

    #[test]
    fn label_numeric_with_trailing_label_takes_numeric() {
        // "7.5 HIGH" is a real-world `database_specific.severity` shape.
        // The leading numeric should win.
        assert_eq!(label_to_severity("7.5 HIGH"), Some(SeverityThreshold::High));
        assert_eq!(
            label_to_severity("9.8 CRITICAL"),
            Some(SeverityThreshold::Critical)
        );
    }

    #[test]
    fn label_with_leading_whitespace_is_trimmed() {
        assert_eq!(label_to_severity("  HIGH  "), Some(SeverityThreshold::High));
    }
}
