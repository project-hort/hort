//! CVSS / OSV-scanner severity → [`SeverityThreshold`] mapping. Pure
//! function; no I/O, no allocation beyond an optional fallback string
//! parse.
//!
//! The osv-scanner output exposes severity in two shapes:
//!
//! 1. `groups[].max_severity` — a bare numeric string like `"7.2"`,
//!    `"9.8"`, or `""` (unscored). This is the preferred input.
//! 2. `severity[].score` — a CVSS vector like
//!    `"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C"`
//!    where the trailing portion may include a `/` followed by the
//!    bare score. osv-scanner does not embed the numeric base score in
//!    the vector itself, so this fallback path is best-effort: we
//!    look for a trailing numeric `/<float>` segment, then fall through
//!    to a label match.
//!
//! Bands (mirrored from `hort-adapters-advisory-osv::severity`):
//!
//! | Numeric score          | Threshold |
//! |------------------------|-----------|
//! | `>= 9.0`               | Critical  |
//! | `>= 7.0` and `< 9.0`   | High      |
//! | `>= 4.0` and `< 7.0`   | Medium    |
//! | `>= 0.1` and `< 4.0`   | Low       |
//! | otherwise              | (string fallback, else `Medium`) |

use hort_domain::entities::scan_policy::SeverityThreshold;

/// Map a CVSS base score to a [`SeverityThreshold`]. Returns `None` for
/// non-finite or out-of-range inputs (negative, > 10.0, NaN, infinity).
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
        // 0.0 ≤ score < 0.1 — CVSS spec calls this "None"; we have no
        // matching variant.
        None
    }
}

/// Parse a `groups[].max_severity` string. Accepts:
/// - bare numeric: `"7.2"`, `"9.8"`;
/// - empty string: returns `None` (osv-scanner emits this when the
///   group has no scored vulnerabilities — the caller falls back).
pub(crate) fn parse_max_severity(s: &str) -> Option<f32> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<f32>().ok()
}

/// Best-effort score extraction from a CVSS vector string like
/// `"CVSS:3.1/AV:L/.../A:H/E:H/RL:O/RC:C/7.2"`. Walks the slash-separated
/// segments and returns the first one that parses as a float in the
/// CVSS range.
///
/// osv-scanner emits the score inside the vector inconsistently across
/// CVSS versions; this is a defence-in-depth fallback only — the
/// preferred path is `groups[].max_severity`.
pub(crate) fn extract_score_from_cvss_vector(vector: &str) -> Option<f32> {
    for segment in vector.split('/') {
        if let Ok(v) = segment.trim().parse::<f32>() {
            if (0.0..=10.0).contains(&v) {
                return Some(v);
            }
        }
    }
    None
}

/// Map a severity label string to a [`SeverityThreshold`]. Mirrors the
/// advisory adapter's behaviour: numeric strings band-map; well-known
/// labels (`critical` / `high` / `medium` / `moderate` / `low`)
/// resolve directly; everything else returns `None`.
pub(crate) fn label_to_severity(label: &str) -> Option<SeverityThreshold> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return None;
    }
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

    // ----- cvss_score_to_severity — band boundaries ------------------------

    #[test]
    fn score_at_or_above_9_is_critical() {
        assert_eq!(
            cvss_score_to_severity(9.0),
            Some(SeverityThreshold::Critical)
        );
        assert_eq!(
            cvss_score_to_severity(9.5),
            Some(SeverityThreshold::Critical)
        );
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
        assert_eq!(cvss_score_to_severity(0.09), None);
        assert_eq!(cvss_score_to_severity(0.0), None);
    }

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

    // ----- parse_max_severity -----------------------------------------------

    #[test]
    fn parse_max_severity_handles_bare_numeric() {
        assert_eq!(parse_max_severity("7.2"), Some(7.2));
        assert_eq!(parse_max_severity("9.8"), Some(9.8));
    }

    #[test]
    fn parse_max_severity_returns_none_for_empty_or_whitespace() {
        assert_eq!(parse_max_severity(""), None);
        assert_eq!(parse_max_severity("   "), None);
    }

    #[test]
    fn parse_max_severity_returns_none_for_garbage() {
        assert_eq!(parse_max_severity("HIGH"), None);
    }

    #[test]
    fn parse_max_severity_trims_whitespace() {
        assert_eq!(parse_max_severity("  7.2  "), Some(7.2));
    }

    // ----- extract_score_from_cvss_vector -----------------------------------

    #[test]
    fn extract_score_picks_trailing_numeric_segment() {
        assert_eq!(
            extract_score_from_cvss_vector("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/7.2"),
            Some(7.2)
        );
    }

    #[test]
    fn extract_score_returns_none_when_no_numeric_segment_present() {
        assert_eq!(
            extract_score_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
    }

    #[test]
    fn extract_score_skips_out_of_range_values() {
        // A segment that parses as a float but exceeds 10.0 must be
        // ignored — the CVSS contract bounds scores at [0, 10].
        assert_eq!(extract_score_from_cvss_vector("CVSS:3.1/100.0/AV:N"), None);
    }

    // ----- label_to_severity ------------------------------------------------

    #[test]
    fn label_critical_maps_to_critical() {
        assert_eq!(
            label_to_severity("CRITICAL"),
            Some(SeverityThreshold::Critical)
        );
    }

    #[test]
    fn label_numeric_uses_band() {
        assert_eq!(label_to_severity("7.5"), Some(SeverityThreshold::High));
    }

    #[test]
    fn label_unknown_returns_none() {
        assert_eq!(label_to_severity("nuclear"), None);
        assert_eq!(label_to_severity(""), None);
    }

    #[test]
    fn label_moderate_maps_to_medium() {
        assert_eq!(
            label_to_severity("moderate"),
            Some(SeverityThreshold::Medium)
        );
    }
}
