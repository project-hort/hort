//! Artifact-age evaluator.
//!
//! A `max_age_secs` violation is `Medium` severity — the operator declared a
//! soft staleness cap, not a critical-bug-class gate. Callers feed the
//! result through the
//! [`ViolationsAccumulator`](crate::policy::ViolationsAccumulator) which
//! escalates `Medium` into [`PolicyAction::Warn`](crate::policy::PolicyAction::Warn)
//! by default — the policy's own `action` (Block / Warn / Allow) wins
//! over the per-violation severity if escalated through
//! [`collect_with_policy_action`](crate::policy::ViolationsAccumulator::collect_with_policy_action).

use chrono::{DateTime, Utc};

use crate::entities::scan_policy::SeverityThreshold;
use crate::events::PolicyViolation;

/// Stable rule identifier emitted by every violation produced here.
pub const RULE: &str = "max-artifact-age";

/// Returns at most one violation when the artifact's age (`now -
/// artifact_ingested_at`) exceeds `max_age_secs`. `None` for
/// `max_age_secs` is "no cap" — never produces a violation. A negative
/// or zero `max_age_secs` is treated as "everything is too old".
///
/// Ages computed as whole seconds via
/// [`chrono::Duration::num_seconds`]. Out-of-range subtractions (e.g.
/// `now < ingested_at`, which can happen if the clock skews backwards
/// between ingest and evaluation) yield a negative age and never
/// trigger a violation.
pub fn evaluate_age_gates(
    artifact_ingested_at: DateTime<Utc>,
    now: DateTime<Utc>,
    max_age_secs: Option<i64>,
) -> Vec<PolicyViolation> {
    let Some(max) = max_age_secs else {
        return Vec::new();
    };

    let age_secs = (now - artifact_ingested_at).num_seconds();
    if age_secs <= max {
        return Vec::new();
    }

    vec![PolicyViolation {
        rule: RULE.to_string(),
        severity: SeverityThreshold::Medium,
        message: format!("Artifact is {age_secs} seconds old (maximum: {max} seconds)"),
        details: serde_json::json!({
            "age_secs": age_secs,
            "max_age_secs": max,
        }),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("fixed timestamp")
    }

    #[test]
    fn no_max_age_no_violations_even_for_ancient_artifacts() {
        let ingested = ts(0);
        let now = ts(10_000_000_000); // ~317 years later
        let violations = evaluate_age_gates(ingested, now, None);
        assert!(violations.is_empty());
    }

    #[test]
    fn at_cap_no_violation() {
        // age_secs == max_age_secs → not over the cap.
        let ingested = ts(1_000_000);
        let now = ts(1_000_000 + 3600);
        let violations = evaluate_age_gates(ingested, now, Some(3600));
        assert!(violations.is_empty(), "at-cap must not violate");
    }

    #[test]
    fn over_cap_one_medium_violation() {
        let ingested = ts(1_000_000);
        let now = ts(1_000_000 + 3601);
        let violations = evaluate_age_gates(ingested, now, Some(3600));
        assert_eq!(violations.len(), 1);
        let v = &violations[0];
        assert_eq!(v.rule, RULE);
        assert_eq!(v.severity, SeverityThreshold::Medium);
        assert!(
            v.message.contains("3601") && v.message.contains("3600"),
            "message must echo computed age + cap: {}",
            v.message
        );
        let details = v.details.as_object().expect("details is object");
        assert_eq!(details["age_secs"].as_i64(), Some(3601));
        assert_eq!(details["max_age_secs"].as_i64(), Some(3600));
    }

    #[test]
    fn well_over_cap_one_violation_with_correct_age() {
        // A week-old artifact under a 1-hour cap.
        let ingested = ts(1_000_000);
        let now = ts(1_000_000 + 7 * 24 * 3600);
        let violations = evaluate_age_gates(ingested, now, Some(3600));
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].details["age_secs"].as_i64(),
            Some(7 * 24 * 3600)
        );
    }

    #[test]
    fn negative_clock_skew_no_violation() {
        // `now` precedes `ingested_at` (clock skew). The conservative
        // behaviour is to not violate — an artifact "from the future"
        // is not stale.
        let ingested = ts(2_000_000);
        let now = ts(1_000_000); // skewed backward by ~12 days
        let violations = evaluate_age_gates(ingested, now, Some(3600));
        assert!(violations.is_empty());
    }

    #[test]
    fn zero_cap_blocks_anything_older_than_zero_seconds() {
        // Operator deliberately configured `max_age_secs = 0` ("everything
        // is too old"). The validator must honour that — no special-
        // casing zero into "disabled."
        let ingested = ts(1_000_000);
        let now = ts(1_000_000 + 1);
        let violations = evaluate_age_gates(ingested, now, Some(0));
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn zero_cap_at_exact_zero_age_no_violation() {
        // age_secs == 0 == max → on-the-cap, no violation.
        let ingested = ts(1_000_000);
        let now = ts(1_000_000);
        let violations = evaluate_age_gates(ingested, now, Some(0));
        assert!(violations.is_empty());
    }

    #[test]
    fn produced_violation_validates_under_event_caps() {
        let ingested = ts(1_000_000);
        let now = ts(1_000_000 + 7200);
        let violations = evaluate_age_gates(ingested, now, Some(3600));
        for v in violations {
            v.validate().expect("produced violation must validate");
        }
    }
}
