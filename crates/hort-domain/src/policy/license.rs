//! License-policy evaluator.
//!
//! ## License-policy JSON shape (v1)
//!
//! ```json
//! {
//!   "name": "prod-default",
//!   "allowed_licenses": ["Apache-2.0", "MIT"],
//!   "denied_licenses": ["GPL-3.0"],
//!   "allow_unknown": false,
//!   "action": "Block"
//! }
//! ```
//!
//! All five fields are optional:
//! - `name` — defaults to `"<unnamed>"`. Surfaces in `details` for
//!   operator attribution.
//! - `allowed_licenses` / `denied_licenses` — default to empty arrays.
//!   Empty `allowed` means "no positive list, fall through to
//!   `allow_unknown`."
//! - `allow_unknown` — defaults to `false` (strict).
//! - `action` — defaults to [`PolicyAction::Warn`]. Accepted variants
//!   are `"Allow" | "Warn" | "Block"` (case-insensitive).
//!
//! `null` is the "no license_policy declared" sentinel stored
//! in the projection's JSONB column when the
//! operator left the field unset — zero violations,
//! [`PolicyAction::Allow`]. Other top-level non-objects (array,
//! string, number, bool) signal an operator typo: the evaluator
//! emits one [`SeverityThreshold::Medium`] `license-policy-shape`
//! violation paired with [`PolicyAction::Warn`] so the audit trail
//! captures the misconfiguration without blocking the artifact
//! lifecycle. The evaluator NEVER panics on bad input — operator
//! configuration mistakes must not crash domain code.

use crate::entities::scan_policy::SeverityThreshold;
use crate::events::PolicyViolation;
use crate::policy::primitives::PolicyAction;

/// Stable rule identifier emitted by every violation produced here.
pub const RULE: &str = "license-compliance";

/// Stable rule identifier for an invalid policy-shape signal.
pub const RULE_SHAPE: &str = "license-policy-shape";

/// Maximum length of a single license SPDX expression accepted by the
/// evaluator. Beyond this length the value is treated as malformed
/// input and ignored — the evaluator does not allocate unbounded
/// `to_uppercase` buffers.
const MAX_LICENSE_LEN: usize = 256;

/// Evaluates the artifact's licenses against the policy. See module
/// rustdoc for the JSON shape and defaults.
///
/// Returns `(violations, action)` — the action is the
/// `policy.action` field (or its default), regardless of whether any
/// violations were produced. The caller feeds the pair through
/// [`collect_with_policy_action`](crate::policy::ViolationsAccumulator::collect_with_policy_action).
pub fn evaluate_license_policy(
    licenses: &[String],
    policy: &serde_json::Value,
) -> (Vec<PolicyViolation>, PolicyAction) {
    // Null is the "no license_policy declared" sentinel stored in the
    // projection's JSONB column when the operator left
    // the field unset — silently passes through.
    if policy.is_null() {
        return (Vec::new(), PolicyAction::Allow);
    }

    // Top-level non-object (array, string, number, bool) → operator
    // typo. Emit a single shape violation so it surfaces in audit, and
    // pair it with `PolicyAction::Warn` so the surrounding accumulator
    // logs but does not block the artifact lifecycle on an operator
    // configuration mistake. NEVER panic — domain layer must be
    // resilient to bad JSONB on disk.
    let Some(obj) = policy.as_object() else {
        let kind = json_kind(policy);
        let violation = PolicyViolation {
            rule: RULE_SHAPE.to_string(),
            severity: SeverityThreshold::Medium,
            message: format!("license_policy is not a JSON object (got {kind})"),
            details: serde_json::json!({ "kind": kind }),
        };
        return (vec![violation], PolicyAction::Warn);
    };

    // Parse `action` first so even shape-error paths return the
    // operator's intent. A bad-shape `action` field defaults to Warn.
    let action = parse_action(obj.get("action")).unwrap_or(PolicyAction::Warn);

    // Parse list fields. A non-array yields an empty list (the
    // permissive interpretation: "no entries declared"). Per-element
    // non-string entries are skipped silently — they would never match
    // a real license string anyway.
    let allowed = parse_string_list(obj.get("allowed_licenses"));
    let denied = parse_string_list(obj.get("denied_licenses"));
    let allow_unknown = obj
        .get("allow_unknown")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let policy_name = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<unnamed>")
        .to_string();

    let mut denied_found: Vec<String> = Vec::new();
    let mut unknown_found: Vec<String> = Vec::new();

    for license in licenses {
        if license.len() > MAX_LICENSE_LEN {
            continue;
        }
        let normalised = license.to_uppercase();

        if denied.iter().any(|d| d.to_uppercase() == normalised) {
            denied_found.push(license.clone());
            continue;
        }

        if !allowed.is_empty()
            && !allowed.iter().any(|a| a.to_uppercase() == normalised)
            && !allow_unknown
        {
            unknown_found.push(license.clone());
        }
    }

    let mut violations = Vec::new();

    if !denied_found.is_empty() {
        violations.push(PolicyViolation {
            rule: RULE.to_string(),
            severity: SeverityThreshold::Medium,
            message: format!(
                "Found {} denied licenses: {}",
                denied_found.len(),
                denied_found.join(", ")
            ),
            details: serde_json::json!({
                "denied_licenses": denied_found,
                "policy_name": policy_name,
            }),
        });
    }

    if !unknown_found.is_empty() {
        violations.push(PolicyViolation {
            rule: RULE.to_string(),
            severity: SeverityThreshold::Medium,
            message: format!(
                "Found {} licenses not in allowed list: {}",
                unknown_found.len(),
                unknown_found.join(", ")
            ),
            details: serde_json::json!({
                "unknown_licenses": unknown_found,
                "policy_name": policy_name,
            }),
        });
    }

    (violations, action)
}

/// Names the JSON kind of `value` for shape-violation diagnostics.
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Parses a policy `action` JSON value. Accepts `"Allow" | "Warn" |
/// "Block"` (case-insensitive). Returns `None` for an absent /
/// non-string / unrecognised value — caller decides the default.
fn parse_action(value: Option<&serde_json::Value>) -> Option<PolicyAction> {
    let s = value?.as_str()?;
    match s.to_ascii_lowercase().as_str() {
        "allow" => Some(PolicyAction::Allow),
        "warn" => Some(PolicyAction::Warn),
        "block" => Some(PolicyAction::Block),
        _ => None,
    }
}

/// Parses a JSON array-of-strings. Non-array input → empty list.
/// Non-string elements are dropped.
fn parse_string_list(value: Option<&serde_json::Value>) -> Vec<String> {
    let Some(arr) = value.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_policy_apache_only() -> serde_json::Value {
        serde_json::json!({
            "name": "prod-default",
            "allowed_licenses": ["Apache-2.0", "MIT"],
            "denied_licenses": ["GPL-3.0"],
            "allow_unknown": false,
            "action": "Block"
        })
    }

    // ---- empty policy / passthrough ----------------------------------------

    #[test]
    fn null_policy_no_violations_action_allow() {
        let (v, a) = evaluate_license_policy(&["MIT".into()], &serde_json::Value::Null);
        assert!(v.is_empty());
        assert_eq!(a, PolicyAction::Allow);
    }

    #[test]
    fn empty_object_policy_no_violations_default_action_warn() {
        // Empty object: action defaults to Warn per module rustdoc.
        // No allowed/denied lists, no unknown handling — every license
        // passes through.
        let (v, a) = evaluate_license_policy(&["MIT".into()], &serde_json::json!({}));
        assert!(v.is_empty());
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn no_licenses_at_all_no_violations() {
        let (v, a) = evaluate_license_policy(&[], &block_policy_apache_only());
        assert!(v.is_empty());
        assert_eq!(a, PolicyAction::Block);
    }

    // ---- denied-license path ----------------------------------------------

    #[test]
    fn denied_license_one_violation_action_block() {
        let licenses = vec!["GPL-3.0".to_string()];
        let (v, a) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, RULE);
        assert_eq!(v[0].severity, SeverityThreshold::Medium);
        assert!(v[0].message.contains("GPL-3.0"));
        assert_eq!(v[0].details["policy_name"], "prod-default");
        assert_eq!(a, PolicyAction::Block);
    }

    #[test]
    fn denied_match_is_case_insensitive() {
        let licenses = vec!["gpl-3.0".to_string()];
        let (v, _) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        assert_eq!(v.len(), 1);
    }

    // ---- allowed-license path ---------------------------------------------

    #[test]
    fn allowed_license_no_violations() {
        let licenses = vec!["MIT".to_string(), "Apache-2.0".to_string()];
        let (v, a) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        assert!(v.is_empty());
        assert_eq!(a, PolicyAction::Block);
    }

    #[test]
    fn allowed_match_is_case_insensitive() {
        let licenses = vec!["mit".to_string()];
        let (v, _) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        assert!(v.is_empty());
    }

    // ---- unknown-license path ---------------------------------------------

    #[test]
    fn unknown_license_violation_when_allow_unknown_false() {
        let licenses = vec!["BSD-3-Clause".to_string()];
        let (v, a) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        assert_eq!(v.len(), 1);
        assert!(v[0].message.contains("BSD-3-Clause"));
        assert!(v[0].message.contains("not in allowed list"));
        assert_eq!(a, PolicyAction::Block);
    }

    #[test]
    fn unknown_license_no_violation_when_allow_unknown_true() {
        let policy = serde_json::json!({
            "allowed_licenses": ["MIT"],
            "allow_unknown": true,
            "action": "Warn",
        });
        let licenses = vec!["BSD-3-Clause".to_string()];
        let (v, a) = evaluate_license_policy(&licenses, &policy);
        assert!(v.is_empty());
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn empty_allowed_list_no_unknown_violations_even_when_allow_unknown_false() {
        // There is no positive list to enforce, so unknown licenses
        // pass through. Only denied list still applies.
        let policy = serde_json::json!({
            "denied_licenses": ["GPL-3.0"],
            "allow_unknown": false,
            "action": "Block",
        });
        let licenses = vec!["MIT".to_string(), "BSD-3-Clause".to_string()];
        let (v, _) = evaluate_license_policy(&licenses, &policy);
        assert!(v.is_empty());
    }

    // ---- denied + unknown both fire ---------------------------------------

    #[test]
    fn both_denied_and_unknown_two_violations() {
        let licenses = vec![
            "GPL-3.0".to_string(),      // denied
            "BSD-3-Clause".to_string(), // unknown (not in allowed)
        ];
        let (v, a) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        assert_eq!(v.len(), 2);
        // Order: denied first, unknown second.
        assert!(v[0].message.contains("denied"));
        assert!(v[1].message.contains("not in allowed list"));
        assert_eq!(a, PolicyAction::Block);
    }

    // ---- action parsing ---------------------------------------------------

    #[test]
    fn action_warn_value_returned_as_warn() {
        let policy = serde_json::json!({ "action": "Warn" });
        let (_, a) = evaluate_license_policy(&[], &policy);
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn action_allow_value_returned_as_allow() {
        let policy = serde_json::json!({ "action": "Allow" });
        let (_, a) = evaluate_license_policy(&[], &policy);
        assert_eq!(a, PolicyAction::Allow);
    }

    #[test]
    fn action_case_insensitive() {
        for s in ["BLOCK", "block", "Block", "BlOcK"] {
            let policy = serde_json::json!({ "action": s });
            let (_, a) = evaluate_license_policy(&[], &policy);
            assert_eq!(a, PolicyAction::Block, "input {s}");
        }
    }

    #[test]
    fn unrecognised_action_string_defaults_to_warn() {
        let policy = serde_json::json!({ "action": "deny" });
        let (_, a) = evaluate_license_policy(&[], &policy);
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn missing_action_defaults_to_warn() {
        let policy = serde_json::json!({ "denied_licenses": ["GPL-3.0"] });
        let (_, a) = evaluate_license_policy(&[], &policy);
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn non_string_action_defaults_to_warn() {
        let policy = serde_json::json!({ "action": 42 });
        let (_, a) = evaluate_license_policy(&[], &policy);
        assert_eq!(a, PolicyAction::Warn);
    }

    // ---- invalid policy shapes (no panics, no violations) -----------------

    #[test]
    fn top_level_array_emits_shape_violation_and_warns() {
        let policy = serde_json::json!(["GPL-3.0"]);
        let (v, a) = evaluate_license_policy(&["GPL-3.0".into()], &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, RULE_SHAPE);
        assert_eq!(v[0].severity, SeverityThreshold::Medium);
        assert!(
            v[0].message.contains("array"),
            "kind in message: {}",
            v[0].message
        );
        assert_eq!(v[0].details["kind"], "array");
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn top_level_string_emits_shape_violation_and_warns() {
        let policy = serde_json::json!("not-a-policy");
        let (v, a) = evaluate_license_policy(&["GPL-3.0".into()], &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, RULE_SHAPE);
        assert_eq!(v[0].details["kind"], "string");
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn top_level_number_emits_shape_violation_and_warns() {
        let policy = serde_json::json!(42);
        let (v, a) = evaluate_license_policy(&[], &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].details["kind"], "number");
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn top_level_bool_emits_shape_violation_and_warns() {
        let policy = serde_json::json!(true);
        let (v, a) = evaluate_license_policy(&[], &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].details["kind"], "bool");
        assert_eq!(a, PolicyAction::Warn);
    }

    #[test]
    fn shape_violation_validates_under_event_caps() {
        // Defence-in-depth: even the shape-error path must produce a
        // PolicyViolation that satisfies validate().
        let policy = serde_json::json!("not-a-policy");
        let (v, _) = evaluate_license_policy(&[], &policy);
        v[0].validate().expect("shape violation must validate");
    }

    #[test]
    fn non_array_denied_field_treated_as_empty() {
        // The "shape error" we tolerate: scalar where an array is
        // expected → empty list. Mirrors the lenient parser interpretation
        // documented in the module rustdoc.
        let policy = serde_json::json!({
            "denied_licenses": "GPL-3.0",
            "action": "Block",
        });
        let (v, a) = evaluate_license_policy(&["GPL-3.0".into()], &policy);
        assert!(v.is_empty(), "scalar where array expected → no enforcement");
        assert_eq!(a, PolicyAction::Block);
    }

    #[test]
    fn non_string_list_elements_skipped() {
        let policy = serde_json::json!({
            "denied_licenses": [42, "GPL-3.0", null, true, "MIT"],
            "action": "Block",
        });
        let (v, _) = evaluate_license_policy(&["GPL-3.0".into()], &policy);
        assert_eq!(v.len(), 1, "valid GPL-3.0 entry still enforces");
    }

    #[test]
    fn non_bool_allow_unknown_defaults_to_false() {
        let policy = serde_json::json!({
            "allowed_licenses": ["MIT"],
            "allow_unknown": "yes",
            "action": "Block",
        });
        let (v, _) = evaluate_license_policy(&["BSD-3-Clause".into()], &policy);
        assert_eq!(v.len(), 1, "non-bool allow_unknown must default to strict");
    }

    // ---- pathological inputs ----------------------------------------------

    #[test]
    fn over_long_license_string_skipped() {
        // A license literal beyond MAX_LICENSE_LEN is dropped on the
        // way in — defence against pathological inputs that would
        // allocate large `to_uppercase` buffers.
        let huge = "X".repeat(MAX_LICENSE_LEN + 1);
        let licenses = vec![huge];
        let (v, _) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        // Not denied, not in allowed list, but skipped before the
        // unknown check — so no violation.
        assert!(v.is_empty());
    }

    #[test]
    fn at_max_length_license_evaluated_normally() {
        let on_cap = "X".repeat(MAX_LICENSE_LEN);
        let licenses = vec![on_cap.clone()];
        let (v, _) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        // Counts as unknown — `MAX_LICENSE_LEN` is the inclusive cap.
        assert_eq!(v.len(), 1);
        assert!(v[0].message.contains(&on_cap));
    }

    // ---- produced violations validate -------------------------------------

    #[test]
    fn produced_violations_validate_under_event_caps() {
        let licenses = vec!["GPL-3.0".into(), "BSD-3-Clause".into()];
        let (v, _) = evaluate_license_policy(&licenses, &block_policy_apache_only());
        for vi in v {
            vi.validate().expect("produced violation must validate");
        }
    }

    #[test]
    fn missing_policy_name_falls_back_to_unnamed_sentinel() {
        let policy = serde_json::json!({
            "denied_licenses": ["GPL-3.0"],
            "action": "Block",
        });
        let (v, _) = evaluate_license_policy(&["GPL-3.0".into()], &policy);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].details["policy_name"], "<unnamed>");
    }
}
