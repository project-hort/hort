//! `kind: CurationRule` schema, parser, and per-spec validation.
//!
//! Curation rules are a standalone first-class kind, separate from
//! `Repository`. This module is the gitops-facing parser; the domain
//! entity lives in `hort_domain::entities::curation_rule::CurationRule`.
//!
//! Cross-spec resolution (`Repository.curationRules` references a
//! declared `CurationRule.metadata.name`) lives in `crate::desired`.

use std::path::Path;
use std::str::FromStr;

use hort_domain::entities::curation_rule::CurationRuleAction;
use hort_domain::entities::repository::RepositoryFormat;
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};

/// Shape of a `kind: CurationRule` YAML body.
///
/// `format` is either the literal `"any"` (matches every format) or a
/// known `RepositoryFormat` key (`npm`, `pypi`, ...). Unknown format
/// strings fall through `RepositoryFormat::FromStr` to
/// `RepositoryFormat::Other(_)` — that pattern is treated as an error
/// here, mirroring `RepositorySpec`'s rejection of `Other` formats.
///
/// `action` parses through `CurationRuleAction::FromStr` (case-
/// insensitive, surfaces as a typed validation error on failure).
///
/// `pattern` and `reason` are free-form strings; the domain policy
/// evaluator interprets `pattern` — this layer just carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurationRuleSpec {
    /// `"any"` or a known `RepositoryFormat` key. Validation rejects
    /// unknown formats so a typo doesn't silently produce a no-op
    /// rule that never matches anything.
    pub format: String,
    /// Glob-style match on the package name. The matching engine lives
    /// in the domain policy evaluator; this layer only carries the string.
    pub pattern: String,
    /// One of `block | warn | allow`. Validated via
    /// `CurationRuleAction::FromStr`.
    pub action: String,
    /// Operator-facing free text recorded with each match — appears
    /// in quarantine events and audit output.
    pub reason: String,
}

/// Parse one `CurationRule` envelope.
pub fn parse_curation_rule(
    _path: &Path,
    bytes: &[u8],
) -> Result<Envelope<CurationRuleSpec>, ParseError> {
    let env: Envelope<CurationRuleSpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::CurationRule {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["CurationRule"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    Ok(env)
}

/// Per-spec validation. Confirms `format` is `"any"` or a known
/// `RepositoryFormat`, and that `action` parses through
/// `CurationRuleAction::FromStr`.
pub fn validate_curation_rule(env: &Envelope<CurationRuleSpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::CurationRule,
            name: env.metadata.name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    if env.spec.pattern.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::CurationRule,
            name: env.metadata.name.clone(),
            detail: "spec.pattern must not be blank".into(),
        });
    }

    if env.spec.reason.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::CurationRule,
            name: env.metadata.name.clone(),
            detail: "spec.reason must not be blank".into(),
        });
    }

    // `format`: literal "any" OR a known `RepositoryFormat`.
    // `RepositoryFormat::FromStr` is infallible and falls back to
    // `Other(_)`, so we explicitly reject the `Other` arm.
    let format_lower = env.spec.format.to_lowercase();
    if format_lower != "any" {
        let parsed: RepositoryFormat = env.spec.format.parse().unwrap_or(RepositoryFormat::Generic);
        if matches!(parsed, RepositoryFormat::Other(_)) {
            errors.push(ValidationError::UnknownEnumValue {
                field: "spec.format",
                got: env.spec.format.clone(),
                expected: vec!["any", "npm", "pypi", "cargo", "maven", "docker", "..."],
            });
        }
    }

    if CurationRuleAction::from_str(&env.spec.action).is_err() {
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.action",
            got: env.spec.action.clone(),
            expected: vec!["block", "warn", "allow"],
        });
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    fn yaml(name: &str, body: &str) -> String {
        format!(
            "apiVersion: project-hort.de/v1beta1\nkind: CurationRule\nmetadata:\n  name: {name}\nspec:{body}"
        )
    }

    #[test]
    fn parse_full_rule_round_trip() {
        let body = "
  format: any
  pattern: \"xz-utils*\"
  action: block
  reason: CVE-2024-3094
";
        let env = parse_curation_rule(&p(), yaml("block-cve-2024-3094", body).as_bytes()).unwrap();
        assert_eq!(env.spec.format, "any");
        assert_eq!(env.spec.pattern, "xz-utils*");
        assert_eq!(env.spec.action, "block");
        assert_eq!(env.spec.reason, "CVE-2024-3094");
        assert!(validate_curation_rule(&env).is_empty());
    }

    #[test]
    fn parse_specific_format_round_trip() {
        let body = "
  format: npm
  pattern: \"left-pad\"
  action: warn
  reason: \"deprecated package\"
";
        let env = parse_curation_rule(&p(), yaml("warn-leftpad", body).as_bytes()).unwrap();
        assert!(validate_curation_rule(&env).is_empty());
    }

    #[test]
    fn validate_accepts_all_three_actions() {
        for action in ["block", "warn", "allow"] {
            let body = format!(
                "
  format: any
  pattern: x
  action: {action}
  reason: test
"
            );
            let env = parse_curation_rule(&p(), yaml("r", &body).as_bytes()).unwrap();
            assert!(
                validate_curation_rule(&env).is_empty(),
                "action `{action}` must validate"
            );
        }
    }

    #[test]
    fn validate_rejects_unknown_action() {
        let body = "
  format: any
  pattern: x
  action: deny
  reason: test
";
        let env = parse_curation_rule(&p(), yaml("r", body).as_bytes()).unwrap();
        let errors = validate_curation_rule(&env);
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.action" && got == "deny"
        )));
    }

    #[test]
    fn validate_rejects_unknown_format() {
        let body = "
  format: madeupformat
  pattern: x
  action: block
  reason: test
";
        let env = parse_curation_rule(&p(), yaml("r", body).as_bytes()).unwrap();
        let errors = validate_curation_rule(&env);
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.format" && got == "madeupformat"
        )));
    }

    #[test]
    fn validate_rejects_blank_pattern() {
        let body = "
  format: any
  pattern: ''
  action: block
  reason: test
";
        let env = parse_curation_rule(&p(), yaml("r", body).as_bytes()).unwrap();
        let errors = validate_curation_rule(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("spec.pattern")));
    }

    #[test]
    fn validate_rejects_blank_reason() {
        let body = "
  format: any
  pattern: x
  action: block
  reason: ''
";
        let env = parse_curation_rule(&p(), yaml("r", body).as_bytes()).unwrap();
        let errors = validate_curation_rule(&env);
        assert!(errors.iter().any(|e| e.to_string().contains("spec.reason")));
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  format: any
  pattern: x
  action: block
  reason: r
  bogus: 1
";
        let err = parse_curation_rule(&p(), yaml("r", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn parse_rejects_missing_required_field() {
        let body = "
  format: any
  pattern: x
  action: block
";
        let err = parse_curation_rule(&p(), yaml("r", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let body = "
  format: any
  pattern: x
  action: block
  reason: r
";
        let yaml_doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: CurationRule\nmetadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_curation_rule(&p(), yaml_doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }

    #[test]
    fn validate_format_any_is_case_insensitive() {
        // `RepositoryFormat::FromStr` lowercases input before matching;
        // the explicit "any" check should follow the same convention so
        // operators don't get bitten by `Any` vs `any`.
        let body = "
  format: ANY
  pattern: x
  action: block
  reason: r
";
        let env = parse_curation_rule(&p(), yaml("r", body).as_bytes()).unwrap();
        assert!(validate_curation_rule(&env).is_empty());
    }
}
