//! `kind: Exclusion` schema, parser, and per-spec validation.
//!
//! Event-sourced sub-state of a parent `ScanPolicy`: identity is
//! `(policy_name, cve_id, package_pattern_or_null)`.
//! This module covers schema + per-envelope validation only. Cross-doc
//! rules (parent policy must exist; `(cve_id, package_pattern)` unique
//! per parent) live in `crate::desired::validate`.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};
use crate::scope::ScopeSpec;

/// Shape of a `kind: Exclusion` YAML body.
///
/// `policy` references the parent `ScanPolicy.metadata.name`. The
/// cross-spec validator in `crate::desired` resolves the reference;
/// here we only check it is non-blank.
///
/// `expiresAt` is RFC3339 / ISO-8601 — `chrono::DateTime` parses both
/// when fed through `serde`. `None` means "no expiry" — the
/// projection drops the row when removed by gitops, never on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExclusionSpec {
    /// Parent `ScanPolicy.metadata.name`. Cross-spec validation
    /// enforces existence in `DesiredState.scan_policies`.
    pub policy: String,
    pub cve_id: String,
    /// Optional glob match restricting the exclusion to a subset of
    /// affected packages. `None` exempts every package matching the
    /// CVE (typical when the registry serves only one package family).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_pattern: Option<String>,
    /// `global` or `{ repository: <metadata.name> }`. The cross-spec
    /// validator does NOT resolve the repository reference here —
    /// the apply pipeline inherits the resolution from the parent
    /// policy's scope when present.
    pub scope: ScopeSpec,
    /// Operator-facing rationale stored on the `ExclusionAdded`
    /// event. Mandatory by intent — empty rationale is an audit
    /// failure mode.
    pub reason: String,
    /// Optional RFC3339 timestamp. Serde parses from
    /// `"2026-12-31T23:59:59Z"` directly — operators don't need a
    /// custom converter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Parse one `Exclusion` envelope.
pub fn parse_exclusion(_path: &Path, bytes: &[u8]) -> Result<Envelope<ExclusionSpec>, ParseError> {
    let env: Envelope<ExclusionSpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::Exclusion {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["Exclusion"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    Ok(env)
}

/// Per-spec validation. Cross-spec rules — parent policy resolution,
/// per-policy `(cve_id, pattern)` uniqueness — live in
/// `crate::desired::validate`.
pub fn validate_exclusion(env: &Envelope<ExclusionSpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::Exclusion,
            name: env.metadata.name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    if env.spec.policy.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::Exclusion,
            name: env.metadata.name.clone(),
            detail: "spec.policy must not be blank".into(),
        });
    }

    if env.spec.cve_id.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::Exclusion,
            name: env.metadata.name.clone(),
            detail: "spec.cveId must not be blank".into(),
        });
    }

    if env.spec.reason.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::Exclusion,
            name: env.metadata.name.clone(),
            detail: "spec.reason must not be blank".into(),
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
            "apiVersion: project-hort.de/v1beta1\nkind: Exclusion\nmetadata:\n  name: {name}\nspec:{body}"
        )
    }

    #[test]
    fn parse_full_exclusion_round_trip() {
        let body = "
  policy: prod-default
  cveId: CVE-2024-3094
  packagePattern: \"xz-utils@<5.6.2\"
  scope: global
  reason: \"Patched in container layer\"
  expiresAt: \"2026-12-31T23:59:59Z\"
";
        let env = parse_exclusion(&p(), yaml("cve-2024-3094-on-old-xz", body).as_bytes()).unwrap();
        assert_eq!(env.spec.policy, "prod-default");
        assert_eq!(env.spec.cve_id, "CVE-2024-3094");
        assert_eq!(env.spec.package_pattern.as_deref(), Some("xz-utils@<5.6.2"));
        assert_eq!(env.spec.scope, ScopeSpec::Global);
        assert!(env.spec.expires_at.is_some());
        assert!(validate_exclusion(&env).is_empty());
    }

    #[test]
    fn parse_minimal_exclusion_omits_optional_fields() {
        let body = "
  policy: prod-default
  cveId: CVE-2025-0001
  scope: global
  reason: \"Will fix in next release\"
";
        let env = parse_exclusion(&p(), yaml("cve-2025-0001", body).as_bytes()).unwrap();
        assert!(env.spec.package_pattern.is_none());
        assert!(env.spec.expires_at.is_none());
        assert!(validate_exclusion(&env).is_empty());
    }

    #[test]
    fn parse_repository_scoped_exclusion_round_trip() {
        let body = "
  policy: npm-strict
  cveId: CVE-2024-9999
  scope:
    repository: npm-public
  reason: \"Scoped to mirror only\"
";
        let env = parse_exclusion(&p(), yaml("cve-2024-9999", body).as_bytes()).unwrap();
        assert!(matches!(env.spec.scope, ScopeSpec::Repository(_)));
        assert!(validate_exclusion(&env).is_empty());
    }

    #[test]
    fn parse_rejects_missing_policy() {
        let body = "
  cveId: CVE-2024-3094
  scope: global
  reason: r
";
        let err = parse_exclusion(&p(), yaml("ex", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_missing_cve_id() {
        let body = "
  policy: p
  scope: global
  reason: r
";
        let err = parse_exclusion(&p(), yaml("ex", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  policy: p
  cveId: CVE-1
  scope: global
  reason: r
  bogus: 1
";
        let err = parse_exclusion(&p(), yaml("ex", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn parse_rejects_malformed_expires_at() {
        let body = "
  policy: p
  cveId: CVE-1
  scope: global
  reason: r
  expiresAt: \"yesterday\"
";
        let err = parse_exclusion(&p(), yaml("ex", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn validate_rejects_blank_cve_id() {
        let body = "
  policy: p
  cveId: '   '
  scope: global
  reason: r
";
        let env = parse_exclusion(&p(), yaml("ex", body).as_bytes()).unwrap();
        let errors = validate_exclusion(&env);
        assert!(errors.iter().any(|e| e.to_string().contains("spec.cveId")));
    }

    #[test]
    fn validate_rejects_blank_policy() {
        let body = "
  policy: '   '
  cveId: CVE-1
  scope: global
  reason: r
";
        let env = parse_exclusion(&p(), yaml("ex", body).as_bytes()).unwrap();
        let errors = validate_exclusion(&env);
        assert!(errors.iter().any(|e| e.to_string().contains("spec.policy")));
    }

    #[test]
    fn validate_rejects_blank_reason() {
        let body = "
  policy: p
  cveId: CVE-1
  scope: global
  reason: ''
";
        let env = parse_exclusion(&p(), yaml("ex", body).as_bytes()).unwrap();
        let errors = validate_exclusion(&env);
        assert!(errors.iter().any(|e| e.to_string().contains("spec.reason")));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let body = "
  policy: p
  cveId: CVE-1
  scope: global
  reason: r
";
        let yaml_doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: Exclusion\nmetadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_exclusion(&p(), yaml_doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }
}
