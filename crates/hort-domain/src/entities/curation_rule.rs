//! `CurationRule` — standalone gitops-managed package curation rule.
//!
//! Curation rules are first-class entities that operators declare in
//! `$HORT_CONFIG_DIR` and reference from a `Repository`'s spec by
//! `metadata.name`. The runtime curation evaluator loads the rules attached
//! to a repository via `CurationRuleRepository::list_for_repo` at ingest
//! time.
//!
//! See `docs/architecture/how-to/declare-gitops-config.md` for the YAML
//! shape.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::managed_by::ManagedBy;
use crate::entities::repository::RepositoryFormat;
use crate::error::DomainError;

// ---------------------------------------------------------------------------
// CurationRuleAction
// ---------------------------------------------------------------------------

/// What an evaluator should do when an artifact matches a [`CurationRule`].
///
/// Mirrors the `action` column on the `curation_rules` table (`006_curation.sql`);
/// the column is constrained to the same three string values via CHECK.
/// `FromStr` and `Display` are case-insensitive on parse and lowercase on
/// display so YAML, SQL, and metric labels share one spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CurationRuleAction {
    /// Refuse the artifact outright. The curation evaluator translates
    /// this into a quarantine event with `reason` carried through.
    Block,
    /// Allow the artifact but emit a warning event so an operator can
    /// follow up out-of-band.
    Warn,
    /// Explicit allow-list override. Useful when a broader `Block` rule
    /// would otherwise catch a specific known-good package.
    Allow,
}

impl fmt::Display for CurationRuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => f.write_str("block"),
            Self::Warn => f.write_str("warn"),
            Self::Allow => f.write_str("allow"),
        }
    }
}

impl FromStr for CurationRuleAction {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "warn" => Ok(Self::Warn),
            "allow" => Ok(Self::Allow),
            _ => Err(DomainError::Validation(format!(
                "unknown curation rule action: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// CurationRule
// ---------------------------------------------------------------------------

/// A single package-level curation directive.
///
/// `name` is the gitops `metadata.name`, unique across all rules — the apply
/// pipeline diffs by name. `format = None` matches packages of any format;
/// otherwise the rule fires only when `RepositoryFormat` matches. `package_pattern`
/// is a glob-style match on the package name (the matching engine is
/// format-handler territory; the entity just carries the string).
///
/// `managed_by` follows the same provenance contract as other gitops kinds
/// — `Local` rows are CRUD-mutable; `GitOps` rows are owned by `$HORT_CONFIG_DIR`
/// and the public CRUD path refuses to mutate them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CurationRule {
    pub id: Uuid,
    pub name: String,
    /// `None` is the YAML `any` keyword — match every format. Specific
    /// formats restrict the rule to artifacts in that format only.
    pub format: Option<RepositoryFormat>,
    pub package_pattern: String,
    pub action: CurationRuleAction,
    pub reason: String,
    pub managed_by: ManagedBy,
    /// SHA-256 of the canonicalised gitops `spec` JSON; non-`None` only
    /// for `ManagedBy::GitOps` rows.
    pub managed_by_digest: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- CurationRuleAction --------------------------------------------------

    #[test]
    fn action_display_lowercase() {
        assert_eq!(CurationRuleAction::Block.to_string(), "block");
        assert_eq!(CurationRuleAction::Warn.to_string(), "warn");
        assert_eq!(CurationRuleAction::Allow.to_string(), "allow");
    }

    #[test]
    fn action_from_str_round_trip() {
        for v in [
            CurationRuleAction::Block,
            CurationRuleAction::Warn,
            CurationRuleAction::Allow,
        ] {
            let parsed: CurationRuleAction = v.to_string().parse().unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn action_from_str_case_insensitive() {
        let cases = [
            ("BLOCK", CurationRuleAction::Block),
            ("Block", CurationRuleAction::Block),
            ("WARN", CurationRuleAction::Warn),
            ("Allow", CurationRuleAction::Allow),
        ];
        for (input, expected) in cases {
            let parsed: CurationRuleAction = input.parse().unwrap();
            assert_eq!(parsed, expected, "failed on input {input}");
        }
    }

    #[test]
    fn action_from_str_unknown_is_validation_error() {
        let err = "deny".parse::<CurationRuleAction>().unwrap_err();
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("deny"), "msg should name the bad input: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn action_from_str_empty_is_validation_error() {
        let err = "".parse::<CurationRuleAction>().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- CurationRule --------------------------------------------------------

    fn sample_rule(format: Option<RepositoryFormat>) -> CurationRule {
        CurationRule {
            id: Uuid::nil(),
            name: "block-cve-2024-3094".into(),
            format,
            package_pattern: "xz-utils*".into(),
            action: CurationRuleAction::Block,
            reason: "CVE-2024-3094".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        }
    }

    #[test]
    fn rule_clone_eq_round_trip_any_format() {
        let r = sample_rule(None);
        assert_eq!(r, r.clone());
        assert!(r.format.is_none());
    }

    #[test]
    fn rule_clone_eq_round_trip_specific_format() {
        let r = sample_rule(Some(RepositoryFormat::Npm));
        assert_eq!(r, r.clone());
        assert_eq!(r.format, Some(RepositoryFormat::Npm));
    }

    #[test]
    fn rule_local_default_has_no_digest() {
        let r = CurationRule {
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            ..sample_rule(None)
        };
        assert_eq!(r.managed_by, ManagedBy::Local);
        assert!(r.managed_by_digest.is_none());
    }

    #[test]
    fn rule_serde_round_trip() {
        let r = sample_rule(Some(RepositoryFormat::Pypi));
        let json = serde_json::to_string(&r).unwrap();
        let decoded: CurationRule = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }
}
