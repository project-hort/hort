//! Envelope shared by every gitops-managed YAML object.
//!
//! Every file under `$HORT_CONFIG_DIR` carries the four-field envelope
//! (`apiVersion`, `kind`, `metadata`, `spec`). The envelope itself is
//! kind-agnostic — `Spec` is a type parameter that the per-kind parsers
//! (`crate::repository`, `crate::claim_mapping`) substitute. See
//! `docs/architecture/how-to/declare-gitops-config.md`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ParseError;

/// The four-field envelope wrapping every declarable object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<Spec> {
    #[serde(rename = "apiVersion")]
    pub api_version: ApiVersion,
    pub kind: Kind,
    pub metadata: Metadata,
    pub spec: Spec,
}

/// API version literal. Only `project-hort.de/v1beta1` is accepted in v1.
///
/// `v1beta1` carries the "stabilising schema, removal-after-deprecation-window"
/// semantics — additive changes can land without a bump, but removals and
/// breaking renames are announced one minor before they take effect. There
/// is no automatic upgrade of older versions; operators re-emit when a new
/// variant is added here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiVersion {
    V1Beta1,
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1Beta1 => f.write_str("project-hort.de/v1beta1"),
        }
    }
}

impl FromStr for ApiVersion {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "project-hort.de/v1beta1" => Ok(Self::V1Beta1),
            _ => Err(ParseError::UnsupportedApiVersion { got: s.to_string() }),
        }
    }
}

/// Serde plumbing — the on-the-wire representation is the literal
/// version string, not a tagged enum.
impl Serialize for ApiVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ApiVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// Declarable kinds in v1. Each kind has a paired parser module.
///
/// `PermissionGrant` / `CurationRule` are CRUD-extension kinds (reuse
/// the `KindPlan` diff machinery); `ScanPolicy` / `Exclusion` are
/// event-sourced (run through the `ApplyEventSourcedKind` trait).
///
/// `UpstreamMapping` is a CRUD-extension shape that depends on
/// `ArtifactRepository` (resolves `spec.repository → repository_id` at
/// apply time).
///
/// `OidcIssuer` and `ServiceAccount` are CRUD-extension gitops kinds
/// for workload identity federation and service-account declaration
/// (ADR 0018).
///
/// The RBAC model is additive-claims (ADR 0012): there are no `Role` or
/// `GroupMapping` kinds; `ClaimMapping` (IdP-group → claim) carries
/// claim resolution, and `PermissionGrant` has a sum-typed subject
/// (`claims` / `user`). Roles do not exist as a gitops kind —
/// operator-side YAML templating owns permission bundling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    ArtifactRepository,
    ClaimMapping,
    PermissionGrant,
    CurationRule,
    ScanPolicy,
    Exclusion,
    UpstreamMapping,
    OidcIssuer,
    ServiceAccount,
    /// The event-sourced retention-policy gitops kind. Runs through
    /// `RetentionPolicyUseCase` (append `RetentionPolicyChanged` +
    /// upsert `retention_policy_projections`), the same event-sourced
    /// shape as `ScanPolicy`.
    RetentionPolicy,
    /// The gitops surface for the apply-config grant linter
    /// ([`crate::lint_config::PermissionGrantLintConfigSpec`], ADR 0015).
    /// This is a **singleton** kind: at most one envelope cluster-wide
    /// (>1 is a named apply-time validation error, never a silent
    /// last-wins). It carries the operator opt-*out* surface
    /// (`single_claim_allowlist` + per-rule downgrade actions); the
    /// surface is deliberately gitops-only, not an env/file path, so it
    /// is visible in the apply diff. Absent kind ⇒ the secure default
    /// (every relevant grant shape rejects).
    PermissionGrantLintConfig,
}

impl Kind {
    /// All known kind names. Used for error rendering and to populate
    /// `ParseError::UnknownKind::valid`.
    pub const KNOWN: &'static [&'static str] = &[
        "ArtifactRepository",
        "ClaimMapping",
        "PermissionGrant",
        "CurationRule",
        "ScanPolicy",
        "Exclusion",
        "UpstreamMapping",
        "OidcIssuer",
        "ServiceAccount",
        "RetentionPolicy",
        "PermissionGrantLintConfig",
    ];

    /// Lowercase short identifier used for log/metric labels and API
    /// problem+json `kind` fields. Bounded set, safe for cardinality.
    pub fn label(self) -> &'static str {
        match self {
            Self::ArtifactRepository => "repository",
            Self::ClaimMapping => "claim_mapping",
            Self::PermissionGrant => "permission_grant",
            Self::CurationRule => "curation_rule",
            Self::ScanPolicy => "scan_policy",
            Self::Exclusion => "exclusion",
            Self::UpstreamMapping => "upstream_mapping",
            Self::OidcIssuer => "oidc_issuer",
            Self::ServiceAccount => "service_account",
            Self::RetentionPolicy => "retention_policy",
            Self::PermissionGrantLintConfig => "permission_grant_lint_config",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactRepository => f.write_str("ArtifactRepository"),
            Self::ClaimMapping => f.write_str("ClaimMapping"),
            Self::PermissionGrant => f.write_str("PermissionGrant"),
            Self::CurationRule => f.write_str("CurationRule"),
            Self::ScanPolicy => f.write_str("ScanPolicy"),
            Self::Exclusion => f.write_str("Exclusion"),
            Self::UpstreamMapping => f.write_str("UpstreamMapping"),
            Self::OidcIssuer => f.write_str("OidcIssuer"),
            Self::ServiceAccount => f.write_str("ServiceAccount"),
            Self::RetentionPolicy => f.write_str("RetentionPolicy"),
            Self::PermissionGrantLintConfig => f.write_str("PermissionGrantLintConfig"),
        }
    }
}

impl FromStr for Kind {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ArtifactRepository" => Ok(Self::ArtifactRepository),
            "ClaimMapping" => Ok(Self::ClaimMapping),
            "PermissionGrant" => Ok(Self::PermissionGrant),
            "CurationRule" => Ok(Self::CurationRule),
            "ScanPolicy" => Ok(Self::ScanPolicy),
            "Exclusion" => Ok(Self::Exclusion),
            "UpstreamMapping" => Ok(Self::UpstreamMapping),
            "OidcIssuer" => Ok(Self::OidcIssuer),
            "ServiceAccount" => Ok(Self::ServiceAccount),
            "RetentionPolicy" => Ok(Self::RetentionPolicy),
            "PermissionGrantLintConfig" => Ok(Self::PermissionGrantLintConfig),
            _ => Err(ParseError::UnknownKind {
                got: s.to_string(),
                valid: Self::KNOWN,
            }),
        }
    }
}

impl Serialize for Kind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// Shared metadata block. v1 only carries `name`; future fields
/// (labels, annotations) plug in here without a schema bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ApiVersion ---------------------------------------------------------

    #[test]
    fn api_version_display() {
        assert_eq!(ApiVersion::V1Beta1.to_string(), "project-hort.de/v1beta1");
    }

    #[test]
    fn api_version_from_str_accepts_canonical() {
        let v: ApiVersion = "project-hort.de/v1beta1".parse().unwrap();
        assert_eq!(v, ApiVersion::V1Beta1);
    }

    #[test]
    fn api_version_from_str_rejects_unknown() {
        let err = "project-hort.de/v2".parse::<ApiVersion>().unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("v2") && rendered.contains("project-hort.de/v1beta1"),
            "error must name both the bad version and the known one: {rendered}"
        );
    }

    #[test]
    fn api_version_from_str_rejects_empty() {
        assert!("".parse::<ApiVersion>().is_err());
    }

    #[test]
    fn api_version_serde_roundtrip() {
        // Wrap in a tiny struct so we exercise serde, not just FromStr.
        #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
        struct Wrap {
            v: ApiVersion,
        }
        let w = Wrap {
            v: ApiVersion::V1Beta1,
        };
        let yaml = serde_yaml_ng::to_string(&w).unwrap();
        let back: Wrap = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(w, back);
    }

    // -- Kind ---------------------------------------------------------------

    #[test]
    fn kind_display_round_trips_with_from_str() {
        for k in [
            Kind::ArtifactRepository,
            Kind::ClaimMapping,
            Kind::PermissionGrant,
            Kind::CurationRule,
            Kind::ScanPolicy,
            Kind::Exclusion,
            Kind::UpstreamMapping,
            Kind::OidcIssuer,
            Kind::ServiceAccount,
            Kind::RetentionPolicy,
            Kind::PermissionGrantLintConfig,
        ] {
            let parsed: Kind = k.to_string().parse().unwrap();
            assert_eq!(parsed, k);
        }
    }

    #[test]
    fn kind_label_is_lowercase_underscored() {
        assert_eq!(Kind::ArtifactRepository.label(), "repository");
        assert_eq!(Kind::ClaimMapping.label(), "claim_mapping");
        assert_eq!(Kind::PermissionGrant.label(), "permission_grant");
        assert_eq!(Kind::CurationRule.label(), "curation_rule");
        assert_eq!(Kind::ScanPolicy.label(), "scan_policy");
        assert_eq!(Kind::Exclusion.label(), "exclusion");
        assert_eq!(Kind::UpstreamMapping.label(), "upstream_mapping");
        assert_eq!(Kind::OidcIssuer.label(), "oidc_issuer");
        assert_eq!(Kind::ServiceAccount.label(), "service_account");
        assert_eq!(Kind::RetentionPolicy.label(), "retention_policy");
        assert_eq!(
            Kind::PermissionGrantLintConfig.label(),
            "permission_grant_lint_config"
        );
    }

    #[test]
    fn kind_known_lists_every_variant() {
        // Ensure the KNOWN array stays in lockstep with the enum
        // variants — the unknown-kind error message reads from this.
        // `RetentionPolicy` and the singleton cluster-config kind
        // `PermissionGrantLintConfig` are both counted here.
        assert_eq!(Kind::KNOWN.len(), 11);
        for &name in Kind::KNOWN {
            let parsed: Kind = name.parse().expect("KNOWN entry must round-trip");
            assert_eq!(parsed.to_string(), name);
        }
    }

    #[test]
    fn kind_from_str_is_case_sensitive() {
        // YAML envelopes use exact PascalCase. A loose match would let a
        // typo like `artifactrepository` quietly succeed and surprise the
        // operator at apply-time when the field-mapping doesn't fit.
        assert!("artifactrepository".parse::<Kind>().is_err());
        assert!("ARTIFACTREPOSITORY".parse::<Kind>().is_err());
    }

    #[test]
    fn kind_from_str_unknown_lists_known_in_error() {
        let err = "Repository".parse::<Kind>().unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ArtifactRepository"));
        assert!(rendered.contains("ClaimMapping"));
        // The Initiative-14 additions must surface in the same error
        // message — operators typing `policy` should see `ScanPolicy`
        // suggested, not silently fall through to a generic message.
        assert!(rendered.contains("ScanPolicy"));
        assert!(rendered.contains("Exclusion"));
    }
}
