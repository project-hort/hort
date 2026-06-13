//! `ScopeSpec` — shared between `ScanPolicy` and `Exclusion`.
//!
//! The YAML surface accepts two shapes:
//!
//! ```yaml
//! scope: global
//! ```
//!
//! ```yaml
//! scope:
//!   repository: npm-public
//! ```
//!
//! The string-form maps to [`ScopeSpec::Global`]; the mapping-form to
//! [`ScopeSpec::Repository`] carrying the referenced repository's
//! `metadata.name` (the cross-spec validator in `crate::desired`
//! resolves the name to a UUID at apply-time).
//!
//! `untagged` is the right serde shape here: the two on-the-wire forms
//! are structurally distinct (string vs map), so serde unambiguously
//! picks the right variant without an explicit `kind:` discriminator.

use serde::{Deserialize, Serialize};

/// Scope discriminator carried by `ScanPolicy` and `Exclusion`.
///
/// `Global` matches the YAML literal `global`; `Repository(name)`
/// matches the YAML map `{ repository: <name> }`. Repository name
/// resolution to a UUID is the apply pipeline's job — this enum just
/// carries the operator-supplied string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeSpec {
    /// `scope: global` — applies to every repository.
    #[serde(rename = "global", with = "scope_global_str")]
    Global,
    /// `scope: { repository: <metadata.name> }` — scoped to one
    /// declared `ArtifactRepository`. Cross-spec validation ensures
    /// the referenced repository exists in `DesiredState.repositories`.
    Repository(RepositoryScope),
}

/// Wrapper around the `repository: <name>` mapping form. The single-
/// field struct lets serde's untagged dispatch see a map shape and
/// route to this variant (a bare `String` would collide with the
/// string form `Global` uses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryScope {
    pub repository: String,
}

/// serde shim that pins the `Global` variant to the literal string
/// `"global"` in both directions. Untagged enums need a serializer /
/// deserializer hook for unit variants because the default behaviour
/// would emit `null`, not the discriminator string.
mod scope_global_str {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("global")
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw == "global" {
            Ok(())
        } else {
            Err(serde::de::Error::custom(format!(
                "scope must be the literal string `global` or a mapping \
                 `{{ repository: <name> }}`, got `{raw}`"
            )))
        }
    }
}

impl ScopeSpec {
    /// Convenience accessor used by validators and the dangling-
    /// reference check in `crate::desired`. Returns the referenced
    /// repository name when the scope is `Repository`, `None` for
    /// `Global`.
    pub fn repository_name(&self) -> Option<&str> {
        match self {
            Self::Global => None,
            Self::Repository(r) => Some(&r.repository),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct Wrap {
        scope: ScopeSpec,
    }

    #[test]
    fn parses_global_string_form() {
        let yaml = "scope: global\n";
        let w: Wrap = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(w.scope, ScopeSpec::Global);
    }

    #[test]
    fn parses_repository_mapping_form() {
        let yaml = "scope:\n  repository: npm-public\n";
        let w: Wrap = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(
            w.scope,
            ScopeSpec::Repository(RepositoryScope {
                repository: "npm-public".into()
            })
        );
    }

    #[test]
    fn rejects_unknown_string() {
        // serde's untagged enum dispatch swallows the inner branch's
        // custom messages and surfaces a bare "did not match any
        // variant" error. The structural property we pin is that the
        // unknown form is rejected at all — operator-friendly
        // diagnostics for the bare-string case live one level up
        // (the parent kind module surfaces the surrounding context
        // when serde_yaml_ng wraps the error with the field path).
        let yaml = "scope: cluster\n";
        assert!(serde_yaml_ng::from_str::<Wrap>(yaml).is_err());
    }

    #[test]
    fn rejects_unknown_mapping_field() {
        // `deny_unknown_fields` on RepositoryScope ensures typos in the
        // mapping form fail loudly rather than silently producing an
        // invalid scope.
        let yaml = "scope:\n  repo: npm-public\n";
        assert!(serde_yaml_ng::from_str::<Wrap>(yaml).is_err());
    }

    #[test]
    fn round_trips_global_through_yaml() {
        let original = Wrap {
            scope: ScopeSpec::Global,
        };
        let yaml = serde_yaml_ng::to_string(&original).unwrap();
        assert!(yaml.contains("global"));
        let back: Wrap = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn round_trips_repository_through_yaml() {
        let original = Wrap {
            scope: ScopeSpec::Repository(RepositoryScope {
                repository: "pypi-public".into(),
            }),
        };
        let yaml = serde_yaml_ng::to_string(&original).unwrap();
        let back: Wrap = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn repository_name_accessor() {
        assert_eq!(ScopeSpec::Global.repository_name(), None);
        assert_eq!(
            ScopeSpec::Repository(RepositoryScope {
                repository: "x".into(),
            })
            .repository_name(),
            Some("x")
        );
    }
}
