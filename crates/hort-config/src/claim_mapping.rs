//! `kind: ClaimMapping` schema and parser (ADR 0012).
//!
//! Single parser entry point: `parse_claim_mapping` accepts the
//! canonical one-object-per-file envelope shape:
//!
//! ```yaml
//! apiVersion: project-hort.de/v1beta1
//! kind: ClaimMapping
//! metadata:
//!   name: admins
//! spec:
//!   idpGroup: hort-admins
//!   claim: admin
//! ```
//!
//! The RBAC model is additive-claims (ADR 0012): a `ClaimMapping`
//! declares which IdP group name resolves to which registry **claim
//! name** (there is no group-to-role mapping — there are no roles). The
//! server flattens the caller's `groups` claim against the
//! `claim_mappings` table at authentication time
//! (`hort-app::rbac::resolve_claims`). The two-field minimal shape
//! mirrors `hort_domain::entities::rbac::ClaimMapping`'s gitops-relevant
//! fields (`idp_group` + `claim`); `id`, timestamps, `managed_by`, and
//! the digest are server-assigned at apply time.
//!
//! The legacy `mappings: [...]` multi-object root shape is not accepted;
//! files declaring it surface `ParseError::UnsupportedShape` from the
//! dispatch layer in `desired::parse_one_file`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::ParseError;

/// Shape of a `kind: ClaimMapping` YAML body.
///
/// `idpGroup` is the external identity-provider group-claim value,
/// matched verbatim against an entry of the JWT `groups` claim at
/// authentication time. `claim` is the registry claim name the group
/// resolves to; grants requiring that claim are then satisfied for any
/// caller whose resolved claim set contains it. Both fields are
/// required and non-blank (enforced at parse time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimMappingSpec {
    /// External identity-provider group-claim value. Matched verbatim
    /// against the JWT `groups` claim at authentication time.
    pub idp_group: String,
    /// Registry claim name this group resolves to. `ClaimMapping` is
    /// the only source of resolved claim names (ADR 0012) — code paths
    /// must not invent claim names at runtime. The single synthetic
    /// exception is the `admin` claim derived from `user.is_admin=true`.
    pub claim: String,
}

/// Parse one canonical-shape `ClaimMapping` envelope.
///
/// `path` is purely diagnostic — the caller renders `ParseErrors`
/// lines from a `(PathBuf, ParseError)` vec.
pub fn parse_claim_mapping(
    path: &Path,
    bytes: &[u8],
) -> Result<Envelope<ClaimMappingSpec>, ParseError> {
    let env: Envelope<ClaimMappingSpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::ClaimMapping {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["ClaimMapping"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    if env.spec.idp_group.trim().is_empty() {
        return Err(ParseError::Yaml(yaml_invariant(
            path,
            "spec.idpGroup must not be empty",
        )));
    }
    if env.spec.claim.trim().is_empty() {
        return Err(ParseError::Yaml(yaml_invariant(
            path,
            "spec.claim must not be empty",
        )));
    }
    Ok(env)
}

/// Build a `serde_yaml_ng::Error` that carries a custom message via the
/// YAML scanner's "custom" branch. Lets us reuse `ParseError::Yaml` for
/// both shape failures (deserialize) and content failures (empty
/// fields) without inventing two more `ParseError` variants for what is
/// essentially the same operator-facing error category.
fn yaml_invariant(_path: &Path, message: &str) -> serde_yaml_ng::Error {
    serde::de::Error::custom(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    // -- canonical shape ----------------------------------------------------

    #[test]
    fn parse_canonical_envelope_round_trip() {
        let yaml = "apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: admins
spec:
  idpGroup: hort-admins
  claim: admin
";
        let env = parse_claim_mapping(&p(), yaml.as_bytes()).unwrap();
        assert_eq!(env.metadata.name, "admins");
        assert_eq!(env.spec.idp_group, "hort-admins");
        assert_eq!(env.spec.claim, "admin");
    }

    #[test]
    fn empty_idp_group_is_rejected() {
        let yaml = "apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: admins
spec:
  idpGroup: ''
  claim: admin
";
        let err = parse_claim_mapping(&p(), yaml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("idpGroup"));
    }

    #[test]
    fn empty_claim_is_rejected() {
        let yaml = "apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: admins
spec:
  idpGroup: g
  claim: ''
";
        let err = parse_claim_mapping(&p(), yaml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("claim"));
    }

    #[test]
    fn whitespace_only_idp_group_is_rejected() {
        // Defensive — operators shouldn't write `idpGroup: "   "`, but
        // matching `is_empty` after `trim` makes the rejection
        // intentional rather than accidental on the trim side.
        let yaml = "apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: admins
spec:
  idpGroup: '   '
  claim: admin
";
        let err = parse_claim_mapping(&p(), yaml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn unknown_field_in_spec_is_rejected() {
        let yaml = "apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: admins
spec:
  idpGroup: g
  claim: c
  bogus_field: 1
";
        let err = parse_claim_mapping(&p(), yaml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus_field"));
    }

    #[test]
    fn legacy_group_role_fields_are_rejected() {
        // Backwards-compat regression: the legacy `group:`/`role:`
        // GroupMapping shape is intentionally NOT supported. The kind
        // is renamed AND the field names changed; `deny_unknown_fields`
        // makes the old shape surface as a parse error rather than
        // silently dropping the fields.
        let yaml = "apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: admins
spec:
  group: hort-admins
  role: admin
";
        let err = parse_claim_mapping(&p(), yaml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn empty_metadata_name_is_rejected() {
        let yaml = "apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: ''
spec:
  idpGroup: g
  claim: c
";
        let err = parse_claim_mapping(&p(), yaml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }

    #[test]
    fn wrong_kind_envelope_is_rejected() {
        let yaml = "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: admins
spec:
  idpGroup: g
  claim: c
";
        // `serde` will fail to deserialize the spec shape against
        // `ClaimMappingSpec` first because `name`/`format`/etc. aren't
        // present. We don't pin the exact variant here; what matters is
        // that the wrong kind never round-trips silently.
        assert!(parse_claim_mapping(&p(), yaml.as_bytes()).is_err());
    }
}
