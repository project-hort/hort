//! `kind: RetentionPolicy` schema, parser, and per-spec validation.
//!
//! Event-sourced kind: the apply pipeline diffs the desired YAML
//! against the current `retention_policy_projections` row and emits
//! `RetentionPolicyChanged` domain events via `RetentionPolicyUseCase`.
//! This module supplies only the schema + per-envelope validation; the
//! diff-and-emit machinery lives in
//! `ApplyConfigUseCase::apply_retention_policies`.
//!
//! ## Machine envelope
//!
//! This module implements the *machine* envelope: a `ScanPolicySpec`-shaped
//! YAML whose `predicate` / `scope` are the JSON serde forms of
//! [`PolicyPredicate`](hort_domain::retention::PolicyPredicate) /
//! [`RetentionScope`](hort_domain::retention::RetentionScope) (both are
//! `Serialize + Deserialize` in `hort-domain`). The apply pipeline is
//! the only way to configure retention policies in v1 (every policy
//! aggregate is gitops-authored — there is no imperative HTTP API,
//! exactly like `ScanPolicy`). `RetentionScope::Repos` carries
//! repository **UUIDs** in this machine envelope; resolving repo
//! `metadata.name` → id is a planned DSL follow-on not yet implemented.
//!
//! The apply-time `IngestSource(Direct)` warning lands in
//! `ApplyConfigUseCase`, NOT here — this layer is pure schema.

use std::path::Path;

use hort_domain::retention::{PolicyPredicate, RetentionScope};
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};

/// Deserialize the operator-authored `predicate` mapping into
/// [`PolicyPredicate`]. The YAML body is parsed into a
/// `serde_json::Value` first (so the operator writes the JSON-shaped
/// externally-tagged form — `{AgeExceeds: 2592000}` — rather than
/// `serde_yaml`'s `!AgeExceeds` tag form), then `serde_json::from_value`
/// resolves the domain enum. Returns the typed error so the call site
/// can attach the policy name.
pub fn predicate_from_value(v: &serde_json::Value) -> Result<PolicyPredicate, serde_json::Error> {
    serde_json::from_value(v.clone())
}

/// As [`predicate_from_value`] for the
/// [`RetentionScope`](hort_domain::retention::RetentionScope). `pub` so
/// the `hort-app` apply pipeline (`apply_retention_policies`) can resolve
/// the machine-envelope `Value` into the domain enum.
pub fn scope_from_value(v: &serde_json::Value) -> Result<RetentionScope, serde_json::Error> {
    serde_json::from_value(v.clone())
}

/// Shape of a `kind: RetentionPolicy` YAML body.
///
/// `predicate` and `scope` are the domain enums deserialized
/// directly from their serde JSON form (the machine envelope). Their
/// structural bounds (composite depth/width, non-zero TTLs, CVSS
/// range, repo-list / pattern length) are enforced by the domain
/// validators in `validate_retention_policy` — keeping the wire
/// shape as the typed enum means a malformed value surfaces as a
/// typed validation error referencing the policy name, and the same
/// validator runs again at event-replay time (defence in depth).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionPolicySpec {
    /// The retention match predicate, written in the
    /// externally-tagged **JSON shape** (e.g. `predicate: {AgeExceeds:
    /// 2592000}` or a nested `Composite`). Held as opaque
    /// `serde_json::Value` at the wire layer (YAML maps → JSON
    /// objects) and resolved to
    /// [`PolicyPredicate`](hort_domain::retention::PolicyPredicate) by
    /// `validate_retention_policy` / the apply use case via
    /// [`predicate_from_value`]. Carrying it as `Value` (rather than
    /// the typed enum) is deliberate: `serde_yaml_ng` represents Rust
    /// externally-tagged enums with `!Variant` YAML tags, which is NOT
    /// the JSON-shaped machine-envelope contract the operator writes;
    /// going via JSON preserves the JSON form and surfaces a malformed
    /// value as a typed validation error naming the policy.
    pub predicate: serde_json::Value,
    /// Which artifacts the policy applies to —
    /// [`RetentionScope`](hort_domain::retention::RetentionScope) in its
    /// JSON shape (e.g. `scope: AllRepos`, `scope: {Repos: ["<uuid>"]}`,
    /// `scope: {IngestSource: Proxied}`). Same `Value`-then-resolve
    /// rationale as `predicate`.
    pub scope: serde_json::Value,
}

/// Parse one `RetentionPolicy` envelope.
pub fn parse_retention_policy(
    _path: &Path,
    bytes: &[u8],
) -> Result<Envelope<RetentionPolicySpec>, ParseError> {
    let env: Envelope<RetentionPolicySpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::RetentionPolicy {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["RetentionPolicy"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    Ok(env)
}

/// Per-spec validation:
/// - `metadata.name` non-blank
/// - `predicate` passes B1's
///   [`PolicyPredicate::validate`](hort_domain::retention::PolicyPredicate::validate)
///   (composite depth/width, non-zero TTLs, CVSS range, `KeepLastN`
///   non-zero)
/// - `scope` passes B1's
///   [`RetentionScope::validate`](hort_domain::retention::RetentionScope::validate)
///   (non-empty / bounded `Repos`, bounded `PackageNamePattern`)
///
/// The §6-invariant-8 *security-predicate-does-not-exclude-direct-uploads*
/// `info!` warning is **not** a validation reject — it fires at apply
/// time in `ApplyConfigUseCase::apply_retention_policies` (B1
/// acceptance bullet 4: it is operator-intent advisory, the policy
/// still applies). This function only enforces structural validity.
pub fn validate_retention_policy(env: &Envelope<RetentionPolicySpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::RetentionPolicy,
            name: env.metadata.name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    match predicate_from_value(&env.spec.predicate) {
        Ok(predicate) => {
            if let Err(e) = predicate.validate() {
                errors.push(ValidationError::Invalid {
                    kind: Kind::RetentionPolicy,
                    name: env.metadata.name.clone(),
                    detail: format!("spec.predicate is invalid: {e}"),
                });
            }
        }
        Err(e) => errors.push(ValidationError::Invalid {
            kind: Kind::RetentionPolicy,
            name: env.metadata.name.clone(),
            detail: format!("spec.predicate is not a valid retention predicate: {e}"),
        }),
    }

    match scope_from_value(&env.spec.scope) {
        Ok(scope) => {
            if let Err(e) = scope.validate() {
                errors.push(ValidationError::Invalid {
                    kind: Kind::RetentionPolicy,
                    name: env.metadata.name.clone(),
                    detail: format!("spec.scope is invalid: {e}"),
                });
            }
        }
        Err(e) => errors.push(ValidationError::Invalid {
            kind: Kind::RetentionPolicy,
            name: env.metadata.name.clone(),
            detail: format!("spec.scope is not a valid retention scope: {e}"),
        }),
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
            "apiVersion: project-hort.de/v1beta1\nkind: RetentionPolicy\n\
             metadata:\n  name: {name}\nspec:{body}"
        )
    }

    #[test]
    fn parse_age_exceeds_round_trip_all_repos() {
        let body = "
  predicate:
    AgeExceeds: 2592000
  scope: AllRepos
";
        let env = parse_retention_policy(&p(), yaml("retain-30d", body).as_bytes()).unwrap();
        let pred = predicate_from_value(&env.spec.predicate).expect("predicate resolves");
        assert_eq!(pred, PolicyPredicate::AgeExceeds(2_592_000));
        let scope = scope_from_value(&env.spec.scope).expect("scope resolves");
        assert_eq!(scope, RetentionScope::AllRepos);
        assert!(validate_retention_policy(&env).is_empty());
    }

    #[test]
    fn parse_security_composite_with_proxied_scope() {
        // Machine-envelope (JSON-shaped) form fixture.
        let body = "
  predicate:
    Composite:
      - And
      - - HasFindingAboveSeverity: High
        - HasFixAvailable
        - HasFindingDetectedFor: 604800
  scope:
    IngestSource: Proxied
";
        let env =
            parse_retention_policy(&p(), yaml("retain-vuln-proxied", body).as_bytes()).unwrap();
        let pred = predicate_from_value(&env.spec.predicate).expect("predicate resolves");
        assert!(pred.is_security_driven());
        let scope = scope_from_value(&env.spec.scope).expect("scope resolves");
        assert!(scope.excludes_direct_uploads());
        assert!(validate_retention_policy(&env).is_empty());
    }

    #[test]
    fn validate_rejects_zero_second_age_ttl() {
        // PolicyPredicate::validate rejects a 0s TTL footgun.
        let body = "
  predicate:
    AgeExceeds: 0
  scope: AllRepos
";
        let env = parse_retention_policy(&p(), yaml("bad", body).as_bytes()).unwrap();
        let errs = validate_retention_policy(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("spec.predicate is invalid")),
            "expected a predicate validation error, got {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_empty_repos_scope() {
        let body = "
  predicate:
    AgeExceeds: 60
  scope:
    Repos: []
";
        let env = parse_retention_policy(&p(), yaml("bad-scope", body).as_bytes()).unwrap();
        let errs = validate_retention_policy(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("spec.scope is invalid")),
            "expected a scope validation error, got {errs:?}"
        );
    }

    #[test]
    fn parse_rejects_wrong_kind() {
        let doc = "apiVersion: project-hort.de/v1beta1\nkind: ScanPolicy\n\
                   metadata:\n  name: x\nspec:\n  predicate:\n    AgeExceeds: 60\n  scope: AllRepos\n";
        let err = parse_retention_policy(&p(), doc.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            ParseError::UnknownKind { .. } | ParseError::Yaml(_)
        ));
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  predicate:
    AgeExceeds: 60
  scope: AllRepos
  bogus: 1
";
        let err = parse_retention_policy(&p(), yaml("p", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let body = "
  predicate:
    AgeExceeds: 60
  scope: AllRepos
";
        let doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: RetentionPolicy\n\
             metadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_retention_policy(&p(), doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }
}
