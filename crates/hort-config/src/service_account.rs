//! `kind: ServiceAccount` schema, parser, and per-spec validation.
//!
//! Declares a non-human identity (see ADR 0018). One envelope per
//! identity; envelope identity is `metadata.name`. Valid shapes:
//! - `federatedIdentities` + `fallbackRotation` (both blocks set)
//! - `federatedIdentities` only (federation-only SA)
//! - `fallbackRotation` only (legacy CI that can't do OIDC)
//! - neither (PAT-only SA an operator mints via `hort-cli admin token issue`)
//!
//! See `docs/architecture/how-to/declare-gitops-config.md` for the
//! canonical YAML.
//!
//! # Apply-time invariants
//!
//! - `role` ∈ `{developer, reader}`. Admin SAs are forbidden by design
//!   — admin is reserved for short-lived interactive sessions.
//! - `repositories` non-empty (no global service-account grants).
//! - `federatedIdentities[].issuer` non-blank. **Cross-kind FK
//!   resolution lives in
//!   `ApplyConfigUseCase::validate_service_account_issuer_fk`** —
//!   spec-level validation is kind-local. A follow-on will merge the
//!   FK check into the use case's main `validate_against` helper once
//!   that signature is widened to accept the desired-state diff.
//! - `federatedIdentities[].claims` **non-empty** — empty claims means
//!   "any JWT from this issuer can assume me," which is a
//!   privilege-escalation footgun. Hard rejection.
//! - `fallbackRotation.targetSecret.name` / `.namespace` non-blank;
//!   names must match the k8s DNS label/subdomain regex (≤63 chars).
//! - `fallbackRotation.format` ∈ `{dockerconfigjson, opaque}`.
//! - `fallbackRotation.rotationInterval` ≥ 1h (`humantime`).
//! - `fallbackRotation.validity` ≥ 2 × `rotationInterval`. The factor
//!   of two is the safety margin for consumer-side Secret reload
//!   latency.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};

/// `role` values the apply-time validator accepts. Admin is forbidden
/// — admin is reserved for short-lived interactive sessions.
const ALLOWED_ROLES: &[&str] = &["developer", "reader"];

/// `fallbackRotation.format` values the apply-time validator accepts.
/// Mirrors the domain enum
/// ([`SecretFormat`](hort_domain::entities::service_account::SecretFormat)).
const ALLOWED_SECRET_FORMATS: &[&str] = &["dockerconfigjson", "opaque"];

/// Minimum `fallbackRotation.rotationInterval`. The reconciler ticks
/// every 15 minutes by default; an interval below 1h would let a
/// reconciler-induced rotation storm exceed the issuer's natural-expiry
/// grace window.
const MIN_ROTATION_INTERVAL: Duration = Duration::from_secs(3600);

/// Maximum length of a k8s DNS subdomain / label per RFC 1123. Both
/// the Secret name and the namespace cap at 63 characters as the
/// stricter of the two limits — k8s allows 253 for subdomains but
/// most cluster admission webhooks normalise on 63.
const MAX_K8S_NAME_LEN: usize = 63;

/// Shape of a `kind: ServiceAccount` YAML body.
///
/// `deny_unknown_fields` rejects typos at parse time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceAccountSpec {
    /// Role granted to the SA. Apply-time validator gates to
    /// `{developer, reader}`.
    pub role: String,
    /// Repositories the role is scoped to. Non-empty at apply time.
    pub repositories: Vec<String>,
    /// Federation trust policy. Optional — an SA may exist without any
    /// federated identities (PAT-only path).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub federated_identities: Vec<FederatedIdentitySpec>,
    /// Fallback PAT-rotation target. Optional — an SA may exist
    /// without rotation (federation-only path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_rotation: Option<FallbackRotationSpec>,
}

/// One federation trust relationship.
///
/// `claims` is `BTreeMap` — wire shape matches the domain entity's
/// `BTreeMap<String, String>`, and the order-stable serialisation
/// simplifies the apply-pass digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedIdentitySpec {
    /// References an `OidcIssuer.metadata.name`. Apply-time
    /// cross-kind FK lives in
    /// `ApplyConfigUseCase::validate_service_account_issuer_fk`
    /// (merging the helper into `validate_against` is the follow-on).
    pub issuer: String,
    /// Exact-match claim set. Non-empty at apply time.
    pub claims: BTreeMap<String, String>,
}

/// Fallback PAT-rotation target shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FallbackRotationSpec {
    pub target_secret: TargetSecretSpec,
    /// Humantime string. Min `1h`. Default `"6h"`.
    #[serde(default = "default_rotation_interval")]
    pub rotation_interval: String,
    /// Humantime string. Must be ≥ 2 × `rotation_interval`.
    /// Default `"24h"`.
    #[serde(default = "default_validity")]
    pub validity: String,
}

/// Target k8s Secret coordinates + wire-format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetSecretSpec {
    pub name: String,
    pub namespace: String,
    /// `dockerconfigjson` | `opaque`. Validated against
    /// [`ALLOWED_SECRET_FORMATS`].
    pub format: String,
}

fn default_rotation_interval() -> String {
    "6h".to_string()
}

fn default_validity() -> String {
    "24h".to_string()
}

/// Parse one `ServiceAccount` envelope.
pub fn parse_service_account(
    _path: &Path,
    bytes: &[u8],
) -> Result<Envelope<ServiceAccountSpec>, ParseError> {
    let env: Envelope<ServiceAccountSpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::ServiceAccount {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["ServiceAccount"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    Ok(env)
}

/// Per-spec validation. Returns every violation rather than
/// first-error-wins.
///
/// Cross-kind FK (`federatedIdentities[].issuer` matches some
/// `OidcIssuer.name` in desired-state OR snapshot) is the apply use
/// case's responsibility — see
/// `ApplyConfigUseCase::validate_service_account_issuer_fk` (the
/// dedicated helper that lives next to `apply()`). Merging that
/// helper into the main `validate_against` signature is a planned
/// follow-on once the helper's snapshot+desired signature is widened.
pub fn validate_service_account(env: &Envelope<ServiceAccountSpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let name = env.metadata.name.clone();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::ServiceAccount,
            name: name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    // -- role ---------------------------------------------------------------
    if !ALLOWED_ROLES.contains(&env.spec.role.as_str()) {
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.role",
            got: env.spec.role.clone(),
            expected: ALLOWED_ROLES.to_vec(),
        });
    }

    // -- repositories -------------------------------------------------------
    if env.spec.repositories.is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::ServiceAccount,
            name: name.clone(),
            detail: "spec.repositories must contain at least one entry \
                     — no global service-account grants"
                .into(),
        });
    }
    for repo in &env.spec.repositories {
        if repo.trim().is_empty() {
            errors.push(ValidationError::Invalid {
                kind: Kind::ServiceAccount,
                name: name.clone(),
                detail: "spec.repositories[*] must not be blank".into(),
            });
        }
    }

    // -- federatedIdentities ------------------------------------------------
    for (idx, fi) in env.spec.federated_identities.iter().enumerate() {
        if fi.issuer.trim().is_empty() {
            errors.push(ValidationError::Invalid {
                kind: Kind::ServiceAccount,
                name: name.clone(),
                detail: format!("spec.federatedIdentities[{idx}].issuer must not be blank"),
            });
        }
        if fi.claims.is_empty() {
            // Load-bearing: an empty claim set means "any JWT from this
            // issuer can assume me," which is a privilege-escalation
            // footgun on a misconfigured issuer. Hard reject.
            errors.push(ValidationError::Invalid {
                kind: Kind::ServiceAccount,
                name: name.clone(),
                detail: format!(
                    "spec.federatedIdentities[{idx}].claims must contain at least one entry \
                     — empty claims means any JWT from this issuer can assume the SA \
                     (privilege-escalation footgun)"
                ),
            });
        }
        for (k, v) in &fi.claims {
            if k.trim().is_empty() {
                errors.push(ValidationError::Invalid {
                    kind: Kind::ServiceAccount,
                    name: name.clone(),
                    detail: format!("spec.federatedIdentities[{idx}].claims has a blank key"),
                });
            }
            if v.trim().is_empty() {
                errors.push(ValidationError::Invalid {
                    kind: Kind::ServiceAccount,
                    name: name.clone(),
                    detail: format!(
                        "spec.federatedIdentities[{idx}].claims[`{k}`] value must not be blank"
                    ),
                });
            }
        }
    }

    // -- fallbackRotation ---------------------------------------------------
    if let Some(rotation) = env.spec.fallback_rotation.as_ref() {
        validate_target_secret(&rotation.target_secret, &name, &mut errors);
        validate_rotation_durations(rotation, &name, &mut errors);
    }

    errors
}

// ---------------------------------------------------------------------------
// Under-constrained federated-issuer warning
// ---------------------------------------------------------------------------

/// Claim keys that, on a GitHub/GitLab-Actions-shaped issuer, identify
/// only the *repository/project* — necessary but not sufficient to
/// scope a trust policy. A workflow in the named repo can mint a token
/// carrying these regardless of branch/environment, so an FI
/// constrained on these *alone* is assumable by any job in the repo.
const REPO_SCOPE_ONLY_CLAIMS: &[&str] = &["repository", "project_path"];

/// Claim keys that discriminate *which* workflow run / branch /
/// environment / relying party the token was minted for. At least one
/// (or an explicit `aud`) must accompany a repo-scope claim for the
/// trust policy to be meaningfully narrow.
const DISCRIMINATING_CLAIMS: &[&str] = &["ref", "environment", "workflow", "aud"];

/// One under-constrained `federatedIdentities[]` entry. The boot
/// caller (which owns `tracing`; `hort-config` deliberately has none —
/// see the crate-level dependency rule) logs each as a `warn!`. This
/// is a *warning*, never a hard `ValidationError`: a repo-only policy
/// is risky but not invalid, and an operator on a single-tenant repo
/// may legitimately accept the residual risk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnderConstrainedFederatedIdentity {
    /// The owning `ServiceAccount.metadata.name`.
    pub service_account: String,
    /// 0-based index into `spec.federatedIdentities`.
    pub index: usize,
    /// The `issuer` reference of the offending FI.
    pub issuer: String,
    /// Pre-rendered operator-facing message (no PII — only the SA name,
    /// index, and issuer reference, all operator-authored).
    pub message: String,
}

/// Detect under-constrained `federatedIdentities[]` entries.
/// Two distinct, mutually-exclusive warning classes:
///
/// 1. **Repo-scope without discriminator**: the FI names a
///    `repository`/`project_path` but pins no discriminating
///    `ref`/`environment`/`workflow`/`aud` — any *workflow in that
///    repo* can assume the identity. The canonical "named the repo,
///    forgot to pin the branch/env" mistake.
/// 2. **No scope-narrowing claim at all**: the FI's claim set
///    contains *neither* a repo-scope claim *nor* a discriminator —
///    e.g. a `sub`-only / issuer-only fragment. This is *more*
///    under-constrained than (1): any JWT from the issuer matching the
///    declared `sub` literal can assume the SA.
///
/// Pure — returns the findings; the caller emits the `warn!`. Does NOT
/// push `ValidationError`s, so apply still succeeds (an
/// under-constrained policy is a footgun, not a schema violation; an
/// operator on a single-tenant repo may legitimately accept the
/// residual risk — see `apply_config_use_case`'s call site). An empty
/// `claims` map never reaches here: it is hard-rejected upstream by the
/// non-empty-claims rule in [`validate_service_account`].
pub fn detect_under_constrained_federated_identities(
    env: &Envelope<ServiceAccountSpec>,
) -> Vec<UnderConstrainedFederatedIdentity> {
    let mut findings = Vec::new();
    for (idx, fi) in env.spec.federated_identities.iter().enumerate() {
        let has_repo_scope = fi
            .claims
            .keys()
            .any(|k| REPO_SCOPE_ONLY_CLAIMS.contains(&k.as_str()));
        let has_discriminator = fi
            .claims
            .keys()
            .any(|k| DISCRIMINATING_CLAIMS.contains(&k.as_str()));

        if !has_repo_scope {
            // Class 2: no scope-narrowing claim AT ALL — neither a
            // repo-scope claim nor a discriminator. A discriminator on
            // its own (e.g. `ref` without a `repository`) is still
            // some narrowing, so it is not this class. Only the truly
            // unscoped shape (`sub`-only / issuer-only) is flagged here.
            if !has_discriminator {
                findings.push(UnderConstrainedFederatedIdentity {
                    service_account: env.metadata.name.clone(),
                    index: idx,
                    issuer: fi.issuer.clone(),
                    message: format!(
                        "ServiceAccount `{}` federatedIdentities[{idx}] (issuer `{}`) declares \
                         no scope-narrowing claim (no repo/project + no \
                         ref/environment/workflow/aud) — any JWT from this issuer matching the \
                         declared sub can assume this identity. Add a scope-narrowing claim or \
                         pin `aud`.",
                        env.metadata.name, fi.issuer
                    ),
                });
            }
            continue;
        }

        // Class 1: has a repo-scope claim but no discriminator.
        if has_discriminator {
            continue;
        }
        findings.push(UnderConstrainedFederatedIdentity {
            service_account: env.metadata.name.clone(),
            index: idx,
            issuer: fi.issuer.clone(),
            message: format!(
                "ServiceAccount `{}` federatedIdentities[{idx}] (issuer `{}`) constrains only \
                 a repository/project claim without a discriminating ref/environment/workflow/aud \
                 — any workflow in that repo can assume this identity. Add a discriminating \
                 claim (e.g. `ref`, `environment`, `workflow`) or pin `aud`.",
                env.metadata.name, fi.issuer
            ),
        });
    }
    findings
}

/// Validate the target-Secret coordinates: non-blank name + namespace,
/// k8s name regex, format ∈ closed set.
fn validate_target_secret(
    secret: &TargetSecretSpec,
    sa_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    if secret.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::ServiceAccount,
            name: sa_name.to_string(),
            detail: "spec.fallbackRotation.targetSecret.name must not be blank".into(),
        });
    } else if !is_valid_k8s_name(&secret.name) {
        errors.push(ValidationError::Invalid {
            kind: Kind::ServiceAccount,
            name: sa_name.to_string(),
            detail: format!(
                "spec.fallbackRotation.targetSecret.name `{}` is not a valid k8s name \
                 (lowercase alphanumeric + `-`, ≤{MAX_K8S_NAME_LEN} chars, no leading/trailing `-`)",
                secret.name
            ),
        });
    }

    if secret.namespace.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::ServiceAccount,
            name: sa_name.to_string(),
            detail: "spec.fallbackRotation.targetSecret.namespace must not be blank".into(),
        });
    } else if !is_valid_k8s_name(&secret.namespace) {
        errors.push(ValidationError::Invalid {
            kind: Kind::ServiceAccount,
            name: sa_name.to_string(),
            detail: format!(
                "spec.fallbackRotation.targetSecret.namespace `{}` is not a valid k8s namespace \
                 (lowercase alphanumeric + `-`, ≤{MAX_K8S_NAME_LEN} chars)",
                secret.namespace
            ),
        });
    }

    if !ALLOWED_SECRET_FORMATS.contains(&secret.format.as_str()) {
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.fallbackRotation.targetSecret.format",
            got: secret.format.clone(),
            expected: ALLOWED_SECRET_FORMATS.to_vec(),
        });
    }
}

/// Validate the rotation/validity humantime durations + the
/// `validity ≥ 2 × rotationInterval` safety-margin invariant.
fn validate_rotation_durations(
    rotation: &FallbackRotationSpec,
    sa_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    let rotation_duration = match humantime::parse_duration(&rotation.rotation_interval) {
        Ok(d) => Some(d),
        Err(err) => {
            errors.push(ValidationError::Invalid {
                kind: Kind::ServiceAccount,
                name: sa_name.to_string(),
                detail: format!(
                    "spec.fallbackRotation.rotationInterval `{}` is not a valid humantime duration: {err}",
                    rotation.rotation_interval
                ),
            });
            None
        }
    };
    let validity_duration = match humantime::parse_duration(&rotation.validity) {
        Ok(d) => Some(d),
        Err(err) => {
            errors.push(ValidationError::Invalid {
                kind: Kind::ServiceAccount,
                name: sa_name.to_string(),
                detail: format!(
                    "spec.fallbackRotation.validity `{}` is not a valid humantime duration: {err}",
                    rotation.validity
                ),
            });
            None
        }
    };

    if let Some(d) = rotation_duration {
        if d < MIN_ROTATION_INTERVAL {
            errors.push(ValidationError::Invalid {
                kind: Kind::ServiceAccount,
                name: sa_name.to_string(),
                detail: format!(
                    "spec.fallbackRotation.rotationInterval `{}` is below the minimum of 1h \
                     — shorter intervals risk rotation-storm against the issuer",
                    rotation.rotation_interval
                ),
            });
        }
    }

    if let (Some(r), Some(v)) = (rotation_duration, validity_duration) {
        if v < r.saturating_mul(2) {
            errors.push(ValidationError::Invalid {
                kind: Kind::ServiceAccount,
                name: sa_name.to_string(),
                detail: format!(
                    "spec.fallbackRotation.validity `{}` must be at least 2× rotationInterval `{}` \
                     — consumer-side Secret reload needs at least one full rotation cycle of overlap",
                    rotation.validity, rotation.rotation_interval
                ),
            });
        }
    }
}

/// Lightweight RFC 1123 DNS label / subdomain check. Accepts
/// lowercase alphanumerics and `-`, refuses leading/trailing `-`,
/// length ≤ [`MAX_K8S_NAME_LEN`]. Does not handle the full subdomain
/// (`.`-separated) shape — operators using a multi-segment namespace
/// is out of scope for v1 (k8s namespaces are single segments anyway).
fn is_valid_k8s_name(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_K8S_NAME_LEN {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
            "apiVersion: project-hort.de/v1beta1\nkind: ServiceAccount\nmetadata:\n  name: {name}\nspec:{body}"
        )
    }

    // -- Happy paths --------------------------------------------------------

    #[test]
    fn parse_minimal_pat_only_round_trip() {
        // Neither federation nor rotation declared — valid (operator
        // mints PATs via hort-cli admin token issue).
        let body = "
  role: developer
  repositories: [pypi-internal]
";
        let env = parse_service_account(&p(), yaml("pat-only", body).as_bytes()).unwrap();
        assert_eq!(env.spec.role, "developer");
        assert_eq!(env.spec.repositories, vec!["pypi-internal"]);
        assert!(env.spec.federated_identities.is_empty());
        assert!(env.spec.fallback_rotation.is_none());
        assert!(validate_service_account(&env).is_empty());
    }

    #[test]
    fn parse_federation_only_round_trip() {
        let body = "
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
        environment: production
";
        let env = parse_service_account(&p(), yaml("ci-pypi-pusher", body).as_bytes()).unwrap();
        assert_eq!(env.spec.federated_identities.len(), 1);
        assert_eq!(env.spec.federated_identities[0].claims.len(), 2);
        assert!(env.spec.fallback_rotation.is_none());
        assert!(validate_service_account(&env).is_empty());
    }

    #[test]
    fn parse_full_round_trip() {
        let body = "
  role: developer
  repositories: [pypi-internal, npm-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
  fallbackRotation:
    targetSecret:
      name: ci-hort-token
      namespace: ci-system
      format: dockerconfigjson
    rotationInterval: 6h
    validity: 24h
";
        let env = parse_service_account(&p(), yaml("ci-full", body).as_bytes()).unwrap();
        assert_eq!(env.spec.role, "developer");
        let rot = env.spec.fallback_rotation.as_ref().unwrap();
        assert_eq!(rot.target_secret.format, "dockerconfigjson");
        assert_eq!(rot.rotation_interval, "6h");
        assert_eq!(rot.validity, "24h");
        assert!(validate_service_account(&env).is_empty());
    }

    #[test]
    fn parse_fallback_rotation_defaults_when_omitted() {
        // `rotationInterval` and `validity` carry serde defaults; only
        // `targetSecret` is required.
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: my-secret
      namespace: my-ns
      format: opaque
";
        let env = parse_service_account(&p(), yaml("defaults", body).as_bytes()).unwrap();
        let rot = env.spec.fallback_rotation.as_ref().unwrap();
        assert_eq!(rot.rotation_interval, "6h");
        assert_eq!(rot.validity, "24h");
        assert!(validate_service_account(&env).is_empty());
    }

    // -- Parse rejects ------------------------------------------------------

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  role: developer
  repositories: [r]
  bogus: 1
";
        let err = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn parse_rejects_missing_role() {
        let body = "
  repositories: [r]
";
        let err = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_missing_repositories() {
        let body = "
  role: developer
";
        let err = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let body = "
  role: developer
  repositories: [r]
";
        let yaml_doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: ServiceAccount\nmetadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_service_account(&p(), yaml_doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }

    // -- Validate rejects ---------------------------------------------------

    #[test]
    fn validate_rejects_admin_role() {
        // Admin is reserved for short-lived interactive sessions.
        let body = "
  role: admin
  repositories: [r]
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.role" && got == "admin"
        )));
    }

    #[test]
    fn validate_rejects_unknown_role() {
        let body = "
  role: superuser
  repositories: [r]
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, .. } if *field == "spec.role"
        )));
    }

    #[test]
    fn validate_accepts_developer_and_reader() {
        for role in ["developer", "reader"] {
            let body = format!(
                "
  role: {role}
  repositories: [r]
"
            );
            let env = parse_service_account(&p(), yaml("x", &body).as_bytes()).unwrap();
            assert!(validate_service_account(&env).is_empty());
        }
    }

    #[test]
    fn validate_rejects_empty_repositories() {
        let body = "
  role: developer
  repositories: []
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("repositories")));
    }

    #[test]
    fn validate_rejects_blank_repository_entry() {
        let body = "
  role: developer
  repositories: ['   ']
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("repositories[*]")));
    }

    #[test]
    fn validate_rejects_blank_issuer_reference() {
        let body = "
  role: developer
  repositories: [r]
  federatedIdentities:
    - issuer: ''
      claims:
        repository: my-org/my-repo
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("issuer")));
    }

    #[test]
    fn validate_rejects_empty_claims_map() {
        // Load-bearing anti-footgun rule: empty claims = "any JWT from
        // this issuer can assume me." Must be a hard reject.
        let body = "
  role: developer
  repositories: [r]
  federatedIdentities:
    - issuer: github-actions
      claims: {}
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("privilege-escalation")),
            "expected empty-claims rejection mentioning privilege-escalation, got: {errs:?}"
        );
    }

    // -- Under-constrained-issuer warning --

    #[test]
    fn under_constrained_warning_fires_on_repo_only_fi() {
        // Repository-only fragment, no ref/environment/workflow/aud —
        // any workflow in my-org/my-repo can assume this identity.
        let body = "
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
";
        let env = parse_service_account(&p(), yaml("ci-loose", body).as_bytes()).unwrap();
        // It must still VALIDATE (warning, not error).
        assert!(
            validate_service_account(&env).is_empty(),
            "a repo-only FI is a footgun, not a schema violation"
        );
        let findings = detect_under_constrained_federated_identities(&env);
        assert_eq!(findings.len(), 1, "expected one under-constrained finding");
        assert_eq!(findings[0].index, 0);
        assert_eq!(findings[0].issuer, "github-actions");
        assert_eq!(findings[0].service_account, "ci-loose");
        assert!(
            findings[0].message.contains("discriminating"),
            "message must explain the discriminating-claim risk, got: {:?}",
            findings[0].message
        );
    }

    #[test]
    fn under_constrained_warning_silent_when_environment_pins_it() {
        // repository + environment ⇒ discriminating ⇒ no finding.
        let body = "
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
        environment: production
";
        let env = parse_service_account(&p(), yaml("ci-tight", body).as_bytes()).unwrap();
        assert!(detect_under_constrained_federated_identities(&env).is_empty());
    }

    #[test]
    fn under_constrained_warning_silent_when_aud_pins_it() {
        // repository + aud ⇒ a discriminating claim ⇒ silent.
        let body = "
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: gitlab-ci
      claims:
        project_path: my-group/my-project
        aud: hort-server
";
        let env = parse_service_account(&p(), yaml("ci-aud", body).as_bytes()).unwrap();
        assert!(detect_under_constrained_federated_identities(&env).is_empty());
    }

    // -- sub-only / issuer-only warning (second, distinct warning class) --

    #[test]
    fn under_constrained_warning_fires_on_sub_only_fi() {
        // (test a) An FI with only a `sub` claim has NO scope-narrowing
        // claim at all (neither a REPO_SCOPE_ONLY_CLAIMS nor a
        // DISCRIMINATING_CLAIMS member) — any JWT from this issuer
        // matching the declared `sub` literal can assume the SA. This
        // is MORE under-constrained than the repo-with-no-discriminator
        // case; it must emit the "no scope-narrowing claim" warning class.
        let body = "
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        sub: some-stable-subject
";
        let env = parse_service_account(&p(), yaml("ci-sub", body).as_bytes()).unwrap();
        // Still VALIDATES (warning, not error) — warn-not-reject preserved.
        assert!(
            validate_service_account(&env).is_empty(),
            "a sub-only FI is a footgun, not a schema violation"
        );
        let findings = detect_under_constrained_federated_identities(&env);
        assert_eq!(findings.len(), 1, "expected one under-constrained finding");
        assert_eq!(findings[0].index, 0);
        assert_eq!(findings[0].issuer, "github-actions");
        assert_eq!(findings[0].service_account, "ci-sub");
        assert!(
            findings[0].message.contains("no scope-narrowing claim"),
            "message must describe the sub-only no-scope-narrowing risk, got: {:?}",
            findings[0].message
        );
    }

    #[test]
    fn under_constrained_repo_only_class_fires_its_original_warning() {
        // (test b) The EXISTING class — a repo-scope claim with no
        // discriminator — must STILL fire its original warning (no
        // regression). The class-1 message is the "constrains only a
        // repository/project claim" shape, distinct from the sub-only
        // class-2 "no scope-narrowing claim" message.
        let body = "
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
";
        let env = parse_service_account(&p(), yaml("ci-repo-only", body).as_bytes()).unwrap();
        let findings = detect_under_constrained_federated_identities(&env);
        assert_eq!(
            findings.len(),
            1,
            "the existing repo-only class must still fire"
        );
        assert!(
            findings[0].message.contains("discriminating")
                && !findings[0].message.contains("no scope-narrowing claim"),
            "must be the EXISTING repo-only-without-discriminator message, got: {:?}",
            findings[0].message
        );
    }

    #[test]
    fn under_constrained_silent_on_well_formed_repo_plus_discriminator() {
        // (test c) repository + ref ⇒ a repo-scope claim AND a
        // discriminating claim ⇒ well-formed ⇒ NO warning of either class.
        let body = "
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
        ref: main
";
        let env = parse_service_account(&p(), yaml("ci-well-formed", body).as_bytes()).unwrap();
        assert!(
            detect_under_constrained_federated_identities(&env).is_empty(),
            "a repo-scope + discriminator FI is well-formed; no warning expected"
        );
    }

    #[test]
    fn empty_claims_rejected_upstream_never_reaches_detector() {
        // (test d) An FI with `claims = {}` is rejected UPSTREAM by the
        // non-empty-claims rule in `validate_service_account` (the
        // `fi.claims.is_empty()` arm — the rule the domain entity's
        // docstring names `validate_federated_identity_claims_non_empty`).
        // Apply rejects on those ValidationErrors before
        // `detect_under_constrained_federated_identities` is ever
        // consulted, so the detector never has to reason about an empty
        // claim map. We assert BOTH facts: the upstream hard reject, and
        // that the detector itself produces no finding for the empty
        // shape (it has neither a repo-scope nor a discriminator member,
        // but the upstream reject is the load-bearing control).
        let body = "
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims: {}
";
        let env = parse_service_account(&p(), yaml("ci-empty", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("privilege-escalation")),
            "empty claims must be a hard upstream reject, got: {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_blank_claim_value() {
        let body = "
  role: developer
  repositories: [r]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: '   '
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("claims")));
    }

    // -- fallbackRotation validation ----------------------------------------

    #[test]
    fn validate_rejects_blank_target_secret_name() {
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: ''
      namespace: ci-system
      format: opaque
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("targetSecret.name")));
    }

    #[test]
    fn validate_rejects_blank_target_secret_namespace() {
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: ci-token
      namespace: ''
      format: opaque
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("targetSecret.namespace")));
    }

    #[test]
    fn validate_rejects_invalid_k8s_secret_name() {
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: 'Has_Underscores'
      namespace: ci-system
      format: opaque
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("not a valid k8s name")));
    }

    #[test]
    fn validate_rejects_overly_long_k8s_name() {
        let long_name = "a".repeat(MAX_K8S_NAME_LEN + 1);
        let body = format!(
            "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: '{long_name}'
      namespace: ci-system
      format: opaque
"
        );
        let env = parse_service_account(&p(), yaml("x", &body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("not a valid k8s name")));
    }

    #[test]
    fn validate_rejects_unknown_secret_format() {
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: ci-token
      namespace: ci-system
      format: yaml
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.fallbackRotation.targetSecret.format" && got == "yaml"
        )));
    }

    #[test]
    fn validate_accepts_both_secret_formats() {
        for fmt in ["dockerconfigjson", "opaque"] {
            let body = format!(
                "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: ci-token
      namespace: ci-system
      format: {fmt}
"
            );
            let env = parse_service_account(&p(), yaml("x", &body).as_bytes()).unwrap();
            assert!(validate_service_account(&env).is_empty());
        }
    }

    #[test]
    fn validate_rejects_short_rotation_interval() {
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: ci-token
      namespace: ci-system
      format: opaque
    rotationInterval: 30m
    validity: 24h
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("below the minimum")));
    }

    #[test]
    fn validate_rejects_unparseable_durations() {
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: ci-token
      namespace: ci-system
      format: opaque
    rotationInterval: not-a-duration
    validity: also-bad
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("rotationInterval")));
        assert!(errs.iter().any(|e| e.to_string().contains("validity")));
    }

    #[test]
    fn validate_rejects_validity_below_twice_rotation_interval() {
        // The validity must be at least 2× the rotation interval —
        // load-bearing safety margin for consumer-side Secret reload.
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: ci-token
      namespace: ci-system
      format: opaque
    rotationInterval: 6h
    validity: 8h
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("at least 2× rotationInterval")),
            "expected 2x rule rejection, got: {errs:?}"
        );
    }

    #[test]
    fn validate_accepts_validity_exactly_twice_rotation_interval() {
        let body = "
  role: developer
  repositories: [r]
  fallbackRotation:
    targetSecret:
      name: ci-token
      namespace: ci-system
      format: opaque
    rotationInterval: 6h
    validity: 12h
";
        let env = parse_service_account(&p(), yaml("x", body).as_bytes()).unwrap();
        let errs = validate_service_account(&env);
        assert!(
            errs.is_empty(),
            "validity exactly 2× rotation must pass: {errs:?}"
        );
    }

    #[test]
    fn validate_rejects_blank_metadata_name() {
        let env = Envelope {
            api_version: crate::envelope::ApiVersion::V1Beta1,
            kind: Kind::ServiceAccount,
            metadata: crate::envelope::Metadata { name: "   ".into() },
            spec: ServiceAccountSpec {
                role: "developer".into(),
                repositories: vec!["r".into()],
                federated_identities: vec![],
                fallback_rotation: None,
            },
        };
        let errs = validate_service_account(&env);
        assert!(errs.iter().any(|e| e.to_string().contains("blank")));
    }

    // -- is_valid_k8s_name helper ------------------------------------------

    #[test]
    fn k8s_name_helper_accepts_canonical_shapes() {
        assert!(is_valid_k8s_name("a"));
        assert!(is_valid_k8s_name("my-ns"));
        assert!(is_valid_k8s_name("ci-system"));
        assert!(is_valid_k8s_name("foo-bar-baz-2"));
    }

    #[test]
    fn k8s_name_helper_rejects_invalid_shapes() {
        assert!(!is_valid_k8s_name(""));
        assert!(!is_valid_k8s_name("-leading"));
        assert!(!is_valid_k8s_name("trailing-"));
        assert!(!is_valid_k8s_name("Has-Upper"));
        assert!(!is_valid_k8s_name("under_score"));
        assert!(!is_valid_k8s_name("dot.notation"));
        assert!(!is_valid_k8s_name(&"a".repeat(MAX_K8S_NAME_LEN + 1)));
    }
}
