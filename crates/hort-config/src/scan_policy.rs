//! `kind: ScanPolicy` schema, parser, and per-spec validation.
//!
//! Event-sourced kind: the apply pipeline diffs the desired YAML
//! against the current `ScanPolicyProjection` and emits
//! `PolicyCreated` / `PolicyUpdated` / `PolicyArchived` domain events.
//! This module supplies only the schema + per-envelope validation;
//! the `ApplyEventSourcedKind` trait that owns the diff-and-emit
//! machinery lives in a separate crate.
//!
//! See `docs/architecture/how-to/declare-gitops-config.md` for the
//! canonical YAML.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use hort_domain::entities::scan_policy::{
    ProvenanceMode, SeverityThreshold, SignerIdentityPattern,
};
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ValidationError};
use crate::scope::ScopeSpec;

/// Shape of a `kind: ScanPolicy` YAML body.
///
/// `severityThreshold` and the duration fields are validated through
/// their domain-layer / `humantime` parsers in `validate_scan_policy`
/// — keeping the wire shape as `String` lets a malformed value
/// surface as a typed validation error referencing the field path,
/// rather than as a generic serde "unknown variant" message that
/// would lose the field context.
///
/// `licensePolicy` is passed through as opaque JSON. Validation of its
/// internal shape is deferred to the policy evaluator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanPolicySpec {
    /// `global` or `{ repository: <metadata.name> }`. See [`ScopeSpec`].
    pub scope: ScopeSpec,
    /// `critical | high | medium | low`. Validated via
    /// `SeverityThreshold::FromStr`.
    pub severity_threshold: String,
    /// Humantime duration string (e.g. `"24h"`, `"7d"`). Validated
    /// via `humantime::parse_duration`.
    pub quarantine_duration: String,
    pub require_approval: bool,
    /// Per-policy supply-chain provenance enforcement mode
    /// (`off | verify_if_present | required`). Validated via
    /// [`ProvenanceMode::FromStr`] in [`validate_scan_policy`]. Defaults
    /// to `verify_if_present` when omitted — the fail-safe default that
    /// never gates release.
    #[serde(default = "default_provenance_mode")]
    pub provenance_mode: String,
    /// The provenance verifier backends to run (mirrors `scanBackends`).
    /// Each entry must match a `ProvenancePort` registered in the worker
    /// (e.g. `"cosign"`). Defaults to `["cosign"]`; an empty list is
    /// permitted only when `provenanceMode: off` (enforced by the
    /// apply-time linter via the domain `validate_provenance_config`
    /// hook).
    #[serde(default = "default_provenance_backends")]
    pub provenance_backends: Vec<String>,
    /// The allowed-signer `{issuer, san}` patterns a verified signature
    /// must match one of. Defaults to empty; under
    /// `provenanceMode: required` an empty list is an apply-time reject
    /// (any-signer footgun), under `verify_if_present` an apply-time
    /// warn (tampering-only detection).
    #[serde(default)]
    pub provenance_identities: Vec<SignerIdentitySpec>,
    /// Optional humantime duration. `None` when omitted from the
    /// YAML — the evaluator treats this as "no age cap".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_artifact_age: Option<String>,
    /// Operator-supplied JSON object describing license rules. Passed
    /// through to the evaluator without inspection — the schema is
    /// owned by the policy evaluator, not by this layer. Optional;
    /// when omitted, defaults to `Value::Null`, which the evaluator's
    /// `has_license_policy` short-circuits as "no policy declared". The
    /// asymmetry with `max_artifact_age` was a wire-schema bug — both
    /// fields are functionally opt-in and should be omittable.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub license_policy: serde_json::Value,
    /// Names of the scanner backends invoked per scan. Each entry must
    /// match a backend registered in `scanner_registry` (validated at
    /// gitops apply time against the live worker registry; see
    /// [`validate_scan_policy_backends`] in `crate::desired`). An empty
    /// `Vec` means "no scanning"; an absent field defaults to
    /// `vec!["trivy"]`.
    #[serde(default = "default_scan_backends")]
    pub scan_backends: Vec<String>,
    /// Interval in hours between bulk re-scans of artifacts governed
    /// by this policy. Default 24h. The value `0` is **explicitly
    /// meaningful** — it disables rescanning for every artifact
    /// governed by this policy. Negative values are rejected by
    /// `validate_scan_policy`.
    #[serde(default = "default_rescan_interval_hours")]
    pub rescan_interval_hours: i32,
}

/// Out-of-the-box `scanBackends` default when the YAML omits the
/// field. Matches
/// [`hort_domain::policy::scan::DefaultPolicy::block_on_critical_default_backends`]
/// — Trivy is the always-on baseline backend.
fn default_scan_backends() -> Vec<String> {
    vec!["trivy".to_string()]
}

/// The YAML wire shape of one allowed-signer pattern.
///
/// Maps 1:1 onto the domain [`SignerIdentitySpec`] →
/// [`hort_domain::entities::scan_policy::SignerIdentityPattern`] (the
/// per-element constructor validator runs in
/// [`validate_scan_policy`]). `deny_unknown_fields` so a typo'd key
/// (`subject:` for `san:`) surfaces as a parse error rather than a
/// silently-dropped pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignerIdentitySpec {
    /// OIDC issuer URL pattern the Fulcio cert was minted against.
    pub issuer: String,
    /// Certificate Subject Alternative Name pattern (the workload
    /// identity).
    pub san: String,
}

/// Out-of-the-box `provenanceMode` default when the YAML omits the
/// field: `verify_if_present`, the fail-safe default that verifies a
/// present bundle but never gates release. Mirrors
/// [`ProvenanceMode::default`].
fn default_provenance_mode() -> String {
    ProvenanceMode::default().to_string()
}

/// Out-of-the-box `provenanceBackends` default when the YAML omits the
/// field: `["cosign"]`, the deployed Tier-1 verifier set.
fn default_provenance_backends() -> Vec<String> {
    vec!["cosign".to_string()]
}

/// Out-of-the-box `rescanIntervalHours` default when the YAML omits
/// the field. Matches
/// [`hort_domain::policy::scan::DefaultPolicy::rescan_interval_hours`]
/// — 24 hours.
fn default_rescan_interval_hours() -> i32 {
    hort_domain::policy::scan::DefaultPolicy::rescan_interval_hours()
}

/// Parse one `ScanPolicy` envelope.
pub fn parse_scan_policy(
    _path: &Path,
    bytes: &[u8],
) -> Result<Envelope<ScanPolicySpec>, ParseError> {
    let env: Envelope<ScanPolicySpec> = serde_yaml_ng::from_slice(bytes)?;
    if env.kind != Kind::ScanPolicy {
        return Err(ParseError::UnknownKind {
            got: env.kind.to_string(),
            valid: &["ScanPolicy"],
        });
    }
    if env.metadata.name.is_empty() {
        return Err(ParseError::EmptyMetadataName);
    }
    Ok(env)
}

/// Per-spec validation:
/// - `severityThreshold` parses via `SeverityThreshold::FromStr`
/// - `quarantineDuration` and `maxArtifactAge` (when present) parse
///   via `humantime::parse_duration`
///
/// Cross-spec rules (scope.repository resolves to a declared repo,
/// duplicate names) live in `crate::desired`.
pub fn validate_scan_policy(env: &Envelope<ScanPolicySpec>) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if env.metadata.name.trim().is_empty() {
        errors.push(ValidationError::Invalid {
            kind: Kind::ScanPolicy,
            name: env.metadata.name.clone(),
            detail: "metadata.name must not be blank".into(),
        });
    }

    if SeverityThreshold::from_str(&env.spec.severity_threshold).is_err() {
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.severityThreshold",
            got: env.spec.severity_threshold.clone(),
            expected: vec!["critical", "high", "medium", "low"],
        });
    }

    if let Err(err) = parse_humantime(&env.spec.quarantine_duration) {
        errors.push(ValidationError::Invalid {
            kind: Kind::ScanPolicy,
            name: env.metadata.name.clone(),
            detail: format!(
                "spec.quarantineDuration `{}` is not a valid humantime duration: {err}",
                env.spec.quarantine_duration
            ),
        });
    }

    if let Some(age) = env.spec.max_artifact_age.as_ref() {
        if let Err(err) = parse_humantime(age) {
            errors.push(ValidationError::Invalid {
                kind: Kind::ScanPolicy,
                name: env.metadata.name.clone(),
                detail: format!(
                    "spec.maxArtifactAge `{age}` is not a valid humantime duration: {err}"
                ),
            });
        }
    }

    // `rescanIntervalHours` must be >= 0. The value `0` is the operator
    // opt-out (disables rescanning); negative values are nonsense and
    // would never produce eligibility under the cron-rescan handler's
    // `now() - last_scan_at > rescan_interval_hours * 1h` filter.
    // Reject loud rather than silently behaving as "disabled".
    if env.spec.rescan_interval_hours < 0 {
        errors.push(ValidationError::Invalid {
            kind: Kind::ScanPolicy,
            name: env.metadata.name.clone(),
            detail: format!(
                "spec.rescanIntervalHours `{}` must be >= 0 (use 0 to disable rescanning)",
                env.spec.rescan_interval_hours
            ),
        });
    }

    // `provenanceMode` parses via the domain enum. The
    // mode↔backends/identity *combination* rules (Required+empty-identities
    // reject, mode!=Off+empty-backends reject, VerifyIfPresent+empty-
    // identities warn) are the domain `validate_provenance_config` hook's
    // job, wired into apply; here we only validate the wire shape of
    // each field in isolation.
    if ProvenanceMode::from_str(&env.spec.provenance_mode).is_err() {
        errors.push(ValidationError::UnknownEnumValue {
            field: "spec.provenanceMode",
            got: env.spec.provenance_mode.clone(),
            expected: vec!["off", "verify_if_present", "required"],
        });
    }

    // Each declared signer pattern runs the domain per-element
    // constructor validator: non-empty issuer + san, bounded length,
    // no control characters. A malformed pattern is a typed error
    // naming the offending index.
    for (idx, ident) in env.spec.provenance_identities.iter().enumerate() {
        if let Err(err) = SignerIdentityPattern::new(ident.issuer.clone(), ident.san.clone()) {
            errors.push(ValidationError::Invalid {
                kind: Kind::ScanPolicy,
                name: env.metadata.name.clone(),
                detail: format!("spec.provenanceIdentities[{idx}] is invalid: {err}"),
            });
        }
    }

    errors
}

/// Wrap `humantime::parse_duration` in a small helper so the call site
/// reads cleanly. Returns the parsed `Duration`; the duration value
/// itself is unused at parse time (the apply pipeline re-parses when
/// it needs to snapshot the value into the event). The sole purpose
/// here is round-trip validation that the operator-supplied string
/// is well-formed before any DB write.
fn parse_humantime(s: &str) -> Result<Duration, humantime::DurationError> {
    humantime::parse_duration(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::RepositoryScope;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    fn yaml(name: &str, body: &str) -> String {
        format!(
            "apiVersion: project-hort.de/v1beta1\nkind: ScanPolicy\nmetadata:\n  name: {name}\nspec:{body}"
        )
    }

    #[test]
    fn parse_full_policy_round_trip_global_scope() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  provenanceMode: required
  provenanceBackends: [cosign]
  provenanceIdentities:
    - issuer: https://token.actions.githubusercontent.com
      san: https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
  maxArtifactAge: 90d
  licensePolicy:
    allowed: [Apache-2.0, MIT]
    denied: [GPL-3.0]
";
        let env = parse_scan_policy(&p(), yaml("prod-default", body).as_bytes()).unwrap();
        assert_eq!(env.spec.scope, ScopeSpec::Global);
        assert_eq!(env.spec.severity_threshold, "high");
        assert_eq!(env.spec.quarantine_duration, "24h");
        assert!(env.spec.require_approval);
        assert_eq!(env.spec.provenance_mode, "required");
        assert_eq!(env.spec.provenance_backends, vec!["cosign"]);
        assert_eq!(env.spec.provenance_identities.len(), 1);
        assert_eq!(
            env.spec.provenance_identities[0].issuer,
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(env.spec.max_artifact_age.as_deref(), Some("90d"));
        // licensePolicy is a JSON object passed through as-is.
        assert!(env.spec.license_policy.is_object());
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn parse_round_trip_repository_scope() {
        let body = "
  scope:
    repository: npm-public
  severityThreshold: critical
  quarantineDuration: 1h
  requireApproval: false
  provenanceMode: off
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("npm-strict", body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.scope,
            ScopeSpec::Repository(RepositoryScope {
                repository: "npm-public".into()
            })
        );
        assert_eq!(env.spec.provenance_mode, "off");
        assert_eq!(env.spec.provenance_backends, vec!["cosign"]);
        assert!(env.spec.provenance_identities.is_empty());
        assert!(env.spec.max_artifact_age.is_none());
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn validate_rejects_unknown_severity_threshold() {
        let body = "
  scope: global
  severityThreshold: nuclear
  quarantineDuration: 24h
  requireApproval: false
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap();
        let errors = validate_scan_policy(&env);
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.severityThreshold" && got == "nuclear"
        )));
    }

    #[test]
    fn validate_rejects_malformed_quarantine_duration() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: \"24garbage\"
  requireApproval: false
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap();
        let errors = validate_scan_policy(&env);
        assert!(errors.iter().any(|e| {
            e.to_string().contains("quarantineDuration") && e.to_string().contains("24garbage")
        }));
    }

    #[test]
    fn validate_rejects_malformed_max_artifact_age() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 1h
  requireApproval: false
  maxArtifactAge: forever
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap();
        let errors = validate_scan_policy(&env);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("maxArtifactAge")));
    }

    #[test]
    fn validate_skips_max_artifact_age_when_omitted() {
        let body = "
  scope: global
  severityThreshold: low
  quarantineDuration: 30m
  requireApproval: false
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap();
        assert!(validate_scan_policy(&env).is_empty());
    }

    // `scanBackends` round-trip + default behaviour.
    #[test]
    fn parse_round_trips_explicit_scan_backends_list() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  scanBackends: [trivy, osv]
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("with-backends", body).as_bytes()).unwrap();
        assert_eq!(env.spec.scan_backends, vec!["trivy", "osv"]);
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn parse_omitted_scan_backends_defaults_to_trivy() {
        // Out-of-the-box deployments must scan with Trivy. The default
        // matches `DefaultPolicy::block_on_critical_default_backends`.
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("default-backends", body).as_bytes()).unwrap();
        assert_eq!(env.spec.scan_backends, vec!["trivy".to_string()]);
    }

    // Provenance trio round-trip + defaults + validation.
    #[test]
    fn parse_omitted_provenance_mode_defaults_to_verify_if_present() {
        // The fail-safe default: verify if present, never gate release.
        // provenanceBackends defaults to ["cosign"].
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("default-prov", body).as_bytes()).unwrap();
        assert_eq!(env.spec.provenance_mode, "verify_if_present");
        assert_eq!(env.spec.provenance_backends, vec!["cosign".to_string()]);
        assert!(env.spec.provenance_identities.is_empty());
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn parse_round_trips_explicit_provenance_trio() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  provenanceMode: required
  provenanceBackends: [cosign]
  provenanceIdentities:
    - issuer: https://token.actions.githubusercontent.com
      san: https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("strict-prov", body).as_bytes()).unwrap();
        assert_eq!(env.spec.provenance_mode, "required");
        assert_eq!(env.spec.provenance_backends, vec!["cosign".to_string()]);
        assert_eq!(env.spec.provenance_identities.len(), 1);
        assert_eq!(
            env.spec.provenance_identities[0].san,
            "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
        );
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn parse_round_trips_provenance_mode_off_with_empty_backends() {
        // mode: off is the only state that legitimately carries empty
        // backends; the per-spec validator does not reject the shape
        // (the mode↔backends combination rule is enforced by the apply linter).
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  provenanceMode: off
  provenanceBackends: []
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("off-prov", body).as_bytes()).unwrap();
        assert_eq!(env.spec.provenance_mode, "off");
        assert!(env.spec.provenance_backends.is_empty());
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn validate_rejects_unknown_provenance_mode() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  provenanceMode: paranoid
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap();
        let errors = validate_scan_policy(&env);
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.provenanceMode" && got == "paranoid"
        )));
    }

    #[test]
    fn validate_rejects_empty_issuer_in_provenance_identity() {
        // The domain per-element constructor validator runs on each
        // declared signer pattern; an empty issuer is a typed error
        // naming the offending index.
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  provenanceMode: required
  provenanceIdentities:
    - issuer: \"\"
      san: some-san
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap();
        let errors = validate_scan_policy(&env);
        assert!(
            errors.iter().any(|e| {
                let s = e.to_string();
                s.contains("provenanceIdentities[0]") && s.contains("issuer")
            }),
            "empty issuer must surface a validation error naming the index: {errors:?}"
        );
    }

    #[test]
    fn parse_rejects_unknown_field_in_provenance_identity() {
        // SignerIdentitySpec denies unknown fields — a `subject:` typo
        // (for `san:`) is a parse error, not a silently-dropped pattern.
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  provenanceMode: required
  provenanceIdentities:
    - issuer: iss
      subject: oops
  licensePolicy: {}
";
        let err = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    // `rescanIntervalHours` round-trip + default + validation.
    #[test]
    fn parse_round_trips_explicit_rescan_interval_hours() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  rescanIntervalHours: 48
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("with-rescan", body).as_bytes()).unwrap();
        assert_eq!(env.spec.rescan_interval_hours, 48);
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn parse_omitted_rescan_interval_hours_defaults_to_24() {
        // Out-of-the-box deployments rescan every 24 hours. The
        // default matches `DefaultPolicy::rescan_interval_hours`.
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("default-rescan", body).as_bytes()).unwrap();
        assert_eq!(env.spec.rescan_interval_hours, 24);
    }

    #[test]
    fn validate_accepts_zero_rescan_interval_hours_as_disabled() {
        // `0` is the operator opt-out: rescanning disabled for this
        // policy entirely. Validation must not reject it.
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  rescanIntervalHours: 0
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("disabled-rescan", body).as_bytes()).unwrap();
        assert_eq!(env.spec.rescan_interval_hours, 0);
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn validate_rejects_negative_rescan_interval_hours() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  rescanIntervalHours: -1
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap();
        let errors = validate_scan_policy(&env);
        assert!(
            errors.iter().any(|e| {
                e.to_string().contains("rescanIntervalHours")
                    && e.to_string().contains("-1")
                    && e.to_string().contains(">= 0")
            }),
            "negative rescanIntervalHours must surface a Validation error \
             naming the offending value and the >= 0 rule, got: {errors:?}"
        );
    }

    #[test]
    fn parse_explicit_empty_scan_backends_means_no_scanning() {
        // Empty list is a valid "operator opt-out of scanning"
        // declaration. Per-spec validation does not reject an empty
        // list; the apply-time cross-spec check just has no entries to
        // verify against the registry.
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: false
  scanBackends: []
  licensePolicy: {}
";
        let env = parse_scan_policy(&p(), yaml("no-scan", body).as_bytes()).unwrap();
        assert!(env.spec.scan_backends.is_empty());
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn parse_accepts_omitted_license_policy_defaulting_to_null() {
        // Symmetric with `validate_skips_max_artifact_age_when_omitted`:
        // both fields are functionally opt-in and must parse cleanly
        // when omitted. The evaluator's `has_license_policy`
        // short-circuits `Value::Null` as "no policy declared".
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 1h
  requireApproval: false
";
        let env = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap();
        assert_eq!(env.spec.license_policy, serde_json::Value::Null);
        assert!(validate_scan_policy(&env).is_empty());
    }

    #[test]
    fn validate_accepts_complex_humantime_strings() {
        // Cover the more interesting humantime spellings — `1h 30m`
        // and `2weeks` are both supported and operators do reach for
        // them (cf. Kubernetes-style policy objects).
        for s in ["1h", "1h 30m", "7d", "2weeks", "30s"] {
            let body = format!(
                "
  scope: global
  severityThreshold: high
  quarantineDuration: \"{s}\"
  requireApproval: false
  licensePolicy: {{}}
"
            );
            let env = parse_scan_policy(&p(), yaml("p", &body).as_bytes()).unwrap();
            assert!(
                validate_scan_policy(&env).is_empty(),
                "humantime `{s}` must validate cleanly"
            );
        }
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 1h
  requireApproval: false
  licensePolicy: {}
  bogus: 1
";
        let err = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn parse_rejects_missing_severity_threshold() {
        let body = "
  scope: global
  quarantineDuration: 1h
  requireApproval: false
  licensePolicy: {}
";
        let err = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_invalid_scope_string() {
        let body = "
  scope: cluster
  severityThreshold: high
  quarantineDuration: 1h
  requireApproval: false
  licensePolicy: {}
";
        let err = parse_scan_policy(&p(), yaml("p", body).as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Yaml(_)));
    }

    #[test]
    fn parse_rejects_empty_metadata_name() {
        let body = "
  scope: global
  severityThreshold: high
  quarantineDuration: 1h
  requireApproval: false
  licensePolicy: {}
";
        let yaml_doc = format!(
            "apiVersion: project-hort.de/v1beta1\nkind: ScanPolicy\nmetadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_scan_policy(&p(), yaml_doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }
}
