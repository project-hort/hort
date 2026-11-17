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
//! [`RetentionScopeSpec`]. The apply pipeline is
//! the only way to configure retention policies in v1 (every policy
//! aggregate is gitops-authored — there is no imperative HTTP API,
//! exactly like `ScanPolicy`).
//!
//! The one place this envelope's `scope` deliberately diverges from the
//! domain enum is [`RetentionScopeSpec::Repos`], which carries
//! repository **`metadata.name`s** — the domain's
//! `RetentionScope::Repos(Vec<Uuid>)` is the *resolved* form. That is
//! the same operator-names / domain-ids split `ScanPolicy` uses
//! (`ScopeSpec` → `PolicyScope`): the cross-spec validator in
//! [`crate::desired`] requires every named repository to be declared in
//! the same desired state, and the apply pipeline resolves each name to
//! its id exactly once, before any event is emitted. A repository UUID
//! is never a valid value here.
//!
//! The apply-time `IngestSource(Direct)` warning lands in
//! `ApplyConfigUseCase`, NOT here — this layer is pure schema.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::DomainResult;
use hort_domain::events::IngestSource;
use hort_domain::retention::{HeldState, PolicyPredicate, RetentionScope, MAX_REPOS_IN_SCOPE};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// As [`predicate_from_value`] for [`RetentionScopeSpec`]. `pub` so
/// the `hort-app` apply pipeline (`apply_retention_policies`) can
/// resolve the machine-envelope `Value` into the operator-surface enum,
/// and from there into the domain
/// [`RetentionScope`](hort_domain::retention::RetentionScope).
pub fn scope_from_value(v: &serde_json::Value) -> Result<RetentionScopeSpec, serde_json::Error> {
    serde_json::from_value(v.clone())
}

/// Operator-surface form of
/// [`RetentionScope`](hort_domain::retention::RetentionScope).
///
/// Variant-for-variant identical to the domain enum — same names, same
/// JSON shape — except [`Self::Repos`], which carries repository
/// `metadata.name`s where the domain carries `Uuid`s. Names are what an
/// operator can actually write: every other reference in the gitops
/// tree is by name, and an id is worthless the moment the instance is
/// rebuilt from a fresh database. Resolution happens exactly once, in
/// the apply pipeline, through the same `repo_id_by_name` map the
/// `ScanPolicy` scope resolves through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionScopeSpec {
    /// Every repository in the deployment.
    AllRepos,
    /// An explicit list of repository `metadata.name`s. Each must
    /// resolve to an `ArtifactRepository` declared in the same desired
    /// state (cross-spec rule in [`crate::desired`]).
    Repos(Vec<String>),
    /// Every repository of a given package format.
    Format(RepositoryFormat),
    /// Artifacts whose package name matches a glob.
    PackageNamePattern(String),
    /// Restrict to artifacts whose `ArtifactIngested.source` matches.
    IngestSource(IngestSource),
}

impl RetentionScopeSpec {
    /// The repository names this scope references — empty for every
    /// variant but [`Self::Repos`]. The cross-spec dangling-reference
    /// check in [`crate::desired`] walks this; mirrors
    /// [`crate::scope::ScopeSpec::repository_name`].
    pub fn repository_names(&self) -> &[String] {
        match self {
            Self::Repos(names) => names,
            Self::AllRepos
            | Self::Format(_)
            | Self::PackageNamePattern(_)
            | Self::IngestSource(_) => &[],
        }
    }

    /// Validate the scope's structural bounds *pre-resolution*, so a
    /// malformed envelope is rejected before any write rather than
    /// surfacing as a mid-apply domain error.
    ///
    /// Every name-free variant delegates to its domain twin, which owns
    /// the bound. Only [`Self::Repos`] is checked here, because its
    /// operator form is a name list the domain never sees; it shares the
    /// domain's [`MAX_REPOS_IN_SCOPE`] so a spec that passes here can
    /// never resolve into a domain scope that fails there (name → id
    /// resolution is 1:1).
    pub fn validate(&self) -> DomainResult<()> {
        match self {
            Self::Repos(names) => {
                if names.is_empty() {
                    return Err(hort_domain::error::DomainError::Validation(
                        "RetentionScope::Repos must name at least one repository".into(),
                    ));
                }
                if names.len() > MAX_REPOS_IN_SCOPE {
                    return Err(hort_domain::error::DomainError::Validation(format!(
                        "RetentionScope::Repos exceeds the maximum of {MAX_REPOS_IN_SCOPE} \
                         repositories (got {})",
                        names.len()
                    )));
                }
                Ok(())
            }
            Self::PackageNamePattern(p) => RetentionScope::PackageNamePattern(p.clone()).validate(),
            Self::AllRepos => RetentionScope::AllRepos.validate(),
            Self::Format(f) => RetentionScope::Format(f.clone()).validate(),
            Self::IngestSource(s) => RetentionScope::IngestSource(*s).validate(),
        }
    }

    /// Resolve into the domain
    /// [`RetentionScope`](hort_domain::retention::RetentionScope).
    ///
    /// `Err` carries the first repository name absent from
    /// `repo_id_by_name`. The apply pipeline treats that as an invariant
    /// violation — the cross-spec validator already proved every name is
    /// declared — exactly as the `ScanPolicy` scope resolution does; the
    /// `Result` exists only so the panic message lives at the apply
    /// site, next to the ordering guarantee it depends on.
    pub fn resolve(
        &self,
        repo_id_by_name: &HashMap<String, Uuid>,
    ) -> Result<RetentionScope, String> {
        Ok(match self {
            Self::AllRepos => RetentionScope::AllRepos,
            Self::Repos(names) => {
                let mut ids = Vec::with_capacity(names.len());
                for name in names {
                    ids.push(*repo_id_by_name.get(name).ok_or_else(|| name.clone())?);
                }
                RetentionScope::Repos(ids)
            }
            Self::Format(f) => RetentionScope::Format(f.clone()),
            Self::PackageNamePattern(p) => RetentionScope::PackageNamePattern(p.clone()),
            Self::IngestSource(s) => RetentionScope::IngestSource(*s),
        })
    }
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
    /// the typed enum) is deliberate: the operator contract is the
    /// JSON-shaped machine envelope, and binding the field to the Rust
    /// enum would make whatever the YAML layer does with an
    /// externally-tagged enum — historically a `!Variant` tag — the wire
    /// form instead. Going via JSON preserves the JSON form regardless of
    /// the YAML layer underneath and surfaces a malformed value as a typed
    /// validation error naming the policy.
    pub predicate: serde_json::Value,
    /// Which artifacts the policy applies to — [`RetentionScopeSpec`]
    /// in its JSON shape (e.g. `scope: AllRepos`,
    /// `scope: {Repos: [npm-public, pypi-mirror]}`,
    /// `scope: {IngestSource: Proxied}`). Same `Value`-then-resolve
    /// rationale as `predicate`. The `Repos` list holds repository
    /// `metadata.name`s, never ids.
    pub scope: serde_json::Value,
    /// The **held** quarantine states this policy may expire an
    /// artifact out of: `heldStates: [Rejected, ScanIndeterminate]`.
    /// Absent or `[]` — the default, and the state of every policy
    /// that does not mention it — means the policy cannot expire a
    /// held artifact at all.
    ///
    /// A held artifact (`quarantined` / `rejected` /
    /// `scan_indeterminate`) is retained scan evidence or an artifact
    /// awaiting a decision, and five independent gates refuse to
    /// collect it. Naming a state here is the only thing that opens
    /// them, and only for this policy and only for that state.
    ///
    /// Typed rather than a `serde_json::Value`, unlike `predicate` and
    /// `scope`: it is a plain list of unit-variant names with no
    /// externally-tagged shape for the YAML layer to mangle, so there
    /// is no wire form to protect by going through JSON, and binding
    /// the field to the enum makes an unknown state name a parse error
    /// naming the field instead of an opt-in that resolves later.
    ///
    /// **Paired requirement, enforced at apply:** a non-empty
    /// `heldStates` needs a `predicate` whose **every** successful
    /// branch carries a positive `AgeExceeds`, which is then measured
    /// from the artifact's entry into the held state rather than from
    /// its creation. See
    /// [`validate_retention_policy`].
    #[serde(default)]
    pub held_states: BTreeSet<HeldState>,
}

/// Parse one `RetentionPolicy` envelope.
pub fn parse_retention_policy(
    _path: &Path,
    bytes: &[u8],
) -> Result<Envelope<RetentionPolicySpec>, ParseError> {
    let env: Envelope<RetentionPolicySpec> = crate::yaml::from_slice(bytes)?;
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
/// - `scope` passes [`RetentionScopeSpec::validate`] (non-empty /
///   bounded `Repos`, bounded `PackageNamePattern`)
/// - a non-empty `heldStates` has a `predicate` whose **every**
///   successful branch carries a positive `AgeExceeds`
///   ([`PolicyPredicate::every_branch_has_positive_age_bound`](hort_domain::retention::PolicyPredicate::every_branch_has_positive_age_bound))
///
/// ## Why the held-state rule is a reject and not a warning
///
/// `heldStates` is the operator surface that lets a retention policy
/// collect **retained scan evidence** — a rejected artifact, a
/// quarantined one, one whose scan terminally failed. An opt-in whose
/// predicate can fire without time in that state expires such an
/// artifact the moment it is first judged, which is the one outcome
/// the whole exception exists to avoid. So the admission test is on
/// the predicate's structure and it is fail-closed: the operator
/// either states a span or does not get the exception.
///
/// "Mentions an age predicate" is deliberately **not** the test.
/// `HasFindingDetectedFor` dates the vulnerability, not the artifact's
/// time in the state; `UnusedFor` has no download anchor and is
/// rejected elsewhere for deciding on age while naming usage; and a
/// `Composite(Or, …)` can carry an age bound on one arm and match
/// immediately through another. The rule follows what a match
/// actually requires — see the domain function's own docs.
///
/// Scoped to this envelope's own spec, like the two validators above,
/// which is why it lives here rather than as a `LinterRule` in the
/// `hort-app` lint registry: it needs no other envelope, no registry
/// and no capability map to decide, and `DesiredState::validate` runs
/// it on every apply.
///
/// The cross-spec rule — every `Repos` entry names a declared
/// `ArtifactRepository` — lives in [`crate::desired`], the only layer
/// that can see the other envelopes.
///
/// The *security-predicate-does-not-exclude-direct-uploads* `info!` warning
/// is **not** a validation reject — it fires at apply time in
/// `ApplyConfigUseCase::apply_retention_policies` (it is operator-intent
/// advisory; the policy still applies). This function only enforces
/// structural validity.
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
            if !env.spec.held_states.is_empty() && !predicate.every_branch_has_positive_age_bound()
            {
                // `HeldState`'s `Debug` names are its variant names, which
                // are the names an operator writes in `heldStates` — so
                // the message quotes the YAML back without a third
                // hand-written copy of the vocabulary to keep in step.
                let states = format!("{:?}", env.spec.held_states);
                errors.push(ValidationError::Invalid {
                    kind: Kind::RetentionPolicy,
                    name: env.metadata.name.clone(),
                    detail: format!(
                        "`spec.heldStates` is {states}, so this policy may expire retained \
                         scan evidence — but `spec.predicate` has a branch that can match \
                         with no positive `AgeExceeds` bound, which would expire such an \
                         artifact the moment it is judged. Every branch that can fire must \
                         carry one: under a `heldStates` opt-in `AgeExceeds` is measured \
                         from the artifact's entry into the held state, not from its \
                         creation. Note that an `Or` needs the bound on *every* arm (one \
                         arm matching on its own skips the others), that \
                         `HasFindingDetectedFor` dates the vulnerability rather than time \
                         in the state, and that an `And` needs it on only one child. \
                         Remove `heldStates` or add the bound. (retention policy: `{name}`)",
                        name = env.metadata.name,
                    ),
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
            "apiVersion: project-hort.de/v1\nkind: RetentionPolicy\n\
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
        assert_eq!(scope, RetentionScopeSpec::AllRepos);
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
        assert_eq!(
            scope
                .resolve(&HashMap::new())
                .expect("name-free scope resolves"),
            RetentionScope::IngestSource(IngestSource::Proxied)
        );
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

    // -- RetentionScopeSpec: the operator surface carries names ---------

    #[test]
    fn parse_repos_scope_carries_names_not_uuids() {
        let body = "
  predicate:
    AgeExceeds: 2592000
  scope:
    Repos: [npm-public, pypi-mirror]
";
        let env = parse_retention_policy(&p(), yaml("retain-named", body).as_bytes()).unwrap();
        let scope = scope_from_value(&env.spec.scope).expect("scope resolves");
        assert_eq!(
            scope,
            RetentionScopeSpec::Repos(vec!["npm-public".into(), "pypi-mirror".into()])
        );
        assert!(validate_retention_policy(&env).is_empty());
    }

    /// A UUID in the YAML is not a UUID to this layer — it is just an
    /// unlucky repository *name*. Nothing downstream ever parses a
    /// `Repos` entry as an id, so a tree that still carries the retired
    /// UUID form fails the cross-spec declared-repository rule rather
    /// than applying against a stale id.
    #[test]
    fn a_uuid_in_the_repos_list_is_read_as_a_name() {
        let body = "
  predicate:
    AgeExceeds: 60
  scope:
    Repos: ['67e55044-10b1-426f-9247-bb680e5fe0c8']
";
        let env = parse_retention_policy(&p(), yaml("legacy-uuid", body).as_bytes()).unwrap();
        let scope = scope_from_value(&env.spec.scope).expect("scope resolves");
        assert_eq!(
            scope,
            RetentionScopeSpec::Repos(vec!["67e55044-10b1-426f-9247-bb680e5fe0c8".into()])
        );
    }

    #[test]
    fn repository_names_is_empty_for_every_name_free_variant() {
        assert!(RetentionScopeSpec::AllRepos.repository_names().is_empty());
        assert!(RetentionScopeSpec::Format(RepositoryFormat::Npm)
            .repository_names()
            .is_empty());
        assert!(RetentionScopeSpec::PackageNamePattern("x-*".into())
            .repository_names()
            .is_empty());
        assert!(RetentionScopeSpec::IngestSource(IngestSource::Proxied)
            .repository_names()
            .is_empty());
        assert_eq!(
            RetentionScopeSpec::Repos(vec!["a".into(), "b".into()]).repository_names(),
            ["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn spec_validate_bounds_the_name_list() {
        RetentionScopeSpec::Repos(vec!["a".into()])
            .validate()
            .unwrap();
        RetentionScopeSpec::Repos(vec!["a".into(); MAX_REPOS_IN_SCOPE])
            .validate()
            .unwrap();

        let empty = RetentionScopeSpec::Repos(Vec::new())
            .validate()
            .unwrap_err();
        assert!(
            empty.to_string().contains("at least one repository"),
            "got {empty}"
        );
        let over = RetentionScopeSpec::Repos(vec!["a".into(); MAX_REPOS_IN_SCOPE + 1])
            .validate()
            .unwrap_err();
        assert!(over.to_string().contains("maximum"), "got {over}");
    }

    #[test]
    fn spec_validate_delegates_the_name_free_variants_to_the_domain() {
        RetentionScopeSpec::AllRepos.validate().unwrap();
        RetentionScopeSpec::Format(RepositoryFormat::Cargo)
            .validate()
            .unwrap();
        RetentionScopeSpec::IngestSource(IngestSource::Direct)
            .validate()
            .unwrap();
        RetentionScopeSpec::PackageNamePattern("org.example.*".into())
            .validate()
            .unwrap();
        let err = RetentionScopeSpec::PackageNamePattern(String::new())
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got {err}");
    }

    #[test]
    fn resolve_maps_names_to_ids_preserving_order() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let map: HashMap<String, Uuid> = [
            ("npm-public".to_string(), a),
            ("pypi-mirror".to_string(), b),
        ]
        .into_iter()
        .collect();
        let resolved = RetentionScopeSpec::Repos(vec!["pypi-mirror".into(), "npm-public".into()])
            .resolve(&map)
            .expect("both names are declared");
        assert_eq!(resolved, RetentionScope::Repos(vec![b, a]));
    }

    #[test]
    fn resolve_reports_the_first_undeclared_name() {
        let map: HashMap<String, Uuid> = [("npm-public".to_string(), Uuid::from_u128(1))]
            .into_iter()
            .collect();
        let missing = RetentionScopeSpec::Repos(vec!["npm-public".into(), "ghost".into()])
            .resolve(&map)
            .unwrap_err();
        assert_eq!(missing, "ghost");
    }

    #[test]
    fn resolve_passes_every_name_free_variant_through_unchanged() {
        let empty = HashMap::new();
        assert_eq!(
            RetentionScopeSpec::AllRepos.resolve(&empty).unwrap(),
            RetentionScope::AllRepos
        );
        assert_eq!(
            RetentionScopeSpec::Format(RepositoryFormat::Oci)
                .resolve(&empty)
                .unwrap(),
            RetentionScope::Format(RepositoryFormat::Oci)
        );
        assert_eq!(
            RetentionScopeSpec::PackageNamePattern("a/*".into())
                .resolve(&empty)
                .unwrap(),
            RetentionScope::PackageNamePattern("a/*".into())
        );
        assert_eq!(
            RetentionScopeSpec::IngestSource(IngestSource::Direct)
                .resolve(&empty)
                .unwrap(),
            RetentionScope::IngestSource(IngestSource::Direct)
        );
    }

    #[test]
    fn spec_scope_clone_debug_eq_cover() {
        let a = RetentionScopeSpec::Repos(vec!["npm-public".into()]);
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, RetentionScopeSpec::AllRepos);
        assert!(format!("{a:?}").contains("npm-public"));
        // The JSON machine envelope round-trips both directions.
        let json = serde_json::to_value(&a).unwrap();
        let back: RetentionScopeSpec = serde_json::from_value(json).unwrap();
        assert_eq!(a, back);
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
        let doc = "apiVersion: project-hort.de/v1\nkind: ScanPolicy\n\
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
            "apiVersion: project-hort.de/v1\nkind: RetentionPolicy\n\
             metadata:\n  name: ''\nspec:{body}"
        );
        let err = parse_retention_policy(&p(), doc.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::EmptyMetadataName));
    }

    // -- heldStates --------------------------------------------------------

    #[test]
    fn held_states_defaults_to_empty() {
        let body = "
  predicate:
    AgeExceeds: 2592000
  scope: AllRepos
";
        let env = parse_retention_policy(&p(), yaml("retain-30d", body).as_bytes()).unwrap();
        assert!(
            env.spec.held_states.is_empty(),
            "a policy that does not mention heldStates opts in to nothing"
        );
        assert!(validate_retention_policy(&env).is_empty());
    }

    #[test]
    fn held_states_round_trips_with_an_age_bound() {
        let body = "
  predicate:
    AgeExceeds: 7776000
  scope: AllRepos
  heldStates: [Rejected, ScanIndeterminate]
";
        let env =
            parse_retention_policy(&p(), yaml("collect-evidence-90d", body).as_bytes()).unwrap();
        assert_eq!(
            env.spec.held_states,
            BTreeSet::from([HeldState::Rejected, HeldState::ScanIndeterminate])
        );
        assert!(validate_retention_policy(&env).is_empty());
    }

    #[test]
    fn an_unknown_held_state_name_is_a_parse_error() {
        let body = "
  predicate:
    AgeExceeds: 7776000
  scope: AllRepos
  heldStates: [Released]
";
        let err = parse_retention_policy(&p(), yaml("bad", body).as_bytes())
            .expect_err("Released is not a held state");
        // The field is bound to the enum, so the failure is a parse
        // error that enumerates the three valid states — not an opt-in
        // that resolves later into something nobody checked. The three
        // names are the operator-actionable part of the message.
        let rendered = format!("{err}");
        for state in ["Quarantined", "Rejected", "ScanIndeterminate"] {
            assert!(
                rendered.contains(state),
                "the error should enumerate the valid states, got: {rendered}"
            );
        }
        assert!(rendered.contains("Released"), "{rendered}");
    }

    /// **The decisive case: an `Or` whose other arm matches
    /// immediately.** It mentions an age predicate and would expire a
    /// rejected artifact the moment a severe finding is reported
    /// against it, so "has an age predicate" must not pass it.
    #[test]
    fn an_or_whose_other_arm_matches_immediately_is_rejected() {
        let body = r#"
  predicate:
    Composite:
      - Or
      - - AgeExceeds: 2592000
        - HasFindingAboveSeverity: High
  scope: AllRepos
  heldStates: [Rejected]
"#;
        let env = parse_retention_policy(&p(), yaml("collect-severe", body).as_bytes()).unwrap();
        let errs = validate_retention_policy(&env);
        assert_eq!(errs.len(), 1, "expected one error, got {errs:?}");
        let rendered = format!("{:?}", errs[0]);
        assert!(rendered.contains("heldStates"), "{rendered}");
        assert!(rendered.contains("AgeExceeds"), "{rendered}");
        assert!(
            rendered.contains("Or"),
            "the error must name the Or arm trap: {rendered}"
        );
        // The message quotes the opt-in back, so the operator reads
        // which states they asked for rather than inferring it.
        assert!(rendered.contains("Rejected"), "{rendered}");
    }

    /// The rejected message names **every** state the opt-in asked
    /// for, in the spelling the YAML used — so an operator editing a
    /// multi-state opt-in can see which of them the rule is about.
    #[test]
    fn the_rejection_names_every_opted_in_state() {
        let body = r#"
  predicate:
    KeepLastN: 3
  scope: AllRepos
  heldStates: [Quarantined, Rejected, ScanIndeterminate]
"#;
        let env = parse_retention_policy(&p(), yaml("collect-all-held", body).as_bytes()).unwrap();
        let errs = validate_retention_policy(&env);
        assert_eq!(errs.len(), 1, "expected one error, got {errs:?}");
        let rendered = format!("{:?}", errs[0]);
        for state in ["Quarantined", "Rejected", "ScanIndeterminate"] {
            assert!(
                rendered.contains(state),
                "the message must name {state}: {rendered}"
            );
        }
    }

    /// The same predicate with **no** opt-in is accepted: the rule is
    /// the opt-in's, and an existing severity policy over served
    /// artifacts must not have been outlawed.
    #[test]
    fn the_same_or_predicate_without_an_opt_in_is_accepted() {
        let body = r#"
  predicate:
    Composite:
      - Or
      - - AgeExceeds: 2592000
        - HasFindingAboveSeverity: High
  scope: AllRepos
"#;
        let env = parse_retention_policy(&p(), yaml("expire-severe", body).as_bytes()).unwrap();
        assert!(validate_retention_policy(&env).is_empty());
    }

    /// `HasFindingDetectedFor` dates the **vulnerability**, not time in
    /// the state, so it is not a held-state age bound however long it
    /// is.
    #[test]
    fn has_finding_detected_for_is_not_a_held_state_age_bound() {
        let body = r#"
  predicate:
    HasFindingDetectedFor: 7776000
  scope: AllRepos
  heldStates: [Quarantined]
"#;
        let env =
            parse_retention_policy(&p(), yaml("collect-known-cves", body).as_bytes()).unwrap();
        assert_eq!(validate_retention_policy(&env).len(), 1);
    }

    /// `KeepLastN` has no time in it, so a count-based policy cannot
    /// carry the exception.
    #[test]
    fn keep_last_n_is_not_a_held_state_age_bound() {
        let body = r#"
  predicate:
    KeepLastN: 3
  scope: AllRepos
  heldStates: [Rejected]
"#;
        let env = parse_retention_policy(&p(), yaml("keep-three", body).as_bytes()).unwrap();
        assert_eq!(validate_retention_policy(&env).len(), 1);
    }

    /// An `And` needs the bound on only one child: every child must
    /// hold for the conjunction to match, so one bounded child bounds
    /// it. This is the canonical shape for the exception.
    #[test]
    fn an_and_with_one_age_bounded_child_is_accepted() {
        let body = r#"
  predicate:
    Composite:
      - And
      - - HasFindingAboveSeverity: High
        - AgeExceeds: 7776000
  scope: AllRepos
  heldStates: [Rejected]
"#;
        let env = parse_retention_policy(&p(), yaml("collect-severe-after-90d", body).as_bytes())
            .unwrap();
        assert!(validate_retention_policy(&env).is_empty());
    }
}
