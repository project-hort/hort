//! `DesiredState` — the parsed-and-validated set of objects from
//! `$HORT_CONFIG_DIR`. Item 8 consumes this into `ApplyConfigUseCase`.
//!
//! Two validation entry points:
//! - `validate()` — environment-agnostic rules (per-spec validation
//!   from Items 5/6, plus duplicate-name and cross-spec
//!   virtual-member resolution). Pure-static — unit tests don't need
//!   a snapshot.
//! - `validate_against(snapshot, env)` — adds the snapshot- and
//!   env-aware rules: managed conflicts (a desired entry collides
//!   with a current `Local` row) and the §8.1 rule
//!   "HORT_AUTH_PROVIDER=disabled but ClaimMapping declared = fatal".
//!
//! Both collect every error before returning — operators want one
//! complete list per boot pass, not first-error-wins.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::claim_mapping::{parse_claim_mapping, ClaimMappingSpec};
use crate::curation_rule::{parse_curation_rule, validate_curation_rule, CurationRuleSpec};
use crate::diff::CurrentSnapshot;
use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ParseErrors, ValidationError, ValidationErrors};
use crate::exclusion::{parse_exclusion, validate_exclusion, ExclusionSpec};
use crate::lint_config::{parse_lint_config, validate_lint_config, PermissionGrantLintConfigSpec};
use crate::oidc_issuer::{parse_oidc_issuer, validate_oidc_issuer, OidcIssuerSpec};
use crate::permission_grant::{
    parse_permission_grant, validate_permission_grant, PermissionGrantSpec,
};
use crate::repository::{parse_repository, validate_repository, RepositorySpec};
use crate::retention_policy::{
    parse_retention_policy, validate_retention_policy, RetentionPolicySpec,
};
use crate::scan_policy::{parse_scan_policy, validate_scan_policy, ScanPolicySpec};
use crate::service_account::{parse_service_account, validate_service_account, ServiceAccountSpec};
use crate::upstream_mapping::{
    parse_upstream_mapping, validate_upstream_mapping, UpstreamMappingSpec,
};

/// Parsed desired state from a directory walk.
///
/// `permission_grants` / `curation_rules` are CRUD-extension kinds;
/// `scan_policies` / `exclusions` are event-sourced and feed into the
/// `ApplyEventSourcedKind` machinery — they are represented identically
/// in `DesiredState` but the apply pipeline dispatches on kind type.
///
/// `upstream_mappings` is a CRUD-extension kind; depends on
/// `repositories` for `spec.repository → repository_id` resolution at
/// apply time.
///
/// `claim_mappings` replaced the earlier `roles` + `group_mappings`
/// model (additive-claims, see ADR 0012).
#[derive(Debug, Default, Clone)]
pub struct DesiredState {
    pub repositories: Vec<Envelope<RepositorySpec>>,
    pub claim_mappings: Vec<Envelope<ClaimMappingSpec>>,
    pub permission_grants: Vec<Envelope<PermissionGrantSpec>>,
    pub curation_rules: Vec<Envelope<CurationRuleSpec>>,
    pub scan_policies: Vec<Envelope<ScanPolicySpec>>,
    /// Event-sourced retention policies. Same shape/dispatch as
    /// `scan_policies` (gitops-authored via `RetentionPolicyUseCase`).
    pub retention_policies: Vec<Envelope<RetentionPolicySpec>>,
    pub exclusions: Vec<Envelope<ExclusionSpec>>,
    pub upstream_mappings: Vec<Envelope<UpstreamMappingSpec>>,
    /// Declared OIDC trust relationships for workload federation.
    /// Applied before `service_accounts` so the cross-kind FK
    /// (`ServiceAccount.federatedIdentities[].issuer` references
    /// `OidcIssuer.name`) resolves cleanly.
    pub oidc_issuers: Vec<Envelope<OidcIssuerSpec>>,
    /// Declared non-human identities (ADR 0018).
    pub service_accounts: Vec<Envelope<ServiceAccountSpec>>,
    /// The apply-config grant linter's operator opt-out surface.
    /// **Singleton**: `Option`, not `Vec` — at most one cluster-wide.
    /// A second declaration is detected at absorb time (every
    /// contributing path is recorded in `lint_config_sources`) and
    /// surfaced as [`ValidationError::SingletonConflict`] from
    /// [`DesiredState::validate`], never a silent last-wins. Absent ⇒
    /// the secure `LintConfig::default()` (wired in
    /// `ApplyConfigUseCase`); a missing kind is *not* a downgrade.
    pub lint_config: Option<Envelope<PermissionGrantLintConfigSpec>>,
    /// Every path that declared a `PermissionGrantLintConfig`. A
    /// length above one means the singleton was violated; `validate`
    /// renders the `SingletonConflict` error listing them all. Kept
    /// separate from `source_files` (which is `(kind, name)`-keyed)
    /// because the singleton constraint is per-*kind*,
    /// name-independent. `pub` to match every other `DesiredState`
    /// field (the struct is a plain data carrier built field-wise and
    /// via `..Default::default()` in `hort-app` tests; a private field
    /// would break struct-update syntax cross-crate — E0451).
    pub lint_config_sources: Vec<PathBuf>,
    /// Every source-file path that declared a given `(kind, name)`.
    /// Vec rather than `PathBuf` so a duplicate-name validation
    /// failure can list every offending file, not just the last one
    /// recorded. The Vec is single-element for the happy path.
    pub source_files: HashMap<EnvelopeKey, Vec<PathBuf>>,
}

/// `(kind, name)` key — both are part of the identity because two
/// kinds can legitimately reuse a name (`name: admins` for an
/// ArtifactRepository AND a ClaimMapping is fine; the duplicate-name
/// check is per-kind).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnvelopeKey {
    pub kind: Kind,
    pub name: String,
}

/// Environment hints the snapshot-aware validator needs.
///
/// Modelled here rather than borrowed from `hort_server::config::AuthConfig`
/// so `hort-config` doesn't drag the OIDC URL / signing key surface into
/// its runtime-free type system. The boot caller maps from
/// `AuthConfig::{Disabled, Oidc(_)}` → `EnvSnapshot::auth_provider` at
/// the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvSnapshot {
    pub auth_provider: EnvAuthProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvAuthProvider {
    Disabled,
    Oidc,
}

impl DesiredState {
    /// Parse every file in the input. Collects every per-file error
    /// before returning — never short-circuits on the first failure.
    ///
    /// Dispatch:
    /// 1. Try to peek at the top-level `kind` field. If present,
    ///    route to the matching kind parser.
    /// 2. If absent and the document has a top-level `mappings:` key
    ///    (the removed multi-object root shape), surface
    ///    `ParseError::UnsupportedShape` so the operator re-emits the
    ///    file as one canonical envelope per mapping.
    /// 3. Anything else surfaces as `UnknownKind`.
    pub fn parse_files(
        files: impl IntoIterator<Item = (PathBuf, Vec<u8>)>,
    ) -> Result<Self, ParseErrors> {
        let mut state = DesiredState::default();
        let mut errors = Vec::new();

        for (path, bytes) in files {
            match parse_one_file(&path, &bytes) {
                Ok(parsed) => state.absorb(parsed, &path),
                Err(e) => errors.push((path, e)),
            }
        }

        if errors.is_empty() {
            Ok(state)
        } else {
            Err(ParseErrors(errors))
        }
    }

    fn absorb(&mut self, parsed: ParsedFile, source: &std::path::Path) {
        match parsed {
            ParsedFile::Repository(boxed) => {
                let env = *boxed;
                self.record_source(Kind::ArtifactRepository, &env.metadata.name, source);
                self.repositories.push(env);
            }
            ParsedFile::ClaimMapping(env) => {
                self.record_source(Kind::ClaimMapping, &env.metadata.name, source);
                self.claim_mappings.push(env);
            }
            ParsedFile::PermissionGrant(env) => {
                self.record_source(Kind::PermissionGrant, &env.metadata.name, source);
                self.permission_grants.push(env);
            }
            ParsedFile::CurationRule(env) => {
                self.record_source(Kind::CurationRule, &env.metadata.name, source);
                self.curation_rules.push(env);
            }
            ParsedFile::ScanPolicy(boxed) => {
                let env = *boxed;
                self.record_source(Kind::ScanPolicy, &env.metadata.name, source);
                self.scan_policies.push(env);
            }
            ParsedFile::RetentionPolicy(boxed) => {
                let env = *boxed;
                self.record_source(Kind::RetentionPolicy, &env.metadata.name, source);
                self.retention_policies.push(env);
            }
            ParsedFile::Exclusion(env) => {
                self.record_source(Kind::Exclusion, &env.metadata.name, source);
                self.exclusions.push(env);
            }
            ParsedFile::UpstreamMapping(env) => {
                self.record_source(Kind::UpstreamMapping, &env.metadata.name, source);
                self.upstream_mappings.push(env);
            }
            ParsedFile::OidcIssuer(env) => {
                self.record_source(Kind::OidcIssuer, &env.metadata.name, source);
                self.oidc_issuers.push(env);
            }
            ParsedFile::ServiceAccount(boxed) => {
                let env = *boxed;
                self.record_source(Kind::ServiceAccount, &env.metadata.name, source);
                self.service_accounts.push(env);
            }
            ParsedFile::PermissionGrantLintConfig(boxed) => {
                let env = *boxed;
                self.record_source(Kind::PermissionGrantLintConfig, &env.metadata.name, source);
                // Singleton: keep the FIRST envelope so `validate`
                // still per-spec-validates a config, and record EVERY
                // contributing path so a >1 declaration surfaces as a
                // named `SingletonConflict` (never a silent last-wins
                // — design doc §6 invariant 2).
                self.lint_config_sources.push(source.to_path_buf());
                if self.lint_config.is_none() {
                    self.lint_config = Some(env);
                }
            }
        }
    }

    /// Append `source` to the `source_files` entry for `(kind, name)`.
    /// Push-not-overwrite so duplicate-name validation can report every
    /// contributing path (the `validate()` rule above), not just the
    /// last one absorbed.
    fn record_source(&mut self, kind: Kind, name: &str, source: &std::path::Path) {
        self.source_files
            .entry(EnvelopeKey {
                kind,
                name: name.to_string(),
            })
            .or_default()
            .push(source.to_path_buf());
    }

    /// Environment-agnostic validation. Returns every violation.
    ///
    /// Cross-spec rules:
    /// - No two `(kind, name)` pairs.
    /// - Per-spec validation runs here on every entry.
    /// - Virtual repositories must reference desired-state members
    ///   only — referencing a `Local` row from a managed virtual
    ///   surfaces as `DanglingVirtualMember` (the snapshot path
    ///   doesn't relax this; v1 keeps the gitops surface
    ///   self-contained).
    /// - Cross-doc reference rules: `PermissionGrant.repository` (when
    ///   set) resolves to a declared `ArtifactRepository`;
    ///   `Repository.curation_rules` entries resolve to declared
    ///   `CurationRule` envelopes; `Exclusion.policy` resolves to a
    ///   declared `ScanPolicy`. Roles are not a gitops kind; there is
    ///   no `PermissionGrant.role` cross-doc reference.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();

        // Per-spec validation.
        for env in &self.repositories {
            errors.extend(validate_repository(env));
        }
        // ClaimMapping per-spec rules are enforced at parse time
        // (empty idpGroup/claim rejected in `parse_claim_mapping`); no
        // post-parse hook to add here.
        for env in &self.permission_grants {
            errors.extend(validate_permission_grant(env));
        }
        for env in &self.curation_rules {
            errors.extend(validate_curation_rule(env));
        }
        for env in &self.scan_policies {
            errors.extend(validate_scan_policy(env));
        }
        for env in &self.retention_policies {
            errors.extend(validate_retention_policy(env));
        }
        for env in &self.exclusions {
            errors.extend(validate_exclusion(env));
        }
        for env in &self.upstream_mappings {
            errors.extend(validate_upstream_mapping(env));
        }
        for env in &self.oidc_issuers {
            errors.extend(validate_oidc_issuer(env));
        }
        for env in &self.service_accounts {
            errors.extend(validate_service_account(env));
        }
        if let Some(env) = &self.lint_config {
            errors.extend(validate_lint_config(env));
        }

        // Singleton enforcement. More than one `PermissionGrantLintConfig`
        // is a named error, not a silent last-wins — the linter config is
        // the load-bearing security opt-out for the permission-grant linter.
        if self.lint_config_sources.len() > 1 {
            errors.push(ValidationError::SingletonConflict {
                kind: Kind::PermissionGrantLintConfig,
                count: self.lint_config_sources.len(),
                files: self.lint_config_sources.clone(),
            });
        }

        // Duplicate names per kind.
        push_duplicates(
            Kind::ArtifactRepository,
            self.repositories.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::ClaimMapping,
            self.claim_mappings.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::PermissionGrant,
            self.permission_grants.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::CurationRule,
            self.curation_rules.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::ScanPolicy,
            self.scan_policies.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::RetentionPolicy,
            self.retention_policies.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::Exclusion,
            self.exclusions.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::UpstreamMapping,
            self.upstream_mappings.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::OidcIssuer,
            self.oidc_issuers.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );
        push_duplicates(
            Kind::ServiceAccount,
            self.service_accounts.iter().map(|e| &e.metadata.name),
            &self.source_files,
            &mut errors,
        );

        // Virtual-member references must point at another declared
        // repository (see ADR 0008).
        let declared_repos: std::collections::HashSet<&str> = self
            .repositories
            .iter()
            .map(|e| e.metadata.name.as_str())
            .collect();
        for env in &self.repositories {
            if let Some(members) = env.spec.virtual_members.as_ref() {
                for member in members {
                    if !declared_repos.contains(member.as_str()) {
                        errors.push(ValidationError::DanglingVirtualMember {
                            virtual_repo: env.metadata.name.clone(),
                            missing_member: member.clone(),
                        });
                    }
                }
            }
        }

        // Cross-doc reference rules. Roles are no longer a gitops kind
        // so there is no system-role protection rule to enforce.
        push_init14_reference_errors(self, &declared_repos, &mut errors);
        push_per_policy_exclusion_duplicates(&self.exclusions, &mut errors);
        push_upstream_mapping_reference_errors(self, &declared_repos, &mut errors);
        push_upstream_mapping_identity_duplicates(&self.upstream_mappings, &mut errors);
        push_upstream_mapping_format_compatibility_errors(self, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }

    /// Snapshot- and env-aware validation.
    ///
    /// Adds:
    /// - `ManagedConflict` — desired declares an entry whose name
    ///   matches a current `Local` row.
    /// - `AuthProviderDisabledWithGroupMappings` — keyed off
    ///   `ClaimMapping` declarations; the variant name is retained to
    ///   keep the cross-crate error API stable.
    pub fn validate_against(
        &self,
        snapshot: &CurrentSnapshot,
        env: &EnvSnapshot,
    ) -> Result<(), ValidationErrors> {
        let mut errors = match self.validate() {
            Ok(()) => Vec::new(),
            Err(ValidationErrors(v)) => v,
        };

        // Managed conflict: desired entry collides with a Local row.
        let local_repos: std::collections::HashSet<&str> = snapshot
            .repositories
            .iter()
            .filter(|r| r.managed_by == hort_domain::entities::managed_by::ManagedBy::Local)
            .map(|r| r.key.as_str())
            .collect();
        for env in &self.repositories {
            if local_repos.contains(env.metadata.name.as_str()) {
                errors.push(ValidationError::ManagedConflict {
                    kind: Kind::ArtifactRepository,
                    name: env.metadata.name.clone(),
                });
            }
        }
        let local_mappings: std::collections::HashSet<&str> = snapshot
            .claim_mappings
            .iter()
            .filter(|m| m.managed_by == hort_domain::entities::managed_by::ManagedBy::Local)
            .map(|m| m.name.as_str())
            .collect();
        for env in &self.claim_mappings {
            if local_mappings.contains(env.metadata.name.as_str()) {
                errors.push(ValidationError::ManagedConflict {
                    kind: Kind::ClaimMapping,
                    name: env.metadata.name.clone(),
                });
            }
        }

        // HORT_AUTH_PROVIDER=disabled + non-empty claim_mappings is
        // fatal. Catches operators who set HORT_AUTH_PROVIDER=disabled
        // but left mappings declared, which would silently produce
        // dormant rows that never fire. The error variant name
        // (`AuthProviderDisabledWithGroupMappings`) is retained to keep
        // the cross-crate error API stable; its rendered message names
        // `ClaimMapping`.
        if matches!(env.auth_provider, EnvAuthProvider::Disabled) && !self.claim_mappings.is_empty()
        {
            let names: Vec<String> = self
                .claim_mappings
                .iter()
                .map(|e| e.metadata.name.clone())
                .collect();
            errors.push(ValidationError::AuthProviderDisabledWithGroupMappings {
                count: names.len(),
                names,
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

/// Internal: result of parsing one file. The repository and scan-policy
/// envelopes are boxed because their specs are much larger than the
/// others (clippy::large_enum_variant); the indirection is one heap
/// allocation per parsed file, which is negligible alongside the YAML
/// parser's own allocations.
enum ParsedFile {
    Repository(Box<Envelope<RepositorySpec>>),
    ClaimMapping(Envelope<ClaimMappingSpec>),
    PermissionGrant(Envelope<PermissionGrantSpec>),
    CurationRule(Envelope<CurationRuleSpec>),
    ScanPolicy(Box<Envelope<ScanPolicySpec>>),
    /// Boxed to match the `ScanPolicy` shape; the spec carries the
    /// predicate-tree + scope enums.
    RetentionPolicy(Box<Envelope<RetentionPolicySpec>>),
    Exclusion(Envelope<ExclusionSpec>),
    UpstreamMapping(Envelope<UpstreamMappingSpec>),
    OidcIssuer(Envelope<OidcIssuerSpec>),
    /// Boxed because `ServiceAccountSpec` carries a Vec and an Option,
    /// making the variant noticeably larger than the others
    /// (clippy::large_enum_variant). One heap allocation per parsed
    /// file is negligible alongside the YAML parser's own allocations.
    ServiceAccount(Box<Envelope<ServiceAccountSpec>>),
    /// The singleton apply-config linter config. Boxed to match the
    /// other Vec/Option-carrying specs (clippy::large_enum_variant).
    PermissionGrantLintConfig(Box<Envelope<PermissionGrantLintConfigSpec>>),
}

fn parse_one_file(path: &std::path::Path, bytes: &[u8]) -> Result<ParsedFile, ParseError> {
    // Peek at the raw YAML to decide which parser to invoke.
    let raw: serde_yaml_ng::Value = serde_yaml_ng::from_slice(bytes)?;
    let kind = raw.get("kind").and_then(|v| v.as_str());
    if let Some(kind_str) = kind {
        match kind_str {
            "ArtifactRepository" => {
                parse_repository(path, bytes).map(|e| ParsedFile::Repository(Box::new(e)))
            }
            "ClaimMapping" => parse_claim_mapping(path, bytes).map(ParsedFile::ClaimMapping),
            "PermissionGrant" => {
                parse_permission_grant(path, bytes).map(ParsedFile::PermissionGrant)
            }
            "CurationRule" => parse_curation_rule(path, bytes).map(ParsedFile::CurationRule),
            "ScanPolicy" => {
                parse_scan_policy(path, bytes).map(|e| ParsedFile::ScanPolicy(Box::new(e)))
            }
            "RetentionPolicy" => parse_retention_policy(path, bytes)
                .map(|e| ParsedFile::RetentionPolicy(Box::new(e))),
            "Exclusion" => parse_exclusion(path, bytes).map(ParsedFile::Exclusion),
            "UpstreamMapping" => {
                parse_upstream_mapping(path, bytes).map(ParsedFile::UpstreamMapping)
            }
            "OidcIssuer" => parse_oidc_issuer(path, bytes).map(ParsedFile::OidcIssuer),
            "ServiceAccount" => {
                parse_service_account(path, bytes).map(|e| ParsedFile::ServiceAccount(Box::new(e)))
            }
            "PermissionGrantLintConfig" => parse_lint_config(path, bytes)
                .map(|e| ParsedFile::PermissionGrantLintConfig(Box::new(e))),
            other => Err(ParseError::UnknownKind {
                got: other.to_string(),
                valid: Kind::KNOWN,
            }),
        }
    } else if raw.get("mappings").is_some() {
        // The legacy `mappings: [{group, role}]` multi-object root shape
        // was removed. Surface a typed error so the operator knows to
        // re-emit the file as one canonical envelope per mapping. The
        // dispatch peeks at the root key first so canonical-shape files
        // (which carry `kind:` and never `mappings:`) cannot be misrouted.
        Err(ParseError::UnsupportedShape {
            detected: "mappings",
            expected: "one envelope per file",
        })
    } else {
        Err(ParseError::UnknownKind {
            got: "<missing>".into(),
            valid: Kind::KNOWN,
        })
    }
}

/// Cross-doc reference checks.
///
/// The reference relationships, kept together so the rule list is
/// reviewable in one place:
/// 1. `PermissionGrant.repository` (when set) → declared
///    `ArtifactRepository.metadata.name` (the same `declared_repos`
///    set the virtual-member check uses).
/// 2. `Repository.curation_rules` (when set) → declared
///    `CurationRule.metadata.name`.
/// 3. `Exclusion.policy` → declared `ScanPolicy.metadata.name`.
///
/// Roles are not a gitops kind; there is no `PermissionGrant.role`
/// cross-doc reference. The `subject` shape is validated per-spec in
/// `validate_permission_grant`.
///
/// Each violation surfaces as a single `DanglingReference` error that
/// names the referrer envelope, the field path, and the missing
/// target — operators see one self-contained message per bad link.
fn push_init14_reference_errors(
    state: &DesiredState,
    declared_repos: &std::collections::HashSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    let declared_curation_rules: std::collections::HashSet<&str> = state
        .curation_rules
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();
    let declared_policies: std::collections::HashSet<&str> = state
        .scan_policies
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();

    for env in &state.permission_grants {
        if let Some(repo) = env.spec.repository.as_ref() {
            if !repo.trim().is_empty() && !declared_repos.contains(repo.as_str()) {
                errors.push(ValidationError::DanglingReference {
                    referrer_kind: Kind::PermissionGrant,
                    referrer_name: env.metadata.name.clone(),
                    field: "spec.repository",
                    target_kind: Kind::ArtifactRepository,
                    missing_name: repo.clone(),
                });
            }
        }
    }

    for env in &state.repositories {
        if let Some(rule_names) = env.spec.curation_rules.as_ref() {
            for name in rule_names {
                if !declared_curation_rules.contains(name.as_str()) {
                    errors.push(ValidationError::DanglingReference {
                        referrer_kind: Kind::ArtifactRepository,
                        referrer_name: env.metadata.name.clone(),
                        field: "spec.curationRules",
                        target_kind: Kind::CurationRule,
                        missing_name: name.clone(),
                    });
                }
            }
        }
    }

    for env in &state.exclusions {
        let policy = &env.spec.policy;
        if !policy.trim().is_empty() && !declared_policies.contains(policy.as_str()) {
            errors.push(ValidationError::DanglingReference {
                referrer_kind: Kind::Exclusion,
                referrer_name: env.metadata.name.clone(),
                field: "spec.policy",
                target_kind: Kind::ScanPolicy,
                missing_name: policy.clone(),
            });
        }
    }
}

// The `push_system_role_errors` helper was removed when the `Role` kind
// was retired (additive-claims model; see ADR 0012). There is no
// `isSystem` flag to mirror against a seed table.

/// Per-policy duplicate exclusion check.
///
/// Per design doc §3.3, exclusion identity is
/// `(cve_id, package_pattern_or_null)` SCOPED to the parent policy.
/// Two exclusions in the same policy with the same `(cve_id, pattern)`
/// is a duplicate; the same pair under two different policies is
/// independent. The standard `metadata.name` duplicate check (above)
/// already catches a globally-duplicated `metadata.name`; this helper
/// catches the more subtle case where two distinct envelope names
/// declare the same exclusion identity within a single policy.
fn push_per_policy_exclusion_duplicates(
    exclusions: &[Envelope<ExclusionSpec>],
    errors: &mut Vec<ValidationError>,
) {
    let mut seen: HashMap<(String, String, Option<String>), &Envelope<ExclusionSpec>> =
        HashMap::new();
    for env in exclusions {
        let key = (
            env.spec.policy.clone(),
            env.spec.cve_id.clone(),
            env.spec.package_pattern.clone(),
        );
        if let Some(prior) = seen.get(&key) {
            // Render the conflicting envelope's name in the detail so
            // the operator can locate both halves.
            errors.push(ValidationError::Invalid {
                kind: Kind::Exclusion,
                name: env.metadata.name.clone(),
                detail: format!(
                    "duplicate exclusion identity (policy=`{}`, cveId=`{}`, packagePattern=`{}`) \
                     also declared by `{}` — exclusions are unique per parent policy",
                    env.spec.policy,
                    env.spec.cve_id,
                    env.spec.package_pattern.as_deref().unwrap_or("<none>"),
                    prior.metadata.name,
                ),
            });
        } else {
            seen.insert(key, env);
        }
    }
}

/// Find every name that appears more than once for `kind`, push a
/// `DuplicateName` error per offender. `source_files` records every
/// path that declared the key — the error lists them all so an
/// operator with five duplicates doesn't have to grep for the rest.
fn push_duplicates<'a, I>(
    kind: Kind,
    names: I,
    source_files: &HashMap<EnvelopeKey, Vec<PathBuf>>,
    errors: &mut Vec<ValidationError>,
) where
    I: IntoIterator<Item = &'a String>,
{
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let names: Vec<&str> = names.into_iter().map(String::as_str).collect();
    for n in &names {
        *counts.entry(*n).or_insert(0) += 1;
    }
    for (name, count) in counts {
        if count <= 1 {
            continue;
        }
        let files = source_files
            .get(&EnvelopeKey {
                kind,
                name: name.to_string(),
            })
            .cloned()
            .unwrap_or_default();
        errors.push(ValidationError::DuplicateName {
            kind,
            name: name.to_string(),
            files,
        });
    }
}

/// Apply-time validation that every `ScanPolicy.scanBackends` entry
/// matches a backend name registered in the live `scanner_registry`.
///
/// `live_backends` is the union of `backends` arrays across every
/// row in `scanner_registry` whose `last_heartbeat` falls inside the
/// 5-minute liveness window. The caller — gitops apply
/// — reads the registry once per apply via
/// [`hort_domain::ports::scanner_registry_repository::ScannerRegistryRepository::list_live`]
/// and flattens the result before invoking this function. We take a
/// `&[String]` rather than the live registry handle so this module
/// stays free of async / port traits and remains a pure validation
/// surface.
///
/// Behaviour:
/// - An empty `scanBackends: []` declaration is **valid** — operators
///   may opt out of scanning entirely. The function never returns an
///   error for an empty list, regardless of `live_backends`.
/// - A non-empty `scanBackends` entry that does not appear in
///   `live_backends` produces one [`ValidationError::Invalid`] per
///   offending value; the error detail names the offending value and
///   the registered names so operators can spot a typo immediately.
/// - **Empty-registry behaviour**: when `live_backends.is_empty()`
///   (no workers ever booted, or every worker's heartbeat is stale),
///   any non-empty `scanBackends` declaration is rejected — apply
///   fails loud rather than silently writing a policy that would
///   never produce findings. The error detail surfaces the empty
///   registered-set so operators see "no live workers" rather than a
///   confusing "got X, expected []" message.
///
/// This function is exposed publicly so the gitops pipeline
/// (`ApplyConfigUseCase::apply`) can invoke it after fetching the
/// live registry snapshot. It is intentionally NOT folded into
/// [`DesiredState::validate_against`] because that signature is
/// snapshot-only; threading the registry through `CurrentSnapshot`
/// would conflate the read-side `ManagedBy=Local` snapshot with the
/// write-side worker-coordination table.
pub fn validate_scan_policy_backends(
    state: &DesiredState,
    live_backends: &[String],
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let live_set: std::collections::HashSet<&str> =
        live_backends.iter().map(String::as_str).collect();

    // Stable, comma-separated list of registered names for the error
    // detail. Sorting keeps the message deterministic across runs so
    // the same misconfiguration produces the same error string.
    let mut sorted_live: Vec<&str> = live_set.iter().copied().collect();
    sorted_live.sort_unstable();
    let registered_summary = if sorted_live.is_empty() {
        "<no live worker registered>".to_string()
    } else {
        sorted_live.join(", ")
    };

    for env in &state.scan_policies {
        for backend in &env.spec.scan_backends {
            if !live_set.contains(backend.as_str()) {
                errors.push(ValidationError::Invalid {
                    kind: Kind::ScanPolicy,
                    name: env.metadata.name.clone(),
                    detail: format!(
                        "spec.scanBackends entry `{backend}` is not a registered scanner \
                         backend (registered: {registered_summary}) — start an \
                         hort-worker advertising `{backend}` or remove the entry"
                    ),
                });
            }
        }
    }

    errors
}

/// Cross-opt-in collapse linter (see ADR 0015 + ADR 0016).
///
/// Rejects every `RepositoryUpstreamMapping` with
/// `trust_upstream_publish_time = true` whose **resolved** `ScanPolicy`
/// has an empty `scan_backends` list. The combination collapses the
/// quarantine Gate-2 observation window: a publish-time-trusted upstream
/// serving an artifact with an attacker-asserted epoch publish-time,
/// governed by a scan-waived policy, releases on
/// `quarantine_until <= now()` alone (observation window shrinks to ≤
/// sweep-tick latency). The release authority
/// `ReleaseAuthorization::ScanWaived` accepts the candidate because no
/// scan needs to complete.
///
/// **Resolution rule.** For each mapping, the owning repository's
/// resolved `ScanPolicy` is:
/// 1. Any policy whose `scope = Repository(owning_repo)`, **else**
/// 2. Any policy whose `scope = Global`, **else**
/// 3. No resolved policy — no rule violation. The
///    `hort_domain::policy::scan::DefaultPolicy` baseline ships
///    `["trivy"]`, so a desired state with no `ScanPolicy` envelopes is
///    not a collapse risk. A future change to the in-code default would
///    be the right place to revisit this branch.
///
/// **Fail-closed.** No escape hatch / override flag. The operator's
/// recourse is to amend the policy (add a backend, even a no-op one) or
/// split the upstream mapping off into its own repo with its own policy.
///
/// Pure function of `DesiredState`; no live registry handle required
/// (mirrors `validate_scan_policy_backends`'s signature shape). The
/// caller is `ApplyConfigUseCase::apply`, which invokes this alongside
/// `validate_scan_policy_backends` after the snapshot-validation stage.
pub fn validate_trust_upstream_publish_time_against_scan_backends(
    state: &DesiredState,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    // Index the desired scan policies by scope kind. The "resolved
    // policy for a repo" follows the same precedence the runtime uses:
    // a `Repository(name)`-scoped policy wins over the `Global` policy.
    // Built once per apply rather than re-scanned per mapping.
    let mut repo_scoped: HashMap<&str, &Envelope<ScanPolicySpec>> = HashMap::new();
    let mut global_policy: Option<&Envelope<ScanPolicySpec>> = None;
    for env in &state.scan_policies {
        match &env.spec.scope {
            crate::scope::ScopeSpec::Repository(r) => {
                // If two policies declare the same repository scope, the
                // duplicate-name / duplicate-scope checks elsewhere will
                // surface that as a separate validation error; here we
                // keep the first-seen entry (stable iteration order) so
                // the linter's behaviour is deterministic regardless of
                // YAML load order.
                repo_scoped.entry(r.repository.as_str()).or_insert(env);
            }
            crate::scope::ScopeSpec::Global => {
                if global_policy.is_none() {
                    global_policy = Some(env);
                }
            }
        }
    }

    for env in &state.upstream_mappings {
        if !env.spec.trust_upstream_publish_time {
            continue;
        }
        let repo_key = env.spec.repository.as_str();
        let resolved = repo_scoped.get(repo_key).copied().or(global_policy);
        let Some(policy) = resolved else {
            // No operator policy applies. The in-code `DefaultPolicy`
            // baseline ships a non-empty `scan_backends`, so the
            // collapse cannot occur. No error.
            continue;
        };
        if policy.spec.scan_backends.is_empty() {
            errors.push(ValidationError::Invalid {
                kind: Kind::UpstreamMapping,
                name: env.metadata.name.clone(),
                detail: format!(
                    "spec.trustUpstreamPublishTime=true combined with the resolved \
                     ScanPolicy `{policy_key}` (scan_backends: []) for repository \
                     `{repo_key}` collapses the quarantine observation window: a \
                     publish-time-trusted upstream `{upstream_url}` serving an \
                     artifact whose claimed publish-time is in the past, governed \
                     by a scan-waived policy, releases on \
                     `quarantine_until <= now()` alone. Amend the policy to set a \
                     non-empty `scanBackends` (re-enabling the scan gate) or split \
                     this upstream mapping off into a repository whose resolved \
                     policy runs a scanner.",
                    policy_key = policy.metadata.name,
                    repo_key = repo_key,
                    upstream_url = env.spec.upstream_url,
                ),
            });
        }
    }

    errors
}

/// Apply-time linter rejecting an inert `PrefetchPolicy.max_age_days`.
///
/// The field is accepted-but-not-enforced today: the prefetch planner
/// has no per-version `published_at` surface to gate against, so a
/// `maxAgeDays: 90` operator pin is silently inert. Accepting a
/// risk-significant field while the consumer silently ignores it is a
/// hard architectural block (see ADR 0015). The field stays in the
/// schema for forward-compat — a future enforcement iteration can ship
/// the per-version timestamp surface and remove the linter rejection.
/// Removing the field now would foreclose the planned enforcement.
///
/// **Fail-closed.** No escape hatch. The operator-actionable error
/// message names the offending `repo_key` and points at the future
/// enforcement initiative; the operator's recourse is to drop the
/// field. Once removed the apply re-runs cleanly.
///
/// Pure function of `DesiredState`; runs alongside
/// [`validate_scan_policy_backends`] and
/// [`validate_trust_upstream_publish_time_against_scan_backends`] after
/// the snapshot-validation stage. One error per offending repository.
pub fn validate_prefetch_max_age_days_not_implemented(
    state: &DesiredState,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for env in &state.repositories {
        if env.spec.prefetch_policy.max_age_days.is_some() {
            errors.push(ValidationError::Invalid {
                kind: Kind::ArtifactRepository,
                name: env.metadata.name.clone(),
                detail: format!(
                    "`prefetchPolicy.maxAgeDays` enforcement is not yet implemented \
                     (the prefetch planner has no per-version published-at surface). \
                     Remove the field to apply. (repository: `{repo_key}`)",
                    repo_key = env.metadata.name,
                ),
            });
        }
    }
    errors
}

/// Every `UpstreamMapping.spec.repository` must resolve to a declared
/// `ArtifactRepository.metadata.name`. The apply pipeline needs the
/// repository_id for the row insert; a dangling reference at
/// validate-time is preferable to a `repository not found` panic at
/// apply-time.
fn push_upstream_mapping_reference_errors(
    state: &DesiredState,
    declared_repos: &std::collections::HashSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    for env in &state.upstream_mappings {
        let repo = &env.spec.repository;
        if !repo.trim().is_empty() && !declared_repos.contains(repo.as_str()) {
            errors.push(ValidationError::DanglingReference {
                referrer_kind: Kind::UpstreamMapping,
                referrer_name: env.metadata.name.clone(),
                field: "spec.repository",
                target_kind: Kind::ArtifactRepository,
                missing_name: repo.clone(),
            });
        }
    }
}

/// `spec.upstreamNamePrefix` is OCI-effective only.
/// A non-OCI repository (npm, PyPI, Cargo, Maven, etc.) carrying the
/// field is rejected at gitops parse time — those format adapters
/// don't consume the field, so silently persisting it would diverge
/// gitops state from runtime behaviour.
///
/// The check runs *after* `push_upstream_mapping_reference_errors`, so
/// a mapping whose `spec.repository` doesn't resolve to a declared
/// `ArtifactRepository` is already reported as `DanglingReference` —
/// this pass treats an unresolved reference as "skip, the dangling-
/// reference error is the operator's actionable fix" rather than
/// emitting two errors for the same root cause.
fn push_upstream_mapping_format_compatibility_errors(
    state: &DesiredState,
    errors: &mut Vec<ValidationError>,
) {
    let repos_by_name: HashMap<&str, &str> = state
        .repositories
        .iter()
        .map(|e| (e.metadata.name.as_str(), e.spec.format.as_str()))
        .collect();

    for env in &state.upstream_mappings {
        let Some(_) = env.spec.upstream_name_prefix.as_ref() else {
            continue;
        };
        let Some(&format) = repos_by_name.get(env.spec.repository.as_str()) else {
            // Dangling reference — already reported by
            // `push_upstream_mapping_reference_errors`. Skip.
            continue;
        };
        if format != "oci" {
            errors.push(ValidationError::Invalid {
                kind: Kind::UpstreamMapping,
                name: env.metadata.name.clone(),
                detail: format!(
                    "spec.upstreamNamePrefix is OCI-effective only; \
                     repository `{}` has format `{format}`. Either remove \
                     the field (no other format adapter consumes it) or \
                     change the repository's format to `oci`.",
                    env.spec.repository
                ),
            });
        }
    }
}

/// Composite-identity duplicate check for upstream mappings.
///
/// The DB diff identity is `(repository, path_prefix)` — two YAML
/// envelopes with different `metadata.name` but the same identity
/// would both attempt to write the same row, succeeding for whichever
/// landed last. Catch the collision at validation time so the operator
/// fixes the YAML rather than discovering surprise behaviour at apply.
///
/// Mirrors `push_per_policy_exclusion_duplicates`: the standard
/// `metadata.name` duplicate check (above) catches name collisions;
/// this catches the more subtle case where two envelopes have distinct
/// names but collapse to the same DB identity.
fn push_upstream_mapping_identity_duplicates(
    mappings: &[Envelope<UpstreamMappingSpec>],
    errors: &mut Vec<ValidationError>,
) {
    let mut seen: HashMap<(String, String), &Envelope<UpstreamMappingSpec>> = HashMap::new();
    for env in mappings {
        let key = (env.spec.repository.clone(), env.spec.path_prefix.clone());
        if let Some(prior) = seen.get(&key) {
            errors.push(ValidationError::Invalid {
                kind: Kind::UpstreamMapping,
                name: env.metadata.name.clone(),
                detail: format!(
                    "duplicate upstream-mapping identity (repository=`{}`, pathPrefix=`{}`) \
                     also declared by `{}` — mappings are unique per (repository, pathPrefix)",
                    env.spec.repository, env.spec.path_prefix, prior.metadata.name,
                ),
            });
        } else {
            seen.insert(key, env);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{CurrentClaimMapping, CurrentRepository};
    use hort_domain::entities::managed_by::ManagedBy;
    use uuid::Uuid;

    fn repo_yaml(name: &str, repo_type: &str, members: Option<&[&str]>) -> Vec<u8> {
        let members_line = match members {
            Some(m) => format!("  virtualMembers: [{}]\n", m.join(", ")),
            None => String::new(),
        };
        let proxy_line = if repo_type == "proxy" {
            "  proxy: { upstreamUrl: https://example.com }\n"
        } else {
            ""
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: {name}
spec:
  name: {name}
  format: npm
  type: {repo_type}
  storage: {{ backend: filesystem, path: /data/{name} }}
{proxy_line}{members_line}  isPublic: true
  replicationPriority: immediate
"
        )
        .into_bytes()
    }

    fn cm_yaml(meta_name: &str, idp_group: &str, claim: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: ClaimMapping
metadata:
  name: {meta_name}
spec:
  idpGroup: {idp_group}
  claim: {claim}
"
        )
        .into_bytes()
    }

    fn legacy_mappings_yaml() -> Vec<u8> {
        b"mappings:
  - group: hort-admins
    role: admin
"
        .to_vec()
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    // -- parse_files --------------------------------------------------------

    #[test]
    fn parse_files_dispatches_by_kind() {
        let files = vec![
            (p("a.yaml"), repo_yaml("a", "hosted", None)),
            (p("admins.yaml"), cm_yaml("admins", "g", "admin")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert_eq!(state.repositories.len(), 1);
        assert_eq!(state.claim_mappings.len(), 1);
        assert_eq!(
            state.source_files[&EnvelopeKey {
                kind: Kind::ArtifactRepository,
                name: "a".into()
            }],
            vec![p("a.yaml")]
        );
    }

    #[test]
    fn parse_files_collects_every_per_file_error() {
        let files = vec![
            (p("good.yaml"), repo_yaml("good", "hosted", None)),
            (p("bad.yaml"), b"not a valid yaml: : :".to_vec()),
            (p("worse.yaml"), b"!@#$%^".to_vec()),
        ];
        let err = DesiredState::parse_files(files).unwrap_err();
        let paths: Vec<&PathBuf> = err.0.iter().map(|(p, _)| p).collect();
        assert!(paths.contains(&&p("bad.yaml")));
        assert!(paths.contains(&&p("worse.yaml")));
        assert!(!paths.contains(&&p("good.yaml")));
    }

    #[test]
    fn parse_files_legacy_mappings_shape_is_rejected() {
        // The `mappings: [...]` multi-object root shape was removed
        // (no kind:, top-level `mappings:` key). Operators must re-emit
        // each entry as a one-envelope-per-file canonical envelope.
        // The canonical IdP-mapping kind is `ClaimMapping`.
        let files = vec![(p("legacy.yaml"), legacy_mappings_yaml())];
        let err = DesiredState::parse_files(files).unwrap_err();
        match &err.0[0].1 {
            ParseError::UnsupportedShape { detected, expected } => {
                assert_eq!(*detected, "mappings");
                assert_eq!(*expected, "one envelope per file");
            }
            other => panic!("expected UnsupportedShape, got {other:?}"),
        }
    }

    #[test]
    fn parse_files_unknown_kind_surfaces_error() {
        let yaml = b"apiVersion: project-hort.de/v1beta1
kind: Bogus
metadata: { name: x }
spec: {}
"
        .to_vec();
        let files = vec![(p("bogus.yaml"), yaml)];
        let err = DesiredState::parse_files(files).unwrap_err();
        assert!(matches!(err.0[0].1, ParseError::UnknownKind { .. }));
    }

    // -- validate -----------------------------------------------------------

    #[test]
    fn validate_catches_duplicate_repository_names_and_lists_every_offending_path() {
        // Drive parse_files end-to-end so `source_files` is populated
        // by the production path. Two files declaring the same name
        // must surface BOTH paths in the DuplicateName error — the
        // single-path regression this test pins is the original
        // review concern (operator should not have to grep for the
        // sibling files).
        let files = vec![
            (p("a.yaml"), repo_yaml("dup", "hosted", None)),
            (p("b.yaml"), repo_yaml("dup", "hosted", None)),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        let dup_err = err
            .0
            .iter()
            .find_map(|e| match e {
                ValidationError::DuplicateName { name, files, .. } if name == "dup" => Some(files),
                _ => None,
            })
            .expect("duplicate-name error must fire");
        assert!(dup_err.contains(&p("a.yaml")), "files list: {dup_err:?}");
        assert!(dup_err.contains(&p("b.yaml")), "files list: {dup_err:?}");
        assert_eq!(
            dup_err.len(),
            2,
            "every duplicate path must be listed, not just the last one absorbed"
        );
    }

    #[test]
    fn validate_catches_dangling_virtual_member() {
        let files = vec![
            (
                p("v.yaml"),
                repo_yaml("v", "virtual", Some(&["a", "ghost"])),
            ),
            (p("a.yaml"), repo_yaml("a", "hosted", None)),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        let dangle = err.0.iter().find(|e| {
            matches!(
                e,
                ValidationError::DanglingVirtualMember {
                    missing_member, ..
                } if missing_member == "ghost"
            )
        });
        assert!(dangle.is_some(), "should fire on `ghost` member: {err:?}");
        // `a` IS in the desired state — it must NOT fire.
        assert!(!err.0.iter().any(|e| matches!(
            e,
            ValidationError::DanglingVirtualMember {
                missing_member, ..
            } if missing_member == "a"
        )));
    }

    #[test]
    fn validate_passes_clean_state() {
        let files = vec![
            (p("a.yaml"), repo_yaml("a", "hosted", None)),
            (p("admins.yaml"), cm_yaml("admins", "g", "admin")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(state.validate().is_ok());
    }

    // -- validate_against ---------------------------------------------------

    fn snapshot_with_local_repo(key: &str) -> CurrentSnapshot {
        CurrentSnapshot {
            repositories: vec![CurrentRepository {
                id: Uuid::new_v4(),
                key: key.into(),
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
            }],
            ..CurrentSnapshot::default()
        }
    }

    fn env(provider: EnvAuthProvider) -> EnvSnapshot {
        EnvSnapshot {
            auth_provider: provider,
        }
    }

    #[test]
    fn validate_against_catches_managed_conflict_on_repository() {
        let files = vec![(p("c.yaml"), repo_yaml("colliding", "hosted", None))];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state
            .validate_against(
                &snapshot_with_local_repo("colliding"),
                &env(EnvAuthProvider::Oidc),
            )
            .unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::ManagedConflict { name, .. } if name == "colliding"
        )));
    }

    #[test]
    fn validate_against_catches_managed_conflict_on_claim_mapping() {
        let files = vec![(p("g.yaml"), cm_yaml("admins", "g", "admin"))];
        let state = DesiredState::parse_files(files).unwrap();
        let snapshot = CurrentSnapshot {
            claim_mappings: vec![CurrentClaimMapping {
                name: "admins".into(),
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
            }],
            ..CurrentSnapshot::default()
        };
        let err = state
            .validate_against(&snapshot, &env(EnvAuthProvider::Oidc))
            .unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::ManagedConflict { kind, name }
                if *kind == Kind::ClaimMapping && name == "admins"
        )));
    }

    #[test]
    fn validate_against_fails_when_auth_disabled_and_mappings_declared() {
        let files = vec![
            (p("a.yaml"), cm_yaml("admins", "g", "admin")),
            (p("r.yaml"), cm_yaml("readers", "g2", "reader")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state
            .validate_against(&CurrentSnapshot::default(), &env(EnvAuthProvider::Disabled))
            .unwrap_err();
        // The variant name (`AuthProviderDisabledWithGroupMappings`)
        // is retained for cross-crate API stability; it fires on
        // `ClaimMapping` declarations.
        let auth_err = err.0.iter().find(|e| {
            matches!(
                e,
                ValidationError::AuthProviderDisabledWithGroupMappings { count, names }
                    if *count == 2
                        && names.contains(&"admins".to_string())
                        && names.contains(&"readers".to_string())
            )
        });
        assert!(auth_err.is_some(), "should fire: {err:?}");
    }

    #[test]
    fn validate_against_passes_when_auth_oidc_with_mappings() {
        let files = vec![(p("a.yaml"), cm_yaml("admins", "g", "admin"))];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(state
            .validate_against(&CurrentSnapshot::default(), &env(EnvAuthProvider::Oidc))
            .is_ok());
    }

    #[test]
    fn validate_against_aggregates_validate_errors() {
        // A bad spec should NOT short-circuit the snapshot/env checks
        // — operators want every applicable error in one boot pass.
        let mut state = DesiredState::default();
        state
            .repositories
            .push(serde_yaml_ng::from_slice(&repo_yaml("ok", "hosted", None)).unwrap());
        state
            .claim_mappings
            .push(serde_yaml_ng::from_slice(&cm_yaml("admins", "g", "admin")).unwrap());
        let err = state
            .validate_against(&CurrentSnapshot::default(), &env(EnvAuthProvider::Disabled))
            .unwrap_err();
        // The `ok` repo plus a single mapping under `Disabled` →
        // exactly one validation error (the auth one).
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::AuthProviderDisabledWithGroupMappings { .. }
        )));
    }

    // ===================================================================
    // Cross-doc validation rules
    // ===================================================================

    /// A `Claims`-subject `PermissionGrant` envelope.
    /// `claim` is wrapped in a single-element required set.
    fn pg_yaml(name: &str, claim: &str, permission: &str, repository: Option<&str>) -> Vec<u8> {
        let repo_line = match repository {
            Some(r) => format!("  repository: {r}\n"),
            None => String::new(),
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: {name}
spec:
  subject: {{ kind: claims, required: [{claim}] }}
  permission: {permission}
{repo_line}"
        )
        .into_bytes()
    }

    fn cr_yaml(name: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: CurationRule
metadata:
  name: {name}
spec:
  format: any
  pattern: \"x*\"
  action: block
  reason: test
"
        )
        .into_bytes()
    }

    fn sp_yaml(name: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: {name}
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  licensePolicy: {{}}
"
        )
        .into_bytes()
    }

    fn ex_yaml(name: &str, policy: &str, cve_id: &str, package_pattern: Option<&str>) -> Vec<u8> {
        let pattern_line = match package_pattern {
            Some(p) => format!("  packagePattern: \"{p}\"\n"),
            None => String::new(),
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: Exclusion
metadata:
  name: {name}
spec:
  policy: {policy}
  cveId: {cve_id}
  scope: global
  reason: test
{pattern_line}"
        )
        .into_bytes()
    }

    /// Helper that wraps a `RepositorySpec` body with `curationRules`
    /// declared. The base `repo_yaml` helper above doesn't expose
    /// curation references; this builds one inline.
    fn repo_yaml_with_curation_rules(name: &str, rules: &[&str]) -> Vec<u8> {
        let rules_line = if rules.is_empty() {
            String::new()
        } else {
            format!("  curationRules: [{}]\n", rules.join(", "))
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: {name}
spec:
  name: {name}
  format: npm
  type: hosted
  storage: {{ backend: filesystem, path: /data/{name} }}
  isPublic: true
  replicationPriority: immediate
{rules_line}"
        )
        .into_bytes()
    }

    // -- duplicate-name detection per kind ---------------------------------

    #[test]
    fn validate_catches_duplicate_claim_mapping_names() {
        let files = vec![
            (p("a.yaml"), cm_yaml("dup", "g1", "developer")),
            (p("b.yaml"), cm_yaml("dup", "g2", "reader")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DuplicateName { kind: Kind::ClaimMapping, name, .. } if name == "dup"
        )));
    }

    #[test]
    fn validate_catches_duplicate_curation_rule_names() {
        let files = vec![
            (p("a.yaml"), cr_yaml("rule")),
            (p("b.yaml"), cr_yaml("rule")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DuplicateName { kind: Kind::CurationRule, name, .. } if name == "rule"
        )));
    }

    #[test]
    fn validate_catches_duplicate_scan_policy_names() {
        let files = vec![
            (p("a.yaml"), sp_yaml("dup-policy")),
            (p("b.yaml"), sp_yaml("dup-policy")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DuplicateName {
                kind: Kind::ScanPolicy,
                ..
            }
        )));
    }

    // -- exclusion duplicate identity rules --------------------------------

    #[test]
    fn validate_catches_duplicate_exclusion_within_same_policy() {
        // Two exclusions with the same `(policy, cveId, packagePattern)`
        // — distinct envelope names but identical identity. The
        // per-policy uniqueness rule must fire.
        let files = vec![
            (p("p.yaml"), sp_yaml("p")),
            (p("a.yaml"), ex_yaml("ex-a", "p", "CVE-1", Some("xz*"))),
            (p("b.yaml"), ex_yaml("ex-b", "p", "CVE-1", Some("xz*"))),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| {
            let s = e.to_string();
            s.contains("duplicate exclusion identity") && s.contains("CVE-1")
        }));
    }

    #[test]
    fn validate_allows_same_exclusion_across_different_policies() {
        // Identity is per-policy: `(p1, CVE-1, x)` and `(p2, CVE-1, x)`
        // are independent exclusions — operators may declare the same
        // CVE-pattern under multiple parent policies without conflict.
        let files = vec![
            (p("p1.yaml"), sp_yaml("p1")),
            (p("p2.yaml"), sp_yaml("p2")),
            (p("a.yaml"), ex_yaml("ex-on-p1", "p1", "CVE-1", Some("xz*"))),
            (p("b.yaml"), ex_yaml("ex-on-p2", "p2", "CVE-1", Some("xz*"))),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(
            state.validate().is_ok(),
            "exclusion identity is per-policy — same (cve, pattern) under \
             different policies must be accepted"
        );
    }

    // -- dangling reference detection --------------------------------------

    #[test]
    fn validate_accepts_permission_grant_with_no_repository_reference() {
        // The `PermissionGrant.role` cross-doc reference was removed when
        // the `Role` kind was retired (additive-claims model). A
        // claims-subject global grant has no resolvable cross-doc
        // reference at all and must validate cleanly.
        let files = vec![(p("g.yaml"), pg_yaml("g", "developer", "read", None))];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(
            state.validate().is_ok(),
            "a claims-subject grant has no role reference to dangle"
        );
    }

    #[test]
    fn validate_catches_dangling_permission_grant_repository_reference() {
        // The only remaining cross-doc reference on a grant is
        // `spec.repository` → declared `ArtifactRepository`.
        let files = vec![(
            p("g.yaml"),
            pg_yaml("g", "developer", "read", Some("ghost-repo")),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DanglingReference {
                referrer_kind: Kind::PermissionGrant,
                target_kind: Kind::ArtifactRepository,
                field,
                missing_name, ..
            } if missing_name == "ghost-repo" && *field == "spec.repository"
        )));
    }

    #[test]
    fn validate_accepts_permission_grant_with_resolved_repository() {
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-public", "hosted", None)),
            (
                p("g.yaml"),
                pg_yaml("g", "developer", "read", Some("npm-public")),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(state.validate().is_ok());
    }

    #[test]
    fn validate_catches_invalid_permission_string_on_grant() {
        // Per-spec validation rejects an unparseable `permission`.
        let files = vec![(p("g.yaml"), pg_yaml("g", "developer", "publish", None))];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::UnknownEnumValue { field, got, .. }
                if *field == "spec.permission" && got == "publish"
        )));
    }

    #[test]
    fn validate_catches_dangling_curation_rule_reference_from_repo() {
        let files = vec![(
            p("repo.yaml"),
            repo_yaml_with_curation_rules("npm-public", &["block-cve-2024-3094"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DanglingReference {
                referrer_kind: Kind::ArtifactRepository,
                target_kind: Kind::CurationRule,
                missing_name, ..
            } if missing_name == "block-cve-2024-3094"
        )));
    }

    #[test]
    fn validate_accepts_repo_with_resolved_curation_rule_reference() {
        let files = vec![
            (p("rule.yaml"), cr_yaml("block-cve-2024-3094")),
            (
                p("repo.yaml"),
                repo_yaml_with_curation_rules("npm-public", &["block-cve-2024-3094"]),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(state.validate().is_ok());
    }

    #[test]
    fn validate_catches_dangling_exclusion_policy_reference() {
        let files = vec![(
            p("ex.yaml"),
            ex_yaml("orphan-ex", "ghost-policy", "CVE-1", None),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DanglingReference {
                referrer_kind: Kind::Exclusion,
                target_kind: Kind::ScanPolicy,
                missing_name, ..
            } if missing_name == "ghost-policy"
        )));
    }

    #[test]
    fn validate_accepts_exclusion_with_resolved_policy_reference() {
        let files = vec![
            (p("p.yaml"), sp_yaml("prod-default")),
            (p("ex.yaml"), ex_yaml("ex-1", "prod-default", "CVE-1", None)),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(state.validate().is_ok());
    }

    // The system-role-protection tests were removed when the `Role` kind
    // was retired (additive-claims model); the `isSystem` seed-mirror
    // rule no longer exists.

    // -- parse_files dispatch covers the additive-claims CRUD kinds ------

    #[test]
    fn parse_files_dispatches_additive_claims_kinds() {
        let files = vec![
            (p("mapping.yaml"), cm_yaml("admins", "grp", "admin")),
            (p("grant.yaml"), pg_yaml("g", "admin", "read", None)),
            (p("rule.yaml"), cr_yaml("rule")),
            (p("policy.yaml"), sp_yaml("p")),
            (p("ex.yaml"), ex_yaml("ex", "p", "CVE-1", None)),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert_eq!(state.claim_mappings.len(), 1);
        assert_eq!(state.permission_grants.len(), 1);
        assert_eq!(state.curation_rules.len(), 1);
        assert_eq!(state.scan_policies.len(), 1);
        assert_eq!(state.exclusions.len(), 1);
        // The full graph is consistent — should validate clean.
        assert!(state.validate().is_ok());
    }

    // ===================================================================
    // validate_scan_policy_backends
    // ===================================================================

    /// Build a `ScanPolicy` YAML with an explicit `scanBackends` list.
    /// Mirrors `sp_yaml` (which omits the field, exercising the default
    /// path) so the apply-time validation tests can drive specific
    /// values into the cross-spec check.
    fn sp_yaml_with_backends(name: &str, backends: &[&str]) -> Vec<u8> {
        let backend_line = if backends.is_empty() {
            "  scanBackends: []\n".to_string()
        } else {
            format!("  scanBackends: [{}]\n", backends.join(", "))
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: {name}
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
{backend_line}  licensePolicy: {{}}
"
        )
        .into_bytes()
    }

    #[test]
    fn validate_scan_policy_backends_accepts_known_backend() {
        let files = vec![(
            p("p.yaml"),
            sp_yaml_with_backends("strict", &["trivy", "osv"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let live = vec!["trivy".to_string(), "osv".to_string()];
        let errors = validate_scan_policy_backends(&state, &live);
        assert!(
            errors.is_empty(),
            "every entry resolves against the live registry: {errors:?}"
        );
    }

    #[test]
    fn validate_scan_policy_backends_rejects_unknown_backend_with_descriptive_message() {
        let files = vec![(
            p("p.yaml"),
            sp_yaml_with_backends("strict", &["trivy", "ghost"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let live = vec!["trivy".to_string(), "osv".to_string()];
        let errors = validate_scan_policy_backends(&state, &live);
        assert_eq!(errors.len(), 1);
        let detail = errors[0].to_string();
        assert!(
            detail.contains("`ghost`"),
            "error must name the offending entry: {detail}"
        );
        // Both registered backends must surface so the operator can
        // spot a typo immediately.
        assert!(
            detail.contains("trivy"),
            "error must list registered backends: {detail}"
        );
        assert!(
            detail.contains("osv"),
            "error must list registered backends: {detail}"
        );
        assert!(
            detail.contains("scanBackends"),
            "error must surface the field name: {detail}"
        );
    }

    #[test]
    fn validate_scan_policy_backends_empty_list_is_valid_under_any_registry() {
        // Empty list = "operator opted out of scanning". Must not
        // surface an error regardless of what's in the registry.
        let files = vec![(p("p.yaml"), sp_yaml_with_backends("noscan", &[]))];
        let state = DesiredState::parse_files(files).unwrap();
        // With backends registered:
        assert!(validate_scan_policy_backends(&state, &["trivy".into()]).is_empty());
        // With no backends registered:
        assert!(validate_scan_policy_backends(&state, &[]).is_empty());
    }

    #[test]
    fn validate_scan_policy_backends_empty_registry_rejects_non_empty_declaration() {
        // Empty registry but non-empty `scanBackends:` declaration —
        // apply must fail loud rather than silently writing a policy
        // that would never produce findings.
        let files = vec![(p("p.yaml"), sp_yaml_with_backends("strict", &["trivy"]))];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_scan_policy_backends(&state, &[]);
        assert_eq!(errors.len(), 1);
        let detail = errors[0].to_string();
        // The "no live worker" sentinel must surface so operators
        // diagnose missing workers rather than chasing a typo.
        assert!(
            detail.contains("no live worker"),
            "error must mention that no live workers are registered: {detail}"
        );
    }

    #[test]
    fn validate_scan_policy_backends_aggregates_one_error_per_offender() {
        let files = vec![(
            p("p.yaml"),
            sp_yaml_with_backends("multi-bad", &["ghost-a", "ghost-b", "trivy"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let live = vec!["trivy".to_string()];
        let errors = validate_scan_policy_backends(&state, &live);
        assert_eq!(
            errors.len(),
            2,
            "one error per offending entry, not one per envelope"
        );
        let combined = errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" || ");
        assert!(combined.contains("`ghost-a`"));
        assert!(combined.contains("`ghost-b`"));
    }

    #[test]
    fn validate_scan_policy_backends_default_yaml_resolves_against_default_registry() {
        // The minimal `sp_yaml` (no scanBackends key) defaults to
        // `["trivy"]`. With a live worker advertising `trivy`, the
        // policy must validate — proving the default + happy path
        // hook up correctly.
        let files = vec![(p("p.yaml"), sp_yaml("default-backends"))];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_scan_policy_backends(&state, &["trivy".to_string()]);
        assert!(
            errors.is_empty(),
            "default scanBackends must validate against a trivy-only registry: {errors:?}"
        );
    }

    // -------------------------------------------------------------------
    // validate_trust_upstream_publish_time_against_scan_backends
    // -------------------------------------------------------------------

    /// Build a `ScanPolicy` YAML with explicit scope + scan_backends.
    /// `scope` is either `global` or a `{repository: <name>}` mapping.
    fn sp_yaml_with_scope_and_backends(name: &str, scope_yaml: &str, backends: &[&str]) -> Vec<u8> {
        let backend_line = if backends.is_empty() {
            "  scanBackends: []\n".to_string()
        } else {
            format!("  scanBackends: [{}]\n", backends.join(", "))
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: {name}
spec:
  scope: {scope_yaml}
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
{backend_line}  licensePolicy: {{}}
"
        )
        .into_bytes()
    }

    /// Build an `UpstreamMapping` YAML with `trustUpstreamPublishTime`
    /// either set or omitted.
    fn um_yaml_with_trust_pt(
        meta_name: &str,
        repository: &str,
        upstream_url: &str,
        trust_publish_time: bool,
    ) -> Vec<u8> {
        let trust_line = if trust_publish_time {
            "  trustUpstreamPublishTime: true\n"
        } else {
            ""
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: UpstreamMapping
metadata:
  name: {meta_name}
spec:
  repository: {repository}
  pathPrefix: ''
  upstreamUrl: {upstream_url}
{trust_line}  auth:
    type: anonymous
"
        )
        .into_bytes()
    }

    #[test]
    fn validate_trust_upstream_publish_time_accepts_default_off_combination() {
        // `trustUpstreamPublishTime` defaults to false — the linter
        // never fires regardless of policy backends.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-public", "proxy", None)),
            (
                p("policy.yaml"),
                sp_yaml_with_scope_and_backends("p1", "global", &[]),
            ),
            (
                p("um.yaml"),
                um_yaml_with_trust_pt("npm-up", "npm-public", "https://registry.npmjs.org", false),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_trust_upstream_publish_time_against_scan_backends(&state);
        assert!(
            errors.is_empty(),
            "linter must not fire when trust_upstream_publish_time=false: {errors:?}"
        );
    }

    #[test]
    fn validate_trust_upstream_publish_time_rejects_global_scan_waived_combination() {
        // The global policy waives scanning AND the mapping opts into
        // publish-time anchoring → reject.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-public", "proxy", None)),
            (
                p("policy.yaml"),
                sp_yaml_with_scope_and_backends("global-waiver", "global", &[]),
            ),
            (
                p("um.yaml"),
                um_yaml_with_trust_pt("npm-up", "npm-public", "https://registry.npmjs.org", true),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_trust_upstream_publish_time_against_scan_backends(&state);
        assert_eq!(errors.len(), 1, "expected one rejection: {errors:?}");
        let detail = errors[0].to_string();
        assert!(detail.contains("npm-public"), "names repo: {detail}");
        assert!(
            detail.contains("https://registry.npmjs.org"),
            "names upstream URL: {detail}"
        );
        assert!(detail.contains("global-waiver"), "names policy: {detail}");
    }

    #[test]
    fn validate_trust_upstream_publish_time_repo_scoped_policy_wins_over_global() {
        // A repo-scoped policy with a non-empty scan_backends overrides
        // a global policy that waives scanning. The linter resolves the
        // narrower policy → no rejection.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-public", "proxy", None)),
            (
                p("global.yaml"),
                sp_yaml_with_scope_and_backends("global-waiver", "global", &[]),
            ),
            (
                p("scoped.yaml"),
                sp_yaml_with_scope_and_backends(
                    "scoped-trivy",
                    "{ repository: npm-public }",
                    &["trivy"],
                ),
            ),
            (
                p("um.yaml"),
                um_yaml_with_trust_pt("npm-up", "npm-public", "https://registry.npmjs.org", true),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_trust_upstream_publish_time_against_scan_backends(&state);
        assert!(
            errors.is_empty(),
            "scoped policy with scanner running must override global waiver: {errors:?}"
        );
    }

    #[test]
    fn validate_trust_upstream_publish_time_rejects_repo_scoped_scan_waiver() {
        // Repo-scoped scan_backends=[] is the offending policy even
        // when a global non-waived policy exists — the repo-scoped
        // entry wins resolution.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-public", "proxy", None)),
            (
                p("global.yaml"),
                sp_yaml_with_scope_and_backends("global-trivy", "global", &["trivy"]),
            ),
            (
                p("scoped.yaml"),
                sp_yaml_with_scope_and_backends("scoped-waiver", "{ repository: npm-public }", &[]),
            ),
            (
                p("um.yaml"),
                um_yaml_with_trust_pt("npm-up", "npm-public", "https://registry.npmjs.org", true),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_trust_upstream_publish_time_against_scan_backends(&state);
        assert_eq!(errors.len(), 1, "expected one rejection: {errors:?}");
        let detail = errors[0].to_string();
        assert!(
            detail.contains("scoped-waiver"),
            "names the resolved (scoped) policy, not the global: {detail}"
        );
    }

    #[test]
    fn validate_trust_upstream_publish_time_no_policy_no_rejection() {
        // No `ScanPolicy` envelope at all → the in-code `DefaultPolicy`
        // baseline (non-empty scan_backends) applies; the linter has
        // no operator policy to flag.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-public", "proxy", None)),
            (
                p("um.yaml"),
                um_yaml_with_trust_pt("npm-up", "npm-public", "https://registry.npmjs.org", true),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_trust_upstream_publish_time_against_scan_backends(&state);
        assert!(
            errors.is_empty(),
            "no operator policy → DefaultPolicy applies, no rejection: {errors:?}"
        );
    }

    // -- Cross-format reject for upstreamNamePrefix --------------------
    //
    // The field is OCI-effective only. A non-OCI repository (npm,
    // PyPI, Cargo, Maven, etc.) declaring `upstreamNamePrefix: ...` is
    // an operator error — those format adapters don't consume the
    // field, so silently persisting it would diverge gitops state from
    // runtime behaviour.

    fn repo_yaml_with_format(name: &str, format: &str, repo_type: &str) -> Vec<u8> {
        let proxy_line = if repo_type == "proxy" {
            "  proxy: { upstreamUrl: https://example.com }\n"
        } else {
            ""
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: {name}
spec:
  name: {name}
  format: {format}
  type: {repo_type}
  storage: {{ backend: filesystem, path: /data/{name} }}
{proxy_line}  isPublic: true
  replicationPriority: immediate
"
        )
        .into_bytes()
    }

    // ===================================================================
    // OidcIssuer + ServiceAccount round-trip
    // ===================================================================

    fn oidc_yaml(name: &str, url: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: OidcIssuer
metadata:
  name: {name}
spec:
  issuerUrl: {url}
  audiences: [hort-server]
"
        )
        .into_bytes()
    }

    fn um_yaml_with_prefix(meta_name: &str, repository: &str, prefix: Option<&str>) -> Vec<u8> {
        let prefix_line = match prefix {
            Some(p) => format!("  upstreamNamePrefix: {p}\n"),
            None => String::new(),
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: UpstreamMapping
metadata:
  name: {meta_name}
spec:
  repository: {repository}
  pathPrefix: ''
  upstreamUrl: https://zot.example.com
{prefix_line}  auth:
    type: anonymous
"
        )
        .into_bytes()
    }

    fn sa_yaml(name: &str, repo: &str, issuer: Option<&str>) -> Vec<u8> {
        let federated = match issuer {
            None => String::new(),
            Some(i) => format!(
                "  federatedIdentities:
    - issuer: {i}
      claims:
        repository: my-org/my-repo
"
            ),
        };
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: {name}
spec:
  role: developer
  repositories: [{repo}]
{federated}"
        )
        .into_bytes()
    }

    #[test]
    fn validate_rejects_upstream_name_prefix_on_non_oci_repository() {
        // npm repo + the field set → must reject with both
        // upstreamNamePrefix and the actual format named in the error.
        let files = vec![
            (
                p("repo.yaml"),
                repo_yaml_with_format("npm-mirror", "npm", "proxy"),
            ),
            (
                p("mapping.yaml"),
                um_yaml_with_prefix("npm-um", "npm-mirror", Some("docker.io")),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().expect_err("npm + field must be rejected");
        let msgs: Vec<String> = err.0.iter().map(ToString::to_string).collect();
        let combined = msgs.join("\n");
        assert!(
            combined.contains("upstreamNamePrefix"),
            "error must name the offending field; got `{combined}`"
        );
        assert!(
            combined.contains("npm"),
            "error must name the actual repository format; got `{combined}`"
        );
    }

    #[test]
    fn validate_accepts_upstream_name_prefix_on_oci_repository() {
        let files = vec![
            (
                p("repo.yaml"),
                repo_yaml_with_format("oci-mirror", "oci", "proxy"),
            ),
            (
                p("mapping.yaml"),
                um_yaml_with_prefix("oci-um", "oci-mirror", Some("docker.io")),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        state.validate().expect("oci + field must validate clean");
    }

    #[test]
    fn validate_accepts_non_oci_repository_without_upstream_name_prefix() {
        // npm repo + the field absent → must accept (back-compat with
        // existing non-OCI mappings).
        let files = vec![
            (
                p("repo.yaml"),
                repo_yaml_with_format("npm-mirror", "npm", "proxy"),
            ),
            (
                p("mapping.yaml"),
                um_yaml_with_prefix("npm-um", "npm-mirror", None),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        state
            .validate()
            .expect("npm + no field must validate clean (back-compat)");
    }

    #[test]
    fn parse_files_dispatches_oidc_issuer_and_service_account() {
        let files = vec![
            (
                p("issuer.yaml"),
                oidc_yaml("github-actions", "https://example.com"),
            ),
            (p("sa.yaml"), sa_yaml("ci-pusher", "pypi-internal", None)),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert_eq!(state.oidc_issuers.len(), 1);
        assert_eq!(state.service_accounts.len(), 1);
        assert_eq!(state.oidc_issuers[0].metadata.name, "github-actions");
        assert_eq!(state.service_accounts[0].metadata.name, "ci-pusher");
    }

    #[test]
    fn fixture_round_trip_parse_validate_diff_with_machine_identity_kinds() {
        // End-to-end fixture: parse → validate → diff with a mix of
        // existing kinds (Repository, PermissionGrant) and the two
        // machine-identity kinds (OidcIssuer, ServiceAccount). The
        // fixture must validate clean and produce a create-only
        // ApplyPlan (no current snapshot).
        let files = vec![
            (p("repo.yaml"), repo_yaml("pypi-internal", "hosted", None)),
            (
                p("issuer.yaml"),
                oidc_yaml(
                    "github-actions",
                    "https://token.actions.githubusercontent.com",
                ),
            ),
            (
                p("sa.yaml"),
                sa_yaml("ci-pypi-pusher", "pypi-internal", Some("github-actions")),
            ),
            (
                p("grant.yaml"),
                pg_yaml("dev-read-pypi", "admin", "read", Some("pypi-internal")),
            ),
        ];
        let state = DesiredState::parse_files(files).expect("parse");
        state.validate().expect("validate");

        let plan = crate::diff::diff(&CurrentSnapshot::default(), &state);
        // Every kind we declared has at least one create entry.
        assert_eq!(plan.repositories.create.len(), 1);
        assert_eq!(plan.oidc_issuers.create.len(), 1);
        assert_eq!(plan.service_accounts.create.len(), 1);
        assert_eq!(plan.permission_grants.create.len(), 1);
    }

    #[test]
    fn validate_catches_duplicate_oidc_issuer_names() {
        let files = vec![
            (p("a.yaml"), oidc_yaml("dup", "https://a.example.com")),
            (p("b.yaml"), oidc_yaml("dup", "https://b.example.com")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DuplicateName { kind: Kind::OidcIssuer, name, .. } if name == "dup"
        )));
    }

    #[test]
    fn validate_catches_duplicate_service_account_names() {
        let files = vec![
            (p("a.yaml"), sa_yaml("dup", "r", None)),
            (p("b.yaml"), sa_yaml("dup", "r", None)),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DuplicateName { kind: Kind::ServiceAccount, name, .. } if name == "dup"
        )));
    }

    // -- PermissionGrantLintConfig (singleton) ------------------------------

    fn lint_yaml(name: &str, body: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1beta1
kind: PermissionGrantLintConfig
metadata:
  name: {name}
spec:{body}"
        )
        .into_bytes()
    }

    #[test]
    fn parse_files_dispatches_lint_config_singleton() {
        let files = vec![(
            p("lint.yaml"),
            lint_yaml("linter", "\n  singleClaimAllowlist: [team-alpha]\n"),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let env = state.lint_config.as_ref().expect("lint_config absorbed");
        assert_eq!(env.metadata.name, "linter");
        assert_eq!(env.spec.single_claim_allowlist, vec!["team-alpha"]);
        state
            .validate()
            .expect("a single valid lint config validates");
    }

    #[test]
    fn validate_rejects_more_than_one_lint_config_envelope() {
        // Singleton: two PermissionGrantLintConfig envelopes produces a
        // named SingletonConflict listing every file — never a silent
        // last-wins.
        let files = vec![
            (p("a.yaml"), lint_yaml("first", " {}")),
            (p("b.yaml"), lint_yaml("second", " {}")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        let conflict = err
            .0
            .iter()
            .find_map(|e| match e {
                ValidationError::SingletonConflict {
                    kind: Kind::PermissionGrantLintConfig,
                    count,
                    files,
                } => Some((*count, files.clone())),
                _ => None,
            })
            .expect("expected a SingletonConflict error");
        assert_eq!(conflict.0, 2);
        let rendered = err.to_string();
        assert!(rendered.contains("a.yaml"));
        assert!(rendered.contains("b.yaml"));
    }

    #[test]
    fn validate_propagates_lint_config_per_spec_errors() {
        // A reserved allowlist entry must surface through DesiredState
        // (per-spec validation is dispatched, not only the singleton
        // count).
        let files = vec![(
            p("lint.yaml"),
            lint_yaml("linter", "\n  singleClaimAllowlist: [admin]\n"),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::Invalid {
                kind: Kind::PermissionGrantLintConfig,
                ..
            }
        )));
    }

    #[test]
    fn absent_lint_config_is_none_and_validates() {
        // A bundle with no PermissionGrantLintConfig is valid; the
        // Option stays None and the apply layer uses the secure default.
        let files = vec![(p("repo.yaml"), repo_yaml("r", "hosted", None))];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(state.lint_config.is_none());
        state.validate().expect("absent lint config is fine");
    }

    #[test]
    fn parse_files_routes_unknown_kind_and_lists_known_kinds() {
        let yaml = b"apiVersion: project-hort.de/v1beta1
kind: Bogus
metadata: { name: x }
spec: {}
"
        .to_vec();
        let files = vec![(p("bogus.yaml"), yaml)];
        let err = DesiredState::parse_files(files).unwrap_err();
        match &err.0[0].1 {
            ParseError::UnknownKind { valid, .. } => {
                assert!(valid.contains(&"ClaimMapping"));
                assert!(valid.contains(&"PermissionGrant"));
                assert!(valid.contains(&"CurationRule"));
                assert!(valid.contains(&"ScanPolicy"));
                assert!(valid.contains(&"Exclusion"));
                assert!(valid.contains(&"PermissionGrantLintConfig"));
                assert!(!valid.contains(&"Role"));
                assert!(!valid.contains(&"GroupMapping"));
            }
            other => panic!("expected UnknownKind, got {other:?}"),
        }
    }
}
