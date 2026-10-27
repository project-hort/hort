//! `DesiredState` — the parsed-and-validated set of objects from
//! `$HORT_CONFIG_DIR`. `ApplyConfigUseCase` consumes this.
//!
//! Two validation entry points:
//! - `validate()` — environment-agnostic rules (per-spec validation,
//!   plus duplicate-name and cross-spec virtual-member resolution).
//!   Pure-static — unit tests don't need a snapshot.
//! - `validate_against(snapshot, env)` — adds the snapshot- and
//!   env-aware rules: managed conflicts (a desired entry collides
//!   with a current `Local` row) and the rule
//!   "HORT_AUTH_PROVIDER=disabled but ClaimMapping declared = fatal".
//!
//! Both collect every error before returning — operators want one
//! complete list per boot pass, not first-error-wins.

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use hort_domain::entities::scan_policy::CompositeVerdictMode;
use hort_domain::retention::PolicyPredicate;

use crate::claim_mapping::{parse_claim_mapping, ClaimMappingSpec};
use crate::curation_rule::{parse_curation_rule, validate_curation_rule, CurationRuleSpec};
use crate::diff::CurrentSnapshot;
use crate::envelope::{Envelope, Kind};
use crate::error::{ParseError, ParseErrors, ValidationError, ValidationErrors};
use crate::exclusion::{parse_exclusion, validate_exclusion, ExclusionSpec};
use crate::lint_config::{parse_lint_config, validate_lint_config, PermissionGrantLintConfigSpec};
use crate::oidc_issuer::{parse_oidc_issuer, validate_oidc_issuer, OidcIssuerSpec};
use crate::permission_grant::{
    parse_permission_grant, validate_permission_grant, GrantSubjectSpec, PermissionGrantSpec,
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
                // named `SingletonConflict` (never a silent last-wins).
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
        // Name → declared `spec.type` string, so a member reference can
        // be resolved to the referenced repo's type for the
        // no-nested-virtuals rule below. This is the cross-spec
        // resolution the per-spec validator cannot do (it sees one
        // envelope at a time). `from_str` failures are ignored here — an
        // unknown `spec.type` on the member is already reported by that
        // member's own per-spec `validate_repository` pass.
        let declared_repo_types: HashMap<&str, &str> = self
            .repositories
            .iter()
            .map(|e| (e.metadata.name.as_str(), e.spec.repo_type.as_str()))
            .collect();
        for env in &self.repositories {
            if let Some(members) = env.spec.virtual_members.as_ref() {
                for member in members {
                    if !declared_repos.contains(member.as_str()) {
                        errors.push(ValidationError::DanglingVirtualMember {
                            virtual_repo: env.metadata.name.clone(),
                            missing_member: member.clone(),
                        });
                        continue;
                    }
                    // No nested virtuals (ADR 0031 rule 5, spec §7.5):
                    // a member that is itself `type: virtual` would force
                    // recursive resolution; v1 keeps resolution a single
                    // flat priority list, so reject at apply. Resolved
                    // cross-spec: the member is another declared
                    // `ArtifactRepository` whose type we look up here.
                    if let Some(member_type) = declared_repo_types.get(member.as_str()) {
                        use hort_domain::entities::repository::RepositoryType;
                        if matches!(
                            RepositoryType::from_str(member_type),
                            Ok(RepositoryType::Virtual)
                        ) {
                            errors.push(ValidationError::Invalid {
                                kind: Kind::ArtifactRepository,
                                name: env.metadata.name.clone(),
                                detail: format!(
                                    "virtualMembers entry `{member}` is itself \
                                     type=virtual — nested virtual repositories are \
                                     not supported; a member must be a non-virtual \
                                     repository (see ADR 0031)"
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Cross-doc reference rules. Roles are no longer a gitops kind
        // so there is no system-role protection rule to enforce.
        push_init14_reference_errors(self, &declared_repos, &mut errors);
        push_per_policy_exclusion_duplicates(&self.exclusions, &mut errors);
        push_scan_policy_scope_duplicates(&self.scan_policies, &mut errors);
        push_scan_policy_scope_reference_errors(self, &declared_repos, &mut errors);
        push_retention_policy_scope_reference_errors(self, &declared_repos, &mut errors);
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
    // Peek at the raw YAML to decide which parser to invoke. Untyped
    // because the envelope's `spec` shape is exactly what is not known
    // yet; `serde_json::Value` is the crate's one untyped target.
    let raw: serde_json::Value = crate::yaml::from_slice(bytes)?;
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
    let declared_service_accounts: std::collections::HashSet<&str> = state
        .service_accounts
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
        // A `serviceAccount` subject must name a declared
        // `ServiceAccount` — same cross-spec resolution shape as the
        // `spec.repository` reference above (the per-spec validator sees
        // one envelope at a time and cannot resolve it). The apply
        // pipeline resolves the name to the SA's backing-user UUID; a
        // dangling name would mint nothing, so reject at apply.
        if let GrantSubjectSpec::ServiceAccount { name } = &env.spec.subject {
            if !name.trim().is_empty() && !declared_service_accounts.contains(name.as_str()) {
                errors.push(ValidationError::DanglingReference {
                    referrer_kind: Kind::PermissionGrant,
                    referrer_name: env.metadata.name.clone(),
                    field: "spec.subject.name",
                    target_kind: Kind::ServiceAccount,
                    missing_name: name.clone(),
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
/// Exclusion identity is `(cve_id, package_pattern_or_null)` SCOPED to
/// the parent policy.
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

/// Apply-time validation that every `ScanPolicy.scanBackends` entry names a
/// scanner backend this build actually supports.
///
/// `valid_backends` is the set of backend names the caller considers valid.
/// The gitops apply pipeline passes the **compiled-in** capability set
/// (`hort_app::scanning::KNOWN_SCAN_BACKENDS`) — NOT a live `scanner_registry`
/// snapshot. Validating a *name* against the live worker registry was a
/// boot-ordering hazard (regression **H20**): on a fresh deployment the apply
/// runs before any worker has registered, so the live set is transiently
/// empty and a correct `scanBackends: [trivy]` policy was rejected
/// fail-closed, parking the server with no retry. A backend name is valid or
/// not as a permanent property of the build, independent of worker-liveness
/// timing; whether a worker advertising it is *running* is a runtime-liveness
/// concern for metrics/health, not a config-validity error. We take a
/// `&[String]` rather than any port handle so this module stays free of
/// async / port traits and remains a pure validation surface.
///
/// Behaviour:
/// - An empty `scanBackends: []` declaration is **valid** — operators
///   may opt out of scanning entirely. The function never returns an
///   error for an empty list, regardless of `valid_backends`.
/// - A non-empty `scanBackends` entry that does not appear in
///   `valid_backends` produces one [`ValidationError::Invalid`] per
///   offending value; the error detail names the offending value and
///   the supported names so operators can spot a typo immediately.
/// - When `valid_backends.is_empty()` (a build with no scanner adapters
///   compiled in — not reachable through the production caller, whose
///   capability set is non-empty), any non-empty `scanBackends`
///   declaration is rejected; the detail surfaces a `<none compiled in>`
///   sentinel rather than a confusing "got X, expected []" message.
///
/// This function is exposed publicly so the gitops pipeline
/// (`ApplyConfigUseCase::apply`) can invoke it. It is intentionally NOT folded
/// into [`DesiredState::validate_against`] because that signature is
/// snapshot-only; the supported-backend set is a deployment capability fact,
/// not part of the read-side `ManagedBy=Local` snapshot.
pub fn validate_scan_policy_backends(
    state: &DesiredState,
    valid_backends: &[String],
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let valid_set: std::collections::HashSet<&str> =
        valid_backends.iter().map(String::as_str).collect();

    // Stable, comma-separated list of supported names for the error
    // detail. Sorting keeps the message deterministic across runs so
    // the same misconfiguration produces the same error string.
    let mut sorted_valid: Vec<&str> = valid_set.iter().copied().collect();
    sorted_valid.sort_unstable();
    let supported_summary = if sorted_valid.is_empty() {
        "<none compiled in>".to_string()
    } else {
        sorted_valid.join(", ")
    };

    for env in &state.scan_policies {
        for backend in &env.spec.scan_backends {
            if !valid_set.contains(backend.as_str()) {
                errors.push(ValidationError::Invalid {
                    kind: Kind::ScanPolicy,
                    name: env.metadata.name.clone(),
                    detail: format!(
                        "spec.scanBackends entry `{backend}` is not a supported scanner \
                         backend (supported: {supported_summary}) — remove it or use a \
                         supported backend"
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
                // `DesiredState::validate` rejects more than one active
                // ScanPolicy per scope before this linter ever runs, so
                // at most one entry can exist per repository here. The
                // `or_insert` is defensive, not a tie-break: it keeps
                // this function total (and its own unit tests, which
                // build a `DesiredState` directly and skip `validate`,
                // deterministic) rather than assuming the invariant holds.
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
/// enforcement; the operator's recourse is to drop the
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

/// Apply-time linter rejecting a `PrefetchPolicy.triggers` entry a
/// repository's format cannot honour.
///
/// `transitive_deps` and `scheduled` both require the format's handler to
/// declare the `VersionDiscovery` capability group (ADR 0005); a
/// repository declaring either on a format whose handler does not is
/// accepted at apply today and silently never fires (see
/// [`hort_domain::entities::repository::PrefetchTrigger::requires_version_discovery`]).
/// `on_dist_tag_move` needs no such declaration — OCI fires it today with
/// no `VersionDiscovery` implementation — so it is never rejected here.
///
/// This is the same accepted-but-inert anti-pattern
/// [`validate_prefetch_max_age_days_not_implemented`] closes for
/// `maxAgeDays`; ADR 0015 makes it a hard block.
///
/// `version_discovery_capable_formats` is the set of `format_key()`
/// strings some compiled-in `FormatHandler` declares the group for. The
/// caller derives it from the handler registry's own
/// `FormatHandler::version_discovery()` declaration — this function reads
/// only that set, never a maintained format list, so a format that gains
/// (or loses) `VersionDiscovery` changes this rejection with no edit
/// here.
///
/// **Fail-closed.** No escape hatch. The operator-actionable error names
/// the repository, its format, and the offending trigger, and tells the
/// operator to either remove the trigger or fall back to warming the
/// repository from outside Hort (a scheduled pull against the proxy)
/// until the format implements `VersionDiscovery`.
///
/// Pure function of `DesiredState` plus the capability set; runs
/// alongside [`validate_prefetch_max_age_days_not_implemented`] after the
/// snapshot-validation stage. One error per offending trigger.
pub fn validate_prefetch_triggers_require_version_discovery(
    state: &DesiredState,
    version_discovery_capable_formats: &std::collections::HashSet<String>,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for env in &state.repositories {
        if version_discovery_capable_formats.contains(&env.spec.format) {
            continue;
        }
        for trigger in &env.spec.prefetch_policy.triggers {
            if !trigger.requires_version_discovery() {
                continue;
            }
            errors.push(ValidationError::Invalid {
                kind: Kind::ArtifactRepository,
                name: env.metadata.name.clone(),
                detail: format!(
                    "`prefetchPolicy.triggers` includes `{trigger}`, which requires the \
                     VersionDiscovery capability; the `{format}` format handler does not \
                     declare it, so the trigger is accepted but never fires. Remove \
                     `{trigger}` from `triggers`, or warm this repository from outside Hort \
                     (a scheduled pull against the proxy) until `{format}` implements \
                     VersionDiscovery. (repository: `{repo_key}`, format: `{format}`)",
                    trigger = trigger,
                    format = env.spec.format,
                    repo_key = env.metadata.name,
                ),
            });
        }
    }
    errors
}

/// Apply-time linter rejecting a `RetentionPolicy` whose predicate uses
/// [`PolicyPredicate::UnusedFor`](hort_domain::retention::PolicyPredicate::UnusedFor).
///
/// `UnusedFor` is not inert — it is *mislabelled*. No port supplies a
/// last-download anchor, so `RetentionUseCase` builds every
/// `EvaluationInputs` with `last_downloaded_at: None`, and the pure
/// evaluator's `None` arm measures the interval from `created_at`.
/// `UnusedFor(N)` therefore decides exactly what `AgeExceeds(N)` decides:
/// an artifact pulled every hour expires the moment it is old enough.
/// An operator writing `UnusedFor` is making a decision about *usage* and
/// silently gets a decision about *age* — which on a hosted repository
/// inverts the intent, since a year-old daily-pulled artifact is the last
/// thing "unused" should reach and the first thing "old" does. Accepting
/// a risk-significant field whose runtime meaning is not the one it
/// names is a hard architectural block (ADR 0015, which treats the
/// weaker accepted-but-inert case the same way).
///
/// **Retirement trigger.** This rejection is wrong the moment
/// `UnusedFor` starts meaning what it says. That happens when
/// `RetentionUseCase`'s `EvaluationInputs` construction stops passing the
/// hard-coded `last_downloaded_at: None` and feeds a real last-download
/// anchor from a port. Delete this function, its `LinterRule` row, its
/// metric constant and its metrics-catalog entry **in that same commit** —
/// a guard kept past the condition that justified it is worse than no
/// guard, because the next reader has to re-derive whether it still
/// applies.
///
/// **Fail-closed.** No escape hatch: the operator either says
/// `AgeExceeds` (which is what the deployment would actually do) or drops
/// the predicate until the usage signal exists.
///
/// The walk is recursive over the whole `Composite` tree — a nested
/// `UnusedFor` evaluates exactly like a root one, so inspecting only the
/// root would leave the hole open one `Composite` deep. One error per
/// offending envelope, not per occurrence: the defect is the envelope's,
/// and a composite naming `UnusedFor` three times is one thing to fix.
///
/// A predicate that does not deserialize is skipped: that error belongs
/// to `validate_retention_policy`, and naming `UnusedFor` in a second
/// error on an envelope whose predicate could not be read at all would be
/// a guess. A predicate that *does* resolve but fails
/// `PolicyPredicate::validate` — `UnusedFor(0)` — has two independent
/// defects; apply aborts on the structural one first and this rule
/// surfaces once that is fixed.
///
/// Pure function of `DesiredState`; runs alongside
/// [`validate_prefetch_max_age_days_not_implemented`].
pub fn validate_retention_unused_for_not_implemented(state: &DesiredState) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for env in &state.retention_policies {
        let Ok(predicate) = crate::retention_policy::predicate_from_value(&env.spec.predicate)
        else {
            continue;
        };
        if !predicate_mentions_unused_for(&predicate) {
            continue;
        }
        // `mentions` is true and the root is not itself `UnusedFor` ⇒ the
        // occurrence is inside a `Composite`. Say so: an operator staring
        // at a multi-level tree needs to know the reject is not about the
        // outermost node.
        let site = if matches!(predicate, PolicyPredicate::UnusedFor(_)) {
            "`spec.predicate` is `UnusedFor`"
        } else {
            "`spec.predicate` nests `UnusedFor` inside a `Composite`"
        };
        errors.push(ValidationError::Invalid {
            kind: Kind::RetentionPolicy,
            name: env.metadata.name.clone(),
            detail: format!(
                "{site}, but no last-download signal is implemented: the evaluator is \
                 handed no last-used timestamp and falls back to the artifact's creation \
                 time, so `UnusedFor(N)` expires exactly what `AgeExceeds(N)` expires — \
                 including an artifact downloaded today. Write `AgeExceeds` if age is what \
                 was meant, or drop the predicate until the usage signal exists. \
                 (retention policy: `{name}`)",
                name = env.metadata.name,
            ),
        });
    }
    errors
}

/// `true` iff `pred` or any descendant of a `Composite` is
/// `UnusedFor`. Mirrors the arm grouping of
/// [`PolicyPredicate::is_security_driven`](hort_domain::retention::PolicyPredicate::is_security_driven),
/// the in-tree recursive walk over this same tree, so the two read
/// identically; the exhaustive match (no wildcard) makes a new predicate
/// variant a compile error here rather than a silent `false`.
fn predicate_mentions_unused_for(pred: &PolicyPredicate) -> bool {
    match pred {
        PolicyPredicate::UnusedFor(_) => true,
        PolicyPredicate::Composite(_, children) => {
            children.iter().any(predicate_mentions_unused_for)
        }
        PolicyPredicate::AgeExceeds(_)
        | PolicyPredicate::KeepLastN(_)
        | PolicyPredicate::HasFindingAboveSeverity(_)
        | PolicyPredicate::HasFindingAboveCvss(_)
        | PolicyPredicate::HasFixAvailable
        | PolicyPredicate::HasFindingDetectedFor(_) => false,
    }
}

/// Apply-time linter rejecting a `ScanPolicy.licensePolicy` that
/// declares licence rules the scan path cannot apply.
///
/// The field is accepted, stored on the projection and visible to an
/// auditor, and decides nothing. `evaluate_scan_result` dispatches to
/// [`evaluate_license_policy`](hort_domain::policy::evaluate_license_policy)
/// with a hard-coded **empty** licence list — no port surfaces an
/// artifact's licences — so a well-formed
/// `{"denied_licenses":["GPL-3.0"],"action":"Block"}` compares the
/// denied set against zero licences, produces zero violations, and
/// leaves the scan clean whatever the artifact's licence actually is.
/// The only thing the dispatch can still produce is a
/// `license-policy-shape` advisory against a malformed value, which
/// never blocks. An operator declaring a denied-licence list is making
/// a compliance decision on the assumption the field gates releases;
/// accepting a risk-significant field whose consumer silently ignores
/// it is a hard architectural block (ADR 0015).
///
/// **The inert default is `null` or `{}`**, and both keep applying
/// exactly as before:
/// [`has_license_policy`](hort_domain::policy::has_license_policy) is
/// the single definition
/// of "declared" shared with the evaluator's own dispatch guard, so the
/// set rejected here is exactly the set that would reach the evaluator.
/// A tree that writes `licensePolicy: {}` (what every shipped example
/// tree writes) is untouched.
///
/// **Retirement trigger.** This rejection is wrong the moment licences
/// reach the evaluator. That happens when `evaluate_scan_result` stops
/// passing `&[]` and feeds a real licence list from a port (an SBOM
/// surface). Delete this function, its `LinterRule` row, its metric
/// constant and its metrics-catalog entry **in that same commit**.
///
/// **Fail-closed.** No escape hatch: the operator either removes the
/// field or drops the compliance claim until the licence input exists.
///
/// Pure function of `DesiredState`; one error per offending envelope.
pub fn validate_scan_policy_license_policy_not_implemented(
    state: &DesiredState,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for env in &state.scan_policies {
        if !hort_domain::policy::has_license_policy(&env.spec.license_policy) {
            continue;
        }
        errors.push(ValidationError::Invalid {
            kind: Kind::ScanPolicy,
            name: env.metadata.name.clone(),
            detail: format!(
                "`licensePolicy` enforcement is not implemented: the scan path evaluates \
                 the policy against an empty licence list (no port surfaces an artifact's \
                 licences), so every rule in it matches nothing and the scan stays clean \
                 whatever the artifact is licensed under. Remove the field — or write \
                 `licensePolicy: {{}}` — to apply; a different value does not change \
                 this. (scan policy: `{name}`)",
                name = env.metadata.name,
            ),
        });
    }
    errors
}

/// Apply-time linter rejecting an `Exclusion.scope` that names a
/// repository.
///
/// The rationale is
/// [`SCOPE_NOT_ENFORCED`](hort_domain::policy::SCOPE_NOT_ENFORCED) —
/// the finding filter never reads the scope, so a waiver narrowed to
/// one repository silently clears its CVE everywhere the parent policy
/// reaches. This is the ADR 0015 block with the blast radius pointing
/// the wrong way: the operator's edit *looks* like a narrowing and acts
/// like a widening.
///
/// **The inert default is `scope: global`** and keeps applying exactly
/// as before. `scope` is a required field on the spec, so there is no
/// "absent" case to consider.
///
/// This is one of **two** writers that has to refuse the scope — the
/// other is `PolicyUseCase::add_exclusion`, which the HTTP write
/// surface reaches outside the desired-tree lint. A linter row on its
/// own would close the declared path and leave the API path open.
///
/// **Also what keeps `ExclusionsApplier::resolve_scope`'s panic
/// unreachable.** That resolver maps a scope's repository name to an id
/// through a map built from the declared repositories and treats a miss
/// as an invariant violation; a panic is not a `GitopsBootError`, so
/// the boot path cannot park on it and the pod crashloops with the
/// earlier stages written. Rejecting *every* repository scope here is
/// strictly stronger than a dangling-reference rule would be (which is
/// why no such rule exists for this kind, unlike `ScanPolicy`'s own
/// `push_scan_policy_scope_reference_errors`) — with this row in
/// place no repository scope reaches the resolver at all.
///
/// **Fail-closed.** No escape hatch: the operator either says
/// `scope: global` — which is what the deployment would actually do —
/// or drops the exclusion until per-repository scoping is implemented.
///
/// Pure function of `DesiredState`; one error per offending envelope.
pub fn validate_exclusion_scope_not_implemented(state: &DesiredState) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for env in &state.exclusions {
        let crate::scope::ScopeSpec::Repository(scope) = &env.spec.scope else {
            continue;
        };
        errors.push(ValidationError::Invalid {
            kind: Kind::Exclusion,
            name: env.metadata.name.clone(),
            detail: format!(
                "`spec.scope` names repository `{repository}`, but {rationale}. Write \
                 `scope: global` if clearing this CVE everywhere the policy governs is \
                 what was meant, or drop the exclusion until per-repository scoping is \
                 implemented. (exclusion: `{name}`, parent policy: `{policy}`)",
                repository = scope.repository,
                rationale = hort_domain::policy::SCOPE_NOT_ENFORCED,
                name = env.metadata.name,
                policy = env.spec.policy,
            ),
        });
    }
    errors
}

/// Apply-time linter rejecting a `virtualMembers` entry whose format
/// differs from the virtual repository's own.
///
/// Nothing compares the two. Cross-spec validation requires each member
/// to be declared and non-virtual; the per-spec virtual-shape validator
/// checks only the virtual's *own* format against
/// `VIRTUAL_SERVE_SUPPORTED_FORMATS`; and at serve time
/// `VirtualResolutionUseCase::resolve_members` re-checks Read
/// visibility and repository type, not format. So a `pypi` hosted
/// repository can be a member of an `npm` virtual, and — because a
/// non-proxy member *owns* the names it holds (the name-level pinning
/// rule, ADR 0031) — it can own a package name inside that npm
/// virtual, suppressing the npm proxy for that name while holding
/// nothing an npm client can install.
///
/// There is no format-compatibility model to appeal to: the operator
/// composing a virtual is making a decision about what the endpoint
/// serves, on the assumption that a member's format is checked against
/// it. That assumption is the ADR 0015 block.
///
/// **The inert default is a member whose format matches**, which is
/// every shipped example tree, and keeps applying exactly as before.
/// Formats are compared through
/// [`RepositoryFormat::from_str`](hort_domain::entities::repository::RepositoryFormat)
/// rather than as raw strings, so the comparison normalises case the
/// same way every runtime format lookup does — a member declaring
/// `NPM` inside an `npm` virtual is the matching case, not a mismatch.
///
/// A member name that resolves to no declared repository is skipped:
/// that error is `DanglingVirtualMember`'s, and naming a format for a
/// repository the bundle does not declare would be a guess.
///
/// **Fail-closed.** No escape hatch: a cross-format aggregate needs one
/// virtual per format.
///
/// Pure function of `DesiredState`; one error per offending
/// (virtual, member) pair — each is a separate member line to fix.
pub fn validate_virtual_member_formats_not_enforced(state: &DesiredState) -> Vec<ValidationError> {
    use hort_domain::entities::repository::{RepositoryFormat, RepositoryType};

    let declared_format_by_name: HashMap<&str, &str> = state
        .repositories
        .iter()
        .map(|e| (e.metadata.name.as_str(), e.spec.format.as_str()))
        .collect();

    let mut errors = Vec::new();
    for env in &state.repositories {
        if !matches!(
            RepositoryType::from_str(&env.spec.repo_type),
            Ok(RepositoryType::Virtual)
        ) {
            continue;
        }
        // Infallible parse (unknown formats become `Other(lowercased)`),
        // so an unknown format on either side still compares — row 0's
        // own format rule is what rejects the unknown token.
        let Ok(virtual_format) = RepositoryFormat::from_str(&env.spec.format);
        for member in env.spec.virtual_members.as_deref().unwrap_or(&[]) {
            let Some(member_format_str) = declared_format_by_name.get(member.as_str()) else {
                continue;
            };
            let Ok(member_format) = RepositoryFormat::from_str(member_format_str);
            if member_format == virtual_format {
                continue;
            }
            errors.push(ValidationError::Invalid {
                kind: Kind::ArtifactRepository,
                name: env.metadata.name.clone(),
                detail: format!(
                    "`virtualMembers` entry `{member}` declares format \
                     `{member_format_str}` while this virtual repository declares \
                     `{virtual_format_str}`, and no format-compatibility check is \
                     implemented — neither apply nor serve-time member resolution \
                     compares the two, so the member is resolved for \
                     `{virtual_format_str}` requests regardless, and a non-proxy \
                     one additionally owns the names it holds there, suppressing \
                     the virtual's other members for them. Remove the entry, or \
                     aggregate it in a separate `{member_format_str}` virtual. \
                     (virtual repository: `{name}`)",
                    member = member,
                    member_format_str = member_format_str,
                    virtual_format_str = env.spec.format,
                    name = env.metadata.name,
                ),
            });
        }
    }
    errors
}

/// Apply-time linter rejecting a `ScanPolicy.maxArtifactAge` that
/// declares a staleness cap nothing evaluates.
///
/// The field travels the whole configuration path and is read by
/// nothing that decides: it is parsed, format-validated, converted to
/// `max_artifact_age_secs` on the projection, diffed field-by-field,
/// event-sourced onto the policy stream, persisted, and written into
/// the config snapshot. The evaluator
/// [`evaluate_age_gates`](hort_domain::policy::evaluate_age_gates)
/// exists and would turn an exceeded cap into a `Medium`
/// `max-artifact-age` violation — but it has **no production caller**,
/// only its own unit tests. No scan-result evaluation, no release
/// decision and no retention pass ever asks the question, so no
/// artifact is ever flagged for age.
///
/// An operator writing `maxArtifactAge: 90d` has declared a staleness
/// cap, can read it back from the policy and sees it in both the
/// config snapshot and drift detection — while every artifact older
/// than the cap keeps passing every gate. Accepting a risk-significant
/// field whose consumer silently ignores it is a hard architectural
/// block (ADR 0015); this is the same shape as
/// [`validate_prefetch_max_age_days_not_implemented`] one policy kind
/// over.
///
/// **The inert default is the absent field** (equivalently, an explicit
/// `maxArtifactAge: null`, which deserialises to the same `None`).
/// `max_artifact_age` is an `Option<String>` whose `None` the evaluator
/// reads as "no cap", so **any** `Some` is the rejection: unlike row
/// 10's `licensePolicy: {}` there is no value that declares nothing, and
/// `0s` — which would flag everything if anything read it — is refused
/// exactly like `90d`. A tree that never claimed an age cap applies
/// exactly as before.
///
/// **Retirement trigger.** This rejection is wrong the moment a
/// consumer exists. That happens when something feeds
/// `ScanPolicyProjection.max_artifact_age_secs` and the artifact's
/// ingest instant through `evaluate_age_gates` and folds the resulting
/// violation into the accumulator. Delete this function, its
/// `LinterRule` row, its metric constant and its metrics-catalog entry
/// **in that same commit**; the format validation in
/// `validate_scan_policy_env` stays either way.
///
/// **Fail-closed.** No escape hatch: the operator either removes the
/// field or drops the staleness claim until the evaluator is wired.
///
/// Pure function of `DesiredState`; one error per offending envelope.
pub fn validate_scan_policy_max_artifact_age_not_implemented(
    state: &DesiredState,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for env in &state.scan_policies {
        let Some(age) = env.spec.max_artifact_age.as_ref() else {
            continue;
        };
        errors.push(ValidationError::Invalid {
            kind: Kind::ScanPolicy,
            name: env.metadata.name.clone(),
            detail: format!(
                "`maxArtifactAge` enforcement is not implemented: the cap is stored on \
                 the policy and never evaluated (the age evaluator has no caller on any \
                 scan, release or retention path), so no artifact is ever flagged for \
                 age however old it is. Remove the field to apply; a different duration \
                 does not change this. (scan policy: `{name}`, declared cap: `{age}`)",
                name = env.metadata.name,
                age = age,
            ),
        });
    }
    errors
}

/// Row 15 — a `ScanPolicy` that promotes the composed-image verdict to
/// release authority while declaring **no scanner backends**
/// (ADR 0064 D6 × ADR 0016's cross-opt-in matrix, closed under ADR 0015).
///
/// Two operator opt-ins that each change which analysis decides the
/// release gate, and together they cancel. `scanBackends: []` is the
/// explicit scan waiver: `ScanOrchestrationUseCase::run_scan` returns
/// `SkippedNoBackends` on it **before** a composition is resolved, so no
/// manifest in the policy's scope ever carries a composite assessment —
/// and `compositeVerdictMode: promoted` then grants release authority to
/// a verdict that is never produced. The operator has declared a control
/// and configured away the only thing that could exercise it, which is
/// precisely the accepted-but-inert field ADR 0015 treats as a hard
/// block, reached through a pair of fields rather than through one.
///
/// Decidable from a **single envelope** — both fields live on the same
/// `ScanPolicy` spec, and policy resolution picks one whole policy
/// (repo-scoped wins over global), so the mode and the backend list the
/// orchestrator reads always come from the same row. That is why this is
/// a per-envelope rule here rather than a cross-envelope one in
/// `hort-app::lint::static_validate`, where its nearest sibling
/// [`validate_trust_upstream_publish_time_requires_scan_backends`] has to
/// live because the two halves of *that* collapse sit on an
/// `UpstreamMapping` and a `ScanPolicy` respectively.
///
/// **Not a missing-control row**, so it has no retirement trigger: the
/// composite verdict's consumer exists and is enforced the moment apply
/// accepts `promoted`. The combination stays wrong under any future
/// implementation, because a waived scan has nothing to promote.
///
/// **Fail-closed, never a runtime fallback.** The structural close is an
/// apply-time rejection of the dangerous combination (ADR 0016), not a
/// degraded-authority path that silently treats `promoted` as `observed`
/// for a scope with no backends — an operator reading the policy back
/// would see a promotion that is not in effect.
///
/// Pure function of `DesiredState`; one error per offending envelope.
pub fn validate_scan_policy_promoted_composite_requires_scan_backends(
    state: &DesiredState,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for env in &state.scan_policies {
        // Read off the parsed domain value, not the wire string: a
        // mis-spelled mode is `validate_scan_policy`'s typed reject and
        // must not be read here as either posture.
        let promoted = CompositeVerdictMode::from_str(&env.spec.composite_verdict_mode)
            .is_ok_and(|mode| mode.carries_release_authority());
        if !promoted || !env.spec.scan_backends.is_empty() {
            continue;
        }
        errors.push(ValidationError::Invalid {
            kind: Kind::ScanPolicy,
            name: env.metadata.name.clone(),
            detail: format!(
                "`compositeVerdictMode: promoted` with an empty `scanBackends` promotes a \
                 verdict that is never produced: an empty backend list waives scanning for \
                 every artifact this policy governs, and the scan returns before a composed \
                 image is resolved — so no manifest ever carries a composite assessment for \
                 the promotion to act on. Declare the backends that should assess the \
                 composition (`scanBackends: [trivy]`), or leave \
                 `compositeVerdictMode: observed` while the scan stays waived. (scan policy: \
                 `{name}`)",
                name = env.metadata.name,
            ),
        });
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

/// Cross-doc reference check for a `RetentionPolicy`'s repository
/// scope.
///
/// `scope: { Repos: [<metadata.name>, …] }` names repositories the
/// apply pipeline resolves to UUIDs through `repo_id_by_name`, which is
/// built from `DesiredState.repositories`. A name absent from that map
/// has no id to resolve to, and the resolution site treats a miss as an
/// invariant violation rather than papering over it — so an undeclared
/// name has to be rejected here, before any write. Mirrors the
/// `ScanPolicy` scope rule and the `UpstreamMapping.spec.repository`
/// rule: one `DanglingReference` per offending value, naming it.
///
/// A scope that does not deserialize is skipped: the per-spec validator
/// already reported it, and reporting the same envelope twice for one
/// defect helps nobody.
fn push_retention_policy_scope_reference_errors(
    state: &DesiredState,
    declared_repos: &std::collections::HashSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    for env in &state.retention_policies {
        let Ok(scope) = crate::retention_policy::scope_from_value(&env.spec.scope) else {
            continue;
        };
        for name in scope.repository_names() {
            if !declared_repos.contains(name.as_str()) {
                errors.push(ValidationError::DanglingReference {
                    referrer_kind: Kind::RetentionPolicy,
                    referrer_name: env.metadata.name.clone(),
                    field: "spec.scope.Repos",
                    target_kind: Kind::ArtifactRepository,
                    missing_name: name.clone(),
                });
            }
        }
    }
}

/// Scope-uniqueness check for `ScanPolicy`.
///
/// A `ScanPolicy`'s scope (`Global` or `Repository(<name>)`) is the key
/// the runtime resolver looks up by — at most one active policy may
/// occupy a scope, or resolution has no way to pick between them
/// deterministically. A second same-scope policy is not merely
/// confusing: it makes the effective policy depend on load order (or
/// iteration order over a set, in the general case), which can silently
/// widen the effective `scanBackends` a mapping resolves against a
/// stricter operator intended.
///
/// Mirrors `push_upstream_mapping_identity_duplicates`: the standard
/// `metadata.name` duplicate check (above, in `validate`) catches name
/// collisions; this catches the case where two envelopes have distinct
/// names but collapse to the same scope. Unlike that helper's pairwise
/// "also declared by `<prior>`" message, every envelope in an offending
/// scope gets its own error whose detail lists ALL of that scope's
/// names — not just one other — so an operator with three colliding
/// policies sees the full set from any one of the three errors.
fn push_scan_policy_scope_duplicates(
    policies: &[Envelope<ScanPolicySpec>],
    errors: &mut Vec<ValidationError>,
) {
    let mut by_scope: HashMap<Option<&str>, Vec<&Envelope<ScanPolicySpec>>> = HashMap::new();
    for env in policies {
        by_scope
            .entry(env.spec.scope.repository_name())
            .or_default()
            .push(env);
    }
    for (scope, group) in &by_scope {
        if group.len() <= 1 {
            continue;
        }
        let scope_desc = match scope {
            None => "Global".to_string(),
            Some(repository) => format!("Repository(`{repository}`)"),
        };
        let mut names: Vec<&str> = group.iter().map(|e| e.metadata.name.as_str()).collect();
        names.sort_unstable();
        let names_joined = names.join(", ");
        for env in group {
            errors.push(ValidationError::Invalid {
                kind: Kind::ScanPolicy,
                name: env.metadata.name.clone(),
                detail: format!(
                    "duplicate ScanPolicy scope {scope_desc} — {} active envelopes declare it: \
                     {names_joined} — at most one ScanPolicy may be active per scope, or \
                     resolution has no deterministic way to choose between them",
                    group.len(),
                ),
            });
        }
    }
}

/// Cross-doc reference check for a `ScanPolicy`'s repository scope.
///
/// `scope: { repository: <metadata.name> }` names a repository the apply
/// pipeline resolves to a UUID through `repo_id_by_name`, which is built
/// from `DesiredState.repositories`. A name absent from that map has no
/// id to resolve to, and both resolution sites — `resolve_scope` in
/// `hort-app`'s apply pipeline and `ScanPolicyApplier::resolve_scope` —
/// treat a miss as an invariant violation and panic. A panic is not a
/// `GitopsBootError`, so the boot path cannot park not-ready on it: it
/// crashloops, with the earlier stages of the same apply already
/// written. An undeclared name therefore has to be rejected here, before
/// any write. Mirrors `push_retention_policy_scope_reference_errors` and
/// the `UpstreamMapping.spec.repository` rule: one `DanglingReference`
/// per offending value, naming it.
///
/// Unlike the retention sibling there is no unparsable-scope case to
/// skip: [`ScanPolicySpec::scope`] is a typed
/// [`ScopeSpec`](crate::scope::ScopeSpec), so a scope that does not
/// deserialize fails its own envelope's parse and never reaches a
/// `DesiredState` at all.
fn push_scan_policy_scope_reference_errors(
    state: &DesiredState,
    declared_repos: &std::collections::HashSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    for env in &state.scan_policies {
        let Some(name) = env.spec.scope.repository_name() else {
            // `Global` — no repository reference to resolve.
            continue;
        };
        if !declared_repos.contains(name) {
            errors.push(ValidationError::DanglingReference {
                referrer_kind: Kind::ScanPolicy,
                referrer_name: env.metadata.name.clone(),
                field: "spec.scope.repository",
                target_kind: Kind::ArtifactRepository,
                missing_name: name.to_string(),
            });
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
            "apiVersion: project-hort.de/v1
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
            "apiVersion: project-hort.de/v1
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

    /// Issue #67: a tree with SOME envelopes on the new stable `v1` and
    /// SOME still on `v1beta1` parses and cross-validates identically —
    /// the version bump is opt-in per file, never a forced operator
    /// migration.
    #[test]
    fn parse_files_accepts_mixed_v1_and_v1beta1_apiversions() {
        let v1beta1_repo = b"apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: legacy-repo
spec:
  name: legacy-repo
  format: npm
  type: hosted
  storage: { backend: filesystem, path: /data/legacy-repo }
  isPublic: true
  replicationPriority: immediate
"
        .to_vec();
        let files = vec![
            (p("legacy.yaml"), v1beta1_repo),
            (p("a.yaml"), repo_yaml("a", "hosted", None)),
            (p("admins.yaml"), cm_yaml("admins", "g", "admin")),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert_eq!(state.repositories.len(), 2);
        assert_eq!(state.claim_mappings.len(), 1);
        state
            .validate()
            .expect("mixed v1/v1beta1 tree must cross-validate cleanly");
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
        let yaml = b"apiVersion: project-hort.de/v1
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
    fn validate_catches_nested_virtual_member() {
        // ADR 0031 rule 5 / spec §7.5: a `virtualMembers` entry that is itself
        // `type: virtual` is rejected at apply — v1 keeps resolution a single
        // flat priority list (no recursive member resolution).
        let files = vec![
            (p("v.yaml"), repo_yaml("v", "virtual", Some(&["inner"]))),
            (p("inner.yaml"), repo_yaml("inner", "virtual", Some(&["a"]))),
            (p("a.yaml"), repo_yaml("a", "hosted", None)),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(
            err.0.iter().any(|e| matches!(
                e,
                ValidationError::Invalid { detail, .. } if detail.contains("nested virtual")
            )),
            "should reject `inner` (type=virtual) as a member: {err:?}"
        );
    }

    #[test]
    fn validate_allows_non_virtual_members() {
        // The nested-virtual check must NOT fire when every member is a
        // non-virtual repo (exercises the `Ok(Virtual)`-false arm of the
        // member-type match).
        let files = vec![
            (p("v.yaml"), repo_yaml("v", "virtual", Some(&["a", "b"]))),
            (p("a.yaml"), repo_yaml("a", "hosted", None)),
            (p("b.yaml"), repo_yaml("b", "proxy", None)),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        // Other errors may be present (e.g. the serve-support stopgap), so
        // inspect the error set directly rather than asserting Ok/Err.
        let errs = state.validate().err().map(|e| e.0).unwrap_or_default();
        assert!(
            !errs.iter().any(|e| matches!(
                e,
                ValidationError::Invalid { detail, .. } if detail.contains("nested virtual")
            )),
            "non-virtual members must not raise the nested-virtual error: {errs:?}"
        );
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
            .push(crate::yaml::from_slice(&repo_yaml("ok", "hosted", None)).unwrap());
        state
            .claim_mappings
            .push(crate::yaml::from_slice(&cm_yaml("admins", "g", "admin")).unwrap());
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
            "apiVersion: project-hort.de/v1
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

    /// A `PermissionGrant` envelope with a `serviceAccount` subject
    /// (ADR 0037 / spec §9).
    fn pg_sa_yaml(name: &str, sa: &str, permission: &str, repository: Option<&str>) -> Vec<u8> {
        let repo_line = match repository {
            Some(r) => format!("  repository: {r}\n"),
            None => String::new(),
        };
        format!(
            "apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: {name}
spec:
  subject: {{ kind: serviceAccount, name: {sa} }}
  permission: {permission}
{repo_line}"
        )
        .into_bytes()
    }

    fn cr_yaml(name: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
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
            "apiVersion: project-hort.de/v1
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
            "apiVersion: project-hort.de/v1
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
            "apiVersion: project-hort.de/v1
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

    // -- RetentionPolicy scope reference rule -------------------------------

    fn rp_yaml(name: &str, scope_yaml: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
kind: RetentionPolicy
metadata:
  name: {name}
spec:
  predicate:
    AgeExceeds: 2592000
  scope: {scope_yaml}
"
        )
        .into_bytes()
    }

    #[test]
    fn validate_accepts_retention_scope_naming_a_repository_declared_in_the_same_bundle() {
        // The ordering guarantee this pins: a retention policy may name a
        // repository declared in the SAME desired state. Nothing has to
        // pre-exist in the database.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (
                p("rp.yaml"),
                rp_yaml("retain-npm", "{ Repos: [npm-internal] }"),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        state.validate().expect("declared repository resolves");
    }

    #[test]
    fn validate_rejects_retention_scope_naming_an_undeclared_repository() {
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (
                p("rp.yaml"),
                rp_yaml("retain-ghost", "{ Repos: [npm-internal, ghost-repo] }"),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        let dangling: Vec<&ValidationError> = err
            .0
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    ValidationError::DanglingReference {
                        referrer_kind: Kind::RetentionPolicy,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(
            dangling.len(),
            1,
            "only the undeclared name is an error, got: {:?}",
            err.0
        );
        let rendered = dangling[0].to_string();
        assert!(
            rendered.contains("ghost-repo"),
            "the message must name the offending value: {rendered}"
        );
        assert!(
            rendered.contains("retain-ghost"),
            "the message must name the referrer: {rendered}"
        );
    }

    /// The retired UUID form is not grandfathered: a tree that still
    /// writes repository ids now fails the declared-repository rule,
    /// because the id is read as a name and no repository is named that.
    #[test]
    fn validate_rejects_a_retention_scope_still_written_as_uuids() {
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (
                p("rp.yaml"),
                rp_yaml(
                    "retain-legacy",
                    "{ Repos: ['67e55044-10b1-426f-9247-bb680e5fe0c8'] }",
                ),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(
            err.0.iter().any(|e| e
                .to_string()
                .contains("67e55044-10b1-426f-9247-bb680e5fe0c8")),
            "got: {:?}",
            err.0
        );
    }

    #[test]
    fn validate_ignores_name_free_retention_scopes() {
        let files = vec![
            (p("a.yaml"), rp_yaml("retain-all", "AllRepos")),
            (
                p("b.yaml"),
                rp_yaml("retain-proxied", "{ IngestSource: Proxied }"),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        state
            .validate()
            .expect("no repository reference to resolve");
    }

    /// A scope that does not deserialize is the per-spec validator's
    /// error to report; the reference check must not pile a second,
    /// misleading error onto the same envelope.
    #[test]
    fn validate_reports_an_unparsable_retention_scope_once() {
        let files = vec![(p("rp.yaml"), rp_yaml("retain-bogus", "{ NotAScope: [] }"))];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(
            err.0.iter().any(|e| e
                .to_string()
                .contains("spec.scope is not a valid retention scope")),
            "got: {:?}",
            err.0
        );
        assert!(
            !err.0.iter().any(|e| matches!(
                e,
                ValidationError::DanglingReference {
                    referrer_kind: Kind::RetentionPolicy,
                    ..
                }
            )),
            "an unparsable scope must not also produce a dangling reference: {:?}",
            err.0
        );
    }

    // -- RetentionPolicy `UnusedFor` rejection ------------------------------

    /// A `RetentionPolicy` envelope carrying an arbitrary predicate. The
    /// scope is `AllRepos` so nothing but the predicate rule can fire.
    fn rp_pred_yaml(name: &str, predicate_yaml: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
kind: RetentionPolicy
metadata:
  name: {name}
spec:
  predicate: {predicate_yaml}
  scope: AllRepos
"
        )
        .into_bytes()
    }

    fn state_with_predicates(entries: &[(&str, &str)]) -> DesiredState {
        let files: Vec<(PathBuf, Vec<u8>)> = entries
            .iter()
            .enumerate()
            .map(|(i, (name, pred))| (p(&format!("rp{i}.yaml")), rp_pred_yaml(name, pred)))
            .collect();
        DesiredState::parse_files(files).unwrap()
    }

    #[test]
    fn unused_for_at_the_root_is_rejected() {
        let state = state_with_predicates(&[("reclaim-cold", "{ UnusedFor: 7776000 }")]);
        let errors = validate_retention_unused_for_not_implemented(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
        let rendered = errors[0].to_string();
        assert!(
            rendered.contains("reclaim-cold"),
            "must name the envelope: {rendered}"
        );
        assert!(
            rendered.contains("`spec.predicate` is `UnusedFor`"),
            "must locate the predicate at the root: {rendered}"
        );
        assert!(
            rendered.contains("AgeExceeds"),
            "must name the alternative: {rendered}"
        );
        assert!(
            rendered.contains("creation time"),
            "must state the fallback that makes the label wrong: {rendered}"
        );
    }

    /// The hole a root-only rule would leave: a `Composite` child
    /// evaluates exactly like a root predicate.
    #[test]
    fn unused_for_nested_in_a_composite_is_rejected() {
        let state = state_with_predicates(&[(
            "reclaim-nested",
            "{ Composite: [Or, [{ AgeExceeds: 2592000 }, { UnusedFor: 7776000 }]] }",
        )]);
        let errors = validate_retention_unused_for_not_implemented(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
        let rendered = errors[0].to_string();
        assert!(
            rendered.contains("nests `UnusedFor` inside a `Composite`"),
            "a nested hit must say so, not read as a root predicate: {rendered}"
        );
    }

    /// Two levels down — the walk recurses, it does not peek one deep.
    #[test]
    fn unused_for_nested_two_levels_deep_is_rejected() {
        let state = state_with_predicates(&[(
            "reclaim-deep",
            "{ Composite: [And, [{ Composite: [Or, [{ UnusedFor: 60 }, HasFixAvailable]] }]] }",
        )]);
        let errors = validate_retention_unused_for_not_implemented(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
    }

    /// One error per envelope, not per occurrence — the defect is the
    /// envelope's and the operator fixes it once.
    #[test]
    fn several_unused_for_occurrences_in_one_envelope_report_once() {
        let state = state_with_predicates(&[(
            "reclaim-twice",
            "{ Composite: [Or, [{ UnusedFor: 60 }, { UnusedFor: 120 }]] }",
        )]);
        let errors = validate_retention_unused_for_not_implemented(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
    }

    #[test]
    fn each_offending_envelope_gets_its_own_error() {
        let state = state_with_predicates(&[
            ("reclaim-a", "{ UnusedFor: 60 }"),
            ("keep-b", "{ AgeExceeds: 60 }"),
            ("reclaim-c", "{ UnusedFor: 120 }"),
        ]);
        let errors = validate_retention_unused_for_not_implemented(&state);
        assert_eq!(errors.len(), 2, "got: {errors:?}");
        let rendered: Vec<String> = errors.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().any(|e| e.contains("reclaim-a")));
        assert!(rendered.iter().any(|e| e.contains("reclaim-c")));
        assert!(
            !rendered.iter().any(|e| e.contains("keep-b")),
            "AgeExceeds is untouched: {rendered:?}"
        );
    }

    /// `AgeExceeds` is the semantics `UnusedFor` accidentally delivers
    /// today, so it is the one predicate the rule must never touch.
    #[test]
    fn age_exceeds_is_never_rejected() {
        let state = state_with_predicates(&[("retain-90d", "{ AgeExceeds: 7776000 }")]);
        assert!(validate_retention_unused_for_not_implemented(&state).is_empty());
    }

    /// Every other predicate shape, root and nested, stays accepted.
    #[test]
    fn every_other_predicate_is_untouched() {
        let state = state_with_predicates(&[
            ("p-age", "{ AgeExceeds: 60 }"),
            ("p-keep", "{ KeepLastN: 5 }"),
            ("p-sev", "{ HasFindingAboveSeverity: High }"),
            ("p-cvss", "{ HasFindingAboveCvss: 7.5 }"),
            ("p-fix", "HasFixAvailable"),
            ("p-detected", "{ HasFindingDetectedFor: 604800 }"),
            (
                "p-composite",
                "{ Composite: [And, [{ AgeExceeds: 60 }, HasFixAvailable, \
                 { Composite: [Or, [{ KeepLastN: 3 }, { HasFindingDetectedFor: 60 }]] }]] }",
            ),
        ]);
        let errors = validate_retention_unused_for_not_implemented(&state);
        assert!(errors.is_empty(), "got: {errors:?}");
    }

    /// A predicate that does not deserialize is the per-spec validator's
    /// error to report; this rule must not pile a second, misleading
    /// error onto the same envelope.
    #[test]
    fn an_unparsable_predicate_is_not_double_reported() {
        let state = state_with_predicates(&[("retain-bogus", "{ NotAPredicate: 1 }")]);
        assert!(validate_retention_unused_for_not_implemented(&state).is_empty());
        // …and the per-spec validator is the one that does report it.
        let err = state.validate().unwrap_err();
        assert!(
            err.0.iter().any(|e| e
                .to_string()
                .contains("spec.predicate is not a valid retention predicate")),
            "got: {:?}",
            err.0
        );
    }

    #[test]
    fn a_state_with_no_retention_policies_reports_nothing() {
        assert!(validate_retention_unused_for_not_implemented(&DesiredState::default()).is_empty());
    }

    // -- ScanPolicy scope-uniqueness rules ----------------------------------

    #[test]
    fn validate_catches_two_global_scan_policies() {
        let files = vec![
            (
                p("a.yaml"),
                sp_yaml_with_scope_and_backends("p-a", "global", &["trivy"]),
            ),
            (
                p("b.yaml"),
                sp_yaml_with_scope_and_backends("p-b", "global", &["trivy"]),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        let matching: Vec<&ValidationError> = err
            .0
            .iter()
            .filter(|e| e.to_string().contains("duplicate ScanPolicy scope"))
            .collect();
        assert!(
            !matching.is_empty(),
            "expected a duplicate-scope error, got: {:?}",
            err.0
        );
        for e in &matching {
            let s = e.to_string();
            assert!(s.contains("Global"), "must name the scope: {s}");
            assert!(
                s.contains("p-a") && s.contains("p-b"),
                "must list both offending names: {s}"
            );
        }
    }

    #[test]
    fn validate_catches_two_same_repository_scan_policies() {
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (
                p("a.yaml"),
                sp_yaml_with_scope_and_backends("p-a", "{ repository: npm-internal }", &["trivy"]),
            ),
            (
                p("b.yaml"),
                sp_yaml_with_scope_and_backends("p-b", "{ repository: npm-internal }", &["trivy"]),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| {
            let s = e.to_string();
            s.contains("duplicate ScanPolicy scope")
                && s.contains("npm-internal")
                && s.contains("p-a")
                && s.contains("p-b")
        }));
    }

    #[test]
    fn validate_allows_distinct_scan_policy_scopes() {
        // Two different repository scopes plus one Global — every scope
        // is occupied by exactly one policy, so this must validate clean.
        let files = vec![
            (p("repo-a.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (p("repo-b.yaml"), repo_yaml("pypi-internal", "hosted", None)),
            (
                p("a.yaml"),
                sp_yaml_with_scope_and_backends("p-a", "{ repository: npm-internal }", &["trivy"]),
            ),
            (
                p("b.yaml"),
                sp_yaml_with_scope_and_backends("p-b", "{ repository: pypi-internal }", &["trivy"]),
            ),
            (
                p("g.yaml"),
                sp_yaml_with_scope_and_backends("p-global", "global", &["trivy"]),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(
            state.validate().is_ok(),
            "distinct scopes (two repositories + Global) must not collide: {:?}",
            state.validate().err()
        );
    }

    #[test]
    fn validate_rejects_the_gate2_collapse_combination() {
        // The exact bypass the ADR 0016 linter exists to fail-closed
        // reject: a strict Global policy (scan_backends: [trivy]) and a
        // second, permissive Global policy (scan_backends: []) both pass
        // per-spec validation individually. Without the scope-uniqueness
        // rule, the runtime resolver's iteration order — not the
        // operator's intent — decides which one governs a
        // `trustUpstreamPublishTime: true` mapping, silently collapsing
        // the quarantine observation window. This must now fail at
        // apply, before the linter ever runs.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-public", "proxy", None)),
            (
                p("strict.yaml"),
                sp_yaml_with_scope_and_backends("p-strict", "global", &["trivy"]),
            ),
            (
                p("open.yaml"),
                sp_yaml_with_scope_and_backends("p-open", "global", &[]),
            ),
            (
                p("um.yaml"),
                um_yaml_with_trust_pt("npm-up", "npm-public", "https://registry.npmjs.org", true),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(
            err.0.iter().any(|e| {
                let s = e.to_string();
                s.contains("duplicate ScanPolicy scope")
                    && s.contains("Global")
                    && s.contains("p-strict")
                    && s.contains("p-open")
            }),
            "the Gate-2 collapse combination must fail on the duplicate-scope error, got: {:?}",
            err.0
        );
    }

    // -- ScanPolicy scope reference rule ------------------------------------

    #[test]
    fn validate_accepts_scan_policy_scope_naming_a_repository_declared_in_the_same_bundle() {
        // The ordering guarantee this pins: a scan policy may name a
        // repository declared in the SAME desired state. Nothing has to
        // pre-exist in the database.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (
                p("sp.yaml"),
                sp_yaml_with_scope_and_backends(
                    "scan-npm",
                    "{ repository: npm-internal }",
                    &["trivy"],
                ),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        state.validate().expect("declared repository resolves");
    }

    #[test]
    fn validate_rejects_scan_policy_scope_naming_an_undeclared_repository() {
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (
                p("sp.yaml"),
                sp_yaml_with_scope_and_backends(
                    "scan-ghost",
                    "{ repository: ghost-repo }",
                    &["trivy"],
                ),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        let dangling: Vec<&ValidationError> = err
            .0
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    ValidationError::DanglingReference {
                        referrer_kind: Kind::ScanPolicy,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(
            dangling.len(),
            1,
            "only the undeclared name is an error, got: {:?}",
            err.0
        );
        let rendered = dangling[0].to_string();
        assert!(
            rendered.contains("ghost-repo"),
            "the message must name the offending value: {rendered}"
        );
        assert!(
            rendered.contains("scan-ghost"),
            "the message must name the referrer: {rendered}"
        );
        assert!(
            rendered.contains("spec.scope.repository"),
            "the message must name the field: {rendered}"
        );
    }

    /// A `Global` scope references nothing, so the rule must stay silent
    /// — the scope that resolves without a map lookup at all.
    #[test]
    fn validate_ignores_global_scan_policy_scopes() {
        let files = vec![(p("sp.yaml"), sp_yaml("scan-everything"))];
        let state = DesiredState::parse_files(files).unwrap();
        state
            .validate()
            .expect("no repository reference to resolve");
    }

    /// An empty repository name is undeclared like any other: no
    /// repository can carry a blank `metadata.name`, so the scope has no
    /// id to resolve to and the rule must reject it rather than read the
    /// blank as "unscoped".
    #[test]
    fn validate_rejects_a_blank_scan_policy_scope_repository() {
        let files = vec![(
            p("sp.yaml"),
            sp_yaml_with_scope_and_backends("scan-blank", "{ repository: '' }", &["trivy"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(
            err.0.iter().any(|e| matches!(
                e,
                ValidationError::DanglingReference {
                    referrer_kind: Kind::ScanPolicy,
                    referrer_name,
                    ..
                } if referrer_name == "scan-blank"
            )),
            "got: {:?}",
            err.0
        );
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
        // `p1`/`p2` need distinct scopes (only one ScanPolicy may be
        // active per scope) — scope has no bearing on exclusion
        // identity, which is what this test actually exercises. `p2`'s
        // scoped repository is declared because a scope naming an
        // undeclared one is itself a validation error.
        let files = vec![
            (p("p1.yaml"), sp_yaml("p1")),
            (p("repo.yaml"), repo_yaml("other-repo", "hosted", None)),
            (
                p("p2.yaml"),
                sp_yaml_with_scope_and_backends("p2", "{ repository: other-repo }", &["trivy"]),
            ),
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
    fn validate_catches_dangling_permission_grant_service_account_reference() {
        // A `serviceAccount` subject must name a declared ServiceAccount;
        // a missing name dangles, mirroring the repository-reference check.
        let files = vec![(p("g.yaml"), pg_sa_yaml("g", "ghost-sa", "read", None))];
        let state = DesiredState::parse_files(files).unwrap();
        let err = state.validate().unwrap_err();
        assert!(err.0.iter().any(|e| matches!(
            e,
            ValidationError::DanglingReference {
                referrer_kind: Kind::PermissionGrant,
                target_kind: Kind::ServiceAccount,
                field,
                missing_name, ..
            } if missing_name == "ghost-sa" && *field == "spec.subject.name"
        )));
    }

    #[test]
    fn validate_accepts_global_service_account_grant_with_declared_sa() {
        // The headline operator path: a declared SA + a standalone GLOBAL
        // (`repository: None`) serviceAccount grant — the way to express
        // global read / curate / admin_task_invoke for an SA.
        let files = vec![
            (p("repo.yaml"), repo_yaml("npm-public", "hosted", None)),
            (p("sa.yaml"), sa_yaml("maintainer-dev", None)),
            (
                p("g.yaml"),
                pg_sa_yaml("maintainer-dev-global-read", "maintainer-dev", "read", None),
            ),
        ];
        let state = DesiredState::parse_files(files).unwrap();
        assert!(
            state.validate().is_ok(),
            "a global serviceAccount grant referencing a declared SA must validate"
        );
    }

    #[test]
    fn validate_accepts_repo_scoped_service_account_curate_grant() {
        let files = vec![
            (p("repo.yaml"), repo_yaml("oci-prod", "hosted", None)),
            (p("sa.yaml"), sa_yaml("maintainer-curator", None)),
            (
                p("g.yaml"),
                pg_sa_yaml(
                    "curator-grant",
                    "maintainer-curator",
                    "curate",
                    Some("oci-prod"),
                ),
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
            "apiVersion: project-hort.de/v1
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
        let supported = vec!["trivy".to_string(), "osv".to_string()];
        let errors = validate_scan_policy_backends(&state, &supported);
        assert!(
            errors.is_empty(),
            "every entry is in the supported set: {errors:?}"
        );
    }

    #[test]
    fn validate_scan_policy_backends_rejects_unknown_backend_with_descriptive_message() {
        let files = vec![(
            p("p.yaml"),
            sp_yaml_with_backends("strict", &["trivy", "ghost"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let supported = vec!["trivy".to_string(), "osv".to_string()];
        let errors = validate_scan_policy_backends(&state, &supported);
        assert_eq!(errors.len(), 1);
        let detail = errors[0].to_string();
        assert!(
            detail.contains("`ghost`"),
            "error must name the offending entry: {detail}"
        );
        // Both supported backends must surface so the operator can
        // spot a typo immediately.
        assert!(
            detail.contains("trivy"),
            "error must list supported backends: {detail}"
        );
        assert!(
            detail.contains("osv"),
            "error must list supported backends: {detail}"
        );
        assert!(
            detail.contains("scanBackends"),
            "error must surface the field name: {detail}"
        );
    }

    #[test]
    fn validate_scan_policy_backends_empty_list_is_always_valid() {
        // Empty list = "operator opted out of scanning". Must not
        // surface an error regardless of the supported set.
        let files = vec![(p("p.yaml"), sp_yaml_with_backends("noscan", &[]))];
        let state = DesiredState::parse_files(files).unwrap();
        // With backends supported:
        assert!(validate_scan_policy_backends(&state, &["trivy".into()]).is_empty());
        // With an empty supported set:
        assert!(validate_scan_policy_backends(&state, &[]).is_empty());
    }

    #[test]
    fn validate_scan_policy_backends_empty_supported_set_rejects_non_empty_declaration() {
        // Defensive: a build with NO scanner adapters compiled in (empty
        // supported set) rejects any non-empty `scanBackends:` declaration
        // rather than silently writing a policy that could never be
        // satisfied. Not reachable through the production caller, whose
        // capability set (`KNOWN_SCAN_BACKENDS`) is non-empty.
        let files = vec![(p("p.yaml"), sp_yaml_with_backends("strict", &["trivy"]))];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_scan_policy_backends(&state, &[]);
        assert_eq!(errors.len(), 1);
        let detail = errors[0].to_string();
        // The `<none compiled in>` sentinel must surface so the message
        // reads sensibly rather than "got X, expected []".
        assert!(
            detail.contains("none compiled in"),
            "error must surface the empty-supported-set sentinel: {detail}"
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
    fn validate_scan_policy_backends_default_yaml_resolves_against_supported_set() {
        // The minimal `sp_yaml` (no scanBackends key) defaults to
        // `["trivy"]`. With `trivy` in the supported set, the policy must
        // validate — proving the default + happy path hook up correctly.
        let files = vec![(p("p.yaml"), sp_yaml("default-backends"))];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_scan_policy_backends(&state, &["trivy".to_string()]);
        assert!(
            errors.is_empty(),
            "default scanBackends must validate against a trivy-only supported set: {errors:?}"
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
            "apiVersion: project-hort.de/v1
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
            "apiVersion: project-hort.de/v1
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
            "apiVersion: project-hort.de/v1
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
            "apiVersion: project-hort.de/v1
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
            "apiVersion: project-hort.de/v1
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

    fn sa_yaml(name: &str, issuer: Option<&str>) -> Vec<u8> {
        let spec = match issuer {
            None => "spec: {}\n".to_string(),
            Some(i) => format!(
                "spec:
  federatedIdentities:
    - issuer: {i}
      claims:
        repository: my-org/my-repo
"
            ),
        };
        format!(
            "apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: {name}
{spec}"
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
            (p("sa.yaml"), sa_yaml("ci-pusher", None)),
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
                sa_yaml("ci-pypi-pusher", Some("github-actions")),
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
            (p("a.yaml"), sa_yaml("dup", None)),
            (p("b.yaml"), sa_yaml("dup", None)),
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
            "apiVersion: project-hort.de/v1
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
        let yaml = b"apiVersion: project-hort.de/v1
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

    // ===================================================================
    // validate_prefetch_triggers_require_version_discovery
    // ===================================================================

    fn repo_yaml_with_prefetch(name: &str, format: &str, triggers: &[&str]) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: {name}
spec:
  name: {name}
  format: {format}
  type: hosted
  storage: {{ backend: filesystem, path: /data/{name} }}
  isPublic: true
  replicationPriority: immediate
  prefetchPolicy:
    enabled: true
    triggers: [{triggers}]
",
            triggers = triggers.join(", "),
        )
        .into_bytes()
    }

    fn capable(formats: &[&str]) -> std::collections::HashSet<String> {
        formats.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn prefetch_trigger_transitive_deps_rejected_on_non_capable_format() {
        let files = vec![(
            p("maven-proxy.yaml"),
            repo_yaml_with_prefetch("maven-proxy", "maven", &["transitive_deps"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_prefetch_triggers_require_version_discovery(&state, &capable(&[]));
        assert_eq!(errors.len(), 1);
        let ValidationError::Invalid { name, detail, .. } = &errors[0] else {
            panic!("expected Invalid, got {:?}", errors[0]);
        };
        assert_eq!(name, "maven-proxy");
        assert!(detail.contains("transitive_deps"), "{detail}");
        assert!(detail.contains("maven"), "{detail}");
        assert!(detail.contains("maven-proxy"), "{detail}");
    }

    #[test]
    fn prefetch_trigger_scheduled_rejected_on_non_capable_format() {
        let files = vec![(
            p("helm-proxy.yaml"),
            repo_yaml_with_prefetch("helm-proxy", "helm", &["scheduled"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_prefetch_triggers_require_version_discovery(&state, &capable(&[]));
        assert_eq!(errors.len(), 1);
        let ValidationError::Invalid { detail, .. } = &errors[0] else {
            panic!("expected Invalid, got {:?}", errors[0]);
        };
        assert!(detail.contains("scheduled"), "{detail}");
        assert!(detail.contains("helm"), "{detail}");
    }

    #[test]
    fn prefetch_trigger_on_dist_tag_move_accepted_on_non_capable_format() {
        let files = vec![(
            p("oci-proxy.yaml"),
            repo_yaml_with_prefetch("oci-proxy", "oci", &["on_dist_tag_move"]),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_prefetch_triggers_require_version_discovery(&state, &capable(&[]));
        assert!(
            errors.is_empty(),
            "on_dist_tag_move must never be rejected: {errors:?}"
        );
    }

    #[test]
    fn prefetch_trigger_every_trigger_accepted_on_capable_format() {
        let files = vec![(
            p("npm-proxy.yaml"),
            repo_yaml_with_prefetch(
                "npm-proxy",
                "npm",
                &["transitive_deps", "scheduled", "on_dist_tag_move"],
            ),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let errors =
            validate_prefetch_triggers_require_version_discovery(&state, &capable(&["npm"]));
        assert!(
            errors.is_empty(),
            "a VersionDiscovery-capable format must accept every trigger: {errors:?}"
        );
    }

    #[test]
    fn prefetch_trigger_reports_one_error_per_offending_trigger() {
        let files = vec![(
            p("maven-proxy.yaml"),
            repo_yaml_with_prefetch(
                "maven-proxy",
                "maven",
                &["transitive_deps", "scheduled", "on_dist_tag_move"],
            ),
        )];
        let state = DesiredState::parse_files(files).unwrap();
        let errors = validate_prefetch_triggers_require_version_discovery(&state, &capable(&[]));
        assert_eq!(
            errors.len(),
            2,
            "on_dist_tag_move must not add a third error: {errors:?}"
        );
    }

    // ======================================================================
    // Three further ADR 0015 accepted-but-inert operator surfaces:
    // `ScanPolicy.licensePolicy`, `Exclusion.scope`, and a
    // `virtualMembers` entry's format. Each is accepted, stored, visible
    // to an auditor, and decides nothing; each rejection names the field
    // and says what is missing, so an operator does not retry with a
    // different value.
    // ======================================================================

    /// A `ScanPolicy` envelope with an explicit `licensePolicy` body.
    fn sp_yaml_with_license_policy(name: &str, license_policy_yaml: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: {name}
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  licensePolicy: {license_policy_yaml}
"
        )
        .into_bytes()
    }

    fn state_with_license_policies(entries: &[(&str, &str)]) -> DesiredState {
        let files: Vec<(PathBuf, Vec<u8>)> = entries
            .iter()
            .enumerate()
            .map(|(i, (name, lp))| {
                (
                    p(&format!("sp{i}.yaml")),
                    sp_yaml_with_license_policy(name, lp),
                )
            })
            .collect();
        DesiredState::parse_files(files).unwrap()
    }

    #[test]
    fn a_declared_license_policy_is_rejected() {
        let state = state_with_license_policies(&[(
            "prod-default",
            r#"{ denied_licenses: ["GPL-3.0"], action: Block }"#,
        )]);
        let errors = validate_scan_policy_license_policy_not_implemented(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
        let rendered = errors[0].to_string();
        assert!(
            rendered.contains("prod-default"),
            "must name the envelope: {rendered}"
        );
        assert!(
            rendered.contains("licensePolicy"),
            "must name the field: {rendered}"
        );
        assert!(
            rendered.contains("not implemented") && rendered.contains("empty licence list"),
            "must say what is missing, not just that the value is refused: {rendered}"
        );
        assert!(
            rendered.contains("a different value does not change this"),
            "must stop the operator retrying with another value: {rendered}"
        );
    }

    /// The two inert forms. `{}` is what every shipped example tree
    /// writes and an omitted field parses to `null`; both are the
    /// evaluator's own "no policy declared" short-circuit, so both must
    /// keep applying.
    #[test]
    fn the_inert_license_policy_forms_are_accepted() {
        let state = state_with_license_policies(&[("empty-object", "{}")]);
        assert!(
            validate_scan_policy_license_policy_not_implemented(&state).is_empty(),
            "`licensePolicy: {{}}` is the inert default"
        );

        // Omitted entirely — the field defaults to `Value::Null`.
        let omitted = DesiredState::parse_files(vec![(p("sp.yaml"), sp_yaml("omitted"))]).unwrap();
        assert!(
            validate_scan_policy_license_policy_not_implemented(&omitted).is_empty(),
            "an omitted licensePolicy is the inert default"
        );
        let none_at_all = DesiredState::default();
        assert!(
            validate_scan_policy_license_policy_not_implemented(&none_at_all).is_empty(),
            "no ScanPolicy at all cannot produce a finding"
        );
    }

    /// A malformed value (a bare list where an object belongs) is
    /// rejected too. At runtime it reaches the evaluator and produces a
    /// non-blocking `license-policy-shape` advisory — still no licence
    /// decision — so leaving it accepted would keep exactly the assurance
    /// this rule removes.
    #[test]
    fn a_malformed_license_policy_is_rejected_as_well() {
        let state = state_with_license_policies(&[("typo", r#"["GPL-3.0"]"#)]);
        assert_eq!(
            validate_scan_policy_license_policy_not_implemented(&state).len(),
            1,
            "a non-object licensePolicy still declares an intent nothing honours"
        );
    }

    #[test]
    fn each_offending_scan_policy_gets_its_own_license_error() {
        let state = state_with_license_policies(&[
            ("declares-a", r#"{ action: Block }"#),
            ("inert-b", "{}"),
            ("declares-c", r#"{ allowed_licenses: ["MIT"] }"#),
        ]);
        let errors = validate_scan_policy_license_policy_not_implemented(&state);
        assert_eq!(errors.len(), 2, "got: {errors:?}");
        let rendered: Vec<String> = errors.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().any(|e| e.contains("declares-a")));
        assert!(rendered.iter().any(|e| e.contains("declares-c")));
        assert!(
            !rendered.iter().any(|e| e.contains("inert-b")),
            "the inert default is untouched: {rendered:?}"
        );
    }

    // -- Exclusion scope ---------------------------------------------------

    /// An `Exclusion` envelope with an explicit `scope` body.
    fn ex_yaml_with_scope(name: &str, policy: &str, cve_id: &str, scope_yaml: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
kind: Exclusion
metadata:
  name: {name}
spec:
  policy: {policy}
  cveId: {cve_id}
  scope: {scope_yaml}
  reason: test
"
        )
        .into_bytes()
    }

    #[test]
    fn an_exclusion_scoped_to_a_repository_is_rejected() {
        let state = DesiredState::parse_files(vec![(
            p("ex.yaml"),
            ex_yaml_with_scope(
                "cve-2024-3094-on-xz",
                "prod-default",
                "CVE-2024-3094",
                "{ repository: npm-internal }",
            ),
        )])
        .unwrap();
        let errors = validate_exclusion_scope_not_implemented(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
        let rendered = errors[0].to_string();
        assert!(
            rendered.contains("cve-2024-3094-on-xz") && rendered.contains("prod-default"),
            "must name the exclusion and its parent policy: {rendered}"
        );
        assert!(
            rendered.contains("npm-internal"),
            "must name the repository the operator scoped it to: {rendered}"
        );
        assert!(
            rendered.contains("not enforced") && rendered.contains("never reads"),
            "must say the control is missing, not merely that the value is refused: \
             {rendered}"
        );
        assert!(
            rendered.contains("every repository the parent policy governs"),
            "must say what the scope actually does today: {rendered}"
        );
        assert!(
            rendered.contains("scope: global"),
            "must name the one accepted form: {rendered}"
        );
    }

    /// The rejection reaches a repository the bundle DOES declare too —
    /// it is the scope that is refused, not a dangling reference. This is
    /// what makes `ExclusionsApplier::resolve_scope`'s panic unreachable:
    /// a dangling-reference rule would have let a resolvable name
    /// through.
    #[test]
    fn an_exclusion_scoped_to_a_declared_repository_is_rejected_too() {
        let state = DesiredState::parse_files(vec![
            (p("r.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (p("sp.yaml"), sp_yaml("prod-default")),
            (
                p("ex.yaml"),
                ex_yaml_with_scope(
                    "cve-on-declared",
                    "prod-default",
                    "CVE-2024-0001",
                    "{ repository: npm-internal }",
                ),
            ),
        ])
        .unwrap();
        assert_eq!(
            validate_exclusion_scope_not_implemented(&state).len(),
            1,
            "a declared repository name does not make the scope enforceable"
        );
    }

    #[test]
    fn a_global_exclusion_scope_is_accepted() {
        let state = DesiredState::parse_files(vec![(
            p("ex.yaml"),
            ex_yaml("cve-global", "prod-default", "CVE-2024-0002", None),
        )])
        .unwrap();
        assert!(
            validate_exclusion_scope_not_implemented(&state).is_empty(),
            "`scope: global` is the inert default"
        );
        assert!(
            validate_exclusion_scope_not_implemented(&DesiredState::default()).is_empty(),
            "no Exclusion at all cannot produce a finding"
        );
    }

    #[test]
    fn each_offending_exclusion_gets_its_own_scope_error() {
        let state = DesiredState::parse_files(vec![
            (
                p("a.yaml"),
                ex_yaml_with_scope("scoped-a", "p", "CVE-1", "{ repository: r1 }"),
            ),
            (p("b.yaml"), ex_yaml("global-b", "p", "CVE-2", None)),
            (
                p("c.yaml"),
                ex_yaml_with_scope("scoped-c", "p", "CVE-3", "{ repository: r2 }"),
            ),
        ])
        .unwrap();
        let errors = validate_exclusion_scope_not_implemented(&state);
        assert_eq!(errors.len(), 2, "got: {errors:?}");
        let rendered: Vec<String> = errors.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().any(|e| e.contains("scoped-a")));
        assert!(rendered.iter().any(|e| e.contains("scoped-c")));
        assert!(
            !rendered.iter().any(|e| e.contains("global-b")),
            "the global scope is untouched: {rendered:?}"
        );
    }

    // -- virtualMembers format ---------------------------------------------

    /// A `type: virtual` repository over `members`, on `format`.
    fn virtual_repo_yaml(name: &str, format: &str, members: &[&str]) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: {name}
spec:
  name: {name}
  format: {format}
  type: virtual
  virtualMembers: [{members}]
  isPublic: true
  replicationPriority: on_demand
",
            members = members.join(", ")
        )
        .into_bytes()
    }

    #[test]
    fn a_virtual_member_on_another_format_is_rejected() {
        let state = DesiredState::parse_files(vec![
            (
                p("v.yaml"),
                virtual_repo_yaml("all-npm", "npm", &["py-lib"]),
            ),
            (
                p("m.yaml"),
                repo_yaml_with_format("py-lib", "pypi", "hosted"),
            ),
        ])
        .unwrap();
        let errors = validate_virtual_member_formats_not_enforced(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
        let rendered = errors[0].to_string();
        assert!(
            rendered.contains("all-npm") && rendered.contains("py-lib"),
            "must name the virtual and the offending member: {rendered}"
        );
        assert!(
            rendered.contains("pypi") && rendered.contains("npm"),
            "must name both formats: {rendered}"
        );
        assert!(
            rendered.contains("no format-compatibility check is implemented"),
            "must say the control is missing: {rendered}"
        );
        assert!(
            rendered.contains("suppress"),
            "must say what the accepted member would do — own names inside the \
             virtual: {rendered}"
        );
    }

    #[test]
    fn a_same_format_virtual_member_is_accepted() {
        let state = DesiredState::parse_files(vec![
            (
                p("v.yaml"),
                virtual_repo_yaml("all-npm", "npm", &["npm-internal", "npm-public"]),
            ),
            (p("a.yaml"), repo_yaml("npm-internal", "hosted", None)),
            (p("b.yaml"), repo_yaml("npm-public", "proxy", None)),
        ])
        .unwrap();
        assert!(
            validate_virtual_member_formats_not_enforced(&state).is_empty(),
            "a format-homogeneous virtual is the inert default"
        );
    }

    /// Case is normalised the same way every runtime format lookup
    /// normalises it, so `NPM` inside an `npm` virtual is the matching
    /// case rather than a mismatch the operator cannot explain.
    #[test]
    fn member_format_comparison_normalises_case() {
        let state = DesiredState::parse_files(vec![
            (
                p("v.yaml"),
                virtual_repo_yaml("all-npm", "npm", &["shouty"]),
            ),
            (
                p("m.yaml"),
                repo_yaml_with_format("shouty", "NPM", "hosted"),
            ),
        ])
        .unwrap();
        assert!(
            validate_virtual_member_formats_not_enforced(&state).is_empty(),
            "`NPM` and `npm` are the same format to every runtime lookup"
        );
    }

    /// A member name that resolves to nothing is `DanglingVirtualMember`'s
    /// error; naming a format for an undeclared repository would be a
    /// guess.
    #[test]
    fn an_undeclared_virtual_member_produces_no_format_error() {
        let state = DesiredState::parse_files(vec![(
            p("v.yaml"),
            virtual_repo_yaml("all-npm", "npm", &["never-declared"]),
        )])
        .unwrap();
        assert!(
            validate_virtual_member_formats_not_enforced(&state).is_empty(),
            "the dangling-member rule owns this envelope's error"
        );
    }

    /// A non-virtual repository is never inspected — `virtualMembers` on
    /// one is already its own per-spec rejection.
    #[test]
    fn a_non_virtual_repository_is_not_inspected_for_member_formats() {
        let state = DesiredState::parse_files(vec![
            (
                p("h.yaml"),
                repo_yaml("hosted-with-members", "hosted", Some(&["py-lib"])),
            ),
            (
                p("m.yaml"),
                repo_yaml_with_format("py-lib", "pypi", "hosted"),
            ),
        ])
        .unwrap();
        assert!(
            validate_virtual_member_formats_not_enforced(&state).is_empty(),
            "only a type=virtual repository resolves members"
        );
    }

    #[test]
    fn each_offending_member_gets_its_own_format_error() {
        let state = DesiredState::parse_files(vec![
            (
                p("v.yaml"),
                virtual_repo_yaml("all-npm", "npm", &["npm-ok", "py-lib", "crate-lib"]),
            ),
            (p("a.yaml"), repo_yaml("npm-ok", "hosted", None)),
            (
                p("b.yaml"),
                repo_yaml_with_format("py-lib", "pypi", "hosted"),
            ),
            (
                p("c.yaml"),
                repo_yaml_with_format("crate-lib", "cargo", "hosted"),
            ),
        ])
        .unwrap();
        let errors = validate_virtual_member_formats_not_enforced(&state);
        assert_eq!(
            errors.len(),
            2,
            "one error per offending member line, not one per virtual: {errors:?}"
        );
        let rendered: Vec<String> = errors.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().any(|e| e.contains("py-lib")));
        assert!(rendered.iter().any(|e| e.contains("crate-lib")));
        assert!(
            !rendered.iter().any(|e| e.contains("npm-ok")),
            "the matching member is untouched: {rendered:?}"
        );
    }

    // -- ScanPolicy.maxArtifactAge ----------------------------------------

    /// A `ScanPolicy` envelope carrying an explicit `maxArtifactAge`.
    /// `sp_yaml` omits the field, which is the inert default.
    fn sp_yaml_with_max_artifact_age(name: &str, age: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: {name}
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  maxArtifactAge: {age}
  licensePolicy: {{}}
"
        )
        .into_bytes()
    }

    #[test]
    fn a_declared_max_artifact_age_is_rejected() {
        let state = DesiredState::parse_files(vec![(
            p("sp.yaml"),
            sp_yaml_with_max_artifact_age("prod-default", "90d"),
        )])
        .unwrap();
        let errors = validate_scan_policy_max_artifact_age_not_implemented(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
        let rendered = errors[0].to_string();
        assert!(
            rendered.contains("prod-default"),
            "must name the envelope: {rendered}"
        );
        assert!(
            rendered.contains("maxArtifactAge"),
            "must name the field: {rendered}"
        );
        assert!(
            rendered.contains("not implemented") && rendered.contains("never evaluated"),
            "must say what is missing, not just that the value is refused: {rendered}"
        );
        assert!(
            rendered.contains("Remove the field to apply"),
            "must say how to apply: {rendered}"
        );
        assert!(
            rendered.contains("a different duration does not change this"),
            "must stop the operator retrying with another duration: {rendered}"
        );
        assert!(
            rendered.contains("90d"),
            "must echo the declared cap so the operator finds the line: {rendered}"
        );
    }

    /// The only inert form is the absent field — `max_artifact_age` is an
    /// `Option<String>` the evaluator reads as "no cap" when `None`, so
    /// unlike row 10's `licensePolicy: {}` there is no accepted *value*.
    /// An explicit `maxArtifactAge: null` is the same `None` and is
    /// therefore accepted too; it is asserted because the doc comment
    /// claims it, not because any tree writes it.
    #[test]
    fn an_omitted_max_artifact_age_is_accepted() {
        let omitted = DesiredState::parse_files(vec![(p("sp.yaml"), sp_yaml("omitted"))]).unwrap();
        assert!(
            validate_scan_policy_max_artifact_age_not_implemented(&omitted).is_empty(),
            "an omitted maxArtifactAge is the inert default"
        );
        let explicit_null = DesiredState::parse_files(vec![(
            p("sp.yaml"),
            sp_yaml_with_max_artifact_age("explicit-null", "null"),
        )])
        .unwrap();
        assert!(
            explicit_null.scan_policies[0]
                .spec
                .max_artifact_age
                .is_none(),
            "`maxArtifactAge: null` must deserialise to `None`, or the next \
             assertion passes for the wrong reason"
        );
        assert!(
            validate_scan_policy_max_artifact_age_not_implemented(&explicit_null).is_empty(),
            "an explicit null is the same inert state as the absent field"
        );
        let none_at_all = DesiredState::default();
        assert!(
            validate_scan_policy_max_artifact_age_not_implemented(&none_at_all).is_empty(),
            "no ScanPolicy at all cannot produce a finding"
        );
    }

    /// Any duration is rejected, not just a long one: the rejection is
    /// about the missing consumer, so a `0s` cap — which would flag
    /// everything if anything read it — is refused the same way.
    #[test]
    fn every_duration_is_rejected_including_the_strictest() {
        for age in ["0s", "1h", "90d", "10years"] {
            let state = DesiredState::parse_files(vec![(
                p("sp.yaml"),
                sp_yaml_with_max_artifact_age("any-cap", age),
            )])
            .unwrap();
            assert_eq!(
                validate_scan_policy_max_artifact_age_not_implemented(&state).len(),
                1,
                "`{age}` must be rejected — the control is missing, not the value wrong"
            );
        }
    }

    #[test]
    fn each_offending_scan_policy_gets_its_own_max_artifact_age_error() {
        let state = DesiredState::parse_files(vec![
            (
                p("sp0.yaml"),
                sp_yaml_with_max_artifact_age("declares-a", "90d"),
            ),
            (p("sp1.yaml"), sp_yaml("inert-b")),
            (
                p("sp2.yaml"),
                sp_yaml_with_max_artifact_age("declares-c", "7d"),
            ),
        ])
        .unwrap();
        let errors = validate_scan_policy_max_artifact_age_not_implemented(&state);
        assert_eq!(errors.len(), 2, "got: {errors:?}");
        let rendered: Vec<String> = errors.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().any(|e| e.contains("declares-a")));
        assert!(rendered.iter().any(|e| e.contains("declares-c")));
        assert!(
            !rendered.iter().any(|e| e.contains("inert-b")),
            "the inert default is untouched: {rendered:?}"
        );
    }

    /// The format validation this row sits beside is untouched: a
    /// malformed duration is still the per-envelope validator's finding
    /// (`validate_scan_policy_env`), which runs at row 0 — before this
    /// row — and names the parse failure rather than the missing
    /// consumer. Both fire on a malformed value; neither replaces the
    /// other.
    #[test]
    fn a_malformed_duration_still_reaches_the_format_validator() {
        let state = DesiredState::parse_files(vec![(
            p("sp.yaml"),
            sp_yaml_with_max_artifact_age("typo", "forever"),
        )])
        .unwrap();
        let row_0 = state
            .validate()
            .expect_err("a malformed duration is still a row-0 error");
        assert!(
            row_0.to_string().contains("maxArtifactAge")
                && row_0.to_string().contains("not a valid humantime duration"),
            "the format check must survive this row: {row_0}"
        );
        assert_eq!(
            validate_scan_policy_max_artifact_age_not_implemented(&state).len(),
            1,
            "and the declared-cap rejection still applies to it"
        );
    }

    // -- ScanPolicy.compositeVerdictMode x scanBackends (row 15) ----------

    /// A `ScanPolicy` envelope with both halves of the cross-opt-in
    /// stated. `backends` goes in verbatim, so a caller can write `[]`.
    fn sp_yaml_with_composite(name: &str, mode: &str, backends: &str) -> Vec<u8> {
        format!(
            "apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: {name}
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  compositeVerdictMode: {mode}
  scanBackends: {backends}
  licensePolicy: {{}}
"
        )
        .into_bytes()
    }

    #[test]
    fn promoting_the_composite_verdict_with_no_scan_backends_is_rejected() {
        let state = DesiredState::parse_files(vec![(
            p("sp.yaml"),
            sp_yaml_with_composite("waived-but-promoted", "promoted", "[]"),
        )])
        .unwrap();
        let errors = validate_scan_policy_promoted_composite_requires_scan_backends(&state);
        assert_eq!(errors.len(), 1, "got: {errors:?}");
        let rendered = errors[0].to_string();
        assert!(
            rendered.contains("waived-but-promoted"),
            "must name the envelope: {rendered}"
        );
        assert!(
            rendered.contains("compositeVerdictMode: promoted")
                && rendered.contains("scanBackends"),
            "must name BOTH halves of the collapse, not one: {rendered}"
        );
        assert!(
            rendered.contains("never produced"),
            "must say why the combination is inert rather than merely refusing it: {rendered}"
        );
        assert!(
            rendered.contains("scanBackends: [trivy]")
                && rendered.contains("compositeVerdictMode: observed"),
            "must name both ways out — declare backends, or do not promote: {rendered}"
        );
    }

    /// Each half is load-bearing on its own, which is what makes this a
    /// cross-opt-in collapse rather than an inert field: neither value
    /// alone is refused.
    #[test]
    fn either_half_of_the_collapse_alone_is_accepted() {
        let promoted_with_backends = DesiredState::parse_files(vec![(
            p("sp.yaml"),
            sp_yaml_with_composite("promoted-scanning", "promoted", "[trivy]"),
        )])
        .unwrap();
        assert!(
            validate_scan_policy_promoted_composite_requires_scan_backends(&promoted_with_backends)
                .is_empty(),
            "a promotion with a backend to produce the verdict is the supported posture"
        );

        let waived_unpromoted = DesiredState::parse_files(vec![(
            p("sp.yaml"),
            sp_yaml_with_composite("waived", "observed", "[]"),
        )])
        .unwrap();
        assert!(
            validate_scan_policy_promoted_composite_requires_scan_backends(&waived_unpromoted)
                .is_empty(),
            "the scan waiver is an existing, supported posture and this row must not touch it"
        );
    }

    /// The default posture is the accepted one, so no tree that predates
    /// the field can be rejected by this row — including a tree that
    /// waives scanning.
    #[test]
    fn an_omitted_composite_verdict_mode_is_accepted_even_with_no_backends() {
        let state = DesiredState::parse_files(vec![
            (p("a.yaml"), sp_yaml("defaults")),
            (
                p("b.yaml"),
                "apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: legacy-waiver
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 24h
  requireApproval: true
  scanBackends: []
  licensePolicy: {}
"
                .as_bytes()
                .to_vec(),
            ),
        ])
        .unwrap();
        assert!(
            validate_scan_policy_promoted_composite_requires_scan_backends(&state).is_empty(),
            "the field's absence is the inert posture; a pre-existing tree applies unchanged"
        );
    }

    /// One error per offending envelope, so an operator fixes every
    /// offender in one pass rather than being sent round the loop.
    #[test]
    fn every_offending_policy_is_reported() {
        let state = DesiredState::parse_files(vec![
            (
                p("a.yaml"),
                sp_yaml_with_composite("alpha", "promoted", "[]"),
            ),
            (
                p("b.yaml"),
                sp_yaml_with_composite("beta", "promoted", "[]"),
            ),
            (
                p("c.yaml"),
                sp_yaml_with_composite("gamma", "promoted", "[trivy]"),
            ),
        ])
        .unwrap();
        let rendered: Vec<String> =
            validate_scan_policy_promoted_composite_requires_scan_backends(&state)
                .iter()
                .map(ToString::to_string)
                .collect();
        assert_eq!(rendered.len(), 2, "one per offender: {rendered:?}");
        assert!(rendered.iter().any(|e| e.contains("alpha")));
        assert!(rendered.iter().any(|e| e.contains("beta")));
        assert!(
            !rendered.iter().any(|e| e.contains("gamma")),
            "the compliant policy is untouched: {rendered:?}"
        );
    }

    /// A mis-spelled mode is `validate_scan_policy`'s typed reject and
    /// must not be read here as *either* posture: reading it as
    /// `promoted` would reject a bundle on a second, confusing ground,
    /// and the parse failure is the actionable message.
    #[test]
    fn a_malformed_mode_is_left_to_the_per_envelope_validator() {
        let state = DesiredState::parse_files(vec![(
            p("sp.yaml"),
            sp_yaml_with_composite("typo", "promotd", "[]"),
        )])
        .unwrap();
        assert!(
            validate_scan_policy_promoted_composite_requires_scan_backends(&state).is_empty(),
            "an unparseable mode is not a promotion"
        );
        let row_0 = state
            .validate()
            .expect_err("a malformed mode is still a row-0 error");
        assert!(
            row_0.to_string().contains("compositeVerdictMode"),
            "and that is the message the operator gets: {row_0}"
        );
    }
}
