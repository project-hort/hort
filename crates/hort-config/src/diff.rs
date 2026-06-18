//! Snapshot, ApplyPlan, and the `diff` function.
//!
//! `diff` is pure: it reads a `CurrentSnapshot` and a `DesiredState`
//! and produces an `ApplyPlan` describing the create/update/delete/
//! unchanged decisions per kind. No I/O — the `ApplyConfigUseCase`
//! executes the plan; this module only computes it.
//!
//! "Changed" is digest-based: `spec_digest` hashes the canonicalised
//! spec (sorted-key JSON, then SHA-256). The digest is written alongside
//! each managed row, so re-applying the same YAML on the next boot
//! produces an empty plan instead of a redundant UPDATE.

use std::collections::{HashMap, HashSet};

use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::rbac::Permission;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::claim_mapping::ClaimMappingSpec;
use crate::curation_rule::CurationRuleSpec;
use crate::desired::DesiredState;
use crate::envelope::Envelope;
use crate::oidc_issuer::OidcIssuerSpec;
use crate::permission_grant::{GrantIdentity, PermissionGrantSpec};
use crate::repository::RepositorySpec;
use crate::service_account::ServiceAccountSpec;
use crate::upstream_mapping::UpstreamMappingSpec;

/// A snapshot of current state, built by the boot caller from
/// `RepositoryRepository::list` and
/// `ClaimMappingRepository::list_managed_by_gitops`.
///
/// Carries only the fields the diff cares about (id/name/managed_by/
/// digest) — the full entities are not needed here. Keeping the
/// snapshot lean lets unit tests build fixtures without reaching into
/// every domain field.
///
/// Carries the CRUD-extension views (`permission_grants`,
/// `curation_rules`); event-sourced kinds (`scan_policies`,
/// `exclusions`) are NOT represented here — their projection is
/// consulted directly by the `ApplyEventSourcedKind` trait.
///
/// `roles` + `group_mappings` have been replaced by `claim_mappings`
/// (additive-claims model, see ADR 0012) and `permission_grants` uses
/// the subject shape.
#[derive(Debug, Clone, Default)]
pub struct CurrentSnapshot {
    pub repositories: Vec<CurrentRepository>,
    pub claim_mappings: Vec<CurrentClaimMapping>,
    pub permission_grants: Vec<CurrentPermissionGrant>,
    pub curation_rules: Vec<CurrentCurationRule>,
    pub upstream_mappings: Vec<CurrentUpstreamMapping>,
    /// Declared OIDC issuers loaded by the apply pipeline from
    /// `OidcIssuerRepository::list`. The row has no `managed_by`
    /// column (the aggregate is gitops-only), so the snapshot view
    /// carries only the id + name + digest.
    pub oidc_issuers: Vec<CurrentOidcIssuer>,
    /// Declared service accounts.
    pub service_accounts: Vec<CurrentServiceAccount>,
    /// Set of `managed_by_digest` values
    /// owned by `ServiceAccount` aggregates. The PG-sweep in
    /// [`diff_permission_grants`] consults this set to skip rows whose
    /// digest belongs to an SA (snapshot-side); those rows are
    /// reconciled by `reconcile_service_account_grants` /
    /// `delete_service_account_grants` in the apply use case, NOT by
    /// the PG delete plan.
    ///
    /// The set is computed by the snapshot builder (in
    /// `hort-app::apply_config_use_case::build_snapshot`) over the full
    /// SA aggregates loaded from the SA repository — the diff layer is
    /// pure and accepts the already-computed set. The canonical digest
    /// scheme (`sha256("sa-grant|{sa.id}|{role}|{permission}|{sorted_repos}")`)
    /// uses the SA's UUID, so the set is keyed off the SAs in the
    /// snapshot — including SAs about to be deleted (whose SA-owned
    /// grants must continue to be excluded from the PG sweep until
    /// `apply_service_accounts` cleans them up).
    pub sa_owned_grant_digests: HashSet<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentRepository {
    pub id: Uuid,
    pub key: String,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
}

/// Current-snapshot view of one `claim_mappings` row (replaces the
/// retired `CurrentGroupMapping`).
///
/// Identity is `name` (the envelope `metadata.name`). The diff layer
/// keys off it exactly as the dropped group-mapping diff did — only
/// the table and the spec body changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentClaimMapping {
    pub name: String,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
}

/// Current-snapshot view of one `permission_grants` row.
///
/// The diff identity is subject-dependent
/// ([`crate::permission_grant::GrantIdentity`]):
/// `(sorted required_claims, repository, permission)` for a `Claims`
/// subject; `(user_id, repository, permission)` for a `User` subject.
/// This is the same logical key the apply UPSERT uses. `metadata.name`
/// on the YAML envelope is operator-cosmetic and does NOT participate
/// in identity.
///
/// The apply pipeline materialises `repository_name` (the row's
/// `repository_id` UUID resolved to its `ArtifactRepository.key` via
/// the loaded repository snapshot) and `user_id` (the row's
/// `user_id`, stringified) and feeds them here. The diff layer is
/// pure: it does no lookups itself. Exactly one of `required_claims`
/// / `user_id` is `Some` per row (the `subject_exclusive` DB CHECK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentPermissionGrant {
    pub id: Uuid,
    /// `Some` for a `Claims` subject (already sorted by the snapshot
    /// builder so it compares equal to the desired-side sorted set).
    pub required_claims: Option<Vec<String>>,
    /// `Some` for a `User` subject — the row's `user_id` stringified.
    pub user_id: Option<String>,
    pub permission: Permission,
    pub repository_name: Option<String>,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
}

/// Current-snapshot view of one `curation_rules` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentCurationRule {
    pub id: Uuid,
    pub name: String,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
}

/// Current-snapshot view of one `oidc_issuers` row.
///
/// Identity is `name` — name-based identity means an issuer-URL
/// change surfaces as `Updated`, not `Created+Deleted`, preserving
/// audit continuity. No `managed_by` column on the underlying table
/// (the aggregate is gitops-only); the snapshot view drops the
/// corresponding field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentOidcIssuer {
    pub id: Uuid,
    pub name: String,
    /// SHA-256 of the canonicalised spec, captured by the apply use
    /// case when it persists the row. The diff uses this to decide
    /// `unchanged` vs `update`. `None` means "row exists but no
    /// digest captured" — out-of-band INSERTs or migrated-in rows;
    /// the diff treats that as `update` to bring the row under the
    /// digest contract.
    pub digest: Option<[u8; 32]>,
}

/// Current-snapshot view of one `service_accounts` row.
///
/// Identity is `name`. The diff identity for the SA aggregate is
/// envelope-level — the federated-identity sub-rows and the
/// fallback-rotation row are reconciled inside the apply use case's
/// `apply_service_accounts` transaction (replace-on-update).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentServiceAccount {
    pub id: Uuid,
    pub name: String,
    pub digest: Option<[u8; 32]>,
}

/// Current-snapshot view of one `repository_upstream_mappings` row.
///
/// Diff identity is the composite `(repository_name, path_prefix)` —
/// the same pair the schema-level UNIQUE constraint enforces. The apply
/// pipeline materialises `repository_name` from its loaded repository
/// snapshot (UUID `repository_id` → `key`) and feeds the pair here. The
/// diff layer is pure: it does no lookups itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentUpstreamMapping {
    pub id: Uuid,
    pub repository_name: String,
    pub path_prefix: String,
    pub managed_by: ManagedBy,
    pub managed_by_digest: Option<[u8; 32]>,
}

/// What `apply` should do for one kind. `Spec` is `RepositorySpec` or
/// `ClaimMappingSpec`.
#[derive(Debug, Clone)]
pub struct KindPlan<Spec, K>
where
    Spec: Clone,
    K: Clone,
{
    pub create: Vec<Envelope<Spec>>,
    /// Entries whose digest changed since last apply.
    pub update: Vec<Envelope<Spec>>,
    /// Identifiers of `managed_by = GitOps` rows present in the
    /// snapshot but absent from the desired state. Repositories key
    /// off `Uuid`; claim mappings key off `name` (the table doesn't
    /// expose UUIDs to the gitops surface).
    pub delete: Vec<K>,
    /// Counter only — boot log emits this in the apply summary.
    pub unchanged: usize,
}

impl<Spec: Clone, K: Clone> Default for KindPlan<Spec, K> {
    fn default() -> Self {
        Self {
            create: Vec::new(),
            update: Vec::new(),
            delete: Vec::new(),
            unchanged: 0,
        }
    }
}

/// The complete plan, kind by kind. Applied in topological order:
/// ClaimMapping first (no foreign references), then ArtifactRepository
/// in two passes (rows then virtual-member edges).
///
/// The topological order: `ClaimMapping` and `CurationRule` have no
/// inbound references and apply first; `Repository` references
/// `CurationRule` (so curation rules apply first); `PermissionGrant`
/// references `Repository` (and, for a `User` subject, a backing user)
/// and applies last among CRUD kinds. Event-sourced kinds run after
/// CRUD via `ApplyEventSourcedKind`.
///
/// `roles` / `group_mappings` plans were dropped when those kinds were
/// retired (additive-claims model, see ADR 0012).
#[derive(Debug, Clone, Default)]
pub struct ApplyPlan {
    pub repositories: KindPlan<RepositorySpec, Uuid>,
    pub claim_mappings: KindPlan<ClaimMappingSpec, String>,
    pub permission_grants: KindPlan<PermissionGrantSpec, Uuid>,
    pub curation_rules: KindPlan<CurationRuleSpec, Uuid>,
    pub upstream_mappings: KindPlan<UpstreamMappingSpec, Uuid>,
    /// Applied after `repositories` and before `service_accounts` so
    /// the cross-kind FK (`ServiceAccount.federatedIdentities[].issuer`
    /// references `OidcIssuer.name`) resolves cleanly during audit.
    pub oidc_issuers: KindPlan<OidcIssuerSpec, String>,
    /// Applied after `oidc_issuers`. `K = String` (the SA name) —
    /// `delete_by_name` is the port verb.
    pub service_accounts: KindPlan<ServiceAccountSpec, String>,
}

/// Pure diff: produce an `ApplyPlan` given the current snapshot and
/// the desired state. Five outcomes per object:
///
/// - **Create**: in desired, not in current.
/// - **Update**: in both, digest differs.
/// - **Delete**: in current with `managed_by = GitOps`, absent in desired.
/// - **Unchanged**: in both, digest matches.
/// - **Conflict**: in current with `managed_by = Local`, also in desired
///   — surfaces from `validate_against`, NOT from `diff`. The diff
///   silently treats `Local` rows as if they're not there for the
///   create/update decision (validate_against has already failed) —
///   downstream callers therefore never see a conflict here.
pub fn diff(current: &CurrentSnapshot, desired: &DesiredState) -> ApplyPlan {
    ApplyPlan {
        repositories: diff_repositories(current, desired),
        claim_mappings: diff_claim_mappings(current, desired),
        permission_grants: diff_permission_grants(current, desired),
        curation_rules: diff_curation_rules(current, desired),
        upstream_mappings: diff_upstream_mappings(current, desired),
        oidc_issuers: diff_oidc_issuers(current, desired),
        service_accounts: diff_service_accounts(current, desired),
    }
}

fn diff_repositories(
    current: &CurrentSnapshot,
    desired: &DesiredState,
) -> KindPlan<RepositorySpec, Uuid> {
    let mut plan = KindPlan::<RepositorySpec, Uuid>::default();
    let current_managed: HashMap<&str, &CurrentRepository> = current
        .repositories
        .iter()
        .filter(|r| r.managed_by == ManagedBy::GitOps)
        .map(|r| (r.key.as_str(), r))
        .collect();
    let desired_keys: HashSet<&str> = desired
        .repositories
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();

    for env in &desired.repositories {
        let digest = spec_digest_repository(&env.spec);
        match current_managed.get(env.metadata.name.as_str()) {
            None => plan.create.push(env.clone()),
            Some(existing) => {
                if existing.managed_by_digest == Some(digest) {
                    plan.unchanged += 1;
                } else {
                    plan.update.push(env.clone());
                }
            }
        }
    }

    for cur in current.repositories.iter() {
        if cur.managed_by != ManagedBy::GitOps {
            continue;
        }
        if !desired_keys.contains(cur.key.as_str()) {
            plan.delete.push(cur.id);
        }
    }

    plan
}

fn diff_claim_mappings(
    current: &CurrentSnapshot,
    desired: &DesiredState,
) -> KindPlan<ClaimMappingSpec, String> {
    let mut plan = KindPlan::<ClaimMappingSpec, String>::default();
    let current_managed: HashMap<&str, &CurrentClaimMapping> = current
        .claim_mappings
        .iter()
        .filter(|g| g.managed_by == ManagedBy::GitOps)
        .map(|g| (g.name.as_str(), g))
        .collect();
    let desired_names: HashSet<&str> = desired
        .claim_mappings
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();

    for env in &desired.claim_mappings {
        let digest = spec_digest_claim_mapping(&env.spec);
        match current_managed.get(env.metadata.name.as_str()) {
            None => plan.create.push(env.clone()),
            Some(existing) => {
                if existing.managed_by_digest == Some(digest) {
                    plan.unchanged += 1;
                } else {
                    plan.update.push(env.clone());
                }
            }
        }
    }

    for cur in current.claim_mappings.iter() {
        if cur.managed_by != ManagedBy::GitOps {
            continue;
        }
        if !desired_names.contains(cur.name.as_str()) {
            plan.delete.push(cur.name.clone());
        }
    }

    plan
}

/// Subject-dependent identity of one current `permission_grants` row,
/// mapped to the same
/// [`crate::permission_grant::GrantIdentity`] the desired side
/// produces so the two compare directly. The snapshot builder has
/// already sorted `required_claims`, so the `Claims` arm does not
/// re-sort.
fn current_grant_identity(g: &CurrentPermissionGrant) -> Option<GrantIdentity> {
    match (&g.required_claims, &g.user_id) {
        (Some(required), None) => Some(GrantIdentity::Claims {
            required: required.clone(),
            repository: g.repository_name.clone(),
            permission: g.permission,
        }),
        (None, Some(user_id)) => Some(GrantIdentity::User {
            user_id: user_id.clone(),
            repository: g.repository_name.clone(),
            permission: g.permission,
        }),
        // Both/neither set violates the `subject_exclusive` DB CHECK;
        // a row that reaches the diff in this shape is excluded from
        // identity matching (the apply layer surfaces the invariant).
        _ => None,
    }
}

/// PermissionGrant diff. One envelope = one grant = one
/// subject-dependent identity. The envelope is classified as:
///
/// - **create** when its identity has no matching managed row.
/// - **update** when a matching row exists but its digest differs
///   from the new envelope's digest.
/// - **unchanged** when a matching row exists with an equal digest.
///
/// Per-row counters are emitted by `apply_permission_grants` during
/// the UPSERT loop; the diff only classifies envelopes.
fn diff_permission_grants(
    current: &CurrentSnapshot,
    desired: &DesiredState,
) -> KindPlan<PermissionGrantSpec, Uuid> {
    let mut plan = KindPlan::<PermissionGrantSpec, Uuid>::default();
    let current_managed: HashMap<GrantIdentity, &CurrentPermissionGrant> = current
        .permission_grants
        .iter()
        .filter(|g| g.managed_by == ManagedBy::GitOps)
        .filter_map(|g| current_grant_identity(g).map(|ident| (ident, g)))
        .collect();
    let desired_identities: HashSet<GrantIdentity> = desired
        .permission_grants
        .iter()
        .map(|e| e.spec.diff_identity())
        .collect();

    for env in &desired.permission_grants {
        let digest = spec_digest_permission_grant(&env.spec);
        let identity = env.spec.diff_identity();
        match current_managed.get(&identity) {
            None => plan.create.push(env.clone()),
            Some(existing) => {
                if existing.managed_by_digest == Some(digest) {
                    plan.unchanged += 1;
                } else {
                    plan.update.push(env.clone());
                }
            }
        }
    }

    for cur in current.permission_grants.iter() {
        if cur.managed_by != ManagedBy::GitOps {
            continue;
        }
        // SA-owned grants are tagged with a digest computed by
        // `reconcile_service_account_grants`; their lifecycle belongs
        // to the SA, not to any `PermissionGrant` envelope. Excluding
        // them here keeps the PG-sweep from over-deleting SA-owned rows
        // on an apply that declares the SA but no mirror
        // `PermissionGrant`, and routes the SA-delete cleanup through
        // `delete_service_account_grants` (the only path that should
        // touch these rows).
        //
        // Why a digest and NOT `users.is_service_account = true`?
        // An SA's authority is materialised as
        // `GrantSubject::User(backing_user_id)` rows. A human admin can
        // independently create a `User`-subject grant for that same
        // backing user on an unrelated repo (operationally legitimate).
        // The digest is per-SA-spec, so it identifies the rows the SA
        // aggregate owns without trampling admin-created grants on the
        // shared backing user. The is_service_account predicate would
        // over-collapse: every grant on the SA's backing user would be
        // exempt from the PG sweep, which is wrong because
        // admin-created ones should remain admin-managed (no
        // `managed_by_digest`).
        if let Some(digest) = cur.managed_by_digest {
            if current.sa_owned_grant_digests.contains(&digest) {
                continue;
            }
        }
        match current_grant_identity(cur) {
            Some(ident) if !desired_identities.contains(&ident) => {
                plan.delete.push(cur.id);
            }
            // A malformed-subject row (both/neither column set) has no
            // identity to match; the apply layer surfaces the invariant
            // — the diff does not over-delete it on absence.
            _ => {}
        }
    }

    plan
}

fn diff_curation_rules(
    current: &CurrentSnapshot,
    desired: &DesiredState,
) -> KindPlan<CurationRuleSpec, Uuid> {
    let mut plan = KindPlan::<CurationRuleSpec, Uuid>::default();
    let current_managed: HashMap<&str, &CurrentCurationRule> = current
        .curation_rules
        .iter()
        .filter(|r| r.managed_by == ManagedBy::GitOps)
        .map(|r| (r.name.as_str(), r))
        .collect();
    let desired_names: HashSet<&str> = desired
        .curation_rules
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();

    for env in &desired.curation_rules {
        let digest = spec_digest_curation_rule(&env.spec);
        match current_managed.get(env.metadata.name.as_str()) {
            None => plan.create.push(env.clone()),
            Some(existing) => {
                if existing.managed_by_digest == Some(digest) {
                    plan.unchanged += 1;
                } else {
                    plan.update.push(env.clone());
                }
            }
        }
    }

    for cur in current.curation_rules.iter() {
        if cur.managed_by != ManagedBy::GitOps {
            continue;
        }
        if !desired_names.contains(cur.name.as_str()) {
            plan.delete.push(cur.id);
        }
    }

    plan
}

/// Diff upstream mappings.
///
/// Identity is the composite `(repository_name, path_prefix)` — operator-
/// chosen `metadata.name` is cosmetic, exactly as for `PermissionGrant`.
/// The apply pipeline (`apply_upstream_mappings`) resolves
/// `desired.spec.repository → repository_id` against the loaded
/// repository snapshot.
type UpstreamMappingIdentity = (String, String);

fn upstream_mapping_identity(spec: &UpstreamMappingSpec) -> UpstreamMappingIdentity {
    (spec.repository.clone(), spec.path_prefix.clone())
}

fn current_upstream_mapping_identity(m: &CurrentUpstreamMapping) -> UpstreamMappingIdentity {
    (m.repository_name.clone(), m.path_prefix.clone())
}

fn diff_upstream_mappings(
    current: &CurrentSnapshot,
    desired: &DesiredState,
) -> KindPlan<UpstreamMappingSpec, Uuid> {
    let mut plan = KindPlan::<UpstreamMappingSpec, Uuid>::default();
    let current_managed: HashMap<UpstreamMappingIdentity, &CurrentUpstreamMapping> = current
        .upstream_mappings
        .iter()
        .filter(|m| m.managed_by == ManagedBy::GitOps)
        .map(|m| (current_upstream_mapping_identity(m), m))
        .collect();
    let desired_identities: HashSet<UpstreamMappingIdentity> = desired
        .upstream_mappings
        .iter()
        .map(|e| upstream_mapping_identity(&e.spec))
        .collect();

    for env in &desired.upstream_mappings {
        let digest = spec_digest_upstream_mapping(&env.spec);
        let identity = upstream_mapping_identity(&env.spec);
        match current_managed.get(&identity) {
            None => plan.create.push(env.clone()),
            Some(existing) => {
                if existing.managed_by_digest == Some(digest) {
                    plan.unchanged += 1;
                } else {
                    plan.update.push(env.clone());
                }
            }
        }
    }

    for cur in current.upstream_mappings.iter() {
        if cur.managed_by != ManagedBy::GitOps {
            continue;
        }
        if !desired_identities.contains(&current_upstream_mapping_identity(cur)) {
            plan.delete.push(cur.id);
        }
    }

    plan
}

/// Diff for `OidcIssuer` envelopes.
///
/// Standard "name as identity, digest as change-detector" shape — no
/// `managed_by` filtering because the underlying table has no such
/// column (the aggregate is gitops-only). Every row in
/// `current.oidc_issuers` is treated as gitops-managed.
fn diff_oidc_issuers(
    current: &CurrentSnapshot,
    desired: &DesiredState,
) -> KindPlan<OidcIssuerSpec, String> {
    let mut plan = KindPlan::<OidcIssuerSpec, String>::default();
    let current_by_name: HashMap<&str, &CurrentOidcIssuer> = current
        .oidc_issuers
        .iter()
        .map(|i| (i.name.as_str(), i))
        .collect();
    let desired_names: HashSet<&str> = desired
        .oidc_issuers
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();

    for env in &desired.oidc_issuers {
        let digest = spec_digest_oidc_issuer(&env.spec);
        match current_by_name.get(env.metadata.name.as_str()) {
            None => plan.create.push(env.clone()),
            Some(existing) => {
                if existing.digest == Some(digest) {
                    plan.unchanged += 1;
                } else {
                    plan.update.push(env.clone());
                }
            }
        }
    }

    for cur in current.oidc_issuers.iter() {
        if !desired_names.contains(cur.name.as_str()) {
            plan.delete.push(cur.name.clone());
        }
    }

    plan
}

/// Diff for `ServiceAccount` envelopes.
///
/// Same shape as [`diff_oidc_issuers`]. The SA envelope's identity is
/// `metadata.name`; the sub-aggregates (federated identities,
/// fallback rotation) live on dependent rows and are reconciled
/// inside the apply use case's `apply_service_accounts` transaction.
fn diff_service_accounts(
    current: &CurrentSnapshot,
    desired: &DesiredState,
) -> KindPlan<ServiceAccountSpec, String> {
    let mut plan = KindPlan::<ServiceAccountSpec, String>::default();
    let current_by_name: HashMap<&str, &CurrentServiceAccount> = current
        .service_accounts
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    let desired_names: HashSet<&str> = desired
        .service_accounts
        .iter()
        .map(|e| e.metadata.name.as_str())
        .collect();

    for env in &desired.service_accounts {
        let digest = spec_digest_service_account(&env.spec);
        match current_by_name.get(env.metadata.name.as_str()) {
            None => plan.create.push(env.clone()),
            Some(existing) => {
                if existing.digest == Some(digest) {
                    plan.unchanged += 1;
                } else {
                    plan.update.push(env.clone());
                }
            }
        }
    }

    for cur in current.service_accounts.iter() {
        if !desired_names.contains(cur.name.as_str()) {
            plan.delete.push(cur.name.clone());
        }
    }

    plan
}

/// SHA-256 over the canonicalised JSON of an `OidcIssuerSpec`.
/// Canonicalisation drops field order and
/// whitespace; re-applying the same YAML produces the same digest
/// across boots.
pub fn spec_digest_oidc_issuer(spec: &OidcIssuerSpec) -> [u8; 32] {
    let mut normalised = spec.clone();
    // Sort audiences + allowed_algorithms so operator reordering in
    // YAML doesn't trigger a spurious "update" — the validation pass
    // treats both as unordered sets, the digest should too.
    normalised.audiences.sort();
    normalised.allowed_algorithms.sort();
    sha256_canonical_json(&normalised)
}

/// SHA-256 over the canonicalised JSON of a `ServiceAccountSpec`.
///
/// `repositories` and `federated_identities` are sorted before
/// hashing so re-ordering in YAML doesn't flip the digest. The
/// `claims` map inside each `FederatedIdentitySpec` is already a
/// `BTreeMap` (key-sorted), so no extra normalisation there.
pub fn spec_digest_service_account(spec: &ServiceAccountSpec) -> [u8; 32] {
    let mut normalised = spec.clone();
    normalised.repositories.sort();
    // Sort by `(issuer, claims)` for stability — two envelopes
    // declaring the same SA with the same trust policy but the
    // identities listed in a different order must digest the same.
    normalised.federated_identities.sort_by(|a, b| {
        a.issuer
            .cmp(&b.issuer)
            .then_with(|| a.claims.cmp(&b.claims))
    });
    sha256_canonical_json(&normalised)
}

/// SHA-256 over the canonicalised JSON of `spec`.
///
/// "Canonical" = `serde_json::to_value` (which serialises to a
/// `Map<String, Value>` with insertion order in serde_json 1.x), then
/// re-serialise into a `BTreeMap` to force lexicographic key order
/// before hashing. Whitespace in the YAML doesn't matter (we hash
/// the parsed struct), and field ordering in the YAML doesn't matter
/// either (we sort).
///
/// Generic over `Spec: Serialize` so both kinds can share the
/// algorithm. `RepositorySpec` is special-cased to also sort the
/// `virtual_members` list before hashing — operators reordering the
/// same membership in YAML must produce the same digest.
pub fn spec_digest_repository(spec: &RepositorySpec) -> [u8; 32] {
    let mut normalised = spec.clone();
    if let Some(members) = normalised.virtual_members.as_mut() {
        members.sort();
    }
    sha256_canonical_json(&normalised)
}

/// SHA-256 over the canonicalised JSON of a `ClaimMappingSpec`
/// (replaces the retired `spec_digest_group_mapping`).
///
/// The canonicalisation step (sorted keys at every level) means YAML
/// field reordering does not produce a spurious "spec changed"
/// outcome on re-apply.
pub fn spec_digest_claim_mapping(spec: &ClaimMappingSpec) -> [u8; 32] {
    sha256_canonical_json(spec)
}

/// SHA-256 over the canonicalised JSON of a `PermissionGrantSpec`.
///
/// `subject` is internally tagged; a `Claims` subject's `required`
/// array is **not** sorted here — the digest tracks the operator's
/// declared spec verbatim (a reordered claim list is a different
/// digest → `update`). Diff *identity* (`diff_identity`) sorts the
/// claim set so a reordered-but-equivalent grant still matches the
/// same row; the digest then drives the unchanged-vs-update decision
/// for that matched row.
pub fn spec_digest_permission_grant(spec: &PermissionGrantSpec) -> [u8; 32] {
    sha256_canonical_json(spec)
}

/// SHA-256 over the canonicalised JSON of a `CurationRuleSpec`.
pub fn spec_digest_curation_rule(spec: &CurationRuleSpec) -> [u8; 32] {
    sha256_canonical_json(spec)
}

/// SHA-256 over the canonicalised JSON of an `UpstreamMappingSpec`.
/// The canonicalisation drops field order and whitespace so two YAMLs
/// declaring the same logical mapping produce the same digest on
/// re-apply.
pub fn spec_digest_upstream_mapping(spec: &UpstreamMappingSpec) -> [u8; 32] {
    sha256_canonical_json(spec)
}

fn sha256_canonical_json<S: Serialize>(value: &S) -> [u8; 32] {
    // Round-trip through serde_json::Value to canonicalise the shape,
    // then through a BTreeMap-backed `to_string` so the output has
    // sorted keys at every level.
    let v = serde_json::to_value(value).expect("Spec must serialize");
    let canonical = canonicalise(&v);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Recursively render a `serde_json::Value` with sorted object keys.
/// Arrays preserve their order — `spec_digest_repository` sorts the
/// member list explicitly because reordering YAML members must not
/// change the digest, but an array of, say, `curation` rules is
/// position-significant and stays in input order.
fn canonicalise(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap(),
        serde_json::Value::Array(a) => {
            let items: Vec<String> = a.iter().map(canonicalise).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(map) => {
            // BTreeMap forces lexicographic key order.
            let sorted: std::collections::BTreeMap<&String, &serde_json::Value> =
                map.iter().collect();
            let items: Vec<String> = sorted
                .into_iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonicalise(val)
                    )
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ApiVersion, Kind, Metadata};
    use crate::repository::StorageSpec;

    fn repo_spec(name: &str) -> RepositorySpec {
        RepositorySpec {
            name: name.into(),
            description: None,
            format: "npm".into(),
            repo_type: "hosted".into(),
            storage: Some(StorageSpec {
                backend: "filesystem".into(),
                path: format!("/data/{name}"),
            }),
            proxy: None,
            virtual_members: None,
            is_public: true,
            download_audit_enabled: false,
            index_mode: hort_domain::entities::repository::IndexMode::default(),
            prefetch_policy: hort_domain::entities::repository::PrefetchPolicy::default(),
            quota_bytes: None,
            replication_priority: "immediate".into(),
            promotion: None,
            curation_rules: None,
        }
    }

    fn repo_env(name: &str) -> Envelope<RepositorySpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ArtifactRepository,
            metadata: Metadata { name: name.into() },
            spec: repo_spec(name),
        }
    }

    fn cm_env(name: &str, idp_group: &str, claim: &str) -> Envelope<ClaimMappingSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ClaimMapping,
            metadata: Metadata { name: name.into() },
            spec: ClaimMappingSpec {
                idp_group: idp_group.into(),
                claim: claim.into(),
            },
        }
    }

    fn current_repo(
        key: &str,
        managed_by: ManagedBy,
        digest: Option<[u8; 32]>,
    ) -> CurrentRepository {
        CurrentRepository {
            id: Uuid::new_v4(),
            key: key.into(),
            managed_by,
            managed_by_digest: digest,
        }
    }

    fn current_cm(
        name: &str,
        managed_by: ManagedBy,
        digest: Option<[u8; 32]>,
    ) -> CurrentClaimMapping {
        CurrentClaimMapping {
            name: name.into(),
            managed_by,
            managed_by_digest: digest,
        }
    }

    // -- diff outcomes ------------------------------------------------------

    #[test]
    fn empty_snapshot_empty_desired_yields_empty_plan() {
        let plan = diff(&CurrentSnapshot::default(), &DesiredState::default());
        assert!(plan.repositories.create.is_empty());
        assert!(plan.repositories.update.is_empty());
        assert!(plan.repositories.delete.is_empty());
        assert_eq!(plan.repositories.unchanged, 0);
    }

    #[test]
    fn pure_create_when_desired_only() {
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("a"));
        desired.claim_mappings.push(cm_env("admins", "g", "r"));
        let plan = diff(&CurrentSnapshot::default(), &desired);
        assert_eq!(plan.repositories.create.len(), 1);
        assert_eq!(plan.repositories.create[0].metadata.name, "a");
        assert_eq!(plan.claim_mappings.create.len(), 1);
    }

    #[test]
    fn unchanged_when_digest_matches() {
        let env = repo_env("a");
        let digest = spec_digest_repository(&env.spec);
        let snapshot = CurrentSnapshot {
            repositories: vec![current_repo("a", ManagedBy::GitOps, Some(digest))],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        let plan = diff(&snapshot, &desired);
        assert!(plan.repositories.create.is_empty());
        assert!(plan.repositories.update.is_empty());
        assert_eq!(plan.repositories.unchanged, 1);
    }

    #[test]
    fn update_when_digest_differs() {
        let env = repo_env("a");
        let snapshot = CurrentSnapshot {
            repositories: vec![current_repo(
                "a",
                ManagedBy::GitOps,
                Some([0xff; 32]), // wrong digest
            )],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        let plan = diff(&snapshot, &desired);
        assert!(plan.repositories.create.is_empty());
        assert_eq!(plan.repositories.update.len(), 1);
        assert_eq!(plan.repositories.unchanged, 0);
    }

    #[test]
    fn delete_for_managed_row_absent_from_desired() {
        let stale_id = Uuid::new_v4();
        let snapshot = CurrentSnapshot {
            repositories: vec![CurrentRepository {
                id: stale_id,
                key: "stale".into(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some([0; 32]),
            }],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert_eq!(plan.repositories.delete, vec![stale_id]);
    }

    #[test]
    fn local_row_absent_from_desired_is_not_deleted() {
        // Only `managed_by = GitOps` rows are diff candidates. A
        // Local row that the operator created via the API stays
        // untouched even if no YAML mentions it.
        let snapshot = CurrentSnapshot {
            repositories: vec![current_repo("user-created", ManagedBy::Local, None)],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert!(plan.repositories.delete.is_empty());
    }

    #[test]
    fn local_row_with_same_key_as_desired_is_not_visible_to_diff() {
        // Conflict surfaces from `validate_against`; the diff itself
        // treats Local rows as invisible.
        let snapshot = CurrentSnapshot {
            repositories: vec![current_repo("npm-public", ManagedBy::Local, None)],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public"));
        let plan = diff(&snapshot, &desired);
        // The desired entry is treated as a create because there's no
        // matching managed row in current. `validate_against` is what
        // catches the operator before this plan runs.
        assert_eq!(plan.repositories.create.len(), 1);
    }

    #[test]
    fn claim_mapping_diff_keys_off_name() {
        let env = cm_env("admins", "g", "r");
        let digest = spec_digest_claim_mapping(&env.spec);
        let snapshot = CurrentSnapshot {
            claim_mappings: vec![current_cm("admins", ManagedBy::GitOps, Some(digest))],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.claim_mappings.push(env);
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.claim_mappings.unchanged, 1);
    }

    #[test]
    fn claim_mapping_delete_lists_name() {
        let snapshot = CurrentSnapshot {
            claim_mappings: vec![current_cm("readers", ManagedBy::GitOps, Some([1; 32]))],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert_eq!(plan.claim_mappings.delete, vec!["readers".to_string()]);
    }

    // -- spec_digest stability ---------------------------------------------

    #[test]
    fn repo_digest_stable_across_repeated_calls() {
        let s = repo_spec("a");
        assert_eq!(spec_digest_repository(&s), spec_digest_repository(&s));
    }

    #[test]
    fn repo_digest_changes_when_field_changes() {
        let mut a = repo_spec("a");
        let mut b = a.clone();
        b.is_public = !a.is_public;
        assert_ne!(spec_digest_repository(&a), spec_digest_repository(&b));
        // Spot-check: changing the description also changes the digest.
        a.description = Some("new".into());
        assert_ne!(spec_digest_repository(&a), spec_digest_repository(&b));
    }

    #[test]
    fn repo_digest_insensitive_to_member_ordering() {
        // Reordering virtualMembers in YAML must not trigger an
        // "update" outcome — operators shouldn't have to canonicalise
        // their lists by hand.
        let mut a = repo_spec("v");
        a.repo_type = "virtual".into();
        a.virtual_members = Some(vec!["b".into(), "a".into(), "c".into()]);
        let mut b = a.clone();
        b.virtual_members = Some(vec!["c".into(), "a".into(), "b".into()]);
        assert_eq!(spec_digest_repository(&a), spec_digest_repository(&b));
    }

    #[test]
    fn repo_digest_changes_when_member_set_changes() {
        let mut a = repo_spec("v");
        a.repo_type = "virtual".into();
        a.virtual_members = Some(vec!["a".into(), "b".into()]);
        let mut b = a.clone();
        b.virtual_members = Some(vec!["a".into(), "c".into()]);
        assert_ne!(spec_digest_repository(&a), spec_digest_repository(&b));
    }

    #[test]
    fn claim_mapping_digest_stable_and_field_sensitive() {
        let a = ClaimMappingSpec {
            idp_group: "g".into(),
            claim: "r".into(),
        };
        let b = a.clone();
        assert_eq!(spec_digest_claim_mapping(&a), spec_digest_claim_mapping(&b));
        let c = ClaimMappingSpec {
            idp_group: "g".into(),
            claim: "admin".into(),
        };
        assert_ne!(spec_digest_claim_mapping(&a), spec_digest_claim_mapping(&c));
    }

    // -- PermissionGrant subject helpers -----------------------------------

    use crate::permission_grant::GrantSubjectSpec;

    /// A `Claims`-subject grant: required claims (verbatim, unsorted),
    /// permission, optional repository.
    fn pg_claims_spec(
        required: &[&str],
        permission: &str,
        repository: Option<&str>,
    ) -> PermissionGrantSpec {
        PermissionGrantSpec {
            subject: GrantSubjectSpec::Claims {
                required: required.iter().map(ToString::to_string).collect(),
            },
            permission: permission.into(),
            repository: repository.map(Into::into),
        }
    }

    fn pg_claims_env(
        name: &str,
        required: &[&str],
        permission: &str,
        repository: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::PermissionGrant,
            metadata: Metadata { name: name.into() },
            spec: pg_claims_spec(required, permission, repository),
        }
    }

    fn pg_user_env(
        name: &str,
        user_id: &str,
        permission: &str,
        repository: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::PermissionGrant,
            metadata: Metadata { name: name.into() },
            spec: PermissionGrantSpec {
                subject: GrantSubjectSpec::User {
                    user_id: user_id.into(),
                },
                permission: permission.into(),
                repository: repository.map(Into::into),
            },
        }
    }

    /// Current snapshot row for a `Claims` grant. `required` is stored
    /// already-sorted (the snapshot builder sorts before handing to the
    /// diff), so callers pass it sorted.
    fn current_pg_claims(
        required: &[&str],
        permission: Permission,
        repository: Option<&str>,
        managed_by: ManagedBy,
        digest: Option<[u8; 32]>,
    ) -> CurrentPermissionGrant {
        CurrentPermissionGrant {
            id: Uuid::new_v4(),
            required_claims: Some(required.iter().map(ToString::to_string).collect()),
            user_id: None,
            permission,
            repository_name: repository.map(Into::into),
            managed_by,
            managed_by_digest: digest,
        }
    }

    fn current_pg_user(
        user_id: &str,
        permission: Permission,
        repository: Option<&str>,
        managed_by: ManagedBy,
        digest: Option<[u8; 32]>,
    ) -> CurrentPermissionGrant {
        CurrentPermissionGrant {
            id: Uuid::new_v4(),
            required_claims: None,
            user_id: Some(user_id.into()),
            permission,
            repository_name: repository.map(Into::into),
            managed_by,
            managed_by_digest: digest,
        }
    }

    fn cr_spec(action: &str) -> CurationRuleSpec {
        CurationRuleSpec {
            format: "any".into(),
            pattern: "x*".into(),
            action: action.into(),
            reason: "test".into(),
        }
    }

    fn cr_env(name: &str, action: &str) -> Envelope<CurationRuleSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::CurationRule,
            metadata: Metadata { name: name.into() },
            spec: cr_spec(action),
        }
    }

    fn current_cr(
        name: &str,
        managed_by: ManagedBy,
        digest: Option<[u8; 32]>,
    ) -> CurrentCurationRule {
        CurrentCurationRule {
            id: Uuid::new_v4(),
            name: name.into(),
            managed_by,
            managed_by_digest: digest,
        }
    }

    #[test]
    fn permission_grant_digest_stable_and_field_sensitive() {
        let a = pg_claims_spec(&["developer"], "read", None);
        assert_eq!(
            spec_digest_permission_grant(&a),
            spec_digest_permission_grant(&a.clone())
        );
        // Permission change → digest changes.
        let b = pg_claims_spec(&["developer"], "write", None);
        assert_ne!(
            spec_digest_permission_grant(&a),
            spec_digest_permission_grant(&b)
        );
        // Repository scope change → digest changes.
        let c = pg_claims_spec(&["developer"], "read", Some("npm-public"));
        assert_ne!(
            spec_digest_permission_grant(&a),
            spec_digest_permission_grant(&c)
        );
        // Subject kind change (Claims → User) → digest changes.
        let d = PermissionGrantSpec {
            subject: GrantSubjectSpec::User {
                user_id: "u".into(),
            },
            permission: "read".into(),
            repository: None,
        };
        assert_ne!(
            spec_digest_permission_grant(&a),
            spec_digest_permission_grant(&d)
        );
    }

    #[test]
    fn permission_grant_digest_tracks_claim_order_but_identity_does_not() {
        // The digest is verbatim (a reordered claim list is a different
        // digest → `update`), but the diff *identity* sorts the claim
        // set so the reordered grant matches the same row.
        let a = pg_claims_spec(&["developer", "team-alpha"], "read", None);
        let b = pg_claims_spec(&["team-alpha", "developer"], "read", None);
        assert_ne!(
            spec_digest_permission_grant(&a),
            spec_digest_permission_grant(&b)
        );
        assert_eq!(a.diff_identity(), b.diff_identity());
    }

    #[test]
    fn curation_rule_digest_stable_and_field_sensitive() {
        let a = cr_spec("block");
        assert_eq!(spec_digest_curation_rule(&a), spec_digest_curation_rule(&a));
        let b = cr_spec("warn");
        assert_ne!(spec_digest_curation_rule(&a), spec_digest_curation_rule(&b));
        let mut c = a.clone();
        c.format = "npm".into();
        assert_ne!(spec_digest_curation_rule(&a), spec_digest_curation_rule(&c));
    }

    // -- KindPlan flow per kind -------------------------------------------

    #[test]
    fn claim_mapping_diff_creates_when_managed_row_absent() {
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("admins", "grp", "admin"));
        let plan = diff(&CurrentSnapshot::default(), &desired);
        assert_eq!(plan.claim_mappings.create.len(), 1);
        assert_eq!(plan.claim_mappings.create[0].metadata.name, "admins");
        assert!(plan.claim_mappings.update.is_empty());
        assert!(plan.claim_mappings.delete.is_empty());
        assert_eq!(plan.claim_mappings.unchanged, 0);
    }

    #[test]
    fn claim_mapping_diff_update_when_digest_differs() {
        let env = cm_env("admins", "grp", "admin");
        let snapshot = CurrentSnapshot {
            claim_mappings: vec![current_cm("admins", ManagedBy::GitOps, Some([0xff; 32]))],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.claim_mappings.push(env);
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.claim_mappings.update.len(), 1);
        assert_eq!(plan.claim_mappings.unchanged, 0);
    }

    #[test]
    fn claim_mapping_diff_skips_local_rows_for_delete() {
        // Only `GitOps` rows are diff candidates — a Local row stays
        // untouched even if the desired state is empty.
        let snapshot = CurrentSnapshot {
            claim_mappings: vec![current_cm("admins", ManagedBy::Local, None)],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert!(plan.claim_mappings.delete.is_empty());
    }

    #[test]
    fn permission_grant_claims_diff_creates_updates_deletes() {
        // Identity is the subject-dependent key
        // `(sorted required_claims, repository, permission)`. The
        // desired YAML's `metadata.name` is operator-cosmetic and does
        // NOT participate.
        let env = pg_claims_env("dev-read", &["developer"], "read", None);
        let digest = spec_digest_permission_grant(&env.spec);

        // create case
        let mut desired = DesiredState::default();
        desired.permission_grants.push(env.clone());
        let plan = diff(&CurrentSnapshot::default(), &desired);
        assert_eq!(plan.permission_grants.create.len(), 1);

        // unchanged case — current row's identity matches desired.
        let snapshot = CurrentSnapshot {
            permission_grants: vec![current_pg_claims(
                &["developer"],
                Permission::Read,
                None,
                ManagedBy::GitOps,
                Some(digest),
            )],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.permission_grants.unchanged, 1);

        // update case — same identity, stale digest.
        let snapshot = CurrentSnapshot {
            permission_grants: vec![current_pg_claims(
                &["developer"],
                Permission::Read,
                None,
                ManagedBy::GitOps,
                Some([0xaa; 32]),
            )],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.permission_grants.update.len(), 1);

        // delete case — current row's identity absent from desired.
        let stale = current_pg_claims(
            &["ghost"],
            Permission::Admin,
            Some("repo-x"),
            ManagedBy::GitOps,
            Some([0; 32]),
        );
        let stale_id = stale.id;
        let snapshot = CurrentSnapshot {
            permission_grants: vec![stale],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert_eq!(plan.permission_grants.delete, vec![stale_id]);
    }

    #[test]
    fn permission_grant_user_subject_round_trips_through_diff() {
        // A `User`-subject grant (SA pattern) keys off
        // `(user_id, repository, permission)`.
        let env = pg_user_env(
            "sa-write",
            "11111111-1111-1111-1111-111111111111",
            "write",
            None,
        );
        let digest = spec_digest_permission_grant(&env.spec);
        let mut desired = DesiredState::default();
        desired.permission_grants.push(env);

        // unchanged — matching User row.
        let snapshot = CurrentSnapshot {
            permission_grants: vec![current_pg_user(
                "11111111-1111-1111-1111-111111111111",
                Permission::Write,
                None,
                ManagedBy::GitOps,
                Some(digest),
            )],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.permission_grants.unchanged, 1);

        // A Claims row with the same repo/permission is a DIFFERENT
        // identity — the User envelope is a create, the Claims row a
        // delete.
        let stale = current_pg_claims(
            &["developer"],
            Permission::Write,
            None,
            ManagedBy::GitOps,
            Some([0; 32]),
        );
        let stale_id = stale.id;
        let snapshot = CurrentSnapshot {
            permission_grants: vec![stale],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.permission_grants.create.len(), 1);
        assert_eq!(plan.permission_grants.delete, vec![stale_id]);
    }

    #[test]
    fn permission_grant_diff_freeform_metadata_name_is_unchanged_when_identity_matches() {
        // Identity is the subject key, NOT the YAML envelope's
        // `metadata.name`. An envelope named `dev-read-pypi` matches a
        // current row whose identity is the same, regardless of the
        // freeform name; the diff also tolerates a different-but-
        // equivalent claim ORDER (identity sorts the set).
        let env = pg_claims_env("dev-read-pypi", &["team-alpha", "developer"], "read", None);
        let digest = spec_digest_permission_grant(&env.spec);
        let snapshot = CurrentSnapshot {
            // snapshot builder stores the set sorted
            permission_grants: vec![current_pg_claims(
                &["developer", "team-alpha"],
                Permission::Read,
                None,
                ManagedBy::GitOps,
                Some(digest),
            )],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.permission_grants.push(env);
        let plan = diff(&snapshot, &desired);
        assert!(plan.permission_grants.create.is_empty());
        assert!(plan.permission_grants.update.is_empty());
        assert!(plan.permission_grants.delete.is_empty());
        assert_eq!(plan.permission_grants.unchanged, 1);
    }

    #[test]
    fn permission_grant_diff_repository_scope_changes_identity() {
        // A grant with `repository: None` (global) is a different
        // identity from the same claims+permission scoped to a
        // specific repo. Changing the scope must produce a delete +
        // create pair, not an update.
        let env_scoped = pg_claims_env("dev-read-npm", &["developer"], "read", Some("npm-public"));
        let snapshot = CurrentSnapshot {
            permission_grants: vec![current_pg_claims(
                &["developer"],
                Permission::Read,
                None, // global
                ManagedBy::GitOps,
                Some([0; 32]),
            )],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.permission_grants.push(env_scoped);
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.permission_grants.create.len(), 1);
        assert_eq!(plan.permission_grants.delete.len(), 1);
    }

    #[test]
    fn permission_grant_malformed_subject_row_is_not_over_deleted() {
        // A row with both/neither subject column set violates the
        // `subject_exclusive` DB CHECK; the diff has no identity to
        // match and must NOT push it to delete (the apply layer
        // surfaces the invariant instead).
        let malformed = CurrentPermissionGrant {
            id: Uuid::new_v4(),
            required_claims: None,
            user_id: None,
            permission: Permission::Read,
            repository_name: None,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0; 32]),
        };
        let snapshot = CurrentSnapshot {
            permission_grants: vec![malformed],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert!(plan.permission_grants.delete.is_empty());
    }

    #[test]
    fn curation_rule_diff_creates_updates_deletes() {
        let env = cr_env("block-cve", "block");
        let digest = spec_digest_curation_rule(&env.spec);

        let mut desired = DesiredState::default();
        desired.curation_rules.push(env.clone());

        // create
        let plan = diff(&CurrentSnapshot::default(), &desired);
        assert_eq!(plan.curation_rules.create.len(), 1);

        // unchanged
        let snapshot = CurrentSnapshot {
            curation_rules: vec![current_cr("block-cve", ManagedBy::GitOps, Some(digest))],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.curation_rules.unchanged, 1);

        // update
        let snapshot = CurrentSnapshot {
            curation_rules: vec![current_cr("block-cve", ManagedBy::GitOps, Some([0xff; 32]))],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.curation_rules.update.len(), 1);

        // delete
        let stale = current_cr("stale", ManagedBy::GitOps, Some([0; 32]));
        let stale_id = stale.id;
        let snapshot = CurrentSnapshot {
            curation_rules: vec![stale],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert_eq!(plan.curation_rules.delete, vec![stale_id]);
    }

    #[test]
    fn local_curation_row_with_same_name_as_desired_is_invisible_to_diff() {
        // Same anti-shadowing rule as repositories: a local row with
        // the same name surfaces from `validate_against`'s
        // ManagedConflict, never from the diff itself.
        let snapshot = CurrentSnapshot {
            curation_rules: vec![current_cr("block-cve", ManagedBy::Local, None)],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.curation_rules.push(cr_env("block-cve", "block"));
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.curation_rules.create.len(), 1);
    }

    // ===================================================================
    // OidcIssuer + ServiceAccount diff tests
    // ===================================================================

    use crate::oidc_issuer::OidcIssuerSpec;
    use crate::service_account::{
        FallbackRotationSpec, FederatedIdentitySpec, ServiceAccountSpec, TargetSecretSpec,
    };
    use std::collections::BTreeMap;

    fn oidc_spec() -> OidcIssuerSpec {
        OidcIssuerSpec {
            issuer_url: "https://token.actions.githubusercontent.com".into(),
            audiences: vec!["hort-server".into()],
            jwks_refresh_interval: "1h".into(),
            allowed_algorithms: vec!["RS256".into()],
            require_jti: true,
        }
    }

    fn oidc_env(name: &str) -> Envelope<OidcIssuerSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::OidcIssuer,
            metadata: Metadata { name: name.into() },
            spec: oidc_spec(),
        }
    }

    fn current_oidc(name: &str, digest: Option<[u8; 32]>) -> CurrentOidcIssuer {
        CurrentOidcIssuer {
            id: Uuid::new_v4(),
            name: name.into(),
            digest,
        }
    }

    fn sa_spec() -> ServiceAccountSpec {
        let mut claims = BTreeMap::new();
        claims.insert("repository".into(), "my-org/my-repo".into());
        ServiceAccountSpec {
            role: "developer".into(),
            repositories: vec!["pypi-internal".into()],
            federated_identities: vec![FederatedIdentitySpec {
                issuer: "github-actions".into(),
                claims,
            }],
            fallback_rotation: Some(FallbackRotationSpec {
                target_secret: TargetSecretSpec {
                    name: "ci-token".into(),
                    namespace: "ci-system".into(),
                    format: "opaque".into(),
                },
                rotation_interval: "6h".into(),
                validity: "24h".into(),
            }),
        }
    }

    fn sa_env(name: &str) -> Envelope<ServiceAccountSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ServiceAccount,
            metadata: Metadata { name: name.into() },
            spec: sa_spec(),
        }
    }

    fn current_sa(name: &str, digest: Option<[u8; 32]>) -> CurrentServiceAccount {
        CurrentServiceAccount {
            id: Uuid::new_v4(),
            name: name.into(),
            digest,
        }
    }

    // -- OidcIssuer diff ----------------------------------------------------

    #[test]
    fn oidc_issuer_diff_create_when_managed_absent() {
        let mut desired = DesiredState::default();
        desired.oidc_issuers.push(oidc_env("github-actions"));
        let plan = diff(&CurrentSnapshot::default(), &desired);
        assert_eq!(plan.oidc_issuers.create.len(), 1);
        assert_eq!(plan.oidc_issuers.create[0].metadata.name, "github-actions");
    }

    #[test]
    fn oidc_issuer_diff_unchanged_when_digest_matches() {
        let env = oidc_env("github-actions");
        let digest = spec_digest_oidc_issuer(&env.spec);
        let snapshot = CurrentSnapshot {
            oidc_issuers: vec![current_oidc("github-actions", Some(digest))],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.oidc_issuers.push(env);
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.oidc_issuers.unchanged, 1);
        assert!(plan.oidc_issuers.create.is_empty());
        assert!(plan.oidc_issuers.update.is_empty());
    }

    #[test]
    fn oidc_issuer_diff_update_when_digest_differs() {
        let snapshot = CurrentSnapshot {
            oidc_issuers: vec![current_oidc("github-actions", Some([0xff; 32]))],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.oidc_issuers.push(oidc_env("github-actions"));
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.oidc_issuers.update.len(), 1);
        assert_eq!(plan.oidc_issuers.unchanged, 0);
    }

    #[test]
    fn oidc_issuer_diff_delete_when_absent_from_desired() {
        let snapshot = CurrentSnapshot {
            oidc_issuers: vec![current_oidc("stale", Some([0; 32]))],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert_eq!(plan.oidc_issuers.delete, vec!["stale".to_string()]);
    }

    #[test]
    fn oidc_issuer_digest_insensitive_to_audience_ordering() {
        let mut a = oidc_spec();
        a.audiences = vec!["a".into(), "b".into(), "c".into()];
        let mut b = a.clone();
        b.audiences = vec!["c".into(), "a".into(), "b".into()];
        assert_eq!(spec_digest_oidc_issuer(&a), spec_digest_oidc_issuer(&b));
    }

    #[test]
    fn oidc_issuer_digest_changes_when_url_changes() {
        let a = oidc_spec();
        let mut b = a.clone();
        b.issuer_url = "https://other.example.com".into();
        assert_ne!(spec_digest_oidc_issuer(&a), spec_digest_oidc_issuer(&b));
    }

    // -- ServiceAccount diff ------------------------------------------------

    #[test]
    fn service_account_diff_create_when_managed_absent() {
        let mut desired = DesiredState::default();
        desired.service_accounts.push(sa_env("ci-pypi-pusher"));
        let plan = diff(&CurrentSnapshot::default(), &desired);
        assert_eq!(plan.service_accounts.create.len(), 1);
    }

    #[test]
    fn service_account_diff_unchanged_when_digest_matches() {
        let env = sa_env("ci-pypi-pusher");
        let digest = spec_digest_service_account(&env.spec);
        let snapshot = CurrentSnapshot {
            service_accounts: vec![current_sa("ci-pypi-pusher", Some(digest))],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.service_accounts.push(env);
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.service_accounts.unchanged, 1);
    }

    #[test]
    fn service_account_diff_update_when_digest_differs() {
        let snapshot = CurrentSnapshot {
            service_accounts: vec![current_sa("ci-pypi-pusher", Some([0xaa; 32]))],
            ..CurrentSnapshot::default()
        };
        let mut desired = DesiredState::default();
        desired.service_accounts.push(sa_env("ci-pypi-pusher"));
        let plan = diff(&snapshot, &desired);
        assert_eq!(plan.service_accounts.update.len(), 1);
    }

    #[test]
    fn service_account_diff_delete_when_absent_from_desired() {
        let snapshot = CurrentSnapshot {
            service_accounts: vec![current_sa("orphan", Some([1; 32]))],
            ..CurrentSnapshot::default()
        };
        let plan = diff(&snapshot, &DesiredState::default());
        assert_eq!(plan.service_accounts.delete, vec!["orphan".to_string()]);
    }

    #[test]
    fn service_account_digest_insensitive_to_repository_ordering() {
        let mut a = sa_spec();
        a.repositories = vec!["a".into(), "b".into()];
        let mut b = a.clone();
        b.repositories = vec!["b".into(), "a".into()];
        assert_eq!(
            spec_digest_service_account(&a),
            spec_digest_service_account(&b)
        );
    }

    #[test]
    fn service_account_digest_changes_when_role_changes() {
        let a = sa_spec();
        let mut b = a.clone();
        b.role = "reader".into();
        assert_ne!(
            spec_digest_service_account(&a),
            spec_digest_service_account(&b)
        );
    }

    #[test]
    fn service_account_digest_insensitive_to_federated_identity_ordering() {
        // Two federated-identity entries; declaration order in YAML
        // must not flip the digest.
        let mut a = sa_spec();
        let mut claims_2 = BTreeMap::new();
        claims_2.insert("aud".into(), "hort-cli".into());
        a.federated_identities.push(FederatedIdentitySpec {
            issuer: "gitlab".into(),
            claims: claims_2,
        });
        let mut b = a.clone();
        b.federated_identities.reverse();
        assert_eq!(
            spec_digest_service_account(&a),
            spec_digest_service_account(&b)
        );
    }
}
