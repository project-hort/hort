//! `ApplyConfigUseCase` — execute a `DesiredState` against the
//! managed-write port methods (see
//! `docs/architecture/how-to/declare-gitops-config.md`).
//!
//! Wired into the boot sequence; this use case has no
//! HTTP surface. It is the single point of truth for "compute the
//! plan, then apply it" — the diff is in `hort-config`, the writes
//! land via the managed-write methods on `RepositoryRepository`,
//! `CurationRuleRepository`, through `AuthorityLifecyclePort` for the
//! five authority kinds whose rows commit with their audit events,
//! and through `PolicyUseCase` for event-sourced kinds.
//!
//! # Additive-claims RBAC model (ADR 0012)
//!
//! There is no `roles` table and no role-and-group-mapping RBAC
//! model. Claim mappings are applied by `apply_claim_mappings`
//! (`ClaimMappingRepository`, `claim_mappings` table). The
//! `PermissionGrant` branch is built
//! around the sum-typed [`GrantSubject`] diff identity
//! (`(sorted required_claims, repository_id, permission)` for `Claims`;
//! `(user_id, repository_id, permission)` for `User`).
//!
//! `AuthorityLifecyclePort::commit_claim_mappings` /
//! `commit_permission_grants` are **whole-partition reconcile
//! primitives that carry their own audit trail**: the apply
//! branch builds the *complete* desired gitops-managed set, diffs it
//! against `list_managed_by_gitops` to emit one
//! `ClaimMappingApplied`/`PermissionGrantApplied` per added-or-changed
//! row and one `ClaimMappingRevoked`/`PermissionGrantRevoked` per
//! removed row (audit-event-per-mutation invariant), then commits the
//! complete set **and** those events in one transaction — the adapter
//! does the atomic delete-absent + upsert-present and joins the audit
//! append to the same transaction. Because the reconcile covers the
//! *entire* gitops partition, the ServiceAccount `User`-subject grants
//! and the envelope-declared grants are unioned into one
//! `commit_permission_grants` call.
//!
//! # Why the audit append rides the row transaction
//!
//! The five security-relevant CRUD kinds — permission grants, claim
//! mappings, OIDC issuers, gitops-managed upstream mappings,
//! service-account aggregates — each used to write their row, commit
//! it, and append the attesting event in a separate call. An append
//! failure (or a process termination) after that commit left the row
//! **active with nothing in the authorization stream attesting it**,
//! and the retry could not repair it: the next apply derives its
//! events from the prior *rows*, which already hold the change, so it
//! emits nothing. All five now route through
//! `AuthorityLifecyclePort`, whose adapter commits rows + events in
//! one `PgUnitOfWork`. Consequence an operator will notice: an
//! event-store failure during any of those five applies now leaves
//! the rows **unchanged** — the apply fails closed instead of
//! half-done.
//!
//! The five repository ports no longer carry the write method the port
//! replaced, so a future apply branch cannot reintroduce the dual
//! write — it is a compile error, not a review rule. The one write
//! that stays outside the transaction is the backing `users` row for a
//! declared `ServiceAccount`, and it has to: the FK from
//! `service_accounts.backing_user_id` requires it to be durable first.
//! See `apply_service_accounts` for why an orphan backing user confers
//! nothing.
//!
//! # Topological apply
//!
//! 1. **Stage 1 (no inbound refs):** ClaimMapping, CurationRule.
//! 2. **Stage 2 (depends on stage 1):** Repository (resolves
//!    `curation_rule_names` → ids, writes the junction edges via
//!    `set_curation_rules_for_repository`), ScanPolicy (event-sourced —
//!    routed through `PolicyUseCase::create_policy` /
//!    `PolicyUseCase::update_policy` / `archive_policy`).
//! 3. **Stage 3 (depends on stage 2):** Exclusion (event-sourced
//!    sub-state of ScanPolicy — routed through
//!    `PolicyUseCase::add_exclusion` / `remove_exclusion`),
//!    virtual-repo membership, then OidcIssuer → ServiceAccount, then
//!    the consolidated PermissionGrant reconcile (envelope grants ∪
//!    SA-owned `User`-subject grants — refs Repository + backing
//!    users, so it runs after both Repository rows and ServiceAccount
//!    backing users exist).
//!
//! Strict-atomic: any port failure aborts the boot. v1 has no
//! rollback — the boot exits non-zero, the operator fixes the YAML
//! and restarts. The "half-applied" state is observable, but the
//! operator's recovery action is identical (correct the config and
//! restart), so adding rollback would be ceremony for no benefit.
//!
//! # ApplyReport choice
//!
//! `ApplyReport` keeps the rolled-up `created/updated/deleted/unchanged`
//! counters. The
//! per-kind dimensional breakdown is carried by the
//! `hort_gitops_objects_total{kind, result}` metric; duplicating it in a
//! per-kind sub-report struct would force every caller (currently just
//! `gitops_boot::tracing::info!`) to enumerate the seven kinds and
//! offer no observability beyond what the metric already exposes.
//!
//! # Reuse of `PolicyUseCase`
//!
//! Event-sourced kinds (`ScanPolicy`, `Exclusion`) route through
//! `PolicyUseCase` rather than calling `EventStore::append` +
//! `PolicyProjectionRepository::upsert` directly. The use case is the
//! only writer of policy events workspace-wide — centralising the
//! optimistic-concurrency + projection-write code there keeps the
//! invariant single-sourced.
//!
//! For the create branch the pipeline mints `policy_id` itself by
//! constructing a `CreatePolicyCommand` directly from the
//! `ScanPolicySpec`; the `ScanPolicyApplier` is consulted only for the
//! update branch (existing projection vs new spec). This avoids
//! double-minting an id and discarding one half.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Utc;
use hort_config::claim_mapping::ClaimMappingSpec;
use hort_config::desired::EnvSnapshot;
use hort_config::diff::{
    diff, spec_digest_claim_mapping, spec_digest_curation_rule, spec_digest_permission_grant,
    spec_digest_repository, spec_digest_upstream_mapping, ApplyPlan, CurrentClaimMapping,
    CurrentCurationRule, CurrentOidcIssuer, CurrentPermissionGrant, CurrentRepository,
    CurrentServiceAccount, CurrentSnapshot, CurrentUpstreamMapping, KindPlan,
};
use hort_config::envelope::{Envelope, Kind};
use hort_config::exclusion::ExclusionSpec;
use hort_config::oidc_issuer::OidcIssuerSpec;
use hort_config::permission_grant::{GrantSubjectSpec, PermissionGrantSpec};
use hort_config::repository::RepositorySpec;
use hort_config::scan_policy::ScanPolicySpec;
use hort_config::scope::ScopeSpec;
use hort_config::service_account::ServiceAccountSpec;
use hort_config::upstream_mapping::UpstreamMappingSpec;
use hort_config::DesiredState;
use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::oidc_issuer::{JwtAlg, OidcIssuer};
use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, Permission, PermissionGrant};
use hort_domain::entities::repository::{
    ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use hort_domain::entities::scan_policy::SeverityThreshold;

// The ScanPolicy wire->domain provenance mappers live in
// the shared `hort_app::provenance` module (single source for apply + the
// offline validator), not duplicated here.
use crate::provenance::{
    negligible_action_from_spec, provenance_identities_from_spec, provenance_mode_from_spec,
    scan_enforcement_from_spec,
};
use hort_domain::entities::service_account::{
    backing_username, FallbackRotation, FederatedIdentity, SecretFormat, ServiceAccount,
};
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::error::DomainError;
use hort_domain::events::{
    Actor, ClaimMappingApplied, ClaimMappingRevoked, CurationActionTag, CurationApplied,
    CurationTrigger, DomainEvent, GitOpsActor, GrantSubjectRecord, OidcIssuerCreated,
    OidcIssuerDeleted, OidcIssuerUpdated, PermissionGrantApplied, PermissionGrantRevoked,
    PolicyScope, RepositoryUpstreamMappingChanged, ServiceAccountCreated, ServiceAccountDeleted,
    ServiceAccountUpdated, StreamId, UpstreamMappingChange,
};
use hort_domain::policy::{evaluate_curation_retroactive, RetroactiveCurationOutcome};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::authority_lifecycle::{
    AuthorityLifecyclePort, OidcIssuerChange, ServiceAccountCommit, UpstreamMappingCommit,
};
use hort_domain::ports::claim_mapping_repository::ClaimMappingRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};
use hort_domain::ports::federated_jwt_validator::FederatedJwtValidator;
use hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository;
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, RepositoryUpstreamMappingArgs, RepositoryUpstreamMappingRepository,
    UpstreamAuth,
};
use hort_domain::ports::secret_port::SecretRef;
use hort_domain::ports::service_account_repository::ServiceAccountRepository;
use hort_domain::ports::upstream_index_cache_invalidator::UpstreamIndexCacheInvalidator;
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::types::PageRequest;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::gitops::event_sourced::{ApplyEventSourcedKind, ExclusionsApplier, ScanPolicyApplier};
use crate::lint::LinterRule;
use crate::metrics::{
    emit_gitops_event, emit_gitops_object, emit_policy_evaluation, emit_policy_violations,
    gitops_kind, policy_decision_point, GitopsObjectResult, PolicyEvaluationResult,
};

/// Operator-controlled enumerated
/// allowlist of upstream hosts, enforced at gitops-apply time on
/// `RepositoryUpstreamMapping` rows.
///
/// Driven by the `HORT_UPSTREAM_ALLOWLIST_HOSTS` env var on the server.
/// Parse via [`UpstreamHostAllowlist::parse`]; the use case never
/// touches the env var directly so the application layer stays I/O
/// free.
///
/// **Apply-time-only enforcement:** the host check fires inside
/// `apply_upstream_mappings` when a mapping is created or updated.
/// Tightening the allowlist later (removing a host and re-applying)
/// does NOT re-validate existing mappings — only rows that appear in
/// the apply diff are rechecked. See `docs/operator/upstream-trust-model.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamHostAllowlist {
    /// `HORT_UPSTREAM_ALLOWLIST_HOSTS` is unset OR set to the empty string.
    /// Empty-string is treated as unset (not as `Strict`) because
    /// k8s ConfigMap defaults, docker-compose `${VAR:-}`, and shell
    /// `export VAR=` all silently produce the empty value — those
    /// would otherwise turn every upstream mapping into a hard reject
    /// with no operator intent.
    Disabled,
    /// `HORT_UPSTREAM_ALLOWLIST_HOSTS=__deny_all__` (literal sentinel,
    /// exact match). Every upstream mapping is rejected — bootstrap-
    /// only deployments. The literal sentinel is conspicuous,
    /// intentional, and grep-friendly in operator scripts; it is the
    /// only way to opt into strict mode.
    Strict,
    /// `HORT_UPSTREAM_ALLOWLIST_HOSTS=host1,host2,...` — comma-separated
    /// host list. Only mapping URLs whose host is **exactly** in the
    /// list pass apply-time validation. No suffix matching
    /// (`*.example.com`) — that would silently widen the trust
    /// boundary; if a future operator needs it the design must be
    /// re-opened.
    Hosts(Vec<String>),
}

impl UpstreamHostAllowlist {
    /// Literal sentinel value that opts into [`Self::Strict`] mode.
    /// Pinned as a `const` so a typo in the use-case validation site
    /// is a compile-time mismatch rather than a silent posture flip.
    pub const STRICT_SENTINEL: &'static str = "__deny_all__";

    /// Parse the raw value of the `HORT_UPSTREAM_ALLOWLIST_HOSTS` env var
    /// into the tri-state. `None` (variable unset) and `Some("")`
    /// (variable set to empty string) both produce
    /// [`Self::Disabled`] — see the type-level docs for the footgun
    /// rationale.
    ///
    /// Whitespace around comma-separated entries is trimmed; empty
    /// entries (e.g. trailing comma, `,,` doubled separator) are
    /// silently dropped. A list that reduces to zero non-empty hosts
    /// after trimming collapses to [`Self::Disabled`] — this matches
    /// the empty-string rule (`HORT_UPSTREAM_ALLOWLIST_HOSTS=,` is
    /// indistinguishable from the empty case for an operator and
    /// should not silently flip to `Hosts(vec![])` which would
    /// reject every mapping).
    pub fn parse(raw: Option<&str>) -> Self {
        let Some(s) = raw else {
            return Self::Disabled;
        };
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Self::Disabled;
        }
        if trimmed == Self::STRICT_SENTINEL {
            return Self::Strict;
        }
        let hosts: Vec<String> = trimmed
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            .collect();
        if hosts.is_empty() {
            // Operator wrote `HORT_UPSTREAM_ALLOWLIST_HOSTS=,` or similar.
            // Collapse to Disabled rather than `Hosts(vec![])` (which
            // would reject every mapping silently — same footgun
            // class as the empty-string case).
            Self::Disabled
        } else {
            Self::Hosts(hosts)
        }
    }

    /// Convenience: parse straight from `std::env::var`. Returns
    /// [`Self::Disabled`] when the var is not set (`Err`) so a
    /// `NotUnicode` error is surfaced separately from a missing
    /// var. Test code bypasses this and calls [`Self::parse`]
    /// directly.
    pub fn from_env(var: &str) -> Self {
        match std::env::var(var) {
            Ok(v) => Self::parse(Some(v.as_str())),
            Err(std::env::VarError::NotPresent) => Self::Disabled,
            // NotUnicode: treat the same as unset; the alternative
            // is panicking at boot which is worse than the loud
            // "host not in list" the operator will see when their
            // first apply runs.
            Err(std::env::VarError::NotUnicode(_)) => Self::Disabled,
        }
    }

    /// True when `host` is permitted by this allowlist.
    /// `Disabled` — every host passes (default posture).
    /// `Strict` — no host passes (deny-all).
    /// `Hosts(list)` — exact match against the list.
    pub fn permits(&self, host: &str) -> bool {
        match self {
            Self::Disabled => true,
            Self::Strict => false,
            Self::Hosts(list) => list.iter().any(|h| h == host),
        }
    }
}
use crate::gitops_apply_status::ApplyKindCounts;
use crate::use_cases::upstream_index_cache_invalidator::invalidate_after_reject;
use crate::use_cases::{
    append_any_with_conflict_retry, event_append_backoff, EVENT_APPEND_RETRY_ATTEMPTS,
};
use crate::use_cases::{
    AddExclusionCommand, CreatePolicyCommand, FieldChange, PolicyUseCase, RemoveExclusionCommand,
    UpdatePolicyCommand,
};
use crate::use_cases::{ArtifactAtVersion, OverCapStream};

/// One per-object outcome counter rolled up after an apply.
///
/// The `retro_warn_count` and `retro_block_count` fields
/// record the side effects of the retroactive curation
/// pass — independent of `created` / `updated` / `deleted`, which count
/// rule-row writes. A single rule create can produce many retroactive
/// events when the rule attaches to a populated repository.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ApplyReport {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unchanged: usize,
    /// Number of `RetroWarn` outcomes from the
    /// retroactive curation pass. Each emits one `CurationApplied`
    /// event on the per-repo curation stream; no artifact-state change.
    pub retro_warn_count: usize,
    /// Number of `RetroBlock` outcomes from the
    /// retroactive curation pass. Each emits one `CurationApplied`
    /// event AND one `ArtifactRejected` event, atomic per-artifact.
    pub retro_block_count: usize,
    /// Per-kind breakdown of the same object deltas the aggregate
    /// counters above roll up, projected from the apply plan so the
    /// numbers reach the caller instead of dying with the plan.
    ///
    /// Covers five CRUD kinds; the aggregate spans more (see
    /// [`ApplyKindCounts`]), so the breakdown does not sum to the total.
    pub per_kind: ApplyKindCounts,
}

// The `RULE_TRUST_UPSTREAM_PUBLISH_TIME_REQUIRES_
// SCAN_BACKENDS` / `RULE_PREFETCH_MAX_AGE_DAYS_NOT_IMPLEMENTED` `rule`
// label consts moved to `crate::lint::static_validate` so the pure
// validator's `LinterRule::metric_rule()` and this caller's emission site
// share one definition (no duplicated string literal). This caller reads
// them through `LinterRule::metric_rule()`.

pub struct ApplyConfigUseCase {
    repositories: Arc<dyn RepositoryRepository>,
    /// Whole-partition reconcile port for
    /// `claim_mappings` (ADR 0012). Read-side only in this use case —
    /// the apply diff runs off `list_managed_by_gitops`; the write goes
    /// through [`Self::authority`], which commits the reconcile and the
    /// revoke/apply audit events this use case derived in one
    /// transaction.
    claim_mappings: Arc<dyn ClaimMappingRepository>,
    /// Whole-partition reconcile port for
    /// `permission_grants` (ADR 0012;
    /// there is no `role_id` in the additive-claims model). A grant
    /// carries a sum-typed [`GrantSubject`] (`Claims` XOR `User`).
    /// Read-side only in this use case — the apply diff runs off
    /// `list_managed_by_gitops`; the write goes through
    /// [`Self::authority`].
    permission_grants: Arc<dyn PermissionGrantRepository>,
    /// Atomic authority-row-plus-audit-event writer for the three
    /// security-relevant CRUD kinds — permission grants, claim mappings
    /// and OIDC issuers. One call commits the desired rows **and** the
    /// audit batches the prior-vs-desired diff produced; the whole
    /// gitops-partition reconcile (grants / claim mappings) and the
    /// per-row upsert/delete set (issuers) join that one transaction.
    ///
    /// This closes a dual-write the three branches shared: each wrote
    /// its row, committed it, and appended the attesting event in a
    /// separate call, so an append failure — or a process termination —
    /// left the grant, mapping or issuer **active with nothing in the
    /// authorization stream attesting it**, in a state the retry
    /// cannot repair (the next apply diffs against the already-changed
    /// rows and emits nothing).
    ///
    /// A **required** [`Self::new`] parameter, not an opt-in builder: a
    /// composition point that cannot supply an atomic writer must fail
    /// to build rather than inherit its way back onto the
    /// commit-then-append path.
    authority: Arc<dyn AuthorityLifecyclePort>,
    /// Standalone curation-rule rows plus
    /// the `repository_curation_rules` junction-edge writer.
    curation_rules: Arc<dyn CurationRuleRepository>,
    /// Projection-port the apply pipeline
    /// reads to drive the event-sourced diff for `ScanPolicy` and to
    /// list still-active policies absent from the desired state.
    policy_projections: Arc<dyn PolicyProjectionRepository>,
    /// Single writer of policy events
    /// workspace-wide. The pipeline routes every event-sourced
    /// mutation through this use case so optimistic-concurrency +
    /// projection upsert stay co-located.
    policies: Arc<PolicyUseCase>,
    /// Read-side artifact lookup for the
    /// retroactive curation pass. The apply pipeline lists active
    /// artifacts in each repo attached to a newly-created or tightened
    /// rule and re-evaluates them against the just-applied rule set.
    artifacts: Arc<dyn ArtifactRepository>,
    /// Atomic artifact-state-plus-events writer
    /// for the `RetroBlock` arm. `commit_transition` persists the
    /// state change AND the `ArtifactRejected` event in one
    /// transaction, so a concurrent ingest cannot leave the artifact
    /// in `Released` while the rejection event lands on its stream.
    artifact_lifecycle: Arc<dyn ArtifactLifecyclePort>,
    /// Generic event-store handle for the
    /// `CurationApplied` events on the per-repo curation stream.
    /// `ArtifactLifecyclePort` is artifact-stream-specific; the
    /// curation stream lives outside any artifact aggregate.
    events: Arc<EventStorePublisher>,
    /// Managed-write port for the
    /// `repository_upstream_mappings` table. There is no
    /// admin REST writer; the gitops apply
    /// pipeline is the sole writer.
    upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    /// Operator-controlled enumerated
    /// allowlist for upstream mapping hosts. Default
    /// [`UpstreamHostAllowlist::Disabled`] preserves the historical
    /// posture (every host accepted); production deployments are
    /// expected to set `HORT_UPSTREAM_ALLOWLIST_HOSTS` to either the
    /// strict sentinel or an explicit host list. See
    /// `docs/operator/upstream-trust-model.md`.
    upstream_allowlist: UpstreamHostAllowlist,
    /// Refcount projection. The
    /// retroactive curation `RetroBlock` arm sweeps every
    /// `content_references` row whose `source_artifact_id` matches the
    /// just-rejected artifact, mirroring the ingest-path warn-on-fail
    /// posture: a transient PG outage between the lifecycle commit
    /// and the refcount sweep does NOT abort the rejection (the
    /// artifact row is the authoritative state). The refcount reconcile
    /// sweep heals any drift. Stored as the raw port handle (not the
    /// `ContentReferenceUseCase` wrapper) for the same composition-
    /// order reason as `IngestUseCase` and `QuarantineUseCase`: the
    /// wrapper sits at a higher tier.
    content_references: Arc<dyn ContentReferenceIndex>,
    /// Read/write port for `oidc_issuers` (ADR 0018). The
    /// apply pipeline is the only writer; the federation handler
    /// is the only read-heavy consumer.
    oidc_issuers: Arc<dyn OidcIssuerRepository>,
    /// Read/write port for the
    /// `service_accounts` aggregate (SA row + federated identities +
    /// fallback rotation; ADR 0018).
    service_accounts: Arc<dyn ServiceAccountRepository>,
    /// The apply pipeline manages the backing
    /// `users` row for every declared `ServiceAccount` (`username =
    /// "sa:" || sa.name`, `is_service_account = true`). The user row
    /// is shared infrastructure — never deleted by the SA apply path
    /// (other code may grant it tokens).
    users: Arc<dyn UserRepository>,
    /// Optional `FederatedJwtValidator` for apply-time JWKS warm-up.
    /// When `Some(_)`, every newly-created or updated `OidcIssuer` row
    /// triggers a best-effort `refresh_issuer` call so the first
    /// federation `validate()` request against that issuer does NOT
    /// pay the discovery + JWKS round-trip cost.
    ///
    /// The slot is `Option<_>` because composition wires the validator
    /// only when at least one OIDC primitive is present (auth disabled
    /// or no trusted issuers yet → `None`); the apply pipeline must
    /// still be constructable in that posture. A `None` slot causes
    /// `apply_oidc_issuers` to skip warm-up entirely — federation
    /// works lazily via the cache-miss path on first request.
    ///
    /// **Critical invariant.** Warm-up failures **do NOT fail the
    /// apply** — they are operator-feedback-only via `tracing::warn!`
    /// + `hort_jwks_refresh_total{result="apply_warmup_failed"}`.
    federated_jwt_validator: Option<Arc<dyn FederatedJwtValidator>>,
    /// Apply-config linter strictness (ADR 0015). **Defaults to
    /// [`LintConfig::default`] (secure-by-default reject posture)**;
    /// the production composition root
    /// ([`Self::new`]) never overrides it, so an apply with zero
    /// operator config rejects the over-broad grant shapes. An
    /// operator downgrade is an explicit, audited gitops-config
    /// mutation surfaced via [`Self::with_lint_config`] (mirrors the
    /// `with_federated_jwt_validator` builder pattern and the
    /// `upstream_allowlist` opt-in/opt-out shape). There is no
    /// env-var and no global `warn` switch.
    lint_config: crate::lint::LintConfig,
    /// The event-sourced retention-policy apply slot.
    ///
    /// A **required** [`Self::new`] parameter — `Option`-typed but not
    /// omittable. The distinction is the point: the slot stayed
    /// builder-optional while retention had no consumer, and the
    /// production composition root was written without ever calling the
    /// builder, so every `RetentionPolicy` envelope an operator authored
    /// was parsed, validated, warned about and dropped. A required
    /// argument forces every composition point to state its answer;
    /// omission is a compile error rather than an inherited `None`.
    /// Mirrors [`Self::version_discovery_capable_formats`], which is
    /// required for the same reason.
    ///
    /// `None` stays expressible — a composition with no retention
    /// projection (test harnesses) is legitimate. When `None`,
    /// `apply_retention_policies` is a **loud** no-op: a `RetentionPolicy`
    /// YAML present with the slot unwired warns, never silently drops.
    /// [`Self::with_retention`] overrides the initial value after
    /// construction (call-site ergonomics only — it does not make the
    /// slot optional).
    retention: Option<RetentionApply>,
    /// The deployment's **effective global storage backend**.
    ///
    /// `None` when the composition root did not wire it (every
    /// pre-existing test harness, and any composition that does not opt
    /// in); production always wires it (`hort-server` maps its
    /// already-in-scope `StorageConfig` and calls
    /// [`Self::with_effective_storage_backend`]). When `None` the
    /// per-repo-vs-global storage-backend cross-check is **skipped**
    /// (so a pre-existing harness keeps compiling/passing unchanged —
    /// the constructor signature is byte-unchanged). When `Some(_)`, a
    /// per-repo `spec.storage.backend` differing from this value is
    /// rejected at apply (fail-closed, loud). The
    /// value is the *true* `{filesystem, s3}` deployment fact, never
    /// the coarse `StoragePort::backend_label()` `{filesystem,
    /// object_store}` (which would fail-*wrong* on
    /// `s3`-on-S3). Builder-shaped exactly like `with_retention` /
    /// `with_lint_config` so the 16-arg constructor is unchanged.
    effective_storage_backend: Option<crate::storage_backend::EffectiveStorageBackend>,
    /// Optional invalidator for cached
    /// upstream packument / simple-index entries on the retroactive-
    /// rejection path. `None` keeps the use case constructable in
    /// every default test harness; production wires it via
    /// [`Self::with_upstream_index_cache_invalidator`]. When `None`,
    /// the `commit_retroactive_block` post-commit hook is a no-op
    /// (TTL-only freshness posture). Builder-shaped
    /// exactly like `with_effective_storage_backend` /
    /// `with_lint_config` so the 16-arg constructor is unchanged.
    upstream_index_cache_invalidator: Option<Arc<dyn UpstreamIndexCacheInvalidator>>,
    /// The set of repository-format strings (ADR 0027)
    /// some registered `ProvenancePort` `applies_to` (the **static**
    /// backend→format capability map; Tier-1 = `{"oci"}` for cosign).
    /// Drives the apply-time fail-closed reject of a
    /// `provenance_mode: Required` policy whose resolved scope maps to a
    /// format **absent** from this set — there is no verifier to satisfy
    /// the `Required` gate, so the artifact would stay `Pending` forever
    /// (fail-closed). The check is necessarily static: apply runs on
    /// hort-server while a verifier's *live* enablement is a hort-worker
    /// deploy concern.
    ///
    /// **Default empty** (set by [`Self::new`]) so the composition root
    /// compiles unchanged until the root wires the real capability set via
    /// [`Self::with_provenance_capable_formats`]. Default-empty is
    /// fail-closed: a `Required` policy on *any* format is rejected until
    /// the operator's deployment proves a verifier applies to that
    /// format. Mirrors `IngestUseCase::with_provenance_capable_formats`
    /// exactly. The `mode != Off` / empty-backends /
    /// empty-identities / warn rules do NOT consult this set — they come
    /// from the format-/registry-agnostic domain hook
    /// [`hort_domain::entities::scan_policy::ScanPolicyProjection::validate_provenance_config`].
    provenance_capable_formats: Arc<HashSet<String>>,
    /// Row 6b — the set of repository-format strings whose compiled-in
    /// `FormatHandler` declares the `VersionDiscovery` capability group
    /// (ADR 0005). A **required** [`Self::new`] parameter, not an
    /// optional builder: unlike [`Self::provenance_capable_formats`],
    /// there is no runtime default that answers row 6b's rejection
    /// question correctly in both directions (empty would reject
    /// `transitive_deps`/`scheduled` on every capable format; skip-when-
    /// absent is exactly the fail-open hole ADR 0015's structural close
    /// exists to prevent). So a composition point that forgets to supply
    /// the set fails to build rather than silently disabling the rule.
    /// The composition root passes the real set derived from the
    /// compiled-in handler registry; [`Self::with_version_discovery_capable_formats`]
    /// lets a caller override the initial value after construction.
    version_discovery_capable_formats: Arc<HashSet<String>>,
}

/// The retention-policy apply dependencies, installed as
/// a unit via [`ApplyConfigUseCase::with_retention`]. Bundling the
/// projection reader + the use-case writer keeps the builder a single
/// opt-in site (mirrors how `policy_projections` + `policies` pair for
/// `ScanPolicy`).
pub struct RetentionApply {
    projections: Arc<dyn hort_domain::ports::retention_policy_projection_repository::RetentionPolicyProjectionRepository>,
    policies: Arc<crate::use_cases::retention_policy_use_case::RetentionPolicyUseCase>,
}

impl RetentionApply {
    pub fn new(
        projections: Arc<dyn hort_domain::ports::retention_policy_projection_repository::RetentionPolicyProjectionRepository>,
        policies: Arc<crate::use_cases::retention_policy_use_case::RetentionPolicyUseCase>,
    ) -> Self {
        Self {
            projections,
            policies,
        }
    }
}

/// Compile-time gate for the authorization-event batch builders
/// ([`ApplyConfigUseCase::authorization_batches`] /
/// [`ApplyConfigUseCase::grouped_authorization_batches`]).
///
/// **Architectural intent.** The builders assemble `RoleDefined` /
/// `GroupMappingAdded` / `PermissionGrantAdded` / etc. — a set of
/// audit events whose only legitimate emitter is the gitops apply
/// pipeline. Before this gate, any future contributor could call the
/// helpers from any code path inside `hort-app`; the architectural
/// invariant "authorization events come from gitops apply only" was
/// convention, not compile-time enforced. The token plus the pub-crate
/// constructor turns the invariant into a compile error: without a
/// `&GitOpsApplyToken`, the builders refuse to compile, and a
/// `GitOpsApplyToken` cannot be constructed outside `hort-app` (the
/// constructor is `pub(crate)`).
///
/// **Why not a marker trait or zero-sized type alias?** The choice is
/// deliberate: a marker trait would let any caller implement it on
/// their own type and bypass the gate; a zero-sized type alias
/// without a sealed constructor would be public-constructible.
/// `pub struct GitOpsApplyToken { _private: () }` plus
/// `pub(crate) fn for_gitops_boot()` is the minimal pattern that
/// makes the sealed-constructor property hold.
///
/// **Single-construction-point.** There is exactly one constructor —
/// [`for_gitops_boot`](Self::for_gitops_boot) — and it is called from
/// exactly one site, the start of [`ApplyConfigUseCase::apply`]. Adding
/// a second constructor would defeat the gate; treat that as a review
/// finding requiring a design-doc update.
pub struct GitOpsApplyToken {
    _private: (),
}

impl GitOpsApplyToken {
    /// Constructor restricted to the gitops boot path.
    ///
    /// Visibility is `pub(crate)` so external crates (`hort-server`,
    /// `hort-http-*`, adapters) cannot mint a token even if they import
    /// the type. The architectural intent is "the only call site is
    /// inside [`ApplyConfigUseCase::apply`]"; the visibility makes
    /// "construction outside this crate" a compile error, not a
    /// reviewer-vigilance task.
    ///
    /// ```compile_fail
    /// // GitOpsApplyToken cannot be constructed outside the use case crate.
    /// // The struct is public so the type can be referenced (helper
    /// // signatures take `&GitOpsApplyToken`), but the constructor is
    /// // `pub(crate)`. A doc-test running outside `hort-app` therefore
    /// // fails to compile when it tries to call the constructor.
    /// let _t = hort_app::use_cases::apply_config_use_case::GitOpsApplyToken::for_gitops_boot();
    /// ```
    ///
    /// ```compile_fail
    /// // The struct's private field also cannot be reached, so a
    /// // would-be caller cannot construct via record syntax either.
    /// let _t = hort_app::use_cases::apply_config_use_case::GitOpsApplyToken { _private: () };
    /// ```
    pub(crate) fn for_gitops_boot() -> Self {
        Self { _private: () }
    }
}

/// How one [`PRE_WRITE_REJECT_ROWS`] row assembles the message it aborts
/// with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowAbort {
    /// `"; "`-join every finding of the row, so the operator sees all
    /// offenders in one pass. The default for a new row: the validator
    /// collects them all anyway and the offline `validate-config` prints
    /// them all, so a reject that named one of five offenders would send
    /// the operator round the loop five times.
    EveryFinding,
    /// Take the first finding only. Reserved for the rows whose inline
    /// predecessor aborted on the first violation *within* the row
    /// (`validate_provenance_config` / `reject_repo_storage_backend_mismatch`);
    /// changing them would change the message an already-failing config
    /// rejects with.
    FirstFinding,
    /// `"; "`-join the row's findings with duplicates collapsed. For a row
    /// whose finding text identifies the *rule* and not the offending
    /// object: the grant linter reports one finding per (grant, rule)
    /// violation but renders no grant identity into the message, so ten
    /// grants tripping one rule produce ten byte-identical sentences and
    /// joining them verbatim is pure noise. Collapsed, the operator gets
    /// one sentence per rule — the information the grant stage's own
    /// aggregate message carried.
    DistinctFindings,
}

/// Every reject row [`ApplyConfigUseCase::run_pre_write_validation`]
/// consumes from the [`crate::lint::StaticConfigValidator`] report, in
/// apply's row order, with the `error!` line and the message assembly each
/// aborts with.
///
/// This is a value rather than a comment because the list is a claim about
/// completeness — "every rejection the apply can reach is reachable before
/// the first write" — and a comment cannot fail.
/// `pre_write_validation_consumes_every_reject_row` matches exhaustively
/// over [`LinterRule`] and asserts that every rejecting rule appears here,
/// so a new lint row has to state where it is consumed instead of silently
/// deferring its rejection to a write-capable stage. The two rows that are
/// deliberately absent are the two that are not rejects collected from this
/// table: `SaIssuerFk` (consumed by its own dedicated abort just above the
/// walk, to keep its distinct `error!` + joined envelope) and
/// `UnderConstrainedFederatedIdentities` (advisory only — it never aborts).
const PRE_WRITE_REJECT_ROWS: &[(LinterRule, &str, RowAbort)] = &[
    (
        LinterRule::TrustUpstreamPublishTimeRequiresScanBackends,
        "gitops apply: trust_upstream_publish_time × scan_backends:[] linter rejected combination(s)",
        RowAbort::EveryFinding,
    ),
    (
        LinterRule::PrefetchMaxAgeDaysNotImplemented,
        "gitops apply: prefetchPolicy.maxAgeDays linter rejected envelope(s) (field accepted-but-inert)",
        RowAbort::EveryFinding,
    ),
    (
        LinterRule::PrefetchTriggerRequiresVersionDiscovery,
        "gitops apply: prefetchPolicy.triggers linter rejected envelope(s) (trigger requires VersionDiscovery, format handler does not declare it)",
        RowAbort::EveryFinding,
    ),
    (
        LinterRule::ProvenanceConfig,
        "gitops apply: provenanceMode linter rejected ScanPolicy envelope(s)",
        RowAbort::FirstFinding,
    ),
    (
        LinterRule::RepoStorageBackendMismatch,
        "gitops apply: rejected — per-repository storage backend differs from the deployment's effective global backend; per-repository storage routing is unsupported in v2",
        RowAbort::FirstFinding,
    ),
    (
        LinterRule::ScanBackendCapability,
        "gitops apply: scanBackends linter rejected ScanPolicy envelope(s) (backend cannot analyse a governed repository's format — scanner capability map)",
        RowAbort::EveryFinding,
    ),
    // Row 8 sits before row 9 because that is where the validator collects
    // it: the walk's "first row with an error finding" and the report's
    // "first error in row order" have to name the same row, or the two
    // halves of the no-drift guarantee answer differently for a bundle
    // that trips both.
    (
        LinterRule::PermissionGrant,
        "gitops apply: permission-grant linter rejected the desired set (secure-by-default — operator allowlist/downgrade is the only escape hatch)",
        RowAbort::DistinctFindings,
    ),
    (
        LinterRule::RetentionUnusedForNotImplemented,
        "gitops apply: retention predicate linter rejected RetentionPolicy envelope(s) (UnusedFor has no last-download signal and silently decides on age)",
        RowAbort::EveryFinding,
    ),
    (
        LinterRule::ScanPolicyLicensePolicyNotImplemented,
        "gitops apply: licensePolicy linter rejected ScanPolicy envelope(s) (the scan path evaluates the policy against an empty licence list, so it decides nothing)",
        RowAbort::EveryFinding,
    ),
    (
        LinterRule::ExclusionScopeNotImplemented,
        "gitops apply: exclusion scope linter rejected Exclusion envelope(s) (the finding filter never reads the scope, so the waiver clears its CVE everywhere the policy governs)",
        RowAbort::EveryFinding,
    ),
    (
        LinterRule::VirtualMemberFormatNotEnforced,
        "gitops apply: virtualMembers linter rejected ArtifactRepository envelope(s) (member format differs from the virtual's and no compatibility check is implemented)",
        RowAbort::EveryFinding,
    ),
    (
        LinterRule::ScanPolicyMaxArtifactAgeNotImplemented,
        "gitops apply: maxArtifactAge linter rejected ScanPolicy envelope(s) (the age evaluator has no caller, so the cap is stored and never applied)",
        RowAbort::EveryFinding,
    ),
];

impl ApplyConfigUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        claim_mappings: Arc<dyn ClaimMappingRepository>,
        permission_grants: Arc<dyn PermissionGrantRepository>,
        authority: Arc<dyn AuthorityLifecyclePort>,
        curation_rules: Arc<dyn CurationRuleRepository>,
        policy_projections: Arc<dyn PolicyProjectionRepository>,
        policies: Arc<PolicyUseCase>,
        artifacts: Arc<dyn ArtifactRepository>,
        artifact_lifecycle: Arc<dyn ArtifactLifecyclePort>,
        events: Arc<EventStorePublisher>,
        upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
        upstream_allowlist: UpstreamHostAllowlist,
        content_references: Arc<dyn ContentReferenceIndex>,
        oidc_issuers: Arc<dyn OidcIssuerRepository>,
        service_accounts: Arc<dyn ServiceAccountRepository>,
        users: Arc<dyn UserRepository>,
        version_discovery_capable_formats: Arc<HashSet<String>>,
        retention: Option<RetentionApply>,
    ) -> Self {
        Self {
            repositories,
            claim_mappings,
            permission_grants,
            authority,
            curation_rules,
            policy_projections,
            policies,
            artifacts,
            artifact_lifecycle,
            events,
            upstream_mappings,
            upstream_allowlist,
            content_references,
            oidc_issuers,
            service_accounts,
            users,
            federated_jwt_validator: None,
            // Supplied by the caller, not defaulted: a composition
            // point that has no retention projection must say `None`
            // out loud. `None` keeps `apply_retention_policies` a
            // warned no-op, never a silent drop.
            retention,
            // Secure-by-default linter posture (ADR 0015). The
            // production path constructs through `new` only, so the
            // linter rejects single-claim / wildcard-non-admin /
            // unjustified-high-privilege grants with zero operator
            // config. Operator downgrade is `with_lint_config` only.
            lint_config: crate::lint::LintConfig::default(),
            // The per-repo-vs-global
            // storage-backend cross-check is opt-in via
            // `with_effective_storage_backend`. `None` here keeps the
            // constructor signature byte-unchanged and skips the
            // cross-check (every pre-existing test harness is
            // unaffected; production wires it from `hort-server`).
            effective_storage_backend: None,
            // Upstream-index cache invalidator
            // opt-in via `with_upstream_index_cache_invalidator`. `None`
            // keeps the use case constructable in every default
            // test harness; production wires it from `hort-server`. The
            // retroactive-block post-commit hook is a no-op when None.
            upstream_index_cache_invalidator: None,
            // Default empty; the composition root wires the real set
            // via `with_provenance_capable_formats`. Default-empty is
            // fail-closed: a `Required` provenance policy on any format
            // is apply-rejected until the operator's deployment proves a
            // verifier applies (mirrors the IngestUseCase default).
            provenance_capable_formats: Arc::new(HashSet::new()),
            version_discovery_capable_formats,
        }
    }

    /// Override the set of repository-format strings whose compiled-in
    /// `FormatHandler` declares the `VersionDiscovery` capability group
    /// (ADR 0005), installed as a required [`Self::new`] parameter.
    /// Builder-style purely for call-site ergonomics (a caller that wants
    /// a different set than the one it constructed with does not need to
    /// re-supply every other constructor argument); it does not make the
    /// capability set optional — [`Self::new`] already requires an
    /// initial value.
    ///
    /// The apply-time linter consults this set together with each
    /// repository's declared `prefetchPolicy.triggers`: a `transitive_deps`
    /// or `scheduled` trigger on a format **absent** from the set is
    /// rejected (the trigger is accepted but never fires without the
    /// capability). `on_dist_tag_move` never consults this set.
    #[must_use]
    pub fn with_version_discovery_capable_formats(
        mut self,
        formats: impl IntoIterator<Item = String>,
    ) -> Self {
        self.version_discovery_capable_formats = Arc::new(formats.into_iter().collect());
        self
    }

    /// Install the set of repository-format
    /// strings some registered `ProvenancePort` `applies_to` (the static
    /// backend→format capability map; Tier-1 = `{"oci"}` for cosign;
    /// ADR 0027).
    /// Builder-style so the composition root wires it without
    /// changing the [`Self::new`] arg list — every existing call site
    /// keeps compiling with the default empty set. Mirrors
    /// `IngestUseCase::with_provenance_capable_formats` exactly.
    ///
    /// The apply-time linter consults this set together with each
    /// `provenance_mode: Required` policy's resolved format(s): a
    /// `Required` scope mapping to a format **absent** from the set is
    /// rejected (no verifier exists to satisfy the gate ⇒ artifacts would
    /// stay `Pending` forever — fail-closed).
    #[must_use]
    pub fn with_provenance_capable_formats(
        mut self,
        formats: impl IntoIterator<Item = String>,
    ) -> Self {
        self.provenance_capable_formats = Arc::new(formats.into_iter().collect());
        self
    }

    /// Install the upstream packument /
    /// simple-index cache invalidator. Called from the composition
    /// root (`hort-server`) after [`Self::new`]; without it, the
    /// `commit_retroactive_block` post-commit cache-invalidation hook
    /// is a no-op (TTL-only freshness posture). Builder-
    /// shaped exactly like [`Self::with_federated_jwt_validator`].
    #[must_use]
    pub fn with_upstream_index_cache_invalidator(
        mut self,
        invalidator: Arc<dyn UpstreamIndexCacheInvalidator>,
    ) -> Self {
        self.upstream_index_cache_invalidator = Some(invalidator);
        self
    }

    /// Attach a
    /// [`FederatedJwtValidator`] so apply-time JWKS warm-up fires for
    /// every newly-created or updated `OidcIssuer` row.
    ///
    /// Composition root calls this after [`Self::new`] when the
    /// federation validator is wired (multi-issuer adapter present;
    /// `HORT_FEDERATED_JWT_VALIDATOR=enabled` and at least one
    /// `OidcIssuer` row reachable). Tests bypass this method to seed
    /// a mock validator; the default `None` slot keeps every
    /// validator-less test harness compiling unchanged.
    pub fn with_federated_jwt_validator(
        mut self,
        validator: Arc<dyn FederatedJwtValidator>,
    ) -> Self {
        self.federated_jwt_validator = Some(validator);
        self
    }

    /// Install
    /// an operator-tuned [`LintConfig`](crate::lint::LintConfig)
    /// (ADR 0015).
    ///
    /// The default ([`Self::new`]) is the secure-by-default reject
    /// posture; this builder is the **only** way to relax it, and
    /// only via explicit gitops config (the operator's downgrade is a
    /// committed, diff-visible, audited config mutation). There is no
    /// env-var path and no global `warn` switch. Mirrors the
    /// `with_federated_jwt_validator` builder shape so the production
    /// composition root opts in/out at one site; test harnesses use
    /// it to install a permissive config for reconcile-mechanics
    /// tests (the same pattern as `build_harness_with_allowlist`).
    pub fn with_lint_config(mut self, lint_config: crate::lint::LintConfig) -> Self {
        self.lint_config = lint_config;
        self
    }

    /// Override the event-sourced retention-policy apply dependencies
    /// (projection reader + `RetentionPolicyUseCase`) installed as a
    /// required [`Self::new`] argument.
    ///
    /// Builder-style purely for call-site ergonomics (a caller holding
    /// an already-constructed use case does not have to re-supply every
    /// other constructor argument); it does **not** make the slot
    /// optional — [`Self::new`] already requires an explicit value.
    /// Same shape, and same rationale, as
    /// [`Self::with_version_discovery_capable_formats`].
    #[must_use]
    pub fn with_retention(mut self, retention: RetentionApply) -> Self {
        self.retention = Some(retention);
        self
    }

    /// Install the deployment's **effective global storage backend**
    /// so a per-repo `storage.backend` that differs from it is
    /// rejected at apply (fail-closed, loud).
    ///
    /// The composition root (`hort-server`) maps its already-in-scope
    /// `StorageConfig::{Filesystem,S3}` onto
    /// [`EffectiveStorageBackend`](crate::storage_backend::EffectiveStorageBackend)
    /// and calls this after [`Self::new`]; without it, the cross-check
    /// is skipped (`None` slot — every pre-existing test harness keeps
    /// compiling/passing unchanged). Builder-shaped exactly like
    /// `with_lint_config` / `with_retention` so the constructor
    /// signature is byte-unchanged (no port-contract change, no
    /// `ApplyConfigUseCase::new` change). The value is the *true*
    /// `{filesystem, s3}` deployment fact — never the coarse
    /// `StoragePort::backend_label()` `{filesystem, object_store}`,
    /// which would fail-*wrong* on a legitimate `s3`-on-S3 config
    /// (rejected as security theater).
    pub fn with_effective_storage_backend(
        mut self,
        backend: crate::storage_backend::EffectiveStorageBackend,
    ) -> Self {
        self.effective_storage_backend = Some(backend);
        self
    }

    /// Resolve the
    /// **effective** [`LintConfig`](crate::lint::LintConfig) for one
    /// apply, *before* the grant linter runs, so an allowlist entry and
    /// a single-claim grant using that claim land cleanly **in the same
    /// bundle**.
    ///
    /// Resolution order:
    ///
    /// - **Bundle declares `PermissionGrantLintConfig`** → the bundle's
    ///   spec is the effective config (`LintConfig::from(&spec)`). The
    ///   kind carries the *full* `LintConfig` shape, so
    ///   the bundle's declaration overlays the composed default
    ///   wholesale — this is the "same-bundle" path: the spec is
    ///   resolved here, **before** [`Self::apply_permission_grants`], so
    ///   a grant whose sole claim was just allowlisted passes the
    ///   linter in the same apply.
    /// - **Bundle omits the kind** → the composition-root-installed
    ///   `self.lint_config` (the [`Self::with_lint_config`] boot seam;
    ///   [`LintConfig::default`] when the root never opted out). A
    ///   a missing kind is **not** a downgrade — the secure default
    ///   is preserved verbatim.
    ///
    /// Observability (**counts
    /// only, never claim names**): a resolved *non-default* config logs
    /// `info!` with `single_claim_allowlist_len` + `rule_overrides_count`
    /// (a security-relevant config change is operator-visible). A
    /// `>1 PermissionGrantLintConfig` declaration logs `warn!`
    /// (operator config error, recoverable by fixing YAML) and falls
    /// back to the secure default — `validate_against` (run earlier in
    /// [`Self::apply`]) already hard-rejects this via
    /// `ValidationError::SingletonConflict`, so this `warn!` is the
    /// resolver's defense-in-depth operator-actionable signal, not the
    /// reject itself. `hort_apply_config_linter_total{rule,result}` is
    /// **unchanged** — no new metric, no new label (only the linter's
    /// *config source* changes; the linter still emits its metric
    /// unchanged).
    ///
    /// Pure over `(self.lint_config, desired.lint_config)` apart from
    /// the structured log — no I/O, no port call. Threaded into
    /// [`Self::apply_permission_grants`] as a parameter (a private
    /// helper, not a port contract — `ApplyConfigUseCase::new`'s 9-arg
    /// signature is unchanged, mirroring the
    /// `with_retention`/`with_federated_jwt_validator` builder
    /// precedent; `feedback_no_port_contract_changes`).
    fn resolve_effective_lint_config(&self, desired: &DesiredState) -> crate::lint::LintConfig {
        // The verdict is single-sourced through the shared pure resolver
        // so apply and the offline `StaticConfigValidator`
        // row 8 cannot drift. This wrapper layers apply's audit-logging
        // side-effects (which the pure core deliberately omits) on top.

        // Defense-in-depth: `validate_against` already rejected a
        // singleton conflict before we get here, but log the
        // operator-actionable signal at the resolution site too (the
        // resolver must never silently last-wins a security opt-out).
        if desired.lint_config_sources.len() > 1 {
            tracing::warn!(
                lint_config_source_count = desired.lint_config_sources.len(),
                "gitops apply: more than one PermissionGrantLintConfig declared \
                 (singleton kind) — falling back to the secure default; fix the \
                 YAML so exactly one (or zero) PermissionGrantLintConfig exists"
            );
        }

        let resolved = crate::lint::resolve_effective_lint_config(&self.lint_config, desired);

        // A resolved config that differs from the secure default — and
        // that came from an operator-declared envelope (a `>1`-source
        // fallback or an absent kind is never an operator opt-out, even
        // when `self.lint_config` happens to be non-default) — is a
        // security-relevant, operator-authored config change. Log it
        // (counts only; claim names are operator topology, never
        // logged).
        let from_operator_envelope =
            desired.lint_config_sources.len() <= 1 && desired.lint_config.is_some();
        if from_operator_envelope && resolved != crate::lint::LintConfig::default() {
            let rule_overrides_count = [
                resolved.rule_overrides.single_claim_grant.is_some(),
                resolved.rule_overrides.direct_user_grant.is_some(),
                resolved.rule_overrides.wildcard_repo_non_admin.is_some(),
            ]
            .iter()
            .filter(|present| **present)
            .count();
            tracing::info!(
                single_claim_allowlist_len = resolved.single_claim_allowlist.len(),
                rule_overrides_count,
                "gitops apply: operator PermissionGrantLintConfig resolved \
                 (non-default, diff-visible, audited opt-out)"
            );
        }

        resolved
    }

    /// Pre-write validation + lint pass.
    ///
    /// Runs every check that is **provably performed before the first DB
    /// write** (`apply`'s Stage-1 `save_managed`): snapshot/env validation,
    /// the SA->issuer FK check, every reject row in
    /// [`PRE_WRITE_REJECT_ROWS`], and the upstream-host allowlist gate.
    /// Only the
    /// `build_snapshot` reads touch the database -- zero writes. (The
    /// `scanBackends` check validates against the compiled-in
    /// `crate::scanning::KNOWN_SCAN_BACKENDS` set, so it does no I/O and is
    /// immune to worker-registration timing -- see regression H20.)
    ///
    /// The completeness claim this pass carries is that **no rejection the
    /// apply can reach is reachable only from a write-capable stage**: the
    /// apply writes between its stages and ships no rollback, so a
    /// late-stage reject leaves a partial apply -- a refused tightening
    /// beside a committed loosening of the same bundle. Two tests hold the
    /// claim: `pre_write_validation_consumes_every_reject_row` (no lint row
    /// may be omitted from the table) and
    /// `every_rejecting_apply_stage_is_rejected_pre_write` (per-stage
    /// corpus). The stages keep their own checks as defence-in-depth, where
    /// a reject is then a `DomainError::Invariant`-grade contract violation
    /// rather than operator error.
    ///
    /// This is the seam `gitops_boot` uses (via [`Self::preflight_validate`])
    /// to PARK not-ready on a pre-write config error instead of
    /// crashlooping: a failure here cannot have left a half-applied state,
    /// so parking is safe -- unlike the in-stage validation inside the apply
    /// stages, which is mid-write-capable and must still crash.
    ///
    /// `emit_advisories` gates the two always-on advisory `warn!`s
    /// (under-constrained federated identities; provenance
    /// `verify_if_present` without identities). `apply` passes `true` (it is
    /// the write path and logs them exactly once); the boot preflight passes
    /// `false`, so a preflight-then-apply sequence does not double-log them.
    /// The hard-reject linter metrics are NOT gated -- they fire only on the
    /// failing path, after which `apply` is never reached, so they still emit
    /// exactly once.
    async fn run_pre_write_validation(
        &self,
        desired: &DesiredState,
        env: &EnvSnapshot,
        snapshot: &CurrentSnapshot,
        emit_advisories: bool,
    ) -> AppResult<()> {
        // ----- validate against snapshot+env (row 1) -----
        // Snapshot/env-dependent — stays inline (NOT in the offline
        // `StaticConfigValidator`). Its own abort, no linter metric.
        if let Err(errs) = desired.validate_against(snapshot, env) {
            tracing::error!(
                error_count = errs.0.len(),
                "gitops apply: validation failed against snapshot/env"
            );
            return Err(AppError::Domain(DomainError::Validation(errs.to_string())));
        }

        // The snapshot-free rows (rows 2,3,5,6,6b,
        // 7,7b,7c,8,9) are collected by the pure `StaticConfigValidator`, in
        // apply's row order, with NO early return / metric / `tracing`.
        // This caller walks the report below and reproduces the historical
        // first-failing-row abort + per-rule metric emission byte-
        // identically — the no-drift guarantee shared with the offline
        // `hort-server validate-config` command. The env/DB rows (1 above,
        // 4 below) stay inline.
        //
        // Row 8 (the permission-grant linter) is enabled here via
        // `with_grant_lint_base`. It is the one row whose verdict the apply
        // pipeline could also reach from its own grant stage, and that stage
        // runs after the repository, policy and mapping writes — so a grant
        // the linter refuses used to abort the apply with a loosened policy
        // from the same bundle already committed. The row's rejection
        // therefore belongs here, before the first write. What licenses
        // running it this early is that the rules read only the grant's
        // subject shape, permission and whether it is repo-scoped — never a
        // resolved id value — so the validator's placeholder-id expansion
        // produces the same verdict as the stage's port-built set
        // (`static_validator_row8_and_apply_grant_linter_agree`).
        //
        // The base is `self.lint_config` (the composition-root config, secure
        // default unless the root opted out), NOT the resolved one: the
        // validator resolves the bundle's own `PermissionGrantLintConfig`
        // partition on top of it through the shared pure resolver, exactly as
        // the grant stage does, so a same-bundle allowlist-then-use still
        // commits. The audited `resolve_effective_lint_config` wrapper stays
        // on the write path — its `info!`/`warn!` must be emitted once per
        // apply, and this pass runs twice per boot (preflight, then apply).
        //
        // No linter metric is emitted from here. Row 8's
        // `hort_apply_config_linter_total` is the grant stage's own emission
        // over the port-built desired set, which stays where it is; a
        // metric-free validator is what keeps the offline
        // `validate-config` path from inventing series (see
        // `LinterRule::metric_rule`).
        use crate::lint::StaticConfigValidator;
        let validator = StaticConfigValidator::new(
            self.provenance_capable_formats.clone(),
            self.version_discovery_capable_formats.clone(),
            self.effective_storage_backend,
        )
        .with_grant_lint_base(self.lint_config.clone());
        let report = validator.validate(desired);

        // Row 2 (SA→issuer cross-kind FK) precedes row 4: first-failing-
        // row aborts. Same `tracing::error!` + `"; "`-joined
        // `DomainError::Validation` envelope, no linter metric (row 2
        // never emitted one).
        let fk_errors: Vec<&str> = report
            .errors
            .iter()
            .filter(|f| f.rule == LinterRule::SaIssuerFk)
            .map(|f| f.message.as_str())
            .collect();
        if !fk_errors.is_empty() {
            tracing::error!(
                error_count = fk_errors.len(),
                "gitops apply: ServiceAccount.federatedIdentities[].issuer cross-kind FK validation failed"
            );
            return Err(AppError::Domain(DomainError::Validation(
                fk_errors.join("; "),
            )));
        }

        // Apply-time advisory WARNING (never a hard reject) for
        // under-constrained `federatedIdentities[]`. The
        // validator carries the typed fields in `warn_context`; this caller
        // re-emits them as the original STRUCTURED `warn!` fields
        // (service_account / federated_identity_index / issuer) — byte-identical
        // to the historical inline line, so operator log/SIEM pipelines keying
        // on them keep working. Gated by `emit_advisories` so
        // a preflight-then-apply does not double-log. A warning, not a
        // `ValidationError` — apply still succeeds.
        if emit_advisories {
            for w in report
                .warnings
                .iter()
                .filter(|f| f.rule == LinterRule::UnderConstrainedFederatedIdentities)
            {
                match &w.warn_context {
                    Some(crate::lint::WarnContext::UnderConstrainedFederatedIdentities {
                        service_account,
                        federated_identity_index,
                        issuer,
                        detail,
                    }) => {
                        tracing::warn!(
                            service_account = %service_account,
                            federated_identity_index = *federated_identity_index,
                            issuer = %issuer,
                            "gitops apply: under-constrained federatedIdentities — {detail}"
                        );
                    }
                    // No structured context (shouldn't happen for this rule) —
                    // fall back to the flat rendered message.
                    _ => tracing::warn!("{}", w.message),
                }
            }
        }

        // ----- Apply-time scanner-backend validation against the
        // compiled-in capability set (`crate::scanning::KNOWN_SCAN_BACKENDS`),
        // NOT the live `scanner_registry`. Surfaces an unknown
        // `scanBackends:` entry (a typo, or a backend this build does not
        // ship) as a pre-write `Validation` error before the diff/apply
        // stage starts, matching the error shape used by `validate_against`
        // (snapshot+env).
        //
        // Why the static set and not the live `scanner_registry`:
        // validating a backend *name* against the live worker registry was a
        // boot-ordering hazard (regression H20). On a fresh deployment the
        // gitops boot runs this preflight before any `hort-worker` has
        // registered its first heartbeat, so the live set is transiently
        // empty and a correct `scanBackends: [trivy]` policy was rejected
        // fail-closed — parking the server not-ready with no retry. A
        // backend name is valid or not as a permanent property of the build,
        // independent of worker-registration timing; whether a worker
        // advertising it is *running* is a runtime-liveness concern for
        // metrics/health, not a config-validity error. See
        // `crate::scanning` and the validator's rustdoc.
        let valid_backends: Vec<String> = crate::scanning::KNOWN_SCAN_BACKENDS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let scan_backend_errors =
            hort_config::desired::validate_scan_policy_backends(desired, &valid_backends);
        if !scan_backend_errors.is_empty() {
            tracing::error!(
                error_count = scan_backend_errors.len(),
                "gitops apply: scanBackends validation failed (unsupported backend)"
            );
            let joined = scan_backend_errors
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(AppError::Domain(DomainError::Validation(joined)));
        }

        // ----- Post-row-4 snapshot-free rejects, collected by
        //       `StaticConfigValidator` above. -----
        //
        // The rows, their `error!` lines and their message assembly are
        // [`PRE_WRITE_REJECT_ROWS`] — a value, not a comment, so
        // `pre_write_validation_consumes_every_reject_row` can assert the
        // set is complete instead of a reader having to notice an omission.
        // On the FIRST row with any error finding: emit that row's metric
        // (where the rule has one — `LinterRule::metric_rule`) once per
        // finding, log its `error!`, and return its
        // `AppError::Domain(DomainError::Validation(_))`. Later rows are
        // NOT emitted/reported.
        for (rule, error_log, abort) in PRE_WRITE_REJECT_ROWS.iter().copied() {
            let messages: Vec<&str> = report
                .errors
                .iter()
                .filter(|f| f.rule == rule)
                .map(|f| f.message.as_str())
                .collect();
            if messages.is_empty() {
                continue;
            }
            // Per-row metric, one increment per offending finding, for the
            // rows that have one. Independent of the message assembly
            // below: a row can reject every offender in its message and
            // still carry no metric (row 8 — the grant stage owns that
            // series).
            if let Some(metric_rule) = rule.metric_rule() {
                tracing::error!(error_count = messages.len(), "{error_log}");
                for _ in 0..messages.len() {
                    crate::metrics::emit_apply_config_linter(
                        metric_rule,
                        crate::metrics::LinterResult::Reject,
                    );
                }
            } else {
                tracing::error!("{error_log}");
            }
            return Err(AppError::Domain(DomainError::Validation(match abort {
                RowAbort::EveryFinding => messages.join("; "),
                RowAbort::FirstFinding => messages[0].to_string(),
                RowAbort::DistinctFindings => {
                    let mut seen: HashSet<&str> = HashSet::new();
                    messages
                        .iter()
                        .filter(|m| seen.insert(m))
                        .copied()
                        .collect::<Vec<&str>>()
                        .join("; ")
                }
            })));
        }

        // No post-row-4 error: surface the provenance advisory warning(s)
        // (row 7 `verify_if_present` without identities), re-emitting the
        // original STRUCTURED `warn!(policy = …, "…")` from `warn_context`
        // — gated by `emit_advisories`.
        //
        // ACCEPTED BEHAVIOUR CHANGE: the historical inline
        // `validate_provenance_config` emitted each policy's warn inline,
        // per-policy, so a verify_if_present warn for an EARLIER policy still
        // surfaced even when a LATER policy hard-rejected the row. The
        // validator now collects all row-7 findings and this caller emits the
        // warns only on the clean post-abort path — so a co-occurring row-5/6/
        // 7/7b reject suppresses these advisory warns. Advisory-only (no
        // verdict/metric impact) and self-correcting once the operator fixes
        // the reject and re-applies; deemed acceptable.
        if emit_advisories {
            for w in report
                .warnings
                .iter()
                .filter(|f| f.rule == LinterRule::ProvenanceConfig)
            {
                match &w.warn_context {
                    Some(crate::lint::WarnContext::ProvenanceVerifyIfPresent { policy }) => {
                        tracing::warn!(
                            policy = %policy,
                            "gitops apply: ScanPolicy provenanceMode `verify_if_present` with \
                             empty `provenanceIdentities` — tampering is detected (a \
                             forged/untrusted signature is rejected) but no signer is pinned. \
                             Often intended; declare `provenanceIdentities` to enforce which \
                             signer is trusted."
                        );
                    }
                    // No structured context (e.g. a row-8 grant-lint warning if
                    // ever surfaced here) — fall back to the flat message.
                    _ => tracing::warn!("{}", w.message),
                }
            }
        }

        // ----- upstream-host allowlist (pre-write park gate) -----
        // Enforce HORT_UPSTREAM_ALLOWLIST_HOSTS BEFORE any DB write, so an
        // un-allowlisted upstream host parks boot not-ready
        // (`GitopsBootError::PreflightValidate`, a `DomainError::Validation`)
        // instead of writing Stage-1/2 rows and then crashlooping. The check
        // is diff-scoped (create+update) to match the write-time enforcement
        // in `apply_upstream_mappings`, so `delete`/unchanged rows stay
        // exempt. `diff` is pure; `apply` recomputes it after this pass with
        // the same snapshot, so the two plans agree.
        let plan = diff(snapshot, desired);
        self.check_upstream_allowlist_for_plan(&plan.upstream_mappings)?;

        Ok(())
    }

    /// Pre-write validation/lint gate for the boot path.
    ///
    /// `gitops_boot` calls this **before** [`Self::apply`] so a
    /// provably-pre-write config error parks the pod not-ready instead of
    /// crashlooping. Returns `DomainError::Validation` for a config error
    /// (boot maps it to the park-eligible
    /// `GitopsBootError::PreflightValidate`). Builds its own snapshot; boot
    /// then re-enters `apply`, which builds its own and re-runs the same
    /// checks with advisories enabled. No DB writes occur on any path.
    pub async fn preflight_validate(
        &self,
        desired: &DesiredState,
        env: &EnvSnapshot,
    ) -> AppResult<()> {
        let snapshot = self.build_snapshot().await?;
        self.run_pre_write_validation(desired, env, &snapshot, false)
            .await
    }

    /// Execute one apply.
    ///
    /// 1. Build a `CurrentSnapshot` from the read-side ports.
    /// 2. `validate_against` (snapshot + env). Any error → `Err`.
    /// 3. `diff` to produce the plan.
    /// 4. Three-stage topological apply (see module docs).
    /// 5. Strict-atomic on first port failure.
    #[tracing::instrument(skip(self, desired, env))]
    pub async fn apply(&self, desired: DesiredState, env: EnvSnapshot) -> AppResult<ApplyReport> {
        // ----- snapshot -----
        let snapshot = self.build_snapshot().await?;

        // ----- pre-write validation/lint -----
        // Every check below is provably before the first DB write. The boot
        // path runs this same pass via `preflight_validate` BEFORE calling
        // `apply`, so a pre-write config error parks not-ready instead of
        // crashlooping; here `true` emits the always-on advisories exactly
        // once on the write path.
        self.run_pre_write_validation(&desired, &env, &snapshot, true)
            .await?;

        // ----- plan -----
        let plan: ApplyPlan = diff(&snapshot, &desired);
        // The per-kind breakdown is captured from the plan up front.
        // Every CRUD kind's apply below increments the aggregate
        // counters from these very lists, and apply is strict-atomic
        // (the first port failure aborts), so on the `Ok` path the
        // planned per-kind numbers ARE the applied ones. Projected
        // rather than recomputed — the plan is dropped at the end of
        // this function.
        let mut report = ApplyReport {
            per_kind: ApplyKindCounts::from_plan(&plan),
            ..ApplyReport::default()
        };

        // Mint the typed-token at the
        // single legitimate construction site (the public entry to
        // gitops apply). The append-helper signatures borrow this
        // token, so any non-gitops caller of the helpers fails to
        // compile. See [`GitOpsApplyToken`] for the full architectural
        // intent.
        let token = GitOpsApplyToken::for_gitops_boot();

        // ----- Stage 1: no inbound refs -----
        // Order within the stage is stable for testability but does NOT
        // imply a dependency edge: ClaimMapping and CurationRule are
        // mutually independent. There is no `Role` branch in the
        // additive-claims model (ADR 0012).
        self.apply_claim_mappings(&plan.claim_mappings, &desired, &mut report, &token)
            .await?;
        self.apply_curation_rules(&plan.curation_rules, &mut report)
            .await?;

        // ----- Stage 2: depends on stage 1 -----
        // Repository rows + curation-rule junction-edge writes; then
        // event-sourced ScanPolicy applies via PolicyUseCase.
        self.apply_repository_rows(&plan.repositories, &desired, &mut report)
            .await?;
        let repo_id_by_name = self.collect_repo_id_by_name(&desired).await?;
        self.apply_scan_policies(&desired, &repo_id_by_name, &mut report)
            .await?;
        // Event-sourced retention policies, same shape
        // as ScanPolicy (gitops-authored via RetentionPolicyUseCase).
        self.apply_retention_policies(&desired, &repo_id_by_name, &mut report)
            .await?;

        // ----- Stage 3: depends on stage 2 -----
        // Exclusion (refs ScanPolicy projection), UpstreamMapping (refs
        // Repository), virtual-repo membership edges. PermissionGrant
        // is handled by the consolidated reconcile below.
        self.apply_exclusions(&desired, &repo_id_by_name, &mut report)
            .await?;
        self.apply_upstream_mappings(
            &plan.upstream_mappings,
            &repo_id_by_name,
            &mut report,
            &token,
        )
        .await?;
        self.apply_virtual_members(&desired).await?;

        // ----- OidcIssuer → ServiceAccount -----
        // OidcIssuer first (no inbound refs from existing kinds);
        // ServiceAccount after (cross-kind FK on issuer name has
        // already been validated in `validate_service_account_issuer_fk`).
        // ServiceAccount apply only manages the SA
        // aggregate + the backing `users` row — its `User`-subject
        // grants are reconciled by the consolidated PermissionGrant
        // pass below.
        self.apply_oidc_issuers(&plan.oidc_issuers, &mut report, &token)
            .await?;
        self.apply_service_accounts(&plan.service_accounts, &mut report, &token)
            .await?;

        // ----- Consolidated PermissionGrant
        // reconcile (runs LAST). `AuthorityLifecyclePort::commit_permission_grants`
        // reconciles the *entire* `managed_by = gitops` partition in one
        // atomic delete-absent + upsert-present, so the
        // envelope-declared grants AND the SA-owned
        // `User`-subject grants MUST be unioned into one call — a second
        // independent writer would delete the first's rows. By now the
        // backing `users` rows (ServiceAccount apply, above) and the
        // repository rows (Stage 2) all exist, so every grant's
        // `repository_id` / SA `user_id` resolves.
        //
        // Correctness-critical — resolve the
        // effective `LintConfig` from the bundle's lint-config
        // partition *before* the grant linter runs inside
        // `apply_permission_grants`. This is what makes an allowlist
        // entry + a single-claim grant using that claim in the SAME
        // bundle apply cleanly (same-bundle allowlist + grant pattern).
        // Absent kind ⇒ the composition-root default
        // (`LintConfig::default()` unless the root opted out via
        // `with_lint_config`) — a missing kind is not a downgrade.
        //
        // The pre-write pass resolved the same thing for its row 8, through
        // the same shared pure resolver, so the same-bundle
        // allowlist-then-use pattern commits at both gates rather than
        // being refused by the earlier one. This call keeps the audited
        // `info!`/`warn!` side of the resolution, which belongs on the
        // write path and must happen once per apply.
        let effective_lint_config = self.resolve_effective_lint_config(&desired);
        self.apply_permission_grants(
            &plan.permission_grants,
            &desired,
            &effective_lint_config,
            &mut report,
            &token,
        )
        .await?;

        // ----- unchanged counters from CRUD plans -----
        emit_unchanged(
            gitops_kind::REPOSITORY,
            plan.repositories.unchanged,
            &mut report,
        );
        // There is no `Role` plan; the claim-mapping plan
        // is `plan.claim_mappings` and the gitops kind label is
        // `claim_mapping` (ADR 0012).
        emit_unchanged(
            gitops_kind::CLAIM_MAPPING,
            plan.claim_mappings.unchanged,
            &mut report,
        );
        emit_unchanged(
            gitops_kind::PERMISSION_GRANT,
            plan.permission_grants.unchanged,
            &mut report,
        );
        emit_unchanged(
            gitops_kind::CURATION_RULE,
            plan.curation_rules.unchanged,
            &mut report,
        );
        emit_unchanged(
            gitops_kind::UPSTREAM_MAPPING,
            plan.upstream_mappings.unchanged,
            &mut report,
        );
        emit_unchanged(
            gitops_kind::OIDC_ISSUER,
            plan.oidc_issuers.unchanged,
            &mut report,
        );
        emit_unchanged(
            gitops_kind::SERVICE_ACCOUNT,
            plan.service_accounts.unchanged,
            &mut report,
        );

        tracing::info!(
            created = report.created,
            updated = report.updated,
            deleted = report.deleted,
            unchanged = report.unchanged,
            "gitops apply complete"
        );
        // NOTE: `hort_gitops_apply_total` is emitted by the boot caller
        // (`hort-server::gitops_boot::classify_and_emit_apply_metric`),
        // NOT here. Per the architect's "each metric emitted at exactly
        // one layer" rule, this use case only emits the per-object
        // counter via `emit_gitops_object`. Dual emission would
        // double-count and (worse) classify validation failures
        // differently between the two layers.
        Ok(report)
    }

    async fn build_snapshot(&self) -> AppResult<CurrentSnapshot> {
        // Pull every repository (managed + local). The snapshot keeps
        // local rows so `validate_against` can fire `ManagedConflict`.
        let repos_page = self
            .repositories
            .list(PageRequest::new(0, u64::MAX), None)
            .await?;
        let repositories: Vec<CurrentRepository> = repos_page
            .items
            .into_iter()
            .map(|r| CurrentRepository {
                id: r.id,
                key: r.key,
                managed_by: r.managed_by,
                managed_by_digest: r.managed_by_digest,
            })
            .collect();

        // Claim mappings (ADR 0012). The
        // managed subset is sufficient for the diff; local-row collision
        // is enforced by `validate_against`. Identity is the envelope
        // `metadata.name`; the adapter's `list_managed_by_gitops`
        // already filters to the gitops partition. The diff view keys
        // off `name`, so we synthesise a stable per-mapping name from
        // `(idp_group, claim)` — the same key the gitops envelope's
        // `metadata.name` resolves to and the table's UNIQUE constraint
        // enforces. Using the natural key keeps the diff identity
        // table-aligned without a separate name column on the port.
        let stored_mappings = self.claim_mappings.list_managed_by_gitops().await?;
        let claim_mappings: Vec<CurrentClaimMapping> = stored_mappings
            .into_iter()
            .map(|m| CurrentClaimMapping {
                name: claim_mappings::claim_mapping_identity_name(&m.idp_group, &m.claim),
                managed_by: m.managed_by,
                managed_by_digest: m.managed_by_digest,
            })
            .collect();

        // Repositories already hold every row (managed + local) from
        // the page above; resolve `repository_id` → key for the grant
        // diff view.
        let repo_name_by_id: HashMap<Uuid, String> =
            repositories.iter().map(|r| (r.id, r.key.clone())).collect();

        // The PermissionGrant diff identity is
        // subject-dependent: `(sorted required_claims, repository,
        // permission)` for a `Claims` subject; `(user_id, repository,
        // permission)` for a `User` subject. The diff layer is pure: we
        // materialise the subject columns + the repository key here.
        let managed_grants = self.permission_grants.list_managed_by_gitops().await?;
        let permission_grants: Vec<CurrentPermissionGrant> = managed_grants
            .into_iter()
            .map(|g| {
                let repository_name = g.repository_id.map(|id| {
                    repo_name_by_id
                        .get(&id)
                        .cloned()
                        // INVARIANT: a gitops grant row FKs into
                        // `repositories(id)` (ON DELETE CASCADE). A
                        // missing entry means the page didn't load it;
                        // fall back to the UUID string so the diff stays
                        // total (the desired identity won't match it).
                        .unwrap_or_else(|| id.to_string())
                });
                let (required_claims, user_id) = match &g.subject {
                    GrantSubject::Claims(required) => {
                        let mut sorted = required.clone();
                        sorted.sort();
                        (Some(sorted), None)
                    }
                    GrantSubject::User(uid) => (None, Some(uid.to_string())),
                };
                CurrentPermissionGrant {
                    id: g.id,
                    required_claims,
                    user_id,
                    permission: g.permission,
                    repository_name,
                    managed_by: g.managed_by,
                    managed_by_digest: g.managed_by_digest,
                }
            })
            .collect();

        let managed_rules = self.curation_rules.list_managed_by_gitops().await?;
        let curation_rules = managed_rules
            .into_iter()
            .map(|r| CurrentCurationRule {
                id: r.id,
                name: r.name,
                managed_by: r.managed_by,
                managed_by_digest: r.managed_by_digest,
            })
            .collect();

        // Populate the upstream-mapping
        // diff view. The diff identity is `(repository_name, path_prefix)`,
        // so we resolve the row's `repository_id` UUID back to the
        // repository key via the snapshot we already loaded.
        let managed_upstream = self.upstream_mappings.list_managed_by_gitops().await?;
        let upstream_mappings = managed_upstream
            .into_iter()
            .map(|m| {
                let repository_name = repo_name_by_id
                    .get(&m.repository_id)
                    .cloned()
                    // INVARIANT: every row in `repository_upstream_mappings`
                    // FKs into `repositories(id)` (ON DELETE CASCADE),
                    // so a missing entry would mean the repositories
                    // page above didn't load. Falling back to the UUID
                    // string keeps the diff functional — the desired
                    // identity won't match it and the row will be
                    // scheduled for delete (then immediately re-created
                    // on the next apply against the fresh snapshot).
                    .unwrap_or_else(|| m.repository_id.to_string());
                CurrentUpstreamMapping {
                    id: m.id,
                    repository_name,
                    path_prefix: m.path_prefix,
                    managed_by: m.managed_by,
                    managed_by_digest: m.managed_by_digest,
                }
            })
            .collect();

        // Load `oidc_issuers` + `service_accounts`
        // for the diff. No `managed_by` filtering: the underlying tables
        // have no such column (gitops-only aggregates).
        // The digest field is currently `None` for every row — the
        // tables deliberately omit a `managed_by_digest` column. The diff
        // treats `None` as "force update on next apply" which is the
        // correct conservative behaviour: re-applying re-stamps the row
        // and re-applies fall through to `unchanged` from then on.
        let oidc_issuer_entities = self.oidc_issuers.list().await?;
        let oidc_issuers_snapshot: Vec<CurrentOidcIssuer> = oidc_issuer_entities
            .into_iter()
            .map(|i| CurrentOidcIssuer {
                id: i.id,
                name: i.name,
                digest: None,
            })
            .collect();
        let sa_entities = self.service_accounts.list().await?;
        // `ServiceAccount.name → backing-user UUID (stringified)` for
        // every SA whose aggregate (and therefore backing `users` row)
        // already exists. The diff layer uses it to resolve a
        // `serviceAccount`-subject grant's identity to the persisted
        // `User(backing_user_id)` row, so a re-apply is `unchanged`
        // rather than churning create+delete. A brand-new SA is absent
        // from this map (it is created later in the same apply), so its
        // grant falls back to the name-keyed transient identity →
        // `create` on the first apply. See ADR 0037.
        let sa_backing_user_ids_by_name: HashMap<String, String> = sa_entities
            .iter()
            .map(|s| (s.name.clone(), s.backing_user_id.to_string()))
            .collect();
        let service_accounts_snapshot: Vec<CurrentServiceAccount> = sa_entities
            .into_iter()
            .map(|s| CurrentServiceAccount {
                id: s.id,
                name: s.name,
                digest: None,
            })
            .collect();

        Ok(CurrentSnapshot {
            repositories,
            claim_mappings,
            permission_grants,
            curation_rules,
            upstream_mappings,
            oidc_issuers: oidc_issuers_snapshot,
            service_accounts: service_accounts_snapshot,
            sa_backing_user_ids_by_name,
        })
    }
}

fn emit_unchanged(kind: &'static str, count: usize, report: &mut ApplyReport) {
    for _ in 0..count {
        emit_gitops_object(kind, GitopsObjectResult::Unchanged);
    }
    report.unchanged += count;
}

/// Subject-dependent diff/upsert identity for a
/// `PermissionGrant`. `Claims` grants key off
/// `(sorted required_claims, repository_id, permission)`; `User`
/// grants key off `(user_id, repository_id, permission)`. The two
/// arms are disjoint by construction. `Permission` is `Copy + Eq +
/// Hash`; `Vec<String>` / `Uuid` / `Option<Uuid>` are all `Hash +
/// Eq`, so the tuple is a valid `HashMap` key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum GrantIdentityKey {
    Claims(Vec<String>, Option<Uuid>, Permission),
    User(Uuid, Option<Uuid>, Permission),
}

/// Compute the subject-dependent identity key for a grant. The
/// `Claims` arm sorts the claim set so a re-ordered YAML declaration
/// produces the same key (apply replay = no-op), matching
/// `hort_config::permission_grant::PermissionGrantSpec::diff_identity`
/// and the snapshot builder's sort in `build_snapshot`.
pub(super) fn grant_identity_key(
    subject: &GrantSubject,
    repository_id: Option<Uuid>,
    permission: Permission,
) -> GrantIdentityKey {
    match subject {
        GrantSubject::Claims(required) => {
            let mut sorted = required.clone();
            sorted.sort();
            GrantIdentityKey::Claims(sorted, repository_id, permission)
        }
        GrantSubject::User(uid) => GrantIdentityKey::User(*uid, repository_id, permission),
    }
}

/// Build a `RepositoryUpstreamMapping`
/// from a YAML `UpstreamMappingSpec` envelope plus the resolved
/// `repository_id` (apply pipeline supplies the latter from
/// `repo_id_by_name`).
///
fn create_command_from_spec(
    env: &Envelope<ScanPolicySpec>,
    repo_id_by_name: &HashMap<String, Uuid>,
) -> CreatePolicyCommand {
    let scope = resolve_scope(&env.spec.scope, repo_id_by_name);
    CreatePolicyCommand {
        name: env.metadata.name.clone(),
        scope,
        severity_threshold: SeverityThreshold::from_str(&env.spec.severity_threshold)
            .expect("INVARIANT: severity_threshold validated by hort-config"),
        quarantine_duration_secs: humantime_secs(&env.spec.quarantine_duration),
        require_approval: env.spec.require_approval,
        // The provenance trio (ADR 0027).
        // hort-config validated the wire shape (mode parses, each
        // identity passes the per-element constructor) before this site.
        provenance_mode: provenance_mode_from_spec(&env.spec.provenance_mode),
        provenance_backends: env.spec.provenance_backends.clone(),
        provenance_identities: provenance_identities_from_spec(&env.spec.provenance_identities),
        max_artifact_age_secs: env.spec.max_artifact_age.as_deref().map(humantime_secs),
        license_policy: env.spec.license_policy.clone(),
        // `scan_backends` flows from YAML to the
        // create command. Apply-time validation against the compiled-in
        // `crate::scanning::KNOWN_SCAN_BACKENDS` set happens upstream of this
        // helper, in `ApplyConfigUseCase::apply` (see the
        // `validate_scan_policy_backends` call site there); reaching
        // this code path implies every entry is a supported backend.
        scan_backends: env.spec.scan_backends.clone(),
        // `rescan_interval_hours` flows from YAML to
        // the create command. `validate_scan_policy` (hort-config) has
        // already enforced `>= 0` upstream of this helper.
        rescan_interval_hours: env.spec.rescan_interval_hours,
        // `negligible_action` flows from YAML to the create command.
        // hort-config validated the wire value (parses to one of
        // ignore/warn/block) before this site.
        negligible_action: negligible_action_from_spec(&env.spec.negligible_action),
        // `enforcement` flows from YAML to the create command.
        // hort-config validated the wire value (parses to reject/record)
        // before this site.
        enforcement: scan_enforcement_from_spec(&env.spec.enforcement),
    }
}

fn update_command_from_diff(
    policy_id: Uuid,
    env: &Envelope<ScanPolicySpec>,
    repo_id_by_name: &HashMap<String, Uuid>,
) -> UpdatePolicyCommand {
    // `PolicyUseCase::update_policy` does its own per-field same-value
    // skip — it's safe (and simpler) to set every field unconditionally
    // here and let the use case compute the actual change set. The
    // applier's diff is still the right layer for the pipeline-level
    // "did anything change?" decision because it lets us skip the
    // `update_policy` call entirely when the spec matches.
    let scope = resolve_scope(&env.spec.scope, repo_id_by_name);
    UpdatePolicyCommand {
        policy_id,
        name: FieldChange::Set(env.metadata.name.clone()),
        scope: FieldChange::Set(scope),
        severity_threshold: FieldChange::Set(
            SeverityThreshold::from_str(&env.spec.severity_threshold)
                .expect("INVARIANT: severity_threshold validated by hort-config"),
        ),
        quarantine_duration_secs: FieldChange::Set(humantime_secs(&env.spec.quarantine_duration)),
        require_approval: FieldChange::Set(env.spec.require_approval),
        // The provenance trio (ADR 0027).
        provenance_mode: FieldChange::Set(provenance_mode_from_spec(&env.spec.provenance_mode)),
        provenance_backends: FieldChange::Set(env.spec.provenance_backends.clone()),
        provenance_identities: FieldChange::Set(provenance_identities_from_spec(
            &env.spec.provenance_identities,
        )),
        max_artifact_age_secs: FieldChange::Set(
            env.spec.max_artifact_age.as_deref().map(humantime_secs),
        ),
        license_policy: FieldChange::Set(env.spec.license_policy.clone()),
        // Flow scan_backends through the update
        // command. `update_policy` does its own per-field same-value
        // skip so unconditionally setting it is safe.
        scan_backends: FieldChange::Set(env.spec.scan_backends.clone()),
        // Flow rescan_interval_hours through. Same
        // argument: per-field same-value skip in `update_policy`.
        rescan_interval_hours: FieldChange::Set(env.spec.rescan_interval_hours),
        // Flow negligible_action through. Same argument: per-field
        // same-value skip in `update_policy`.
        negligible_action: FieldChange::Set(negligible_action_from_spec(
            &env.spec.negligible_action,
        )),
        // Flow enforcement through. Same argument: per-field same-value
        // skip in `update_policy`.
        enforcement: FieldChange::Set(scan_enforcement_from_spec(&env.spec.enforcement)),
    }
}

/// Resolve a `ScanPolicy`'s operator-authored scope into the domain form.
///
/// Panics on a repository name absent from `repo_id_by_name`, and the
/// rule that makes that an invariant rather than an operator-reachable
/// crash is `push_scan_policy_scope_reference_errors` in
/// `hort-config`'s `desired` module: it rejects a
/// `scope: { repository: <name> }` naming a repository no envelope
/// declares, with a `DanglingReference`, in `DesiredState::validate` —
/// which both the boot preflight and `hort-server validate-config` run
/// before the first write. The pipeline fills the map from the same
/// `DesiredState` before dispatching policy applies, so every name that
/// reaches here is in it. A softer fallback would mean that rule's
/// guarantee is no longer load-bearing, and the two resolution paths
/// would drift.
fn resolve_scope(scope: &ScopeSpec, repo_id_by_name: &HashMap<String, Uuid>) -> PolicyScope {
    match scope {
        ScopeSpec::Global => PolicyScope::Global,
        ScopeSpec::Repository(r) => {
            let id = *repo_id_by_name.get(&r.repository).unwrap_or_else(|| {
                panic!(
                    "INVARIANT: ScanPolicy references repository name '{}' that is not in \
                     repo_id_by_name — pipeline must populate the map from DesiredState before \
                     dispatching scan-policy applies",
                    r.repository
                )
            });
            PolicyScope::Repository(id)
        }
    }
}

/// Resolve a `RetentionPolicy`'s operator-authored scope into the
/// domain form, mirroring [`resolve_scope`].
///
/// Panics on a repository name absent from `repo_id_by_name`, for the
/// same reason `resolve_scope` does — with
/// `push_retention_policy_scope_reference_errors` as the rule that
/// carries the guarantee here, and the apply pipeline filling the map
/// from `DesiredState` before dispatching policy applies. A softer
/// fallback here would mean that rule's guarantee is no longer
/// load-bearing, and the two resolution paths would drift.
fn resolve_retention_scope(
    scope: &hort_config::retention_policy::RetentionScopeSpec,
    repo_id_by_name: &HashMap<String, Uuid>,
) -> hort_domain::retention::RetentionScope {
    scope.resolve(repo_id_by_name).unwrap_or_else(|missing| {
        panic!(
            "INVARIANT: RetentionPolicy references repository name '{missing}' that is not in \
             repo_id_by_name — pipeline must populate the map from DesiredState before \
             dispatching retention-policy applies"
        )
    })
}

fn humantime_secs(s: &str) -> i64 {
    let dur = humantime::parse_duration(s).expect("INVARIANT: humantime validated by hort-config");
    i64::try_from(dur.as_secs()).expect("INVARIANT: duration validated to fit in i64")
}

/// Produce the canonical *identifier* form of
/// a [`SecretRef`] for inclusion in a
/// [`RepositoryUpstreamMappingChanged`] audit event payload.
///
/// Shape: `"<source>:<location>"` — e.g. `"env_var:DOCKERHUB_TOKEN"`,
/// `"file:/run/secrets/ghcr-token"`. The `<source>` discriminant uses
/// the same lower-snake-case wire form as
/// `SecretRef::source` serialises (`env_var` / `file`), so the audit
/// trail rolls up cleanly across mappings that share a backend.
///
/// **Identifier only — never the value.** The event payload carries
/// the operator-disclosed reference, never the resolved bytes the
/// `SecretPort` would return on `resolve()`. The literal string is
/// recorded as-is for forensic correlation against the secret-store
/// audit log (the identifier, not the value, is recorded).
///
/// See `crates/hort-domain/src/events/authorization_events.rs` →
/// `upstream_mapping_changed_payload_records_identifier_not_value`
/// for the load-bearing security gate that pins this contract.
fn secret_ref_name(secret_ref: &SecretRef) -> String {
    use hort_domain::ports::secret_port::SecretSource;
    let source = match secret_ref.source {
        SecretSource::EnvVar => "env_var",
        SecretSource::File => "file",
    };
    format!("{source}:{}", secret_ref.location)
}

fn gitops_actor_for_kind(kind: Kind) -> Actor {
    Actor::GitOps(GitOpsActor {
        source_file: format!("<gitops apply: kind={}>", kind.label()),
        spec_digest: [0u8; 32],
        applied_at: Utc::now(),
    })
}

/// Translate `DomainError::Conflict` from an event-store append into
/// the apply-pipeline-level `ConcurrentModification` error and emit a
/// boundary-level `tracing::warn!`. The per-stream `warn!` already
/// fired inside `PolicyUseCase`; this one is the apply-pipeline
/// observability event.
fn map_concurrent_modification(err: AppError) -> AppError {
    match err {
        AppError::Domain(DomainError::Conflict(msg)) => {
            tracing::warn!(
                conflict_message = %msg,
                "strict-atomic abort: concurrent policy modification",
            );
            AppError::ConcurrentModification(msg)
        }
        other => other,
    }
}

mod claim_mappings;
mod curation;
mod exclusions;
mod oidc_issuers;
mod permission_grants;
mod repositories;
mod retention;
mod scan_policies;
mod service_accounts;
mod upstream_mappings;
mod virtual_members;

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only — the provenance mappers live in `crate::provenance`;
    // these types are referenced only by the fixtures.
    use hort_config::scan_policy::SignerIdentitySpec;
    use hort_domain::entities::scan_policy::{NegligibleAction, ProvenanceMode, ScanEnforcement};

    use crate::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use crate::use_cases::test_support::{MockCall, MockRepositoryRepository};
    use hort_config::envelope::{ApiVersion, Metadata};
    use hort_config::repository::StorageSpec;

    /// Default `RepositoryAccessUseCase` for tests
    /// that instantiate `PolicyUseCase` but do not exercise the
    /// `hort_curation_decisions_total{repository}` label resolution
    /// directly. Disabled RBAC + empty store; lookups collapse to the
    /// `unknown` sentinel (the helper handles the
    /// `METRICS_INCLUDE_REPOSITORY_LABEL=false` collapse via its own
    /// constructor flag — set to `true` here so the test surface
    /// matches the production composition's default).
    pub(in crate::use_cases::apply_config_use_case) fn default_repository_access_for_policy(
    ) -> Arc<RepositoryAccessUseCase> {
        Arc::new(RepositoryAccessUseCase::new(
            Arc::new(MockRepositoryRepository::new()),
            RbacAccess::Disabled,
            true,
        ))
    }
    use hort_domain::entities::rbac::{ClaimMapping, GrantSubject, PermissionGrant};
    use hort_domain::entities::repository::IndexMode;
    use hort_domain::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection};
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::claim_mapping_repository::ClaimMappingRepository;
    use hort_domain::ports::event_store::{
        AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
    };
    use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
    use hort_domain::ports::BoxFuture;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // --- mock ClaimMappingRepository ---------------------------------------
    //
    // `reconcile_managed_rows(&[items])` is the whole-partition
    // primitive: in one call the adapter deletes every
    // gitops-managed row whose `(idp_group, claim)` identity is absent
    // from `items` and upserts every row that is present, keyed on that
    // identity (not the surrogate id) so an unchanged replay is a no-op.
    // The mock mirrors that exactly so the production diff
    // (`apply_claim_mappings`'s `prior_by_identity`) behaves correctly
    // across re-applies.

    #[derive(Default)]
    pub(in crate::use_cases::apply_config_use_case) struct MockClaimMappingRepo {
        /// gitops-managed rows keyed by the `(idp_group, claim)` natural
        /// identity — the same key the reconcile upserts on.
        pub(in crate::use_cases::apply_config_use_case) managed:
            Mutex<HashMap<(String, String), ClaimMapping>>,
        /// Every reconcile invocation's complete slice (test
        /// introspection: call count + last authoritative set).
        reconcile_calls: Mutex<Vec<Vec<ClaimMapping>>>,
    }

    impl MockClaimMappingRepo {
        pub(in crate::use_cases::apply_config_use_case) fn new() -> Self {
            Self::default()
        }
        /// Number of reconcile invocations (the apply pipeline commits
        /// once per `apply_claim_mappings`, unconditionally).
        pub(in crate::use_cases::apply_config_use_case) fn reconcile_call_count(&self) -> usize {
            self.reconcile_calls.lock().unwrap().len()
        }
        /// Current managed-row count after the last reconcile.
        pub(in crate::use_cases::apply_config_use_case) fn managed_count(&self) -> usize {
            self.managed.lock().unwrap().len()
        }
    }

    impl ClaimMappingRepository for MockClaimMappingRepo {
        fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<ClaimMapping>>> {
            let v: Vec<ClaimMapping> = self.managed.lock().unwrap().values().cloned().collect();
            Box::pin(async move { Ok(v) })
        }
        fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<ClaimMapping>>> {
            let v: Vec<ClaimMapping> = self.managed.lock().unwrap().values().cloned().collect();
            Box::pin(async move { Ok(v) })
        }
    }

    impl MockClaimMappingRepo {
        /// The whole-partition reconcile, as an **inherent** method:
        /// replace the entire managed set with `items`, keyed on
        /// `(idp_group, claim)`.
        ///
        /// [`ClaimMappingRepository`] carries no write method any more
        /// — the write is
        /// `AuthorityLifecyclePort::commit_claim_mappings`, which
        /// commits the reconcile with its audit batch in one
        /// transaction. [`MockAuthorityLifecycle`] writes through here,
        /// exactly as the Postgres adapter writes through
        /// `claim_mapping_repo::reconcile_managed_claim_mappings_in_tx`:
        /// the body stays, the trait wrapper is what went away.
        fn reconcile_managed_rows(&self, items: &[ClaimMapping]) {
            self.reconcile_calls.lock().unwrap().push(items.to_vec());
            let mut managed = self.managed.lock().unwrap();
            *managed = items
                .iter()
                .map(|m| ((m.idp_group.clone(), m.claim.clone()), m.clone()))
                .collect();
        }
    }

    // --- mock RoleRepository -----------------------------------------------

    // --- mock PermissionGrantRepository ------------------------------------
    //
    // There is no `RoleRepository`; grants persist on their own port.
    // `reconcile_managed_rows(&[items])` is the whole-partition
    // primitive: delete every gitops-managed grant whose subject-
    // dependent identity (`grant_identity_key` — `(sorted required_claims,
    // repository_id, permission)` for `Claims`; `(user_id, repository_id,
    // permission)` for `User`) is absent from `items`, upsert every row
    // present, keyed on that identity so an unchanged replay is a no-op.
    // The mock replicates that so the production diff
    // (`apply_permission_grants`'s `prior_by_identity`) is exercised
    // faithfully across re-applies.

    #[derive(Default)]
    pub(in crate::use_cases::apply_config_use_case) struct MockPermissionGrantRepo {
        /// gitops-managed grants keyed by the subject-dependent identity
        /// (`GrantIdentityKey`) — the same key the reconcile upserts
        /// on. Keeps surrogate-id churn out of the test assertions.
        managed: Mutex<HashMap<GrantIdentityKey, PermissionGrant>>,
        /// Every reconcile invocation's complete authoritative slice
        /// (call count + last reconciled set introspection).
        reconcile_calls: Mutex<Vec<Vec<PermissionGrant>>>,
    }

    impl MockPermissionGrantRepo {
        pub(in crate::use_cases::apply_config_use_case) fn new() -> Self {
            Self::default()
        }
        /// Number of reconcile invocations. `apply_permission_grants`
        /// commits exactly once per apply, unconditionally — the
        /// consolidated reconcile that covers envelope + SA-owned grants.
        pub(in crate::use_cases::apply_config_use_case) fn reconcile_call_count(&self) -> usize {
            self.reconcile_calls.lock().unwrap().len()
        }
        /// Current managed-grant count after the last reconcile.
        pub(in crate::use_cases::apply_config_use_case) fn managed_count(&self) -> usize {
            self.managed.lock().unwrap().len()
        }
        /// Snapshot of the current managed grant set (post-reconcile).
        pub(in crate::use_cases::apply_config_use_case) fn managed_snapshot(
            &self,
        ) -> Vec<PermissionGrant> {
            self.managed.lock().unwrap().values().cloned().collect()
        }
    }

    impl PermissionGrantRepository for MockPermissionGrantRepo {
        fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
            let v: Vec<PermissionGrant> = self.managed.lock().unwrap().values().cloned().collect();
            Box::pin(async move { Ok(v) })
        }
        fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<PermissionGrant>>> {
            let v: Vec<PermissionGrant> = self.managed.lock().unwrap().values().cloned().collect();
            Box::pin(async move { Ok(v) })
        }
    }

    impl MockPermissionGrantRepo {
        /// The whole-partition reconcile, as an **inherent** method:
        /// replace the entire managed set with `items`, keyed on the
        /// subject-dependent identity. See
        /// [`MockClaimMappingRepo::reconcile_managed_rows`] for why
        /// this is not a trait method; the adapter's counterpart is
        /// `permission_grant_repo::reconcile_managed_grants_in_tx`.
        fn reconcile_managed_rows(&self, items: &[PermissionGrant]) {
            self.reconcile_calls.lock().unwrap().push(items.to_vec());
            let mut managed = self.managed.lock().unwrap();
            *managed = items
                .iter()
                .map(|g| {
                    (
                        grant_identity_key(&g.subject, g.repository_id, g.permission),
                        g.clone(),
                    )
                })
                .collect();
        }
    }

    // --- mock AuthorityLifecyclePort ---------------------------------------
    //
    // The five authority kinds no longer write their rows through the
    // row ports and then append; they hand rows + audit batches to
    // `AuthorityLifecyclePort` in one call — and the row ports no longer
    // carry a write method at all, so the mistake is a compile error.
    // This mock writes through the same row mocks and event-store mock
    // the harness already holds (via their inherent `*_row` /
    // `reconcile_managed_rows` methods), so every pre-existing assertion
    // on `h.claim_mappings` / `h.grant_repo` / `h.oidc_issuers` /
    // `h.upstream` / `h.service_accounts` / `h.events` keeps meaning
    // what it meant.
    //
    // The transaction is modelled by **outcome**: an armed failure
    // returns `Err` having written neither the rows nor the events —
    // which is what the Postgres adapter's rollback leaves behind. The
    // rollback itself is pinned against a real server in
    // `hort-adapters-postgres/tests/authority_audit_atomicity.rs`; what
    // these app-layer tests pin is that the apply branch has no path
    // that writes a row outside this one call.

    /// Which authority write a [`MockAuthorityLifecycle`] call or armed
    /// failure refers to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(in crate::use_cases::apply_config_use_case) enum AuthoritySite {
        PermissionGrants,
        ClaimMappings,
        OidcIssuers,
        UpstreamMappings,
        ServiceAccounts,
    }

    pub(in crate::use_cases::apply_config_use_case) struct MockAuthorityLifecycle {
        claim_mappings: Arc<MockClaimMappingRepo>,
        grants: Arc<MockPermissionGrantRepo>,
        oidc_issuers: Arc<crate::use_cases::test_support::MockOidcIssuerRepository>,
        upstream_mappings:
            Arc<crate::use_cases::test_support::MockRepositoryUpstreamMappingRepository>,
        service_accounts: Arc<crate::use_cases::test_support::MockServiceAccountRepository>,
        events: Arc<MockPolicyEventStore>,
        /// One-shot armed failures, keyed by site. Consumed on use.
        next_error: Mutex<HashMap<AuthoritySite, DomainError>>,
        /// `(site, batch_count)` per call, in call order — including
        /// calls that then failed.
        commits: Mutex<Vec<(AuthoritySite, usize)>>,
    }

    impl MockAuthorityLifecycle {
        pub(in crate::use_cases::apply_config_use_case) fn new(
            claim_mappings: Arc<MockClaimMappingRepo>,
            grants: Arc<MockPermissionGrantRepo>,
            oidc_issuers: Arc<crate::use_cases::test_support::MockOidcIssuerRepository>,
            upstream_mappings: Arc<
                crate::use_cases::test_support::MockRepositoryUpstreamMappingRepository,
            >,
            service_accounts: Arc<crate::use_cases::test_support::MockServiceAccountRepository>,
            events: Arc<MockPolicyEventStore>,
        ) -> Self {
            Self {
                claim_mappings,
                grants,
                oidc_issuers,
                upstream_mappings,
                service_accounts,
                events,
                next_error: Mutex::new(HashMap::new()),
                commits: Mutex::new(Vec::new()),
            }
        }

        /// Arm a one-shot failure for the next commit at `site`. The
        /// commit records the attempt and then writes nothing — the
        /// adapter's all-or-nothing outcome.
        pub(in crate::use_cases::apply_config_use_case) fn fail_next(
            &self,
            site: AuthoritySite,
            err: DomainError,
        ) {
            self.next_error.lock().unwrap().insert(site, err);
        }

        /// `(site, batch_count)` per commit call, in call order.
        pub(in crate::use_cases::apply_config_use_case) fn commits(
            &self,
        ) -> Vec<(AuthoritySite, usize)> {
            self.commits.lock().unwrap().clone()
        }

        /// Record the call and consume an armed failure. `Err` here is
        /// the rolled-back outcome: no row write, no append.
        fn enter(&self, site: AuthoritySite, batch_count: usize) -> DomainResult<()> {
            self.commits.lock().unwrap().push((site, batch_count));
            match self.next_error.lock().unwrap().remove(&site) {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        async fn append_all(&self, batches: Vec<AppendEvents>) -> DomainResult<()> {
            for batch in batches {
                self.events.append(batch).await?;
            }
            Ok(())
        }
    }

    impl AuthorityLifecyclePort for MockAuthorityLifecycle {
        fn commit_permission_grants<'a>(
            &'a self,
            desired: &'a [PermissionGrant],
            batches: Vec<AppendEvents>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async move {
                self.enter(AuthoritySite::PermissionGrants, batches.len())?;
                self.grants.reconcile_managed_rows(desired);
                self.append_all(batches).await
            })
        }

        fn commit_claim_mappings<'a>(
            &'a self,
            desired: &'a [ClaimMapping],
            batches: Vec<AppendEvents>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async move {
                self.enter(AuthoritySite::ClaimMappings, batches.len())?;
                self.claim_mappings.reconcile_managed_rows(desired);
                self.append_all(batches).await
            })
        }

        fn commit_oidc_issuers<'a>(
            &'a self,
            change: &'a OidcIssuerChange,
            batches: Vec<AppendEvents>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async move {
                self.enter(AuthoritySite::OidcIssuers, batches.len())?;
                for issuer in &change.upserts {
                    self.oidc_issuers.upsert_row(issuer);
                }
                for name in &change.deletes {
                    self.oidc_issuers.delete_row(name);
                }
                self.append_all(batches).await
            })
        }

        fn commit_upstream_mappings<'a>(
            &'a self,
            change: &'a UpstreamMappingCommit,
            batches: Vec<AppendEvents>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async move {
                self.enter(AuthoritySite::UpstreamMappings, batches.len())?;
                for mapping in &change.upserts {
                    self.upstream_mappings.write_managed_row(mapping)?;
                }
                for id in &change.deletes {
                    self.upstream_mappings.delete_managed_row(*id);
                }
                self.append_all(batches).await
            })
        }

        fn commit_service_accounts<'a>(
            &'a self,
            change: &'a ServiceAccountCommit,
            batches: Vec<AppendEvents>,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async move {
                self.enter(AuthoritySite::ServiceAccounts, batches.len())?;
                for sa in &change.upserts {
                    self.service_accounts.upsert_row(sa);
                }
                for name in &change.deletes {
                    self.service_accounts.delete_row(name);
                }
                self.append_all(batches).await
            })
        }
    }

    // --- mock CurationRuleRepository ---------------------------------------

    #[derive(Default)]
    pub(in crate::use_cases::apply_config_use_case) struct MockCurationRuleRepo {
        managed: Mutex<HashMap<Uuid, CurationRule>>,
        save_calls: Mutex<Vec<CurationRule>>,
        delete_calls: Mutex<Vec<String>>,
        set_junction_calls: Mutex<Vec<(Uuid, Vec<Uuid>)>>,
        /// Reverse-index `rule_id → [repository_id]` for
        /// `list_repos_for_rule`.
        by_rule: Mutex<HashMap<Uuid, Vec<Uuid>>>,
    }

    impl MockCurationRuleRepo {
        fn new() -> Self {
            Self::default()
        }
        pub(in crate::use_cases::apply_config_use_case) fn save_count(&self) -> usize {
            self.save_calls.lock().unwrap().len()
        }
        pub(in crate::use_cases::apply_config_use_case) fn delete_count(&self) -> usize {
            self.delete_calls.lock().unwrap().len()
        }
        pub(in crate::use_cases::apply_config_use_case) fn junction_calls(
            &self,
        ) -> Vec<(Uuid, Vec<Uuid>)> {
            self.set_junction_calls.lock().unwrap().clone()
        }
        /// Explicit reverse-index seed for
        /// retroactive-evaluation tests that need `list_repos_for_rule`
        /// to return a non-empty result before the apply runs.
        pub(in crate::use_cases::apply_config_use_case) fn link_rule_to_repo(
            &self,
            rule_id: Uuid,
            repository_id: Uuid,
        ) {
            let mut by_rule = self.by_rule.lock().unwrap();
            let entry = by_rule.entry(rule_id).or_default();
            if !entry.contains(&repository_id) {
                entry.push(repository_id);
            }
        }
    }

    impl CurationRuleRepository for MockCurationRuleRepo {
        fn find_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<CurationRule>>> {
            let n = name.to_string();
            let r = self
                .managed
                .lock()
                .unwrap()
                .values()
                .find(|r| r.name == n)
                .cloned();
            Box::pin(async move { Ok(r) })
        }
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Option<CurationRule>>> {
            let r = self.managed.lock().unwrap().get(&id).cloned();
            Box::pin(async move { Ok(r) })
        }
        fn list_for_repo(
            &self,
            repository_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<CurationRule>>> {
            // Resolve via the reverse-index `by_rule` so the mock
            // matches Postgres-adapter semantics (junction join). Tests
            // that seed via `link_rule_to_repo` see the linked rules
            // here; tests that don't link see empty.
            let rules: Vec<CurationRule> = {
                let by_rule = self.by_rule.lock().unwrap();
                let managed = self.managed.lock().unwrap();
                by_rule
                    .iter()
                    .filter_map(|(rule_id, repos)| {
                        if repos.contains(&repository_id) {
                            managed.get(rule_id).cloned()
                        } else {
                            None
                        }
                    })
                    .collect()
            };
            Box::pin(async move { Ok(rules) })
        }
        fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<CurationRule>>> {
            let v = self.managed.lock().unwrap().values().cloned().collect();
            Box::pin(async move { Ok(v) })
        }
        fn save_managed(&self, rule: &CurationRule) -> BoxFuture<'_, DomainResult<()>> {
            self.save_calls.lock().unwrap().push(rule.clone());
            self.managed.lock().unwrap().insert(rule.id, rule.clone());
            Box::pin(async { Ok(()) })
        }
        fn delete_managed(&self, name: &str) -> BoxFuture<'_, DomainResult<()>> {
            self.delete_calls.lock().unwrap().push(name.to_string());
            self.managed.lock().unwrap().retain(|_, r| r.name != name);
            Box::pin(async { Ok(()) })
        }
        fn set_curation_rules_for_repository(
            &self,
            repository_id: Uuid,
            rule_ids: &[Uuid],
        ) -> BoxFuture<'_, DomainResult<()>> {
            self.set_junction_calls
                .lock()
                .unwrap()
                .push((repository_id, rule_ids.to_vec()));
            // Update the reverse-index in lockstep — the Postgres adapter
            // truncates per-repo edges via `set_curation_rules_for_repository`
            // and re-inserts; the mock follows the same semantics so
            // `list_repos_for_rule` stays consistent across calls.
            {
                let mut by_rule = self.by_rule.lock().unwrap();
                // Strip every existing (rule, repo) edge for this repo.
                for repos in by_rule.values_mut() {
                    repos.retain(|r| *r != repository_id);
                }
                // Insert the new edges.
                for rid in rule_ids {
                    let entry = by_rule.entry(*rid).or_default();
                    if !entry.contains(&repository_id) {
                        entry.push(repository_id);
                    }
                }
            }
            Box::pin(async { Ok(()) })
        }

        fn list_repos_for_rule(&self, rule_id: Uuid) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
            let v = self
                .by_rule
                .lock()
                .unwrap()
                .get(&rule_id)
                .cloned()
                .unwrap_or_default();
            Box::pin(async move { Ok(v) })
        }
    }

    // --- mock PolicyProjectionRepository -----------------------------------

    #[derive(Default)]
    pub(in crate::use_cases::apply_config_use_case) struct MockPolicyProjections {
        by_id: Mutex<HashMap<Uuid, ScanPolicyProjection>>,
        by_name: Mutex<HashMap<String, ScanPolicyProjection>>,
        exclusions: Mutex<HashMap<Uuid, Vec<ExclusionProjection>>>,
    }

    impl MockPolicyProjections {
        pub(in crate::use_cases::apply_config_use_case) fn new() -> Self {
            Self::default()
        }
        pub(in crate::use_cases::apply_config_use_case) fn insert_active(
            &self,
            p: ScanPolicyProjection,
        ) {
            self.by_id.lock().unwrap().insert(p.policy_id, p.clone());
            self.by_name.lock().unwrap().insert(p.name.clone(), p);
        }
        pub(in crate::use_cases::apply_config_use_case) fn insert_exclusion(
            &self,
            e: ExclusionProjection,
        ) {
            self.exclusions
                .lock()
                .unwrap()
                .entry(e.policy_id)
                .or_default()
                .push(e);
        }
    }

    impl PolicyProjectionRepository for MockPolicyProjections {
        fn find_by_id(
            &self,
            id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
            let r = self.by_id.lock().unwrap().get(&id).cloned();
            Box::pin(async move { Ok(r) })
        }
        fn find_by_name(
            &self,
            name: &str,
        ) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
            let r = self
                .by_name
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .filter(|p| !p.archived);
            Box::pin(async move { Ok(r) })
        }
        fn find_by_name_including_archived(
            &self,
            name: &str,
        ) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
            let r = self.by_name.lock().unwrap().get(name).cloned();
            Box::pin(async move { Ok(r) })
        }
        fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<ScanPolicyProjection>>> {
            let v: Vec<ScanPolicyProjection> = self
                .by_id
                .lock()
                .unwrap()
                .values()
                .filter(|p| !p.archived)
                .cloned()
                .collect();
            Box::pin(async move { Ok(v) })
        }
        fn list_exclusions_for_policy(
            &self,
            policy_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<ExclusionProjection>>> {
            let v = self
                .exclusions
                .lock()
                .unwrap()
                .get(&policy_id)
                .cloned()
                .unwrap_or_default();
            Box::pin(async move { Ok(v) })
        }
        fn upsert(&self, projection: &ScanPolicyProjection) -> BoxFuture<'_, DomainResult<()>> {
            self.by_id
                .lock()
                .unwrap()
                .insert(projection.policy_id, projection.clone());
            self.by_name
                .lock()
                .unwrap()
                .insert(projection.name.clone(), projection.clone());
            Box::pin(async { Ok(()) })
        }
        fn upsert_exclusion(
            &self,
            exclusion: &ExclusionProjection,
        ) -> BoxFuture<'_, DomainResult<()>> {
            self.exclusions
                .lock()
                .unwrap()
                .entry(exclusion.policy_id)
                .or_default()
                .push(exclusion.clone());
            Box::pin(async { Ok(()) })
        }
        fn delete_exclusion(&self, exclusion_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            for list in self.exclusions.lock().unwrap().values_mut() {
                list.retain(|e| e.exclusion_id != exclusion_id);
            }
            Box::pin(async { Ok(()) })
        }
    }

    // --- mock EventStore (controllable for conflict-injection) -------------

    enum AppendOutcome {
        Ok,
        Conflict,
    }

    pub(in crate::use_cases::apply_config_use_case) struct MockPolicyEventStore {
        appended: Mutex<Vec<AppendEvents>>,
        next_outcomes: Mutex<Vec<AppendOutcome>>,
    }

    impl MockPolicyEventStore {
        pub(in crate::use_cases::apply_config_use_case) fn new() -> Self {
            Self {
                appended: Mutex::new(Vec::new()),
                next_outcomes: Mutex::new(Vec::new()),
            }
        }
        pub(in crate::use_cases::apply_config_use_case) fn appended(&self) -> Vec<AppendEvents> {
            self.appended.lock().unwrap().clone()
        }
        pub(in crate::use_cases::apply_config_use_case) fn schedule_conflict_on_next_append(&self) {
            self.next_outcomes
                .lock()
                .unwrap()
                .push(AppendOutcome::Conflict);
        }
    }

    impl EventStore for MockPolicyEventStore {
        fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            let outcome = self
                .next_outcomes
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(AppendOutcome::Ok);
            let count = batch.events.len() as u64;
            self.appended.lock().unwrap().push(batch);
            Box::pin(async move {
                match outcome {
                    AppendOutcome::Ok => Ok(AppendResult {
                        stream_position: count.saturating_sub(1),
                        global_positions: (0..count).collect(),
                    }),
                    AppendOutcome::Conflict => Err(DomainError::Conflict(
                        "stale expected_version (mock injection)".into(),
                    )),
                }
            })
        }
        fn read_stream(
            &self,
            stream_id: &StreamId,
            from: ReadFrom,
            max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
            // Replay from the captured `appended` Vec so the
            // audit-completeness regression test
            // can read the authorization stream back through the
            // `EventStore::read_stream` contract (rather than peeking
            // at the mock's internals). Honors `from` (Start vs
            // After(N)) and `max_count`.
            use hort_domain::events::PersistedEvent;
            let target = stream_id.clone();
            let appended = self.appended.lock().unwrap().clone();
            let mut events: Vec<PersistedEvent> = Vec::new();
            let mut stream_position: u64 = 0;
            let mut global_position: u64 = 0;
            for batch in &appended {
                if batch.stream_id != target {
                    // Bump global_position for the events in other
                    // streams so the global ordering still
                    // approximates an append-only log; the assertion
                    // sites rely only on stream_position so the
                    // approximation is fine.
                    global_position += batch.events.len() as u64;
                    continue;
                }
                for to_append in &batch.events {
                    let pos = stream_position;
                    stream_position += 1;
                    let gpos = global_position;
                    global_position += 1;
                    let include = match from {
                        ReadFrom::Start => true,
                        ReadFrom::After(after) => pos > after,
                    };
                    if !include {
                        continue;
                    }
                    if events.len() as u64 >= max_count {
                        break;
                    }
                    events.push(PersistedEvent {
                        event_id: to_append.event_id,
                        stream_id: target.clone(),
                        stream_position: pos,
                        global_position: gpos,
                        event: to_append.event.clone(),
                        correlation_id: batch.correlation_id,
                        causation_id: batch.causation_id,
                        actor: batch.actor.clone(),
                        event_version: 1,
                        stored_at: Utc::now(),
                    });
                }
            }
            Box::pin(async move { Ok(events) })
        }
        fn read_category(
            &self,
            _category: StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::events::PersistedEvent>>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        // Retention stubs: apply-config mock; retention paths are
        // unreachable from policy-driven apply, panic on call.
        fn delete_stream(
            &self,
            _stream_id: StreamId,
            _authority: hort_domain::ports::event_store::SealAuthority,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
            Box::pin(async { unimplemented!("retention path unused by apply-config tests") })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
            _authority: hort_domain::ports::event_store::SealAuthority,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::event_store::SealOutcome>> {
            Box::pin(async { unimplemented!("retention path unused by apply-config tests") })
        }
    }

    // --- fixtures ----------------------------------------------------------

    pub(in crate::use_cases::apply_config_use_case) fn repo_env(
        name: &str,
        repo_type: &str,
    ) -> Envelope<RepositorySpec> {
        let spec = RepositorySpec {
            name: name.into(),
            description: None,
            format: "npm".into(),
            repo_type: repo_type.into(),
            storage: Some(StorageSpec {
                backend: "filesystem".into(),
                path: format!("/data/{name}"),
            }),
            proxy: if repo_type == "proxy" {
                Some(hort_config::repository::ProxySpec {
                    upstream_url: "https://example.com".into(),
                    index_upstream_url: None,
                })
            } else {
                None
            },
            virtual_members: None,
            is_public: true,
            download_audit_enabled: false,
            index_mode: IndexMode::default(),
            prefetch_policy: hort_domain::entities::repository::PrefetchPolicy::default(),
            quota_bytes: None,
            replication_priority: "immediate".into(),
            promotion: None,
            curation_rules: None,
        };
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ArtifactRepository,
            metadata: Metadata { name: name.into() },
            spec,
        }
    }

    /// `ClaimMapping` envelope fixture.
    /// `idp_group` is the external IdP
    /// group-claim value; `claim` is the registry claim name it
    /// resolves to.
    ///
    /// The `_name` arg is accepted for call-site readability/parity
    /// with the old `gm_env` signature but is intentionally NOT used as
    /// the envelope `metadata.name`: the shipped `diff_claim_mappings`
    /// keys the diff identity off `CurrentClaimMapping.name`, which
    /// `build_snapshot` derives as `claim_mapping_identity_name(
    /// idp_group, claim)` (the port persists only `idp_group`+`claim`,
    /// not a freeform name — there is no name column on
    /// `claim_mappings`). For the create/unchanged/update report
    /// counters to reconcile across re-applies the envelope name MUST
    /// equal that identity form (consistent with `apply_claim_mappings`
    /// keying its reconcile on the `(idp_group, claim)` pair).
    pub(in crate::use_cases::apply_config_use_case) fn cm_env(
        _name: &str,
        idp_group: &str,
        claim: &str,
    ) -> Envelope<ClaimMappingSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ClaimMapping,
            metadata: Metadata {
                // Mirror `claim_mapping_identity_name` (module-private)
                // — `"{idp_group}\u{1f}{claim}"`.
                name: format!("{idp_group}\u{1f}{claim}"),
            },
            spec: ClaimMappingSpec {
                idp_group: idp_group.into(),
                claim: claim.into(),
            },
        }
    }

    /// `PermissionGrant` envelope with a **claims** subject
    /// (`GrantSubjectSpec::Claims`). `required` is the claim set the
    /// caller must wholly possess.
    pub(in crate::use_cases::apply_config_use_case) fn grant_env(
        name: &str,
        required: &[&str],
        permission: &str,
        repo: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::PermissionGrant,
            metadata: Metadata { name: name.into() },
            spec: PermissionGrantSpec {
                subject: GrantSubjectSpec::Claims {
                    required: required.iter().map(|s| (*s).to_string()).collect(),
                },
                permission: permission.into(),
                repository: repo.map(Into::into),
            },
        }
    }

    /// `PermissionGrant` envelope with a **user** subject
    /// (`GrantSubjectSpec::User`) — the direct-user / service-account
    /// binding shape.
    fn user_grant_env(
        name: &str,
        user_id: Uuid,
        permission: &str,
        repo: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::PermissionGrant,
            metadata: Metadata { name: name.into() },
            spec: PermissionGrantSpec {
                subject: GrantSubjectSpec::User {
                    user_id: user_id.to_string(),
                },
                permission: permission.into(),
                repository: repo.map(Into::into),
            },
        }
    }

    /// `PermissionGrant` envelope with a **serviceAccount** subject
    /// (`GrantSubjectSpec::ServiceAccount`) — the gitops-spec sugar the
    /// apply pipeline resolves to `GrantSubject::User(backing_user_id)`
    /// (ADR 0037 / spec §9).
    pub(in crate::use_cases::apply_config_use_case) fn sa_grant_env(
        name: &str,
        sa_name: &str,
        permission: &str,
        repo: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::PermissionGrant,
            metadata: Metadata { name: name.into() },
            spec: PermissionGrantSpec {
                subject: GrantSubjectSpec::ServiceAccount {
                    name: sa_name.into(),
                },
                permission: permission.into(),
                repository: repo.map(Into::into),
            },
        }
    }

    pub(in crate::use_cases::apply_config_use_case) fn rule_env(
        name: &str,
        action: &str,
        pattern: &str,
        reason: &str,
    ) -> Envelope<hort_config::curation_rule::CurationRuleSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::CurationRule,
            metadata: Metadata { name: name.into() },
            spec: hort_config::curation_rule::CurationRuleSpec {
                format: "any".into(),
                pattern: pattern.into(),
                action: action.into(),
                reason: reason.into(),
            },
        }
    }

    /// A `ScanPolicy` envelope that applies cleanly.
    ///
    /// `license_policy` is `Null` and `max_artifact_age` is `None` —
    /// both inert defaults — and both must stay that way for every
    /// fixture that is expected to apply: a declared `licensePolicy` is
    /// an apply-time rejection because the scan path evaluates it
    /// against an empty licence list, and a declared `maxArtifactAge` is
    /// one because the age evaluator has no caller. A test that wants
    /// either rejection sets the field itself.
    pub(in crate::use_cases::apply_config_use_case) fn scan_policy_env(
        name: &str,
    ) -> Envelope<ScanPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ScanPolicy,
            metadata: Metadata { name: name.into() },
            spec: ScanPolicySpec {
                scope: ScopeSpec::Global,
                severity_threshold: "high".into(),
                quarantine_duration: "24h".into(),
                require_approval: true,
                provenance_mode: "verify_if_present".into(),
                provenance_backends: vec!["cosign".to_string()],
                provenance_identities: Vec::new(),
                max_artifact_age: None,
                license_policy: serde_json::Value::Null,
                scan_backends: vec!["trivy".to_string()],
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
                enforcement: "reject".into(),
            },
        }
    }

    pub(in crate::use_cases::apply_config_use_case) fn exclusion_env(
        name: &str,
        policy: &str,
        cve: &str,
    ) -> Envelope<ExclusionSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::Exclusion,
            metadata: Metadata { name: name.into() },
            spec: ExclusionSpec {
                policy: policy.into(),
                cve_id: cve.into(),
                package_pattern: None,
                scope: ScopeSpec::Global,
                reason: "operator rationale".into(),
                expires_at: None,
            },
        }
    }

    pub(in crate::use_cases::apply_config_use_case) struct Harness {
        pub(in crate::use_cases::apply_config_use_case) uc: ApplyConfigUseCase,
        pub(in crate::use_cases::apply_config_use_case) repos: Arc<MockRepositoryRepository>,
        pub(in crate::use_cases::apply_config_use_case) claim_mappings: Arc<MockClaimMappingRepo>,
        pub(in crate::use_cases::apply_config_use_case) grant_repo: Arc<MockPermissionGrantRepo>,
        pub(in crate::use_cases::apply_config_use_case) rule_repo: Arc<MockCurationRuleRepo>,
        pub(in crate::use_cases::apply_config_use_case) proj: Arc<MockPolicyProjections>,
        pub(in crate::use_cases::apply_config_use_case) events: Arc<MockPolicyEventStore>,
        pub(in crate::use_cases::apply_config_use_case) artifacts:
            Arc<crate::use_cases::test_support::MockArtifactRepository>,
        pub(in crate::use_cases::apply_config_use_case) lifecycle:
            Arc<crate::use_cases::test_support::MockArtifactLifecycle>,
        // Used by the 14b-14 upstream-mapping happy-path test; the
        // earlier 14b-9 tests don't read it.
        #[allow(dead_code)]
        pub(in crate::use_cases::apply_config_use_case) upstream:
            Arc<crate::use_cases::test_support::MockRepositoryUpstreamMappingRepository>,
        // Refcount projection mock.
        // Read by the
        // `retroactive_curation_reject_sweeps_content_references` test;
        // every other test ignores it (the mock starts empty and the
        // tests don't seed rows).
        #[allow(dead_code)]
        pub(in crate::use_cases::apply_config_use_case) content_refs:
            Arc<crate::use_cases::test_support::MockContentReferenceIndex>,
        // OidcIssuer / ServiceAccount gitops surface mocks. Default empty;
        // SA tests seed via the `repos` mock + the harness's `users`
        // mock and let the apply pipeline write through.
        #[allow(dead_code)]
        pub(in crate::use_cases::apply_config_use_case) oidc_issuers:
            Arc<crate::use_cases::test_support::MockOidcIssuerRepository>,
        #[allow(dead_code)]
        pub(in crate::use_cases::apply_config_use_case) service_accounts:
            Arc<crate::use_cases::test_support::MockServiceAccountRepository>,
        #[allow(dead_code)]
        pub(in crate::use_cases::apply_config_use_case) users:
            Arc<crate::use_cases::test_support::MockUserRepository>,
        /// The atomic authority writer the three authority branches
        /// commit through. Tests arm a per-site failure on it to pin
        /// the fail-closed outcome.
        pub(in crate::use_cases::apply_config_use_case) authority: Arc<MockAuthorityLifecycle>,
    }

    /// Reconcile-mechanics harness. Pins a **permissive**
    /// `LintConfig` (the linter analogue of
    /// `UpstreamHostAllowlist::Disabled`) so the pre-existing
    /// grant-diff / idempotence tests keep testing reconcile, not the
    /// linter. The linter's own behaviour is covered by the
    /// `lint::permission_grants` unit tests and the secure-by-default
    /// apply-level tests, which use
    /// [`build_harness_with_lint_config`] with
    /// [`crate::lint::LintConfig::default`].
    pub(in crate::use_cases::apply_config_use_case) fn build_harness() -> Harness {
        build_harness_with_lint_config(crate::lint::LintConfig::permissive_for_tests())
    }

    /// Harness with an explicit `LintConfig`. The
    /// secure-by-default apply-level tests pass
    /// [`crate::lint::LintConfig::default`] here to prove a wildcard /
    /// single-claim grant fails the whole apply with **zero** operator
    /// config. Mirrors `build_harness_with_allowlist`'s shape.
    pub(in crate::use_cases::apply_config_use_case) fn build_harness_with_lint_config(
        lint: crate::lint::LintConfig,
    ) -> Harness {
        let repos = Arc::new(MockRepositoryRepository::new());
        let claim_mappings = Arc::new(MockClaimMappingRepo::new());
        let grant_repo = Arc::new(MockPermissionGrantRepo::new());
        let rule_repo = Arc::new(MockCurationRuleRepo::new());
        let proj = Arc::new(MockPolicyProjections::new());
        let events = Arc::new(MockPolicyEventStore::new());
        let artifacts = Arc::new(crate::use_cases::test_support::MockArtifactRepository::new());
        let lifecycle = Arc::new(crate::use_cases::test_support::MockArtifactLifecycle::new(
            artifacts.clone(),
        ));
        let upstream = Arc::new(
            crate::use_cases::test_support::MockRepositoryUpstreamMappingRepository::new(),
        );
        let content_refs =
            Arc::new(crate::use_cases::test_support::MockContentReferenceIndex::new());
        let policies = Arc::new(PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            proj.clone(),
            artifacts.clone(),
            lifecycle.clone(),
            Arc::new(crate::use_cases::test_support::MockStoragePort::new()),
            default_repository_access_for_policy(),
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new()),
            Arc::new(crate::use_cases::test_support::MockJobsRepository::default()),
        ));
        // OidcIssuer / ServiceAccount gitops surface mocks.
        let oidc_issuers =
            Arc::new(crate::use_cases::test_support::MockOidcIssuerRepository::new());
        let service_accounts =
            Arc::new(crate::use_cases::test_support::MockServiceAccountRepository::new());
        let users = Arc::new(crate::use_cases::test_support::MockUserRepository::new());
        // Atomic authority writer — writes through the row mocks above
        // so the pre-existing row assertions keep working.
        let authority = Arc::new(MockAuthorityLifecycle::new(
            claim_mappings.clone(),
            grant_repo.clone(),
            oidc_issuers.clone(),
            upstream.clone(),
            service_accounts.clone(),
            events.clone(),
        ));
        let uc = ApplyConfigUseCase::new(
            repos.clone(),
            claim_mappings.clone(),
            grant_repo.clone(),
            authority.clone(),
            rule_repo.clone(),
            proj.clone(),
            policies,
            artifacts.clone(),
            lifecycle.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            upstream.clone(),
            // Default test posture: allowlist disabled — preserves
            // the historical `Disabled` behaviour for every existing
            // test. Allowlist tests build a fresh
            // harness with `build_harness_with_allowlist`.
            UpstreamHostAllowlist::Disabled,
            content_refs.clone(),
            oidc_issuers.clone(),
            service_accounts.clone(),
            users.clone(),
            // Default test posture: "npm" is VersionDiscovery-capable so
            // the pre-existing (pre-row-6b) prefetch-trigger tests that
            // don't care about this rule keep passing unmodified. Tests
            // that DO care override via `with_version_discovery_capable_formats`.
            Arc::new(["npm".to_string()].into_iter().collect()),
            // No retention projection in this harness. Explicit,
            // not inherited: the slot is a required argument so a
            // composition that skips retention says so, and the
            // apply warns on every envelope it then drops.
            None,
        )
        // The caller supplies the `LintConfig`.
        // `build_harness` passes `permissive_for_tests()` (the
        // `UpstreamHostAllowlist::Disabled` analogue) so
        // reconcile-mechanics tests are not perturbed; the
        // secure-by-default apply-level tests pass
        // `LintConfig::default()` to prove zero-config rejection.
        .with_lint_config(lint);
        Harness {
            uc,
            repos,
            claim_mappings,
            grant_repo,
            rule_repo,
            proj,
            events,
            artifacts,
            lifecycle,
            upstream,
            content_refs,
            oidc_issuers,
            service_accounts,
            users,
            authority,
        }
    }

    /// Build a harness with a non-default
    /// upstream allowlist. The allowlist tests need to exercise the
    /// `Strict` and `Hosts(...)` arms; everything else continues to
    /// use [`build_harness`] (which pins `Disabled`).
    fn build_harness_with_allowlist(allowlist: UpstreamHostAllowlist) -> Harness {
        let repos = Arc::new(MockRepositoryRepository::new());
        let claim_mappings = Arc::new(MockClaimMappingRepo::new());
        let grant_repo = Arc::new(MockPermissionGrantRepo::new());
        let rule_repo = Arc::new(MockCurationRuleRepo::new());
        let proj = Arc::new(MockPolicyProjections::new());
        let events = Arc::new(MockPolicyEventStore::new());
        let artifacts = Arc::new(crate::use_cases::test_support::MockArtifactRepository::new());
        let lifecycle = Arc::new(crate::use_cases::test_support::MockArtifactLifecycle::new(
            artifacts.clone(),
        ));
        let upstream = Arc::new(
            crate::use_cases::test_support::MockRepositoryUpstreamMappingRepository::new(),
        );
        let content_refs =
            Arc::new(crate::use_cases::test_support::MockContentReferenceIndex::new());
        let policies = Arc::new(PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(events.clone()),
            proj.clone(),
            artifacts.clone(),
            lifecycle.clone(),
            Arc::new(crate::use_cases::test_support::MockStoragePort::new()),
            default_repository_access_for_policy(),
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new()),
            Arc::new(crate::use_cases::test_support::MockJobsRepository::default()),
        ));
        let oidc_issuers =
            Arc::new(crate::use_cases::test_support::MockOidcIssuerRepository::new());
        let service_accounts =
            Arc::new(crate::use_cases::test_support::MockServiceAccountRepository::new());
        let users = Arc::new(crate::use_cases::test_support::MockUserRepository::new());
        // Atomic authority writer — writes through the row mocks above
        // so the pre-existing row assertions keep working.
        let authority = Arc::new(MockAuthorityLifecycle::new(
            claim_mappings.clone(),
            grant_repo.clone(),
            oidc_issuers.clone(),
            upstream.clone(),
            service_accounts.clone(),
            events.clone(),
        ));
        let uc = ApplyConfigUseCase::new(
            repos.clone(),
            claim_mappings.clone(),
            grant_repo.clone(),
            authority.clone(),
            rule_repo.clone(),
            proj.clone(),
            policies,
            artifacts.clone(),
            lifecycle.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            upstream.clone(),
            allowlist,
            content_refs.clone(),
            oidc_issuers.clone(),
            service_accounts.clone(),
            users.clone(),
            // See `build_harness_with_lint_config` — same default posture.
            Arc::new(["npm".to_string()].into_iter().collect()),
            // No retention projection in this harness. Explicit,
            // not inherited: the slot is a required argument so a
            // composition that skips retention says so, and the
            // apply warns on every envelope it then drops.
            None,
        )
        // Permissive linter (see `build_harness`).
        .with_lint_config(crate::lint::LintConfig::permissive_for_tests());
        Harness {
            uc,
            repos,
            claim_mappings,
            grant_repo,
            rule_repo,
            proj,
            events,
            artifacts,
            lifecycle,
            upstream,
            content_refs,
            oidc_issuers,
            service_accounts,
            users,
            authority,
        }
    }

    // ===================================================================
    // Apply-config linter wiring (ADR 0015).
    // These tests assert the linter runs INSIDE
    // `apply_permission_grants` BEFORE the whole-partition
    // commit, with the secure-by-default reject
    // posture, under ZERO operator config. They use
    // `build_harness_with_lint_config(LintConfig::default())` — NOT
    // the permissive `build_harness` — so the default
    // `ApplyConfigUseCase::new` production posture is exercised.
    // ===================================================================

    /// **The canonical secure-by-default apply-level test (red-first).**
    /// A gitops bundle containing a single `wildcard-repo-non-admin`
    /// grant (Claims subject, `repository: None`, non-Admin
    /// permission) MUST fail the whole apply with
    /// `AppError::Domain(DomainError::Validation(_))` under **zero**
    /// operator config — proving the secure-by-default posture
    /// (blocking out of the box, not opt-in). No grant row and no
    /// `PermissionGrantApplied` event lands (strict-atomic abort before
    /// the commit).
    #[tokio::test]
    async fn secure_by_default_wildcard_grant_fails_apply_with_zero_config() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        // A multi-claim wildcard non-admin write grant — isolates the
        // wildcard-repo-non-admin rule (multi-claim so the
        // single-claim rule does not also fire).
        desired.permission_grants.push(grant_env(
            "ops-write-everywhere",
            &["developer", "ops"],
            "write",
            None,
        ));
        let err =
            h.uc.apply(desired, env_oidc())
                .await
                .expect_err("a wildcard-repo-non-admin grant must fail apply by default");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("linter") && msg.contains("wildcard-repo-non-admin"),
                    "validation error must name the rejecting linter rule, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        // Strict-atomic: the reconcile commit never ran, so no
        // gitops-managed grant row was written.
        assert_eq!(
            h.grant_repo.reconcile_call_count(),
            0,
            "linter reject must abort BEFORE the whole-partition commit"
        );
        assert_eq!(h.grant_repo.managed_count(), 0);
    }

    /// A non-allowlisted single-claim grant fails apply by default
    /// (`single-claim-grant` rejects, the allowlist is the per-claim
    /// opt-out).
    #[tokio::test]
    async fn secure_by_default_single_claim_grant_fails_apply() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public", "hosted"));
        // Single claim, repo-scoped (so ONLY the single-claim rule
        // fires, not the wildcard rule).
        desired.permission_grants.push(grant_env(
            "solo-claim-read",
            &["team-alpha"],
            "read",
            Some("npm-public"),
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(msg.contains("single-claim-grant"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        assert_eq!(h.grant_repo.reconcile_call_count(), 0);
    }

    /// An unjustified direct-`User` **Admin** grant fails apply by
    /// default (the highest-privilege claim-bypass shape).
    #[tokio::test]
    async fn secure_by_default_unjustified_user_admin_grant_fails_apply() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        // A bare operator-hand-declared `User` grant (not derived from
        // any declared ServiceAccount) — its uid is NOT in the linter's
        // SA-owned exemption set, so it is unjustified by provenance
        // (the v1 justification signal — see the linter doc's
        // design-doc-vs-as-built reconciliation).
        desired.permission_grants.push(user_grant_env(
            "break-glass-admin",
            Uuid::new_v4(),
            "admin",
            None,
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("direct-user-grant-without-justification"),
                    "got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        assert_eq!(h.grant_repo.reconcile_call_count(), 0);
    }

    /// A `claim_mappings` row resolving to the reserved
    /// `service_account` token-kind discriminator fails the apply by
    /// default (claim-name-collision — no downgrade knob).
    ///
    /// **Ordering, resolved.** The collision rule is one of the grant
    /// linter's, and the linter used to run only inside
    /// `apply_permission_grants` — which the pipeline reaches *after*
    /// `apply_claim_mappings`' whole-partition commit. The apply
    /// failed either way, but the claim-mapping partition had already been
    /// reconciled when it did: a refused mapping left behind as a
    /// committed reconcile of the partition it belongs to. The linter's
    /// rejection is now consumed in the pre-write pass
    /// (`PRE_WRITE_REJECT_ROWS`), so this rule is strict-atomic like the
    /// three grant rules — asserted below on the claim-mapping partition
    /// itself, not only on the grant one.
    #[tokio::test]
    async fn secure_by_default_reserved_claim_mapping_fails_apply() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("svc", "sa-group", "service_account"));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(msg.contains("claim-name-collision"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        // The whole apply failed (the load-bearing property), and nothing
        // was written: neither the grant partition nor — the part that
        // changed — the Stage-1 claim-mapping partition.
        assert_eq!(h.grant_repo.reconcile_call_count(), 0);
        assert_eq!(
            h.claim_mappings.reconcile_call_count(),
            0,
            "the reject is now pre-write, so the Stage-1 claim-mapping \
             reconcile must not have run"
        );
        assert_eq!(h.claim_mappings.managed_count(), 0);
    }

    /// An operator downgrade (explicit, audited gitops config) of the
    /// `wildcard-repo-non-admin` rule to `Warn` lets the same bundle
    /// from the canonical test apply successfully — proving the
    /// escape hatch is config-driven (no env-var) and the apply
    /// commits when the operator has explicitly opted out.
    #[tokio::test]
    async fn operator_downgrade_lets_wildcard_grant_apply() {
        let cfg = crate::lint::LintConfig {
            rule_overrides: crate::lint::permission_grants::RuleOverrides {
                wildcard_repo_non_admin: Some(crate::lint::RuleAction::Warn),
                ..crate::lint::permission_grants::RuleOverrides::default()
            },
            ..crate::lint::LintConfig::default()
        };
        let h = build_harness_with_lint_config(cfg);
        let mut desired = DesiredState::default();
        desired.permission_grants.push(grant_env(
            "ops-write-everywhere",
            &["developer", "ops"],
            "write",
            None,
        ));
        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("an explicit operator downgrade must let the apply commit");
        assert_eq!(report.created, 1);
        assert_eq!(h.grant_repo.reconcile_call_count(), 1);
        assert_eq!(h.grant_repo.managed_count(), 1);
    }

    /// The secure-by-default config still lets a *clean* bundle apply
    /// (multi-claim repo-scoped grant + justified direct grant +
    /// ordinary claim mapping) — the linter is not a blanket block.
    #[tokio::test]
    async fn secure_by_default_clean_bundle_applies() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public", "hosted"));
        desired.claim_mappings.push(cm_env("a", "g-a", "developer"));
        desired.permission_grants.push(grant_env(
            "dev-team-write",
            &["developer", "team-alpha"],
            "write",
            Some("npm-public"),
        ));
        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("a clean bundle must apply under the secure default");
        // repo + claim mapping + grant.
        assert_eq!(report.created, 3);
        assert_eq!(h.grant_repo.reconcile_call_count(), 1);
    }

    // ===================================================================
    // Apply-ordering: the bundle's
    // `PermissionGrantLintConfig` partition resolves BEFORE the grant
    // linter runs, so an allowlist entry + a single-claim grant using
    // that claim land cleanly in ONE bundle. These use
    // `build_harness_with_lint_config(LintConfig::default())` — the
    // production secure-by-default posture (the composition root never
    // calls `with_lint_config`); the bundle is the ONLY relaxation
    // source, exactly as a real gitops apply.
    // ===================================================================

    /// Build a `kind: PermissionGrantLintConfig` envelope (the singleton
    /// gitops surface) with the given allowlist + optional
    /// per-rule downgrades, and place it on `desired` the way
    /// `DesiredState::absorb` would (the `Option` slot + the
    /// per-source-path bookkeeping the singleton check reads).
    pub(in crate::use_cases::apply_config_use_case) fn put_lint_config(
        desired: &mut DesiredState,
        name: &str,
        allowlist: &[&str],
        overrides: hort_config::lint_config::RuleOverridesSpec,
    ) {
        let env = Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::PermissionGrantLintConfig,
            metadata: Metadata { name: name.into() },
            spec: hort_config::lint_config::PermissionGrantLintConfigSpec {
                single_claim_allowlist: allowlist.iter().map(|s| (*s).to_string()).collect(),
                rule_overrides: overrides,
            },
        };
        desired.lint_config = Some(env);
        desired
            .lint_config_sources
            .push(std::path::PathBuf::from(format!("{name}.yaml")));
    }

    /// **Red-first (regression).** An allowlist entry AND a single-claim
    /// grant using exactly that claim, declared in the SAME bundle,
    /// applies cleanly — the lint-config partition is resolved *before*
    /// the grant linter, so the grant is the per-claim opt-out and
    /// `single-claim-grant` passes. Previously the production path was
    /// hardwired to `LintConfig::default()` (empty allowlist) so this
    /// bundle rejected unconditionally.
    #[tokio::test]
    async fn same_bundle_allowlist_then_single_claim_grant_applies() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public", "hosted"));
        // The opt-out and the grant using it, in ONE commit.
        put_lint_config(
            &mut desired,
            "rbac-lint",
            &["team-alpha"],
            hort_config::lint_config::RuleOverridesSpec::default(),
        );
        desired.permission_grants.push(grant_env(
            "solo-claim-read",
            &["team-alpha"],
            "read",
            Some("npm-public"),
        ));
        let report = h.uc.apply(desired, env_oidc()).await.expect(
            "allowlist+grant in one bundle must apply (ordering: allowlist resolves before linter)",
        );
        // repo + grant created; the linter did NOT reject.
        assert_eq!(report.created, 2);
        assert_eq!(h.grant_repo.reconcile_call_count(), 1);
        assert_eq!(h.grant_repo.managed_count(), 1);
    }

    /// Absent `PermissionGrantLintConfig` ⇒ `LintConfig::default()`
    /// (secure default unchanged). A non-allowlisted single-claim grant
    /// with NO lint-config kind still rejects — a missing kind is NOT a
    /// downgrade (the secure default is preserved).
    #[tokio::test]
    async fn absent_lint_config_kind_keeps_secure_default_reject() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public", "hosted"));
        // No put_lint_config — the kind is absent.
        desired.permission_grants.push(grant_env(
            "solo-claim-read",
            &["team-alpha"],
            "read",
            Some("npm-public"),
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("single-claim-grant"),
                    "absent kind must keep the secure reject, got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        assert_eq!(h.grant_repo.reconcile_call_count(), 0);
    }

    /// A bundle-supplied per-rule downgrade
    /// (`wildcard-repo-non-admin` → `warn`) takes effect on the linter
    /// in the same apply: a wildcard non-admin grant that would reject
    /// under the default now commits because the bundle's
    /// `PermissionGrantLintConfig` resolved first.
    #[tokio::test]
    async fn bundle_downgrade_override_takes_effect_on_linter() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        put_lint_config(
            &mut desired,
            "rbac-lint",
            &[],
            hort_config::lint_config::RuleOverridesSpec {
                wildcard_repo_non_admin: Some(hort_config::lint_config::RuleActionSpec::Warn),
                ..hort_config::lint_config::RuleOverridesSpec::default()
            },
        );
        desired.permission_grants.push(grant_env(
            "ops-write-everywhere",
            &["developer", "ops"],
            "write",
            None,
        ));
        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("a bundle-declared downgrade must let the wildcard grant commit");
        assert_eq!(report.created, 1);
        assert_eq!(h.grant_repo.reconcile_call_count(), 1);
    }

    /// `resolve_effective_lint_config`: absent kind → the
    /// composition-root default (here `LintConfig::default()` because
    /// the harness never opts out) — verifying the composition-root
    /// default is used, and exercises the `None` arm of the resolver.
    #[test]
    fn resolver_absent_kind_returns_composition_root_default() {
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let desired = DesiredState::default();
        let resolved = h.uc.resolve_effective_lint_config(&desired);
        assert_eq!(resolved, crate::lint::LintConfig::default());
    }

    /// `resolve_effective_lint_config`: absent kind returns the
    /// composition-root-installed config verbatim when the root opted
    /// out via `with_lint_config` (the boot seam), proving "absent kind
    /// ⇒ composed default", not "absent kind ⇒ hardcoded default".
    #[test]
    fn resolver_absent_kind_returns_boot_seam_config() {
        let seam = crate::lint::LintConfig {
            single_claim_allowlist: vec!["boot-blessed".into()],
            ..crate::lint::LintConfig::default()
        };
        let h = build_harness_with_lint_config(seam.clone());
        let desired = DesiredState::default();
        let resolved = h.uc.resolve_effective_lint_config(&desired);
        assert_eq!(resolved, seam);
    }

    /// `resolve_effective_lint_config`: `>1` declared envelope →
    /// secure default + a `warn!` (defense-in-depth; `validate_against`
    /// hard-rejects this earlier, but the resolver must never silently
    /// last-wins a security opt-out). Asserts the warn fires with a
    /// count, no claim names.
    #[test]
    fn resolver_more_than_one_envelope_warns_and_returns_default() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        // Two declarations: the absorb layer keeps the first in the
        // Option but records BOTH source paths → singleton violated.
        put_lint_config(
            &mut desired,
            "lint-a",
            &["team-alpha"],
            hort_config::lint_config::RuleOverridesSpec::default(),
        );
        desired
            .lint_config_sources
            .push(std::path::PathBuf::from("lint-b.yaml"));

        let resolved = h.uc.resolve_effective_lint_config(&desired);
        assert_eq!(
            resolved,
            crate::lint::LintConfig::default(),
            ">1 envelope must fall back to the secure default"
        );
        let records = captured.lock().unwrap();
        let warn = records
            .iter()
            .find(|(lvl, _)| *lvl == tracing::Level::WARN)
            .expect("a >1-envelope resolution must warn");
        assert!(
            warn.1.contains("lint_config_source_count")
                && warn.1.contains("more than one PermissionGrantLintConfig"),
            "warn must carry the count + the singleton message, got: {}",
            warn.1
        );
        assert!(
            !warn.1.contains("team-alpha"),
            "warn must NOT log claim names (operator topology — counts only): {}",
            warn.1
        );
    }

    /// `resolve_effective_lint_config`: a resolved *non-default* config
    /// logs `info!` with `single_claim_allowlist_len` +
    /// `rule_overrides_count` and **no claim names** (counts only).
    #[test]
    fn resolver_non_default_config_logs_info_counts_only() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        put_lint_config(
            &mut desired,
            "rbac-lint",
            &["team-alpha", "platform-readers"],
            hort_config::lint_config::RuleOverridesSpec {
                single_claim_grant: Some(hort_config::lint_config::RuleActionSpec::Warn),
                ..hort_config::lint_config::RuleOverridesSpec::default()
            },
        );
        let resolved = h.uc.resolve_effective_lint_config(&desired);
        assert_eq!(resolved.single_claim_allowlist.len(), 2);

        let records = captured.lock().unwrap();
        let info = records
            .iter()
            .find(|(lvl, _)| *lvl == tracing::Level::INFO)
            .expect("a resolved non-default lint config must log info");
        assert!(
            info.1.contains("single_claim_allowlist_len=2"),
            "info must carry the allowlist length, got: {}",
            info.1
        );
        assert!(
            info.1.contains("rule_overrides_count=1"),
            "info must carry the override count, got: {}",
            info.1
        );
        assert!(
            !info.1.contains("team-alpha") && !info.1.contains("platform-readers"),
            "info must NOT log claim names (counts only): {}",
            info.1
        );
    }

    /// `resolve_effective_lint_config`: a bundle whose spec maps to the
    /// secure default (empty allowlist, no overrides) does NOT log
    /// `info!` — only a *non-default* resolved config is the
    /// security-relevant change worth surfacing. Exercises the
    /// `resolved == default` branch of the resolver.
    #[test]
    fn resolver_default_equivalent_bundle_does_not_log_info() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        put_lint_config(
            &mut desired,
            "rbac-lint",
            &[],
            hort_config::lint_config::RuleOverridesSpec::default(),
        );
        let resolved = h.uc.resolve_effective_lint_config(&desired);
        assert_eq!(resolved, crate::lint::LintConfig::default());

        let records = captured.lock().unwrap();
        assert!(
            !records.iter().any(|(lvl, _)| *lvl == tracing::Level::INFO),
            "a default-equivalent bundle is not a security-relevant change — no info"
        );
    }

    // -- tracing capture machinery (mirrors `repository_access.rs`'s
    //    pattern; see that module for the callsite-cache
    //    race rationale) ---------------------------------------------------

    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct CapturingLayer {
        records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for CapturingLayer
    where
        S: tracing::Subscriber,
    {
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = TracingMessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }
    }

    #[derive(Default)]
    struct TracingMessageVisitor {
        combined: String,
    }
    impl tracing::field::Visit for TracingMessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    static TRACING_TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn install_global_passthrough_subscriber() {
        use std::sync::OnceLock;
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let global_layer = CapturingLayer::default();
            let global_subscriber = tracing_subscriber::Registry::default().with(global_layer);
            let _ = tracing::subscriber::set_global_default(global_subscriber);
        });
    }

    pub(in crate::use_cases::apply_config_use_case) fn env_oidc() -> EnvSnapshot {
        EnvSnapshot {
            auth_provider: hort_config::EnvAuthProvider::Oidc,
        }
    }

    fn env_disabled() -> EnvSnapshot {
        EnvSnapshot {
            auth_provider: hort_config::EnvAuthProvider::Disabled,
        }
    }

    // ===================================================================
    // Pre-existing baseline: empty/idempotent/repo paths still pass
    // ===================================================================

    #[tokio::test]
    async fn empty_desired_empty_snapshot_yields_zero_report() {
        let h = build_harness();
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report, ApplyReport::default());
    }

    #[tokio::test]
    async fn pure_create_with_one_repo_and_one_mapping() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("a", "hosted"));
        desired.claim_mappings.push(cm_env("admins", "g", "admin"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 2);
        assert!(!h
            .repos
            .calls()
            .iter()
            .any(|c| matches!(c, MockCall::Save(_))));
        // Whole-partition reconcile — one commit
        // call carrying the single declared mapping row.
        assert_eq!(h.claim_mappings.reconcile_call_count(), 1);
        assert_eq!(h.claim_mappings.managed_count(), 1);
    }

    #[tokio::test]
    async fn idempotent_reapply_makes_no_port_writes() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("a", "hosted"));
        desired.claim_mappings.push(cm_env("admins", "g", "admin"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let saves_before = h
            .repos
            .calls()
            .iter()
            .filter(|c| matches!(c, MockCall::SaveManaged(_, _)))
            .count();
        // The whole-partition reconcile primitive is
        // called unconditionally once per apply;
        // idempotence is observed via zero report churn + a stable
        // managed-row set, not a call-count delta.
        let managed_before = h.claim_mappings.managed_count();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 0);
        assert_eq!(report.updated, 0);
        assert_eq!(report.unchanged, 2);
        let saves_after = h
            .repos
            .calls()
            .iter()
            .filter(|c| matches!(c, MockCall::SaveManaged(_, _)))
            .count();
        assert_eq!(saves_before, saves_after);
        assert_eq!(managed_before, h.claim_mappings.managed_count());
    }

    #[tokio::test]
    async fn auth_provider_disabled_with_mappings_aborts() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.claim_mappings.push(cm_env("admins", "g", "admin"));
        let err = h.uc.apply(desired, env_disabled()).await.unwrap_err();
        assert!(err.to_string().contains("HORT_AUTH_PROVIDER=disabled"));
    }

    #[tokio::test]
    async fn proxy_without_upstream_url_is_validation_error() {
        let h = build_harness();
        let mut env = repo_env("p", "proxy");
        env.spec.proxy = None;
        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("type=proxy") || msg.contains("upstream"));
    }

    #[tokio::test]
    async fn first_failure_aborts_strict_atomic() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("a", "hosted"));
        desired.repositories.push(repo_env("b", "hosted"));
        h.repos
            .fail_next_save_managed(DomainError::Invariant("disk full".into()));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        assert!(err.to_string().contains("disk full"));
    }

    // ===================================================================
    // ClaimMapping apply (ADR 0012 — there is no Role CRUD block and
    // no `roles` table). Every
    // test here asserts shipped `apply_claim_mappings` behaviour: a
    // single whole-partition reconcile per apply,
    // `ClaimMappingApplied` on create OR digest change, silence on an
    // unchanged digest, `ClaimMappingRevoked` for a prior managed row
    // absent from desired, and "empty desired revokes all".
    // ===================================================================

    /// Read every `DomainEvent` appended to the global authorization
    /// stream (`ClaimMapping*`/`PermissionGrant*`
    /// global mutations route there via `StreamId::authorization()`).
    pub(in crate::use_cases::apply_config_use_case) async fn authz_events(
        h: &Harness,
    ) -> Vec<DomainEvent> {
        h.events
            .read_stream(&StreamId::authorization(), ReadFrom::Start, u64::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.event)
            .collect()
    }

    // ===================================================================
    // PermissionGrant apply (claims-subject; ADR 0012).
    // There is no `role`-keyed grant or per-row save API:
    // a grant carries a sum-typed `GrantSubject`, persistence is the
    // whole-partition reconcile, and the
    // diff identity is `(sorted required_claims, repository_id,
    // permission)` for `Claims` / `(user_id, repository_id, permission)`
    // for `User`.
    // ===================================================================

    fn count_pg_applied(evts: &[DomainEvent]) -> usize {
        evts.iter()
            .filter(|e| matches!(e, DomainEvent::PermissionGrantApplied(_)))
            .count()
    }

    fn count_pg_revoked(evts: &[DomainEvent]) -> usize {
        evts.iter()
            .filter(|e| matches!(e, DomainEvent::PermissionGrantRevoked(_)))
            .count()
    }

    // -------------------------------------------------------------------
    // Grant rows commit with their audit events (one transaction).
    // -------------------------------------------------------------------

    /// An audit-append failure during the grant apply leaves the
    /// gitops partition **exactly as it was** — the apply fails closed
    /// rather than half-done. This is the property the retry cannot
    /// supply: a committed row with no event is invisible to the next
    /// apply's prior-vs-desired diff, so no replacement event is ever
    /// emitted.
    #[tokio::test]
    async fn permission_grant_commit_failure_leaves_the_partition_unchanged() {
        let h = build_harness();
        let mut seeded = DesiredState::default();
        seeded
            .permission_grants
            .push(grant_env("dev-read", &["developer", "ops"], "read", None));
        h.uc.apply(seeded, env_oidc()).await.unwrap();
        assert_eq!(h.grant_repo.managed_count(), 1);
        let before = h.grant_repo.managed_snapshot();
        let applied_before = count_pg_applied(&authz_events(&h).await);
        let saves_before = h.grant_repo.reconcile_call_count();

        // A different desired set, with the commit armed to fail.
        h.authority.fail_next(
            AuthoritySite::PermissionGrants,
            DomainError::Invariant("event store unavailable".into()),
        );
        let mut next = DesiredState::default();
        next.permission_grants.push(grant_env(
            "sec-curate",
            &["security", "ops"],
            "curate",
            None,
        ));
        let err =
            h.uc.apply(next, env_oidc())
                .await
                .expect_err("an audit-append failure must fail the apply");
        assert!(
            err.to_string().contains("event store unavailable"),
            "the event-store failure must surface, got: {err}"
        );

        assert_eq!(
            h.grant_repo.reconcile_call_count(),
            saves_before,
            "no second row write may have landed — rows and events commit together"
        );
        assert_eq!(
            h.grant_repo.managed_snapshot(),
            before,
            "the gitops grant partition must be byte-identical to its pre-apply state"
        );
        assert_eq!(
            count_pg_applied(&authz_events(&h).await),
            applied_before,
            "no audit event may have landed either"
        );
    }

    /// A grant reconcile that routes events to several streams hands
    /// the whole batch list to **one** commit call, which is what makes
    /// the multi-stream append atomic. Before the port each stream was
    /// its own `EventStore::append` transaction, so a list that failed
    /// part-way left some repository streams audited and others not.
    #[tokio::test]
    async fn permission_grant_commit_takes_every_stream_in_one_call() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public", "hosted"));
        // One repo-scoped grant (routes to the repository stream) and
        // one wildcard grant (routes to the authorization stream).
        desired.permission_grants.push(grant_env(
            "dev-read-npm",
            &["developer", "ops"],
            "read",
            Some("npm-public"),
        ));
        desired.permission_grants.push(grant_env(
            "admin-everywhere",
            &["platform", "admins"],
            "admin",
            None,
        ));
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let grant_commits: Vec<usize> = h
            .authority
            .commits()
            .into_iter()
            .filter(|(site, _)| *site == AuthoritySite::PermissionGrants)
            .map(|(_, batches)| batches)
            .collect();
        assert_eq!(
            grant_commits,
            vec![2],
            "exactly one commit call carrying both stream batches"
        );

        let repo_id = h.repos.find_by_key("npm-public").await.unwrap().id;
        assert_eq!(
            count_pg_applied(&repo_stream_events(&h.events, repo_id).await),
            1,
            "the repo-scoped grant is audited on its repository stream"
        );
        assert_eq!(
            count_pg_applied(&authz_events(&h).await),
            1,
            "the wildcard grant is audited on the authorization stream"
        );
    }

    #[tokio::test]
    async fn create_permission_grant_resolves_claims_and_repository() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public", "hosted"));
        desired.permission_grants.push(grant_env(
            "dev-read-npm",
            &["developer"],
            "read",
            Some("npm-public"),
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        // Repo + Grant = 2 created (no `roles` table).
        assert_eq!(report.created, 2);
        assert_eq!(h.grant_repo.reconcile_call_count(), 1);
        assert_eq!(h.grant_repo.managed_count(), 1);
        let g = &h.grant_repo.managed_snapshot()[0];
        assert_eq!(
            g.subject,
            GrantSubject::Claims(vec!["developer".to_string()])
        );
        assert_eq!(g.permission, Permission::Read);
        assert!(g.repository_id.is_some());
    }

    /// End-to-end check that a
    /// `PermissionGrant` carrying the `curate` permission flows
    /// cleanly through the gitops apply path: validator accepts it
    /// (`Permission::FromStr` arm + the `expected` list pin in
    /// `unknown_permission_diagnostic_lists_every_variant`), the apply
    /// stage resolves it to `Permission::Curate`, and the managed grant
    /// is persisted. The `FromStr` arm is a non-compile-checked surface
    /// (non-exhaustive `match`) — this test is the load-bearing pin
    /// against a silent gitops-parsing breakage.
    #[tokio::test]
    async fn create_curate_permission_grant_applies_cleanly() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.permission_grants.push(grant_env(
            "sec-curator",
            &["security-team"],
            "curate",
            None,
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1);
        assert_eq!(h.grant_repo.managed_count(), 1);
        let g = &h.grant_repo.managed_snapshot()[0];
        assert_eq!(
            g.subject,
            GrantSubject::Claims(vec!["security-team".to_string()])
        );
        assert_eq!(g.permission, Permission::Curate);
        assert!(g.repository_id.is_none());
    }

    #[tokio::test]
    async fn create_user_subject_permission_grant_parses_uuid_and_reconciles() {
        // The `GrantSubjectSpec::User { user_id }` arm:
        // the apply layer parses the string user-id to a `Uuid` and
        // materialises a `GrantSubject::User` grant. The User-subject
        // diff key is `(user_id, repository_id, permission)`, so an
        // unchanged replay is a no-op.
        let h = build_harness();
        let uid = Uuid::new_v4();
        let mut desired = DesiredState::default();
        // Global grant (`repository: None`) so the audit event routes
        // to `StreamId::authorization()` (repo-scoped
        // grants route to `StreamId::repository(r)` instead).
        desired
            .permission_grants
            .push(user_grant_env("sa-write-global", uid, "write", None));
        let report = h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        assert_eq!(report.created, 1); // grant only (no `roles` table)
        assert_eq!(h.grant_repo.managed_count(), 1);
        let g = &h.grant_repo.managed_snapshot()[0];
        assert_eq!(g.subject, GrantSubject::User(uid));
        assert_eq!(g.permission, Permission::Write);
        assert_eq!(g.repository_id, None);
        let applied_after_create = count_pg_applied(&authz_events(&h).await);
        assert_eq!(applied_after_create, 1);

        // Replay the identical desired set → User-subject diff key
        // matches → no-op (no new PermissionGrantApplied, stable set).
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 0);
        assert_eq!(report.updated, 0);
        assert!(report.unchanged >= 1);
        assert_eq!(h.grant_repo.managed_count(), 1);
        assert_eq!(
            count_pg_applied(&authz_events(&h).await),
            applied_after_create,
            "an unchanged User-subject grant replay must emit no PermissionGrantApplied"
        );
    }

    #[tokio::test]
    async fn user_subject_grant_invalid_uuid_fails_apply() {
        // The apply layer parses `subject.userId`; a
        // non-UUID string is a Validation error (the apply aborts
        // strict-atomic before any reconcile).
        let h = build_harness();
        let mut desired = DesiredState::default();
        let mut env = user_grant_env("bad", Uuid::new_v4(), "read", None);
        env.spec.subject = GrantSubjectSpec::User {
            user_id: "not-a-uuid".into(),
        };
        desired.permission_grants.push(env);
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not-a-uuid") || msg.to_lowercase().contains("uuid"),
            "expected a UUID-parse validation error, got: {msg}"
        );
        // Strict-atomic: nothing reconciled.
        assert_eq!(h.grant_repo.managed_count(), 0);
    }

    #[tokio::test]
    async fn delete_permission_grant_when_absent_from_desired() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .permission_grants
            .push(grant_env("dev-read-global", &["developer"], "read", None));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        assert_eq!(h.grant_repo.managed_count(), 1);

        // Drop the grant from desired → whole-partition reconcile drops
        // it + a PermissionGrantRevoked attests the removal.
        desired.permission_grants.clear();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(h.grant_repo.managed_count(), 0);
        assert_eq!(count_pg_revoked(&authz_events(&h).await), 1);
    }

    #[tokio::test]
    async fn permission_grant_diff_identity_is_subject_triple_freeform_name_idempotent() {
        // The diff identity for a `Claims` grant is
        // `(sorted required_claims, repository_id, permission)` — NOT
        // the operator-supplied `metadata.name`. Replaying the same
        // declaration (even renamed) is a no-op: zero report churn and
        // a stable managed grant set.
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .permission_grants
            .push(grant_env("dev-read-global", &["developer"], "read", None));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        assert_eq!(h.grant_repo.managed_count(), 1);
        let applied_before = count_pg_applied(&authz_events(&h).await);
        assert_eq!(applied_before, 1);

        // Re-apply the SAME desired state, same freeform name → no-op.
        let report = h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        assert_eq!(report.created, 0);
        assert_eq!(report.updated, 0);
        assert!(report.unchanged >= 1);
        assert_eq!(
            count_pg_applied(&authz_events(&h).await),
            applied_before,
            "matching subject-triple → no new PermissionGrantApplied"
        );
        assert_eq!(h.grant_repo.managed_count(), 1);

        // Renaming the YAML envelope (same subject triple) is also a no-op.
        desired.permission_grants[0].metadata.name = "dev-read-pypi".into();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 0);
        assert_eq!(report.updated, 0);
        assert_eq!(
            count_pg_applied(&authz_events(&h).await),
            applied_before,
            "renaming metadata.name with the same subject triple stays unchanged"
        );
    }

    #[tokio::test]
    async fn permission_grant_diff_triple_mismatch_emits_revoke_then_apply() {
        // Companion: when the subject triple changes (permission flips
        // read → write) the diff treats the old identity as revoked
        // (absent from the desired set) and the new spec as applied.
        // One PermissionGrantRevoked + one PermissionGrantApplied.
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .permission_grants
            .push(grant_env("dev-read-global", &["developer"], "read", None));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let applied_before = count_pg_applied(&authz_events(&h).await);
        let revoked_before = count_pg_revoked(&authz_events(&h).await);
        assert_eq!(applied_before, 1);
        assert_eq!(revoked_before, 0);

        // Change the permission — same metadata.name, different triple.
        desired.permission_grants[0].spec.permission = "write".into();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        let evts = authz_events(&h).await;
        assert_eq!(
            count_pg_revoked(&evts) - revoked_before,
            1,
            "subject-triple mismatch must emit one PermissionGrantRevoked"
        );
        assert_eq!(
            count_pg_applied(&evts) - applied_before,
            1,
            "subject-triple mismatch must emit one PermissionGrantApplied"
        );
        assert_eq!(report.created, 1);
        assert_eq!(report.deleted, 1);
        // The reconciled set still holds exactly one grant (the new
        // write identity replaced the old read identity).
        assert_eq!(h.grant_repo.managed_count(), 1);
        assert_eq!(
            h.grant_repo.managed_snapshot()[0].permission,
            Permission::Write
        );
    }

    // ===================================================================
    // Cross-stage: full create-all happy path
    // ===================================================================

    #[tokio::test]
    async fn create_all_kinds_at_once_succeeds() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public", "hosted"));
        desired.claim_mappings.push(cm_env("admins", "g", "admin"));
        desired
            .curation_rules
            .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
        desired.permission_grants.push(grant_env(
            "dev-read-npm",
            &["developer"],
            "read",
            Some("npm-public"),
        ));
        desired.scan_policies.push(scan_policy_env("prod-default"));
        desired
            .exclusions
            .push(exclusion_env("ex1", "prod-default", "CVE-2024-0001"));

        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        // 6 objects created (one per kind — `roles` is dropped):
        // repository, claim_mapping, curation_rule, permission_grant,
        // scan_policy, exclusion.
        assert_eq!(report.created, 6);

        // Spot-check: every CRUD writer fired once via the
        // whole-partition reconcile primitive.
        assert_eq!(h.claim_mappings.reconcile_call_count(), 1);
        assert_eq!(h.claim_mappings.managed_count(), 1);
        assert_eq!(h.grant_repo.reconcile_call_count(), 1);
        assert_eq!(h.grant_repo.managed_count(), 1);
        assert_eq!(h.rule_repo.save_count(), 1);
        // PolicyUseCase fired twice (PolicyCreated + ExclusionAdded).
        // Filter by stream category so this assertion stays focused on
        // policy-event throughput.
        let policy_appends = h
            .events
            .appended()
            .into_iter()
            .filter(|b| b.stream_id.category == StreamCategory::Policy)
            .count();
        assert_eq!(policy_appends, 2);
    }

    // ===================================================================
    // Metric emission (gitops_objects_total per kind)
    // ===================================================================

    /// One `(CompositeKey, Option<Unit>, Option<SharedString>, DebugValue)`
    /// tuple as returned by `Snapshot::into_vec`. Aliased so the tests
    /// don't have to spell the four-tuple every time.
    type SnapshotEntry = (
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        metrics_util::debugging::DebugValue,
    );

    /// Sum the `Counter` deltas for every series in `entries` matching
    /// `metric` AND every (label, value) pair in `wanted`. Tests call
    /// this multiple times against the same `into_vec()` output —
    /// `Snapshot` is not `Clone`, so the caller materialises it once.
    pub(in crate::use_cases::apply_config_use_case) fn counter_value_for(
        entries: &[SnapshotEntry],
        metric: &str,
        wanted: &[(&str, &str)],
    ) -> u64 {
        let mut total = 0u64;
        for (k, _, _, value) in entries {
            if k.key().name() != metric {
                continue;
            }
            let labels: HashMap<&str, &str> =
                k.key().labels().map(|l| (l.key(), l.value())).collect();
            if !wanted
                .iter()
                .all(|(key, val)| labels.get(*key) == Some(val))
            {
                continue;
            }
            if let metrics_util::debugging::DebugValue::Counter(v) = value {
                total += v;
            }
        }
        total
    }

    #[test]
    fn emits_per_kind_objects_total_for_each_new_kind() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired.claim_mappings.push(cm_env("admins", "g", "admin"));
                desired
                    .curation_rules
                    .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        // Find hort_gitops_objects_total entries — there must be at
        // least one with the cataloged `kind=claim_mapping` label the
        // claim-mapping apply emits,
        // and one with kind=curation_rule.
        let mut saw_claim_mapping = false;
        let mut saw_rule = false;
        for (k, _, _, _) in entries {
            if k.key().name() == "hort_gitops_objects_total" {
                let labels: HashMap<&str, &str> =
                    k.key().labels().map(|l| (l.key(), l.value())).collect();
                match labels.get("kind").copied() {
                    Some("claim_mapping") => saw_claim_mapping = true,
                    Some("curation_rule") => saw_rule = true,
                    _ => {}
                }
            }
        }
        assert!(
            saw_claim_mapping,
            "expected hort_gitops_objects_total{{kind=group_mapping}}"
        );
        assert!(
            saw_rule,
            "expected hort_gitops_objects_total{{kind=curation_rule}}"
        );
    }

    // ===================================================================
    // hort_gitops_events_emitted_total emission
    // for the event-sourced kinds (scan_policy / exclusion). Each test
    // captures with `with_local_recorder` and asserts the per-(kind,
    // event_type) counter delta matches the events the apply pipeline
    // dispatched through `PolicyUseCase`. CRUD-only kinds (role,
    // permission_grant, curation_rule) tick `hort_gitops_objects_total`
    // (covered above) but never tick `events_emitted_total`.
    // ===================================================================

    #[test]
    fn create_scan_policy_emits_one_policy_created_event_metric() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired.scan_policies.push(scan_policy_env("prod-default"));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        // events_emitted_total{kind=scan_policy, event_type=PolicyCreated} == 1
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "scan_policy"), ("event_type", "PolicyCreated")],
            ),
            1,
        );
        // objects_total{kind=scan_policy, result=created} == 1
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "scan_policy"), ("result", "created")],
            ),
            1,
        );
        // No PolicyUpdated/PolicyArchived ticks on a fresh create.
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "scan_policy"), ("event_type", "PolicyUpdated")],
            ),
            0,
        );
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "scan_policy"), ("event_type", "PolicyArchived")],
            ),
            0,
        );
    }

    #[test]
    fn update_scan_policy_two_field_change_emits_two_policy_updated_events() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired.scan_policies.push(scan_policy_env("p1"));
                h.uc.apply(desired.clone(), env_oidc()).await.unwrap();

                // Touch two fields — severity_threshold + require_approval.
                desired.scan_policies[0].spec.severity_threshold = "critical".into();
                desired.scan_policies[0].spec.require_approval = false;
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        // One PolicyCreated (initial apply) + two PolicyUpdated (the
        // 2-field update); both branches emit events_emitted_total.
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "scan_policy"), ("event_type", "PolicyCreated")],
            ),
            1,
        );
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "scan_policy"), ("event_type", "PolicyUpdated")],
            ),
            2,
        );
        // objects_total ticks once per envelope outcome — the update
        // touches one envelope so result=updated == 1, regardless of
        // how many fields changed.
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "scan_policy"), ("result", "updated")],
            ),
            1,
        );
    }

    #[test]
    fn archive_scan_policy_emits_one_policy_archived_event_metric() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired.scan_policies.push(scan_policy_env("p1"));
                h.uc.apply(desired, env_oidc()).await.unwrap();
                // Drop the policy → archive branch.
                h.uc.apply(DesiredState::default(), env_oidc())
                    .await
                    .unwrap();
            });
        });
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "scan_policy"), ("event_type", "PolicyArchived")],
            ),
            1,
        );
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "scan_policy"), ("result", "deleted")],
            ),
            1,
        );
    }

    #[test]
    fn idempotent_scan_policy_reapply_emits_no_event_metric() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired.scan_policies.push(scan_policy_env("p1"));
                // First apply mints PolicyCreated; second is a true no-op.
                h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        // Exactly one PolicyCreated across the two applies.
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "scan_policy"), ("event_type", "PolicyCreated")],
            ),
            1,
        );
        // No spurious PolicyUpdated on idempotent reapply.
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "scan_policy"), ("event_type", "PolicyUpdated")],
            ),
            0,
        );
        // objects_total ticks unchanged for the second apply.
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "scan_policy"), ("result", "unchanged")],
            ),
            1,
        );
    }

    #[test]
    fn create_claim_mapping_emits_objects_total_but_not_events_emitted_total() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired.claim_mappings.push(cm_env("admins", "g", "admin"));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        // The claim-mapping apply emits the cataloged
        // `kind=claim_mapping` label.
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "claim_mapping"), ("result", "created")],
            ),
            1,
        );
        // ClaimMapping is CRUD-shaped at the gitops-metric level, not
        // an `hort_gitops_events_emitted_total` source (only the
        // event-sourced scan_policy / exclusion kinds tick that).
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "claim_mapping")],
            ),
            0,
        );
    }

    #[test]
    fn create_permission_grant_emits_objects_total_kind_permission_grant() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired.permission_grants.push(grant_env(
                    "dev-read-global",
                    &["developer"],
                    "read",
                    None,
                ));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "permission_grant"), ("result", "created")],
            ),
            1,
        );
    }

    // ----------------------------------------------------------------------
    // UpstreamMapping apply branch
    // ----------------------------------------------------------------------

    pub(in crate::use_cases::apply_config_use_case) fn upstream_mapping_env(
        name: &str,
        repository: &str,
        path_prefix: &str,
        upstream_url: &str,
    ) -> Envelope<UpstreamMappingSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::UpstreamMapping,
            metadata: Metadata { name: name.into() },
            spec: UpstreamMappingSpec {
                repository: repository.into(),
                path_prefix: path_prefix.into(),
                upstream_url: upstream_url.into(),
                upstream_name_prefix: None,
                auth: hort_config::upstream_mapping::UpstreamAuthSpec {
                    r#type: "anonymous".into(),
                    username: None,
                },
                secret_ref: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
            },
        }
    }

    // -- upstreamNamePrefix end-to-end ---------------------------------------
    //
    // The field is threaded from `UpstreamMappingSpec` through
    // `ApplyConfigUseCase::apply_upstream_mappings` into
    // `RepositoryUpstreamMappingArgs`. Diff identity stays
    // `(repository, path_prefix)`; the new field participates in the
    // spec digest so a value change produces `result=updated`, not
    // `delete + create` or a no-op.

    pub(in crate::use_cases::apply_config_use_case) fn upstream_mapping_env_with_prefix(
        name: &str,
        repository: &str,
        path_prefix: &str,
        upstream_url: &str,
        prefix: Option<&str>,
    ) -> Envelope<UpstreamMappingSpec> {
        let mut env = upstream_mapping_env(name, repository, path_prefix, upstream_url);
        env.spec.upstream_name_prefix = prefix.map(str::to_owned);
        env
    }

    /// `upstreamNamePrefix` is OCI-effective only; the cross-spec
    /// validator (`push_upstream_mapping_format_compatibility_errors`)
    /// rejects the field on non-OCI repositories. The default
    /// `repo_env` builds an `npm` repository, so the name-prefix tests
    /// need an OCI variant.
    pub(in crate::use_cases::apply_config_use_case) fn oci_repo_env(
        name: &str,
    ) -> Envelope<RepositorySpec> {
        let mut env = repo_env(name, "proxy");
        env.spec.format = "oci".into();
        env
    }

    // ===================================================================
    // Authz audit events on gitops apply
    // (NIS2 Art. 21(2)(h)). The audit-completeness regression
    // test lives here. A future refactor that drops
    // an event emission from the gitops apply path MUST fail one of
    // these tests; that is the load-bearing security property.
    // ===================================================================

    use hort_domain::events::{DomainEvent as DE, StreamCategory};
    use hort_domain::ports::event_store::ReadFrom as RF;

    /// Read every event on the global authorization stream as a
    /// `Vec<DomainEvent>`. The mock's `read_stream` impl replays from
    /// `appended` so this exercises the public `EventStore::read_stream`
    /// contract, not the mock's internals.
    async fn authz_stream_events(events: &MockPolicyEventStore) -> Vec<DE> {
        events
            .read_stream(&StreamId::authorization(), RF::Start, u64::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.event)
            .collect()
    }

    /// Audit-completeness gate (roles, the role-permission-set
    /// diff, and the `GroupMapping*`/`Role*` events do not exist in the
    /// additive-claims model — ADR 0012).
    ///
    /// Drives `ApplyConfigUseCase::apply` with a planned mutation for
    /// each authz kind (ClaimMapping create / digest-change /
    /// revoke; global PermissionGrant create / revoke) and asserts the
    /// matching audit event lands on `StreamId::authorization()`.
    /// A future refactor that drops an emission from the gitops apply
    /// path MUST fail this test — that is the load-bearing security
    /// property.
    #[tokio::test]
    async fn gitops_apply_emits_claim_authz_audit_events_on_every_mutation() {
        // -- Phase 1: create a claim mapping + a global grant --
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("dev-team", "g-eng", "developer"));
        desired
            .permission_grants
            .push(grant_env("dev-read", &["developer"], "read", None));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();

        let after_create = authz_stream_events(&h.events).await;
        let cm_applied: Vec<&ClaimMappingApplied> = after_create
            .iter()
            .filter_map(|e| match e {
                DE::ClaimMappingApplied(a) => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(
            cm_applied.len(),
            1,
            "create must emit exactly one ClaimMappingApplied"
        );
        assert_eq!(cm_applied[0].idp_group, "g-eng");
        assert_eq!(cm_applied[0].claim, "developer");

        let pg_applied: Vec<&PermissionGrantApplied> = after_create
            .iter()
            .filter_map(|e| match e {
                DE::PermissionGrantApplied(a) => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(
            pg_applied.len(),
            1,
            "create must emit exactly one PermissionGrantApplied"
        );
        assert_eq!(pg_applied[0].permission, Permission::Read);
        assert_eq!(pg_applied[0].repository_id, None);
        assert_eq!(
            pg_applied[0].subject,
            GrantSubjectRecord::Claims {
                required: vec!["developer".to_string()]
            }
        );

        // Both global-grant + claim-mapping events route to the global
        // authorization stream (`repository_id = None`
        // ⇒ `StreamId::authorization()`).
        let routed_to_authz = h
            .events
            .appended()
            .into_iter()
            .filter(|b| b.stream_id.category == StreamCategory::Authorization)
            .count();
        assert!(
            routed_to_authz >= 2,
            "at least one batch per kind must route to Authorization, got {routed_to_authz}",
        );

        // -- Phase 2: retarget the mapping. The reconcile keys the
        // claim-mapping identity off `(idp_group, claim)`, so changing
        // the claim is a NEW identity: the old `(g-eng, developer)` is
        // revoked and the new `(g-eng, admin)` is applied (there is no
        // separate *Updated event; the apply/revoke pair is the audit
        // attestation). `authz_stream_events` replays the full stream,
        // so counts are cumulative. --
        let appended_before_update = h.events.appended().len();
        desired.claim_mappings[0] = cm_env("dev-team", "g-eng", "admin");
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let after_update = authz_stream_events(&h.events).await;
        let cm_applied_after_update = after_update
            .iter()
            .filter(|e| matches!(e, DE::ClaimMappingApplied(_)))
            .count();
        assert_eq!(
            cm_applied_after_update, 2,
            "create + retarget ⇒ two cumulative ClaimMappingApplied"
        );
        let cm_revoked_after_update = after_update
            .iter()
            .filter(|e| matches!(e, DE::ClaimMappingRevoked(_)))
            .count();
        assert_eq!(
            cm_revoked_after_update, 1,
            "the retarget revokes the old (g-eng, developer) identity"
        );
        assert!(h.events.appended().len() > appended_before_update);

        // -- Phase 3: delete (clear desired) → the surviving claim
        // mapping `(g-eng, admin)` and the grant are revoked; audit
        // events for both must land (cumulative totals). --
        h.uc.apply(DesiredState::default(), env_oidc())
            .await
            .unwrap();
        let after_delete = authz_stream_events(&h.events).await;
        let cm_revoked = after_delete
            .iter()
            .filter(|e| matches!(e, DE::ClaimMappingRevoked(_)))
            .count();
        assert_eq!(
            cm_revoked, 2,
            "cumulative: developer revoked at retarget + admin revoked at delete"
        );
        let pg_revoked = after_delete
            .iter()
            .filter(|e| matches!(e, DE::PermissionGrantRevoked(_)))
            .count();
        assert_eq!(pg_revoked, 1, "absent grant must be revoked");
    }

    /// Empty event batches MUST NOT cause an EventStore append (saves
    /// a round-trip and avoids spurious empty correlation_ids on the
    /// audit stream). Drive the apply with an empty desired set
    /// (`apply_claim_mappings` + `apply_permission_grants` both see an
    /// empty plan) and assert no batch lands on the authorization
    /// stream.
    #[tokio::test]
    async fn empty_authz_plan_appends_no_authorization_event() {
        let h = build_harness();
        h.uc.apply(DesiredState::default(), env_oidc())
            .await
            .unwrap();
        let authz_batches = h
            .events
            .appended()
            .into_iter()
            .filter(|b| b.stream_id.category == StreamCategory::Authorization)
            .count();
        assert_eq!(authz_batches, 0);
    }

    // ===================================================================
    // Authz audit events on gitops apply,
    // repo-scoped (PermissionGrant + UpstreamMapping). Mirrors the
    // global audit-completeness regression test pattern above.
    // ===================================================================

    use hort_domain::events::{
        PermissionGrantApplied as PGA, PermissionGrantRevoked as PGR,
        RepositoryUpstreamMappingChanged as RUMC, UpstreamMappingChange as UMC,
    };
    use hort_domain::ports::secret_port::{SecretRef, SecretSource};

    /// Helper — read every event on a given Repository(repo_id) stream
    /// as a `Vec<DomainEvent>`. `pub(in …)` so the per-branch test
    /// modules (e.g. `upstream_mappings::tests`) can read a repo-scoped
    /// stream without a second copy of this.
    pub(in crate::use_cases::apply_config_use_case) async fn repo_stream_events(
        events: &MockPolicyEventStore,
        repo_id: Uuid,
    ) -> Vec<DE> {
        events
            .read_stream(&StreamId::repository(repo_id), RF::Start, u64::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.event)
            .collect()
    }

    /// Build an UpstreamMapping envelope that carries a `secret_ref`,
    /// for the rotation tests below.
    fn upstream_mapping_env_with_secret(
        name: &str,
        repository: &str,
        path_prefix: &str,
        upstream_url: &str,
        location: &str,
    ) -> Envelope<UpstreamMappingSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::UpstreamMapping,
            metadata: Metadata { name: name.into() },
            spec: UpstreamMappingSpec {
                repository: repository.into(),
                path_prefix: path_prefix.into(),
                upstream_url: upstream_url.into(),
                upstream_name_prefix: None,
                auth: hort_config::upstream_mapping::UpstreamAuthSpec {
                    r#type: "basic".into(),
                    username: Some("alice".into()),
                },
                secret_ref: Some(SecretRef {
                    source: SecretSource::EnvVar,
                    location: location.into(),
                }),
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
            },
        }
    }

    /// Audit-completeness gate, repo-scoped slice. Drives
    /// `ApplyConfigUseCase::apply` with a planned mutation for each
    /// repo-scoped authz kind (PermissionGrant repo-scoped, PermissionGrant
    /// global, RepositoryUpstreamMapping create/update/delete) and
    /// asserts the matching audit event lands on the right stream.
    #[tokio::test]
    async fn gitops_apply_emits_repo_scoped_grant_audit_to_repository_stream() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("npm-public", "hosted"));
        desired.permission_grants.push(grant_env(
            "dev-read-npm",
            &["developer"],
            "read",
            Some("npm-public"),
        ));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();

        // Resolve the repo id post-apply (the diff path mints it).
        let npm_repo = h.repos.find_by_key("npm-public").await.unwrap();

        // PermissionGrantApplied MUST land on Repository(npm_repo.id),
        // NOT on the Authorization stream — repo-scoped grants are
        // routed by repository_id.
        let on_repo = repo_stream_events(&h.events, npm_repo.id).await;
        let pga: Vec<&PGA> = on_repo
            .iter()
            .filter_map(|e| match e {
                DE::PermissionGrantApplied(p) => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(
            pga.len(),
            1,
            "expected one PermissionGrantApplied on Repository({}); got {}",
            npm_repo.id,
            pga.len()
        );
        assert_eq!(pga[0].repository_id, Some(npm_repo.id));
        assert_eq!(pga[0].permission, Permission::Read);
        assert_eq!(
            pga[0].subject,
            GrantSubjectRecord::Claims {
                required: vec!["developer".to_string()]
            }
        );

        // The Authorization stream must NOT carry this repo-scoped
        // grant — it is the global stream.
        let on_authz = authz_stream_events(&h.events).await;
        let global_pgas: Vec<&PGA> = on_authz
            .iter()
            .filter_map(|e| match e {
                DE::PermissionGrantApplied(p) => Some(p),
                _ => None,
            })
            .filter(|p| p.repository_id == Some(npm_repo.id))
            .collect();
        assert!(
            global_pgas.is_empty(),
            "repo-scoped grant must NOT land on Authorization stream"
        );

        // Drop the grant — PermissionGrantRevoked must land on the
        // same Repository(npm_repo.id) stream.
        desired.permission_grants.clear();
        h.uc.apply(desired, env_oidc()).await.unwrap();
        let on_repo_after_delete = repo_stream_events(&h.events, npm_repo.id).await;
        let pgr: Vec<&PGR> = on_repo_after_delete
            .iter()
            .filter_map(|e| match e {
                DE::PermissionGrantRevoked(p) => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(
            pgr.len(),
            1,
            "expected one PermissionGrantRevoked on Repository({}); got {}",
            npm_repo.id,
            pgr.len()
        );
        assert_eq!(pgr[0].repository_id, Some(npm_repo.id));
    }

    #[tokio::test]
    async fn gitops_apply_emits_global_grant_audit_to_authorization_stream() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        // Global grant — `repository: None`.
        desired
            .permission_grants
            .push(grant_env("dev-read-global", &["developer"], "read", None));
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let on_authz = authz_stream_events(&h.events).await;
        let pga_global: Vec<&PGA> = on_authz
            .iter()
            .filter_map(|e| match e {
                DE::PermissionGrantApplied(p) => Some(p),
                _ => None,
            })
            .filter(|p| p.repository_id.is_none())
            .collect();
        assert_eq!(
            pga_global.len(),
            1,
            "expected one global PermissionGrantApplied on Authorization stream; got {}",
            pga_global.len()
        );
        assert_eq!(pga_global[0].permission, Permission::Read);
        assert_eq!(
            pga_global[0].subject,
            GrantSubjectRecord::Claims {
                required: vec!["developer".to_string()]
            }
        );
    }

    /// The load-bearing rotation regression test. Drives an
    /// upstream-mapping rotation that changes `secret_ref` and asserts
    /// `RepositoryUpstreamMappingChanged { change: Updated, .. }`
    /// lands with `previous_secret_ref: Some(...)` /
    /// `new_secret_ref: Some(...)` carrying the secret-ref
    /// **identifier** (`<source>:<location>`) — never a resolved
    /// value. Pairs with the unit-level security gate in
    /// `authorization_events.rs`.
    #[tokio::test]
    async fn gitops_apply_emits_upstream_mapping_changed_on_secret_rotation() {
        let h = build_harness();
        // Initial apply: mapping with secret_ref = env_var:V1.
        let desired_v1 = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env_with_secret(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
                "DOCKERHUB_TOKEN_V1",
            )],
            ..Default::default()
        };
        h.uc.apply(desired_v1, env_oidc()).await.unwrap();
        let repo = h.repos.find_by_key("oci-mirror-e2e").await.unwrap();

        // First apply must land a Created RepositoryUpstreamMappingChanged.
        let on_repo = repo_stream_events(&h.events, repo.id).await;
        let created: Vec<&RUMC> = on_repo
            .iter()
            .filter_map(|e| match e {
                DE::RepositoryUpstreamMappingChanged(r) => Some(r),
                _ => None,
            })
            .filter(|r| r.change == UMC::Created)
            .collect();
        assert_eq!(
            created.len(),
            1,
            "expected one Created event on Repository({}); got {}",
            repo.id,
            created.len()
        );
        assert_eq!(
            created[0].new_secret_ref.as_deref(),
            Some("env_var:DOCKERHUB_TOKEN_V1"),
            "new_secret_ref must carry the identifier `<source>:<location>`"
        );
        assert_eq!(created[0].previous_secret_ref, None);
        assert_eq!(
            created[0].new_url.as_deref(),
            Some("https://registry-1.docker.io")
        );

        // Re-apply with rotated secret_ref. `previous_secret_ref`
        // and `new_secret_ref` must both be `Some(<identifier>)`,
        // carrying the V1 / V2 names — NOT the resolved value.
        let desired_v2 = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env_with_secret(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
                "DOCKERHUB_TOKEN_V2",
            )],
            ..Default::default()
        };
        h.uc.apply(desired_v2, env_oidc()).await.unwrap();

        let on_repo_after = repo_stream_events(&h.events, repo.id).await;
        let updated: Vec<&RUMC> = on_repo_after
            .iter()
            .filter_map(|e| match e {
                DE::RepositoryUpstreamMappingChanged(r) => Some(r),
                _ => None,
            })
            .filter(|r| r.change == UMC::Updated)
            .collect();
        assert_eq!(
            updated.len(),
            1,
            "expected one Updated event after secret_ref rotation; got {}",
            updated.len()
        );
        assert_eq!(
            updated[0].previous_secret_ref.as_deref(),
            Some("env_var:DOCKERHUB_TOKEN_V1"),
        );
        assert_eq!(
            updated[0].new_secret_ref.as_deref(),
            Some("env_var:DOCKERHUB_TOKEN_V2"),
        );
        // Defence-in-depth: the per-batch payload also doesn't leak
        // any value — the test seeds the env var with a sentinel
        // value, then asserts the batch's serialised JSON contains
        // only the identifiers, never the value.
        const RESOLVED_VALUE_SENTINEL: &str = "S3CRET-DO-NOT-LEAK";
        let any_batch_with_rumc = h
            .events
            .appended()
            .into_iter()
            .find(|b| {
                b.events.iter().any(|e| {
                    matches!(
                        e.event,
                        DomainEvent::RepositoryUpstreamMappingChanged(ref r)
                            if r.change == UMC::Updated
                    )
                })
            })
            .expect("batch with the Updated event must have been appended");
        // Force a reasonable scan of the entire batch's payload
        // serialisation. We don't have direct access to the raw
        // payload bytes the event store would persist, so serialise
        // each event independently — the same path the Postgres
        // mapper uses.
        for e in &any_batch_with_rumc.events {
            let json = serde_json::to_string(&e.event).expect("serialise event payload");
            assert!(
                !json.contains(RESOLVED_VALUE_SENTINEL),
                "SECURITY REGRESSION: serialised event leaks resolved secret value: {json}"
            );
        }
    }

    /// Removing a managed mapping must emit
    /// `RepositoryUpstreamMappingChanged { change: Removed, .. }`
    /// carrying the prior `secret_ref` identifier and URL.
    #[tokio::test]
    async fn gitops_apply_emits_upstream_mapping_changed_on_delete() {
        let h = build_harness();
        let with_mapping = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env_with_secret(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
                "DOCKERHUB_TOKEN",
            )],
            ..Default::default()
        };
        h.uc.apply(with_mapping, env_oidc()).await.unwrap();
        let repo = h.repos.find_by_key("oci-mirror-e2e").await.unwrap();

        // Re-apply with the mapping omitted.
        let without_mapping = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![],
            ..Default::default()
        };
        h.uc.apply(without_mapping, env_oidc()).await.unwrap();

        let on_repo = repo_stream_events(&h.events, repo.id).await;
        let removed: Vec<&RUMC> = on_repo
            .iter()
            .filter_map(|e| match e {
                DE::RepositoryUpstreamMappingChanged(r) => Some(r),
                _ => None,
            })
            .filter(|r| r.change == UMC::Removed)
            .collect();
        assert_eq!(
            removed.len(),
            1,
            "expected one Removed event after mapping deleted; got {}",
            removed.len()
        );
        assert_eq!(
            removed[0].previous_secret_ref.as_deref(),
            Some("env_var:DOCKERHUB_TOKEN")
        );
        assert_eq!(removed[0].new_secret_ref, None);
        assert_eq!(
            removed[0].previous_url.as_deref(),
            Some("https://registry-1.docker.io")
        );
        assert_eq!(removed[0].new_url, None);
    }

    /// Direct unit test for the secret_ref_name helper. Pins the
    /// `<source>:<location>` wire form for both backends.
    #[test]
    fn secret_ref_name_env_var_form() {
        let r = SecretRef {
            source: SecretSource::EnvVar,
            location: "DOCKERHUB_TOKEN".into(),
        };
        assert_eq!(secret_ref_name(&r), "env_var:DOCKERHUB_TOKEN");
    }

    #[test]
    fn secret_ref_name_file_form() {
        let r = SecretRef {
            source: SecretSource::File,
            location: "/run/secrets/ghcr-token".into(),
        };
        assert_eq!(secret_ref_name(&r), "file:/run/secrets/ghcr-token");
    }

    /// Empty PermissionGrant plan must produce no append on either
    /// the Authorization or any Repository stream — bookend to the
    /// `empty_role_plan_appends_no_authorization_event` test.
    #[tokio::test]
    async fn empty_permission_grant_plan_appends_no_audit_event() {
        let h = build_harness();
        let baseline = h.events.appended().len();
        h.uc.apply(DesiredState::default(), env_oidc())
            .await
            .unwrap();
        let after = h.events.appended();
        let new = &after[baseline..];
        let any_pg = new.iter().any(|b| {
            b.events.iter().any(|e| {
                matches!(
                    e.event,
                    DomainEvent::PermissionGrantApplied(_) | DomainEvent::PermissionGrantRevoked(_)
                )
            })
        });
        assert!(
            !any_pg,
            "empty PermissionGrant plan must emit no audit events"
        );
    }

    /// Empty UpstreamMapping plan must produce no
    /// `RepositoryUpstreamMappingChanged` event.
    #[tokio::test]
    async fn empty_upstream_mapping_plan_appends_no_audit_event() {
        let h = build_harness();
        let baseline = h.events.appended().len();
        h.uc.apply(DesiredState::default(), env_oidc())
            .await
            .unwrap();
        let after = h.events.appended();
        let new = &after[baseline..];
        let any_mapping = new.iter().any(|b| {
            b.events
                .iter()
                .any(|e| matches!(e.event, DomainEvent::RepositoryUpstreamMappingChanged(_)))
        });
        assert!(
            !any_mapping,
            "empty UpstreamMapping plan must emit no audit events"
        );
    }

    // ===================================================================
    // Upstream allowlist policy.
    //
    // The tri-state `UpstreamHostAllowlist` has three variants:
    //   - `Disabled` (default; legacy posture)
    //   - `Strict`   (literal `__deny_all__` sentinel; bootstrap mode)
    //   - `Hosts(_)` (operator-enumerated allowlist; production mode)
    //
    // The tests below cover each shape end-to-end through the apply
    // pipeline plus the parser-level footgun guards (empty-string ==
    // unset, pathological `,,,`, sentinel mid-list).
    // ===================================================================

    // --- parser tests (UpstreamHostAllowlist::parse) -------------------

    #[test]
    fn allowlist_parse_unset_is_disabled() {
        // Unset env var (`std::env::var` returned `Err(NotPresent)`) —
        // the safe default. Existing deployments must not regress.
        assert_eq!(
            UpstreamHostAllowlist::parse(None),
            UpstreamHostAllowlist::Disabled
        );
    }

    #[test]
    fn allowlist_parse_empty_string_is_disabled() {
        // The footgun guard. Operator wrote `HORT_UPSTREAM_ALLOWLIST_HOSTS=`
        // (k8s ConfigMap default, docker-compose `${VAR:-}`, shell
        // `export VAR=`); we treat it identically to unset rather
        // than as `Strict` — which would silently break every
        // upstream pull.
        assert_eq!(
            UpstreamHostAllowlist::parse(Some("")),
            UpstreamHostAllowlist::Disabled
        );
        // Whitespace-only is also the empty case.
        assert_eq!(
            UpstreamHostAllowlist::parse(Some("   ")),
            UpstreamHostAllowlist::Disabled
        );
    }

    #[test]
    fn allowlist_parse_strict_sentinel_is_strict() {
        assert_eq!(
            UpstreamHostAllowlist::parse(Some("__deny_all__")),
            UpstreamHostAllowlist::Strict
        );
        // The sentinel is exact-match only — wrapping whitespace is
        // allowed (a YAML editor may add it) but an extra trailing
        // host means "list with sentinel-as-host", which is just a
        // host list (the user clearly didn't want strict mode if
        // they listed a host alongside).
        assert_eq!(
            UpstreamHostAllowlist::parse(Some("  __deny_all__  ")),
            UpstreamHostAllowlist::Strict
        );
    }

    #[test]
    fn allowlist_parse_strict_sentinel_const_is_canonical() {
        // Pinned constant — typo in the use-case validation site
        // becomes a compile error rather than a silent posture flip.
        assert_eq!(UpstreamHostAllowlist::STRICT_SENTINEL, "__deny_all__");
    }

    #[test]
    fn allowlist_parse_single_host() {
        let parsed = UpstreamHostAllowlist::parse(Some("registry.npmjs.org"));
        match parsed {
            UpstreamHostAllowlist::Hosts(hs) => assert_eq!(hs, vec!["registry.npmjs.org"]),
            other => panic!("expected Hosts, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_parse_comma_list_trims_and_drops_empties() {
        // Input mirrors a real operator's potentially-messy YAML or
        // env file: trailing comma, doubled separator, padded spaces.
        let parsed =
            UpstreamHostAllowlist::parse(Some(" registry.npmjs.org , pypi.org ,, crates.io , "));
        match parsed {
            UpstreamHostAllowlist::Hosts(hs) => {
                assert_eq!(hs, vec!["registry.npmjs.org", "pypi.org", "crates.io"]);
            }
            other => panic!("expected Hosts, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_parse_only_commas_collapses_to_disabled() {
        // `HORT_UPSTREAM_ALLOWLIST_HOSTS=,,,,` reduces to zero hosts after
        // trimming. The same safety as the empty-string case applies:
        // collapse to `Disabled` instead of `Hosts(vec![])` (which
        // would reject every mapping silently — same footgun class).
        assert_eq!(
            UpstreamHostAllowlist::parse(Some(",,,")),
            UpstreamHostAllowlist::Disabled
        );
    }

    // --- permits() lookup ----------------------------------------------

    #[test]
    fn allowlist_permits_disabled_passes_every_host() {
        let a = UpstreamHostAllowlist::Disabled;
        assert!(a.permits("anything.example.com"));
        assert!(a.permits("evil.attacker.test"));
    }

    #[test]
    fn allowlist_permits_strict_rejects_every_host() {
        let a = UpstreamHostAllowlist::Strict;
        assert!(!a.permits("registry.npmjs.org"));
        assert!(!a.permits("pypi.org"));
    }

    #[test]
    fn allowlist_permits_hosts_exact_match_only() {
        let a = UpstreamHostAllowlist::Hosts(vec![
            "registry.npmjs.org".to_string(),
            "pypi.org".to_string(),
        ]);
        assert!(a.permits("registry.npmjs.org"));
        assert!(a.permits("pypi.org"));
        // No suffix matching by design — `*.example.com` is NOT
        // implemented (out of scope here).
        assert!(!a.permits("subdomain.registry.npmjs.org"));
        assert!(!a.permits("registry-1.docker.io"));
        // Case-sensitive — same as URL host comparison; if the
        // operator types `Pypi.org` they get a miss (loud) rather
        // than a silent normalisation.
        assert!(!a.permits("Pypi.org"));
    }

    // --- end-to-end apply behaviour -----------------------------------

    /// Default-posture preservation: `Disabled` allowlist accepts
    /// every mapping, just like the historical unfiltered posture.
    #[tokio::test]
    async fn allowlist_disabled_accepts_any_host() {
        let h = build_harness_with_allowlist(UpstreamHostAllowlist::Disabled);
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-anywhere",
                "oci-mirror",
                "anywhere/",
                "https://anywhere.example.test",
            )],
            ..Default::default()
        };
        h.uc.apply(desired, env_oidc())
            .await
            .expect("Disabled allowlist must accept any host");
        assert_eq!(h.upstream.entry_count(), 1, "mapping must persist");
    }

    /// Strict mode rejects EVERY mapping — even the most innocent-
    /// looking public registry. Bootstrap-only deployments rely on
    /// this.
    #[tokio::test]
    async fn allowlist_strict_rejects_every_mapping() {
        let h = build_harness_with_allowlist(UpstreamHostAllowlist::Strict);
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        let err =
            h.uc.apply(desired, env_oidc())
                .await
                .expect_err("Strict allowlist must reject all mappings");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("registry-1.docker.io"),
                    "error must name the rejected host, got: {msg}"
                );
                assert!(
                    msg.contains("HORT_UPSTREAM_ALLOWLIST_HOSTS"),
                    "error must point operator at the env var, got: {msg}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
        // Strict-atomic: no row was saved.
        assert_eq!(
            h.upstream.entry_count(),
            0,
            "no mapping must persist after rejection"
        );
    }

    /// Issue #8 regression (boot park). An un-allowlisted upstream host is
    /// caught in the PRE-WRITE `preflight_validate` pass and surfaces as a
    /// `DomainError::Validation`, which `gitops_boot` maps to the
    /// park-eligible `GitopsBootError::PreflightValidate` — so the pod parks
    /// not-ready instead of writing Stage-1/2 rows and crashlooping.
    #[tokio::test]
    async fn preflight_validate_parks_on_un_allowlisted_upstream_host() {
        let h = build_harness_with_allowlist(UpstreamHostAllowlist::Hosts(vec![
            "registry.npmjs.org".to_string(),
        ]));
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        let err =
            h.uc.preflight_validate(&desired, &env_oidc())
                .await
                .expect_err("preflight must reject an un-allowlisted upstream host pre-write");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("registry-1.docker.io"),
                    "preflight error must name the rejected host, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
    }

    /// Issue #8 regression (no partial write). When an upstream host is not
    /// allowlisted, `apply` aborts in the pre-write pass, so NO repository
    /// row is written. The pre-fix path wrote Stage-2 repositories and then
    /// failed the Stage-3 allowlist check, leaving a half-applied config that
    /// crashlooped (a non-park `Apply` error) — this asserts zero repo writes.
    #[tokio::test]
    async fn apply_rejects_un_allowlisted_host_without_writing_repository_rows() {
        let h = build_harness_with_allowlist(UpstreamHostAllowlist::Hosts(vec![
            "registry.npmjs.org".to_string(),
        ]));
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h.uc.apply(desired, env_oidc())
            .await
            .expect_err("apply must reject an un-allowlisted upstream host");
        let repo_writes = h
            .repos
            .call_log
            .lock()
            .unwrap()
            .iter()
            .filter(|c| matches!(c, MockCall::SaveManaged(..)))
            .count();
        assert_eq!(
            repo_writes, 0,
            "no repository row must be written when apply is rejected pre-write (issue #8)"
        );
        assert_eq!(h.upstream.entry_count(), 0, "no mapping persisted");
    }

    /// Allowlist with the host present accepts the mapping.
    #[tokio::test]
    async fn allowlist_hosts_match_accepts_mapping() {
        let h = build_harness_with_allowlist(UpstreamHostAllowlist::Hosts(vec![
            "registry-1.docker.io".to_string(),
            "registry.npmjs.org".to_string(),
        ]));
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h.uc.apply(desired, env_oidc())
            .await
            .expect("listed host must be accepted");
        assert_eq!(h.upstream.entry_count(), 1);
    }

    /// Allowlist with a different host rejects the mapping with the
    /// specified error shape and increments the metric.
    #[test]
    fn allowlist_hosts_miss_rejects_with_metric() {
        let snap = crate::metrics::capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let h = build_harness_with_allowlist(UpstreamHostAllowlist::Hosts(vec![
                    // Operator allowed only npmjs; the mapping
                    // points at dockerhub which is NOT on the list.
                    "registry.npmjs.org".to_string(),
                ]));
                let desired = DesiredState {
                    repositories: vec![repo_env("oci-mirror", "proxy")],
                    upstream_mappings: vec![upstream_mapping_env(
                        "oci-mirror-dockerhub",
                        "oci-mirror",
                        "dockerhub/",
                        "https://registry-1.docker.io",
                    )],
                    ..Default::default()
                };
                let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
                match err {
                    AppError::Domain(DomainError::Validation(msg)) => {
                        assert!(
                            msg.contains("registry-1.docker.io"),
                            "error must name rejected host: {msg}"
                        );
                    }
                    other => panic!("expected Validation, got {other:?}"),
                }
            });
        });
        // Assert the metric fired with the right labels.
        let entries = snap.into_vec();
        let mut found = false;
        for (key, _, _, value) in &entries {
            let inner = key.key();
            if inner.name() != "hort_gitops_objects_total" {
                continue;
            }
            let labels: std::collections::HashMap<&str, &str> =
                inner.labels().map(|l| (l.key(), l.value())).collect();
            if labels.get("kind") == Some(&"upstream_mapping")
                && labels.get("result") == Some(&"rejected_not_in_allowlist")
            {
                if let metrics_util::debugging::DebugValue::Counter(v) = value {
                    assert!(*v >= 1, "counter must increment");
                    found = true;
                }
            }
        }
        assert!(
            found,
            "hort_gitops_objects_total{{kind=upstream_mapping,result=rejected_not_in_allowlist}} \
             must fire on rejection"
        );
    }

    /// Mixed plan: one allowed mapping + one disallowed mapping. The
    /// apply must abort on the first miss with no partial save —
    /// strict-atomic posture (matches the broader gitops apply
    /// contract).
    #[tokio::test]
    async fn allowlist_hosts_aborts_apply_strict_atomic() {
        let h = build_harness_with_allowlist(UpstreamHostAllowlist::Hosts(vec![
            "registry.npmjs.org".to_string(),
        ]));
        let desired = DesiredState {
            repositories: vec![
                repo_env("npm-mirror", "proxy"),
                repo_env("docker-mirror", "proxy"),
            ],
            upstream_mappings: vec![
                upstream_mapping_env(
                    "npm-mirror-up",
                    "npm-mirror",
                    "npm/",
                    "https://registry.npmjs.org",
                ),
                upstream_mapping_env(
                    "docker-mirror-up",
                    "docker-mirror",
                    "dockerhub/",
                    "https://registry-1.docker.io",
                ),
            ],
            ..Default::default()
        };
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
        // Strict-atomic: NO mapping was saved (the allowed one would
        // have been written by `save_managed` if the gate ran
        // mapping-by-mapping mid-loop; the gate runs as a pre-pass
        // so an early reject blocks ALL writes).
        assert_eq!(
            h.upstream.entry_count(),
            0,
            "strict-atomic: no mapping must persist when any one is rejected"
        );
    }

    /// URL parse failure surfaces as a distinct validation error,
    /// NOT as a `rejected_not_in_allowlist` increment. Conflating
    /// the two would muddy the metric.
    #[test]
    fn allowlist_unparseable_url_does_not_emit_allowlist_miss_metric() {
        let snap = crate::metrics::capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let h = build_harness_with_allowlist(UpstreamHostAllowlist::Hosts(vec![
                    "registry.npmjs.org".to_string(),
                ]));
                let desired = DesiredState {
                    repositories: vec![repo_env("oci-mirror", "proxy")],
                    upstream_mappings: vec![upstream_mapping_env(
                        "oci-mirror-bad",
                        "oci-mirror",
                        "dockerhub/",
                        // Missing scheme — `url::Url::parse` will
                        // reject this. The use case must surface
                        // the parse error path, not the allowlist
                        // miss path.
                        "not-a-url",
                    )],
                    ..Default::default()
                };
                let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
                match err {
                    AppError::Domain(DomainError::Validation(msg)) => {
                        assert!(
                            !msg.contains("not in HORT_UPSTREAM_ALLOWLIST_HOSTS"),
                            "URL parse failure must not be classified as an allowlist miss: {msg}"
                        );
                    }
                    other => panic!("expected Validation error, got {other:?}"),
                }
            });
        });
        // Assert the rejected_not_in_allowlist metric DID NOT fire.
        let entries = snap.into_vec();
        for (key, _, _, _) in &entries {
            let inner = key.key();
            if inner.name() != "hort_gitops_objects_total" {
                continue;
            }
            let labels: std::collections::HashMap<&str, &str> =
                inner.labels().map(|l| (l.key(), l.value())).collect();
            assert_ne!(
                labels.get("result"),
                Some(&"rejected_not_in_allowlist"),
                "URL parse failure must NOT bump the allowlist-miss counter"
            );
        }
    }

    /// Delete-row exemption: the gate runs only over `plan.create` +
    /// `plan.update`. Removing a mapping that was previously
    /// permitted under a looser allowlist must succeed regardless of
    /// the now-tighter allowlist — otherwise tightening the
    /// allowlist would also block GC of mappings the operator wants
    /// gone. (Apply-time-only enforcement.)
    #[tokio::test]
    async fn allowlist_delete_path_exempt_from_host_check() {
        // First apply: write the mapping under `Disabled` (legacy
        // posture; the operator might have rolled an allowlist out
        // AFTER the mapping was already in production).
        let h_seed = build_harness_with_allowlist(UpstreamHostAllowlist::Disabled);
        let with_mapping = DesiredState {
            repositories: vec![repo_env("oci-mirror", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h_seed.uc.apply(with_mapping, env_oidc()).await.unwrap();
        assert_eq!(h_seed.upstream.entry_count(), 1);

        // Second apply: rebuild a harness whose mock state mirrors
        // `h_seed`'s upstream snapshot, but tighten the allowlist
        // and drop the mapping from desired. The diff classifies
        // the row as `delete`. The gate must NOT block the delete.
        //
        // Note: the mock repos all share state through Arc but are
        // distinct instances per harness. Re-using the same
        // `h_seed` is the simplest model — the harness exposes the
        // use case with the seeded upstream snapshot and we just
        // re-construct the use case with the new allowlist by
        // reaching into Arc clones.
        let h = h_seed; // alias for clarity
        let strict_uc = ApplyConfigUseCase::new(
            h.repos.clone(),
            h.claim_mappings.clone(),
            h.grant_repo.clone(),
            h.authority.clone(),
            h.rule_repo.clone(),
            h.proj.clone(),
            Arc::new(PolicyUseCase::new(
                crate::event_store_publisher::wrap_for_test(h.events.clone()),
                h.proj.clone(),
                h.artifacts.clone(),
                h.lifecycle.clone(),
                Arc::new(crate::use_cases::test_support::MockStoragePort::new()),
                default_repository_access_for_policy(),
                Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new()),
                Arc::new(crate::use_cases::test_support::MockJobsRepository::default()),
            )),
            h.artifacts.clone(),
            h.lifecycle.clone(),
            crate::event_store_publisher::wrap_for_test(h.events.clone()),
            h.upstream.clone(),
            UpstreamHostAllowlist::Hosts(vec!["registry.npmjs.org".to_string()]),
            h.content_refs.clone(),
            h.oidc_issuers.clone(),
            h.service_accounts.clone(),
            h.users.clone(),
            Arc::new(["npm".to_string()].into_iter().collect()),
            // No retention projection in this harness. Explicit,
            // not inherited: the slot is a required argument so a
            // composition that skips retention says so, and the
            // apply warns on every envelope it then drops.
            None,
        );
        let without_mapping = DesiredState {
            repositories: vec![repo_env("oci-mirror", "proxy")],
            upstream_mappings: vec![],
            ..Default::default()
        };
        strict_uc
            .apply(without_mapping, env_oidc())
            .await
            .expect("delete path must not be gated by the allowlist");
        assert_eq!(
            h.upstream.entry_count(),
            0,
            "the mapping must be deleted regardless of allowlist state"
        );
    }

    // ------------------------------------------------------------------
    // Apply-time scan-backend validation.
    //
    // The validator (`hort_config::desired::validate_scan_policy_backends`)
    // is unit-tested in `hort-config`; these tests pin the *wiring* — that
    // `ApplyConfigUseCase::apply` invokes it against the compiled-in
    // `crate::scanning::KNOWN_SCAN_BACKENDS` set (NOT the live
    // `scanner_registry`) before the diff/apply stage. Validating against
    // the static set is what makes a correct `scanBackends: [trivy]` policy
    // apply on a fresh boot with zero workers registered (regression H20);
    // `build_harness()` wires no scanner registry at all, so these tests
    // exercise exactly that no-workers posture.
    // ------------------------------------------------------------------

    /// Helper for the backend-validation tests — build a `ScanPolicy` with the
    /// supplied `scan_backends` list. Uses the same defaults as
    /// `scan_policy_env` for everything else.
    fn scan_policy_with_backends(name: &str, backends: Vec<&str>) -> Envelope<ScanPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ScanPolicy,
            metadata: Metadata { name: name.into() },
            spec: ScanPolicySpec {
                scope: ScopeSpec::Global,
                severity_threshold: "high".into(),
                quarantine_duration: "24h".into(),
                require_approval: true,
                provenance_mode: "verify_if_present".into(),
                provenance_backends: vec!["cosign".to_string()],
                provenance_identities: Vec::new(),
                max_artifact_age: None,
                license_policy: serde_json::Value::Null,
                scan_backends: backends.into_iter().map(str::to_string).collect(),
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
                enforcement: "reject".into(),
            },
        }
    }

    /// Apply re-declares a YAML for a
    /// policy whose projection was archived by a previous apply. The
    /// pipeline must reactivate the existing row (preserve `policy_id`
    /// + event-stream history) rather than minting a new policy_id and
    /// colliding on the UNIQUE-name constraint.
    #[tokio::test]
    async fn apply_reactivates_archived_policy_when_yaml_re_declares_same_name() {
        let h = build_harness();
        let policy_id = Uuid::new_v4();
        let now = Utc::now();
        h.proj.insert_active(ScanPolicyProjection {
            policy_id,
            name: "p1".into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: true,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: Some(90 * 24 * 3600),
            license_policy: serde_json::Value::Null,
            // The crucial bit — this row is archived. The previous
            // apply ran with the YAML absent, archived `p1`, and
            // left the row in `policy_projections`.
            archived: true,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            stream_version: 3,
            created_at: now,
            updated_at: now,
        });

        let mut desired = DesiredState::default();
        desired
            .scan_policies
            .push(scan_policy_with_backends("p1", vec!["trivy"]));

        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must reactivate, not collide");

        // Reactivation lands in the `updated` bucket, not `created` —
        // a new row would have been a unique-key violation against
        // the existing archived row.
        assert_eq!(
            report.created, 0,
            "apply must NOT take the create path when an archived row exists"
        );
        assert_eq!(
            report.updated, 1,
            "apply must reactivate (counted as updated)"
        );

        // The reactivation event landed on the existing stream
        // (same policy_id), not on a freshly minted one.
        let appends = h.events.appended();
        let reactivated_count = appends
            .iter()
            .flat_map(|a| &a.events)
            .filter(
                |e| matches!(&e.event, DomainEvent::PolicyReactivated(r) if r.policy_id == policy_id),
            )
            .count();
        assert_eq!(
            reactivated_count, 1,
            "exactly one PolicyReactivated must land on the existing policy stream"
        );

        // No PolicyCreated must fire — that would mint a new policy_id.
        let created_count = appends
            .iter()
            .flat_map(|a| &a.events)
            .filter(|e| matches!(&e.event, DomainEvent::PolicyCreated(_)))
            .count();
        assert_eq!(
            created_count, 0,
            "PolicyCreated must NOT fire when reactivation is the right branch"
        );
    }

    /// Apply succeeds when every entry in
    /// `ScanPolicy.scan_backends` is a supported (compiled-in) backend.
    /// Pins the happy path of the wiring.
    #[tokio::test]
    async fn apply_succeeds_when_scan_backends_are_supported() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .scan_policies
            .push(scan_policy_with_backends("p1", vec!["trivy"]));
        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed when scan_backends ⊆ KNOWN_SCAN_BACKENDS");
        assert_eq!(report.created, 1);
    }

    /// H20 regression. A correct `scan_backends: [trivy]` policy must apply
    /// even though NO scanner worker has registered — the production
    /// boot-race posture (`build_harness()` wires no scanner registry at
    /// all). The previous build validated `scan_backends` against the live
    /// `scanner_registry`, so on a fresh deploy this rejected fail-closed and
    /// parked the server not-ready with no retry. Validating against the
    /// compiled-in `KNOWN_SCAN_BACKENDS` set removes the race.
    #[tokio::test]
    async fn apply_succeeds_for_known_backend_without_live_workers() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .scan_policies
            .push(scan_policy_with_backends("p1", vec!["trivy"]));
        let report = h.uc.apply(desired, env_oidc()).await.expect(
            "H20: a correct scan_backends:[trivy] policy must apply with zero workers registered",
        );
        assert_eq!(report.created, 1);
    }

    /// Apply rejects an unsupported `scan_backends`
    /// entry with a `Validation` error. Without the wiring, this test
    /// fails because `apply` returns `Ok` (the misconfiguration only
    /// surfaces at runtime as a `tracing::warn!` from the orchestrator).
    #[tokio::test]
    async fn apply_rejects_unknown_scan_backend_with_validation_error() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .scan_policies
            .push(scan_policy_with_backends("p1", vec!["grype"]));
        let err =
            h.uc.apply(desired, env_oidc())
                .await
                .expect_err("apply must reject an unsupported scan_backends entry");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("grype"),
                    "validation error must name the offending backend, got: {msg}"
                );
                assert!(
                    msg.contains("trivy"),
                    "validation error must list the supported names so the operator \
                     spots the typo, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
    }

    /// Empty `scan_backends` is the operator opt-out
    /// path: the policy is valid (ADR 0007 `ScanWaived`). The validator's
    /// empty-input rule (see `validate_scan_policy_backends` rustdoc) must
    /// keep working through the wiring.
    #[tokio::test]
    async fn apply_accepts_empty_scan_backends() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .scan_policies
            .push(scan_policy_with_backends("p1", vec![]));
        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must accept opt-out (empty scan_backends)");
        assert_eq!(report.created, 1);
    }

    /// A `DesiredState` with no `ScanPolicy`
    /// envelopes still runs the validator (which iterates an empty list and
    /// returns no errors) and apply proceeds. Pins that the wiring does NOT
    /// special-case an empty `desired.scan_policies` — the check is harmless
    /// and uniform.
    #[tokio::test]
    async fn apply_with_no_scan_policy_skips_backend_validation() {
        let h = build_harness();
        let desired = DesiredState::default();
        let _report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed when desired has no scan policies");
    }

    // ===================================================================
    // Gitops apply linter rejecting the
    // cross-opt-in collapse `trust_upstream_publish_time = true` AND
    // resolved `ScanPolicy.scan_backends.is_empty()`. The interaction
    // collapses the release gate's observation-window mitigation: a
    // publish-time-trusted
    // upstream serving an artifact with an epoch publish-time, governed
    // by a scan-waived policy, releases on `quarantine_until <= now()`
    // alone (observation window ≤ sweep-tick). The linter is fail-closed
    // — no escape hatch; operator recourse is amend the policy or split
    // the upstream mapping. See ADR 0016.
    // ===================================================================

    /// Apply rejects the combination at the gitops boundary.
    /// The mapping has `trust_upstream_publish_time = true`; the
    /// scoped scan policy waives scanning (`scan_backends = []`).
    /// The rejection mirrors `validate_scan_policy_backends`'s shape:
    /// `AppError::Domain(DomainError::Validation(message))`. The
    /// message names the offending `(repo_key, upstream_url,
    /// policy_key)` tuple so the operator sees which combination
    /// tripped the rule. The `hort_apply_config_linter_total{rule,
    /// result=reject}` counter ticks with the
    /// `trust_upstream_publish_time_requires_scan_backends` rule key.
    #[test]
    fn apply_rejects_trust_upstream_publish_time_when_resolved_policy_waives_scanning() {
        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut mapping_env = upstream_mapping_env(
                    "oci-mirror-dockerhub",
                    "oci-mirror-e2e",
                    "dockerhub/",
                    "https://registry-1.docker.io",
                );
                mapping_env.spec.trust_upstream_publish_time = true;
                // Scoped policy waives scanning. Apply-time validation
                // must reject the combination before any diff/apply
                // stage runs.
                let policy_env =
                    scan_policy_with_repo_scope_and_backends("p1", "oci-mirror-e2e", vec![]);
                let desired = DesiredState {
                    repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
                    upstream_mappings: vec![mapping_env],
                    scan_policies: vec![policy_env],
                    ..Default::default()
                };
                captured_err = Some(h.uc.apply(desired, env_oidc()).await.expect_err(
                    "apply must reject trust_upstream_publish_time + scan_backends:[]",
                ));
            });
        });
        let err = captured_err.expect("apply must have errored");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("oci-mirror-e2e"),
                    "validation error must name the offending repo key, got: {msg}"
                );
                assert!(
                    msg.contains("https://registry-1.docker.io"),
                    "validation error must name the offending upstream URL, got: {msg}"
                );
                assert!(
                    msg.contains("p1"),
                    "validation error must name the offending policy key, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        // The linter metric ticked with the new rule key and result=reject.
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "trust_upstream_publish_time_requires_scan_backends"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once for the offending mapping",
        );
    }

    /// The resolved scan policy runs a scanner, so the publish-time
    /// opt-in is permitted. The apply pipeline proceeds normally
    /// (Gate 2 is still operative; the cross-opt-in collapse does not
    /// occur). The linter metric does NOT tick a `reject` result for
    /// this rule.
    #[test]
    fn apply_accepts_trust_upstream_publish_time_when_resolved_policy_runs_scanner() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut mapping_env = upstream_mapping_env(
                    "oci-mirror-dockerhub",
                    "oci-mirror-e2e",
                    "dockerhub/",
                    "https://registry-1.docker.io",
                );
                mapping_env.spec.trust_upstream_publish_time = true;
                let policy_env =
                    scan_policy_with_repo_scope_and_backends("p1", "oci-mirror-e2e", vec!["trivy"]);
                let desired = DesiredState {
                    repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
                    upstream_mappings: vec![mapping_env],
                    scan_policies: vec![policy_env],
                    ..Default::default()
                };
                h.uc.apply(desired, env_oidc())
                    .await
                    .expect("apply must succeed: publish-time-trusted + scanner-runs");
            });
        });
        // No reject for the new rule under the happy path.
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "trust_upstream_publish_time_requires_scan_backends"),
                    ("result", "reject"),
                ],
            ),
            0,
            "linter metric must NOT tick reject when the resolved policy runs a scanner",
        );
    }

    // ===================================================================
    // Gitops apply linter rejecting an
    // inert `PrefetchPolicy.max_age_days`. The field is honoured by the
    // schema (the column lives in `repositories`) but the
    // planner ignores it — operators setting `maxAgeDays: 90` get no
    // enforcement. The architect anti-pattern *"Policy field accepted
    // at apply, inert at runtime"* is a hard block; the
    // apply-time linter closes the rule on its canonical exemplar. The
    // field stays in the schema for forward-compat: a future prefetch
    // surface extension can ship per-version timestamp gating and the
    // linter line goes away. See ADR 0015.
    // ===================================================================

    /// Apply rejects a `PrefetchPolicy.max_age_days = Some(_)`
    /// envelope at the gitops boundary. The rejection mirrors
    /// `validate_scan_policy_backends`'s shape:
    /// `AppError::Domain(DomainError::Validation(message))`. The
    /// message names the offending `repo_key` plus the operator-
    /// actionable pointer ("Remove the field to apply.") and the
    /// `hort_apply_config_linter_total{rule,result=reject}` counter
    /// ticks with the new `prefetch_max_age_days_not_implemented`
    /// rule key.
    #[test]
    fn apply_rejects_prefetch_policy_with_max_age_days_set() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};

        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut env = repo_env("npm-with-inert-max-age", "proxy");
                env.spec.prefetch_policy = PrefetchPolicy {
                    enabled: true,
                    triggers: vec![PrefetchTrigger::Scheduled],
                    max_age_days: Some(90),
                    ..PrefetchPolicy::default()
                };
                let mut desired = DesiredState::default();
                desired.repositories.push(env);
                captured_err =
                    Some(h.uc.apply(desired, env_oidc()).await.expect_err(
                        "apply must reject prefetch_policy with max_age_days = Some(_)",
                    ));
            });
        });
        let err = captured_err.expect("apply must have errored");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("npm-with-inert-max-age"),
                    "validation error must name the offending repo key, got: {msg}"
                );
                assert!(
                    msg.contains("maxAgeDays") || msg.contains("max_age_days"),
                    "validation error must name the offending field, got: {msg}"
                );
                assert!(
                    msg.contains("not yet implemented"),
                    "validation error must surface the operator-actionable pointer, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "prefetch_max_age_days_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once for the offending PrefetchPolicy",
        );
    }

    /// Happy path: a `PrefetchPolicy` with `max_age_days = None` (the
    /// default) passes the linter cleanly. The linter metric does NOT
    /// tick a `reject` result for this rule.
    #[test]
    fn apply_accepts_prefetch_policy_with_max_age_days_none() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};

        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut env = repo_env("npm-no-inert-max-age", "proxy");
                env.spec.prefetch_policy = PrefetchPolicy {
                    enabled: true,
                    triggers: vec![PrefetchTrigger::Scheduled],
                    max_age_days: None,
                    ..PrefetchPolicy::default()
                };
                let mut desired = DesiredState::default();
                desired.repositories.push(env);
                h.uc.apply(desired, env_oidc())
                    .await
                    .expect("apply must succeed when max_age_days is None");
            });
        });
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "prefetch_max_age_days_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            0,
            "linter metric must NOT tick reject when max_age_days is None",
        );
    }

    // ===================================================================
    // Gitops apply linter rejecting a `PrefetchPolicy.triggers` entry a
    // repository's format cannot honour (row 6b). `transitive_deps` and
    // `scheduled` both require the format's handler to declare the
    // `VersionDiscovery` capability group (ADR 0005); `on_dist_tag_move`
    // does not (OCI fires it today with no `VersionDiscovery`
    // implementation) and must never be rejected. The capability set is a
    // required `ApplyConfigUseCase::new` argument — `build_harness`
    // supplies `{"npm"}` as its default test posture, and these tests
    // override it via `with_version_discovery_capable_formats` to
    // exercise both the rejecting and the accepting side of the rule.
    // ===================================================================

    /// A `transitive_deps` trigger on a format absent from the wired
    /// capability set is rejected, naming the repository, the format, and
    /// the offending trigger; the linter metric ticks once.
    #[test]
    fn apply_rejects_transitive_deps_trigger_on_non_version_discovery_format() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};

        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let uc =
                    h.uc.with_version_discovery_capable_formats(["npm".to_string()]);
                let mut env = repo_env("maven-transitive", "proxy");
                env.spec.format = "maven".into();
                env.spec.prefetch_policy = PrefetchPolicy {
                    enabled: true,
                    triggers: vec![PrefetchTrigger::TransitiveDeps],
                    ..PrefetchPolicy::default()
                };
                let mut desired = DesiredState::default();
                desired.repositories.push(env);
                captured_err = Some(uc.apply(desired, env_oidc()).await.expect_err(
                    "apply must reject transitive_deps on a non-VersionDiscovery format",
                ));
            });
        });
        let err = captured_err.expect("apply must have errored");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(msg.contains("maven-transitive"), "got: {msg}");
                assert!(msg.contains("maven"), "got: {msg}");
                assert!(msg.contains("transitive_deps"), "got: {msg}");
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "prefetch_trigger_requires_version_discovery"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once for the offending trigger",
        );
    }

    /// A `scheduled` trigger on a format absent from the wired capability
    /// set is rejected the same way.
    #[test]
    fn apply_rejects_scheduled_trigger_on_non_version_discovery_format() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc =
                h.uc.with_version_discovery_capable_formats(["npm".to_string()]);
            let mut env = repo_env("helm-scheduled", "proxy");
            env.spec.format = "helm".into();
            env.spec.prefetch_policy = PrefetchPolicy {
                enabled: true,
                triggers: vec![PrefetchTrigger::Scheduled],
                ..PrefetchPolicy::default()
            };
            let mut desired = DesiredState::default();
            desired.repositories.push(env);
            let err = uc
                .apply(desired, env_oidc())
                .await
                .expect_err("apply must reject scheduled on a non-VersionDiscovery format");
            match err {
                AppError::Domain(DomainError::Validation(msg)) => {
                    assert!(msg.contains("helm-scheduled"), "got: {msg}");
                    assert!(msg.contains("scheduled"), "got: {msg}");
                }
                other => {
                    panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}")
                }
            }
        });
    }

    /// `on_dist_tag_move` never requires `VersionDiscovery` — OCI fires it
    /// today with no such implementation. A repository declaring only
    /// this trigger on a format absent from the capability set still
    /// applies cleanly.
    #[test]
    fn apply_accepts_on_dist_tag_move_trigger_on_non_version_discovery_format() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc =
                h.uc.with_version_discovery_capable_formats(["npm".to_string()]);
            let mut env = repo_env("oci-tag-move", "proxy");
            env.spec.format = "oci".into();
            env.spec.prefetch_policy = PrefetchPolicy {
                enabled: true,
                triggers: vec![PrefetchTrigger::OnDistTagMove],
                ..PrefetchPolicy::default()
            };
            let mut desired = DesiredState::default();
            desired.repositories.push(env);
            uc.apply(desired, env_oidc())
                .await
                .expect("on_dist_tag_move must apply cleanly on any format");
        });
    }

    /// A `transitive_deps` trigger on a format the wired capability set
    /// DOES include applies cleanly.
    #[test]
    fn apply_accepts_transitive_deps_trigger_on_version_discovery_format() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc =
                h.uc.with_version_discovery_capable_formats(["npm".to_string()]);
            let mut env = repo_env("npm-transitive", "proxy");
            env.spec.prefetch_policy = PrefetchPolicy {
                enabled: true,
                triggers: vec![PrefetchTrigger::TransitiveDeps],
                ..PrefetchPolicy::default()
            };
            let mut desired = DesiredState::default();
            desired.repositories.push(env);
            uc.apply(desired, env_oidc())
                .await
                .expect("transitive_deps must apply cleanly on a VersionDiscovery-capable format");
        });
    }

    /// `build_harness`'s default capability set (`{"npm"}`) is itself the
    /// live proof the rule is not skippable: a `transitive_deps` trigger
    /// on maven — a format absent from that default, with no override —
    /// is rejected through the harness's own baseline construction, not
    /// through a test-specific opt-in.
    #[test]
    fn apply_rejects_trigger_on_non_capable_format_via_harness_default_capability_set() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};

        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut env = repo_env("maven-default-set", "proxy");
                env.spec.format = "maven".into();
                env.spec.prefetch_policy = PrefetchPolicy {
                    enabled: true,
                    triggers: vec![PrefetchTrigger::TransitiveDeps],
                    ..PrefetchPolicy::default()
                };
                let mut desired = DesiredState::default();
                desired.repositories.push(env);
                captured_err = Some(h.uc.apply(desired, env_oidc()).await.expect_err(
                    "the harness's own default capability set must reject a non-capable format",
                ));
            });
        });
        let err = captured_err.expect("apply must have errored");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(msg.contains("maven-default-set"), "got: {msg}");
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "prefetch_trigger_requires_version_discovery"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once — the rule is not skippable",
        );
    }

    // ===================================================================
    // Gitops apply linter rejecting a `RetentionPolicy` predicate that
    // uses `UnusedFor` (row 9). No port supplies a last-download anchor,
    // so the evaluator measures from the creation time and `UnusedFor(N)`
    // silently decides what `AgeExceeds(N)` decides.
    // ===================================================================

    /// A `RetentionPolicy` envelope over `AllRepos` carrying `predicate`
    /// verbatim (the wire form is an opaque `serde_json::Value`).
    fn retention_policy_env_for_apply(
        name: &str,
        predicate: serde_json::Value,
    ) -> Envelope<hort_config::retention_policy::RetentionPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::RetentionPolicy,
            metadata: Metadata { name: name.into() },
            spec: hort_config::retention_policy::RetentionPolicySpec {
                predicate,
                scope: serde_json::json!("AllRepos"),
            },
        }
    }

    /// The pre-write pass rejects `UnusedFor` — nested inside a
    /// `Composite`, which is the case a root-only rule would let through —
    /// and ticks `hort_apply_config_linter_total` once for the envelope.
    #[test]
    fn apply_rejects_retention_policy_with_nested_unused_for() {
        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let desired = DesiredState {
                    retention_policies: vec![retention_policy_env_for_apply(
                        "reclaim-cold-nested",
                        serde_json::json!({
                            "Composite": [
                                "Or",
                                [{ "AgeExceeds": 2_592_000u64 }, { "UnusedFor": 7_776_000u64 }]
                            ]
                        }),
                    )],
                    ..Default::default()
                };
                captured_err = Some(
                    h.uc.preflight_validate(&desired, &env_oidc())
                        .await
                        .expect_err("apply must reject a predicate using UnusedFor"),
                );
            });
        });
        let err = captured_err.expect("apply must have errored");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("reclaim-cold-nested"),
                    "validation error must name the offending policy, got: {msg}"
                );
                assert!(
                    msg.contains("UnusedFor"),
                    "validation error must name the offending predicate, got: {msg}"
                );
                assert!(
                    msg.contains("AgeExceeds"),
                    "validation error must name the alternative, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "retention_unused_for_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once for the offending RetentionPolicy",
        );
    }

    /// `AgeExceeds` — the semantics `UnusedFor` accidentally delivers
    /// today — passes the pre-write pass untouched and ticks no reject.
    #[test]
    fn apply_accepts_retention_policy_with_age_exceeds() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let desired = DesiredState {
                    retention_policies: vec![retention_policy_env_for_apply(
                        "retain-90d",
                        serde_json::json!({ "AgeExceeds": 7_776_000u64 }),
                    )],
                    ..Default::default()
                };
                h.uc.preflight_validate(&desired, &env_oidc())
                    .await
                    .expect("AgeExceeds must pass the pre-write pass");
            });
        });
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "retention_unused_for_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            0,
            "linter metric must NOT tick reject for AgeExceeds",
        );
    }

    // ===================================================================
    // Gitops apply linter rejecting the three further accepted-but-inert
    // operator surfaces (rows 10, 11, 12 — ADR 0015):
    //
    //   - `ScanPolicy.licensePolicy` — the scan path evaluates it against
    //     an empty licence list, so every rule in it matches nothing.
    //   - `Exclusion.scope` — the finding filter never reads it, so a
    //     waiver narrowed to one repository clears its CVE everywhere.
    //   - a `virtualMembers` entry's format — nothing compares it with
    //     the virtual's, so a member can own names for a format it does
    //     not serve.
    //
    // Each pair below is the acceptance shape the item asks for: the
    // field set fails the apply and ticks its rule's counter once; the
    // field absent or at its inert default applies and ticks nothing.
    // ===================================================================

    /// A declared `licensePolicy` fails the apply, naming the policy, the
    /// field and the missing enforcement, and ticks
    /// `scan_policy_license_policy_not_implemented` once.
    #[test]
    fn apply_rejects_scan_policy_with_a_declared_license_policy() {
        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut env = scan_policy_env("prod-with-licence-rules");
                env.spec.license_policy = serde_json::json!({
                    "denied_licenses": ["GPL-3.0"],
                    "action": "Block",
                });
                let desired = DesiredState {
                    scan_policies: vec![env],
                    ..Default::default()
                };
                captured_err = Some(
                    h.uc.apply(desired, env_oidc())
                        .await
                        .expect_err("apply must reject a declared licensePolicy"),
                );
            });
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("prod-with-licence-rules"),
                    "must name the offending policy, got: {msg}"
                );
                assert!(
                    msg.contains("licensePolicy"),
                    "must name the offending field, got: {msg}"
                );
                assert!(
                    msg.contains("not implemented") && msg.contains("empty licence list"),
                    "must say what is missing, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        assert_eq!(
            counter_value_for(
                &snap.into_vec(),
                "hort_apply_config_linter_total",
                &[
                    ("rule", "scan_policy_license_policy_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once for the offending ScanPolicy",
        );
    }

    /// Both inert forms still apply: `{}` (what every shipped example
    /// tree writes) and `null` (the omitted field). The rule removes an
    /// assurance; it must not change what a tree that never claimed it
    /// does.
    #[test]
    fn apply_accepts_scan_policy_with_an_inert_license_policy() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                for (what, value) in [
                    ("an empty object", serde_json::json!({})),
                    ("the omitted default", serde_json::Value::Null),
                ] {
                    let h = build_harness();
                    let mut env = scan_policy_env("prod-inert-licence");
                    env.spec.license_policy = value;
                    h.uc.apply(
                        DesiredState {
                            scan_policies: vec![env],
                            ..Default::default()
                        },
                        env_oidc(),
                    )
                    .await
                    .unwrap_or_else(|e| panic!("apply must succeed for {what}: {e:?}"));
                    assert!(
                        !h.events.appended().is_empty(),
                        "{what} must still create the policy — the accept side cannot \
                         pass vacuously"
                    );
                }
            });
        });
        assert_eq!(
            counter_value_for(
                &snap.into_vec(),
                "hort_apply_config_linter_total",
                &[
                    ("rule", "scan_policy_license_policy_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            0,
            "linter metric must NOT tick reject for an inert licensePolicy",
        );
    }

    /// A repository-scoped `Exclusion` fails the apply and ticks
    /// `exclusion_scope_not_implemented` once. The parent policy is
    /// declared and the scoped repository is declared, so neither the
    /// parent-reference rule nor a dangling reference is what refuses it.
    #[test]
    fn apply_rejects_exclusion_scoped_to_a_repository() {
        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut ex = exclusion_env("cve-on-one-repo", "prod-default", "CVE-2026-0001");
                ex.spec.scope = ScopeSpec::Repository(hort_config::scope::RepositoryScope {
                    repository: "npm-internal".into(),
                });
                let desired = DesiredState {
                    repositories: vec![repo_env("npm-internal", "hosted")],
                    scan_policies: vec![scan_policy_env("prod-default")],
                    exclusions: vec![ex],
                    ..Default::default()
                };
                captured_err = Some(
                    h.uc.apply(desired, env_oidc())
                        .await
                        .expect_err("apply must reject a repository-scoped exclusion"),
                );
            });
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("cve-on-one-repo") && msg.contains("npm-internal"),
                    "must name the exclusion and the repository it was scoped to, \
                     got: {msg}"
                );
                assert!(
                    msg.contains("not enforced") && msg.contains("never reads"),
                    "must say the control is missing, got: {msg}"
                );
                assert!(
                    msg.contains("scope: global"),
                    "must name the one accepted form, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        assert_eq!(
            counter_value_for(
                &snap.into_vec(),
                "hort_apply_config_linter_total",
                &[
                    ("rule", "exclusion_scope_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once for the offending Exclusion",
        );
    }

    /// `scope: global` — the inert default, and the only form the schema
    /// now accepts — applies and emits the `ExclusionAdded`.
    #[test]
    fn apply_accepts_exclusion_with_a_global_scope() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let desired = DesiredState {
                    scan_policies: vec![scan_policy_env("prod-default")],
                    exclusions: vec![exclusion_env(
                        "cve-everywhere",
                        "prod-default",
                        "CVE-2026-0002",
                    )],
                    ..Default::default()
                };
                h.uc.apply(desired, env_oidc())
                    .await
                    .expect("a global-scope exclusion must apply");
                assert!(
                    h.events.appended().iter().any(|b| b
                        .events
                        .iter()
                        .any(|e| matches!(e.event, DomainEvent::ExclusionAdded(_)))),
                    "the accept side must actually write the exclusion: {:?}",
                    h.events.appended()
                );
            });
        });
        assert_eq!(
            counter_value_for(
                &snap.into_vec(),
                "hort_apply_config_linter_total",
                &[
                    ("rule", "exclusion_scope_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            0,
            "linter metric must NOT tick reject for a global scope",
        );
    }

    /// A `virtualMembers` entry on another format fails the apply and
    /// ticks `virtual_member_format_not_enforced` once. The member is
    /// declared and non-virtual, so neither the dangling-member rule nor
    /// the no-nested-virtuals rule is what refuses it.
    #[test]
    fn apply_rejects_virtual_member_on_another_format() {
        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut virt = repo_env_with_format("all-npm", "virtual", "npm");
                virt.spec.virtual_members = Some(vec!["py-lib".into()]);
                let desired = DesiredState {
                    repositories: vec![virt, repo_env_with_format("py-lib", "hosted", "pypi")],
                    ..Default::default()
                };
                captured_err = Some(
                    h.uc.apply(desired, env_oidc())
                        .await
                        .expect_err("apply must reject a cross-format virtual member"),
                );
            });
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("all-npm") && msg.contains("py-lib"),
                    "must name the virtual and the offending member, got: {msg}"
                );
                assert!(
                    msg.contains("pypi") && msg.contains("npm"),
                    "must name both formats, got: {msg}"
                );
                assert!(
                    msg.contains("no format-compatibility check is implemented"),
                    "must say the control is missing, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        assert_eq!(
            counter_value_for(
                &snap.into_vec(),
                "hort_apply_config_linter_total",
                &[
                    ("rule", "virtual_member_format_not_enforced"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once for the offending member",
        );
    }

    /// A format-homogeneous virtual — the inert default, and every
    /// shipped example tree — applies unchanged.
    #[test]
    fn apply_accepts_virtual_member_on_the_same_format() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut virt = repo_env_with_format("all-npm", "virtual", "npm");
                virt.spec.virtual_members = Some(vec!["npm-internal".into()]);
                let desired = DesiredState {
                    repositories: vec![virt, repo_env_with_format("npm-internal", "hosted", "npm")],
                    ..Default::default()
                };
                h.uc.apply(desired, env_oidc())
                    .await
                    .expect("a same-format virtual must apply");
                assert!(
                    !h.repos.calls().is_empty(),
                    "the accept side must actually write the repositories"
                );
            });
        });
        assert_eq!(
            counter_value_for(
                &snap.into_vec(),
                "hort_apply_config_linter_total",
                &[
                    ("rule", "virtual_member_format_not_enforced"),
                    ("result", "reject"),
                ],
            ),
            0,
            "linter metric must NOT tick reject for a same-format member",
        );
    }

    /// A declared `maxArtifactAge` fails the apply, naming the policy,
    /// the field and the missing enforcement, and ticks
    /// `scan_policy_max_artifact_age_not_implemented` once.
    #[test]
    fn apply_rejects_scan_policy_with_a_declared_max_artifact_age() {
        use crate::metrics::capture_metrics;
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut env = scan_policy_env("prod-with-age-cap");
                env.spec.max_artifact_age = Some("90d".into());
                let desired = DesiredState {
                    scan_policies: vec![env],
                    ..Default::default()
                };
                captured_err = Some(
                    h.uc.apply(desired, env_oidc())
                        .await
                        .expect_err("apply must reject a declared maxArtifactAge"),
                );
            });
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("prod-with-age-cap"),
                    "must name the offending policy, got: {msg}"
                );
                assert!(
                    msg.contains("maxArtifactAge"),
                    "must name the offending field, got: {msg}"
                );
                assert!(
                    msg.contains("not implemented") && msg.contains("never evaluated"),
                    "must say what is missing, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
        assert_eq!(
            counter_value_for(
                &snap.into_vec(),
                "hort_apply_config_linter_total",
                &[
                    ("rule", "scan_policy_max_artifact_age_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            1,
            "linter metric must tick once for the offending ScanPolicy",
        );
    }

    /// The inert form — the absent field, which is what every shipped
    /// example tree writes — still applies. Unlike row 10 there is no
    /// accepted *value* to check beside it: `None` is the only inert
    /// state `Option<String>` has.
    #[test]
    fn apply_accepts_scan_policy_without_a_max_artifact_age() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut env = scan_policy_env("prod-no-age-cap");
                env.spec.max_artifact_age = None;
                h.uc.apply(
                    DesiredState {
                        scan_policies: vec![env],
                        ..Default::default()
                    },
                    env_oidc(),
                )
                .await
                .expect("an omitted maxArtifactAge must apply");
                assert!(
                    !h.events.appended().is_empty(),
                    "the accept side must still create the policy — it cannot pass \
                     vacuously"
                );
            });
        });
        assert_eq!(
            counter_value_for(
                &snap.into_vec(),
                "hort_apply_config_linter_total",
                &[
                    ("rule", "scan_policy_max_artifact_age_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            0,
            "linter metric must NOT tick reject for an omitted maxArtifactAge",
        );
    }

    // ===================================================================
    // `StaticConfigValidator` extraction.
    // (a) No-drift parity: the apply pre-write pass's static subset
    //     and `StaticConfigValidator::validate` agree on the reject SET
    //     (which rule aborts first).
    // (b) Apply-path metric byte-identity: rows 5/6 still tick
    //     `hort_apply_config_linter_total{rule,result}` ONCE PER offending
    //     envelope (not once per row), and the abort returns that rule's
    //     error — unchanged by the refactor.
    // ===================================================================

    /// For a corpus of bad configs, the rule the apply pre-write pass
    /// aborts on equals the FIRST-error-in-row-order rule
    /// `StaticConfigValidator::validate` reports. Rows 1/4 (env/DB) do not
    /// trip for these corpus configs (clean snapshot, default `trivy`
    /// registry), so the apply abort is exactly the static subset's first
    /// reject — proving no drift between `validate-config` and apply.
    #[tokio::test]
    async fn static_validator_and_apply_agree_on_reject_rule() {
        use crate::lint::{LinterRule, StaticConfigValidator};

        // Each corpus entry: (a builder of a bad DesiredState, the rule we
        // expect the static subset to abort on).
        struct Case {
            desired: DesiredState,
            expect_rule: LinterRule,
            effective_backend: Option<crate::storage_backend::EffectiveStorageBackend>,
        }

        let mut npm_max_age = repo_env("npm-inert", "proxy");
        npm_max_age.spec.prefetch_policy.max_age_days = Some(90);

        let mut s3_repo = repo_env("s3-on-fs", "hosted");
        s3_repo.spec.storage.as_mut().unwrap().backend = "s3".into();

        let cases = vec![
            // Row 2 — SA references an undeclared issuer.
            Case {
                desired: DesiredState {
                    service_accounts: vec![service_account_env_for_apply(
                        "ci",
                        Some("missing-idp"),
                    )],
                    ..Default::default()
                },
                expect_rule: LinterRule::SaIssuerFk,
                effective_backend: None,
            },
            // Row 5 — trust_upstream_publish_time × scan_backends:[].
            Case {
                desired: {
                    let mut m = upstream_mapping_env(
                        "m1",
                        "oci-mirror",
                        "dockerhub/",
                        "https://registry-1.docker.io",
                    );
                    m.spec.trust_upstream_publish_time = true;
                    DesiredState {
                        repositories: vec![repo_env("oci-mirror", "proxy")],
                        upstream_mappings: vec![m],
                        scan_policies: vec![scan_policy_with_repo_scope_and_backends(
                            "p1",
                            "oci-mirror",
                            vec![],
                        )],
                        ..Default::default()
                    }
                },
                expect_rule: LinterRule::TrustUpstreamPublishTimeRequiresScanBackends,
                effective_backend: None,
            },
            // Row 6 — inert PrefetchPolicy.max_age_days.
            Case {
                desired: DesiredState {
                    repositories: vec![npm_max_age],
                    ..Default::default()
                },
                expect_rule: LinterRule::PrefetchMaxAgeDaysNotImplemented,
                effective_backend: None,
            },
            // Row 7 — Required provenance on a no-verifier (npm) format.
            Case {
                desired: DesiredState {
                    repositories: vec![repo_env_with_format("npm-proxy", "proxy", "npm")],
                    scan_policies: vec![provenance_scan_policy_repo_scope(
                        "p-req-npm",
                        "npm-proxy",
                        "required",
                        vec!["cosign"],
                        vec![sample_identity_spec()],
                    )],
                    ..Default::default()
                },
                expect_rule: LinterRule::ProvenanceConfig,
                effective_backend: None,
            },
            // Row 7b — per-repo storage backend mismatch (needs a wired
            // effective backend).
            Case {
                desired: DesiredState {
                    repositories: vec![s3_repo],
                    ..Default::default()
                },
                expect_rule: LinterRule::RepoStorageBackendMismatch,
                effective_backend: Some(
                    crate::storage_backend::EffectiveStorageBackend::Filesystem,
                ),
            },
            // Row 7c — `osv` paired with an OCI repository (no SBOM
            // source, so the backend can never produce a verdict there).
            Case {
                desired: DesiredState {
                    repositories: vec![repo_env_with_format("oci-proxy", "proxy", "oci")],
                    scan_policies: vec![scan_policy_with_repo_scope_and_backends(
                        "p-oci-osv",
                        "oci-proxy",
                        vec!["osv"],
                    )],
                    ..Default::default()
                },
                expect_rule: LinterRule::ScanBackendCapability,
                effective_backend: None,
            },
            // Row 9 — a RetentionPolicy predicate using `UnusedFor`.
            Case {
                desired: DesiredState {
                    retention_policies: vec![retention_policy_env_for_apply(
                        "reclaim-cold",
                        serde_json::json!({ "UnusedFor": 7_776_000u64 }),
                    )],
                    ..Default::default()
                },
                expect_rule: LinterRule::RetentionUnusedForNotImplemented,
                effective_backend: None,
            },
            // Row 10 — a ScanPolicy declaring licence rules the scan
            // path evaluates against no licences.
            Case {
                desired: DesiredState {
                    scan_policies: vec![{
                        let mut env = scan_policy_env("p-licence");
                        env.spec.license_policy =
                            serde_json::json!({ "denied_licenses": ["GPL-3.0"] });
                        env
                    }],
                    ..Default::default()
                },
                expect_rule: LinterRule::ScanPolicyLicensePolicyNotImplemented,
                effective_backend: None,
            },
            // Row 11 — an Exclusion scoped to a repository the finding
            // filter never reads.
            Case {
                desired: DesiredState {
                    repositories: vec![repo_env("npm-internal", "hosted")],
                    scan_policies: vec![scan_policy_env("p-parent")],
                    exclusions: vec![{
                        let mut ex = exclusion_env("cve-scoped", "p-parent", "CVE-2026-0003");
                        ex.spec.scope =
                            ScopeSpec::Repository(hort_config::scope::RepositoryScope {
                                repository: "npm-internal".into(),
                            });
                        ex
                    }],
                    ..Default::default()
                },
                expect_rule: LinterRule::ExclusionScopeNotImplemented,
                effective_backend: None,
            },
            // Row 12 — a virtual member on another format.
            Case {
                desired: DesiredState {
                    repositories: vec![
                        {
                            let mut virt = repo_env_with_format("all-npm", "virtual", "npm");
                            virt.spec.virtual_members = Some(vec!["py-lib".into()]);
                            virt
                        },
                        repo_env_with_format("py-lib", "hosted", "pypi"),
                    ],
                    ..Default::default()
                },
                expect_rule: LinterRule::VirtualMemberFormatNotEnforced,
                effective_backend: None,
            },
            // Row 13 — a ScanPolicy declaring a staleness cap the age
            // evaluator never applies.
            Case {
                desired: DesiredState {
                    scan_policies: vec![{
                        let mut env = scan_policy_env("p-stale-cap");
                        env.spec.max_artifact_age = Some("90d".into());
                        env
                    }],
                    ..Default::default()
                },
                expect_rule: LinterRule::ScanPolicyMaxArtifactAgeNotImplemented,
                effective_backend: None,
            },
        ];

        for case in cases {
            // The pure validator's first-error-in-row-order rule.
            let validator = StaticConfigValidator::new(
                Arc::new(["oci".to_string()].into_iter().collect()),
                // No case in this corpus exercises row 6b.
                Arc::new(HashSet::new()),
                case.effective_backend,
            );
            let report = validator.validate(&case.desired);
            let static_first = report.errors.first().unwrap_or_else(|| {
                panic!("validator must report ≥1 error for {:?}", case.expect_rule)
            });
            assert_eq!(
                static_first.rule, case.expect_rule,
                "validator first-error rule mismatch"
            );

            // The apply pre-write pass (via the public preflight seam) must
            // abort with the SAME rule's first-finding message — proving the
            // apply abort tracks the static subset, no drift.
            let h = build_harness();
            let uc = match case.effective_backend {
                Some(b) => h.uc.with_effective_storage_backend(b),
                None => h.uc,
            }
            .with_provenance_capable_formats(["oci".to_string()]);
            let err = uc
                .preflight_validate(&case.desired, &env_oidc())
                .await
                .expect_err("apply pre-write pass must reject this corpus config");
            match err {
                AppError::Domain(DomainError::Validation(msg)) => {
                    assert!(
                        msg.contains(&static_first.message),
                        "apply abort message for {:?} must carry the static \
                         validator's first finding.\n  apply: {msg}\n  static: {}",
                        case.expect_rule,
                        static_first.message,
                    );
                }
                other => panic!("expected Validation error, got {other:?}"),
            }
        }
    }

    /// The offline `StaticConfigValidator` row 8
    /// and the REAL apply path agree on whether the permission-grant
    /// linter rejects, for a corpus covering one reject per grant rule
    /// plus a clean pass. The validator runs offline with placeholder
    /// ids; apply runs through the real ports (resolving repos / SAs to
    /// DB ids and synthesising SA-owned grants). The verdict is invariant
    /// to id VALUES, so the two must agree — proving the offline
    /// expansion replicates apply's grant set, no drift.
    ///
    /// This invariance is what licenses consuming row 8 in the pre-write
    /// pass (`PRE_WRITE_REJECT_ROWS`), and consuming it there changes what
    /// each arm of this test observes:
    ///
    /// - **reject cases** — apply now aborts in the pre-write pass, so the
    ///   verdict it reports *is* the validator's. The grant stage's gate
    ///   survives as defence-in-depth over the port-built set; it is no
    ///   longer reachable through the public API for a bundle the
    ///   placeholder expansion already refuses, which is the point of
    ///   moving the rejection before the first write.
    /// - **clean cases** — apply reaches the grant stage, which runs the
    ///   linter over the port-built set and must also pass. This direction
    ///   is unchanged and still non-trivial: it is what would catch a
    ///   placeholder expansion that passed something the real set rejects.
    #[tokio::test]
    async fn static_validator_row8_and_apply_grant_linter_agree() {
        use crate::lint::{LinterRule, StaticConfigValidator};

        // (desired-builder, seed-fn, expect_reject) — each desired trips a
        // single grant rule (or none, for the clean case). The seed-fn
        // inserts the repos the apply expansion needs to resolve.
        struct Case {
            name: &'static str,
            desired: DesiredState,
            expect_reject: bool,
        }

        // Every referenced repository is DECLARED as an envelope so apply's
        // desired-side cross-validate (grant.repository must resolve) passes
        // and apply reaches the grant linter — the row-8 verdict is invariant
        // to this declaration (it only reads grant subject/permission/
        // repository.is_none()).
        let cases = vec![
            // single-claim grant → reject.
            Case {
                name: "single-claim",
                desired: DesiredState {
                    repositories: vec![repo_env("repo-x", "hosted")],
                    permission_grants: vec![grant_env(
                        "solo",
                        &["team-alpha"],
                        "read",
                        Some("repo-x"),
                    )],
                    ..Default::default()
                },
                expect_reject: true,
            },
            // wildcard-repo non-admin Claims grant → reject.
            Case {
                name: "wildcard-non-admin",
                desired: DesiredState {
                    permission_grants: vec![grant_env(
                        "everywhere",
                        &["developer", "ops"],
                        "write",
                        None,
                    )],
                    ..Default::default()
                },
                expect_reject: true,
            },
            // unjustified high-priv direct-user grant → reject.
            Case {
                name: "direct-user-admin",
                desired: DesiredState {
                    permission_grants: vec![user_grant_env("god", Uuid::new_v4(), "admin", None)],
                    ..Default::default()
                },
                expect_reject: true,
            },
            // reserved-claim-name collision → reject.
            Case {
                name: "claim-collision",
                desired: DesiredState {
                    claim_mappings: vec![cm_env("bad", "ops-group", "service_account")],
                    ..Default::default()
                },
                expect_reject: true,
            },
            // Clean: multi-claim repo-scoped grant + ordinary mapping → pass.
            Case {
                name: "clean",
                desired: DesiredState {
                    repositories: vec![repo_env("repo-x", "hosted")],
                    permission_grants: vec![grant_env(
                        "scoped",
                        &["developer", "team-alpha"],
                        "write",
                        Some("repo-x"),
                    )],
                    claim_mappings: vec![cm_env("m1", "dev-group", "developer")],
                    ..Default::default()
                },
                expect_reject: false,
            },
        ];

        for case in cases {
            // --- offline validator (row 8 enabled) ---
            let validator = StaticConfigValidator::new(
                Arc::new(["oci".to_string()].into_iter().collect()),
                // No case in this corpus exercises row 6b.
                Arc::new(HashSet::new()),
                None,
            )
            .with_grant_lint_base(crate::lint::LintConfig::default());
            let report = validator.validate(&case.desired);
            let validator_rejects = report
                .errors
                .iter()
                .any(|f| f.rule == LinterRule::PermissionGrant);
            assert_eq!(
                validator_rejects, case.expect_reject,
                "validator row-8 verdict mismatch for `{}`: {:?}",
                case.name, report.errors
            );

            // --- real apply path (secure-default LintConfig) ---
            let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
            // The referenced repository is DECLARED as an envelope (above):
            // on the clean cases apply's repository stage creates it through
            // the mock BEFORE the grant stage, so the grant expansion's
            // `find_by_key` resolves it. No pre-seed (a pre-seeded
            // `managed_by=local` row would make apply reject the
            // re-declaration before reaching the linter).
            let apply_result = h.uc.apply(case.desired.clone(), env_oidc()).await;
            // The grant-lint reject now lands in the pre-write pass, which
            // aborts with the row-8 finding verbatim; the grant stage's own
            // aggregate message ("apply-config linter rejected N …") is only
            // reachable if the placeholder-id expansion and the port-built
            // set ever disagreed. Accept either — what this asserts is the
            // verdict, not which of the two gates produced it.
            let apply_rejects = match &apply_result {
                Err(AppError::Domain(DomainError::Validation(msg))) => {
                    msg.contains("permission-grant linter rule")
                        || msg.contains("apply-config linter rejected")
                }
                _ => false,
            };
            assert_eq!(
                apply_rejects, case.expect_reject,
                "apply grant-linter verdict mismatch for `{}`: {apply_result:?}",
                case.name
            );

            // Parity: the two paths agree.
            assert_eq!(
                validator_rejects, apply_rejects,
                "row-8 / apply parity broken for `{}`",
                case.name
            );

            // On the clean cases the grant stage DID run, over the
            // port-built desired set, and passed: an `Ok` apply is the
            // port-built linter's own verdict, not the validator's. That is
            // the half of the parity the pre-write reject cannot shadow —
            // a placeholder expansion that passed something the port-built
            // set rejects would fail here.
            if !case.expect_reject {
                assert_eq!(
                    h.grant_repo.reconcile_call_count(),
                    1,
                    "a clean bundle must reach the grant stage's own lint + \
                     reconcile for `{}`",
                    case.name
                );
            }
        }
    }

    // ===================================================================
    // Pre-write rejection completeness.
    //
    // The apply writes between its stages and ships no rollback, so a
    // rejection reachable only from a write-capable stage leaves a partial
    // apply: the reachable bad state is a tightening refused while a
    // loosening from the same bundle has already landed. The claim these
    // tests hold is therefore "every rejection the apply can reach is
    // reachable before the first write", in two complementary shapes — a
    // structural one over the lint rows, and a per-stage corpus.
    // ===================================================================

    /// `PRE_WRITE_REJECT_ROWS` is COMPLETE: every [`LinterRule`] that can
    /// produce an error finding is consumed by the pre-write pass.
    ///
    /// This is the enumeration turned into a checked claim. The table used
    /// to be a comment listing the rows the pass consumed, and a comment
    /// cannot fail — which is how the grant lint stayed off the list while
    /// its rejection ran inside the last apply stage, behind the
    /// repository, policy and mapping writes. The classification below is
    /// wildcard-free, so a new `LinterRule` variant does not compile until
    /// its author states where its verdict is surfaced; if the answer is
    /// "a reject", the assertion then requires it to be in the table.
    #[test]
    fn pre_write_validation_consumes_every_reject_row() {
        /// Where the pre-write pass surfaces a rule's verdict.
        #[derive(Debug, PartialEq, Eq)]
        enum Consumption {
            /// Walked from `PRE_WRITE_REJECT_ROWS`.
            Table,
            /// A dedicated pre-write abort outside the table, kept separate
            /// because it has its own `error!` line and error envelope.
            Dedicated,
            /// Advisory: the rule emits warnings only and never aborts, so
            /// there is no rejection to bring forward.
            AdvisoryOnly,
        }

        // No `_` arm, on purpose: `LinterRule` is not `#[non_exhaustive]`,
        // so a new variant fails to COMPILE here until it is consciously
        // classified.
        fn consumption(rule: LinterRule) -> Consumption {
            match rule {
                LinterRule::TrustUpstreamPublishTimeRequiresScanBackends
                | LinterRule::PrefetchMaxAgeDaysNotImplemented
                | LinterRule::PrefetchTriggerRequiresVersionDiscovery
                | LinterRule::ProvenanceConfig
                | LinterRule::RepoStorageBackendMismatch
                | LinterRule::ScanBackendCapability
                | LinterRule::PermissionGrant
                | LinterRule::RetentionUnusedForNotImplemented
                | LinterRule::ScanPolicyLicensePolicyNotImplemented
                | LinterRule::ExclusionScopeNotImplemented
                | LinterRule::VirtualMemberFormatNotEnforced
                | LinterRule::ScanPolicyMaxArtifactAgeNotImplemented => Consumption::Table,
                // Row 2 — its own abort immediately before row 4, so the
                // cross-kind FK keeps its distinct log line and its
                // `"; "`-joined envelope.
                LinterRule::SaIssuerFk => Consumption::Dedicated,
                // Row 3 — advisory warning only.
                LinterRule::UnderConstrainedFederatedIdentities => Consumption::AdvisoryOnly,
            }
        }

        /// Every `LinterRule` variant, once. The wildcard-free `match`
        /// above is the compile-time guarantee that this list is complete;
        /// the array is what lets the assertions iterate it.
        const ALL_RULES: &[LinterRule] = &[
            LinterRule::SaIssuerFk,
            LinterRule::UnderConstrainedFederatedIdentities,
            LinterRule::TrustUpstreamPublishTimeRequiresScanBackends,
            LinterRule::PrefetchMaxAgeDaysNotImplemented,
            LinterRule::PrefetchTriggerRequiresVersionDiscovery,
            LinterRule::ProvenanceConfig,
            LinterRule::RepoStorageBackendMismatch,
            LinterRule::ScanBackendCapability,
            LinterRule::PermissionGrant,
            LinterRule::RetentionUnusedForNotImplemented,
            LinterRule::ScanPolicyLicensePolicyNotImplemented,
            LinterRule::ExclusionScopeNotImplemented,
            LinterRule::VirtualMemberFormatNotEnforced,
            LinterRule::ScanPolicyMaxArtifactAgeNotImplemented,
        ];

        let in_table: HashSet<LinterRule> =
            PRE_WRITE_REJECT_ROWS.iter().map(|(r, _, _)| *r).collect();
        assert_eq!(
            in_table.len(),
            PRE_WRITE_REJECT_ROWS.len(),
            "PRE_WRITE_REJECT_ROWS lists a rule twice — the second entry is \
             dead (the walk aborts on the first row with findings)"
        );

        for &rule in ALL_RULES {
            let classified = consumption(rule);
            assert_eq!(
                in_table.contains(&rule),
                classified == Consumption::Table,
                "{rule:?} is classified {classified:?} but \
                 PRE_WRITE_REJECT_ROWS membership says otherwise. A rejecting \
                 lint row that is NOT consumed by the pre-write pass can only \
                 reject from inside a write-capable apply stage, which leaves \
                 a partial apply behind. Add it to the table (and give it an \
                 `error!` line + a RowAbort), or classify it Dedicated / \
                 AdvisoryOnly and say where its verdict is surfaced."
            );
        }

        // Counter-assertion: the classification is not vacuously
        // Table-for-everything, and the array did not lose a variant to a
        // rename. Three buckets, with the counts the as-built pass has.
        let table = ALL_RULES
            .iter()
            .filter(|r| consumption(**r) == Consumption::Table)
            .count();
        let dedicated = ALL_RULES
            .iter()
            .filter(|r| consumption(**r) == Consumption::Dedicated)
            .count();
        let advisory = ALL_RULES
            .iter()
            .filter(|r| consumption(**r) == Consumption::AdvisoryOnly)
            .count();
        assert_eq!(
            (table, dedicated, advisory),
            (12, 1, 1),
            "the LinterRule bucket counts changed — a silent reclassification \
             (or a variant missing from ALL_RULES) is exactly what this guard \
             exists to catch"
        );
    }

    /// For every apply stage that can refuse an operator config, the boot
    /// preflight refuses the same bundle — so the refusal happens before
    /// the first write and `gitops_boot` parks not-ready instead of
    /// crashlooping on a half-applied tree.
    ///
    /// Each case names the stage whose check would refuse the bundle and
    /// the pre-write row that now catches it first. The test has teeth in
    /// the direction that matters: delete the pre-write row and the
    /// matching case goes red, because the stage's own check still refuses
    /// the bundle (the stages keep theirs as defence-in-depth) while the
    /// preflight no longer does.
    ///
    /// Two cases in the corpus are worse than a late refusal and are
    /// carried here for the same reason: neither `apply_scan_policies`
    /// nor `apply_exclusions` *refuses* a scope naming an undeclared
    /// repository, they panic on it, which is not a `GitopsBootError` and
    /// so cannot park the pod at all. Deleting either pre-write rule
    /// turns this test's `apply` call into that panic — which is the
    /// standing proof that `ExclusionsApplier::resolve_scope`'s panic is
    /// unreachable from operator config.
    ///
    /// # What the corpus is, and what it is not
    ///
    /// The cases are **hand-written, one per rejecting stage**, and the
    /// coverage claim is therefore only as complete as this list. The
    /// companion test above (`pre_write_validation_consumes_every_reject_row`)
    /// IS derived — its wildcard-free `match` over `LinterRule` fails to
    /// compile until a new variant is classified — but that covers the
    /// linter rows, not the stages: a stage can refuse through a domain
    /// constructor, a port lookup or a `FromStr` with no lint row behind
    /// it, which is exactly what the two newest cases below
    /// (`apply_curation_rules`, `apply_virtual_members`) do. Those two
    /// were absent for as long as the list was the only inventory, and
    /// while both were covered by a preflight mirror throughout, losing
    /// either mirror would have left this purported stage-completeness
    /// test green. A new rejection arm added to a represented stage has
    /// the same exposure. There is one stage function per apply pass, so
    /// the list is checkable by reading `apply`; it is not checked by the
    /// compiler.
    #[tokio::test]
    async fn every_rejecting_apply_stage_is_rejected_pre_write() {
        struct Case {
            /// The stage whose check refuses this bundle, and the pre-write
            /// row that makes the same verdict reachable earlier.
            what: &'static str,
            desired: DesiredState,
        }

        let mut undeclared_issuer_sa = DesiredState::default();
        undeclared_issuer_sa
            .service_accounts
            .push(service_account_env_for_apply("ci", Some("missing-idp")));

        let mut proxy_without_block = repo_env("npm-proxy", "proxy");
        proxy_without_block.spec.proxy = None;

        let mut bad_jwks_interval = oidc_issuer_env_for_apply("corp");
        bad_jwks_interval.spec.jwks_refresh_interval = "every other tuesday".into();

        let mut scoped_scan_policy_at_a_ghost = scan_policy_env("scoped-at-a-ghost");
        scoped_scan_policy_at_a_ghost.spec.scope =
            ScopeSpec::Repository(hort_config::scope::RepositoryScope {
                repository: "not-declared".into(),
            });

        let mut exclusion_scoped_at_a_ghost =
            exclusion_env("scoped-at-a-ghost", "p-parent", "CVE-2026-0004");
        exclusion_scoped_at_a_ghost.spec.scope =
            ScopeSpec::Repository(hort_config::scope::RepositoryScope {
                repository: "not-declared".into(),
            });

        let mut half_mtls = upstream_mapping_env(
            "m-half-mtls",
            "oci-mirror",
            "dockerhub/",
            "https://registry-1.docker.io",
        );
        half_mtls.spec.mtls_cert_ref = Some(SecretRef {
            source: SecretSource::EnvVar,
            location: "CLIENT_CERT".into(),
        });

        // A `type: virtual` repo naming a member the bundle does not
        // declare. `repo_env`'s `npm` format is serve-supported, so the
        // only thing wrong with this bundle is the member reference.
        let mut virtual_at_a_ghost_member = repo_env("npm-aggregate", "virtual");
        virtual_at_a_ghost_member.spec.virtual_members = Some(vec!["not-declared".into()]);

        let cases = vec![
            // `apply_claim_mappings` (Stage 1) — the grant linter's
            // claim-name-collision rule. Row 8: before this moved forward,
            // the Stage-1 claim-mapping partition reconcile had already run
            // when the linter refused.
            Case {
                what: "apply_permission_grants / claim-name-collision (row 8)",
                desired: DesiredState {
                    claim_mappings: vec![cm_env("svc", "sa-group", "service_account")],
                    ..Default::default()
                },
            },
            // `apply_permission_grants` (last) — the three grant rules.
            Case {
                what: "apply_permission_grants / single-claim-grant (row 8)",
                desired: DesiredState {
                    repositories: vec![repo_env("repo-x", "hosted")],
                    permission_grants: vec![grant_env(
                        "solo",
                        &["team-alpha"],
                        "read",
                        Some("repo-x"),
                    )],
                    ..Default::default()
                },
            },
            Case {
                what: "apply_permission_grants / wildcard-repo-non-admin (row 8)",
                desired: DesiredState {
                    permission_grants: vec![grant_env(
                        "everywhere",
                        &["developer", "ops"],
                        "write",
                        None,
                    )],
                    ..Default::default()
                },
            },
            Case {
                what: "apply_permission_grants / direct-user-grant (row 8)",
                desired: DesiredState {
                    permission_grants: vec![user_grant_env("god", Uuid::new_v4(), "admin", None)],
                    ..Default::default()
                },
            },
            // `apply_upstream_mappings` (Stage 3) — the value-object
            // constructor's TLS invariants, mirrored at per-spec validation.
            Case {
                what: "apply_upstream_mappings / RepositoryUpstreamMapping::new TLS pairing",
                desired: DesiredState {
                    repositories: vec![repo_env("oci-mirror", "proxy")],
                    upstream_mappings: vec![half_mtls],
                    ..Default::default()
                },
            },
            // `apply_repository_rows` (Stage 2) — `build_repository_from_spec`
            // refuses a proxy with no upstream URL; per-spec validation
            // refuses the missing `proxy:` block that produces it.
            Case {
                what: "apply_repository_rows / proxy without an upstream URL",
                desired: DesiredState {
                    repositories: vec![proxy_without_block],
                    ..Default::default()
                },
            },
            // `apply_scan_policies` (Stage 2) — `resolve_scope`'s
            // repository-name lookup. This stage does not refuse such a
            // bundle, it PANICS on it, which no boot path can park on; the
            // pre-write reference rule
            // (`push_scan_policy_scope_reference_errors`) is what keeps the
            // panic unreachable from operator config.
            Case {
                what: "apply_scan_policies / resolve_scope repository name",
                desired: DesiredState {
                    scan_policies: vec![scoped_scan_policy_at_a_ghost],
                    ..Default::default()
                },
            },
            // `apply_exclusions` (Stage 3) — `ExclusionsApplier::resolve_scope`.
            // Same shape as the scan-policy case above and worse in reach:
            // that resolver panics on a repository name absent from the
            // id map, and `validate_exclusion_scope_not_implemented` keeps
            // it unreachable by refusing EVERY repository scope — so this
            // case covers both the undeclared name (panic) and a declared
            // one (which would resolve, and then be refused by
            // `PolicyUseCase::add_exclusion` from a write-capable stage).
            Case {
                what: "apply_exclusions / resolve_scope repository name",
                desired: DesiredState {
                    scan_policies: vec![scan_policy_env("p-parent")],
                    exclusions: vec![exclusion_scoped_at_a_ghost],
                    ..Default::default()
                },
            },
            // `apply_retention_policies` (Stage 2) — the predicate resolve.
            Case {
                what: "apply_retention_policies / predicate resolve",
                desired: DesiredState {
                    retention_policies: vec![retention_policy_env_for_apply(
                        "nonsense",
                        serde_json::json!({ "NotAPredicate": 1 }),
                    )],
                    ..Default::default()
                },
            },
            // `apply_oidc_issuers` — `humantime` parse of the refresh
            // interval, guarded by the per-spec rule that parses it first.
            Case {
                what: "apply_oidc_issuers / jwksRefreshInterval parse",
                desired: DesiredState {
                    oidc_issuers: vec![bad_jwks_interval],
                    ..Default::default()
                },
            },
            // `apply_service_accounts` — the cross-kind issuer FK (row 2,
            // the pass's dedicated abort).
            Case {
                what: "apply_service_accounts / issuer cross-kind FK (row 2)",
                desired: undeclared_issuer_sa,
            },
            // `apply_curation_rules` (Stage 1) —
            // `build_curation_rule_from_spec`'s
            // `CurationRuleAction::from_str`, which refuses an action
            // outside {block, warn, allow} while building the rule. The
            // mirror is per-spec `validate_curation_rule`. Worth a case
            // of its own because of WHERE the stage sits: Stage 1 runs
            // after `apply_claim_mappings`, so a late refusal here
            // leaves the claim-mapping partition already reconciled.
            Case {
                what: "apply_curation_rules / CurationRuleAction::from_str",
                desired: DesiredState {
                    curation_rules: vec![rule_env(
                        "cr-bad-action",
                        "quarantine",
                        "left-pad",
                        "operator rationale",
                    )],
                    ..Default::default()
                },
            },
            // `apply_virtual_members` (Stage 3) — the declared-member
            // key→id resolution (`repositories.find_by_key`), which
            // fails `NotFound` for a member no envelope declares. The
            // mirror is cross-document `DanglingVirtualMember`. Stage 3
            // is after the repository, policy and mapping writes, so
            // this is the partial-apply shape at its widest.
            Case {
                what: "apply_virtual_members / member key resolution",
                desired: DesiredState {
                    repositories: vec![virtual_at_a_ghost_member],
                    ..Default::default()
                },
            },
        ];

        for case in cases {
            // Secure-default lint config: the grant rows must reject with
            // zero operator config, which is the posture they ship in.
            let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
            let Err(err) = h.uc.preflight_validate(&case.desired, &env_oidc()).await else {
                panic!(
                    "`{}` is refused by a write-capable apply stage, so the \
                     pre-write pass must refuse it too — otherwise an apply \
                     carrying it writes the earlier stages and only then fails, \
                     leaving a partial apply with no rollback",
                    case.what
                )
            };
            assert!(
                matches!(err, AppError::Domain(DomainError::Validation(_))),
                "`{}` must surface as a park-eligible Validation error \
                 (`GitopsBootError::PreflightValidate`), got {err:?}",
                case.what
            );

            // And the write path agrees, with nothing written: the pre-write
            // pass runs first inside `apply`, so no stage is entered.
            let h2 = build_harness_with_lint_config(crate::lint::LintConfig::default());
            h2.uc
                .apply(case.desired.clone(), env_oidc())
                .await
                .expect_err("apply must refuse the same bundle");
            assert!(
                h2.repos.calls().is_empty()
                    && h2.claim_mappings.reconcile_call_count() == 0
                    && h2.grant_repo.reconcile_call_count() == 0
                    && h2.events.appended().is_empty(),
                "`{}` must abort before the first write; repo calls {:?}, \
                 claim-mapping reconciles {}, grant reconciles {}, events {}",
                case.what,
                h2.repos.calls(),
                h2.claim_mappings.reconcile_call_count(),
                h2.grant_repo.reconcile_call_count(),
                h2.events.appended().len(),
            );
        }
    }

    /// The acceptance shape for the grant lint: a bundle carrying a grant
    /// the linter refuses AND a loosening scan policy leaves the policy
    /// projection unchanged.
    ///
    /// Before the grant lint's rejection moved into the pre-write pass, the
    /// reachable bad state was exactly this: the loosened policy committed
    /// in Stage 2, the tightening refused in the final stage, and the
    /// operator's atomic-looking `apply` returning an error with the
    /// loosening live.
    #[tokio::test]
    async fn row8_reject_beside_a_loosening_scan_policy_writes_nothing() {
        // Loosened on all three axes an operator would notice.
        let mut loosened = scan_policy_env("relaxed");
        loosened.spec.enforcement = "record".into();
        loosened.spec.require_approval = false;
        loosened.spec.severity_threshold = "critical".into();

        // Positive control: the loosening policy alone applies and lands,
        // so the "nothing written" assertions below cannot pass vacuously.
        let control = build_harness_with_lint_config(crate::lint::LintConfig::default());
        control
            .uc
            .apply(
                DesiredState {
                    scan_policies: vec![loosened.clone()],
                    ..Default::default()
                },
                env_oidc(),
            )
            .await
            .expect("the loosening policy alone must apply cleanly");
        assert!(
            !control.events.appended().is_empty(),
            "positive control: applying the loosening policy must append the \
             ScanPolicy event that creates its projection"
        );

        // A tightening grant the linter refuses (wildcard-repo non-admin),
        // in the same bundle as the loosening.
        let desired = DesiredState {
            scan_policies: vec![loosened],
            permission_grants: vec![grant_env(
                "ops-write-everywhere",
                &["developer", "ops"],
                "write",
                None,
            )],
            ..Default::default()
        };

        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let err =
            h.uc.apply(desired.clone(), env_oidc())
                .await
                .expect_err("the refused grant must fail the whole apply");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => assert!(
                msg.contains("wildcard-repo-non-admin"),
                "the abort must name the rejecting grant rule, got: {msg}"
            ),
            other => panic!("expected Validation, got {other:?}"),
        }
        assert!(
            h.events.appended().is_empty(),
            "the loosening scan policy must NOT have been written — {} event \
             batch(es) landed",
            h.events.appended().len()
        );
        assert_eq!(h.grant_repo.reconcile_call_count(), 0);

        // The boot preflight reaches the same verdict, so the pod parks.
        h.uc.preflight_validate(&desired, &env_oidc())
            .await
            .expect_err("the boot preflight must refuse the same bundle");
    }

    /// A row that renders the rule and not the offending object collapses
    /// its duplicate findings into one sentence per rule.
    ///
    /// Two grants trip `single-claim-grant`, so the grant linter reports two
    /// findings whose messages are byte-identical (the message names the
    /// rule; the offending grant's identity is deliberately not rendered —
    /// claim names are operator topology). Joining them verbatim would hand
    /// the operator the same sentence twice and say nothing more; the
    /// `RowAbort::DistinctFindings` collapse is what keeps the abort as
    /// informative as the grant stage's own aggregate message was.
    #[tokio::test]
    async fn row8_abort_collapses_duplicate_findings_of_the_same_rule() {
        let desired = DesiredState {
            repositories: vec![repo_env("repo-x", "hosted"), repo_env("repo-y", "hosted")],
            permission_grants: vec![
                grant_env("solo-x", &["team-alpha"], "read", Some("repo-x")),
                grant_env("solo-y", &["team-beta"], "read", Some("repo-y")),
            ],
            ..Default::default()
        };
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let err =
            h.uc.preflight_validate(&desired, &env_oidc())
                .await
                .expect_err("two single-claim grants must be refused");
        let AppError::Domain(DomainError::Validation(msg)) = err else {
            panic!("expected Validation, got {err:?}")
        };
        assert_eq!(
            msg.matches("single-claim-grant").count(),
            1,
            "the rule must be named once, not once per offending grant: {msg}"
        );

        // Counter-assertion: a bundle tripping TWO DIFFERENT grant rules
        // names both, so the collapse is a dedupe and not a truncation.
        let two_rules = DesiredState {
            permission_grants: vec![
                grant_env("solo", &["team-alpha"], "read", None),
                user_grant_env("god", Uuid::new_v4(), "admin", None),
            ],
            ..Default::default()
        };
        let h2 = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let err2 = h2
            .uc
            .preflight_validate(&two_rules, &env_oidc())
            .await
            .expect_err("both grants must be refused");
        let AppError::Domain(DomainError::Validation(msg2)) = err2 else {
            panic!("expected Validation, got {err2:?}")
        };
        for rule in [
            "single-claim-grant",
            "wildcard-repo-non-admin",
            "direct-user-grant-without-justification",
        ] {
            assert!(
                msg2.contains(rule),
                "the abort must name every rejecting rule; `{rule}` missing from: {msg2}"
            );
        }
    }
    /// The grant lint's `hort_apply_config_linter_total` emission is
    /// unchanged by the move: it is the grant stage's own, over the
    /// port-built desired set, and the validator emits none.
    ///
    /// Two halves, and both are load-bearing. On a CLEAN apply the stage
    /// still evaluates every (grant, rule) pair and still ticks the
    /// counter — the pre-write pass running the same rules metric-free did
    /// not move or duplicate that series. On a REFUSED apply the pass
    /// aborts first, so no series is emitted at all: the rejection is
    /// reported by the `Validation` error (and, at boot,
    /// `hort_gitops_apply_total{result="validation_error"}`), not by a
    /// per-rule counter. That is the deliberate trade of rejecting before
    /// the first write rather than after it.
    #[test]
    fn row8_apply_path_metric_emission_is_unchanged() {
        use crate::metrics::capture_metrics;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        // Clean: a multi-claim repo-scoped grant passes every rule.
        let clean = capture_metrics(|| {
            let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
            runtime.block_on(async {
                h.uc.apply(
                    DesiredState {
                        repositories: vec![repo_env("repo-x", "hosted")],
                        permission_grants: vec![grant_env(
                            "scoped",
                            &["developer", "team-alpha"],
                            "write",
                            Some("repo-x"),
                        )],
                        ..Default::default()
                    },
                    env_oidc(),
                )
                .await
                .expect("the clean bundle must apply");
            });
        });
        let clean_entries = clean.into_vec();
        assert_eq!(
            counter_value_for(
                &clean_entries,
                "hort_apply_config_linter_total",
                &[("rule", "single-claim-grant"), ("result", "pass")],
            ),
            1,
            "the grant stage's per-(grant, rule) emission over the port-built \
             set must be untouched by the pre-write pass"
        );

        // Refused: the pre-write pass aborts, so the grant stage — and its
        // emission — is never reached.
        let refused = capture_metrics(|| {
            let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
            runtime.block_on(async {
                h.uc.apply(
                    DesiredState {
                        permission_grants: vec![grant_env(
                            "everywhere",
                            &["developer", "ops"],
                            "write",
                            None,
                        )],
                        ..Default::default()
                    },
                    env_oidc(),
                )
                .await
                .expect_err("the refused bundle must fail the apply");
            });
        });
        let refused_entries = refused.into_vec();
        assert_eq!(
            counter_value_for(
                &refused_entries,
                "hort_apply_config_linter_total",
                &[("rule", "wildcard-repo-non-admin"), ("result", "reject")],
            ),
            0,
            "a bundle refused before the first write emits no grant-linter \
             series: the validator is metric-free by design (the offline \
             `validate-config` path must invent no series) and the stage that \
             owns the emission is never reached"
        );
    }

    /// Apply-path metric byte-identity — rows 5 and 6 each tick
    /// `hort_apply_config_linter_total{rule,result=reject}` ONCE PER
    /// offending envelope (not once per row), and the abort returns that
    /// rule's error. Two offenders ⇒ count 2, proving the refactor kept
    /// the `for _ in 0..count` emission shape.
    #[test]
    fn apply_emits_one_linter_metric_per_offending_envelope_unchanged() {
        use crate::metrics::capture_metrics;

        // Row 6 — two repositories each with an inert max_age_days ⇒ the
        // prefetch linter aborts FIRST (row 6 precedes row 7/7b) and ticks
        // its counter twice.
        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut r1 = repo_env("npm-a", "proxy");
                r1.spec.prefetch_policy.max_age_days = Some(30);
                let mut r2 = repo_env("npm-b", "proxy");
                r2.spec.prefetch_policy.max_age_days = Some(60);
                let desired = DesiredState {
                    repositories: vec![r1, r2],
                    ..Default::default()
                };
                captured_err = Some(
                    h.uc.apply(desired, env_oidc())
                        .await
                        .expect_err("two inert max_age_days repos must reject"),
                );
            });
        });
        // The abort is the prefetch rule's error (row 6 first).
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(msg.contains("npm-a") && msg.contains("npm-b"), "got: {msg}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "prefetch_max_age_days_not_implemented"),
                    ("result", "reject"),
                ],
            ),
            2,
            "row-6 linter metric must tick once PER offending PrefetchPolicy (2)",
        );
        // Row 7/7b never reached (row 6 aborted first) — no other rule
        // ticked.
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[("rule", "trust_upstream_publish_time_requires_scan_backends",)],
            ),
            0,
            "no other linter rule should tick on a row-6 abort",
        );
    }

    /// Row-5 multi-offender metric — two trust_pt mappings whose resolved
    /// policy waives scanning ⇒ the counter ticks twice, and the abort
    /// is that rule's error. (Row 5 precedes row 6.)
    #[test]
    fn apply_row5_metric_ticks_once_per_offending_mapping_unchanged() {
        use crate::metrics::capture_metrics;

        let mut captured_err: Option<AppError> = None;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut m1 =
                    upstream_mapping_env("m1", "mirror-a", "a/", "https://registry-1.docker.io");
                m1.spec.trust_upstream_publish_time = true;
                let mut m2 =
                    upstream_mapping_env("m2", "mirror-b", "b/", "https://registry-1.docker.io");
                m2.spec.trust_upstream_publish_time = true;
                let desired = DesiredState {
                    repositories: vec![
                        repo_env("mirror-a", "proxy"),
                        repo_env("mirror-b", "proxy"),
                    ],
                    upstream_mappings: vec![m1, m2],
                    scan_policies: vec![
                        scan_policy_with_repo_scope_and_backends("p-a", "mirror-a", vec![]),
                        scan_policy_with_repo_scope_and_backends("p-b", "mirror-b", vec![]),
                    ],
                    ..Default::default()
                };
                captured_err = Some(
                    h.uc.apply(desired, env_oidc())
                        .await
                        .expect_err("two trust_pt × scan_backends:[] mappings must reject"),
                );
            });
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(_)) => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_apply_config_linter_total",
                &[
                    ("rule", "trust_upstream_publish_time_requires_scan_backends"),
                    ("result", "reject"),
                ],
            ),
            2,
            "row-5 linter metric must tick once PER offending mapping (2)",
        );
    }

    // ===================================================================
    // Apply-time fail-closed
    // provenance-config linter (ADR 0027). Mirrors the
    // `trust_upstream_publish_time_requires_scan_backends` / `max_age_days`
    // reject patterns above. Four rules:
    //   - REJECT `Required` on a scope resolving to a format with no
    //     registered `ProvenancePort` (the apply-only rule — needs the
    //     `provenance_capable_formats` set + scope→format resolution;
    //     names the format, points at Tier 2).
    //   - REJECT `mode != Off` with empty `provenance_backends`
    //     (consumes domain `ProvenanceConfigError::NonOffWithoutBackends`).
    //   - REJECT `Required` with empty `provenance_identities`
    //     (consumes domain `ProvenanceConfigError::RequiredWithoutIdentities`).
    //   - WARN `VerifyIfPresent` with empty `provenance_identities`
    //     (consumes domain `ProvenanceConfigWarning::...`; apply succeeds).
    // `require_approval` is deliberately NOT linted.
    // ===================================================================

    /// Provenance-linter helper — a `ScanPolicy` envelope with a
    /// `Repository` scope and explicit provenance fields. Mirrors
    /// `scan_policy_with_repo_scope_and_backends`'s shape so only the
    /// provenance dimensions under test vary; `scan_backends` defaults to
    /// `["trivy"]` so the default-registry harness validates cleanly.
    fn provenance_scan_policy_repo_scope(
        name: &str,
        repository: &str,
        mode: &str,
        provenance_backends: Vec<&str>,
        provenance_identities: Vec<SignerIdentitySpec>,
    ) -> Envelope<ScanPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ScanPolicy,
            metadata: Metadata { name: name.into() },
            spec: ScanPolicySpec {
                scope: ScopeSpec::Repository(hort_config::scope::RepositoryScope {
                    repository: repository.into(),
                }),
                severity_threshold: "high".into(),
                quarantine_duration: "24h".into(),
                require_approval: true,
                provenance_mode: mode.into(),
                provenance_backends: provenance_backends
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                provenance_identities,
                max_artifact_age: None,
                license_policy: serde_json::Value::Null,
                scan_backends: vec!["trivy".to_string()],
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
                enforcement: "reject".into(),
            },
        }
    }

    /// Provenance-linter helper — a `ScanPolicy` envelope with `Global`
    /// scope and explicit provenance fields.
    fn provenance_scan_policy_global_scope(
        name: &str,
        mode: &str,
        provenance_backends: Vec<&str>,
        provenance_identities: Vec<SignerIdentitySpec>,
    ) -> Envelope<ScanPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ScanPolicy,
            metadata: Metadata { name: name.into() },
            spec: ScanPolicySpec {
                scope: ScopeSpec::Global,
                severity_threshold: "high".into(),
                quarantine_duration: "24h".into(),
                require_approval: true,
                provenance_mode: mode.into(),
                provenance_backends: provenance_backends
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                provenance_identities,
                max_artifact_age: None,
                license_policy: serde_json::Value::Null,
                scan_backends: vec!["trivy".to_string()],
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
                enforcement: "reject".into(),
            },
        }
    }

    /// Provenance-linter helper — a repository envelope with a chosen
    /// `format` (the base `repo_env` hardcodes `"npm"`).
    fn repo_env_with_format(name: &str, repo_type: &str, format: &str) -> Envelope<RepositorySpec> {
        let mut env = repo_env(name, repo_type);
        env.spec.format = format.into();
        env
    }

    /// Provenance-linter helper — a valid `{issuer, san}` identity spec.
    fn sample_identity_spec() -> SignerIdentitySpec {
        SignerIdentitySpec {
            issuer: "https://token.actions.githubusercontent.com".into(),
            san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                .into(),
        }
    }

    /// REJECT: `provenance_mode: Required` on a scope resolving to a
    /// format with no registered `ProvenancePort` (capable set `{"oci"}`,
    /// scope resolves to an `npm` repo). The message names the format and
    /// points at the verifier-deployment fix.
    #[test]
    fn apply_rejects_required_provenance_on_no_verifier_format() {
        let mut captured_err: Option<AppError> = None;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            // Tier-1 capability set: cosign applies to OCI only.
            let uc = h.uc.with_provenance_capable_formats(["oci".to_string()]);
            let desired = DesiredState {
                repositories: vec![repo_env_with_format("npm-proxy", "proxy", "npm")],
                scan_policies: vec![provenance_scan_policy_repo_scope(
                    "p-required-npm",
                    "npm-proxy",
                    "required",
                    vec!["cosign"],
                    vec![sample_identity_spec()],
                )],
                ..Default::default()
            };
            captured_err = Some(
                uc.apply(desired, env_oidc())
                    .await
                    .expect_err("apply must reject Required on a no-verifier format"),
            );
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("npm"),
                    "validation error must name the no-verifier format, got: {msg}"
                );
                assert!(
                    msg.contains("p-required-npm"),
                    "validation error must name the offending policy, got: {msg}"
                );
                assert!(
                    msg.to_lowercase().contains("provenance"),
                    "validation error must mention provenance, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
    }

    /// REJECT: a `Global`-scoped `Required` policy is rejected when ANY
    /// declared repository's format lacks a verifier — the offending
    /// format is named.
    #[test]
    fn apply_rejects_required_provenance_global_scope_with_no_verifier_repo() {
        let mut captured_err: Option<AppError> = None;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc = h.uc.with_provenance_capable_formats(["oci".to_string()]);
            // One OCI repo (covered) and one cargo repo (not covered) —
            // the Global Required policy applies to both, so cargo is the
            // offender.
            let desired = DesiredState {
                repositories: vec![
                    repo_env_with_format("oci-proxy", "proxy", "oci"),
                    repo_env_with_format("cargo-proxy", "proxy", "cargo"),
                ],
                scan_policies: vec![provenance_scan_policy_global_scope(
                    "p-required-global",
                    "required",
                    vec!["cosign"],
                    vec![sample_identity_spec()],
                )],
                ..Default::default()
            };
            captured_err = Some(uc.apply(desired, env_oidc()).await.expect_err(
                "apply must reject Global Required when a repo format has no verifier",
            ));
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("cargo"),
                    "validation error must name the no-verifier format, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
    }

    /// REJECT: `mode != Off` with empty `provenance_backends` — consumes
    /// the domain `ProvenanceConfigError::NonOffWithoutBackends`.
    #[test]
    fn apply_rejects_non_off_provenance_with_empty_backends() {
        let mut captured_err: Option<AppError> = None;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc = h.uc.with_provenance_capable_formats(["oci".to_string()]);
            let desired = DesiredState {
                repositories: vec![repo_env_with_format("oci-proxy", "proxy", "oci")],
                scan_policies: vec![provenance_scan_policy_repo_scope(
                    "p-no-backends",
                    "oci-proxy",
                    "verify_if_present",
                    vec![],
                    vec![sample_identity_spec()],
                )],
                ..Default::default()
            };
            captured_err = Some(
                uc.apply(desired, env_oidc())
                    .await
                    .expect_err("apply must reject mode != Off with empty provenance_backends"),
            );
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("p-no-backends"),
                    "validation error must name the offending policy, got: {msg}"
                );
                assert!(
                    msg.contains("provenanceBackends") || msg.contains("provenance_backends"),
                    "validation error must name the empty backends field, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
    }

    /// REJECT: `Required` with empty `provenance_identities` — consumes
    /// the domain `ProvenanceConfigError::RequiredWithoutIdentities`
    /// (the any-signer footgun).
    #[test]
    fn apply_rejects_required_provenance_with_empty_identities() {
        let mut captured_err: Option<AppError> = None;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc = h.uc.with_provenance_capable_formats(["oci".to_string()]);
            let desired = DesiredState {
                repositories: vec![repo_env_with_format("oci-proxy", "proxy", "oci")],
                scan_policies: vec![provenance_scan_policy_repo_scope(
                    "p-required-no-ids",
                    "oci-proxy",
                    "required",
                    vec!["cosign"],
                    vec![],
                )],
                ..Default::default()
            };
            captured_err = Some(
                uc.apply(desired, env_oidc())
                    .await
                    .expect_err("apply must reject Required with empty provenance_identities"),
            );
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("p-required-no-ids"),
                    "validation error must name the offending policy, got: {msg}"
                );
                assert!(
                    msg.contains("provenanceIdentities") || msg.contains("provenance_identities"),
                    "validation error must name the empty identities field, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
    }

    /// WARN: `VerifyIfPresent` with empty `provenance_identities` —
    /// consumes the domain
    /// `ProvenanceConfigWarning::VerifyIfPresentWithoutIdentities`.
    /// Apply still succeeds (tampering-only detection is a legitimate
    /// operator choice).
    #[test]
    fn apply_warns_but_succeeds_verify_if_present_with_empty_identities() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc = h.uc.with_provenance_capable_formats(["oci".to_string()]);
            let desired = DesiredState {
                repositories: vec![repo_env_with_format("oci-proxy", "proxy", "oci")],
                scan_policies: vec![provenance_scan_policy_repo_scope(
                    "p-verify-no-ids",
                    "oci-proxy",
                    "verify_if_present",
                    vec!["cosign"],
                    vec![],
                )],
                ..Default::default()
            };
            // VerifyIfPresent + empty identities is a WARN, not a reject —
            // apply must succeed.
            uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed: VerifyIfPresent + empty identities is a warning");
        });
    }

    /// `preflight_validate` surfaces a pre-write config error the same way
    /// `apply` would (`DomainError::Validation`) but WITHOUT running any
    /// write stage. `gitops_boot` maps this to the park-eligible
    /// `GitopsBootError::PreflightValidate`, so the pod parks not-ready
    /// instead of crashlooping. Mirrors
    /// `apply_rejects_unknown_scan_backend_with_validation_error`.
    #[tokio::test]
    async fn preflight_validate_rejects_unknown_scan_backend() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .scan_policies
            .push(scan_policy_with_backends("p1", vec!["grype"]));
        let err =
            h.uc.preflight_validate(&desired, &env_oidc())
                .await
                .expect_err("preflight must reject an unsupported scan_backends entry");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("grype"),
                    "preflight validation error must name the offending backend, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
    }

    /// H20 regression, boot path. `preflight_validate` is the seam
    /// `gitops_boot` runs before `apply`; on a fresh deploy it executes
    /// before any worker has registered. A correct `scan_backends: [trivy]`
    /// policy must pass preflight (return `Ok`) in that no-workers posture —
    /// the previous build returned `DomainError::Validation` here, which
    /// `gitops_boot` mapped to the park-eligible
    /// `GitopsBootError::PreflightValidate`, parking the pod not-ready with
    /// no retry.
    #[tokio::test]
    async fn preflight_validate_accepts_known_backend_without_live_workers() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .scan_policies
            .push(scan_policy_with_backends("p1", vec!["trivy"]));
        h.uc.preflight_validate(&desired, &env_oidc()).await.expect(
            "H20: preflight must accept scan_backends:[trivy] with zero workers registered",
        );
    }

    /// `preflight_validate` returns `Ok(())` for a valid config AND
    /// suppresses the always-on advisory `warn!`s (`emit_advisories =
    /// false`), so the boot's preflight-then-`apply` sequence does not
    /// double-log them — `apply` re-runs the same pass with advisories
    /// enabled and emits each exactly once. Drives the gated provenance
    /// advisory path on its suppressed side with a `VerifyIfPresent +
    /// empty identities` policy (a WARN, not a reject), and reaches the
    /// (also-gated) under-constrained-FI advisory line with no service
    /// accounts present.
    #[test]
    fn preflight_validate_accepts_and_suppresses_advisories() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc = h.uc.with_provenance_capable_formats(["oci".to_string()]);
            let desired = DesiredState {
                repositories: vec![repo_env_with_format("oci-proxy", "proxy", "oci")],
                scan_policies: vec![provenance_scan_policy_repo_scope(
                    "p-verify-no-ids",
                    "oci-proxy",
                    "verify_if_present",
                    vec!["cosign"],
                    vec![],
                )],
                ..Default::default()
            };
            uc.preflight_validate(&desired, &env_oidc())
                .await
                .expect("preflight must accept VerifyIfPresent + empty identities (advisory only)");
        });
    }

    /// ACCEPT: `Required` on an OCI/cosign scope with a valid identity
    /// (capable set `{"oci"}`). The fully-configured happy path applies
    /// cleanly.
    #[test]
    fn apply_accepts_required_provenance_on_oci_with_identity() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            let uc = h.uc.with_provenance_capable_formats(["oci".to_string()]);
            let desired = DesiredState {
                repositories: vec![repo_env_with_format("oci-proxy", "proxy", "oci")],
                scan_policies: vec![provenance_scan_policy_repo_scope(
                    "p-required-oci",
                    "oci-proxy",
                    "required",
                    vec!["cosign"],
                    vec![sample_identity_spec()],
                )],
                ..Default::default()
            };
            uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed: Required on OCI/cosign with a valid identity");
        });
    }

    /// ACCEPT: an empty `provenance_capable_formats` set fail-closes a
    /// `Required` policy on *every* format, including OCI. Proves the
    /// default-empty posture.
    #[test]
    fn apply_rejects_required_provenance_when_capable_set_empty() {
        let mut captured_err: Option<AppError> = None;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            // No `with_provenance_capable_formats` call — the default
            // empty set means no format has a verifier yet.
            let h = build_harness();
            let desired = DesiredState {
                repositories: vec![repo_env_with_format("oci-proxy", "proxy", "oci")],
                scan_policies: vec![provenance_scan_policy_repo_scope(
                    "p-required-oci-empty-set",
                    "oci-proxy",
                    "required",
                    vec!["cosign"],
                    vec![sample_identity_spec()],
                )],
                ..Default::default()
            };
            captured_err = Some(
                h.uc.apply(desired, env_oidc())
                    .await
                    .expect_err("Required must reject when the capable set is empty"),
            );
        });
        match captured_err.expect("apply must have errored") {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("oci"),
                    "validation error must name the (uncovered) format, got: {msg}"
                );
            }
            other => panic!("expected AppError::Domain(DomainError::Validation(_)), got {other:?}"),
        }
    }

    /// ACCEPT: `provenance_mode: Off` with empty backends/identities is
    /// fully inert — never linted, never rejected, regardless of format
    /// or the capable set.
    #[test]
    fn apply_accepts_off_provenance_inert_regardless_of_format() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let h = build_harness();
            // Empty capable set + a non-OCI format: Off is inert, so no
            // reject.
            let desired = DesiredState {
                repositories: vec![repo_env_with_format("npm-proxy", "proxy", "npm")],
                scan_policies: vec![provenance_scan_policy_repo_scope(
                    "p-off",
                    "npm-proxy",
                    "off",
                    vec![],
                    vec![],
                )],
                ..Default::default()
            };
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed: Off provenance is inert");
        });
    }

    /// Cross-opt-in-linter helper — builds a `ScanPolicy` envelope with a
    /// `Repository` scope (so the cross-rule resolution path picks
    /// this policy for the named repo). Mirrors `scan_policy_env`'s
    /// non-scope defaults so only the dimensions under test
    /// (`scope`, `scan_backends`) vary.
    fn scan_policy_with_repo_scope_and_backends(
        name: &str,
        repository: &str,
        backends: Vec<&str>,
    ) -> Envelope<ScanPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ScanPolicy,
            metadata: Metadata { name: name.into() },
            spec: ScanPolicySpec {
                scope: ScopeSpec::Repository(hort_config::scope::RepositoryScope {
                    repository: repository.into(),
                }),
                severity_threshold: "high".into(),
                quarantine_duration: "24h".into(),
                require_approval: true,
                provenance_mode: "verify_if_present".into(),
                provenance_backends: vec!["cosign".to_string()],
                provenance_identities: Vec::new(),
                max_artifact_age: None,
                license_policy: serde_json::Value::Null,
                scan_backends: backends.into_iter().map(str::to_string).collect(),
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
                enforcement: "reject".into(),
            },
        }
    }

    // ===================================================================
    // OidcIssuer + ServiceAccount apply tests
    // ===================================================================

    use hort_config::oidc_issuer::OidcIssuerSpec;
    use hort_config::service_account::{FederatedIdentitySpec, ServiceAccountSpec};
    use std::collections::BTreeMap;

    pub(in crate::use_cases::apply_config_use_case) fn oidc_issuer_env_for_apply(
        name: &str,
    ) -> Envelope<OidcIssuerSpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::OidcIssuer,
            metadata: Metadata { name: name.into() },
            spec: OidcIssuerSpec {
                issuer_url: format!("https://{name}.example.com"),
                audiences: vec!["hort-server".into()],
                jwks_refresh_interval: "1h".into(),
                allowed_algorithms: vec!["RS256".into()],
                require_jti: true,
            },
        }
    }

    pub(in crate::use_cases::apply_config_use_case) fn service_account_env_for_apply(
        sa_name: &str,
        issuer: Option<&str>,
    ) -> Envelope<ServiceAccountSpec> {
        let federated_identities = match issuer {
            None => vec![],
            Some(issuer_name) => {
                let mut claims = BTreeMap::new();
                claims.insert("repository".into(), "my-org/my-repo".into());
                vec![FederatedIdentitySpec {
                    issuer: issuer_name.into(),
                    claims,
                }]
            }
        };
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ServiceAccount,
            metadata: Metadata {
                name: sa_name.into(),
            },
            spec: ServiceAccountSpec {
                federated_identities,
                fallback_rotation: None,
            },
        }
    }

    /// Lightweight helper for these tests; the project's
    /// `sample_repository()` returns a generic-format repo, but here we
    /// need a controllable `key`.
    pub(in crate::use_cases::apply_config_use_case) fn sample_repository_for_test(
        key: &str,
    ) -> Repository {
        Repository {
            id: Uuid::new_v4(),
            key: key.into(),
            name: key.into(),
            description: None,
            format: RepositoryFormat::Pypi,
            repo_type: RepositoryType::Hosted,
            storage_backend: "filesystem".into(),
            storage_path: format!("/data/{key}"),
            upstream_url: None,
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: hort_domain::entities::repository::PrefetchPolicy::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }
}
