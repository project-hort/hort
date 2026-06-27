//! `ApplyConfigUseCase` — execute a `DesiredState` against the
//! managed-write port methods (see
//! `docs/architecture/how-to/declare-gitops-config.md`).
//!
//! Wired into the boot sequence; this use case has no
//! HTTP surface. It is the single point of truth for "compute the
//! plan, then apply it" — the diff is in `hort-config`, the writes
//! land via the managed-write methods on `RepositoryRepository`,
//! `ClaimMappingRepository`, `PermissionGrantRepository`,
//! `CurationRuleRepository`, and through `PolicyUseCase` for
//! event-sourced kinds.
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
//! `ClaimMappingRepository::save_managed` /
//! `PermissionGrantRepository::save_managed` are **whole-partition
//! reconcile primitives**: the apply
//! branch builds the *complete* desired gitops-managed set, diffs it
//! against `list_managed_by_gitops` to emit one
//! `ClaimMappingApplied`/`PermissionGrantApplied` per added-or-changed
//! row and one `ClaimMappingRevoked`/`PermissionGrantRevoked` per
//! removed row (audit-event-per-mutation invariant), then calls
//! `save_managed(&complete_desired_set)` once — the adapter does the
//! atomic delete-absent + upsert-present. Because `save_managed`
//! reconciles the *entire* gitops partition, the ServiceAccount
//! `User`-subject grants and the envelope-declared grants are unioned
//! into one `save_managed(permission_grants)` call.
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
use hort_domain::ports::claim_mapping_repository::ClaimMappingRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
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
use crate::use_cases::read_expected_version;
use crate::use_cases::upstream_index_cache_invalidator::invalidate_after_reject;
use crate::use_cases::{
    AddExclusionCommand, CreatePolicyCommand, FieldChange, PolicyUseCase, RemoveExclusionCommand,
    UpdatePolicyCommand,
};

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
    /// `claim_mappings` (ADR 0012).
    /// `save_managed` is the atomic delete-absent + upsert-present
    /// primitive; revoke/apply audit events are emitted by this use
    /// case, not the adapter.
    claim_mappings: Arc<dyn ClaimMappingRepository>,
    /// Whole-partition reconcile port for
    /// `permission_grants` (ADR 0012;
    /// there is no `role_id` in the additive-claims model). A grant
    /// carries a sum-typed [`GrantSubject`] (`Claims` XOR `User`).
    /// `save_managed` reconciles the **entire** gitops partition, so
    /// envelope-declared grants and SA-owned `User`-subject
    /// grants are unioned into a single call.
    permission_grants: Arc<dyn PermissionGrantRepository>,
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
    /// The event-sourced
    /// retention-policy apply slot. `None` when the retention
    /// projection port + use case are not wired (test
    /// harnesses, and any composition that does not opt in); the
    /// production composition root (`hort-server`/`hort-worker`) installs
    /// it via [`Self::with_retention`]. When `None`,
    /// `apply_retention_policies` is a logged no-op (a `RetentionPolicy`
    /// YAML present with the slot unwired is operator-visible, not a
    /// silent drop). Builder-shaped exactly like
    /// `with_federated_jwt_validator` / `with_lint_config` so the
    /// constructor signature (9 call sites) stays unchanged.
    ///
    /// Open item — retention-apply slot unwired:
    /// `with_retention()` stays builder-optional until the
    /// consumer ships. Sweep this slot's `Option` shape when
    /// artifact retention goes live.
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

/// Compile-time gate for the
/// authorization-event append helpers ([`ApplyConfigUseCase::
/// append_authorization_events`] /
/// [`ApplyConfigUseCase::append_grouped_authorization_events`]).
///
/// **Architectural intent.** The helpers persist `RoleDefined` /
/// `GroupMappingAdded` / `PermissionGrantAdded` / etc. — a set of
/// audit events whose only legitimate emitter is the gitops apply
/// pipeline. Before this gate, any future contributor could call the
/// helpers from any code path inside `hort-app`; the architectural
/// invariant "authorization events come from gitops apply only" was
/// convention, not compile-time enforced. The token plus the pub-crate
/// constructor turns the invariant into a compile error: without a
/// `&GitOpsApplyToken`, the helpers refuse to compile, and a
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

impl ApplyConfigUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        claim_mappings: Arc<dyn ClaimMappingRepository>,
        permission_grants: Arc<dyn PermissionGrantRepository>,
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
    ) -> Self {
        Self {
            repositories,
            claim_mappings,
            permission_grants,
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
            // Retention apply opt-in (None until the
            // composition root calls `with_retention`). A
            // `RetentionPolicy` YAML with this unwired is a logged
            // no-op, never a silent drop.
            retention: None,
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
        }
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

    /// Install the event-sourced retention-policy apply
    /// dependencies (projection reader + `RetentionPolicyUseCase`).
    ///
    /// Composition root calls this after [`Self::new`]; without it,
    /// `apply_retention_policies` is a logged no-op. Builder-shaped
    /// like `with_federated_jwt_validator` so the constructor stays
    /// unchanged (the 9 `ApplyConfigUseCase::new` call sites are not
    /// touched — only the production composition root chains
    /// `.with_retention(...)`).
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
    /// the SA->issuer FK check, the `scanBackends` /
    /// `trust_upstream_publish_time` / `prefetchPolicy.maxAgeDays` /
    /// provenance linters, and the per-repo storage-backend check. Only the
    /// `build_snapshot` reads touch the database -- zero writes. (The
    /// `scanBackends` check validates against the compiled-in
    /// `crate::scanning::KNOWN_SCAN_BACKENDS` set, so it does no I/O and is
    /// immune to worker-registration timing -- see regression H20.)
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

        // The snapshot-free rows (rows 2,3,5,6,
        // 7,7b) are collected by the pure `StaticConfigValidator`, in
        // apply's row order, with NO early return / metric / `tracing`.
        // This caller walks the report below and reproduces the historical
        // first-failing-row abort + per-rule metric emission byte-
        // identically — the no-drift guarantee shared with the offline
        // `hort-server validate-config` command. The env/DB rows (1 above,
        // 4 below) stay inline.
        use crate::lint::{LinterRule, StaticConfigValidator};
        let report = StaticConfigValidator::new(
            self.provenance_capable_formats.clone(),
            self.effective_storage_backend,
        )
        .validate(desired);

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

        // ----- Post-row-4 snapshot-free rejects (rows 5,6,7,7b),
        //       collected by `StaticConfigValidator` above. -----
        //
        // Reproduce the historical first-failing-row abort byte-
        // identically: walk the rule order [trust_pt, prefetch,
        // provenance, storage-backend] and, on the FIRST rule with any
        // error finding, emit that rule's metric (where it has one — rows
        // 5/6 only, via `LinterRule::metric_rule`) once per finding, log
        // the same `error!`, and return that rule's
        // `AppError::Domain(DomainError::Validation(_))`. Later rules are
        // NOT emitted/reported.
        //
        // - Rows 5 (trust_upstream_publish_time × scan_backends:[])
        //   and 6 (PrefetchPolicy.max_age_days) historically
        //   `"; "`-join every finding of the row AND tick
        //   `hort_apply_config_linter_total{rule, result=reject}` once per
        //   finding (cardinality bounded by mappings / repositories).
        // - Rows 7 (provenance-config) and 7b (per-repo
        //   storage-backend mismatch) historically aborted on the FIRST
        //   violation WITHIN the row (single-message reject, no metric);
        //   the validator collects every finding for the offline CLI, but
        //   this caller takes only the first to stay byte-identical.
        for (rule, error_log) in [
            (
                LinterRule::TrustUpstreamPublishTimeRequiresScanBackends,
                "gitops apply: trust_upstream_publish_time × scan_backends:[] linter rejected combination(s)",
            ),
            (
                LinterRule::PrefetchMaxAgeDaysNotImplemented,
                "gitops apply: prefetchPolicy.maxAgeDays linter rejected envelope(s) (field accepted-but-inert)",
            ),
            (
                LinterRule::ProvenanceConfig,
                "gitops apply: provenanceMode linter rejected ScanPolicy envelope(s)",
            ),
            (
                LinterRule::RepoStorageBackendMismatch,
                "gitops apply: rejected — per-repository storage backend differs from the deployment's effective global backend; per-repository storage routing is unsupported in v2",
            ),
        ] {
            let messages: Vec<&str> = report
                .errors
                .iter()
                .filter(|f| f.rule == rule)
                .map(|f| f.message.as_str())
                .collect();
            if messages.is_empty() {
                continue;
            }
            // Per-rule metric (rows 5/6 only — `metric_rule` is `None`
            // for rows 7/7b). One increment per offending finding.
            if let Some(metric_rule) = rule.metric_rule() {
                tracing::error!(error_count = messages.len(), "{error_log}");
                for _ in 0..messages.len() {
                    crate::metrics::emit_apply_config_linter(
                        metric_rule,
                        crate::metrics::LinterResult::Reject,
                    );
                }
                return Err(AppError::Domain(DomainError::Validation(
                    messages.join("; "),
                )));
            }
            // Rows 7 / 7b — first-violation-within-the-row abort
            // (single-message reject, no linter metric), preserving the
            // historical `validate_provenance_config` /
            // `reject_repo_storage_backend_mismatch` shape exactly.
            tracing::error!("{error_log}");
            return Err(AppError::Domain(DomainError::Validation(
                messages[0].to_string(),
            )));
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
        let mut report = ApplyReport::default();

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
        self.apply_retention_policies(&desired, &mut report).await?;

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
        self.apply_oidc_issuers(&plan.oidc_issuers, &mut report)
            .await?;
        self.apply_service_accounts(&plan.service_accounts, &mut report)
            .await?;

        // ----- Consolidated PermissionGrant
        // reconcile (runs LAST). `PermissionGrantRepository::save_managed`
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
                name: claim_mapping_identity_name(&m.idp_group, &m.claim),
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
        // Compute the SA-owned permission-grant
        // digest set BEFORE we drop the full SA aggregates. Each SA
        // contributes exactly one digest (the canonical form is
        // `sha256("sa-grant|{sa.id}|{role}|{permission}|{sorted_repos}")`,
        // identical to `reconcile_service_account_grants` / `delete_
        // service_account_grants` so the set matches every row those
        // helpers wrote). The set covers every snapshot SA — including
        // SAs about to be deleted — because their rows are in the DB
        // until `apply_service_accounts` removes them; the PG-sweep
        // must skip them throughout the apply.
        let sa_owned_grant_digests: HashSet<[u8; 32]> = sa_entities
            .iter()
            .filter_map(|sa| {
                // `service_account_permission_for_role` is fallible —
                // a stored row with a corrupt role lands here. Skip
                // it: the PG-sweep won't see a digest for the corrupt
                // SA, so it falls back to the default delete sweep,
                // which is harmless because the apply pipeline will
                // also fail downstream (`reconcile_service_account_
                // grants` raises the same error). Logging the skip is
                // worth it though.
                let Ok(permission) = service_account_permission_for_role(&sa.role) else {
                    tracing::warn!(
                        service_account = %sa.name,
                        role = %sa.role,
                        "build_snapshot: invalid role on stored service account; \
                         excluded from sa_owned_grant_digests"
                    );
                    return None;
                };
                let mut sorted: Vec<&str> = sa.repositories.iter().map(String::as_str).collect();
                sorted.sort_unstable();
                let canonical = format!(
                    "sa-grant|{}|{}|{}|{}",
                    sa.id,
                    sa.role,
                    permission,
                    sorted.join(",")
                );
                Some(sha256_of(&canonical))
            })
            .collect();
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
            sa_owned_grant_digests,
            sa_backing_user_ids_by_name,
        })
    }

    // -- Stage 1 helpers ----------------------------------------------------

    /// Apply `ClaimMapping` create / update / delete (ADR 0012;
    /// `ClaimMappingRepository`, `claim_mappings` table —
    /// there is no `roles` table in the additive-claims model).
    ///
    /// **Whole-partition reconcile.**
    /// `ClaimMappingRepository::save_managed` atomically deletes every
    /// gitops-managed row absent from `items` and upserts every row in
    /// `items` (keyed on the `(idp_group, claim)` UNIQUE identity). The
    /// branch therefore:
    ///
    /// 1. builds the **complete** desired gitops-managed mapping set
    ///    from every declared envelope (`desired.claim_mappings`, not
    ///    just the changed subset — `save_managed` is whole-partition);
    /// 2. reads the prior managed set (`list_managed_by_gitops`) and
    ///    diffs it against the desired set by `(idp_group, claim)` to
    ///    emit one `ClaimMappingApplied` per added-or-changed row and
    ///    one `ClaimMappingRevoked` per removed row
    ///    (audit-event-per-mutation invariant);
    /// 3. calls `save_managed(&complete_desired_set)` once.
    ///
    /// Diff-then-emit failure-mode contract is preserved:
    /// a `save_managed` failure aborts the apply (strict-atomic) before
    /// any audit event lands; a save that succeeds followed by an
    /// event-store append failure surfaces the apply error and the next
    /// apply re-runs the diff against the now-saved state (idempotent —
    /// no events to re-emit). The `plan` argument drives the
    /// per-envelope `created` / `updated` / `deleted` report + metric
    /// counters; the audit events are derived from the live
    /// prior-vs-desired diff so they stay correct even if the plan's
    /// coarse classification and the row state diverge.
    async fn apply_claim_mappings(
        &self,
        plan: &KindPlan<ClaimMappingSpec, String>,
        desired: &DesiredState,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        // Prior gitops-managed set, keyed by the natural identity
        // `(idp_group, claim)` — the same key `save_managed` upserts on
        // and the table's UNIQUE constraint enforces.
        let prior = self.claim_mappings.list_managed_by_gitops().await?;
        let prior_by_identity: HashMap<(String, String), ClaimMapping> = prior
            .into_iter()
            .map(|m| ((m.idp_group.clone(), m.claim.clone()), m))
            .collect();

        // Complete desired gitops-managed set — every declared envelope,
        // not just the plan's changed subset (`save_managed` reconciles
        // the whole partition). The digest is the canonicalised spec
        // hash; the adapter writes `managed_by = gitops` unconditionally.
        let mut desired_set: Vec<ClaimMapping> = Vec::with_capacity(desired.claim_mappings.len());
        let mut desired_identities: HashSet<(String, String)> = HashSet::new();
        let mut authz_events: Vec<EventToAppend> = Vec::new();
        for env in &desired.claim_mappings {
            let digest = spec_digest_claim_mapping(&env.spec);
            let idp_group = env.spec.idp_group.clone();
            let claim = env.spec.claim.clone();
            let identity = (idp_group.clone(), claim.clone());
            desired_identities.insert(identity.clone());

            // Reuse the prior row's surrogate id when the identity
            // already exists so the audit `mapping_id` stays stable
            // across re-applies; mint a fresh one for a brand-new
            // mapping.
            let existing = prior_by_identity.get(&identity);
            let mapping_id = existing.map(|m| m.id).unwrap_or_else(Uuid::new_v4);

            // Emit `ClaimMappingApplied` for create OR digest change.
            // An unchanged digest is a no-op (no audit event, no churn).
            let changed = match existing {
                None => true,
                Some(prev) => prev.managed_by_digest != Some(digest),
            };
            if changed {
                authz_events.push(EventToAppend::new(DomainEvent::ClaimMappingApplied(
                    ClaimMappingApplied {
                        mapping_id,
                        idp_group: idp_group.clone(),
                        claim: claim.clone(),
                    },
                )));
            }

            desired_set.push(ClaimMapping {
                id: mapping_id,
                idp_group,
                claim,
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some(digest),
            });
        }

        // Revocations: every prior gitops-managed identity absent from
        // the desired set. `save_managed` deletes these rows; the audit
        // event attests the removal.
        for ((idp_group, claim), prev) in &prior_by_identity {
            if !desired_identities.contains(&(idp_group.clone(), claim.clone())) {
                authz_events.push(EventToAppend::new(DomainEvent::ClaimMappingRevoked(
                    ClaimMappingRevoked {
                        mapping_id: prev.id,
                        idp_group: idp_group.clone(),
                        claim: claim.clone(),
                    },
                )));
            }
        }

        // Per-envelope report + metric counters from the diff plan,
        // `kind="claim_mapping"`.
        for _ in &plan.create {
            emit_gitops_object(gitops_kind::CLAIM_MAPPING, GitopsObjectResult::Created);
            report.created += 1;
        }
        for _ in &plan.update {
            emit_gitops_object(gitops_kind::CLAIM_MAPPING, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for _ in &plan.delete {
            emit_gitops_object(gitops_kind::CLAIM_MAPPING, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        // Whole-partition atomic delete-absent + upsert-present.
        self.claim_mappings.save_managed(&desired_set).await?;

        self.append_authorization_events(authz_events, Kind::ClaimMapping, token)
            .await?;
        Ok(())
    }

    /// Append a batch of authorization audit events to the global
    /// authorization stream.
    ///
    /// `expected_version: Any` — gitops apply runs in
    /// a single boot-time process and concurrent apply is prevented
    /// at a higher layer (boot lock). No-op when `events` is empty
    /// (avoids an unnecessary append round-trip).
    ///
    /// **Compile-time gate.** The
    /// `_token: &GitOpsApplyToken` argument refuses to compile any
    /// caller outside the gitops apply pipeline. The token is
    /// constructible only from inside `hort-app` (via the `pub(crate)`
    /// constructor), and a non-gitops caller has nothing to pass. See
    /// [`GitOpsApplyToken`] for the architectural rationale.
    async fn append_authorization_events(
        &self,
        events: Vec<EventToAppend>,
        kind: Kind,
        _token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let actor = gitops_actor_for_kind(kind);
        self.events
            .append(AppendEvents {
                stream_id: StreamId::authorization(),
                expected_version: ExpectedVersion::Any,
                events,
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor,
            })
            .await?;
        Ok(())
    }

    /// Append a per-stream batch of authorization audit events.
    ///
    /// Used by the repo-scoped emitters (`apply_permission_grants`,
    /// `apply_upstream_mappings`) that route events to either
    /// `StreamCategory::Repository(r)` or `StreamCategory::Authorization`
    /// depending on the per-row `repository_id`. One append round-trip
    /// per stream — empty buckets are skipped. `expected_version: Any`
    /// (gitops apply is single-process per boot lock).
    ///
    /// **Compile-time gate.** Same
    /// `_token: &GitOpsApplyToken` argument as
    /// [`append_authorization_events`](Self::append_authorization_events) — see that
    /// docstring for the full architectural rationale.
    async fn append_grouped_authorization_events(
        &self,
        events_by_stream: HashMap<StreamId, Vec<EventToAppend>>,
        kind: Kind,
        _token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        if events_by_stream.is_empty() {
            return Ok(());
        }
        let actor = gitops_actor_for_kind(kind);
        // Sort by stream_id for deterministic test assertions; the
        // event store contract does not require ordering across
        // streams (each stream's `stream_position` is independent),
        // but iteration order on a HashMap is non-deterministic and a
        // future test that asserts append ordering would be flaky
        // otherwise. Sort key is the stream's Display form.
        let mut sorted: Vec<(StreamId, Vec<EventToAppend>)> =
            events_by_stream.into_iter().collect();
        sorted.sort_by_key(|(s, _)| s.to_string());
        for (stream_id, events) in sorted {
            if events.is_empty() {
                continue;
            }
            self.events
                .append(AppendEvents {
                    stream_id,
                    expected_version: ExpectedVersion::Any,
                    events,
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: actor.clone(),
                })
                .await?;
        }
        Ok(())
    }

    /// Apply curation-rule create / update / delete from the gitops
    /// plan + run the retroactive curation evaluation pass.
    ///
    /// The retroactive pass fires on every rule that is either
    /// **newly declared** OR **tightened** (`Allow → Warn`, `Allow →
    /// Block`, `Warn → Block`). Pattern broadening is **deferred**
    /// per the design — pattern-equivalence detection isn't trivial,
    /// and operators who broaden a pattern can re-trigger by also
    /// tightening the action or deleting + re-adding the rule.
    /// Weakenings (`Block → Warn`, `Block → Allow`, `Warn → Allow`)
    /// and rule deletions emit no retroactive events: rejection is
    /// sticky per the asymmetric semantics, mirroring the architect-
    /// skill quarantine invariant 3 admin-explicit-release path.
    ///
    /// Strict-atomic: any `ArtifactRejected` append failure (typically
    /// optimistic-concurrency `Conflict` from a concurrent ingest)
    /// aborts the apply pipeline. The operator restarts; the second
    /// pass re-resolves the now-consistent state and continues.
    async fn apply_curation_rules(
        &self,
        plan: &KindPlan<hort_config::curation_rule::CurationRuleSpec, Uuid>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        // Capture old action BEFORE save_managed
        // for every rule in `plan.update`. Tightening detection compares
        // old vs new and is the trigger for the retroactive pass.
        let mut old_action_by_name: HashMap<String, CurationRuleAction> = HashMap::new();
        for env in &plan.update {
            if let Some(existing) = self.curation_rules.find_by_name(&env.metadata.name).await? {
                old_action_by_name.insert(env.metadata.name.clone(), existing.action);
            }
        }

        // Track which rules need a retroactive evaluation pass after
        // `save_managed` lands. A rule is a candidate when:
        //   1. it is newly declared (`plan.create`), OR
        //   2. its action tightened on update.
        let mut retro_candidate_names: Vec<String> = Vec::new();

        for env in plan.create.iter() {
            // Re-use existing UUID if a managed row already exists for
            // this name (the rule is in `plan.create` because the
            // diff classifier saw no row, but a defensive lookup
            // matches the established pattern). Mint otherwise.
            let digest = spec_digest_curation_rule(&env.spec);
            let id = self
                .curation_rules
                .find_by_name(&env.metadata.name)
                .await?
                .map(|r| r.id)
                .unwrap_or_else(Uuid::new_v4);
            let rule = build_curation_rule_from_spec(env, id, &digest)?;
            self.curation_rules.save_managed(&rule).await?;
            retro_candidate_names.push(env.metadata.name.clone());
        }

        for env in plan.update.iter() {
            let digest = spec_digest_curation_rule(&env.spec);
            let id = self
                .curation_rules
                .find_by_name(&env.metadata.name)
                .await?
                .map(|r| r.id)
                .unwrap_or_else(Uuid::new_v4);
            let rule = build_curation_rule_from_spec(env, id, &digest)?;
            // Detect tightening before the save: Allow → Warn|Block,
            // Warn → Block. (Allow → Allow / Warn → Warn / Block → Block
            // would be `unchanged`, not in `plan.update`.)
            let old = old_action_by_name.get(&env.metadata.name).copied();
            let tightened = matches!(
                (old, rule.action),
                (Some(CurationRuleAction::Allow), CurationRuleAction::Warn)
                    | (Some(CurationRuleAction::Allow), CurationRuleAction::Block)
                    | (Some(CurationRuleAction::Warn), CurationRuleAction::Block)
            );
            self.curation_rules.save_managed(&rule).await?;
            if tightened {
                retro_candidate_names.push(env.metadata.name.clone());
            }
        }

        for _ in &plan.create {
            emit_gitops_object(gitops_kind::CURATION_RULE, GitopsObjectResult::Created);
            report.created += 1;
        }
        for _ in &plan.update {
            emit_gitops_object(gitops_kind::CURATION_RULE, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        // Same id-vs-name mismatch as `apply_roles`: the `KindPlan`
        // emits ids, the port's `delete_managed` takes a name. Look
        // each up via the bounded `list_managed_by_gitops` snapshot.
        let managed = self.curation_rules.list_managed_by_gitops().await?;
        let name_by_id: HashMap<Uuid, String> =
            managed.iter().map(|r| (r.id, r.name.clone())).collect();
        for id in &plan.delete {
            let name = name_by_id.get(id).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "curation rule id {id} scheduled for delete is not in list_managed_by_gitops"
                ))
            })?;
            self.curation_rules.delete_managed(name).await?;
            emit_gitops_object(gitops_kind::CURATION_RULE, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        // Retroactive curation evaluation. Runs AFTER all
        // rule writes in this pass have landed so the per-repo rule set
        // each candidate is evaluated against is the post-apply view.
        for rule_name in retro_candidate_names {
            self.run_retroactive_curation_for_rule(&rule_name, report)
                .await?;
        }

        Ok(())
    }

    /// Run the retroactive curation evaluation pass for one
    /// candidate rule.
    ///
    /// Resolves linked repos via `list_repos_for_rule`, materialises
    /// each repo's just-applied rule set via `list_for_repo`, walks
    /// active artifacts, and emits `CurationApplied` (per `RetroWarn`
    /// or `RetroBlock`) plus `ArtifactRejected` (per `RetroBlock`).
    ///
    /// `RetroBlock` events go through `commit_transition` so the
    /// artifact-state mutation and event are atomic — a concurrent
    /// ingest cannot leave the artifact `Released` while the
    /// `ArtifactRejected` event lands on its stream. Optimistic-
    /// concurrency conflicts surface as `DomainError::Conflict` and
    /// are mapped to `AppError::ConcurrentModification` via
    /// [`map_concurrent_modification`] — strict-atomic abort.
    async fn run_retroactive_curation_for_rule(
        &self,
        rule_name: &str,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let rule = self
            .curation_rules
            .find_by_name(rule_name)
            .await?
            .ok_or_else(|| {
                DomainError::Invariant(format!(
                    "retroactive curation: rule '{rule_name}' missing after save_managed"
                ))
            })?;

        let repo_ids = self.curation_rules.list_repos_for_rule(rule.id).await?;
        if repo_ids.is_empty() {
            tracing::debug!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                "retroactive curation pass: no linked repos, skipping"
            );
            return Ok(());
        }

        let actor = gitops_actor_for_kind(Kind::CurationRule);

        for repo_id in repo_ids {
            // Materialise the just-applied rule set for this repo —
            // first-match-wins iteration depends on the post-apply
            // ordering, so we re-read every iteration.
            let rules_active_on_repo = self.curation_rules.list_for_repo(repo_id).await?;
            let active_list = self.artifacts.list_active_for_repo(repo_id).await?;
            // `list_active_for_repo`
            // returns a `LimitedList` capped at `LIMIT_LIST_MAX_ITEMS`. When the
            // cap fires we still process what we got. Whether the remainder
            // gets picked up by a subsequent apply depends on the rule effects:
            // a `RetroBlock` rule mutates the active set (blocked artifacts
            // leave it), so the next pass walks fresh territory; a
            // `RetroWarn`-only rule set does not mutate state, so an
            // unchanging >cap active set will re-emit the same warning every
            // apply. The `warn!` below is the operator-actionable signal.
            if active_list.truncated {
                tracing::warn!(
                    repository_id = %repo_id,
                    cap = hort_domain::types::LIMIT_LIST_MAX_ITEMS,
                    "result set truncated; only the first cap active artifacts \
                     in this repo were re-evaluated against the new policy. \
                     If this triggers repeatedly without the active set \
                     shrinking, review whether any rule has a Block effect or \
                     whether the cap should be raised for this repo."
                );
            }
            let artifacts = active_list.items;

            let mut retro_warn = 0usize;
            let mut retro_block = 0usize;

            for artifact in artifacts {
                let coords = hort_domain::types::ArtifactCoords {
                    name: artifact.name.clone(),
                    name_as_published: artifact.name_as_published.clone(),
                    version: artifact.version.clone(),
                    path: artifact.path.clone(),
                    // `Artifact` carries the repository's format, but we
                    // need it on the coords for the format-gate; resolve
                    // via the repository row.
                    format: self
                        .repositories
                        .find_by_id(artifact.repository_id)
                        .await?
                        .format,
                    metadata: serde_json::Value::Null,
                };

                let outcome = evaluate_curation_retroactive(&coords, &rules_active_on_repo);
                match outcome {
                    RetroactiveCurationOutcome::NoChange => {
                        emit_policy_evaluation(
                            policy_decision_point::CURATION_RETROACTIVE,
                            PolicyEvaluationResult::NoChange,
                        );
                    }
                    RetroactiveCurationOutcome::RetroWarn {
                        rule_name: r_name,
                        reason,
                        rule_id,
                    } => {
                        self.append_curation_applied(
                            repo_id,
                            coords.clone(),
                            rule_id,
                            r_name,
                            CurationActionTag::Warn,
                            reason.clone(),
                            actor.clone(),
                        )
                        .await
                        .map_err(map_concurrent_modification)?;
                        retro_warn += 1;
                        report.retro_warn_count += 1;
                        tracing::info!(
                            rule_id = %rule_id,
                            repository_id = %repo_id,
                            artifact_id = %artifact.id,
                            action = "warn",
                            "retroactive curation transition"
                        );
                        emit_policy_evaluation(
                            policy_decision_point::CURATION_RETROACTIVE,
                            PolicyEvaluationResult::RetroWarn,
                        );
                        emit_policy_violations(
                            policy_decision_point::CURATION_RETROACTIVE,
                            &[hort_domain::events::PolicyViolation {
                                rule: "curation-warn".to_string(),
                                severity: SeverityThreshold::Low,
                                message: reason,
                                details: serde_json::Value::Null,
                            }],
                        );
                    }
                    RetroactiveCurationOutcome::RetroBlock {
                        rule_name: r_name,
                        reason,
                        rule_id,
                    } => {
                        self.append_curation_applied(
                            repo_id,
                            coords.clone(),
                            rule_id,
                            r_name.clone(),
                            CurationActionTag::Block,
                            reason.clone(),
                            actor.clone(),
                        )
                        .await
                        .map_err(map_concurrent_modification)?;
                        self.commit_retroactive_block(
                            artifact,
                            rule_id,
                            reason.clone(),
                            actor.clone(),
                        )
                        .await
                        .map_err(map_concurrent_modification)?;
                        retro_block += 1;
                        report.retro_block_count += 1;
                        tracing::info!(
                            rule_id = %rule_id,
                            repository_id = %repo_id,
                            action = "block",
                            "retroactive curation transition"
                        );
                        emit_policy_evaluation(
                            policy_decision_point::CURATION_RETROACTIVE,
                            PolicyEvaluationResult::RetroBlock,
                        );
                        emit_policy_violations(
                            policy_decision_point::CURATION_RETROACTIVE,
                            &[hort_domain::events::PolicyViolation {
                                rule: "curation-block".to_string(),
                                severity: SeverityThreshold::High,
                                message: reason,
                                details: serde_json::Value::Null,
                            }],
                        );
                    }
                }
            }

            tracing::info!(
                rule_id = %rule.id,
                repository_id = %repo_id,
                retro_warn,
                retro_block,
                "retroactive curation pass complete"
            );
        }

        Ok(())
    }

    /// Append a `CurationApplied` event on the per-repo curation
    /// stream. No artifact-state change here — the `RetroBlock` arm
    /// also calls [`Self::commit_retroactive_block`] for the artifact-
    /// stream side.
    #[allow(clippy::too_many_arguments)]
    async fn append_curation_applied(
        &self,
        repository_id: Uuid,
        coords: hort_domain::types::ArtifactCoords,
        rule_id: Uuid,
        rule_name: String,
        action: CurationActionTag,
        reason: String,
        actor: Actor,
    ) -> AppResult<()> {
        let stream_id = StreamId::curation_per_repo(repository_id);
        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;
        let event = CurationApplied {
            repository_id,
            coords,
            rule_id,
            rule_name,
            action,
            reason,
            trigger: CurationTrigger::Retroactive,
        };
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend::new(DomainEvent::CurationApplied(event))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor,
            })
            .await?;
        Ok(())
    }

    /// Commit the artifact-stream side of a `RetroBlock`. Atomic —
    /// `commit_transition` writes the artifact-state mutation AND the
    /// `ArtifactRejected` event in one transaction.
    async fn commit_retroactive_block(
        &self,
        mut artifact: hort_domain::entities::artifact::Artifact,
        rule_id: Uuid,
        reason: String,
        actor: Actor,
    ) -> AppResult<()> {
        let stream_id = StreamId::artifact(artifact.id);
        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;
        let artifact_id = artifact.id;
        let reject_event = artifact.reject_from_retroactive_curation(rule_id, reason)?;
        self.artifact_lifecycle
            .commit_transition(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactRejected(
                        reject_event,
                    ))],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor,
                },
                None,
            )
            .await?;

        // Sweep `content_references`
        // rows for the rejected source. Same posture as the
        // scan-driven reject path in `quarantine_use_case`: the
        // artifact row stays alive after `ArtifactRejected` (rejection
        // is sticky; hard-delete is forbidden), so the
        // FK CASCADE never fires and the surviving rows would mislead
        // `PurgeUseCase`. Failure is warn-only — the
        // rejection itself has landed. The refcount reconcile sweep
        // heals any drift.
        if let Err(e) = self.content_references.delete_by_source(artifact_id).await {
            tracing::warn!(
                artifact_id = %artifact_id,
                error = %e,
                stage = "content_references_delete_on_reject",
                "content_references delete failed on retroactive curation reject; refcount row \
                 not deleted on reject — refcount eventual, operator reconcile is future work"
            );
        }

        // Best-effort upstream-index cache
        // invalidation. Same post-commit-warn-on-fail posture as the
        // refcount sweep above and the symmetric curator-block /
        // scan-driven-reject hooks: the retroactive `ArtifactRejected`
        // append already committed; the `NonServableStatusFilter` on
        // the next index build is the load-bearing close. No-op when
        // the composition root did not wire an invalidator.
        if let Some(invalidator) = self.upstream_index_cache_invalidator.as_ref() {
            invalidate_after_reject(
                invalidator,
                artifact_id,
                artifact.repository_id,
                &artifact.name,
            )
            .await;
        }

        Ok(())
    }

    // -- Stage 2 helpers ----------------------------------------------------

    async fn apply_repository_rows(
        &self,
        plan: &KindPlan<RepositorySpec, Uuid>,
        desired: &DesiredState,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        for env in plan.create.iter().chain(plan.update.iter()) {
            let digest = spec_digest_repository(&env.spec);
            let id = self.resolve_repo_id(&env.metadata.name).await?;
            let repo = build_repository_from_spec(env, id, self.effective_storage_backend)?;
            self.repositories.save_managed(&repo, &digest).await?;
        }
        for _ in &plan.create {
            emit_gitops_object(gitops_kind::REPOSITORY, GitopsObjectResult::Created);
            report.created += 1;
        }
        for _ in &plan.update {
            emit_gitops_object(gitops_kind::REPOSITORY, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for id in &plan.delete {
            self.repositories.delete_managed(*id).await?;
            emit_gitops_object(gitops_kind::REPOSITORY, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        // Junction-edge writes for every
        // declared repository whose spec carries `curation_rules`.
        // Always-write rather than digest-tracked-edges: the per-edge
        // spec digest doesn't include the resolved-rule ids (it's a
        // list of rule names), and `set_curation_rules_for_repository`
        // is idempotent. Cleared (empty Vec) reaches us identically to
        // a populated Vec — the operator removed every name and the
        // junction now empties.
        for env in &desired.repositories {
            let rule_names = env.spec.curation_rules.as_deref().unwrap_or(&[]);
            // Resolve repo id from the post-stage-1+repo-row state.
            let repo = self.repositories.find_by_key(&env.metadata.name).await?;
            // Resolve rule names → ids via find_by_name on the freshly-
            // applied rules. Validation in `validate_against` already
            // confirmed every name is a declared CurationRule, so the
            // `None` branch here would only fire on a port-layer
            // inconsistency — surface as Invariant.
            let mut rule_ids = Vec::with_capacity(rule_names.len());
            for name in rule_names {
                let rule = self
                    .curation_rules
                    .find_by_name(name)
                    .await?
                    .ok_or_else(|| {
                        DomainError::Invariant(format!(
                            "repository '{}' references curation rule '{name}' that vanished \
                             between stage 1 apply and stage 2 junction write",
                            env.metadata.name
                        ))
                    })?;
                rule_ids.push(rule.id);
            }
            self.curation_rules
                .set_curation_rules_for_repository(repo.id, &rule_ids)
                .await?;
        }
        Ok(())
    }

    /// Apply event-sourced `ScanPolicy` envelopes.
    ///
    /// For each desired envelope:
    /// - Read the projection by name. `None` → mint a new policy via
    ///   `PolicyUseCase::create_policy`.
    /// - `Some(_)` → consult `ScanPolicyApplier::diff` to compute the
    ///   minimal update event set. Extract each `PolicyUpdated.field`
    ///   into the corresponding `FieldChange<_>` on `UpdatePolicyCommand`
    ///   and dispatch through `PolicyUseCase::update_policy`.
    ///
    /// For every active projection whose name is absent from desired,
    /// archive it via `PolicyUseCase::archive_policy`.
    async fn apply_scan_policies(
        &self,
        desired: &DesiredState,
        repo_id_by_name: &HashMap<String, Uuid>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let actor = gitops_actor_for_kind(Kind::ScanPolicy);
        let applier = ScanPolicyApplier::new(repo_id_by_name.clone());

        let desired_names: HashSet<&str> = desired
            .scan_policies
            .iter()
            .map(|e| e.metadata.name.as_str())
            .collect();

        // Apply each desired policy.
        for env in &desired.scan_policies {
            // First, look only at active rows (`find_by_name` filters
            // archived). If found, take the unchanged / update branch.
            // Otherwise probe `find_by_name_including_archived` so we
            // can distinguish "never existed" from "archived row of the
            // same name exists" — the latter requires reactivation
            // before any spec diff is applied
            // (gitops re-declaring an archived YAML must
            // preserve `policy_id` + event-stream history rather than
            // colliding with the existing UNIQUE-name row).
            let active = self
                .policy_projections
                .find_by_name(&env.metadata.name)
                .await?;
            match active {
                Some(proj) => {
                    let projection_opt = Some(proj.clone());
                    let events = applier.diff(env, projection_opt.as_ref());
                    if events.is_empty() {
                        emit_gitops_object(gitops_kind::SCAN_POLICY, GitopsObjectResult::Unchanged);
                        report.unchanged += 1;
                    } else {
                        let cmd = update_command_from_diff(proj.policy_id, env, repo_id_by_name);
                        self.policies
                            .update_policy(cmd, actor.clone())
                            .await
                            .map_err(map_concurrent_modification)?;
                        emit_gitops_object(gitops_kind::SCAN_POLICY, GitopsObjectResult::Updated);
                        // Emit one
                        // `hort_gitops_events_emitted_total` per event the
                        // applier produced. `update_policy` appends one
                        // `PolicyUpdated` per actually-changed field —
                        // the applier's diff and the use case's diff
                        // both visit the same field set in the same
                        // order, so `events.len()` is the canonical
                        // event count for this update. Label value
                        // comes from `DomainEvent::event_type()` — a
                        // `&'static str` from a static table.
                        for event in &events {
                            emit_gitops_event(gitops_kind::SCAN_POLICY, event.event_type());
                        }
                        report.updated += 1;
                    }
                }
                None => {
                    // No active row. Probe for an archived row of the
                    // same name before falling through to create.
                    let archived = self
                        .policy_projections
                        .find_by_name_including_archived(&env.metadata.name)
                        .await?;
                    match archived {
                        Some(proj) if proj.archived => {
                            // Reactivate first, then diff against the
                            // post-reactivation projection so any spec
                            // deltas land as a follow-on PolicyUpdated
                            // batch in the same apply pass.
                            self.policies
                                .reactivate_policy(proj.policy_id, actor.clone())
                                .await
                                .map_err(map_concurrent_modification)?;
                            emit_gitops_object(
                                gitops_kind::SCAN_POLICY,
                                GitopsObjectResult::Updated,
                            );
                            emit_gitops_event(gitops_kind::SCAN_POLICY, "PolicyReactivated");

                            // Re-read to pick up the bumped
                            // stream_version + flipped `archived` flag
                            // before computing the spec diff. The
                            // applier's `diff` ignores the archived
                            // field, so any spec deltas surface as
                            // ordinary PolicyUpdated events.
                            let post = self
                                .policy_projections
                                .find_by_name(&env.metadata.name)
                                .await?;
                            let events = applier.diff(env, post.as_ref());
                            if !events.is_empty() {
                                let cmd =
                                    update_command_from_diff(proj.policy_id, env, repo_id_by_name);
                                self.policies
                                    .update_policy(cmd, actor.clone())
                                    .await
                                    .map_err(map_concurrent_modification)?;
                                for event in &events {
                                    emit_gitops_event(gitops_kind::SCAN_POLICY, event.event_type());
                                }
                            }
                            report.updated += 1;
                        }
                        // No row in any state — clean create.
                        _ => {
                            // Pipeline mints id (the design-doc choice —
                            // avoids the applier's mint-and-discard).
                            // Build the command directly from the spec.
                            let cmd = create_command_from_spec(env, repo_id_by_name);
                            self.policies
                                .create_policy(cmd, actor.clone())
                                .await
                                .map_err(map_concurrent_modification)?;
                            emit_gitops_object(
                                gitops_kind::SCAN_POLICY,
                                GitopsObjectResult::Created,
                            );
                            // Emit the per-event
                            // counter. `event_type` is the `DomainEvent`
                            // discriminant (catalog-bounded), not a
                            // free-form caller string.
                            // `PolicyUseCase::create_policy` appends
                            // exactly one `PolicyCreated`; emit one
                            // increment after the append succeeds.
                            emit_gitops_event(gitops_kind::SCAN_POLICY, "PolicyCreated");
                            report.created += 1;
                        }
                    }
                }
            }
        }

        // Archive every active projection that disappeared from desired.
        let active = self.policy_projections.list_active().await?;
        for proj in active {
            if !desired_names.contains(proj.name.as_str()) {
                self.policies
                    .archive_policy(proj.policy_id, actor.clone())
                    .await
                    .map_err(map_concurrent_modification)?;
                emit_gitops_object(gitops_kind::SCAN_POLICY, GitopsObjectResult::Deleted);
                // `archive_policy` appends exactly
                // one `PolicyArchived` event.
                emit_gitops_event(gitops_kind::SCAN_POLICY, "PolicyArchived");
                report.deleted += 1;
            }
        }
        Ok(())
    }

    /// Apply event-sourced `RetentionPolicy` envelopes.
    ///
    /// Mirrors [`Self::apply_scan_policies`]: per desired envelope,
    /// `find_by_name` → create (no row) / update (active row, predicate
    /// or scope changed; `RetentionPolicyUseCase::update_policy`
    /// short-circuits an unchanged spec to a no-op) / unchanged. Every
    /// active projection absent from desired is archived.
    ///
    /// **Terminal-archive divergence from the ScanPolicy reactivation
    /// path:** RetentionPolicy has no `Reactivated` event. A re-declared *archived*
    /// name is treated as a **new policy** (fresh `policy_id`) — the
    /// partial-unique-on-active-name index does not collide because it
    /// only covers `archived = false`, and the old archived stream
    /// stays as audit history. So there is no
    /// `find_by_name_including_archived` reactivate branch here; the
    /// `find_by_name` (active-only) miss falls straight to create.
    ///
    /// **Apply-time security-scope warning:**
    /// after resolving the predicate + scope, if the predicate is
    /// security-driven AND the scope does not exclude
    /// `IngestSource(Direct)`, emit an `info!` (NOT an error — the
    /// policy still applies; this is operator-intent advisory). The
    /// runtime retention evaluator deliberately does NOT block; this
    /// is the single home of that warning.
    ///
    /// No-op (logged) when the retention apply slot is unwired
    /// (`with_retention` not called) — a `RetentionPolicy` YAML present
    /// with the slot unwired is operator-visible, never a silent drop.
    ///
    /// Open item — retention-apply slot unwired:
    /// `with_retention()` stays builder-optional until the
    /// consumer ships. Sweep this slot's `Option` shape when
    /// artifact retention goes live.
    async fn apply_retention_policies(
        &self,
        desired: &DesiredState,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let Some(retention) = self.retention.as_ref() else {
            if !desired.retention_policies.is_empty() {
                tracing::warn!(
                    count = desired.retention_policies.len(),
                    "RetentionPolicy envelopes present but the retention apply \
                     slot is unwired (ApplyConfigUseCase::with_retention not \
                     called) — skipping; these policies will NOT be applied \
                     until the composition root wires retention"
                );
            }
            return Ok(());
        };

        let actor = gitops_actor_for_kind(Kind::RetentionPolicy);
        let desired_names: HashSet<&str> = desired
            .retention_policies
            .iter()
            .map(|e| e.metadata.name.as_str())
            .collect();

        for env in &desired.retention_policies {
            let name = &env.metadata.name;
            // Resolve the JSON-shaped machine-envelope predicate +
            // scope into domain enums (the `hort-config` layer
            // holds them as `serde_json::Value`; per-spec validation
            // already ran in `DesiredState::validate`, so a parse
            // failure here is a contract violation surfaced as a
            // domain Validation error).
            let predicate = hort_config::retention_policy::predicate_from_value(
                &env.spec.predicate,
            )
            .map_err(|e| {
                AppError::Domain(DomainError::Validation(format!(
                    "RetentionPolicy '{name}': predicate resolve: {e}"
                )))
            })?;
            let scope =
                hort_config::retention_policy::scope_from_value(&env.spec.scope).map_err(|e| {
                    AppError::Domain(DomainError::Validation(format!(
                        "RetentionPolicy '{name}': scope resolve: {e}"
                    )))
                })?;

            // A security-driven predicate must exclude
            // direct uploads, or the operator is told (advisory, NOT
            // a reject — the policy applies).
            if predicate.is_security_driven() && !scope.excludes_direct_uploads() {
                tracing::info!(
                    policy = %name,
                    "retention policy: a security-driven predicate's resolved \
                     scope does not exclude IngestSource(Direct) — directly \
                     uploaded artifacts (which may be the only build of a \
                     version in production) are deletable by this policy. \
                     Confirm intent in YAML review."
                );
            }

            match retention.projections.find_by_name(name).await? {
                Some(existing) => {
                    // Active row: update path. `update_policy`
                    // short-circuits an unchanged predicate+scope to
                    // a no-op (Ok, zero events) — mirror the
                    // ScanPolicy unchanged/updated accounting.
                    if existing.predicate == predicate && existing.scope == scope {
                        emit_gitops_object(
                            gitops_kind::RETENTION_POLICY,
                            GitopsObjectResult::Unchanged,
                        );
                        report.unchanged += 1;
                    } else {
                        retention
                            .policies
                            .update_policy(
                                crate::use_cases::retention_policy_use_case::UpdateRetentionPolicyCommand {
                                    policy_id: existing.policy_id,
                                    predicate,
                                    scope,
                                },
                                actor.clone(),
                            )
                            .await
                            .map_err(map_concurrent_modification)?;
                        emit_gitops_object(
                            gitops_kind::RETENTION_POLICY,
                            GitopsObjectResult::Updated,
                        );
                        emit_gitops_event(gitops_kind::RETENTION_POLICY, "RetentionPolicyUpdated");
                        report.updated += 1;
                    }
                }
                None => {
                    // No active row of this name. Per the
                    // terminal-archive model a re-declared archived
                    // name mints a FRESH policy_id (no reactivation),
                    // so create unconditionally — the
                    // partial-unique-on-active-name index does not
                    // collide with an archived same-name row.
                    retention
                        .policies
                        .create_policy(
                            crate::use_cases::retention_policy_use_case::CreateRetentionPolicyCommand {
                                name: name.clone(),
                                predicate,
                                scope,
                            },
                            actor.clone(),
                        )
                        .await
                        .map_err(map_concurrent_modification)?;
                    emit_gitops_object(gitops_kind::RETENTION_POLICY, GitopsObjectResult::Created);
                    emit_gitops_event(gitops_kind::RETENTION_POLICY, "RetentionPolicyCreated");
                    report.created += 1;
                }
            }
        }

        // Archive every active projection absent from desired.
        for proj in retention.projections.list_active_rows().await? {
            if !desired_names.contains(proj.name.as_str()) {
                retention
                    .policies
                    .archive_policy(
                        proj.policy_id,
                        // Archived-by: the gitops actor's identity is
                        // carried on the event's `actor` column; the
                        // RetentionPolicyEvent::Archived.by is the
                        // domain-level "who" — use the nil sentinel
                        // (gitops-system), consistent with how the
                        // ScanPolicy archive path attributes via the
                        // actor, not a payload user id.
                        Uuid::nil(),
                        actor.clone(),
                    )
                    .await
                    .map_err(map_concurrent_modification)?;
                emit_gitops_object(gitops_kind::RETENTION_POLICY, GitopsObjectResult::Deleted);
                emit_gitops_event(gitops_kind::RETENTION_POLICY, "RetentionPolicyArchived");
                report.deleted += 1;
            }
        }
        Ok(())
    }

    // -- Stage 3 helpers ----------------------------------------------------

    /// Consolidated PermissionGrant reconcile (ADR 0012).
    ///
    /// `PermissionGrantRepository::save_managed` reconciles the **entire**
    /// `managed_by = gitops` partition (atomic delete-absent +
    /// upsert-present, keyed on the subject-dependent identity —
    /// `(sorted required_claims, repository_id, permission)` for
    /// `Claims`; `(user_id, repository_id, permission)` for `User`). The
    /// envelope-declared grants AND the ServiceAccount-owned
    /// `User`-subject grants therefore MUST be unioned into one
    /// call — two independent writers would delete each other's rows.
    ///
    /// Steps:
    ///
    /// 1. build the complete desired set: every `desired.permission_grants`
    ///    envelope mapped to a domain `PermissionGrant` (with the
    ///    sum-typed [`GrantSubject`]), plus one
    ///    `GrantSubject::User(backing_user_id)` row per
    ///    `(ServiceAccount, repo)` pair (the role
    ///    bundle is code-expanded by `service_account_permission_for_role`,
    ///    NOT a `claim_mappings` consultation, NOT a `Claims` subject);
    /// 2. diff the prior managed set (`list_managed_by_gitops`) against
    ///    the desired set by subject-dependent identity to emit one
    ///    `PermissionGrantApplied` per added-or-changed row and one
    ///    `PermissionGrantRevoked` per removed row, routed to
    ///    `StreamCategory::Repository(r)` for a repo-scoped grant or
    ///    `StreamCategory::Authorization` for a global grant
    ///    (audit-event-per-mutation invariant — there is no `role_id`;
    ///    the subject is the `GrantSubjectRecord` payload);
    /// 3. `save_managed(&complete_set)` once.
    ///
    /// Diff-then-emit failure-mode contract preserved:
    /// a `save_managed` failure aborts the apply before any audit event
    /// lands; an append failure after a successful save surfaces the
    /// apply error and the next apply re-runs the (now no-op) diff.
    async fn apply_permission_grants(
        &self,
        plan: &KindPlan<PermissionGrantSpec, Uuid>,
        desired: &DesiredState,
        // The effective `LintConfig` resolved by
        // `resolve_effective_lint_config` BEFORE this call (so a
        // same-bundle allowlist-then-use commits). Passed in rather
        // than read off `&self.lint_config` so the bundle's
        // lint-config partition is honored in the same apply; a private
        // helper parameter, NOT a port-contract change (the public
        // `ApplyConfigUseCase::new` signature is unchanged).
        lint_config: &crate::lint::LintConfig,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        // Prior gitops-managed grant set, keyed by subject-dependent
        // identity (the same key `save_managed` upserts on). The
        // surrogate id + digest carry through so re-applies are stable
        // and the audit `grant_id` matches the existing row.
        let prior = self.permission_grants.list_managed_by_gitops().await?;
        let prior_by_identity: HashMap<GrantIdentityKey, PermissionGrant> = prior
            .into_iter()
            .map(|g| {
                (
                    grant_identity_key(&g.subject, g.repository_id, g.permission),
                    g,
                )
            })
            .collect();

        // ---- complete desired set ----
        let mut desired_set: Vec<PermissionGrant> = Vec::new();
        let mut desired_identities: HashSet<GrantIdentityKey> = HashSet::new();
        // Backing-user ids of SA-owned
        // `User`-subject grants (the legitimate auto-synthesised
        // direct-user path). The linter's
        // `direct-user-grant-without-justification` rule exempts these
        // (justified by provenance); a bare operator-hand-declared
        // `User` grant whose uid is NOT here is the shape that rule
        // rejects.
        let mut sa_owned_user_ids: HashSet<Uuid> = HashSet::new();

        // (a) envelope-declared grants.
        for env in &desired.permission_grants {
            let digest = spec_digest_permission_grant(&env.spec);
            let permission = Permission::from_str(&env.spec.permission).map_err(|_| {
                // Unreachable in practice: `validate_permission_grant`
                // gated the permission string before the apply stage.
                DomainError::Invariant(format!(
                    "PermissionGrant `{}` carries permission `{}` that should have been \
                     rejected by validate_permission_grant",
                    env.metadata.name, env.spec.permission
                ))
            })?;
            let repository_id = match env.spec.repository.as_deref() {
                Some(name) => Some(self.repositories.find_by_key(name).await?.id),
                None => None,
            };
            let subject = match &env.spec.subject {
                GrantSubjectSpec::Claims { required } => {
                    let mut sorted = required.clone();
                    sorted.sort();
                    GrantSubject::Claims(sorted)
                }
                GrantSubjectSpec::User { user_id } => {
                    let uid = Uuid::parse_str(user_id.trim()).map_err(|_| {
                        DomainError::Validation(format!(
                            "PermissionGrant `{}` subject.userId `{}` is not a valid UUID",
                            env.metadata.name, user_id
                        ))
                    })?;
                    GrantSubject::User(uid)
                }
                GrantSubjectSpec::ServiceAccount { name } => {
                    // Gitops-spec sugar: resolve the named ServiceAccount
                    // to its backing-user UUID and materialise the grant
                    // as `GrantSubject::User(backing_user_id)` — the
                    // domain taxonomy stays two-variant (ADR 0012/0037).
                    // `apply_service_accounts` ran earlier in this apply
                    // (Stage above), so the SA aggregate + backing user
                    // exist and resolve here. A dangling name is rejected
                    // cross-spec at validate-time (`DanglingReference`).
                    let sa = self
                        .service_accounts
                        .get_by_name(name)
                        .await?
                        .ok_or_else(|| {
                            DomainError::Validation(format!(
                                "PermissionGrant `{}` subject.serviceAccount `{name}` names no \
                                 declared ServiceAccount — define the ServiceAccount in gitops \
                                 and apply first",
                                env.metadata.name
                            ))
                        })?;
                    let backing_user_id = sa.backing_user_id;
                    // This backing user-id is an SA-owned
                    // (provenance-justified) direct-user subject — exempt
                    // it from the `direct-user-grant-without-justification`
                    // linter rule, exactly like the SA-role-derived grants
                    // in step (b). Without this a global serviceAccount
                    // grant (the audited operator path for global / curate
                    // / admin_task_invoke authority) would trip the
                    // high-privilege reject arm.
                    sa_owned_user_ids.insert(backing_user_id);
                    GrantSubject::User(backing_user_id)
                }
            };
            self.push_desired_grant(
                subject,
                repository_id,
                permission,
                digest,
                &prior_by_identity,
                &mut desired_set,
                &mut desired_identities,
            );
        }

        // (b) ServiceAccount-owned `User`-subject grants.
        // The role bundle is code-expanded over the fixed
        // {developer, reader} enum — never a `claim_mappings`
        // consultation, never a `Claims` subject.
        // `apply_service_accounts` (the pass before this consolidated
        // reconcile) has already upserted the SA aggregate + backing
        // user, so both resolve here.
        for env in &desired.service_accounts {
            let permission = service_account_permission_for_role(&env.spec.role)?;
            let sa = self
                .service_accounts
                .get_by_name(&env.metadata.name)
                .await?
                .ok_or_else(|| {
                    DomainError::Invariant(format!(
                        "ServiceAccount `{}` not found after apply_service_accounts — \
                         the SA aggregate pass must run before the grant reconcile",
                        env.metadata.name
                    ))
                })?;
            let backing_user_id = sa.backing_user_id;
            // This backing user-id is an SA-owned
            // (provenance-justified) direct-user subject — exempt from
            // the `direct-user-grant-without-justification` linter rule.
            sa_owned_user_ids.insert(backing_user_id);
            // SA-owned digest: keyed on `sa.id` and stable across YAML
            // repo re-orderings — byte-identical to the snapshot's
            // `sa_owned_grant_digests` canonical form
            // (`sha256("sa-grant|{sa.id}|{role}|{permission}|{sorted_repos}")`,
            // computed in `build_snapshot`), so the diff layer's
            // SA-exclusion keeps these rows out of
            // the per-envelope PG plan while this consolidated reconcile
            // owns their lifecycle.
            let mut sorted_repos: Vec<&str> =
                env.spec.repositories.iter().map(String::as_str).collect();
            sorted_repos.sort_unstable();
            let canonical = format!(
                "sa-grant|{}|{}|{}|{}",
                sa.id,
                env.spec.role,
                permission,
                sorted_repos.join(",")
            );
            let digest = sha256_of(&canonical);
            for repo_name in &env.spec.repositories {
                let repository_id = Some(self.repositories.find_by_key(repo_name).await?.id);
                self.push_desired_grant(
                    GrantSubject::User(backing_user_id),
                    repository_id,
                    permission,
                    digest,
                    &prior_by_identity,
                    &mut desired_set,
                    &mut desired_identities,
                );
            }
        }

        // ---- permission-grant linter (ADR 0015) ----
        //
        // This linter is the load-bearing mitigation for
        // additive-claims' deliberate loss of *server-enforced*
        // "every grant has both legs". It runs over the fully-built
        // desired set (envelope grants ∪ SA-owned
        // `User`-subject grants) AND the desired `claim_mappings`,
        // BEFORE the whole-partition `save_managed` commit and BEFORE
        // any audit event is constructed — a `Reject` aborts the
        // apply strict-atomic so no row and no `PermissionGrantApplied`
        // / `ClaimMappingApplied` event lands. The metric
        // (`hort_apply_config_linter_total{rule,result}`) is emitted
        // per (grant|row, rule) evaluation inside the linter.
        let desired_claim_mappings: Vec<ClaimMapping> = desired
            .claim_mappings
            .iter()
            .map(|env| ClaimMapping {
                // The `claim-name-collision` rule reads only `claim`;
                // id / managed_by / digest are irrelevant to it, so a
                // minimal projection keeps the linter pure over its
                // inputs without a prior-set lookup or digest work.
                id: Uuid::new_v4(),
                idp_group: env.spec.idp_group.clone(),
                claim: env.spec.claim.clone(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: None,
            })
            .collect();
        let lint_outcome = crate::lint::lint_permission_grants(
            &desired_set,
            &desired_claim_mappings,
            &sa_owned_user_ids,
            lint_config,
        );
        if lint_outcome.rejected() {
            let reject_rules: Vec<&str> = lint_outcome
                .violations
                .iter()
                .filter(|v| v.action == crate::lint::RuleAction::Reject)
                .map(|v| v.rule)
                .collect();
            tracing::error!(
                rejected_rules = ?reject_rules,
                "gitops apply: permission-grant linter rejected the desired set \
                 (secure-by-default — operator allowlist/downgrade \
                 is the only escape hatch)"
            );
            return Err(AppError::Domain(DomainError::Validation(format!(
                "apply-config linter rejected {} grant/claim-mapping rule \
                 violation(s): [{}]. The secure-by-default posture rejects \
                 single-claim, wildcard-repo-non-admin, unjustified \
                 high-privilege direct-user grants, and reserved-claim-name \
                 collisions; relax via an explicit, audited operator \
                 LintConfig downgrade.",
                reject_rules.len(),
                reject_rules.join(", ")
            ))));
        }

        // ---- audit diff: applied (added/changed) + revoked (removed) ----
        let mut authz_events_by_stream: HashMap<StreamId, Vec<EventToAppend>> = HashMap::new();
        for grant in &desired_set {
            let identity =
                grant_identity_key(&grant.subject, grant.repository_id, grant.permission);
            let changed = match prior_by_identity.get(&identity) {
                None => true,
                Some(prev) => prev.managed_by_digest != grant.managed_by_digest,
            };
            if changed {
                let stream_id = match grant.repository_id {
                    Some(r) => StreamId::repository(r),
                    None => StreamId::authorization(),
                };
                authz_events_by_stream
                    .entry(stream_id)
                    .or_default()
                    .push(EventToAppend::new(DomainEvent::PermissionGrantApplied(
                        PermissionGrantApplied {
                            grant_id: grant.id,
                            subject: GrantSubjectRecord::from_subject(&grant.subject),
                            permission: grant.permission,
                            repository_id: grant.repository_id,
                        },
                    )));
            }
        }
        for (identity, prev) in &prior_by_identity {
            if !desired_identities.contains(identity) {
                let stream_id = match prev.repository_id {
                    Some(r) => StreamId::repository(r),
                    None => StreamId::authorization(),
                };
                authz_events_by_stream
                    .entry(stream_id)
                    .or_default()
                    .push(EventToAppend::new(DomainEvent::PermissionGrantRevoked(
                        PermissionGrantRevoked {
                            grant_id: prev.id,
                            subject: GrantSubjectRecord::from_subject(&prev.subject),
                            permission: prev.permission,
                            repository_id: prev.repository_id,
                        },
                    )));
            }
        }

        // Per-envelope report + metric counters from the diff plan. The
        // diff layer already excludes SA-owned digests from the PG plan
        // (`sa_owned_grant_digests`), so the
        // SA-owned rows do not double-count here; their lifecycle is
        // attested by the audit diff above.
        for _ in &plan.create {
            emit_gitops_object(gitops_kind::PERMISSION_GRANT, GitopsObjectResult::Created);
            report.created += 1;
        }
        for _ in &plan.update {
            emit_gitops_object(gitops_kind::PERMISSION_GRANT, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for _ in &plan.delete {
            emit_gitops_object(gitops_kind::PERMISSION_GRANT, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        let total_pg_events: usize = authz_events_by_stream.values().map(Vec::len).sum();
        if total_pg_events > 0 {
            tracing::info!(
                kind = "permission_grant",
                events = total_pg_events,
                streams = authz_events_by_stream.len(),
                "permission_grant audit events committed"
            );
        }

        // Whole-partition atomic delete-absent + upsert-present (covers
        // envelope grants AND SA-owned grants in one transaction).
        self.permission_grants.save_managed(&desired_set).await?;

        self.append_grouped_authorization_events(
            authz_events_by_stream,
            Kind::PermissionGrant,
            token,
        )
        .await?;
        Ok(())
    }

    /// Push one desired grant into the reconcile set, reusing the prior
    /// row's surrogate id when an identity-equal managed row exists
    /// (stable `grant_id` across re-applies; fresh UUID otherwise).
    #[allow(clippy::too_many_arguments)]
    fn push_desired_grant(
        &self,
        subject: GrantSubject,
        repository_id: Option<Uuid>,
        permission: Permission,
        digest: [u8; 32],
        prior_by_identity: &HashMap<GrantIdentityKey, PermissionGrant>,
        desired_set: &mut Vec<PermissionGrant>,
        desired_identities: &mut HashSet<GrantIdentityKey>,
    ) {
        let identity = grant_identity_key(&subject, repository_id, permission);
        let id = prior_by_identity
            .get(&identity)
            .map(|p| p.id)
            .unwrap_or_else(Uuid::new_v4);
        let created_at = prior_by_identity
            .get(&identity)
            .map(|p| p.created_at)
            .unwrap_or_else(Utc::now);
        desired_identities.insert(identity);
        desired_set.push(PermissionGrant {
            id,
            subject,
            repository_id,
            permission,
            created_at,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some(digest),
        });
    }

    /// Apply event-sourced `Exclusion` envelopes.
    ///
    /// Per parent `ScanPolicy`:
    /// 1. Build the desired `Vec<ExclusionSpec>` for THIS policy by
    ///    filtering `DesiredState.exclusions` on `spec.policy ==
    ///    policy_name`.
    /// 2. Read the current `Vec<ExclusionProjection>` via
    ///    `list_exclusions_for_policy`.
    /// 3. Run `ExclusionsApplier::diff` to produce the event set.
    /// 4. Translate each `ExclusionAdded` / `ExclusionRemoved` into
    ///    the matching `PolicyUseCase` call. The use case mints fresh
    ///    `exclusion_id`s on add — the applier-minted id is discarded
    ///    for the same reason as `PolicyCreated` (single source of
    ///    truth for id minting).
    async fn apply_exclusions(
        &self,
        desired: &DesiredState,
        repo_id_by_name: &HashMap<String, Uuid>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let actor = gitops_actor_for_kind(Kind::Exclusion);

        // Group desired exclusions by their parent policy name. Empty
        // policies (declared with no exclusions) still need to flow
        // through the diff so any current projection rows get removed.
        let mut by_policy: HashMap<&str, Vec<&Envelope<ExclusionSpec>>> = HashMap::new();
        for ex in &desired.exclusions {
            by_policy
                .entry(ex.spec.policy.as_str())
                .or_default()
                .push(ex);
        }
        for env in &desired.scan_policies {
            by_policy.entry(env.metadata.name.as_str()).or_default();
        }

        for (policy_name, ex_envs) in by_policy {
            // Re-read the parent projection. For policies just created
            // in stage 2, this returns the freshly-upserted row.
            let Some(parent) = self.policy_projections.find_by_name(policy_name).await? else {
                // The parent policy reference passed validation (it's
                // either a desired policy or — if dangling — was
                // already rejected by `validate_against`). Reaching
                // this branch means the projection didn't materialise
                // after a stage-2 create; surface as Invariant.
                return Err(DomainError::Invariant(format!(
                    "exclusions reference policy '{policy_name}' but its projection \
                     is missing after stage 2 — projection upsert may have failed silently"
                ))
                .into());
            };

            let applier = ExclusionsApplier::new(parent.policy_id, repo_id_by_name.clone());
            let current = self
                .policy_projections
                .list_exclusions_for_policy(parent.policy_id)
                .await?;

            let desired_specs: Vec<ExclusionSpec> =
                ex_envs.iter().map(|e| e.spec.clone()).collect();
            let synthetic = Envelope {
                api_version: hort_config::envelope::ApiVersion::V1Beta1,
                kind: Kind::Exclusion,
                metadata: hort_config::envelope::Metadata {
                    name: format!("__bundle__{policy_name}"),
                },
                spec: desired_specs,
            };
            let events = applier.diff(&synthetic, Some(&current));

            for event in events {
                // Capture the discriminant before
                // the match arm moves the inner payload — `event_type()`
                // borrows `&self`, which is fine here, and yields the
                // catalog-bounded `&'static str` we want as the metric
                // label. Emission happens AFTER the use-case call
                // succeeds (one branch below), so a strict-atomic
                // abort never tick this counter.
                let event_type = event.event_type();
                match event {
                    DomainEvent::ExclusionAdded(payload) => {
                        let cmd = AddExclusionCommand {
                            policy_id: parent.policy_id,
                            cve_id: payload.cve_id,
                            package_pattern: payload.package_pattern,
                            scope: payload.scope,
                            reason: payload.reason,
                            expires_at: payload.expires_at,
                        };
                        self.policies
                            .add_exclusion(cmd, actor.clone())
                            .await
                            .map_err(map_concurrent_modification)?;
                        emit_gitops_object(gitops_kind::EXCLUSION, GitopsObjectResult::Created);
                        emit_gitops_event(gitops_kind::EXCLUSION, event_type);
                        report.created += 1;
                    }
                    DomainEvent::ExclusionRemoved(payload) => {
                        let cmd = RemoveExclusionCommand {
                            policy_id: parent.policy_id,
                            exclusion_id: payload.exclusion_id,
                            reason: payload.reason,
                        };
                        self.policies
                            .remove_exclusion(cmd, actor.clone())
                            .await
                            .map_err(map_concurrent_modification)?;
                        emit_gitops_object(gitops_kind::EXCLUSION, GitopsObjectResult::Deleted);
                        emit_gitops_event(gitops_kind::EXCLUSION, event_type);
                        report.deleted += 1;
                    }
                    other => {
                        // ExclusionsApplier::diff only emits Added/Removed.
                        return Err(DomainError::Invariant(format!(
                            "ExclusionsApplier emitted unexpected event type: {}",
                            other.event_type()
                        ))
                        .into());
                    }
                }
            }
        }
        Ok(())
    }

    /// Apply the upstream-mapping plan.
    ///
    /// Stage 3: depends on Repository being applied first so
    /// `repo_id_by_name` is populated for every desired repository.
    /// Each `create` and `update` calls `save_managed`, with the
    /// digest computed from the spec; deletes call `delete_managed_by_id`.
    ///
    /// `repo_id_by_name` carries the post-Stage-2 view, so a desired
    /// mapping that references a freshly-created repository resolves
    /// correctly (cross-doc-reference validation already ensured the
    /// key exists in the map).
    async fn apply_upstream_mappings(
        &self,
        plan: &KindPlan<UpstreamMappingSpec, Uuid>,
        repo_id_by_name: &HashMap<String, Uuid>,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        // Operator-enumerated upstream-host
        // allowlist enforcement. Run BEFORE any save_managed call so a
        // miss aborts the apply with no partial writes. This is
        // apply-time-only — only rows in the apply diff
        // (create + update) are checked. An unchanged row that was
        // saved under a previous, looser allowlist stays as-is until
        // its YAML is touched (documented limitation; see
        // `docs/operator/upstream-trust-model.md`). `delete` rows are
        // deliberately exempt — removing a mapping that was previously
        // permitted should always succeed regardless of current
        // allowlist state, otherwise tightening the allowlist would
        // also block GC of mappings the operator wants gone.
        for env in plan.create.iter().chain(plan.update.iter()) {
            self.check_upstream_host_allowed(&env.spec.upstream_url, &env.metadata.name)?;
        }

        // Collect per-stream audit events.
        // Every UpstreamMapping mutation is repo-scoped (the row
        // carries a non-NULL `repository_id`), so the routing target
        // is always `StreamCategory::Repository(r)`. Same diff-then-
        // emit failure-mode contract as `apply_permission_grants`.
        let mut authz_events_by_stream: HashMap<StreamId, Vec<EventToAppend>> = HashMap::new();

        // Capture prior-state for every update row before any
        // save_managed runs. This mirrors the model from `apply_roles`. We need
        // the prior `(secret_ref, upstream_url, id, repository_id)`
        // to compute the `previous_*` fields on the
        // `RepositoryUpstreamMappingChanged` event before the upsert
        // overwrites them.
        let pre_update_state: HashMap<Uuid, RepositoryUpstreamMapping> = if plan.update.is_empty() {
            HashMap::new()
        } else {
            self.upstream_mappings
                .list_managed_by_gitops()
                .await?
                .into_iter()
                .map(|m| (m.id, m))
                .collect()
        };

        for env in plan.create.iter().chain(plan.update.iter()) {
            let digest = spec_digest_upstream_mapping(&env.spec);
            let repository_id = *repo_id_by_name.get(&env.spec.repository).ok_or_else(|| {
                // Validation runs before diff, so a missing
                // entry here would indicate a bug in
                // `validate()` rather than operator error.
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` references repository `{}` not in \
                             repo_id_by_name — cross-doc validation slipped",
                    env.metadata.name, env.spec.repository
                ))
            })?;
            let mapping = build_upstream_mapping_from_spec(env, repository_id, &digest)?;
            self.upstream_mappings.save_managed(&mapping).await?;
        }

        // Build `RepositoryUpstreamMappingChanged` audit events for
        // every create / update / delete row. The `previous_*` /
        // `new_*` payload fields carry the secret-ref **identifier**
        // (`<source>:<location>`) and the literal upstream URL —
        // never the resolved secret value. The post-save snapshot
        // resolves the row's actual primary key via
        // `find_managed_by_repo_and_prefix`.
        let post_save_state: HashMap<(Uuid, String), RepositoryUpstreamMapping> =
            if plan.create.is_empty() && plan.update.is_empty() {
                HashMap::new()
            } else {
                self.upstream_mappings
                    .list_managed_by_gitops()
                    .await?
                    .into_iter()
                    .map(|m| ((m.repository_id, m.path_prefix.clone()), m))
                    .collect()
            };

        for env in plan.create.iter() {
            let repository_id = *repo_id_by_name.get(&env.spec.repository).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` references repository `{}` not in repo_id_by_name",
                    env.metadata.name, env.spec.repository
                ))
            })?;
            let key = (repository_id, env.spec.path_prefix.clone());
            let saved = post_save_state.get(&key).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` not in post-save snapshot at key (repo={repository_id}, prefix={:?})",
                    env.metadata.name, env.spec.path_prefix
                ))
            })?;
            let stream_id = StreamId::repository(repository_id);
            authz_events_by_stream
                .entry(stream_id)
                .or_default()
                .push(EventToAppend::new(
                    DomainEvent::RepositoryUpstreamMappingChanged(
                        RepositoryUpstreamMappingChanged {
                            mapping_id: saved.id,
                            repository_id,
                            change: UpstreamMappingChange::Created,
                            previous_secret_ref: None,
                            new_secret_ref: env.spec.secret_ref.as_ref().map(secret_ref_name),
                            previous_url: None,
                            new_url: Some(env.spec.upstream_url.clone()),
                        },
                    ),
                ));
            emit_gitops_object(gitops_kind::UPSTREAM_MAPPING, GitopsObjectResult::Created);
            report.created += 1;
        }
        for env in plan.update.iter() {
            let repository_id = *repo_id_by_name.get(&env.spec.repository).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` references repository `{}` not in repo_id_by_name",
                    env.metadata.name, env.spec.repository
                ))
            })?;
            let key = (repository_id, env.spec.path_prefix.clone());
            let saved = post_save_state.get(&key).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` not in post-save snapshot at key (repo={repository_id}, prefix={:?})",
                    env.metadata.name, env.spec.path_prefix
                ))
            })?;
            // Prior state lookup: keyed by the post-save id (which is
            // stable across upsert per the adapter contract). When the
            // diff classifier saw an update but the prior snapshot
            // does not contain the row (race window between snapshot
            // collection and save_managed), fall back to None — the
            // event still records the post-state, which is the
            // operator-visible thing.
            let prior = pre_update_state.get(&saved.id);
            let previous_secret_ref = prior
                .and_then(|p| p.secret_ref.as_ref())
                .map(secret_ref_name);
            let previous_url = prior.map(|p| p.upstream_url.clone());
            let stream_id = StreamId::repository(repository_id);
            authz_events_by_stream
                .entry(stream_id)
                .or_default()
                .push(EventToAppend::new(
                    DomainEvent::RepositoryUpstreamMappingChanged(
                        RepositoryUpstreamMappingChanged {
                            mapping_id: saved.id,
                            repository_id,
                            change: UpstreamMappingChange::Updated,
                            previous_secret_ref,
                            new_secret_ref: env.spec.secret_ref.as_ref().map(secret_ref_name),
                            previous_url,
                            new_url: Some(env.spec.upstream_url.clone()),
                        },
                    ),
                ));
            emit_gitops_object(gitops_kind::UPSTREAM_MAPPING, GitopsObjectResult::Updated);
            report.updated += 1;
        }

        // Read about-to-be-deleted rows BEFORE any
        // delete_managed_by_id runs. This snapshot is bounded by the
        // `idx_repository_upstream_mappings_managed_by` partial index
        // and the operator's repo count (typically O(10s)).
        let pre_delete_state: HashMap<Uuid, RepositoryUpstreamMapping> = if plan.delete.is_empty() {
            HashMap::new()
        } else {
            self.upstream_mappings
                .list_managed_by_gitops()
                .await?
                .into_iter()
                .map(|m| (m.id, m))
                .collect()
        };
        for id in &plan.delete {
            self.upstream_mappings.delete_managed_by_id(*id).await?;
            if let Some(prior) = pre_delete_state.get(id) {
                let stream_id = StreamId::repository(prior.repository_id);
                authz_events_by_stream
                    .entry(stream_id)
                    .or_default()
                    .push(EventToAppend::new(
                        DomainEvent::RepositoryUpstreamMappingChanged(
                            RepositoryUpstreamMappingChanged {
                                mapping_id: prior.id,
                                repository_id: prior.repository_id,
                                change: UpstreamMappingChange::Removed,
                                previous_secret_ref: prior.secret_ref.as_ref().map(secret_ref_name),
                                new_secret_ref: None,
                                previous_url: Some(prior.upstream_url.clone()),
                                new_url: None,
                            },
                        ),
                    ));
            }
            emit_gitops_object(gitops_kind::UPSTREAM_MAPPING, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        // Per-kind audit-commit log
        // line. All UpstreamMapping events are repo-scoped, so
        // `streams` here is the count of distinct repositories
        // touched in this apply.
        let total_um_events: usize = authz_events_by_stream.values().map(Vec::len).sum();
        if total_um_events > 0 {
            tracing::info!(
                kind = "upstream_mapping",
                events = total_um_events,
                streams = authz_events_by_stream.len(),
                "upstream_mapping audit events committed"
            );
        }
        self.append_grouped_authorization_events(
            authz_events_by_stream,
            Kind::UpstreamMapping,
            token,
        )
        .await?;

        Ok(())
    }

    /// Host-allowlist gate for
    /// `apply_upstream_mappings`. Parses the mapping's
    /// `upstream_url`, looks up the host, and consults
    /// [`UpstreamHostAllowlist::permits`].
    ///
    /// On miss: emits
    /// `hort_gitops_objects_total{kind="upstream_mapping",result="rejected_not_in_allowlist"}`
    /// and returns
    /// `AppError::Domain(DomainError::Validation("upstream host '<host>' not in HORT_UPSTREAM_ALLOWLIST_HOSTS"))`
    /// so the apply aborts cleanly. The metric increment + the error
    /// give two independent signals (Prometheus alert + boot exit
    /// non-zero); operators see whichever they look at first.
    ///
    /// `Disabled` mode short-circuits: every host passes without
    /// parsing the URL. This keeps the default deployment posture's
    /// per-mapping cost at zero — the parser only runs when the
    /// operator has opted into enforcement.
    ///
    /// **URL parse failure** propagates the existing
    /// `RepositoryUpstreamMappingArgs::try_into_mapping` validation
    /// error path — it is NOT classified as
    /// `rejected_not_in_allowlist`. A malformed URL is an operator
    /// authoring bug (caught later by `build_upstream_mapping_from_spec`),
    /// not an allowlist policy violation, and conflating the two
    /// would muddy the metric. We surface the parse error here so
    /// the operator sees one error per mapping rather than the
    /// allowlist gate masking it.
    fn check_upstream_host_allowed(&self, upstream_url: &str, mapping_name: &str) -> AppResult<()> {
        // Default-posture short-circuit. No URL parse, no host
        // extraction — the allowlist is operator-opt-in.
        if matches!(self.upstream_allowlist, UpstreamHostAllowlist::Disabled) {
            return Ok(());
        }
        let parsed = url::Url::parse(upstream_url).map_err(|e| {
            // Distinct from the allowlist miss path: a bad URL is an
            // authoring bug, not a policy violation.
            AppError::Domain(DomainError::Validation(format!(
                "UpstreamMapping `{mapping_name}` has an unparseable upstream_url \
                 `{upstream_url}`: {e}"
            )))
        })?;
        let host = parsed.host_str().ok_or_else(|| {
            AppError::Domain(DomainError::Validation(format!(
                "UpstreamMapping `{mapping_name}` upstream_url `{upstream_url}` \
                 has no host component"
            )))
        })?;
        if self.upstream_allowlist.permits(host) {
            return Ok(());
        }
        // Loud miss. Bump the metric BEFORE returning so the counter
        // increments regardless of how the apply caller logs the
        // error (gitops_boot maps the AppError to a parse_error /
        // validation_error / apply_error bucket — different from the
        // per-object signal this counter carries).
        emit_gitops_object(
            gitops_kind::UPSTREAM_MAPPING,
            GitopsObjectResult::RejectedNotInAllowlist,
        );
        Err(AppError::Domain(DomainError::Validation(format!(
            "upstream host '{host}' not in HORT_UPSTREAM_ALLOWLIST_HOSTS"
        ))))
    }

    /// Pass 3 — for every desired `type: virtual` repo, reconcile
    /// the membership edge set against current state. Idempotent:
    /// when the declared and current edge sets match, no port
    /// mutation happens.
    ///
    /// Doesn't take the pre-apply `CurrentSnapshot` because it would
    /// be stale for any virtual repo stage 2 just created. Current
    /// edges are read fresh per virtual repo via `get_virtual_members`.
    async fn apply_virtual_members(&self, desired: &DesiredState) -> AppResult<()> {
        for env in &desired.repositories {
            let Some(declared_members) = env.spec.virtual_members.as_ref() else {
                continue;
            };
            let virtual_repo = match self.repositories.find_by_key(&env.metadata.name).await {
                Ok(r) => r,
                Err(e) => return Err(e.into()),
            };

            // Resolve declared member keys to ids, **preserving the
            // `virtualMembers` list order** — that order is the resolution
            // priority (ADR 0031 rule 3). `replace_virtual_members` assigns
            // `priority` = list index, so the declared order is the priority.
            let mut declared_ordered: Vec<Uuid> = Vec::with_capacity(declared_members.len());
            for member_key in declared_members {
                let m = self.repositories.find_by_key(member_key).await?;
                declared_ordered.push(m.id);
            }

            // `get_virtual_members` returns members already ordered by
            // priority, so this is the current ordered edge list.
            let current_ordered: Vec<Uuid> = self
                .repositories
                .get_virtual_members(virtual_repo.id)
                .await?
                .into_iter()
                .map(|r| r.id)
                .collect();

            // Idempotent: when the declared list matches the current
            // priority-ordered edges exactly (same members, same order), make
            // no port mutation. Otherwise reconcile via the **atomic**
            // `replace_virtual_members` so persisted `priority` always tracks
            // the `virtualMembers` index AND a concurrent reader (another
            // replica on the shared DB during a rolling deploy) never observes
            // a partial member set. A pure reorder (no set change) still
            // re-pins priority. The prior remove-loop-then-add-loop was
            // non-transactional: its mid-reconcile window could transiently
            // drop the owner edge, making an owned name look unowned and
            // momentarily un-suppressing proxies (ADR 0031 rule 2b / S-2).
            if declared_ordered == current_ordered {
                continue;
            }
            self.repositories
                .replace_virtual_members(virtual_repo.id, &declared_ordered)
                .await?;
        }
        Ok(())
    }

    async fn collect_repo_id_by_name(
        &self,
        desired: &DesiredState,
    ) -> AppResult<HashMap<String, Uuid>> {
        let mut out = HashMap::with_capacity(desired.repositories.len());
        for env in &desired.repositories {
            // Each declared repo just had `save_managed` run in stage 2
            // → it exists. `find_by_key` resolves the id.
            let repo = self.repositories.find_by_key(&env.metadata.name).await?;
            out.insert(env.metadata.name.clone(), repo.id);
        }
        Ok(out)
    }

    /// Re-use existing UUID if a managed row already exists for this
    /// key (UPDATE path); mint a new one otherwise (CREATE path).
    /// `save_managed` does an INSERT-or-UPDATE on the supplied id.
    async fn resolve_repo_id(&self, key: &str) -> AppResult<Uuid> {
        match self.repositories.find_by_key(key).await {
            Ok(r) => Ok(r.id),
            Err(DomainError::NotFound { .. }) => Ok(Uuid::new_v4()),
            Err(e) => Err(e.into()),
        }
    }

    // -- OidcIssuer + ServiceAccount apply ----------------------------------

    /// Apply `OidcIssuer` create / update / delete from the gitops
    /// plan. Per-row event emission lands on the
    /// [`StreamCategory::Authorization`] stream alongside the other
    /// apply-time authz mutations.
    async fn apply_oidc_issuers(
        &self,
        plan: &KindPlan<OidcIssuerSpec, String>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let mut events: Vec<EventToAppend> = Vec::new();
        let now = Utc::now();

        for env in &plan.create {
            let id = self
                .oidc_issuers
                .get_by_name(&env.metadata.name)
                .await?
                .map(|i| i.id)
                .unwrap_or_else(Uuid::new_v4);
            let issuer = build_oidc_issuer_from_spec(env, id)?;
            self.oidc_issuers.upsert(&issuer).await?;
            // Best-effort
            // JWKS warm-up. MUST NOT fail the apply on error; federation
            // works lazily via the cache-miss path on first request.
            self.warm_up_oidc_jwks(&issuer).await;
            events.push(EventToAppend::new(DomainEvent::OidcIssuerCreated(
                OidcIssuerCreated {
                    issuer_id: id,
                    name: env.metadata.name.clone(),
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::OIDC_ISSUER, GitopsObjectResult::Created);
            report.created += 1;
        }
        for env in &plan.update {
            let existing = self
                .oidc_issuers
                .get_by_name(&env.metadata.name)
                .await?
                .ok_or_else(|| {
                    DomainError::Invariant(format!(
                        "OidcIssuer `{}` scheduled for update but not present in snapshot",
                        env.metadata.name
                    ))
                })?;
            let issuer = build_oidc_issuer_from_spec(env, existing.id)?;
            self.oidc_issuers.upsert(&issuer).await?;
            // Best-effort
            // JWKS warm-up on update too (jwks_uri or audiences may have
            // shifted; populate the cache so the next federation
            // request sees the post-update key set without an inline
            // fetch tax). MUST NOT fail the apply on error.
            self.warm_up_oidc_jwks(&issuer).await;
            events.push(EventToAppend::new(DomainEvent::OidcIssuerUpdated(
                OidcIssuerUpdated {
                    issuer_id: existing.id,
                    name: env.metadata.name.clone(),
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::OIDC_ISSUER, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for name in &plan.delete {
            // Resolve the row's id for the audit-event payload BEFORE
            // the DELETE — once the row is gone we can't recover it.
            let prior_id = self
                .oidc_issuers
                .get_by_name(name)
                .await?
                .map(|i| i.id)
                .unwrap_or_else(Uuid::new_v4);
            self.oidc_issuers.delete_by_name(name).await?;
            events.push(EventToAppend::new(DomainEvent::OidcIssuerDeleted(
                OidcIssuerDeleted {
                    issuer_id: prior_id,
                    name: name.clone(),
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::OIDC_ISSUER, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        if !events.is_empty() {
            tracing::info!(
                kind = gitops_kind::OIDC_ISSUER,
                events = events.len(),
                "oidc_issuer audit events committed"
            );
            let actor = gitops_actor_for_kind(Kind::OidcIssuer);
            self.events
                .append(AppendEvents {
                    stream_id: StreamId::authorization(),
                    expected_version: ExpectedVersion::Any,
                    events,
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor,
                })
                .await?;
        }
        Ok(())
    }

    /// Apply-time
    /// JWKS warm-up. Best-effort: on any error, emit `tracing::warn!`
    /// and let the apply proceed. The adapter (`MultiIssuerJwksValidator::
    /// refresh_issuer_impl`) emits `hort_jwks_refresh_total{result=
    /// apply_warmup_failed}` itself via the `RefreshContext::ApplyWarmup`
    /// switch, so this helper only handles the tracing side.
    ///
    /// Federation works lazily even when warm-up fails: the first
    /// `validate()` call against a freshly-applied issuer pays the
    /// discovery + JWKS round-trip cost on demand. The warm-up exists
    /// to surface "the gitops apply pushed a config that the IdP
    /// can't serve" as an operator-visible signal without a real
    /// federation request having to arrive first.
    ///
    /// `None` validator slot (`new()`-only composition, no
    /// `with_federated_jwt_validator`) skips warm-up entirely.
    async fn warm_up_oidc_jwks(&self, issuer: &OidcIssuer) {
        let Some(validator) = self.federated_jwt_validator.as_ref() else {
            return;
        };
        match validator.refresh_issuer(issuer).await {
            Ok(()) => {
                tracing::debug!(
                    issuer_name = %issuer.name,
                    "OidcIssuer JWKS apply-time warm-up populated cache"
                );
            }
            Err(reason) => {
                // Operator-feedback-only: the apply is NOT failed.
                // Federation will fetch lazily on first request. The
                // metric is emitted by the adapter's
                // `RefreshContext::ApplyWarmup` failure paths
                // (`hort_jwks_refresh_total{result=apply_warmup_failed}`).
                tracing::warn!(
                    issuer_name = %issuer.name,
                    reason = reason.as_str(),
                    "OidcIssuer JWKS apply-time warm-up failed — \
                     federation will fetch lazily on first use"
                );
            }
        }
    }

    /// Apply `ServiceAccount` create / update / delete from the gitops
    /// plan. Each create / update step:
    ///
    /// 1. Ensures a backing `users` row exists (`username = "sa:" || name`,
    ///    `is_service_account = true`). The user row is shared
    ///    infrastructure — created on first apply, never deleted by
    ///    the apply path.
    /// 2. Composes the full SA aggregate (SA row +
    ///    federated_identities + fallback_rotation) and calls
    ///    `service_accounts.upsert`, which runs the whole shape in a
    ///    single transaction.
    /// 3. Manages the role/repo grants — one `permission_grants` row
    ///    per `(role, repo)` pair (Permission::Write is the read+write
    ///    surface for developer SAs; reader SAs get Permission::Read).
    ///    Idempotent: re-applying the same SA does not produce
    ///    duplicate grant rows because each grant is upserted by
    ///    `(role_id, repository_id, permission)` triple.
    ///
    /// Delete path: removes the SA aggregate (CASCADE drops sub-rows)
    /// and the permission grants. The backing `users` row stays.
    async fn apply_service_accounts(
        &self,
        plan: &KindPlan<ServiceAccountSpec, String>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let mut events: Vec<EventToAppend> = Vec::new();
        let now = Utc::now();

        for env in &plan.create {
            let (backing_user_id, sa_id) = self.upsert_service_account_aggregate(env, true).await?;
            events.push(EventToAppend::new(DomainEvent::ServiceAccountCreated(
                ServiceAccountCreated {
                    service_account_id: sa_id,
                    service_account_name: env.metadata.name.clone(),
                    backing_user_id,
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::SERVICE_ACCOUNT, GitopsObjectResult::Created);
            report.created += 1;
        }
        for env in &plan.update {
            let (_, sa_id) = self.upsert_service_account_aggregate(env, false).await?;
            events.push(EventToAppend::new(DomainEvent::ServiceAccountUpdated(
                ServiceAccountUpdated {
                    service_account_id: sa_id,
                    service_account_name: env.metadata.name.clone(),
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::SERVICE_ACCOUNT, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for name in &plan.delete {
            let existing = self.service_accounts.get_by_name(name).await?;
            let Some(sa) = existing else {
                // Row already gone (out-of-band delete or no-op
                // re-apply) — fall through silently. Idempotent.
                continue;
            };
            // The SA's `User`-subject permission grants
            // are NOT deleted here. A deleted SA is absent from
            // `desired.service_accounts`, so the consolidated
            // PermissionGrant reconcile (`apply_permission_grants`,
            // which runs after this pass) does not include its grants
            // in the desired set; `save_managed`'s whole-partition
            // delete-absent removes them atomically. Deleting them here
            // would be a no-op-with-extra-round-trips at best and a
            // double-delete race at worst.
            self.service_accounts.delete_by_name(name).await?;
            events.push(EventToAppend::new(DomainEvent::ServiceAccountDeleted(
                ServiceAccountDeleted {
                    service_account_id: sa.id,
                    service_account_name: name.clone(),
                    backing_user_id: sa.backing_user_id,
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::SERVICE_ACCOUNT, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        if !events.is_empty() {
            tracing::info!(
                kind = gitops_kind::SERVICE_ACCOUNT,
                events = events.len(),
                "service_account audit events committed"
            );
            let actor = gitops_actor_for_kind(Kind::ServiceAccount);
            self.events
                .append(AppendEvents {
                    stream_id: StreamId::authorization(),
                    expected_version: ExpectedVersion::Any,
                    events,
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor,
                })
                .await?;
        }
        Ok(())
    }

    /// Combined SA-create-or-update workhorse: ensure backing user,
    /// upsert SA aggregate. Returns `(backing_user_id,
    /// service_account_id)`.
    ///
    /// This does not reconcile the SA's permission
    /// grants. SA authority is materialised as
    /// `GrantSubject::User(backing_user_id)` rows by the consolidated
    /// `apply_permission_grants` pass, which runs after every SA's
    /// aggregate + backing user exists (one whole-partition
    /// `save_managed` covering envelope grants ∪ SA-owned grants).
    ///
    /// `is_create` is informational — the row UPSERT handles both
    /// cases atomically. We thread it for future-friendly logging
    /// only.
    async fn upsert_service_account_aggregate(
        &self,
        env: &Envelope<ServiceAccountSpec>,
        _is_create: bool,
    ) -> AppResult<(Uuid, Uuid)> {
        // 1. Backing user.
        let backing_user_id = self.ensure_backing_user(&env.metadata.name).await?;

        // 2. SA aggregate. Resolve a stable id when the row exists.
        let existing_id = self
            .service_accounts
            .get_by_name(&env.metadata.name)
            .await?
            .map(|s| s.id);
        let sa_id = existing_id.unwrap_or_else(Uuid::new_v4);
        let sa = build_service_account_from_spec(env, sa_id, backing_user_id)?;
        self.service_accounts.upsert(&sa).await?;

        Ok((backing_user_id, sa_id))
    }

    /// Look up the backing user by `username = "sa:" || sa_name` and
    /// return its id, creating the row if it doesn't exist.
    ///
    /// The user row is shared infrastructure — we never
    /// delete it from the apply path. Other code (API
    /// token issuance, audit attribution) may grant or revoke tokens
    /// scoped to this user independent of the SA aggregate lifecycle.
    async fn ensure_backing_user(&self, sa_name: &str) -> AppResult<Uuid> {
        let username = backing_username(sa_name);
        if let Some(user) = self.users.find_by_username(&username).await? {
            return Ok(user.id);
        }
        let user = User {
            id: Uuid::new_v4(),
            username: username.clone(),
            // Synthesised email — not used for delivery, but the
            // `users.email` column is NOT NULL in the existing schema.
            email: format!("{username}@service-accounts.local"),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: Some(format!("Service account: {sa_name}")),
            is_active: true,
            is_admin: false,
            is_service_account: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.users.save(&user).await?;
        tracing::info!(
            entity = "service_account_backing_user",
            username = %username,
            "created backing users row for service account"
        );
        Ok(user.id)
    }
}

fn emit_unchanged(kind: &'static str, count: usize, report: &mut ApplyReport) {
    for _ in 0..count {
        emit_gitops_object(kind, GitopsObjectResult::Unchanged);
    }
    report.unchanged += count;
}

/// Build an `OidcIssuer` from a validated spec envelope.
/// The `validate_oidc_issuer` pass has already gated the
/// algorithm strings, so every `JwtAlg::from_str` is expected to
/// succeed — a failure here is an `Invariant` because it means the
/// validator was bypassed.
fn build_oidc_issuer_from_spec(env: &Envelope<OidcIssuerSpec>, id: Uuid) -> AppResult<OidcIssuer> {
    debug_assert!(matches!(env.kind, Kind::OidcIssuer));
    let spec = &env.spec;
    let jwks_refresh_interval =
        humantime::parse_duration(&spec.jwks_refresh_interval).map_err(|e| {
            DomainError::Invariant(format!(
                "OidcIssuer `{}`: jwksRefreshInterval validation passed but parse failed: {e}",
                env.metadata.name
            ))
        })?;
    let allowed_algorithms: Vec<JwtAlg> = spec
        .allowed_algorithms
        .iter()
        .map(|s| {
            JwtAlg::from_str(s).map_err(|e| {
                DomainError::Invariant(format!(
                    "OidcIssuer `{}`: allowedAlgorithms `{s}` validation passed but parse failed: {e}",
                    env.metadata.name
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(OidcIssuer {
        id,
        name: env.metadata.name.clone(),
        issuer_url: spec.issuer_url.clone(),
        audiences: spec.audiences.clone(),
        jwks_refresh_interval,
        allowed_algorithms,
        // Threaded verbatim from the
        // spec. `#[serde(default)]` already resolved a missing
        // `requireJti:` to `true` (the silent-apply tightening).
        require_jti: spec.require_jti,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

/// Build a `ServiceAccount` aggregate (SA row + federated identities
/// + optional fallback rotation) from a validated spec envelope.
///
/// The `validate_service_account` pass has already gated every value;
/// fall through to `Invariant` for any parse-after-validate failure.
fn build_service_account_from_spec(
    env: &Envelope<ServiceAccountSpec>,
    id: Uuid,
    backing_user_id: Uuid,
) -> AppResult<ServiceAccount> {
    debug_assert!(matches!(env.kind, Kind::ServiceAccount));
    let spec = &env.spec;
    let federated_identities: Vec<FederatedIdentity> = spec
        .federated_identities
        .iter()
        .map(|fi| FederatedIdentity {
            issuer_name: fi.issuer.clone(),
            claims: fi.claims.clone(),
        })
        .collect();
    let fallback_rotation = match &spec.fallback_rotation {
        None => None,
        Some(r) => {
            let rotation_interval = humantime::parse_duration(&r.rotation_interval).map_err(
                |e| {
                    DomainError::Invariant(format!(
                        "ServiceAccount `{}`: rotationInterval validation passed but parse failed: {e}",
                        env.metadata.name
                    ))
                },
            )?;
            let validity = humantime::parse_duration(&r.validity).map_err(|e| {
                DomainError::Invariant(format!(
                    "ServiceAccount `{}`: validity validation passed but parse failed: {e}",
                    env.metadata.name
                ))
            })?;
            let format = match r.target_secret.format.as_str() {
                "dockerconfigjson" => SecretFormat::Dockerconfigjson,
                "opaque" => SecretFormat::Opaque,
                other => {
                    return Err(DomainError::Invariant(format!(
                        "ServiceAccount `{}`: targetSecret.format `{other}` validation \
                         passed but enum mapping failed",
                        env.metadata.name
                    ))
                    .into());
                }
            };
            Some(FallbackRotation {
                target_secret_name: r.target_secret.name.clone(),
                target_secret_namespace: r.target_secret.namespace.clone(),
                format,
                rotation_interval,
                validity,
            })
        }
    };
    Ok(ServiceAccount {
        id,
        name: env.metadata.name.clone(),
        backing_user_id,
        role: spec.role.clone(),
        repositories: spec.repositories.clone(),
        federated_identities,
        fallback_rotation,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

/// Map a service-account role name to the matching `Permission`. The
/// apply-time validator gates `role ∈ {developer, reader}`, so any
/// other value reaching this helper is an `Invariant`.
///
/// - `developer` → `Permission::Write` (by convention
///   developer = read+write+delete, with `Write` standing in
///   for the bundled grant because the `Permission` enum is flat).
/// - `reader` → `Permission::Read`.
///
/// `pub` so cross-crate callers (notably the `hort-http-core` federation
/// `/api/v1/token/exchange` handler, which mints SA tokens from
/// validated JWTs) can stamp the federation token's
/// `declared_permissions` from the same role-mapping table the apply
/// pipeline uses; otherwise the federation cap leg of
/// `RbacEvaluator::authorize` denies every check (empty cap permissions
/// never `contains(&requested)` — see `cap_allows_optional_repo`).
pub fn service_account_permission_for_role(role: &str) -> Result<Permission, DomainError> {
    match role {
        "developer" => Ok(Permission::Write),
        "reader" => Ok(Permission::Read),
        other => Err(DomainError::Invariant(format!(
            "service-account role `{other}` is not in {{developer, reader}}"
        ))),
    }
}

/// SHA-256 of an arbitrary string, returned as a 32-byte digest.
/// Used by `reconcile_service_account_grants` to tag grants with a
/// stable identity-of-the-source-SA digest.
fn sha256_of(s: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Build a `Repository` from a `RepositorySpec` envelope. Inlines the
/// validator from `RepositoryUseCase::create` (the upstream-url
/// requirement on `Proxy` repos): the public use case rejects every
/// gitops-managed write, so the apply pipeline must NOT route through
/// it. Five lines of duplication beats a shared validator module that
/// exists for one extra caller.
fn build_repository_from_spec(
    env: &Envelope<RepositorySpec>,
    id: Uuid,
    effective_backend: Option<crate::storage_backend::EffectiveStorageBackend>,
) -> AppResult<Repository> {
    debug_assert!(matches!(env.kind, Kind::ArtifactRepository));
    let spec = &env.spec;

    // RepositoryFormat::FromStr::Err is Infallible — unknown names map
    // to RepositoryFormat::Other(_), they don't fail. Unwrap is exact;
    // unwrap_or would express uncertainty that doesn't exist. The
    // unknown-format guard runs in `validate_repository` before apply.
    let format: RepositoryFormat = spec.format.parse().unwrap();
    let repo_type = RepositoryType::from_str(&spec.repo_type)?;
    let replication_priority = ReplicationPriority::from_str(&spec.replication_priority)?;
    let upstream_url = spec.proxy.as_ref().map(|p| p.upstream_url.clone());
    // Typed `index_upstream_url` override for split-
    // host registries (currently consulted only by the Cargo handler).
    // Cross-spec validation in `hort-config::validate_repository` rejects
    // `Some(_)` when format != cargo or repo_type != proxy, so by the
    // time the apply pipeline reaches this converter the surface is
    // narrow.
    let index_upstream_url = spec
        .proxy
        .as_ref()
        .and_then(|p| p.index_upstream_url.clone());

    if matches!(repo_type, RepositoryType::Proxy) && upstream_url.is_none() {
        return Err(
            DomainError::Validation("proxy repository must have an upstream URL".into()).into(),
        );
    }

    // `spec.storage` is optional. Omitting
    // it is the documented honest path — inherit the deployment's
    // effective global backend (per-repo storage is not
    // routing-effective in v2; see the `StorageSpec` honesty note). The
    // `storage_*` columns are NOT NULL with no usable default, so the
    // omitted case is resolved to concrete, internally-consistent
    // values here (never NULL, never a magic free-string sentinel —
    // that was the original footgun): the effective global backend if the
    // composition wired one, else `"filesystem"` (the DB column default
    // and the domain default — the least-surprising fallback when the
    // cross-check is unwired); the placement-inert `storage_path`
    // becomes the repo key (stable across re-apply, NOT NULL, honest —
    // no fabricated filesystem prefix). When the operator *did* supply
    // a block, it is used verbatim (the apply-time mismatch reject runs
    // separately in `reject_repo_storage_backend_mismatch`).
    let (storage_backend, storage_path) = match spec.storage.as_ref() {
        Some(s) => (s.backend.clone(), s.path.clone()),
        None => {
            let backend = effective_backend
                .map(|e| e.as_spec_str().to_string())
                .unwrap_or_else(|| "filesystem".to_string());
            (backend, env.metadata.name.clone())
        }
    };

    let now = Utc::now();
    Ok(Repository {
        id,
        key: env.metadata.name.clone(),
        name: spec.name.clone(),
        description: spec.description.clone(),
        format,
        repo_type,
        storage_backend,
        storage_path,
        upstream_url,
        index_upstream_url,
        is_public: spec.is_public,
        // Opt-in per-repo download auditing.
        // Mirrors the `is_public` spec→domain plumbing exactly;
        // `#[serde(default)]` on the spec field makes absence == false
        // (non-breaking for existing gitops configs).
        download_audit_enabled: spec.download_audit_enabled,
        quota_bytes: spec.quota_bytes,
        replication_priority,
        promotion: spec.promotion.clone(),
        // The spec carries a list of `CurationRule`
        // names (from `spec.curationRules`). The apply pipeline writes
        // them through `set_curation_rules_for_repository` after the
        // repository row itself; this in-memory carrier just preserves
        // the list for downstream callers that may inspect the
        // `Repository` value.
        curation_rule_names: spec.curation_rules.clone().unwrap_or_default(),
        // The optional `indexMode` gitops field
        // (`#[serde(default)]`) lands here verbatim. Absent ⇒
        // `IndexMode::ReleasedOnly` via the enum's `Default` impl —
        // the build-safe posture, matching the migration column
        // default and the mapper's defensive fallback.
        index_mode: spec.index_mode,
        // The optional `prefetchPolicy` gitops field
        // (`#[serde(default)]`) lands here verbatim. Absent ⇒
        // `PrefetchPolicy::default()` (disabled, no triggers, default
        // depths) — matches the migration column defaults
        // (`prefetch_enabled = false`, `prefetch_triggers = NULL`) and
        // the mapper's defensive fallback. The prefetch pipeline is the
        // consumer; this converter only threads the typed value.
        prefetch_policy: spec.prefetch_policy.clone(),
        created_at: now,
        updated_at: now,
        managed_by: ManagedBy::GitOps,
        managed_by_digest: None, // save_managed sets this
    })
}

/// The `claim_mappings` diff identity is the natural
/// `(idp_group, claim)` pair (the table's UNIQUE key). The
/// `CurrentClaimMapping` snapshot view keys off a single `name`
/// string, so the snapshot builder synthesises a stable composite
/// name from the pair. The separator (`\u{1f}`, ASCII Unit Separator)
/// cannot appear in an `idp_group` / `claim` value (both are
/// non-blank operator strings), so the encoding is injective —
/// distinct pairs never collide on the synthesised name.
fn claim_mapping_identity_name(idp_group: &str, claim: &str) -> String {
    format!("{idp_group}\u{1f}{claim}")
}

/// Subject-dependent diff/upsert identity for a
/// `PermissionGrant`. `Claims` grants key off
/// `(sorted required_claims, repository_id, permission)`; `User`
/// grants key off `(user_id, repository_id, permission)`. The two
/// arms are disjoint by construction. `Permission` is `Copy + Eq +
/// Hash`; `Vec<String>` / `Uuid` / `Option<Uuid>` are all `Hash +
/// Eq`, so the tuple is a valid `HashMap` key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum GrantIdentityKey {
    Claims(Vec<String>, Option<Uuid>, Permission),
    User(Uuid, Option<Uuid>, Permission),
}

/// Compute the subject-dependent identity key for a grant. The
/// `Claims` arm sorts the claim set so a re-ordered YAML declaration
/// produces the same key (apply replay = no-op), matching
/// `hort_config::permission_grant::PermissionGrantSpec::diff_identity`
/// and the snapshot builder's sort in `build_snapshot`.
fn grant_identity_key(
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
/// Auth-variant translation:
/// - `anonymous` → `UpstreamAuth::Anonymous`
/// - `bearer_challenge` → `UpstreamAuth::BearerChallenge`
/// - `basic` → `UpstreamAuth::Basic { username }`
///
/// The closed enum was already enforced by `validate_upstream_mapping`;
/// an unknown value here is an invariant.
fn build_upstream_mapping_from_spec(
    env: &Envelope<UpstreamMappingSpec>,
    repository_id: Uuid,
    digest: &[u8; 32],
) -> AppResult<RepositoryUpstreamMapping> {
    debug_assert!(matches!(env.kind, Kind::UpstreamMapping));
    let upstream_auth = match env.spec.auth.r#type.as_str() {
        "anonymous" => UpstreamAuth::Anonymous,
        "bearer_challenge" => UpstreamAuth::BearerChallenge,
        "basic" => {
            // `validate_upstream_mapping` rejected the empty/missing
            // username path for the basic variant; if we reach here
            // without one, the validator slipped — surface as an
            // invariant rather than panic.
            let username = env.spec.auth.username.clone().ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` has type=basic but no username — \
                     validate_upstream_mapping slipped",
                    env.metadata.name
                ))
            })?;
            UpstreamAuth::Basic { username }
        }
        other => {
            return Err(DomainError::Invariant(format!(
                "UpstreamMapping `{}` has unknown auth.type `{}` that should have been \
                 rejected by validate_upstream_mapping",
                env.metadata.name, other
            ))
            .into());
        }
    };
    let now = Utc::now();
    // Gitops apply funnels through
    // `RepositoryUpstreamMapping::new`, which enforces the
    // transport-scheme invariant at the value-object boundary. The
    // YAML validator already rejects http:// without
    // `insecureUpstreamUrl: true`; the constructor is the
    // defence-in-depth re-check so any future bypass of validate_*
    // surfaces here, not at fetch time.
    let mapping = RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
        // Adapter's INSERT ... ON CONFLICT (repository_id, path_prefix)
        // DO UPDATE preserves the existing row id on conflict, so the
        // freshly-minted id here is harmless on the update path.
        id: Uuid::new_v4(),
        repository_id,
        path_prefix: env.spec.path_prefix.clone(),
        upstream_url: env.spec.upstream_url.clone(),
        upstream_name_prefix: env.spec.upstream_name_prefix.clone(),
        upstream_auth,
        secret_ref: env.spec.secret_ref.clone(),
        managed_by: ManagedBy::GitOps,
        managed_by_digest: Some(*digest),
        insecure_upstream_url: env.spec.insecure_upstream_url,
        // Per-upstream opt-in to publish-time
        // anchoring of the quarantine window (ADR 0007). Plain bool,
        // default `false`, plumbed through to the row. No apply-time
        // validator mirroring `insecure_upstream_url`'s scheme guard —
        // this flag is not a security knob, just a trust signal for
        // the quarantine-window anchor computation.
        trust_upstream_publish_time: env.spec.trust_upstream_publish_time,
        // Per-upstream TLS material. The apply pipeline only wires the
        // data through; fetch-path behaviour (cert load, rustls
        // verifier, metric emission) lives in the upstream adapter. The
        // value-object constructor below enforces the
        // pairing + scheme + hex-format invariants.
        mtls_cert_ref: env.spec.mtls_cert_ref.clone(),
        mtls_key_ref: env.spec.mtls_key_ref.clone(),
        ca_bundle_ref: env.spec.ca_bundle_ref.clone(),
        pinned_cert_sha256: env.spec.pinned_cert_sha256.clone(),
        created_at: now,
        updated_at: now,
    })?;
    Ok(mapping)
}

fn build_curation_rule_from_spec(
    env: &Envelope<hort_config::curation_rule::CurationRuleSpec>,
    id: Uuid,
    digest: &[u8; 32],
) -> AppResult<CurationRule> {
    debug_assert!(matches!(env.kind, Kind::CurationRule));
    let action = CurationRuleAction::from_str(&env.spec.action)?;
    // `format: "any"` (case-insensitive) → None; otherwise parse via
    // RepositoryFormat. The `validate_curation_rule` checker rejected
    // `Other(_)` already, so an unknown format here is an invariant.
    let format = if env.spec.format.eq_ignore_ascii_case("any") {
        None
    } else {
        let parsed: RepositoryFormat = env.spec.format.parse().unwrap();
        if matches!(parsed, RepositoryFormat::Other(_)) {
            return Err(DomainError::Invariant(format!(
                "CurationRule '{}' carries unknown format '{}' that should have been \
                 rejected by validate_curation_rule",
                env.metadata.name, env.spec.format
            ))
            .into());
        }
        Some(parsed)
    };
    Ok(CurationRule {
        id,
        name: env.metadata.name.clone(),
        format,
        package_pattern: env.spec.pattern.clone(),
        action,
        reason: env.spec.reason.clone(),
        managed_by: ManagedBy::GitOps,
        managed_by_digest: Some(*digest),
    })
}

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
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only — the provenance mappers live in `crate::provenance`;
    // these types are referenced only by the fixtures.
    use hort_config::scan_policy::SignerIdentitySpec;
    use hort_domain::entities::scan_policy::{NegligibleAction, ProvenanceMode};

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
    fn default_repository_access_for_policy() -> Arc<RepositoryAccessUseCase> {
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
    // `save_managed(&[items])` is the whole-partition reconcile
    // primitive: in one call the adapter deletes every
    // gitops-managed row whose `(idp_group, claim)` identity is absent
    // from `items` and upserts every row that is present, keyed on that
    // identity (not the surrogate id) so an unchanged replay is a no-op.
    // The mock mirrors that exactly so the production diff
    // (`apply_claim_mappings`'s `prior_by_identity`) behaves correctly
    // across re-applies.

    #[derive(Default)]
    struct MockClaimMappingRepo {
        /// gitops-managed rows keyed by the `(idp_group, claim)` natural
        /// identity — same key `save_managed` reconciles on.
        managed: Mutex<HashMap<(String, String), ClaimMapping>>,
        /// Every `save_managed` invocation's complete slice (test
        /// introspection: call count + last authoritative set).
        save_managed_calls: Mutex<Vec<Vec<ClaimMapping>>>,
    }

    impl MockClaimMappingRepo {
        fn new() -> Self {
            Self::default()
        }
        /// Number of `save_managed` invocations (the apply pipeline
        /// calls it once per `apply_claim_mappings`, unconditionally).
        fn save_managed_call_count(&self) -> usize {
            self.save_managed_calls.lock().unwrap().len()
        }
        /// Current managed-row count after the last reconcile.
        fn managed_count(&self) -> usize {
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
        fn save_managed(&self, items: &[ClaimMapping]) -> BoxFuture<'_, DomainResult<()>> {
            self.save_managed_calls.lock().unwrap().push(items.to_vec());
            // Whole-partition reconcile: replace the entire managed set
            // with `items` keyed on `(idp_group, claim)`.
            let mut managed = self.managed.lock().unwrap();
            *managed = items
                .iter()
                .map(|m| ((m.idp_group.clone(), m.claim.clone()), m.clone()))
                .collect();
            Box::pin(async { Ok(()) })
        }
    }

    // --- mock RoleRepository -----------------------------------------------

    // --- mock PermissionGrantRepository ------------------------------------
    //
    // There is no `RoleRepository`; grants persist on their own port.
    // `save_managed(&[items])` is the whole-partition reconcile
    // primitive: delete every gitops-managed grant whose subject-
    // dependent identity (`grant_identity_key` — `(sorted required_claims,
    // repository_id, permission)` for `Claims`; `(user_id, repository_id,
    // permission)` for `User`) is absent from `items`, upsert every row
    // present, keyed on that identity so an unchanged replay is a no-op.
    // The mock replicates that so the production diff
    // (`apply_permission_grants`'s `prior_by_identity`) is exercised
    // faithfully across re-applies.

    #[derive(Default)]
    struct MockPermissionGrantRepo {
        /// gitops-managed grants keyed by the subject-dependent identity
        /// (`GrantIdentityKey`) — the same key `save_managed` reconciles
        /// on. Keeps surrogate-id churn out of the test assertions.
        managed: Mutex<HashMap<GrantIdentityKey, PermissionGrant>>,
        /// Every `save_managed` invocation's complete authoritative
        /// slice (call count + last reconciled set introspection).
        save_managed_calls: Mutex<Vec<Vec<PermissionGrant>>>,
    }

    impl MockPermissionGrantRepo {
        fn new() -> Self {
            Self::default()
        }
        /// Number of `save_managed` invocations. `apply_permission_grants`
        /// calls it exactly once per apply, unconditionally — the
        /// consolidated reconcile that covers envelope + SA-owned grants.
        fn save_managed_call_count(&self) -> usize {
            self.save_managed_calls.lock().unwrap().len()
        }
        /// Current managed-grant count after the last reconcile.
        fn managed_count(&self) -> usize {
            self.managed.lock().unwrap().len()
        }
        /// Snapshot of the current managed grant set (post-reconcile).
        fn managed_snapshot(&self) -> Vec<PermissionGrant> {
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
        fn save_managed(&self, items: &[PermissionGrant]) -> BoxFuture<'_, DomainResult<()>> {
            self.save_managed_calls.lock().unwrap().push(items.to_vec());
            // Whole-partition reconcile keyed on the subject-dependent
            // identity — replace the entire managed set.
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
            Box::pin(async { Ok(()) })
        }
    }

    // --- mock CurationRuleRepository ---------------------------------------

    #[derive(Default)]
    struct MockCurationRuleRepo {
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
        fn save_count(&self) -> usize {
            self.save_calls.lock().unwrap().len()
        }
        fn delete_count(&self) -> usize {
            self.delete_calls.lock().unwrap().len()
        }
        fn junction_calls(&self) -> Vec<(Uuid, Vec<Uuid>)> {
            self.set_junction_calls.lock().unwrap().clone()
        }
        /// Explicit reverse-index seed for
        /// retroactive-evaluation tests that need `list_repos_for_rule`
        /// to return a non-empty result before the apply runs.
        fn link_rule_to_repo(&self, rule_id: Uuid, repository_id: Uuid) {
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
    struct MockPolicyProjections {
        by_id: Mutex<HashMap<Uuid, ScanPolicyProjection>>,
        by_name: Mutex<HashMap<String, ScanPolicyProjection>>,
        exclusions: Mutex<HashMap<Uuid, Vec<ExclusionProjection>>>,
    }

    impl MockPolicyProjections {
        fn new() -> Self {
            Self::default()
        }
        fn insert_active(&self, p: ScanPolicyProjection) {
            self.by_id.lock().unwrap().insert(p.policy_id, p.clone());
            self.by_name.lock().unwrap().insert(p.name.clone(), p);
        }
        fn insert_exclusion(&self, e: ExclusionProjection) {
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

    struct MockPolicyEventStore {
        appended: Mutex<Vec<AppendEvents>>,
        next_outcomes: Mutex<Vec<AppendOutcome>>,
    }

    impl MockPolicyEventStore {
        fn new() -> Self {
            Self {
                appended: Mutex::new(Vec::new()),
                next_outcomes: Mutex::new(Vec::new()),
            }
        }
        fn appended(&self) -> Vec<AppendEvents> {
            self.appended.lock().unwrap().clone()
        }
        fn schedule_conflict_on_next_append(&self) {
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
        fn delete_stream(&self, _stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!("retention path unused by apply-config tests") })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unimplemented!("retention path unused by apply-config tests") })
        }
    }

    // --- fixtures ----------------------------------------------------------

    fn repo_env(name: &str, repo_type: &str) -> Envelope<RepositorySpec> {
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
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ArtifactRepository,
            metadata: Metadata { name: name.into() },
            spec,
        }
    }

    fn virtual_env(name: &str, members: &[&str]) -> Envelope<RepositorySpec> {
        let mut env = repo_env(name, "virtual");
        env.spec.virtual_members = Some(members.iter().map(|s| (*s).into()).collect());
        env
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
    fn cm_env(_name: &str, idp_group: &str, claim: &str) -> Envelope<ClaimMappingSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
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
    fn grant_env(
        name: &str,
        required: &[&str],
        permission: &str,
        repo: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
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
            api_version: ApiVersion::V1Beta1,
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
    fn sa_grant_env(
        name: &str,
        sa_name: &str,
        permission: &str,
        repo: Option<&str>,
    ) -> Envelope<PermissionGrantSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
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

    fn rule_env(
        name: &str,
        action: &str,
        pattern: &str,
        reason: &str,
    ) -> Envelope<hort_config::curation_rule::CurationRuleSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
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

    fn scan_policy_env(name: &str) -> Envelope<ScanPolicySpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
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
                max_artifact_age: Some("90d".into()),
                license_policy: serde_json::json!({"allowed": ["MIT"]}),
                scan_backends: vec!["trivy".to_string()],
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
            },
        }
    }

    fn exclusion_env(name: &str, policy: &str, cve: &str) -> Envelope<ExclusionSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
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

    struct Harness {
        uc: ApplyConfigUseCase,
        repos: Arc<MockRepositoryRepository>,
        claim_mappings: Arc<MockClaimMappingRepo>,
        grant_repo: Arc<MockPermissionGrantRepo>,
        rule_repo: Arc<MockCurationRuleRepo>,
        proj: Arc<MockPolicyProjections>,
        events: Arc<MockPolicyEventStore>,
        artifacts: Arc<crate::use_cases::test_support::MockArtifactRepository>,
        lifecycle: Arc<crate::use_cases::test_support::MockArtifactLifecycle>,
        // Used by the 14b-14 upstream-mapping happy-path test; the
        // earlier 14b-9 tests don't read it.
        #[allow(dead_code)]
        upstream: Arc<crate::use_cases::test_support::MockRepositoryUpstreamMappingRepository>,
        // Refcount projection mock.
        // Read by the
        // `retroactive_curation_reject_sweeps_content_references` test;
        // every other test ignores it (the mock starts empty and the
        // tests don't seed rows).
        #[allow(dead_code)]
        content_refs: Arc<crate::use_cases::test_support::MockContentReferenceIndex>,
        // OidcIssuer / ServiceAccount gitops surface mocks. Default empty;
        // SA tests seed via the `repos` mock + the harness's `users`
        // mock and let the apply pipeline write through.
        #[allow(dead_code)]
        oidc_issuers: Arc<crate::use_cases::test_support::MockOidcIssuerRepository>,
        #[allow(dead_code)]
        service_accounts: Arc<crate::use_cases::test_support::MockServiceAccountRepository>,
        #[allow(dead_code)]
        users: Arc<crate::use_cases::test_support::MockUserRepository>,
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
    fn build_harness() -> Harness {
        build_harness_with_lint_config(crate::lint::LintConfig::permissive_for_tests())
    }

    /// Harness with an explicit `LintConfig`. The
    /// secure-by-default apply-level tests pass
    /// [`crate::lint::LintConfig::default`] here to prove a wildcard /
    /// single-claim grant fails the whole apply with **zero** operator
    /// config. Mirrors `build_harness_with_allowlist`'s shape.
    fn build_harness_with_lint_config(lint: crate::lint::LintConfig) -> Harness {
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
        ));
        // OidcIssuer / ServiceAccount gitops surface mocks.
        let oidc_issuers =
            Arc::new(crate::use_cases::test_support::MockOidcIssuerRepository::new());
        let service_accounts =
            Arc::new(crate::use_cases::test_support::MockServiceAccountRepository::new());
        let users = Arc::new(crate::use_cases::test_support::MockUserRepository::new());
        let uc = ApplyConfigUseCase::new(
            repos.clone(),
            claim_mappings.clone(),
            grant_repo.clone(),
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
        ));
        let oidc_issuers =
            Arc::new(crate::use_cases::test_support::MockOidcIssuerRepository::new());
        let service_accounts =
            Arc::new(crate::use_cases::test_support::MockServiceAccountRepository::new());
        let users = Arc::new(crate::use_cases::test_support::MockUserRepository::new());
        let uc = ApplyConfigUseCase::new(
            repos.clone(),
            claim_mappings.clone(),
            grant_repo.clone(),
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
        }
    }

    // ===================================================================
    // Apply-config linter wiring (ADR 0015).
    // These tests assert the linter runs INSIDE
    // `apply_permission_grants` BEFORE the whole-partition
    // `save_managed` commit, with the secure-by-default reject
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
    /// `save_managed`).
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
            h.grant_repo.save_managed_call_count(),
            0,
            "linter reject must abort BEFORE the whole-partition save_managed"
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
        assert_eq!(h.grant_repo.save_managed_call_count(), 0);
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
        assert_eq!(h.grant_repo.save_managed_call_count(), 0);
    }

    /// A `claim_mappings` row resolving to the reserved
    /// `service_account` token-kind discriminator fails the apply by
    /// default (claim-name-collision — no downgrade knob).
    ///
    /// **Ordering caveat (recorded residual).** The linter is wired at
    /// the Item-10 seam inside `apply_permission_grants`, which the
    /// pipeline runs *after* `apply_claim_mappings`' whole-partition
    /// `save_managed`. So for the collision rule the apply still
    /// **fails** (the gitops apply returns `Err`, the operator's CI is
    /// red, the bad mapping never goes live in an *accepted* state), but
    /// the claim-mapping partition reconcile already ran before the abort.
    /// The three grant rules ARE strict-atomic —
    /// they reject before the grant `save_managed`. Making the
    /// collision rule strict-atomic too would require running a
    /// claim-mapping pre-check before `apply_claim_mappings`, which is
    /// outside this item's seam (and `apply_claim_mappings` is out of
    /// scope). Flagged to the orchestrator as a follow-on.
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
        // The whole apply failed (the load-bearing property). The
        // grant partition was NOT written (linter aborts before the
        // grant save_managed).
        assert_eq!(h.grant_repo.save_managed_call_count(), 0);
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
        assert_eq!(h.grant_repo.save_managed_call_count(), 1);
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
        assert_eq!(h.grant_repo.save_managed_call_count(), 1);
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
    fn put_lint_config(
        desired: &mut DesiredState,
        name: &str,
        allowlist: &[&str],
        overrides: hort_config::lint_config::RuleOverridesSpec,
    ) {
        let env = Envelope {
            api_version: ApiVersion::V1Beta1,
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
        assert_eq!(h.grant_repo.save_managed_call_count(), 1);
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
        assert_eq!(h.grant_repo.save_managed_call_count(), 0);
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
        assert_eq!(h.grant_repo.save_managed_call_count(), 1);
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

    fn env_oidc() -> EnvSnapshot {
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
        // Whole-partition reconcile — one `save_managed`
        // call carrying the single declared mapping row.
        assert_eq!(h.claim_mappings.save_managed_call_count(), 1);
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
        // The whole-partition `save_managed` reconcile primitive is
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

    /// Gitops YAML carrying
    /// `proxy.indexUpstreamUrl` lands the override on the persisted
    /// `Repository` row. Exercises the converter at
    /// `build_repository_from_spec`: the field is read off
    /// `spec.proxy.index_upstream_url` and copied onto
    /// `Repository.index_upstream_url`. End-to-end through the apply
    /// pipeline so any future refactor of the converter that drops
    /// the field gets caught.
    #[tokio::test]
    async fn apply_propagates_proxy_index_upstream_url_onto_repository() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("cargo-proxy", "proxy");
        env.spec.format = "cargo".into();
        let proxy = env.spec.proxy.as_mut().expect("proxy block");
        proxy.upstream_url = "https://crates.io".into();
        proxy.index_upstream_url = Some("https://internal-index.example.com".into());

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        // Reach the persisted repo through the trait surface — the
        // mock stores the row inside `save_managed`, so `find_by_key`
        // must surface the propagated field.
        let stored = h.repos.find_by_key("cargo-proxy").await.unwrap();
        assert_eq!(
            stored.index_upstream_url.as_deref(),
            Some("https://internal-index.example.com"),
            "apply pipeline must propagate proxy.indexUpstreamUrl onto Repository.index_upstream_url"
        );
    }

    // -- gitops apply propagates `indexMode` ---------------------------------

    /// A gitops `ArtifactRepository` envelope carrying
    /// `indexMode: include_pending` lands the typed `IndexMode` on
    /// the persisted `Repository` row. Mirror of the
    /// `index_upstream_url` propagation test: exercises the converter
    /// at `build_repository_from_spec` end-to-end through the apply
    /// pipeline so any future refactor that drops the field gets caught.
    #[tokio::test]
    async fn apply_propagates_index_mode_include_pending_onto_repository() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("npm-filter", "proxy");
        env.spec.index_mode = IndexMode::IncludePending;

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("npm-filter").await.unwrap();
        assert_eq!(
            stored.index_mode,
            IndexMode::IncludePending,
            "apply pipeline must propagate spec.indexMode onto Repository.index_mode"
        );
    }

    // -- gitops apply propagates `prefetchPolicy` ----------------------------

    /// A gitops `ArtifactRepository` envelope
    /// carrying a populated `prefetchPolicy` block lands the typed
    /// `PrefetchPolicy` on the persisted `Repository` row. Mirror of
    /// the `index_mode` propagation test: exercises the converter at
    /// `build_repository_from_spec` end-to-end through the apply
    /// pipeline so any future refactor that drops the field gets
    /// caught.
    #[tokio::test]
    async fn apply_propagates_populated_prefetch_policy_onto_repository() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("npm-prefetch", "proxy");
        let policy = PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::OnDistTagMove, PrefetchTrigger::Scheduled],
            depth: 11,
            transitive_depth: 6,
            // `max_age_days` is rejected at
            // apply by `validate_prefetch_max_age_days_not_implemented`
            // until the per-version timestamp surface lands
            // (ADR 0015). Set to `None` here so the
            // round-trip-other-fields coverage stays meaningful; the
            // reject path is exercised by
            // `apply_rejects_prefetch_policy_with_max_age_days_set`.
            max_age_days: None,
            // Non-default sentinel so the
            // apply-pipeline round-trip of the knob is pinned.
            max_descendants: 500,
        };
        env.spec.prefetch_policy = policy.clone();

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("npm-prefetch").await.unwrap();
        assert_eq!(
            stored.prefetch_policy, policy,
            "apply pipeline must propagate spec.prefetchPolicy onto Repository.prefetch_policy"
        );
    }

    /// Negative half: a repo declared YAML-side with
    /// no `prefetchPolicy` field lands `PrefetchPolicy::default()` (the
    /// `#[serde(default)]`). Locks down the disabled-by-default posture
    /// so a future refactor that wires a stray override cannot silently
    /// turn every existing repo into a mirror.
    #[tokio::test]
    async fn apply_defaults_prefetch_policy_to_disabled_when_absent() {
        use hort_domain::entities::repository::PrefetchPolicy;
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        // `repo_env` builds the spec with `PrefetchPolicy::default()` —
        // the same shape as an omitted-field gitops YAML after serde's
        // default.
        let env = repo_env("npm-prefetch-default", "proxy");

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("npm-prefetch-default").await.unwrap();
        assert_eq!(stored.prefetch_policy, PrefetchPolicy::default());
        assert!(!stored.prefetch_policy.enabled);
        assert!(stored.prefetch_policy.triggers.is_empty());
    }

    /// Negative half: a repo declared YAML-side with
    /// no `indexMode` field lands `IndexMode::ReleasedOnly` (the
    /// `#[serde(default)]`). Locks down the default so a future
    /// refactor that wires a stray override does not silently flip the
    /// build-safe posture for every existing repo.
    #[tokio::test]
    async fn apply_defaults_index_mode_to_released_only_when_absent() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        // `repo_env` builds the spec with `IndexMode::default()` (i.e.
        // `ReleasedOnly`) — the same shape as an omitted-field gitops
        // YAML after serde's default.
        let env = repo_env("npm-default", "proxy");

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("npm-default").await.unwrap();
        assert_eq!(stored.index_mode, IndexMode::ReleasedOnly);
    }

    /// Negative half of the propagation test: a cargo proxy with no
    /// override declared YAML-side stores `None`. Locks down the
    /// default so a future refactor that wires a stray default doesn't
    /// silently turn the override on for every cargo proxy.
    #[tokio::test]
    async fn apply_leaves_index_upstream_url_none_when_unset() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("cargo-proxy-default", "proxy");
        env.spec.format = "cargo".into();
        let proxy = env.spec.proxy.as_mut().expect("proxy block");
        proxy.upstream_url = "https://crates.io".into();
        // index_upstream_url left at its serde default (None).

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("cargo-proxy-default").await.unwrap();
        assert!(stored.index_upstream_url.is_none());
    }

    // ===================================================================
    // Apply-time per-repo-vs-effective-global storage-backend reject.
    //
    // `EffectiveStorageBackend` is the *true* `{filesystem, s3}`
    // deployment fact (never the coarse `StoragePort::backend_label()`
    // `{filesystem, object_store}` — that would fail-*wrong*). The
    // builder seam mirrors `with_lint_config` / `with_retention`:
    // `new()` is byte-unchanged, the field defaults to `None`, and
    // `None` ⇒ the cross-check is skipped (so every pre-existing test
    // harness — which never calls the builder — keeps passing
    // unchanged; `build_harness()` is the witness).
    // ===================================================================

    /// `Some(eff)` + a per-repo `storage.backend` differing from the
    /// effective global backend ⇒ the whole apply is rejected with the
    /// canonical operator wording, extended to name the effective
    /// global backend. Fail-closed and loud.
    ///
    /// New-branch coverage: `Some(eff)` taken + `repo.storage.backend
    /// != eff.as_spec_str()` true ⇒ reject (the `s3`-spec-on-
    /// `Filesystem`-deployment direction; exercises
    /// `EffectiveStorageBackend::Filesystem.as_spec_str()`).
    #[tokio::test]
    async fn apply_rejects_per_repo_backend_mismatching_effective_global() {
        let h = build_harness();
        let mut env = repo_env("s3-on-fs-deploy", "hosted");
        // The deployment is filesystem; the operator wrote s3.
        env.spec.storage.as_mut().unwrap().backend = "s3".into();

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h.uc.with_effective_storage_backend(
            crate::storage_backend::EffectiveStorageBackend::Filesystem,
        );
        let err = uc.apply(desired, env_oidc()).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("per-repository storage")
                && msg.contains("s3")
                && msg.contains("filesystem"),
            "reject must reuse the canonical wording and name BOTH \
             the offending per-repo value and the effective global \
             backend; got: {msg}"
        );
    }

    /// The other enum arm / spec-string direction: an `s3` deployment
    /// with a per-repo `backend: filesystem` is equally rejected.
    /// Exercises `EffectiveStorageBackend::S3.as_spec_str()` in the
    /// reject path.
    #[tokio::test]
    async fn apply_rejects_filesystem_repo_on_s3_deployment() {
        let h = build_harness();
        let env = repo_env("fs-on-s3-deploy", "hosted"); // repo_env defaults backend=filesystem

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h
            .uc
            .with_effective_storage_backend(crate::storage_backend::EffectiveStorageBackend::S3);
        let err = uc.apply(desired, env_oidc()).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("per-repository storage")
                && msg.contains("filesystem")
                && msg.contains("s3"),
            "s3-deployment + per-repo filesystem must reject and name \
             both; got: {msg}"
        );
    }

    /// `Some(eff)` + a per-repo `storage.backend` *matching* the
    /// effective global backend ⇒ the cross-check passes; the apply
    /// proceeds normally and the row lands. New-branch coverage:
    /// `Some(eff)` taken + the `!=` guard false ⇒ no reject.
    #[tokio::test]
    async fn apply_accepts_per_repo_backend_matching_effective_global() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let env = repo_env("fs-on-fs-deploy", "hosted"); // backend=filesystem

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h.uc.with_effective_storage_backend(
            crate::storage_backend::EffectiveStorageBackend::Filesystem,
        );
        uc.apply(desired, env_oidc())
            .await
            .expect("matching backend must apply cleanly");

        let stored = h.repos.find_by_key("fs-on-fs-deploy").await.unwrap();
        assert_eq!(stored.storage_backend, "filesystem");
    }

    /// `None` (the default — the builder never called) ⇒ the
    /// cross-check is skipped entirely; an `s3`-backed repo applies on
    /// a harness that wired no effective backend. This is the witness
    /// that every pre-existing harness (none of which call the
    /// builder) keeps compiling and passing unchanged. New-branch
    /// coverage: `self.effective_storage_backend` is `None` ⇒ the
    /// `if let Some(..)` is not taken.
    #[tokio::test]
    async fn apply_skips_backend_cross_check_when_effective_unset() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness(); // never calls with_effective_storage_backend
        let mut env = repo_env("s3-repo-unchecked", "hosted");
        env.spec.storage.as_mut().unwrap().backend = "s3".into();

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        h.uc.apply(desired, env_oidc())
            .await
            .expect("None effective backend must skip the cross-check");

        let stored = h.repos.find_by_key("s3-repo-unchecked").await.unwrap();
        assert_eq!(stored.storage_backend, "s3");
    }

    // ---- storage-omitted is the honest path -------------------------------

    /// The rc.19 regression, at the apply layer. A repo whose
    /// `storage:` block is omitted applies cleanly **and** the
    /// persisted row inherits the deployment's effective global
    /// backend — the documented honest path the storage validator's
    /// own remedy points at. This config previously could not even parse
    /// (`missing field 'storage'`), so the remedy was unimplementable.
    #[tokio::test]
    async fn storage_omitted_inherits_effective_global_s3() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("omitted-on-s3", "hosted");
        env.spec.storage = None; // operator omitted the block

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h
            .uc
            .with_effective_storage_backend(crate::storage_backend::EffectiveStorageBackend::S3);
        uc.apply(desired, env_oidc())
            .await
            .expect("a storage-omitted repo must apply — not reject, not crash");

        let stored = h.repos.find_by_key("omitted-on-s3").await.unwrap();
        assert_eq!(
            stored.storage_backend, "s3",
            "omitted storage must inherit the effective global backend"
        );
        assert_eq!(
            stored.storage_path, "omitted-on-s3",
            "omitted storage_path resolves to the repo key (NOT NULL, stable, inert)"
        );
    }

    /// Omitted storage with **no** effective backend wired (the
    /// pre-existing-harness shape) falls back to `filesystem` — the DB
    /// column default and domain default — never NULL, never a magic
    /// sentinel.
    #[tokio::test]
    async fn storage_omitted_no_effective_defaults_filesystem() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness(); // no with_effective_storage_backend
        let mut env = repo_env("omitted-no-eff", "hosted");
        env.spec.storage = None;

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        h.uc.apply(desired, env_oidc())
            .await
            .expect("omitted storage + no effective backend must apply");

        let stored = h.repos.find_by_key("omitted-no-eff").await.unwrap();
        assert_eq!(stored.storage_backend, "filesystem");
        assert_eq!(stored.storage_path, "omitted-no-eff");
    }

    /// The self-contradiction, pinned closed: omitted storage is the
    /// validator's own suggested remedy, so it must **not** be
    /// rejected by the per-repo-vs-global mismatch check even when an
    /// effective backend is wired (omission inherits by construction —
    /// there is nothing to mismatch).
    #[tokio::test]
    async fn storage_omitted_not_rejected_by_mismatch_check() {
        let h = build_harness();
        let mut env = repo_env("omitted-not-rejected", "hosted");
        env.spec.storage = None;

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h
            .uc
            .with_effective_storage_backend(crate::storage_backend::EffectiveStorageBackend::S3);
        uc.apply(desired, env_oidc()).await.expect(
            "omitted storage is the validator's own remedy — it must inherit, \
             never trip reject_repo_storage_backend_mismatch",
        );
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

    #[tokio::test]
    async fn apply_rejects_virtual_repo_until_serve_supported() {
        // ADR 0015 inert-field stopgap (spec §9 part A): applying a
        // `type: virtual` repo fails pre-write validation when the format is
        // absent from `VIRTUAL_SERVE_SUPPORTED_FORMATS`. npm/pypi/cargo/maven/
        // gradle are lifted; `oci` is a known, still-unsupported format — the
        // correct steady state — so this exercises the stopgap through the real
        // apply path (`run_pre_write_validation` → `validate_against` → `validate`).
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("a", "hosted"));
        let mut vroot = virtual_env("vroot", &["a"]);
        vroot.spec.format = "oci".into();
        desired.repositories.push(vroot);
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        assert!(
            err.to_string().contains("not yet serve-supported"),
            "expected serve-support rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn apply_npm_virtual_passes_validation_and_reconciles_members() {
        // npm/pypi/cargo/maven/gradle are lifted into
        // `VIRTUAL_SERVE_SUPPORTED_FORMATS`, so a `type: virtual` npm repo
        // passes apply validation and the member reconcile runs end-to-end
        // through `apply()` (no longer orphaned by the stopgap). A
        // still-unsupported format (e.g. oci) trips the stopgap — see
        // `apply_rejects_virtual_repo_until_serve_supported`.
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("a", "hosted"));
        desired.repositories.push(virtual_env("vroot", &["a"]));
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let vroot = h.repos.find_by_key("vroot").await.unwrap();
        let members: Vec<String> = h
            .repos
            .get_virtual_members(vroot.id)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.key)
            .collect();
        assert_eq!(
            members,
            vec!["a".to_string()],
            "npm virtual member edge reconciled via apply()"
        );
    }

    // The three tests below drive `apply_virtual_members` **directly** — they
    // keep the order-aware reconcile and its edge cases (idempotent re-apply,
    // atomic replace on a list edit) covered without a full `apply()`
    // round-trip. The end-to-end npm path is covered by
    // `apply_npm_virtual_passes_validation_and_reconciles_members` above; the
    // pypi/cargo formats are still stopgapped at validation, so the direct
    // drive is the only way to exercise the reconcile for them until they lift.

    /// Collect the ordered id lists of every `ReplaceMembers` call for `vroot`.
    fn replace_calls_for(h: &Harness, vroot_id: Uuid) -> Vec<Vec<Uuid>> {
        h.repos
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                MockCall::ReplaceMembers(v, ids) if v == vroot_id => Some(ids),
                _ => None,
            })
            .collect()
    }

    /// Assert no per-edge (non-atomic) member mutation ever happened.
    fn assert_no_per_edge_mutations(h: &Harness) {
        assert!(
            h.repos
                .calls()
                .iter()
                .all(|c| !matches!(c, MockCall::AddMember(..) | MockCall::RemoveMember(..))),
            "member reconcile must be atomic (ADR 0031 / S-2) — never per-edge add/remove"
        );
    }

    #[tokio::test]
    async fn apply_virtual_members_replaces_edges_in_declared_order() {
        // Reconcile from an empty edge set: members are written in
        // `virtualMembers` order via one ATOMIC replace, so persisted priority
        // == list index.
        let h = build_harness();
        for key in ["vroot", "a", "b"] {
            h.repos.insert(sample_repository_for_test(key));
        }
        let mut desired = DesiredState::default();
        desired.repositories.push(virtual_env("vroot", &["a", "b"]));

        h.uc.apply_virtual_members(&desired).await.unwrap();

        let vroot = h.repos.find_by_key("vroot").await.unwrap();
        let a = h.repos.find_by_key("a").await.unwrap();
        let b = h.repos.find_by_key("b").await.unwrap();
        let members: Vec<String> = h
            .repos
            .get_virtual_members(vroot.id)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.key)
            .collect();
        assert_eq!(members, vec!["a".to_string(), "b".to_string()]);
        assert_no_per_edge_mutations(&h);
        assert_eq!(
            replace_calls_for(&h, vroot.id),
            vec![vec![a.id, b.id]],
            "one atomic replace in declared order"
        );
    }

    #[tokio::test]
    async fn apply_virtual_members_idempotent_when_order_matches() {
        // Declared list already matches the current priority-ordered edges:
        // no port mutation (no churn).
        let h = build_harness();
        for key in ["vroot", "a", "b"] {
            h.repos.insert(sample_repository_for_test(key));
        }
        let vroot = h.repos.find_by_key("vroot").await.unwrap();
        let a = h.repos.find_by_key("a").await.unwrap();
        let b = h.repos.find_by_key("b").await.unwrap();
        h.repos.seed_virtual_member(vroot.id, a.id);
        h.repos.seed_virtual_member(vroot.id, b.id);

        let mut desired = DesiredState::default();
        desired.repositories.push(virtual_env("vroot", &["a", "b"]));
        h.uc.apply_virtual_members(&desired).await.unwrap();

        let mutations = h
            .repos
            .calls()
            .into_iter()
            .filter(|c| {
                matches!(
                    c,
                    MockCall::AddMember(..)
                        | MockCall::RemoveMember(..)
                        | MockCall::ReplaceMembers(..)
                )
            })
            .count();
        assert_eq!(mutations, 0, "matching declared order must not churn edges");
    }

    #[tokio::test]
    async fn apply_virtual_members_reorders_atomically() {
        // A pure reorder (same set, different order) re-pins priority via one
        // ATOMIC replace — a concurrent reader never sees a partial set with
        // the owner edge transiently removed (ADR 0031 rule 2b / S-2).
        let h = build_harness();
        for key in ["vroot", "a", "b", "c"] {
            h.repos.insert(sample_repository_for_test(key));
        }
        let vroot = h.repos.find_by_key("vroot").await.unwrap();
        let a = h.repos.find_by_key("a").await.unwrap();
        let b = h.repos.find_by_key("b").await.unwrap();
        let c = h.repos.find_by_key("c").await.unwrap();
        h.repos.seed_virtual_member(vroot.id, a.id);
        h.repos.seed_virtual_member(vroot.id, b.id);
        h.repos.seed_virtual_member(vroot.id, c.id);

        let mut desired = DesiredState::default();
        desired
            .repositories
            .push(virtual_env("vroot", &["c", "a", "b"]));
        h.uc.apply_virtual_members(&desired).await.unwrap();

        let members: Vec<String> = h
            .repos
            .get_virtual_members(vroot.id)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.key)
            .collect();
        assert_eq!(
            members,
            vec!["c".to_string(), "a".to_string(), "b".to_string()]
        );
        assert_no_per_edge_mutations(&h);
        assert_eq!(
            replace_calls_for(&h, vroot.id),
            vec![vec![c.id, a.id, b.id]],
            "one atomic replace re-pinning the declared order"
        );
    }

    // ===================================================================
    // ClaimMapping apply (ADR 0012 — there is no Role CRUD block and
    // no `roles` table). Every
    // test here asserts shipped `apply_claim_mappings` behaviour: a
    // single whole-partition `save_managed` per apply,
    // `ClaimMappingApplied` on create OR digest change, silence on an
    // unchanged digest, `ClaimMappingRevoked` for a prior managed row
    // absent from desired, and "empty desired revokes all".
    // ===================================================================

    /// Read every `DomainEvent` appended to the global authorization
    /// stream (`ClaimMapping*`/`PermissionGrant*`
    /// global mutations route there via `StreamId::authorization()`).
    async fn authz_events(h: &Harness) -> Vec<DomainEvent> {
        h.events
            .read_stream(&StreamId::authorization(), ReadFrom::Start, u64::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.event)
            .collect()
    }

    fn count_cm_applied(evts: &[DomainEvent]) -> usize {
        evts.iter()
            .filter(|e| matches!(e, DomainEvent::ClaimMappingApplied(_)))
            .count()
    }

    fn count_cm_revoked(evts: &[DomainEvent]) -> usize {
        evts.iter()
            .filter(|e| matches!(e, DomainEvent::ClaimMappingRevoked(_)))
            .count()
    }

    #[tokio::test]
    async fn apply_claim_mappings_create_emits_applied_and_reconciles() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("devs", "g-dev", "developer"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1);
        // Whole-partition reconcile fires exactly once.
        assert_eq!(h.claim_mappings.save_managed_call_count(), 1);
        assert_eq!(h.claim_mappings.managed_count(), 1);
        let evts = authz_events(&h).await;
        assert_eq!(
            count_cm_applied(&evts),
            1,
            "create must emit exactly one ClaimMappingApplied"
        );
        if let Some(DomainEvent::ClaimMappingApplied(a)) = evts
            .iter()
            .find(|e| matches!(e, DomainEvent::ClaimMappingApplied(_)))
        {
            assert_eq!(a.idp_group, "g-dev");
            assert_eq!(a.claim, "developer");
        } else {
            panic!("no ClaimMappingApplied event");
        }
    }

    /// Retargeting a claim mapping. The design keys both the reconcile
    /// (`apply_claim_mappings`, on the `(idp_group, claim)` pair) and
    /// the diff identity (`diff_claim_mappings`, on `metadata.name` =
    /// the identity-encoded name) off the `(idp_group, claim)` pair, and
    /// `spec_digest_claim_mapping` is a pure function of that same pair.
    /// Consequently a *same-identity digest change is unreachable by
    /// construction* — changing the claim is a NEW identity: the old
    /// `(g-dev, developer)` is revoked and the new `(g-dev, admin)` is
    /// applied. This pins that shipped reconcile semantics.
    #[tokio::test]
    async fn apply_claim_mappings_retarget_revokes_old_and_applies_new() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("devs", "g-dev", "developer"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let applied_before = count_cm_applied(&authz_events(&h).await);
        let revoked_before = count_cm_revoked(&authz_events(&h).await);
        assert_eq!(applied_before, 1);
        assert_eq!(revoked_before, 0);
        // Retarget `g-dev` from `developer` → `admin`. New identity:
        // the old mapping is absent from desired (revoked), the new one
        // is created (applied). The reconciled set still holds one row.
        desired.claim_mappings[0] = cm_env("devs", "g-dev", "admin");
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1);
        assert_eq!(report.deleted, 1);
        let evts = authz_events(&h).await;
        assert_eq!(
            count_cm_applied(&evts),
            applied_before + 1,
            "the new identity must emit a ClaimMappingApplied"
        );
        assert_eq!(
            count_cm_revoked(&evts),
            revoked_before + 1,
            "the old identity must emit a ClaimMappingRevoked"
        );
        assert_eq!(h.claim_mappings.managed_count(), 1);
        let row = &h.claim_mappings.managed.lock().unwrap();
        assert!(row.contains_key(&("g-dev".to_string(), "admin".to_string())));
    }

    #[tokio::test]
    async fn apply_claim_mappings_unchanged_is_silent() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("devs", "g-dev", "developer"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let applied_before = count_cm_applied(&authz_events(&h).await);
        // Replay the identical desired set → unchanged digest → no new
        // ClaimMappingApplied (silent no-op — unchanged digest).
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.created, 0);
        assert_eq!(report.updated, 0);
        assert_eq!(
            count_cm_applied(&authz_events(&h).await),
            applied_before,
            "an unchanged-digest replay must emit no ClaimMappingApplied"
        );
    }

    #[tokio::test]
    async fn apply_claim_mappings_absent_is_revoked() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("devs", "g-dev", "developer"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(h.claim_mappings.managed_count(), 1);
        // Re-apply with the mapping gone → prior gitops-managed row
        // absent from desired → ClaimMappingRevoked + the
        // whole-partition reconcile drops it.
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(h.claim_mappings.managed_count(), 0);
        assert_eq!(
            count_cm_revoked(&authz_events(&h).await),
            1,
            "a now-absent managed mapping must emit one ClaimMappingRevoked"
        );
    }

    #[tokio::test]
    async fn apply_claim_mappings_empty_desired_revokes_all() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.claim_mappings.push(cm_env("a", "g-a", "ca"));
        desired.claim_mappings.push(cm_env("b", "g-b", "cb"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(h.claim_mappings.managed_count(), 2);
        // Empty `claim_mappings` slice in desired → save_managed(&[])
        // revokes the entire gitops-managed partition.
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report.deleted, 2);
        assert_eq!(h.claim_mappings.managed_count(), 0);
        assert_eq!(count_cm_revoked(&authz_events(&h).await), 2);
    }

    // ===================================================================
    // Stage 1 CRUD: CurationRule
    // ===================================================================

    #[tokio::test]
    async fn create_curation_rule_calls_save_managed() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(h.rule_repo.save_count(), 1);
        assert_eq!(report.created, 1);
    }

    #[tokio::test]
    async fn update_curation_rule_when_action_changes() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("rule-a", "warn", "p", "r"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let saves_before = h.rule_repo.save_count();
        desired.curation_rules[0].spec.action = "block".into();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.updated, 1);
        assert_eq!(h.rule_repo.save_count(), saves_before + 1);
    }

    #[tokio::test]
    async fn delete_curation_rule_when_absent_from_desired() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("r1", "block", "p", "r"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(h.rule_repo.delete_count(), 1);
    }

    // ===================================================================
    // Stage 2: Repository + curation-rule junction
    // ===================================================================

    #[tokio::test]
    async fn repository_with_curation_rule_writes_junction_with_resolved_id() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
        let mut repo = repo_env("rust-public", "hosted");
        repo.spec.curation_rules = Some(vec!["allow-rust".into()]);
        desired.repositories.push(repo);

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let calls = h.rule_repo.junction_calls();
        assert_eq!(
            calls.len(),
            1,
            "expect one set_curation_rules_for_repository call"
        );
        let (_repo_id, rule_ids) = &calls[0];
        assert_eq!(rule_ids.len(), 1);
    }

    #[tokio::test]
    async fn repository_curation_rules_cleared_writes_empty_junction() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
        let mut repo = repo_env("rust-public", "hosted");
        repo.spec.curation_rules = Some(vec!["allow-rust".into()]);
        desired.repositories.push(repo);
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();

        let junction_count_before = h.rule_repo.junction_calls().len();
        desired.repositories[0].spec.curation_rules = Some(vec![]);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let after = h.rule_repo.junction_calls();
        assert!(after.len() > junction_count_before);
        let last = after.last().unwrap();
        assert!(
            last.1.is_empty(),
            "expected empty rule_ids, got {:?}",
            last.1
        );
    }

    // ===================================================================
    // Stage 2: ScanPolicy event-sourced apply
    // ===================================================================

    #[tokio::test]
    async fn create_scan_policy_routes_through_policy_use_case() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("prod-default"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1);
        // PolicyUseCase::create_policy appended a PolicyCreated event.
        let appends = h.events.appended();
        assert_eq!(appends.len(), 1);
        assert!(matches!(
            appends[0].events[0].event,
            DomainEvent::PolicyCreated(_)
        ));
        // Actor must be GitOps.
        assert!(matches!(appends[0].actor, Actor::GitOps(_)));
    }

    #[tokio::test]
    async fn idempotent_scan_policy_reapply_emits_zero_events() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("prod-default"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let appends_before = h.events.appended().len();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.unchanged, 1);
        assert_eq!(h.events.appended().len(), appends_before);
    }

    #[tokio::test]
    async fn update_scan_policy_single_field_routes_through_update_policy() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("prod-default"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let appends_before = h.events.appended().len();

        // Mutate one field — severity_threshold high → critical.
        desired.scan_policies[0].spec.severity_threshold = "critical".into();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.updated, 1);
        // Exactly one new append (the PolicyUpdated batch).
        let new_appends = &h.events.appended()[appends_before..];
        assert_eq!(new_appends.len(), 1);
        // The single event in the batch is a PolicyUpdated for SeverityThreshold.
        assert_eq!(new_appends[0].events.len(), 1);
        assert!(matches!(
            new_appends[0].events[0].event,
            DomainEvent::PolicyUpdated(_)
        ));
    }

    #[tokio::test]
    async fn missing_scan_policy_archives_via_policy_use_case() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("prod-default"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        let appends_before = h.events.appended().len();

        // Drop the desired scan policy.
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report.deleted, 1);
        let new_appends = &h.events.appended()[appends_before..];
        assert_eq!(new_appends.len(), 1);
        assert!(matches!(
            new_appends[0].events[0].event,
            DomainEvent::PolicyArchived(_)
        ));
    }

    #[tokio::test]
    async fn concurrent_modification_aborts_strict_atomic() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("p1"));
        desired.scan_policies.push(scan_policy_env("p2"));
        // Inject a Conflict on the very first append (the create of p1).
        h.events.schedule_conflict_on_next_append();

        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        assert!(matches!(err, AppError::ConcurrentModification(_)));
        // After the conflict, the apply MUST abort: only the conflict-
        // injected append is in the log; p2 is never attempted.
        let appends = h.events.appended();
        assert_eq!(
            appends.len(),
            1,
            "stage 2 must not continue past concurrent-modification abort: got {} appends",
            appends.len()
        );
    }

    // ===================================================================
    // PermissionGrant apply (claims-subject; ADR 0012).
    // There is no `role`-keyed grant or per-row save API:
    // a grant carries a sum-typed `GrantSubject`, persistence is the
    // whole-partition `save_managed` reconcile, and the
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
        assert_eq!(h.grant_repo.save_managed_call_count(), 1);
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
    // Stage 3: Exclusion event-sourced apply
    // ===================================================================

    #[tokio::test]
    async fn add_exclusion_routes_through_policy_use_case() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("p1"));
        desired
            .exclusions
            .push(exclusion_env("ex-cve-1", "p1", "CVE-2024-0001"));

        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        // 1 policy + 1 exclusion = 2 created.
        assert_eq!(report.created, 2);
        // Two appends: PolicyCreated then ExclusionAdded.
        let appends = h.events.appended();
        assert!(appends
            .iter()
            .any(|b| { matches!(b.events[0].event, DomainEvent::ExclusionAdded(_)) }));
    }

    #[tokio::test]
    async fn remove_exclusion_when_absent_from_desired() {
        // Seed a current projection with one exclusion, then re-apply
        // with the parent policy still declared but the exclusion
        // dropped. The applier should produce one ExclusionRemoved.
        let h = build_harness();
        // Stage 1: seed a projection so the ScanPolicy diff reads
        // existing projection (rather than create-from-scratch).
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
            license_policy: serde_json::json!({"allowed": ["MIT"]}),
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        });
        let exclusion_id = Uuid::new_v4();
        h.proj.insert_exclusion(ExclusionProjection {
            exclusion_id,
            policy_id,
            cve_id: "CVE-2024-0001".into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "old".into(),
            added_by_actor_id: None,
            expires_at: None,
        });

        // Desired has the policy but NO exclusion.
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("p1"));

        h.uc.apply(desired, env_oidc()).await.unwrap();

        // Look for an ExclusionRemoved append.
        let appends = h.events.appended();
        let removed_count = appends
            .iter()
            .filter(|b| {
                b.events
                    .iter()
                    .any(|e| matches!(e.event, DomainEvent::ExclusionRemoved(_)))
            })
            .count();
        assert_eq!(removed_count, 1);
    }

    #[tokio::test]
    async fn change_exclusion_scope_emits_remove_then_add() {
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
            license_policy: serde_json::json!({"allowed": ["MIT"]}),
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        });
        let old_id = Uuid::new_v4();
        h.proj.insert_exclusion(ExclusionProjection {
            exclusion_id: old_id,
            policy_id,
            cve_id: "CVE-2024-0001".into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "rev1".into(),
            added_by_actor_id: None,
            expires_at: None,
        });

        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("p1"));
        let mut ex = exclusion_env("ex-cve-1", "p1", "CVE-2024-0001");
        ex.spec.reason = "rev2".into();
        desired.exclusions.push(ex);

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let appends = h.events.appended();
        let removed = appends
            .iter()
            .filter(|b| {
                b.events
                    .iter()
                    .any(|e| matches!(e.event, DomainEvent::ExclusionRemoved(_)))
            })
            .count();
        let added = appends
            .iter()
            .filter(|b| {
                b.events
                    .iter()
                    .any(|e| matches!(e.event, DomainEvent::ExclusionAdded(_)))
            })
            .count();
        assert_eq!(removed, 1, "scope/reason change must emit a Removed");
        assert_eq!(added, 1, "scope/reason change must emit an Added");
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
        assert_eq!(h.claim_mappings.save_managed_call_count(), 1);
        assert_eq!(h.claim_mappings.managed_count(), 1);
        assert_eq!(h.grant_repo.save_managed_call_count(), 1);
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
    fn counter_value_for(entries: &[SnapshotEntry], metric: &str, wanted: &[(&str, &str)]) -> u64 {
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
    fn add_exclusion_emits_one_exclusion_added_event_metric() {
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
                desired
                    .exclusions
                    .push(exclusion_env("ex1", "p1", "CVE-2024-0001"));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "exclusion"), ("event_type", "ExclusionAdded")],
            ),
            1,
        );
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "exclusion"), ("result", "created")],
            ),
            1,
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

    #[test]
    fn create_curation_rule_emits_objects_total_kind_curation_rule() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired
                    .curation_rules
                    .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "curation_rule"), ("result", "created")],
            ),
            1,
        );
    }

    // ===================================================================
    // Retroactive curation evaluation
    // ===================================================================

    /// Helper: seed a repository row in `MockRepositoryRepository` with a
    /// known id, key, and format so the apply pipeline's
    /// `find_by_key` (during stage 2 junction-write) and
    /// `find_by_id` (during the retroactive pass coords assembly) both
    /// succeed.
    fn seed_repo(
        repos: &Arc<MockRepositoryRepository>,
        key: &str,
        format: RepositoryFormat,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();
        repos.insert(Repository {
            id,
            key: key.into(),
            name: key.into(),
            description: None,
            format,
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
            created_at: now,
            updated_at: now,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        });
        id
    }

    /// Helper: seed an active artifact (Quarantined or Released) in
    /// `MockArtifactRepository` with a known name + format. Returns the
    /// artifact id so tests can assert state transitions.
    fn seed_active_artifact(
        artifacts: &Arc<crate::use_cases::test_support::MockArtifactRepository>,
        repository_id: Uuid,
        name: &str,
        status: hort_domain::entities::artifact::QuarantineStatus,
    ) -> Uuid {
        use hort_domain::entities::artifact::Artifact;
        use hort_domain::types::ContentHash;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        artifacts.insert(Artifact {
            id,
            repository_id,
            name: name.into(),
            name_as_published: name.into(),
            version: Some("1.0.0".into()),
            path: format!("{name}/1.0.0/{name}-1.0.0.tgz"),
            size_bytes: 1024,
            sha256_checksum: hash,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/gzip".into(),
            quarantine_status: status,
            // Store the observation-window anchor;
            // the deadline is computed live.
            quarantine_window_start: Some(now),
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: now,
            updated_at: now,
        });
        id
    }

    /// Wire `MockCurationRuleRepo`'s reverse-index after a curation
    /// rule lands. The mock's `save_managed` stores the rule but does
    /// not auto-link to repos (the apply pipeline drives the junction
    /// edges via `set_curation_rules_for_repository`); for the
    /// retroactive-pass tests we link the freshly-saved rule to a
    /// pre-seeded repo manually.
    async fn link_rule_after_apply(h: &Harness, rule_name: &str, repo_id: Uuid) {
        let rule = h
            .rule_repo
            .find_by_name(rule_name)
            .await
            .unwrap()
            .expect("rule landed");
        h.rule_repo.link_rule_to_repo(rule.id, repo_id);
    }

    /// Declaring a `Block` rule for the first time triggers the retroactive
    /// pass on previously-active matching artifacts. The
    /// artifact transitions to `Rejected` AND the apply emits both a
    /// `CurationApplied { trigger: Retroactive, action: Block }` on the
    /// per-repo curation stream and an `ArtifactRejected` on the
    /// artifact stream.
    #[tokio::test]
    async fn retro_block_creates_rule_then_rejects_matching_artifact() {
        // To trigger the retroactive pass we use the tightening path:
        // apply an Allow rule first (silent), then tighten to Block.
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        let artifact_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );

        // Apply 1 — Allow rule. No retroactive evaluation; report
        // counters stay zero.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.retro_warn_count, 0);
        assert_eq!(report.retro_block_count, 0);

        // Wire reverse-index now that rule exists.
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;

        // Apply 2 — same name, action tightens Allow → Block. The
        // retroactive pass hits.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        assert_eq!(report.retro_block_count, 1);
        assert_eq!(report.retro_warn_count, 0);

        // Artifact transitioned to Rejected.
        let after = h.artifacts.get(artifact_id).unwrap();
        assert_eq!(
            after.quarantine_status,
            hort_domain::entities::artifact::QuarantineStatus::Rejected
        );

        // The lifecycle port saw the commit_transition with an
        // ArtifactRejected payload carrying RejectionReason::CurationRetroactive.
        let transitions = h.lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (_a, batch, _meta) = &transitions[0];
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0].event {
            DomainEvent::ArtifactRejected(r) => {
                assert!(matches!(
                    r.rejected_by,
                    hort_domain::events::RejectionReason::CurationRetroactive { .. }
                ));
                assert_eq!(r.reason, "supply chain");
            }
            other => panic!("expected ArtifactRejected, got {other:?}"),
        }

        // The event-store saw a CurationApplied with trigger=Retroactive
        // on the curation stream for this repo.
        let mut found = false;
        for batch in h.events.appended() {
            if batch.stream_id == StreamId::curation_per_repo(repo_id) {
                for ev in &batch.events {
                    if let DomainEvent::CurationApplied(c) = &ev.event {
                        assert_eq!(c.trigger, CurationTrigger::Retroactive);
                        assert_eq!(c.action, CurationActionTag::Block);
                        assert_eq!(c.repository_id, repo_id);
                        found = true;
                    }
                }
            }
        }
        assert!(found, "expected CurationApplied on curation stream");
    }

    /// Retroactive curation pass emits
    /// `decision_point=curation_retroactive` with `result=retro_block`
    /// when a tightened rule transitions an existing artifact to
    /// `Rejected`, plus a violations counter under `rule=curation-block`.
    #[test]
    fn retroactive_curation_block_emits_metrics() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let h = build_harness();
                let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
                let _aid = seed_active_artifact(
                    &h.artifacts,
                    repo_id,
                    "left-pad",
                    hort_domain::entities::artifact::QuarantineStatus::Released,
                );
                let mut desired = DesiredState::default();
                desired.curation_rules.push(rule_env(
                    "block-leftpad",
                    "allow",
                    "left-pad",
                    "trusted",
                ));
                h.uc.apply(desired, env_oidc()).await.unwrap();
                link_rule_after_apply(&h, "block-leftpad", repo_id).await;

                let mut desired = DesiredState::default();
                desired.curation_rules.push(rule_env(
                    "block-leftpad",
                    "block",
                    "left-pad",
                    "supply chain",
                ));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_evaluation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "curation_retroactive")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "retro_block")
            }),
            "RetroBlock outcome must emit decision_point=curation_retroactive, result=retro_block"
        );
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_violations_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "curation_retroactive")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "rule" && l.value() == "curation-block")
            }),
            "RetroBlock outcome must emit rule=curation-block"
        );
    }

    /// Acceptance: a retroactive
    /// curation `RetroBlock` outcome MUST sweep every
    /// `content_references` row whose `source_artifact_id` matches the
    /// just-rejected artifact. Mirrors the scan-driven reject path
    /// covered by `quarantine_reject_sweeps_content_references`. The
    /// artifact row stays alive (rejection is sticky), so the FK
    /// CASCADE never fires; the explicit `delete_by_source` sweep is
    /// the only mechanism that keeps the projection consistent with
    /// the artifact's terminal state.
    #[tokio::test]
    async fn retroactive_curation_reject_sweeps_content_references() {
        use hort_domain::ports::content_reference_index::ContentReference;
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        let artifact_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );
        let primary_hash = h.artifacts.get(artifact_id).unwrap().sha256_checksum;
        let blob_hash: hort_domain::types::ContentHash =
            "1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap();
        // Seed both refcount rows that an ingest with HashReference-
        // strategy metadata would have produced: primary_content +
        // metadata_blob, sharing the source.
        h.content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: primary_hash.clone(),
                kind: "primary_content".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        h.content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: blob_hash.clone(),
                kind: "metadata_blob".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(
            h.content_refs.entry_count(),
            2,
            "fixture: two refcount rows seeded for the artifact-about-to-retro-reject"
        );

        // Apply 1 — Allow rule (silent; no retroactive evaluation).
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;
        // Refcount untouched by the silent path.
        assert_eq!(h.content_refs.entry_count(), 2);

        // Apply 2 — tighten Allow → Block. The retroactive pass hits
        // `commit_retroactive_block`, which now sweeps refcount rows.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.retro_block_count, 1, "the retro block must fire");

        // Both refcount rows must be gone, regardless of kind.
        assert_eq!(
            h.content_refs.entry_count(),
            0,
            "retro-block must sweep every content_references row for the source"
        );
        let primary_rows = h
            .content_refs
            .find_by_target(repo_id, &primary_hash, Some("primary_content"))
            .await
            .unwrap();
        assert_eq!(primary_rows.len(), 0, "primary_content row gone");
        let blob_rows = h
            .content_refs
            .find_by_target(repo_id, &blob_hash, Some("metadata_blob"))
            .await
            .unwrap();
        assert_eq!(blob_rows.len(), 0, "metadata_blob row gone");
    }

    /// Branch coverage for the
    /// warn-on-fail arm at `commit_retroactive_block` after
    /// `reject_from_retroactive_curation`. The refcount sweep is
    /// post-commit eventual — when
    /// `delete_by_source` fails on the retroactive-curation reject
    /// path, the outer `apply` MUST still return `Ok` because the
    /// `ArtifactRejected` event has already been appended and is the
    /// authoritative state change. The seeded refcount row is left
    /// in place and is repaired by the Phase B reconcile sweep.
    #[tokio::test]
    async fn retroactive_curation_reject_refcount_delete_failure_is_warn_only() {
        use hort_domain::ports::content_reference_index::ContentReference;
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        let artifact_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );
        let primary_hash = h.artifacts.get(artifact_id).unwrap().sha256_checksum;

        // Seed one refcount row so the post-reject `delete_by_source`
        // has a concrete target; the assertion that the row remains
        // is sharper than asserting an already-empty mock stayed
        // empty.
        h.content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: primary_hash.clone(),
                kind: "primary_content".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(h.content_refs.entry_count(), 1, "fixture seeded");

        // Apply 1 — Allow rule (silent; no retroactive evaluation).
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;
        assert_eq!(
            h.content_refs.entry_count(),
            1,
            "silent-path apply must not touch refcount"
        );

        // Arm a one-shot delete failure. The next `delete_by_source`
        // call (from the about-to-fire retro-block) consumes it.
        h.content_refs
            .fail_next_delete(hort_domain::error::DomainError::Invariant(
                "synthetic failure: delete_by_source on retro-curation reject".into(),
            ));

        // Apply 2 — tighten Allow → Block. Retroactive pass hits
        // `commit_retroactive_block`; the inner sweep fails; the
        // outer `apply` must still succeed and the report must
        // record the retro-block.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed even when refcount sweep fails on retro-block");
        assert_eq!(
            report.retro_block_count, 1,
            "the retro block must still fire"
        );

        // Load-bearing: the seeded refcount row is STILL present
        // after the warn-arm fired. A future change that aborts the
        // apply on delete-failure would either flip the
        // `.expect("apply must succeed")` above or the row would be
        // gone (because the arm reached delete and unwound) — either
        // outcome would fail this assertion.
        assert_eq!(
            h.content_refs.entry_count(),
            1,
            "warn-on-fail must leave the seeded row in place; reconcile is future work"
        );
        let rows = h
            .content_refs
            .find_by_target(repo_id, &primary_hash, Some("primary_content"))
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "primary_content row still present after the warn arm fired"
        );
    }

    /// Declaring `Block` then weakening to `Allow` must NOT auto-unblock
    /// the previously-rejected artifact. Rejection is sticky; admin
    /// explicit release is the override.
    #[tokio::test]
    async fn retro_weaken_does_not_unblock_or_emit_events() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);

        // Seed an already-rejected artifact (the `list_active_for_repo`
        // SQL excludes these, so the retroactive pass should not touch it).
        let _rejected_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Rejected,
        );

        // Apply 1 — Block rule; link to repo.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;

        let events_before = h.events.appended().len();
        let transitions_before = h.lifecycle.committed_transitions().len();

        // Apply 2 — weaken to Allow.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "revoked"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        // No retroactive counters incremented (weakening is silent).
        assert_eq!(report.retro_warn_count, 0);
        assert_eq!(report.retro_block_count, 0);

        // No new events on any stream from the retro path.
        assert_eq!(
            h.events.appended().len(),
            events_before,
            "weakening must NOT emit events"
        );
        assert_eq!(
            h.lifecycle.committed_transitions().len(),
            transitions_before,
            "weakening must NOT mutate artifact state"
        );
    }

    /// Declaring a Warn rule emits CurationApplied on the curation stream
    /// but does NOT mutate artifact state.
    #[tokio::test]
    async fn retro_warn_emits_event_without_state_change() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        let artifact_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "moment",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );

        // Apply 1 — Allow rule.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("warn-moment", "allow", "moment", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "warn-moment", repo_id).await;

        // Apply 2 — tighten to Warn.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("warn-moment", "warn", "moment", "deprecated"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        assert_eq!(report.retro_warn_count, 1);
        assert_eq!(report.retro_block_count, 0);

        // Artifact state is unchanged (still Released).
        let after = h.artifacts.get(artifact_id).unwrap();
        assert_eq!(
            after.quarantine_status,
            hort_domain::entities::artifact::QuarantineStatus::Released
        );

        // No artifact-stream commit_transition fired.
        assert!(h.lifecycle.committed_transitions().is_empty());

        // CurationApplied with action=Warn fired on the curation stream.
        let mut found = false;
        for batch in h.events.appended() {
            if batch.stream_id == StreamId::curation_per_repo(repo_id) {
                for ev in &batch.events {
                    if let DomainEvent::CurationApplied(c) = &ev.event {
                        assert_eq!(c.trigger, CurationTrigger::Retroactive);
                        assert_eq!(c.action, CurationActionTag::Warn);
                        found = true;
                    }
                }
            }
        }
        assert!(found, "expected CurationApplied(Warn) on curation stream");
    }

    /// `list_active_for_repo` excludes `Rejected` artifacts; the
    /// retroactive pass on a rule that would block them is a no-op
    /// (no events, no state change). Defends the "rejection is sticky"
    /// property at the repo-listing layer.
    #[tokio::test]
    async fn retro_skips_already_rejected_artifacts() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        // Only a rejected artifact exists.
        seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Rejected,
        );

        // Apply 1 — Allow rule.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;

        // Apply 2 — tighten to Block. The rejected artifact is invisible
        // to the retroactive pass.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        assert_eq!(report.retro_block_count, 0);
        assert_eq!(report.retro_warn_count, 0);
        assert!(h.lifecycle.committed_transitions().is_empty());
    }

    /// Strict-atomic discipline — a concurrent ingest causing
    /// `commit_transition` to fail with `Conflict` aborts the entire
    /// apply pipeline as `AppError::ConcurrentModification`. The
    /// operator restarts; the second pass re-resolves and continues
    /// (covered by re-running the apply on a fresh harness).
    #[tokio::test]
    async fn retro_block_optimistic_concurrency_aborts_strict_atomic() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );

        // Apply 1 — Allow rule, link.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;

        // Inject a Conflict on the next commit_transition (simulating a
        // concurrent ingest racing the retroactive pass).
        h.lifecycle
            .fail_next_commit(DomainError::Conflict("stale stream version".into()));

        // Apply 2 — tighten Allow → Block. The retroactive pass hits a
        // Conflict; strict-atomic aborts.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        assert!(matches!(err, AppError::ConcurrentModification(_)));
    }

    /// Declaring a NEW rule with action=Allow does NOT trigger any
    /// retroactive events even when matching artifacts exist
    /// (Allow → NoChange is silent).
    #[tokio::test]
    async fn retro_create_allow_rule_emits_no_events() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );

        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("allow-leftpad", "allow", "left-pad", "trusted"));
        // Pre-link so the retro pass would see the repo.
        // We need to apply first to get the rule id, then link, then
        // re-apply — but the create branch is what triggers the retro
        // pass on first apply. Instead, seed the link via a manual
        // post-save hook: use `link_rule_to_repo` AFTER the apply
        // resolved the id.
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "allow-leftpad", repo_id).await;

        // The first apply was a `create` and IS a retro candidate, but
        // the rule's action is Allow — outcome is NoChange. So no
        // events are emitted regardless of the candidate flag.
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        // Reapply is unchanged; no retro candidacy triggered.
        assert_eq!(report.retro_block_count, 0);
        assert_eq!(report.retro_warn_count, 0);
        assert!(h.lifecycle.committed_transitions().is_empty());
    }

    // ----------------------------------------------------------------------
    // UpstreamMapping apply branch
    // ----------------------------------------------------------------------

    fn upstream_mapping_env(
        name: &str,
        repository: &str,
        path_prefix: &str,
        upstream_url: &str,
    ) -> Envelope<UpstreamMappingSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
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

    /// Happy path: a desired `UpstreamMapping` against a freshly-
    /// created repository round-trips through the apply pipeline. The
    /// pipeline must resolve `spec.repository` → `repository_id` from
    /// the Stage 2 result map, then `save_managed` the row with
    /// `managed_by=GitOps`.
    #[tokio::test]
    async fn apply_upstream_mapping_create_writes_managed_row() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };

        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        // One mapping created (the Repository also counts as `created`,
        // so we assert the upstream-mapping write specifically through
        // the mock instead of the rolled-up counter).
        assert!(
            report.created >= 2,
            "expected at least repo + mapping creates, got {}",
            report.created
        );
        // Mock recorded one managed row at (repo_id, "dockerhub/").
        let listed = h
            .upstream
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path_prefix, "dockerhub/");
        assert_eq!(listed[0].managed_by, ManagedBy::GitOps);
        assert!(listed[0].managed_by_digest.is_some());
        assert_eq!(listed[0].upstream_url, "https://registry-1.docker.io");
    }

    /// Re-applying the same desired state produces zero churn — the
    /// digest matches, the diff classifies the mapping as `unchanged`,
    /// and `save_managed` is NOT called the second time.
    #[tokio::test]
    async fn apply_upstream_mapping_reapply_is_idempotent() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let listed_first = h.upstream.list_managed_by_gitops().await.unwrap();
        let id_first = listed_first[0].id;
        let digest_first = listed_first[0].managed_by_digest;

        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        // Second apply: row stays put, digest unchanged.
        let listed_second = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed_second.len(), 1);
        assert_eq!(listed_second[0].id, id_first, "id stays stable");
        assert_eq!(
            listed_second[0].managed_by_digest, digest_first,
            "digest stays stable"
        );
        // The mapping contributes one to the unchanged counter.
        assert!(
            report.unchanged >= 1,
            "expected at least the mapping in unchanged, got {}",
            report.unchanged
        );
    }

    // -- trustUpstreamPublishTime end-to-end --------------------------------
    //
    // The quarantine-window anchor computation is the
    // consumer. These tests pin the spec → Args → persisted-row
    // threading so a regression in the apply pipeline surfaces here
    // rather than at anchor-computation time. Mirrors the
    // upstream_name_prefix end-to-end tests.

    /// Round-trip: Some(true) in the spec lands as `true` on the
    /// persisted row.
    #[tokio::test]
    async fn apply_upstream_mapping_threads_trust_upstream_publish_time_true_to_persisted_row() {
        let h = build_harness();
        let mut mapping_env = upstream_mapping_env(
            "oci-mirror-dockerhub",
            "oci-mirror-e2e",
            "dockerhub/",
            "https://registry-1.docker.io",
        );
        mapping_env.spec.trust_upstream_publish_time = true;
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![mapping_env],
            ..Default::default()
        };

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let listed = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(
            listed[0].trust_upstream_publish_time,
            "the apply pipeline must thread trustUpstreamPublishTime=true through to the row"
        );
    }

    /// Round-trip: Some(false) in the spec lands as `false` on the
    /// persisted row — and the field-absent default (Phase-1
    /// happy-path envelope) also lands as `false`. One test covers
    /// both because they share the same expected outcome and the
    /// distinction (explicit vs. defaulted) is already covered by the
    /// hort-config parser unit tests.
    #[tokio::test]
    async fn apply_upstream_mapping_defaults_trust_upstream_publish_time_to_false() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            // upstream_mapping_env constructs the spec with
            // trust_upstream_publish_time: false (the Phase-1 default
            // envelope shape) — this is the absent-field case at
            // YAML-level after serde-default kicked in.
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let listed = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(
            !listed[0].trust_upstream_publish_time,
            "the default-`false` spec must produce a row with trust_upstream_publish_time = false"
        );
    }

    // -- upstreamNamePrefix end-to-end ---------------------------------------
    //
    // The field is threaded from `UpstreamMappingSpec` through
    // `ApplyConfigUseCase::apply_upstream_mappings` into
    // `RepositoryUpstreamMappingArgs`. Diff identity stays
    // `(repository, path_prefix)`; the new field participates in the
    // spec digest so a value change produces `result=updated`, not
    // `delete + create` or a no-op.

    fn upstream_mapping_env_with_prefix(
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
    fn oci_repo_env(name: &str) -> Envelope<RepositorySpec> {
        let mut env = repo_env(name, "proxy");
        env.spec.format = "oci".into();
        env
    }

    /// End-to-end: YAML spec with `upstreamNamePrefix` set →
    /// `ApplyConfigUseCase::apply` → re-load the mapping from the mock
    /// port. The field must survive the round-trip from spec to
    /// `RepositoryUpstreamMappingArgs` to the persisted row.
    #[tokio::test]
    async fn apply_upstream_mapping_threads_upstream_name_prefix_to_persisted_row() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![oci_repo_env("oci-mirror-e2e")],
            upstream_mappings: vec![upstream_mapping_env_with_prefix(
                "oci-via-zot",
                "oci-mirror-e2e",
                "",
                "https://zot.example.com",
                Some("docker.io"),
            )],
            ..Default::default()
        };

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let listed = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].upstream_name_prefix.as_deref(),
            Some("docker.io"),
            "the apply pipeline must thread upstreamNamePrefix through to the row"
        );
    }

    /// Diff-identity invariant: the new field participates in the
    /// spec digest, so changing it across re-applies produces a
    /// single `result=updated` event — NOT `deleted+created` (which
    /// would happen if the field were part of the identity tuple) and
    /// NOT a no-op (which would happen if the field were absent from
    /// the digest input). This rules out all four bad outcomes:
    ///
    /// (a) the two specs produce DIFFERENT digests
    /// (b) the apply classifies the change as one `result=updated`
    /// (c) NOT `result=deleted` + `result=created`
    /// (d) NOT zero events (no-op)
    #[tokio::test]
    async fn upstream_name_prefix_change_produces_one_updated_event_not_create_delete_or_noop() {
        let h = build_harness();

        let before_spec = upstream_mapping_env_with_prefix(
            "oci-via-zot",
            "oci-mirror-e2e",
            "",
            "https://zot.example.com",
            Some("docker.io"),
        );
        let after_spec = upstream_mapping_env_with_prefix(
            "oci-via-zot",
            "oci-mirror-e2e",
            "",
            "https://zot.example.com",
            Some("docker.io/sub"),
        );

        // (a) Digests differ across the two specs.
        let digest_before = spec_digest_upstream_mapping(&before_spec.spec);
        let digest_after = spec_digest_upstream_mapping(&after_spec.spec);
        assert_ne!(
            digest_before, digest_after,
            "spec_digest_upstream_mapping must change when upstreamNamePrefix changes — \
             otherwise the diff layer cannot detect the value change. This rules out \
             the no-op-from-missing-hash bug where the implementer adds the field to \
             the struct but forgets to hash it."
        );

        // First apply seeds the mapping.
        let first = DesiredState {
            repositories: vec![oci_repo_env("oci-mirror-e2e")],
            upstream_mappings: vec![before_spec],
            ..Default::default()
        };
        h.uc.apply(first, env_oidc()).await.unwrap();
        let row_count_after_first = h.upstream.entry_count();
        assert_eq!(row_count_after_first, 1, "seed apply must write one row");

        // Re-apply with the prefix changed.
        let second = DesiredState {
            repositories: vec![oci_repo_env("oci-mirror-e2e")],
            upstream_mappings: vec![after_spec],
            ..Default::default()
        };
        let report = h.uc.apply(second, env_oidc()).await.unwrap();

        // The mapping contributes exactly one to `updated`. Other
        // updates may happen (the repository itself ticks `unchanged`),
        // so we filter by inspecting the mock's mapping content
        // rather than counting all events.
        let listed = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed.len(), 1, "row count unchanged after update");
        assert_eq!(
            listed[0].upstream_name_prefix.as_deref(),
            Some("docker.io/sub"),
            "(b) update path must write the new value"
        );

        // (c) NOT delete+create: the row id is stable across the
        // re-apply (a delete+create would surface as a new id).
        // (b) at least one mapping update.
        assert!(
            report.updated >= 1,
            "(b) expected at least one updated event for the mapping; got report={report:?}"
        );

        // (d) NOT zero events (no-op): if the prefix change were
        // invisible to the digest, the mapping would land in
        // `unchanged` and `updated` would be 0 *for the mapping*. We
        // already asserted updated >= 1 above; explicitly cross-check
        // that the persisted prefix value was rewritten — not just
        // that the counter ticked for some other kind of change.
        assert_ne!(
            listed[0].upstream_name_prefix.as_deref(),
            Some("docker.io"),
            "(d) the persisted row must reflect the new prefix; \
             reverting to the old value would mean the apply pipeline \
             ignored the change"
        );
    }

    /// Removing a mapping from desired while it remains as a managed
    /// row in current produces a delete.
    #[tokio::test]
    async fn apply_upstream_mapping_absent_in_desired_deletes_managed_row() {
        let h = build_harness();
        let with_mapping = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h.uc.apply(with_mapping, env_oidc()).await.unwrap();
        assert_eq!(h.upstream.entry_count(), 1);

        // Re-apply with the mapping omitted — repo still declared.
        let without_mapping = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![],
            ..Default::default()
        };
        let report = h.uc.apply(without_mapping, env_oidc()).await.unwrap();
        assert!(
            report.deleted >= 1,
            "expected the mapping in deleted, got {}",
            report.deleted
        );
        assert_eq!(
            h.upstream.entry_count(),
            0,
            "managed mapping must be removed"
        );
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
    /// as a `Vec<DomainEvent>`.
    async fn repo_stream_events(events: &MockPolicyEventStore, repo_id: Uuid) -> Vec<DE> {
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
            api_version: ApiVersion::V1Beta1,
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
            h.rule_repo.clone(),
            h.proj.clone(),
            Arc::new(PolicyUseCase::new(
                crate::event_store_publisher::wrap_for_test(h.events.clone()),
                h.proj.clone(),
                h.artifacts.clone(),
                h.lifecycle.clone(),
                Arc::new(crate::use_cases::test_support::MockStoragePort::new()),
                default_repository_access_for_policy(),
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
            api_version: ApiVersion::V1Beta1,
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
                max_artifact_age: Some("90d".into()),
                license_policy: serde_json::json!({"allowed": ["MIT"]}),
                scan_backends: backends.into_iter().map(str::to_string).collect(),
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
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
            license_policy: serde_json::json!({"allowed": ["MIT"]}),
            // The crucial bit — this row is archived. The previous
            // apply ran with the YAML absent, archived `p1`, and
            // left the row in `policy_projections`.
            archived: true,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
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
            // Row 2 — SA references an undeclared issuer (the repository it
            // references IS declared so row 1 `validate_against` passes and
            // the abort is exactly the row-2 FK check).
            Case {
                desired: DesiredState {
                    repositories: vec![repo_env("pypi-internal", "hosted")],
                    service_accounts: vec![service_account_env_for_apply(
                        "ci",
                        &["pypi-internal"],
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
        ];

        for case in cases {
            // The pure validator's first-error-in-row-order rule.
            let validator = StaticConfigValidator::new(
                Arc::new(["oci".to_string()].into_iter().collect()),
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
            // apply's repository stage creates it through the mock BEFORE the
            // grant stage, so the grant expansion's `find_by_key` resolves it.
            // No pre-seed (a pre-seeded `managed_by=local` row would make
            // apply reject the re-declaration before reaching the linter).
            let apply_result = h.uc.apply(case.desired.clone(), env_oidc()).await;
            let apply_rejects = match &apply_result {
                Err(AppError::Domain(DomainError::Validation(msg))) => {
                    msg.contains("apply-config linter rejected")
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
        }
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
            api_version: ApiVersion::V1Beta1,
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
                max_artifact_age: Some("90d".into()),
                license_policy: serde_json::json!({"allowed": ["MIT"]}),
                scan_backends: vec!["trivy".to_string()],
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
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
            api_version: ApiVersion::V1Beta1,
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
                max_artifact_age: Some("90d".into()),
                license_policy: serde_json::json!({"allowed": ["MIT"]}),
                scan_backends: vec!["trivy".to_string()],
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
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
            api_version: ApiVersion::V1Beta1,
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
                max_artifact_age: Some("90d".into()),
                license_policy: serde_json::json!({"allowed": ["MIT"]}),
                scan_backends: backends.into_iter().map(str::to_string).collect(),
                rescan_interval_hours: 24,
                negligible_action: "ignore".into(),
            },
        }
    }

    // ===================================================================
    // OidcIssuer + ServiceAccount apply tests
    // ===================================================================

    use hort_config::oidc_issuer::OidcIssuerSpec;
    use hort_config::service_account::{FederatedIdentitySpec, ServiceAccountSpec};
    use std::collections::BTreeMap;

    fn oidc_issuer_env_for_apply(name: &str) -> Envelope<OidcIssuerSpec> {
        Envelope {
            api_version: ApiVersion::V1Beta1,
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

    fn service_account_env_for_apply(
        sa_name: &str,
        repos: &[&str],
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
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ServiceAccount,
            metadata: Metadata {
                name: sa_name.into(),
            },
            spec: ServiceAccountSpec {
                role: "developer".into(),
                repositories: repos.iter().map(|s| (*s).into()).collect(),
                federated_identities,
                fallback_rotation: None,
            },
        }
    }

    /// The SA apply path does no
    /// `RoleRepository::find_by_name(&sa.role)` lookup — the role-name
    /// bundle is code-expanded by `service_account_permission_for_role`
    /// over the fixed `developer`/`reader` enum, never a `roles` table
    /// or `claim_mappings` consultation. There is therefore nothing to
    /// seed; this is a behaviour-preserving no-op kept so the SA test
    /// call sites read unchanged (returns a throwaway id the callers
    /// previously used only as a placeholder).
    fn seed_developer_role(_h: &Harness) -> Uuid {
        Uuid::new_v4()
    }

    // -- OidcIssuer apply --------------------------------------------------

    #[tokio::test]
    async fn apply_oidc_issuer_creates_new_row_and_emits_event() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1, "exactly one row created");
        let stored = h.oidc_issuers.snapshot();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, "github-actions");
        assert_eq!(stored[0].issuer_url, "https://github-actions.example.com");
    }

    #[tokio::test]
    async fn apply_oidc_issuer_is_idempotent_on_reapply() {
        let h = build_harness();
        let env = oidc_issuer_env_for_apply("github-actions");
        let mut desired_a = DesiredState::default();
        desired_a.oidc_issuers.push(env.clone());
        h.uc.apply(desired_a, env_oidc()).await.unwrap();
        // First apply created the issuer. Snapshot's digest is `None`,
        // so the diff currently classifies the second apply as
        // `update` rather than `unchanged` — but the post-apply row
        // count must still be exactly 1.
        let mut desired_b = DesiredState::default();
        desired_b.oidc_issuers.push(env);
        h.uc.apply(desired_b, env_oidc()).await.unwrap();
        assert_eq!(h.oidc_issuers.snapshot().len(), 1);
    }

    #[tokio::test]
    async fn apply_oidc_issuer_delete_removes_row() {
        let h = build_harness();
        let env = oidc_issuer_env_for_apply("github-actions");
        let mut desired = DesiredState::default();
        desired.oidc_issuers.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(h.oidc_issuers.snapshot().len(), 1);
        // Re-apply with no issuers — the row is scheduled for delete.
        let empty = DesiredState::default();
        let report = h.uc.apply(empty, env_oidc()).await.unwrap();
        assert_eq!(report.deleted, 1);
        assert!(h.oidc_issuers.snapshot().is_empty());
    }

    // -- apply-time JWKS warm-up tests ---------------------------------------

    /// Helper: rebuild the apply use case from a base harness with a
    /// `MockFederatedJwtValidator` attached. Returns the
    /// already-shared mock so tests can seed `register_refresh_outcome`
    /// and assert on `refresh_calls`.
    fn install_validator(
        h: &Harness,
    ) -> (
        ApplyConfigUseCase,
        Arc<crate::use_cases::test_support::MockFederatedJwtValidator>,
    ) {
        let validator = Arc::new(crate::use_cases::test_support::MockFederatedJwtValidator::new());
        let policies = Arc::new(PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(h.events.clone()),
            h.proj.clone(),
            h.artifacts.clone(),
            h.lifecycle.clone(),
            Arc::new(crate::use_cases::test_support::MockStoragePort::new()),
            default_repository_access_for_policy(),
        ));
        let uc = ApplyConfigUseCase::new(
            h.repos.clone(),
            h.claim_mappings.clone(),
            h.grant_repo.clone(),
            h.rule_repo.clone(),
            h.proj.clone(),
            policies,
            h.artifacts.clone(),
            h.lifecycle.clone(),
            crate::event_store_publisher::wrap_for_test(h.events.clone()),
            h.upstream.clone(),
            UpstreamHostAllowlist::Disabled,
            h.content_refs.clone(),
            h.oidc_issuers.clone(),
            h.service_accounts.clone(),
            h.users.clone(),
        )
        // Permissive linter (see `build_harness`) —
        // the OIDC warm-up tests apply only `oidc_issuers` envelopes,
        // but pinning permissive keeps parity with `build_harness`
        // (the harness this is derived from) so a future grant added
        // to one of these tests is not silently rejected.
        .with_lint_config(crate::lint::LintConfig::permissive_for_tests())
        .with_federated_jwt_validator(validator.clone() as Arc<dyn FederatedJwtValidator>);
        (uc, validator)
    }

    /// M2 invariant 1 — when warm-up succeeds, the apply succeeds and
    /// the row is created. Validator was invoked exactly once with the
    /// expected issuer name.
    #[tokio::test]
    async fn apply_oidc_issuer_warm_up_success_does_not_fail_apply() {
        let h = build_harness();
        let (uc, validator) = install_validator(&h);
        validator.register_refresh_outcome("github-actions", Ok(()));

        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));

        let report = uc
            .apply(desired, env_oidc())
            .await
            .expect("apply must succeed on warm-up success");
        assert_eq!(report.created, 1, "row was created");
        assert_eq!(h.oidc_issuers.snapshot().len(), 1, "row persists");
        // Warm-up fired exactly once with the right name.
        assert_eq!(
            validator.refresh_calls(),
            vec!["github-actions".to_string()],
            "refresh_issuer must be invoked once with the persisted issuer's name"
        );
    }

    /// M2 invariant 2 (load-bearing) — when warm-up FAILS, the apply
    /// STILL SUCCEEDS. Federation works lazily on first request; warm-up
    /// is operator-feedback-only.
    #[tokio::test]
    async fn apply_oidc_issuer_warm_up_failure_does_not_fail_apply() {
        let h = build_harness();
        let (uc, validator) = install_validator(&h);
        validator.register_refresh_outcome(
            "github-actions",
            Err(hort_domain::ports::federated_jwt_validator::FederationDenyReason::UnknownKid),
        );

        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));

        // CRITICAL: apply must succeed even though warm-up failed.
        let report = uc
            .apply(desired, env_oidc())
            .await
            .expect("warm-up failure MUST NOT fail the apply (M2 invariant)");
        assert_eq!(report.created, 1, "row was created despite warm-up failure");
        assert_eq!(
            h.oidc_issuers.snapshot().len(),
            1,
            "row persists in repo despite warm-up failure"
        );
        // Warm-up was attempted (the failure is visible via `tracing::warn!`,
        // not via apply failure).
        assert_eq!(
            validator.refresh_calls(),
            vec!["github-actions".to_string()],
            "refresh_issuer must still be invoked even when failing"
        );
    }

    /// M2 — warm-up is invoked on the update path too (jwks_uri or
    /// audiences may have shifted; populate the cache so the next
    /// federation request sees the post-update key set without an
    /// inline fetch tax).
    #[tokio::test]
    async fn apply_oidc_issuer_warm_up_fires_on_update() {
        let h = build_harness();
        // First apply creates the row (use the harness's
        // no-validator path, since we want to test the second apply's
        // update arm).
        let mut desired_a = DesiredState::default();
        desired_a
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        h.uc.apply(desired_a, env_oidc()).await.unwrap();
        assert_eq!(h.oidc_issuers.snapshot().len(), 1);

        // Second apply uses a new harness-shaped UC with the validator
        // installed. The diff classifies as `update` (snapshot digest
        // is `None` so even an identical envelope goes through update).
        let (uc, validator) = install_validator(&h);
        validator.register_refresh_outcome("github-actions", Ok(()));
        let mut desired_b = DesiredState::default();
        desired_b
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        uc.apply(desired_b, env_oidc())
            .await
            .expect("update apply must succeed");

        assert_eq!(
            validator.refresh_calls(),
            vec!["github-actions".to_string()],
            "refresh_issuer must fire on the update path too"
        );
    }

    /// When no validator is wired (None slot), warm-up is skipped
    /// silently and the apply still succeeds. This is the default
    /// posture for every validator-less test harness; this test guards
    /// the slot.
    #[tokio::test]
    async fn apply_oidc_issuer_without_validator_skips_warm_up_silently() {
        let h = build_harness();
        // `build_harness` uses `ApplyConfigUseCase::new` only — no
        // `with_federated_jwt_validator` call.
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));

        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed with no validator wired");
        assert_eq!(report.created, 1);
    }

    // -- ServiceAccount apply ----------------------------------------------

    #[tokio::test]
    async fn apply_service_account_creates_backing_user_and_sa_row() {
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pypi-pusher",
            &["pypi-internal"],
            None,
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1, "exactly one SA created");
        // Backing user exists.
        let user = h
            .users
            .find_by_username("sa:ci-pypi-pusher")
            .await
            .unwrap()
            .expect("backing user must exist after SA apply");
        assert!(user.is_service_account);
        // SA row exists, points at the backing user.
        let sas = h.service_accounts.snapshot();
        assert_eq!(sas.len(), 1);
        assert_eq!(sas[0].backing_user_id, user.id);
    }

    #[tokio::test]
    async fn apply_service_account_reapply_is_idempotent_no_duplicate_user_or_grants() {
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });

        let env = service_account_env_for_apply("ci-pypi-pusher", &["pypi-internal"], None);
        let mut desired_a = DesiredState::default();
        desired_a.service_accounts.push(env.clone());
        h.uc.apply(desired_a, env_oidc()).await.unwrap();

        let mut desired_b = DesiredState::default();
        desired_b.service_accounts.push(env);
        h.uc.apply(desired_b, env_oidc()).await.unwrap();

        // Exactly one backing user, exactly one SA row, exactly one
        // permission grant — re-applying must not duplicate any of them.
        let users_page = h.users.list(PageRequest::new(0, 100)).await.unwrap();
        let sa_users: Vec<_> = users_page
            .items
            .iter()
            .filter(|u| u.is_service_account)
            .collect();
        assert_eq!(sa_users.len(), 1, "exactly one SA backing user");
        assert_eq!(h.service_accounts.snapshot().len(), 1, "exactly one SA row");
        // SA authority is a `GrantSubject::User(backing
        // _user_id)` grant materialised through the consolidated
        // whole-partition `permission_grants.save_managed` reconcile.
        // Re-applying the identical SA env must not duplicate the
        // grant — the User-subject diff key
        // `(user_id, repository_id, permission)` makes the replay a
        // no-op, so exactly one managed grant survives.
        let managed = h.grant_repo.managed_snapshot();
        assert_eq!(managed.len(), 1, "exactly one SA-owned grant after reapply");
        assert_eq!(managed[0].subject, GrantSubject::User(sa_users[0].id));
    }

    /// Closure proof — replay the operator's rc.20 bundle
    /// (`glci-supply-chain-security` SA + `developer` claim grants
    /// covered by a `singleClaimAllowlist: [developer]` lint config +
    /// `gitlab-kdp` OidcIssuer) and assert the SA-derived User-subject
    /// grant lands in the managed partition. The operator's "no
    /// User-subject grant persisted" observation must be reproducible
    /// here if it is a code bug; a green test rules code out and pins
    /// the contract that future changes must preserve.
    #[tokio::test]
    async fn apply_operator_f9_bundle_persists_sa_owned_user_subject_grant() {
        use hort_config::lint_config::RuleOverridesSpec;
        let h = build_harness();
        // Operator's bundle declares the ArtifactRepository as well; let
        // the apply path create it (no harness pre-seed — that would
        // collide with the managed_by=gitops upsert).
        let mut desired = DesiredState::default();
        desired
            .repositories
            .push(repo_env("supply-chain-security", "hosted"));
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("gitlab-kdp"));
        desired
            .claim_mappings
            .push(cm_env("admins", "platform-admins", "admin"));
        desired
            .claim_mappings
            .push(cm_env("developers", "developers", "developer"));
        desired.permission_grants.push(grant_env(
            "developer-write-supply-chain-security",
            &["developer"],
            "write",
            Some("supply-chain-security"),
        ));
        desired.permission_grants.push(grant_env(
            "developer-read-supply-chain-security",
            &["developer"],
            "read",
            Some("supply-chain-security"),
        ));
        put_lint_config(
            &mut desired,
            "rbac-lint",
            &["developer"],
            RuleOverridesSpec::default(),
        );
        desired.service_accounts.push(service_account_env_for_apply(
            "glci-supply-chain-security",
            &["supply-chain-security"],
            Some("gitlab-kdp"),
        ));

        h.uc.apply(desired, env_oidc())
            .await
            .expect("operator bundle must apply cleanly");

        let sa_user = h
            .users
            .find_by_username("sa:glci-supply-chain-security")
            .await
            .unwrap()
            .expect("SA backing user must exist after apply");
        let managed = h.grant_repo.managed_snapshot();
        // Operator's "no User-subject grant persisted" assertion fails
        // if the harness disagrees — this is the load-bearing assert.
        let sa_grant = managed
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::User(uid) if *uid == sa_user.id))
            .expect(
                "SA-derived `GrantSubject::User(backing_user_id)` grant for \
                 supply-chain-security must be in the managed partition",
            );
        assert_eq!(sa_grant.permission, Permission::Write);
        assert!(
            sa_grant.repository_id.is_some(),
            "SA-derived grant must be repo-scoped, not global"
        );
    }

    // -- ServiceAccount-subject standalone grants (ADR 0037 / spec §9) -----

    #[tokio::test]
    async fn apply_global_service_account_grant_resolves_to_backing_user() {
        // A declared SA + a standalone GLOBAL serviceAccount Read grant.
        // The grant must materialise as `GrantSubject::User(backing_user_id)`
        // with `repository_id: None` — the global authority an SA envelope
        // (always repo-scoped) cannot express.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "npm-public".into(),
            ..sample_repository_for_test("npm-public")
        });
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "maintainer-dev",
            &["npm-public"],
            None,
        ));
        desired.permission_grants.push(sa_grant_env(
            "maintainer-dev-global-read",
            "maintainer-dev",
            "read",
            None, // global
        ));

        h.uc.apply(desired, env_oidc())
            .await
            .expect("global serviceAccount grant must apply");

        let sa_user = h
            .users
            .find_by_username("sa:maintainer-dev")
            .await
            .unwrap()
            .expect("SA backing user must exist");
        let managed = h.grant_repo.managed_snapshot();
        // The standalone GLOBAL grant resolves to User(backing) / None.
        let global = managed
            .iter()
            .find(|g| {
                matches!(&g.subject, GrantSubject::User(uid) if *uid == sa_user.id)
                    && g.repository_id.is_none()
                    && g.permission == Permission::Read
            })
            .expect("global User(backing_user_id) Read grant must be present");
        assert!(global.repository_id.is_none());
    }

    #[tokio::test]
    async fn apply_service_account_grant_reapply_is_idempotent_no_churn() {
        // THE diff-idempotence assertion. Apply the SAME config (SA +
        // standalone global serviceAccount Read grant) twice; the second
        // apply must produce ZERO add/remove churn in the managed grant
        // partition — the SA-name resolves to the same backing_user_id and
        // the resolved User(uuid) row diffs identically across applies.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "npm-public".into(),
            ..sample_repository_for_test("npm-public")
        });
        let build = || {
            let mut d = DesiredState::default();
            d.service_accounts.push(service_account_env_for_apply(
                "maintainer-dev",
                &["npm-public"],
                None,
            ));
            d.permission_grants.push(sa_grant_env(
                "maintainer-dev-global-read",
                "maintainer-dev",
                "read",
                None,
            ));
            d
        };

        h.uc.apply(build(), env_oidc()).await.unwrap();
        // Managed set after first apply: the SA-role-derived repo-scoped
        // grant + the standalone global grant = 2.
        let first = h.grant_repo.managed_snapshot();
        let first_count = first.len();
        assert_eq!(
            first_count, 2,
            "SA role-derived repo grant + standalone global grant = 2"
        );
        // Capture surrogate ids so we can prove they carry through.
        let mut first_ids: Vec<Uuid> = first.iter().map(|g| g.id).collect();
        first_ids.sort();

        h.uc.apply(build(), env_oidc()).await.unwrap();
        let second = h.grant_repo.managed_snapshot();
        assert_eq!(
            second.len(),
            first_count,
            "re-applying the identical config must not change the managed grant count"
        );
        let mut second_ids: Vec<Uuid> = second.iter().map(|g| g.id).collect();
        second_ids.sort();
        assert_eq!(
            first_ids, second_ids,
            "surrogate grant ids must carry through a no-op re-apply (no delete+recreate churn)"
        );
        // Exactly one save_managed call per apply (two total).
        assert_eq!(h.grant_repo.save_managed_call_count(), 2);
    }

    #[tokio::test]
    async fn apply_repo_scoped_service_account_curate_grant_resolves() {
        // Repo-scoped `curate` — non-read/write authority an SA role
        // bundle cannot grant. Resolves to User(backing) scoped to the repo.
        let h = build_harness();
        seed_developer_role(&h);
        // Declare the repo in the bundle (let the apply create it) so the
        // grant's `spec.repository` cross-spec reference resolves; a
        // pre-seeded harness row would collide with the managed upsert.
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("oci-prod", "hosted"));
        desired.service_accounts.push(service_account_env_for_apply(
            "maintainer-curator",
            &["oci-prod"],
            None,
        ));
        desired.permission_grants.push(sa_grant_env(
            "curator-grant",
            "maintainer-curator",
            "curate",
            Some("oci-prod"),
        ));

        h.uc.apply(desired, env_oidc())
            .await
            .expect("repo-scoped serviceAccount curate grant must apply");

        let sa_user = h
            .users
            .find_by_username("sa:maintainer-curator")
            .await
            .unwrap()
            .expect("SA backing user must exist");
        let managed = h.grant_repo.managed_snapshot();
        let curate = managed
            .iter()
            .find(|g| {
                matches!(&g.subject, GrantSubject::User(uid) if *uid == sa_user.id)
                    && g.permission == Permission::Curate
            })
            .expect("User(backing_user_id) Curate grant must be present");
        assert!(
            curate.repository_id.is_some(),
            "curate grant is repo-scoped"
        );
    }

    #[tokio::test]
    async fn apply_global_service_account_grant_passes_secure_default_linter() {
        // The audited operator path: a GLOBAL serviceAccount grant under
        // the SECURE-BY-DEFAULT linter (no downgrade). It must NOT trip
        // the `direct-user-grant-without-justification` reject arm — the
        // resolved backing user is SA-owned (provenance-justified), so the
        // linter exempts it exactly like an SA role-derived grant.
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        h.repos.insert(Repository {
            key: "npm-public".into(),
            ..sample_repository_for_test("npm-public")
        });
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "maintainer-dev",
            &["npm-public"],
            None,
        ));
        desired.permission_grants.push(sa_grant_env(
            "maintainer-dev-global-read",
            "maintainer-dev",
            "read",
            None,
        ));

        h.uc.apply(desired, env_oidc())
            .await
            .expect("a global serviceAccount grant must clear the SECURE-DEFAULT linter");
    }

    #[tokio::test]
    async fn apply_service_account_grant_naming_missing_sa_fails_validation() {
        // A serviceAccount-subject grant naming an undeclared SA is a
        // cross-spec DanglingReference — apply must fail before any write.
        let h = build_harness();
        h.repos.insert(Repository {
            key: "npm-public".into(),
            ..sample_repository_for_test("npm-public")
        });
        let mut desired = DesiredState::default();
        desired
            .permission_grants
            .push(sa_grant_env("dangling", "ghost-sa", "read", None));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("ghost-sa"),
            "validation error must name the missing ServiceAccount: {rendered}"
        );
        // No grant was written.
        assert_eq!(h.grant_repo.save_managed_call_count(), 0);
    }

    #[tokio::test]
    async fn apply_service_account_with_unknown_issuer_fails_validation() {
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pypi-pusher",
            &["pypi-internal"],
            Some("ghost-issuer"), // not declared!
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("ghost-issuer"),
            "FK error must name the missing issuer: {rendered}"
        );
        assert!(
            rendered.contains("OidcIssuer") || rendered.contains("oidc"),
            "FK error must mention OidcIssuer: {rendered}"
        );
    }

    #[tokio::test]
    async fn apply_service_account_with_declared_issuer_in_same_pass_succeeds() {
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        // OidcIssuer declared in the same apply — the FK check accepts
        // either snapshot or desired, with desired winning.
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pypi-pusher",
            &["pypi-internal"],
            Some("github-actions"),
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 2, "issuer + SA both created");
    }

    // -- apply-time under-constrained-FI
    //    warning is WIRED into the production apply path ------------------
    //
    // Historically `detect_under_constrained_federated_identities`
    // was dead code (only `#[test]` callers in `hort-config`); commit
    // `37ece7da` falsely claimed a boot caller emitted the `warn!`. These
    // tests prove `ApplyConfigUseCase::apply` now actually emits one
    // structured `warn!` per under-constrained FI — and does NOT for a
    // well-constrained one — using the established `set_default` tracing-
    // capture pattern (mirrors `quarantine_use_case.rs`'s audit-log
    // assertions and the dependency-rule note on `hort-config`: the pure
    // detector returns findings, this caller logs them).

    #[derive(Clone, Default)]
    struct F7CapturingLayer {
        records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for F7CapturingLayer
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
            let mut visitor = F7MessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }
    }

    #[derive(Default)]
    struct F7MessageVisitor {
        combined: String,
    }
    impl tracing::field::Visit for F7MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    static F7_TRACING_TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// A well-constrained FI: repository + a discriminating
    /// `environment` claim ⇒ the detector must stay silent.
    fn service_account_env_well_constrained(
        sa_name: &str,
        repos: &[&str],
        issuer: &str,
    ) -> Envelope<ServiceAccountSpec> {
        let mut claims = BTreeMap::new();
        claims.insert("repository".into(), "my-org/my-repo".into());
        claims.insert("environment".into(), "production".into());
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ServiceAccount,
            metadata: Metadata {
                name: sa_name.into(),
            },
            spec: ServiceAccountSpec {
                role: "developer".into(),
                repositories: repos.iter().map(|s| (*s).into()).collect(),
                federated_identities: vec![FederatedIdentitySpec {
                    issuer: issuer.into(),
                    claims,
                }],
                fallback_rotation: None,
            },
        }
    }

    // Synchronous `#[test]` driving the async `apply` via a
    // current-thread runtime's `block_on` — mirrors
    // `quarantine_use_case.rs`'s `admin_release_success_log_carries_user_id`
    // shape. A `#[tokio::test]` would hold the serialization
    // `MutexGuard` across the `.await` (clippy `await_holding_lock`);
    // `block_on` keeps the guard on the synchronous stack so it is
    // never held *across* a suspension point.

    #[test]
    fn apply_emits_warn_for_under_constrained_federated_identity() {
        use tracing_subscriber::layer::SubscriberExt;

        let _serial = F7_TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let layer = F7CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let h = build_harness();
            seed_developer_role(&h);
            h.repos.insert(Repository {
                key: "pypi-internal".into(),
                ..sample_repository_for_test("pypi-internal")
            });
            let mut desired = DesiredState::default();
            desired
                .oidc_issuers
                .push(oidc_issuer_env_for_apply("github-actions"));
            // `service_account_env_for_apply(..., Some(_))` builds an FI
            // with ONLY a `repository` claim — the under-constrained shape
            // (no ref/environment/workflow/aud discriminator).
            desired.service_accounts.push(service_account_env_for_apply(
                "ci-loose",
                &["pypi-internal"],
                Some("github-actions"),
            ));

            // Apply MUST still succeed — warning, not ValidationError.
            let report = h.uc.apply(desired, env_oidc()).await.unwrap();
            assert_eq!(
                report.created, 2,
                "issuer + SA both created; apply succeeds"
            );
        });

        let records = captured.lock().unwrap();
        let warn = records
            .iter()
            .find(|(lvl, msg)| {
                *lvl == tracing::Level::WARN
                    && msg.contains("under-constrained federatedIdentities")
            })
            .expect(
                "ApplyConfigUseCase::apply must emit a WARN for an under-constrained FI \
                 (detector was previously dead code before this wiring)",
            );
        let msg = &warn.1;
        assert!(
            msg.contains("ci-loose"),
            "warn must carry the SA name (operator-authored identifier): {msg}"
        );
        assert!(
            msg.contains("github-actions"),
            "warn must carry the issuer reference: {msg}"
        );
        assert!(
            msg.contains("discriminating"),
            "warn must forward the detector's remediation message: {msg}"
        );
    }

    #[test]
    fn apply_does_not_warn_for_well_constrained_federated_identity() {
        use tracing_subscriber::layer::SubscriberExt;

        let _serial = F7_TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let layer = F7CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let h = build_harness();
            seed_developer_role(&h);
            h.repos.insert(Repository {
                key: "pypi-internal".into(),
                ..sample_repository_for_test("pypi-internal")
            });
            let mut desired = DesiredState::default();
            desired
                .oidc_issuers
                .push(oidc_issuer_env_for_apply("github-actions"));
            desired
                .service_accounts
                .push(service_account_env_well_constrained(
                    "ci-tight",
                    &["pypi-internal"],
                    "github-actions",
                ));

            let report = h.uc.apply(desired, env_oidc()).await.unwrap();
            assert_eq!(report.created, 2, "issuer + SA both created");
        });

        let records = captured.lock().unwrap();
        assert!(
            !records
                .iter()
                .any(|(_, msg)| msg.contains("under-constrained federatedIdentities")),
            "a repository+environment FI is well-constrained — no under-constrained warning expected"
        );
    }

    #[tokio::test]
    async fn apply_service_account_referencing_about_to_be_deleted_issuer_fails_validation() {
        // Regression guard. The FK validator
        // must consider only the *post-apply* set of OidcIssuers, which is
        // exactly `desired.oidc_issuers`. Issuers present in the snapshot
        // but absent from desired are being deleted by omission and must
        // NOT satisfy the FK for any ServiceAccount that still references
        // them — otherwise the apply would leave a dangling logical FK
        // (the `service_account_federated_identities` row points at an
        // issuer name that no longer exists, and every later federation
        // exchange against that SA returns `UnknownIssuer`).
        //
        // Test shape:
        //   snapshot: OidcIssuer `legacy-idp`, ServiceAccount `legacy-sa`
        //             federated to `legacy-idp` (seeded directly).
        //   desired:  ServiceAccount `legacy-sa` federated to `legacy-idp`
        //             (no OidcIssuer envelopes — `legacy-idp` is being
        //             deleted by omission).
        // Expected: apply fails with a validation error naming both the
        //           SA and the missing issuer.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        // Seed the snapshot: an OidcIssuer that the desired state will
        // delete by omission.
        let snapshot_issuer = OidcIssuer {
            id: Uuid::new_v4(),
            name: "legacy-idp".into(),
            issuer_url: "https://legacy-idp.example.com".into(),
            audiences: vec!["hort-server".into()],
            jwks_refresh_interval: std::time::Duration::from_secs(3600),
            allowed_algorithms: vec![JwtAlg::Rs256],
            require_jti: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        h.oidc_issuers.upsert(&snapshot_issuer).await.unwrap();
        // Build a desired with the SA still referencing `legacy-idp` but
        // NO OidcIssuer envelopes — the issuer is being deleted by
        // omission.
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "legacy-sa",
            &["pypi-internal"],
            Some("legacy-idp"),
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("legacy-sa"),
            "FK error must name the offending ServiceAccount: {rendered}"
        );
        assert!(
            rendered.contains("legacy-idp"),
            "FK error must name the missing OidcIssuer: {rendered}"
        );
    }

    #[tokio::test]
    async fn apply_service_account_delete_preserves_backing_user_row() {
        // Invariant: the backing user is shared infrastructure
        // — deleting the SA must NOT delete the user.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        let env = service_account_env_for_apply("ci-pypi-pusher", &["pypi-internal"], None);
        let mut desired = DesiredState::default();
        desired.service_accounts.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert!(h
            .users
            .find_by_username("sa:ci-pypi-pusher")
            .await
            .unwrap()
            .is_some());

        // Re-apply with no SA — delete sweep runs.
        // The PG sweep skips SA-owned grants (their digests are computed
        // from the snapshot SAs and excluded from the PG delete plan), so
        // `report.deleted` is exactly the SA row count. The SA-owned
        // permission grant is removed by `delete_service_account_grants`
        // and is NOT counted in `report.deleted` (the SA-sweep bumps
        // `report.deleted` once per SA, not once per grant).
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(
            report.deleted, 1,
            "SA-owned grants are deleted by \
             delete_service_account_grants, not by the PG sweep; \
             only the SA row contributes to report.deleted"
        );
        assert!(h.service_accounts.snapshot().is_empty());
        // The backing user row stays.
        assert!(
            h.users
                .find_by_username("sa:ci-pypi-pusher")
                .await
                .unwrap()
                .is_some(),
            "backing user row must persist across SA delete (shared infrastructure)"
        );
    }

    #[tokio::test]
    async fn apply_permission_grants_sweep_does_not_touch_sa_owned_grants() {
        // Regression guard for
        // the consolidated reconcile. `apply_permission_grants`
        // materialises envelope grants AND SA-owned
        // `GrantSubject::User(backing_user_id)` grants in a single
        // whole-partition `save_managed` call. Re-applying the SAME SA
        // with no `PermissionGrant` envelopes must NOT revoke the
        // SA-owned grants — the User-subject diff key
        // `(user_id, repository_id, permission)` keeps them in the
        // desired set across re-applies, so the managed set is stable
        // and no PermissionGrantRevoked is emitted for them.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        h.repos.insert(Repository {
            key: "npm-internal".into(),
            ..sample_repository_for_test("npm-internal")
        });

        // First apply: seed the SA + its two SA-owned permission grants.
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pusher",
            &["pypi-internal", "npm-internal"],
            None,
        ));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        // Two repos → two SA-owned User-subject grants.
        let managed_after_seed = h.grant_repo.managed_snapshot();
        assert_eq!(
            managed_after_seed.len(),
            2,
            "SA with two repos materialises two User-subject grants"
        );
        assert!(
            managed_after_seed
                .iter()
                .all(|g| matches!(g.subject, GrantSubject::User(_))),
            "SA-owned grants must be User-subject"
        );
        let revoked_after_seed = h
            .events
            .appended()
            .into_iter()
            .flat_map(|b| b.events)
            .filter(|e| matches!(e.event, DomainEvent::PermissionGrantRevoked(_)))
            .count();

        // Second apply: same SA, no PermissionGrant envelopes — this is
        // the scenario the prior agent reported as buggy. The PG sweep
        // would previously schedule the SA-owned grants for delete (their
        // digests carry `managed_by = GitOps`, no mirror envelope in
        // desired). The PG planner must short-circuit this by excluding
        // SA-owned digests from the PG delete plan.
        let mut desired_b = DesiredState::default();
        desired_b
            .service_accounts
            .push(service_account_env_for_apply(
                "ci-pusher",
                &["pypi-internal", "npm-internal"],
                None,
            ));
        h.uc.apply(desired_b, env_oidc()).await.unwrap();

        // The SA-owned grants survive the re-apply unchanged …
        let managed_after_reapply = h.grant_repo.managed_snapshot();
        assert_eq!(
            managed_after_reapply.len(),
            2,
            "SA-owned grants must persist across the re-apply"
        );
        // … and no PermissionGrantRevoked was emitted for them
        // (the consolidated reconcile keeps SA-owned
        // User-subject rows in the desired set, so the whole-partition
        // diff never marks them absent).
        let revoked_after_reapply = h
            .events
            .appended()
            .into_iter()
            .flat_map(|b| b.events)
            .filter(|e| matches!(e.event, DomainEvent::PermissionGrantRevoked(_)))
            .count();
        assert_eq!(
            revoked_after_reapply, revoked_after_seed,
            "re-applying the same SA must not revoke its own grants"
        );
    }

    /// Lightweight helper for these tests; the project's
    /// `sample_repository()` returns a generic-format repo, but here we
    /// need a controllable `key`.
    fn sample_repository_for_test(key: &str) -> Repository {
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

    // =======================================================================
    // apply_retention_policies (create / update / archive /
    // unchanged accounting + the security-scope apply-time warning + the
    // unwired-slot no-op).
    // =======================================================================
    mod retention_apply {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        use hort_config::desired::DesiredState;
        use hort_config::envelope::{ApiVersion, Envelope, Kind, Metadata};
        use hort_config::retention_policy::RetentionPolicySpec;
        use hort_domain::error::DomainResult;
        use hort_domain::events::{Actor, ApiActor, PersistedEvent, StreamCategory, StreamId};
        use hort_domain::ports::event_store::{
            AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
        };
        use hort_domain::ports::retention_policy_projection_repository::{
            RetentionPolicyProjectionRepository, RetentionPolicyRow,
        };
        use hort_domain::ports::BoxFuture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Registry;
        use uuid::Uuid;

        use crate::use_cases::apply_config_use_case::{ApplyConfigUseCase, RetentionApply};
        use crate::use_cases::retention_policy_use_case::RetentionPolicyUseCase;

        // -- tracing capture (the established repository_access pattern) --
        #[derive(Clone, Default)]
        struct CapLayer {
            records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
        }
        impl<S> tracing_subscriber::Layer<S> for CapLayer
        where
            S: tracing::Subscriber,
        {
            fn register_callsite(
                &self,
                _m: &'static tracing::Metadata<'static>,
            ) -> tracing::subscriber::Interest {
                tracing::subscriber::Interest::sometimes()
            }
            fn enabled(
                &self,
                _m: &tracing::Metadata<'_>,
                _c: tracing_subscriber::layer::Context<'_, S>,
            ) -> bool {
                true
            }
            fn on_event(
                &self,
                e: &tracing::Event<'_>,
                _c: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let mut v = MsgVisitor::default();
                e.record(&mut v);
                self.records
                    .lock()
                    .unwrap()
                    .push((*e.metadata().level(), v.s));
            }
        }
        #[derive(Default)]
        struct MsgVisitor {
            s: String,
        }
        impl tracing::field::Visit for MsgVisitor {
            fn record_debug(&mut self, f: &tracing::field::Field, val: &dyn std::fmt::Debug) {
                self.s.push_str(&format!("{}={:?} ", f.name(), val));
            }
            fn record_str(&mut self, f: &tracing::field::Field, val: &str) {
                self.s.push_str(&format!("{}={} ", f.name(), val));
            }
        }
        static TRACING_MUTEX: Mutex<()> = Mutex::new(());
        fn install_global() {
            use std::sync::OnceLock;
            static I: OnceLock<()> = OnceLock::new();
            I.get_or_init(|| {
                let _ = tracing::subscriber::set_global_default(
                    Registry::default().with(CapLayer::default()),
                );
            });
        }

        // -- minimal mocks (same shape as retention_policy_use_case_tests) --
        struct MockEvents;
        impl EventStore for MockEvents {
            fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
                let n = batch.events.len() as u64;
                Box::pin(async move {
                    Ok(AppendResult {
                        stream_position: n.saturating_sub(1),
                        global_positions: (0..n).collect(),
                    })
                })
            }
            fn read_stream(
                &self,
                _s: &StreamId,
                _f: ReadFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn read_category(
                &self,
                _c: StreamCategory,
                _f: SubscribeFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn delete_stream(&self, _s: StreamId) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unimplemented!() })
            }
            fn archive_stream(&self, _s: StreamId, _t: &str) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unimplemented!() })
            }
        }

        #[derive(Default)]
        struct MockProj {
            rows: Mutex<HashMap<Uuid, RetentionPolicyRow>>,
        }
        impl MockProj {
            fn active_count(&self) -> usize {
                self.rows
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|r| !r.archived)
                    .count()
            }
        }
        impl RetentionPolicyProjectionRepository for MockProj {
            fn list_active(
                &self,
            ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::retention::RetentionPolicy>>>
            {
                let v: Vec<_> = self
                    .rows
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|r| !r.archived)
                    .cloned()
                    .map(RetentionPolicyRow::into_policy)
                    .collect();
                Box::pin(async move { Ok(v) })
            }
            fn find_by_name(
                &self,
                name: &str,
            ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
                let f = self
                    .rows
                    .lock()
                    .unwrap()
                    .values()
                    .find(|r| r.name == name && !r.archived)
                    .cloned();
                Box::pin(async move { Ok(f) })
            }
            fn find_by_name_including_archived(
                &self,
                name: &str,
            ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
                let f = self
                    .rows
                    .lock()
                    .unwrap()
                    .values()
                    .find(|r| r.name == name)
                    .cloned();
                Box::pin(async move { Ok(f) })
            }
            fn list_active_rows(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicyRow>>> {
                let v: Vec<_> = self
                    .rows
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|r| !r.archived)
                    .cloned()
                    .collect();
                Box::pin(async move { Ok(v) })
            }
            fn upsert(&self, row: &RetentionPolicyRow) -> BoxFuture<'_, DomainResult<()>> {
                self.rows.lock().unwrap().insert(row.policy_id, row.clone());
                Box::pin(async { Ok(()) })
            }
        }

        fn rp_env(
            name: &str,
            predicate: serde_json::Value,
            scope: serde_json::Value,
        ) -> Envelope<RetentionPolicySpec> {
            Envelope {
                api_version: ApiVersion::V1Beta1,
                kind: Kind::RetentionPolicy,
                metadata: Metadata { name: name.into() },
                spec: RetentionPolicySpec { predicate, scope },
            }
        }

        fn make_uc(proj: Arc<MockProj>) -> ApplyConfigUseCase {
            let events = crate::event_store_publisher::wrap_for_test(Arc::new(MockEvents));
            let rp_uc = Arc::new(RetentionPolicyUseCase::new(events, proj.clone()));
            // Reuse the apply harness's full constructor via the
            // module-level `build_harness`, then override retention.
            super::build_harness()
                .uc
                .with_retention(RetentionApply::new(proj, rp_uc))
        }

        fn nil_actor() -> Actor {
            Actor::Api(ApiActor {
                user_id: Uuid::nil(),
            })
        }

        #[tokio::test]
        async fn create_then_unchanged_then_update_then_archive_accounting() {
            let proj = Arc::new(MockProj::default());
            let uc = make_uc(proj.clone());

            // 1. create
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "retain-30d",
                serde_json::json!({ "AgeExceeds": 2_592_000 }),
                serde_json::json!("AllRepos"),
            ));
            let r = uc.apply(d, super::env_oidc()).await.expect("apply create");
            assert_eq!(r.created, 1, "first apply creates");
            assert_eq!(proj.active_count(), 1);

            // 2. same spec → unchanged (no event)
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "retain-30d",
                serde_json::json!({ "AgeExceeds": 2_592_000 }),
                serde_json::json!("AllRepos"),
            ));
            let r = uc
                .apply(d, super::env_oidc())
                .await
                .expect("apply unchanged");
            assert_eq!(r.unchanged, 1, "same spec is unchanged");
            assert_eq!(r.created, 0);

            // 3. changed predicate → update
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "retain-30d",
                serde_json::json!({ "AgeExceeds": 5_184_000 }),
                serde_json::json!("AllRepos"),
            ));
            let r = uc.apply(d, super::env_oidc()).await.expect("apply update");
            assert_eq!(r.updated, 1, "changed predicate updates");

            // 4. absent from desired → archive
            let r = uc
                .apply(DesiredState::default(), super::env_oidc())
                .await
                .expect("apply archive");
            assert_eq!(r.deleted, 1, "absent policy archived");
            assert_eq!(proj.active_count(), 0);
        }

        /// A security-driven predicate whose scope does NOT exclude
        /// IngestSource(Direct) fires an apply-time `info!` (NOT an error —
        /// the policy still applies). A proxied-scoped security predicate
        /// does NOT warn.
        #[test]
        fn inv8_security_predicate_non_direct_excluding_scope_warns_but_applies() {
            install_global();
            let _g = TRACING_MUTEX
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let layer = CapLayer::default();
            let captured = layer.records.clone();
            let _sub = tracing::subscriber::set_default(Registry::default().with(layer));
            tracing::callsite::rebuild_interest_cache();

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            // Security predicate (HasFixAvailable) + AllRepos scope
            // (does NOT exclude Direct) → must warn AND still create.
            let proj = Arc::new(MockProj::default());
            let uc = make_uc(proj.clone());
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "vuln-allrepos",
                serde_json::json!("HasFixAvailable"),
                serde_json::json!("AllRepos"),
            ));
            let r = rt.block_on(uc.apply(d, super::env_oidc())).expect("apply");
            assert_eq!(
                r.created, 1,
                "the policy still applies (advisory, not reject)"
            );

            let recs = captured.lock().unwrap();
            assert!(
                recs.iter().any(|(lvl, msg)| *lvl == tracing::Level::INFO
                    && msg.contains("does not exclude IngestSource(Direct)")
                    && msg.contains("vuln-allrepos")),
                "info! must fire for a security predicate with a \
                 non-direct-excluding scope; captured: {recs:?}"
            );
            drop(recs);

            // Proxied scope EXCLUDES direct → must NOT warn.
            let proj2 = Arc::new(MockProj::default());
            let uc2 = make_uc(proj2);
            captured.lock().unwrap().clear();
            let mut d2 = DesiredState::default();
            d2.retention_policies.push(rp_env(
                "vuln-proxied",
                serde_json::json!("HasFixAvailable"),
                serde_json::json!({ "IngestSource": "Proxied" }),
            ));
            rt.block_on(uc2.apply(d2, super::env_oidc()))
                .expect("apply");
            let recs2 = captured.lock().unwrap();
            assert!(
                !recs2
                    .iter()
                    .any(|(_, msg)| msg.contains("does not exclude IngestSource(Direct)")),
                "a proxied-scoped (direct-excluding) security predicate must \
                 NOT fire the warning; captured: {recs2:?}"
            );
        }

        /// Unwired retention slot: a `RetentionPolicy` envelope present
        /// but `with_retention` not called → logged no-op, NOT a silent
        /// drop and NOT an apply failure.
        #[tokio::test]
        async fn unwired_slot_is_logged_noop_not_failure() {
            // build_harness() does NOT call with_retention.
            let h = super::build_harness();
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "orphan",
                serde_json::json!({ "AgeExceeds": 60 }),
                serde_json::json!("AllRepos"),
            ));
            let r =
                h.uc.apply(d, super::env_oidc())
                    .await
                    .expect("apply must NOT fail when retention slot is unwired");
            assert_eq!(r.created, 0, "unwired slot creates nothing");
        }

        /// The actor threaded into the retention lifecycle append is
        /// the gitops actor (apply is gitops-authored, exactly like
        /// ScanPolicy) — NOT the RetentionScheduler actor (that is the
        /// runtime Evaluated breadcrumb's actor).
        #[tokio::test]
        async fn create_uses_gitops_actor_not_retention_scheduler() {
            // Captured by routing through a spy event store.
            struct SpyEvents {
                seen: Mutex<Vec<Actor>>,
            }
            impl EventStore for SpyEvents {
                fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
                    self.seen.lock().unwrap().push(batch.actor.clone());
                    let n = batch.events.len() as u64;
                    Box::pin(async move {
                        Ok(AppendResult {
                            stream_position: n.saturating_sub(1),
                            global_positions: (0..n).collect(),
                        })
                    })
                }
                fn read_stream(
                    &self,
                    _s: &StreamId,
                    _f: ReadFrom,
                    _m: u64,
                ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                    Box::pin(async { Ok(Vec::new()) })
                }
                fn read_category(
                    &self,
                    _c: StreamCategory,
                    _f: SubscribeFrom,
                    _m: u64,
                ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                    Box::pin(async { Ok(Vec::new()) })
                }
                fn delete_stream(&self, _s: StreamId) -> BoxFuture<'_, DomainResult<()>> {
                    Box::pin(async { unimplemented!() })
                }
                fn archive_stream(
                    &self,
                    _s: StreamId,
                    _t: &str,
                ) -> BoxFuture<'_, DomainResult<()>> {
                    Box::pin(async { unimplemented!() })
                }
            }
            let spy = Arc::new(SpyEvents {
                seen: Mutex::new(Vec::new()),
            });
            let proj = Arc::new(MockProj::default());
            let rp_uc = Arc::new(RetentionPolicyUseCase::new(
                crate::event_store_publisher::wrap_for_test(spy.clone()),
                proj.clone(),
            ));
            let uc = super::build_harness()
                .uc
                .with_retention(RetentionApply::new(proj, rp_uc));
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "g",
                serde_json::json!({ "AgeExceeds": 60 }),
                serde_json::json!("AllRepos"),
            ));
            let _ = nil_actor(); // keep helper referenced
            uc.apply(d, super::env_oidc()).await.expect("apply");
            let seen = spy.seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert!(
                matches!(seen[0], Actor::GitOps(_)),
                "retention lifecycle append must use the gitops actor, got {:?}",
                seen[0]
            );
        }
    }
}
