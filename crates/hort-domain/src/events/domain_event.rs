use serde::{Deserialize, Serialize};

use crate::error::DomainResult;

use super::api_token_events::{
    ApiTokenIssuanceDenied, ApiTokenIssued, ApiTokenRevoked, ApiTokenUsed,
};
use super::artifact_events::{
    ApprovalDecided, ApprovalRequested, ArtifactBecameVulnerable, ArtifactCorrupted,
    ArtifactExpired, ArtifactIngested, ArtifactPromoted, ArtifactPurged, ArtifactQuarantined,
    ArtifactReEvaluated, ArtifactRejected, ArtifactReleased, ChecksumMismatch, ChecksumVerified,
    PolicyEvaluated, PromotionRejected, PromotionRequested, ProvenanceRejected, ProvenanceVerified,
    ScanCompleted, ScanIndeterminate, ScanRequested,
};
use super::artifact_group_events::{
    ArtifactGroupInitiated, ArtifactGroupMemberAdded, ArtifactGroupMemberRemoved,
    ArtifactGroupPrimaryRoleAssigned,
};
use super::auth_events::{AdminStatusChanged, AuthenticationAttempted, OidcKeyRotated};
use super::authorization_events::{
    ClaimMappingApplied, ClaimMappingRevoked, PermissionGrantApplied, PermissionGrantRevoked,
    RepositoryUpstreamMappingChanged, TaskFailed, TaskInvoked,
};
use super::cas_scrub_events::CasIntegrityMismatch;
use super::curation_events::CurationApplied;
use super::download_events::ArtifactDownloaded;
use super::oidc_issuer_events::{OidcIssuerCreated, OidcIssuerDeleted, OidcIssuerUpdated};
use super::policy_events::{
    ExclusionAdded, ExclusionRemoved, PolicyArchived, PolicyCreated, PolicyReactivated,
    PolicyUpdated,
};
use super::ref_events::{RefMoved, RefRetired};
use super::retention_events::StreamSealed;
// The `RetentionPolicyEvent` aggregate
// lifecycle enum (a sibling `crate::retention` module, no import
// cycle: `retention` and `events` are both top-level `pub mod`s in
// `hort-domain`) is bridged into `DomainEvent` via the
// `RetentionPolicyChanged` wrapper (Shape A) rather than duplicating
// the retention payload types.
use super::service_account_events::{
    ServiceAccountCreated, ServiceAccountDeleted, ServiceAccountTokenRotated, ServiceAccountUpdated,
};
use super::subscription_events::{
    SubscriptionCreated, SubscriptionCreationDenied, SubscriptionDeleted, SubscriptionDisabled,
    SubscriptionPaused, SubscriptionResumed, SubscriptionUpdated,
};
use crate::retention::RetentionPolicyEvent;

/// All domain events in the system.
///
/// Artifact lifecycle events and policy lifecycle events share this enum
/// so that a single `EventPort` handles all streams uniformly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DomainEvent {
    // -- Artifact lifecycle --
    ArtifactIngested(ArtifactIngested),
    ChecksumVerified(ChecksumVerified),
    ChecksumMismatch(ChecksumMismatch),
    ArtifactQuarantined(ArtifactQuarantined),
    ScanRequested(ScanRequested),
    ScanCompleted(ScanCompleted),
    /// Emitted alongside `ScanCompleted` when
    /// the new findings contain CVEs absent from the most recent prior
    /// scan. See `ArtifactBecameVulnerable` and
    /// `docs/architecture/explanation/scanning-pipeline.md`.
    ArtifactBecameVulnerable(ArtifactBecameVulnerable),
    ArtifactReleased(ArtifactReleased),
    ArtifactRejected(ArtifactRejected),
    /// Terminal scan failure (every configured
    /// backend errored and the job exhausted its retry budget). Drives
    /// the `QuarantineStatus -> ScanIndeterminate` fail-closed
    /// transition, appended on the artifact stream alongside the status
    /// change via `ArtifactLifecyclePort::commit_transition_with_score`.
    /// Distinct from `ScanCompleted` (the scanner decided); fail-closed
    /// per ADR 0007. Additive on this `#[non_exhaustive]` enum.
    ScanIndeterminate(ScanIndeterminate),
    /// A supply-chain provenance
    /// attestation (ADR 0027) was verified against the policy's allowed signer
    /// identities. Success record only; like `ScanCompleted(clean)` it
    /// does NOT release the artifact early. Under `Required` mode the
    /// release sweep reads its existence to clear the provenance gate.
    /// Lands on `StreamCategory::Artifact`. Additive on this
    /// `#[non_exhaustive]` enum.
    ProvenanceVerified(ProvenanceVerified),
    /// A provenance check (ADR 0027) rejected the
    /// artifact (forged/untrusted signature, malformed bundle, or
    /// unsigned-under-`Required`). Drives `QuarantineStatus -> Rejected`,
    /// terminal under the release surfaces (like `ScanCompleted(findings)`).
    /// Lands on `StreamCategory::Artifact`. Additive on this
    /// `#[non_exhaustive]` enum.
    ProvenanceRejected(ProvenanceRejected),
    /// Post-exclusion-add re-evaluation of a
    /// previously rejected artifact. Companion to the
    /// `ArtifactQuarantined` / `ArtifactReleased { PolicyReEvaluation }`
    /// transition event appended on the same stream batch.
    ArtifactReEvaluated(ArtifactReEvaluated),
    PromotionRequested(PromotionRequested),
    PolicyEvaluated(PolicyEvaluated),
    ApprovalRequested(ApprovalRequested),
    ApprovalDecided(ApprovalDecided),
    ArtifactPromoted(ArtifactPromoted),
    PromotionRejected(PromotionRejected),
    /// A retention policy fired and
    /// this artifact is eligible for purge. Recorded on the artifact
    /// stream **before** any storage deletion so the policy decision is
    /// auditable independently of purge success. Additive on this
    /// `#[non_exhaustive]` enum.
    ArtifactExpired(ArtifactExpired),
    /// The storage delete completed
    /// (or the blob was confirmed already absent). Terminal event for an
    /// `ArtifactExpired` work item; `refs_remaining` carries the
    /// post-decrement cross-`kind` refcount. Idempotent (ADR 0028).
    /// Additive on this `#[non_exhaustive]` enum.
    ArtifactPurged(ArtifactPurged),

    // -- Download audit --
    /// Opt-in per-`(repository, UTC-date)` download-audit fact —
    /// appended by `ArtifactUseCase::download` **only when the served
    /// artifact's `Repository.download_audit_enabled` is true**. Lands
    /// on a dedicated `StreamCategory::DownloadAudit` stream (NOT the
    /// artifact aggregate / lifecycle stream), `ExpectedVersion::Any`.
    /// The subject rides the payload `DownloadActor` (decision A —
    /// mirrors `AuthenticationAttempted`); the batch recorder is
    /// `system_actor()`. Subscription-excluded
    /// (`HIGH_VOLUME_EVENT_TYPES`); the per-format download *count*
    /// stays Prometheus-only (`hort_download_total`). Additive on this
    /// `#[non_exhaustive]` enum.
    ArtifactDownloaded(ArtifactDownloaded),

    // -- Policy lifecycle --
    PolicyCreated(PolicyCreated),
    PolicyUpdated(PolicyUpdated),
    ExclusionAdded(ExclusionAdded),
    ExclusionRemoved(ExclusionRemoved),
    PolicyArchived(PolicyArchived),
    /// Gitops apply re-declared a YAML
    /// for a policy whose projection was archived. Reactivation flips
    /// `archived = false` on the existing row, preserving the
    /// `policy_id` and event-stream history. Without this event the
    /// apply would take the create path and collide with the archived
    /// row's UNIQUE-name constraint.
    PolicyReactivated(PolicyReactivated),

    // -- CAS integrity (ADR 0003) --
    CasIntegrityMismatch(CasIntegrityMismatch),
    /// Emitted when the CAS scrubber
    /// detects a content-hash divergence AND the operator opted into
    /// `HORT_CAS_SCRUB_ACTION_ON_MISMATCH=tombstone`. Companion to
    /// `CasIntegrityMismatch`: the mismatch event is the audit fact;
    /// this event is the artifact-level state transition (to
    /// `quarantine_status = 'rejected'`). Lands on the artifact's own
    /// stream alongside the persisted state change via
    /// `ArtifactLifecyclePort::commit_transition`.
    ArtifactCorrupted(ArtifactCorrupted),

    // -- Mutable-ref lifecycle --
    RefMoved(RefMoved),
    RefRetired(RefRetired),

    // -- Artifact-group lifecycle --
    ArtifactGroupInitiated(ArtifactGroupInitiated),
    ArtifactGroupMemberAdded(ArtifactGroupMemberAdded),
    ArtifactGroupMemberRemoved(ArtifactGroupMemberRemoved),
    ArtifactGroupPrimaryRoleAssigned(ArtifactGroupPrimaryRoleAssigned),

    // -- Curation decisions --
    CurationApplied(CurationApplied),

    // -- Authentication attempts --
    AuthenticationAttempted(AuthenticationAttempted),

    // -- OIDC JWKS key rotation --
    /// Emitted by
    /// `hort-adapters-oidc::OidcProvider` from the slow-path
    /// `resolve_jwk` after `JwksCache::replace` actually changes the
    /// cached kid set. Lands on the per-UTC-date auth-attempts stream
    /// alongside `AuthenticationAttempted` (smallest blast radius —
    /// see the `OidcKeyRotated` doc comment for the rationale).
    OidcKeyRotated(OidcKeyRotated),

    // -- Persisted-admin-bit transition audit --
    /// Emitted by `hort-app::use_cases::authenticate_use_case` when the
    /// login-path recompute+persist site flips an **existing** user
    /// row's `is_admin` bit. The persistence mechanism itself is the
    /// intended design (ADR 0012) — this event is
    /// observability only: it makes a spurious flip (transient IdP
    /// outage / empty-groups response) auditable. Lands on the per-user
    /// stream (`StreamId::user(user_id)`); see the `AdminStatusChanged`
    /// doc comment for the stream-choice rationale.
    AdminStatusChanged(AdminStatusChanged),

    // -- Authorization-model audit (claim-based RBAC, ADR 0012) --
    /// An IdP-group → registry-claim mapping was
    /// created or updated by gitops apply. Lives on the
    /// global `StreamCategory::Authorization` stream.
    ClaimMappingApplied(ClaimMappingApplied),
    /// A gitops-managed claim mapping was removed.
    ClaimMappingRevoked(ClaimMappingRevoked),

    // -- Authorization-model audit, repo-scoped --
    /// A permission grant was applied; the payload carries a sum-typed
    /// `GrantSubjectRecord` (ADR 0012).
    PermissionGrantApplied(PermissionGrantApplied),
    PermissionGrantRevoked(PermissionGrantRevoked),
    RepositoryUpstreamMappingChanged(RepositoryUpstreamMappingChanged),

    // -- Native API token audit --
    /// Successful PAT or service-account issuance — token-owner stream.
    ApiTokenIssued(ApiTokenIssued),
    /// Successful PAT or service-account revocation — token-owner stream.
    ApiTokenRevoked(ApiTokenRevoked),
    /// Refused issuance — requesting-actor stream. Records the four
    /// edge-case rejections (cap-exceeds-authority,
    /// service-account-self-mint, admin-token-disallowed,
    /// unbounded-svc-token-disallowed) plus the schema-level rejects
    /// (invalid_repository_set, admin-token-exceeds-30-days,
    /// not-service-account).
    ApiTokenIssuanceDenied(ApiTokenIssuanceDenied),
    /// Throttled per-`(token_id, UTC-date)` token-use audit fact.
    /// Appended by
    /// `PatValidationUseCase::validate_pat` on the success path only,
    /// to a dedicated [`super::StreamCategory::TokenUse`] stream (NOT
    /// the token-owner's `User` lifecycle stream), `ExpectedVersion::Any`.
    /// Throttled to ≤ 1 append per hour per `token_id`; subscription-
    /// excluded (`HIGH_VOLUME_EVENT_TYPES`). Additive on this
    /// `#[non_exhaustive]` enum.
    ApiTokenUsed(ApiTokenUsed),

    // -- Admin-task invocation audit --
    /// An admin-task enqueue was accepted. Lands on
    /// `StreamCategory::Authorization` (the single global authz stream).
    TaskInvoked(TaskInvoked),
    /// An admin-task enqueue failed after the RBAC gate (e.g. DB error).
    /// Lands on `StreamCategory::Authorization`.
    TaskFailed(TaskFailed),

    // -- OIDC issuer lifecycle (ADR 0018) --
    /// `kind: OidcIssuer` envelope minted a new `oidc_issuers` row.
    OidcIssuerCreated(OidcIssuerCreated),
    /// Existing `oidc_issuers` row was updated by the apply pass.
    OidcIssuerUpdated(OidcIssuerUpdated),
    /// `kind: OidcIssuer` envelope removed; `oidc_issuers` row deleted.
    OidcIssuerDeleted(OidcIssuerDeleted),

    // -- Service-account lifecycle (ADR 0018) --
    /// `kind: ServiceAccount` envelope minted a new `service_accounts` row.
    ServiceAccountCreated(ServiceAccountCreated),
    /// Existing `service_accounts` row was updated by the apply pass.
    ServiceAccountUpdated(ServiceAccountUpdated),
    /// `kind: ServiceAccount` envelope removed; `service_accounts` row deleted.
    ServiceAccountDeleted(ServiceAccountDeleted),
    /// Fallback PAT rotation reconciler minted a new SA token and
    /// wrote it to the declared target k8s Secret. Lands
    /// on the backing-user's stream alongside the correlated
    /// `ApiTokenIssued`.
    ServiceAccountTokenRotated(ServiceAccountTokenRotated),

    // -- Subscription lifecycle --
    /// Successful subscription creation — owner's user stream.
    SubscriptionCreated(SubscriptionCreated),
    /// Refused subscription creation — requesting actor's user stream.
    SubscriptionCreationDenied(SubscriptionCreationDenied),
    /// Successful `PATCH /api/v1/subscriptions/:id` — owner's user stream.
    SubscriptionUpdated(SubscriptionUpdated),
    /// Subscription paused (owner or admin) — owner's user stream.
    SubscriptionPaused(SubscriptionPaused),
    /// Paused subscription resumed (owner or admin) — owner's user stream.
    SubscriptionResumed(SubscriptionResumed),
    /// Subscription deleted (owner or admin) — owner's user stream.
    SubscriptionDeleted(SubscriptionDeleted),
    /// Dispatcher (or admin action) transitioned the subscription to
    /// `Disabled` — owner's user stream. No silent muting.
    SubscriptionDisabled(SubscriptionDisabled),

    // -- Event-store retention sealing --
    /// Tamper-evident retention tombstone. Appended (through the normal
    /// chained append path, to the never-deleted audit-meta stream
    /// `admin-eventstore-retention`) immediately before the retention
    /// path's `delete_stream` / `archive_stream` removes a whole terminal
    /// stream. Carries the deleted stream's chain head so an absent
    /// stream with a matching anchored `StreamSealed` is a verifier
    /// `SealedGap`, not a `Broken` chain.
    ///
    /// **Defined in `retention_events`; emitted only by the
    /// eventstore-retention path** — there
    /// is no emitter in the domain layer. The enum is
    /// `#[non_exhaustive]`, so this is
    /// an additive change: no existing match arm shape changes.
    StreamSealed(StreamSealed),

    // -- Retention-policy lifecycle --
    /// Event-sourced retention-policy lifecycle. A
    /// **single wrapper** carrying the existing
    /// [`RetentionPolicyEvent`] (`Created` / `Updated` / `Archived` /
    /// `Evaluated`) verbatim — the wrapper does not duplicate the
    /// inner payloads.
    /// Lands on the dedicated [`super::StreamCategory::RetentionPolicy`]
    /// stream ([`super::StreamId::retention_policy`]). `event_type()`
    /// discriminates the inner variant
    /// (`"RetentionPolicyCreated"` / `…Updated` / `…Archived` /
    /// `…Evaluated`); `validate()` delegates to
    /// [`RetentionPolicyEvent::validate`]. The projection-load adapter
    /// unwraps these rows and folds them through the pure
    /// `RetentionPolicy::project`. Appended by `RetentionPolicyUseCase`
    /// (gitops-authored, `GitOpsActor`); the `Evaluated` breadcrumb is
    /// appended by `RetentionEvaluateHandler` (`RetentionScheduler`
    /// actor). Additive on this `#[non_exhaustive]` enum.
    RetentionPolicyChanged(RetentionPolicyEvent),
}

impl DomainEvent {
    /// Returns the event type name for serialisation and logging.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::ArtifactIngested(_) => "ArtifactIngested",
            Self::ChecksumVerified(_) => "ChecksumVerified",
            Self::ChecksumMismatch(_) => "ChecksumMismatch",
            Self::ArtifactQuarantined(_) => "ArtifactQuarantined",
            Self::ScanRequested(_) => "ScanRequested",
            Self::ScanCompleted(_) => "ScanCompleted",
            Self::ArtifactBecameVulnerable(_) => "ArtifactBecameVulnerable",
            Self::ArtifactReleased(_) => "ArtifactReleased",
            Self::ArtifactRejected(_) => "ArtifactRejected",
            Self::ScanIndeterminate(_) => "ScanIndeterminate",
            Self::ProvenanceVerified(_) => "ProvenanceVerified",
            Self::ProvenanceRejected(_) => "ProvenanceRejected",
            Self::ArtifactReEvaluated(_) => "ArtifactReEvaluated",
            Self::PromotionRequested(_) => "PromotionRequested",
            Self::PolicyEvaluated(_) => "PolicyEvaluated",
            Self::ApprovalRequested(_) => "ApprovalRequested",
            Self::ApprovalDecided(_) => "ApprovalDecided",
            Self::ArtifactPromoted(_) => "ArtifactPromoted",
            Self::PromotionRejected(_) => "PromotionRejected",
            Self::ArtifactExpired(_) => "ArtifactExpired",
            Self::ArtifactPurged(_) => "ArtifactPurged",
            Self::ArtifactDownloaded(_) => "ArtifactDownloaded",
            Self::PolicyCreated(_) => "PolicyCreated",
            Self::PolicyUpdated(_) => "PolicyUpdated",
            Self::ExclusionAdded(_) => "ExclusionAdded",
            Self::ExclusionRemoved(_) => "ExclusionRemoved",
            Self::PolicyArchived(_) => "PolicyArchived",
            Self::PolicyReactivated(_) => "PolicyReactivated",
            Self::CasIntegrityMismatch(_) => "CasIntegrityMismatch",
            Self::ArtifactCorrupted(_) => "ArtifactCorrupted",
            Self::RefMoved(_) => "RefMoved",
            Self::RefRetired(_) => "RefRetired",
            Self::ArtifactGroupInitiated(_) => "ArtifactGroupInitiated",
            Self::ArtifactGroupMemberAdded(_) => "ArtifactGroupMemberAdded",
            Self::ArtifactGroupMemberRemoved(_) => "ArtifactGroupMemberRemoved",
            Self::ArtifactGroupPrimaryRoleAssigned(_) => "ArtifactGroupPrimaryRoleAssigned",
            Self::CurationApplied(_) => "CurationApplied",
            Self::AuthenticationAttempted(_) => "AuthenticationAttempted",
            Self::OidcKeyRotated(_) => "OidcKeyRotated",
            Self::AdminStatusChanged(_) => "AdminStatusChanged",
            Self::ClaimMappingApplied(_) => "ClaimMappingApplied",
            Self::ClaimMappingRevoked(_) => "ClaimMappingRevoked",
            Self::PermissionGrantApplied(_) => "PermissionGrantApplied",
            Self::PermissionGrantRevoked(_) => "PermissionGrantRevoked",
            Self::RepositoryUpstreamMappingChanged(_) => "RepositoryUpstreamMappingChanged",
            Self::ApiTokenIssued(_) => "ApiTokenIssued",
            Self::ApiTokenRevoked(_) => "ApiTokenRevoked",
            Self::ApiTokenIssuanceDenied(_) => "ApiTokenIssuanceDenied",
            Self::ApiTokenUsed(_) => "ApiTokenUsed",
            Self::TaskInvoked(_) => "TaskInvoked",
            Self::TaskFailed(_) => "TaskFailed",
            Self::OidcIssuerCreated(_) => "OidcIssuerCreated",
            Self::OidcIssuerUpdated(_) => "OidcIssuerUpdated",
            Self::OidcIssuerDeleted(_) => "OidcIssuerDeleted",
            Self::ServiceAccountCreated(_) => "ServiceAccountCreated",
            Self::ServiceAccountUpdated(_) => "ServiceAccountUpdated",
            Self::ServiceAccountDeleted(_) => "ServiceAccountDeleted",
            Self::ServiceAccountTokenRotated(_) => "ServiceAccountTokenRotated",
            Self::SubscriptionCreated(_) => "SubscriptionCreated",
            Self::SubscriptionCreationDenied(_) => "SubscriptionCreationDenied",
            Self::SubscriptionUpdated(_) => "SubscriptionUpdated",
            Self::SubscriptionPaused(_) => "SubscriptionPaused",
            Self::SubscriptionResumed(_) => "SubscriptionResumed",
            Self::SubscriptionDeleted(_) => "SubscriptionDeleted",
            Self::SubscriptionDisabled(_) => "SubscriptionDisabled",
            Self::StreamSealed(_) => "StreamSealed",
            // Discriminate the inner retention variant so the
            // event-store row's `event_type` column distinguishes the
            // four retention-policy lifecycle facts (the scan-policy
            // precedent uses one flat `event_type` per lifecycle
            // event; the wrapper reproduces that granularity here
            // without duplicating the inner payload structs).
            Self::RetentionPolicyChanged(e) => match e {
                RetentionPolicyEvent::Created { .. } => "RetentionPolicyCreated",
                RetentionPolicyEvent::Updated { .. } => "RetentionPolicyUpdated",
                RetentionPolicyEvent::Archived { .. } => "RetentionPolicyArchived",
                RetentionPolicyEvent::Evaluated { .. } => "RetentionPolicyEvaluated",
            },
        }
    }

    /// The serde externally-tagged variant key for this event — the
    /// JSON object key serde emits (`{"<key>": {fields}}`) and the key
    /// `serde_json::from_value::<DomainEvent>` expects.
    ///
    /// **Why this is distinct from [`Self::event_type`].** For every
    /// other variant the serde key and `event_type()` are
    /// byte-identical (the persistence path
    /// `hort-adapters-postgres::mappers::serialize_event_data` /
    /// `deserialize_event_data` and the chain `canonical_payload_bytes`
    /// all use `event_type()` as the serde tag).
    /// `RetentionPolicyChanged` is the **one** variant whose
    /// `event_type()` (the inner-discriminated
    /// `"RetentionPolicyCreated"` / `…Updated` / `…Archived` /
    /// `…Evaluated`, Shape A) is NOT its serde key (always
    /// `"RetentionPolicyChanged"` — the enum variant name). The
    /// serialize/deserialize reshape must `map.remove` / re-tag with
    /// THIS key, not `event_type()`, or the payload is silently
    /// dropped. The stored `events.event_type` column still carries
    /// `event_type()` (the discriminated form — the
    /// per-lifecycle-fact granularity); only the serde plumbing uses
    /// the variant key. See [`Self::serde_key_for_event_type`] for the
    /// inverse used on the deserialize path.
    pub fn serde_variant_key(&self) -> &'static str {
        match self {
            Self::RetentionPolicyChanged(_) => "RetentionPolicyChanged",
            // Every other variant: serde key == event_type()
            // (exhaustively pinned by the chain round-trip test).
            other => other.event_type(),
        }
    }

    /// Inverse of [`Self::serde_variant_key`]: given a stored
    /// `events.event_type` string, return the serde externally-tagged
    /// variant key needed to reconstruct the `{"<key>": data}` JSON
    /// `serde_json::from_value::<DomainEvent>` parses.
    ///
    /// Identity for every non-wrapper `event_type` (the stored type IS
    /// the serde key). The four discriminated retention strings
    /// all map back to the single `RetentionPolicyChanged` wrapper key
    /// — the serde-untagged inner enum then resolves the `Created` /
    /// `Updated` / `Archived` / `Evaluated` variant from the payload
    /// shape. Returns the input unchanged for any other string so a
    /// plain `event_type` round-trips byte-identically (the function
    /// is total — an unknown string is handled by the downstream
    /// `from_value` "unknown variant" error, exactly as before).
    pub fn serde_key_for_event_type(event_type: &str) -> &str {
        match event_type {
            "RetentionPolicyCreated"
            | "RetentionPolicyUpdated"
            | "RetentionPolicyArchived"
            | "RetentionPolicyEvaluated" => "RetentionPolicyChanged",
            other => other,
        }
    }

    /// `true` for the **authorization-model-mutation** event types — facts
    /// that record a change to the instance's RBAC / identity-provisioning
    /// model and therefore expose the instance's authorization topology.
    ///
    /// This predicate is the
    /// *type*-based half of the privileged-read gate. Several of these
    /// types ride a **non-admin stream category** because they carry a
    /// `repository_id` and route to `StreamCategory::Repository`
    /// (`requires_admin() == false`) — `PermissionGrantApplied` /
    /// `PermissionGrantRevoked` / `RepositoryUpstreamMappingChanged`. Keying
    /// the gate on `StreamCategory::requires_admin()` alone therefore leaks
    /// repo-scoped grant / upstream-mapping topology to any `Read` principal
    /// on the repo. The events read handler (`hort-http-events`) and
    /// `subscription_filter::matches` require `Permission::Admin` whenever
    /// this predicate (or [`Self::is_privileged_audit`]) is `true`,
    /// **regardless** of the carrying stream's category.
    ///
    /// The match is **exhaustive with no `_` wildcard arm on purpose**: a
    /// future `DomainEvent` variant fails to compile here until its
    /// authorization-disposition is consciously decided, so a new variant
    /// cannot silently default into the "leak-to-`Read`" bucket (the RT-2
    /// root of a silently-leaking-event bug class).
    ///
    /// `CurationApplied` is deliberately **not** in this set: curation
    /// outcomes are visible to repo readers by design (it rides the
    /// non-admin `Curation` category) and is outside that scope.
    /// `TaskInvoked` / `TaskFailed` / `StreamSealed` are already gated by
    /// their `requires_admin() == true` categories (`Authorization` /
    /// `Admin`); the type predicate is additive, so leaving them `false`
    /// here is correct.
    #[must_use]
    pub fn is_authorization_model_mutation(&self) -> bool {
        match self {
            // -- Authorization model: per-repo grants + claim mappings +
            //    upstream-mapping changes (ADR 0012).
            Self::PermissionGrantApplied(_)
            | Self::PermissionGrantRevoked(_)
            | Self::RepositoryUpstreamMappingChanged(_)
            | Self::ClaimMappingApplied(_)
            | Self::ClaimMappingRevoked(_)
            // -- Persisted-admin-bit transition audit.
            | Self::AdminStatusChanged(_)
            // -- OIDC issuer lifecycle (identity provisioning, ADR 0018).
            | Self::OidcIssuerCreated(_)
            | Self::OidcIssuerUpdated(_)
            | Self::OidcIssuerDeleted(_)
            // -- Service-account lifecycle (identity provisioning, ADR 0018).
            | Self::ServiceAccountCreated(_)
            | Self::ServiceAccountUpdated(_)
            | Self::ServiceAccountDeleted(_)
            | Self::ServiceAccountTokenRotated(_)
            // -- Retention-policy lifecycle (governs destructive GC;
            //    predicate + scope mutation).
            | Self::RetentionPolicyChanged(_) => true,

            // -- Everything else is NOT an authorization-model mutation. --
            Self::ArtifactIngested(_)
            | Self::ChecksumVerified(_)
            | Self::ChecksumMismatch(_)
            | Self::ArtifactQuarantined(_)
            | Self::ScanRequested(_)
            | Self::ScanCompleted(_)
            | Self::ArtifactBecameVulnerable(_)
            | Self::ArtifactReleased(_)
            | Self::ArtifactRejected(_)
            | Self::ScanIndeterminate(_)
            | Self::ProvenanceVerified(_)
            | Self::ProvenanceRejected(_)
            | Self::ArtifactReEvaluated(_)
            | Self::PromotionRequested(_)
            | Self::PolicyEvaluated(_)
            | Self::ApprovalRequested(_)
            | Self::ApprovalDecided(_)
            | Self::ArtifactPromoted(_)
            | Self::PromotionRejected(_)
            | Self::ArtifactExpired(_)
            | Self::ArtifactPurged(_)
            | Self::ArtifactDownloaded(_)
            | Self::PolicyCreated(_)
            | Self::PolicyUpdated(_)
            | Self::ExclusionAdded(_)
            | Self::ExclusionRemoved(_)
            | Self::PolicyArchived(_)
            | Self::PolicyReactivated(_)
            | Self::CasIntegrityMismatch(_)
            | Self::ArtifactCorrupted(_)
            | Self::RefMoved(_)
            | Self::RefRetired(_)
            | Self::ArtifactGroupInitiated(_)
            | Self::ArtifactGroupMemberAdded(_)
            | Self::ArtifactGroupMemberRemoved(_)
            | Self::ArtifactGroupPrimaryRoleAssigned(_)
            | Self::CurationApplied(_)
            | Self::AuthenticationAttempted(_)
            | Self::OidcKeyRotated(_)
            | Self::ApiTokenIssued(_)
            | Self::ApiTokenRevoked(_)
            | Self::ApiTokenIssuanceDenied(_)
            | Self::ApiTokenUsed(_)
            | Self::TaskInvoked(_)
            | Self::TaskFailed(_)
            | Self::SubscriptionCreated(_)
            | Self::SubscriptionCreationDenied(_)
            | Self::SubscriptionUpdated(_)
            | Self::SubscriptionPaused(_)
            | Self::SubscriptionResumed(_)
            | Self::SubscriptionDeleted(_)
            | Self::SubscriptionDisabled(_)
            | Self::StreamSealed(_) => false,
        }
    }

    /// `true` for the **privileged-audit** event types — high-volume
    /// privileged-observation facts (download / token-use / authentication
    /// telemetry + native-token issuance audit) whose disclosure leaks an
    /// instance's access / credential-exercise history.
    ///
    /// The locus is
    /// `ArtifactDownloaded`: it carries a `repository_id` (lands on
    /// `StreamCategory::DownloadAudit`) and
    /// [`crate::entities::subscription::EventTypeKind::repository_id`]
    /// returns `Some(repo)` for it, so the *None-repo*
    /// admin re-check never sees it and it escapes to any `Read` principal
    /// on the repo. Like [`Self::is_authorization_model_mutation`], when
    /// this predicate is `true` the read + subscription gates require
    /// `Permission::Admin` regardless of the carrying stream's category.
    ///
    /// Exhaustive, no `_` wildcard arm — same RT-2 rationale as
    /// [`Self::is_authorization_model_mutation`].
    #[must_use]
    pub fn is_privileged_audit(&self) -> bool {
        match self {
            // -- High-volume privileged observation (download / token-use /
            //    auth telemetry — the HIGH_VOLUME_EVENT_TYPES surface plus
            //    the native-token issuance audit + OIDC key rotation).
            Self::ArtifactDownloaded(_)
            | Self::ApiTokenUsed(_)
            | Self::AuthenticationAttempted(_)
            | Self::ApiTokenIssued(_)
            | Self::ApiTokenRevoked(_)
            | Self::ApiTokenIssuanceDenied(_)
            | Self::OidcKeyRotated(_) => true,

            // -- Everything else is NOT a privileged-audit observation. --
            Self::ArtifactIngested(_)
            | Self::ChecksumVerified(_)
            | Self::ChecksumMismatch(_)
            | Self::ArtifactQuarantined(_)
            | Self::ScanRequested(_)
            | Self::ScanCompleted(_)
            | Self::ArtifactBecameVulnerable(_)
            | Self::ArtifactReleased(_)
            | Self::ArtifactRejected(_)
            | Self::ScanIndeterminate(_)
            | Self::ProvenanceVerified(_)
            | Self::ProvenanceRejected(_)
            | Self::ArtifactReEvaluated(_)
            | Self::PromotionRequested(_)
            | Self::PolicyEvaluated(_)
            | Self::ApprovalRequested(_)
            | Self::ApprovalDecided(_)
            | Self::ArtifactPromoted(_)
            | Self::PromotionRejected(_)
            | Self::ArtifactExpired(_)
            | Self::ArtifactPurged(_)
            | Self::PolicyCreated(_)
            | Self::PolicyUpdated(_)
            | Self::ExclusionAdded(_)
            | Self::ExclusionRemoved(_)
            | Self::PolicyArchived(_)
            | Self::PolicyReactivated(_)
            | Self::CasIntegrityMismatch(_)
            | Self::ArtifactCorrupted(_)
            | Self::RefMoved(_)
            | Self::RefRetired(_)
            | Self::ArtifactGroupInitiated(_)
            | Self::ArtifactGroupMemberAdded(_)
            | Self::ArtifactGroupMemberRemoved(_)
            | Self::ArtifactGroupPrimaryRoleAssigned(_)
            | Self::CurationApplied(_)
            | Self::AdminStatusChanged(_)
            | Self::ClaimMappingApplied(_)
            | Self::ClaimMappingRevoked(_)
            | Self::PermissionGrantApplied(_)
            | Self::PermissionGrantRevoked(_)
            | Self::RepositoryUpstreamMappingChanged(_)
            | Self::TaskInvoked(_)
            | Self::TaskFailed(_)
            | Self::OidcIssuerCreated(_)
            | Self::OidcIssuerUpdated(_)
            | Self::OidcIssuerDeleted(_)
            | Self::ServiceAccountCreated(_)
            | Self::ServiceAccountUpdated(_)
            | Self::ServiceAccountDeleted(_)
            | Self::ServiceAccountTokenRotated(_)
            | Self::SubscriptionCreated(_)
            | Self::SubscriptionCreationDenied(_)
            | Self::SubscriptionUpdated(_)
            | Self::SubscriptionPaused(_)
            | Self::SubscriptionResumed(_)
            | Self::SubscriptionDeleted(_)
            | Self::SubscriptionDisabled(_)
            | Self::StreamSealed(_)
            | Self::RetentionPolicyChanged(_) => false,
        }
    }

    /// Validate the event payload. Delegates to the inner struct's `validate()`.
    pub fn validate(&self) -> DomainResult<()> {
        match self {
            Self::ArtifactIngested(e) => e.validate(),
            Self::ChecksumVerified(e) => e.validate(),
            Self::ChecksumMismatch(e) => e.validate(),
            Self::ArtifactQuarantined(e) => e.validate(),
            Self::ScanRequested(e) => e.validate(),
            Self::ScanCompleted(e) => e.validate(),
            Self::ArtifactBecameVulnerable(e) => e.validate(),
            Self::ArtifactReleased(e) => e.validate(),
            Self::ArtifactRejected(e) => e.validate(),
            Self::ScanIndeterminate(e) => e.validate(),
            Self::ProvenanceVerified(e) => e.validate(),
            Self::ProvenanceRejected(e) => e.validate(),
            Self::ArtifactReEvaluated(e) => e.validate(),
            Self::PromotionRequested(e) => e.validate(),
            Self::PolicyEvaluated(e) => e.validate(),
            Self::ApprovalRequested(e) => e.validate(),
            Self::ApprovalDecided(e) => e.validate(),
            Self::ArtifactPromoted(e) => e.validate(),
            Self::PromotionRejected(e) => e.validate(),
            Self::ArtifactExpired(e) => e.validate(),
            Self::ArtifactPurged(e) => e.validate(),
            Self::ArtifactDownloaded(e) => e.validate(),
            Self::PolicyCreated(e) => e.validate(),
            Self::PolicyUpdated(e) => e.validate(),
            Self::ExclusionAdded(e) => e.validate(),
            Self::ExclusionRemoved(e) => e.validate(),
            Self::PolicyArchived(e) => e.validate(),
            Self::PolicyReactivated(e) => e.validate(),
            Self::CasIntegrityMismatch(e) => e.validate(),
            Self::ArtifactCorrupted(e) => e.validate(),
            Self::RefMoved(e) => e.validate(),
            Self::RefRetired(e) => e.validate(),
            Self::ArtifactGroupInitiated(e) => e.validate(),
            Self::ArtifactGroupMemberAdded(e) => e.validate(),
            Self::ArtifactGroupMemberRemoved(e) => e.validate(),
            Self::ArtifactGroupPrimaryRoleAssigned(e) => e.validate(),
            Self::CurationApplied(e) => e.validate(),
            Self::AuthenticationAttempted(e) => e.validate(),
            Self::OidcKeyRotated(e) => e.validate(),
            Self::AdminStatusChanged(e) => e.validate(),
            Self::ClaimMappingApplied(e) => e.validate(),
            Self::ClaimMappingRevoked(e) => e.validate(),
            Self::PermissionGrantApplied(e) => e.validate(),
            Self::PermissionGrantRevoked(e) => e.validate(),
            Self::RepositoryUpstreamMappingChanged(e) => e.validate(),
            Self::ApiTokenIssued(e) => e.validate(),
            Self::ApiTokenRevoked(e) => e.validate(),
            Self::ApiTokenIssuanceDenied(e) => e.validate(),
            Self::ApiTokenUsed(e) => e.validate(),
            Self::TaskInvoked(e) => e.validate(),
            Self::TaskFailed(e) => e.validate(),
            Self::OidcIssuerCreated(e) => e.validate(),
            Self::OidcIssuerUpdated(e) => e.validate(),
            Self::OidcIssuerDeleted(e) => e.validate(),
            Self::ServiceAccountCreated(e) => e.validate(),
            Self::ServiceAccountUpdated(e) => e.validate(),
            Self::ServiceAccountDeleted(e) => e.validate(),
            Self::ServiceAccountTokenRotated(e) => e.validate(),
            Self::SubscriptionCreated(e) => e.validate(),
            Self::SubscriptionCreationDenied(e) => e.validate(),
            Self::SubscriptionUpdated(e) => e.validate(),
            Self::SubscriptionPaused(e) => e.validate(),
            Self::SubscriptionResumed(e) => e.validate(),
            Self::SubscriptionDeleted(e) => e.validate(),
            Self::SubscriptionDisabled(e) => e.validate(),
            Self::StreamSealed(e) => e.validate(),
            // Delegate to the inner retention event's per-event
            // structural validator (`predicate.validate()` /
            // `scope.validate()` / name bound on the config-bearing
            // variants).
            Self::RetentionPolicyChanged(e) => e.validate(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::api_token_events::{
        ApiTokenIssuanceDenied, ApiTokenIssued, ApiTokenRevoked, ApiTokenUsed, DenialReason,
        RevokeReason,
    };
    use super::super::artifact_events::{
        ApprovalDecision, ArtifactCorrupted, ArtifactExpired, ArtifactPurged, IngestSource,
        PolicyResult, ProvenanceRejected, ProvenanceVerified, RejectionReason, ReleaseReason,
        SeveritySummary,
    };
    use super::super::artifact_group_events::{
        ArtifactGroupInitiated, ArtifactGroupMemberAdded, ArtifactGroupMemberRemoved,
        ArtifactGroupPrimaryRoleAssigned,
    };
    use super::super::auth_events::{AdminStatusChanged, AuthenticationAttempted, OidcKeyRotated};
    use super::super::authorization_events::{
        ClaimMappingApplied, ClaimMappingRevoked, GrantSubjectRecord, PermissionGrantApplied,
        PermissionGrantRevoked, RepositoryUpstreamMappingChanged, TaskFailed, TaskInvoked,
        UpstreamMappingChange,
    };
    use super::super::cas_scrub_events::CasIntegrityMismatch;
    use super::super::curation_events::{CurationActionTag, CurationTrigger};
    use super::super::download_events::{ArtifactDownloaded, DownloadActor};
    use super::super::oidc_issuer_events::{
        OidcIssuerCreated, OidcIssuerDeleted, OidcIssuerUpdated,
    };
    use super::super::policy_events::{PolicyField, PolicyReactivated, PolicyScope};
    use super::super::ref_events::{RefMoved, RefRetired};
    use super::super::retention_events::StreamSealed;
    use super::super::service_account_events::{
        SerdeSecretFormat, ServiceAccountCreated, ServiceAccountDeleted,
        ServiceAccountTokenRotated, ServiceAccountUpdated,
    };
    use super::super::subscription_events::{
        FilterSummary, RepositoryScopeKind, SubscriptionCreated, SubscriptionCreationDenied,
        SubscriptionDeleted, SubscriptionDisabled, SubscriptionPaused, SubscriptionResumed,
        SubscriptionUpdated, TargetKindWire,
    };
    use super::*;
    use crate::entities::api_token::TokenKind;
    use crate::entities::artifact::QuarantineStatus;
    use crate::entities::mutable_ref::RefTarget;
    use crate::entities::rbac::Permission;
    use crate::entities::repository::RepositoryFormat;
    use crate::entities::scan_policy::SeverityThreshold;
    use crate::entities::subscription::{DisableReason, SubscriptionDenialReason};
    use crate::ports::provenance::{ProvenanceRejectReason, SignerIdentity};
    use crate::retention::{
        ExpirationReason, PolicyPredicate, RetentionPolicyEvent, RetentionScope,
    };
    use crate::types::ArtifactCoords;
    use crate::types::Finding;
    use chrono::Utc;
    use uuid::Uuid;

    fn sha256() -> crate::types::ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    /// Returns the canonical 64-variant vector used to cover every
    /// `DomainEvent` match arm. Factored out so tests in sibling modules
    /// (e.g. `events::chain`) can reuse it without maintaining a second
    /// list. This is `pub(crate)` so it is reachable from `#[cfg(test)]`
    /// blocks anywhere inside `hort-domain`; it is not part of the public
    /// API (test-only, gated by `#[cfg(test)]`).
    pub(crate) fn all_test_variants() -> Vec<DomainEvent> {
        vec![
            DomainEvent::ArtifactIngested(ArtifactIngested {
                artifact_id: Uuid::nil(),
                repository_id: Uuid::nil(),
                name: "pkg".into(),
                version: Some("1.0".into()),
                sha256: sha256(),
                size_bytes: 1,
                source: IngestSource::Direct,
                metadata: serde_json::Value::Null,
                metadata_blob: None,
                upstream_published_at: None,
            }),
            DomainEvent::ChecksumVerified(ChecksumVerified {
                artifact_id: Uuid::nil(),
                algorithm: crate::types::HashAlgorithm::Sha256,
                upstream_value: sha256().to_string(),
                computed_value: sha256().to_string(),
            }),
            DomainEvent::ChecksumMismatch(ChecksumMismatch {
                repository_id: Uuid::nil(),
                coords: ArtifactCoords {
                    name: "pkg".into(),
                    name_as_published: "pkg".into(),
                    version: Some("1.0".into()),
                    path: "pkg/1.0/pkg-1.0.tar.gz".into(),
                    format: RepositoryFormat::Pypi,
                    metadata: serde_json::Value::Null,
                },
                format: "pypi".into(),
                algorithm: crate::types::HashAlgorithm::Sha256,
                upstream_value: sha256().to_string(),
                computed_value: sha256().to_string(),
            }),
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id: Uuid::nil(),
                quarantine_window_start: Utc::now(),
            }),
            DomainEvent::ScanRequested(ScanRequested {
                artifact_id: Uuid::nil(),
                scanner: "trivy".into(),
            }),
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id: Uuid::nil(),
                scanner: "trivy".into(),
                finding_count: 0,
                severity_summary: SeveritySummary {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    negligible: 0,
                },
                findings_blob: None,
            }),
            DomainEvent::ArtifactBecameVulnerable(ArtifactBecameVulnerable {
                artifact_id: Uuid::nil(),
                new_findings: vec![Finding {
                    purl: "pkg:npm/lodash@4.17.20".into(),
                    vulnerability_id: "CVE-2021-23337".into(),
                    severity: SeverityThreshold::High,
                    cvss_score: Some(7.2),
                    title: "Command Injection in lodash".into(),
                    fixed_versions: vec!["4.17.21".into()],
                    source_scanner: "trivy".into(),
                    references: vec![],
                    aliases: vec![],
                }],
                previously_clean_at: Utc::now(),
            }),
            DomainEvent::ArtifactReleased(ArtifactReleased {
                artifact_id: Uuid::nil(),
                released_by: ReleaseReason::Timer,
                released_by_user_id: None,
                justification: None,
            }),
            DomainEvent::ArtifactRejected(ArtifactRejected {
                artifact_id: Uuid::nil(),
                rejected_by: RejectionReason::Scanner,
                reason: "CVE-2024-0001".into(),
            }),
            DomainEvent::ScanIndeterminate(ScanIndeterminate {
                artifact_id: Uuid::nil(),
                scanner: "trivy,osv".into(),
                reason: "all scan backends failed".into(),
                attempts: 5,
            }),
            DomainEvent::ProvenanceVerified(ProvenanceVerified {
                artifact_id: Uuid::nil(),
                content_hash: sha256(),
                backend: "cosign".into(),
                signer: SignerIdentity {
                    issuer: "https://token.actions.githubusercontent.com".into(),
                    san:
                        "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                            .into(),
                },
                predicate_type: Some("https://slsa.dev/provenance/v1".into()),
            }),
            DomainEvent::ProvenanceRejected(ProvenanceRejected {
                artifact_id: Uuid::nil(),
                content_hash: sha256(),
                backend: "cosign".into(),
                reason: ProvenanceRejectReason::UntrustedIdentity,
            }),
            DomainEvent::ArtifactReEvaluated(ArtifactReEvaluated {
                artifact_id: Uuid::nil(),
                policy_id: Uuid::nil(),
                trigger_exclusion_id: Uuid::nil(),
                previous_status: QuarantineStatus::Rejected,
                new_status: QuarantineStatus::Released,
            }),
            DomainEvent::PromotionRequested(PromotionRequested {
                artifact_id: Uuid::nil(),
                source_repository_id: Uuid::nil(),
                target_repository_id: Uuid::nil(),
            }),
            DomainEvent::PolicyEvaluated(PolicyEvaluated {
                artifact_id: Uuid::nil(),
                policy_id: Uuid::nil(),
                result: PolicyResult::Pass,
                violations: vec![],
            }),
            DomainEvent::ApprovalRequested(ApprovalRequested {
                artifact_id: Uuid::nil(),
                source_repository_id: Uuid::nil(),
                target_repository_id: Uuid::nil(),
            }),
            DomainEvent::ApprovalDecided(ApprovalDecided {
                artifact_id: Uuid::nil(),
                decision: ApprovalDecision::Approved,
                notes: None,
            }),
            DomainEvent::ArtifactPromoted(ArtifactPromoted {
                artifact_id: Uuid::nil(),
                source_repository_id: Uuid::nil(),
                target_repository_id: Uuid::nil(),
            }),
            DomainEvent::PromotionRejected(PromotionRejected {
                artifact_id: Uuid::nil(),
                source_repository_id: Uuid::nil(),
                target_repository_id: Uuid::nil(),
                reason: "policy".into(),
            }),
            DomainEvent::ArtifactExpired(ArtifactExpired {
                artifact_id: Uuid::nil(),
                policy_id: Uuid::nil(),
                policy_name: "90-day-age".into(),
                reason: ExpirationReason::AgeExceeded {
                    published_at: Utc::now(),
                    ttl_secs: 86_400,
                },
                eligible_at: Utc::now(),
            }),
            DomainEvent::ArtifactPurged(ArtifactPurged {
                artifact_id: Uuid::nil(),
                content_hash: sha256(),
                refs_remaining: 0,
                purged_at: Utc::now(),
            }),
            DomainEvent::ArtifactDownloaded(ArtifactDownloaded {
                artifact_id: Uuid::nil(),
                repository_id: Uuid::nil(),
                content_hash: sha256(),
                actor: DownloadActor::Anonymous,
                occurred_at: Utc::now(),
            }),
            DomainEvent::PolicyCreated(PolicyCreated {
                policy_id: Uuid::nil(),
                name: "default".into(),
                scope: PolicyScope::Global,
                config_snapshot: serde_json::json!({}),
            }),
            DomainEvent::PolicyUpdated(PolicyUpdated {
                policy_id: Uuid::nil(),
                field: PolicyField::Name,
                previous_value: serde_json::json!("old"),
                new_value: serde_json::json!("new"),
            }),
            DomainEvent::ExclusionAdded(ExclusionAdded {
                policy_id: Uuid::nil(),
                exclusion_id: Uuid::nil(),
                cve_id: "CVE-2024-0001".into(),
                package_pattern: None,
                scope: PolicyScope::Global,
                reason: "false positive".into(),
                expires_at: None,
            }),
            DomainEvent::ExclusionRemoved(ExclusionRemoved {
                policy_id: Uuid::nil(),
                exclusion_id: Uuid::nil(),
                reason: "revoked".into(),
            }),
            DomainEvent::PolicyArchived(PolicyArchived {
                policy_id: Uuid::nil(),
            }),
            DomainEvent::PolicyReactivated(PolicyReactivated {
                policy_id: Uuid::nil(),
            }),
            DomainEvent::CasIntegrityMismatch(CasIntegrityMismatch {
                content_hash: sha256(),
                backend: "filesystem".into(),
                observed_hash: sha256(),
            }),
            DomainEvent::ArtifactCorrupted(ArtifactCorrupted {
                artifact_id: Uuid::nil(),
                computed_hash: sha256(),
                expected_hash: sha256(),
                detected_at: Utc::now(),
            }),
            DomainEvent::RefMoved(RefMoved {
                ref_id: Uuid::nil(),
                repository_id: Uuid::nil(),
                namespace: "library/nginx".into(),
                ref_name: "latest".into(),
                from: None,
                to: RefTarget::ContentHash(sha256()),
            }),
            DomainEvent::RefRetired(RefRetired {
                ref_id: Uuid::nil(),
                repository_id: Uuid::nil(),
                namespace: "library/nginx".into(),
                ref_name: "latest".into(),
                last_target: RefTarget::ContentHash(sha256()),
            }),
            DomainEvent::ArtifactGroupInitiated(ArtifactGroupInitiated {
                group_id: Uuid::nil(),
                repository_id: Uuid::nil(),
                coords: ArtifactCoords {
                    name: "my-pkg".into(),
                    name_as_published: "my-pkg".into(),
                    version: Some("1.0.0".into()),
                    path: String::new(),
                    format: RepositoryFormat::Maven,
                    metadata: serde_json::Value::Null,
                },
                primary_role: "pom".into(),
            }),
            DomainEvent::ArtifactGroupMemberAdded(ArtifactGroupMemberAdded {
                group_id: Uuid::nil(),
                role: "jar".into(),
                artifact_id: Uuid::nil(),
            }),
            DomainEvent::ArtifactGroupMemberRemoved(ArtifactGroupMemberRemoved {
                group_id: Uuid::nil(),
                artifact_id: Uuid::nil(),
                reason: Some("admin".into()),
            }),
            DomainEvent::ArtifactGroupPrimaryRoleAssigned(ArtifactGroupPrimaryRoleAssigned {
                group_id: Uuid::nil(),
                primary_role: "pom".into(),
            }),
            DomainEvent::CurationApplied(CurationApplied {
                repository_id: Uuid::nil(),
                coords: ArtifactCoords {
                    name: "xz-utils".into(),
                    name_as_published: "xz-utils".into(),
                    version: Some("1.0.0".into()),
                    path: String::new(),
                    format: RepositoryFormat::Pypi,
                    metadata: serde_json::Value::Null,
                },
                rule_id: Uuid::nil(),
                rule_name: "block-xz".into(),
                action: CurationActionTag::Block,
                reason: "supply-chain risk".into(),
                trigger: CurationTrigger::Retroactive,
            }),
            DomainEvent::AuthenticationAttempted(AuthenticationAttempted {
                client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 42)),
                result: "local_invalid_credentials".into(),
                external_id_if_decoded: Some("alice".into()),
                at: Utc::now(),
            }),
            DomainEvent::OidcKeyRotated(OidcKeyRotated {
                kid_added: "kid-new".into(),
                kid_evicted: Some("kid-old".into()),
                fetched_at: Utc::now(),
            }),
            DomainEvent::AdminStatusChanged(AdminStatusChanged {
                user_id: Uuid::nil(),
                external_id: "realm-users:abc-123".into(),
                granted: true,
                at: Utc::now(),
            }),
            DomainEvent::ClaimMappingApplied(ClaimMappingApplied {
                mapping_id: Uuid::nil(),
                idp_group: "ops-team".into(),
                claim: "admin".into(),
            }),
            DomainEvent::ClaimMappingRevoked(ClaimMappingRevoked {
                mapping_id: Uuid::nil(),
                idp_group: "ops-team".into(),
                claim: "admin".into(),
            }),
            DomainEvent::PermissionGrantApplied(PermissionGrantApplied {
                grant_id: Uuid::nil(),
                subject: GrantSubjectRecord::Claims {
                    required: vec!["developer".into()],
                },
                permission: Permission::Read,
                repository_id: None,
            }),
            DomainEvent::PermissionGrantRevoked(PermissionGrantRevoked {
                grant_id: Uuid::nil(),
                subject: GrantSubjectRecord::User {
                    user_id: Uuid::nil(),
                },
                permission: Permission::Read,
                repository_id: Some(Uuid::nil()),
            }),
            DomainEvent::RepositoryUpstreamMappingChanged(RepositoryUpstreamMappingChanged {
                mapping_id: Uuid::nil(),
                repository_id: Uuid::nil(),
                change: UpstreamMappingChange::Updated,
                previous_secret_ref: Some("env_var:OLD_TOKEN".into()),
                new_secret_ref: Some("env_var:NEW_TOKEN".into()),
                previous_url: Some("https://registry-1.docker.io".into()),
                new_url: Some("https://registry-1.docker.io".into()),
            }),
            DomainEvent::ApiTokenIssued(ApiTokenIssued {
                token_id: Uuid::nil(),
                user_id: Uuid::nil(),
                kind: TokenKind::Pat,
                declared_permissions: vec![Permission::Read],
                repository_ids: None,
                expires_at: None,
                minted_by_admin_id: None,
                at: Utc::now(),
                source_issuer: None,
                source_jti: None,
                source_sub: None,
            }),
            DomainEvent::ApiTokenRevoked(ApiTokenRevoked {
                token_id: Uuid::nil(),
                user_id: Uuid::nil(),
                revoked_by_admin_id: None,
                reason: RevokeReason::OperatorRequest,
                at: Utc::now(),
            }),
            DomainEvent::ApiTokenIssuanceDenied(ApiTokenIssuanceDenied {
                target_user_id: Uuid::nil(),
                requested_kind: TokenKind::Pat,
                requested_permissions: vec![Permission::Admin],
                requested_repository_ids: None,
                denial_reason: DenialReason::AdminTokenDisallowed,
                at: Utc::now(),
            }),
            DomainEvent::ApiTokenUsed(ApiTokenUsed {
                token_id: Uuid::nil(),
                user_id: Uuid::nil(),
                kind: TokenKind::Pat,
                occurred_at: Utc::now(),
            }),
            DomainEvent::TaskInvoked(TaskInvoked {
                task_job_id: Uuid::nil(),
                kind: "noop".into(),
                params_digest: "0".repeat(64),
                duplicate_of: None,
            }),
            DomainEvent::TaskFailed(TaskFailed {
                task_job_id: Uuid::nil(),
                kind: "noop".into(),
                reason: "db connection lost".into(),
                final_attempt: false,
            }),
            DomainEvent::OidcIssuerCreated(OidcIssuerCreated {
                issuer_id: Uuid::nil(),
                name: "github-actions".into(),
                at: Utc::now(),
            }),
            DomainEvent::OidcIssuerUpdated(OidcIssuerUpdated {
                issuer_id: Uuid::nil(),
                name: "github-actions".into(),
                at: Utc::now(),
            }),
            DomainEvent::OidcIssuerDeleted(OidcIssuerDeleted {
                issuer_id: Uuid::nil(),
                name: "github-actions".into(),
                at: Utc::now(),
            }),
            DomainEvent::ServiceAccountCreated(ServiceAccountCreated {
                service_account_id: Uuid::nil(),
                service_account_name: "ci-pypi-pusher".into(),
                backing_user_id: Uuid::nil(),
                at: Utc::now(),
            }),
            DomainEvent::ServiceAccountUpdated(ServiceAccountUpdated {
                service_account_id: Uuid::nil(),
                service_account_name: "ci-pypi-pusher".into(),
                at: Utc::now(),
            }),
            DomainEvent::ServiceAccountDeleted(ServiceAccountDeleted {
                service_account_id: Uuid::nil(),
                service_account_name: "ci-pypi-pusher".into(),
                backing_user_id: Uuid::nil(),
                at: Utc::now(),
            }),
            DomainEvent::ServiceAccountTokenRotated(ServiceAccountTokenRotated {
                service_account_id: Uuid::nil(),
                service_account_name: "ci-pypi-pusher".into(),
                token_id: Uuid::nil(),
                target_secret_namespace: "ci-system".into(),
                target_secret_name: "ci-hort-token".into(),
                format: SerdeSecretFormat::Dockerconfigjson,
                at: Utc::now(),
            }),
            DomainEvent::SubscriptionCreated(SubscriptionCreated {
                subscription_id: Uuid::nil(),
                owner_user_id: Uuid::nil(),
                target_kind: TargetKindWire::Webhook,
                filter_summary: FilterSummary {
                    categories: vec!["artifact".into()],
                    event_type_count: 1,
                    repository_scope_kind: RepositoryScopeKind::OwnedByActor,
                    predicate_hash: [0; 32],
                },
                snapshot_claims_count: 0,
                at: Utc::now(),
            }),
            DomainEvent::SubscriptionCreationDenied(SubscriptionCreationDenied {
                requesting_user_id: Uuid::nil(),
                requested_target_kind: TargetKindWire::NatsJetStream,
                attempted_filter_summary: FilterSummary {
                    categories: vec!["artifact".into()],
                    event_type_count: 1,
                    repository_scope_kind: RepositoryScopeKind::Some,
                    predicate_hash: [0; 32],
                },
                denial_reason: SubscriptionDenialReason::PlaintextWebhookDisallowed,
                at: Utc::now(),
            }),
            DomainEvent::SubscriptionUpdated(SubscriptionUpdated {
                subscription_id: Uuid::nil(),
                owner_user_id: Uuid::nil(),
                changed_fields: vec!["name".into()],
                snapshot_claims_count: 0,
                at: Utc::now(),
            }),
            DomainEvent::SubscriptionPaused(SubscriptionPaused {
                subscription_id: Uuid::nil(),
                owner_user_id: Uuid::nil(),
                at: Utc::now(),
            }),
            DomainEvent::SubscriptionResumed(SubscriptionResumed {
                subscription_id: Uuid::nil(),
                owner_user_id: Uuid::nil(),
                at: Utc::now(),
            }),
            DomainEvent::SubscriptionDeleted(SubscriptionDeleted {
                subscription_id: Uuid::nil(),
                owner_user_id: Uuid::nil(),
                at: Utc::now(),
            }),
            DomainEvent::SubscriptionDisabled(SubscriptionDisabled {
                subscription_id: Uuid::nil(),
                owner_user_id: Uuid::nil(),
                reason: DisableReason::OperatorDisabled,
                at: Utc::now(),
            }),
            DomainEvent::StreamSealed(StreamSealed {
                sealed_stream_id: "authorization-00000000-0000-0000-0000-000000000000".into(),
                sealed_stream_category: "authorization".into(),
                final_stream_position: 3,
                final_event_hash: [0u8; 32],
                event_count: 4,
                retention_policy_id: Uuid::nil(),
                actor_id: None,
            }),
            // The four inner RetentionPolicyEvent
            // discriminations (wrapper shape). Created carries the
            // predicate + scope that re-validate in `validate()`.
            DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Created {
                id: Uuid::nil(),
                name: "retain-proxied-30d".into(),
                predicate: PolicyPredicate::AgeExceeds(2_592_000),
                scope: RetentionScope::AllRepos,
                created_at: Utc::now(),
            }),
            DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Updated {
                id: Uuid::nil(),
                predicate: PolicyPredicate::AgeExceeds(5_184_000),
                scope: RetentionScope::AllRepos,
                updated_at: Utc::now(),
            }),
            DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Archived {
                id: Uuid::nil(),
                by: Uuid::nil(),
                archived_at: Utc::now(),
            }),
            DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Evaluated {
                id: Uuid::nil(),
                evaluated_at: Utc::now(),
                matched_count: 7,
                expired_count: 3,
            }),
        ]
    }

    /// `event_type()` discriminates the inner retention variant
    /// so the event-store `event_type` column distinguishes the four
    /// retention-policy lifecycle facts (the scan-policy flat-per-event
    /// granularity, reproduced via the wrapper without payload
    /// duplication). All four arms covered.
    #[test]
    fn retention_policy_changed_event_type_discriminates_inner_variant() {
        let created = DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: "p".into(),
            predicate: PolicyPredicate::AgeExceeds(60),
            scope: RetentionScope::AllRepos,
            created_at: Utc::now(),
        });
        assert_eq!(created.event_type(), "RetentionPolicyCreated");

        let updated = DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Updated {
            id: Uuid::nil(),
            predicate: PolicyPredicate::AgeExceeds(60),
            scope: RetentionScope::AllRepos,
            updated_at: Utc::now(),
        });
        assert_eq!(updated.event_type(), "RetentionPolicyUpdated");

        let archived = DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Archived {
            id: Uuid::nil(),
            by: Uuid::nil(),
            archived_at: Utc::now(),
        });
        assert_eq!(archived.event_type(), "RetentionPolicyArchived");

        let evaluated = DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Evaluated {
            id: Uuid::nil(),
            evaluated_at: Utc::now(),
            matched_count: 1,
            expired_count: 0,
        });
        assert_eq!(evaluated.event_type(), "RetentionPolicyEvaluated");
    }

    /// `validate()` delegates to
    /// `RetentionPolicyEvent::validate()`. A malformed embedded
    /// predicate (zero-second `AgeExceeds` — a zero TTL is rejected)
    /// surfaces as `DomainError::Validation` through the wrapper, NOT
    /// silently accepted.
    #[test]
    fn retention_policy_changed_validate_delegates_to_inner() {
        let ok = DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: "ok".into(),
            predicate: PolicyPredicate::AgeExceeds(60),
            scope: RetentionScope::AllRepos,
            created_at: Utc::now(),
        });
        assert!(ok.validate().is_ok());

        let bad = DomainEvent::RetentionPolicyChanged(RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: "bad".into(),
            // A zero-second TTL is a footgun and is rejected by
            // `PolicyPredicate::validate()`.
            predicate: PolicyPredicate::AgeExceeds(0),
            scope: RetentionScope::AllRepos,
            created_at: Utc::now(),
        });
        let err = bad.validate().unwrap_err();
        assert!(
            matches!(err, crate::error::DomainError::Validation(_)),
            "expected the inner predicate validator to reject a 0s TTL through the wrapper, got {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // Authorization-model / privileged-audit event-type predicates.
    // -------------------------------------------------------------------

    /// The authorization-model-mutation set.
    /// These leak the instance's RBAC / identity-provisioning topology and
    /// must require `Permission::Admin` on the read + subscription gates
    /// regardless of the carrying stream's category. Returns the event
    /// type names so the assertions read against the live `event_type()`.
    fn auth_mutation_type_names() -> &'static [&'static str] {
        &[
            "PermissionGrantApplied",
            "PermissionGrantRevoked",
            "RepositoryUpstreamMappingChanged",
            "ClaimMappingApplied",
            "ClaimMappingRevoked",
            "AdminStatusChanged",
            "OidcIssuerCreated",
            "OidcIssuerUpdated",
            "OidcIssuerDeleted",
            "ServiceAccountCreated",
            "ServiceAccountUpdated",
            "ServiceAccountDeleted",
            "ServiceAccountTokenRotated",
            // RetentionPolicyChanged's event_type() discriminates the
            // inner variant; the four discriminated strings all map to
            // the one wrapper, so test against the wrapper predicate via
            // the bucket helper below rather than by name here.
        ]
    }

    /// The privileged-audit set. High-volume
    /// privileged-observation telemetry + native-token issuance audit.
    fn privileged_audit_type_names() -> &'static [&'static str] {
        &[
            "ArtifactDownloaded",
            "ApiTokenUsed",
            "AuthenticationAttempted",
            "ApiTokenIssued",
            "ApiTokenRevoked",
            "ApiTokenIssuanceDenied",
            "OidcKeyRotated",
        ]
    }

    /// Every authorization-model-mutation type is classified
    /// `is_authorization_model_mutation()` AND is NOT a privileged-audit.
    #[test]
    fn authorization_model_mutations_are_classified() {
        for e in all_test_variants() {
            let t = e.event_type();
            if auth_mutation_type_names().contains(&t)
                || matches!(e, DomainEvent::RetentionPolicyChanged(_))
            {
                assert!(
                    e.is_authorization_model_mutation(),
                    "{t} must be an authorization-model mutation"
                );
                assert!(
                    !e.is_privileged_audit(),
                    "{t} is an auth-model mutation, not a privileged-audit"
                );
            }
        }
    }

    /// Every privileged-audit type is classified
    /// `is_privileged_audit()` AND is NOT an authorization-model mutation.
    #[test]
    fn privileged_audits_are_classified() {
        for e in all_test_variants() {
            let t = e.event_type();
            if privileged_audit_type_names().contains(&t) {
                assert!(
                    e.is_privileged_audit(),
                    "{t} must be a privileged-audit observation"
                );
                assert!(
                    !e.is_authorization_model_mutation(),
                    "{t} is a privileged-audit, not an auth-model mutation"
                );
            }
        }
    }

    /// Ordinary repo / lifecycle events fall in NEITHER bucket — they must
    /// keep flowing to a `Read` principal (no regression). `ArtifactIngested`
    /// / `ArtifactReleased` are the canonical exemplars; `CurationApplied`
    /// is explicitly `neither` (curation outcomes are visible to repo
    /// readers by design — NOT scope creep into the admin gate).
    #[test]
    fn ordinary_repo_events_are_in_neither_bucket() {
        for e in all_test_variants() {
            let t = e.event_type();
            let in_auth = auth_mutation_type_names().contains(&t)
                || matches!(e, DomainEvent::RetentionPolicyChanged(_));
            let in_audit = privileged_audit_type_names().contains(&t);
            if !in_auth && !in_audit {
                assert!(
                    !e.is_authorization_model_mutation(),
                    "{t} must NOT be an authorization-model mutation"
                );
                assert!(
                    !e.is_privileged_audit(),
                    "{t} must NOT be a privileged-audit observation"
                );
            }
        }
        // Spot-check the named exemplars directly so the rationale is
        // pinned even if the helper lists drift.
        let ingested = all_test_variants()
            .into_iter()
            .find(|e| e.event_type() == "ArtifactIngested")
            .unwrap();
        assert!(!ingested.is_authorization_model_mutation());
        assert!(!ingested.is_privileged_audit());
        let curation = all_test_variants()
            .into_iter()
            .find(|e| e.event_type() == "CurationApplied")
            .unwrap();
        assert!(
            !curation.is_authorization_model_mutation() && !curation.is_privileged_audit(),
            "CurationApplied is visible to repo readers by design — neither bucket"
        );
    }

    /// RT-2 exhaustiveness guard (mirrors the linter's
    /// `every_permission_variant_is_classified`). Every `DomainEvent`
    /// variant lands in **exactly one** of `{auth_mutation,
    /// privileged_audit, neither}` — the two predicates are mutually
    /// exclusive and total over the enum. `all_test_variants()` is the
    /// canonical one-per-variant vector (its own arms are pinned exhaustive
    /// by `validate_dispatches_to_every_variant`), so any future variant
    /// added to the enum forces a new arm there AND a classification here.
    /// The predicates themselves carry the no-`_`-wildcard compile guard
    /// (a new variant fails to compile until classified); this test pins
    /// the runtime mutual-exclusivity / totality contract.
    #[test]
    fn every_domain_event_lands_in_exactly_one_bucket() {
        for e in all_test_variants() {
            let auth = e.is_authorization_model_mutation();
            let audit = e.is_privileged_audit();
            assert!(
                !(auth && audit),
                "{} classified as BOTH auth-model-mutation and privileged-audit",
                e.event_type()
            );
        }
    }

    /// Covers every match arm in `DomainEvent::validate()` by constructing
    /// a minimal valid instance of each variant and dispatching through
    /// the enum's `validate()` method.
    #[test]
    fn validate_dispatches_to_every_variant() {
        let variants = all_test_variants();
        // All variants dispatch through `validate()` without panic; each
        // inner validate() returns Ok for these minimal-valid instances.
        for e in &variants {
            e.validate()
                .unwrap_or_else(|err| panic!("{} validation failed: {err}", e.event_type()));
            // Also exercise event_type() for the same arms, keeping both
            // match statements covered together.
            let _name = e.event_type();
        }
    }
}
