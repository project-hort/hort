//! Event-notification subscription entity + filter / target types.
//!
//! See `docs/architecture/explanation/event-notifications.md` for the
//! subscription model, filter contract, and port traits.
//!
//! # Invariants encoded here
//!
//! - **No `Serialize` / `Deserialize` impl on any subscription type.** These
//!   are domain types. Adapter-side DTOs (the postgres adapter's
//!   `subscription_repo.rs`, the HTTP handler request DTOs) handle JSONB and
//!   wire serialisation. Adding `#[derive(Deserialize)]` here would let
//!   external input forge a [`Subscription`] with an arbitrary webhook
//!   `secret_ref`, `owner_user_id`, or `last_delivered_position`.
//!   Compile-time invariants
//!   in the test module enforce this via
//!   `static_assertions::assert_not_impl_any!`.
//! - **No I/O imports.** `hort-domain` is pure Rust, zero I/O — the file
//!   imports `chrono`, `uuid`, `url`, and the local event-type module only.
//!   No `sqlx`, `reqwest`, `axum`, or `tracing`.
//! - **Closed-enum filter.** Filter
//!   expressiveness is bounded by the [`EventTypeKind`] / [`RepositoryScope`]
//!   / [`NamedPredicate`] enums. There is **no expression DSL**, no
//!   field-level matchers, no wildcards. The named-predicate set
//!   ([`NamedPredicate`]) currently has **zero variants** — see its
//!   documentation for the rationale and the audited extension path.
//! - **High-volume event-type exclusion.** The
//!   const [`HIGH_VOLUME_EVENT_TYPES`] is the canonical exclusion list; the
//!   subscription use case hard-rejects subscriptions whose filter requests
//!   any of these. The list contains `ArtifactDownloaded`, `ApiTokenUsed`,
//!   and `AuthenticationAttempted`. All three are emittable from
//!   [`crate::events::DomainEvent`]. The exclusion is an *issuance-time*
//!   guard on subscription filters, **not** an emittability statement:
//!   these events are emitted and retained (opt-in per-repo download audit /
//!   per-use token audit / auth audit) but stay subscription-excluded
//!   because they are high-volume — see [`HIGH_VOLUME_EVENT_TYPES`].
//! - **Closed-enum discriminators DO derive `Serialize` + `Deserialize`.** Per
//!   the `api_token_events.rs` precedent (see the module-level
//!   "no PII" comment there), the small audit-only enums embedded in
//!   subscription lifecycle event payloads
//!   ([`SubscriptionDenialReason`], [`SsrfBlockReason`], [`DisableReason`])
//!   serialise into the JSONB event-store column and must round-trip — so
//!   they carry serde derives. These enums carry no PII, no URLs, no
//!   secret material; they are pure discriminator tags. The carrying entity
//!   ([`Subscription`]) and its target / filter / state composite types
//!   stay non-`Deserialize` — handler input is parsed via adapter DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::error::{DomainError, DomainResult};
use crate::events::{DomainEvent, PersistedEvent, StreamCategory};
use crate::ports::event_notifier::NotifyFailureReason;
use crate::ports::secret_port::SecretRef;

// ---------------------------------------------------------------------------
// SubscriptionId
// ---------------------------------------------------------------------------

/// Newtype around `Uuid` identifying a [`Subscription`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub Uuid);

// ---------------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------------

/// Operator-authored subscription that delivers filtered events to one
/// [`SubscriptionTarget`].
///
/// **Ownership and audit attribution.** The
/// `owner_user_id` is the authz scope — current grants on this user filter
/// every delivery. `created_by_token_id` is *audit attribution only*: it
/// records which token authored the row but does not drive authz. Rotating
/// the token does not cascade — the cap is captured at creation time as the
/// explicit list inside `filter.repositories`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// Subscription identifier (newtype around `Uuid`).
    pub id: SubscriptionId,
    /// User whose live grants gate delivery (authz scope).
    pub owner_user_id: Uuid,
    /// Token that authored the row. Audit attribution only — does **not**
    /// drive authz; the user's live grants always do.
    pub created_by_token_id: Option<Uuid>,
    /// Operator-facing label, unique per `(owner_user_id, name)`.
    pub name: String,
    /// Optional free-form description (length-capped at 1024 — see
    /// [`validate_description`]).
    pub description: Option<String>,
    /// Where matching events are delivered.
    pub target: SubscriptionTarget,
    /// What matches (categories / event types / repository scope / named
    /// predicates).
    pub filter: SubscriptionFilter,
    /// Authority floor — the owner's resolved claim set (ADR 0012)
    /// captured at create and **re-set on every update**.
    /// The dispatcher synthesises the delivery principal from this
    /// snapshot rather than re-resolving `claim_mappings` at delivery
    /// time, so events deliver under the same authority floor the
    /// creator had at the most recent fresh-session interaction. This
    /// is a security *floor* (full-replace on update),
    /// asymmetric with `filter.repositories` (a shrink-only cap).
    /// `token_kind` is deliberately absent from the
    /// snapshot — it is a property of how *this request* authenticated,
    /// not of the durable subscription authority floor.
    pub snapshot_claims: Vec<String>,
    /// Active / paused / disabled.
    pub state: SubscriptionState,
    /// Visibility aid — last successfully-delivered global position.
    /// **Not** delivery semantics; the notifier is best-effort.
    pub last_delivered_position: Option<u64>,
    /// Most-recent failure observed. Overwritten on every new failure.
    pub last_failure: Option<SubscriptionFailure>,
    /// Wall-clock at create time.
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// SubscriptionTarget
// ---------------------------------------------------------------------------

/// Where the dispatcher pushes matching events.
///
/// Connection details for NATS (URL, NKey, token) live in composition-root
/// config — not on the subscription row. One JetStream connection per
/// hort-server process; per-subscription credentials would put secrets in
/// subscription rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionTarget {
    /// HTTP webhook receiver.
    Webhook {
        /// Receiver URL. `https://` only unless
        /// `HORT_WEBHOOK_ALLOW_PLAINTEXT=true` (composition-root knob).
        url: Url,
        /// Reference to the shared secret used to HMAC-sign deliveries
        /// (`X-Ak-Signature: sha256=<hex>`). Resolved at delivery time
        /// via [`SecretPort`]; the **plaintext bytes never touch the
        /// subscription row** — only the `(source, location)` locator
        /// does.
        ///
        /// This mirrors
        /// [`RepositoryUpstreamMapping.secret_ref`]: the
        /// row carries a `SecretRef`, not the secret material, so a
        /// reader of the subscription store / backup cannot reconstruct
        /// the HMAC key and forge signed deliveries. (Storing the
        /// Argon2id PHC string of the secret and HMAC'ing with *that*
        /// would not help — the stored hash *would be* the key, so
        /// hashing at rest gives no protection.)
        ///
        /// The wire format is unchanged: receivers still verify
        /// HMAC-SHA256 over the same body; only the key changes from
        /// "the stored hash" to "the SecretPort-resolved plaintext".
        ///
        /// [`SecretPort`]: crate::ports::secret_port::SecretPort
        /// [`RepositoryUpstreamMapping.secret_ref`]: crate::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping::secret_ref
        secret_ref: SecretRef,
    },
    /// NATS JetStream subject.
    NatsJetStream {
        /// JetStream subject validated against the NATS subject grammar
        /// (`[a-zA-Z0-9._-]+(\.[a-zA-Z0-9._-]+)*`, no wildcards).
        subject: String,
    },
}

// ---------------------------------------------------------------------------
// SubscriptionFilter
// ---------------------------------------------------------------------------

/// Closed-enum filter applied at every delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionFilter {
    /// Stream categories the subscription consumes. Empty list means
    /// "no categories" — i.e. a subscription that never delivers; the use
    /// case rejects this at issuance.
    pub categories: Vec<StreamCategory>,
    /// Event-type filter (`All` or an explicit `Some(_)` list).
    pub event_types: EventTypeFilter,
    /// Repository scope.
    pub repositories: RepositoryScope,
    /// Named composite predicates. v1 ships zero variants — see
    /// [`NamedPredicate`].
    pub named_predicates: Vec<NamedPredicate>,
}

// ---------------------------------------------------------------------------
// EventTypeFilter
// ---------------------------------------------------------------------------

/// Event-type filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventTypeFilter {
    /// Every event type in the selected categories matches.
    All,
    /// Only event types whose kind is in the list match.
    Some(Vec<EventTypeKind>),
}

impl EventTypeFilter {
    /// Returns `true` when the event-type filter matches the given event.
    ///
    /// `All` short-circuits to `true`. `Some(kinds)` checks membership of
    /// `EventTypeKind::of(&event.event)` in `kinds`.
    pub fn matches(&self, event: &PersistedEvent) -> bool {
        match self {
            EventTypeFilter::All => true,
            EventTypeFilter::Some(kinds) => {
                let kind = EventTypeKind::of(&event.event);
                kinds.contains(&kind)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EventTypeKind
// ---------------------------------------------------------------------------

/// Closed enum mirroring [`crate::events::DomainEvent`] variants — including
/// the three high-volume event types that stay subscription-excluded
/// (see [`HIGH_VOLUME_EVENT_TYPES`]) but are all emittable.
///
/// **Exhaustiveness invariant.** [`EventTypeKind::of`] matches `DomainEvent`
/// without a `_ =>` arm; adding a new `DomainEvent` variant is a compile
/// error here, **on purpose**. The compile error
/// forces the contributor to decide whether the new variant carries a
/// repository association and what its `EventTypeKind` is.
///
/// The three high-volume variants ([`EventTypeKind::ArtifactDownloaded`],
/// [`EventTypeKind::ApiTokenUsed`], [`EventTypeKind::AuthenticationAttempted`])
/// live in this enum so the issuance-time exclusion check
/// ([`HIGH_VOLUME_EVENT_TYPES`]) is canonical. All three exist in
/// `DomainEvent` and are emitted in production: `AuthenticationAttempted`
/// (auth audit), `ArtifactDownloaded` (opt-in per-repo download audit),
/// and `ApiTokenUsed` (per-use token audit). They remain
/// subscription-excluded because they are high-volume — emittability and
/// subscription-eligibility are independent properties.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventTypeKind {
    // -- Artifact lifecycle --
    ArtifactIngested,
    ChecksumVerified,
    ChecksumMismatch,
    ArtifactQuarantined,
    ScanRequested,
    ScanCompleted,
    ArtifactBecameVulnerable,
    ArtifactReleased,
    ArtifactRejected,
    ScanIndeterminate,
    /// Supply-chain provenance attestation (ADR 0027)
    /// verified. Lands on the artifact stream; no direct repository
    /// association (same posture as the other post-ingest
    /// artifact-lifecycle kinds).
    ProvenanceVerified,
    /// Provenance check (ADR 0027) rejected the
    /// artifact. Same (no-)repository-association posture.
    ProvenanceRejected,
    ArtifactReEvaluated,
    PromotionRequested,
    PolicyEvaluated,
    ApprovalRequested,
    ApprovalDecided,
    ArtifactPromoted,
    PromotionRejected,
    /// Retention policy fired,
    /// artifact eligible for purge. Lands on the artifact stream; no
    /// direct repository association (the artifact aggregate identifies
    /// the repo indirectly, same posture as the other post-ingest
    /// artifact-lifecycle kinds).
    ArtifactExpired,
    /// Storage delete completed (or
    /// blob confirmed absent). Terminal for `ArtifactExpired`; same
    /// (no-)repository-association posture.
    ArtifactPurged,

    // -- Policy lifecycle --
    PolicyCreated,
    PolicyUpdated,
    ExclusionAdded,
    ExclusionRemoved,
    PolicyArchived,
    PolicyReactivated,

    // -- CAS integrity --
    CasIntegrityMismatch,
    ArtifactCorrupted,

    // -- Mutable-ref lifecycle --
    RefMoved,
    RefRetired,

    // -- Artifact-group lifecycle --
    ArtifactGroupInitiated,
    ArtifactGroupMemberAdded,
    ArtifactGroupMemberRemoved,
    ArtifactGroupPrimaryRoleAssigned,

    // -- Curation decisions --
    CurationApplied,

    // -- Authentication --
    AuthenticationAttempted,
    OidcKeyRotated,
    /// A persisted `User.is_admin`
    /// bit flipped on an OIDC login. Per-user authority audit; no
    /// repository association.
    AdminStatusChanged,

    // -- Authorization model (claim-based RBAC, ADR 0012) --
    ClaimMappingApplied,
    ClaimMappingRevoked,
    PermissionGrantApplied,
    PermissionGrantRevoked,
    RepositoryUpstreamMappingChanged,

    // -- Native API token audit --
    ApiTokenIssued,
    ApiTokenRevoked,
    ApiTokenIssuanceDenied,

    // -- Admin-task invocation audit --
    TaskInvoked,
    TaskFailed,

    // -- OIDC issuer + service-account lifecycle (ADR 0018) --
    OidcIssuerCreated,
    OidcIssuerUpdated,
    OidcIssuerDeleted,
    ServiceAccountCreated,
    ServiceAccountUpdated,
    ServiceAccountDeleted,
    ServiceAccountTokenRotated,

    // -- Subscription lifecycle --
    SubscriptionCreated,
    SubscriptionCreationDenied,
    SubscriptionUpdated,
    SubscriptionPaused,
    SubscriptionResumed,
    SubscriptionDeleted,
    SubscriptionDisabled,

    // -- Event-store retention sealing --
    // Internal tamper-evidence tombstone on the never-deleted
    // `admin-eventstore-retention` audit-meta stream. Present here
    // only to satisfy the exhaustiveness invariant — it carries no
    // repository association and is not intended as a
    // user-subscribable event type.
    StreamSealed,

    // -- High-volume slots (subscription-excluded; in HIGH_VOLUME_EVENT_TYPES) --
    // Emittable from DomainEvent (opt-in per-repo download audit).
    // Still subscription-excluded — the exclusion is the issuance-time
    // guard, not an emittability one.
    ArtifactDownloaded,
    // Emittable from DomainEvent (per-use token audit). Still
    // subscription-excluded for the same high-volume reason.
    ApiTokenUsed,

    // -- Retention-policy lifecycle --
    // The dedicated `StreamCategory::RetentionPolicy` lifecycle
    // (`DomainEvent::RetentionPolicyChanged` wrapping
    // `RetentionPolicyEvent`). Present here to satisfy the
    // exhaustiveness invariant. It carries no
    // repository association (a `RetentionScope::Repos` list is not a
    // single `repository_id`, exactly like the scan-policy
    // lifecycle) and is grouped with the other policy-lifecycle kinds
    // — admin-only audit, NOT a user-subscribable per-repo event.
    RetentionPolicyChanged,
}

impl EventTypeKind {
    /// Project a [`DomainEvent`] to its [`EventTypeKind`].
    ///
    /// **Exhaustive match — no `_ =>` arm.** Adding a new `DomainEvent`
    /// variant fails to compile here until the contributor adds the
    /// corresponding `EventTypeKind` variant and its arm. This is the
    /// closed-enum invariant.
    pub fn of(event: &DomainEvent) -> EventTypeKind {
        match event {
            DomainEvent::ArtifactIngested(_) => EventTypeKind::ArtifactIngested,
            DomainEvent::ChecksumVerified(_) => EventTypeKind::ChecksumVerified,
            DomainEvent::ChecksumMismatch(_) => EventTypeKind::ChecksumMismatch,
            DomainEvent::ArtifactQuarantined(_) => EventTypeKind::ArtifactQuarantined,
            DomainEvent::ScanRequested(_) => EventTypeKind::ScanRequested,
            DomainEvent::ScanCompleted(_) => EventTypeKind::ScanCompleted,
            DomainEvent::ArtifactBecameVulnerable(_) => EventTypeKind::ArtifactBecameVulnerable,
            DomainEvent::ArtifactReleased(_) => EventTypeKind::ArtifactReleased,
            DomainEvent::ArtifactRejected(_) => EventTypeKind::ArtifactRejected,
            DomainEvent::ScanIndeterminate(_) => EventTypeKind::ScanIndeterminate,
            DomainEvent::ProvenanceVerified(_) => EventTypeKind::ProvenanceVerified,
            DomainEvent::ProvenanceRejected(_) => EventTypeKind::ProvenanceRejected,
            DomainEvent::ArtifactReEvaluated(_) => EventTypeKind::ArtifactReEvaluated,
            DomainEvent::PromotionRequested(_) => EventTypeKind::PromotionRequested,
            DomainEvent::PolicyEvaluated(_) => EventTypeKind::PolicyEvaluated,
            DomainEvent::ApprovalRequested(_) => EventTypeKind::ApprovalRequested,
            DomainEvent::ApprovalDecided(_) => EventTypeKind::ApprovalDecided,
            DomainEvent::ArtifactPromoted(_) => EventTypeKind::ArtifactPromoted,
            DomainEvent::PromotionRejected(_) => EventTypeKind::PromotionRejected,
            DomainEvent::ArtifactExpired(_) => EventTypeKind::ArtifactExpired,
            DomainEvent::ArtifactPurged(_) => EventTypeKind::ArtifactPurged,
            DomainEvent::ArtifactDownloaded(_) => EventTypeKind::ArtifactDownloaded,
            DomainEvent::PolicyCreated(_) => EventTypeKind::PolicyCreated,
            DomainEvent::PolicyUpdated(_) => EventTypeKind::PolicyUpdated,
            DomainEvent::ExclusionAdded(_) => EventTypeKind::ExclusionAdded,
            DomainEvent::ExclusionRemoved(_) => EventTypeKind::ExclusionRemoved,
            DomainEvent::PolicyArchived(_) => EventTypeKind::PolicyArchived,
            DomainEvent::PolicyReactivated(_) => EventTypeKind::PolicyReactivated,
            DomainEvent::CasIntegrityMismatch(_) => EventTypeKind::CasIntegrityMismatch,
            DomainEvent::ArtifactCorrupted(_) => EventTypeKind::ArtifactCorrupted,
            DomainEvent::RefMoved(_) => EventTypeKind::RefMoved,
            DomainEvent::RefRetired(_) => EventTypeKind::RefRetired,
            DomainEvent::ArtifactGroupInitiated(_) => EventTypeKind::ArtifactGroupInitiated,
            DomainEvent::ArtifactGroupMemberAdded(_) => EventTypeKind::ArtifactGroupMemberAdded,
            DomainEvent::ArtifactGroupMemberRemoved(_) => EventTypeKind::ArtifactGroupMemberRemoved,
            DomainEvent::ArtifactGroupPrimaryRoleAssigned(_) => {
                EventTypeKind::ArtifactGroupPrimaryRoleAssigned
            }
            DomainEvent::CurationApplied(_) => EventTypeKind::CurationApplied,
            DomainEvent::AuthenticationAttempted(_) => EventTypeKind::AuthenticationAttempted,
            DomainEvent::OidcKeyRotated(_) => EventTypeKind::OidcKeyRotated,
            DomainEvent::AdminStatusChanged(_) => EventTypeKind::AdminStatusChanged,
            DomainEvent::ClaimMappingApplied(_) => EventTypeKind::ClaimMappingApplied,
            DomainEvent::ClaimMappingRevoked(_) => EventTypeKind::ClaimMappingRevoked,
            DomainEvent::PermissionGrantApplied(_) => EventTypeKind::PermissionGrantApplied,
            DomainEvent::PermissionGrantRevoked(_) => EventTypeKind::PermissionGrantRevoked,
            DomainEvent::RepositoryUpstreamMappingChanged(_) => {
                EventTypeKind::RepositoryUpstreamMappingChanged
            }
            DomainEvent::ApiTokenIssued(_) => EventTypeKind::ApiTokenIssued,
            DomainEvent::ApiTokenRevoked(_) => EventTypeKind::ApiTokenRevoked,
            DomainEvent::ApiTokenIssuanceDenied(_) => EventTypeKind::ApiTokenIssuanceDenied,
            DomainEvent::ApiTokenUsed(_) => EventTypeKind::ApiTokenUsed,
            DomainEvent::TaskInvoked(_) => EventTypeKind::TaskInvoked,
            DomainEvent::TaskFailed(_) => EventTypeKind::TaskFailed,
            DomainEvent::OidcIssuerCreated(_) => EventTypeKind::OidcIssuerCreated,
            DomainEvent::OidcIssuerUpdated(_) => EventTypeKind::OidcIssuerUpdated,
            DomainEvent::OidcIssuerDeleted(_) => EventTypeKind::OidcIssuerDeleted,
            DomainEvent::ServiceAccountCreated(_) => EventTypeKind::ServiceAccountCreated,
            DomainEvent::ServiceAccountUpdated(_) => EventTypeKind::ServiceAccountUpdated,
            DomainEvent::ServiceAccountDeleted(_) => EventTypeKind::ServiceAccountDeleted,
            DomainEvent::ServiceAccountTokenRotated(_) => EventTypeKind::ServiceAccountTokenRotated,
            DomainEvent::SubscriptionCreated(_) => EventTypeKind::SubscriptionCreated,
            DomainEvent::SubscriptionCreationDenied(_) => EventTypeKind::SubscriptionCreationDenied,
            DomainEvent::SubscriptionUpdated(_) => EventTypeKind::SubscriptionUpdated,
            DomainEvent::SubscriptionPaused(_) => EventTypeKind::SubscriptionPaused,
            DomainEvent::SubscriptionResumed(_) => EventTypeKind::SubscriptionResumed,
            DomainEvent::SubscriptionDeleted(_) => EventTypeKind::SubscriptionDeleted,
            DomainEvent::SubscriptionDisabled(_) => EventTypeKind::SubscriptionDisabled,
            DomainEvent::StreamSealed(_) => EventTypeKind::StreamSealed,
            DomainEvent::RetentionPolicyChanged(_) => EventTypeKind::RetentionPolicyChanged,
        }
    }

    /// Extract the repository association from an event payload.
    ///
    /// **Exhaustive match — no `_ =>` arm.** Returns `Some(uuid)` only when
    /// the payload carries a single `repository_id` field. Payloads with
    /// `source_repository_id` + `target_repository_id` pairs (promotion
    /// events) return `None` for v1 — the dispatcher then falls through to
    /// the `RepositoryScope::OwnedByActor` no-op step ("for
    /// events without a repository association ... the predicate downstream
    /// falls back to no repo association"). Subscription-lifecycle /
    /// user-lifecycle / policy-lifecycle / auth-event variants return
    /// `None`.
    pub fn repository_id(event: &DomainEvent) -> Option<Uuid> {
        match event {
            // -- Artifact lifecycle: only ArtifactIngested carries a direct
            // repository_id; the rest live on artifact streams and identify
            // repo indirectly via the artifact aggregate.
            DomainEvent::ArtifactIngested(e) => Some(e.repository_id),
            DomainEvent::ChecksumVerified(_) => None,
            DomainEvent::ChecksumMismatch(e) => Some(e.repository_id),
            DomainEvent::ArtifactQuarantined(_) => None,
            DomainEvent::ScanRequested(_) => None,
            DomainEvent::ScanCompleted(_) => None,
            DomainEvent::ArtifactBecameVulnerable(_) => None,
            DomainEvent::ArtifactReleased(_) => None,
            DomainEvent::ArtifactRejected(_) => None,
            DomainEvent::ScanIndeterminate(_) => None,
            // Provenance events land on the artifact stream; the
            // artifact aggregate identifies the repo indirectly (no
            // direct repository_id), same posture as the other
            // post-ingest artifact-lifecycle events.
            DomainEvent::ProvenanceVerified(_) => None,
            DomainEvent::ProvenanceRejected(_) => None,
            DomainEvent::ArtifactReEvaluated(_) => None,
            // Promotion events carry source + target repos; no single
            // repository_id, so v1 returns None per the task spec.
            DomainEvent::PromotionRequested(_) => None,
            DomainEvent::PolicyEvaluated(_) => None,
            DomainEvent::ApprovalRequested(_) => None,
            DomainEvent::ApprovalDecided(_) => None,
            DomainEvent::ArtifactPromoted(_) => None,
            DomainEvent::PromotionRejected(_) => None,
            // Retention lifecycle: lands on
            // the artifact stream; the artifact aggregate identifies the
            // repo indirectly, so no direct repository_id — same as the
            // other post-ingest artifact-lifecycle events above.
            DomainEvent::ArtifactExpired(_) => None,
            DomainEvent::ArtifactPurged(_) => None,
            // Download audit: the payload carries
            // the repository_id directly (it is the stream-sharding
            // key). Returned here for the dispatcher's repo-scope
            // filter even though the event type is in
            // HIGH_VOLUME_EVENT_TYPES and is therefore
            // subscription-excluded at issuance regardless.
            DomainEvent::ArtifactDownloaded(e) => Some(e.repository_id),

            // -- Policy lifecycle: no repository association.
            DomainEvent::PolicyCreated(_) => None,
            DomainEvent::PolicyUpdated(_) => None,
            DomainEvent::ExclusionAdded(_) => None,
            DomainEvent::ExclusionRemoved(_) => None,
            DomainEvent::PolicyArchived(_) => None,
            DomainEvent::PolicyReactivated(_) => None,

            // -- CAS-integrity / auth: no repository association.
            DomainEvent::CasIntegrityMismatch(_) => None,
            DomainEvent::ArtifactCorrupted(_) => None,
            DomainEvent::AuthenticationAttempted(_) => None,
            DomainEvent::OidcKeyRotated(_) => None,
            DomainEvent::AdminStatusChanged(_) => None,

            // -- Mutable-ref lifecycle: directly repo-scoped.
            DomainEvent::RefMoved(e) => Some(e.repository_id),
            DomainEvent::RefRetired(e) => Some(e.repository_id),

            // -- Artifact-group lifecycle: only `ArtifactGroupInitiated`
            // carries the repo; the per-group member events identify it
            // indirectly via the group aggregate.
            DomainEvent::ArtifactGroupInitiated(e) => Some(e.repository_id),
            DomainEvent::ArtifactGroupMemberAdded(_) => None,
            DomainEvent::ArtifactGroupMemberRemoved(_) => None,
            DomainEvent::ArtifactGroupPrimaryRoleAssigned(_) => None,

            // -- Curation decisions: directly repo-scoped.
            DomainEvent::CurationApplied(e) => Some(e.repository_id),

            // -- Authorization model: per-event optional repo. Global
            // role / mapping events have no repo association.
            DomainEvent::ClaimMappingApplied(_) => None,
            DomainEvent::ClaimMappingRevoked(_) => None,
            DomainEvent::PermissionGrantApplied(e) => e.repository_id,
            DomainEvent::PermissionGrantRevoked(e) => e.repository_id,
            DomainEvent::RepositoryUpstreamMappingChanged(e) => Some(e.repository_id),

            // -- Native API token + admin-task audit: user-scoped, not repo.
            DomainEvent::ApiTokenIssued(_) => None,
            DomainEvent::ApiTokenRevoked(_) => None,
            DomainEvent::ApiTokenIssuanceDenied(_) => None,
            // Token-use audit: a token use has
            // NO repository association (the explicit contrast to
            // `ArtifactDownloaded` → `Some(repo)`); the stream
            // is sharded per-(token_id, UTC-date), not per-repo.
            DomainEvent::ApiTokenUsed(_) => None,
            DomainEvent::TaskInvoked(_) => None,
            DomainEvent::TaskFailed(_) => None,

            // -- OIDC issuer + service-account lifecycle (ADR 0018):
            // gitops / machine-identity events, no repository
            // association (same posture as the policy + auth groups).
            DomainEvent::OidcIssuerCreated(_) => None,
            DomainEvent::OidcIssuerUpdated(_) => None,
            DomainEvent::OidcIssuerDeleted(_) => None,
            DomainEvent::ServiceAccountCreated(_) => None,
            DomainEvent::ServiceAccountUpdated(_) => None,
            DomainEvent::ServiceAccountDeleted(_) => None,
            DomainEvent::ServiceAccountTokenRotated(_) => None,

            // -- Subscription lifecycle: owner's
            // user stream, not repo-scoped. Every subscription
            // lifecycle variant returns None.
            DomainEvent::SubscriptionCreated(_) => None,
            DomainEvent::SubscriptionCreationDenied(_) => None,
            DomainEvent::SubscriptionUpdated(_) => None,
            DomainEvent::SubscriptionPaused(_) => None,
            DomainEvent::SubscriptionResumed(_) => None,
            DomainEvent::SubscriptionDeleted(_) => None,
            DomainEvent::SubscriptionDisabled(_) => None,

            // -- Event-store retention sealing:
            // global `admin-eventstore-retention` audit-meta stream,
            // not repo-scoped.
            DomainEvent::StreamSealed(_) => None,

            // -- Retention-policy lifecycle:
            // a retention policy's scope may name repositories
            // (`RetentionScope::Repos`) but there is no single
            // `repository_id` field — same as the scan-policy
            // lifecycle, which also returns None. The event is
            // admin-only policy audit, not a per-repo subscribable.
            DomainEvent::RetentionPolicyChanged(_) => None,
        }
    }

    /// Returns `true` when this kind is in [`HIGH_VOLUME_EVENT_TYPES`].
    ///
    /// Used by the issuance use case to reject filters that request
    /// any of `ArtifactDownloaded`, `ApiTokenUsed`, or
    /// `AuthenticationAttempted`.
    pub fn is_high_volume(&self) -> bool {
        HIGH_VOLUME_EVENT_TYPES.contains(self)
    }
}

/// High-volume event-type exclusion list.
///
/// Subscriptions whose filter requests any of these are rejected at
/// issuance with [`SubscriptionDenialReason::UnsupportedEventType`]. The
/// list is a compile-time `const` so the exclusion is canonical and any
/// future change to it is deliberate.
///
/// All three list members are emittable from `DomainEvent` and are emitted
/// in production: `AuthenticationAttempted` (auth audit),
/// `ArtifactDownloaded` (opt-in per-repo download audit), and `ApiTokenUsed`
/// (per-use token audit). They are on this list because
/// they are high-volume, not because they are unemitted — the exclusion
/// gates subscription *filters* at issuance, independently of emission.
pub const HIGH_VOLUME_EVENT_TYPES: &[EventTypeKind] = &[
    EventTypeKind::ArtifactDownloaded,
    EventTypeKind::ApiTokenUsed,
    EventTypeKind::AuthenticationAttempted,
];

// ---------------------------------------------------------------------------
// RepositoryScope
// ---------------------------------------------------------------------------

/// Repository scope component of [`SubscriptionFilter`].
///
/// Token-cap interaction:
/// - `OwnedByActor` requires an uncapped session (no repo cap on the token).
///   Repo-capped tokens MUST supply `Some(filter_ids)` so the cap is captured
///   as the stored list — see [`SubscriptionDenialReason::RepoScopeMustBeExplicit`].
/// - `Some(ids)` is the explicit allow-list snapshot — token-cap intersected
///   with caller's live `Read` grants at creation time.
/// - `All` requires `Permission::Admin` AND an uncapped token — see
///   [`SubscriptionDenialReason::AdminScopeRequiresAdmin`] /
///   [`SubscriptionDenialReason::AdminScopeRequiresUncappedToken`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryScope {
    /// Every repository the owner can currently read. Resolved live at
    /// delivery — resolved live at the dispatcher.
    OwnedByActor,
    /// Explicit allow-list (cap snapshot).
    Some(Vec<Uuid>),
    /// Every repository in the system. Admin-only at issuance.
    All,
}

// ---------------------------------------------------------------------------
// NamedPredicate
// ---------------------------------------------------------------------------

/// Closed enum of named composite predicates over event payloads.
///
/// **v1 ships zero variants.** The type is reserved as the audited extension
/// point for future composite filters; for v1 every consumer that needs
/// composite logic computes it client-side from the raw events delivered by
/// category + event-type + repository filtering. The no-DSL stance is
/// settled and closed indefinitely.
///
/// Adding a v1.x variant requires its own PR, its own catalog entry, its
/// own test, and confirmation that the consumer demand is real (not
/// speculative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamedPredicate {}

// ---------------------------------------------------------------------------
// SubscriptionState
// ---------------------------------------------------------------------------

/// Subscription delivery state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionState {
    /// Delivering normally.
    Active,
    /// Operator-paused via `PATCH /api/v1/subscriptions/:id`. Delivery
    /// stopped but the row is retained.
    Paused,
    /// Delivery suspended by a system condition. Operator must explicitly
    /// re-enable.
    Disabled {
        /// Why the dispatcher suspended delivery.
        reason: DisableReason,
        /// When the transition occurred.
        since: DateTime<Utc>,
    },
}

/// Reason a subscription transitioned to [`SubscriptionState::Disabled`].
///
/// Derives `Serialize` + `Deserialize` per the module-level "closed-enum
/// discriminators" exception — this enum is the payload of
/// [`crate::events::SubscriptionDisabled`] and must round-trip through
/// JSONB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DisableReason {
    /// The `owner_user_id` was deactivated.
    OwnerDeactivated,
    /// The dispatcher's 100-failures-per-hour budget exhausted — see
    /// the delivery failure budget limit.
    DeliveryFailureBudgetExhausted,
    /// Explicit admin action via `PATCH .../disable`.
    OperatorDisabled,
}

// ---------------------------------------------------------------------------
// SubscriptionFailure
// ---------------------------------------------------------------------------

/// Per-subscription most-recent-failure record. Overwritten on every new
/// failure. Re-uses [`NotifyFailureReason`] from
/// [`crate::ports::event_notifier`] so the dispatcher can store a port-level
/// reason verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionFailure {
    /// When the failure was observed.
    pub at: DateTime<Utc>,
    /// Port-level reason (re-exported from
    /// [`crate::ports::event_notifier`]).
    pub reason: NotifyFailureReason,
    /// Consecutive failures since the last successful delivery. Reset to
    /// `0` on first success.
    pub consecutive_failures: u32,
}

// ---------------------------------------------------------------------------
// SsrfBlockReason
// ---------------------------------------------------------------------------

/// SSRF-check outcome from [`crate::ports::webhook_target_guard::WebhookTargetGuard`].
///
/// Matches the [`crate::ports::webhook_target_guard::WebhookTargetGuard::check`]
/// failure shape AND the metric label values for the
/// `hort_webhook_ssrf_block_total{reason}` counter (see
/// `docs/metrics-catalog.md`); the counter has three label values, this
/// enum is canonical.
///
/// Derives `Serialize` + `Deserialize` per the module-level "closed-enum
/// discriminators" exception — this enum is embedded in
/// [`SubscriptionDenialReason::WebhookTargetNotRoutable`], which is the
/// payload of [`crate::events::SubscriptionCreationDenied`] and must
/// round-trip through JSONB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SsrfBlockReason {
    /// The URL's host is an IP literal that fails `hort_net_egress::is_routable`.
    IpLiteralNotRoutable,
    /// The URL's host resolved to a set that contains a non-routable IP.
    DnsResolvedNotRoutable,
    /// DNS resolution failed entirely (NXDOMAIN, SERVFAIL, timeout, …).
    DnsResolutionFailed,
}

// ---------------------------------------------------------------------------
// SubscriptionDenialReason
// ---------------------------------------------------------------------------

/// Closed enum of reasons a subscription CRUD call is refused.
///
/// Each variant maps to a distinct `SubscriptionCreationDenied`
/// `denial_reason` event value and a distinct HTTP `400` / `403` error
/// shape. The dispatcher does not produce these — only the use case does.
///
/// Derives `Serialize` + `Deserialize` per the module-level "closed-enum
/// discriminators" exception — this enum is the payload of
/// [`crate::events::SubscriptionCreationDenied`] and must round-trip
/// through JSONB.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubscriptionDenialReason {
    /// Filter requested a high-volume event type from
    /// [`HIGH_VOLUME_EVENT_TYPES`].
    UnsupportedEventType,
    /// `RepositoryScope::Some(ids)` where the caller lacks `Read` on at
    /// least one id.
    RepoNotAuthorised,
    /// `RepositoryScope::All` requested by a non-admin caller.
    AdminScopeRequiresAdmin,
    /// `RepositoryScope::All` requested via a repo-capped token.
    AdminScopeRequiresUncappedToken,
    /// `RepositoryScope::OwnedByActor` requested via a repo-capped token
    /// (the cap must be captured as an explicit list).
    RepoScopeMustBeExplicit,
    /// `RepositoryScope::Some(filter_ids)` where
    /// `filter_ids ⊄ token_cap.repository_ids`.
    RepoScopeExceedsTokenCap,
    /// `Webhook { url: http://... }` and `HORT_WEBHOOK_ALLOW_PLAINTEXT=false`.
    PlaintextWebhookDisallowed,
    /// `Webhook { url, .. }` whose host failed the
    /// [`crate::ports::webhook_target_guard::WebhookTargetGuard`] check and
    /// the operator did not opt in via `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS`.
    WebhookTargetNotRoutable {
        /// Underlying block reason (canonical metric label set).
        ssrf_block_reason: SsrfBlockReason,
    },
    /// `filter.categories` intersects the privileged
    /// `ADMIN_CATEGORIES` set (`Policy`, `Admin`, `Authorization`,
    /// `User`, `AuthAttempts` — the categories
    /// [`crate::events::StreamCategory::requires_admin`] returns `true`
    /// for) while the acting principal does not satisfy
    /// `Permission::Admin`. Distinct from the SSRF / token-cap /
    /// high-volume reasons so SIEM/audit consumers can isolate the
    /// privileged-category-exfiltration attempt class. The acting principal's
    /// authority is evaluated live at the call site, never read from
    /// `snapshot_claims`.
    PrivilegedCategoryRequiresAdmin,
    /// Subject violates the NATS subject grammar.
    InvalidNatsSubject,
    /// URL parse / scheme validation failure.
    InvalidWebhookUrl,
    /// `(owner_user_id, name)` unique-constraint violation.
    DuplicateName,
}

// ---------------------------------------------------------------------------
// Validation functions
// ---------------------------------------------------------------------------

/// Maximum operator-facing label length (matches the
/// `subscriptions.name VARCHAR(255)` column).
const NAME_MAX_LEN: usize = 255;

/// Maximum free-form description length (matches the
/// `subscriptions_description_length_check` CHECK constraint).
const DESCRIPTION_MAX_LEN: usize = 1024;

/// Validate the operator-facing label (`Subscription.name`).
///
/// Returns `Err(DomainError::Validation)` when:
/// - `name` is empty, OR
/// - `name.len()` (UTF-8 bytes) exceeds [`NAME_MAX_LEN`] (255).
pub fn validate_name(name: &str) -> DomainResult<()> {
    if name.is_empty() {
        return Err(DomainError::Validation(
            "subscription name must not be empty".into(),
        ));
    }
    if name.len() > NAME_MAX_LEN {
        return Err(DomainError::Validation(format!(
            "subscription name exceeds {NAME_MAX_LEN} bytes"
        )));
    }
    Ok(())
}

/// Validate the optional description (`Subscription.description`).
///
/// Returns `Err(DomainError::Validation)` when `Some(d)` and
/// `d.len()` (UTF-8 bytes) exceeds [`DESCRIPTION_MAX_LEN`] (1024).
/// `None` is always accepted.
pub fn validate_description(d: Option<&str>) -> DomainResult<()> {
    if let Some(text) = d {
        if text.len() > DESCRIPTION_MAX_LEN {
            return Err(DomainError::Validation(format!(
                "subscription description exceeds {DESCRIPTION_MAX_LEN} bytes"
            )));
        }
    }
    Ok(())
}

/// Validate a NATS JetStream subject against the per-segment grammar.
///
/// Accepts: `[a-zA-Z0-9._-]+(\.[a-zA-Z0-9._-]+)*` — one or more dot-separated
/// segments where each segment is non-empty and uses ASCII alphanumerics,
/// dot, underscore, or hyphen. Rejects wildcards (`*`, `>`), empty segments,
/// and the empty subject. Implemented as a character walk — no regex crate
/// (`hort-domain` is dependency-minimal).
pub fn validate_nats_subject(subject: &str) -> DomainResult<()> {
    if subject.is_empty() {
        return Err(DomainError::Validation(
            "NATS subject must not be empty".into(),
        ));
    }
    let mut segment_len = 0usize;
    for ch in subject.chars() {
        if ch == '.' {
            if segment_len == 0 {
                return Err(DomainError::Validation(
                    "NATS subject must not contain empty segments".into(),
                ));
            }
            segment_len = 0;
            continue;
        }
        if !is_valid_subject_char(ch) {
            return Err(DomainError::Validation(format!(
                "NATS subject contains invalid character: {ch:?}"
            )));
        }
        segment_len += 1;
    }
    if segment_len == 0 {
        return Err(DomainError::Validation(
            "NATS subject must not end with '.'".into(),
        ));
    }
    Ok(())
}

/// `true` when `ch` is one of `[a-zA-Z0-9_-]`.
///
/// Wildcards (`*`, `>`) and any other character return `false`.
fn is_valid_subject_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

/// Validate the webhook URL scheme.
///
/// Returns `Err(DomainError::Validation)` when:
/// - `scheme` is not `https`, AND
/// - `allow_plaintext` is `false` (so `http://` is rejected by default).
///
/// `allow_plaintext = true` admits both `http://` and `https://`. Any other
/// scheme is rejected unconditionally. The constructor cannot perform
/// SSRF checks — that's I/O and lives in
/// [`crate::ports::webhook_target_guard::WebhookTargetGuard`].
pub fn validate_webhook_url(url: &Url, allow_plaintext: bool) -> DomainResult<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_plaintext => Ok(()),
        "http" => Err(DomainError::Validation(
            "plaintext webhook URL rejected (HORT_WEBHOOK_ALLOW_PLAINTEXT=false)".into(),
        )),
        other => Err(DomainError::Validation(format!(
            "unsupported webhook URL scheme: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::api_token::TokenKind;
    use crate::entities::artifact::QuarantineStatus;
    use crate::entities::mutable_ref::RefTarget;
    use crate::entities::rbac::Permission;
    use crate::entities::repository::RepositoryFormat;
    use crate::entities::scan_policy::SeverityThreshold;
    use crate::events::{Actor, ApiActor, StreamId};
    use crate::events::{
        AdminStatusChanged, ApiTokenIssuanceDenied, ApiTokenIssued, ApiTokenRevoked, ApiTokenUsed,
        ApprovalDecided, ApprovalDecision, ApprovalRequested, ArtifactBecameVulnerable,
        ArtifactCorrupted, ArtifactDownloaded, ArtifactExpired, ArtifactGroupInitiated,
        ArtifactGroupMemberAdded, ArtifactGroupMemberRemoved, ArtifactGroupPrimaryRoleAssigned,
        ArtifactIngested, ArtifactPromoted, ArtifactPurged, ArtifactQuarantined,
        ArtifactReEvaluated, ArtifactRejected, ArtifactReleased, AuthenticationAttempted,
        CasIntegrityMismatch, ChecksumMismatch, ChecksumVerified, ClaimMappingApplied,
        ClaimMappingRevoked, CurationActionTag, CurationApplied, CurationTrigger,
        DenialReason as TokenDenialReason, DownloadActor, ExclusionAdded, ExclusionRemoved,
        FilterSummary, GrantSubjectRecord, IngestSource, OidcKeyRotated, PermissionGrantApplied,
        PermissionGrantRevoked, PolicyArchived, PolicyCreated, PolicyEvaluated, PolicyField,
        PolicyResult, PolicyScope, PolicyUpdated, PromotionRejected, PromotionRequested, RefMoved,
        RefRetired, RejectionReason, ReleaseReason, RepositoryScopeKind,
        RepositoryUpstreamMappingChanged, RevokeReason, ScanCompleted, ScanRequested,
        SeveritySummary, SubscriptionCreated, SubscriptionCreationDenied, SubscriptionDeleted,
        SubscriptionDisabled, SubscriptionPaused, SubscriptionResumed, SubscriptionUpdated,
        TargetKindWire, TaskFailed, TaskInvoked, UpstreamMappingChange,
    };
    use crate::retention::ExpirationReason;
    use crate::types::{ArtifactCoords, ContentHash, Finding};
    use chrono::Utc;

    fn sha256() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    fn persisted(event: DomainEvent) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(Uuid::new_v4()),
            stream_position: 0,
            global_position: 0,
            event,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    fn artifact_ingested(repo: Uuid) -> DomainEvent {
        DomainEvent::ArtifactIngested(ArtifactIngested {
            artifact_id: Uuid::new_v4(),
            repository_id: repo,
            name: "pkg".into(),
            version: Some("1.0".into()),
            sha256: sha256(),
            size_bytes: 1,
            source: IngestSource::Direct,
            metadata: serde_json::Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        })
    }

    // -------- SubscriptionId / equality --------

    #[test]
    fn subscription_id_eq_and_clone() {
        let uid = Uuid::new_v4();
        let a = SubscriptionId(uid);
        let b = SubscriptionId(uid);
        let cloned = a;
        assert_eq!(a, b);
        assert_eq!(a, cloned);
        assert_ne!(a, SubscriptionId(Uuid::new_v4()));
    }

    // -------- validate_name --------

    #[test]
    fn validate_name_accepts_ordinary() {
        validate_name("ci-replicator").unwrap();
    }

    #[test]
    fn validate_name_rejects_empty() {
        let err = validate_name("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn validate_name_accepts_at_limit() {
        let s = "x".repeat(NAME_MAX_LEN);
        validate_name(&s).unwrap();
    }

    #[test]
    fn validate_name_rejects_over_limit() {
        let s = "x".repeat(NAME_MAX_LEN + 1);
        let err = validate_name(&s).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -------- validate_description --------

    #[test]
    fn validate_description_accepts_none() {
        validate_description(None).unwrap();
    }

    #[test]
    fn validate_description_accepts_empty_some() {
        validate_description(Some("")).unwrap();
    }

    #[test]
    fn validate_description_accepts_at_limit() {
        let s = "y".repeat(DESCRIPTION_MAX_LEN);
        validate_description(Some(&s)).unwrap();
    }

    #[test]
    fn validate_description_rejects_over_limit() {
        let s = "y".repeat(DESCRIPTION_MAX_LEN + 1);
        let err = validate_description(Some(&s)).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -------- validate_nats_subject --------

    #[test]
    fn nats_subject_accepts_single_segment() {
        validate_nats_subject("events").unwrap();
    }

    #[test]
    fn nats_subject_accepts_multi_segment() {
        validate_nats_subject("hort.events.artifact-promoted").unwrap();
    }

    #[test]
    fn nats_subject_accepts_underscore_and_hyphen() {
        validate_nats_subject("hort_events.replicator-1").unwrap();
    }

    #[test]
    fn nats_subject_rejects_empty() {
        let err = validate_nats_subject("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn nats_subject_rejects_star_wildcard() {
        let err = validate_nats_subject("hort.*.events").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn nats_subject_rejects_gt_wildcard() {
        let err = validate_nats_subject("hort.events.>").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn nats_subject_rejects_empty_leading_segment() {
        let err = validate_nats_subject(".hort.events").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn nats_subject_rejects_empty_internal_segment() {
        let err = validate_nats_subject("hort..events").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn nats_subject_rejects_trailing_dot() {
        let err = validate_nats_subject("hort.events.").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn nats_subject_rejects_space() {
        let err = validate_nats_subject("hort events").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn nats_subject_rejects_unicode() {
        let err = validate_nats_subject("horté.events").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -------- validate_webhook_url --------

    #[test]
    fn webhook_url_https_always_ok() {
        let u: Url = "https://example.com/hook".parse().unwrap();
        validate_webhook_url(&u, false).unwrap();
        validate_webhook_url(&u, true).unwrap();
    }

    #[test]
    fn webhook_url_http_rejected_by_default() {
        let u: Url = "http://example.com/hook".parse().unwrap();
        let err = validate_webhook_url(&u, false).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn webhook_url_http_allowed_with_opt_in() {
        let u: Url = "http://example.com/hook".parse().unwrap();
        validate_webhook_url(&u, true).unwrap();
    }

    #[test]
    fn webhook_url_rejects_unknown_scheme() {
        let u: Url = "ftp://example.com/".parse().unwrap();
        let err_off = validate_webhook_url(&u, false).unwrap_err();
        let err_on = validate_webhook_url(&u, true).unwrap_err();
        assert!(matches!(err_off, DomainError::Validation(_)));
        assert!(matches!(err_on, DomainError::Validation(_)));
    }

    // -------- EventTypeFilter::matches --------

    #[test]
    fn event_type_filter_all_short_circuits_true() {
        let ev = persisted(artifact_ingested(Uuid::new_v4()));
        assert!(EventTypeFilter::All.matches(&ev));
    }

    #[test]
    fn event_type_filter_some_matches_listed_kind() {
        let ev = persisted(artifact_ingested(Uuid::new_v4()));
        let f = EventTypeFilter::Some(vec![EventTypeKind::ArtifactIngested]);
        assert!(f.matches(&ev));
    }

    #[test]
    fn event_type_filter_some_rejects_unlisted_kind() {
        let ev = persisted(artifact_ingested(Uuid::new_v4()));
        let f = EventTypeFilter::Some(vec![EventTypeKind::ArtifactPromoted]);
        assert!(!f.matches(&ev));
    }

    #[test]
    fn event_type_filter_some_empty_never_matches() {
        let ev = persisted(artifact_ingested(Uuid::new_v4()));
        let f = EventTypeFilter::Some(vec![]);
        assert!(!f.matches(&ev));
    }

    // -------- EventTypeKind::is_high_volume / HIGH_VOLUME_EVENT_TYPES --------

    #[test]
    fn high_volume_constants_are_the_three_documented() {
        assert_eq!(HIGH_VOLUME_EVENT_TYPES.len(), 3);
        assert!(HIGH_VOLUME_EVENT_TYPES.contains(&EventTypeKind::ArtifactDownloaded));
        assert!(HIGH_VOLUME_EVENT_TYPES.contains(&EventTypeKind::ApiTokenUsed));
        assert!(HIGH_VOLUME_EVENT_TYPES.contains(&EventTypeKind::AuthenticationAttempted));
    }

    #[test]
    fn is_high_volume_true_for_each_excluded_kind() {
        assert!(EventTypeKind::ArtifactDownloaded.is_high_volume());
        assert!(EventTypeKind::ApiTokenUsed.is_high_volume());
        assert!(EventTypeKind::AuthenticationAttempted.is_high_volume());
    }

    #[test]
    fn is_high_volume_false_for_lifecycle_kinds() {
        assert!(!EventTypeKind::ArtifactIngested.is_high_volume());
        assert!(!EventTypeKind::ArtifactPromoted.is_high_volume());
        assert!(!EventTypeKind::ApiTokenIssued.is_high_volume());
    }

    // -------- EventTypeKind::of / repository_id — exhaustive coverage --------

    /// Build one minimal-valid `DomainEvent` per variant. The returned vec
    /// length therefore must match the `DomainEvent` variant count, and
    /// every arm of `EventTypeKind::of` / `EventTypeKind::repository_id`
    /// is exercised below.
    fn one_of_each_domain_event(repo: Uuid) -> Vec<(DomainEvent, EventTypeKind, Option<Uuid>)> {
        vec![
            (
                artifact_ingested(repo),
                EventTypeKind::ArtifactIngested,
                Some(repo),
            ),
            (
                DomainEvent::ChecksumVerified(ChecksumVerified {
                    artifact_id: Uuid::nil(),
                    algorithm: crate::types::HashAlgorithm::Sha256,
                    upstream_value: sha256().to_string(),
                    computed_value: sha256().to_string(),
                }),
                EventTypeKind::ChecksumVerified,
                None,
            ),
            (
                DomainEvent::ChecksumMismatch(ChecksumMismatch {
                    repository_id: repo,
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
                EventTypeKind::ChecksumMismatch,
                Some(repo),
            ),
            (
                DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                    artifact_id: Uuid::nil(),
                    quarantine_window_start: Utc::now(),
                }),
                EventTypeKind::ArtifactQuarantined,
                None,
            ),
            (
                DomainEvent::ScanRequested(ScanRequested {
                    artifact_id: Uuid::nil(),
                    scanner: "trivy".into(),
                }),
                EventTypeKind::ScanRequested,
                None,
            ),
            (
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
                EventTypeKind::ScanCompleted,
                None,
            ),
            (
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
                        informational_class: None,
                    }],
                    previously_clean_at: Utc::now(),
                }),
                EventTypeKind::ArtifactBecameVulnerable,
                None,
            ),
            (
                DomainEvent::ArtifactReleased(ArtifactReleased {
                    artifact_id: Uuid::nil(),
                    released_by: ReleaseReason::Timer,
                    released_by_user_id: None,
                    justification: None,
                }),
                EventTypeKind::ArtifactReleased,
                None,
            ),
            (
                DomainEvent::ArtifactRejected(ArtifactRejected {
                    artifact_id: Uuid::nil(),
                    rejected_by: RejectionReason::Scanner,
                    reason: "CVE-2024-0001".into(),
                }),
                EventTypeKind::ArtifactRejected,
                None,
            ),
            (
                DomainEvent::ArtifactReEvaluated(ArtifactReEvaluated {
                    artifact_id: Uuid::nil(),
                    policy_id: Uuid::nil(),
                    trigger_exclusion_id: Uuid::nil(),
                    previous_status: QuarantineStatus::Rejected,
                    new_status: QuarantineStatus::Released,
                }),
                EventTypeKind::ArtifactReEvaluated,
                None,
            ),
            (
                DomainEvent::PromotionRequested(PromotionRequested {
                    artifact_id: Uuid::nil(),
                    source_repository_id: Uuid::nil(),
                    target_repository_id: Uuid::nil(),
                }),
                EventTypeKind::PromotionRequested,
                None,
            ),
            (
                DomainEvent::PolicyEvaluated(PolicyEvaluated {
                    artifact_id: Uuid::nil(),
                    policy_id: Uuid::nil(),
                    result: PolicyResult::Pass,
                    violations: vec![],
                }),
                EventTypeKind::PolicyEvaluated,
                None,
            ),
            (
                DomainEvent::ApprovalRequested(ApprovalRequested {
                    artifact_id: Uuid::nil(),
                    source_repository_id: Uuid::nil(),
                    target_repository_id: Uuid::nil(),
                }),
                EventTypeKind::ApprovalRequested,
                None,
            ),
            (
                DomainEvent::ApprovalDecided(ApprovalDecided {
                    artifact_id: Uuid::nil(),
                    decision: ApprovalDecision::Approved,
                    notes: None,
                }),
                EventTypeKind::ApprovalDecided,
                None,
            ),
            (
                DomainEvent::ArtifactPromoted(ArtifactPromoted {
                    artifact_id: Uuid::nil(),
                    source_repository_id: Uuid::nil(),
                    target_repository_id: Uuid::nil(),
                }),
                EventTypeKind::ArtifactPromoted,
                None,
            ),
            (
                DomainEvent::PromotionRejected(PromotionRejected {
                    artifact_id: Uuid::nil(),
                    source_repository_id: Uuid::nil(),
                    target_repository_id: Uuid::nil(),
                    reason: "policy".into(),
                }),
                EventTypeKind::PromotionRejected,
                None,
            ),
            (
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
                EventTypeKind::ArtifactExpired,
                None,
            ),
            (
                DomainEvent::ArtifactPurged(ArtifactPurged {
                    artifact_id: Uuid::nil(),
                    content_hash: sha256(),
                    refs_remaining: 0,
                    purged_at: Utc::now(),
                }),
                EventTypeKind::ArtifactPurged,
                None,
            ),
            (
                DomainEvent::ArtifactDownloaded(ArtifactDownloaded {
                    artifact_id: Uuid::nil(),
                    repository_id: repo,
                    content_hash: sha256(),
                    actor: DownloadActor::Anonymous,
                    occurred_at: Utc::now(),
                }),
                EventTypeKind::ArtifactDownloaded,
                // B12: the payload carries repository_id directly (the
                // stream-sharding key) — repository_id() returns it.
                Some(repo),
            ),
            (
                DomainEvent::PolicyCreated(PolicyCreated {
                    policy_id: Uuid::nil(),
                    name: "default".into(),
                    scope: PolicyScope::Global,
                    config_snapshot: serde_json::json!({}),
                }),
                EventTypeKind::PolicyCreated,
                None,
            ),
            (
                DomainEvent::PolicyUpdated(PolicyUpdated {
                    policy_id: Uuid::nil(),
                    field: PolicyField::Name,
                    previous_value: serde_json::json!("old"),
                    new_value: serde_json::json!("new"),
                }),
                EventTypeKind::PolicyUpdated,
                None,
            ),
            (
                DomainEvent::ExclusionAdded(ExclusionAdded {
                    policy_id: Uuid::nil(),
                    exclusion_id: Uuid::nil(),
                    cve_id: "CVE-2024-0001".into(),
                    package_pattern: None,
                    scope: PolicyScope::Global,
                    reason: "false positive".into(),
                    expires_at: None,
                }),
                EventTypeKind::ExclusionAdded,
                None,
            ),
            (
                DomainEvent::ExclusionRemoved(ExclusionRemoved {
                    policy_id: Uuid::nil(),
                    exclusion_id: Uuid::nil(),
                    reason: "revoked".into(),
                }),
                EventTypeKind::ExclusionRemoved,
                None,
            ),
            (
                DomainEvent::PolicyArchived(PolicyArchived {
                    policy_id: Uuid::nil(),
                }),
                EventTypeKind::PolicyArchived,
                None,
            ),
            (
                DomainEvent::CasIntegrityMismatch(CasIntegrityMismatch {
                    content_hash: sha256(),
                    backend: "filesystem".into(),
                    observed_hash: sha256(),
                }),
                EventTypeKind::CasIntegrityMismatch,
                None,
            ),
            (
                DomainEvent::ArtifactCorrupted(ArtifactCorrupted {
                    artifact_id: Uuid::nil(),
                    computed_hash: sha256(),
                    expected_hash: sha256(),
                    detected_at: Utc::now(),
                }),
                EventTypeKind::ArtifactCorrupted,
                None,
            ),
            (
                DomainEvent::RefMoved(RefMoved {
                    ref_id: Uuid::nil(),
                    repository_id: repo,
                    namespace: "library/nginx".into(),
                    ref_name: "latest".into(),
                    from: None,
                    to: RefTarget::ContentHash(sha256()),
                }),
                EventTypeKind::RefMoved,
                Some(repo),
            ),
            (
                DomainEvent::RefRetired(RefRetired {
                    ref_id: Uuid::nil(),
                    repository_id: repo,
                    namespace: "library/nginx".into(),
                    ref_name: "latest".into(),
                    last_target: RefTarget::ContentHash(sha256()),
                }),
                EventTypeKind::RefRetired,
                Some(repo),
            ),
            (
                DomainEvent::ArtifactGroupInitiated(ArtifactGroupInitiated {
                    group_id: Uuid::nil(),
                    repository_id: repo,
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
                EventTypeKind::ArtifactGroupInitiated,
                Some(repo),
            ),
            (
                DomainEvent::ArtifactGroupMemberAdded(ArtifactGroupMemberAdded {
                    group_id: Uuid::nil(),
                    role: "jar".into(),
                    artifact_id: Uuid::nil(),
                }),
                EventTypeKind::ArtifactGroupMemberAdded,
                None,
            ),
            (
                DomainEvent::ArtifactGroupMemberRemoved(ArtifactGroupMemberRemoved {
                    group_id: Uuid::nil(),
                    artifact_id: Uuid::nil(),
                    reason: Some("admin".into()),
                }),
                EventTypeKind::ArtifactGroupMemberRemoved,
                None,
            ),
            (
                DomainEvent::ArtifactGroupPrimaryRoleAssigned(ArtifactGroupPrimaryRoleAssigned {
                    group_id: Uuid::nil(),
                    primary_role: "pom".into(),
                }),
                EventTypeKind::ArtifactGroupPrimaryRoleAssigned,
                None,
            ),
            (
                DomainEvent::CurationApplied(CurationApplied {
                    repository_id: repo,
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
                EventTypeKind::CurationApplied,
                Some(repo),
            ),
            (
                DomainEvent::AuthenticationAttempted(AuthenticationAttempted {
                    client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 42)),
                    result: "local_invalid_credentials".into(),
                    external_id_if_decoded: Some("alice".into()),
                    at: Utc::now(),
                }),
                EventTypeKind::AuthenticationAttempted,
                None,
            ),
            (
                DomainEvent::OidcKeyRotated(OidcKeyRotated {
                    kid_added: "kid-new".into(),
                    kid_evicted: Some("kid-old".into()),
                    fetched_at: Utc::now(),
                }),
                EventTypeKind::OidcKeyRotated,
                None,
            ),
            (
                DomainEvent::AdminStatusChanged(AdminStatusChanged {
                    user_id: Uuid::nil(),
                    external_id: "realm-users:abc-123".into(),
                    granted: true,
                    at: Utc::now(),
                }),
                EventTypeKind::AdminStatusChanged,
                None,
            ),
            (
                DomainEvent::ClaimMappingApplied(ClaimMappingApplied {
                    mapping_id: Uuid::nil(),
                    idp_group: "ops-team".into(),
                    claim: "admin".into(),
                }),
                EventTypeKind::ClaimMappingApplied,
                None,
            ),
            (
                DomainEvent::ClaimMappingRevoked(ClaimMappingRevoked {
                    mapping_id: Uuid::nil(),
                    idp_group: "ops-team".into(),
                    claim: "admin".into(),
                }),
                EventTypeKind::ClaimMappingRevoked,
                None,
            ),
            (
                DomainEvent::PermissionGrantApplied(PermissionGrantApplied {
                    grant_id: Uuid::nil(),
                    subject: GrantSubjectRecord::Claims {
                        required: vec!["developer".into()],
                    },
                    permission: Permission::Read,
                    repository_id: Some(repo),
                }),
                EventTypeKind::PermissionGrantApplied,
                Some(repo),
            ),
            (
                DomainEvent::PermissionGrantRevoked(PermissionGrantRevoked {
                    grant_id: Uuid::nil(),
                    subject: GrantSubjectRecord::User {
                        user_id: Uuid::nil(),
                    },
                    permission: Permission::Read,
                    repository_id: None,
                }),
                EventTypeKind::PermissionGrantRevoked,
                None,
            ),
            (
                DomainEvent::RepositoryUpstreamMappingChanged(RepositoryUpstreamMappingChanged {
                    mapping_id: Uuid::nil(),
                    repository_id: repo,
                    change: UpstreamMappingChange::Updated,
                    previous_secret_ref: Some("env_var:OLD_TOKEN".into()),
                    new_secret_ref: Some("env_var:NEW_TOKEN".into()),
                    previous_url: Some("https://registry-1.docker.io".into()),
                    new_url: Some("https://registry-1.docker.io".into()),
                }),
                EventTypeKind::RepositoryUpstreamMappingChanged,
                Some(repo),
            ),
            (
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
                EventTypeKind::ApiTokenIssued,
                None,
            ),
            (
                DomainEvent::ApiTokenRevoked(ApiTokenRevoked {
                    token_id: Uuid::nil(),
                    user_id: Uuid::nil(),
                    revoked_by_admin_id: None,
                    reason: RevokeReason::OperatorRequest,
                    at: Utc::now(),
                }),
                EventTypeKind::ApiTokenRevoked,
                None,
            ),
            (
                DomainEvent::ApiTokenIssuanceDenied(ApiTokenIssuanceDenied {
                    target_user_id: Uuid::nil(),
                    requested_kind: TokenKind::Pat,
                    requested_permissions: vec![Permission::Admin],
                    requested_repository_ids: None,
                    denial_reason: TokenDenialReason::AdminTokenDisallowed,
                    at: Utc::now(),
                }),
                EventTypeKind::ApiTokenIssuanceDenied,
                None,
            ),
            (
                DomainEvent::ApiTokenUsed(ApiTokenUsed {
                    token_id: Uuid::nil(),
                    user_id: Uuid::nil(),
                    kind: TokenKind::Pat,
                    occurred_at: Utc::now(),
                }),
                EventTypeKind::ApiTokenUsed,
                // B13: a token use has NO repository association — the
                // explicit contrast to B12's ArtifactDownloaded → Some(repo).
                None,
            ),
            (
                DomainEvent::TaskInvoked(TaskInvoked {
                    task_job_id: Uuid::nil(),
                    kind: "noop".into(),
                    params_digest: "0".repeat(64),
                    duplicate_of: None,
                }),
                EventTypeKind::TaskInvoked,
                None,
            ),
            (
                DomainEvent::TaskFailed(TaskFailed {
                    task_job_id: Uuid::nil(),
                    kind: "noop".into(),
                    reason: "db connection lost".into(),
                    final_attempt: false,
                }),
                EventTypeKind::TaskFailed,
                None,
            ),
            (
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
                EventTypeKind::SubscriptionCreated,
                None,
            ),
            (
                DomainEvent::SubscriptionCreationDenied(SubscriptionCreationDenied {
                    requesting_user_id: Uuid::nil(),
                    requested_target_kind: TargetKindWire::NatsJetStream,
                    attempted_filter_summary: FilterSummary {
                        categories: vec!["artifact".into()],
                        event_type_count: 0,
                        repository_scope_kind: RepositoryScopeKind::Some,
                        predicate_hash: [0; 32],
                    },
                    denial_reason: SubscriptionDenialReason::DuplicateName,
                    at: Utc::now(),
                }),
                EventTypeKind::SubscriptionCreationDenied,
                None,
            ),
            (
                DomainEvent::SubscriptionUpdated(SubscriptionUpdated {
                    subscription_id: Uuid::nil(),
                    owner_user_id: Uuid::nil(),
                    changed_fields: vec!["filter".into()],
                    snapshot_claims_count: 0,
                    at: Utc::now(),
                }),
                EventTypeKind::SubscriptionUpdated,
                None,
            ),
            (
                DomainEvent::SubscriptionPaused(SubscriptionPaused {
                    subscription_id: Uuid::nil(),
                    owner_user_id: Uuid::nil(),
                    at: Utc::now(),
                }),
                EventTypeKind::SubscriptionPaused,
                None,
            ),
            (
                DomainEvent::SubscriptionResumed(SubscriptionResumed {
                    subscription_id: Uuid::nil(),
                    owner_user_id: Uuid::nil(),
                    at: Utc::now(),
                }),
                EventTypeKind::SubscriptionResumed,
                None,
            ),
            (
                DomainEvent::SubscriptionDeleted(SubscriptionDeleted {
                    subscription_id: Uuid::nil(),
                    owner_user_id: Uuid::nil(),
                    at: Utc::now(),
                }),
                EventTypeKind::SubscriptionDeleted,
                None,
            ),
            (
                DomainEvent::SubscriptionDisabled(SubscriptionDisabled {
                    subscription_id: Uuid::nil(),
                    owner_user_id: Uuid::nil(),
                    reason: DisableReason::DeliveryFailureBudgetExhausted,
                    at: Utc::now(),
                }),
                EventTypeKind::SubscriptionDisabled,
                None,
            ),
        ]
    }

    #[test]
    fn event_type_kind_of_and_repository_id_match_table() {
        let repo = Uuid::new_v4();
        let entries = one_of_each_domain_event(repo);
        for (event, expected_kind, expected_repo) in &entries {
            assert_eq!(
                EventTypeKind::of(event),
                *expected_kind,
                "event_type_kind::of mismatch for {expected_kind:?}",
            );
            assert_eq!(
                EventTypeKind::repository_id(event),
                *expected_repo,
                "event_type_kind::repository_id mismatch for {expected_kind:?}",
            );
        }
    }

    #[test]
    fn permission_grant_applied_with_no_repo_returns_none() {
        let ev = DomainEvent::PermissionGrantApplied(PermissionGrantApplied {
            grant_id: Uuid::nil(),
            subject: GrantSubjectRecord::Claims {
                required: vec!["developer".into()],
            },
            permission: Permission::Read,
            repository_id: None,
        });
        assert_eq!(EventTypeKind::repository_id(&ev), None);
    }

    #[test]
    fn permission_grant_revoked_with_repo_returns_some() {
        let repo = Uuid::new_v4();
        let ev = DomainEvent::PermissionGrantRevoked(PermissionGrantRevoked {
            grant_id: Uuid::nil(),
            subject: GrantSubjectRecord::User {
                user_id: Uuid::nil(),
            },
            permission: Permission::Read,
            repository_id: Some(repo),
        });
        assert_eq!(EventTypeKind::repository_id(&ev), Some(repo));
    }

    // -------- RepositoryScope smoke --------

    #[test]
    fn repository_scope_clone_and_eq() {
        let a = RepositoryScope::OwnedByActor;
        let b = a.clone();
        assert_eq!(a, b);
        let list = RepositoryScope::Some(vec![Uuid::nil()]);
        assert_eq!(list.clone(), list);
        assert_eq!(RepositoryScope::All, RepositoryScope::All);
        assert_ne!(RepositoryScope::All, RepositoryScope::OwnedByActor);
    }

    // -------- SubscriptionTarget smoke --------

    fn webhook_secret_ref() -> SecretRef {
        use crate::ports::secret_port::SecretSource;
        SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        }
    }

    #[test]
    fn subscription_target_webhook_clone_and_eq() {
        let url: Url = "https://example.com/h".parse().unwrap();
        let a = SubscriptionTarget::Webhook {
            url: url.clone(),
            secret_ref: webhook_secret_ref(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn subscription_target_webhook_carries_secret_ref_not_a_hash() {
        // The webhook target must carry a
        // `SecretRef` locator, NOT the secret material (previously the
        // Argon2id PHC string, which doubled as the HMAC key). The
        // discriminating assertion: the variant destructures to a
        // `SecretRef` whose `(source, location)` is the env-var locator
        // — the secret bytes are nowhere on the row.
        use crate::ports::secret_port::SecretSource;
        let url: Url = "https://example.com/h".parse().unwrap();
        let target = SubscriptionTarget::Webhook {
            url,
            secret_ref: webhook_secret_ref(),
        };
        match target {
            SubscriptionTarget::Webhook { secret_ref, .. } => {
                assert_eq!(secret_ref.source, SecretSource::EnvVar);
                assert_eq!(secret_ref.location, "HORT_WEBHOOK_SECRET");
            }
            SubscriptionTarget::NatsJetStream { .. } => panic!("expected Webhook variant"),
        }
    }

    #[test]
    fn subscription_target_nats_clone_and_eq() {
        let a = SubscriptionTarget::NatsJetStream {
            subject: "hort.events".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(
            a,
            SubscriptionTarget::NatsJetStream {
                subject: "hort.other".into(),
            }
        );
    }

    // -------- SubscriptionState / DisableReason --------

    #[test]
    fn subscription_state_active_paused_disabled_distinct() {
        let active = SubscriptionState::Active;
        let paused = SubscriptionState::Paused;
        let disabled = SubscriptionState::Disabled {
            reason: DisableReason::OperatorDisabled,
            since: Utc::now(),
        };
        assert_ne!(active, paused);
        assert_ne!(paused, disabled);
        assert_ne!(active, disabled);
        assert_eq!(active.clone(), active);
    }

    #[test]
    fn disable_reason_all_variants_distinct() {
        let a = DisableReason::OwnerDeactivated;
        let b = DisableReason::DeliveryFailureBudgetExhausted;
        let c = DisableReason::OperatorDisabled;
        let copied = a;
        assert_eq!(a, copied);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    // -------- SubscriptionFailure --------

    #[test]
    fn subscription_failure_round_trip_construction() {
        let f = SubscriptionFailure {
            at: Utc::now(),
            reason: NotifyFailureReason::Http5xx { status: 503 },
            consecutive_failures: 1,
        };
        let cloned = f.clone();
        assert_eq!(f, cloned);
    }

    // -------- SsrfBlockReason / SubscriptionDenialReason --------

    #[test]
    fn ssrf_block_reason_all_variants_distinct() {
        let a = SsrfBlockReason::IpLiteralNotRoutable;
        let b = SsrfBlockReason::DnsResolvedNotRoutable;
        let c = SsrfBlockReason::DnsResolutionFailed;
        let copied = a;
        assert_eq!(a, copied);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn subscription_denial_reason_variants_distinct_and_clone() {
        let variants = [
            SubscriptionDenialReason::UnsupportedEventType,
            SubscriptionDenialReason::RepoNotAuthorised,
            SubscriptionDenialReason::AdminScopeRequiresAdmin,
            SubscriptionDenialReason::AdminScopeRequiresUncappedToken,
            SubscriptionDenialReason::RepoScopeMustBeExplicit,
            SubscriptionDenialReason::RepoScopeExceedsTokenCap,
            SubscriptionDenialReason::PlaintextWebhookDisallowed,
            SubscriptionDenialReason::WebhookTargetNotRoutable {
                ssrf_block_reason: SsrfBlockReason::IpLiteralNotRoutable,
            },
            SubscriptionDenialReason::InvalidNatsSubject,
            SubscriptionDenialReason::InvalidWebhookUrl,
            SubscriptionDenialReason::DuplicateName,
        ];
        for (i, a) in variants.iter().enumerate() {
            let cloned = a.clone();
            assert_eq!(a, &cloned);
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "{i}!={j} should not be equal");
                }
            }
        }
    }

    #[test]
    fn webhook_target_not_routable_carries_inner_reason() {
        let a = SubscriptionDenialReason::WebhookTargetNotRoutable {
            ssrf_block_reason: SsrfBlockReason::DnsResolvedNotRoutable,
        };
        let b = SubscriptionDenialReason::WebhookTargetNotRoutable {
            ssrf_block_reason: SsrfBlockReason::DnsResolutionFailed,
        };
        assert_ne!(a, b);
    }

    // -------- Subscription construction smoke --------

    #[test]
    fn subscription_can_be_constructed_and_cloned() {
        let url: Url = "https://example.com/h".parse().unwrap();
        let sub = Subscription {
            id: SubscriptionId(Uuid::new_v4()),
            owner_user_id: Uuid::new_v4(),
            created_by_token_id: None,
            name: "ci".into(),
            description: Some("CI replicator".into()),
            target: SubscriptionTarget::Webhook {
                url,
                secret_ref: webhook_secret_ref(),
            },
            filter: SubscriptionFilter {
                categories: vec![StreamCategory::Artifact],
                event_types: EventTypeFilter::Some(vec![EventTypeKind::ArtifactPromoted]),
                repositories: RepositoryScope::OwnedByActor,
                named_predicates: vec![],
            },
            snapshot_claims: vec!["developer".into(), "team-alpha".into()],
            state: SubscriptionState::Active,
            last_delivered_position: None,
            last_failure: None,
            created_at: Utc::now(),
        };
        let cloned = sub.clone();
        assert_eq!(sub, cloned);
    }

    // -------- No-deserialize compile-time guards --------

    // None of the carrying subscription-domain types may implement
    // Deserialize. The adapter-side DTOs (postgres adapter's
    // `subscription_repo.rs`) handle JSONB; HTTP handler DTOs
    // (`hort-http-subscriptions`) handle wire input. Adding
    // `#[derive(Deserialize)]` to any of these is a review-blocking change
    // that this macro turns into a compile error.
    //
    // EXCEPTION: `DisableReason`, `SubscriptionDenialReason`, and
    // `SsrfBlockReason` deliberately DO derive `Serialize` + `Deserialize`
    // because they are the closed-enum discriminator payloads of the
    // subscription lifecycle events and must round-trip
    // through the event store JSONB. Same precedent as `RevokeReason` /
    // `DenialReason` in `api_token_events.rs`. They carry no PII, no URLs,
    // no secrets — only discriminator tags.
    static_assertions::assert_not_impl_any!(Subscription: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(SubscriptionTarget: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(SubscriptionFilter: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(EventTypeFilter: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(EventTypeKind: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(RepositoryScope: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(NamedPredicate: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(SubscriptionState: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(SubscriptionFailure: serde::de::DeserializeOwned);
}
