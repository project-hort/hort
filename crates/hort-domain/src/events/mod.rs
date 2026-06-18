//! Domain events — immutable facts recording state transitions.
//!
//! Events live in a closed enum hierarchy ([`DomainEvent`]) wrapped in a
//! [`PersistedEvent`] envelope that the event store assigns on append.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

mod api_token_events;
mod artifact_events;
mod artifact_group_events;
mod auth_events;
mod authorization_events;
mod cas_scrub_events;
mod chain;
mod checkpoint_build;
mod curation_events;
mod domain_event;
mod download_events;
mod oidc_issuer_events;
mod policy_events;
mod ref_events;
mod retention_events;
mod service_account_events;
mod subscription_events;
mod validation;

#[cfg(test)]
mod tests;

pub use api_token_events::*;
pub use artifact_events::*;
pub use artifact_group_events::*;
pub use auth_events::*;
pub use authorization_events::*;
pub use cas_scrub_events::*;
pub use chain::*;
pub use checkpoint_build::*;
pub use curation_events::*;
pub use domain_event::*;
pub use download_events::*;
pub use oidc_issuer_events::*;
pub use policy_events::*;
pub use ref_events::*;
pub use retention_events::*;
pub use service_account_events::*;
pub use subscription_events::*;

// ---------------------------------------------------------------------------
// StreamCategory / StreamId
// ---------------------------------------------------------------------------

/// The aggregate type for an event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum StreamCategory {
    Artifact,
    Policy,
    /// Audit-meta stream category. Wire form is `"admin"`;
    /// `StreamId::admin(uuid)` produces `"admin-<uuid>"` streams.
    ///
    /// The sole consumer is `StreamId::eventstore_retention()`:
    /// a single never-deleted audit-meta
    /// stream carrying `StreamSealed` retention tombstones.
    Admin,
    /// Mutable-ref lifecycle events (`RefMoved`, `RefRetired`).
    /// The category's wire form is `"ref"`; `StreamId::ref_(ref_id)` produces
    /// `"ref-<uuid>"` streams — one stream per ref. Each ref's history (moves
    /// plus retirement) is ordered within its own stream.
    Ref,
    /// Artifact-group lifecycle events
    /// (`ArtifactGroupInitiated`, `ArtifactGroupMemberAdded`,
    /// `ArtifactGroupMemberRemoved`, `ArtifactGroupPrimaryRoleAssigned`).
    /// The category's wire form is `"artifact_group"` — underscore-separated
    /// so `StreamId::FromStr`'s `split_once('-')` does not collide with the
    /// `"artifact"` prefix. `StreamId::artifact_group(group_id)` produces
    /// `"artifact_group-<uuid>"` streams — one stream per group. Every
    /// member-add / remove plus the initial creation and primary-role
    /// assignment land on the same stream, ordered within it.
    ArtifactGroup,
    /// Curation-decision audit events
    /// (`CurationApplied`). The category's wire form is `"curation"`;
    /// `StreamId::curation_per_repo(repository_id)` produces
    /// `"curation-<uuid>"` streams — one stream per repository. Both
    /// ingest-time `Warn` decisions and retroactive evaluation
    /// (`CurationTrigger::Retroactive`) hits land on the same per-repo
    /// stream, ordered by global position.
    Curation,
    /// Repository aggregate stream. The wire form
    /// is `"repository"`; `StreamId::repository(repository_id)` produces
    /// `"repository-<uuid>"` streams. The first event class on this
    /// aggregate is `ChecksumMismatch` — emitted by `ingest_verified`
    /// when an upstream-published checksum disagrees with the bytes on
    /// the wire (no artifact row is minted on the mismatch path, hence
    /// the repository, not the artifact, owns the audit trail). Future
    /// repo-scoped events (config changes, mapping failures) land here
    /// as they arise.
    Repository,
    /// Authentication-attempt audit streams
    /// (NIS2 Art. 21(2)(h)). The wire form is `"auth"`;
    /// [`StreamId::auth_attempts`] produces one stream per UTC date.
    /// Only failures land here; successes stay in tracing only (the
    /// audit-value-per-byte trade-off — every authenticated request
    /// would otherwise dominate stream volume). Throttled to ≤ 1
    /// append per 60s per `(client_ip_bucket, result)` tuple at the
    /// use-case layer; see `hort-app::metrics::client_ip_bucket`.
    AuthAttempts,
    /// Authorization-model mutation audit stream
    /// (NIS2 Art. 21(2)(h)). The wire form is
    /// `"authorization"`; [`StreamId::authorization`] produces one
    /// global stream (`authorization-<uuidv5("gitops")>`). The
    /// stream carries `ClaimMappingApplied` / `ClaimMappingRevoked`
    /// (and global `PermissionGrantApplied` / `PermissionGrantRevoked`)
    /// events emitted
    /// by `ApplyConfigUseCase::apply` whenever the gitops apply path
    /// mutates the global authorization model. The state itself
    /// stays in CRUD; this stream is audit-only attribution and does
    /// not drive a projection. Repo-scoped authz audit (per-repo
    /// permission grants, upstream mappings) lands on
    /// `StreamCategory::Repository`.
    Authorization,
    /// Per-user audit-attribution stream
    /// (native API tokens). The wire form is `"user"`;
    /// [`StreamId::user`] produces `"user-<uuid>"` streams — one
    /// stream per user.
    ///
    /// A dedicated category: the
    /// per-user streams pattern (`StreamCategory::Admin` is admin-only,
    /// not the per-user lifecycle for ordinary users) leaves no
    /// other variant that fits. `User` is the smallest
    /// well-justified deviation: it mirrors `Admin`'s shape (one
    /// stream per `users.id`), keeps every other category distinct,
    /// and is required by the `ApiTokenIssued` /
    /// `ApiTokenRevoked` (token-owner stream) and
    /// `ApiTokenIssuanceDenied` (requesting-actor stream).
    User,
    /// Opt-in per-`(repository, UTC-date)` download-audit streams.
    /// The wire form is
    /// `"download_audit"` — underscore-separated (NOT `download-audit`)
    /// so [`StreamId::FromStr`]'s `split_once('-')` does not split the
    /// category prefix; same discipline as `"artifact_group"`.
    /// [`StreamId::download_audit`] produces one stream per
    /// `(repository_id, UTC date)`. Only repositories with
    /// `download_audit_enabled = true` emit
    /// [`ArtifactDownloaded`] here; the event type stays in
    /// `HIGH_VOLUME_EVENT_TYPES` (subscription-excluded). The opt-in
    /// flag is the volume control — there is no throttle.
    DownloadAudit,
    /// Throttled per-`(token_id, UTC-date)` token-use audit streams.
    /// The wire form is
    /// `"token_use"` — underscore-separated (NOT `token-use`) so
    /// [`StreamId::FromStr`]'s `split_once('-')` does not split the
    /// category prefix at the first `-`; same discipline as
    /// `"artifact_group"` / `"download_audit"`.
    /// [`StreamId::token_use`] produces one stream per
    /// `(token_id, UTC date)`. [`ApiTokenUsed`] lands here on every
    /// successful PAT validation that wins the per-`token_id` 1-hour
    /// throttle; the event type stays in `HIGH_VOLUME_EVENT_TYPES`
    /// (subscription-excluded). The throttle is the volume control —
    /// contrast `DownloadAudit`'s opt-in flag.
    TokenUse,
    /// Event-sourced retention-policy lifecycle stream.
    /// The wire form is `"retention_policy"` —
    /// underscore-separated (NOT `retention-policy`) so
    /// [`StreamId::FromStr`]'s `split_once('-')` does not split the
    /// category prefix at the first `-`; same discipline as
    /// `"artifact_group"` / `"download_audit"` / `"token_use"`.
    /// [`StreamId::retention_policy`] produces one stream per
    /// retention-policy id. Carries
    /// [`DomainEvent::RetentionPolicyChanged`] (the
    /// `RetentionPolicyEvent` `Created` / `Updated` / `Archived` /
    /// `Evaluated`). A **dedicated** category, NOT a reuse of
    /// [`Self::Policy`] (scan-policy): retention and scan policy are a
    /// deliberate type divergence (`RetentionScope` is
    /// distinct from `events::PolicyScope`), and the scan-policy
    /// projection is structurally incompatible with a retention-policy
    /// predicate-tree projection. Privileged-category audit (grouped
    /// with `Policy` in [`Self::requires_admin`]).
    RetentionPolicy,
}

impl StreamCategory {
    /// Single source of truth for the
    /// privileged-category table: `true` for the `ADMIN_CATEGORIES`
    /// set (`Policy`, `Admin`, `Authorization`, `User`, `AuthAttempts`)
    /// — categories whose events expose the instance's RBAC / policy /
    /// token / auth mutation history and therefore require live
    /// `Permission::Admin` to read *or* subscribe to. `false` for the
    /// per-repo categories, where per-event repository-scope filtering
    /// applies instead.
    ///
    /// Lives in `hort-domain` (not the HTTP layer) because a
    /// private handler-side `category_requires_admin` is something
    /// `hort-app`
    /// (`SubscriptionUseCase`, the notification dispatcher) cannot call
    /// — `hort-http-events` depends on `hort-app`, so the reverse import
    /// would be a circular crate dependency *and* an
    /// application→inbound-adapter layering inversion. Drift between
    /// the events-read gate and the subscription gate is the bug class
    /// this single definition prevents.
    /// `hort-http-events::category_requires_admin` is now a thin
    /// delegator to this method (pinned by a delegation test).
    ///
    /// The match is exhaustive on purpose: a new `StreamCategory`
    /// variant fails to compile here until its admin-gate disposition
    /// is decided.
    #[must_use]
    pub fn requires_admin(&self) -> bool {
        match self {
            StreamCategory::Artifact
            | StreamCategory::ArtifactGroup
            | StreamCategory::Ref
            | StreamCategory::Curation
            | StreamCategory::Repository => false,
            StreamCategory::Policy
            | StreamCategory::Admin
            | StreamCategory::Authorization
            | StreamCategory::User
            | StreamCategory::AuthAttempts
            // B12: a download-audit stream aggregates every served
            // download for a repo+date — reading or subscribing to it
            // is a privileged cross-repo audit operation, grouped with
            // AuthAttempts / User. Per-event repo-scope filtering does
            // not apply (the whole stream is one repo's pull history,
            // but the read gate is admin-only audit access).
            | StreamCategory::DownloadAudit
            // A token-use stream is the per-token credential-
            // exercise history — reading or subscribing to it is a
            // privileged audit operation, grouped with AuthAttempts /
            // User / DownloadAudit (no per-event repo scope: token use
            // has no repository association).
            | StreamCategory::TokenUse
            // A retention-policy stream is RBAC/policy-mutation
            // history (predicate + scope changes that govern
            // destructive GC) — grouped with Policy / Authorization /
            // Admin. Reading or subscribing to it is a privileged
            // policy-audit operation; no per-event repo scope applies.
            | StreamCategory::RetentionPolicy => true,
        }
    }
}

/// Identifies an event stream.
///
/// Convention: `"{category}-{entity_id}"` when serialised as a string.
/// - Artifact streams: `"artifact-{artifact_id}"`
/// - Policy streams: `"policy-{policy_id}"`
/// - Admin streams: `"admin-{uuid}"` — audit-meta (retention sealing)
///
/// The category prefix enables category-based subscriptions (e.g. subscribe
/// to all `artifact-*` streams for the quarantine projection).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct StreamId {
    pub category: StreamCategory,
    pub entity_id: Uuid,
}

impl StreamId {
    pub fn artifact(id: Uuid) -> Self {
        Self {
            category: StreamCategory::Artifact,
            entity_id: id,
        }
    }

    pub fn policy(id: Uuid) -> Self {
        Self {
            category: StreamCategory::Policy,
            entity_id: id,
        }
    }

    /// Construct a retention-policy lifecycle stream for the given
    /// retention-policy id.
    ///
    /// Used by `RetentionPolicyUseCase` (the gitops-authored
    /// create/update/archive path) to append
    /// [`DomainEvent::RetentionPolicyChanged`] (the
    /// `RetentionPolicyEvent`) under a per-policy stream. The wire
    /// form is `"retention_policy-<uuid>"`; the underscore in the
    /// category prefix keeps `StreamId::FromStr`'s `split_once('-')`
    /// from confusing it with a `policy-<uuid>` (scan-policy)
    /// stream. Dedicated category — see the
    /// [`StreamCategory::RetentionPolicy`] docstring for why this is
    /// not a reuse of [`StreamCategory::Policy`].
    pub fn retention_policy(id: Uuid) -> Self {
        Self {
            category: StreamCategory::RetentionPolicy,
            entity_id: id,
        }
    }

    /// Construct an admin-category stream for an arbitrary `uuid`.
    ///
    /// This convenience
    /// constructor is unused by the production code path —
    /// `eventstore_retention()` is the only
    /// emitter on `StreamCategory::Admin` and constructs its stream
    /// directly. The constructor is retained so the `StreamId::FromStr`
    /// round-trip for `"admin-<uuid>"` wire forms has a symmetric
    /// builder; tests in this module exercise it.
    pub fn admin(id: Uuid) -> Self {
        Self {
            category: StreamCategory::Admin,
            entity_id: id,
        }
    }

    /// Construct a ref-category stream for the given ref id.
    ///
    /// Used by `RefLifecyclePort` implementations to emit `RefMoved` /
    /// `RefRetired` events under a per-ref stream. The `ref_id` is the
    /// `mutable_refs.id` UUID; each ref's history — every move plus its
    /// eventual retirement — is ordered within its own stream.
    ///
    /// The trailing underscore disambiguates from the `ref` keyword.
    pub fn ref_(id: Uuid) -> Self {
        Self {
            category: StreamCategory::Ref,
            entity_id: id,
        }
    }

    /// Construct an artifact-group stream for the given group id.
    ///
    /// Used by `ArtifactGroupLifecyclePort` implementations to emit
    /// `ArtifactGroupInitiated` / `ArtifactGroupMemberAdded` /
    /// `ArtifactGroupMemberRemoved` / `ArtifactGroupPrimaryRoleAssigned`
    /// events under a per-group stream. The stream wire form is
    /// `"artifact_group-<uuid>"`; the underscore in the category prefix is
    /// what keeps `StreamId::FromStr`'s `split_once('-')` from confusing a
    /// group stream with an artifact stream. See the category docstring and
    /// the parser-collision regression test in `events::tests`.
    pub fn artifact_group(id: Uuid) -> Self {
        Self {
            category: StreamCategory::ArtifactGroup,
            entity_id: id,
        }
    }

    /// Construct a curation-category stream for the given repository.
    ///
    /// Used by `IngestUseCase::ingest` (ingest-time `Warn` decisions)
    /// and `ApplyConfigUseCase::apply_curation_rules` (retroactive
    /// evaluation pass) to emit `CurationApplied` events under a
    /// per-repository stream. The `repository_id` is the
    /// `repositories.id` UUID; one stream per repository ordered within
    /// itself by the event store.
    pub fn curation_per_repo(repository_id: Uuid) -> Self {
        Self {
            category: StreamCategory::Curation,
            entity_id: repository_id,
        }
    }

    /// Construct a repository-category stream for the given repository.
    ///
    /// Used by `IngestUseCase::ingest_verified` to append
    /// `ChecksumMismatch` events on the mismatch path (no artifact row
    /// is minted under mint-after-verify, so the aggregate is the
    /// repository, not the artifact). The `repository_id` is the
    /// `repositories.id` UUID; one stream per repository, ordered by
    /// global position.
    pub fn repository(repository_id: Uuid) -> Self {
        Self {
            category: StreamCategory::Repository,
            entity_id: repository_id,
        }
    }

    /// Construct an auth-attempts stream for the given UTC date.
    ///
    /// One stream per UTC date — daily rotation. The `entity_id` is a
    /// deterministic UUIDv5 derived from the `YYYY-MM-DD` date string
    /// under the OID namespace, so the same calendar date always
    /// resolves to the same stream id across replicas and restarts.
    /// The wire form is therefore `auth-<uuid>`, with the human-
    /// readable date carried in the event payload's `at` field — the
    /// stream id stays a UUID for parser symmetry with every other
    /// category, and the daily-rotation invariant is preserved by
    /// derivation (one date → one UUID → one stream).
    ///
    /// Used by `hort-app::use_cases::authenticate_use_case` and
    /// `hort-http-core::middleware::auth` to append
    /// [`AuthenticationAttempted`] failures with `ExpectedVersion::Any`
    /// (no per-stream concurrency check — failure events are
    /// independent observations).
    pub fn auth_attempts(date: chrono::NaiveDate) -> Self {
        let date_str = date.format("%Y-%m-%d").to_string();
        let entity_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, date_str.as_bytes());
        Self {
            category: StreamCategory::AuthAttempts,
            entity_id,
        }
    }

    /// Construct the single global authorization audit stream
    /// (NIS2 Art. 21(2)(h)).
    ///
    /// One global stream — these events are infrequent (gitops apply
    /// runs at boot or operator-initiated re-apply) and the audit
    /// consumer reads the whole stream. The `entity_id` is a
    /// deterministic UUIDv5 derived from the literal `"gitops"` under
    /// the OID namespace, so the same global stream id resolves
    /// across replicas and restarts. The wire form is therefore
    /// `authorization-<uuid>`, with the canonical "authz:gitops"
    /// shorthand corresponding to this single id.
    ///
    /// Used by `ApplyConfigUseCase::apply_claim_mappings` /
    /// `apply_permission_grants` to append `ClaimMappingApplied` /
    /// `ClaimMappingRevoked` / `PermissionGrantApplied` /
    /// `PermissionGrantRevoked`
    /// with `ExpectedVersion::Any` (no per-stream concurrency check —
    /// gitops apply is single-process per boot lock; concurrent apply
    /// is prevented at a higher layer).
    pub fn authorization() -> Self {
        let entity_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, b"gitops");
        Self {
            category: StreamCategory::Authorization,
            entity_id,
        }
    }

    /// `StreamSealed` / destructive-task audit-meta stream.
    /// Stable v5-derived UUID over a fixed label — same shape as the
    /// shipped `StreamId::authorization()` / daily-rotation ctors.
    /// Wire form: `admin-<stable-uuid>`.
    pub fn eventstore_retention() -> Self {
        Self {
            category: StreamCategory::Admin,
            entity_id: Uuid::new_v5(&Uuid::NAMESPACE_OID, b"eventstore-retention"),
        }
    }

    /// Construct a per-user stream for the given user id (native API
    /// token audit).
    ///
    /// Used by `ApiTokenUseCase::issue_self_token`,
    /// `issue_for_service_account`, and `revoke` to emit
    /// `ApiTokenIssued` / `ApiTokenRevoked` to the **token-owner's**
    /// user stream and `ApiTokenIssuanceDenied` to the **requesting
    /// actor's** user stream. The wire form is `"user-<uuid>"`.
    pub fn user(user_id: Uuid) -> Self {
        Self {
            category: StreamCategory::User,
            entity_id: user_id,
        }
    }

    /// Construct a download-audit stream for the given repository and
    /// UTC date.
    ///
    /// One stream per `(repository_id, UTC date)`. The `entity_id` is a
    /// deterministic UUIDv5 derived from
    /// `"download-audit:{repository_id}:{YYYY-MM-DD}"` under the OID
    /// namespace, so the same repo+date always resolves to the same
    /// stream id across replicas and restarts — the same derivation
    /// shape as [`StreamId::auth_attempts`] (date-only) and
    /// [`StreamId::authorization`] (fixed label). The wire form is
    /// therefore `download_audit-<uuid>`, with the human-readable repo
    /// + date carried in the payload's `repository_id` / `occurred_at`.
    ///
    /// Used by `hort-app::use_cases::artifact_use_case::download` to
    /// append [`ArtifactDownloaded`] with `ExpectedVersion::Any` (no
    /// per-stream concurrency check — each served download is an
    /// independent observation; concurrent `Any` appends to one
    /// high-volume audit stream are the B15-reconciled chain class).
    pub fn download_audit(repository_id: Uuid, date: chrono::NaiveDate) -> Self {
        let key = format!("download-audit:{repository_id}:{}", date.format("%Y-%m-%d"));
        let entity_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, key.as_bytes());
        Self {
            category: StreamCategory::DownloadAudit,
            entity_id,
        }
    }

    /// Construct a token-use audit stream for the given token and UTC
    /// date.
    ///
    /// One stream per `(token_id, UTC date)`. The `entity_id` is a
    /// deterministic UUIDv5 derived from
    /// `"token-use:{token_id}:{YYYY-MM-DD}"` under the OID namespace,
    /// so the same token+date always resolves to the same stream id
    /// across replicas and restarts — the same derivation shape as
    /// [`StreamId::download_audit`] (per-`(scope, date)`) and
    /// [`StreamId::auth_attempts`] (date-only). The wire form is
    /// therefore `token_use-<uuid>`, with the human-readable token +
    /// date carried in the payload's `token_id` / `occurred_at`. The
    /// keyspace is bounded by server-controlled `token_id`s (not
    /// attacker-supplied), so per-token sharding cannot be abused to
    /// mint unbounded streams.
    ///
    /// Used by `hort-app::use_cases::pat_validation_use_case` to append
    /// [`ApiTokenUsed`] with `ExpectedVersion::Any` (no per-stream
    /// concurrency check — each use is an independent observation;
    /// concurrent `Any` appends to one throttled audit stream are the
    /// B15-reconciled chain class).
    pub fn token_use(token_id: Uuid, date: chrono::NaiveDate) -> Self {
        let key = format!("token-use:{token_id}:{}", date.format("%Y-%m-%d"));
        let entity_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, key.as_bytes());
        Self {
            category: StreamCategory::TokenUse,
            entity_id,
        }
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cat = match self.category {
            StreamCategory::Artifact => "artifact",
            StreamCategory::Policy => "policy",
            StreamCategory::Admin => "admin",
            StreamCategory::Ref => "ref",
            StreamCategory::ArtifactGroup => "artifact_group",
            StreamCategory::Curation => "curation",
            StreamCategory::Repository => "repository",
            StreamCategory::AuthAttempts => "auth",
            StreamCategory::Authorization => "authorization",
            StreamCategory::User => "user",
            StreamCategory::DownloadAudit => "download_audit",
            StreamCategory::TokenUse => "token_use",
            StreamCategory::RetentionPolicy => "retention_policy",
        };
        write!(f, "{cat}-{}", self.entity_id)
    }
}

impl std::str::FromStr for StreamId {
    type Err = crate::error::DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use crate::error::DomainError;

        // Split on the first '-' only. This works because category names
        // ("artifact", "policy", "admin", "ref", "artifact_group",
        // "download_audit", "token_use", …) contain no hyphens. If a
        // new category with a hyphen is ever added, this parser must
        // be updated.
        //
        // Note: `"artifact_group"`, `"download_audit"`, and
        // `"token_use"` use an underscore specifically so this
        // splitter does not confuse them with the `"artifact"` /
        // `"download"` / `"token"` prefixes — `split_once('-')` on
        // `"token_use-<uuid>"` yields `("token_use", "<uuid>")`. See
        // the parser-collision regression tests in `events::tests`.
        let (cat_str, uuid_str) = s.split_once('-').ok_or_else(|| {
            DomainError::Validation(format!(
                "invalid stream ID format (expected 'category-uuid'): {s}"
            ))
        })?;

        let category = match cat_str {
            "artifact" => StreamCategory::Artifact,
            "policy" => StreamCategory::Policy,
            "admin" => StreamCategory::Admin,
            "ref" => StreamCategory::Ref,
            "artifact_group" => StreamCategory::ArtifactGroup,
            "curation" => StreamCategory::Curation,
            "repository" => StreamCategory::Repository,
            "auth" => StreamCategory::AuthAttempts,
            "authorization" => StreamCategory::Authorization,
            "user" => StreamCategory::User,
            "download_audit" => StreamCategory::DownloadAudit,
            "token_use" => StreamCategory::TokenUse,
            "retention_policy" => StreamCategory::RetentionPolicy,
            _ => {
                return Err(DomainError::Validation(format!(
                    "unknown stream category: {cat_str}"
                )));
            }
        };

        let entity_id = uuid_str
            .parse::<Uuid>()
            .map_err(|e| DomainError::Validation(format!("invalid UUID in stream ID: {e}")))?;

        Ok(StreamId {
            category,
            entity_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Actor types (security-critical split — audit finding C2)
// ---------------------------------------------------------------------------

/// Actor originating from an authenticated API request.
/// Inbound adapters (HTTP, gRPC) construct this from the verified session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiActor {
    pub user_id: Uuid,
}

impl fmt::Display for ApiActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "user:{}", self.user_id)
    }
}

/// Marker token required to construct an [`InternalActor`].
///
/// The inner field is `pub(crate)`, so only code within `hort-domain` can create
/// this token. `hort-app` (which depends on `hort-domain`) receives the
/// constructors via re-exported helpers — but the inbound-HTTP crates
/// (`hort-http-core`, `hort-http-<format>`) cannot construct
/// `InternalActorToken(())` because the inner `()` is `pub(crate)`.
///
/// This is a compile-time guarantee that API handlers cannot forge internal
/// actor identities.
pub struct InternalActorToken(pub(crate) ());

/// Actor originating from internal system processes.
///
/// Only constructible via the sealed [`InternalActorToken`] pattern or
/// [`Actor::from_persisted`] (event store reconstruction).
///
/// This type does NOT derive `Deserialize` — it cannot be deserialized
/// from JSON, HTTP request bodies, or any external input. This is a
/// compile-time guarantee that API handlers cannot forge internal actor
/// identities. The event store adapter reconstructs `Actor` from database
/// columns via [`Actor::from_persisted`], not via serde deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum InternalActor {
    /// The system itself (background jobs, projections, automated rules).
    System,
    /// A timer-based trigger (quarantine expiry sweep).
    Timer,
    /// The retention scheduler. Carries the
    /// `ArtifactExpired` / `ArtifactPurged` decisions emitted by the
    /// `RetentionEvaluateHandler` / `RetentionPurgeHandler` task
    /// handlers and the destructive-task `TaskInvoked` / `TaskFailed`
    /// audit (ADR 0028). Distinct from
    /// [`Self::Timer`] (the quarantine-expiry sweep) so a destructive
    /// retention-purge / event-store-archive append is attributable to
    /// the retention subsystem specifically, not conflated with the
    /// generic timer sweep. Persisted as `actor_type='retention_scheduler'`
    /// (the `004_events.sql` `chk_actor_id` / `events_actor_type_check`
    /// no-actor-id branch, edited in place pre-release).
    RetentionScheduler,
}

impl InternalActor {
    /// Construct a System actor. Requires a token that only `hort-domain`
    /// (and by extension `hort-app` helpers) can produce.
    pub fn system(_token: InternalActorToken) -> Self {
        Self::System
    }

    /// Construct a Timer actor. Requires a token that only `hort-domain`
    /// (and by extension `hort-app` helpers) can produce.
    pub fn timer(_token: InternalActorToken) -> Self {
        Self::Timer
    }

    /// Construct a RetentionScheduler actor. Requires a
    /// token that only `hort-domain` (and by extension `hort-app` helpers)
    /// can produce.
    pub fn retention_scheduler(_token: InternalActorToken) -> Self {
        Self::RetentionScheduler
    }
}

impl fmt::Display for InternalActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => f.write_str("system"),
            Self::Timer => f.write_str("timer"),
            Self::RetentionScheduler => f.write_str("retention_scheduler"),
        }
    }
}

/// Actor produced by the gitops apply pipeline.
///
/// Carries the source-of-truth metadata an audit trail needs to answer
/// "which YAML file changed this object, and what was its content
/// digest at apply time?" without having to join against an external
/// log. Persisted as `actor_type='gitops'` plus the `actor_source_file`
/// and `actor_spec_digest` columns introduced by `004_events.sql` (edited
/// in place; pre-release).
///
/// Like the other actor structs in this module, `GitOpsActor` does
/// **not** derive `Deserialize` — actors are server-constructed in
/// `hort-app::ApplyConfigUseCase`, never read from API input.
/// The persisted-storage round-trip goes through
/// [`Actor::from_persisted_gitops`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitOpsActor {
    /// Path relative to `$HORT_CONFIG_DIR`, e.g.
    /// `repositories/npm-public.yaml`.
    pub source_file: String,
    /// SHA-256 of the canonicalised `spec` JSON at apply time. Lets a
    /// future audit query confirm "this event was produced from the
    /// exact spec bytes that hash to X" without re-reading the YAML.
    pub spec_digest: [u8; 32],
    /// Wall-clock timestamp at the moment `ApplyConfigUseCase` ran.
    /// Stored separately from the event's `stored_at` because the
    /// apply may emit several events for one object and the operator
    /// reads "applied_at" as a single fact about the spec, not per-
    /// event.
    pub applied_at: DateTime<Utc>,
}

impl fmt::Display for GitOpsActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gitops:{}", self.source_file)
    }
}

/// Unified actor stored in events. Constructed by use cases, never by handlers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Actor {
    Api(ApiActor),
    Internal(InternalActor),
    /// Gitops apply pipeline. The source file +
    /// spec digest are persisted as separate columns; see
    /// `Actor::from_persisted_gitops`.
    GitOps(GitOpsActor),
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(api) => write!(f, "{api}"),
            Self::Internal(internal) => write!(f, "{internal}"),
            Self::GitOps(gitops) => write!(f, "{gitops}"),
        }
    }
}

impl Actor {
    /// Reconstruct an Actor from persisted storage columns.
    ///
    /// This is the designated deserialization path for the event store adapter.
    /// It bypasses `InternalActorToken` intentionally — reconstructing from
    /// trusted storage is not the same as creating from API input.
    /// **No API handler may call this method.**
    ///
    /// `actor_type = "gitops"` is intentionally rejected here even
    /// though the column value is valid — a gitops row carries two
    /// extra columns (source_file, spec_digest) that this signature
    /// can't see. The adapter mapper inspects `actor_type` first and
    /// dispatches to [`Actor::from_persisted_gitops`] when it sees
    /// `"gitops"`. The split keeps the no-extra-args API monomorphic
    /// and forces the call site to be explicit about which columns it
    /// has in scope, which is the property we want at the persistence
    /// boundary.
    pub fn from_persisted(
        actor_type: &str,
        actor_id: Option<Uuid>,
    ) -> crate::error::DomainResult<Self> {
        use crate::error::DomainError;
        match (actor_type, actor_id) {
            ("api", Some(uid)) => Ok(Actor::Api(ApiActor { user_id: uid })),
            ("api", None) => Err(DomainError::Invariant("api actor missing user_id".into())),
            ("system", None) => Ok(Actor::Internal(InternalActor::System)),
            ("timer", None) => Ok(Actor::Internal(InternalActor::Timer)),
            ("retention_scheduler", None) => Ok(Actor::Internal(InternalActor::RetentionScheduler)),
            ("system" | "timer" | "retention_scheduler", Some(_)) => Err(DomainError::Invariant(
                format!("internal actor {actor_type} must not have actor_id"),
            )),
            ("gitops", _) => Err(DomainError::Invariant(
                "gitops actor requires source_file + spec_digest — adapter must call \
                 Actor::from_persisted_gitops"
                    .into(),
            )),
            _ => Err(DomainError::Invariant(format!(
                "unknown actor_type: {actor_type}"
            ))),
        }
    }

    /// Reconstruct a [`Actor::GitOps`] variant from the three columns
    /// the adapter has in scope. Same trust contract as
    /// [`Actor::from_persisted`] — never callable from an API handler.
    ///
    /// Separate from `from_persisted` rather than overloaded with
    /// optional columns: the caller knows up-front whether it is
    /// dealing with a gitops row (it inspects `actor_type` first) and
    /// the explicit constructor makes that branch impossible to reach
    /// by accident from a non-gitops code path.
    pub fn from_persisted_gitops(
        source_file: String,
        spec_digest: [u8; 32],
        applied_at: DateTime<Utc>,
    ) -> Self {
        Actor::GitOps(GitOpsActor {
            source_file,
            spec_digest,
            applied_at,
        })
    }
}

/// Create a System actor for internal use (scanner integration, background jobs).
///
/// Callable from any crate that depends on `hort-domain`. The security boundary
/// is that arbitrary `InternalActor` variants cannot be constructed without the
/// sealed `InternalActorToken` — these factory functions are the controlled API
/// surface.
pub fn system_actor() -> Actor {
    Actor::Internal(InternalActor::system(InternalActorToken(())))
}

/// Create a Timer actor for background timer-triggered operations (quarantine expiry).
///
/// Same security model as [`system_actor`].
pub fn timer_actor() -> Actor {
    Actor::Internal(InternalActor::timer(InternalActorToken(())))
}

/// Create a RetentionScheduler actor for the
/// retention task handlers (`RetentionEvaluateHandler` /
/// `RetentionPurgeHandler` `ArtifactExpired` / `ArtifactPurged`
/// appends + the destructive-task audit).
///
/// Same security model as [`system_actor`]: the sealed
/// [`InternalActorToken`] is the controlled construction surface; an
/// API handler cannot forge this identity.
pub fn retention_scheduler_actor() -> Actor {
    Actor::Internal(InternalActor::retention_scheduler(InternalActorToken(())))
}

// ---------------------------------------------------------------------------
// PersistedEvent
// ---------------------------------------------------------------------------

/// A domain event as persisted in the event store.
///
/// The `event_id`, `stream_position`, `global_position`, and `stored_at`
/// fields are assigned by the store on append — they are never caller-supplied.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PersistedEvent {
    /// Unique event identifier (assigned by the store).
    pub event_id: Uuid,
    /// The stream this event belongs to.
    pub stream_id: StreamId,
    /// Position within the stream (0-based, monotonically increasing).
    pub stream_position: u64,
    /// Global ordering across all streams (assigned by the store).
    pub global_position: u64,
    /// The domain event payload.
    pub event: DomainEvent,
    /// Correlation ID linking related events across streams.
    pub correlation_id: Uuid,
    /// The event that directly caused this event (if any).
    /// `None` for events triggered by external commands; `Some(event_id)` for
    /// events triggered by processing another event (e.g. `ScanCompleted` ->
    /// `ArtifactRejected`).
    pub causation_id: Option<Uuid>,
    /// The actor who caused this event.
    pub actor: Actor,
    /// Schema version of the event payload (default 1). Incremented on breaking
    /// changes to the payload struct. The mapper must handle all versions.
    pub event_version: u32,
    /// Timestamp assigned by the store. Informational only — `global_position`
    /// is the authoritative ordering. May be non-monotonic under clock skew.
    pub stored_at: DateTime<Utc>,
}
