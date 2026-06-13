//! Request/response DTOs for the `/api/v1/subscriptions` surface.
//!
//! Per ADR 0008, the domain types (`Subscription`, `SubscriptionTarget`,
//! `SubscriptionFilter`, …) MUST NOT derive `Deserialize` — only handler
//! DTOs are reconstituted from external input. These DTOs map TO domain
//! types before calling the use case and FROM domain types on responses.
//!
//! ## EventTypeKind / StreamCategory wire form
//!
//! `EventTypeKind` is a closed enum in `hort-domain::entities::subscription`
//! without a `FromStr` impl. Wire mapping is done via the closed-match
//! helper [`parse_event_type_kind`] in this module — the wire boundary is
//! the only place where wire-shaped strings are parsed into the closed
//! enum, so adding a new variant fails to compile here on purpose.
//!
//! `StreamCategory` is similarly parsed via [`parse_stream_category`];
//! the wire forms mirror `StreamId`'s `Display`/`FromStr` impls in
//! `hort-domain::events::mod` (e.g. `"artifact"`, `"artifact_group"`).
//!
//! ## Webhook secret handling
//!
//! [`SubscriptionTargetDto::Webhook`] carries a **`secret_ref`** — an
//! env-var / file *locator*, NOT the secret material. This mirrors the
//! upstream-mapping precedent (`hort-config`'s
//! `UpstreamMappingSpec.secret_ref: Option<SecretRef>`;
//! see `how-to/wire-secrets.md`):
//! the operator provisions the shared secret out-of-band (env var or
//! mounted file) and the request references it by `(source, location)`.
//! The plaintext bytes never touch the wire, the subscription row, or a
//! create response — resolution happens at delivery time via
//! [`SecretPort`]. There is therefore no "shown once" plaintext field
//! anymore; the create response is the canonical subscription shape with
//! nothing secret-derived added.
//!
//! The wire shape reuses [`SecretRef`]'s own `serde` (same as
//! `UpstreamMappingSpec`): `SecretRef` is a locator/config type, not one
//! of the forge-sensitive domain types in the "Domain type
//! deserialization in API layer" anti-pattern (that closed list is
//! `Actor` / `ApiActor` / `InternalActor` / `PersistedEvent` /
//! `StreamId` / `StreamCategory`). The locator-format rule
//! (`source: env_var` ⇒ POSIX-portable name; `source: file` ⇒ absolute
//! path) is enforced at this wire boundary by
//! [`validate_webhook_secret_ref`], the same boundary discipline
//! `hort-config::validate_secret_ref` applies to the gitops surface.
//!
//! [`SecretPort`]: hort_domain::ports::secret_port::SecretPort
//! [`SecretRef`]: hort_domain::ports::secret_port::SecretRef

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use hort_domain::entities::subscription::{
    EventTypeFilter, EventTypeKind, NamedPredicate, RepositoryScope, Subscription,
    SubscriptionFilter, SubscriptionState, SubscriptionTarget,
};
use hort_domain::events::StreamCategory;
use hort_domain::ports::secret_port::{SecretRef, SecretSource};

// ---------------------------------------------------------------------------
// Create request
// ---------------------------------------------------------------------------

/// `POST /api/v1/subscriptions` request body.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub target: SubscriptionTargetDto,
    pub filter: SubscriptionFilterDto,
}

/// Wire shape for [`SubscriptionTarget`] — the `Webhook` variant carries
/// a **`secret_ref`** locator (mirrors upstream-mapping; F-19), NOT the
/// secret material. The response variant
/// ([`SubscriptionTargetResponseDto`]) omits the `secret_ref` entirely.
///
/// `url` is wire-shaped as a `String` rather than `url::Url` so this
/// crate's `url` workspace pin can stay feature-minimal (the workspace
/// pin doesn't enable `serde`). Parsing happens in
/// [`map_target_to_domain`].
///
/// `secret_ref` reuses [`SecretRef`]'s own `serde` — the wire JSON is
/// `{"source": "env_var" | "file", "location": "..."}`, identical to
/// `hort-config`'s `UpstreamMappingSpec.secret_ref`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubscriptionTargetDto {
    Webhook { url: String, secret_ref: SecretRef },
    NatsJetStream { subject: String },
}

/// Wire shape for [`SubscriptionFilter`]. `categories` and the kinds
/// inside `event_types: Some {...}` are wire strings; mapping happens in
/// [`map_create_request_to_domain`] / [`map_filter_to_domain`].
#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionFilterDto {
    pub categories: Vec<String>,
    pub event_types: EventTypeFilterDto,
    pub repositories: RepositoryScopeDto,
    /// v1 ships zero [`NamedPredicate`] variants. Wire form accepts a
    /// list of names so future predicate additions are forward-compat;
    /// any non-empty list rejects with `400 unsupported_named_predicate`.
    #[serde(default)]
    pub named_predicates: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventTypeFilterDto {
    All,
    Some { kinds: Vec<String> },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositoryScopeDto {
    OwnedByActor,
    Some { repository_ids: Vec<Uuid> },
    All,
}

// ---------------------------------------------------------------------------
// Update request
// ---------------------------------------------------------------------------

/// `PATCH /api/v1/subscriptions/:id` request body.
///
/// Outer `Option` is "leave alone" vs "change to". For `description`, the
/// inner `Option<Option<String>>` distinguishes "leave alone" (outer
/// `None`), "set to NULL" (`Some(None)`, i.e. the wire JSON `"description":
/// null`), and "set to new text" (`Some(Some("..."))`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateSubscriptionRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// `description` accepts an explicit `null` (clear). See the
    /// [`deserialize_explicit_null_option`] adapter at the bottom of this
    /// file.
    #[serde(default, deserialize_with = "deserialize_explicit_null_option")]
    pub description: Option<Option<String>>,
    #[serde(default)]
    pub target: Option<SubscriptionTargetDto>,
    #[serde(default)]
    pub filter: Option<SubscriptionFilterDto>,
    #[serde(default)]
    pub state: Option<SubscriptionStateDto>,
}

/// State writes via PATCH: only the two operator-driven transitions are
/// expressible on the wire. `Disabled` is server-side only (the
/// dispatcher's failure budget reaches that state, not the operator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum SubscriptionStateDto {
    Active,
    Paused,
}

impl SubscriptionStateDto {
    /// Convert to the domain enum. `Disabled` is intentionally not
    /// constructible here; callers always supply `Active`/`Paused`.
    pub fn to_domain(self) -> SubscriptionState {
        match self {
            Self::Active => SubscriptionState::Active,
            Self::Paused => SubscriptionState::Paused,
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Wire shape for a single subscription. Omits the webhook `secret_ref`
/// locator entirely — read paths never echo any secret-derived field
/// (F-19: there is no plaintext or hash anywhere to echo).
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionResponse {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub target: SubscriptionTargetResponseDto,
    pub filter: SubscriptionFilterResponseDto,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

// `POST /api/v1/subscriptions` returns the canonical
// [`SubscriptionResponse`] directly. F-19 removed the former
// `CreateSubscriptionResponse` wrapper and its `secret_plaintext`
// "shown once" field: the request now references an already-provisioned
// secret via `secret_ref` (mirroring upstream-mapping), so the create
// path never handles plaintext and has nothing one-shot to echo.

/// Response shape for [`SubscriptionTarget`].
///
/// The `Webhook.url` is wire-serialized as a `String` (rather than via
/// `Url`'s `serde` feature) so this crate's dep on the `url` workspace
/// pin can stay feature-minimal. `Url::to_string()` is canonical for
/// the consumer; the request side parses back via `Url::from_str` on
/// the inbound DTO ([`SubscriptionTargetDto`]).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubscriptionTargetResponseDto {
    Webhook { url: String },
    NatsJetStream { subject: String },
}

/// Filter on the wire (response side). Mirrors [`SubscriptionFilterDto`]
/// but Serialize-only — wire input lives in the request DTO.
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionFilterResponseDto {
    pub categories: Vec<String>,
    pub event_types: EventTypeFilterResponseDto,
    pub repositories: RepositoryScopeResponseDto,
    pub named_predicates: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventTypeFilterResponseDto {
    All,
    Some { kinds: Vec<String> },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositoryScopeResponseDto {
    OwnedByActor,
    Some { repository_ids: Vec<Uuid> },
    All,
}

/// Paginated response.
#[derive(Debug, Clone, Serialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Mapping errors
// ---------------------------------------------------------------------------

/// DTO-side parse / mapping errors. Distinct from
/// `SubscriptionError` because these fire BEFORE the use case is
/// called — they shape unconditionally to `400 Bad Request`.
#[derive(Debug, thiserror::Error)]
pub enum DtoMapError {
    #[error("unknown stream category: {0}")]
    UnknownStreamCategory(String),
    #[error("unknown event type kind: {0}")]
    UnknownEventTypeKind(String),
    #[error("named predicates are not supported in v1; received: {0:?}")]
    UnsupportedNamedPredicate(Vec<String>),
    #[error("invalid webhook url: {0}")]
    InvalidWebhookUrl(String),
    /// The webhook `secret_ref` locator is structurally invalid
    /// (`source: env_var` with a non-POSIX name, or `source: file`
    /// with a relative path). Mirrors `hort-config`'s
    /// `SecretRefLocationInvalid` boundary check (see `how-to/wire-secrets.md`).
    #[error("invalid webhook secret_ref: {0}")]
    InvalidWebhookSecretRef(String),
}

// ---------------------------------------------------------------------------
// DTO → domain mapping
// ---------------------------------------------------------------------------

/// Map a [`CreateSubscriptionRequest`] to the use-case-facing
/// [`hort_app::use_cases::subscription_use_case::CreateSubscriptionRequest`].
///
/// The webhook `secret_ref` is a locator only (F-19) — no secret
/// material is read or hashed here; the locator format is validated at
/// this wire boundary by [`validate_webhook_secret_ref`].
pub fn map_create_request_to_domain(
    req: CreateSubscriptionRequest,
) -> Result<hort_app::use_cases::subscription_use_case::CreateSubscriptionRequest, DtoMapError> {
    let filter = map_filter_to_domain(req.filter)?;
    let target = map_target_to_domain(req.target)?;
    Ok(
        hort_app::use_cases::subscription_use_case::CreateSubscriptionRequest {
            name: req.name,
            description: req.description,
            target,
            filter,
        },
    )
}

/// Map an [`UpdateSubscriptionRequest`] to the use-case-facing
/// [`hort_app::use_cases::subscription_use_case::UpdateSubscriptionRequest`].
///
/// A new webhook target (if supplied) carries a `secret_ref` locator
/// only (F-19) — no plaintext is produced, so there is nothing for the
/// handler to echo.
pub fn map_update_request_to_domain(
    req: UpdateSubscriptionRequest,
) -> Result<hort_app::use_cases::subscription_use_case::UpdateSubscriptionRequest, DtoMapError> {
    let target = match req.target {
        Some(t) => Some(map_target_to_domain(t)?),
        None => None,
    };
    let filter = req.filter.map(map_filter_to_domain).transpose()?;
    Ok(
        hort_app::use_cases::subscription_use_case::UpdateSubscriptionRequest {
            name: req.name,
            description: req.description,
            target,
            filter,
            state: req.state.map(SubscriptionStateDto::to_domain),
        },
    )
}

/// Map a wire-shape [`SubscriptionFilterDto`] to the domain
/// [`SubscriptionFilter`].
pub fn map_filter_to_domain(f: SubscriptionFilterDto) -> Result<SubscriptionFilter, DtoMapError> {
    let categories: Result<Vec<StreamCategory>, DtoMapError> = f
        .categories
        .iter()
        .map(|s| parse_stream_category(s))
        .collect();

    let event_types = match f.event_types {
        EventTypeFilterDto::All => EventTypeFilter::All,
        EventTypeFilterDto::Some { kinds } => {
            let parsed: Result<Vec<EventTypeKind>, DtoMapError> =
                kinds.iter().map(|s| parse_event_type_kind(s)).collect();
            EventTypeFilter::Some(parsed?)
        }
    };

    let repositories = match f.repositories {
        RepositoryScopeDto::OwnedByActor => RepositoryScope::OwnedByActor,
        RepositoryScopeDto::Some { repository_ids } => RepositoryScope::Some(repository_ids),
        RepositoryScopeDto::All => RepositoryScope::All,
    };

    if !f.named_predicates.is_empty() {
        return Err(DtoMapError::UnsupportedNamedPredicate(f.named_predicates));
    }

    Ok(SubscriptionFilter {
        categories: categories?,
        event_types,
        repositories,
        named_predicates: Vec::<NamedPredicate>::new(),
    })
}

/// Map a wire-shape [`SubscriptionTargetDto`] to a domain
/// [`SubscriptionTarget`].
///
/// The webhook `secret_ref` is carried through verbatim (it is a
/// locator, not secret material; F-19) after its `(source, location)`
/// shape is validated at this boundary by
/// [`validate_webhook_secret_ref`].
fn map_target_to_domain(t: SubscriptionTargetDto) -> Result<SubscriptionTarget, DtoMapError> {
    match t {
        SubscriptionTargetDto::Webhook { url, secret_ref } => {
            let parsed =
                url::Url::parse(&url).map_err(|e| DtoMapError::InvalidWebhookUrl(e.to_string()))?;
            validate_webhook_secret_ref(&secret_ref)?;
            Ok(SubscriptionTarget::Webhook {
                url: parsed,
                secret_ref,
            })
        }
        SubscriptionTargetDto::NatsJetStream { subject } => {
            Ok(SubscriptionTarget::NatsJetStream { subject })
        }
    }
}

/// Validate the locator format of a webhook [`SecretRef`] at the wire
/// boundary. Same rule `hort-config`'s `validate_secret_ref` applies to
/// the gitops surface (see `how-to/wire-secrets.md`) — `hort-http-subscriptions`
/// cannot depend on `hort-config` (inbound-HTTP dep-graph rule, ADR 0008),
/// so the
/// small rule is mirrored here, the same way this module already
/// mirrors the closed-match wire vocabularies (`parse_event_type_kind`,
/// `parse_stream_category`).
///
/// - `source: env_var` ⇒ `location` must match `^[A-Z_][A-Z0-9_]*$`
///   (POSIX-portable identifier).
/// - `source: file` ⇒ `location` must be an absolute path
///   (`starts_with('/')`).
///
/// Existence of the referenced env var / file is NOT checked here — it
/// is resolved at delivery time via [`SecretPort`]; the operator may
/// provision it after the subscription is created (same deferral
/// `validate_secret_ref` documents).
///
/// [`SecretPort`]: hort_domain::ports::secret_port::SecretPort
fn validate_webhook_secret_ref(secret_ref: &SecretRef) -> Result<(), DtoMapError> {
    match secret_ref.source {
        SecretSource::EnvVar => {
            if !is_posix_env_var_name(&secret_ref.location) {
                return Err(DtoMapError::InvalidWebhookSecretRef(format!(
                    "with `source: env_var` must match `^[A-Z_][A-Z0-9_]*$`, got `{}`",
                    secret_ref.location
                )));
            }
        }
        SecretSource::File => {
            if !secret_ref.location.starts_with('/') {
                return Err(DtoMapError::InvalidWebhookSecretRef(format!(
                    "with `source: file` must be an absolute path, got `{}`",
                    secret_ref.location
                )));
            }
        }
    }
    Ok(())
}

/// POSIX-portable env-var name check: `^[A-Z_][A-Z0-9_]*$`. Hand-rolled
/// byte check — this crate has no `regex` dep, matching the established
/// `hort-config::is_posix_env_var_name` pattern (the rule is duplicated,
/// not the code, because the dep graph forbids importing it).
fn is_posix_env_var_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b == b'_' || b.is_ascii_uppercase() => {}
        _ => return false,
    }
    bytes.all(|b| b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Domain → response mapping
// ---------------------------------------------------------------------------

/// Map a domain [`Subscription`] to the wire [`SubscriptionResponse`].
/// Drops the webhook `secret_hash` — the response NEVER carries either
/// the plaintext or the hash on read paths.
pub fn map_subscription_to_response(s: Subscription) -> SubscriptionResponse {
    let target = match s.target {
        SubscriptionTarget::Webhook { url, .. } => SubscriptionTargetResponseDto::Webhook {
            url: url.to_string(),
        },
        SubscriptionTarget::NatsJetStream { subject } => {
            SubscriptionTargetResponseDto::NatsJetStream { subject }
        }
    };
    let filter = SubscriptionFilterResponseDto {
        categories: s
            .filter
            .categories
            .iter()
            .map(stream_category_wire)
            .collect(),
        event_types: match s.filter.event_types {
            EventTypeFilter::All => EventTypeFilterResponseDto::All,
            EventTypeFilter::Some(kinds) => EventTypeFilterResponseDto::Some {
                kinds: kinds.iter().map(event_type_kind_wire).collect(),
            },
        },
        repositories: match s.filter.repositories {
            RepositoryScope::OwnedByActor => RepositoryScopeResponseDto::OwnedByActor,
            RepositoryScope::Some(ids) => RepositoryScopeResponseDto::Some {
                repository_ids: ids,
            },
            RepositoryScope::All => RepositoryScopeResponseDto::All,
        },
        // v1 ships zero predicates — the response is always empty.
        named_predicates: Vec::new(),
    };
    SubscriptionResponse {
        id: s.id.0,
        owner_user_id: s.owner_user_id,
        name: s.name,
        description: s.description,
        target,
        filter,
        state: subscription_state_wire(&s.state).to_string(),
        created_at: s.created_at,
    }
}

// ---------------------------------------------------------------------------
// Closed-match parsers (no `FromStr` on the domain types — wire shape is
// the adapter's responsibility per ADR 0008).
// ---------------------------------------------------------------------------

/// Parse the wire form of [`StreamCategory`]. Same string table as
/// `StreamId::Display`/`FromStr` in `hort-domain::events::mod`.
pub fn parse_stream_category(s: &str) -> Result<StreamCategory, DtoMapError> {
    Ok(match s {
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
        other => return Err(DtoMapError::UnknownStreamCategory(other.to_string())),
    })
}

/// Wire form of [`StreamCategory`]. Mirrors `StreamId::Display`.
fn stream_category_wire(c: &StreamCategory) -> String {
    match c {
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
    }
    .to_string()
}

/// Parse the wire form of [`EventTypeKind`]. The match is closed — adding
/// a new `EventTypeKind` variant fails to compile here on purpose:
/// the adapter must opt new variants into the wire vocabulary.
///
/// The high-volume forward-compat variants (`ArtifactDownloaded`,
/// `ApiTokenUsed`) are accepted at parse time because the use case
/// rejects them with `400 unsupported_event_type`, which is a more
/// precise error than "unknown kind". `AuthenticationAttempted` is
/// already in `DomainEvent` and is rejected for the same reason.
pub fn parse_event_type_kind(s: &str) -> Result<EventTypeKind, DtoMapError> {
    Ok(match s {
        "ArtifactIngested" => EventTypeKind::ArtifactIngested,
        "ChecksumVerified" => EventTypeKind::ChecksumVerified,
        "ChecksumMismatch" => EventTypeKind::ChecksumMismatch,
        "ArtifactQuarantined" => EventTypeKind::ArtifactQuarantined,
        "ScanRequested" => EventTypeKind::ScanRequested,
        "ScanCompleted" => EventTypeKind::ScanCompleted,
        "ArtifactBecameVulnerable" => EventTypeKind::ArtifactBecameVulnerable,
        "ArtifactReleased" => EventTypeKind::ArtifactReleased,
        "ArtifactRejected" => EventTypeKind::ArtifactRejected,
        "ScanIndeterminate" => EventTypeKind::ScanIndeterminate,
        "ProvenanceVerified" => EventTypeKind::ProvenanceVerified,
        "ProvenanceRejected" => EventTypeKind::ProvenanceRejected,
        "ArtifactReEvaluated" => EventTypeKind::ArtifactReEvaluated,
        "PromotionRequested" => EventTypeKind::PromotionRequested,
        "PolicyEvaluated" => EventTypeKind::PolicyEvaluated,
        "ApprovalRequested" => EventTypeKind::ApprovalRequested,
        "ApprovalDecided" => EventTypeKind::ApprovalDecided,
        "ArtifactPromoted" => EventTypeKind::ArtifactPromoted,
        "PromotionRejected" => EventTypeKind::PromotionRejected,
        "PolicyCreated" => EventTypeKind::PolicyCreated,
        "PolicyUpdated" => EventTypeKind::PolicyUpdated,
        "ExclusionAdded" => EventTypeKind::ExclusionAdded,
        "ExclusionRemoved" => EventTypeKind::ExclusionRemoved,
        "PolicyArchived" => EventTypeKind::PolicyArchived,
        "CasIntegrityMismatch" => EventTypeKind::CasIntegrityMismatch,
        "ArtifactCorrupted" => EventTypeKind::ArtifactCorrupted,
        "RefMoved" => EventTypeKind::RefMoved,
        "RefRetired" => EventTypeKind::RefRetired,
        "ArtifactGroupInitiated" => EventTypeKind::ArtifactGroupInitiated,
        "ArtifactGroupMemberAdded" => EventTypeKind::ArtifactGroupMemberAdded,
        "ArtifactGroupMemberRemoved" => EventTypeKind::ArtifactGroupMemberRemoved,
        "ArtifactGroupPrimaryRoleAssigned" => EventTypeKind::ArtifactGroupPrimaryRoleAssigned,
        "CurationApplied" => EventTypeKind::CurationApplied,
        "AuthenticationAttempted" => EventTypeKind::AuthenticationAttempted,
        "OidcKeyRotated" => EventTypeKind::OidcKeyRotated,
        "AdminStatusChanged" => EventTypeKind::AdminStatusChanged,
        "ClaimMappingApplied" => EventTypeKind::ClaimMappingApplied,
        "ClaimMappingRevoked" => EventTypeKind::ClaimMappingRevoked,
        "PermissionGrantApplied" => EventTypeKind::PermissionGrantApplied,
        "PermissionGrantRevoked" => EventTypeKind::PermissionGrantRevoked,
        "RepositoryUpstreamMappingChanged" => EventTypeKind::RepositoryUpstreamMappingChanged,
        "ApiTokenIssued" => EventTypeKind::ApiTokenIssued,
        "ApiTokenRevoked" => EventTypeKind::ApiTokenRevoked,
        "ApiTokenIssuanceDenied" => EventTypeKind::ApiTokenIssuanceDenied,
        "TaskInvoked" => EventTypeKind::TaskInvoked,
        "TaskFailed" => EventTypeKind::TaskFailed,
        "SubscriptionCreated" => EventTypeKind::SubscriptionCreated,
        "SubscriptionCreationDenied" => EventTypeKind::SubscriptionCreationDenied,
        "SubscriptionUpdated" => EventTypeKind::SubscriptionUpdated,
        "SubscriptionPaused" => EventTypeKind::SubscriptionPaused,
        "SubscriptionResumed" => EventTypeKind::SubscriptionResumed,
        "SubscriptionDeleted" => EventTypeKind::SubscriptionDeleted,
        "SubscriptionDisabled" => EventTypeKind::SubscriptionDisabled,
        "ArtifactDownloaded" => EventTypeKind::ArtifactDownloaded,
        "ApiTokenUsed" => EventTypeKind::ApiTokenUsed,
        "PolicyReactivated" => EventTypeKind::PolicyReactivated,
        "OidcIssuerCreated" => EventTypeKind::OidcIssuerCreated,
        "OidcIssuerUpdated" => EventTypeKind::OidcIssuerUpdated,
        "OidcIssuerDeleted" => EventTypeKind::OidcIssuerDeleted,
        "ServiceAccountCreated" => EventTypeKind::ServiceAccountCreated,
        "ServiceAccountUpdated" => EventTypeKind::ServiceAccountUpdated,
        "ServiceAccountDeleted" => EventTypeKind::ServiceAccountDeleted,
        "ServiceAccountTokenRotated" => EventTypeKind::ServiceAccountTokenRotated,
        "ArtifactExpired" => EventTypeKind::ArtifactExpired,
        "ArtifactPurged" => EventTypeKind::ArtifactPurged,
        other => return Err(DtoMapError::UnknownEventTypeKind(other.to_string())),
    })
}

/// Wire form of [`EventTypeKind`]. Closed match — adding a new variant
/// fails to compile here on purpose.
fn event_type_kind_wire(k: &EventTypeKind) -> String {
    match k {
        EventTypeKind::ArtifactIngested => "ArtifactIngested",
        EventTypeKind::ChecksumVerified => "ChecksumVerified",
        EventTypeKind::ChecksumMismatch => "ChecksumMismatch",
        EventTypeKind::ArtifactQuarantined => "ArtifactQuarantined",
        EventTypeKind::ScanRequested => "ScanRequested",
        EventTypeKind::ScanCompleted => "ScanCompleted",
        EventTypeKind::ArtifactBecameVulnerable => "ArtifactBecameVulnerable",
        EventTypeKind::ArtifactReleased => "ArtifactReleased",
        EventTypeKind::ArtifactRejected => "ArtifactRejected",
        EventTypeKind::ScanIndeterminate => "ScanIndeterminate",
        EventTypeKind::ProvenanceVerified => "ProvenanceVerified",
        EventTypeKind::ProvenanceRejected => "ProvenanceRejected",
        EventTypeKind::ArtifactReEvaluated => "ArtifactReEvaluated",
        EventTypeKind::PromotionRequested => "PromotionRequested",
        EventTypeKind::PolicyEvaluated => "PolicyEvaluated",
        EventTypeKind::ApprovalRequested => "ApprovalRequested",
        EventTypeKind::ApprovalDecided => "ApprovalDecided",
        EventTypeKind::ArtifactPromoted => "ArtifactPromoted",
        EventTypeKind::PromotionRejected => "PromotionRejected",
        EventTypeKind::PolicyCreated => "PolicyCreated",
        EventTypeKind::PolicyUpdated => "PolicyUpdated",
        EventTypeKind::ExclusionAdded => "ExclusionAdded",
        EventTypeKind::ExclusionRemoved => "ExclusionRemoved",
        EventTypeKind::PolicyArchived => "PolicyArchived",
        EventTypeKind::CasIntegrityMismatch => "CasIntegrityMismatch",
        EventTypeKind::ArtifactCorrupted => "ArtifactCorrupted",
        EventTypeKind::RefMoved => "RefMoved",
        EventTypeKind::RefRetired => "RefRetired",
        EventTypeKind::ArtifactGroupInitiated => "ArtifactGroupInitiated",
        EventTypeKind::ArtifactGroupMemberAdded => "ArtifactGroupMemberAdded",
        EventTypeKind::ArtifactGroupMemberRemoved => "ArtifactGroupMemberRemoved",
        EventTypeKind::ArtifactGroupPrimaryRoleAssigned => "ArtifactGroupPrimaryRoleAssigned",
        EventTypeKind::CurationApplied => "CurationApplied",
        EventTypeKind::AuthenticationAttempted => "AuthenticationAttempted",
        EventTypeKind::OidcKeyRotated => "OidcKeyRotated",
        EventTypeKind::AdminStatusChanged => "AdminStatusChanged",
        EventTypeKind::ClaimMappingApplied => "ClaimMappingApplied",
        EventTypeKind::ClaimMappingRevoked => "ClaimMappingRevoked",
        EventTypeKind::PermissionGrantApplied => "PermissionGrantApplied",
        EventTypeKind::PermissionGrantRevoked => "PermissionGrantRevoked",
        EventTypeKind::RepositoryUpstreamMappingChanged => "RepositoryUpstreamMappingChanged",
        EventTypeKind::ApiTokenIssued => "ApiTokenIssued",
        EventTypeKind::ApiTokenRevoked => "ApiTokenRevoked",
        EventTypeKind::ApiTokenIssuanceDenied => "ApiTokenIssuanceDenied",
        EventTypeKind::TaskInvoked => "TaskInvoked",
        EventTypeKind::TaskFailed => "TaskFailed",
        EventTypeKind::PolicyReactivated => "PolicyReactivated",
        EventTypeKind::OidcIssuerCreated => "OidcIssuerCreated",
        EventTypeKind::OidcIssuerUpdated => "OidcIssuerUpdated",
        EventTypeKind::OidcIssuerDeleted => "OidcIssuerDeleted",
        EventTypeKind::ServiceAccountCreated => "ServiceAccountCreated",
        EventTypeKind::ServiceAccountUpdated => "ServiceAccountUpdated",
        EventTypeKind::ServiceAccountDeleted => "ServiceAccountDeleted",
        EventTypeKind::ServiceAccountTokenRotated => "ServiceAccountTokenRotated",
        EventTypeKind::SubscriptionCreated => "SubscriptionCreated",
        EventTypeKind::SubscriptionCreationDenied => "SubscriptionCreationDenied",
        EventTypeKind::SubscriptionUpdated => "SubscriptionUpdated",
        EventTypeKind::SubscriptionPaused => "SubscriptionPaused",
        EventTypeKind::SubscriptionResumed => "SubscriptionResumed",
        EventTypeKind::SubscriptionDeleted => "SubscriptionDeleted",
        EventTypeKind::SubscriptionDisabled => "SubscriptionDisabled",
        EventTypeKind::ArtifactDownloaded => "ArtifactDownloaded",
        EventTypeKind::ApiTokenUsed => "ApiTokenUsed",
        // Terminal artifact-lifecycle GC events — low-volume, subscribable
        // (full round-trip, unlike StreamSealed).
        EventTypeKind::ArtifactExpired => "ArtifactExpired",
        EventTypeKind::ArtifactPurged => "ArtifactPurged",
        // Internal retention tombstone. The input-side map
        // (str -> EventTypeKind, above) has no `"StreamSealed"` arm and
        // its catch-all rejects it, so this never appears in a stored
        // subscription filter; the arm exists only to keep this closed
        // match total.
        EventTypeKind::StreamSealed => "StreamSealed",
        // Admin-only policy audit; never appears in a stored user
        // subscription filter. The arm exists only to keep this closed
        // match total.
        EventTypeKind::RetentionPolicyChanged => "RetentionPolicyChanged",
    }
    .to_string()
}

/// Wire form of [`SubscriptionState`]. The `Disabled` variant carries a
/// reason + timestamp on the domain side but the wire surface collapses
/// it to the literal `"disabled"` — the failure reason is in the
/// `SubscriptionDisabled` audit event, not the read DTO.
fn subscription_state_wire(s: &SubscriptionState) -> &'static str {
    match s {
        SubscriptionState::Active => "Active",
        SubscriptionState::Paused => "Paused",
        SubscriptionState::Disabled { .. } => "Disabled",
    }
}

// ---------------------------------------------------------------------------
// PATCH-only-state detection
// ---------------------------------------------------------------------------

/// Returns `true` when the PATCH body sets ONLY the `state` field
/// (every other field is `None`). Used by the handler to dispatch to
/// `pause()` / `resume()` instead of `update()` — matches the design
/// doc §3 "PATCH /:id" surface.
pub fn is_state_only_update(req: &UpdateSubscriptionRequest) -> bool {
    req.state.is_some()
        && req.name.is_none()
        && req.description.is_none()
        && req.target.is_none()
        && req.filter.is_none()
}

// ---------------------------------------------------------------------------
// `Option<Option<String>>` deserializer
// ---------------------------------------------------------------------------

/// Deserializer that distinguishes `"description": null` (clear) from
/// `"description": "..."` (set) from the field being absent (leave
/// alone). `serde`'s `#[serde(default)]` covers the "absent" case
/// (outer `None`); this adapter handles the explicit `null` case (inner
/// `None`, outer `Some(None)`).
fn deserialize_explicit_null_option<'de, D>(de: D) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    // Wire input is either `null` or a string. `Option::deserialize`
    // accepts both; we then wrap in the outer `Some(...)` so the absent
    // case (which `#[serde(default)]` produces as the outer `None`)
    // stays distinct.
    Option::<String>::deserialize(de).map(Some)
}

// ---------------------------------------------------------------------------
// Public helper — used by handler to validate categories uniqueness
// (the use case does not enforce this; the wire surface does).
// ---------------------------------------------------------------------------

/// Returns `true` when `categories` contains a duplicate. Used by the
/// handler to surface a clean `400` rather than letting the dispatcher
/// double-deliver on the same category.
pub fn has_duplicate_categories(categories: &[String]) -> bool {
    let mut seen: HashSet<&str> = HashSet::with_capacity(categories.len());
    categories.iter().any(|c| !seen.insert(c.as_str()))
}
