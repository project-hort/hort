//! PostgreSQL implementation of [`SubscriptionRepository`].
//!
//! Mappings between [`Subscription`] and the on-disk row live in this
//! file rather than in `crate::mappers` — that module is reserved for
//! event-payload mappings.
//!
//! # Adapter-side JSONB discipline
//!
//! `target` and `filter` JSONB columns are encoded / decoded via the
//! in-file [`TargetDto`] / [`FilterDto`] / [`LastFailureDto`] types. The
//! domain entity (`hort_domain::entities::subscription::*`) deliberately
//! does NOT derive `Serialize` / `Deserialize` — the wire boundary is the
//! only place wire-shaped JSON is parsed, so an attacker who can write
//! arbitrary JSONB into the column cannot forge a [`Subscription`] with
//! an arbitrary webhook `secret_ref` or repository scope. The adapter DTOs are
//! private to this module and use [`serde_json::Value`] pattern-matches
//! (matching the precedent in `jobs_repository.rs` /
//! `artifact_group_repo.rs`) rather than a `#[derive(Deserialize)]` —
//! the closed-enum wire form is shorter to encode by hand than to
//! configure through serde attributes.
//!
//! # Tracing discipline
//!
//! - NEVER log raw SQL or bind values.
//! - NEVER log JSONB contents (target URL, secret hash, NATS subject).
//! - Operation logs surface `entity = "Subscription"` and
//!   `subscription_id` only (mirrors `api_token_repo.rs`).

use chrono::{DateTime, Utc};
use hort_domain::entities::subscription::{
    DisableReason, EventTypeFilter, EventTypeKind, NamedPredicate, RepositoryScope, Subscription,
    SubscriptionFailure, SubscriptionFilter, SubscriptionId, SubscriptionState, SubscriptionTarget,
};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::StreamCategory;
use hort_domain::ports::event_notifier::NotifyFailureReason;
use hort_domain::ports::subscription_repository::SubscriptionRepository;
use hort_domain::types::{Page, PageRequest};
use serde_json::{json, Map, Value as JsonValue};
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`SubscriptionRepository`].
pub struct PgSubscriptionRepository {
    pool: PgPool,
}

impl PgSubscriptionRepository {
    /// Construct a new repository handle around a connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Explicit column list — no `SELECT *`. Order MUST match the
/// [`SubscriptionRow::from_sqlx`] field reads so the row decoder picks
/// up columns positionally.
const SELECT_COLS: &str = r#"
    id, owner_user_id, created_by_token_id,
    name, description,
    target_kind, target, filter,
    snapshot_claims,
    state, disable_reason, disabled_since,
    last_delivered_position, last_failure,
    created_at
"#;

// ---------------------------------------------------------------------------
// State / disable-reason text helpers (closed-enum discipline at the SQL
// boundary).
// ---------------------------------------------------------------------------

/// Render a [`SubscriptionState`] discriminant to the wire-format string
/// the `subscriptions.state` column accepts.
///
/// The discriminant only — `since` and `reason` from
/// [`SubscriptionState::Disabled`] are persisted in the dedicated
/// `disabled_since` and `disable_reason` columns.
pub(crate) fn state_to_text(state: &SubscriptionState) -> &'static str {
    match state {
        SubscriptionState::Active => "active",
        SubscriptionState::Paused => "paused",
        SubscriptionState::Disabled { .. } => "disabled",
    }
}

/// Parse the wire-format `state` string from `subscriptions.state` into a
/// discriminant. Re-assembles the full [`SubscriptionState`] using the
/// `disable_reason` + `disabled_since` columns; `Disabled` rows without
/// both populated surface as `DomainError::Invariant`.
pub(crate) fn state_from_text(
    s: &str,
    disable_reason: Option<&str>,
    disabled_since: Option<DateTime<Utc>>,
) -> DomainResult<SubscriptionState> {
    match s {
        "active" => Ok(SubscriptionState::Active),
        "paused" => Ok(SubscriptionState::Paused),
        "disabled" => {
            let reason_str = disable_reason.ok_or_else(|| {
                DomainError::Invariant(
                    "subscriptions row with state='disabled' missing disable_reason".into(),
                )
            })?;
            let reason = disable_reason_from_text(reason_str)?;
            let since = disabled_since.ok_or_else(|| {
                DomainError::Invariant(
                    "subscriptions row with state='disabled' missing disabled_since".into(),
                )
            })?;
            Ok(SubscriptionState::Disabled { reason, since })
        }
        other => Err(DomainError::Invariant(format!(
            "corrupt state value in subscriptions row: {other}"
        ))),
    }
}

/// Render a [`DisableReason`] to the wire-format string the
/// `subscriptions.disable_reason` column's CHECK constraint accepts.
pub(crate) fn disable_reason_to_text(reason: DisableReason) -> &'static str {
    match reason {
        DisableReason::OwnerDeactivated => "owner_deactivated",
        DisableReason::DeliveryFailureBudgetExhausted => "delivery_failure_budget_exhausted",
        DisableReason::OperatorDisabled => "operator_disabled",
    }
}

/// Parse the wire-format `disable_reason` string back into a
/// [`DisableReason`]. The inline DB CHECK pins the column to the three
/// known values; this helper surfaces a corrupt-row Invariant on any
/// other literal.
pub(crate) fn disable_reason_from_text(s: &str) -> DomainResult<DisableReason> {
    match s {
        "owner_deactivated" => Ok(DisableReason::OwnerDeactivated),
        "delivery_failure_budget_exhausted" => Ok(DisableReason::DeliveryFailureBudgetExhausted),
        "operator_disabled" => Ok(DisableReason::OperatorDisabled),
        other => Err(DomainError::Invariant(format!(
            "corrupt disable_reason value in subscriptions row: {other}"
        ))),
    }
}

/// Render the wire-format `target_kind` discriminant string.
pub(crate) fn target_kind_to_text(target: &SubscriptionTarget) -> &'static str {
    match target {
        SubscriptionTarget::Webhook { .. } => "webhook",
        SubscriptionTarget::NatsJetStream { .. } => "nats_jetstream",
    }
}

// ---------------------------------------------------------------------------
// StreamCategory wire form
// ---------------------------------------------------------------------------

/// Wire form for a [`StreamCategory`] inside the `filter.categories`
/// JSON array. Mirrors `StreamId`'s `Display` impl (see
/// `crates/hort-domain/src/events/mod.rs`).
pub(crate) fn stream_category_to_text(c: StreamCategory) -> &'static str {
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
}

/// Inverse of [`stream_category_to_text`]. Unknown literals surface as
/// `DomainError::Invariant` (corrupt JSONB blob).
pub(crate) fn stream_category_from_text(s: &str) -> DomainResult<StreamCategory> {
    match s {
        "artifact" => Ok(StreamCategory::Artifact),
        "policy" => Ok(StreamCategory::Policy),
        "admin" => Ok(StreamCategory::Admin),
        "ref" => Ok(StreamCategory::Ref),
        "artifact_group" => Ok(StreamCategory::ArtifactGroup),
        "curation" => Ok(StreamCategory::Curation),
        "repository" => Ok(StreamCategory::Repository),
        "auth" => Ok(StreamCategory::AuthAttempts),
        "authorization" => Ok(StreamCategory::Authorization),
        "user" => Ok(StreamCategory::User),
        "download_audit" => Ok(StreamCategory::DownloadAudit),
        "token_use" => Ok(StreamCategory::TokenUse),
        "retention_policy" => Ok(StreamCategory::RetentionPolicy),
        other => Err(DomainError::Invariant(format!(
            "corrupt stream_category value in subscriptions.filter JSONB: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// EventTypeKind wire form (PascalCase variant name — matches the
// `event_type` string used in the notification payload).
// ---------------------------------------------------------------------------

/// Wire form for an [`EventTypeKind`] inside the
/// `filter.event_types.kinds` JSON array. The form is the variant name
/// verbatim — matches the `event_type` field shipped in the
/// notification payload so receivers parse one canonical string.
pub(crate) fn event_type_kind_to_text(k: EventTypeKind) -> &'static str {
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
        // Internal retention tombstone on the never-deleted
        // `admin-eventstore-retention` audit-meta stream. Mapped here
        // for the closed round-trip; it is not a user-subscribable event
        // type (the issuance use case never accepts it into a filter).
        EventTypeKind::StreamSealed => "StreamSealed",
        // Mapped here for the closed round-trip; the retention-policy
        // lifecycle is admin-only policy audit, not a user-subscribable
        // event type (the issuance use case never accepts it into a
        // filter — same posture as StreamSealed).
        EventTypeKind::RetentionPolicyChanged => "RetentionPolicyChanged",
    }
}

/// Inverse of [`event_type_kind_to_text`].
pub(crate) fn event_type_kind_from_text(s: &str) -> DomainResult<EventTypeKind> {
    match s {
        "ArtifactIngested" => Ok(EventTypeKind::ArtifactIngested),
        "ChecksumVerified" => Ok(EventTypeKind::ChecksumVerified),
        "ChecksumMismatch" => Ok(EventTypeKind::ChecksumMismatch),
        "ArtifactQuarantined" => Ok(EventTypeKind::ArtifactQuarantined),
        "ScanRequested" => Ok(EventTypeKind::ScanRequested),
        "ScanCompleted" => Ok(EventTypeKind::ScanCompleted),
        "ArtifactBecameVulnerable" => Ok(EventTypeKind::ArtifactBecameVulnerable),
        "ArtifactReleased" => Ok(EventTypeKind::ArtifactReleased),
        "ArtifactRejected" => Ok(EventTypeKind::ArtifactRejected),
        "ScanIndeterminate" => Ok(EventTypeKind::ScanIndeterminate),
        "ProvenanceVerified" => Ok(EventTypeKind::ProvenanceVerified),
        "ProvenanceRejected" => Ok(EventTypeKind::ProvenanceRejected),
        "ArtifactReEvaluated" => Ok(EventTypeKind::ArtifactReEvaluated),
        "PromotionRequested" => Ok(EventTypeKind::PromotionRequested),
        "PolicyEvaluated" => Ok(EventTypeKind::PolicyEvaluated),
        "ApprovalRequested" => Ok(EventTypeKind::ApprovalRequested),
        "ApprovalDecided" => Ok(EventTypeKind::ApprovalDecided),
        "ArtifactPromoted" => Ok(EventTypeKind::ArtifactPromoted),
        "PromotionRejected" => Ok(EventTypeKind::PromotionRejected),
        "PolicyCreated" => Ok(EventTypeKind::PolicyCreated),
        "PolicyUpdated" => Ok(EventTypeKind::PolicyUpdated),
        "ExclusionAdded" => Ok(EventTypeKind::ExclusionAdded),
        "ExclusionRemoved" => Ok(EventTypeKind::ExclusionRemoved),
        "PolicyArchived" => Ok(EventTypeKind::PolicyArchived),
        "CasIntegrityMismatch" => Ok(EventTypeKind::CasIntegrityMismatch),
        "ArtifactCorrupted" => Ok(EventTypeKind::ArtifactCorrupted),
        "RefMoved" => Ok(EventTypeKind::RefMoved),
        "RefRetired" => Ok(EventTypeKind::RefRetired),
        "ArtifactGroupInitiated" => Ok(EventTypeKind::ArtifactGroupInitiated),
        "ArtifactGroupMemberAdded" => Ok(EventTypeKind::ArtifactGroupMemberAdded),
        "ArtifactGroupMemberRemoved" => Ok(EventTypeKind::ArtifactGroupMemberRemoved),
        "ArtifactGroupPrimaryRoleAssigned" => Ok(EventTypeKind::ArtifactGroupPrimaryRoleAssigned),
        "CurationApplied" => Ok(EventTypeKind::CurationApplied),
        "AuthenticationAttempted" => Ok(EventTypeKind::AuthenticationAttempted),
        "OidcKeyRotated" => Ok(EventTypeKind::OidcKeyRotated),
        "AdminStatusChanged" => Ok(EventTypeKind::AdminStatusChanged),
        "ClaimMappingApplied" => Ok(EventTypeKind::ClaimMappingApplied),
        "ClaimMappingRevoked" => Ok(EventTypeKind::ClaimMappingRevoked),
        "PermissionGrantApplied" => Ok(EventTypeKind::PermissionGrantApplied),
        "PermissionGrantRevoked" => Ok(EventTypeKind::PermissionGrantRevoked),
        "RepositoryUpstreamMappingChanged" => Ok(EventTypeKind::RepositoryUpstreamMappingChanged),
        "ApiTokenIssued" => Ok(EventTypeKind::ApiTokenIssued),
        "ApiTokenRevoked" => Ok(EventTypeKind::ApiTokenRevoked),
        "ApiTokenIssuanceDenied" => Ok(EventTypeKind::ApiTokenIssuanceDenied),
        "TaskInvoked" => Ok(EventTypeKind::TaskInvoked),
        "TaskFailed" => Ok(EventTypeKind::TaskFailed),
        "PolicyReactivated" => Ok(EventTypeKind::PolicyReactivated),
        "OidcIssuerCreated" => Ok(EventTypeKind::OidcIssuerCreated),
        "OidcIssuerUpdated" => Ok(EventTypeKind::OidcIssuerUpdated),
        "OidcIssuerDeleted" => Ok(EventTypeKind::OidcIssuerDeleted),
        "ServiceAccountCreated" => Ok(EventTypeKind::ServiceAccountCreated),
        "ServiceAccountUpdated" => Ok(EventTypeKind::ServiceAccountUpdated),
        "ServiceAccountDeleted" => Ok(EventTypeKind::ServiceAccountDeleted),
        "ServiceAccountTokenRotated" => Ok(EventTypeKind::ServiceAccountTokenRotated),
        "SubscriptionCreated" => Ok(EventTypeKind::SubscriptionCreated),
        "SubscriptionCreationDenied" => Ok(EventTypeKind::SubscriptionCreationDenied),
        "SubscriptionUpdated" => Ok(EventTypeKind::SubscriptionUpdated),
        "SubscriptionPaused" => Ok(EventTypeKind::SubscriptionPaused),
        "SubscriptionResumed" => Ok(EventTypeKind::SubscriptionResumed),
        "SubscriptionDeleted" => Ok(EventTypeKind::SubscriptionDeleted),
        "SubscriptionDisabled" => Ok(EventTypeKind::SubscriptionDisabled),
        "ArtifactDownloaded" => Ok(EventTypeKind::ArtifactDownloaded),
        "ApiTokenUsed" => Ok(EventTypeKind::ApiTokenUsed),
        "ArtifactExpired" => Ok(EventTypeKind::ArtifactExpired),
        "ArtifactPurged" => Ok(EventTypeKind::ArtifactPurged),
        "StreamSealed" => Ok(EventTypeKind::StreamSealed),
        "RetentionPolicyChanged" => Ok(EventTypeKind::RetentionPolicyChanged),
        other => Err(DomainError::Invariant(format!(
            "corrupt event_type_kind value in subscriptions.filter JSONB: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// NotifyFailureReason wire form
// ---------------------------------------------------------------------------

/// Encode a [`NotifyFailureReason`] for the `last_failure.reason` JSONB
/// subtree. Tagged enum: `{"kind": "<discriminant>", ...extras}`.
pub(crate) fn notify_failure_reason_to_json(r: &NotifyFailureReason) -> JsonValue {
    match r {
        NotifyFailureReason::RedirectAttempted => json!({"kind": "redirect_attempted"}),
        NotifyFailureReason::Http4xx { status } => json!({"kind": "http_4xx", "status": status}),
        NotifyFailureReason::Http5xx { status } => json!({"kind": "http_5xx", "status": status}),
        NotifyFailureReason::ConnectTimeout => json!({"kind": "connect_timeout"}),
        NotifyFailureReason::RequestTimeout => json!({"kind": "request_timeout"}),
        NotifyFailureReason::Tls => json!({"kind": "tls"}),
        NotifyFailureReason::Dns => json!({"kind": "dns"}),
        NotifyFailureReason::ConnectionRefused => json!({"kind": "connection_refused"}),
        NotifyFailureReason::AckTimeout => json!({"kind": "ack_timeout"}),
        NotifyFailureReason::NatsNak => json!({"kind": "nats_nak"}),
        NotifyFailureReason::ConnectionLost => json!({"kind": "connection_lost"}),
        NotifyFailureReason::Other(s) => json!({"kind": "other", "message": s}),
    }
}

/// Decode a [`NotifyFailureReason`] from JSONB.
pub(crate) fn notify_failure_reason_from_json(v: &JsonValue) -> DomainResult<NotifyFailureReason> {
    let obj = v.as_object().ok_or_else(|| {
        DomainError::Invariant("subscriptions.last_failure.reason must be a JSON object".into())
    })?;
    let kind = obj.get("kind").and_then(JsonValue::as_str).ok_or_else(|| {
        DomainError::Invariant(
            "subscriptions.last_failure.reason missing 'kind' discriminant".into(),
        )
    })?;
    match kind {
        "redirect_attempted" => Ok(NotifyFailureReason::RedirectAttempted),
        "http_4xx" => {
            let status = status_u16(obj, "http_4xx")?;
            Ok(NotifyFailureReason::Http4xx { status })
        }
        "http_5xx" => {
            let status = status_u16(obj, "http_5xx")?;
            Ok(NotifyFailureReason::Http5xx { status })
        }
        "connect_timeout" => Ok(NotifyFailureReason::ConnectTimeout),
        "request_timeout" => Ok(NotifyFailureReason::RequestTimeout),
        "tls" => Ok(NotifyFailureReason::Tls),
        "dns" => Ok(NotifyFailureReason::Dns),
        "connection_refused" => Ok(NotifyFailureReason::ConnectionRefused),
        "ack_timeout" => Ok(NotifyFailureReason::AckTimeout),
        "nats_nak" => Ok(NotifyFailureReason::NatsNak),
        "connection_lost" => Ok(NotifyFailureReason::ConnectionLost),
        "other" => {
            let msg = obj
                .get("message")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| {
                    DomainError::Invariant(
                        "subscriptions.last_failure.reason 'other' missing 'message' field".into(),
                    )
                })?;
            Ok(NotifyFailureReason::Other(msg.to_string()))
        }
        other => Err(DomainError::Invariant(format!(
            "corrupt last_failure.reason kind in subscriptions row: {other}"
        ))),
    }
}

fn status_u16(obj: &Map<String, JsonValue>, kind: &str) -> DomainResult<u16> {
    let raw = obj
        .get("status")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| {
            DomainError::Invariant(format!(
                "subscriptions.last_failure.reason {kind} missing u16 'status'"
            ))
        })?;
    u16::try_from(raw).map_err(|_| {
        DomainError::Invariant(format!(
            "subscriptions.last_failure.reason {kind}.status out of u16 range: {raw}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Adapter DTOs — JSONB encode / decode
//
// These are private to the module and exist purely as the wire <-> domain
// translation layer. Domain types stay non-`Deserialize`; the wire
// boundary lives here.
// ---------------------------------------------------------------------------

/// Adapter DTO for the `target` JSONB column.
///
/// Wire form (internally-tagged):
/// - `{"kind": "webhook", "url": "<url>",
///    "secret_ref": {"source": "env_var"|"file", "location": "<locator>"}}`
/// - `{"kind": "nats_jetstream", "subject": "<subject>"}`
///
/// The webhook secret is stored as a [`SecretRef`] locator (env-var
/// name / file path), **never** the secret material or any hash of it.
/// A reader of this column holds only a pointer; the HMAC key is
/// resolved at delivery time via `SecretPort`. This mirrors the
/// `repository_upstream_mappings` `secret_ref` shape.
///
/// [`SecretRef`]: hort_domain::ports::secret_port::SecretRef
pub(crate) struct TargetDto;

impl TargetDto {
    /// Encode a [`SubscriptionTarget`] to its JSONB wire form.
    pub(crate) fn to_json(t: &SubscriptionTarget) -> JsonValue {
        match t {
            SubscriptionTarget::Webhook { url, secret_ref } => json!({
                "kind": "webhook",
                "url": url.as_str(),
                // `SecretRef` derives `Serialize`; serialising the
                // locator (not the secret) keeps the at-rest column
                // free of key material.
                "secret_ref": serde_json::to_value(secret_ref)
                    .unwrap_or(JsonValue::Null),
            }),
            SubscriptionTarget::NatsJetStream { subject } => json!({
                "kind": "nats_jetstream",
                "subject": subject,
            }),
        }
    }

    /// Decode a [`SubscriptionTarget`] from its JSONB wire form.
    pub(crate) fn from_json(v: &JsonValue) -> DomainResult<SubscriptionTarget> {
        let obj = v.as_object().ok_or_else(|| {
            DomainError::Invariant("subscriptions.target must be a JSON object".into())
        })?;
        let kind = obj.get("kind").and_then(JsonValue::as_str).ok_or_else(|| {
            DomainError::Invariant("subscriptions.target JSONB missing 'kind' discriminant".into())
        })?;
        match kind {
            "webhook" => {
                let url_str = obj.get("url").and_then(JsonValue::as_str).ok_or_else(|| {
                    DomainError::Invariant(
                        "subscriptions.target webhook missing string 'url'".into(),
                    )
                })?;
                let url = Url::parse(url_str).map_err(|e| {
                    DomainError::Invariant(format!(
                        "subscriptions.target webhook 'url' is not a valid URL: {e}"
                    ))
                })?;
                let secret_ref_json = obj.get("secret_ref").ok_or_else(|| {
                    DomainError::Invariant(
                        "subscriptions.target webhook missing 'secret_ref'".into(),
                    )
                })?;
                // `SecretRef` derives `Deserialize`; an unknown
                // `source` discriminant (the closed `SecretSource`
                // enum) fails here rather than silently defaulting.
                let secret_ref: hort_domain::ports::secret_port::SecretRef =
                    serde_json::from_value(secret_ref_json.clone()).map_err(|e| {
                        DomainError::Invariant(format!(
                            "subscriptions.target webhook 'secret_ref' is not a \
                             valid SecretRef: {e}"
                        ))
                    })?;
                Ok(SubscriptionTarget::Webhook { url, secret_ref })
            }
            "nats_jetstream" => {
                let subject = obj
                    .get("subject")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| {
                        DomainError::Invariant(
                            "subscriptions.target nats_jetstream missing string 'subject'".into(),
                        )
                    })?
                    .to_string();
                Ok(SubscriptionTarget::NatsJetStream { subject })
            }
            other => Err(DomainError::Invariant(format!(
                "corrupt target.kind in subscriptions row: {other}"
            ))),
        }
    }
}

/// Adapter DTO for the `filter` JSONB column.
///
/// Wire shape (flat object):
/// ```json
/// {
///   "categories": ["artifact", "policy"],
///   "event_types": {"kind": "all"}
///                | {"kind": "some", "kinds": ["ArtifactIngested", ...]},
///   "repositories": {"kind": "owned_by_actor"}
///                 | {"kind": "some", "repository_ids": ["<uuid>", ...]}
///                 | {"kind": "all"},
///   "named_predicates": []
/// }
/// ```
pub(crate) struct FilterDto;

impl FilterDto {
    /// Encode a [`SubscriptionFilter`] to its JSONB wire form.
    pub(crate) fn to_json(f: &SubscriptionFilter) -> JsonValue {
        let categories: Vec<JsonValue> = f
            .categories
            .iter()
            .map(|c| JsonValue::String(stream_category_to_text(*c).to_string()))
            .collect();
        let event_types = match &f.event_types {
            EventTypeFilter::All => json!({"kind": "all"}),
            EventTypeFilter::Some(kinds) => {
                let kinds: Vec<JsonValue> = kinds
                    .iter()
                    .map(|k| JsonValue::String(event_type_kind_to_text(*k).to_string()))
                    .collect();
                json!({"kind": "some", "kinds": kinds})
            }
        };
        let repositories = match &f.repositories {
            RepositoryScope::OwnedByActor => json!({"kind": "owned_by_actor"}),
            RepositoryScope::Some(ids) => {
                let ids: Vec<JsonValue> = ids
                    .iter()
                    .map(|id| JsonValue::String(id.to_string()))
                    .collect();
                json!({"kind": "some", "repository_ids": ids})
            }
            RepositoryScope::All => json!({"kind": "all"}),
        };
        // `NamedPredicate` is an empty enum in v1 — `named_predicates`
        // is always serialised as an empty array. The shape is reserved
        // for the audited extension path.
        json!({
            "categories": categories,
            "event_types": event_types,
            "repositories": repositories,
            "named_predicates": JsonValue::Array(Vec::new()),
        })
    }

    /// Decode a [`SubscriptionFilter`] from its JSONB wire form.
    pub(crate) fn from_json(v: &JsonValue) -> DomainResult<SubscriptionFilter> {
        let obj = v.as_object().ok_or_else(|| {
            DomainError::Invariant("subscriptions.filter must be a JSON object".into())
        })?;

        let categories_v = obj.get("categories").ok_or_else(|| {
            DomainError::Invariant("subscriptions.filter missing 'categories' array".into())
        })?;
        let categories_arr = categories_v.as_array().ok_or_else(|| {
            DomainError::Invariant("subscriptions.filter.categories must be a JSON array".into())
        })?;
        let categories = categories_arr
            .iter()
            .map(|c| {
                c.as_str()
                    .ok_or_else(|| {
                        DomainError::Invariant(
                            "subscriptions.filter.categories[] must be strings".into(),
                        )
                    })
                    .and_then(stream_category_from_text)
            })
            .collect::<DomainResult<Vec<_>>>()?;

        let event_types = decode_event_types(obj.get("event_types").ok_or_else(|| {
            DomainError::Invariant("subscriptions.filter missing 'event_types'".into())
        })?)?;

        let repositories = decode_repository_scope(obj.get("repositories").ok_or_else(|| {
            DomainError::Invariant("subscriptions.filter missing 'repositories'".into())
        })?)?;

        // v1 invariant — `NamedPredicate` is the empty enum, so any
        // non-empty `named_predicates` array is corrupt JSONB or wire
        // forgery. Reject explicitly rather than silently dropping.
        let predicates_v = obj.get("named_predicates").ok_or_else(|| {
            DomainError::Invariant("subscriptions.filter missing 'named_predicates'".into())
        })?;
        let predicates_arr = predicates_v.as_array().ok_or_else(|| {
            DomainError::Invariant(
                "subscriptions.filter.named_predicates must be a JSON array".into(),
            )
        })?;
        if !predicates_arr.is_empty() {
            return Err(DomainError::Invariant(
                "subscriptions.filter.named_predicates must be empty in v1 (closed-enum)".into(),
            ));
        }
        let named_predicates: Vec<NamedPredicate> = Vec::new();

        Ok(SubscriptionFilter {
            categories,
            event_types,
            repositories,
            named_predicates,
        })
    }
}

fn decode_event_types(v: &JsonValue) -> DomainResult<EventTypeFilter> {
    let obj = v.as_object().ok_or_else(|| {
        DomainError::Invariant("subscriptions.filter.event_types must be a JSON object".into())
    })?;
    let kind = obj.get("kind").and_then(JsonValue::as_str).ok_or_else(|| {
        DomainError::Invariant(
            "subscriptions.filter.event_types missing 'kind' discriminant".into(),
        )
    })?;
    match kind {
        "all" => Ok(EventTypeFilter::All),
        "some" => {
            let arr = obj
                .get("kinds")
                .and_then(JsonValue::as_array)
                .ok_or_else(|| {
                    DomainError::Invariant(
                        "subscriptions.filter.event_types.some missing 'kinds' array".into(),
                    )
                })?;
            let kinds = arr
                .iter()
                .map(|k| {
                    k.as_str()
                        .ok_or_else(|| {
                            DomainError::Invariant(
                                "subscriptions.filter.event_types.kinds[] must be strings".into(),
                            )
                        })
                        .and_then(event_type_kind_from_text)
                })
                .collect::<DomainResult<Vec<_>>>()?;
            Ok(EventTypeFilter::Some(kinds))
        }
        other => Err(DomainError::Invariant(format!(
            "corrupt event_types.kind in subscriptions row: {other}"
        ))),
    }
}

fn decode_repository_scope(v: &JsonValue) -> DomainResult<RepositoryScope> {
    let obj = v.as_object().ok_or_else(|| {
        DomainError::Invariant("subscriptions.filter.repositories must be a JSON object".into())
    })?;
    let kind = obj.get("kind").and_then(JsonValue::as_str).ok_or_else(|| {
        DomainError::Invariant(
            "subscriptions.filter.repositories missing 'kind' discriminant".into(),
        )
    })?;
    match kind {
        "owned_by_actor" => Ok(RepositoryScope::OwnedByActor),
        "all" => Ok(RepositoryScope::All),
        "some" => {
            let arr = obj
                .get("repository_ids")
                .and_then(JsonValue::as_array)
                .ok_or_else(|| {
                    DomainError::Invariant(
                        "subscriptions.filter.repositories.some missing 'repository_ids' array"
                            .into(),
                    )
                })?;
            let ids = arr
                .iter()
                .map(|id| {
                    id.as_str()
                        .ok_or_else(|| {
                            DomainError::Invariant(
                                "subscriptions.filter.repositories.repository_ids[] must be strings"
                                    .into(),
                            )
                        })
                        .and_then(|s| {
                            Uuid::parse_str(s).map_err(|e| {
                                DomainError::Invariant(format!(
                                    "subscriptions.filter.repositories.repository_ids[] not a UUID: {e}"
                                ))
                            })
                        })
                })
                .collect::<DomainResult<Vec<_>>>()?;
            Ok(RepositoryScope::Some(ids))
        }
        other => Err(DomainError::Invariant(format!(
            "corrupt repositories.kind in subscriptions row: {other}"
        ))),
    }
}

/// Adapter DTO for the `last_failure` JSONB column.
///
/// Wire form: `{"at": <RFC3339>, "reason": <NotifyFailureReason JSON>,
/// "consecutive_failures": <u32>}`.
pub(crate) struct LastFailureDto;

impl LastFailureDto {
    /// Encode a [`SubscriptionFailure`] to its JSONB wire form.
    pub(crate) fn to_json(f: &SubscriptionFailure) -> JsonValue {
        json!({
            "at": f.at.to_rfc3339(),
            "reason": notify_failure_reason_to_json(&f.reason),
            "consecutive_failures": f.consecutive_failures,
        })
    }

    /// Decode a [`SubscriptionFailure`] from its JSONB wire form.
    pub(crate) fn from_json(v: &JsonValue) -> DomainResult<SubscriptionFailure> {
        let obj = v.as_object().ok_or_else(|| {
            DomainError::Invariant("subscriptions.last_failure must be a JSON object".into())
        })?;
        let at_str = obj.get("at").and_then(JsonValue::as_str).ok_or_else(|| {
            DomainError::Invariant("subscriptions.last_failure missing string 'at'".into())
        })?;
        let at = DateTime::parse_from_rfc3339(at_str)
            .map_err(|e| {
                DomainError::Invariant(format!(
                    "subscriptions.last_failure 'at' is not a valid RFC3339 timestamp: {e}"
                ))
            })?
            .with_timezone(&Utc);
        let reason = notify_failure_reason_from_json(obj.get("reason").ok_or_else(|| {
            DomainError::Invariant("subscriptions.last_failure missing 'reason'".into())
        })?)?;
        let raw = obj
            .get("consecutive_failures")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| {
                DomainError::Invariant(
                    "subscriptions.last_failure missing u32 'consecutive_failures'".into(),
                )
            })?;
        let consecutive_failures = u32::try_from(raw).map_err(|_| {
            DomainError::Invariant(format!(
                "subscriptions.last_failure.consecutive_failures out of u32 range: {raw}"
            ))
        })?;
        Ok(SubscriptionFailure {
            at,
            reason,
            consecutive_failures,
        })
    }
}

// ---------------------------------------------------------------------------
// SubscriptionRow — sqlx decoded row + try_into_subscription.
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct SubscriptionRow {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub created_by_token_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    #[allow(dead_code)]
    pub target_kind: String,
    pub target: JsonValue,
    pub filter: JsonValue,
    pub snapshot_claims: Vec<String>,
    pub state: String,
    pub disable_reason: Option<String>,
    pub disabled_since: Option<DateTime<Utc>>,
    pub last_delivered_position: Option<i64>,
    pub last_failure: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
}

impl SubscriptionRow {
    /// Convert the raw row into the domain [`Subscription`].
    pub(crate) fn try_into_subscription(self) -> DomainResult<Subscription> {
        let target = TargetDto::from_json(&self.target)?;
        let filter = FilterDto::from_json(&self.filter)?;
        let state = state_from_text(
            &self.state,
            self.disable_reason.as_deref(),
            self.disabled_since,
        )?;
        let last_failure = match &self.last_failure {
            Some(v) => Some(LastFailureDto::from_json(v)?),
            None => None,
        };
        let last_delivered_position = match self.last_delivered_position {
            None => None,
            Some(i) if i < 0 => {
                return Err(DomainError::Invariant(format!(
                    "subscriptions.last_delivered_position is negative ({i})"
                )));
            }
            Some(i) => Some(i as u64),
        };
        Ok(Subscription {
            id: SubscriptionId(self.id),
            owner_user_id: self.owner_user_id,
            created_by_token_id: self.created_by_token_id,
            name: self.name,
            description: self.description,
            target,
            filter,
            snapshot_claims: self.snapshot_claims,
            state,
            last_delivered_position,
            last_failure,
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// NOTIFY emission for the `subscription_changes` channel
// ---------------------------------------------------------------------------

/// Emit `NOTIFY subscription_changes, '<uuid>'` inside the supplied
/// transaction. Pairs with `subscription_change_listener::dispatch_payload`
/// — the LISTEN side parses the same UUID-string format.
///
/// Channel name is fixed (no caller input interpolated into SQL);
/// payload is the canonical UUID string from `Display`, no embedded
/// quotes possible. Mirrors `api_token_repo::revoke`'s NOTIFY shape.
async fn emit_subscription_change_notify(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    subscription_id: Uuid,
) -> DomainResult<()> {
    let payload = format!("'{subscription_id}'");
    let notify_sql = format!(
        "NOTIFY {}, {}",
        crate::subscription_change_listener::SUBSCRIPTION_CHANGES_CHANNEL,
        payload
    );
    sqlx::query(&notify_sql)
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "Subscription", &subscription_id.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SubscriptionRepository impl
// ---------------------------------------------------------------------------

impl SubscriptionRepository for PgSubscriptionRepository {
    fn create(&self, sub: &Subscription) -> BoxFuture<'_, DomainResult<()>> {
        // Clone up-front so the future is `'static`-clean and no borrow
        // crosses the await boundary.
        let sub = sub.clone();
        Box::pin(async move {
            tracing::debug!(
                entity = "Subscription",
                subscription_id = %sub.id.0,
                "create"
            );

            let target_kind = target_kind_to_text(&sub.target);
            let target_json = TargetDto::to_json(&sub.target);
            let filter_json = FilterDto::to_json(&sub.filter);
            let state_str = state_to_text(&sub.state);
            let (disable_reason_str, disabled_since) = match &sub.state {
                SubscriptionState::Disabled { reason, since } => {
                    (Some(disable_reason_to_text(*reason)), Some(*since))
                }
                _ => (None, None),
            };
            let last_failure_json = sub.last_failure.as_ref().map(LastFailureDto::to_json);
            let last_delivered_position_i64: Option<i64> =
                sub.last_delivered_position.map(|p| p as i64);

            // INSERT and NOTIFY run in one transaction so listeners on
            // `subscription_changes` cannot observe the change-notify
            // before the row is visible (mirrors
            // `api_token_repo::revoke`'s shape).
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &sub.id.0.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO subscriptions (
                    id, owner_user_id, created_by_token_id,
                    name, description,
                    target_kind, target, filter,
                    snapshot_claims,
                    state, disable_reason, disabled_since,
                    last_delivered_position, last_failure,
                    created_at
                )
                VALUES (
                    $1, $2, $3,
                    $4, $5,
                    $6, $7, $8,
                    $9,
                    $10, $11, $12,
                    $13, $14,
                    $15
                )
                "#,
            )
            .bind(sub.id.0)
            .bind(sub.owner_user_id)
            .bind(sub.created_by_token_id)
            .bind(&sub.name)
            .bind(&sub.description)
            .bind(target_kind)
            .bind(&target_json)
            .bind(&filter_json)
            .bind(&sub.snapshot_claims)
            .bind(state_str)
            .bind(disable_reason_str)
            .bind(disabled_since)
            .bind(last_delivered_position_i64)
            .bind(&last_failure_json)
            .bind(sub.created_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e, "Subscription", &sub.id.0.to_string()))?;

            // Channel name is fixed (no caller input interpolated); payload
            // is the canonical UUID string from `Display`, no embedded
            // quotes possible.
            emit_subscription_change_notify(&mut tx, sub.id.0).await?;

            tx.commit()
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &sub.id.0.to_string()))?;

            Ok(())
        })
    }

    fn find_by_id(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<Subscription>> {
        Box::pin(async move {
            tracing::debug!(entity = "Subscription", subscription_id = %id.0, "find_by_id");
            let sql = format!("SELECT {SELECT_COLS} FROM subscriptions WHERE id = $1");
            let row: SubscriptionRow = sqlx::query_as(&sql)
                .bind(id.0)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &id.0.to_string()))?;
            row.try_into_subscription()
        })
    }

    fn find_by_name(
        &self,
        owner: Uuid,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Subscription>>> {
        let name = name.to_string();
        Box::pin(async move {
            tracing::debug!(entity = "Subscription", owner_user_id = %owner, "find_by_name");
            let sql = format!(
                "SELECT {SELECT_COLS} FROM subscriptions \
                 WHERE owner_user_id = $1 AND name = $2 LIMIT 1"
            );
            let row: Option<SubscriptionRow> = sqlx::query_as(&sql)
                .bind(owner)
                .bind(&name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", "find_by_name"))?;
            row.map(SubscriptionRow::try_into_subscription).transpose()
        })
    }

    fn list_for_owner(
        &self,
        owner: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Subscription>>> {
        let offset = page.offset as i64;
        let limit = page.limit as i64;
        Box::pin(async move {
            tracing::debug!(entity = "Subscription", owner_user_id = %owner, "list_for_owner");
            let sql = format!(
                "SELECT {SELECT_COLS} FROM subscriptions WHERE owner_user_id = $1 \
                 ORDER BY created_at DESC OFFSET $2 LIMIT $3"
            );
            let rows: Vec<SubscriptionRow> = sqlx::query_as(&sql)
                .bind(owner)
                .bind(offset)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &owner.to_string()))?;

            let total: Option<i64> =
                sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions WHERE owner_user_id = $1")
                    .bind(owner)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "Subscription", "count"))?;

            let items = rows
                .into_iter()
                .map(SubscriptionRow::try_into_subscription)
                .collect::<DomainResult<Vec<_>>>()?;
            Ok(Page {
                items,
                total: total.unwrap_or(0).max(0) as u64,
            })
        })
    }

    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<Subscription>>> {
        Box::pin(async move {
            tracing::debug!(entity = "Subscription", "list_active");
            let sql = format!(
                "SELECT {SELECT_COLS} FROM subscriptions WHERE state = 'active' \
                 ORDER BY created_at ASC"
            );
            let rows: Vec<SubscriptionRow> = sqlx::query_as(&sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", "list_active"))?;
            rows.into_iter()
                .map(SubscriptionRow::try_into_subscription)
                .collect::<DomainResult<Vec<_>>>()
        })
    }

    fn update(&self, sub: &Subscription) -> BoxFuture<'_, DomainResult<()>> {
        // Clone up-front (same discipline as `create`).
        let sub = sub.clone();
        Box::pin(async move {
            tracing::debug!(
                entity = "Subscription",
                subscription_id = %sub.id.0,
                "update"
            );

            let target_kind = target_kind_to_text(&sub.target);
            let target_json = TargetDto::to_json(&sub.target);
            let filter_json = FilterDto::to_json(&sub.filter);
            let state_str = state_to_text(&sub.state);
            let (disable_reason_str, disabled_since) = match &sub.state {
                SubscriptionState::Disabled { reason, since } => {
                    (Some(disable_reason_to_text(*reason)), Some(*since))
                }
                _ => (None, None),
            };
            let last_failure_json = sub.last_failure.as_ref().map(LastFailureDto::to_json);
            let last_delivered_position_i64: Option<i64> =
                sub.last_delivered_position.map(|p| p as i64);

            // UPDATE and NOTIFY in one transaction — see `create`.
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &sub.id.0.to_string()))?;

            // Immutable post-create: id, owner_user_id, created_by_token_id,
            // created_at — these are NOT in the SET list (use-case enforces
            // the contract; the SQL surface mirrors it).
            sqlx::query(
                r#"
                UPDATE subscriptions SET
                    name = $2,
                    description = $3,
                    target_kind = $4,
                    target = $5,
                    filter = $6,
                    snapshot_claims = $7,
                    state = $8,
                    disable_reason = $9,
                    disabled_since = $10,
                    last_delivered_position = $11,
                    last_failure = $12
                WHERE id = $1
                "#,
            )
            .bind(sub.id.0)
            .bind(&sub.name)
            .bind(&sub.description)
            .bind(target_kind)
            .bind(&target_json)
            .bind(&filter_json)
            .bind(&sub.snapshot_claims)
            .bind(state_str)
            .bind(disable_reason_str)
            .bind(disabled_since)
            .bind(last_delivered_position_i64)
            .bind(&last_failure_json)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e, "Subscription", &sub.id.0.to_string()))?;

            emit_subscription_change_notify(&mut tx, sub.id.0).await?;

            tx.commit()
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &sub.id.0.to_string()))?;

            Ok(())
        })
    }

    fn delete(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            tracing::debug!(entity = "Subscription", subscription_id = %id.0, "delete");
            // DELETE and NOTIFY in one transaction — see `create`.
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &id.0.to_string()))?;
            sqlx::query("DELETE FROM subscriptions WHERE id = $1")
                .bind(id.0)
                .execute(&mut *tx)
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &id.0.to_string()))?;
            emit_subscription_change_notify(&mut tx, id.0).await?;
            tx.commit()
                .await
                .map_err(|e| map_sqlx_error(&e, "Subscription", &id.0.to_string()))?;
            Ok(())
        })
    }

    fn update_last_delivered(
        &self,
        id: SubscriptionId,
        position: u64,
        last_failure: Option<&SubscriptionFailure>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        // Encode the failure (if any) eagerly so the future is
        // `'static`-clean.
        let position_i64 = position as i64;
        let last_failure_json = last_failure.map(LastFailureDto::to_json);
        Box::pin(async move {
            tracing::debug!(
                entity = "Subscription",
                subscription_id = %id.0,
                "update_last_delivered"
            );
            sqlx::query(
                "UPDATE subscriptions SET \
                 last_delivered_position = $2, last_failure = $3 \
                 WHERE id = $1",
            )
            .bind(id.0)
            .bind(position_i64)
            .bind(&last_failure_json)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "Subscription", &id.0.to_string()))?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // -----------------------------------------------------------------------
    // TargetDto round-trips
    // -----------------------------------------------------------------------

    fn webhook_secret_ref() -> hort_domain::ports::secret_port::SecretRef {
        hort_domain::ports::secret_port::SecretRef {
            source: hort_domain::ports::secret_port::SecretSource::EnvVar,
            location: "HORT_WEBHOOK_SECRET".into(),
        }
    }

    #[test]
    fn target_dto_webhook_round_trip() {
        let url: Url = "https://hooks.example.com/r/abc".parse().unwrap();
        let target = SubscriptionTarget::Webhook {
            url,
            secret_ref: webhook_secret_ref(),
        };
        let json = TargetDto::to_json(&target);
        let back = TargetDto::from_json(&json).unwrap();
        assert_eq!(target, back);
    }

    #[test]
    fn target_dto_webhook_json_carries_secret_ref_not_hash() {
        // The JSONB column must carry the `(source, location)` locator,
        // NOT the secret material or any hash of it. A reader of the
        // row holds only a pointer to an env var / file — not the
        // HMAC key.
        let url: Url = "https://hooks.example.com/r/abc".parse().unwrap();
        let target = SubscriptionTarget::Webhook {
            url,
            secret_ref: webhook_secret_ref(),
        };
        let json = TargetDto::to_json(&target);
        let obj = json.as_object().expect("object");
        assert_eq!(obj.get("kind").and_then(JsonValue::as_str), Some("webhook"));
        assert!(
            obj.get("secret_hash").is_none(),
            "the legacy at-rest secret_hash field must NOT be emitted"
        );
        let secret = obj
            .get("secret_ref")
            .and_then(JsonValue::as_object)
            .expect("secret_ref object present");
        assert_eq!(
            secret.get("source").and_then(JsonValue::as_str),
            Some("env_var")
        );
        assert_eq!(
            secret.get("location").and_then(JsonValue::as_str),
            Some("HORT_WEBHOOK_SECRET")
        );
    }

    #[test]
    fn target_dto_nats_round_trip() {
        let target = SubscriptionTarget::NatsJetStream {
            subject: "hort.events.artifact_promoted".into(),
        };
        let json = TargetDto::to_json(&target);
        let back = TargetDto::from_json(&json).unwrap();
        assert_eq!(target, back);
    }

    #[test]
    fn target_dto_rejects_missing_kind() {
        let json = json!({"url": "https://example.com/",
            "secret_ref": {"source": "env_var", "location": "X"}});
        let err = TargetDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn target_dto_rejects_unknown_kind() {
        let json = json!({"kind": "kafka", "topic": "foo"});
        let err = TargetDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn target_dto_rejects_non_object() {
        let json = json!(["not", "an", "object"]);
        let err = TargetDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn target_dto_webhook_rejects_bad_url() {
        let json = json!({"kind": "webhook", "url": "not a url",
            "secret_ref": {"source": "env_var", "location": "X"}});
        let err = TargetDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn target_dto_webhook_rejects_missing_secret_ref() {
        let json = json!({"kind": "webhook", "url": "https://example.com/"});
        let err = TargetDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn target_dto_webhook_rejects_malformed_secret_ref() {
        // Unknown `source` discriminant must be rejected — defends the
        // closed `SecretSource` enum at the JSONB boundary.
        let json = json!({"kind": "webhook", "url": "https://example.com/",
            "secret_ref": {"source": "vault", "location": "kv/x"}});
        let err = TargetDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn target_dto_nats_rejects_missing_subject() {
        let json = json!({"kind": "nats_jetstream"});
        let err = TargetDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -----------------------------------------------------------------------
    // FilterDto round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn filter_dto_round_trip_all_events() {
        let f = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact, StreamCategory::Policy],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::OwnedByActor,
            named_predicates: Vec::new(),
        };
        let json = FilterDto::to_json(&f);
        let back = FilterDto::from_json(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn filter_dto_round_trip_some_events() {
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let f = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::Some(vec![
                EventTypeKind::ArtifactIngested,
                EventTypeKind::ArtifactPromoted,
            ]),
            repositories: RepositoryScope::Some(vec![repo_a, repo_b]),
            named_predicates: Vec::new(),
        };
        let json = FilterDto::to_json(&f);
        let back = FilterDto::from_json(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn filter_dto_round_trip_all_repos_scope() {
        let f = SubscriptionFilter {
            categories: vec![StreamCategory::Repository],
            event_types: EventTypeFilter::All,
            repositories: RepositoryScope::All,
            named_predicates: Vec::new(),
        };
        let json = FilterDto::to_json(&f);
        let back = FilterDto::from_json(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn filter_dto_rejects_non_empty_named_predicates() {
        // Forge a JSONB blob with a non-empty named_predicates array;
        // v1 invariant 4 says the closed enum is empty.
        let json = json!({
            "categories": ["artifact"],
            "event_types": {"kind": "all"},
            "repositories": {"kind": "owned_by_actor"},
            "named_predicates": ["forged_predicate"],
        });
        let err = FilterDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn filter_dto_rejects_unknown_category() {
        let json = json!({
            "categories": ["unknown_category"],
            "event_types": {"kind": "all"},
            "repositories": {"kind": "owned_by_actor"},
            "named_predicates": [],
        });
        let err = FilterDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn filter_dto_rejects_unknown_event_type_kind() {
        let json = json!({
            "categories": ["artifact"],
            "event_types": {"kind": "some", "kinds": ["NotARealKind"]},
            "repositories": {"kind": "owned_by_actor"},
            "named_predicates": [],
        });
        let err = FilterDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn filter_dto_rejects_repositories_some_with_invalid_uuid() {
        let json = json!({
            "categories": ["artifact"],
            "event_types": {"kind": "all"},
            "repositories": {"kind": "some", "repository_ids": ["not-a-uuid"]},
            "named_predicates": [],
        });
        let err = FilterDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn filter_dto_rejects_unknown_event_types_kind_discriminant() {
        let json = json!({
            "categories": ["artifact"],
            "event_types": {"kind": "regex", "pattern": ".*"},
            "repositories": {"kind": "owned_by_actor"},
            "named_predicates": [],
        });
        let err = FilterDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn filter_dto_rejects_unknown_repositories_kind_discriminant() {
        let json = json!({
            "categories": ["artifact"],
            "event_types": {"kind": "all"},
            "repositories": {"kind": "by_label", "label": "foo"},
            "named_predicates": [],
        });
        let err = FilterDto::from_json(&json).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -----------------------------------------------------------------------
    // EventTypeKind table-driven round-trip — every present variant.
    // -----------------------------------------------------------------------

    #[test]
    fn event_type_kind_dto_round_trips_every_variant() {
        // ALL `EventTypeKind` variants — including the high-volume slots
        // that are not yet emittable from `DomainEvent` (the wire form
        // is forward-compatible).
        let all = [
            EventTypeKind::ArtifactIngested,
            EventTypeKind::ChecksumVerified,
            EventTypeKind::ChecksumMismatch,
            EventTypeKind::ArtifactQuarantined,
            EventTypeKind::ScanRequested,
            EventTypeKind::ScanCompleted,
            EventTypeKind::ArtifactBecameVulnerable,
            EventTypeKind::ArtifactReleased,
            EventTypeKind::ArtifactRejected,
            EventTypeKind::ScanIndeterminate,
            EventTypeKind::ProvenanceVerified,
            EventTypeKind::ProvenanceRejected,
            EventTypeKind::ArtifactReEvaluated,
            EventTypeKind::PromotionRequested,
            EventTypeKind::PolicyEvaluated,
            EventTypeKind::ApprovalRequested,
            EventTypeKind::ApprovalDecided,
            EventTypeKind::ArtifactPromoted,
            EventTypeKind::PromotionRejected,
            EventTypeKind::PolicyCreated,
            EventTypeKind::PolicyUpdated,
            EventTypeKind::ExclusionAdded,
            EventTypeKind::ExclusionRemoved,
            EventTypeKind::PolicyArchived,
            EventTypeKind::CasIntegrityMismatch,
            EventTypeKind::ArtifactCorrupted,
            EventTypeKind::RefMoved,
            EventTypeKind::RefRetired,
            EventTypeKind::ArtifactGroupInitiated,
            EventTypeKind::ArtifactGroupMemberAdded,
            EventTypeKind::ArtifactGroupMemberRemoved,
            EventTypeKind::ArtifactGroupPrimaryRoleAssigned,
            EventTypeKind::CurationApplied,
            EventTypeKind::AuthenticationAttempted,
            EventTypeKind::OidcKeyRotated,
            EventTypeKind::ClaimMappingApplied,
            EventTypeKind::ClaimMappingRevoked,
            EventTypeKind::PermissionGrantApplied,
            EventTypeKind::PermissionGrantRevoked,
            EventTypeKind::RepositoryUpstreamMappingChanged,
            EventTypeKind::ApiTokenIssued,
            EventTypeKind::ApiTokenRevoked,
            EventTypeKind::ApiTokenIssuanceDenied,
            EventTypeKind::TaskInvoked,
            EventTypeKind::TaskFailed,
            EventTypeKind::ArtifactDownloaded,
            EventTypeKind::ApiTokenUsed,
            EventTypeKind::ArtifactExpired,
            EventTypeKind::ArtifactPurged,
        ];
        for kind in all {
            let s = event_type_kind_to_text(kind);
            let back = event_type_kind_from_text(s).unwrap_or_else(|e| {
                panic!("kind {kind:?} round-trip failed: text={s:?} err={e:?}")
            });
            assert_eq!(kind, back, "wire form {s:?} did not round-trip");
        }
    }

    // -----------------------------------------------------------------------
    // StreamCategory round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn stream_category_dto_round_trips() {
        let all = [
            StreamCategory::Artifact,
            StreamCategory::Policy,
            StreamCategory::Admin,
            StreamCategory::Ref,
            StreamCategory::ArtifactGroup,
            StreamCategory::Curation,
            StreamCategory::Repository,
            StreamCategory::AuthAttempts,
            StreamCategory::Authorization,
            StreamCategory::User,
        ];
        for c in all {
            let s = stream_category_to_text(c);
            let back = stream_category_from_text(s).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn stream_category_from_text_rejects_unknown() {
        let err = stream_category_from_text("not_a_category").unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -----------------------------------------------------------------------
    // state / disable_reason wire form round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn state_to_text_and_back_active() {
        let s = SubscriptionState::Active;
        let text = state_to_text(&s);
        assert_eq!(text, "active");
        let back = state_from_text(text, None, None).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn state_to_text_and_back_paused() {
        let s = SubscriptionState::Paused;
        let text = state_to_text(&s);
        assert_eq!(text, "paused");
        let back = state_from_text(text, None, None).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn state_to_text_and_back_disabled() {
        let now = Utc::now();
        for reason in [
            DisableReason::OwnerDeactivated,
            DisableReason::DeliveryFailureBudgetExhausted,
            DisableReason::OperatorDisabled,
        ] {
            let s = SubscriptionState::Disabled { reason, since: now };
            let text = state_to_text(&s);
            assert_eq!(text, "disabled");
            let back =
                state_from_text(text, Some(disable_reason_to_text(reason)), Some(now)).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn state_from_text_rejects_unknown() {
        let err = state_from_text("frozen", None, None).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn state_from_text_disabled_missing_reason_is_invariant() {
        let err = state_from_text("disabled", None, Some(Utc::now())).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn state_from_text_disabled_missing_since_is_invariant() {
        let err = state_from_text("disabled", Some("operator_disabled"), None).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn disable_reason_to_text_and_back() {
        for reason in [
            DisableReason::OwnerDeactivated,
            DisableReason::DeliveryFailureBudgetExhausted,
            DisableReason::OperatorDisabled,
        ] {
            let s = disable_reason_to_text(reason);
            let back = disable_reason_from_text(s).unwrap();
            assert_eq!(reason, back);
        }
    }

    #[test]
    fn disable_reason_from_text_rejects_unknown() {
        let err = disable_reason_from_text("never_seen").unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -----------------------------------------------------------------------
    // target_kind wire helper
    // -----------------------------------------------------------------------

    #[test]
    fn target_kind_to_text_matches_discriminant() {
        let webhook = SubscriptionTarget::Webhook {
            url: "https://example.com/h".parse().unwrap(),
            secret_ref: webhook_secret_ref(),
        };
        let nats = SubscriptionTarget::NatsJetStream {
            subject: "hort.events".into(),
        };
        assert_eq!(target_kind_to_text(&webhook), "webhook");
        assert_eq!(target_kind_to_text(&nats), "nats_jetstream");
    }

    // -----------------------------------------------------------------------
    // NotifyFailureReason round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn notify_failure_reason_round_trips_every_variant() {
        let cases = [
            NotifyFailureReason::RedirectAttempted,
            NotifyFailureReason::Http4xx { status: 404 },
            NotifyFailureReason::Http5xx { status: 503 },
            NotifyFailureReason::ConnectTimeout,
            NotifyFailureReason::RequestTimeout,
            NotifyFailureReason::Tls,
            NotifyFailureReason::Dns,
            NotifyFailureReason::ConnectionRefused,
            NotifyFailureReason::AckTimeout,
            NotifyFailureReason::NatsNak,
            NotifyFailureReason::ConnectionLost,
            NotifyFailureReason::Other("explanatory reason".into()),
        ];
        for reason in cases {
            let v = notify_failure_reason_to_json(&reason);
            let back = notify_failure_reason_from_json(&v).unwrap();
            assert_eq!(reason, back);
        }
    }

    #[test]
    fn notify_failure_reason_rejects_unknown_kind() {
        let v = json!({"kind": "asteroid_strike"});
        let err = notify_failure_reason_from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn notify_failure_reason_rejects_other_missing_message() {
        let v = json!({"kind": "other"});
        let err = notify_failure_reason_from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn notify_failure_reason_rejects_http_missing_status() {
        let v = json!({"kind": "http_4xx"});
        let err = notify_failure_reason_from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn notify_failure_reason_rejects_status_out_of_range() {
        let v = json!({"kind": "http_4xx", "status": 999999});
        let err = notify_failure_reason_from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn notify_failure_reason_rejects_non_object() {
        let v = json!("redirect_attempted");
        let err = notify_failure_reason_from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -----------------------------------------------------------------------
    // LastFailureDto round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn last_failure_dto_round_trip() {
        let f = SubscriptionFailure {
            at: DateTime::parse_from_rfc3339("2026-05-13T12:34:56Z")
                .unwrap()
                .with_timezone(&Utc),
            reason: NotifyFailureReason::Http5xx { status: 503 },
            consecutive_failures: 17,
        };
        let v = LastFailureDto::to_json(&f);
        let back = LastFailureDto::from_json(&v).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn last_failure_dto_rejects_bad_timestamp() {
        let v = json!({
            "at": "not a timestamp",
            "reason": {"kind": "tls"},
            "consecutive_failures": 1,
        });
        let err = LastFailureDto::from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn last_failure_dto_rejects_missing_at() {
        let v = json!({
            "reason": {"kind": "tls"},
            "consecutive_failures": 1,
        });
        let err = LastFailureDto::from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn last_failure_dto_rejects_missing_consecutive_failures() {
        let v = json!({
            "at": "2026-05-13T12:34:56Z",
            "reason": {"kind": "tls"},
        });
        let err = LastFailureDto::from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn last_failure_dto_rejects_non_object() {
        let v = json!(["array", "not", "object"]);
        let err = LastFailureDto::from_json(&v).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -----------------------------------------------------------------------
    // SubscriptionRow round-trip via DTOs (no DB)
    // -----------------------------------------------------------------------

    #[test]
    fn subscription_row_try_into_subscription_round_trip() {
        let id = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let target = SubscriptionTarget::Webhook {
            url: "https://hooks.example.com/r/abc".parse().unwrap(),
            secret_ref: webhook_secret_ref(),
        };
        let filter = SubscriptionFilter {
            categories: vec![StreamCategory::Artifact],
            event_types: EventTypeFilter::Some(vec![EventTypeKind::ArtifactIngested]),
            repositories: RepositoryScope::Some(vec![repo]),
            named_predicates: Vec::new(),
        };
        let now = Utc::now();
        // `snapshot_claims` is a non-nullable column (DB default `'{}'`).
        // The mapper must carry a non-empty snapshot verbatim through
        // `try_into_subscription` — it is the dispatcher's authority
        // floor, so order and contents are load-bearing and must not be
        // normalised by the mapper.
        let snapshot = vec!["developer".to_string(), "team-alpha".to_string()];
        let row = SubscriptionRow {
            id,
            owner_user_id: owner,
            created_by_token_id: None,
            name: "ci-replicator".into(),
            description: Some("test".into()),
            target_kind: "webhook".into(),
            target: TargetDto::to_json(&target),
            filter: FilterDto::to_json(&filter),
            snapshot_claims: snapshot.clone(),
            state: "active".into(),
            disable_reason: None,
            disabled_since: None,
            last_delivered_position: Some(12_891),
            last_failure: None,
            created_at: now,
        };
        let sub = row.try_into_subscription().unwrap();
        assert_eq!(sub.id, SubscriptionId(id));
        assert_eq!(sub.owner_user_id, owner);
        assert_eq!(sub.target, target);
        assert_eq!(sub.filter, filter);
        assert_eq!(
            sub.snapshot_claims, snapshot,
            "snapshot_claims must round-trip verbatim (authority floor)"
        );
        assert_eq!(sub.state, SubscriptionState::Active);
        assert_eq!(sub.last_delivered_position, Some(12_891));
        assert!(sub.last_failure.is_none());
    }

    #[test]
    fn subscription_row_empty_snapshot_claims_round_trips_as_empty() {
        // The DB default for the new column is `'{}'` — an empty
        // snapshot (subscription created via PAT by a non-admin)
        // must survive the mapper as an empty `Vec`, NOT as `None`/panic.
        let row = SubscriptionRow {
            id: Uuid::new_v4(),
            owner_user_id: Uuid::new_v4(),
            created_by_token_id: None,
            name: "pat-created".into(),
            description: None,
            target_kind: "webhook".into(),
            target: json!({"kind": "webhook", "url": "https://e.com/",
                "secret_ref": {"source": "env_var", "location": "HORT_WEBHOOK_SECRET"}}),
            filter: json!({
                "categories": [],
                "event_types": {"kind": "all"},
                "repositories": {"kind": "owned_by_actor"},
                "named_predicates": [],
            }),
            snapshot_claims: Vec::new(),
            state: "active".into(),
            disable_reason: None,
            disabled_since: None,
            last_delivered_position: None,
            last_failure: None,
            created_at: Utc::now(),
        };
        let sub = row.try_into_subscription().unwrap();
        assert!(
            sub.snapshot_claims.is_empty(),
            "empty snapshot must map to an empty Vec (no admin authority synthesised here)"
        );
    }

    #[test]
    fn subscription_row_negative_last_delivered_position_is_invariant() {
        let row = SubscriptionRow {
            id: Uuid::new_v4(),
            owner_user_id: Uuid::new_v4(),
            created_by_token_id: None,
            name: "x".into(),
            description: None,
            target_kind: "webhook".into(),
            target: json!({"kind": "webhook", "url": "https://e.com/",
                "secret_ref": {"source": "env_var", "location": "HORT_WEBHOOK_SECRET"}}),
            filter: json!({
                "categories": [],
                "event_types": {"kind": "all"},
                "repositories": {"kind": "owned_by_actor"},
                "named_predicates": [],
            }),
            snapshot_claims: Vec::new(),
            state: "active".into(),
            disable_reason: None,
            disabled_since: None,
            last_delivered_position: Some(-1),
            last_failure: None,
            created_at: Utc::now(),
        };
        let err = row.try_into_subscription().unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -----------------------------------------------------------------------
    // Dyn-compat smoke + new() smoke
    // -----------------------------------------------------------------------

    /// Compile-time + runtime assertion that [`PgSubscriptionRepository`]
    /// satisfies the [`SubscriptionRepository`] trait through `&dyn`.
    /// Mirrors `api_token_repo.rs::_assert_dyn_compat`.
    #[tokio::test]
    async fn _assert_dyn_compat() {
        fn _is_dyn(_repo: &dyn SubscriptionRepository) {}
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let repo = PgSubscriptionRepository::new(pool);
        _is_dyn(&repo);
    }

    #[tokio::test]
    async fn pg_subscription_repo_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgSubscriptionRepository::new(pool);
    }

    // -----------------------------------------------------------------------
    // DB-backed integration tests (skipped when DATABASE_URL unset)
    // -----------------------------------------------------------------------

    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// The `snapshot_claims` authority floor must survive a full create
    /// → `find_by_id` round-trip through the `subscriptions` table
    /// verbatim (the dispatcher reads it as the delivery-principal
    /// source of truth; any normalisation here is a silent privilege
    /// drift). Deferred-execution: no `DATABASE_URL` here → `maybe_pool`
    /// returns `None` and this early-returns.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn snapshot_claims_round_trips_through_subscriptions_table() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        // `subscriptions.owner_user_id` is FK → `users(id)`; seed a
        // backing service-account user (mirrors
        // `permission_grant_repo::save_managed_round_trips_user_subject`).
        let owner = Uuid::new_v4();
        let uname = format!("sub-owner-{}", owner.simple());
        sqlx::query(
            "INSERT INTO users (id, username, email, auth_provider, is_service_account) \
             VALUES ($1, $2, $3, 'local', true)",
        )
        .bind(owner)
        .bind(&uname)
        .bind(format!("{uname}@example.test"))
        .execute(&pool)
        .await
        .expect("insert backing owner user");

        let repo = PgSubscriptionRepository::new(pool.clone());
        let id = SubscriptionId(Uuid::new_v4());
        let snapshot = vec!["developer".to_string(), "team-alpha".to_string()];
        let sub = Subscription {
            id,
            owner_user_id: owner,
            created_by_token_id: None,
            name: format!("sub-{}", id.0.simple()),
            description: Some("snapshot round-trip".into()),
            target: SubscriptionTarget::NatsJetStream {
                subject: "hort.events.artifact_promoted".into(),
            },
            filter: SubscriptionFilter {
                categories: vec![StreamCategory::Artifact],
                event_types: EventTypeFilter::All,
                repositories: RepositoryScope::OwnedByActor,
                named_predicates: Vec::new(),
            },
            snapshot_claims: snapshot.clone(),
            state: SubscriptionState::Active,
            last_delivered_position: None,
            last_failure: None,
            created_at: Utc::now(),
        };
        repo.create(&sub).await.expect("create subscription");

        let loaded = repo.find_by_id(id).await.expect("find_by_id");
        assert_eq!(
            loaded.snapshot_claims, snapshot,
            "snapshot_claims must round-trip verbatim through the subscriptions table"
        );

        // An empty-snapshot subscription (PAT-created by a non-admin)
        // must persist + reload as an empty Vec, not the DB default
        // surfacing as anything else.
        let id2 = SubscriptionId(Uuid::new_v4());
        let sub2 = Subscription {
            id: id2,
            name: format!("sub-{}", id2.0.simple()),
            snapshot_claims: Vec::new(),
            ..sub.clone()
        };
        repo.create(&sub2).await.expect("create empty-snapshot sub");
        let loaded2 = repo.find_by_id(id2).await.expect("find_by_id (empty)");
        assert!(
            loaded2.snapshot_claims.is_empty(),
            "empty snapshot_claims must round-trip as an empty Vec"
        );
    }
}
