//! Subscription lifecycle audit events (see
//! `docs/architecture/explanation/event-notifications.md`).
//!
//! Emitted by `SubscriptionUseCase` through `EventStore`.
//! Streams live in category [`StreamCategory::User`](super::StreamCategory::User);
//! each user has one stream keyed by `user_id`.
//!
//! See `docs/architecture/explanation/event-notifications.md` for the
//! on-the-wire contract.
//!
//! # Stream placement
//!
//! - [`SubscriptionCreated`], [`SubscriptionUpdated`], [`SubscriptionPaused`],
//!   [`SubscriptionResumed`], [`SubscriptionDeleted`], [`SubscriptionDisabled`]
//!   land on the **owner's** user stream
//!   ([`StreamId::user(owner_user_id)`](super::StreamId::user)).
//! - [`SubscriptionCreationDenied`] lands on the **requesting actor's**
//!   user stream — there is no subscription row to reference, and the
//!   timeline being audited is "this user tried to create a subscription
//!   and was refused". Same pattern as
//!   [`ApiTokenIssuanceDenied`](super::ApiTokenIssuanceDenied).
//!
//! # No PII / no raw inputs
//!
//! Payloads carry only ids + structural summaries + closed enums. The
//! offending URL host, NATS subject, repository id list, name, and
//! description never reach the audit log — they live in the operational
//! `subscriptions` row (for successful creates) or are dropped (for denies).
//! [`FilterSummary`] is a structural digest (categories, event-type count,
//! repository-scope kind, predicate hash) so the audit consumer can route /
//! aggregate without ingesting the raw filter.
//!
//! # Actor lives on the envelope, not the payload
//!
//! Same convention as [`api_token_events`](super::api_token_events): the
//! authoritative actor is recorded on [`PersistedEvent`](super::PersistedEvent)
//! via the use case's `AppendEvents.actor`; payloads only carry the
//! information the audit consumer cannot recover from the envelope (for
//! [`SubscriptionCreationDenied`], `requesting_user_id` mirrors the envelope
//! actor's `user_id` for indexing parity with `ApiTokenIssuanceDenied`'s
//! `target_user_id` — also redundant by design).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::subscription::{DisableReason, SubscriptionDenialReason};
use crate::error::DomainResult;

// ---------------------------------------------------------------------------
// RepositoryScopeKind
// ---------------------------------------------------------------------------

/// Discriminator mirroring [`crate::entities::subscription::RepositoryScope`]
/// without carrying the repository-id list.
///
/// The actual repository id list (for `Some(_)` scopes) is operational
/// configuration on the `subscriptions` row; it is NOT audit information and
/// is therefore omitted from the lifecycle event payload. The kind
/// alone tells the audit consumer "did the operator pick OwnedByActor /
/// Some / All", which is all the SIEM needs to route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepositoryScopeKind {
    /// Mirrors `RepositoryScope::OwnedByActor`.
    OwnedByActor,
    /// Mirrors `RepositoryScope::Some(_)`. The repo-id list lives in the
    /// `subscriptions.filter` JSONB column, not in the event payload.
    Some,
    /// Mirrors `RepositoryScope::All` (admin-only).
    All,
}

// ---------------------------------------------------------------------------
// TargetKindWire
// ---------------------------------------------------------------------------

/// Wire-form discriminator for [`crate::entities::subscription::SubscriptionTarget`].
///
/// Closed enum — every new `SubscriptionTarget::*` variant needs a matching
/// arm here AND a deferred-items-sweep entry confirming the on-wire
/// `target_kind` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKindWire {
    /// HTTP webhook receiver — mirrors `SubscriptionTarget::Webhook`.
    Webhook,
    /// NATS JetStream subject — mirrors `SubscriptionTarget::NatsJetStream`.
    NatsJetStream,
}

// ---------------------------------------------------------------------------
// FilterSummary
// ---------------------------------------------------------------------------

/// Structural digest of a [`crate::entities::subscription::SubscriptionFilter`].
///
/// Carries:
/// - `categories`: lower-case category strings (mirror
///   [`crate::events::StreamCategory`]'s `Display` impl —
///   `"artifact"`, `"policy"`, `"admin"`, `"ref"`, `"artifact_group"`,
///   `"curation"`, `"repository"`, `"auth"`, `"authorization"`, `"user"`).
///   `Vec<String>` is deliberate for the wire form (just a
///   string list); a typed enum would force readers to share the
///   domain crate's `StreamCategory` definition for a field they only
///   need to filter on.
/// - `event_type_count`: how many `EventTypeKind` entries the filter
///   selected (or `u32::MAX` reserved for `EventTypeFilter::All`'s
///   "unbounded" — the use case picks a literal count for the audit
///   payload).
/// - `repository_scope_kind`: which branch of `RepositoryScope` the
///   filter picked; the actual id list (when `Some(_)`) is omitted.
/// - `predicate_hash`: BLAKE3 of the canonical predicate set. v1 ships
///   zero `NamedPredicate` variants, so the field is the zero array
///   for every v1 event. Audit consumers can detect "this subscription
///   has predicates" via `predicate_hash != [0; 32]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSummary {
    /// Lower-case category strings (see struct docs).
    pub categories: Vec<String>,
    /// Number of `EventTypeKind` entries selected.
    pub event_type_count: u32,
    /// Repository-scope discriminator.
    pub repository_scope_kind: RepositoryScopeKind,
    /// BLAKE3 of the canonical predicate set; `[0; 32]` for v1.
    pub predicate_hash: [u8; 32],
}

impl FilterSummary {
    /// Validate the structural summary. No string lengths to check — the
    /// `categories` strings come from a closed enum's `Display` impl, not
    /// user input. The method is kept for symmetry with
    /// [`super::DomainEvent::validate`].
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SubscriptionCreated
// ---------------------------------------------------------------------------

/// Recorded on every successful subscription creation.
///
/// Lands on the **owner's** user stream
/// ([`StreamId::user(owner_user_id)`](super::StreamId::user)). The actor
/// (which token / which session created the row) lives on the
/// [`PersistedEvent`](super::PersistedEvent) envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionCreated {
    /// Primary key of the row inserted into `subscriptions`.
    pub subscription_id: Uuid,
    /// User whose live grants gate delivery — `subscriptions.owner_user_id`.
    pub owner_user_id: Uuid,
    /// Wire-form target discriminator (no URL / no subject in the payload).
    pub target_kind: TargetKindWire,
    /// Structural digest of the filter — no raw repo-id list, no PII.
    pub filter_summary: FilterSummary,
    /// Number of resolved claim names captured into
    /// `subscriptions.snapshot_claims` at create time.
    /// **Count only** — claim *names* are never logged
    /// (operator-authored, may carry organisational topology). The
    /// count is the audit-useful signal (`0` = created via a PAT /
    /// empty-claims principal, the operator diagnostic).
    pub snapshot_claims_count: u32,
    /// Server-wall-clock at the moment the row was inserted.
    pub at: DateTime<Utc>,
}

impl SubscriptionCreated {
    /// Validate the event payload. No length-checked strings; see
    /// [`FilterSummary::validate`] for the rationale.
    pub fn validate(&self) -> DomainResult<()> {
        self.filter_summary.validate()
    }
}

// ---------------------------------------------------------------------------
// SubscriptionCreationDenied
// ---------------------------------------------------------------------------

/// Recorded on every refused subscription creation.
///
/// Lands on the **requesting actor's** user stream
/// ([`StreamId::user(requesting_user_id)`](super::StreamId::user)) — there
/// is no subscription row to reference, and the timeline being audited is
/// "this user tried to create a subscription and was refused". Same
/// pattern as
/// [`ApiTokenIssuanceDenied`](super::ApiTokenIssuanceDenied).
///
/// `requesting_user_id` mirrors the envelope actor's `user_id` for index
/// parity with `ApiTokenIssuanceDenied.target_user_id`; audit consumers
/// can read it off the payload without joining against the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionCreationDenied {
    /// User who tried to create the subscription. Redundant with the
    /// envelope actor's `user_id`, by design (mirrors
    /// [`ApiTokenIssuanceDenied.target_user_id`](super::ApiTokenIssuanceDenied)).
    pub requesting_user_id: Uuid,
    /// Wire-form target discriminator that was requested.
    pub requested_target_kind: TargetKindWire,
    /// Structural digest of the attempted filter — no raw repo-id list,
    /// no PII, no URL/subject.
    pub attempted_filter_summary: FilterSummary,
    /// Closed denial-reason category (see
    /// [`SubscriptionDenialReason`](crate::entities::subscription::SubscriptionDenialReason)).
    pub denial_reason: SubscriptionDenialReason,
    /// Server-wall-clock at the moment the request was refused.
    pub at: DateTime<Utc>,
}

impl SubscriptionCreationDenied {
    /// Validate the event payload. No length-checked strings.
    pub fn validate(&self) -> DomainResult<()> {
        self.attempted_filter_summary.validate()
    }
}

// ---------------------------------------------------------------------------
// SubscriptionUpdated
// ---------------------------------------------------------------------------

/// Recorded on every successful `PATCH /api/v1/subscriptions/:id`.
///
/// Lands on the **owner's** user stream. The actor performing the update
/// (owner vs admin) lives on the envelope.
///
/// `changed_fields` is a closed-set string list — the accepted values are
/// `"name"`, `"description"`, `"target"`, `"filter"`, `"state"`. A string
/// vec is simpler than a bitflag enum and round-trips cleanly through
/// JSONB; the use case picks values from a constant list, the audit
/// consumer routes on string match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionUpdated {
    /// Primary key of the row that was updated.
    pub subscription_id: Uuid,
    /// Owner — same stream the matching `SubscriptionCreated` landed on.
    pub owner_user_id: Uuid,
    /// Closed-set field names that changed (`"name"`, `"description"`,
    /// `"target"`, `"filter"`, `"state"`).
    pub changed_fields: Vec<String>,
    /// Number of resolved claim names in the post-update
    /// `subscriptions.snapshot_claims` (re-captured
    /// unconditionally on every persisted PATCH; full-replace authority
    /// floor). **Count only** — claim names are never logged. `0`
    /// after an update means the acting principal was a PAT /
    /// empty-claims principal (the PATCH-via-PAT-clears wrinkle).
    pub snapshot_claims_count: u32,
    /// Server-wall-clock at the moment the UPDATE landed.
    pub at: DateTime<Utc>,
}

impl SubscriptionUpdated {
    /// Validate the event payload. No length-checked strings.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SubscriptionPaused / SubscriptionResumed / SubscriptionDeleted
// ---------------------------------------------------------------------------

/// Recorded when the owner or an admin pauses the subscription.
///
/// Lands on the owner's user stream. The actor (self vs admin) lives on
/// the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionPaused {
    pub subscription_id: Uuid,
    pub owner_user_id: Uuid,
    pub at: DateTime<Utc>,
}

impl SubscriptionPaused {
    /// Validate the event payload. No length-checked strings.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

/// Recorded when the owner or an admin resumes a paused subscription.
///
/// Lands on the owner's user stream. The actor (self vs admin) lives on
/// the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionResumed {
    pub subscription_id: Uuid,
    pub owner_user_id: Uuid,
    pub at: DateTime<Utc>,
}

impl SubscriptionResumed {
    /// Validate the event payload. No length-checked strings.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

/// Recorded when the owner or an admin deletes the subscription.
///
/// Lands on the owner's user stream. The row is deleted from
/// `subscriptions`; this event is the durable audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionDeleted {
    pub subscription_id: Uuid,
    pub owner_user_id: Uuid,
    pub at: DateTime<Utc>,
}

impl SubscriptionDeleted {
    /// Validate the event payload. No length-checked strings.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SubscriptionDisabled
// ---------------------------------------------------------------------------

/// Recorded when the dispatcher transitions a subscription into
/// [`SubscriptionState::Disabled`](crate::entities::subscription::SubscriptionState::Disabled).
///
/// Lands on the owner's user stream. Silently dropping into a muted state
/// is a footgun — every disable transition emits this event so operators can
/// see the muted subscription via the audit log even if they miss the
/// CRUD-API state field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionDisabled {
    pub subscription_id: Uuid,
    pub owner_user_id: Uuid,
    /// Why the dispatcher (or an explicit admin action) disabled the
    /// subscription. See
    /// [`DisableReason`](crate::entities::subscription::DisableReason).
    pub reason: DisableReason,
    pub at: DateTime<Utc>,
}

impl SubscriptionDisabled {
    /// Validate the event payload. No length-checked strings.
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::subscription::SsrfBlockReason;

    // -- fixtures ----------------------------------------------------------

    fn filter_summary() -> FilterSummary {
        FilterSummary {
            categories: vec!["artifact".into(), "repository".into()],
            event_type_count: 3,
            repository_scope_kind: RepositoryScopeKind::OwnedByActor,
            predicate_hash: [0; 32],
        }
    }

    fn created() -> SubscriptionCreated {
        SubscriptionCreated {
            subscription_id: Uuid::from_u128(0x5_0B1),
            owner_user_id: Uuid::from_u128(0xACE),
            target_kind: TargetKindWire::Webhook,
            filter_summary: filter_summary(),
            snapshot_claims_count: 0,
            at: Utc::now(),
        }
    }

    fn denied() -> SubscriptionCreationDenied {
        SubscriptionCreationDenied {
            requesting_user_id: Uuid::from_u128(0xACE),
            requested_target_kind: TargetKindWire::Webhook,
            attempted_filter_summary: filter_summary(),
            denial_reason: SubscriptionDenialReason::PlaintextWebhookDisallowed,
            at: Utc::now(),
        }
    }

    fn updated() -> SubscriptionUpdated {
        SubscriptionUpdated {
            subscription_id: Uuid::from_u128(0x5_0B1),
            owner_user_id: Uuid::from_u128(0xACE),
            changed_fields: vec!["name".into(), "filter".into()],
            snapshot_claims_count: 0,
            at: Utc::now(),
        }
    }

    fn paused() -> SubscriptionPaused {
        SubscriptionPaused {
            subscription_id: Uuid::from_u128(0x5_0B1),
            owner_user_id: Uuid::from_u128(0xACE),
            at: Utc::now(),
        }
    }

    fn resumed() -> SubscriptionResumed {
        SubscriptionResumed {
            subscription_id: Uuid::from_u128(0x5_0B1),
            owner_user_id: Uuid::from_u128(0xACE),
            at: Utc::now(),
        }
    }

    fn deleted() -> SubscriptionDeleted {
        SubscriptionDeleted {
            subscription_id: Uuid::from_u128(0x5_0B1),
            owner_user_id: Uuid::from_u128(0xACE),
            at: Utc::now(),
        }
    }

    fn disabled() -> SubscriptionDisabled {
        SubscriptionDisabled {
            subscription_id: Uuid::from_u128(0x5_0B1),
            owner_user_id: Uuid::from_u128(0xACE),
            reason: DisableReason::DeliveryFailureBudgetExhausted,
            at: Utc::now(),
        }
    }

    /// PII / raw-input keys that MUST never appear in any subscription
    /// lifecycle payload (see module docs). Mirrors `api_token_events`'
    /// `issued_payload_does_not_carry_pii_keys` strip.
    const FORBIDDEN_PII_KEYS: &[&str] = &[
        "\"username\"",
        "\"email\"",
        "\"password\"",
        "\"hash\"",
        "\"plaintext\"",
        "\"secret\"",
    ];

    /// Extra forbidden keys for the denial event — the offending input
    /// (URL, subject, repo-id list) must NOT reach the audit payload.
    const FORBIDDEN_DENIAL_INPUT_KEYS: &[&str] = &["\"url\"", "\"subject\"", "\"repository_ids\""];

    // -- FilterSummary -----------------------------------------------------

    #[test]
    fn filter_summary_serde_round_trip_owned_by_actor() {
        let original = FilterSummary {
            repository_scope_kind: RepositoryScopeKind::OwnedByActor,
            ..filter_summary()
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: FilterSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.predicate_hash, [0; 32]);
    }

    #[test]
    fn filter_summary_serde_round_trip_some_and_all() {
        for scope in [RepositoryScopeKind::Some, RepositoryScopeKind::All] {
            let original = FilterSummary {
                repository_scope_kind: scope,
                predicate_hash: [9u8; 32],
                ..filter_summary()
            };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: FilterSummary = serde_json::from_str(&json).unwrap();
            assert_eq!(original, decoded);
            assert_eq!(decoded.predicate_hash, [9u8; 32]);
        }
    }

    #[test]
    fn filter_summary_validate_returns_ok() {
        filter_summary().validate().unwrap();
    }

    #[test]
    fn target_kind_wire_round_trips_both_variants() {
        for k in [TargetKindWire::Webhook, TargetKindWire::NatsJetStream] {
            let json = serde_json::to_string(&k).unwrap();
            let decoded: TargetKindWire = serde_json::from_str(&json).unwrap();
            assert_eq!(k, decoded);
        }
    }

    // -- SubscriptionCreated ----------------------------------------------

    #[test]
    fn created_validate_returns_ok() {
        created().validate().unwrap();
    }

    #[test]
    fn created_serde_round_trip() {
        let original = created();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubscriptionCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn created_payload_does_not_carry_pii_keys() {
        let json = serde_json::to_string(&created()).unwrap();
        for forbidden in FORBIDDEN_PII_KEYS {
            assert!(
                !json.contains(forbidden),
                "SubscriptionCreated JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn created_clone_eq() {
        let a = created();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- SubscriptionCreationDenied ---------------------------------------

    #[test]
    fn denied_validate_returns_ok() {
        denied().validate().unwrap();
    }

    #[test]
    fn denied_serde_round_trip() {
        let original = denied();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubscriptionCreationDenied = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn denied_payload_does_not_carry_pii_keys() {
        let json = serde_json::to_string(&denied()).unwrap();
        for forbidden in FORBIDDEN_PII_KEYS {
            assert!(
                !json.contains(forbidden),
                "SubscriptionCreationDenied JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn denied_payload_does_not_carry_raw_input_keys() {
        let json = serde_json::to_string(&denied()).unwrap();
        for forbidden in FORBIDDEN_DENIAL_INPUT_KEYS {
            assert!(
                !json.contains(forbidden),
                "SubscriptionCreationDenied JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn denied_clone_eq() {
        let a = denied();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn subscription_denial_reason_round_trips_every_variant() {
        // Every variant has to flow through serde without losing
        // discriminant identity — the audit consumer routes on
        // exact-match. WebhookTargetNotRoutable is the only payload-
        // bearing variant; we round-trip each SsrfBlockReason inner.
        let variants: Vec<SubscriptionDenialReason> = vec![
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
            SubscriptionDenialReason::WebhookTargetNotRoutable {
                ssrf_block_reason: SsrfBlockReason::DnsResolvedNotRoutable,
            },
            SubscriptionDenialReason::WebhookTargetNotRoutable {
                ssrf_block_reason: SsrfBlockReason::DnsResolutionFailed,
            },
            SubscriptionDenialReason::InvalidNatsSubject,
            SubscriptionDenialReason::InvalidWebhookUrl,
            SubscriptionDenialReason::DuplicateName,
        ];
        for r in variants {
            let original = SubscriptionCreationDenied {
                denial_reason: r.clone(),
                ..denied()
            };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: SubscriptionCreationDenied = serde_json::from_str(&json).unwrap();
            assert_eq!(original, decoded);
        }
    }

    // -- SubscriptionUpdated ----------------------------------------------

    #[test]
    fn updated_validate_returns_ok() {
        updated().validate().unwrap();
    }

    #[test]
    fn updated_serde_round_trip() {
        let original = updated();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubscriptionUpdated = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn updated_payload_does_not_carry_pii_keys() {
        let json = serde_json::to_string(&updated()).unwrap();
        for forbidden in FORBIDDEN_PII_KEYS {
            assert!(
                !json.contains(forbidden),
                "SubscriptionUpdated JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn updated_clone_eq() {
        let a = updated();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- SubscriptionPaused -----------------------------------------------

    #[test]
    fn paused_validate_returns_ok() {
        paused().validate().unwrap();
    }

    #[test]
    fn paused_serde_round_trip() {
        let original = paused();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubscriptionPaused = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn paused_payload_does_not_carry_pii_keys() {
        let json = serde_json::to_string(&paused()).unwrap();
        for forbidden in FORBIDDEN_PII_KEYS {
            assert!(
                !json.contains(forbidden),
                "SubscriptionPaused JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn paused_clone_eq() {
        let a = paused();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- SubscriptionResumed ----------------------------------------------

    #[test]
    fn resumed_validate_returns_ok() {
        resumed().validate().unwrap();
    }

    #[test]
    fn resumed_serde_round_trip() {
        let original = resumed();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubscriptionResumed = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn resumed_payload_does_not_carry_pii_keys() {
        let json = serde_json::to_string(&resumed()).unwrap();
        for forbidden in FORBIDDEN_PII_KEYS {
            assert!(
                !json.contains(forbidden),
                "SubscriptionResumed JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn resumed_clone_eq() {
        let a = resumed();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- SubscriptionDeleted ----------------------------------------------

    #[test]
    fn deleted_validate_returns_ok() {
        deleted().validate().unwrap();
    }

    #[test]
    fn deleted_serde_round_trip() {
        let original = deleted();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubscriptionDeleted = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn deleted_payload_does_not_carry_pii_keys() {
        let json = serde_json::to_string(&deleted()).unwrap();
        for forbidden in FORBIDDEN_PII_KEYS {
            assert!(
                !json.contains(forbidden),
                "SubscriptionDeleted JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn deleted_clone_eq() {
        let a = deleted();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- SubscriptionDisabled ---------------------------------------------

    #[test]
    fn disabled_validate_returns_ok() {
        disabled().validate().unwrap();
    }

    #[test]
    fn disabled_serde_round_trip() {
        let original = disabled();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubscriptionDisabled = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn disabled_payload_does_not_carry_pii_keys() {
        let json = serde_json::to_string(&disabled()).unwrap();
        for forbidden in FORBIDDEN_PII_KEYS {
            assert!(
                !json.contains(forbidden),
                "SubscriptionDisabled JSON must not carry {forbidden}, got: {json}"
            );
        }
    }

    #[test]
    fn disabled_clone_eq() {
        let a = disabled();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn disabled_round_trips_every_disable_reason() {
        for reason in [
            DisableReason::OwnerDeactivated,
            DisableReason::DeliveryFailureBudgetExhausted,
            DisableReason::OperatorDisabled,
        ] {
            let original = SubscriptionDisabled {
                reason,
                ..disabled()
            };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: SubscriptionDisabled = serde_json::from_str(&json).unwrap();
            assert_eq!(original, decoded);
            assert_eq!(decoded.reason, reason);
        }
    }
}
