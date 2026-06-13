//! Query parameter parsing + response shape for `GET /api/v1/events`
//! (design doc §9).
//!
//! Handler-specific DTOs derive `Deserialize` / `Serialize`; domain
//! types do NOT — the wire shape is owned here, not on the domain.
//! Matches the §8 webhook delivery shape byte-for-byte so consumers
//! parse one envelope regardless of whether the event arrived via
//! push or pull.

use serde::{Deserialize, Serialize};

/// Default `max` page size when the query param is absent.
pub const DEFAULT_MAX: u32 = 100;
/// Upper clamp on `max` — design doc §9 ("clamped to [1, 1000]").
pub const MAX_MAX: u32 = 1000;
/// Default `wait_ms` when the query param is absent (no long-poll).
pub const DEFAULT_WAIT_MS: u32 = 0;
/// Upper clamp on `wait_ms` — design doc §9 ("clamped to [0, 30000]").
pub const MAX_WAIT_MS: u32 = 30_000;

/// Query parameters for `GET /api/v1/events`.
///
/// Field validation per design doc §9:
/// - `category` is required; parsed via [`parse_category`] (closed match).
/// - `after` defaults to 0 (start from beginning of the global log).
/// - `max` defaults to [`DEFAULT_MAX`]; clamped to `[1, MAX_MAX]`.
/// - `wait_ms` defaults to [`DEFAULT_WAIT_MS`]; clamped to `[0, MAX_WAIT_MS]`.
#[derive(Debug, Clone, Deserialize)]
pub struct EventsQuery {
    pub category: String,
    #[serde(default)]
    pub after: u64,
    pub max: Option<u32>,
    pub wait_ms: Option<u32>,
}

impl EventsQuery {
    /// Resolve `max` to its effective value: applies [`DEFAULT_MAX`] when
    /// absent and clamps to `[1, MAX_MAX]`.
    pub fn resolved_max(&self) -> u32 {
        self.max.unwrap_or(DEFAULT_MAX).clamp(1, MAX_MAX)
    }

    /// Resolve `wait_ms` to its effective value: applies
    /// [`DEFAULT_WAIT_MS`] when absent and clamps to `[0, MAX_WAIT_MS]`.
    pub fn resolved_wait_ms(&self) -> u32 {
        self.wait_ms.unwrap_or(DEFAULT_WAIT_MS).min(MAX_WAIT_MS)
    }
}

/// Response envelope for `GET /api/v1/events`. Per design doc §9:
/// - `events` — the page of events visible to the caller (may be smaller
///   than `max` after per-repo filtering).
/// - `next_after` — last-seen `global_position` BEFORE filtering, so
///   consumers replaying don't double-process events that pass filtering
///   on a re-call. This is the design-doc trade-off.
/// - `has_more` — `true` when the unfiltered page size equalled `max`
///   (caller should re-query with the new `next_after`).
#[derive(Debug, Clone, Serialize)]
pub struct EventsResponse {
    pub events: Vec<PersistedEventDto>,
    pub next_after: u64,
    pub has_more: bool,
}

/// Wire-shape of a [`hort_domain::events::PersistedEvent`]. Matches the
/// webhook delivery payload (design doc §8) field-for-field so a
/// consumer parses one envelope regardless of source.
///
/// Field-level notes:
/// - `stream_category` is the lowercase wire string (`"artifact"`,
///   `"artifact_group"`, …), produced via [`stream_category_wire`].
/// - `actor` is a redacted JSON value via [`actor_to_wire`] — internal
///   actor variants don't leak system/timer distinction beyond the
///   `"subkind"` discriminator.
/// - `payload` is `serde_json::to_value(&event.event)` — the
///   `DomainEvent` enum's `Serialize` impl produces the same shape the
///   webhook adapter emits in §8.
#[derive(Debug, Clone, Serialize)]
pub struct PersistedEventDto {
    pub global_position: u64,
    pub stream_id: String,
    pub stream_category: String,
    pub stream_position: u64,
    pub event_id: String,
    pub event_type: String,
    pub event_version: u32,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub actor: serde_json::Value,
    pub correlation_id: String,
    pub causation_id: Option<String>,
    pub payload: serde_json::Value,
}

/// Map a domain [`hort_domain::events::PersistedEvent`] to its wire DTO.
/// See [`PersistedEventDto`] field docs for the exact shape contract.
pub fn map_event(event: &hort_domain::events::PersistedEvent) -> PersistedEventDto {
    PersistedEventDto {
        global_position: event.global_position,
        stream_id: event.stream_id.to_string(),
        stream_category: stream_category_wire(event.stream_id.category).to_string(),
        stream_position: event.stream_position,
        event_id: event.event_id.to_string(),
        event_type: event.event.event_type().to_string(),
        event_version: event.event_version,
        occurred_at: event.stored_at,
        actor: actor_to_wire(&event.actor),
        correlation_id: event.correlation_id.to_string(),
        causation_id: event.causation_id.map(|c| c.to_string()),
        payload: serde_json::to_value(&event.event).unwrap_or(serde_json::Value::Null),
    }
}

/// Lowercase wire string for a [`hort_domain::events::StreamCategory`].
/// Mirrors `StreamId::Display`'s prefix exactly. Closed match — adding
/// a new variant fails to compile here on purpose, same discipline as
/// [`parse_category`].
pub fn stream_category_wire(category: hort_domain::events::StreamCategory) -> &'static str {
    use hort_domain::events::StreamCategory;
    match category {
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

/// Redacted wire form of an [`hort_domain::events::Actor`]. Internal
/// variants leak only the `"subkind"` discriminator (`"system"` /
/// `"timer"`) — no struct-internal state, no token identifiers.
/// API actors expose only `user_id`; gitops actors expose
/// `source_file` only (no `spec_digest` / `applied_at` — those are
/// audit-store concerns, not consumer concerns).
pub fn actor_to_wire(actor: &hort_domain::events::Actor) -> serde_json::Value {
    use hort_domain::events::{Actor, ApiActor, InternalActor};
    match actor {
        Actor::Api(ApiActor { user_id }) => serde_json::json!({
            "kind": "api",
            "user_id": user_id.to_string(),
        }),
        Actor::Internal(InternalActor::System) => serde_json::json!({
            "kind": "internal",
            "subkind": "system",
        }),
        Actor::Internal(InternalActor::Timer) => serde_json::json!({
            "kind": "internal",
            "subkind": "timer",
        }),
        // The retention scheduler. Leaks only the bounded subkind
        // discriminator, no internal state.
        Actor::Internal(InternalActor::RetentionScheduler) => serde_json::json!({
            "kind": "internal",
            "subkind": "retention_scheduler",
        }),
        Actor::GitOps(g) => serde_json::json!({
            "kind": "gitops",
            "source_file": g.source_file,
        }),
    }
}

/// Closed-match category parser. Wire strings mirror
/// `StreamId::FromStr`'s table in `hort-domain::events::mod`. Adding a
/// new `StreamCategory` variant fails to compile here on purpose —
/// same discipline as Item 9's dto.rs uses on filter categories.
pub fn parse_category(s: &str) -> Result<hort_domain::events::StreamCategory, EventsQueryError> {
    use hort_domain::events::StreamCategory;
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
        _ => Err(EventsQueryError::UnknownCategory(s.to_string())),
    }
}

/// Query-param-level errors from [`parse_category`] / the handler's
/// own boundary checks.
#[derive(Debug, thiserror::Error)]
pub enum EventsQueryError {
    #[error("unknown category: {0}")]
    UnknownCategory(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::events::StreamCategory;

    // ---------------------------------------------------------------
    // parse_category: every wire string round-trips. A new variant
    // fails to compile here AND in `stream_category_wire`.
    // ---------------------------------------------------------------

    #[test]
    fn parse_category_accepts_every_wire_string() {
        let cases = [
            ("artifact", StreamCategory::Artifact),
            ("policy", StreamCategory::Policy),
            ("admin", StreamCategory::Admin),
            ("ref", StreamCategory::Ref),
            ("artifact_group", StreamCategory::ArtifactGroup),
            ("curation", StreamCategory::Curation),
            ("repository", StreamCategory::Repository),
            ("auth", StreamCategory::AuthAttempts),
            ("authorization", StreamCategory::Authorization),
            ("user", StreamCategory::User),
            ("download_audit", StreamCategory::DownloadAudit),
            ("token_use", StreamCategory::TokenUse),
        ];
        for (s, expected) in cases {
            assert_eq!(parse_category(s).unwrap(), expected, "wire string `{s}`");
            // Round-trip: the wire form maps back to the same string.
            assert_eq!(stream_category_wire(expected), s, "round-trip for `{s}`");
        }
    }

    #[test]
    fn parse_category_rejects_unknown() {
        let err = parse_category("does_not_exist").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does_not_exist"),
            "error should include the bad value, got: {msg}"
        );
    }

    // ---------------------------------------------------------------
    // EventsQuery clamping.
    // ---------------------------------------------------------------

    #[test]
    fn resolved_max_applies_default_when_absent() {
        let q = EventsQuery {
            category: "artifact".into(),
            after: 0,
            max: None,
            wait_ms: None,
        };
        assert_eq!(q.resolved_max(), DEFAULT_MAX);
    }

    #[test]
    fn resolved_max_clamps_zero_up_to_one() {
        let q = EventsQuery {
            category: "artifact".into(),
            after: 0,
            max: Some(0),
            wait_ms: None,
        };
        assert_eq!(q.resolved_max(), 1);
    }

    #[test]
    fn resolved_max_clamps_above_ceiling() {
        let q = EventsQuery {
            category: "artifact".into(),
            after: 0,
            max: Some(99_999),
            wait_ms: None,
        };
        assert_eq!(q.resolved_max(), MAX_MAX);
    }

    #[test]
    fn resolved_wait_ms_applies_default_when_absent() {
        let q = EventsQuery {
            category: "artifact".into(),
            after: 0,
            max: None,
            wait_ms: None,
        };
        assert_eq!(q.resolved_wait_ms(), DEFAULT_WAIT_MS);
    }

    #[test]
    fn resolved_wait_ms_clamps_above_ceiling() {
        let q = EventsQuery {
            category: "artifact".into(),
            after: 0,
            max: None,
            wait_ms: Some(120_000),
        };
        assert_eq!(q.resolved_wait_ms(), MAX_WAIT_MS);
    }

    // ---------------------------------------------------------------
    // actor_to_wire shape — covers every Actor variant.
    // ---------------------------------------------------------------

    #[test]
    fn actor_to_wire_api_emits_user_id() {
        use hort_domain::events::{Actor, ApiActor};
        let uid = uuid::Uuid::new_v4();
        let v = actor_to_wire(&Actor::Api(ApiActor { user_id: uid }));
        assert_eq!(v["kind"], "api");
        assert_eq!(v["user_id"], uid.to_string());
    }

    #[test]
    fn actor_to_wire_internal_system_emits_subkind() {
        use hort_domain::events::{Actor, InternalActor};
        let v = actor_to_wire(&Actor::Internal(InternalActor::System));
        assert_eq!(v["kind"], "internal");
        assert_eq!(v["subkind"], "system");
    }

    #[test]
    fn actor_to_wire_internal_timer_emits_subkind() {
        use hort_domain::events::{Actor, InternalActor};
        let v = actor_to_wire(&Actor::Internal(InternalActor::Timer));
        assert_eq!(v["kind"], "internal");
        assert_eq!(v["subkind"], "timer");
    }

    #[test]
    fn actor_to_wire_gitops_emits_source_file_only() {
        use hort_domain::events::{Actor, GitOpsActor};
        let v = actor_to_wire(&Actor::GitOps(GitOpsActor {
            source_file: "repositories/npm-public.yaml".into(),
            spec_digest: [0u8; 32],
            applied_at: chrono::Utc::now(),
        }));
        assert_eq!(v["kind"], "gitops");
        assert_eq!(v["source_file"], "repositories/npm-public.yaml");
        // spec_digest / applied_at are not exposed on the wire.
        assert!(v.get("spec_digest").is_none());
        assert!(v.get("applied_at").is_none());
    }
}
