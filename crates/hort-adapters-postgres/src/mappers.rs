use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::postgres::types::PgInterval;
use sqlx::FromRow;
use uuid::Uuid;

use hort_domain::entities::api_token::{ApiToken, TokenKind};
use hort_domain::entities::artifact::{Artifact, ArtifactMetadata, QuarantineStatus};
use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::oidc_issuer::{JwtAlg, OidcIssuer};
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::repository::{
    IndexMode, PrefetchPolicy, PrefetchTrigger, PromotionConfig, ReplicationPriority, Repository,
    RepositoryFormat, RepositoryType,
};
use hort_domain::entities::service_account::{
    FallbackRotation, FederatedIdentity, SecretFormat, ServiceAccount,
};
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::error::DomainError;
use hort_domain::events::{
    Actor, ApiActor, DomainEvent, InternalActor, PersistedEvent, StreamCategory, StreamId,
};
use hort_domain::types::ContentHash;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// RepositoryRow
// ---------------------------------------------------------------------------

/// Database row for the `repositories` table.
///
/// Enum columns are read as `TEXT` (via `::TEXT` casts in SQL) and parsed
/// into domain enums by the `From` impl. This avoids maintaining a parallel
/// set of sqlx enum types and naturally supports `RepositoryFormat::Other`.
#[derive(Debug, FromRow)]
pub struct RepositoryRow {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: String,
    pub repo_type: String,
    pub storage_backend: String,
    pub storage_path: String,
    pub upstream_url: Option<String>,
    /// Typed override for split-host registries (currently consulted
    /// only by the Cargo handler). Migration 096 adds the column NULL.
    /// The cross-spec validator in `hort-config` keeps `Some(_)`
    /// confined to cargo proxy repos so non-cargo rows never carry a
    /// meaningful value here.
    pub index_upstream_url: Option<String>,
    pub is_public: bool,
    /// Opt-in per-repository download auditing (ADR 0020). Migration
    /// 002 adds the column `DEFAULT false NOT NULL` (pre-release
    /// in-place edit); existing rows round-trip as `false`.
    pub download_audit_enabled: bool,
    /// Quarantine-aware index-serve mode (ADR 0007). Migration 002
    /// adds the column `DEFAULT 'released_only' NOT NULL` with a CHECK
    /// over `('released_only','include_pending')` (pre-release in-place
    /// edit; the second literal renamed from `filter_quarantined`);
    /// existing rows round-trip as `ReleasedOnly`.
    pub index_mode: String,
    /// Per-repository prefetch policy master switch
    /// (`prefetch_enabled` in the migration). Migration 002 adds the
    /// column `DEFAULT false NOT NULL` (pre-release in-place edit);
    /// existing rows round-trip as disabled. All prefetch consumers
    /// are gated on this flag.
    pub prefetch_enabled: bool,
    /// `text[]` of snake_case `PrefetchTrigger`
    /// literals. **Empty-list representation:** the column is nullable
    /// and `NULL` is the canonical "no triggers"; the mapper turns
    /// both `NULL` and `'{}'` into an empty `Vec<PrefetchTrigger>`.
    /// The CHECK constraint on the migration pins each element to the
    /// documented value-domain; the mapper's per-element
    /// `from_str().ok()` is defensive belt-and-braces against out-of-
    /// band SQL writes.
    pub prefetch_triggers: Option<Vec<String>>,
    /// N newest non-transitive versions to warm
    /// (`PrefetchPolicy::depth`). Nullable; `NULL` means "use the
    /// in-code default" so existing rows do not surface an
    /// operator-irrelevant number.
    pub prefetch_depth: Option<i32>,
    /// Cascade depth cap (`PrefetchPolicy::transitive_depth`).
    /// Nullable; `NULL` means "use the in-code default".
    pub prefetch_transitive_depth: Option<i32>,
    /// Skip versions older than this many days
    /// (`PrefetchPolicy::max_age_days`). Nullable in both Postgres and
    /// the domain — `NULL` ⇒ `None` ⇒ no age filter.
    pub prefetch_max_age_days: Option<i32>,
    /// Global cumulative cap on the transitive cascade
    /// (`PrefetchPolicy::max_descendants`, ADR 0015). Nullable; `NULL`
    /// means "use the in-code default" (= 200) per the established
    /// nullable-knob convention. Stored as Postgres `int` (i32); the
    /// row mapper narrows `i32 → u32` defensively (negative wrap on
    /// write → `unwrap_or(default)` on read).
    pub prefetch_max_descendants: Option<i32>,
    pub quota_bytes: Option<i64>,
    pub replication_priority: String,
    pub promotion_target_id: Option<Uuid>,
    pub promotion_policy_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// GitOps provenance flag. Migration 093 adds the column with a
    /// `'local'` default; existing rows therefore round trip as
    /// `ManagedBy::Local`. New gitops rows are written via
    /// `RepositoryRepository::save_managed`.
    pub managed_by: String,
    /// SHA-256 of the gitops `spec` JSON; non-NULL only for managed
    /// rows (the partial index `idx_repositories_managed_by` covers
    /// the common gitops sweep query).
    pub managed_by_digest: Option<Vec<u8>>,
}

impl From<RepositoryRow> for Repository {
    fn from(row: RepositoryRow) -> Self {
        // RepositoryFormat::from_str is infallible — unknown values become Other(s)
        let format: RepositoryFormat = row.format.parse().unwrap_or(RepositoryFormat::Generic);

        let repo_type: RepositoryType = row.repo_type.parse().unwrap_or(RepositoryType::Hosted);

        let replication_priority: ReplicationPriority = row
            .replication_priority
            .parse()
            .unwrap_or(ReplicationPriority::OnDemand);

        let promotion = row.promotion_target_id.map(|target_id| PromotionConfig {
            target_id,
            policy_id: row.promotion_policy_id,
        });

        // `curation_rule_names` is loaded from the
        // `repository_curation_rules` junction by the read paths in
        // `repository_repo.rs`, not from the row itself. The row mapper
        // returns an empty list; callers that need the rule attachments
        // populate them after fetching.

        // The DB CHECK constraint pins managed_by to ('local','gitops').
        // Mirror the existing `unwrap_or` defensive pattern used for the
        // other enum-mapped columns: an unknown literal coerces to the
        // safest default rather than panicking. Out-of-band corruption
        // is a separate concern (the strict mapper paths surface it as
        // Invariant on entities that own the security boundary).
        let managed_by = row.managed_by.parse().unwrap_or(ManagedBy::Local);

        // The DB CHECK pins `index_mode` to
        // `('released_only','include_pending')`. Mirror the existing
        // defensive `unwrap_or` pattern used for the other enum-mapped
        // columns: an out-of-band literal coerces to the safest default
        // (`ReleasedOnly` — also the column default, also build-safe)
        // rather than panicking. Only an out-of-band SQL write can land
        // here in production.
        let index_mode = row.index_mode.parse().unwrap_or(IndexMode::ReleasedOnly);

        // Assemble the `PrefetchPolicy` from the per-column row
        // fields. The migration's CHECK pins every `prefetch_triggers`
        // element to the three documented literals (`transitive_deps`,
        // `scheduled`, `on_dist_tag_move`); the mapper's per-element
        // `from_str().ok()` filters silently on the way in (mirrors
        // the `index_mode` + `managed_by` defensive `unwrap_or`
        // posture two stanzas above — an out-of-band SQL write must
        // not panic the read path). The system-level fail-fast for
        // stale literals lives at write-time: the loosened CHECK
        // constraint rejects any new literal not in the three-element
        // allowlist, and the migration's idempotent
        // `array_remove('on_index_fetch')` UPDATE drains any
        // pre-existing rows in lock-step. Nullable knob columns fall
        // back to `PrefetchPolicy::default()`'s values so a row
        // that pre-dates a knob column and a row explicitly declining
        // to set a knob agree.
        let prefetch_default = PrefetchPolicy::default();
        let prefetch_triggers: Vec<PrefetchTrigger> = row
            .prefetch_triggers
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| PrefetchTrigger::from_str(&s).ok())
            .collect();
        let prefetch_policy = PrefetchPolicy {
            enabled: row.prefetch_enabled,
            triggers: prefetch_triggers,
            depth: row
                .prefetch_depth
                .and_then(|d| u32::try_from(d).ok())
                .unwrap_or(prefetch_default.depth),
            transitive_depth: row
                .prefetch_transitive_depth
                .and_then(|d| u32::try_from(d).ok())
                .unwrap_or(prefetch_default.transitive_depth),
            max_age_days: row
                .prefetch_max_age_days
                .and_then(|d| u32::try_from(d).ok()),
            // `NULL` ⇒ in-code default (200). Defensive narrowing
            // mirrors the other nullable-knob columns: a row written
            // with a wrapped-to-negative i32 (out-of-band SQL write)
            // is treated as "absent" and the default applies.
            max_descendants: row
                .prefetch_max_descendants
                .and_then(|d| u32::try_from(d).ok())
                .unwrap_or(prefetch_default.max_descendants),
        };

        let managed_by_digest = row.managed_by_digest.and_then(|bytes| {
            // Truncated/oversized digests on the wire are treated like
            // an absent digest — the diff layer will then see the
            // current state as "no digest known" and produce an
            // `update` outcome on the next apply. This is gentler than
            // panicking and matches the prior defensive posture.
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        });

        Repository {
            id: row.id,
            key: row.key,
            name: row.name,
            description: row.description,
            format,
            repo_type,
            storage_backend: row.storage_backend,
            storage_path: row.storage_path,
            upstream_url: row.upstream_url,
            index_upstream_url: row.index_upstream_url,
            is_public: row.is_public,
            download_audit_enabled: row.download_audit_enabled,
            quota_bytes: row.quota_bytes,
            replication_priority,
            promotion,
            curation_rule_names: Vec::new(),
            index_mode,
            prefetch_policy,
            created_at: row.created_at,
            updated_at: row.updated_at,
            managed_by,
            managed_by_digest,
        }
    }
}

// ---------------------------------------------------------------------------
// ArtifactRow
// ---------------------------------------------------------------------------

/// Database row for the `artifacts` table.
#[derive(Debug, FromRow)]
pub struct ArtifactRow {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub name: String,
    pub name_as_published: String,
    pub version: Option<String>,
    pub path: String,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    pub checksum_sha1: Option<String>,
    pub checksum_md5: Option<String>,
    pub content_type: String,
    pub storage_key: String,
    pub quarantine_status: Option<String>,
    /// The stored observation-window anchor — column
    /// `quarantine_window_start`. The window *deadline* is computed
    /// live, never persisted.
    pub quarantine_window_start: Option<DateTime<Utc>>,
    /// Upstream-asserted publish timestamp, recorded best-effort at
    /// ingest. **Audit field — untrusted.** The window-anchor
    /// computation that consumes it is gated on the per-upstream
    /// `RepositoryUpstreamMapping.trust_upstream_publish_time`
    /// opt-in (ADR 0015); the value being present here is not in
    /// itself consumed by any release path.
    pub upstream_published_at: Option<DateTime<Utc>>,
    pub uploaded_by: Option<Uuid>,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<ArtifactRow> for Artifact {
    type Error = DomainError;

    fn try_from(row: ArtifactRow) -> Result<Self, Self::Error> {
        let quarantine_status = row
            .quarantine_status
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(QuarantineStatus::None);

        let sha256_checksum: ContentHash = row.checksum_sha256.trim().parse().map_err(|_| {
            DomainError::Invariant(format!("corrupt SHA-256 checksum in artifact {}", row.id))
        })?;

        Ok(Artifact {
            id: row.id,
            repository_id: row.repository_id,
            name: row.name,
            name_as_published: row.name_as_published,
            version: row.version,
            path: row.path,
            size_bytes: row.size_bytes,
            sha256_checksum,
            sha1_checksum: row.checksum_sha1,
            md5_checksum: row.checksum_md5,
            content_type: row.content_type,
            quarantine_status,
            // The structured rejection reason is not denormalised onto the
            // `artifacts` projection — it lives on the artifact's
            // `ArtifactRejected` event. The application layer re-hydrates
            // it from the stream before a scan re-evaluation (ADR 0041);
            // a fresh projection load always carries `None`, the same
            // transient-hydration contract as `quarantine_deadline`.
            rejection_reason: None,
            quarantine_window_start: row.quarantine_window_start,
            // The transient computed deadline is NEVER loaded from the
            // store; it is hydrated by the use-case layer on the read
            // path. A fresh row always carries `None`.
            quarantine_deadline: None,
            upstream_published_at: row.upstream_published_at,
            uploaded_by: row.uploaded_by,
            is_deleted: row.is_deleted,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// ArtifactMetadataRow
// ---------------------------------------------------------------------------

/// Database row for the `artifact_metadata` table.
///
/// 1:1 projection of format-specific ingest-time metadata. `format` stores
/// the `RepositoryFormat` display form — unknown values round-trip as
/// `RepositoryFormat::Other` (the conversion is infallible). `metadata_blob`
/// is the raw hex column (`003_artifacts_cas.sql`); conversion to the
/// domain's [`ContentHash`] happens in `TryFrom` and is fallible because
/// a corrupt hash string is a data-integrity error.
#[derive(Debug, FromRow)]
pub struct ArtifactMetadataRow {
    pub artifact_id: Uuid,
    pub format: String,
    pub metadata: serde_json::Value,
    pub metadata_blob: Option<String>,
    pub properties: serde_json::Value,
}

impl TryFrom<ArtifactMetadataRow> for ArtifactMetadata {
    type Error = DomainError;

    fn try_from(row: ArtifactMetadataRow) -> Result<Self, Self::Error> {
        // RepositoryFormat::from_str is infallible — unknown values become
        // Other(s). No default fallback needed.
        let format: RepositoryFormat = row.format.parse().unwrap_or(RepositoryFormat::Generic);

        // `metadata_blob` is written through the adapter's own upsert path,
        // which only ever binds a validated `ContentHash`. A bad hex string
        // reaching this mapper means someone wrote to the DB out-of-band
        // (direct SQL, operator repair, unrelated migration) — treat it as
        // a data-integrity failure, not a validation error surfaced to
        // end users.
        let metadata_blob = row
            .metadata_blob
            .map(|s| {
                ContentHash::from_str(&s).map_err(|e| {
                    tracing::warn!(
                        artifact_id = %row.artifact_id,
                        error = %e,
                        "corrupt metadata_blob hash in artifact_metadata row"
                    );
                    DomainError::Invariant(format!(
                        "corrupt metadata_blob hash in artifact_metadata {}",
                        row.artifact_id
                    ))
                })
            })
            .transpose()?;

        Ok(ArtifactMetadata {
            artifact_id: row.artifact_id,
            format,
            metadata: row.metadata,
            metadata_blob,
            properties: row.properties,
        })
    }
}

// ---------------------------------------------------------------------------
// UserRow
// ---------------------------------------------------------------------------

/// Database row for the `users` table — domain-relevant columns only.
///
/// The password / TOTP / lockout columns no longer exist in the schema.
/// The SELECT must still list columns explicitly — no `SELECT *`.
#[derive(Debug, FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub auth_provider: String,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub is_admin: bool,
    pub is_service_account: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<UserRow> for User {
    type Error = DomainError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        // Strict mapping. The `users.auth_provider` column has a CHECK
        // constraint in the schema, so a non-whitelisted value in a row
        // is a data-integrity failure (out-of-band SQL, corrupted
        // migration, schema drift). Previously this silently defaulted
        // to `Local`, which would let a corrupted row masquerade as a
        // local user. Fail loudly instead.
        let auth_provider: AuthProvider =
            row.auth_provider.parse::<AuthProvider>().map_err(|_| {
                tracing::error!(
                    value = %row.auth_provider,
                    user_id = %row.id,
                    "invalid auth_provider in users row"
                );
                DomainError::Invariant(format!(
                    "unexpected auth_provider in users row: {}",
                    row.auth_provider
                ))
            })?;

        Ok(User {
            id: row.id,
            username: row.username,
            email: row.email,
            auth_provider,
            external_id: row.external_id,
            display_name: row.display_name,
            is_active: row.is_active,
            is_admin: row.is_admin,
            is_service_account: row.is_service_account,
            last_login_at: row.last_login_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// EventRow
// ---------------------------------------------------------------------------

/// Database row for the `events` table.
///
/// `actor_source_file` and `actor_spec_digest` are non-NULL only when
/// `actor_type = 'gitops'`. The 081 migration's `chk_actor_id` enforces
/// the shape — the mapper trusts that and dispatches on `actor_type`
/// alone.
#[derive(Debug, FromRow)]
pub struct EventRow {
    pub event_id: Uuid,
    pub stream_id: String,
    pub stream_category: String,
    pub stream_position: i64,
    pub global_position: i64,
    pub event_type: String,
    pub event_version: i32,
    pub event_data: serde_json::Value,
    pub correlation_id: Uuid,
    pub causation_id: Option<Uuid>,
    pub actor_type: String,
    pub actor_id: Option<Uuid>,
    pub actor_source_file: Option<String>,
    pub actor_spec_digest: Option<Vec<u8>>,
    pub stored_at: DateTime<Utc>,
}

impl TryFrom<EventRow> for PersistedEvent {
    type Error = DomainError;

    fn try_from(row: EventRow) -> Result<Self, Self::Error> {
        let stream_id = StreamId::from_str(&row.stream_id).map_err(|e| {
            tracing::warn!(stream_id = %row.stream_id, "corrupt stream_id in event row");
            DomainError::Invariant(format!("corrupt stream_id: {e}"))
        })?;

        let actor = if row.actor_type == "gitops" {
            // Gitops rows carry source_file + spec_digest in extra
            // columns. The DB CHECK constraint guarantees they're
            // NOT NULL when actor_type='gitops'; we still surface a
            // concrete Invariant if a manual SQL write violated it,
            // since silently constructing a synthetic actor would
            // hide the corruption.
            let source_file = row.actor_source_file.clone().ok_or_else(|| {
                tracing::warn!(
                    event_id = %row.event_id,
                    "gitops event row missing actor_source_file"
                );
                DomainError::Invariant("gitops event missing actor_source_file".into())
            })?;
            let digest_bytes = row.actor_spec_digest.clone().ok_or_else(|| {
                tracing::warn!(
                    event_id = %row.event_id,
                    "gitops event row missing actor_spec_digest"
                );
                DomainError::Invariant("gitops event missing actor_spec_digest".into())
            })?;
            let digest: [u8; 32] = digest_bytes.as_slice().try_into().map_err(|_| {
                tracing::warn!(
                    event_id = %row.event_id,
                    actual_len = digest_bytes.len(),
                    "gitops event row has malformed actor_spec_digest length"
                );
                DomainError::Invariant(format!(
                    "gitops actor_spec_digest must be 32 bytes, got {}",
                    digest_bytes.len()
                ))
            })?;
            Actor::from_persisted_gitops(source_file, digest, row.stored_at)
        } else {
            Actor::from_persisted(&row.actor_type, row.actor_id).inspect_err(|_| {
                tracing::warn!(
                    actor_type = %row.actor_type,
                    actor_id = ?row.actor_id,
                    "corrupt actor in event row"
                );
            })?
        };

        let event = deserialize_event_data(&row.event_type, &row.event_data).inspect_err(|_| {
            tracing::warn!(
                event_type = %row.event_type,
                event_id = %row.event_id,
                "corrupt event_data in event row"
            );
        })?;

        Ok(PersistedEvent {
            event_id: row.event_id,
            stream_id,
            stream_position: row.stream_position as u64,
            global_position: row.global_position as u64,
            event,
            correlation_id: row.correlation_id,
            causation_id: row.causation_id,
            actor,
            event_version: row.event_version as u32,
            stored_at: row.stored_at,
        })
    }
}

/// Serialize a `DomainEvent` into the tagged JSON format stored in `event_data`.
///
/// Format: `{"type": "ArtifactIngested", "data": { ... payload ... }}`
pub(crate) fn serialize_event_data(event: &DomainEvent) -> serde_json::Value {
    let data = serde_json::to_value(event).expect("DomainEvent must be serializable");
    // serde serializes the enum as `{"<serde_key>": { fields }}`.
    // We re-shape to `{"type": "<event_type>", "data": { fields }}`.
    //
    // The stored `type` column carries `event_type()` — for
    // `RetentionPolicyChanged` that is the inner-discriminated
    // `RetentionPolicyCreated`/`…Updated`/`…Archived`/`…Evaluated`.
    // The `map.remove` MUST use `serde_variant_key()` — the actual
    // externally-tagged enum key serde emitted — which equals
    // `event_type()` for every other variant but is the wrapper key
    // `RetentionPolicyChanged` for the retention wrapper. Using
    // `event_type()` here would `remove` a non-existent key and
    // silently null the payload.
    let event_type = event.event_type();
    let serde_key = event.serde_variant_key();
    let payload = match data {
        serde_json::Value::Object(mut map) => {
            map.remove(serde_key).unwrap_or(serde_json::Value::Null)
        }
        other => other,
    };
    serde_json::json!({
        "type": event_type,
        "data": payload
    })
}

/// Deserialize a `DomainEvent` from the tagged JSON format.
fn deserialize_event_data(
    event_type: &str,
    event_data: &serde_json::Value,
) -> Result<DomainEvent, DomainError> {
    let data = event_data
        .get("data")
        .ok_or_else(|| DomainError::Invariant("event_data missing 'data' field".into()))?;

    // Reconstruct the serde enum format: `{"<serde_key>": { fields }}`.
    // The stored `type` is `event_type()`; serde needs the
    // externally-tagged variant key. They differ only for the
    // `RetentionPolicyChanged` wrapper (the four discriminated retention
    // strings all map back to the single wrapper key — serde's untagged
    // inner enum then resolves Created/Updated/Archived/Evaluated from
    // the payload shape). Identity for every other event type.
    let serde_key = DomainEvent::serde_key_for_event_type(event_type);
    let envelope = serde_json::json!({ serde_key: data });
    serde_json::from_value::<DomainEvent>(envelope)
        .map_err(|e| DomainError::Invariant(format!("failed to deserialize {event_type}: {e}")))
}

/// Columns the events-table INSERT writes for an `Actor`.
///
/// Six fields rather than two: `api` carries `actor_id`, `gitops`
/// carries `actor_source_file` + `actor_spec_digest`, and the rest
/// stay `None`. The 081 migration's `chk_actor_id` constraint
/// enforces the same shape on the DB side — this helper is the
/// single point of truth on the Rust side.
pub(crate) struct ActorColumns {
    pub actor_type: &'static str,
    pub actor_id: Option<Uuid>,
    pub actor_source_file: Option<String>,
    pub actor_spec_digest: Option<Vec<u8>>,
}

pub(crate) fn actor_to_columns(actor: &Actor) -> ActorColumns {
    match actor {
        Actor::Api(ApiActor { user_id }) => ActorColumns {
            actor_type: "api",
            actor_id: Some(*user_id),
            actor_source_file: None,
            actor_spec_digest: None,
        },
        Actor::Internal(InternalActor::System) => ActorColumns {
            actor_type: "system",
            actor_id: None,
            actor_source_file: None,
            actor_spec_digest: None,
        },
        Actor::Internal(InternalActor::Timer) => ActorColumns {
            actor_type: "timer",
            actor_id: None,
            actor_source_file: None,
            actor_spec_digest: None,
        },
        // Retention scheduler actor. No actor_id (the `004_events.sql`
        // chk_actor_id no-actor-id branch was extended to include
        // 'retention_scheduler').
        Actor::Internal(InternalActor::RetentionScheduler) => ActorColumns {
            actor_type: "retention_scheduler",
            actor_id: None,
            actor_source_file: None,
            actor_spec_digest: None,
        },
        Actor::GitOps(g) => ActorColumns {
            actor_type: "gitops",
            actor_id: None,
            actor_source_file: Some(g.source_file.clone()),
            actor_spec_digest: Some(g.spec_digest.to_vec()),
        },
    }
}

/// Convert a `StreamId` to database columns for INSERT.
pub(crate) fn stream_id_to_columns(stream_id: &StreamId) -> (String, &'static str) {
    let cat_str = match stream_id.category {
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
    (stream_id.to_string(), cat_str)
}

// ---------------------------------------------------------------------------
// ApiTokenRow
// ---------------------------------------------------------------------------

/// Database row for the `api_tokens` table (migration 008).
///
/// `kind` is stored as `VARCHAR(32)` with the inline CHECK
/// `('pat', 'service_account', 'cli_session')`; the wire string maps to the
/// domain [`TokenKind`] in [`ApiTokenRow::try_into_api_token`].
/// `declared_permissions` is `text[]`; each element parses through
/// [`Permission::from_str`] — an unknown element surfaces as
/// [`DomainError::Invariant`] (mirroring the role repo's discipline) rather
/// than silently dropping. `repository_ids` is `uuid[]` (NULL = inherit user
/// grants).
#[derive(Debug, FromRow)]
pub struct ApiTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub kind: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub declared_permissions: Vec<String>,
    pub repository_ids: Option<Vec<Uuid>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub last_used_user_agent: Option<String>,
    pub created_by_user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

impl ApiTokenRow {
    /// Convert the raw row into the domain [`ApiToken`].
    ///
    /// - `kind` is parsed via [`token_kind_from_text`] — unknown literals
    ///   are `DomainError::Invariant` (the inline DB CHECK already forbids
    ///   them; out-of-band SQL is the only way to land here).
    /// - `declared_permissions` is parsed element-wise via
    ///   [`Permission::from_str`]. ANY unrecognised element fails the
    ///   conversion — silently dropping a permission could narrow the cap
    ///   in a way that surprises operators reading audit logs.
    pub fn try_into_api_token(self) -> Result<ApiToken, DomainError> {
        let kind = token_kind_from_text(&self.kind).inspect_err(|_| {
            tracing::warn!(
                entity = "ApiToken",
                token_id = %self.id,
                value = %self.kind,
                "unknown kind in api_tokens row"
            );
        })?;

        let declared_permissions = self
            .declared_permissions
            .iter()
            .map(|p| {
                Permission::from_str(p).map_err(|_| {
                    tracing::warn!(
                        entity = "ApiToken",
                        token_id = %self.id,
                        value = %p,
                        "unknown permission in api_tokens.declared_permissions"
                    );
                    DomainError::Invariant(format!(
                        "corrupt declared_permissions value in api_tokens row: {p}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ApiToken {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            description: self.description,
            kind,
            token_hash: self.token_hash,
            token_prefix: self.token_prefix,
            declared_permissions,
            repository_ids: self.repository_ids,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
            last_used_at: self.last_used_at,
            last_used_ip: self.last_used_ip,
            last_used_user_agent: self.last_used_user_agent,
            created_by_user_id: self.created_by_user_id,
            created_at: self.created_at,
        })
    }
}

/// Convert the wire-format `kind` string from `api_tokens.kind` into the
/// domain [`TokenKind`].
///
/// Inline DB CHECK pins the column to the three known values; this helper
/// surfaces an Invariant on any other literal (out-of-band SQL).
pub(crate) fn token_kind_from_text(s: &str) -> Result<TokenKind, DomainError> {
    match s {
        "pat" => Ok(TokenKind::Pat),
        "service_account" => Ok(TokenKind::ServiceAccount),
        "cli_session" => Ok(TokenKind::CliSession),
        other => Err(DomainError::Invariant(format!(
            "corrupt kind value in api_tokens row: {other}"
        ))),
    }
}

/// Render the domain [`TokenKind`] into the wire-format string the
/// `api_tokens.kind` column accepts.
pub(crate) fn token_kind_to_text(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Pat => "pat",
        TokenKind::ServiceAccount => "service_account",
        TokenKind::CliSession => "cli_session",
    }
}

// ---------------------------------------------------------------------------
// GitOps machine-identity row mappers
// ---------------------------------------------------------------------------
//
// The `service_accounts` row maps to a `ServiceAccount` with empty
// `federated_identities` and `None` `fallback_rotation`; the repository
// impl issues separate queries to populate them. This keeps each row
// mapper a pure 1:1 column → field translation and matches the
// `RepositoryRow → Repository` precedent (curation rule names are
// loaded out-of-row by `repository_repo.rs`).

/// Translate a `PgInterval` to a `std::time::Duration`.
///
/// `PgInterval` carries months, days, and microseconds as three i64
/// columns. INTERVAL values written by the gitops schema only use the
/// microseconds component (the default `'1 hour'` literal and the
/// apply-side `duration_to_pg_interval` writer both land in
/// `microseconds`), but a defensive translation accepts all three —
/// month/day handling uses the standard non-leap conversion (30 days
/// per month, 86_400 seconds per day) to match
/// `scanner_registry_repository.rs`'s posture on the same shape.
///
/// Negative components, or microseconds that exceed `Duration`'s
/// `u64::MAX` seconds budget, surface as `DomainError::Invariant` —
/// the schema's CHECK constraints and the apply-time validator both
/// reject negative or absurd intervals, so reaching this branch
/// implies out-of-band SQL.
fn pg_interval_to_duration(iv: PgInterval) -> Result<Duration, DomainError> {
    if iv.microseconds < 0 || iv.days < 0 || iv.months < 0 {
        return Err(DomainError::Invariant(format!(
            "negative INTERVAL components are unsupported (months={}, days={}, micros={})",
            iv.months, iv.days, iv.microseconds
        )));
    }
    // Microseconds → secs + nanos. `microseconds` is non-negative,
    // so the cast to u64 is lossless within i64::MAX.
    let micros = iv.microseconds as u64;
    let secs_from_micros = micros / 1_000_000;
    let nanos_remainder = ((micros % 1_000_000) as u32) * 1_000;
    let secs_from_days = (iv.days as u64).saturating_mul(86_400);
    let secs_from_months = (iv.months as u64).saturating_mul(30 * 86_400);
    let total_secs = secs_from_micros
        .checked_add(secs_from_days)
        .and_then(|s| s.checked_add(secs_from_months))
        .ok_or_else(|| {
            DomainError::Invariant("INTERVAL overflows std::time::Duration".to_string())
        })?;
    Ok(Duration::new(total_secs, nanos_remainder))
}

// ---------------------------------------------------------------------------
// OidcIssuerRow → OidcIssuer
// ---------------------------------------------------------------------------

/// Database row for the `oidc_issuers` table (migration 011).
///
/// `jwks_refresh_interval` is read as `PgInterval` (sqlx's native
/// INTERVAL representation) and converted to `std::time::Duration` in
/// the mapper. `allowed_algorithms` is `TEXT[]`; each element parses
/// through [`JwtAlg::from_str`] — unknown literals surface as
/// `DomainError::Invariant` because the apply-time validator gates
/// writes to the supported set (only out-of-band SQL can land here).
#[derive(Debug, FromRow)]
pub struct OidcIssuerRow {
    pub id: Uuid,
    pub name: String,
    pub issuer_url: String,
    pub audiences: Vec<String>,
    pub jwks_refresh_interval: PgInterval,
    pub allowed_algorithms: Vec<String>,
    /// JTI-presence enforcement flag (ADR 0007). `oidc_issuers.require_jti
    /// BOOLEAN NOT NULL DEFAULT TRUE` (migration 011). NOT NULL so the
    /// mapper reads a plain `bool`, not `Option<bool>`.
    pub require_jti: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<OidcIssuerRow> for OidcIssuer {
    type Error = DomainError;

    fn try_from(row: OidcIssuerRow) -> Result<Self, Self::Error> {
        let jwks_refresh_interval = pg_interval_to_duration(row.jwks_refresh_interval)
            .inspect_err(|e| {
                tracing::warn!(
                    entity = "OidcIssuer",
                    issuer_id = %row.id,
                    error = %e,
                    "corrupt jwks_refresh_interval in oidc_issuers row"
                );
            })?;

        let allowed_algorithms = row
            .allowed_algorithms
            .iter()
            .map(|s| {
                JwtAlg::from_str(s).map_err(|_| {
                    tracing::warn!(
                        entity = "OidcIssuer",
                        issuer_id = %row.id,
                        value = %s,
                        "unknown algorithm in oidc_issuers.allowed_algorithms"
                    );
                    DomainError::Invariant(format!(
                        "corrupt allowed_algorithms value in oidc_issuers row: {s}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(OidcIssuer {
            id: row.id,
            name: row.name,
            issuer_url: row.issuer_url,
            audiences: row.audiences,
            jwks_refresh_interval,
            allowed_algorithms,
            require_jti: row.require_jti,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// ServiceAccountRow → ServiceAccount (without sub-aggregates)
// ---------------------------------------------------------------------------

/// Database row for the `service_accounts` table (migration 011).
///
/// The sub-aggregates (`federated_identities`,
/// `fallback_rotation`) live in their own tables and are loaded by
/// the repository impl via separate queries. This mapper produces
/// the SA with empty / `None` sub-blocks; callers compose the full
/// entity by populating those after fetching.
#[derive(Debug, FromRow)]
pub struct ServiceAccountRow {
    pub id: Uuid,
    pub name: String,
    pub backing_user_id: Uuid,
    pub role: String,
    pub repositories: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<ServiceAccountRow> for ServiceAccount {
    fn from(row: ServiceAccountRow) -> Self {
        // Pure 1:1 translation — every field maps directly with no
        // fallible parsing. Apply validator gates `role` to
        // {developer, reader} at write time; the mapper carries the
        // raw string so the future REST surface (if/when it exists)
        // can surface unexpected values without panicking here.
        ServiceAccount {
            id: row.id,
            name: row.name,
            backing_user_id: row.backing_user_id,
            role: row.role,
            repositories: row.repositories,
            federated_identities: Vec::new(),
            fallback_rotation: None,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

// ---------------------------------------------------------------------------
// FederatedIdentityRow → FederatedIdentity
// ---------------------------------------------------------------------------

/// Database row for the `service_account_federated_identities` table
/// (migration 011).
///
/// `claims` is `JSONB` in storage and decoded into `serde_json::Value`
/// on read; the mapper converts the JSON object into the
/// `BTreeMap<String, String>` shape the domain type uses. A non-object
/// JSON value (or a value with non-string children) is a data-integrity
/// failure — the apply use case writes only string→string maps.
#[derive(Debug, FromRow)]
pub struct FederatedIdentityRow {
    pub id: Uuid,
    pub service_account_id: Uuid,
    pub issuer_name: String,
    pub claims: serde_json::Value,
    pub position: i32,
}

impl TryFrom<FederatedIdentityRow> for FederatedIdentity {
    type Error = DomainError;

    fn try_from(row: FederatedIdentityRow) -> Result<Self, Self::Error> {
        let obj = row.claims.as_object().ok_or_else(|| {
            tracing::warn!(
                entity = "FederatedIdentity",
                federated_identity_id = %row.id,
                "claims column is not a JSON object"
            );
            DomainError::Invariant(format!(
                "claims must be a JSON object in service_account_federated_identities row {}",
                row.id
            ))
        })?;
        // Row-decode defense-in-depth. Apply-time validation rejects an
        // empty `claims` map and the DB CHECK (migration 011) blocks the
        // out-of-band write, but a row that predates the CHECK or
        // arrives via a restore must still fail closed here: an empty
        // exact-match set is vacuously-true at the runtime matcher and
        // would let ANY JWT from the issuer assume the SA. Reject
        // rather than return `Ok` for `{}`.
        if obj.is_empty() {
            tracing::warn!(
                entity = "FederatedIdentity",
                federated_identity_id = %row.id,
                "claims column is an empty JSON object — rejecting (defense-in-depth; \
                 empty claims = any JWT from the issuer can assume the SA)"
            );
            return Err(DomainError::Invariant(format!(
                "claims must be a non-empty JSON object in \
                 service_account_federated_identities row {} \
                 (empty claims is a privilege-escalation footgun)",
                row.id
            )));
        }
        let mut claims = BTreeMap::new();
        for (k, v) in obj {
            let s = v.as_str().ok_or_else(|| {
                tracing::warn!(
                    entity = "FederatedIdentity",
                    federated_identity_id = %row.id,
                    key = %k,
                    "non-string claim value in service_account_federated_identities row"
                );
                DomainError::Invariant(format!(
                    "non-string claim value for key '{k}' in \
                     service_account_federated_identities row {}",
                    row.id
                ))
            })?;
            claims.insert(k.clone(), s.to_string());
        }
        Ok(FederatedIdentity {
            issuer_name: row.issuer_name,
            claims,
        })
    }
}

// ---------------------------------------------------------------------------
// FallbackRotationRow → FallbackRotation
// ---------------------------------------------------------------------------

/// Database row for the `service_account_fallback_rotations` table
/// (migration 011).
///
/// `format` is stored as TEXT with an inline CHECK pinning the value
/// to `('dockerconfigjson','opaque')`; the mapper parses through
/// [`SecretFormat::from_str`] and surfaces unknown literals as
/// `DomainError::Invariant`. Both intervals translate through the
/// `pg_interval_to_duration` helper; the DB CHECK
/// `validity >= 2 * rotation_interval` enforces the safety margin.
#[derive(Debug, FromRow)]
pub struct FallbackRotationRow {
    pub service_account_id: Uuid,
    pub target_namespace: String,
    pub target_name: String,
    pub format: String,
    pub rotation_interval: PgInterval,
    pub validity: PgInterval,
}

impl TryFrom<FallbackRotationRow> for FallbackRotation {
    type Error = DomainError;

    fn try_from(row: FallbackRotationRow) -> Result<Self, Self::Error> {
        let format = SecretFormat::from_str(&row.format).map_err(|_| {
            tracing::warn!(
                entity = "FallbackRotation",
                service_account_id = %row.service_account_id,
                value = %row.format,
                "unknown format in service_account_fallback_rotations row"
            );
            DomainError::Invariant(format!(
                "corrupt format value in service_account_fallback_rotations row: {}",
                row.format
            ))
        })?;
        let rotation_interval =
            pg_interval_to_duration(row.rotation_interval).inspect_err(|e| {
                tracing::warn!(
                    entity = "FallbackRotation",
                    service_account_id = %row.service_account_id,
                    error = %e,
                    "corrupt rotation_interval in service_account_fallback_rotations row"
                );
            })?;
        let validity = pg_interval_to_duration(row.validity).inspect_err(|e| {
            tracing::warn!(
                entity = "FallbackRotation",
                service_account_id = %row.service_account_id,
                error = %e,
                "corrupt validity in service_account_fallback_rotations row"
            );
        })?;
        // Schema column names use the operator-facing CRD shape
        // (`target_namespace` / `target_name`); the domain type uses
        // the implementation-facing pair (`target_secret_namespace` /
        // `target_secret_name`). The mapper bridges the two so neither
        // half has to compromise its naming.
        Ok(FallbackRotation {
            target_secret_name: row.target_name,
            target_secret_namespace: row.target_namespace,
            format,
            rotation_interval,
            validity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_row() -> RepositoryRow {
        RepositoryRow {
            id: Uuid::nil(),
            key: "test-repo".into(),
            name: "Test Repo".into(),
            description: Some("A test repo".into()),
            format: "maven".into(),
            repo_type: "hosted".into(),
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/test".into(),
            upstream_url: None,
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            index_mode: "released_only".into(),
            prefetch_enabled: false,
            prefetch_triggers: None,
            prefetch_depth: None,
            prefetch_transitive_depth: None,
            prefetch_max_age_days: None,
            prefetch_max_descendants: None,
            quota_bytes: Some(1_000_000),
            replication_priority: "on_demand".into(),
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: "local".into(),
            managed_by_digest: None,
        }
    }

    #[test]
    fn basic_conversion() {
        let repo: Repository = base_row().into();
        assert_eq!(repo.key, "test-repo");
        assert_eq!(repo.format, RepositoryFormat::Maven);
        assert_eq!(repo.repo_type, RepositoryType::Hosted);
        assert_eq!(repo.replication_priority, ReplicationPriority::OnDemand);
        assert!(repo.promotion.is_none());
        // The row mapper returns an empty `curation_rule_names` list —
        // the junction-table read happens in `repository_repo.rs`, not
        // in the row → entity conversion.
        assert!(repo.curation_rule_names.is_empty());
        // Default managed_by maps to Local (the migration's column default).
        assert_eq!(repo.managed_by, ManagedBy::Local);
        assert!(repo.managed_by_digest.is_none());
    }

    // -- index_upstream_url mapping ------------------------------------------

    /// `index_upstream_url` flows through the row mapper unchanged in
    /// both directions. The migration adds a `TEXT NULL` column;
    /// `RepositoryRow::index_upstream_url` is the same `Option<String>`
    /// shape as the entity field, so the mapper is a straight
    /// assignment. Covers both branches.
    #[test]
    fn index_upstream_url_some_round_trips_through_mapper() {
        let row = RepositoryRow {
            index_upstream_url: Some("https://internal-index.example.com".into()),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(
            repo.index_upstream_url.as_deref(),
            Some("https://internal-index.example.com")
        );
    }

    #[test]
    fn index_upstream_url_none_round_trips_through_mapper() {
        let row = RepositoryRow {
            index_upstream_url: None,
            ..base_row()
        };
        let repo: Repository = row.into();
        assert!(repo.index_upstream_url.is_none());
    }

    // -- download_audit_enabled mapping ---------------------------------------

    /// The opt-in download-audit bool flows through the row mapper
    /// unchanged in both directions. Covers both branches.
    #[test]
    fn download_audit_enabled_true_round_trips_through_mapper() {
        let row = RepositoryRow {
            download_audit_enabled: true,
            ..base_row()
        };
        let repo: Repository = row.into();
        assert!(repo.download_audit_enabled);
    }

    #[test]
    fn download_audit_enabled_false_round_trips_through_mapper() {
        let row = RepositoryRow {
            download_audit_enabled: false,
            ..base_row()
        };
        let repo: Repository = row.into();
        assert!(!repo.download_audit_enabled);
    }

    // -- index_mode mapping --------------------------------------------------

    /// `index_mode` flows through the row mapper unchanged in both
    /// directions. Migration 002 adds the column `DEFAULT 'released_only'
    /// NOT NULL` with a CHECK over `('released_only','include_pending')`;
    /// the mapper turns those literals into the typed `IndexMode`
    /// variants.
    #[test]
    fn index_mode_released_only_round_trips_through_mapper() {
        let row = RepositoryRow {
            index_mode: "released_only".into(),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(repo.index_mode, IndexMode::ReleasedOnly);
    }

    #[test]
    fn index_mode_include_pending_round_trips_through_mapper() {
        let row = RepositoryRow {
            index_mode: "include_pending".into(),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(repo.index_mode, IndexMode::IncludePending);
    }

    /// Defence — DB CHECK keeps this out of production; the mapper still
    /// mirrors the other enum-mapped columns' `unwrap_or` posture and
    /// coerces an out-of-band literal to the safest default
    /// (`ReleasedOnly` — also the column default, also build-safe).
    /// Out-of-band SQL is the only way to land here.
    #[test]
    fn index_mode_unknown_value_defaults_to_released_only() {
        let row = RepositoryRow {
            index_mode: "permissive".into(),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(repo.index_mode, IndexMode::ReleasedOnly);
    }

    // -- prefetch policy mapping ---------------------------------------------

    /// All-nullable / disabled inputs round-trip to the canonical
    /// disabled-default `PrefetchPolicy` — `enabled=false` (from the
    /// `prefetch_enabled` column DEFAULT), empty triggers (NULL ⇒
    /// `Vec::new()`), default depths (NULL ⇒ in-code defaults), no
    /// max-age filter (NULL ⇒ None). This is the shape every existing
    /// row presents after the migration edit lands.
    #[test]
    fn prefetch_policy_defaults_from_nullable_columns() {
        let row = base_row();
        let repo: Repository = row.into();
        assert_eq!(repo.prefetch_policy, PrefetchPolicy::default());
    }

    /// Non-default `prefetch_enabled` flag flows through verbatim.
    #[test]
    fn prefetch_policy_enabled_flag_round_trips() {
        let row = RepositoryRow {
            prefetch_enabled: true,
            ..base_row()
        };
        let repo: Repository = row.into();
        assert!(repo.prefetch_policy.enabled);
    }

    /// A populated `prefetch_triggers` array round-trips through the
    /// mapper preserving order and de-duplication semantics from the
    /// underlying column. Pins the cross-layer literal contract
    /// alongside the migration CHECK + the domain Display strings.
    #[test]
    fn prefetch_policy_triggers_round_trip_all_variants() {
        let row = RepositoryRow {
            prefetch_triggers: Some(vec![
                "transitive_deps".into(),
                "scheduled".into(),
                "on_dist_tag_move".into(),
            ]),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(
            repo.prefetch_policy.triggers,
            vec![
                PrefetchTrigger::TransitiveDeps,
                PrefetchTrigger::Scheduled,
                PrefetchTrigger::OnDistTagMove,
            ]
        );
    }

    /// An empty `prefetch_triggers` array (the `'{}'` representation —
    /// distinct from NULL at the SQL layer but identical at the
    /// domain) maps to an empty `Vec<PrefetchTrigger>`. The CHECK
    /// constraint accepts `'{}'` because the subset operator `<@`
    /// vacuously holds — pinning that the mapper agrees.
    #[test]
    fn prefetch_policy_empty_triggers_array_maps_to_empty_vec() {
        let row = RepositoryRow {
            prefetch_triggers: Some(Vec::new()),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert!(repo.prefetch_policy.triggers.is_empty());
    }

    /// Defence — the DB CHECK keeps an out-of-band literal off disk,
    /// but the mapper still filters silently rather than panicking
    /// (mirrors the `index_mode` + `managed_by` defensive `unwrap_or`
    /// posture in the same `impl From<RepositoryRow> for Repository`).
    ///
    /// The `on_index_fetch` literal was removed in a migration; a
    /// stale row (one that survived the migration UPDATE somehow)
    /// cannot silently re-materialise as a no-longer-existing enum
    /// variant because the row mapper's `from_str().ok()` drops the
    /// unknown element. The system-level fail-fast guarantee lives at
    /// write-time: the loosened CHECK constraint rejects any new
    /// literal not in the three-element allowlist, and the migration's
    /// idempotent `array_remove('on_index_fetch')` UPDATE drains any
    /// pre-existing rows in lock-step. The row mapper is the read-path
    /// consumer (defensive `.ok()` filter), not the write-path
    /// validator (CHECK constraint).
    #[test]
    fn prefetch_policy_unknown_trigger_literal_is_silently_dropped() {
        let row = RepositoryRow {
            prefetch_triggers: Some(vec![
                "transitive_deps".into(),
                "eager".into(),          // unknown — dropped
                "on_index_fetch".into(), // removed trigger literal — dropped
                "scheduled".into(),
            ]),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(
            repo.prefetch_policy.triggers,
            vec![PrefetchTrigger::TransitiveDeps, PrefetchTrigger::Scheduled]
        );
    }

    /// Explicit knob values land on the domain struct verbatim.
    #[test]
    fn prefetch_policy_depths_and_max_age_round_trip() {
        let row = RepositoryRow {
            prefetch_depth: Some(7),
            prefetch_transitive_depth: Some(4),
            prefetch_max_age_days: Some(90),
            // Round-trip the max_descendants knob too (ADR 0015).
            prefetch_max_descendants: Some(500),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(repo.prefetch_policy.depth, 7);
        assert_eq!(repo.prefetch_policy.transitive_depth, 4);
        assert_eq!(repo.prefetch_policy.max_age_days, Some(90));
        assert_eq!(repo.prefetch_policy.max_descendants, 500);
    }

    /// Defence — a negative knob value (impossible via gitops / domain;
    /// only reachable via raw SQL) coerces to the in-code default via
    /// the `try_from` guard. Mirrors the row-mapper's defensive
    /// `unwrap_or` posture for enum columns.
    #[test]
    fn prefetch_policy_negative_knob_falls_back_to_default() {
        let row = RepositoryRow {
            prefetch_depth: Some(-1),
            prefetch_transitive_depth: Some(-99),
            // Same defensive narrowing for max_descendants (ADR 0015).
            prefetch_max_descendants: Some(-1),
            ..base_row()
        };
        let repo: Repository = row.into();
        let d = PrefetchPolicy::default();
        assert_eq!(repo.prefetch_policy.depth, d.depth);
        assert_eq!(repo.prefetch_policy.transitive_depth, d.transitive_depth);
        assert_eq!(repo.prefetch_policy.max_descendants, d.max_descendants);
    }

    /// A NULL `prefetch_max_descendants` column lands the in-code
    /// default (200) on the domain struct, mirroring the nullable-knob
    /// convention for `prefetch_depth` / `prefetch_transitive_depth`
    /// (ADR 0015). Pins the cross-layer default-source contract: the
    /// DDL has NO `DEFAULT 200`; the default lives in
    /// `PrefetchPolicy::default()`.
    #[test]
    fn prefetch_policy_max_descendants_null_falls_back_to_code_default() {
        let row = RepositoryRow {
            prefetch_max_descendants: None,
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(
            repo.prefetch_policy.max_descendants,
            PrefetchPolicy::default().max_descendants,
        );
    }

    // -- managed_by mapping --------------------------------------------------

    #[test]
    fn managed_by_gitops_with_digest_round_trips() {
        let row = RepositoryRow {
            managed_by: "gitops".into(),
            managed_by_digest: Some(vec![0x42; 32]),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(repo.managed_by, ManagedBy::GitOps);
        assert_eq!(repo.managed_by_digest, Some([0x42; 32]));
    }

    #[test]
    fn managed_by_unknown_value_defaults_to_local() {
        // Defensive — DB CHECK prevents this in practice, but the
        // mapper mirrors the row-mapper pattern used for other enum
        // columns: an unknown literal coerces to Local rather than
        // panicking. Out-of-band SQL is the only way to land here.
        let row = RepositoryRow {
            managed_by: "external".into(),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(repo.managed_by, ManagedBy::Local);
    }

    #[test]
    fn managed_by_digest_wrong_length_becomes_none() {
        // 16 bytes is not 32; treat it as "no digest known" and let
        // the diff layer surface an `update` on the next apply rather
        // than panicking on the row mapper.
        let row = RepositoryRow {
            managed_by: "gitops".into(),
            managed_by_digest: Some(vec![0; 16]),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(repo.managed_by, ManagedBy::GitOps);
        assert!(repo.managed_by_digest.is_none());
    }

    #[test]
    fn unknown_format_becomes_other() {
        let row = RepositoryRow {
            format: "flatpak".into(),
            ..base_row()
        };
        let repo: Repository = row.into();
        assert_eq!(repo.format, RepositoryFormat::Other("flatpak".into()));
    }

    #[test]
    fn promotion_present() {
        let target_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let row = RepositoryRow {
            promotion_target_id: Some(target_id),
            promotion_policy_id: Some(policy_id),
            ..base_row()
        };
        let repo: Repository = row.into();
        let promo = repo.promotion.unwrap();
        assert_eq!(promo.target_id, target_id);
        assert_eq!(promo.policy_id, Some(policy_id));
    }

    #[test]
    fn promotion_absent() {
        let row = RepositoryRow {
            promotion_target_id: None,
            promotion_policy_id: Some(Uuid::new_v4()), // policy without target = no config
            ..base_row()
        };
        let repo: Repository = row.into();
        assert!(repo.promotion.is_none());
    }

    #[test]
    fn all_repo_types_parse() {
        for (s, expected) in [
            ("hosted", RepositoryType::Hosted),
            ("proxy", RepositoryType::Proxy),
            ("virtual", RepositoryType::Virtual),
            ("staging", RepositoryType::Staging),
        ] {
            let row = RepositoryRow {
                repo_type: s.into(),
                ..base_row()
            };
            let repo: Repository = row.into();
            assert_eq!(repo.repo_type, expected);
        }
    }

    #[test]
    fn all_replication_priorities_parse() {
        for (s, expected) in [
            ("immediate", ReplicationPriority::Immediate),
            ("scheduled", ReplicationPriority::Scheduled),
            ("on_demand", ReplicationPriority::OnDemand),
            ("local_only", ReplicationPriority::LocalOnly),
        ] {
            let row = RepositoryRow {
                replication_priority: s.into(),
                ..base_row()
            };
            let repo: Repository = row.into();
            assert_eq!(repo.replication_priority, expected);
        }
    }

    // -- ArtifactRow --------------------------------------------------------

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn base_artifact_row() -> ArtifactRow {
        ArtifactRow {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            name: "my-pkg".into(),
            name_as_published: "my-pkg".into(),
            version: Some("1.0.0".into()),
            path: "my-pkg/1.0.0/my-pkg-1.0.0.tar.gz".into(),
            size_bytes: 2048,
            checksum_sha256: VALID_SHA256.into(),
            checksum_sha1: None,
            checksum_md5: None,
            content_type: "application/gzip".into(),
            storage_key: VALID_SHA256.into(),
            quarantine_status: None,
            quarantine_window_start: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn artifact_basic_conversion() {
        let artifact = Artifact::try_from(base_artifact_row()).unwrap();
        assert_eq!(artifact.name, "my-pkg");
        assert_eq!(artifact.sha256_checksum.as_ref(), VALID_SHA256);
        assert_eq!(artifact.quarantine_status, QuarantineStatus::None);
    }

    #[test]
    fn artifact_null_quarantine_is_none() {
        let row = ArtifactRow {
            quarantine_status: None,
            ..base_artifact_row()
        };
        let artifact = Artifact::try_from(row).unwrap();
        assert_eq!(artifact.quarantine_status, QuarantineStatus::None);
    }

    #[test]
    fn artifact_quarantined_status() {
        let row = ArtifactRow {
            quarantine_status: Some("quarantined".into()),
            quarantine_window_start: Some(Utc::now()),
            ..base_artifact_row()
        };
        let artifact = Artifact::try_from(row).unwrap();
        assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
        assert!(artifact.quarantine_window_start.is_some());
        // The transient computed deadline is never loaded from the store.
        assert!(artifact.quarantine_deadline.is_none());
    }

    #[test]
    fn artifact_released_status() {
        let row = ArtifactRow {
            quarantine_status: Some("released".into()),
            ..base_artifact_row()
        };
        let artifact = Artifact::try_from(row).unwrap();
        assert_eq!(artifact.quarantine_status, QuarantineStatus::Released);
    }

    #[test]
    fn artifact_rejected_status() {
        let row = ArtifactRow {
            quarantine_status: Some("rejected".into()),
            ..base_artifact_row()
        };
        let artifact = Artifact::try_from(row).unwrap();
        assert_eq!(artifact.quarantine_status, QuarantineStatus::Rejected);
    }

    #[test]
    fn artifact_unknown_quarantine_defaults_to_none() {
        let row = ArtifactRow {
            quarantine_status: Some("unscanned".into()),
            ..base_artifact_row()
        };
        let artifact = Artifact::try_from(row).unwrap();
        assert_eq!(artifact.quarantine_status, QuarantineStatus::None);
    }

    #[test]
    fn artifact_storage_key_not_in_domain() {
        let row = ArtifactRow {
            storage_key: "some/path/key".into(),
            ..base_artifact_row()
        };
        let artifact = Artifact::try_from(row).unwrap();
        assert_eq!(artifact.sha256_checksum.as_ref(), VALID_SHA256);
    }

    #[test]
    fn artifact_corrupt_checksum_returns_error() {
        let row = ArtifactRow {
            checksum_sha256: "not-a-valid-sha256".into(),
            ..base_artifact_row()
        };
        let result = Artifact::try_from(row);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("corrupt SHA-256"));
    }

    // -- UserRow ------------------------------------------------------------

    fn base_user_row() -> UserRow {
        UserRow {
            id: Uuid::nil(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            auth_provider: "local".into(),
            external_id: None,
            display_name: Some("Alice Smith".into()),
            is_active: true,
            is_admin: false,
            is_service_account: false,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn user_basic_conversion() {
        let user: User = User::try_from(base_user_row()).unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.auth_provider, AuthProvider::Local);
        assert!(user.display_name.is_some());
    }

    #[test]
    fn user_all_auth_providers_parse() {
        for (s, expected) in [
            ("local", AuthProvider::Local),
            ("ldap", AuthProvider::Ldap),
            ("saml", AuthProvider::Saml),
            ("oidc", AuthProvider::Oidc),
        ] {
            let row = UserRow {
                auth_provider: s.into(),
                ..base_user_row()
            };
            let user: User = User::try_from(row).unwrap();
            assert_eq!(user.auth_provider, expected);
        }
    }

    #[test]
    fn user_external_auth() {
        let row = UserRow {
            auth_provider: "oidc".into(),
            external_id: Some("okta|abc123".into()),
            ..base_user_row()
        };
        let user: User = User::try_from(row).unwrap();
        assert_eq!(user.auth_provider, AuthProvider::Oidc);
        assert_eq!(user.external_id.as_deref(), Some("okta|abc123"));
    }

    /// A users row with an unexpected `auth_provider` value must surface
    /// as `DomainError::Invariant`, not silently coerce to `Local`. The
    /// schema CHECK prevents this in practice; the strict mapper is
    /// defense-in-depth against out-of-band writes and schema drift.
    #[test]
    fn user_corrupted_auth_provider_returns_invariant() {
        let row = UserRow {
            auth_provider: "corrupted_value".into(),
            ..base_user_row()
        };
        let result = User::try_from(row);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("corrupted_value"),
            "error message must name the offending value; got: {msg}"
        );
        assert!(
            msg.contains("auth_provider"),
            "error message must identify the column; got: {msg}"
        );
    }

    #[test]
    fn user_empty_auth_provider_returns_invariant() {
        let row = UserRow {
            auth_provider: String::new(),
            ..base_user_row()
        };
        let result = User::try_from(row);
        assert!(matches!(result, Err(DomainError::Invariant(_))));
    }

    // -- EventRow -----------------------------------------------------------

    use super::{actor_to_columns, serialize_event_data, stream_id_to_columns};
    use hort_domain::events::{
        Actor, ApiActor, ArtifactIngested, DomainEvent, IngestSource, InternalActor,
        PersistedEvent, StreamId,
    };

    fn base_event_row() -> EventRow {
        let artifact_id = Uuid::new_v4();
        let event = DomainEvent::ArtifactIngested(ArtifactIngested {
            artifact_id,
            repository_id: Uuid::new_v4(),
            name: "test-pkg".into(),
            version: Some("1.0.0".into()),
            sha256: VALID_SHA256.parse::<ContentHash>().unwrap(),
            size_bytes: 1024,
            source: IngestSource::Direct,
            metadata: serde_json::Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        });
        let event_data = serialize_event_data(&event);

        EventRow {
            event_id: Uuid::new_v4(),
            stream_id: format!("artifact-{artifact_id}"),
            stream_category: "artifact".into(),
            stream_position: 0,
            global_position: 1,
            event_type: "ArtifactIngested".into(),
            event_version: 1,
            event_data,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor_type: "api".into(),
            actor_id: Some(Uuid::new_v4()),
            actor_source_file: None,
            actor_spec_digest: None,
            stored_at: Utc::now(),
        }
    }

    #[test]
    fn event_row_api_actor_conversion() {
        let uid = Uuid::new_v4();
        let row = EventRow {
            actor_type: "api".into(),
            actor_id: Some(uid),
            ..base_event_row()
        };
        let event = PersistedEvent::try_from(row).unwrap();
        assert_eq!(event.actor, Actor::Api(ApiActor { user_id: uid }));
    }

    #[test]
    fn event_row_system_actor_conversion() {
        let row = EventRow {
            actor_type: "system".into(),
            actor_id: None,
            ..base_event_row()
        };
        let event = PersistedEvent::try_from(row).unwrap();
        assert_eq!(event.actor, Actor::Internal(InternalActor::System));
    }

    #[test]
    fn event_row_timer_actor_conversion() {
        let row = EventRow {
            actor_type: "timer".into(),
            actor_id: None,
            ..base_event_row()
        };
        let event = PersistedEvent::try_from(row).unwrap();
        assert_eq!(event.actor, Actor::Internal(InternalActor::Timer));
    }

    #[test]
    fn event_row_unknown_actor_type_is_invariant() {
        let row = EventRow {
            actor_type: "admin".into(),
            actor_id: None,
            ..base_event_row()
        };
        let result = PersistedEvent::try_from(row);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DomainError::Invariant(_)));
    }

    #[test]
    fn event_row_api_without_id_is_invariant() {
        let row = EventRow {
            actor_type: "api".into(),
            actor_id: None,
            ..base_event_row()
        };
        let result = PersistedEvent::try_from(row);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DomainError::Invariant(_)));
    }

    #[test]
    fn event_row_system_with_id_is_invariant() {
        let row = EventRow {
            actor_type: "system".into(),
            actor_id: Some(Uuid::new_v4()),
            ..base_event_row()
        };
        let result = PersistedEvent::try_from(row);
        assert!(result.is_err());
    }

    #[test]
    fn event_row_stream_id_round_trip() {
        let id = Uuid::new_v4();
        let row = EventRow {
            stream_id: format!("policy-{id}"),
            stream_category: "policy".into(),
            ..base_event_row()
        };
        let event = PersistedEvent::try_from(row).unwrap();
        assert_eq!(event.stream_id, StreamId::policy(id));
    }

    #[test]
    fn event_row_corrupt_stream_id_is_invariant() {
        let row = EventRow {
            stream_id: "garbage".into(),
            ..base_event_row()
        };
        let result = PersistedEvent::try_from(row);
        assert!(result.is_err());
    }

    #[test]
    fn event_row_causation_id_round_trip() {
        let cause = Uuid::new_v4();
        let row = EventRow {
            causation_id: Some(cause),
            ..base_event_row()
        };
        let event = PersistedEvent::try_from(row).unwrap();
        assert_eq!(event.causation_id, Some(cause));
    }

    #[test]
    fn event_row_event_version_round_trip() {
        let row = EventRow {
            event_version: 3,
            ..base_event_row()
        };
        let event = PersistedEvent::try_from(row).unwrap();
        assert_eq!(event.event_version, 3);
    }

    #[test]
    fn event_row_corrupt_event_data_is_invariant() {
        let row = EventRow {
            event_data: serde_json::json!({"type": "ArtifactIngested", "data": "not-an-object"}),
            ..base_event_row()
        };
        let result = PersistedEvent::try_from(row);
        assert!(result.is_err());
    }

    #[test]
    fn event_row_domain_event_json_round_trip_artifact() {
        let row = base_event_row();
        let event = PersistedEvent::try_from(row).unwrap();
        assert!(matches!(event.event, DomainEvent::ArtifactIngested(_)));
    }

    #[test]
    fn event_row_domain_event_json_round_trip_policy() {
        use hort_domain::events::{PolicyCreated, PolicyScope};

        let policy_event = DomainEvent::PolicyCreated(PolicyCreated {
            policy_id: Uuid::new_v4(),
            name: "test-policy".into(),
            scope: PolicyScope::Global,
            config_snapshot: serde_json::json!({"threshold": 5}),
        });
        let row = EventRow {
            event_type: "PolicyCreated".into(),
            event_data: serialize_event_data(&policy_event),
            stream_id: format!("policy-{}", Uuid::new_v4()),
            stream_category: "policy".into(),
            ..base_event_row()
        };
        let event = PersistedEvent::try_from(row).unwrap();
        assert!(matches!(event.event, DomainEvent::PolicyCreated(_)));
    }

    #[test]
    fn actor_to_columns_api() {
        let uid = Uuid::new_v4();
        let actor = Actor::Api(ApiActor { user_id: uid });
        let cols = actor_to_columns(&actor);
        assert_eq!(cols.actor_type, "api");
        assert_eq!(cols.actor_id, Some(uid));
        assert!(cols.actor_source_file.is_none());
        assert!(cols.actor_spec_digest.is_none());
    }

    #[test]
    fn actor_to_columns_system() {
        let actor = Actor::Internal(InternalActor::System);
        let cols = actor_to_columns(&actor);
        assert_eq!(cols.actor_type, "system");
        assert_eq!(cols.actor_id, None);
        assert!(cols.actor_source_file.is_none());
        assert!(cols.actor_spec_digest.is_none());
    }

    #[test]
    fn actor_to_columns_timer() {
        let actor = Actor::Internal(InternalActor::Timer);
        let cols = actor_to_columns(&actor);
        assert_eq!(cols.actor_type, "timer");
        assert_eq!(cols.actor_id, None);
        assert!(cols.actor_source_file.is_none());
        assert!(cols.actor_spec_digest.is_none());
    }

    // -- GitOps actor --------------------------------------------------------

    #[test]
    fn actor_to_columns_gitops_writes_source_file_and_digest() {
        let actor = Actor::from_persisted_gitops(
            "repositories/npm-public.yaml".into(),
            [0xab; 32],
            Utc::now(),
        );
        let cols = actor_to_columns(&actor);
        assert_eq!(cols.actor_type, "gitops");
        assert_eq!(cols.actor_id, None);
        assert_eq!(
            cols.actor_source_file.as_deref(),
            Some("repositories/npm-public.yaml")
        );
        assert_eq!(cols.actor_spec_digest.as_deref(), Some(&[0xab; 32][..]));
    }

    #[test]
    fn event_row_gitops_actor_round_trips() {
        let row = EventRow {
            actor_type: "gitops".into(),
            actor_id: None,
            actor_source_file: Some("auth/admins.yaml".into()),
            actor_spec_digest: Some(vec![0xcd; 32]),
            ..base_event_row()
        };
        let event = PersistedEvent::try_from(row).unwrap();
        match event.actor {
            Actor::GitOps(g) => {
                assert_eq!(g.source_file, "auth/admins.yaml");
                assert_eq!(g.spec_digest, [0xcd; 32]);
            }
            other => panic!("expected GitOps actor, got {other:?}"),
        }
    }

    #[test]
    fn event_row_gitops_missing_source_file_is_invariant() {
        let row = EventRow {
            actor_type: "gitops".into(),
            actor_id: None,
            actor_source_file: None,
            actor_spec_digest: Some(vec![0; 32]),
            ..base_event_row()
        };
        let err = PersistedEvent::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("actor_source_file"));
    }

    #[test]
    fn event_row_gitops_missing_digest_is_invariant() {
        let row = EventRow {
            actor_type: "gitops".into(),
            actor_id: None,
            actor_source_file: Some("a.yaml".into()),
            actor_spec_digest: None,
            ..base_event_row()
        };
        let err = PersistedEvent::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("actor_spec_digest"));
    }

    #[test]
    fn event_row_gitops_wrong_digest_length_is_invariant() {
        let row = EventRow {
            actor_type: "gitops".into(),
            actor_id: None,
            actor_source_file: Some("a.yaml".into()),
            actor_spec_digest: Some(vec![0; 16]), // not 32
            ..base_event_row()
        };
        let err = PersistedEvent::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        let msg = err.to_string();
        assert!(msg.contains("32 bytes") && msg.contains("16"));
    }

    #[test]
    fn stream_id_to_columns_artifact() {
        let id = Uuid::new_v4();
        let sid = StreamId::artifact(id);
        let (stream_str, cat_str) = stream_id_to_columns(&sid);
        assert_eq!(stream_str, format!("artifact-{id}"));
        assert_eq!(cat_str, "artifact");
    }

    #[test]
    fn stream_id_to_columns_policy() {
        let id = Uuid::new_v4();
        let sid = StreamId::policy(id);
        let (stream_str, cat_str) = stream_id_to_columns(&sid);
        assert_eq!(stream_str, format!("policy-{id}"));
        assert_eq!(cat_str, "policy");
    }

    #[test]
    fn stream_id_to_columns_ref() {
        let id = Uuid::new_v4();
        let sid = StreamId::ref_(id);
        let (stream_str, cat_str) = stream_id_to_columns(&sid);
        assert_eq!(stream_str, format!("ref-{id}"));
        assert_eq!(cat_str, "ref");
    }

    #[test]
    fn stream_id_to_columns_artifact_group() {
        let id = Uuid::new_v4();
        let sid = StreamId::artifact_group(id);
        let (stream_str, cat_str) = stream_id_to_columns(&sid);
        assert_eq!(stream_str, format!("artifact_group-{id}"));
        assert_eq!(cat_str, "artifact_group");
    }

    #[test]
    fn stream_id_to_columns_download_audit() {
        let repo = Uuid::new_v4();
        let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 18).unwrap();
        let sid = StreamId::download_audit(repo, date);
        let (stream_str, cat_str) = stream_id_to_columns(&sid);
        assert_eq!(stream_str, format!("download_audit-{}", sid.entity_id));
        assert_eq!(cat_str, "download_audit");
    }

    /// Round-trip `DomainEvent::RefMoved` through the adapter's existing
    /// tagged-enum serialisation helpers. The mapper's `serialize_event_data`
    /// and `deserialize_event_data` helpers MUST NOT need modification to
    /// support new `DomainEvent` variants — serde's derived impls handle
    /// that. This test is the proof.
    #[test]
    fn event_row_ref_moved_round_trip_unchanged_mapper() {
        use hort_domain::entities::mutable_ref::RefTarget;
        use hort_domain::events::RefMoved;
        let original = DomainEvent::RefMoved(RefMoved {
            ref_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            from: Some(RefTarget::Version("1.0.0".into())),
            to: RefTarget::ContentHash(VALID_SHA256.parse().unwrap()),
        });
        let encoded = serialize_event_data(&original);
        let decoded = deserialize_event_data(original.event_type(), &encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// Companion round-trip for `DomainEvent::RefRetired`, catching any
    /// wire-format drift specific to the retirement event.
    #[test]
    fn event_row_ref_retired_round_trip_unchanged_mapper() {
        use hort_domain::entities::mutable_ref::RefTarget;
        use hort_domain::events::RefRetired;
        let original = DomainEvent::RefRetired(RefRetired {
            ref_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            last_target: RefTarget::ContentHash(VALID_SHA256.parse().unwrap()),
        });
        let encoded = serialize_event_data(&original);
        let decoded = deserialize_event_data(original.event_type(), &encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// Round-trip `DomainEvent::ArtifactGroupMemberAdded` (the simplest of
    /// the four group events — no nested `ArtifactCoords`) through the
    /// adapter's existing tagged-enum serialisation helpers. Same
    /// Same invariant the `RefMoved` round-trip test locked in:
    /// `serialize_event_data` / `deserialize_event_data` MUST NOT need
    /// modification to support new `DomainEvent` variants — serde's
    /// derived impls handle that.
    #[test]
    fn event_row_artifact_group_member_added_round_trip_unchanged_mapper() {
        use hort_domain::events::ArtifactGroupMemberAdded;
        let original = DomainEvent::ArtifactGroupMemberAdded(ArtifactGroupMemberAdded {
            group_id: Uuid::new_v4(),
            role: "jar".into(),
            artifact_id: Uuid::new_v4(),
        });
        let encoded = serialize_event_data(&original);
        let decoded = deserialize_event_data(original.event_type(), &encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// Round-trip the claim-based authorization audit variants through
    /// the adapter's tagged-enum serialisation (ADR 0012). Replaces
    /// the retired `GroupMappingUpdated` round-trip (the `Role*` /
    /// `GroupMapping*` events were retired with the `roles` /
    /// `group_mappings` tables; pre-v1.0, no compat shim).
    ///
    /// Same invariant the `RefMoved` companion pins: `serialize_event_data`
    /// / `deserialize_event_data` MUST NOT need a new arm for new
    /// `DomainEvent` variants — serde's derived impls + the type-driven
    /// envelope handle it. `PermissionGrantApplied` is the structurally
    /// interesting case (nested sum-typed `GrantSubjectRecord`); this
    /// test is the proof its wire form round-trips through the generic
    /// mapper unchanged.
    #[test]
    fn event_row_claim_based_authz_variants_round_trip_unchanged_mapper() {
        use hort_domain::events::{
            ClaimMappingApplied, ClaimMappingRevoked, GrantSubjectRecord, PermissionGrantApplied,
            PermissionGrantRevoked,
        };

        let cases: Vec<(DomainEvent, &str)> = vec![
            (
                DomainEvent::ClaimMappingApplied(ClaimMappingApplied {
                    mapping_id: Uuid::new_v4(),
                    idp_group: "engineering".into(),
                    claim: "developer".into(),
                }),
                "ClaimMappingApplied",
            ),
            (
                DomainEvent::ClaimMappingRevoked(ClaimMappingRevoked {
                    mapping_id: Uuid::new_v4(),
                    idp_group: "engineering".into(),
                    claim: "developer".into(),
                }),
                "ClaimMappingRevoked",
            ),
            (
                DomainEvent::PermissionGrantApplied(PermissionGrantApplied {
                    grant_id: Uuid::new_v4(),
                    subject: GrantSubjectRecord::Claims {
                        required: vec!["developer".into(), "team-alpha".into()],
                    },
                    permission: Permission::Write,
                    repository_id: Some(Uuid::new_v4()),
                }),
                "PermissionGrantApplied",
            ),
            (
                DomainEvent::PermissionGrantRevoked(PermissionGrantRevoked {
                    grant_id: Uuid::new_v4(),
                    subject: GrantSubjectRecord::User {
                        user_id: Uuid::new_v4(),
                    },
                    permission: Permission::Read,
                    repository_id: None,
                }),
                "PermissionGrantRevoked",
            ),
        ];

        for (original, expected_type) in cases {
            let encoded = serialize_event_data(&original);
            let decoded = deserialize_event_data(original.event_type(), &encoded).unwrap();
            assert_eq!(original, decoded, "round-trip mismatch for {expected_type}");
            // Wire-form pin — the audit consumer matches on the "type"
            // discriminator. A future variant rename must come with a
            // migration of the consumers; this assertion makes the
            // rename a hard fail rather than a silent drift.
            assert_eq!(
                encoded.get("type").and_then(|v| v.as_str()),
                Some(expected_type),
            );
        }
    }

    /// Companion round-trip for `DomainEvent::ArtifactGroupInitiated` —
    /// this one carries a nested `ArtifactCoords`, which is the variant
    /// that motivated adding `Serialize + Deserialize` to
    /// `ArtifactCoords`. If the coords serde derives ever regressed,
    /// this test is the first line that would fail — the tagged-enum
    /// envelope round-trip would throw on deserialise.
    #[test]
    fn event_row_artifact_group_initiated_round_trip_unchanged_mapper() {
        use hort_domain::events::ArtifactGroupInitiated;
        use hort_domain::types::ArtifactCoords;
        let original = DomainEvent::ArtifactGroupInitiated(ArtifactGroupInitiated {
            group_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            coords: ArtifactCoords {
                name: "my-pkg".into(),
                name_as_published: "My_Pkg".into(),
                version: Some("1.2.3".into()),
                path: String::new(),
                format: RepositoryFormat::Maven,
                metadata: serde_json::Value::Null,
            },
            primary_role: "pom".into(),
        });
        let encoded = serialize_event_data(&original);
        let decoded = deserialize_event_data(original.event_type(), &encoded).unwrap();
        assert_eq!(original, decoded);
    }

    // -- ApiTokenRow -------------------------------------------------------

    fn base_api_token_row() -> ApiTokenRow {
        ApiTokenRow {
            id: Uuid::nil(),
            user_id: Uuid::from_u128(1),
            name: "ci-token".into(),
            description: Some("CI publish".into()),
            kind: "pat".into(),
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$sentinel$sentinel".into(),
            token_prefix: "abcd1234".into(),
            declared_permissions: vec!["read".into(), "write".into()],
            repository_ids: Some(vec![Uuid::from_u128(0xA)]),
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: Uuid::from_u128(1),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn api_token_row_basic_pat_round_trip() {
        let row = base_api_token_row();
        let token = row.try_into_api_token().unwrap();
        assert_eq!(token.kind, TokenKind::Pat);
        assert_eq!(
            token.declared_permissions,
            vec![Permission::Read, Permission::Write]
        );
    }

    #[test]
    fn api_token_row_service_account_kind_parses() {
        let row = ApiTokenRow {
            kind: "service_account".into(),
            ..base_api_token_row()
        };
        let token = row.try_into_api_token().unwrap();
        assert_eq!(token.kind, TokenKind::ServiceAccount);
    }

    #[test]
    fn api_token_row_cli_session_kind_parses() {
        let row = ApiTokenRow {
            kind: "cli_session".into(),
            ..base_api_token_row()
        };
        let token = row.try_into_api_token().unwrap();
        assert_eq!(token.kind, TokenKind::CliSession);
    }

    #[test]
    fn api_token_row_unknown_kind_is_invariant() {
        // The DB CHECK forbids this; the mapper is defence-in-depth
        // against out-of-band SQL.
        let row = ApiTokenRow {
            kind: "bogus".into(),
            ..base_api_token_row()
        };
        let err = row.try_into_api_token().unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn api_token_row_unknown_permission_is_invariant() {
        // Silently dropping a permission could narrow the cap and
        // surprise operators reading the audit log — surface loudly.
        let row = ApiTokenRow {
            declared_permissions: vec!["read".into(), "fly".into()],
            ..base_api_token_row()
        };
        let err = row.try_into_api_token().unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        let msg = err.to_string();
        assert!(msg.contains("fly"));
    }

    #[test]
    fn api_token_row_no_repository_ids_inherits() {
        let row = ApiTokenRow {
            repository_ids: None,
            ..base_api_token_row()
        };
        let token = row.try_into_api_token().unwrap();
        assert!(token.repository_ids.is_none());
    }

    #[test]
    fn token_kind_to_text_round_trip() {
        for kind in [
            TokenKind::Pat,
            TokenKind::ServiceAccount,
            TokenKind::CliSession,
        ] {
            let s = token_kind_to_text(kind);
            assert_eq!(token_kind_from_text(s).unwrap(), kind);
        }
    }

    // -- gitops machine-identity mappers -------------------------------------

    // -- pg_interval_to_duration helper --------------------------------------

    #[test]
    fn pg_interval_one_hour_round_trip() {
        // PG default for `oidc_issuers.jwks_refresh_interval` is `'1 hour'`,
        // which sqlx returns as `microseconds = 3_600_000_000`. The mapper
        // must translate that to `Duration::from_secs(3600)` losslessly.
        let iv = PgInterval {
            months: 0,
            days: 0,
            microseconds: 3_600 * 1_000_000,
        };
        assert_eq!(
            pg_interval_to_duration(iv).unwrap(),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn pg_interval_six_hours_round_trip() {
        // Default for `FallbackRotation.rotation_interval`.
        let iv = PgInterval {
            months: 0,
            days: 0,
            microseconds: 6 * 3_600 * 1_000_000,
        };
        assert_eq!(
            pg_interval_to_duration(iv).unwrap(),
            Duration::from_secs(6 * 3600)
        );
    }

    #[test]
    fn pg_interval_with_days_and_microseconds() {
        // `INTERVAL '1 day 1 hour'` arrives as days=1 + micros=3.6e9.
        let iv = PgInterval {
            months: 0,
            days: 1,
            microseconds: 3_600 * 1_000_000,
        };
        assert_eq!(
            pg_interval_to_duration(iv).unwrap(),
            Duration::from_secs(86_400 + 3_600)
        );
    }

    #[test]
    fn pg_interval_with_months_uses_thirty_day_convention() {
        let iv = PgInterval {
            months: 1,
            days: 0,
            microseconds: 0,
        };
        assert_eq!(
            pg_interval_to_duration(iv).unwrap(),
            Duration::from_secs(30 * 86_400)
        );
    }

    #[test]
    fn pg_interval_negative_microseconds_is_invariant() {
        let iv = PgInterval {
            months: 0,
            days: 0,
            microseconds: -1,
        };
        let err = pg_interval_to_duration(iv).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn pg_interval_negative_days_is_invariant() {
        let iv = PgInterval {
            months: 0,
            days: -1,
            microseconds: 0,
        };
        let err = pg_interval_to_duration(iv).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn pg_interval_negative_months_is_invariant() {
        let iv = PgInterval {
            months: -1,
            days: 0,
            microseconds: 0,
        };
        let err = pg_interval_to_duration(iv).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn pg_interval_zero_is_zero_duration() {
        let iv = PgInterval {
            months: 0,
            days: 0,
            microseconds: 0,
        };
        assert_eq!(pg_interval_to_duration(iv).unwrap(), Duration::ZERO);
    }

    #[test]
    fn pg_interval_sub_second_microseconds_carry_nanos() {
        // 1_500_000 µs = 1.5 s — exercises the nanos path.
        let iv = PgInterval {
            months: 0,
            days: 0,
            microseconds: 1_500_000,
        };
        let d = pg_interval_to_duration(iv).unwrap();
        assert_eq!(d.as_secs(), 1);
        assert_eq!(d.subsec_nanos(), 500_000_000);
    }

    // -- OidcIssuerRow → OidcIssuer ------------------------------------------

    fn base_oidc_row() -> OidcIssuerRow {
        OidcIssuerRow {
            id: Uuid::nil(),
            name: "github-actions".into(),
            issuer_url: "https://token.actions.githubusercontent.com".into(),
            audiences: vec!["hort-server".into()],
            jwks_refresh_interval: PgInterval {
                months: 0,
                days: 0,
                microseconds: 3_600 * 1_000_000,
            },
            allowed_algorithms: vec!["RS256".into()],
            require_jti: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn oidc_issuer_basic_round_trip() {
        let row = base_oidc_row();
        let id = row.id;
        let issuer = OidcIssuer::try_from(row).unwrap();
        assert_eq!(issuer.id, id);
        assert_eq!(issuer.name, "github-actions");
        assert_eq!(
            issuer.issuer_url,
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(issuer.audiences, vec!["hort-server"]);
        assert_eq!(issuer.jwks_refresh_interval, Duration::from_secs(3600));
        assert_eq!(issuer.allowed_algorithms, vec![JwtAlg::Rs256]);
        // The NOT-NULL `require_jti` column round-trips into the
        // domain entity (ADR 0007).
        assert!(issuer.require_jti);
    }

    #[test]
    fn oidc_issuer_require_jti_false_round_trips() {
        // An operator that explicitly opted the issuer down to the
        // composite fallback (`require_jti=false`) must round-trip
        // through the mapper as `false` — the secure default does not
        // override a persisted opt-down.
        let row = OidcIssuerRow {
            require_jti: false,
            ..base_oidc_row()
        };
        let issuer = OidcIssuer::try_from(row).unwrap();
        assert!(!issuer.require_jti);
    }

    #[test]
    fn oidc_issuer_multi_algorithm_round_trip() {
        let row = OidcIssuerRow {
            allowed_algorithms: vec!["RS256".into(), "ES256".into(), "RS512".into()],
            ..base_oidc_row()
        };
        let issuer = OidcIssuer::try_from(row).unwrap();
        assert_eq!(
            issuer.allowed_algorithms,
            vec![JwtAlg::Rs256, JwtAlg::Es256, JwtAlg::Rs512]
        );
    }

    #[test]
    fn oidc_issuer_unknown_algorithm_is_invariant() {
        // The apply-time validator gates writes to the supported set,
        // so an unknown literal here means out-of-band SQL. The mapper
        // surfaces it loudly rather than silently dropping the
        // algorithm.
        let row = OidcIssuerRow {
            allowed_algorithms: vec!["RS256".into(), "HS999".into()],
            ..base_oidc_row()
        };
        let err = OidcIssuer::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("HS999"));
    }

    #[test]
    fn oidc_issuer_negative_interval_is_invariant() {
        let row = OidcIssuerRow {
            jwks_refresh_interval: PgInterval {
                months: 0,
                days: 0,
                microseconds: -42,
            },
            ..base_oidc_row()
        };
        let err = OidcIssuer::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn oidc_issuer_empty_audiences_round_trips() {
        // Apply-time validator rejects empty audiences; the mapper
        // does not — this is defence-in-depth shape, not a value
        // assertion. The shape mirrors the `allowed_algorithms`
        // posture: invariants on the values live in the validator,
        // the mapper just translates types.
        let row = OidcIssuerRow {
            audiences: Vec::new(),
            ..base_oidc_row()
        };
        let issuer = OidcIssuer::try_from(row).unwrap();
        assert!(issuer.audiences.is_empty());
    }

    // -- ServiceAccountRow → ServiceAccount ----------------------------------

    fn base_sa_row() -> ServiceAccountRow {
        ServiceAccountRow {
            id: Uuid::nil(),
            name: "ci-pypi-pusher".into(),
            backing_user_id: Uuid::from_u128(1),
            role: "developer".into(),
            repositories: vec!["pypi-internal".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn service_account_row_basic_conversion() {
        let row = base_sa_row();
        let id = row.id;
        let sa: ServiceAccount = row.into();
        assert_eq!(sa.id, id);
        assert_eq!(sa.name, "ci-pypi-pusher");
        assert_eq!(sa.backing_user_id, Uuid::from_u128(1));
        assert_eq!(sa.role, "developer");
        assert_eq!(sa.repositories, vec!["pypi-internal"]);
        // Sub-aggregates are empty; the repository impl populates them
        // via separate queries.
        assert!(sa.federated_identities.is_empty());
        assert!(sa.fallback_rotation.is_none());
    }

    #[test]
    fn service_account_row_multi_repository_conversion() {
        let row = ServiceAccountRow {
            repositories: vec![
                "pypi-internal".into(),
                "npm-internal".into(),
                "oci-internal".into(),
            ],
            ..base_sa_row()
        };
        let sa: ServiceAccount = row.into();
        assert_eq!(sa.repositories.len(), 3);
    }

    #[test]
    fn service_account_row_preserves_role_text_verbatim() {
        // Apply validator gates `role` to {developer, reader}; the
        // mapper carries whatever the column holds. This test pins the
        // raw-string posture so a future REST surface can decide how
        // to handle unexpected values.
        let row = ServiceAccountRow {
            role: "reader".into(),
            ..base_sa_row()
        };
        let sa: ServiceAccount = row.into();
        assert_eq!(sa.role, "reader");
    }

    // -- FederatedIdentityRow → FederatedIdentity ----------------------------

    fn base_federated_row() -> FederatedIdentityRow {
        FederatedIdentityRow {
            id: Uuid::nil(),
            service_account_id: Uuid::from_u128(1),
            issuer_name: "github-actions".into(),
            claims: serde_json::json!({
                "repository": "my-org/my-repo",
                "environment": "production",
            }),
            position: 0,
        }
    }

    #[test]
    fn federated_identity_basic_round_trip() {
        let fi = FederatedIdentity::try_from(base_federated_row()).unwrap();
        assert_eq!(fi.issuer_name, "github-actions");
        assert_eq!(
            fi.claims.get("repository").map(String::as_str),
            Some("my-org/my-repo")
        );
        assert_eq!(
            fi.claims.get("environment").map(String::as_str),
            Some("production")
        );
        // BTreeMap iteration is sorted — load-bearing for audit
        // serialisation determinism.
        let keys: Vec<&String> = fi.claims.keys().collect();
        assert_eq!(keys, vec!["environment", "repository"]);
    }

    #[test]
    fn federated_identity_empty_claims_is_invariant() {
        // Row-decode defense-in-depth. Apply validation rejects empty
        // claims and migration 011 carries a DB CHECK, but a `{}` row
        // arriving via restore or a pre-CHECK write must STILL fail
        // closed here: an empty exact-match set is vacuously-true at
        // the runtime matcher and would let any JWT from the issuer
        // assume the SA. The mapper now returns Err for `{}` (it
        // previously returned Ok — that was the gap closed here).
        let row = FederatedIdentityRow {
            claims: serde_json::json!({}),
            ..base_federated_row()
        };
        let err = FederatedIdentity::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(
            err.to_string().contains("non-empty")
                && err.to_string().contains("privilege-escalation"),
            "empty-claims reject must explain the privilege-escalation footgun, got: {err}"
        );
    }

    #[test]
    fn federated_identity_non_object_claims_is_invariant() {
        let row = FederatedIdentityRow {
            claims: serde_json::json!("not-an-object"),
            ..base_federated_row()
        };
        let err = FederatedIdentity::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("JSON object"));
    }

    #[test]
    fn federated_identity_array_claims_is_invariant() {
        let row = FederatedIdentityRow {
            claims: serde_json::json!(["repository", "my-org/my-repo"]),
            ..base_federated_row()
        };
        let err = FederatedIdentity::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn federated_identity_non_string_claim_value_is_invariant() {
        let row = FederatedIdentityRow {
            claims: serde_json::json!({ "ref_count": 42 }),
            ..base_federated_row()
        };
        let err = FederatedIdentity::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("ref_count"));
    }

    // -- FallbackRotationRow → FallbackRotation ------------------------------

    fn base_fallback_row() -> FallbackRotationRow {
        FallbackRotationRow {
            service_account_id: Uuid::from_u128(1),
            target_namespace: "ci-system".into(),
            target_name: "ci-hort-token".into(),
            format: "dockerconfigjson".into(),
            rotation_interval: PgInterval {
                months: 0,
                days: 0,
                microseconds: 6 * 3_600 * 1_000_000,
            },
            validity: PgInterval {
                months: 0,
                days: 1,
                microseconds: 0,
            },
        }
    }

    #[test]
    fn fallback_rotation_basic_round_trip() {
        let fr = FallbackRotation::try_from(base_fallback_row()).unwrap();
        assert_eq!(fr.target_secret_name, "ci-hort-token");
        assert_eq!(fr.target_secret_namespace, "ci-system");
        assert_eq!(fr.format, SecretFormat::Dockerconfigjson);
        assert_eq!(fr.rotation_interval, Duration::from_secs(6 * 3600));
        assert_eq!(fr.validity, Duration::from_secs(24 * 3600));
    }

    #[test]
    fn fallback_rotation_opaque_format_round_trip() {
        let row = FallbackRotationRow {
            format: "opaque".into(),
            ..base_fallback_row()
        };
        let fr = FallbackRotation::try_from(row).unwrap();
        assert_eq!(fr.format, SecretFormat::Opaque);
    }

    #[test]
    fn fallback_rotation_unknown_format_is_invariant() {
        // The DB CHECK forbids this; the mapper is defence-in-depth.
        let row = FallbackRotationRow {
            format: "yaml".into(),
            ..base_fallback_row()
        };
        let err = FallbackRotation::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("yaml"));
    }

    #[test]
    fn fallback_rotation_negative_rotation_interval_is_invariant() {
        let row = FallbackRotationRow {
            rotation_interval: PgInterval {
                months: 0,
                days: 0,
                microseconds: -1,
            },
            ..base_fallback_row()
        };
        let err = FallbackRotation::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn fallback_rotation_negative_validity_is_invariant() {
        let row = FallbackRotationRow {
            validity: PgInterval {
                months: 0,
                days: -1,
                microseconds: 0,
            },
            ..base_fallback_row()
        };
        let err = FallbackRotation::try_from(row).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }
}
