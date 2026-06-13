//! Download-audit events.
//!
//! Emitted by `hort-app::use_cases::artifact_use_case::download` **only when
//! the served artifact's `Repository.download_audit_enabled` flag is
//! true**. The opt-in flag is the volume control — there is no throttle
//! (contrast [`super::auth_events::AuthenticationAttempted`], which is
//! attacker-driven and throttled). A repository that does not opt in
//! produces no `ArtifactDownloaded` events at all; the per-format
//! download *count* stays Prometheus-only (`hort_download_total`).
//!
//! Streams live in
//! [`StreamCategory::DownloadAudit`](super::StreamCategory::DownloadAudit).
//! Per-`(repository, UTC-date)` rotation:
//! `StreamId::download_audit(repository_id, date)` derives a deterministic
//! UUIDv5 from `"download-audit:{repository_id}:{YYYY-MM-DD}"` so the same
//! repo+date always resolves to the same stream across replicas and
//! restarts (mirroring [`super::StreamId::auth_attempts`]).
//!
//! **Actor model (decision A — payload-only).** The batch
//! `AppendEvents.actor` is `system_actor()` (the recorder); the *subject*
//! — who pulled the bytes — rides the payload [`DownloadActor`]. This is
//! the shipped `AuthenticationAttempted` / `external_id_if_decoded`
//! pattern. We deliberately do NOT add an `Actor::Anonymous` variant: the
//! security-critical actor split + the `chk_actor_id` CHECK must not
//! gain an anonymous shape.
//!
//! **PII note.** `external_id` is the JWT `sub` / supplied identity of
//! the caller that pulled the artifact (a moderate identifier at most —
//! already present in the `users` row and in
//! `AuthenticationAttempted.external_id_if_decoded`). Anonymous pulls
//! carry no identity. No token, no credential material.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::validation::validate_string;

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum allowed length of [`DownloadActor::User::external_id`]. Wide
/// enough to accommodate a 255-char username or a long JWT `sub` claim
/// (Keycloak `realm-users:<uuid>` is well under this) without inviting
/// payload bloat. Mirrors `auth_events::MAX_EXTERNAL_ID_LEN` so the two
/// audit-stream identity fields keep the same bound.
const MAX_EXTERNAL_ID_LEN: usize = 512;

// ---------------------------------------------------------------------------
// DownloadActor
// ---------------------------------------------------------------------------

/// Payload-only subject of an [`ArtifactDownloaded`] event — *who* pulled
/// the bytes.
///
/// This is **not** an [`super::Actor`] variant by design (decision A): the
/// security-critical actor split and the `chk_actor_id` CHECK stay
/// closed. The batch recorder is always `system_actor()`; the subject
/// rides here, exactly as `AuthenticationAttempted.external_id_if_decoded`
/// carries the attempted identity rather than minting a new `Actor`.
///
/// Like the [`super::Actor`] family this enum is `Serialize` /
/// `Deserialize`: it is part of a [`super::DomainEvent`] payload that the
/// event-store adapter round-trips through JSONB. It must never appear in
/// an API request DTO (it never does — it is server-constructed in the
/// download use case from the resolved `CallerPrincipal`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadActor {
    /// An authenticated caller. `user_id` is the internal `users.id`;
    /// `external_id` is the JWT `sub` / supplied identity (mirrors
    /// `CallerPrincipal`).
    User { user_id: Uuid, external_id: String },
    /// An anonymous pull (no resolved principal — public repo, no
    /// credentials). Recorded explicitly so the audit log has no gaps:
    /// "nobody we could identify" is itself an audit fact.
    Anonymous,
}

impl DownloadActor {
    pub fn validate(&self) -> DomainResult<()> {
        match self {
            DownloadActor::User { external_id, .. } => {
                validate_string("external_id", external_id, MAX_EXTERNAL_ID_LEN)
            }
            DownloadActor::Anonymous => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// ArtifactDownloaded
// ---------------------------------------------------------------------------

/// Recorded when an artifact's content was served AND the owning
/// repository opted into download auditing
/// (`Repository.download_audit_enabled = true`).
///
/// # Wire shape
///
/// `occurred_at` is server-wall-clock at the moment the stream was
/// obtained (after the `is_downloadable()` gate). The event store
/// assigns its own `stored_at` on append; both are preserved (one is
/// "the download happened"; the other is "the audit log recorded it") —
/// same semantics as [`super::AuthenticationAttempted::at`].
///
/// `repository_id` is carried directly in the payload (it is the
/// stream-sharding key); `EventTypeKind::repository_id` returns it so
/// the subscription dispatcher's repo-scope filter sees it — though the
/// event type is in `HIGH_VOLUME_EVENT_TYPES` and is therefore
/// subscription-excluded at issuance regardless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDownloaded {
    /// The artifact whose content was served.
    pub artifact_id: Uuid,
    /// The repository the artifact was served from. The
    /// per-`(repo, date)` stream-sharding key.
    pub repository_id: Uuid,
    /// SHA-256 of the served content. [`ContentHash`] is 64 lowercase
    /// hex chars by construction, so no length bound is needed here.
    pub content_hash: ContentHash,
    /// Who pulled the bytes (payload-only subject — see
    /// [`DownloadActor`]).
    pub actor: DownloadActor,
    /// Server-wall-clock at the moment the content stream was obtained.
    pub occurred_at: DateTime<Utc>,
}

impl ArtifactDownloaded {
    pub fn validate(&self) -> DomainResult<()> {
        self.actor.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    fn valid_user() -> ArtifactDownloaded {
        ArtifactDownloaded {
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            content_hash: sha256(),
            actor: DownloadActor::User {
                user_id: Uuid::new_v4(),
                external_id: "keycloak:realm-users:abc-123".into(),
            },
            occurred_at: Utc::now(),
        }
    }

    #[test]
    fn validate_accepts_user_actor() {
        valid_user().validate().unwrap();
    }

    #[test]
    fn validate_accepts_anonymous_actor() {
        let mut e = valid_user();
        e.actor = DownloadActor::Anonymous;
        e.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_external_id() {
        let mut e = valid_user();
        e.actor = DownloadActor::User {
            user_id: Uuid::new_v4(),
            external_id: String::new(),
        };
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("external_id"));
    }

    #[test]
    fn validate_rejects_oversized_external_id() {
        let mut e = valid_user();
        e.actor = DownloadActor::User {
            user_id: Uuid::new_v4(),
            external_id: "x".repeat(MAX_EXTERNAL_ID_LEN + 1),
        };
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("external_id"));
    }

    #[test]
    fn download_actor_validate_anonymous_ok() {
        DownloadActor::Anonymous.validate().unwrap();
    }

    #[test]
    fn serde_roundtrip_preserves_fields_user() {
        let original = valid_user();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ArtifactDownloaded = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn serde_roundtrip_preserves_fields_anonymous() {
        let mut original = valid_user();
        original.actor = DownloadActor::Anonymous;
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ArtifactDownloaded = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
