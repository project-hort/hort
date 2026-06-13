//! Retention / event-store sealing events (event-chain tamper-evidence;
//! ADR 0002, emission discipline in ADR 0020 + ADR 0028).
//!
//! Defines the [`StreamSealed`] audit record. The contract: when
//! `delete_stream` / `archive_stream` removes a whole stream, the
//! retention path MUST first append a `StreamSealed` tombstone, through
//! the normal chained append path, to the never-deleted audit-meta
//! stream ([`StreamCategory::Admin`](super::StreamCategory::Admin), the
//! `StreamId::eventstore_retention()` stream — the derived
//! `admin-<v5-uuid>` id).
//!
//! This module only *defines* the variant; there is no emitter here.
//! The enum is `#[non_exhaustive]`, so adding the variant is additive —
//! no existing match-arm changes shape. The tombstone carries the
//! deleted stream's chain head (`final_event_hash`) so the *fact and
//! head-hash of every deletion* stays permanently chained and
//! externally anchored: an offline verifier treats an absent stream
//! that has a matching, anchored `StreamSealed` record as an expected
//! `SealedGap`, not a `Broken` chain.
//!
//! **No PII.** Like the rest of the event vocabulary the payload only
//! references ids (`sealed_stream_id` is the deleted stream's wire-form
//! string, `retention_policy_id` / `actor_id` are CRUD foreign keys).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainResult;

use super::validation::validate_string;

/// Maximum length of the persisted `sealed_stream_id` wire string.
///
/// Stream ids are `"{category}-{uuid}"` (≤ ~50 chars in practice);
/// 256 is comfortably wide and keeps the envelope small while still
/// being a structural guard against a malformed caller.
const MAX_SEALED_STREAM_ID_LEN: usize = 256;

/// Maximum length of the persisted `sealed_stream_category` wire string
/// (the closed [`StreamCategory`](super::StreamCategory) wire taxonomy —
/// the longest entry today is `"artifact_group"`).
const MAX_SEALED_STREAM_CATEGORY_LEN: usize = 64;

// ---------------------------------------------------------------------------
// StreamSealed
// ---------------------------------------------------------------------------

/// Recorded immediately before `delete_stream` /
/// `archive_stream` removes any row of a terminal stream whose
/// audit-retention floor has elapsed.
///
/// This event is itself a normal chained event on the
/// `StreamId::eventstore_retention()` audit-meta stream (the derived
/// `admin-<v5-uuid>` id), so the *existence and head
/// hash* of every sealed/deleted stream is permanently chained and
/// externally anchored. The verifier semantics:
/// a stream that is absent but has a `StreamSealed` whose
/// `final_event_hash` was covered by an anchored checkpoint
/// at-or-after the seal is an expected `SealedGap`; an absent stream
/// with no matching `StreamSealed` is `Broken`.
///
/// Defined here; **emitted only by the eventstore-retention path**
/// (see the module docstring — no emitter lives in this module).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSealed {
    /// Wire-form string of the stream that was sealed/deleted, exactly
    /// as it was persisted in `events.stream_id` (e.g.
    /// `"authorization-<uuid>"`). Kept as the raw string rather than a
    /// typed `StreamId` because the seal records a historical fact
    /// about a stream that no longer exists; the string is what the
    /// verifier matches against the absent stream.
    pub sealed_stream_id: String,
    /// Wire-form string of the sealed stream's category (e.g.
    /// `"authorization"`), exactly as persisted in
    /// `events.stream_category`.
    pub sealed_stream_category: String,
    /// `stream_position` of the deleted stream's last (head) event —
    /// 0-based, so a single-event stream seals at position 0.
    pub final_stream_position: u64,
    /// The deleted stream's chain head: the `event_hash` of its last
    /// event. 32 raw bytes. The verifier checks this matches the head
    /// the last pre-seal checkpoint anchored.
    pub final_event_hash: [u8; 32],
    /// Number of events the sealed stream contained
    /// (`final_stream_position + 1` for a gapless stream; carried
    /// explicitly so the audit record is self-describing).
    pub event_count: u64,
    /// The retention policy that authorised the deletion (a foreign
    /// key into the CRUD retention-policy store). Lets an auditor
    /// answer "under which policy was this stream sealed?".
    pub retention_policy_id: Uuid,
    /// The actor that performed the retention purge (a foreign key
    /// into the CRUD `users` table, or the system/timer sentinel).
    /// `None` for the system/timer-driven retention sweep.
    pub actor_id: Option<Uuid>,
}

impl StreamSealed {
    /// Validate the event payload. The string fields are bounded
    /// (defence-in-depth against a malformed emitter); the numeric and
    /// id fields are well-formed by construction. Kept for symmetry
    /// with the rest of the event vocabulary so the
    /// [`DomainEvent::validate()`](super::DomainEvent::validate)
    /// dispatch table has a uniform arm.
    pub fn validate(&self) -> DomainResult<()> {
        validate_string(
            "sealed_stream_id",
            &self.sealed_stream_id,
            MAX_SEALED_STREAM_ID_LEN,
        )?;
        validate_string(
            "sealed_stream_category",
            &self.sealed_stream_category,
            MAX_SEALED_STREAM_CATEGORY_LEN,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> StreamSealed {
        StreamSealed {
            sealed_stream_id: "authorization-00000000-0000-0000-0000-000000000000".into(),
            sealed_stream_category: "authorization".into(),
            final_stream_position: 7,
            final_event_hash: [0xab; 32],
            event_count: 8,
            retention_policy_id: Uuid::nil(),
            actor_id: None,
        }
    }

    #[test]
    fn validate_accepts_well_formed() {
        valid()
            .validate()
            .expect("well-formed StreamSealed validates");
    }

    #[test]
    fn validate_rejects_empty_stream_id() {
        let mut s = valid();
        s.sealed_stream_id = String::new();
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("sealed_stream_id"));
    }

    #[test]
    fn validate_rejects_oversize_stream_id() {
        let mut s = valid();
        s.sealed_stream_id = "x".repeat(MAX_SEALED_STREAM_ID_LEN + 1);
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("sealed_stream_id"));
    }

    #[test]
    fn validate_rejects_empty_category() {
        let mut s = valid();
        s.sealed_stream_category = String::new();
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("sealed_stream_category"));
    }

    #[test]
    fn validate_rejects_oversize_category() {
        let mut s = valid();
        s.sealed_stream_category = "y".repeat(MAX_SEALED_STREAM_CATEGORY_LEN + 1);
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("sealed_stream_category"));
    }

    #[test]
    fn serde_round_trips() {
        let s = valid();
        let json = serde_json::to_value(&s).unwrap();
        let back: StreamSealed = serde_json::from_value(json).unwrap();
        assert_eq!(s, back);
    }
}
