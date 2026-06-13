//! CAS integrity scrub events (ADR 0003).
//!
//! Emitted by `CasScrubUseCase` in `hort-app` when a stored blob's
//! re-computed SHA-256 does not match its content-addressable key.
//!
//! Streams live in [`StreamCategory::Artifact`](super::StreamCategory::Artifact)
//! — the audit trail of a tampered blob belongs next to that blob's
//! other lifecycle events. `StreamId::artifact(artifact_id)` is the
//! conventional key; the scrubber, which walks the CAS rather than the
//! artifact table, emits to a dedicated synthetic stream described in
//! the use case docstring. **No schema migration is required** — the
//! events table accepts new `event_type` values by design (stream_category
//! and event_type are `TEXT`, not Postgres enum types).
//!
//! **Flag-only.** Per design doc §2.7 the scrubber does NOT quarantine
//! on mismatch; it records the finding as an event + metric and lets
//! the operator decide the response. An overreactive automation could
//! quarantine a whole CAS shard on a single transient read error.

use serde::{Deserialize, Serialize};

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::validation::validate_string;

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum allowed length of `CasIntegrityMismatch.backend`. The catalog
/// enumerates two values (`filesystem`, `object_store`); a generous cap
/// accommodates a future "backend + region" form without schema change.
const MAX_BACKEND_LEN: usize = 64;

// ---------------------------------------------------------------------------
// CasIntegrityMismatch
// ---------------------------------------------------------------------------

/// Recorded when the CAS scrubber discovers a blob whose re-computed
/// SHA-256 does not match its content-addressable key.
///
/// **Does not quarantine.** The event + the matching
/// `hort_cas_scrub_checks_total{result="hash_mismatch"}` metric are the
/// entire incident record. An operator inspects the event log and
/// takes manual remediation (re-ingest from upstream, quarantine the
/// containing artifact, forensic dump) outside the scrubber path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CasIntegrityMismatch {
    /// The CAS key the blob was stored under — the hash the adapter
    /// expects when serving `get(&hash)`.
    pub content_hash: ContentHash,
    /// The backend that hosts the tampered blob. One of the known
    /// [`StoragePort::backend_label`](crate::ports::storage::StoragePort::backend_label)
    /// values (`"filesystem"` or `"object_store"`).
    pub backend: String,
    /// The SHA-256 that the scrubber actually computed from the stored
    /// bytes. By definition different from `content_hash`; carried here
    /// so the event replay has the forensic evidence without a
    /// re-scrub.
    pub observed_hash: ContentHash,
}

impl CasIntegrityMismatch {
    pub fn validate(&self) -> DomainResult<()> {
        // `content_hash` and `observed_hash` are already-validated
        // `ContentHash` newtypes — no re-validation needed. Only the
        // free-form `backend` string can fall out of range.
        validate_string("backend", &self.backend, MAX_BACKEND_LEN)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const OTHER_HASH: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    fn hash(hex: &str) -> ContentHash {
        hex.parse().unwrap()
    }

    fn valid() -> CasIntegrityMismatch {
        CasIntegrityMismatch {
            content_hash: hash(VALID_HASH),
            backend: "filesystem".into(),
            observed_hash: hash(OTHER_HASH),
        }
    }

    #[test]
    fn validate_accepts_minimal_valid_event() {
        valid().validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_backend() {
        let mut e = valid();
        e.backend = String::new();
        assert!(e.validate().is_err());
    }

    #[test]
    fn validate_rejects_oversized_backend() {
        let mut e = valid();
        e.backend = "b".repeat(MAX_BACKEND_LEN + 1);
        let err = e.validate().unwrap_err();
        assert!(err.to_string().contains("backend"));
    }

    #[test]
    fn validate_accepts_backend_at_exact_cap() {
        let mut e = valid();
        e.backend = "b".repeat(MAX_BACKEND_LEN);
        e.validate().unwrap();
    }

    #[test]
    fn serde_roundtrip_preserves_fields() {
        let original = valid();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: CasIntegrityMismatch = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
