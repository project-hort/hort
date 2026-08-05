//! Shared referenced-tree-descendant predicate (issue #115 item 3).
//!
//! Extracted from the inline `.any(..)` in
//! `IngestUseCase::ingest_inner`'s zero-window carve-out (#46 Item 2) so
//! the provenance orchestrator can apply the SAME definition when
//! deciding whether a `NoAttestation × Required` verdict HOLDS instead
//! of terminally rejecting (issue #115 defect (b)). Two call sites, one
//! definition — a drift between them would mean an artifact treated as a
//! descendant for its quarantine anchor but not for its provenance hold
//! (or vice versa), which is exactly the class of bug that produced #115.
//!
//! Mirrors the `policy_resolution` module's shape (issue #76): a small
//! `pub(crate)` home for a predicate shared across use cases, rather
//! than a method on either use case.
//!
//! # Ingest vs. verdict: the error-direction asymmetry
//!
//! The predicate itself is pure. What differs between the two callers is
//! how a FAILED `content_references` lookup is handled, and the
//! difference is load-bearing — see each call site's comment:
//!
//! - **Ingest** (`ingest_inner`) degrades to `false` on a lookup error.
//!   `false` there means "not a descendant" ⇒ the artifact keeps its
//!   normal FULL observation window — the more conservative outcome.
//! - **Verdict** (`ProvenanceOrchestrationUseCase::verify_artifact`)
//!   PROPAGATES the error. `false` there means "no descendant hold" ⇒
//!   under `Required` with a closed window the artifact is TERMINALLY
//!   REJECTED — the unsafe direction. A failed lookup must fail the job
//!   (dispatcher retries), never silently reject.

use hort_domain::ports::content_reference_index::ContentReference;

/// `content_references.kind` values that are an artifact's OWN
/// bookkeeping rather than "some other artifact references me".
///
/// Every artifact's own ingest writes a `primary_content` row targeting
/// **its own** hash, so an unfiltered "is this hash a target of ANY
/// kind" check would match every artifact against itself and always
/// fire. `metadata_blob` is the same shape for the split-metadata path.
const SELF_REFERENTIAL_KINDS: [&str; 2] = ["primary_content", "metadata_blob"];

/// Is this artifact a **referenced-tree descendant** — i.e. already a
/// `content_references` target of some OTHER, already-ingested artifact?
///
/// `refs` is the result of
/// `ContentReferenceIndex::find_by_target(repo, hash, None)` (the
/// unfiltered kind set) for the artifact's own content hash.
///
/// True iff any row carries a kind outside
/// [`SELF_REFERENTIAL_KINDS`] — a child manifest
/// (`oci_index_member`), a referrer's subject (`oci_subject`), or a
/// config/layer blob (`oci_config` / `oci_layer`, #46 Item 1).
///
/// Callers must pass the UNFILTERED reference set: filtering to a
/// single kind at the port would silently narrow the predicate.
pub(crate) fn is_referenced_tree_descendant(refs: &[ContentReference]) -> bool {
    refs.iter()
        .any(|r| !SELF_REFERENTIAL_KINDS.contains(&r.kind.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use uuid::Uuid;

    use hort_domain::types::ContentHash;

    fn hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("valid sha256 hex")
    }

    fn reference(kind: &str) -> ContentReference {
        ContentReference {
            source_artifact_id: Uuid::new_v4(),
            target_content_hash: hash(),
            kind: kind.to_string(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            repository_id: Uuid::new_v4(),
            recorded_at: Utc::now(),
        }
    }

    #[test]
    fn empty_reference_set_is_not_a_descendant() {
        assert!(!is_referenced_tree_descendant(&[]));
    }

    /// The exact false-positive the kind filter exists to prevent: an
    /// artifact's own `primary_content` refcount row targets its own
    /// hash, so an unfiltered check would make EVERY artifact a
    /// descendant of itself.
    #[test]
    fn own_primary_content_refcount_alone_is_not_a_descendant() {
        assert!(!is_referenced_tree_descendant(&[reference(
            "primary_content"
        )]));
    }

    #[test]
    fn own_metadata_blob_refcount_alone_is_not_a_descendant() {
        assert!(!is_referenced_tree_descendant(&[reference(
            "metadata_blob"
        )]));
    }

    #[test]
    fn both_self_referential_kinds_together_are_not_a_descendant() {
        assert!(!is_referenced_tree_descendant(&[
            reference("primary_content"),
            reference("metadata_blob"),
        ]));
    }

    /// Every tree-edge kind the OCI paths write must register as a
    /// descendant — these are the constituents #115 defect (b) is about.
    #[test]
    fn each_tree_edge_kind_is_a_descendant() {
        for kind in ["oci_config", "oci_layer", "oci_index_member", "oci_subject"] {
            assert!(
                is_referenced_tree_descendant(&[reference(kind)]),
                "kind {kind} must count as a referenced-tree descendant"
            );
        }
    }

    /// The realistic mixed shape: an OCI layer blob carries BOTH its own
    /// `primary_content` refcount AND the parent manifest's `oci_layer`
    /// edge. The tree edge must win.
    #[test]
    fn self_referential_plus_tree_edge_is_a_descendant() {
        assert!(is_referenced_tree_descendant(&[
            reference("primary_content"),
            reference("oci_layer"),
        ]));
    }

    /// An unknown/future kind is treated as a tree edge (not
    /// self-referential) — fail-safe at ingest (full window) and
    /// hold-safe at verdict time.
    #[test]
    fn unknown_kind_is_treated_as_a_descendant() {
        assert!(is_referenced_tree_descendant(&[reference("future_kind")]));
    }
}
