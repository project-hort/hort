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
//!
//! A third caller — the release sweep's expiry backstop — reads the same
//! reference set through the narrower
//! [`is_parent_gated_blob_constituent`], which decides whether the final
//! `provenance-verify` enqueue can be SKIPPED as provably state-neutral.
//! It also propagates a lookup failure: `false` there re-creates the
//! churn the skip exists to remove, `true` would strand the candidate.

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

/// `content_references.kind` values whose TARGET is an OCI **blob** — a
/// manifest's config blob or one of its layer blobs.
///
/// The set is deliberately narrow. It is not "the tree-edge kinds"; it
/// is "the tree-edge kinds whose target can never be the subject of an
/// attestation". `oci_index_member` and `oci_subject` both target a
/// *manifest*, and a manifest CAN acquire its own signature later; a
/// blob cannot (the OCI referrers `subject` is a manifest descriptor,
/// and cosign signs manifest digests).
const PARENT_GATE_BLOB_KINDS: [&str; 2] = ["oci_config", "oci_layer"];

/// Is this artifact a **parent-gated blob constituent** — a config/layer
/// blob whose only inbound edges are its parent manifest's, so no verify
/// run can ever reach a verdict other than the parent-gated hold?
///
/// `refs` is the result of
/// `ContentReferenceIndex::find_by_target(repo, hash, None)` (the
/// unfiltered kind set) for the artifact's own content hash — the SAME
/// input as [`is_referenced_tree_descendant`], of which this is a strict
/// subset (true here ⇒ true there).
///
/// True iff BOTH hold:
///
/// - at least one row carries a kind in [`PARENT_GATE_BLOB_KINDS`] (the
///   artifact really is a manifest's blob constituent), and
/// - EVERY row carries a kind in [`SELF_REFERENTIAL_KINDS`] ∪
///   [`PARENT_GATE_BLOB_KINDS`] — no `oci_subject` (an attestation
///   points at this artifact), no `oci_index_member` (this artifact is a
///   child *manifest*, which can be signed in its own right), and no
///   unknown/future kind.
///
/// # Why the "every row" clause, and why the allowlist is closed
///
/// The one consumer is the release sweep's expiry backstop, which uses
/// this to SKIP enqueueing a final `provenance-verify`. Skipping is the
/// direction that can strand an artifact, so the predicate must be true
/// only where the skipped job is provably state-neutral:
///
/// - a `NoAttestation × Required` verdict on a referenced-tree
///   descendant is HELD, not terminal
///   ([`Artifact::complete_provenance`](hort_domain::entities::artifact::Artifact::complete_provenance));
/// - a `Verified` / `Rejected` verdict requires attestation material,
///   and no attestation can ever target a blob;
/// - so the only verdicts left for a blob constituent are the hold —
///   which changes nothing — and the fail-closed
///   `Rejected{RekorNotFound}` a *fetch failure* produces, which is
///   pure harm on a candidate that had nothing to fetch.
///
/// The inverse conservatism to [`is_referenced_tree_descendant`] is
/// deliberate: there, an unknown kind counts AS a descendant (hold-safe);
/// here, an unknown kind disqualifies the skip (enqueue-safe). Both
/// directions default to "do not terminally decide this artifact".
pub(crate) fn is_parent_gated_blob_constituent(refs: &[ContentReference]) -> bool {
    let mut saw_blob_edge = false;
    for r in refs {
        let kind = r.kind.as_str();
        if PARENT_GATE_BLOB_KINDS.contains(&kind) {
            saw_blob_edge = true;
        } else if !SELF_REFERENTIAL_KINDS.contains(&kind) {
            return false;
        }
    }
    saw_blob_edge
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

    // -- is_parent_gated_blob_constituent -----------------------------

    #[test]
    fn no_references_at_all_is_not_a_parent_gated_blob() {
        assert!(!is_parent_gated_blob_constituent(&[]));
    }

    /// The purged-parent fallback in predicate form: once the parent's
    /// edges are gone, only the artifact's own refcount rows remain and
    /// the skip stops applying, so the expiry backstop resumes and the
    /// artifact settles terminally.
    #[test]
    fn own_refcount_rows_alone_are_not_a_parent_gated_blob() {
        assert!(!is_parent_gated_blob_constituent(&[
            reference("primary_content"),
            reference("metadata_blob"),
        ]));
    }

    #[test]
    fn each_blob_edge_kind_is_a_parent_gated_blob() {
        for kind in PARENT_GATE_BLOB_KINDS {
            assert!(
                is_parent_gated_blob_constituent(&[reference("primary_content"), reference(kind)]),
                "kind {kind} must count as a parent-gated blob constituent"
            );
        }
    }

    /// Mixed tree, shared blob: two parents' layer edges on one blob.
    /// Still parent-gated — held is correct while ANY live parent is
    /// unresolved, and the skip does not depend on how many there are.
    #[test]
    fn two_parents_layer_edges_on_one_blob_stay_parent_gated() {
        assert!(is_parent_gated_blob_constituent(&[
            reference("primary_content"),
            reference("oci_layer"),
            reference("oci_layer"),
        ]));
    }

    /// A child manifest is NOT a blob: it can be signed in its own
    /// right, so a verify of it can still reach a real verdict.
    #[test]
    fn index_member_is_not_a_parent_gated_blob() {
        assert!(!is_parent_gated_blob_constituent(&[reference(
            "oci_index_member"
        )]));
    }

    /// The strand case the narrow set exists to prevent: an artifact an
    /// attestation points at (`oci_subject`) is a verify away from being
    /// cleared, so it must keep the expiry backstop even though the
    /// broader descendant predicate also fires for it.
    #[test]
    fn an_attestation_subject_is_not_a_parent_gated_blob() {
        assert!(!is_parent_gated_blob_constituent(&[
            reference("primary_content"),
            reference("oci_subject"),
        ]));
        // …and the same holds when it is ALSO a blob constituent: one
        // attestation-bearing edge disqualifies the whole skip.
        assert!(!is_parent_gated_blob_constituent(&[
            reference("oci_layer"),
            reference("oci_subject"),
        ]));
    }

    /// Inverse conservatism to [`is_referenced_tree_descendant`]: an
    /// unknown kind counts as a descendant there (hold-safe) but
    /// disqualifies the skip here (enqueue-safe).
    #[test]
    fn unknown_kind_disqualifies_the_parent_gated_skip() {
        assert!(!is_parent_gated_blob_constituent(&[
            reference("oci_layer"),
            reference("future_kind"),
        ]));
    }

    /// Subset invariant: every reference set the skip fires on is also a
    /// referenced-tree descendant, i.e. the skipped verify would have
    /// been HELD by `complete_provenance` rather than deciding anything.
    /// A future edit that widened the skip beyond the hold arm would
    /// break this.
    #[test]
    fn parent_gated_blobs_are_always_referenced_tree_descendants() {
        let kinds = [
            "primary_content",
            "metadata_blob",
            "oci_config",
            "oci_layer",
            "oci_index_member",
            "oci_subject",
            "future_kind",
        ];
        // Every non-empty subset of the kind space, as reference sets.
        for mask in 1u32..(1 << kinds.len()) {
            let refs: Vec<ContentReference> = kinds
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, k)| reference(k))
                .collect();
            if is_parent_gated_blob_constituent(&refs) {
                assert!(
                    is_referenced_tree_descendant(&refs),
                    "skip fired on a set the hold arm would not hold: {:?}",
                    refs.iter().map(|r| &r.kind).collect::<Vec<_>>()
                );
            }
        }
    }
}
