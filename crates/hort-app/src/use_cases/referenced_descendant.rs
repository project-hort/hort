//! Shared referenced-tree-descendant predicate, and the inherited-trust
//! condition the quarantine-anchor carve-out stands on.
//!
//! Extracted from the inline `.any(..)` in
//! `IngestUseCase::ingest_inner`'s zero-window carve-out so every caller
//! applies the SAME definition of "this content is already some other
//! artifact's `content_references` target".
//!
//! Mirrors the `policy_resolution` module's shape: a small `pub(crate)`
//! home for a predicate shared across use cases, rather than a method on
//! either use case.
//!
//! # Two questions, and why only one of them is pure
//!
//! The carve-out that waives the observation window (ADR 0007) is
//! conditional on **inherited trust**: it applies to a
//! `content_references` target of which at least one referencing parent
//! is itself `Released`. A descendant whose parents are all still held
//! keeps the full window, because there is no earlier trusted assessment
//! for its own first-touch scan to be fresher than — on a cold pull of a
//! composed artifact, parent and constituents are minted seconds apart
//! against the same advisory data.
//!
//! That splits into a topology question and a state question:
//!
//! - [`is_referenced_tree_descendant`] — "is this content a target of
//!   some OTHER artifact", over a reference set the caller already holds.
//!   Pure, hence exhaustively testable, and the one definition of the
//!   kind rule.
//! - the parents' quarantine statuses, which is I/O and therefore lives
//!   in [`resolve_released_parent_trust_fail_safe`] rather than in the
//!   predicate. The domain's `derive_quarantine_anchor` takes the
//!   answer as a `bool`, so establishing it is the application layer's
//!   job and the derivation stays pure.
//!
//! # Error direction per caller
//!
//! What differs between the callers is how a FAILED lookup is handled.
//! [`resolve_released_parent_trust_fail_safe`] makes **two** reads, and
//! both degrade in the same direction — toward the artifact keeping its
//! normal FULL observation window, which is the conservative outcome:
//!
//! - **Quarantine-anchor resolution** — `ingest_inner` and
//!   `register_by_hash_inner`, both through
//!   [`resolve_released_parent_trust_fail_safe`]:
//!   - a failed `content_references` target lookup degrades to "not a
//!     descendant", so the carve-out does not apply at all;
//!   - a failed *parent status* read degrades to "that parent is not
//!     `Released`", so it contributes no trust to inherit. Per parent,
//!     not per call: a parent hort did read and found `Released` is
//!     genuine inherited trust, and an unreadable sibling does not
//!     retract it. When every parent read fails the answer is `false` —
//!     the full window — which is the same direction the first read
//!     degrades in.
//!
//!   Neither degradation can reach the zero-window direction, and
//!   neither aborts the mint: an infra hiccup must not fail an ingest
//!   that is otherwise complete.
//! - The release sweep's expiry backstop reads the same reference set
//!   through the narrower [`is_parent_gated_blob_constituent`], which
//!   decides whether the final `provenance-verify` enqueue can be SKIPPED
//!   as provably state-neutral. It PROPAGATES a lookup failure: `false`
//!   there re-creates the churn the skip exists to remove, `true` would
//!   strand the candidate.
//!
//! The provenance orchestrator no longer consults either: under ADR
//! 0039's 2026-09-12 amendment (D1/D3) a `NoAttestation × Required`
//! verdict holds regardless of the artifact's position in the tree, so
//! there is nothing for the predicate to gate there.

use std::collections::HashSet;

use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::types::ContentHash;

/// `content_references.kind` values that are an artifact's OWN
/// bookkeeping rather than "some other artifact references me".
///
/// Every artifact's own ingest writes a `primary_content` row targeting
/// **its own** hash, so an unfiltered "is this hash a target of ANY
/// kind" check would match every artifact against itself and always
/// fire. `metadata_blob` is the same shape for the split-metadata path.
/// `pub` because the held-set overview's SQL binds this list as a
/// `text[]` parameter rather than restating it: the bucket rule has
/// exactly one definition in Rust and SQL forms only the boolean from
/// it. See [`is_parent_gated_blob_constituent_kinds`].
pub const SELF_REFERENTIAL_KINDS: [&str; 2] = ["primary_content", "metadata_blob"];

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
///
/// That requirement is about `kind` and nothing else — it is the
/// `kind_filter` argument of
/// [`ContentReferenceIndex::find_by_target`] that must stay `None`,
/// because this predicate is defined over the complement of
/// [`SELF_REFERENTIAL_KINDS`] and a single-kind read makes every other
/// tree edge unobservable. It says nothing about the LIVENESS of the
/// row's `source_artifact_id`: restricting the set to edges whose
/// source is still live would be a different question, compatible with
/// this one. Nothing restricts it here because no caller has to — the
/// OCI manifest-DELETE handler sweeps a tombstoned manifest's edges,
/// the purge transaction sweeps them again, and the refcount-reconcile
/// sweep drops every edge of a `rejected` source, so a row surfacing
/// through this read has a live source in the steady state.
pub(crate) fn is_referenced_tree_descendant(refs: &[ContentReference]) -> bool {
    refs.iter()
        .any(|r| !SELF_REFERENTIAL_KINDS.contains(&r.kind.as_str()))
}

/// Resolve the referenced-tree-descendant carve-out's **full**
/// condition: is this content a `content_references` target of some
/// other, already-ingested artifact in this repository, **and** is at
/// least one of those referencing parents itself `Released`?
///
/// This is the QUARANTINE-ANCHOR resolution shared by both artifact-
/// minting paths — `IngestUseCase::ingest_inner` (streamed upstream
/// fetch / direct upload) and `IngestUseCase::register_by_hash_inner`
/// (cross-repo mount, coalesced pull-through follower, seed-import
/// cutover). Sharing it is what makes the carve-out caller-independent:
/// both halves are facts about the repository — the topology
/// ([`is_referenced_tree_descendant`]) and the parents' statuses — so
/// the window a descendant receives must not depend on which minting
/// path, or which racer in a dedup coalesce, created its row.
///
/// # Why the second half
///
/// The carve-out rests on the descendant's own first-touch scan being
/// more recent than the parent's ingest-time scan *the operator already
/// trusted at release* — which presupposes a released parent. On a cold
/// pull of a composed artifact there is none: parent and constituents
/// are minted seconds apart against the same advisory data, with the
/// parent's own window still running, so there is no earlier trusted
/// assessment to be fresher than and the waiver would rest on nothing.
/// Requiring a released parent is therefore the carve-out's own
/// rationale stated as a condition; it takes nothing from it (ADR 0007,
/// amended 2026-11-15).
///
/// Repository scope is structural rather than re-checked: the reference
/// set comes from a repo-scoped `find_by_target`, and every writer
/// resolves a claim with the minting artifact's own `repository_id`, so
/// a parent reached from one of these rows is governed by the same
/// policy — and so the same window length — as the constituent it
/// references.
///
/// # Error direction
///
/// `false` is the FAIL-SAFE answer, never fail-open: it yields the
/// artifact's normal FULL observation window and can never reach the
/// zero-window direction. Both reads degrade that way — see the module
/// docs for the two halves, and why the parent degradation is per parent
/// rather than per call.
pub(crate) async fn resolve_released_parent_trust_fail_safe(
    content_references: &dyn ContentReferenceIndex,
    artifacts: &dyn ArtifactRepository,
    repository_id: Uuid,
    artifact_id: Uuid,
    hash: &ContentHash,
) -> bool {
    // The UNFILTERED kind set — `is_referenced_tree_descendant`'s
    // contract; passing a `kind_filter` here would silently narrow it.
    // The contract binds the kind argument only; source liveness is kept
    // out of this set by the writers (see the predicate's docstring),
    // not by a filter on this read.
    let refs = match content_references
        .find_by_target(repository_id, hash, None)
        .await
    {
        Ok(refs) => refs,
        Err(e) => {
            tracing::warn!(
                %artifact_id,
                %repository_id,
                error = %e,
                "content_references target lookup failed; treating as non-descendant \
                 (full window, fail-safe)"
            );
            return false;
        }
    };

    if !is_referenced_tree_descendant(&refs) {
        return false;
    }

    if has_released_referencing_parent(artifacts, repository_id, artifact_id, &refs).await {
        return true;
    }

    tracing::debug!(
        %artifact_id,
        %repository_id,
        "referenced-tree descendant inherits no released-parent trust; the full \
         observation window applies (ADR 0007: the carve-out is conditional on \
         inherited trust)"
    );
    false
}

/// Does any artifact holding a **tree edge** onto `refs`' target carry
/// [`QuarantineStatus::Released`]?
///
/// The parent set is the sources of the edges whose kind is outside
/// [`SELF_REFERENTIAL_KINDS`] — the same complement
/// [`is_referenced_tree_descendant`] is defined over, because a
/// `primary_content` / `metadata_blob` row's source is not a referencing
/// *parent*: it is the artifact's own refcount bookkeeping, or a
/// same-bytes sibling in this repository, and neither is a composed
/// artifact whose release vouched for these constituents.
///
/// Reads are per parent and short-circuit on the first `Released` one,
/// so the warm case — the parent an operator released before its
/// constituents were touched — costs one lookup. Parent ids are
/// de-duplicated first: one manifest can carry several edges onto one
/// target (a config blob that is also a layer, a layer repeated), and
/// those are one parent, not several.
///
/// A parent that cannot be read contributes "not `Released`" and the
/// scan continues. That is the conservative reading of each individual
/// edge: an unreadable parent is no evidence of trust, and a parent that
/// *was* read and is `Released` is evidence an unreadable sibling cannot
/// retract. `find_by_id` excludes soft-deleted rows, so a deleted parent
/// lands here too — correctly, since a withdrawn artifact's release
/// vouches for nothing.
async fn has_released_referencing_parent(
    artifacts: &dyn ArtifactRepository,
    repository_id: Uuid,
    artifact_id: Uuid,
    refs: &[ContentReference],
) -> bool {
    let mut probed: HashSet<Uuid> = HashSet::new();
    for parent_id in refs
        .iter()
        .filter(|r| !SELF_REFERENTIAL_KINDS.contains(&r.kind.as_str()))
        .map(|r| r.source_artifact_id)
    {
        if !probed.insert(parent_id) {
            continue;
        }
        match artifacts.find_by_id(parent_id).await {
            Ok(parent) if parent.quarantine_status == QuarantineStatus::Released => return true,
            // Held, rejected or scan-indeterminate: no trust to inherit.
            // A terminal state is emphatically not trust — it is the
            // opposite verdict on the composed artifact these bytes
            // belong to.
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    %artifact_id,
                    %repository_id,
                    %parent_id,
                    error = %e,
                    "referencing parent lookup failed; treating that parent as not \
                     released (full window, fail-safe)"
                );
            }
        }
    }
    false
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
/// `pub` for the same reason as [`SELF_REFERENTIAL_KINDS`] — the
/// held-set overview binds it as a query parameter.
pub const PARENT_GATE_BLOB_KINDS: [&str; 2] = ["oci_config", "oci_layer"];

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
/// - a `NoAttestation × Required` verdict is HELD, not terminal, and
///   for every shape rather than only for a descendant: an absent
///   attestation states where the evidence was at one instant, which
///   nothing terminal can rest on (ADR 0039 D1/D3,
///   [`Artifact::complete_provenance`](hort_domain::entities::artifact::Artifact::complete_provenance));
/// - a `Verified` / `Rejected` verdict requires attestation material,
///   and no attestation can ever target a blob;
/// - a *fetch failure* is `Indeterminate`, which under `Required` is a
///   hold too — so the only verdicts left for a blob constituent are
///   two holds, and neither changes any state on a candidate that had
///   nothing to fetch.
///
/// The inverse conservatism to [`is_referenced_tree_descendant`] is
/// deliberate: there, an unknown kind counts AS a descendant (hold-safe);
/// here, an unknown kind disqualifies the skip (enqueue-safe). Both
/// directions default to "do not terminally decide this artifact".
pub(crate) fn is_parent_gated_blob_constituent(refs: &[ContentReference]) -> bool {
    is_parent_gated_blob_constituent_kinds(refs.iter().map(|r| r.kind.as_str()))
}

/// [`is_parent_gated_blob_constituent`] over the edges' **kinds** alone
/// — the whole of what the predicate reads.
///
/// This is the one definition of the rule, and it exists separately from
/// the `&[ContentReference]` form for one reason: the held-set
/// overview's aggregate has to answer the same question in SQL, over
/// rows it never materialises as `ContentReference` values. Binding
/// [`PARENT_GATE_BLOB_KINDS`] and [`SELF_REFERENTIAL_KINDS`] into that
/// query as `text[]` parameters lets SQL form only the boolean, so the
/// rule is not re-implemented there — and a DB-backed parity test drives
/// this function and that query over the same kind sets, so neither side
/// can be edited alone.
///
/// Equivalent to: at least one kind in [`PARENT_GATE_BLOB_KINDS`], and
/// every kind in `PARENT_GATE_BLOB_KINDS ∪ SELF_REFERENTIAL_KINDS`. An
/// empty iterator is `false` — a reference-less artifact is nobody's
/// constituent.
pub fn is_parent_gated_blob_constituent_kinds<'a, I>(kinds: I) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    let mut saw_blob_edge = false;
    for kind in kinds {
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

    // -- resolve_released_parent_trust_fail_safe ----------------------
    //
    // The carve-out's full condition, which is the decision this module
    // exists to make: a `content_references` target with at least one
    // `Released` referencing parent waives the observation window; a
    // descendant whose parents are all still held keeps it. Every arm of
    // the resolver and both of its error directions are driven here,
    // against the same mocks the `IngestUseCase` tests use, so the
    // use-case pair above it only has to show the two anchors.

    use hort_domain::error::DomainError;

    use crate::use_cases::test_support::{
        sample_artifact, MockArtifactRepository, MockContentReferenceIndex,
    };

    /// The repository every fixture below works in. `find_by_target` is
    /// repo-scoped, so this is the scope the whole question lives in.
    fn repo_id() -> Uuid {
        Uuid::new_v4()
    }

    /// Seed a parent artifact at `status` and return its id.
    fn parent_at(artifacts: &MockArtifactRepository, repo: Uuid, status: QuarantineStatus) -> Uuid {
        let mut parent = sample_artifact(status);
        parent.repository_id = repo;
        parent.path = format!("parents/{}", parent.id);
        let id = parent.id;
        artifacts.insert(parent);
        id
    }

    /// Record `parent` as referencing [`hash`] under `kind` in `repo`.
    async fn edge(refs: &MockContentReferenceIndex, repo: Uuid, parent: Uuid, kind: &str) {
        refs.insert(ContentReference {
            source_artifact_id: parent,
            target_content_hash: hash(),
            kind: kind.to_string(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            repository_id: repo,
            recorded_at: Utc::now(),
        })
        .await
        .expect("seeding an edge must succeed");
    }

    /// The resolver over [`hash`] in `repo`, as both minting paths call
    /// it. `artifact_id` is only ever logged, so a fresh one is fine.
    async fn resolve(
        refs: &MockContentReferenceIndex,
        artifacts: &MockArtifactRepository,
        repo: Uuid,
    ) -> bool {
        resolve_released_parent_trust_fail_safe(refs, artifacts, repo, Uuid::new_v4(), &hash())
            .await
    }

    fn fixtures() -> (MockContentReferenceIndex, MockArtifactRepository) {
        (
            MockContentReferenceIndex::new(),
            MockArtifactRepository::new(),
        )
    }

    /// THE decision, half one: a descendant of a `Released` parent
    /// inherits its trust and the carve-out applies.
    #[tokio::test]
    async fn a_released_parent_grants_the_carve_out() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        let parent = parent_at(&artifacts, repo, QuarantineStatus::Released);
        edge(&refs, repo, parent, "oci_index_member").await;

        assert!(
            resolve(&refs, &artifacts, repo).await,
            "a child manifest of a released index inherits the trust the \
             operator already placed in that index"
        );
    }

    /// THE decision, half two — and the behaviour change: a descendant
    /// of a parent that is still `Quarantined` has no trust to inherit,
    /// so the carve-out does NOT apply and the artifact keeps its full
    /// window. This is the cold-pull shape, where parent and
    /// constituents are minted seconds apart against the same advisory
    /// data.
    #[tokio::test]
    async fn a_held_parent_does_not_grant_the_carve_out() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        let parent = parent_at(&artifacts, repo, QuarantineStatus::Quarantined);
        edge(&refs, repo, parent, "oci_index_member").await;

        assert!(
            !resolve(&refs, &artifacts, repo).await,
            "a quarantined parent's own window is still running; there is no \
             earlier trusted assessment for the descendant to inherit"
        );
    }

    /// One released parent among held ones is enough: the trust exists,
    /// and a sibling parent still waiting on its own scan does not
    /// retract it.
    #[tokio::test]
    async fn one_released_parent_among_held_ones_is_enough() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        for _ in 0..3 {
            let held = parent_at(&artifacts, repo, QuarantineStatus::Quarantined);
            edge(&refs, repo, held, "oci_layer").await;
        }
        let released = parent_at(&artifacts, repo, QuarantineStatus::Released);
        edge(&refs, repo, released, "oci_layer").await;

        assert!(
            resolve(&refs, &artifacts, repo).await,
            "a shared layer blob one of whose manifests is released inherits \
             that manifest's trust"
        );
    }

    /// …and several held parents with no released one among them is the
    /// full window — the many-parents counterpart of the decision's
    /// second half, so "we found a parent" cannot be mistaken for "we
    /// found trust".
    #[tokio::test]
    async fn several_held_parents_with_none_released_keep_the_full_window() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        for kind in ["oci_layer", "oci_config", "oci_index_member", "oci_subject"] {
            let held = parent_at(&artifacts, repo, QuarantineStatus::Quarantined);
            edge(&refs, repo, held, kind).await;
        }

        assert!(!resolve(&refs, &artifacts, repo).await);
    }

    /// A terminal parent is not trust — it is the opposite verdict on
    /// the composed artifact these bytes belong to. `Rejected` and
    /// `ScanIndeterminate` are both fail-closed states (ADR 0007), and
    /// `None` is "nothing ever held this", which is an absence of
    /// assessment rather than a trusted one.
    #[tokio::test]
    async fn no_parent_status_other_than_released_grants_the_carve_out() {
        for status in [
            QuarantineStatus::Quarantined,
            QuarantineStatus::Rejected,
            QuarantineStatus::ScanIndeterminate,
            QuarantineStatus::None,
        ] {
            let (refs, artifacts) = fixtures();
            let repo = repo_id();
            let parent = parent_at(&artifacts, repo, status);
            edge(&refs, repo, parent, "oci_index_member").await;

            assert!(
                !resolve(&refs, &artifacts, repo).await,
                "a {status} parent must not grant the carve-out"
            );
        }
    }

    /// The first lookup's fail-safe direction: an unreadable
    /// `content_references` index degrades to "not a descendant", so the
    /// carve-out does not apply and the artifact keeps its full window.
    /// A released parent is present and still must not be reached —
    /// without the degradation this would answer `true`.
    #[tokio::test]
    async fn a_failed_target_lookup_keeps_the_full_window() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        let parent = parent_at(&artifacts, repo, QuarantineStatus::Released);
        edge(&refs, repo, parent, "oci_index_member").await;
        refs.fail_next_find_by_target(DomainError::Invariant("index unavailable".into()));

        assert!(
            !resolve(&refs, &artifacts, repo).await,
            "a failed topology read must degrade to the full window, never to \
             the waived one"
        );
    }

    /// The second lookup's fail-safe direction: the edge is there, so
    /// the artifact IS a descendant, but the parent's row cannot be
    /// read. That parent contributes no trust and the answer is the full
    /// window.
    #[tokio::test]
    async fn a_failed_parent_status_read_keeps_the_full_window() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        let parent = parent_at(&artifacts, repo, QuarantineStatus::Released);
        edge(&refs, repo, parent, "oci_index_member").await;
        artifacts.fail_next_find_by_id(DomainError::Invariant("artifacts read failed".into()));

        assert!(
            !resolve(&refs, &artifacts, repo).await,
            "an unreadable parent must contribute no trust — the row says \
             `Released`, and a read that did not land cannot be taken for it"
        );
    }

    /// A parent whose row is gone reaches the same arm by a different
    /// route: `find_by_id` excludes soft-deleted rows, so a withdrawn
    /// parent answers `NotFound` — correctly, since a withdrawn
    /// artifact's release vouches for nothing.
    #[tokio::test]
    async fn a_parent_whose_row_is_absent_keeps_the_full_window() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        edge(&refs, repo, Uuid::new_v4(), "oci_index_member").await;

        assert!(!resolve(&refs, &artifacts, repo).await);
    }

    /// The degradation is per parent, not per call: an unreadable parent
    /// does not retract trust hort did read elsewhere. The armed failure
    /// is consumed by the first read, so the second parent answers
    /// normally.
    #[tokio::test]
    async fn an_unreadable_parent_does_not_retract_a_released_sibling() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        let first = parent_at(&artifacts, repo, QuarantineStatus::Quarantined);
        let second = parent_at(&artifacts, repo, QuarantineStatus::Released);
        // Edge insertion order does not fix read order (the index is a
        // map), so arm the failure and seed BOTH parents such that
        // whichever is read first, a released one is still reachable.
        edge(&refs, repo, first, "oci_layer").await;
        edge(&refs, repo, second, "oci_layer").await;
        let third = parent_at(&artifacts, repo, QuarantineStatus::Released);
        edge(&refs, repo, third, "oci_layer").await;
        artifacts.fail_next_find_by_id(DomainError::Invariant("transient read failure".into()));

        assert!(
            resolve(&refs, &artifacts, repo).await,
            "one failed read must not mask the released parents beside it"
        );
    }

    /// The topology half still gates the trust half: a hash carrying
    /// only the self-referential refcount kinds is nobody's constituent,
    /// so no parent is probed at all — even when the artifact that wrote
    /// those rows is itself `Released`.
    #[tokio::test]
    async fn self_referential_rows_are_not_a_referencing_parent() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        for kind in SELF_REFERENTIAL_KINDS {
            let released = parent_at(&artifacts, repo, QuarantineStatus::Released);
            edge(&refs, repo, released, kind).await;
        }

        assert!(
            !resolve(&refs, &artifacts, repo).await,
            "an artifact's own refcount row, or a same-bytes sibling's, is not \
             a composed parent whose release vouched for these constituents"
        );
    }

    /// No inbound edges at all: not a descendant, nothing probed, full
    /// window. The ordinary case for every standalone artifact.
    #[tokio::test]
    async fn a_hash_nothing_references_keeps_the_full_window() {
        let (refs, artifacts) = fixtures();
        assert!(!resolve(&refs, &artifacts, repo_id()).await);
    }

    /// One parent carrying several edges onto one target is one parent:
    /// the config blob that is also a layer costs one read, not two. The
    /// armed failure proves it — a second read of the same id would
    /// consume nothing and succeed, flipping the answer to `true`.
    #[tokio::test]
    async fn one_parent_with_several_edges_is_probed_once() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        let parent = parent_at(&artifacts, repo, QuarantineStatus::Released);
        edge(&refs, repo, parent, "oci_config").await;
        edge(&refs, repo, parent, "oci_layer").await;
        edge(&refs, repo, parent, "oci_index_member").await;
        artifacts.fail_next_find_by_id(DomainError::Invariant("one read, one failure".into()));

        assert!(
            !resolve(&refs, &artifacts, repo).await,
            "three edges from one parent must be de-duplicated to one read"
        );
    }

    /// The repository scope is the reference set's, not a second filter:
    /// a row recorded in another repository is not in the set this
    /// resolver reads, so its released source cannot grant the
    /// carve-out.
    #[tokio::test]
    async fn a_released_parent_in_another_repository_is_not_in_scope() {
        let (refs, artifacts) = fixtures();
        let repo = repo_id();
        let elsewhere = repo_id();
        let parent = parent_at(&artifacts, elsewhere, QuarantineStatus::Released);
        edge(&refs, elsewhere, parent, "oci_index_member").await;

        assert!(!resolve(&refs, &artifacts, repo).await);
    }

    // -- what the operator is told -------------------------------------
    //
    // The held descendant is the newly-surprising outcome: a layer blob
    // that used to be deliverable in seconds now sits out the window,
    // and these lines are the only place that says why. A log line an
    // operator is expected to find has to be asserted, or it is
    // decoration.

    use crate::use_cases::test_support::tracing_capture::{capture_audit_events, CapturedEvent};

    /// This module's own lines at `level`, so a sibling crate's event
    /// cannot satisfy an assertion about ours.
    fn our_lines(captured: &[CapturedEvent], level: tracing::Level) -> Vec<CapturedEvent> {
        captured
            .iter()
            .filter(|e| {
                e.level == level
                    && e.target
                        .starts_with("hort_app::use_cases::referenced_descendant")
            })
            .cloned()
            .collect()
    }

    /// Drive `body` on a current-thread runtime under the capturing
    /// subscriber — the harness only sees events on its own thread.
    fn captured_resolve(body: impl AsyncFnOnce() -> bool) -> (bool, Vec<CapturedEvent>) {
        capture_audit_events(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("current-thread runtime");
            rt.block_on(body())
        })
    }

    /// A descendant that inherits nothing says so, and names the
    /// artifact and repository an operator would search by.
    #[test]
    fn a_descendant_with_no_released_parent_explains_the_hold() {
        let repo = repo_id();
        let artifact_id = Uuid::new_v4();
        let (answer, captured) = captured_resolve(async || {
            let (refs, artifacts) = fixtures();
            let parent = parent_at(&artifacts, repo, QuarantineStatus::Quarantined);
            edge(&refs, repo, parent, "oci_layer").await;
            resolve_released_parent_trust_fail_safe(&refs, &artifacts, repo, artifact_id, &hash())
                .await
        });

        assert!(!answer);
        let lines = our_lines(&captured, tracing::Level::DEBUG);
        assert_eq!(
            lines.len(),
            1,
            "exactly one line must explain the hold: {captured:#?}"
        );
        assert!(
            lines[0]
                .message()
                .contains("inherits no released-parent trust"),
            "the line must name the condition that was not met: {:#?}",
            lines[0]
        );
        assert_eq!(
            lines[0].fields.get("artifact_id").map(String::as_str),
            Some(artifact_id.to_string().as_str()),
            "the held artifact must be identifiable from the line: {:#?}",
            lines[0]
        );
        assert!(
            our_lines(&captured, tracing::Level::WARN).is_empty(),
            "a parent that was read and is simply held is not a failure: {captured:#?}"
        );
    }

    /// An unreadable parent warns and names which parent, so a hold
    /// caused by an infra fault is distinguishable from one caused by a
    /// parent that really is still held — and the hold is still
    /// explained on its own line.
    #[test]
    fn a_failed_parent_read_warns_and_names_the_parent() {
        let repo = repo_id();
        let parent_slot: std::sync::Mutex<Option<Uuid>> = std::sync::Mutex::new(None);
        let (answer, captured) = captured_resolve(async || {
            let (refs, artifacts) = fixtures();
            let parent = parent_at(&artifacts, repo, QuarantineStatus::Released);
            *parent_slot.lock().expect("uncontended") = Some(parent);
            edge(&refs, repo, parent, "oci_index_member").await;
            artifacts.fail_next_find_by_id(DomainError::Invariant("artifacts read failed".into()));
            resolve_released_parent_trust_fail_safe(
                &refs,
                &artifacts,
                repo,
                Uuid::new_v4(),
                &hash(),
            )
            .await
        });

        assert!(!answer);
        let warns = our_lines(&captured, tracing::Level::WARN);
        assert_eq!(warns.len(), 1, "{captured:#?}");
        assert!(
            warns[0]
                .message()
                .contains("referencing parent lookup failed"),
            "{:#?}",
            warns[0]
        );
        assert_eq!(
            warns[0].fields.get("parent_id").map(String::as_str),
            parent_slot
                .lock()
                .expect("uncontended")
                .map(|id| id.to_string())
                .as_deref(),
            "the unreadable parent must be named: {:#?}",
            warns[0]
        );
        assert_eq!(
            our_lines(&captured, tracing::Level::DEBUG).len(),
            1,
            "the resulting hold is still explained: {captured:#?}"
        );
    }

    /// A failed topology read warns in the first lookup's own terms —
    /// "treating as non-descendant" — and emits no hold explanation,
    /// because as far as this resolver got the artifact is not a
    /// descendant at all.
    #[test]
    fn a_failed_target_lookup_warns_as_a_non_descendant() {
        let repo = repo_id();
        let (answer, captured) = captured_resolve(async || {
            let (refs, artifacts) = fixtures();
            let parent = parent_at(&artifacts, repo, QuarantineStatus::Released);
            edge(&refs, repo, parent, "oci_index_member").await;
            refs.fail_next_find_by_target(DomainError::Invariant("index unavailable".into()));
            resolve_released_parent_trust_fail_safe(
                &refs,
                &artifacts,
                repo,
                Uuid::new_v4(),
                &hash(),
            )
            .await
        });

        assert!(!answer);
        let warns = our_lines(&captured, tracing::Level::WARN);
        assert_eq!(warns.len(), 1, "{captured:#?}");
        assert!(
            warns[0]
                .message()
                .contains("content_references target lookup failed"),
            "{:#?}",
            warns[0]
        );
        assert!(
            our_lines(&captured, tracing::Level::DEBUG).is_empty(),
            "nothing is known about this artifact's parents, so there is no \
             inherited-trust verdict to report: {captured:#?}"
        );
    }
}
