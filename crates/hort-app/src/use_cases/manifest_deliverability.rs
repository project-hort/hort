//! "Is every artifact in this manifest's closure still deliverable?" —
//! resolved once, here, for every caller that serves an OCI manifest.
//!
//! ADR 0062: hort advertises nothing it will not serve. An OCI manifest
//! is immutable content-addressed bytes, so the enforcement shape for it
//! is **refusal of the document** rather than omission of an entry — a
//! client asked for a digest and verifies it, so hort cannot edit the
//! answer. A manifest is therefore deliverable only while every artifact
//! it binds is, and a **terminal** status anywhere in that closure
//! withdraws it.
//!
//! What this closes is a measured contradiction, not a hypothetical: a
//! push reported success over an already terminally rejected layer, the
//! manifest then served `200`, and the layer answered `404
//! BLOB_UNKNOWN` — which a container runtime surfaces as "failed to pull
//! and unpack … not found" after it has already committed to the pull.
//! The same rule has held for every other format since the shared index
//! pipeline existed (`crate::use_cases::index_filters`); the OCI paths
//! were the one place that did not hold it.
//!
//! # The closure comes from the bytes
//!
//! The constituent set is derived from the manifest's own content — the
//! config and layer digests of an image manifest, the children of an
//! index, and transitively each child's own constituents. It is **not**
//! read from the `content_references` edge projection, and that is a
//! standing decision rather than an oversight: edges *nominate* and the
//! bytes decide (ADR 0039's provenance cascade states it for the same
//! walk), and the projection is repairable rather than guaranteed — a
//! membership-edge backfill exists for manifest rows minted before the
//! write path carried their edges. A projection read here would answer a
//! deliverability question from a source that is allowed to be
//! incomplete.
//!
//! Reading bytes is what that costs, and the cost is asymmetric in a way
//! worth knowing before changing it: an **image manifest** needs exactly
//! one CAS read (its own bytes), which is the whole production
//! population this issue is about, while an **index** additionally reads
//! one object per child because a child's own constituents live in that
//! child's bytes. The catalog is then asked **once**, with the whole
//! closure, for the statuses.
//!
//! # Transitive, and bounded twice
//!
//! One hop is an arbitrary cut: an index over a child whose *layers* are
//! terminal would answer `200` and then fail at the child, which is the
//! same contradiction one level up. So the walk is transitive, bounded
//! by the depth cap the eager child ingest already enforces
//! ([`MAX_CHILD_INGEST_DEPTH`]) — walking deeper than the ingest ever
//! fetches would be asking about children this registry declines to
//! pull — and by [`MAX_CLOSURE_EXPANSIONS`], because the depth bound
//! alone does not bound the walk: the domain's per-index breadth cap is
//! 1024, so depth four over it is 1024⁴ nodes.
//!
//! # Absence is not a hold
//!
//! A constituent with no catalog row is **not local yet**, which is the
//! ordinary state of every cold pull-through manifest: those references
//! are registered by digest with no existence check, deliberately, and
//! the client's own blob `GET` is what pulls them through. Treating
//! absence as a hold would refuse every cold pull-through — so a
//! constituent that is merely absent leaves the answer
//! [`ManifestDeliverability::Deliverable`], and only a **present** row in
//! a terminal state changes it. The same applies one level up: a child
//! manifest whose bytes are not in CAS contributes its own digest to the
//! closure (the catalog still answers about it) and nothing else, because
//! there are no bytes to read its constituents from.
//!
//! # What fails closed
//!
//! Failing to resolve the question is not the same as resolving it
//! favourably (ADR 0007). The manifest's **own** bytes being unreadable
//! or unparseable, or the closure outgrowing its budget, leaves hort
//! unable to say what this document binds — so the resolution errors and
//! the caller serves nothing. A **child's** bytes being unreadable is
//! the bounded case above: the child itself is still judged, only its
//! descendants go unasked, and that degradation is reported in the log
//! rather than inverted into a refusal that would catch every cold
//! index.
//!
//! # What this deliberately does not do
//!
//! - It does not consult the caller. A terminal constituent will not
//!   become deliverable by a publisher completing their workflow, so the
//!   write-authorized hold-read (ADR 0055, generalising ADR 0039 §10)
//!   does not extend here: that exemption exists for a **hold**, where
//!   the answer is "not yet".
//! - It does not propagate a `Quarantined` constituent. A hold means
//!   "not yet", the client's own blob fetch already answers it with the
//!   deadline, and propagating it would change the answer for every
//!   fresh push and every pull-through index whose children arrive later
//!   (ADR 0062 decision 3).
//! - It caches nothing. Deliverability is not a property of the
//!   document's own row — it changes in both directions when a
//!   constituent is re-judged, with the document's bytes and status
//!   untouched.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use uuid::Uuid;

use hort_domain::error::DomainError;
use hort_domain::ports::constituent_status::{ConstituentStatusReader, TerminalConstituent};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::ContentHash;

use crate::error::{AppError, AppResult};
use crate::task_handlers::oci_index_child_ingest::MAX_CHILD_INGEST_DEPTH;
use crate::use_cases::cas_bounded_read::read_cas_bounded;

/// Ceiling on one CAS read in the closure walk.
///
/// Matches the default upstream manifest-body cap
/// (`HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE`, 16 MiB), so every manifest
/// hort accepted through pull-through under the default configuration can
/// be resolved. An operator who raises that cap above this ceiling does
/// not get an unbounded buffer here: the read is refused, and for the
/// manifest being served that refusal fails the resolution closed.
const CLOSURE_READ_CAP_BYTES: usize = 16 * 1024 * 1024;

/// Ceiling on the number of CAS objects the walk opens below the
/// manifest being served — i.e. on the number of child manifests it
/// expands.
///
/// The depth cap bounds the *shape* of the tree, not its size: the
/// domain admits 1024 children per index, so four levels of nesting is
/// 1024⁴ nodes and a single client pull could spend the registry's
/// read budget on a pathological upstream's routing documents. 1024 is
/// chosen so that **one** level is always fully resolvable — a legal
/// single-level index, which is what every real multi-arch image is,
/// never meets this bound — while a nested tree that exceeds it is
/// refused rather than walked. Exceeding it fails the resolution
/// **closed**: hort cannot enumerate what the document binds, and ADR
/// 0007 says what to answer then.
const MAX_CLOSURE_EXPANSIONS: usize = 1024;

/// What a manifest read learned about its constituents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestDeliverability {
    /// Nothing in the closure carries a terminal status. Says nothing
    /// about the manifest's **own** status — that gate is the caller's
    /// and runs first.
    Deliverable,
    /// One constituent's lifecycle has concluded against delivery, so the
    /// manifest is not served. Carries the constituent the refusal names:
    /// the digest is the signal that identified the cause in the incident
    /// behind this rule — identical across repeated pulls of one
    /// manifest, different across manifests, which is how a shared base
    /// layer was ruled out.
    TerminalConstituent(TerminalConstituent),
}

/// Resolves [`ManifestDeliverability`] for an OCI manifest.
pub struct ManifestDeliverabilityUseCase {
    storage: Arc<dyn StoragePort>,
    constituents: Arc<dyn ConstituentStatusReader>,
}

/// One node of the walk: bytes already read, and how far below the
/// manifest being served they sit.
struct ClosureNode {
    hash: ContentHash,
    bytes: Vec<u8>,
    depth: u32,
}

/// What one node's bytes bind — kept apart by kind because only an
/// index's children are themselves documents to expand.
enum NodeConstituents {
    /// `manifests[*].digest` of an image index / Docker manifest list.
    IndexChildren(Vec<ContentHash>),
    /// `config` + `layers[*].digest` of a single-image manifest, config
    /// first. Leaves: a blob binds nothing.
    Blobs(Vec<ContentHash>),
}

impl ManifestDeliverabilityUseCase {
    #[must_use]
    pub fn new(
        storage: Arc<dyn StoragePort>,
        constituents: Arc<dyn ConstituentStatusReader>,
    ) -> Self {
        Self {
            storage,
            constituents,
        }
    }

    /// Resolve whether the manifest at `manifest_hash` in
    /// `repository_id` may be served.
    ///
    /// `Err` is the fail-closed answer: the caller serves nothing. See
    /// the module doc for which failures land here and which are
    /// absorbed.
    pub async fn resolve(
        &self,
        repository_id: Uuid,
        manifest_hash: &ContentHash,
    ) -> AppResult<ManifestDeliverability> {
        let closure = self.closure(repository_id, manifest_hash).await?;
        // A document that binds nothing — an artifact manifest with no
        // config and no layers — has nothing to withhold it.
        if closure.is_empty() {
            return Ok(ManifestDeliverability::Deliverable);
        }
        let terminal = self
            .constituents
            .strongest_terminal_constituent(repository_id, &closure)
            .await?;
        match terminal {
            Some(constituent) => {
                // The mandatory server-side line, and the reason it is
                // emitted here rather than at the call site: this is the
                // one place the decision is made, so a second caller
                // cannot serve a refusal without it. The hidden-404 cost
                // ADR 0062 accepts is paid by the client; an operator
                // must still be able to tell a withheld manifest from a
                // broken registry, and that needs all three facts —
                // which manifest, which constituent, and the verdict on
                // it.
                tracing::warn!(
                    %repository_id,
                    manifest = %manifest_hash,
                    constituent = %constituent.content_hash,
                    constituent_status = %constituent.status,
                    closure_size = closure.len(),
                    "manifest withheld: a constituent carries a terminal status, so the \
                     manifest is not deliverable (ADR 0062)"
                );
                Ok(ManifestDeliverability::TerminalConstituent(constituent))
            }
            None => Ok(ManifestDeliverability::Deliverable),
        }
    }

    /// Every content hash the manifest binds, transitively, in closure
    /// order — config before layers, a parent before its children —
    /// deduplicated, and excluding the manifest's own hash.
    ///
    /// The order is load-bearing twice: it decides which constituent a
    /// refusal names when several share the strongest verdict, and it
    /// makes that choice identical for `HEAD` and `GET`.
    async fn closure(
        &self,
        repository_id: Uuid,
        manifest_hash: &ContentHash,
    ) -> AppResult<Vec<ContentHash>> {
        let root_bytes = read_cas_bounded(&*self.storage, manifest_hash, CLOSURE_READ_CAP_BYTES)
            .await
            .map_err(|e| {
                tracing::error!(
                    %repository_id,
                    manifest = %manifest_hash,
                    error = %e,
                    "manifest deliverability: the manifest's own CAS bytes could not be \
                     read, so its constituents are unknown; refusing to serve it"
                );
                e
            })?;

        let mut closure: Vec<ContentHash> = Vec::new();
        // The manifest's own hash is seeded as seen: its status was
        // already decided by the caller's own gate, and a
        // (pathological) self-reference must not re-ask about it.
        let mut seen: HashSet<ContentHash> = HashSet::from([manifest_hash.clone()]);
        let mut frontier: VecDeque<ClosureNode> = VecDeque::from([ClosureNode {
            hash: manifest_hash.clone(),
            bytes: root_bytes,
            depth: 0,
        }]);
        let mut expansions = 0usize;

        while let Some(node) = frontier.pop_front() {
            let constituents = match node_constituents(&node.bytes) {
                Ok(c) => c,
                // The manifest being served: its shape is the thing the
                // answer depends on, so an unparseable or over-cap body
                // fails closed.
                Err(e) if node.depth == 0 => {
                    tracing::error!(
                        %repository_id,
                        manifest = %node.hash,
                        error = %e,
                        "manifest deliverability: the manifest's own bytes did not parse as \
                         an OCI manifest or index, so its constituents are unknown; \
                         refusing to serve it"
                    );
                    return Err(AppError::Domain(e));
                }
                // A child: it is in the closure on its own account and
                // the catalog still judges it. Only its descendants go
                // unasked.
                Err(e) => {
                    tracing::warn!(
                        %repository_id,
                        manifest = %manifest_hash,
                        child = %node.hash,
                        error = %e,
                        "manifest deliverability: a child manifest's bytes did not parse, so \
                         its own constituents are not consulted; the child itself is still \
                         judged"
                    );
                    continue;
                }
            };

            match constituents {
                NodeConstituents::Blobs(blobs) => {
                    for blob in blobs {
                        if seen.insert(blob.clone()) {
                            closure.push(blob);
                        }
                    }
                }
                NodeConstituents::IndexChildren(children) => {
                    for child in children {
                        if !seen.insert(child.clone()) {
                            continue;
                        }
                        closure.push(child.clone());
                        let child_depth = node.depth.saturating_add(1);
                        if child_depth > MAX_CHILD_INGEST_DEPTH {
                            // The child is still judged; its own
                            // constituents are not reachable within the
                            // bound the ingest side also stops at.
                            tracing::warn!(
                                %repository_id,
                                manifest = %manifest_hash,
                                child = %child,
                                depth = child_depth,
                                max_depth = MAX_CHILD_INGEST_DEPTH,
                                "manifest deliverability: nested index at the recursion depth \
                                 cap; the child is judged but its own constituents are not \
                                 consulted"
                            );
                            continue;
                        }
                        if expansions >= MAX_CLOSURE_EXPANSIONS {
                            tracing::error!(
                                %repository_id,
                                manifest = %manifest_hash,
                                expansions,
                                max_expansions = MAX_CLOSURE_EXPANSIONS,
                                "manifest deliverability: closure walk exceeded its expansion \
                                 budget, so the full constituent set is unknown; refusing to \
                                 serve the manifest"
                            );
                            return Err(AppError::Domain(DomainError::Validation(format!(
                                "manifest {manifest_hash} closure exceeds the \
                                 {MAX_CLOSURE_EXPANSIONS}-document expansion budget"
                            ))));
                        }
                        expansions += 1;
                        match read_cas_bounded(&*self.storage, &child, CLOSURE_READ_CAP_BYTES).await
                        {
                            Ok(bytes) => frontier.push_back(ClosureNode {
                                hash: child,
                                bytes,
                                depth: child_depth,
                            }),
                            // Not local yet — the ordinary state of a
                            // cold pull-through index. The catalog has
                            // nothing to say about it either, so this is
                            // the absence arm and not a degradation.
                            Err(AppError::Domain(DomainError::NotFound { .. })) => {
                                tracing::debug!(
                                    %repository_id,
                                    manifest = %manifest_hash,
                                    child = %child,
                                    "manifest deliverability: child manifest is not in CAS \
                                     yet; its own constituents are not consulted"
                                );
                            }
                            Err(e) => tracing::warn!(
                                %repository_id,
                                manifest = %manifest_hash,
                                child = %child,
                                error = %e,
                                "manifest deliverability: a child manifest's CAS bytes could \
                                 not be read, so its own constituents are not consulted; the \
                                 child itself is still judged"
                            ),
                        }
                    }
                }
            }
        }
        Ok(closure)
    }
}

/// Classify one document's bytes and read what it binds.
///
/// The index/manifest dispatch is `hort_domain::oci::is_image_index` —
/// structural (a non-empty `manifests[]`), the same probe the write path
/// and the provenance cascade use, so a document's closure does not
/// depend on which of three places asked.
///
/// An index child whose descriptor names **no addressable content** — no
/// `digest`, an algorithm outside the CAS keyspace, malformed hex — is left
/// out of the closure and reported, rather than failing the read. The
/// consequence of failing it is what decides this: `closure` treats an `Err`
/// at depth 0 as fail-closed and refuses to serve the document, so a hard
/// error here would make every index already in the catalog that carries one
/// such descriptor **unservable** — withdrawing every platform it can still
/// deliver, over one it never could.
///
/// Leaving it out does not make hort advertise something it will not serve,
/// which is the rule this module exists to hold (ADR 0062). A closure entry
/// is a question put to the catalog about a CAS hash, and this descriptor
/// yields no hash to ask about: there is no artifact row, no bytes, and the
/// client that tries to fetch it is answered by the digest parse at the
/// request line before any lookup happens — a clean `UNSUPPORTED` /
/// `DIGEST_INVALID` keyed to the digest it already holds, not a `200`
/// followed by a `404`. The contradiction ADR 0062 closes is the second
/// shape, not the first. The index bytes are also immutable and
/// content-addressed, so refusal of the whole document is the only other
/// lever available here, and it is the wrong one.
fn node_constituents(bytes: &[u8]) -> Result<NodeConstituents, DomainError> {
    if hort_domain::oci::is_image_index(bytes) {
        let declared = hort_domain::oci::index_child_descriptors(bytes)?;
        let children = declared.into_resolvable(|fault| {
            tracing::warn!(
                child = %fault,
                "manifest deliverability: an index child declares no addressable content, \
                 so it is not in the closure; it was never servable from this registry"
            );
        });
        Ok(NodeConstituents::IndexChildren(
            children.into_iter().map(|c| c.hash).collect(),
        ))
    } else {
        Ok(NodeConstituents::Blobs(
            hort_domain::oci::manifest_blob_digests(bytes)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::ports::BoxFuture;
    use serde_json::json;

    use crate::use_cases::test_support::{
        sample_artifact, MockArtifactRepository, MockConstituentStatusReader, MockStoragePort,
    };

    fn hash_of(seed: &str) -> ContentHash {
        let mut hex = String::new();
        for byte in seed.bytes() {
            hex.push_str(&format!("{byte:02x}"));
        }
        while hex.len() < 64 {
            hex.push('0');
        }
        hex.truncate(64);
        hex.parse().expect("synthetic sha256")
    }

    fn digest(hash: &ContentHash) -> String {
        format!("sha256:{hash}")
    }

    fn image_manifest(config: &ContentHash, layers: &[&ContentHash]) -> Vec<u8> {
        json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "digest": digest(config), "size": 1 },
            "layers": layers
                .iter()
                .map(|l| json!({ "digest": digest(l), "size": 1 }))
                .collect::<Vec<_>>(),
        })
        .to_string()
        .into_bytes()
    }

    fn image_index(children: &[&ContentHash]) -> Vec<u8> {
        json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": children
                .iter()
                .map(|c| json!({ "digest": digest(c), "size": 1 }))
                .collect::<Vec<_>>(),
        })
        .to_string()
        .into_bytes()
    }

    struct Fixture {
        repo: Uuid,
        storage: Arc<MockStoragePort>,
        artifacts: Arc<MockArtifactRepository>,
        use_case: ManifestDeliverabilityUseCase,
    }

    fn fixture() -> Fixture {
        let storage = Arc::new(MockStoragePort::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let constituents = Arc::new(MockConstituentStatusReader::new(artifacts.clone()));
        Fixture {
            repo: Uuid::new_v4(),
            storage: storage.clone(),
            artifacts,
            use_case: ManifestDeliverabilityUseCase::new(storage, constituents),
        }
    }

    impl Fixture {
        /// Put `bytes` in CAS at their declared hash.
        fn store(&self, hash: &ContentHash, bytes: Vec<u8>) {
            self.storage.insert_content(hash.clone(), bytes);
        }

        /// Give `hash` a catalog row in this repository carrying `status`.
        fn catalog(&self, hash: &ContentHash, status: QuarantineStatus) {
            let mut artifact: Artifact = sample_artifact(status);
            artifact.repository_id = self.repo;
            artifact.sha256_checksum = hash.clone();
            self.artifacts.insert(artifact);
        }

        async fn resolve(&self, manifest: &ContentHash) -> AppResult<ManifestDeliverability> {
            self.use_case.resolve(self.repo, manifest).await
        }
    }

    // -- the deliverable arms ---------------------------------------------

    /// The arm that must never break: a pull-through manifest whose
    /// constituents are not ingested still resolves deliverable. Treating
    /// absence as a hold inverts every cold pull-through in the registry.
    #[tokio::test]
    async fn constituents_that_are_not_ingested_leave_the_manifest_deliverable() {
        let f = fixture();
        let (manifest, config, layer) = (hash_of("m"), hash_of("c"), hash_of("l"));
        f.store(&manifest, image_manifest(&config, &[&layer]));
        // No catalog rows and no CAS content for either constituent.
        assert_eq!(
            f.resolve(&manifest).await.expect("resolution succeeds"),
            ManifestDeliverability::Deliverable
        );
    }

    /// A held constituent is "not yet", not "never": the client's own
    /// blob fetch answers it with the deadline, and propagating it here
    /// would change the answer for every fresh push.
    #[tokio::test]
    async fn a_quarantined_constituent_leaves_the_manifest_deliverable() {
        let f = fixture();
        let (manifest, config, layer) = (hash_of("m"), hash_of("c"), hash_of("l"));
        f.store(&manifest, image_manifest(&config, &[&layer]));
        f.catalog(&config, QuarantineStatus::Released);
        f.catalog(&layer, QuarantineStatus::Quarantined);
        assert_eq!(
            f.resolve(&manifest).await.expect("resolution succeeds"),
            ManifestDeliverability::Deliverable
        );
    }

    #[tokio::test]
    async fn a_manifest_that_binds_nothing_is_deliverable_without_asking_the_catalog() {
        let f = fixture();
        let manifest = hash_of("m");
        f.store(
            &manifest,
            json!({ "schemaVersion": 2, "layers": [] })
                .to_string()
                .into_bytes(),
        );
        assert_eq!(
            f.resolve(&manifest).await.expect("resolution succeeds"),
            ManifestDeliverability::Deliverable
        );
    }

    // -- the terminal arms -------------------------------------------------

    /// Both roles, driven off the predicate rather than a hand-written
    /// pair, and both terminal statuses. The config case is the shape the
    /// production population has: one rejected `{}` config row shared by
    /// a repository's whole signature inventory.
    #[tokio::test]
    async fn a_terminal_config_or_layer_withholds_the_manifest() {
        for status in QuarantineStatus::ALL
            .into_iter()
            .filter(|status| status.is_terminal())
        {
            for terminal_role in ["config", "layer"] {
                let f = fixture();
                let (manifest, config, layer) = (hash_of("m"), hash_of("c"), hash_of("l"));
                f.store(&manifest, image_manifest(&config, &[&layer]));
                let (offender, innocent) = match terminal_role {
                    "config" => (&config, &layer),
                    _ => (&layer, &config),
                };
                f.catalog(offender, status);
                f.catalog(innocent, QuarantineStatus::Released);
                assert_eq!(
                    f.resolve(&manifest).await.expect("resolution succeeds"),
                    ManifestDeliverability::TerminalConstituent(TerminalConstituent {
                        content_hash: offender.clone(),
                        status,
                    }),
                    "a {status} {terminal_role} must withhold the manifest"
                );
            }
        }
    }

    /// Transitivity, which is the whole of determination 1: an index over
    /// a child whose *layer* is terminal must not answer deliverable and
    /// then fail at the child.
    #[tokio::test]
    async fn an_index_is_withheld_for_a_terminal_layer_of_one_of_its_children() {
        let f = fixture();
        let (index, child, config, layer) =
            (hash_of("i"), hash_of("ch"), hash_of("c"), hash_of("l"));
        f.store(&index, image_index(&[&child]));
        f.store(&child, image_manifest(&config, &[&layer]));
        f.catalog(&child, QuarantineStatus::Released);
        f.catalog(&config, QuarantineStatus::Released);
        f.catalog(&layer, QuarantineStatus::Rejected);
        assert_eq!(
            f.resolve(&index).await.expect("resolution succeeds"),
            ManifestDeliverability::TerminalConstituent(TerminalConstituent {
                content_hash: layer,
                status: QuarantineStatus::Rejected,
            })
        );
    }

    /// A cold index: children declared, none in CAS and none in the
    /// catalog. The walk attempts their bytes, gets absence, and the
    /// answer stays deliverable.
    #[tokio::test]
    async fn an_index_whose_children_are_not_ingested_is_deliverable() {
        let f = fixture();
        let (index, first, second) = (hash_of("i"), hash_of("c1"), hash_of("c2"));
        f.store(&index, image_index(&[&first, &second]));
        assert_eq!(
            f.resolve(&index).await.expect("resolution succeeds"),
            ManifestDeliverability::Deliverable
        );
    }

    // The mandatory refusal line is asserted where it can be captured
    // without fighting for the process-wide subscriber slot: this crate's
    // own suites install a global default of their own, so a
    // thread-local capture harness installed here races them. The
    // assertions live in the OCI manifest handler's suite, over
    // `crate::test_tracing::capture_tracing`, filtered to this module's
    // target — which additionally proves the line is emitted by the
    // resolution rather than re-typed at the call site.

    // -- the closure's shape ----------------------------------------------

    /// Closure order decides which constituent a refusal names when
    /// several share the strongest verdict: config first, then layers in
    /// manifest order. `HEAD` and `GET` run this same walk, so the
    /// ordering is what makes them agree.
    #[tokio::test]
    async fn the_config_precedes_the_layers_in_closure_order() {
        let f = fixture();
        let (manifest, config, layer) = (hash_of("m"), hash_of("c"), hash_of("l"));
        f.store(&manifest, image_manifest(&config, &[&layer]));
        assert_eq!(
            f.use_case
                .closure(f.repo, &manifest)
                .await
                .expect("the closure resolves"),
            vec![config, layer]
        );
    }

    /// A blob shared by two children appears once: the catalog is asked
    /// about a set, not a multiset.
    #[tokio::test]
    async fn a_shared_blob_appears_once_in_the_closure() {
        let f = fixture();
        let (index, first, second, config, shared) = (
            hash_of("i"),
            hash_of("c1"),
            hash_of("c2"),
            hash_of("cfg"),
            hash_of("shared"),
        );
        f.store(&index, image_index(&[&first, &second]));
        f.store(&first, image_manifest(&config, &[&shared]));
        f.store(&second, image_manifest(&config, &[&shared]));
        let closure = f
            .use_case
            .closure(f.repo, &index)
            .await
            .expect("the closure resolves");
        assert_eq!(
            closure,
            vec![first, second, config, shared],
            "children first (parent before child), then each child's blobs, deduplicated"
        );
    }

    /// A manifest that references its own digest does not re-ask about
    /// itself: its status was already decided by the caller's own gate.
    #[tokio::test]
    async fn a_self_referencing_manifest_does_not_appear_in_its_own_closure() {
        let f = fixture();
        let manifest = hash_of("m");
        f.store(&manifest, image_manifest(&manifest, &[&manifest]));
        assert!(f
            .use_case
            .closure(f.repo, &manifest)
            .await
            .expect("the closure resolves")
            .is_empty());
    }

    /// At the depth cap the child is still listed — the catalog judges
    /// it — and only its own constituents go unasked. The bound is the
    /// ingest side's, so the walk never asks about a document this
    /// registry declines to fetch.
    #[tokio::test]
    async fn the_walk_stops_at_the_ingest_depth_cap_but_still_lists_the_child() {
        let f = fixture();
        // A chain of nested indexes one level deeper than the cap, each
        // ending in a manifest whose layer is rejected.
        let levels: Vec<ContentHash> = (0..=MAX_CHILD_INGEST_DEPTH + 1)
            .map(|d| hash_of(&format!("idx{d}")))
            .collect();
        let deep_layer = hash_of("deep-layer");
        for window in levels.windows(2) {
            f.store(&window[0], image_index(&[&window[1]]));
        }
        let deepest = levels.last().expect("the chain is not empty");
        f.store(deepest, image_manifest(&deep_layer, &[]));
        f.catalog(&deep_layer, QuarantineStatus::Rejected);

        let closure = f
            .use_case
            .closure(f.repo, &levels[0])
            .await
            .expect("the closure resolves");
        assert!(
            closure.contains(deepest),
            "the child at the cap is still judged: {closure:?}"
        );
        assert!(
            !closure.contains(&deep_layer),
            "a document past the cap is not expanded, so its blobs are not in the closure: \
             {closure:?}"
        );
        assert_eq!(
            f.resolve(&levels[0]).await.expect("resolution succeeds"),
            ManifestDeliverability::Deliverable,
            "nothing inside the bound is terminal"
        );
    }

    // -- what fails closed -------------------------------------------------

    #[tokio::test]
    async fn an_unreadable_manifest_fails_closed() {
        let f = fixture();
        // No CAS content for the manifest at all.
        let err = f
            .resolve(&hash_of("m"))
            .await
            .expect_err("a manifest whose own bytes are unreadable cannot be judged");
        assert!(
            matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "content",
                    ..
                })
            ),
            "expected the storage NotFound to surface, got {err:?}"
        );
    }

    #[tokio::test]
    async fn an_unparseable_manifest_fails_closed() {
        let f = fixture();
        let manifest = hash_of("m");
        f.store(&manifest, b"not json at all".to_vec());
        let err = f
            .resolve(&manifest)
            .await
            .expect_err("a manifest whose shape is unknown cannot be judged");
        assert!(
            matches!(err, AppError::Domain(DomainError::Validation(_))),
            "expected a Validation refusal, got {err:?}"
        );
    }

    /// A child's bytes failing is the bounded case: the child is still
    /// judged — here it is rejected and the manifest is withheld on its
    /// account — and only its descendants go unasked.
    #[tokio::test]
    async fn an_unparseable_child_still_leaves_the_child_itself_judged() {
        let f = fixture();
        let (index, child) = (hash_of("i"), hash_of("ch"));
        f.store(&index, image_index(&[&child]));
        f.store(&child, b"not json at all".to_vec());
        f.catalog(&child, QuarantineStatus::Rejected);
        assert_eq!(
            f.resolve(&index).await.expect("resolution succeeds"),
            ManifestDeliverability::TerminalConstituent(TerminalConstituent {
                content_hash: child,
                status: QuarantineStatus::Rejected,
            })
        );
    }

    /// A **stored** index declaring a child this registry cannot address is
    /// still servable, and its other children are still judged.
    ///
    /// This is the population the admission fix is about: indexes admitted
    /// before an unaddressable child descriptor was refused. `closure` treats
    /// an `Err` at depth 0 as fail-closed, so making such a descriptor an
    /// error here would make every one of those rows unservable — withdrawing
    /// every platform the index can still deliver, over one it never could.
    ///
    /// Leaving the descriptor out of the closure is not hort advertising
    /// something it will not serve: a closure entry is a question about a CAS
    /// hash, this descriptor yields none, and the client's own fetch for it is
    /// refused by the digest parse at the request line before any lookup.
    #[tokio::test]
    async fn a_stored_index_with_an_unaddressable_child_is_still_resolvable() {
        let f = fixture();
        let (index, child) = (hash_of("i"), hash_of("ch"));
        f.store(
            &index,
            json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    { "digest": format!("sha512:{}", "a".repeat(128)), "size": 1 },
                    { "digest": digest(&child), "size": 1 },
                    { "size": 1 },
                    { "digest": "sha256:not-hex", "size": 1 },
                ],
            })
            .to_string()
            .into_bytes(),
        );
        f.catalog(&child, QuarantineStatus::Released);
        assert_eq!(
            f.resolve(&index).await.expect(
                "an unaddressable child descriptor must not make a stored index unservable"
            ),
            ManifestDeliverability::Deliverable
        );
    }

    /// And the addressable sibling is genuinely still in the closure — so the
    /// test above is not green merely because the walk stopped looking.
    #[tokio::test]
    async fn an_unaddressable_child_does_not_hide_a_terminal_sibling() {
        let f = fixture();
        let (index, child) = (hash_of("i"), hash_of("ch"));
        f.store(
            &index,
            json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    { "size": 1 },
                    { "digest": digest(&child), "size": 1 },
                ],
            })
            .to_string()
            .into_bytes(),
        );
        f.catalog(&child, QuarantineStatus::Rejected);
        assert_eq!(
            f.resolve(&index).await.expect("resolution succeeds"),
            ManifestDeliverability::TerminalConstituent(TerminalConstituent {
                content_hash: child,
                status: QuarantineStatus::Rejected,
            }),
            "the sibling of a skipped descriptor is still judged"
        );
    }

    /// A child whose CAS read fails for a reason other than absence is a
    /// degradation, not an absence: the child is judged, the walk
    /// continues, and the answer is not inverted into a refusal that
    /// would catch every cold index.
    #[tokio::test]
    async fn a_child_whose_backend_errors_does_not_fail_the_resolution() {
        let f = fixture();
        let (index, child) = (hash_of("i"), hash_of("ch"));
        f.store(&index, image_index(&[&child]));
        f.store(&child, image_manifest(&hash_of("c"), &[]));
        f.storage.fail_get_persistent(child.clone());
        assert_eq!(
            f.resolve(&index).await.expect("resolution succeeds"),
            ManifestDeliverability::Deliverable
        );
    }

    /// Budget exhaustion fails closed: hort cannot enumerate what the
    /// document binds.
    #[tokio::test]
    async fn a_closure_past_its_expansion_budget_fails_closed() {
        let f = fixture();
        let root = hash_of("i");
        let children: Vec<ContentHash> = (0..=MAX_CLOSURE_EXPANSIONS)
            .map(|n| hash_of(&format!("c{n}")))
            .collect();
        f.store(
            &root,
            image_index(children.iter().collect::<Vec<_>>().as_slice()),
        );
        // Every child is an index of its own so the walk keeps wanting
        // to expand; their bytes exist so no absence short-circuits it.
        for child in &children {
            f.store(child, image_index(&[&hash_of("leaf")]));
        }
        let err = f
            .resolve(&root)
            .await
            .expect_err("a closure past its budget cannot be enumerated");
        assert!(
            matches!(err, AppError::Domain(DomainError::Validation(_))),
            "expected a Validation refusal, got {err:?}"
        );
    }

    /// A catalog failure is not an absence either: the question could not
    /// be answered, so the manifest is not served.
    #[tokio::test]
    async fn a_catalog_failure_fails_closed() {
        let storage = Arc::new(MockStoragePort::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let constituents = Arc::new(MockConstituentStatusReader::new(artifacts));
        constituents.fail_next(DomainError::Invariant("catalog down".into()));
        let use_case = ManifestDeliverabilityUseCase::new(storage.clone(), constituents);
        let (manifest, config) = (hash_of("m"), hash_of("c"));
        storage.insert_content(manifest.clone(), image_manifest(&config, &[]));
        assert!(
            use_case.resolve(Uuid::new_v4(), &manifest).await.is_err(),
            "an unanswerable question must not resolve deliverable"
        );
    }

    /// The reader is asked **once** per resolution, whatever the closure
    /// size — the criterion the whole shape was chosen for.
    #[tokio::test]
    async fn the_catalog_is_asked_exactly_once_per_resolution() {
        let storage = Arc::new(MockStoragePort::new());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let constituents = Arc::new(MockConstituentStatusReader::new(artifacts.clone()));
        let use_case = ManifestDeliverabilityUseCase::new(storage.clone(), constituents.clone());
        let repo = Uuid::new_v4();
        let (index, child, config) = (hash_of("i"), hash_of("ch"), hash_of("c"));
        storage.insert_content(index.clone(), image_index(&[&child]));
        storage.insert_content(child.clone(), image_manifest(&config, &[]));
        let _ = use_case
            .resolve(repo, &index)
            .await
            .expect("resolution succeeds");
        assert_eq!(
            constituents.calls(),
            1,
            "a per-constituent lookup would put one round trip on every layer of every pull"
        );
    }

    /// The measured CAS cost of resolving from the bytes, pinned per
    /// shape because it is the price determination 2 of this unit's
    /// contract knowingly accepts and the thing a later change would
    /// quietly inflate.
    ///
    /// An **image manifest** — the whole production population this rule
    /// is about, signature manifests included — costs exactly **one**
    /// read: its own bytes, which carry every digest it binds. An
    /// **index** costs `1 + children`, because a child's own
    /// constituents live in that child's bytes and nowhere else; a cold
    /// index pays the same count in absent reads. There is no read per
    /// *blob*: a blob binds nothing, so its bytes are never opened.
    #[tokio::test]
    async fn the_cas_read_count_is_one_per_document_and_never_one_per_blob() {
        // Image manifest with a config and three layers: one read.
        let f = fixture();
        let (manifest, config) = (hash_of("m"), hash_of("c"));
        let layers: Vec<ContentHash> = (0..3).map(|n| hash_of(&format!("l{n}"))).collect();
        f.store(
            &manifest,
            image_manifest(&config, &layers.iter().collect::<Vec<_>>()),
        );
        for blob in std::iter::once(&config).chain(layers.iter()) {
            f.catalog(blob, QuarantineStatus::Released);
        }
        let _ = f.resolve(&manifest).await.expect("resolution succeeds");
        assert_eq!(
            f.storage.get_call_count(),
            1,
            "an image manifest's closure is in its own bytes: one read, whatever the \
             layer count"
        );

        // Index over two children: the index plus one read per child.
        let g = fixture();
        let (index, first, second) = (hash_of("i"), hash_of("c1"), hash_of("c2"));
        g.store(&index, image_index(&[&first, &second]));
        g.store(&first, image_manifest(&config, &[]));
        g.store(&second, image_manifest(&config, &[]));
        let _ = g.resolve(&index).await.expect("resolution succeeds");
        assert_eq!(
            g.storage.get_call_count(),
            3,
            "an index reads its own bytes plus one object per child"
        );

        // A cold index pays the same count — the reads simply miss.
        let h = fixture();
        h.store(&index, image_index(&[&first, &second]));
        let _ = h.resolve(&index).await.expect("resolution succeeds");
        assert_eq!(
            h.storage.get_call_count(),
            3,
            "a cold index attempts the same reads and gets absence"
        );
    }

    /// The port contract's own fail-closed shape: a reader that reports
    /// nothing terminal is not the same as one that errors. Pinned with a
    /// local double so the behaviour does not rest on the harness mock.
    #[tokio::test]
    async fn a_reader_that_reports_nothing_leaves_the_manifest_deliverable() {
        struct Silent;
        impl ConstituentStatusReader for Silent {
            fn strongest_terminal_constituent<'a>(
                &'a self,
                _repository_id: Uuid,
                _constituents: &'a [ContentHash],
            ) -> BoxFuture<'a, Result<Option<TerminalConstituent>, DomainError>> {
                Box::pin(async { Ok(None) })
            }
        }
        let storage = Arc::new(MockStoragePort::new());
        let (manifest, config) = (hash_of("m"), hash_of("c"));
        storage.insert_content(manifest.clone(), image_manifest(&config, &[]));
        let use_case = ManifestDeliverabilityUseCase::new(storage, Arc::new(Silent));
        assert_eq!(
            use_case
                .resolve(Uuid::new_v4(), &manifest)
                .await
                .expect("resolution succeeds"),
            ManifestDeliverability::Deliverable
        );
    }
}
