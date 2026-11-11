//! Shared "do any of hort's own manifests make this blob a layer of a
//! composed image?" resolver — the single definition of that lookup in
//! the application layer.
//!
//! [`LayerRole`] is what decides whether a stored blob may be presented
//! to a scanner **as a root filesystem**. ADR 0064 D6 is the reason the
//! question has to be asked at all: a package-vulnerability finding is a
//! statement about an installed package tree that runs, and
//!
//! > *"hort assesses it today only because every tar-shaped blob is
//! > materialised as a root filesystem — correct for an image layer, a
//! > coincidence for anything else."*
//!
//! So the materialisation has to follow a **declared role** rather than a
//! container shape. The role is not on the blob's row and no format
//! handler can supply it: every OCI blob is stored at one path prefix
//! with one `content_type`, and the role lives in the *manifest's*
//! descriptor ([`FormatHandler::scan_kind`] says so at its own site). The
//! manifests are what hort has, so the manifests are what it asks.
//!
//! # Why the question is asked here and not at ingest
//!
//! Two facts shape the answer, and the resolver's three outcomes are
//! exactly their product:
//!
//! 1. **The role becomes known when a manifest naming the blob commits.**
//!    On a hosted push that is *after* the blob — the distribution spec's
//!    push order is blobs first, manifest last — and the blob's own scan
//!    is enqueued with its ingest. On a pull-through the manifest lands
//!    first and the blob's row is minted by a client's later fetch, so
//!    the role is already known at its first scan. Either way the one
//!    durable record of the role is the manifest's `oci_layer`
//!    membership edge, written **inside the manifest's own mint
//!    transaction** (see
//!    [`ContentReferenceIndex`]'s write-path docs) — so "the manifest
//!    exists" and "its layer claims exist" are one event, and there is
//!    nothing to schedule and nothing to wait for.
//! 2. **An absent parent is not evidence.** ADR 0064 D6 rejects a
//!    per-constituent walk used as a *condition* precisely because "on a
//!    push the layer blobs are ingested, and their scans enqueued, before
//!    the manifest exists; the walk would find no parent for the whole
//!    push population". That hazard is real and it is why
//!    [`LayerRole::Unknown`] — no manifest names the blob, or one does
//!    and could not be resolved — leaves the materialisation exactly as
//!    it was. Withholding it there would take ADR 0064 D2's layer
//!    evidence scan away from every layer of every pushed image,
//!    non-deterministically by job ordering.
//!
//! Only [`LayerRole::NotAnImageLayer`] changes anything, and it is
//! reached only from a **complete, resolved negative**: at least one
//! manifest names these bytes as a layer, every manifest that does was
//! resolved, and not one of them is an image naming them as a layer.
//!
//! # What "is an image" is read off
//!
//! The same two-stage strict parse the composite scan resolves a
//! composition with, and nothing else:
//! [`strict_manifest_nomination`] over the manifest bytes, then
//! [`ManifestNomination::complete_with_config`] over the config bytes.
//! Re-deriving either would put a second answer to "is this an image?"
//! in the tree, and the two could then disagree about one manifest — the
//! blob's materialisation saying "layer of an image" about a manifest the
//! composite path refuses to compose, or the reverse.
//!
//! One arm of the completion is **not** a negative, and that is the
//! stage's own statement rather than a reading of it:
//! [`ConfigRefusal::UnsupportedLayer`] is reached only over a config that
//! has already declared a layered root filesystem with this many layers,
//! *and* over a layer list the manifest stage already cleared of known
//! non-filesystem payloads. An image hort cannot fully compose is still an
//! image, so its openable layers are still image layers and keep their
//! evidence scan; the manifest's own composite verdict is where the
//! incompleteness is answered (ADR 0064 D1).
//!
//! That second condition is what makes the arm safe to read as "still an
//! image", and it did not always hold. A BuildKit attestation manifest's
//! config is image-shaped, so before
//! [`ManifestRefusal::NonFilesystemLayer`] existed its in-toto payload
//! blob reached this arm and was declared an image layer — materialised as
//! a root filesystem, which is exactly the coincidence ADR 0064 D6 took
//! the materialisation off container shape to stop. Now the nomination
//! itself refuses, and a manifest-side refusal is already a resolved
//! negative here, so the payload blob of an attestation, a signature or an
//! SBOM attachment is **not** an image layer and is never presented as a
//! filesystem.
//!
//! [`ManifestRefusal::NonFilesystemLayer`]:
//!     hort_domain::oci::ManifestRefusal::NonFilesystemLayer
//! [`FormatHandler::scan_kind`]:
//!     hort_domain::ports::format_handler::FormatHandler::scan_kind
//! [`ContentReferenceIndex`]:
//!     hort_domain::ports::content_reference_index::ContentReferenceIndex

use std::collections::HashSet;

use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::oci::{strict_manifest_nomination, ConfigRefusal};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::scanner::LayerRole;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{ArtifactKind, ContentHash};

use crate::use_cases::cas_bounded_read::read_cas_bounded;
use crate::use_cases::composite_scan::MAX_COMPOSITION_DOCUMENT_BYTES;

/// The `content_references.kind` the OCI membership-edge writers key a
/// manifest's `layers[]` descriptors on — `ManifestBlobRole::Layer`'s
/// discriminator, written by the manifest-PUT path's `membership_claims`
/// and by the pull-through register-only path.
///
/// Filtering the read on this one kind is right here and would be wrong
/// in [`is_referenced_tree_descendant`](crate::use_cases::referenced_descendant),
/// whose predicate is defined over the *complement* of a kind set and
/// which therefore contracts for an unfiltered read. The question here is
/// about one kind by construction: a blob named only as an `oci_config`,
/// or only as some future tree edge, is not nominated as a layer by
/// anything, and reading those rows in order to discard them would buy
/// nothing.
const OCI_LAYER_EDGE_KIND: &str = "oci_layer";

/// How many nominating manifests one blob's role is resolved against
/// before the resolver gives up and answers [`LayerRole::Unknown`].
///
/// A layer digest may legitimately be shared by every image in a
/// repository — a base layer is the normal case, not a pathology — and
/// the count is bounded by nothing on the write side. The first manifest
/// that *is* an image answers the question, so a shared base layer costs
/// one candidate; the fan-out only grows where no manifest confirms, and
/// there the ceiling bounds the work.
///
/// **Overflow answers `Unknown`, never `NotAnImageLayer`.** That keeps the
/// ceiling monotone: it can only make this resolver less effective, never
/// wrong in the direction that withdraws a materialisation. A bound whose
/// overflow suppressed a scan would be a release-relevant decision taken
/// by a constant.
const MAX_NOMINATING_MANIFESTS: usize = 16;

/// What hort's own manifests declare about `artifact`'s place in a
/// composed image.
///
/// Answers [`LayerRole::Unknown`] without a single read for any row whose
/// kind is not a composition constituent (ADR 0064 D1) — which is every
/// format but OCI, and within OCI every manifest row. The kind is the
/// same one `Finding::may_condemn_artifact` and
/// `NotAnalysable::gates_release` are scoped by, so "whose filesystem
/// belongs to a composition" has one answer across the verdict, the
/// abstention and the materialisation.
///
/// Never fails. Every failure — the edge lookup, the manifest row, either
/// CAS read — degrades to [`LayerRole::Unknown`], because the only
/// outcome that changes behaviour is a resolved negative and a failed read
/// is not one. That direction is the inverse of
/// [`resolve_referenced_tree_descendant_fail_safe`](crate::use_cases::referenced_descendant)'s
/// and for the same underlying rule: each degrades to the answer that
/// does not act.
pub(crate) async fn resolve_layer_role(
    content_references: &dyn ContentReferenceIndex,
    artifacts: &dyn ArtifactRepository,
    storage: &dyn StoragePort,
    artifact: &Artifact,
    kind: ArtifactKind,
) -> LayerRole {
    if !kind.is_composition_constituent() {
        return LayerRole::Unknown;
    }

    let hash = &artifact.sha256_checksum;
    let nominators = match content_references
        .find_by_target(artifact.repository_id, hash, Some(OCI_LAYER_EDGE_KIND))
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                artifact_id = %artifact.id,
                error = %e,
                "layer-role lookup failed; leaving the materialisation as it was",
            );
            return LayerRole::Unknown;
        }
    };

    if nominators.is_empty() {
        // No manifest names these bytes as a layer. That is the ordinary
        // state of a pushed layer whose manifest has not arrived, so it
        // is not evidence of anything.
        return LayerRole::Unknown;
    }

    let mut sources: Vec<Uuid> = Vec::new();
    let mut seen: HashSet<Uuid> = HashSet::new();
    for row in &nominators {
        if seen.insert(row.source_artifact_id) {
            sources.push(row.source_artifact_id);
        }
    }

    let nominating = sources.len();
    if nominating > MAX_NOMINATING_MANIFESTS {
        tracing::warn!(
            artifact_id = %artifact.id,
            nominating_manifests = nominating,
            ceiling = MAX_NOMINATING_MANIFESTS,
            "more manifests name this blob as a layer than the layer-role resolver \
             examines; leaving the materialisation as it was",
        );
        return LayerRole::Unknown;
    }

    // `true` once any candidate could not be resolved — which turns the
    // final answer into `Unknown` rather than a negative, because
    // "nobody declares it a layer" is only true of a set that was read.
    let mut unresolved = false;
    for source in sources {
        match manifest_declares_image_layer(artifacts, storage, source, hash).await {
            Declaration::ImageLayer => return LayerRole::ImageLayer,
            Declaration::NotAnImageLayer => {}
            Declaration::Unresolved => unresolved = true,
        }
    }

    if unresolved {
        LayerRole::Unknown
    } else {
        LayerRole::NotAnImageLayer
    }
}

/// One nominating manifest's answer about one blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Declaration {
    /// This manifest is an image and names the blob among its layers.
    ImageLayer,
    /// This manifest was resolved and is not an image naming the blob as
    /// a layer — its config describes no layered root filesystem, it
    /// disagrees with its own layer count, the strict parse refuses its
    /// descriptors, or it simply does not nominate this blob.
    NotAnImageLayer,
    /// The manifest row or one of the two documents could not be read, so
    /// this manifest states nothing either way.
    Unresolved,
}

/// Resolve what the manifest artifact `source` declares about `hash`.
async fn manifest_declares_image_layer(
    artifacts: &dyn ArtifactRepository,
    storage: &dyn StoragePort,
    source: Uuid,
    hash: &ContentHash,
) -> Declaration {
    let manifest = match artifacts.find_by_id(source).await {
        Ok(manifest) => manifest,
        Err(e) => {
            // A soft-deleted or absent manifest row is not a negative: it
            // is a nomination hort can no longer read. The edge sweep that
            // follows a manifest DELETE removes the row this came from, so
            // this is a narrow race rather than a steady state.
            tracing::debug!(
                manifest_artifact_id = %source,
                error = %e,
                "nominating manifest row is not readable; its declaration is unresolved",
            );
            return Declaration::Unresolved;
        }
    };

    let manifest_bytes = match read_cas_bounded(
        storage,
        &manifest.sha256_checksum,
        MAX_COMPOSITION_DOCUMENT_BYTES,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                manifest_artifact_id = %source,
                error = %e,
                "nominating manifest bytes are not readable; its declaration is unresolved",
            );
            return Declaration::Unresolved;
        }
    };

    // The strict parse, not the lenient `manifest_blob_refs`: a manifest
    // whose descriptors it refuses is one whose layer list hort will not
    // name, and the composite path refuses to compose it for the same
    // reason. That is a resolved negative, not an unread one — including
    // the artifact-manifest refusal, where the nomination's own verdict is
    // that these bytes were never a filesystem, so presenting them as a
    // root filesystem would be a statement about nothing.
    let Ok(nomination) = strict_manifest_nomination(&manifest_bytes) else {
        return Declaration::NotAnImageLayer;
    };

    // Cheap half first: a manifest that does not nominate these bytes at
    // all needs no config read. Reachable when the edge outlived the
    // manifest body it was derived from (a re-push under the same digest
    // cannot change the body, so this is a stale-edge case).
    if !nomination.layers().iter().any(|layer| &layer.hash == hash) {
        return Declaration::NotAnImageLayer;
    }

    let config_hash = nomination.config().clone();
    let config_bytes =
        match read_cas_bounded(storage, &config_hash, MAX_COMPOSITION_DOCUMENT_BYTES).await {
            Ok(bytes) => bytes,
            Err(e) => {
                // The config of a cold pull-through manifest is routinely
                // absent — its edges are registered by digest with no
                // existence check — and without it nothing here can say
                // whether this manifest is an image. Unresolved, so the
                // blob keeps the materialisation it had.
                tracing::debug!(
                    manifest_artifact_id = %source,
                    error = %e,
                    "nominating manifest's config is not readable; its declaration is \
                     unresolved",
                );
                return Declaration::Unresolved;
            }
        };

    match nomination.complete_with_config(&config_bytes) {
        // The config agrees: a layered root filesystem, with this many
        // layers, every container openable. These bytes are one of them.
        Ok(_) => Declaration::ImageLayer,
        // An image hort holds an incomplete composition of is still an
        // image: this arm is reached only over a config that already
        // declared a layered root filesystem, and over a layer list the
        // nomination already cleared of non-filesystem payload formats. So
        // the layers it does declare are image layers, and the manifest's
        // composite verdict is where the incompleteness is answered. An
        // attestation or signature manifest does not reach here — its
        // nomination is refused above, which is a resolved negative.
        Err(ConfigRefusal::UnsupportedLayer { .. }) => Declaration::ImageLayer,
        // Everything else is the config saying this was never an image:
        // no `rootfs`, a `rootfs.type` other than `layers`, a layer count
        // it disagrees with, or bytes that are not an image config at all.
        Err(
            ConfigRefusal::NotParseable(_)
            | ConfigRefusal::RootfsNotLayers
            | ConfigRefusal::DiffIdArity { .. },
        ) => Declaration::NotAnImageLayer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use chrono::Utc;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::error::DomainError;
    use hort_domain::ports::content_reference_index::ContentReference;

    use crate::use_cases::test_support::{
        oci_image_config_bytes, MockArtifactRepository, MockContentReferenceIndex, MockStoragePort,
        OCI_GZIP_LAYER_MEDIA_TYPE,
    };

    const REPO: &str = "11111111-1111-4111-8111-111111111111";

    fn repo_id() -> Uuid {
        REPO.parse().expect("fixture uuid")
    }

    fn real_sha256(bytes: &[u8]) -> ContentHash {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
            .parse()
            .expect("a sha256 hex digest")
    }

    fn hash_of(seed: char) -> ContentHash {
        std::iter::repeat_n(seed, 64)
            .collect::<String>()
            .parse()
            .expect("synthetic sha256")
    }

    /// An artifact row in the fixture repository at `hash`.
    fn row(hash: ContentHash, path: &str) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id(),
            name: "library/nginx".to_string(),
            name_as_published: "library/nginx".to_string(),
            version: Some("1.27".to_string()),
            path: path.to_string(),
            size_bytes: 128,
            sha256_checksum: hash,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".to_string(),
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            provenance_hold_indefinite: false,
            upstream_published_at: None,
            uploaded_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }

    /// An **OCI artifact manifest** — layers declared, and an empty config
    /// that declares no `rootfs`, which is the shape `cosign attach sbom`
    /// and a Helm chart push both produce. The second element is the
    /// config document, which the fixture seeds beside the manifest.
    fn artifact_manifest_documents(layers: &[(&str, &ContentHash)]) -> (Vec<u8>, Vec<u8>) {
        let config_bytes = serde_json::to_vec(&serde_json::json!({})).expect("config serialises");
        let config = real_sha256(&config_bytes);
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/spdx+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": format!("sha256:{config}"),
                "size": config_bytes.len(),
            },
            "layers": layers.iter().map(|(media_type, hash)| serde_json::json!({
                "mediaType": media_type,
                "digest": format!("sha256:{hash}"),
                "size": 64,
            })).collect::<Vec<_>>(),
        }))
        .expect("manifest serialises");
        (manifest_bytes, config_bytes)
    }

    /// An image manifest declaring `layers`, with declared media types.
    fn image_manifest_documents(layers: &[(&str, &ContentHash)]) -> (Vec<u8>, Vec<u8>) {
        let config_bytes = oci_image_config_bytes(layers.len());
        let config = real_sha256(&config_bytes);
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{config}"),
                "size": config_bytes.len(),
            },
            "layers": layers.iter().map(|(media_type, hash)| serde_json::json!({
                "mediaType": media_type,
                "digest": format!("sha256:{hash}"),
                "size": 100,
            })).collect::<Vec<_>>(),
        }))
        .expect("manifest serialises");
        (manifest_bytes, config_bytes)
    }

    /// The three mocks the resolver reads, wired together.
    struct Harness {
        refs: Arc<MockContentReferenceIndex>,
        artifacts: Arc<MockArtifactRepository>,
        storage: Arc<MockStoragePort>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                refs: Arc::new(MockContentReferenceIndex::new()),
                artifacts: Arc::new(MockArtifactRepository::new()),
                storage: Arc::new(MockStoragePort::new()),
            }
        }

        /// Put a manifest's two documents in CAS, mint its artifact row,
        /// and claim `target` as one of its layers — the state the
        /// manifest PUT leaves behind, assembled by hand.
        fn seed_manifest(
            &self,
            manifest_bytes: &[u8],
            config_bytes: &[u8],
            target: &ContentHash,
        ) -> Uuid {
            let manifest_hash = real_sha256(manifest_bytes);
            let manifest_row = row(manifest_hash.clone(), "manifests/sha256:aa");
            let id = manifest_row.id;
            self.artifacts.insert(manifest_row);
            self.storage
                .insert_content(manifest_hash, manifest_bytes.to_vec());
            self.storage
                .insert_content(real_sha256(config_bytes), config_bytes.to_vec());
            self.claim_layer(id, target);
            id
        }

        /// An `oci_layer` edge from `source` to `target`, with no bytes
        /// behind it.
        fn claim_layer(&self, source: Uuid, target: &ContentHash) {
            futures::executor::block_on(self.refs.insert(ContentReference {
                source_artifact_id: source,
                target_content_hash: target.clone(),
                kind: OCI_LAYER_EDGE_KIND.to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id(),
                recorded_at: Utc::now(),
            }))
            .expect("mock insert");
        }

        async fn resolve(&self, blob: &Artifact, kind: ArtifactKind) -> LayerRole {
            resolve_layer_role(&*self.refs, &*self.artifacts, &*self.storage, blob, kind).await
        }
    }

    fn layer_blob() -> Artifact {
        row(hash_of('b'), "blobs/sha256:bbbb")
    }

    /// **Criterion 9's second direction, at the resolver.** A manifest
    /// whose config declares a layered root filesystem makes the blobs it
    /// names image layers, so their isolated evidence scan keeps running
    /// (ADR 0064 D2).
    #[tokio::test]
    async fn an_image_manifests_layer_is_a_declared_image_layer() {
        let blob = layer_blob();
        let h = Harness::new();
        let (manifest, config) =
            image_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        h.seed_manifest(&manifest, &config, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::ImageLayer
        );
    }

    /// **Criterion 9's first direction, at the resolver, on the shape
    /// ADR 0064 D6 names first.** An OCI *artifact* manifest's payload
    /// layer is a gzip tar and is not a root filesystem: its config
    /// declares no `rootfs`, so nothing composes an image from these
    /// bytes and a package finding read out of them would be a statement
    /// about nothing.
    ///
    /// The media type is the ordinary openable layer type on purpose —
    /// the same one a real image layer declares. That is what makes this
    /// the case a shortcut on the layer's own media type would get wrong,
    /// and it is why the config is what decides.
    #[tokio::test]
    async fn an_artifact_manifests_tar_layer_is_declared_not_an_image_layer() {
        let blob = layer_blob();
        let h = Harness::new();
        let (manifest, config) =
            artifact_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        h.seed_manifest(&manifest, &config, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::NotAnImageLayer
        );
    }

    /// **The same direction, on the shape whose config does not say it.** An
    /// attestation manifest's in-toto payload blob is not an image layer
    /// either, and here the *image-shaped* config is the point: this fixture
    /// uses [`image_manifest_documents`], so `rootfs.type` is `layers` and the
    /// `diff_id` arity matches — the identical config a real image gets.
    ///
    /// Before [`ManifestRefusal::NonFilesystemLayer`], that config carried the
    /// nomination all the way to `complete_with_config`, which refused on the
    /// layer's container and was read here as "an image hort cannot finish" —
    /// so the payload blob was declared an image layer and materialised as a
    /// root filesystem. That is the coincidence ADR 0064 D6 took the
    /// materialisation off container shape to stop, arriving through the one
    /// door the config could not close.
    #[tokio::test]
    async fn an_attestation_manifests_payload_layer_is_declared_not_an_image_layer() {
        let blob = layer_blob();
        let h = Harness::new();
        let (manifest, config) = image_manifest_documents(&[(
            hort_domain::oci::IN_TOTO_STATEMENT_MEDIA_TYPE,
            &blob.sha256_checksum,
        )]);
        h.seed_manifest(&manifest, &config, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::NotAnImageLayer,
            "no manifest here composes an image from these bytes, so presenting them as a root \
             filesystem would be a statement about nothing"
        );
    }

    /// An image hort holds an **incomplete** composition of is still an
    /// image, so its openable layers keep their evidence scan.
    ///
    /// `complete_with_config` refuses the composition here — one layer is
    /// `nondistributable`, whose bytes live elsewhere by declaration — but
    /// that refusal is documented as reachable only over a config that
    /// already declared a layered root filesystem. Reading it as "never an
    /// image" would withdraw the evidence scan from every sibling layer of
    /// any image carrying one foreign layer.
    #[tokio::test]
    async fn an_image_with_an_unopenable_layer_still_declares_its_openable_layers() {
        let blob = layer_blob();
        let h = Harness::new();
        let foreign = hash_of('c');
        let (manifest, config) = image_manifest_documents(&[
            (OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                &foreign,
            ),
        ]);
        h.seed_manifest(&manifest, &config, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::ImageLayer
        );
    }

    /// One image among the nominators answers for the blob, whichever
    /// order the edges come back in. A base layer is shared by every
    /// image built on it and by any artifact manifest that happens to
    /// name it; being a layer of *one* image is what makes these bytes a
    /// root filesystem.
    #[tokio::test]
    async fn one_image_among_the_nominators_answers_for_the_blob() {
        let blob = layer_blob();
        let h = Harness::new();
        let (artifact_manifest, artifact_config) =
            artifact_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        h.seed_manifest(&artifact_manifest, &artifact_config, &blob.sha256_checksum);
        let (image_manifest, image_config) =
            image_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        h.seed_manifest(&image_manifest, &image_config, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::ImageLayer
        );
    }

    /// **No manifest names the blob: the role is unknown, not negative.**
    ///
    /// This is the state of every layer of every hosted push at the moment
    /// its own scan runs — blobs first, manifest last — so reading it as
    /// "not a layer" is the regression ADR 0064 D6 rejects a parent walk
    /// for. `Unknown` permits the materialisation, which is what keeps the
    /// layer evidence scan where it was.
    #[tokio::test]
    async fn a_blob_no_manifest_names_has_an_unknown_role() {
        let blob = layer_blob();
        let h = Harness::new();
        let role = h.resolve(&blob, ArtifactKind::OciBlob).await;
        assert_eq!(role, LayerRole::Unknown);
        assert!(
            role.permits_rootfs_materialisation(),
            "an absent manifest must leave the materialisation exactly as it was"
        );
    }

    /// A blob named only as an image **config** is nobody's declared
    /// layer, and the resolver says so without reading a manifest: the
    /// edge read is filtered to `oci_layer`, so an `oci_config` row is not
    /// a nomination. The config's JSON shape is what ends its scan, one
    /// step later and unchanged by this resolver.
    #[tokio::test]
    async fn a_blob_named_only_as_a_config_is_not_a_nomination() {
        let blob = layer_blob();
        let h = Harness::new();
        futures::executor::block_on(h.refs.insert(ContentReference {
            source_artifact_id: Uuid::new_v4(),
            target_content_hash: blob.sha256_checksum.clone(),
            kind: "oci_config".to_string(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            repository_id: repo_id(),
            recorded_at: Utc::now(),
        }))
        .expect("mock insert");
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::Unknown
        );
    }

    /// A manifest row the catalog cannot hand back is a nomination hort
    /// cannot read, so the answer stays `Unknown`. Collapsing it into the
    /// negative would let a lost row withdraw a materialisation.
    #[tokio::test]
    async fn an_unreadable_nominating_manifest_leaves_the_role_unknown() {
        let blob = layer_blob();
        let h = Harness::new();
        h.claim_layer(Uuid::new_v4(), &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::Unknown
        );
    }

    /// A nominating manifest whose own bytes are gone from CAS states
    /// nothing either way — the same direction as an unreadable row, and
    /// for the same reason: only a resolved negative withholds a
    /// materialisation.
    #[tokio::test]
    async fn unreadable_manifest_bytes_leave_the_role_unknown() {
        let blob = layer_blob();
        let h = Harness::new();
        // The manifest row exists and its documents do not — the state a
        // CAS object lost behind a live row leaves.
        let (manifest, _config) =
            artifact_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        let manifest_row = row(real_sha256(&manifest), "manifests/sha256:aa");
        let id = manifest_row.id;
        h.artifacts.insert(manifest_row);
        h.claim_layer(id, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::Unknown,
            "the same fixture answers NotAnImageLayer once its bytes are readable, \
             so this pins the degradation and not the fixture"
        );
    }

    /// The config of a cold pull-through manifest is routinely absent —
    /// its edges are registered by digest with no existence check — and
    /// without it nothing can say whether the manifest is an image.
    #[tokio::test]
    async fn an_absent_config_leaves_the_role_unknown() {
        let blob = layer_blob();
        let h = Harness::new();
        let (manifest, _config) =
            image_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        // Manifest row and manifest bytes, and deliberately no config.
        let manifest_hash = real_sha256(&manifest);
        let manifest_row = row(manifest_hash.clone(), "manifests/sha256:aa");
        let id = manifest_row.id;
        h.artifacts.insert(manifest_row);
        h.storage.insert_content(manifest_hash, manifest);
        h.claim_layer(id, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::Unknown
        );
    }

    /// A failed edge lookup is not evidence either. The membership
    /// projection being unavailable says nothing about these bytes.
    #[tokio::test]
    async fn a_failed_edge_lookup_leaves_the_role_unknown() {
        let blob = layer_blob();
        let h = Harness::new();
        let (manifest, config) =
            artifact_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        h.seed_manifest(&manifest, &config, &blob.sha256_checksum);
        h.refs
            .fail_next_find_by_target(DomainError::Invariant("projection down".into()));
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::Unknown,
            "the same fixture answers NotAnImageLayer when the lookup works, so this \
             pins the degradation and not the fixture"
        );
    }

    /// A manifest whose descriptors the strict parse refuses declares no
    /// image layer hort can name — the same refusal the composite path
    /// takes over the same bytes, so the two cannot disagree about one
    /// manifest.
    #[tokio::test]
    async fn a_manifest_the_strict_parse_refuses_declares_no_image_layer() {
        let blob = layer_blob();
        let h = Harness::new();
        let manifest = b"{not json".to_vec();
        let manifest_hash = real_sha256(&manifest);
        let manifest_row = row(manifest_hash.clone(), "manifests/sha256:aa");
        let id = manifest_row.id;
        h.artifacts.insert(manifest_row);
        h.storage.insert_content(manifest_hash, manifest);
        h.claim_layer(id, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::NotAnImageLayer
        );
    }

    /// An edge that outlived the body it was derived from nominates
    /// nothing: the manifest resolves and simply does not name these
    /// bytes among its layers. Costs no config read.
    #[tokio::test]
    async fn a_manifest_that_does_not_name_the_blob_declares_nothing_about_it() {
        let blob = layer_blob();
        let h = Harness::new();
        let other = hash_of('d');
        let (manifest, config) = image_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &other)]);
        // Seed the manifest's own documents, then claim OUR blob — the
        // stale-edge shape.
        let manifest_hash = real_sha256(&manifest);
        let manifest_row = row(manifest_hash.clone(), "manifests/sha256:aa");
        let id = manifest_row.id;
        h.artifacts.insert(manifest_row);
        h.storage.insert_content(manifest_hash, manifest);
        h.storage
            .insert_content(real_sha256(&config), config.clone());
        h.claim_layer(id, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::NotAnImageLayer
        );
    }

    /// Past the nominator ceiling the answer is `Unknown`, never the
    /// negative — the bound may only make this resolver less effective.
    #[tokio::test]
    async fn past_the_nominator_ceiling_the_role_is_unknown() {
        let blob = layer_blob();
        let h = Harness::new();
        // Every one of these is an artifact manifest, so a resolver that
        // ignored the ceiling would answer `NotAnImageLayer`.
        let (manifest, config) =
            artifact_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        for _ in 0..=MAX_NOMINATING_MANIFESTS {
            let manifest_hash = real_sha256(&manifest);
            let manifest_row = row(manifest_hash.clone(), "manifests/sha256:aa");
            let id = manifest_row.id;
            h.artifacts.insert(manifest_row);
            h.storage.insert_content(manifest_hash, manifest.clone());
            h.storage
                .insert_content(real_sha256(&config), config.clone());
            h.claim_layer(id, &blob.sha256_checksum);
        }
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::Unknown
        );
    }

    /// **The scoping, asserted positively.** A row that is not a
    /// composition constituent asks the registry nothing — the kind gate
    /// is what keeps a Java archive's scan from paying a lookup, and it is
    /// the same kind `gates_release` and `may_condemn_artifact` are scoped
    /// by.
    ///
    /// Driven with an edge set that *would* answer `ImageLayer`, so the
    /// assertion is about the gate and not about an empty fixture.
    #[tokio::test]
    async fn a_non_constituent_kind_asks_the_registry_nothing() {
        let blob = layer_blob();
        let h = Harness::new();
        let (manifest, config) =
            image_manifest_documents(&[(OCI_GZIP_LAYER_MEDIA_TYPE, &blob.sha256_checksum)]);
        h.seed_manifest(&manifest, &config, &blob.sha256_checksum);
        assert_eq!(
            h.resolve(&blob, ArtifactKind::OciBlob).await,
            LayerRole::ImageLayer,
            "the fixture really does declare this blob a layer"
        );
        for kind in [
            ArtifactKind::MavenJar,
            ArtifactKind::NpmTarball,
            ArtifactKind::PyWheel,
            ArtifactKind::OciManifest,
            ArtifactKind::Other,
        ] {
            assert_eq!(
                h.resolve(&blob, kind).await,
                LayerRole::Unknown,
                "{kind} is not a composition constituent, so the role is not its question"
            );
        }
        assert_eq!(
            h.storage.get_call_count(),
            2,
            "two CAS reads in total — the one resolve that was a constituent's"
        );
    }
}
