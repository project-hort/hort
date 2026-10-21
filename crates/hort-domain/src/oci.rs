//! OCI manifest parsing helpers — pure Rust, zero I/O. See ADR 0027.
//!
//! [`sigstore_bundle_layers`] extracts the CAS content hashes of the Sigstore
//! bundle blob(s) a cosign referrer manifest carries, so the provenance
//! orchestrator can read the *bundle* bytes (not the manifest bytes) the
//! Sigstore verifier needs. The same [`SIGSTORE_BUNDLE_MEDIA_TYPE`]
//! discriminator identifies "this OCI referrer is a cosign
//! signature/attestation" on the push-path reconcile.
//!
//! Two of the parsers here read the same `config` + `layers[]` descriptors with
//! **opposite** postures, and a reader must not pick one by name alone:
//! [`manifest_blob_refs`] skips a descriptor it cannot resolve (safe for a
//! clearance cascade — an unresolved constituent is one that does not get
//! cleared), while [`strict_manifest_nomination`] refuses and names the
//! offender (safe for a scan input — a skipped layer is a strict subset of the
//! image that gets analysed and reported as the image). See ADR 0064 D1.

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{DomainError, DomainResult};
use crate::types::ContentHash;

/// The OCI `artifactType` / layer `mediaType` of a Sigstore bundle — the
/// `application/vnd.dev.sigstore.bundle.v0.3+json` format the Sigstore
/// verifier (`hort-adapters-provenance-sigstore`) consumes. The single discriminator
/// for "this OCI referrer is a cosign signature/attestation."
pub const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// The OCI layer `mediaType` of a legacy cosign `simplesigning` signature —
/// the `cosign sign --key` shape (ADR 0039). The layer blob is the
/// `simplesigning` JSON payload (carrying `critical.image.docker-manifest-digest`);
/// the detached signature rides the layer annotation
/// [`COSIGN_SIGNATURE_ANNOTATION`]. Distinct from [`SIGSTORE_BUNDLE_MEDIA_TYPE`]
/// (the keyless v0.3 bundle) — the keyed verifier reads this shape, the Sigstore
/// verifier reads that one.
pub const COSIGN_SIMPLESIGNING_MEDIA_TYPE: &str =
    "application/vnd.dev.cosign.simplesigning.v1+json";

/// The OCI layer annotation key carrying the base64 detached cosign signature
/// over a [`COSIGN_SIMPLESIGNING_MEDIA_TYPE`] payload layer.
pub const COSIGN_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";

/// The `Artifact.path` prefix every OCI **blob** row carries —
/// `blobs/sha256:<hex>`, the OCI Distribution URL minus its
/// `/v2/<name>/` head. Manifests and indexes use a `manifests/` prefix
/// instead, so the two never collide on the `(repository_id, path)`
/// uniqueness constraint.
///
/// Shared rather than spelled out at each site because the prefix is
/// load-bearing in two directions: the OCI HTTP adapter *writes* it when
/// it builds blob coords, and `OciFormatHandler::is_provenance_constituent`
/// *reads* it to decide that a row can never carry its own attestation.
/// A silent divergence between the two would re-open a terminal
/// self-rejection on a correctly-signed image's layers.
pub const OCI_BLOB_PATH_PREFIX: &str = "blobs/sha256:";

/// The `mediaType` of an OCI image index (multi-arch "manifest of manifests"):
/// `application/vnd.oci.image.index.v1+json`. An index carries a `manifests[]`
/// array of child descriptors (one per platform) instead of `config`/`layers`.
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// The `mediaType` of a single-image OCI manifest:
/// `application/vnd.oci.image.manifest.v1+json` — the `config` + `layers[]`
/// shape, as opposed to [`OCI_IMAGE_INDEX_MEDIA_TYPE`]'s `manifests[]`.
///
/// Named here because a composed image's layout has to *write* it:
/// [`ImageLayout::manifest_media_type`] falls back to it for a manifest that
/// declares none, which the image spec permitted before it required the field.
pub const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The `mediaType` of a Docker v2 manifest list — the Docker-schema analogue of
/// [`OCI_IMAGE_INDEX_MEDIA_TYPE`]. Same `manifests[]` shape; recognised so a
/// Docker-toolchain multi-arch push is treated as an index too.
pub const DOCKER_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";

/// Upper bound on the number of child manifest hashes [`index_child_digests`]
/// returns from a single image index. Mirrors the write-path
/// `MAX_BLOB_REFERENCES` cap (`hort-http-oci`) so a pathological
/// `manifests[]` array cannot force the caller to hold an unbounded reference
/// set. A real multi-arch index has a handful of children; 1024 is a generous
/// ceiling. An index declaring more than the cap is **rejected**
/// ([`DomainError::Validation`] from [`index_child_digests`]), never truncated —
/// an over-cap index is refused rather than silently accepted with un-linked
/// children.
const MAX_INDEX_CHILDREN: usize = 1024;

/// Minimal OCI image-manifest projection — only the fields bundle-layer
/// extraction needs. `serde` ignores every other manifest field.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciManifest {
    #[serde(default)]
    artifact_type: Option<String>,
    #[serde(default)]
    layers: Vec<OciLayer>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciLayer {
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    digest: Option<String>,
    /// Layer annotations — the keyed `simplesigning` signature rides
    /// `dev.cosignproject.cosign/signature` here. `serde` defaults to empty for
    /// the bundle/SBOM layers that carry none.
    #[serde(default)]
    annotations: std::collections::HashMap<String, String>,
}

/// Returns the CAS content hash of every layer carrying a Sigstore bundle.
///
/// Two recognition modes (ADR 0027):
/// 1. any layer whose `mediaType` is [`SIGSTORE_BUNDLE_MEDIA_TYPE`]; else
/// 2. the manifest-level `artifactType` is that type **and** there is exactly
///    one layer (cosign new-bundle-format with a generically-typed bundle
///    layer) — that single layer's digest.
///
/// A non-Sigstore referrer (SBOM, an attestation of another predicate, an
/// ordinary image manifest) yields `Ok(vec![])` — skipped, not an error. A
/// layer digest that is not a `sha256:` CAS digest (other algorithm, or
/// malformed hex) is skipped. Malformed / non-manifest JSON is
/// [`crate::error::DomainError::Validation`].
pub fn sigstore_bundle_layers(manifest_json: &[u8]) -> DomainResult<Vec<ContentHash>> {
    let manifest: OciManifest = serde_json::from_slice(manifest_json)
        .map_err(|e| DomainError::Validation(format!("not a valid OCI manifest: {e}")))?;

    // Mode 1: layers whose own `mediaType` is the Sigstore bundle type.
    let mut hashes: Vec<ContentHash> = manifest
        .layers
        .iter()
        .filter(|l| l.media_type.as_deref() == Some(SIGSTORE_BUNDLE_MEDIA_TYPE))
        .filter_map(|l| l.digest.as_deref().and_then(parse_sha256_digest))
        .collect();

    // Mode 2: the manifest-level `artifactType` marks it a bundle and there is
    // exactly one layer (cosign new-bundle-format with a generically-typed
    // bundle layer). Only consulted when mode 1 found nothing.
    if hashes.is_empty()
        && manifest.artifact_type.as_deref() == Some(SIGSTORE_BUNDLE_MEDIA_TYPE)
        && manifest.layers.len() == 1
    {
        if let Some(h) = manifest.layers[0]
            .digest
            .as_deref()
            .and_then(parse_sha256_digest)
        {
            hashes.push(h);
        }
    }

    Ok(hashes)
}

/// Returns `true` iff the manifest is a **pure** Sigstore-bundle referrer:
/// it parses, carries **at least one** layer, and **every** layer's
/// `mediaType` is [`SIGSTORE_BUNDLE_MEDIA_TYPE`].
///
/// This is the push-path *exemption* predicate (ADR 0027): a
/// pushed manifest that matches is landed via the narrow signature-ingest
/// path (status `None`, no scan, no provenance) instead of the generic
/// quarantine/scan pipeline. The exemption trigger is the manifest's
/// declared media types, which a write-authed pusher fully controls — so
/// the predicate is deliberately **stricter** than [`sigstore_bundle_layers`]
/// (which permissively extracts *any* bundle layer for the verifier to
/// read). Requiring *every* layer to be a bundle makes "exempted" ⟺
/// "carries no runnable content": a mixed manifest (one bundle layer plus a
/// `tar+gzip` malware layer) is **not** pure, so it stays scanned. This is
/// the load-bearing anti-scan-evasion guard.
///
/// Recognition is keyed solely on the per-layer `mediaType`; the
/// manifest-level `artifactType` Mode-2 fallback that [`sigstore_bundle_layers`]
/// uses for *reading* is deliberately **not** consulted here — an
/// `artifactType`-only signal would leave a layer's true content untyped
/// and unproven, undermining the "no runnable content" guarantee.
///
/// The manifest `config` descriptor is **intentionally not inspected**: the
/// "no runnable content" guarantee concerns *layers* (the bytes a runtime
/// extracts/runs), not the config blob, which is JSON image-metadata that is
/// never run (a cosign signature manifest's config is the empty `{}` blob).
/// Scanners scan layers, so a config of any media type widens no scan-evasion
/// surface; gating on every *layer* being a bundle is the complete control.
///
/// A manifest with zero layers (or no `layers` key) yields `false` (nothing
/// to exempt). Malformed / non-manifest JSON is
/// [`crate::error::DomainError::Validation`] — the same error shape
/// [`sigstore_bundle_layers`] produces.
pub fn is_pure_sigstore_bundle(manifest_json: &[u8]) -> DomainResult<bool> {
    let manifest: OciManifest = serde_json::from_slice(manifest_json)
        .map_err(|e| DomainError::Validation(format!("not a valid OCI manifest: {e}")))?;

    Ok(!manifest.layers.is_empty()
        && manifest
            .layers
            .iter()
            .all(|l| l.media_type.as_deref() == Some(SIGSTORE_BUNDLE_MEDIA_TYPE)))
}

/// Returns `true` iff the manifest is a **pure** cosign `simplesigning`
/// referrer: it parses, carries **at least one** layer, and **every** layer's
/// `mediaType` is [`COSIGN_SIMPLESIGNING_MEDIA_TYPE`]. The keyed counterpart of
/// [`is_pure_sigstore_bundle`] — the push-path scan exemption (ADR 0039 §8): a
/// keyed `.sig` is signature material, not runnable content, so it is landed via
/// the narrow signature-ingest path (status `None`, no scan, the `oci_subject`
/// link) like a keyless `.sig`. The "every layer" requirement is the same
/// anti-scan-evasion guard: a mixed manifest (a simplesigning layer plus a
/// `tar+gzip` malware layer) is **not** pure → it stays scanned.
///
/// Recognition is keyed solely on the per-layer `mediaType` (not the signature
/// annotation): the exemption is about "no runnable content", which the media
/// type alone establishes. Malformed / non-manifest JSON is
/// [`crate::error::DomainError::Validation`].
pub fn is_pure_simplesigning(manifest_json: &[u8]) -> DomainResult<bool> {
    let manifest: OciManifest = serde_json::from_slice(manifest_json)
        .map_err(|e| DomainError::Validation(format!("not a valid OCI manifest: {e}")))?;

    Ok(!manifest.layers.is_empty()
        && manifest
            .layers
            .iter()
            .all(|l| l.media_type.as_deref() == Some(COSIGN_SIMPLESIGNING_MEDIA_TYPE)))
}

/// Which recognised signature carriage a layer's declared `mediaType` names.
///
/// The two carriages ADR 0039 recognises, and nothing else — an unrecognised
/// media type maps to no carriage ([`Self::of_media_type`] returns `None`),
/// which is what keeps a future bundle format out of every decision keyed on
/// this type instead of being refused by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCarriage {
    /// [`SIGSTORE_BUNDLE_MEDIA_TYPE`] — a Sigstore v0.3 bundle, keyless
    /// (Fulcio cert) or cosign-v3 keyed (bare public key).
    SigstoreBundle,
    /// [`COSIGN_SIMPLESIGNING_MEDIA_TYPE`] — the legacy keyed
    /// `cosign sign --key` payload layer.
    Simplesigning,
}

impl SignatureCarriage {
    /// The carriage `media_type` names, or `None` when it names none.
    pub fn of_media_type(media_type: &str) -> Option<Self> {
        match media_type {
            SIGSTORE_BUNDLE_MEDIA_TYPE => Some(Self::SigstoreBundle),
            COSIGN_SIMPLESIGNING_MEDIA_TYPE => Some(Self::Simplesigning),
            _ => None,
        }
    }

    /// The layer `mediaType` this carriage is declared as — for a diagnostic
    /// that has the carriage in hand and must name what was declared.
    pub fn media_type(self) -> &'static str {
        match self {
            Self::SigstoreBundle => SIGSTORE_BUNDLE_MEDIA_TYPE,
            Self::Simplesigning => COSIGN_SIMPLESIGNING_MEDIA_TYPE,
        }
    }

    /// Does `layer_bytes` have the shape this carriage names?
    ///
    /// **Shape, never validity.** Whether a signature is *valid* needs the
    /// trust root and the subject's bytes and stays in the verifiers
    /// (`hort-adapters-provenance-*`); this answers only "is this the kind of
    /// thing it claims to be", which is what a push-time door can ask without
    /// becoming a verification — or a denial-of-service surface — on the write
    /// path.
    ///
    /// Each arm is at most as strict as the corresponding verifier's own read,
    /// so a `false` here means **no** verifier could have read the bytes
    /// either. See
    /// [`is_well_formed_sigstore_bundle`](crate::provenance_bundle::is_well_formed_sigstore_bundle)
    /// and
    /// [`simplesigning_subject_digest`](crate::provenance_bundle::simplesigning_subject_digest)
    /// for which conditions that leaves and why.
    pub fn accepts(self, layer_bytes: &[u8]) -> bool {
        match self {
            Self::SigstoreBundle => {
                crate::provenance_bundle::is_well_formed_sigstore_bundle(layer_bytes)
            }
            Self::Simplesigning => {
                crate::provenance_bundle::simplesigning_subject_digest(layer_bytes).is_some()
            }
        }
    }
}

/// One layer of a manifest whose declared `mediaType` names a recognised
/// signature carriage: the layer blob's CAS hash plus the carriage it was
/// declared as. Mirrors [`ManifestBlobRef`]'s shape — the hash is what a
/// consumer reads the bytes by, the second field is what it must know about
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredSignatureLayer {
    pub hash: ContentHash,
    pub carriage: SignatureCarriage,
}

/// Every layer of `manifest_json` whose declared `mediaType` names a
/// recognised signature carriage, in manifest order.
///
/// This is the per-layer counterpart of the two purity predicates: they answer
/// "is EVERY layer signature material" over the same declared media types,
/// this one hands back the layers themselves so a consumer can go and look at
/// the bytes behind them. A layer declaring an unrecognised media type is
/// **omitted**, not an error — on a manifest the purity predicates admit there
/// are none, and on any other manifest the caller is not asking about it.
///
/// A layer whose `digest` is absent, uses another algorithm, or is malformed
/// hex is likewise omitted: there is no CAS object to reach for, which is the
/// same skip [`sigstore_bundle_layers`] and [`manifest_blob_refs`] apply.
/// Malformed / non-manifest JSON is [`DomainError::Validation`], the error
/// shape every parser in this module produces.
pub fn declared_signature_layers(
    manifest_json: &[u8],
) -> DomainResult<Vec<DeclaredSignatureLayer>> {
    let manifest: OciManifest = serde_json::from_slice(manifest_json)
        .map_err(|e| DomainError::Validation(format!("not a valid OCI manifest: {e}")))?;

    Ok(manifest
        .layers
        .iter()
        .filter_map(|l| {
            let carriage = SignatureCarriage::of_media_type(l.media_type.as_deref()?)?;
            let hash = l.digest.as_deref().and_then(parse_sha256_digest)?;
            Some(DeclaredSignatureLayer { hash, carriage })
        })
        .collect())
}

/// One legacy cosign `simplesigning` signature carried on a `.sig` referrer:
/// the CAS hash of the payload-layer blob (the `simplesigning` JSON) plus the
/// base64 detached signature read from the layer's
/// [`COSIGN_SIGNATURE_ANNOTATION`]. The keyed verifier
/// (`hort-adapters-provenance-sigstore`) reads the payload blob by
/// `payload_layer` and verifies `signature` over it against the pinned key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplesigningSignature {
    /// CAS content hash of the `simplesigning` payload-layer blob.
    pub payload_layer: ContentHash,
    /// The base64-encoded detached signature (the layer annotation value).
    pub signature: String,
}

/// Extract every legacy cosign `simplesigning` signature a `.sig` referrer
/// manifest carries — the keyed-provenance counterpart of
/// [`sigstore_bundle_layers`] (ADR 0039 §8). For each layer whose `mediaType`
/// is [`COSIGN_SIMPLESIGNING_MEDIA_TYPE`] that ALSO carries a non-empty
/// [`COSIGN_SIGNATURE_ANNOTATION`] and a `sha256:` digest, returns the payload
/// layer hash + the signature. A layer missing either the annotation or a usable
/// `sha256:` digest is **skipped** (not an error) — it cannot be verified. A
/// non-simplesigning referrer (a v0.3 bundle, an SBOM, an ordinary manifest)
/// yields `Ok(vec![])`. Malformed / non-manifest JSON is
/// [`crate::error::DomainError::Validation`] — the same error shape
/// [`sigstore_bundle_layers`] produces.
///
/// Unlike [`sigstore_bundle_layers`] there is no manifest-level `artifactType`
/// fallback: the keyed signature is intrinsically per-layer (payload digest +
/// annotation live on the layer), so an `artifactType`-only signal carries
/// neither and is meaningless here.
pub fn simplesigning_signature_layers(
    manifest_json: &[u8],
) -> DomainResult<Vec<SimplesigningSignature>> {
    let manifest: OciManifest = serde_json::from_slice(manifest_json)
        .map_err(|e| DomainError::Validation(format!("not a valid OCI manifest: {e}")))?;

    Ok(manifest
        .layers
        .iter()
        .filter(|l| l.media_type.as_deref() == Some(COSIGN_SIMPLESIGNING_MEDIA_TYPE))
        .filter_map(|l| {
            let payload_layer = l.digest.as_deref().and_then(parse_sha256_digest)?;
            let signature = l.annotations.get(COSIGN_SIGNATURE_ANNOTATION)?;
            if signature.is_empty() {
                return None;
            }
            Some(SimplesigningSignature {
                payload_layer,
                signature: signature.clone(),
            })
        })
        .collect())
}

/// Upper bound on the number of blob digests [`manifest_blob_digests`]
/// returns from a single image manifest (`config` + `layers[]`). Mirrors the
/// write-path `MAX_BLOB_REFERENCES` cap (`hort-http-oci` `manifests_write.rs`)
/// so a pathological manifest cannot force the provenance cascade to hold an
/// unbounded reference set. A manifest declaring more is **rejected**
/// ([`DomainError::Validation`]), never truncated — mirroring
/// [`index_child_digests`]'s over-cap posture.
const MAX_MANIFEST_BLOBS: usize = 1024;

/// Minimal single-image-manifest projection for
/// [`manifest_blob_digests`] — only the `config` + `layers[]` descriptor
/// digests. A distinct type from [`OciManifest`] (whose parse the
/// media-type/annotation helpers share) so widening this projection can
/// never perturb those parsers. `serde` ignores every other field.
#[derive(Deserialize)]
struct OciManifestBlobRefs {
    #[serde(default)]
    config: Option<OciBlobDescriptor>,
    #[serde(default)]
    layers: Vec<OciBlobDescriptor>,
}

#[derive(Deserialize)]
struct OciBlobDescriptor {
    #[serde(default)]
    digest: Option<String>,
}

/// Returns the CAS content hash of every blob a **single-image manifest**
/// references: the `config` descriptor's digest plus each `layers[*]` digest,
/// in manifest order (config first).
///
/// This is the constituent-derivation primitive of the provenance-clearance
/// cascade (ADR 0039): a manifest's bytes bind its config/layer digests, so a
/// signature verified over the manifest (or over an index that binds the
/// manifest) covers exactly these blobs.
///
/// `sha256`-only: a descriptor whose digest uses another algorithm or is
/// malformed hex is **skipped** (not an error), mirroring
/// [`index_child_digests`]. A descriptor with no `digest`, a missing `config`,
/// or an absent `layers` key are likewise skipped/empty. An image index (no
/// `config`/`layers`) yields `Ok(vec![])`. A manifest declaring more than
/// [`MAX_MANIFEST_BLOBS`] config+layer descriptors is **rejected** as
/// [`DomainError::Validation`] — never silently truncated. Malformed /
/// non-object JSON is [`DomainError::Validation`] — the same error shape
/// [`sigstore_bundle_layers`] produces.
pub fn manifest_blob_digests(manifest_json: &[u8]) -> DomainResult<Vec<ContentHash>> {
    Ok(manifest_blob_refs(manifest_json)?
        .into_iter()
        .map(|r| r.hash)
        .collect())
}

/// Which single-image-manifest descriptor a [`ManifestBlobRef`] came from —
/// the `content_references.kind` discriminator the OCI membership-edge
/// writers (the manifest-PUT path and the pull-through register-only path)
/// key their row on: `"oci_config"` for [`Config`](Self::Config),
/// `"oci_layer"` for [`Layer`](Self::Layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestBlobRole {
    Config,
    Layer,
}

/// One config/layer descriptor resolved from a single-image manifest —
/// the CAS hash plus which descriptor it came from. [`manifest_blob_digests`]
/// collapses this to a flat hash list for the provenance cascade, which
/// treats config and layers uniformly; a consumer that must write a
/// per-role `content_references` edge (config vs. layer) needs the role
/// alongside the hash, which position-in-list alone cannot reliably encode
/// once a malformed descriptor is skipped ahead of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBlobRef {
    pub hash: ContentHash,
    pub role: ManifestBlobRole,
}

/// Returns every blob a **single-image manifest** references, tagged with
/// which descriptor it came from — the role-preserving counterpart of
/// [`manifest_blob_digests`], which this function now implements. Same
/// parse, same cap, same skip/error posture (see that function's doc);
/// order is config first, then layers in manifest order.
pub fn manifest_blob_refs(manifest_json: &[u8]) -> DomainResult<Vec<ManifestBlobRef>> {
    let manifest: OciManifestBlobRefs = serde_json::from_slice(manifest_json)
        .map_err(|e| DomainError::Validation(format!("not a valid OCI manifest: {e}")))?;

    let declared = manifest.layers.len() + usize::from(manifest.config.is_some());
    if declared > MAX_MANIFEST_BLOBS {
        return Err(DomainError::Validation(format!(
            "image manifest references {declared} config/layer blobs; max is {MAX_MANIFEST_BLOBS}",
        )));
    }

    let config_ref = manifest.config.iter().filter_map(|d| {
        d.digest
            .as_deref()
            .and_then(parse_sha256_digest)
            .map(|hash| ManifestBlobRef {
                hash,
                role: ManifestBlobRole::Config,
            })
    });
    let layer_refs = manifest.layers.iter().filter_map(|d| {
        d.digest
            .as_deref()
            .and_then(parse_sha256_digest)
            .map(|hash| ManifestBlobRef {
                hash,
                role: ManifestBlobRole::Layer,
            })
    });

    Ok(config_ref.chain(layer_refs).collect())
}

// ---------------------------------------------------------------------------
// The strict single-image parse — the composed scan unit's input (ADR 0064 D1)
// ---------------------------------------------------------------------------

/// The OCI `mediaType` of an uncompressed image layer:
/// `application/vnd.oci.image.layer.v1.tar`.
const OCI_LAYER_TAR_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

/// The OCI `mediaType` of a gzip-compressed image layer:
/// `application/vnd.oci.image.layer.v1.tar+gzip` — what nearly every image in
/// circulation declares.
const OCI_LAYER_TAR_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// The OCI `mediaType` of a zstd-compressed image layer:
/// `application/vnd.oci.image.layer.v1.tar+zstd` — the third layer container
/// the image spec defines, declared by the toolchains that opt into zstd.
const OCI_LAYER_TAR_ZSTD_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

/// The Docker-schema analogue of [`OCI_LAYER_TAR_GZIP_MEDIA_TYPE`]:
/// `application/vnd.docker.image.rootfs.diff.tar.gzip`. A Docker-toolchain push
/// carries this spelling with the identical container behind it, so a composed
/// image must be derivable from either vocabulary.
const DOCKER_LAYER_TAR_GZIP_MEDIA_TYPE: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// The only `rootfs.type` an OCI image config may declare. A config whose
/// `rootfs` says anything else does not describe a layered filesystem, so the
/// manifest's layer list is not the composition it claims to be.
const ROOTFS_TYPE_LAYERS: &str = "layers";

/// Whether a layer's declared `mediaType` names a container the composed image
/// can be read out of.
///
/// **The set is the scanner's reach, not hort's.** The materialisation under
/// ADR 0064 D1 copies each layer blob from CAS into `blobs/sha256/<digest>`
/// **verbatim** — it decompresses nothing, and cannot, because that path *is*
/// the digest of those bytes and the manifest's descriptors address them by it.
/// So hort's own decoder inventory does not constrain this set; what governs is
/// what the scanner opens once handed the layout.
///
/// That makes the set **measured rather than reasoned**. Against Trivy 0.70.0 —
/// the version `docker/Dockerfile.worker` pins — on hand-built two-layer
/// layouts whose lower layer carried `/etc/os-release` and a dpkg database and
/// whose upper layer carried a larger one and no OS marker of its own, an upper
/// layer declaring `tar`, `tar+gzip` or `tar+zstd` composed identically: same
/// detected OS, same package inventory (measured 2026-10-19). So the upper
/// layer's container did not change what the scanner read out of either layer.
///
/// Measured the same way, the scanner decides by **content** rather than by
/// the declared type — it composed a layer whose `mediaType` was an
/// unrecognised spelling but whose bytes were a plain tar, and it failed the
/// whole scan loudly, with no report, on one declaring `tar+gzip` whose bytes
/// it could not decompress. So this set is hort's own gate in front of that,
/// and refusing a spelling the spec does not define is stricter than the
/// scanner requires: the declared type is what a parse can check, and a
/// composition hort cannot describe is not one it should hand over.
///
/// Questioning the set means **redoing that measurement** against the pinned
/// version. It is deliberately not derivable from the container sniffing in
/// `hort-adapters-scanner-trivy::workspace`, which decodes a layer *itself* to
/// present one blob as a root filesystem — a different path, with a different
/// and narrower decoder inventory, and no authority over this one.
///
/// Everything outside the set is withheld by absence rather than by an
/// enumeration of bad types —
///
/// - a `+xz` or bzip2 spelling is not an OCI layer media type at all. The image
///   spec defines exactly `tar`, `tar+gzip`, `tar+zstd` and their
///   `nondistributable` variants, and Docker adds `…rootfs.diff.tar.gzip`; a
///   spelling nothing can legitimately produce is refused as unrecognised, not
///   as a container awaiting a decoder.
/// - a `nondistributable` / `foreign` layer is bytes that by declaration live
///   somewhere else — fetched from the descriptor's `urls` — so the registry
///   does not hold the composition at all. **That reason is independent of
///   decoding**, so it covers the `nondistributable` zstd spelling too:
///   narrowing the decoding reason must not be allowed to collapse the two.
/// - an unrecognised type names a container nothing has stated it can read.
///
/// All of them must refuse rather than drop: a dropped layer yields a **strict
/// subset** of the image, which a scanner then analyses and reports as the
/// image — a clean verdict about the wrong subject.
///
/// Growing this set is a claim about what the scanner composes, so it belongs
/// with a measurement that shows it, never ahead of one.
fn layer_media_type_is_openable(media_type: &str) -> bool {
    matches!(
        media_type,
        OCI_LAYER_TAR_MEDIA_TYPE
            | OCI_LAYER_TAR_GZIP_MEDIA_TYPE
            | OCI_LAYER_TAR_ZSTD_MEDIA_TYPE
            | DOCKER_LAYER_TAR_GZIP_MEDIA_TYPE
    )
}

/// Which descriptor of a single-image manifest a refusal is about.
///
/// [`Layer`](Self::Layer) carries the **zero-based index in manifest order** —
/// the order the layers are applied in — so the refusal names a position a
/// reader can find in the manifest bytes rather than a digest they must search
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageDescriptorSlot {
    /// The `config` descriptor.
    Config,
    /// `layers[N]`, zero-based in manifest order.
    Layer(usize),
}

impl fmt::Display for ImageDescriptorSlot {
    /// `config` / `layers[N]` — the spelling every phase of a composite scan
    /// names a constituent by, so a refusal from the acquisition and a refusal
    /// from the layout writer point an operator at the same position in the
    /// same manifest.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config => f.write_str("config"),
            Self::Layer(index) => write!(f, "layers[{index}]"),
        }
    }
}

/// Why a declared descriptor does not name a blob in the CAS keyspace.
///
/// No variant carries the offending value: the slot says *which* descriptor and
/// the variant says *what* is wrong with it, which is what a caller needs in
/// order to refuse and name the offender. The declared value is in the manifest
/// bytes the caller already holds, and those bytes are declarant-controlled and
/// unbounded — a refusal is not the place to carry them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorProblem {
    /// The descriptor itself is absent. Only reachable for
    /// [`ImageDescriptorSlot::Config`]: a layer that was never declared is not
    /// a descriptor, it is a shorter `layers[]`.
    Missing,
    /// No `mediaType`. Only reachable for a layer: the config descriptor's
    /// media type is deliberately not inspected, because the config *bytes* are
    /// (its `rootfs`), which is the stronger statement about the same blob.
    MissingMediaType,
    /// No `digest` — the descriptor names no content at all.
    MissingDigest,
    /// The `digest` does not name the `sha256` algorithm. Covers another
    /// algorithm (`sha512:…`) and a digest with no `<algorithm>:` prefix alike:
    /// in both cases nothing identifies a CAS object.
    NotSha256,
    /// A `sha256:` digest whose body is not 64 lowercase hex characters
    /// (short, over-long, non-hex, or upper-case).
    MalformedSha256,
}

/// One layer of a composed image: the CAS hash of the layer blob plus the
/// container it declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLayoutLayer {
    /// CAS content hash of the layer blob.
    pub hash: ContentHash,
    /// The declared layer `mediaType`, always one
    /// [`layer_media_type_is_openable`] admitted — an unopenable container is a
    /// refusal, so it never reaches this struct. Carried so the value that
    /// decided the layer is openable travels with the layer instead of being
    /// re-derived from the manifest bytes downstream.
    pub media_type: String,
}

/// The composed scan unit of a single-image manifest (ADR 0064 D1): the config
/// blob and every layer blob, in the order the layers are applied.
///
/// Config and layers are separate fields rather than one role-tagged list
/// because the composition requires exactly one config and an ordered layer
/// sequence; a flat list would re-admit the positional ambiguity
/// [`ManifestBlobRef`]'s role tag exists to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLayout {
    /// CAS content hash of the image config blob.
    pub config: ContentHash,
    /// Every layer, in manifest order — never a subset. The order is
    /// load-bearing: it is the order the layers are applied in, and a composed
    /// filesystem assembled in any other order is a different filesystem.
    pub layers: Vec<ImageLayoutLayer>,
    /// The manifest's own declared `mediaType`, or
    /// [`OCI_IMAGE_MANIFEST_MEDIA_TYPE`] when it declared none.
    ///
    /// Carried because an OCI image layout's `index.json` descriptor has to
    /// state the media type of the bytes it points at, and the only statement
    /// about those bytes that came *from* those bytes is this one. The stored
    /// artifact row's `content_type` is a header a pusher or an upstream
    /// supplied — which the pull-through membership path already refuses to let
    /// decide a manifest's structure, for the same reason.
    ///
    /// Substituting the OCI image-manifest type for a manifest that declares
    /// none is not a guess: this parse has just established that the bytes are
    /// a single-image manifest whose config describes a layered root
    /// filesystem, which is precisely what that media type asserts. (The image
    /// spec made the field optional before it made it required, so a manifest
    /// from that era legitimately omits it.)
    pub manifest_media_type: String,
}

// ---------------------------------------------------------------------------
// The whole-image budget — read by both phases of a composite scan
// ---------------------------------------------------------------------------

/// Whole-image ceiling on bytes a composition may cost, across the manifest,
/// the config and every layer.
///
/// 8 GiB. A composition is held **verbatim** — the acquisition writes the
/// declared bytes into CAS and the layout holds those same bytes on disk — so
/// this bounds the image's own wire size, the same quantity a registry client
/// pulls. Two things pick 8 rather than a larger number:
///
/// - It is the ceiling the single-blob path already accepts for **one**
///   artifact (`TrivyConfig::max_artifact_size`), so a composite scan can
///   never cost a worker more scratch disk than the worst single-blob scan it
///   already tolerates — however many layers the manifest declares.
/// - It is far above what real images weigh: a distroless or Alpine image is
///   tens of MiB, a full distro base a few hundred, and the heaviest published
///   CUDA / ML images are single-digit GiB compressed.
///
/// For the layout this is also the **scratch-disk** bound, and the two
/// coincide by construction rather than by omission: the layout is the only
/// thing in the workspace — no download staged beside it, no extraction,
/// nothing decompressed — so the bytes written *are* the footprint on disk.
/// The single-blob path needs two numbers precisely because it writes the
/// archive and then unpacks it.
///
/// Deliberately a compile-time constant rather than derived from the
/// operator's per-artifact knob: "this one artifact may be large" and "an
/// image may read this many bytes in aggregate" are different statements, and
/// the second bounds a count the declarant controls.
const MAX_IMAGE_LAYOUT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Whole-image ceiling on the number of CAS objects a composition is made of:
/// the manifest, the config and every layer.
///
/// The bound is 256. Each constituent costs a storage round-trip, a file and
/// an inode — and, on a proxy that has to acquire it, an upstream fetch — so
/// the count is the multiplier on everything else in the budget. Real images
/// are tens of layers — the Docker daemon's own historical ceiling was 127,
/// and a build approaching it is already pathological — so 256 leaves that
/// doubled while refusing the shape the strict parse admits as well-formed (up
/// to [`MAX_MANIFEST_BLOBS`] descriptors). That the parse accepts such a
/// manifest is a statement about the manifest being describable, not about
/// hort agreeing to assemble it.
const MAX_IMAGE_LAYOUT_BLOBS: usize = 256;

/// Wall-clock ceiling on one **bounded span** of a composite scan. There are
/// two: the composition phase — resolving *and* acquiring — and writing the
/// result out as a layout.
///
/// It exists because nothing else bounds those spans. The scanner's own
/// `--timeout` and the adapter's Rust-side backstop around the child only
/// start once the layout exists, and neither a storage stream nor an upstream
/// response that trickles or stalls carries a deadline of its own — so without
/// this a composition could occupy a worker slot indefinitely without ever
/// reaching a scanner. The bound is on **occupancy**, not on the job's claim:
/// the worker renews a running row's lease every `lock_duration / 3`
/// (`JobsRepository::renew_lease`), so a long span does not lose the row — it
/// just holds a slot nothing can use.
///
/// A span is not a *step*. The composition phase reads the manifest document
/// out of CAS, acquires the config, reads it, and acquires the layers — four
/// steps that share **one** of these deadlines between them, including the two
/// reads, whose own ceiling bounds a document's *bytes* and not its time. A
/// composition that is produced in more steps is not a composition hort will
/// wait longer for, because what this bounds is the worker slot and the slot
/// does not care how the work was divided.
///
/// The number is 300 s, matching the default scan timeout
/// (`TrivyConfig::timeout`), so every span of a composite run is one number
/// rather than three. 300 s also covers the byte budget at a modest rate:
/// 8 GiB in 300 s is ~27 MiB/s.
const MAX_IMAGE_LAYOUT_DURATION: Duration = Duration::from_secs(300);

/// The whole-image bounds a composite scan runs under.
///
/// Compile-time policy, not an operator surface: these are safety bounds over
/// input a declarant controls, and an operator who could raise them could
/// re-open the exhaustion surface they close. Tests construct tightened values
/// directly.
///
/// **One definition, read by both phases.** Acquiring a constituent from an
/// upstream and writing it into a layout are different mechanisms in different
/// crates, but they are bounded by the *same* quantities: bytes the
/// composition costs, objects it is made of, wall-clock one span may occupy.
/// Two copies of those numbers could disagree, and the disagreement has a
/// direction — a byte ceiling on the fetch that exceeded the layout's would
/// pull bytes over the network that the layout is then guaranteed to refuse,
/// and a constituent ceiling that lagged it would do the same per object. So
/// the numbers live here, in the layer both phases already depend on, and
/// neither phase states them for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageBudget {
    /// Ceiling on bytes across every constituent.
    pub max_bytes: u64,
    /// Ceiling on constituents (manifest + config + layers).
    pub max_blobs: usize,
    /// Ceiling on wall-clock for one bounded span — the whole composition
    /// phase (its two document reads and its two acquisition phases), or the
    /// layout write. See [`MAX_IMAGE_LAYOUT_DURATION`].
    pub max_duration: Duration,
}

impl ImageBudget {
    /// The shipped bounds. See each constant for what it defends.
    #[must_use]
    pub const fn default_for_composite_scan() -> Self {
        Self {
            max_bytes: MAX_IMAGE_LAYOUT_BYTES,
            max_blobs: MAX_IMAGE_LAYOUT_BLOBS,
            max_duration: MAX_IMAGE_LAYOUT_DURATION,
        }
    }
}

/// Minimal single-image-manifest projection for
/// [`strict_manifest_nomination`]: the `mediaType` discriminator, the `config`
/// and `layers[]` descriptors with their media types, and the *presence* of
/// `manifests[]`.
///
/// A distinct type from [`OciManifestBlobRefs`] for the same reason that one is
/// distinct from [`OciManifest`] — widening one projection must not perturb the
/// parsers the others share — and additionally because the two have opposite
/// postures over the same fields, which no shared projection should be able to
/// blur.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciStrictManifest {
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    config: Option<OciStrictDescriptor>,
    #[serde(default)]
    layers: Vec<OciStrictDescriptor>,
    /// Child descriptors, counted and never read: an index is refused, not
    /// walked, so their contents are not this parse's business. Counting them
    /// is what recognises an index whose `mediaType` is absent or unexpected,
    /// the same structural probe [`is_image_index`] applies.
    #[serde(default)]
    manifests: Vec<serde::de::IgnoredAny>,
}

/// A `config` / `layers[]` descriptor as the strict parse reads it: the two
/// fields a composition needs from it, both optional on the wire so that an
/// omission becomes a named refusal instead of a parse error that cannot say
/// which descriptor was at fault.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciStrictDescriptor {
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    digest: Option<String>,
}

/// Minimal image-**config** projection — only `rootfs`, the one part of the
/// config that makes a checkable statement about the manifest's layer list.
#[derive(Deserialize)]
struct OciImageConfigRootfs {
    #[serde(default)]
    rootfs: Option<OciConfigRootfs>,
}

/// The `rootfs` of an image config.
///
/// `diff_ids` deserialises to a count and not to values on purpose: a `diff_id`
/// is the digest of the **uncompressed** tar while a manifest layer digest is
/// the digest of the **compressed** blob, so the two are not expected to be
/// equal and comparing them would reject every ordinary image. Only the arity
/// is checkable from these bytes alone, and a projection that cannot hold the
/// values cannot be talked into comparing them later.
#[derive(Deserialize)]
struct OciConfigRootfs {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    diff_ids: Vec<serde::de::IgnoredAny>,
}

// ---------------------------------------------------------------------------
// The two stages of the strict parse
// ---------------------------------------------------------------------------

/// What a single-image manifest's own descriptors nominate: the config blob,
/// the ordered layer blobs, and the media type the manifest declares itself to
/// be.
///
/// The product of [`strict_manifest_nomination`] and the input to
/// [`ManifestNomination::complete_with_config`] — the seam between the strict
/// parse's two stages, and the only thing that crosses it. It exists because a
/// caller that must **acquire** the config blob before it can read it needs
/// the manifest's verdict on the manifest's own descriptors *first*: the
/// config digest to acquire is in here, and every refusal that does not depend
/// on the config bytes has already been made by the time one holds it.
///
/// "Nominate" is the **manifest bytes'** nomination — the bytes that decide
/// (ADR 0064 D1) — and not the `content_references` edges', which name a
/// constituent set without ordering it. What is nominated is still only a set
/// of CAS-shaped digests: whether those blobs exist is a completeness
/// precondition the caller owns, and this is the domain layer.
///
/// **Private fields, one producer.** The only way to obtain one is
/// [`strict_manifest_nomination`], which is what lets the completion stage —
/// and therefore every
/// [`ComposedImage`](crate::ports::scanner::ComposedImage) — carry the
/// manifest-side guarantees: a resolved config digest, a resolved digest and
/// an openable container for every declared layer, not an index, at least one
/// layer, and a descriptor count under [`MAX_MANIFEST_BLOBS`]. A hand-built
/// nomination could carry a layer nobody vetted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestNomination {
    /// CAS content hash of the image config blob.
    config: ContentHash,
    /// Every declared layer, in manifest order — never a subset.
    layers: Vec<ImageLayoutLayer>,
    /// The manifest's own declared `mediaType`, or
    /// [`OCI_IMAGE_MANIFEST_MEDIA_TYPE`] when it declared none — see
    /// [`ImageLayout::manifest_media_type`], which is where it ends up.
    manifest_media_type: String,
}

impl ManifestNomination {
    /// CAS content hash of the image config blob the `config` descriptor
    /// names — the first blob a composition needs, because its bytes are what
    /// decide whether there is a composition at all.
    #[must_use]
    pub fn config(&self) -> &ContentHash {
        &self.config
    }

    /// Every layer the manifest declares, in the order they are applied.
    #[must_use]
    pub fn layers(&self) -> &[ImageLayoutLayer] {
        &self.layers
    }

    /// How many CAS objects the nominated composition is made of: the
    /// manifest, the config and every layer.
    ///
    /// The same count
    /// [`ComposedImage::constituent_count`](crate::ports::scanner::ComposedImage::constituent_count)
    /// reports for the composition this nomination completes into — which is
    /// what lets a whole-image count bound be spent **once**, from the
    /// manifest bytes alone, before any of those objects is probed or
    /// fetched.
    #[must_use]
    pub fn constituent_count(&self) -> usize {
        2 + self.layers.len()
    }

    /// The config-completion stage: read the image config blob the nomination
    /// names and either produce the composition or refuse it.
    ///
    /// Only three things are decided here, and all three are statements the
    /// **config bytes** make: that they are an image config document at all,
    /// that they describe a layered root filesystem, and that they describe
    /// one with as many layers as the manifest declared. Everything else was
    /// settled by [`strict_manifest_nomination`] with no config blob in hand.
    ///
    /// Consuming `self` is the point: the nominated layers *are* the
    /// composition's layers, and moving them means no copy of the list
    /// survives to be completed a second time against different bytes.
    ///
    /// A returned [`ImageLayout`] states only that the manifest and its config
    /// **agree** about a composition of CAS-shaped digests. Whether those blobs
    /// are *present* and readable is a completeness precondition the caller
    /// owns — this is the domain layer and it performs no I/O.
    pub fn complete_with_config(self, config_json: &[u8]) -> Result<ImageLayout, ConfigRefusal> {
        let config_doc: OciImageConfigRootfs = match serde_json::from_slice(config_json) {
            Ok(config_doc) => config_doc,
            Err(e) => return Err(ConfigRefusal::NotParseable(format!("{e}"))),
        };
        let Some(rootfs) = config_doc.rootfs.as_ref() else {
            return Err(ConfigRefusal::RootfsNotLayers);
        };
        if rootfs.kind.as_deref() != Some(ROOTFS_TYPE_LAYERS) {
            return Err(ConfigRefusal::RootfsNotLayers);
        }
        let diff_ids = rootfs.diff_ids.len();
        if diff_ids != self.layers.len() {
            return Err(ConfigRefusal::DiffIdArity {
                layers: self.layers.len(),
                diff_ids,
            });
        }

        Ok(ImageLayout {
            config: self.config,
            layers: self.layers,
            manifest_media_type: self.manifest_media_type,
        })
    }
}

/// Why a manifest's own descriptors nominate no composition — the refusal side
/// of [`strict_manifest_nomination`].
///
/// Separate variants rather than one error string, because they do not lead to
/// the same place: [`NotAnImage`](Self::NotAnImage) sends the caller to the
/// index's children (ADR 0064 D5),
/// [`UnsupportedLayer`](Self::UnsupportedLayer) is a capability gap to surface
/// with the media type that caused it, and the descriptor refusals are
/// statements that the manifest disagrees with the OCI image spec. A caller
/// must be able to tell them apart without matching on prose.
///
/// A type of its own — rather than arms of a wider outcome shared with the
/// config stage — is what makes this stage's *reach* readable: these are
/// exactly the refusals that need no config blob, so a caller holding only the
/// manifest bytes can already answer with one, and cannot be handed a
/// composition it has not earned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestRefusal {
    /// An image index or Docker manifest list: it binds references, not a
    /// runnable filesystem, so there is nothing to compose. Deliberately
    /// distinct from an empty result — for a scan input, "no constituents" and
    /// "this is not an image" must not look alike.
    NotAnImage,
    /// A single-image manifest declaring no layers: there is no composed
    /// filesystem to scan. Never "fine, zero layers".
    NoLayers,
    /// More `config` + `layers[]` descriptors than [`MAX_MANIFEST_BLOBS`].
    /// Rejected, never truncated — a truncated layer list is exactly the strict
    /// subset this parse exists to refuse.
    TooManyDescriptors {
        /// `config` + `layers[]` descriptors the manifest declared.
        declared: usize,
        /// The cap ([`MAX_MANIFEST_BLOBS`]).
        max: usize,
    },
    /// A declared descriptor that does not name a blob in the CAS keyspace.
    /// The first such fault in manifest order (config first, then layers by
    /// index); the composition is refused either way, so the parse stops at the
    /// first offender rather than collecting them.
    MalformedDescriptor {
        /// Which descriptor.
        slot: ImageDescriptorSlot,
        /// What is wrong with it.
        problem: DescriptorProblem,
    },
    /// A layer whose declared container the materialisation cannot open — an
    /// unsupported compression, or a `nondistributable` / `foreign` layer whose
    /// bytes are held elsewhere. Carries the declared media type so the caller
    /// can say which layer it withheld for. That string is
    /// declarant-controlled and unbounded, so it belongs in a message, never in
    /// a metric label.
    UnsupportedLayer {
        /// Zero-based index in manifest order.
        index: usize,
        /// The declared `mediaType`.
        media_type: String,
    },
    /// The manifest bytes are not a JSON object of manifest shape. Distinct
    /// from [`ConfigRefusal::NotParseable`] by *type* rather than by variant,
    /// so "which document was junk" — the difference between a bad push and a
    /// bad blob — is a distinction a caller cannot collapse by accident.
    NotParseable(String),
}

/// Why an image config does not complete the composition its manifest
/// nominated — the refusal side of
/// [`ManifestNomination::complete_with_config`].
///
/// Every variant is a statement the **config bytes** make, which is what puts
/// them on this side of the split: each is decidable only with the config blob
/// in hand, and on a pull-through manifest that means only once it has been
/// acquired. Two of the three are additionally the ordinary shape of a large,
/// legitimate population — an OCI *artifact* manifest, whose config is
/// deliberately not an image config — rather than a defect, which is why a
/// caller must be able to tell them apart from the third without matching on
/// prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigRefusal {
    /// The config bytes are not a JSON object of image-config shape. See
    /// [`ManifestRefusal::NotParseable`] for why the two documents' parse
    /// failures are separate types.
    NotParseable(String),
    /// The config declares no `rootfs`, or a `rootfs.type` other than
    /// `layers` — so it does not describe a layered filesystem and the
    /// manifest's layer list is not the composition it claims to be.
    RootfsNotLayers,
    /// The config's `rootfs.diff_ids` does not have one entry per manifest
    /// layer. The two describe the same stack from either end, so a length
    /// disagreement means at least one of them is not about this image.
    DiffIdArity {
        /// Layers the manifest declared.
        layers: usize,
        /// `diff_ids` the config declared.
        diff_ids: usize,
    },
}

/// Resolve `manifest_json` into the set of blobs a single-image manifest
/// nominates — the **manifest-only** stage of the strict parse (ADR 0064 D1),
/// and the strict counterpart of [`manifest_blob_refs`].
///
/// The two postures are deliberate opposites over the same descriptors, and
/// which one is safe depends entirely on what the result is used for:
///
/// - [`manifest_blob_refs`] **skips** a descriptor it cannot resolve. It feeds
///   the provenance-clearance cascade, where a skipped constituent is simply
///   one that does not get cleared — the safe direction.
/// - this function **refuses**, naming the offender. It feeds a scan, where a
///   skipped descriptor yields a strict subset of the image that a scanner
///   analyses and reports as the image: a clean verdict about the wrong
///   subject. Every declared descriptor is therefore accounted for.
///
/// **Nothing here reads the config blob**, and that is the whole reason this
/// stage is separable: a composition's config is itself a constituent, and on
/// a pull-through manifest it is as absent as the layers are, so a caller has
/// to be able to decide every manifest-side refusal *before* it goes and
/// acquires one. Which is also why the config descriptor's **media type** is
/// deliberately not inspected while its digest is: the config *bytes* are
/// (their `rootfs`), which is the stronger statement about the same blob and
/// belongs to the second stage.
///
/// What is *not* decided here is whether a manifest was meant to be a runnable
/// image at all: an artifact or attestation manifest is the caller's call
/// before it asks, and the only manifest kind refused on sight is an index,
/// which binds references rather than a filesystem. The manifest's own
/// `mediaType` is otherwise not required to be a known image type, because OCI
/// made it optional before it made it required and a Docker-schema push spells
/// it differently — the `config` + `layers[]` shape is what is actually
/// load-bearing.
pub fn strict_manifest_nomination(
    manifest_json: &[u8],
) -> Result<ManifestNomination, ManifestRefusal> {
    let manifest: OciStrictManifest = match serde_json::from_slice(manifest_json) {
        Ok(manifest) => manifest,
        Err(e) => return Err(ManifestRefusal::NotParseable(format!("{e}"))),
    };

    // An index binds references, not a runnable filesystem, so it is refused
    // before anything else: its `layers[]` is absent, and every later check
    // would describe it as some kind of defective image instead.
    let declares_index = matches!(
        manifest.media_type.as_deref(),
        Some(OCI_IMAGE_INDEX_MEDIA_TYPE) | Some(DOCKER_MANIFEST_LIST_MEDIA_TYPE)
    );
    if declares_index || !manifest.manifests.is_empty() {
        return Err(ManifestRefusal::NotAnImage);
    }

    if manifest.layers.is_empty() {
        return Err(ManifestRefusal::NoLayers);
    }

    let declared = manifest.layers.len() + usize::from(manifest.config.is_some());
    if declared > MAX_MANIFEST_BLOBS {
        return Err(ManifestRefusal::TooManyDescriptors {
            declared,
            max: MAX_MANIFEST_BLOBS,
        });
    }

    let Some(config_descriptor) = manifest.config.as_ref() else {
        return Err(ManifestRefusal::MalformedDescriptor {
            slot: ImageDescriptorSlot::Config,
            problem: DescriptorProblem::Missing,
        });
    };
    let config = match strict_sha256_digest(config_descriptor.digest.as_deref()) {
        Ok(hash) => hash,
        Err(problem) => {
            return Err(ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Config,
                problem,
            })
        }
    };

    let mut layers = Vec::with_capacity(manifest.layers.len());
    for (index, descriptor) in manifest.layers.iter().enumerate() {
        let slot = ImageDescriptorSlot::Layer(index);
        let Some(media_type) = descriptor.media_type.as_deref() else {
            return Err(ManifestRefusal::MalformedDescriptor {
                slot,
                problem: DescriptorProblem::MissingMediaType,
            });
        };
        let hash = match strict_sha256_digest(descriptor.digest.as_deref()) {
            Ok(hash) => hash,
            Err(problem) => return Err(ManifestRefusal::MalformedDescriptor { slot, problem }),
        };
        // A descriptor fault is a statement about the manifest; an unopenable
        // container is a statement about what the scanner reads out of the
        // composed layout. Both refuse, and the first is reported first because
        // it is the more precise thing to say about the input: a layer whose
        // digest names nothing is not a layer whose container could be shown to
        // compose later.
        if !layer_media_type_is_openable(media_type) {
            return Err(ManifestRefusal::UnsupportedLayer {
                index,
                media_type: media_type.to_owned(),
            });
        }
        layers.push(ImageLayoutLayer {
            hash,
            media_type: media_type.to_owned(),
        });
    }

    Ok(ManifestNomination {
        config,
        layers,
        manifest_media_type: manifest
            .media_type
            .unwrap_or_else(|| OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_owned()),
    })
}

/// Resolve a descriptor's declared `digest` into a CAS [`ContentHash`], or name
/// why it does not resolve.
///
/// The strict counterpart of [`parse_sha256_digest`], which collapses all three
/// failures into `None` because its callers skip. Here the three are distinct
/// because the caller must be able to say which one it refused for.
fn strict_sha256_digest(digest: Option<&str>) -> Result<ContentHash, DescriptorProblem> {
    let Some(digest) = digest else {
        return Err(DescriptorProblem::MissingDigest);
    };
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(DescriptorProblem::NotSha256);
    };
    hex.parse().map_err(|_| DescriptorProblem::MalformedSha256)
}

/// Minimal projection for [`manifest_subject_digest`] — only the
/// `subject` descriptor. A distinct type from [`OciManifestBlobRefs`]
/// and [`OciManifest`] for the same reason they are distinct from each
/// other: widening one projection must not perturb the parsers the other
/// helpers share. `serde` ignores every other manifest field.
#[derive(Deserialize)]
struct OciManifestSubject {
    #[serde(default)]
    subject: Option<OciBlobDescriptor>,
}

/// Returns the CAS content hash the manifest's **`subject` descriptor**
/// names — the artifact an OCI referrer (a cosign signature manifest, an
/// SBOM, an attestation) declares itself to be *about*.
///
/// This is the referrer's own statement of what it covers, read from the
/// referrer's bytes. It is therefore usable where the `oci_subject`
/// `content_references` row is not: that row is a mutable projection
/// derived from this very field at push time, so it can be stale or
/// absent, while the bytes are the thing the pusher's digest commits to.
/// The field is still only a *claim* — it says which artifact a signature
/// purports to cover, never that the signature verifies — so a caller
/// that acts on it must verify the referrer's bundle against that
/// subject's preimage.
///
/// `sha256`-only: a `subject.digest` using another algorithm or malformed
/// hex yields `Ok(None)`, mirroring [`manifest_blob_digests`] and
/// [`index_child_digests`]. A manifest with no `subject` key, a `subject`
/// with no `digest`, or a `null` subject likewise yields `Ok(None)` — a
/// plain image manifest and an index both do. Malformed / non-object JSON
/// is [`DomainError::Validation`] — the same error shape
/// [`sigstore_bundle_layers`] produces.
pub fn manifest_subject_digest(manifest_json: &[u8]) -> DomainResult<Option<ContentHash>> {
    let manifest: OciManifestSubject = serde_json::from_slice(manifest_json)
        .map_err(|e| DomainError::Validation(format!("not a valid OCI manifest: {e}")))?;

    Ok(manifest
        .subject
        .as_ref()
        .and_then(|d| d.digest.as_deref())
        .and_then(parse_sha256_digest))
}

/// Minimal OCI image-index projection — only the `manifests[]` child
/// descriptor array the index helpers read. A distinct type from
/// [`OciManifest`] (which reads `config`/`layers`): an index carries neither,
/// so parsing it as a manifest would silently drop its children. `serde`
/// ignores every other index field (`schemaVersion`, `mediaType`,
/// `annotations`, …). See ADR 0027 and design `docs/plans/oci-image-index.md`
/// §2 (D2).
#[derive(Deserialize)]
struct OciImageIndex {
    /// Child manifest descriptors — one per platform. Defaults to empty for a
    /// single-image manifest (which carries no `manifests` key), so
    /// [`is_image_index`] on such a manifest is `false`.
    #[serde(default)]
    manifests: Vec<OciIndexChild>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciIndexChild {
    #[serde(default)]
    digest: Option<String>,
}

/// Returns `true` iff `manifest_json` parses as a JSON object carrying a
/// **non-empty** `manifests[]` array — i.e. it is an image index / Docker
/// manifest list rather than a single-image manifest (which has `config` +
/// `layers` and no `manifests`).
///
/// Mirrors the shape of [`is_pure_sigstore_bundle`]: recognition is purely
/// structural (presence of children), not media-type-keyed, so an index whose
/// `mediaType` is absent or unexpected is still recognised by its
/// `manifests[]`. A single-image manifest, an empty `manifests: []`, or
/// malformed / non-object JSON all yield `false` (never a panic) — the callers
/// (the write-path dispatch, Item 2) use this as a fail-open shape probe, so a
/// non-index simply routes down the single-image path.
pub fn is_image_index(manifest_json: &[u8]) -> bool {
    serde_json::from_slice::<OciImageIndex>(manifest_json)
        .map(|index| !index.manifests.is_empty())
        .unwrap_or(false)
}

/// Returns the CAS content hash of every child manifest an image index
/// references via `manifests[*].digest`.
///
/// `sha256`-only: a child whose digest uses another algorithm or is malformed
/// hex is **skipped** (not an error), mirroring how [`sigstore_bundle_layers`]
/// treats a non-CAS layer digest — the domain's uniform sha256-only digest
/// handling. A child descriptor with no `digest` is likewise skipped.
///
/// An index declaring more than [`MAX_INDEX_CHILDREN`] children is **rejected**
/// as [`crate::error::DomainError::Validation`] — never silently truncated —
/// mirroring the single-image reference-count cap the write path enforces
/// (`manifests_write.rs` `MAX_BLOB_REFERENCES`), so an over-cap index is refused
/// rather than accepted with un-linked children.
///
/// A single-image manifest (no `manifests[]`) or an empty `manifests: []`
/// yields `Ok(vec![])`. Malformed / non-object JSON is
/// [`crate::error::DomainError::Validation`] — the same error shape
/// [`sigstore_bundle_layers`] produces.
pub fn index_child_digests(manifest_json: &[u8]) -> DomainResult<Vec<ContentHash>> {
    let index: OciImageIndex = serde_json::from_slice(manifest_json)
        .map_err(|e| DomainError::Validation(format!("not a valid OCI image index: {e}")))?;

    if index.manifests.len() > MAX_INDEX_CHILDREN {
        return Err(DomainError::Validation(format!(
            "image index references {} child manifests; max is {}",
            index.manifests.len(),
            MAX_INDEX_CHILDREN,
        )));
    }

    Ok(index
        .manifests
        .iter()
        .filter_map(|child| child.digest.as_deref().and_then(parse_sha256_digest))
        .collect())
}

/// Parse an OCI `<algorithm>:<hex>` digest into a CAS [`ContentHash`]. Only
/// `sha256` maps to the CAS keyspace; any other algorithm, or malformed hex,
/// yields `None` (the caller skips that layer).
fn parse_sha256_digest(digest: &str) -> Option<ContentHash> {
    digest.strip_prefix("sha256:")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DomainError;

    fn hex64(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn manifest(value: &serde_json::Value) -> Vec<u8> {
        value.to_string().into_bytes()
    }

    #[test]
    fn single_bundle_layer_returns_its_content_hash() {
        let hex = hex64('a');
        let m = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{hex}"), "size": 42 }
            ]
        }));
        let got = sigstore_bundle_layers(&m).expect("valid manifest");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), hex.as_str());
    }

    #[test]
    fn multiple_bundle_layers_returns_all_in_order() {
        let (ha, hb) = (hex64('a'), hex64('b'));
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{ha}") },
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{hb}") }
            ]
        }));
        let got = sigstore_bundle_layers(&m).expect("valid");
        let hashes: Vec<&str> = got.iter().map(AsRef::as_ref).collect();
        assert_eq!(hashes, vec![ha.as_str(), hb.as_str()]);
    }

    // -- simplesigning_signature_layers (ADR 0039 §8 keyed carriage) --------

    const SIG_ANNOTATION: &str = "dev.cosignproject.cosign/signature";

    #[test]
    fn simplesigning_layer_returns_payload_and_signature() {
        let hex = hex64('c');
        let sig = "MEUCIQDexampleSignatureBytesBase64==";
        let m = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [
                {
                    "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE,
                    "digest": format!("sha256:{hex}"),
                    "size": 250,
                    "annotations": { SIG_ANNOTATION: sig }
                }
            ]
        }));
        let got = simplesigning_signature_layers(&m).expect("valid manifest");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload_layer.as_ref(), hex.as_str());
        assert_eq!(got[0].signature, sig);
    }

    #[test]
    fn multiple_simplesigning_layers_all_extracted_in_order() {
        let (ha, hb) = (hex64('a'), hex64('b'));
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE, "digest": format!("sha256:{ha}"),
                  "annotations": { SIG_ANNOTATION: "sigA" } },
                { "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE, "digest": format!("sha256:{hb}"),
                  "annotations": { SIG_ANNOTATION: "sigB" } }
            ]
        }));
        let got = simplesigning_signature_layers(&m).expect("valid");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].signature, "sigA");
        assert_eq!(got[1].payload_layer.as_ref(), hb.as_str());
        assert_eq!(got[1].signature, "sigB");
    }

    #[test]
    fn sigstore_bundle_manifest_yields_no_simplesigning() {
        // A keyless v0.3 bundle referrer carries no simplesigning layer.
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) }
            ]
        }));
        assert!(simplesigning_signature_layers(&m)
            .expect("valid")
            .is_empty());
    }

    #[test]
    fn simplesigning_layer_without_annotation_is_skipped() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) }
            ]
        }));
        assert!(simplesigning_signature_layers(&m)
            .expect("valid")
            .is_empty());
    }

    #[test]
    fn simplesigning_layer_empty_signature_is_skipped() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')),
                  "annotations": { SIG_ANNOTATION: "" } }
            ]
        }));
        assert!(simplesigning_signature_layers(&m)
            .expect("valid")
            .is_empty());
    }

    #[test]
    fn simplesigning_layer_non_sha256_digest_is_skipped() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE, "digest": "sha512:abc",
                  "annotations": { SIG_ANNOTATION: "sig" } }
            ]
        }));
        assert!(simplesigning_signature_layers(&m)
            .expect("valid")
            .is_empty());
    }

    #[test]
    fn simplesigning_malformed_json_is_validation_error() {
        let err = simplesigning_signature_layers(b"not json").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn simplesigning_signature_struct_constructs_and_debugs() {
        let s = SimplesigningSignature {
            payload_layer: hex64('a').parse().unwrap(),
            signature: "sig".into(),
        };
        assert_eq!(s.clone(), s);
        assert!(!format!("{s:?}").is_empty());
    }

    #[test]
    fn pure_simplesigning_single_layer_is_true() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) }
            ]
        }));
        assert!(is_pure_simplesigning(&m).expect("valid"));
    }

    #[test]
    fn mixed_simplesigning_and_runnable_layer_is_false() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) },
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": format!("sha256:{}", hex64('b')) }
            ]
        }));
        assert!(!is_pure_simplesigning(&m).expect("valid"));
    }

    #[test]
    fn pure_simplesigning_zero_layers_is_false() {
        let m = manifest(&serde_json::json!({ "layers": [] }));
        assert!(!is_pure_simplesigning(&m).expect("valid"));
    }

    #[test]
    fn pure_simplesigning_bundle_layer_is_false() {
        // A keyless v0.3 bundle is not a simplesigning manifest.
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) }
            ]
        }));
        assert!(!is_pure_simplesigning(&m).expect("valid"));
    }

    #[test]
    fn pure_simplesigning_malformed_json_is_validation_error() {
        let err = is_pure_simplesigning(b"nope").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn non_bundle_layers_return_empty() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": format!("sha256:{}", hex64('c')) }
            ]
        }));
        assert!(sigstore_bundle_layers(&m).expect("valid").is_empty());
    }

    #[test]
    fn artifact_type_with_single_generic_layer_matches() {
        let hex = hex64('d');
        let m = manifest(&serde_json::json!({
            "artifactType": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "layers": [
                { "mediaType": "application/octet-stream", "digest": format!("sha256:{hex}") }
            ]
        }));
        let got = sigstore_bundle_layers(&m).expect("valid");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), hex.as_str());
    }

    #[test]
    fn artifact_type_with_multiple_generic_layers_does_not_match() {
        // artifactType says bundle, but >1 layer and none typed as bundle:
        // ambiguous which layer is the bundle → empty (conservative).
        let m = manifest(&serde_json::json!({
            "artifactType": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "layers": [
                { "mediaType": "application/octet-stream", "digest": format!("sha256:{}", hex64('e')) },
                { "mediaType": "application/octet-stream", "digest": format!("sha256:{}", hex64('f')) }
            ]
        }));
        assert!(sigstore_bundle_layers(&m).expect("valid").is_empty());
    }

    #[test]
    fn artifact_type_single_layer_with_unparseable_digest_returns_empty() {
        // Mode 2 IS entered (artifactType=bundle, one generic layer), but the
        // layer's digest is not a sha256 CAS digest → the `if let Some` guard
        // pushes nothing (the load-bearing None arm — without the guard this
        // would panic on `unwrap`).
        let m = manifest(&serde_json::json!({
            "artifactType": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "layers": [
                { "mediaType": "application/octet-stream",
                  "digest": format!("sha512:{}", "a".repeat(128)) }
            ]
        }));
        assert!(sigstore_bundle_layers(&m).expect("valid").is_empty());
    }

    #[test]
    fn non_sha256_layer_digest_is_skipped() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
                  "digest": format!("sha512:{}", "a".repeat(128)) }
            ]
        }));
        assert!(sigstore_bundle_layers(&m).expect("valid").is_empty());
    }

    #[test]
    fn invalid_hex_layer_digest_is_skipped() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": "sha256:not-valid-hex" }
            ]
        }));
        assert!(sigstore_bundle_layers(&m).expect("valid").is_empty());
    }

    #[test]
    fn bundle_layer_missing_digest_is_skipped() {
        let m = manifest(&serde_json::json!({
            "layers": [ { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE } ]
        }));
        assert!(sigstore_bundle_layers(&m).expect("valid").is_empty());
    }

    #[test]
    fn empty_manifest_object_returns_empty() {
        assert!(sigstore_bundle_layers(b"{}").expect("valid").is_empty());
    }

    #[test]
    fn malformed_json_is_validation_error() {
        let err = sigstore_bundle_layers(b"not json at all").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn non_object_json_is_validation_error() {
        let err = sigstore_bundle_layers(b"[1, 2, 3]").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ----------------------------------------------------------------
    // is_pure_sigstore_bundle (push-path exemption predicate)
    // ----------------------------------------------------------------
    //
    // The *exemption* predicate: stricter than `sigstore_bundle_layers`.
    // `true` iff the manifest parses AND has >= 1 layer AND **every**
    // layer's `mediaType` is the Sigstore bundle media type — proving the
    // manifest carries nothing but bundle blobs (no runnable layer). This
    // is the load-bearing anti-scan-evasion guard: a mixed manifest
    // (bundle + tar+gzip) MUST be `false` so it stays scanned.

    #[test]
    fn pure_single_bundle_layer_is_true() {
        let m = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')), "size": 42 }
            ]
        }));
        assert!(is_pure_sigstore_bundle(&m).expect("valid manifest"));
    }

    #[test]
    fn pure_multiple_bundle_layers_is_true() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) },
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('b')) }
            ]
        }));
        assert!(is_pure_sigstore_bundle(&m).expect("valid"));
    }

    #[test]
    fn mixed_bundle_plus_tar_gzip_layer_is_false() {
        // THE SECURITY GUARD: a bundle layer beside a runnable tar+gzip
        // layer must NOT be exempted — it stays on the scan/quarantine
        // path. The exemption may fire only when "carries no runnable
        // content" holds.
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) },
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": format!("sha256:{}", hex64('b')) }
            ]
        }));
        assert!(
            !is_pure_sigstore_bundle(&m).expect("valid"),
            "a manifest with any non-bundle (runnable) layer must NOT be exempted"
        );
    }

    #[test]
    fn zero_layers_is_false() {
        // No layers at all: nothing to exempt. (An image manifest always
        // carries a config + >= 1 layer; a referrer with zero layers is
        // not a pure-bundle artifact.)
        let m = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": []
        }));
        assert!(!is_pure_sigstore_bundle(&m).expect("valid"));
    }

    #[test]
    fn missing_layers_key_is_false() {
        // `layers` absent (serde default → empty Vec) is the zero-layer
        // case — not exempted.
        assert!(!is_pure_sigstore_bundle(b"{}").expect("valid"));
    }

    #[test]
    fn non_bundle_only_layer_is_false() {
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": format!("sha256:{}", hex64('c')) }
            ]
        }));
        assert!(!is_pure_sigstore_bundle(&m).expect("valid"));
    }

    #[test]
    fn layer_with_no_media_type_is_false() {
        // A layer that declares no `mediaType` cannot be proven a bundle,
        // so the all-layers-bundle predicate fails (fail-closed).
        let m = manifest(&serde_json::json!({
            "layers": [
                { "digest": format!("sha256:{}", hex64('a')) }
            ]
        }));
        assert!(!is_pure_sigstore_bundle(&m).expect("valid"));
    }

    #[test]
    fn pure_predicate_malformed_json_is_validation_error() {
        let err = is_pure_sigstore_bundle(b"not json at all").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn pure_predicate_non_object_json_is_validation_error() {
        let err = is_pure_sigstore_bundle(b"[1, 2, 3]").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ----------------------------------------------------------------
    // SignatureCarriage + declared_signature_layers
    // ----------------------------------------------------------------
    //
    // The per-layer counterpart of the purity predicates: the push-path door
    // needs the layers themselves, so it can read the bytes behind each one
    // and ask whether they are the shape the layer declared.

    #[test]
    fn carriage_recognises_exactly_the_two_declared_media_types() {
        assert_eq!(
            SignatureCarriage::of_media_type(SIGSTORE_BUNDLE_MEDIA_TYPE),
            Some(SignatureCarriage::SigstoreBundle)
        );
        assert_eq!(
            SignatureCarriage::of_media_type(COSIGN_SIMPLESIGNING_MEDIA_TYPE),
            Some(SignatureCarriage::Simplesigning)
        );
    }

    /// Forward compatibility, at the source: an unrecognised media type names
    /// no carriage. A future bundle version is therefore not signature
    /// material to this code at all — it takes the generic, scanned ingest
    /// path — rather than being refused by a door that does not know it.
    #[test]
    fn an_unrecognised_media_type_names_no_carriage() {
        for mt in [
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "application/spdx+json",
            "application/vnd.dev.sigstore.bundle.v0.4+json",
            "",
        ] {
            assert_eq!(
                SignatureCarriage::of_media_type(mt),
                None,
                "media type {mt}"
            );
        }
    }

    #[test]
    fn carriage_round_trips_its_media_type() {
        for c in [
            SignatureCarriage::SigstoreBundle,
            SignatureCarriage::Simplesigning,
        ] {
            assert_eq!(SignatureCarriage::of_media_type(c.media_type()), Some(c));
        }
    }

    #[test]
    fn carriage_accepts_only_its_own_shape() {
        let bundle = serde_json::json!({
            "verificationMaterial": { "publicKey": { "hint": "k" } },
            "dsseEnvelope": { "payload": "e30=", "payloadType": "x", "signatures": [] },
        })
        .to_string();
        let payload = serde_json::json!({
            "critical": { "image": { "docker-manifest-digest": "sha256:aa" } }
        })
        .to_string();

        assert!(SignatureCarriage::SigstoreBundle.accepts(bundle.as_bytes()));
        assert!(!SignatureCarriage::SigstoreBundle.accepts(payload.as_bytes()));
        assert!(SignatureCarriage::Simplesigning.accepts(payload.as_bytes()));
        assert!(!SignatureCarriage::Simplesigning.accepts(bundle.as_bytes()));
        for c in [
            SignatureCarriage::SigstoreBundle,
            SignatureCarriage::Simplesigning,
        ] {
            assert!(!c.accepts(b"unreadable rubbish"), "{c:?} accepted garbage");
        }
    }

    #[test]
    fn carriage_debug_and_copy_are_available() {
        let c = SignatureCarriage::SigstoreBundle;
        let copied = c;
        assert_eq!(copied, c);
        assert!(!format!("{c:?}").is_empty());
    }

    #[test]
    fn declared_signature_layers_returns_both_carriages_in_manifest_order() {
        let (ha, hb) = (hex64('a'), hex64('b'));
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": COSIGN_SIMPLESIGNING_MEDIA_TYPE, "digest": format!("sha256:{ha}") },
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{hb}") }
            ]
        }));
        let got = declared_signature_layers(&m).expect("valid manifest");
        assert_eq!(
            got,
            vec![
                DeclaredSignatureLayer {
                    hash: ha.parse().expect("hex"),
                    carriage: SignatureCarriage::Simplesigning,
                },
                DeclaredSignatureLayer {
                    hash: hb.parse().expect("hex"),
                    carriage: SignatureCarriage::SigstoreBundle,
                },
            ]
        );
        assert!(!format!("{:?}", got[0]).is_empty());
        assert_eq!(got[0].clone(), got[0]);
    }

    /// A layer declaring an unrecognised media type is omitted rather than
    /// erroring: on a manifest the purity predicates admit there are none, and
    /// on a mixed manifest the caller is not asking about the runnable layer.
    #[test]
    fn unrecognised_and_undigestable_layers_are_omitted() {
        let hex = hex64('c');
        let m = manifest(&serde_json::json!({
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": format!("sha256:{}", hex64('a')) },
                // Recognised media type, but no usable CAS digest: nothing to
                // read, so nothing to check.
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE },
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": "sha512:abc" },
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": "sha256:nothex" },
                // No media type at all.
                { "digest": format!("sha256:{}", hex64('b')) },
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{hex}") }
            ]
        }));
        let got = declared_signature_layers(&m).expect("valid manifest");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].hash.as_ref(), hex.as_str());
    }

    #[test]
    fn declared_signature_layers_of_a_layerless_manifest_is_empty() {
        assert!(declared_signature_layers(b"{}").expect("valid").is_empty());
    }

    #[test]
    fn declared_signature_layers_malformed_json_is_validation_error() {
        let err = declared_signature_layers(b"not json at all").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ----------------------------------------------------------------
    // image-index parsing (design §2 D2)
    // ----------------------------------------------------------------
    //
    // `is_image_index` is a structural shape probe (non-empty `manifests[]`);
    // `index_child_digests` extracts the sha256 child manifest hashes,
    // sha256-only + bounded, skipping malformed children (mirroring
    // `sigstore_bundle_layers`) and erroring only on malformed JSON.

    fn index(children: &serde_json::Value) -> Vec<u8> {
        manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": children,
        }))
    }

    #[test]
    fn index_media_type_constants_are_the_registered_types() {
        assert_eq!(
            OCI_IMAGE_INDEX_MEDIA_TYPE,
            "application/vnd.oci.image.index.v1+json"
        );
        assert_eq!(
            DOCKER_MANIFEST_LIST_MEDIA_TYPE,
            "application/vnd.docker.distribution.manifest.list.v2+json"
        );
    }

    #[test]
    fn is_image_index_true_for_non_empty_manifests() {
        let m = index(&serde_json::json!([
            { "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "digest": format!("sha256:{}", hex64('a')), "platform": { "architecture": "amd64", "os": "linux" } },
            { "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "digest": format!("sha256:{}", hex64('b')), "platform": { "architecture": "arm64", "os": "linux" } }
        ]));
        assert!(is_image_index(&m));
    }

    #[test]
    fn is_image_index_false_for_empty_manifests_array() {
        let m = index(&serde_json::json!([]));
        assert!(!is_image_index(&m));
    }

    #[test]
    fn is_image_index_false_for_single_image_manifest() {
        // A single-image manifest carries `config` + `layers`, no `manifests`.
        let m = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": format!("sha256:{}", hex64('c')), "size": 7 },
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": format!("sha256:{}", hex64('d')) }
            ]
        }));
        assert!(!is_image_index(&m));
    }

    #[test]
    fn is_image_index_false_for_malformed_json() {
        assert!(!is_image_index(b"not json at all"));
    }

    #[test]
    fn is_image_index_false_for_non_object_json() {
        assert!(!is_image_index(b"[1, 2, 3]"));
    }

    #[test]
    fn index_child_digests_returns_all_sha256_children_in_order() {
        let (ha, hb) = (hex64('a'), hex64('b'));
        let m = index(&serde_json::json!([
            { "digest": format!("sha256:{ha}") },
            { "digest": format!("sha256:{hb}") }
        ]));
        let got = index_child_digests(&m).expect("valid index");
        let hashes: Vec<&str> = got.iter().map(AsRef::as_ref).collect();
        assert_eq!(hashes, vec![ha.as_str(), hb.as_str()]);
    }

    #[test]
    fn index_child_digests_skips_non_sha256_child() {
        let hex = hex64('a');
        let m = index(&serde_json::json!([
            { "digest": format!("sha256:{hex}") },
            { "digest": format!("sha512:{}", "a".repeat(128)) }
        ]));
        let got = index_child_digests(&m).expect("valid index");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), hex.as_str());
    }

    #[test]
    fn index_child_digests_skips_malformed_hex_child() {
        let m = index(&serde_json::json!([
            { "digest": "sha256:not-valid-hex" }
        ]));
        assert!(index_child_digests(&m).expect("valid index").is_empty());
    }

    #[test]
    fn index_child_digests_skips_child_missing_digest() {
        let m = index(&serde_json::json!([
            { "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "platform": { "architecture": "amd64", "os": "linux" } }
        ]));
        assert!(index_child_digests(&m).expect("valid index").is_empty());
    }

    #[test]
    fn index_child_digests_empty_manifests_is_empty() {
        let m = index(&serde_json::json!([]));
        assert!(index_child_digests(&m).expect("valid index").is_empty());
    }

    #[test]
    fn index_child_digests_single_image_manifest_is_empty() {
        // A single-image manifest has no `manifests[]` → empty (not an error).
        let m = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "digest": format!("sha256:{}", hex64('c')) },
            "layers": [ { "digest": format!("sha256:{}", hex64('d')) } ]
        }));
        assert!(index_child_digests(&m).expect("valid manifest").is_empty());
    }

    #[test]
    fn index_child_digests_over_cap_is_rejected() {
        // Declaring MORE than the cap is REJECTED (never silently truncated),
        // mirroring the single-image reference-count rejection in the write path.
        let over: Vec<serde_json::Value> = (0..MAX_INDEX_CHILDREN + 5)
            .map(|i| serde_json::json!({ "digest": format!("sha256:{i:064x}") }))
            .collect();
        let err = index_child_digests(&index(&serde_json::json!(over))).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(_)),
            "over-cap index must be a Validation error, got {err:?}"
        );

        // Exactly AT the cap succeeds (boundary).
        let at_cap: Vec<serde_json::Value> = (0..MAX_INDEX_CHILDREN)
            .map(|i| serde_json::json!({ "digest": format!("sha256:{i:064x}") }))
            .collect();
        let got = index_child_digests(&index(&serde_json::json!(at_cap))).expect("at-cap index");
        assert_eq!(got.len(), MAX_INDEX_CHILDREN);
    }

    #[test]
    fn index_child_digests_malformed_json_is_validation_error() {
        let err = index_child_digests(b"not json at all").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ----------------------------------------------------------------
    // manifest_blob_digests (provenance-cascade constituent derivation,
    // ADR 0039)
    // ----------------------------------------------------------------
    //
    // config digest first, then layer digests in manifest order;
    // sha256-only + bounded, skipping malformed descriptors (mirroring
    // `index_child_digests`) and erroring only on malformed JSON or an
    // over-cap declaration.

    #[test]
    fn manifest_blob_digests_returns_config_then_layers_in_order() {
        let (hc, ha, hb) = (hex64('c'), hex64('a'), hex64('b'));
        let m = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": format!("sha256:{hc}"), "size": 7 },
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": format!("sha256:{ha}") },
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": format!("sha256:{hb}") }
            ]
        }));
        let got = manifest_blob_digests(&m).expect("valid manifest");
        let hashes: Vec<&str> = got.iter().map(AsRef::as_ref).collect();
        assert_eq!(hashes, vec![hc.as_str(), ha.as_str(), hb.as_str()]);
    }

    #[test]
    fn manifest_blob_digests_missing_config_returns_layers_only() {
        let ha = hex64('a');
        let m = manifest(&serde_json::json!({
            "layers": [ { "digest": format!("sha256:{ha}") } ]
        }));
        let got = manifest_blob_digests(&m).expect("valid manifest");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), ha.as_str());
    }

    #[test]
    fn manifest_blob_digests_skips_non_sha256_and_missing_digests() {
        let ha = hex64('a');
        let m = manifest(&serde_json::json!({
            "config": { "digest": format!("sha512:{}", "a".repeat(128)) },
            "layers": [
                { "digest": format!("sha256:{ha}") },
                { "digest": "sha256:not-valid-hex" },
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip" }
            ]
        }));
        let got = manifest_blob_digests(&m).expect("valid manifest");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), ha.as_str());
    }

    #[test]
    fn manifest_blob_digests_image_index_is_empty() {
        // An index carries no config/layers → empty (not an error): the
        // cascade's caller branches on `is_image_index` first, but the
        // function stays total over the other shape.
        let m = index(&serde_json::json!([
            { "digest": format!("sha256:{}", hex64('a')) }
        ]));
        assert!(manifest_blob_digests(&m).expect("valid").is_empty());
    }

    #[test]
    fn manifest_blob_digests_empty_object_is_empty() {
        assert!(manifest_blob_digests(b"{}").expect("valid").is_empty());
    }

    #[test]
    fn manifest_blob_digests_over_cap_is_rejected() {
        // config + layers together over the cap is REJECTED (never
        // truncated), mirroring `index_child_digests`. The config
        // descriptor counts toward the total: exactly MAX layers + a
        // config is one over.
        let at_cap_layers: Vec<serde_json::Value> = (0..MAX_MANIFEST_BLOBS)
            .map(|i| serde_json::json!({ "digest": format!("sha256:{i:064x}") }))
            .collect();
        let over = manifest(&serde_json::json!({
            "config": { "digest": format!("sha256:{}", hex64('c')) },
            "layers": at_cap_layers,
        }));
        let err = manifest_blob_digests(&over).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(_)),
            "over-cap manifest must be a Validation error, got {err:?}"
        );

        // Exactly AT the cap succeeds (boundary): MAX-1 layers + config.
        let under_layers: Vec<serde_json::Value> = (0..MAX_MANIFEST_BLOBS - 1)
            .map(|i| serde_json::json!({ "digest": format!("sha256:{i:064x}") }))
            .collect();
        let at_cap = manifest(&serde_json::json!({
            "config": { "digest": format!("sha256:{}", hex64('c')) },
            "layers": under_layers,
        }));
        let got = manifest_blob_digests(&at_cap).expect("at-cap manifest");
        assert_eq!(got.len(), MAX_MANIFEST_BLOBS);
    }

    #[test]
    fn manifest_blob_digests_malformed_json_is_validation_error() {
        let err = manifest_blob_digests(b"not json at all").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn manifest_blob_digests_non_object_json_is_validation_error() {
        let err = manifest_blob_digests(b"[1, 2, 3]").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ----------------------------------------------------------------
    // manifest_blob_refs (role-tagged sibling of manifest_blob_digests)
    // ----------------------------------------------------------------

    #[test]
    fn manifest_blob_refs_tags_config_and_layers() {
        let (hc, ha, hb) = (hex64('c'), hex64('a'), hex64('b'));
        let m = manifest(&serde_json::json!({
            "config": { "digest": format!("sha256:{hc}") },
            "layers": [
                { "digest": format!("sha256:{ha}") },
                { "digest": format!("sha256:{hb}") }
            ]
        }));
        let got = manifest_blob_refs(&m).expect("valid manifest");
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].role, ManifestBlobRole::Config);
        assert_eq!(got[0].hash.as_ref(), hc.as_str());
        assert_eq!(got[1].role, ManifestBlobRole::Layer);
        assert_eq!(got[1].hash.as_ref(), ha.as_str());
        assert_eq!(got[2].role, ManifestBlobRole::Layer);
        assert_eq!(got[2].hash.as_ref(), hb.as_str());
    }

    #[test]
    fn manifest_blob_refs_skips_malformed_descriptor_without_shifting_roles() {
        // The config digest is malformed (skipped); both layers are
        // well-formed. The surviving entries must still be tagged Layer,
        // not have the first surviving hash misread as Config by
        // position — this is the case `manifest_blob_digests`'s flat
        // hash list cannot express.
        let (ha, hb) = (hex64('a'), hex64('b'));
        let m = manifest(&serde_json::json!({
            "config": { "digest": "sha256:not-valid-hex" },
            "layers": [
                { "digest": format!("sha256:{ha}") },
                { "digest": format!("sha256:{hb}") }
            ]
        }));
        let got = manifest_blob_refs(&m).expect("valid manifest");
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|r| r.role == ManifestBlobRole::Layer));
        assert_eq!(got[0].hash.as_ref(), ha.as_str());
        assert_eq!(got[1].hash.as_ref(), hb.as_str());
    }

    #[test]
    fn manifest_blob_refs_over_cap_is_rejected() {
        let over_layers: Vec<serde_json::Value> = (0..=MAX_MANIFEST_BLOBS)
            .map(|i| serde_json::json!({ "digest": format!("sha256:{i:064x}") }))
            .collect();
        let over = manifest(&serde_json::json!({ "layers": over_layers }));
        let err = manifest_blob_refs(&over).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn index_child_digests_non_object_json_is_validation_error() {
        let err = index_child_digests(b"[1, 2, 3]").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ----------------------------------------------------------------
    // manifest_subject_digest (the referrer's own claim about what it
    // covers — ADR 0039 D8's membership walk reads it from the bytes)
    // ----------------------------------------------------------------

    #[test]
    fn manifest_subject_digest_returns_the_subject_descriptor_hash() {
        let hex = hex64('d');
        let m = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{hex}"),
                "size": 528
            },
            "layers": [
                { "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) }
            ]
        }));
        let got = manifest_subject_digest(&m).expect("valid manifest");
        assert_eq!(got.as_ref().map(AsRef::as_ref), Some(hex.as_str()));
    }

    #[test]
    fn manifest_subject_digest_absent_subject_is_none() {
        // A plain image manifest and an image index both carry no
        // `subject` — the legacy cosign tag-scheme `.sig` too.
        let image = manifest(&serde_json::json!({
            "config": { "digest": format!("sha256:{}", hex64('c')) },
            "layers": [ { "digest": format!("sha256:{}", hex64('a')) } ]
        }));
        assert_eq!(manifest_subject_digest(&image).expect("valid"), None);
        let index = manifest(&serde_json::json!({
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [ { "digest": format!("sha256:{}", hex64('b')) } ]
        }));
        assert_eq!(manifest_subject_digest(&index).expect("valid"), None);
        assert_eq!(manifest_subject_digest(b"{}").expect("valid"), None);
    }

    #[test]
    fn manifest_subject_digest_null_subject_is_none() {
        let m = manifest(&serde_json::json!({ "subject": serde_json::Value::Null }));
        assert_eq!(manifest_subject_digest(&m).expect("valid"), None);
    }

    #[test]
    fn manifest_subject_digest_subject_without_digest_is_none() {
        let m = manifest(&serde_json::json!({
            "subject": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 7 }
        }));
        assert_eq!(manifest_subject_digest(&m).expect("valid"), None);
    }

    #[test]
    fn manifest_subject_digest_non_sha256_or_malformed_hex_is_none() {
        let other_algo = manifest(&serde_json::json!({
            "subject": { "digest": format!("sha512:{}", hex64('e')) }
        }));
        assert_eq!(manifest_subject_digest(&other_algo).expect("valid"), None);
        let short_hex = manifest(&serde_json::json!({
            "subject": { "digest": "sha256:dead" }
        }));
        assert_eq!(manifest_subject_digest(&short_hex).expect("valid"), None);
        let not_hex = manifest(&serde_json::json!({
            "subject": { "digest": format!("sha256:{}", std::iter::repeat_n('z', 64).collect::<String>()) }
        }));
        assert_eq!(manifest_subject_digest(&not_hex).expect("valid"), None);
    }

    #[test]
    fn manifest_subject_digest_malformed_json_is_validation_error() {
        let err = manifest_subject_digest(b"not json at all").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let err = manifest_subject_digest(b"[1, 2, 3]").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // ----------------------------------------------------------------
    // The strict parse's two stages (the composed scan unit's input,
    // ADR 0064 D1)
    // ----------------------------------------------------------------
    //
    // The deliberate opposite of `manifest_blob_refs` over the same
    // descriptors: every declared descriptor is accounted for, because a
    // dropped layer yields a strict subset of the image that a scanner would
    // analyse and report as the image.
    //
    // Two stages, and which one owns an outcome is part of the contract:
    // `strict_manifest_nomination` decides everything the **manifest bytes**
    // decide, and `ManifestNomination::complete_with_config` everything the
    // **config bytes** do. There is deliberately no form that takes both
    // documents at once — a caller holding one would reach for config bytes
    // before anything had established they exist, and on a pull-through
    // manifest the config blob is as absent as the layers are. So a
    // manifest-side case below has no config document in sight at all, which
    // is the property the composite scan stands on rather than a convenience.

    /// A layer media type **the image spec does not define**, spelled the way
    /// a real one would be so the refusal cannot be mistaken for a parse
    /// failure. Deliberately invented rather than `+xz` or a bzip2 spelling:
    /// those are not OCI layer media types either, and naming one would make
    /// the test read as a claim about xz that the spec does not support. What
    /// is under test is that an **unrecognised** container is withheld.
    const UNRECOGNISED_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+brotli";

    /// The `nondistributable` zstd spelling — openable compression, bytes that
    /// by declaration are not in this registry.
    const NONDISTRIBUTABLE_ZSTD_MEDIA_TYPE: &str =
        "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";

    /// A single-image manifest with `layers` as given and a well-formed
    /// config descriptor.
    fn image_manifest(layers: &serde_json::Value) -> Vec<u8> {
        manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", hex64('c')),
                "size": 7,
            },
            "layers": layers,
        }))
    }

    /// `n` gzip-tar layer descriptors with distinct digests.
    fn gzip_layers(n: usize) -> serde_json::Value {
        serde_json::json!((0..n)
            .map(|i| serde_json::json!({
                "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE,
                "digest": format!("sha256:{i:064x}"),
                "size": 100,
            }))
            .collect::<Vec<_>>())
    }

    /// An image config declaring `n` `diff_ids` — values that deliberately do
    /// NOT match any layer digest, because a `diff_id` is the digest of the
    /// uncompressed tar and a layer digest the digest of the compressed blob.
    fn image_config(n: usize) -> Vec<u8> {
        manifest(&serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": (0..n)
                    .map(|i| format!("sha256:{:064x}", i + 0xd1ff_0000))
                    .collect::<Vec<_>>(),
            },
        }))
    }

    /// Both stages over a pair of documents that **compose**: nominate, then
    /// complete.
    ///
    /// Deliberately success-only. It cannot report *which* stage refused and
    /// it cannot be asked to classify, so it is not the two-document parse
    /// this module no longer has — it is the three lines every "and the
    /// layout looks like this" case would otherwise repeat.
    fn composed(manifest_json: &[u8], config_json: &[u8]) -> ImageLayout {
        strict_manifest_nomination(manifest_json)
            .expect("the manifest must nominate a composition")
            .complete_with_config(config_json)
            .expect("the config must complete the nomination")
    }

    /// What the manifest's own bytes refuse for — from the manifest bytes and
    /// nothing else, which is the whole of this stage's input.
    fn manifest_refusal(manifest_json: &[u8]) -> ManifestRefusal {
        strict_manifest_nomination(manifest_json)
            .expect_err("the manifest's own descriptors must refuse this")
    }

    /// What the config bytes refuse for, over a manifest that nominates.
    fn config_refusal(manifest_json: &[u8], config_json: &[u8]) -> ConfigRefusal {
        strict_manifest_nomination(manifest_json)
            .expect("the manifest must nominate a composition")
            .complete_with_config(config_json)
            .expect_err("the config must refuse to complete the nomination")
    }

    #[test]
    fn a_completed_composition_carries_config_and_layers_in_manifest_order() {
        let layout = composed(&image_manifest(&gzip_layers(2)), &image_config(2));
        assert_eq!(layout.config.as_ref(), hex64('c').as_str());
        let hashes: Vec<&str> = layout.layers.iter().map(|l| l.hash.as_ref()).collect();
        assert_eq!(hashes, vec![format!("{:064x}", 0), format!("{:064x}", 1)]);
        assert!(layout
            .layers
            .iter()
            .all(|l| l.media_type == OCI_LAYER_TAR_GZIP_MEDIA_TYPE));
    }

    #[test]
    fn the_layer_order_follows_the_manifest_not_the_digests() {
        // The layers are declared in descending digest order; the result must
        // keep the declared order, because that is the order they are applied
        // in and a tree assembled in any other order is a different tree.
        let (ha, hb) = (hex64('b'), hex64('a'));
        let m = image_manifest(&serde_json::json!([
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha256:{ha}") },
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha256:{hb}") },
        ]));
        let layout = composed(&m, &image_config(2));
        let hashes: Vec<&str> = layout.layers.iter().map(|l| l.hash.as_ref()).collect();
        assert_eq!(hashes, vec![ha.as_str(), hb.as_str()]);
    }

    #[test]
    fn the_strict_parse_accepts_uncompressed_and_docker_spelled_layers() {
        // The openable set is about the container, not the vocabulary: a
        // Docker-toolchain push and an uncompressed OCI layer compose too.
        let m = image_manifest(&serde_json::json!([
            { "mediaType": OCI_LAYER_TAR_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) },
            { "mediaType": DOCKER_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('b')) },
        ]));
        let layout = composed(&m, &image_config(2));
        assert_eq!(layout.layers[0].media_type, OCI_LAYER_TAR_MEDIA_TYPE);
        assert_eq!(
            layout.layers[1].media_type,
            DOCKER_LAYER_TAR_GZIP_MEDIA_TYPE
        );
    }

    #[test]
    fn a_nomination_does_not_require_a_known_manifest_media_type() {
        // The `config` + `layers[]` shape is what is load-bearing: a
        // Docker-schema manifest and one that declares no `mediaType` at all
        // (legal before OCI made the field required) are both compositions.
        // Only an index is refused on its media type.
        // And whatever it declared travels with the layout, because the
        // layout's `index.json` descriptor has to state it: a declared type is
        // carried verbatim, and an absent one becomes the OCI image-manifest
        // type — which is what the parse has just proved the bytes are.
        let docker = "application/vnd.docker.distribution.manifest.v2+json";
        for (declared, expected) in [
            (serde_json::json!(docker), docker),
            (serde_json::Value::Null, OCI_IMAGE_MANIFEST_MEDIA_TYPE),
        ] {
            let m = manifest(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": declared,
                "config": { "digest": format!("sha256:{}", hex64('c')) },
                "layers": gzip_layers(1),
            }));
            let layout = composed(&m, &image_config(1));
            assert_eq!(layout.layers.len(), 1);
            assert_eq!(
                layout.manifest_media_type, expected,
                "the layout must describe the manifest bytes it will write"
            );
        }
    }

    #[test]
    fn a_missing_digest_names_the_descriptor_that_has_none() {
        let no_config_digest = manifest(&serde_json::json!({
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "size": 7 },
            "layers": gzip_layers(1),
        }));
        assert_eq!(
            manifest_refusal(&no_config_digest),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Config,
                problem: DescriptorProblem::MissingDigest,
            }
        );
        // A layer descriptor that names a container but no content: an
        // openable `mediaType` is not a licence to drop it.
        let no_layer_digest = image_manifest(&serde_json::json!([
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) },
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "size": 100 },
        ]));
        assert_eq!(
            manifest_refusal(&no_layer_digest),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Layer(1),
                problem: DescriptorProblem::MissingDigest,
            }
        );
    }

    #[test]
    fn an_absent_config_descriptor_names_the_config() {
        // No `config` key at all — distinct from a config descriptor that
        // carries no digest, and an error either way: an image manifest
        // without a config is not an image manifest.
        let m = manifest(&serde_json::json!({ "layers": gzip_layers(1) }));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Config,
                problem: DescriptorProblem::Missing,
            }
        );
    }

    #[test]
    fn a_non_sha256_layer_digest_names_the_layer_index() {
        let m = image_manifest(&serde_json::json!([
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) },
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha512:{}", "a".repeat(128)) },
        ]));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Layer(1),
                problem: DescriptorProblem::NotSha256,
            }
        );
    }

    #[test]
    fn a_digest_without_an_algorithm_prefix_is_not_sha256() {
        // A bare hex body names no algorithm, so it identifies no CAS object —
        // the same refusal as another algorithm, deliberately.
        let m = image_manifest(&serde_json::json!([
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": hex64('a') },
        ]));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Layer(0),
                problem: DescriptorProblem::NotSha256,
            }
        );
    }

    #[test]
    fn a_malformed_hex_digest_names_the_layer() {
        for bad in [
            "sha256:not-valid-hex",
            "sha256:dead",
            &format!("sha256:{}", "A".repeat(64)),
            &format!("sha256:{}", "a".repeat(65)),
        ] {
            let m = image_manifest(&serde_json::json!([
                { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": bad },
            ]));
            assert_eq!(
                manifest_refusal(&m),
                ManifestRefusal::MalformedDescriptor {
                    slot: ImageDescriptorSlot::Layer(0),
                    problem: DescriptorProblem::MalformedSha256,
                },
                "{bad} must be refused as malformed, never skipped"
            );
        }
    }

    #[test]
    fn a_malformed_config_digest_names_the_config() {
        let m = manifest(&serde_json::json!({
            "config": { "digest": "sha256:not-valid-hex" },
            "layers": gzip_layers(1),
        }));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Config,
                problem: DescriptorProblem::MalformedSha256,
            }
        );
    }

    #[test]
    fn a_layer_without_a_media_type_names_the_layer() {
        // `mediaType` is required of a descriptor, and an absent one is a
        // defect in the manifest rather than an unsupported container — so it
        // is named as a descriptor fault, which keeps
        // `UnsupportedLayer.media_type` a value that was actually declared.
        let m = image_manifest(&serde_json::json!([
            { "digest": format!("sha256:{}", hex64('a')) },
        ]));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Layer(0),
                problem: DescriptorProblem::MissingMediaType,
            }
        );
    }

    #[test]
    fn a_descriptor_fault_outranks_an_unopenable_container() {
        // Both refuse. The descriptor fault is reported because it is the more
        // precise statement: a layer whose digest names nothing is not a layer
        // whose container could be shown to compose later.
        let m = image_manifest(&serde_json::json!([
            { "mediaType": UNRECOGNISED_LAYER_MEDIA_TYPE, "digest": "sha256:dead" },
        ]));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Layer(0),
                problem: DescriptorProblem::MalformedSha256,
            }
        );
    }

    #[test]
    fn a_non_distributable_layer_is_withheld_with_its_media_type() {
        // A foreign / non-distributable layer's bytes are by declaration held
        // somewhere else, so the registry does not hold the composition at
        // all. Both spellings must be withheld, and the media type must travel
        // with the refusal so the caller can say what it withheld for.
        for (index, media_type) in [
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
        ]
        .into_iter()
        .enumerate()
        {
            let m = image_manifest(&serde_json::json!([
                { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) },
                { "mediaType": media_type, "digest": format!("sha256:{}", hex64('b')) },
            ]));
            assert_eq!(
                manifest_refusal(&m),
                ManifestRefusal::UnsupportedLayer {
                    index: 1,
                    media_type: media_type.to_owned(),
                },
                "spelling {index} must be withheld, never dropped"
            );
        }
    }

    #[test]
    fn the_strict_parse_accepts_a_zstd_layer_the_scanner_composes() {
        // The third container the image spec defines, and one the pinned
        // scanner composes indistinguishably from gzip and plain tar — so
        // withholding it would be a refusal with no reason behind it. The
        // descriptor must survive in manifest order with its declared type, the
        // same as any other openable layer.
        let (lower, upper) = (hex64('a'), hex64('b'));
        let m = image_manifest(&serde_json::json!([
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha256:{lower}") },
            { "mediaType": OCI_LAYER_TAR_ZSTD_MEDIA_TYPE, "digest": format!("sha256:{upper}") },
        ]));
        let layout = composed(&m, &image_config(2));
        let hashes: Vec<&str> = layout.layers.iter().map(|l| l.hash.as_ref()).collect();
        assert_eq!(hashes, vec![lower.as_str(), upper.as_str()]);
        assert_eq!(layout.layers[1].media_type, OCI_LAYER_TAR_ZSTD_MEDIA_TYPE);
    }

    #[test]
    fn an_unopenable_compression_is_withheld_with_its_media_type() {
        // A container the image spec does not define, so nothing can
        // legitimately produce it and nothing has stated it composes. Nothing
        // about the descriptor is malformed — which is exactly why dropping it
        // would be invisible.
        let m = image_manifest(&serde_json::json!([
            { "mediaType": UNRECOGNISED_LAYER_MEDIA_TYPE,
              "digest": format!("sha256:{}", hex64('a')) },
        ]));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::UnsupportedLayer {
                index: 0,
                media_type: UNRECOGNISED_LAYER_MEDIA_TYPE.to_owned(),
            }
        );
    }

    #[test]
    fn a_nondistributable_zstd_is_withheld_though_zstd_is_openable() {
        // The two reasons for refusing a layer are independent, and narrowing
        // one must not collapse the other: `tar+zstd` composes, yet the
        // `nondistributable` zstd spelling is still withheld, because its bytes
        // by declaration live behind the descriptor's `urls` rather than in this
        // registry. "The scanner can open it" was never why a foreign layer was
        // refused.
        let m = image_manifest(&serde_json::json!([
            { "mediaType": OCI_LAYER_TAR_ZSTD_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('a')) },
            { "mediaType": NONDISTRIBUTABLE_ZSTD_MEDIA_TYPE, "digest": format!("sha256:{}", hex64('b')) },
        ]));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::UnsupportedLayer {
                index: 1,
                media_type: NONDISTRIBUTABLE_ZSTD_MEDIA_TYPE.to_owned(),
            }
        );
    }

    #[test]
    fn an_unknown_layer_media_type_is_withheld() {
        let m = image_manifest(&serde_json::json!([
            { "mediaType": "application/vnd.example.unknown.layer",
              "digest": format!("sha256:{}", hex64('a')) },
        ]));
        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::UnsupportedLayer {
                index: 0,
                media_type: "application/vnd.example.unknown.layer".to_owned(),
            }
        );
    }

    #[test]
    fn an_image_index_is_not_an_image() {
        // Not an empty layer list: for a scan input, "no constituents" and
        // "this is not an image" must not look alike (ADR 0064 D5 sends this
        // caller to the index's children instead).
        let oci = index(&serde_json::json!([
            { "digest": format!("sha256:{}", hex64('a')) }
        ]));
        assert_eq!(manifest_refusal(&oci), ManifestRefusal::NotAnImage);
    }

    #[test]
    fn a_docker_manifest_list_is_not_an_image() {
        let list = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST_LIST_MEDIA_TYPE,
            "manifests": [ { "digest": format!("sha256:{}", hex64('a')) } ],
        }));
        assert_eq!(manifest_refusal(&list), ManifestRefusal::NotAnImage);
    }

    #[test]
    fn an_index_that_declares_no_media_type_is_recognised() {
        // Structural recognition, the same probe `is_image_index` applies: a
        // non-empty `manifests[]` is an index whatever its `mediaType` says.
        let headless = manifest(&serde_json::json!({
            "schemaVersion": 2,
            "manifests": [ { "digest": format!("sha256:{}", hex64('a')) } ],
        }));
        assert_eq!(manifest_refusal(&headless), ManifestRefusal::NotAnImage);
        // And an index shape that ALSO carries layers is still not an image:
        // the ambiguity resolves away from "composable", which is the safe
        // direction for a scan input.
        let both = manifest(&serde_json::json!({
            "config": { "digest": format!("sha256:{}", hex64('c')) },
            "layers": gzip_layers(1),
            "manifests": [ { "digest": format!("sha256:{}", hex64('a')) } ],
        }));
        assert_eq!(manifest_refusal(&both), ManifestRefusal::NotAnImage);
    }

    #[test]
    fn zero_layers_is_refused() {
        // There is no composed filesystem to scan. Both spellings — an empty
        // array and an absent key — and never "fine, zero layers".
        let empty = image_manifest(&serde_json::json!([]));
        assert_eq!(manifest_refusal(&empty), ManifestRefusal::NoLayers);
        let absent = manifest(&serde_json::json!({
            "config": { "digest": format!("sha256:{}", hex64('c')) },
        }));
        assert_eq!(manifest_refusal(&absent), ManifestRefusal::NoLayers);
    }

    #[test]
    fn over_cap_is_rejected_and_at_cap_composes() {
        // Rejected, never truncated: a truncated layer list is exactly the
        // strict subset this parse exists to refuse. The config descriptor
        // counts toward the total, so MAX layers + a config is one over.
        let over = manifest(&serde_json::json!({
            "config": { "digest": format!("sha256:{}", hex64('c')) },
            "layers": gzip_layers(MAX_MANIFEST_BLOBS),
        }));
        assert_eq!(
            manifest_refusal(&over),
            ManifestRefusal::TooManyDescriptors {
                declared: MAX_MANIFEST_BLOBS + 1,
                max: MAX_MANIFEST_BLOBS,
            }
        );

        // Exactly AT the cap composes (boundary): MAX-1 layers + config.
        let at_cap = image_manifest(&gzip_layers(MAX_MANIFEST_BLOBS - 1));
        let layout = composed(&at_cap, &image_config(MAX_MANIFEST_BLOBS - 1));
        assert_eq!(layout.layers.len(), MAX_MANIFEST_BLOBS - 1);
    }

    #[test]
    fn a_diff_id_arity_mismatch_is_refused() {
        // The manifest and the config describe the same stack from either
        // end; a length disagreement means at least one of them is not about
        // this image. Only the arity is checkable — the values are digests of
        // different bytes (uncompressed tar vs. compressed blob).
        let m = image_manifest(&gzip_layers(2));
        assert_eq!(
            config_refusal(&m, &image_config(1)),
            ConfigRefusal::DiffIdArity {
                layers: 2,
                diff_ids: 1,
            }
        );
        assert_eq!(
            config_refusal(&m, &image_config(3)),
            ConfigRefusal::DiffIdArity {
                layers: 2,
                diff_ids: 3,
            }
        );
    }

    #[test]
    fn a_rootfs_type_other_than_layers_is_refused() {
        let m = image_manifest(&gzip_layers(1));
        let foreign_type = manifest(&serde_json::json!({
            "rootfs": { "type": "ext4", "diff_ids": [format!("sha256:{}", hex64('d'))] },
        }));
        assert_eq!(
            config_refusal(&m, &foreign_type),
            ConfigRefusal::RootfsNotLayers
        );
        // An absent `rootfs.type` and an absent `rootfs` are the same
        // statement: this config does not describe a layered filesystem.
        let no_type = manifest(&serde_json::json!({
            "rootfs": { "diff_ids": [format!("sha256:{}", hex64('d'))] },
        }));
        assert_eq!(config_refusal(&m, &no_type), ConfigRefusal::RootfsNotLayers);
        assert_eq!(config_refusal(&m, b"{}"), ConfigRefusal::RootfsNotLayers);
    }

    #[test]
    fn a_caller_holding_no_config_bytes_still_gets_the_descriptor_refusal() {
        // The ordering that makes the split usable, and the reason the stages
        // are not one call: a caller that could not fetch a config blob
        // BECAUSE the descriptor naming it was malformed has no config bytes
        // to pass, and must still get the refusal that names that descriptor
        // rather than a complaint about bytes it had to invent. The manifest
        // stage's signature is what carries that now — there are no config
        // bytes to pass it — and the corpus below pins it for all six
        // manifest-side refusals.
        let bad_config_descriptor = manifest(&serde_json::json!({
            "config": { "digest": "sha256:not-valid-hex" },
            "layers": gzip_layers(1),
        }));
        assert_eq!(
            manifest_refusal(&bad_config_descriptor),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Config,
                problem: DescriptorProblem::MalformedSha256,
            }
        );
        // Same for a layer fault, and for the shapes decided even earlier.
        let bad_layer = image_manifest(&serde_json::json!([
            { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": "sha512:x" },
        ]));
        assert_eq!(
            manifest_refusal(&bad_layer),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Layer(0),
                problem: DescriptorProblem::NotSha256,
            }
        );
        assert_eq!(
            manifest_refusal(&image_manifest(&serde_json::json!([]))),
            ManifestRefusal::NoLayers
        );
    }

    #[test]
    fn an_unparseable_manifest_and_an_unparseable_config_are_distinct() {
        // Which document was junk is the difference between a bad push and a
        // bad blob, so the two refusals do not collapse into one — and since
        // the split they cannot, because they are variants of two different
        // types.
        let m = image_manifest(&gzip_layers(1));
        assert!(matches!(
            manifest_refusal(b"not json at all"),
            ManifestRefusal::NotParseable(_)
        ));
        assert!(matches!(
            manifest_refusal(b"[1, 2, 3]"),
            ManifestRefusal::NotParseable(_)
        ));
        assert!(matches!(
            config_refusal(&m, b"not json at all"),
            ConfigRefusal::NotParseable(_)
        ));
        assert!(matches!(
            config_refusal(&m, b"[1, 2, 3]"),
            ConfigRefusal::NotParseable(_)
        ));
        // A `rootfs` of the wrong JSON shape is a parse failure, not a
        // silently-zero arity.
        let rootfs_not_an_object = manifest(&serde_json::json!({ "rootfs": "layers" }));
        assert!(matches!(
            config_refusal(&m, &rootfs_not_an_object),
            ConfigRefusal::NotParseable(_)
        ));
    }

    #[test]
    fn manifest_blob_refs_still_skips_a_non_sha256_descriptor() {
        // The two postures are deliberate opposites over the SAME bytes, and a
        // future reader must find that stated rather than inferred:
        // `manifest_blob_refs` feeds the provenance-clearance cascade, where an
        // unresolved constituent is one that does not get cleared (safe), while
        // `strict_manifest_nomination` feeds a scan, where a dropped layer is a
        // strict subset analysed and reported as the whole image (unsafe).
        let (hc, ha) = (hex64('c'), hex64('a'));
        let m = manifest(&serde_json::json!({
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": format!("sha256:{hc}") },
            "layers": [
                { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE, "digest": format!("sha256:{ha}") },
                { "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE,
                  "digest": format!("sha512:{}", "a".repeat(128)) },
            ],
        }));

        let lenient = manifest_blob_refs(&m).expect("valid manifest");
        assert_eq!(
            lenient.len(),
            2,
            "the non-sha256 layer must still be SKIPPED here, not refused"
        );
        assert_eq!(lenient[0].role, ManifestBlobRole::Config);
        assert_eq!(lenient[1].hash.as_ref(), ha.as_str());

        assert_eq!(
            manifest_refusal(&m),
            ManifestRefusal::MalformedDescriptor {
                slot: ImageDescriptorSlot::Layer(1),
                problem: DescriptorProblem::NotSha256,
            },
            "the same descriptor must be NAMED by the strict parse"
        );
    }

    #[test]
    fn the_composition_types_are_inspectable_and_cloneable() {
        // The layout is carried through orchestration and logged, so the
        // derives are part of the contract.
        let layout = composed(&image_manifest(&gzip_layers(1)), &image_config(1));
        assert_eq!(layout.clone(), layout);
        assert!(format!("{layout:?}").contains("ImageLayout"));
        assert!(format!("{:?}", layout.layers[0].clone()).contains("ImageLayoutLayer"));
        let slot = ImageDescriptorSlot::Layer(3);
        assert_eq!(slot, slot);
        assert!(format!("{slot:?}").contains('3'));
        assert!(format!("{:?}", ImageDescriptorSlot::Config).contains("Config"));
        assert_ne!(
            DescriptorProblem::Missing,
            DescriptorProblem::MissingMediaType
        );
        assert!(format!("{:?}", DescriptorProblem::MissingDigest).contains("MissingDigest"));
    }

    #[test]
    fn openable_layer_media_type_constants_are_the_registered_types() {
        // Pinned against the OCI image-spec / Docker schema2 registrations: a
        // typo here silently withholds every image in circulation.
        assert_eq!(
            OCI_LAYER_TAR_MEDIA_TYPE,
            "application/vnd.oci.image.layer.v1.tar"
        );
        assert_eq!(
            OCI_LAYER_TAR_GZIP_MEDIA_TYPE,
            "application/vnd.oci.image.layer.v1.tar+gzip"
        );
        assert_eq!(
            DOCKER_LAYER_TAR_GZIP_MEDIA_TYPE,
            "application/vnd.docker.image.rootfs.diff.tar.gzip"
        );
        assert_eq!(ROOTFS_TYPE_LAYERS, "layers");
        assert!(layer_media_type_is_openable(OCI_LAYER_TAR_MEDIA_TYPE));
        assert!(layer_media_type_is_openable(OCI_LAYER_TAR_GZIP_MEDIA_TYPE));
        assert!(layer_media_type_is_openable(
            DOCKER_LAYER_TAR_GZIP_MEDIA_TYPE
        ));
        assert!(!layer_media_type_is_openable(""));
        assert!(!layer_media_type_is_openable(
            "application/vnd.oci.image.layer.nondistributable.v1.tar"
        ));
    }

    // -- the two stages, and the ten outcomes they own between them --------
    //
    // The split exists because a composition's **config is itself a
    // constituent**: on a pull-through manifest it is as absent as the layers
    // are, so a caller has to decide every manifest-side refusal before it
    // goes and acquires one, and only then read the config bytes. These tests
    // pin the seam — which stage owns which outcome, over a table that
    // reaches all ten of them.

    /// Which stage decides a corpus entry's outcome, and which outcome that
    /// is.
    ///
    /// Compared by **variant**: two of the nine refusals quote serde's own
    /// complaint, which no test should spell out, and the values each refusal
    /// carries are pinned by its own test above. What this table is for is
    /// *reach* and *ownership*.
    #[derive(Debug)]
    enum Owned {
        /// The manifest's own descriptors settle it — from the manifest bytes
        /// alone, which is why every such entry's config document is `b""`.
        Manifest(ManifestRefusal),
        /// The config bytes settle it, over a nomination the manifest stage
        /// accepted.
        Config(ConfigRefusal),
        /// Both documents agree: the one outcome that is not a refusal.
        Composition,
    }

    /// Every outcome the two stages reach between them — six
    /// [`ManifestRefusal`]s, three [`ConfigRefusal`]s and a composition —
    /// with the documents that reach it and the stage that owns it.
    ///
    /// A manifest-side entry carries **no config document at all** (`b""`),
    /// and that is load-bearing rather than tidy: it is the state a cold
    /// pull-through manifest is actually in, so an entry that needed real
    /// config bytes to reach its refusal would be an entry the composite scan
    /// could not reproduce. One table, read by the ownership test and by the
    /// counter-assertion beside it.
    fn outcome_corpus() -> Vec<(&'static str, Vec<u8>, Vec<u8>, Owned)> {
        vec![
            (
                "a well-formed two-layer image",
                image_manifest(&gzip_layers(2)),
                image_config(2),
                Owned::Composition,
            ),
            (
                "an image index",
                index(&serde_json::json!([{
                    "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                    "digest": format!("sha256:{}", hex64('b')),
                    "size": 100,
                }])),
                b"".to_vec(),
                Owned::Manifest(ManifestRefusal::NotAnImage),
            ),
            (
                "a manifest declaring no layers",
                image_manifest(&serde_json::json!([])),
                b"".to_vec(),
                Owned::Manifest(ManifestRefusal::NoLayers),
            ),
            (
                "one descriptor over the cap",
                manifest(&serde_json::json!({
                    "config": { "digest": format!("sha256:{}", hex64('c')) },
                    "layers": gzip_layers(MAX_MANIFEST_BLOBS),
                })),
                b"".to_vec(),
                Owned::Manifest(ManifestRefusal::TooManyDescriptors {
                    declared: MAX_MANIFEST_BLOBS + 1,
                    max: MAX_MANIFEST_BLOBS,
                }),
            ),
            (
                "a layer descriptor naming no content",
                manifest(&serde_json::json!({
                    "config": { "digest": format!("sha256:{}", hex64('c')) },
                    "layers": [{ "mediaType": OCI_LAYER_TAR_GZIP_MEDIA_TYPE }],
                })),
                b"".to_vec(),
                Owned::Manifest(ManifestRefusal::MalformedDescriptor {
                    slot: ImageDescriptorSlot::Layer(0),
                    problem: DescriptorProblem::MissingDigest,
                }),
            ),
            (
                "a layer container nothing can open",
                image_manifest(&serde_json::json!([{
                    "mediaType": UNRECOGNISED_LAYER_MEDIA_TYPE,
                    "digest": format!("sha256:{}", hex64('1')),
                    "size": 100,
                }])),
                b"".to_vec(),
                Owned::Manifest(ManifestRefusal::UnsupportedLayer {
                    index: 0,
                    media_type: UNRECOGNISED_LAYER_MEDIA_TYPE.to_owned(),
                }),
            ),
            (
                "bytes that are not a manifest document",
                b"not json at all".to_vec(),
                b"".to_vec(),
                Owned::Manifest(ManifestRefusal::NotParseable(String::new())),
            ),
            (
                "bytes that are not an image config document",
                image_manifest(&gzip_layers(1)),
                b"not json at all".to_vec(),
                Owned::Config(ConfigRefusal::NotParseable(String::new())),
            ),
            (
                "a config describing no layered root filesystem",
                image_manifest(&gzip_layers(1)),
                manifest(&serde_json::json!({ "rootfs": { "type": "ext4", "diff_ids": [] } })),
                Owned::Config(ConfigRefusal::RootfsNotLayers),
            ),
            (
                "a config whose diff_ids do not match the layer list",
                image_manifest(&gzip_layers(2)),
                image_config(1),
                Owned::Config(ConfigRefusal::DiffIdArity {
                    layers: 2,
                    diff_ids: 1,
                }),
            ),
        ]
    }

    /// One corpus entry, run through the stage the table says owns it.
    struct CorpusRun {
        label: &'static str,
        /// What the table claims the owning stage answers.
        claimed: Owned,
        /// What that stage actually answered.
        reached: Owned,
        /// How large the entry's config document is — `0` for every
        /// manifest-side entry, which is the point.
        config_document_bytes: usize,
    }

    /// Run each corpus entry through **the stage the table says owns it**,
    /// and report what that stage answered.
    ///
    /// A manifest-side entry is run through the manifest stage alone and its
    /// config document is never passed to anything — which it cannot be,
    /// since that stage's signature does not take one. The two tests below
    /// read this one derivation: one checks it against what the table claims,
    /// the other counts what it covers.
    fn corpus_runs() -> Vec<CorpusRun> {
        outcome_corpus()
            .into_iter()
            .map(|(label, manifest_bytes, config_bytes, claimed)| {
                let reached = match claimed {
                    Owned::Manifest(_) => Owned::Manifest(
                        strict_manifest_nomination(&manifest_bytes).expect_err(label),
                    ),
                    Owned::Config(_) => Owned::Config(
                        strict_manifest_nomination(&manifest_bytes)
                            .expect(label)
                            .complete_with_config(&config_bytes)
                            .expect_err(label),
                    ),
                    Owned::Composition => {
                        assert!(
                            !composed(&manifest_bytes, &config_bytes).layers.is_empty(),
                            "{label}: a composition is never empty"
                        );
                        Owned::Composition
                    }
                };
                CorpusRun {
                    label,
                    claimed,
                    reached,
                    config_document_bytes: config_bytes.len(),
                }
            })
            .collect()
    }

    /// **Every outcome through the stage that owns it.** The manifest stage
    /// reaches each of its six refusals from the manifest bytes alone, with no
    /// config document in the entry at all — and the completion stage reaches
    /// its three only over a nomination the manifest stage accepted.
    ///
    /// The first half is the property the composite scan stands on: it
    /// refuses with no config blob in hand, and no config bytes it might
    /// later acquire can change that answer.
    #[test]
    fn every_outcome_is_reached_through_the_stage_that_owns_it() {
        for run in corpus_runs() {
            let CorpusRun {
                label,
                claimed,
                reached,
                config_document_bytes,
            } = run;
            // Compared by variant, not by value — see `Owned`.
            let same_stage_and_variant = match (&claimed, &reached) {
                (Owned::Manifest(claimed), Owned::Manifest(reached)) => {
                    assert_eq!(
                        config_document_bytes, 0,
                        "{label}: a manifest-side refusal must be reached with no config bytes \
                         at all"
                    );
                    std::mem::discriminant(claimed) == std::mem::discriminant(reached)
                }
                (Owned::Config(claimed), Owned::Config(reached)) => {
                    std::mem::discriminant(claimed) == std::mem::discriminant(reached)
                }
                (Owned::Composition, Owned::Composition) => true,
                // The owning *stage* is already pinned inside
                // `corpus_runs`, which runs only that stage and panics if
                // it does not answer; this is the exhaustiveness fallback.
                _ => false,
            };
            assert!(
                same_stage_and_variant,
                "{label}: expected {claimed:?}, reached {reached:?}"
            );
        }
    }

    /// The counter-assertion the test above needs in order not to be vacuous:
    /// the corpus **reaches** all ten outcomes — six manifest-side refusals,
    /// three config-side, one composition. Without it a variant could leave
    /// the table, or be renamed out of reach, and the ownership test would
    /// still pass over whatever was left.
    #[test]
    fn the_corpus_reaches_every_outcome_of_both_stages() {
        let mut manifest_side = std::collections::HashSet::new();
        let mut config_side = std::collections::HashSet::new();
        let mut compositions = 0usize;
        for run in corpus_runs() {
            match run.reached {
                Owned::Manifest(refusal) => {
                    manifest_side.insert(std::mem::discriminant(&refusal));
                }
                Owned::Config(refusal) => {
                    config_side.insert(std::mem::discriminant(&refusal));
                }
                Owned::Composition => compositions += 1,
            }
        }
        assert_eq!(
            manifest_side.len(),
            6,
            "every ManifestRefusal variant must be reached by the corpus"
        );
        assert_eq!(
            config_side.len(),
            3,
            "every ConfigRefusal variant must be reached by the corpus"
        );
        assert_eq!(
            compositions, 1,
            "and the one outcome that is not a refusal must be reached too"
        );
    }

    /// What the manifest stage hands forward: the config digest to acquire,
    /// the layers in manifest order with the containers that were vetted, and
    /// the whole-image count — all from the manifest bytes alone.
    #[test]
    fn a_nomination_carries_the_config_the_ordered_layers_and_the_count() {
        let nomination = strict_manifest_nomination(&image_manifest(&gzip_layers(3)))
            .expect("a well-formed three-layer manifest nominates");
        assert_eq!(nomination.config().to_string(), hex64('c'));
        let digests: Vec<String> = nomination
            .layers()
            .iter()
            .map(|l| l.hash.to_string())
            .collect();
        assert_eq!(
            digests,
            (0..3).map(|i| format!("{i:064x}")).collect::<Vec<_>>(),
            "the order is the manifest's, and a tree assembled in another order is another tree"
        );
        assert!(nomination
            .layers()
            .iter()
            .all(|l| l.media_type == OCI_LAYER_TAR_GZIP_MEDIA_TYPE));
        assert_eq!(
            nomination.constituent_count(),
            5,
            "the manifest, the config and three layers"
        );
    }

    /// The count a whole-image bound is spent on is the **same** number
    /// before and after completion. It has to be: the bound is checked from
    /// the manifest bytes, before the config blob is acquired, and the layout
    /// writer re-checks it against the composition — so a nomination that
    /// counted differently would let an image through one bound that the
    /// other then refuses, having already paid for the fetch.
    #[test]
    fn the_nominated_count_is_the_composed_count() {
        use crate::ports::scanner::ComposedImage;

        for layers in [1, 2, 7] {
            let bytes = image_manifest(&gzip_layers(layers));
            let nomination = strict_manifest_nomination(&bytes).expect("nominates");
            let nominated = nomination.constituent_count();
            let layout = nomination
                .complete_with_config(&image_config(layers))
                .expect("completes");
            let composed = ComposedImage::new(hex64('a').parse().expect("sha256"), layout);
            assert_eq!(nominated, composed.constituent_count(), "{layers} layers");
        }
    }

    /// A completion consumes the nomination, so the layers the composition
    /// holds are the ones that were vetted — moved, not copied. Pinned
    /// through the one observable consequence: the layout's own fields.
    #[test]
    fn completing_a_nomination_moves_its_layers_into_the_layout() {
        let nomination =
            strict_manifest_nomination(&image_manifest(&gzip_layers(2))).expect("nominates");
        let expected = nomination.layers().to_vec();
        let config = nomination.config().clone();
        let layout = nomination
            .complete_with_config(&image_config(2))
            .expect("completes");
        assert_eq!(layout.layers, expected);
        assert_eq!(layout.config, config);
        assert_eq!(layout.manifest_media_type, OCI_IMAGE_MANIFEST_MEDIA_TYPE);
    }

    /// The refusal types are carried through the application layer's
    /// classification and logged, so the derives are part of the contract.
    #[test]
    fn the_stage_refusal_types_are_inspectable_and_cloneable() {
        let manifest_side = ManifestRefusal::MalformedDescriptor {
            slot: ImageDescriptorSlot::Config,
            problem: DescriptorProblem::Missing,
        };
        assert_eq!(manifest_side.clone(), manifest_side);
        assert!(format!("{manifest_side:?}").contains("MalformedDescriptor"));
        assert_ne!(ManifestRefusal::NotAnImage, ManifestRefusal::NoLayers);

        let config_side = ConfigRefusal::DiffIdArity {
            layers: 3,
            diff_ids: 2,
        };
        assert_eq!(config_side.clone(), config_side);
        assert!(format!("{config_side:?}").contains("DiffIdArity"));
        assert_ne!(ConfigRefusal::RootfsNotLayers, config_side);

        let nomination =
            strict_manifest_nomination(&image_manifest(&gzip_layers(1))).expect("nominates");
        assert_eq!(nomination.clone(), nomination);
        assert!(format!("{nomination:?}").contains("ManifestNomination"));
    }

    // -- the whole-image budget's own numbers ----------------------------

    /// The shipped bounds, pinned so a change to one is a deliberate edit of a
    /// stated number rather than a drift. Pinned here, in the one place the
    /// numbers live, rather than in each phase that reads them — a per-phase
    /// assertion is exactly the second copy this type exists to prevent.
    #[test]
    fn the_shipped_budget_is_the_whole_images_and_not_a_blobs() {
        let budget = ImageBudget::default_for_composite_scan();
        assert_eq!(budget.max_bytes, 8 * 1024 * 1024 * 1024);
        assert_eq!(budget.max_blobs, 256);
        assert_eq!(budget.max_duration, Duration::from_secs(300));
        // The point of the number: a 1024-descriptor manifest is well-formed
        // to the strict parse, so a per-blob bound reused here would have
        // multiplied by the layer count.
        assert!(
            budget.max_blobs < MAX_MANIFEST_BLOBS,
            "the whole-image bound must be tighter than what a manifest may declare"
        );
    }
    /// The slot vocabulary every phase of a composite scan names a constituent
    /// by. Pinned because two phases in two crates render it, and a reader
    /// correlating their log lines is relying on the spelling matching.
    #[test]
    fn a_descriptor_slot_renders_config_and_a_layers_position() {
        assert_eq!(ImageDescriptorSlot::Config.to_string(), "config");
        assert_eq!(ImageDescriptorSlot::Layer(0).to_string(), "layers[0]");
        assert_eq!(ImageDescriptorSlot::Layer(12).to_string(), "layers[12]");
    }
}
