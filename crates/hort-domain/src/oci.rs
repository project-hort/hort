//! OCI manifest parsing helpers — pure Rust, zero I/O. See ADR 0027.
//!
//! [`sigstore_bundle_layers`] extracts the CAS content hashes of the Sigstore
//! bundle blob(s) a cosign referrer manifest carries, so the provenance
//! orchestrator can read the *bundle* bytes (not the manifest bytes) the
//! Sigstore verifier needs. The same [`SIGSTORE_BUNDLE_MEDIA_TYPE`]
//! discriminator identifies "this OCI referrer is a cosign
//! signature/attestation" on the push-path reconcile.

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

/// The `mediaType` of an OCI image index (multi-arch "manifest of manifests"):
/// `application/vnd.oci.image.index.v1+json`. An index carries a `manifests[]`
/// array of child descriptors (one per platform) instead of `config`/`layers`.
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

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
}
