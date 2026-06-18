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
}
