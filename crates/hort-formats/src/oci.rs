// OCI manifest streaming projector (see ADR 0026).
pub mod projection;

use std::io::Read;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::oci::ManifestBlobRef;
use hort_domain::ports::format_handler::{FormatHandler, GroupMembership};
use hort_domain::types::ArtifactCoords;

/// Upper bound on the manifest bytes [`OciFormatHandler::extract_oci_manifest_blob_refs`]
/// reads from the caller's stream before parsing. Mirrors the write path's
/// `MANIFEST_BODY_MAX_BYTES` (`hort-http-oci::manifests_write`) — every
/// manifest already in CAS passed that same cap at ingest (push or
/// pull-through), so this is defence-in-depth against a corrupted stored
/// row, not a limit real manifests ever approach.
const MANIFEST_BLOB_REFS_MAX_BYTES: u64 = 1024 * 1024;

/// OCI format handler.
///
/// Unlike the single-file format handlers (PyPI, cargo, npm), OCI ingest
/// does NOT parse request paths into `ArtifactCoords` via
/// `FormatHandler::parse_download_path` — URL parsing happens in the
/// `/v2/*` request classifier, which constructs coords explicitly. The
/// trait method is present only to satisfy the port contract and returns
/// a validation error if ever called.
///
/// Group attachment is also explicit (see `classify_group_member`): OCI
/// groups are composed post-ingest from parsed manifest JSON in
/// `OciManifestUseCase::put_manifest`, not via the ingest-time hook.
/// Groups are composed only after JSON parse + digest lookup against
/// previously-uploaded blobs, which is outside the ingest-time hook's
/// contract (§2.14.2).
pub struct OciFormatHandler;

impl FormatHandler for OciFormatHandler {
    fn format_key(&self) -> &str {
        "oci"
    }

    /// OCI image names are canonical as uploaded — the spec's name grammar
    /// (`[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*`)
    /// is the normalisation. Returning the input verbatim is the correct
    /// implementation.
    fn normalize_name(&self, name: &str) -> String {
        name.to_owned()
    }

    /// OCI coords come from the `/v2/*` request classifier, not this trait.
    /// The classifier calls `OciManifestUseCase` / `OciBlobUseCase` directly
    /// with a pre-constructed `ArtifactCoords`; this method is never on the
    /// hot path. Returning an error preserves the port contract (the method
    /// must be present) without requiring a fictional URL grammar.
    fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
        Err(DomainError::Validation(
            "oci handlers supply coords directly".into(),
        ))
    }

    /// Explicit override returning `None` — the trait default would give
    /// the same value, but the explicit override documents the §2.14.2
    /// rationale at the impl site: OCI group attachment is explicit in
    /// the manifest-PUT handler (`OciManifestUseCase::put_manifest`
    /// parses the manifest JSON, resolves blob references, and calls
    /// `ArtifactGroupUseCase::add_member` once per member), not implicit
    /// per ingest. Individual blob uploads (config, layer, manifest
    /// bytes) carry no group information — the manifest does, but only
    /// after JSON parse + digest lookup against previously-uploaded
    /// blobs, which is outside the ingest-time hook's contract.
    fn classify_group_member(
        &self,
        _coords: &ArtifactCoords,
        _path: &str,
    ) -> Option<GroupMembership> {
        None
    }

    /// OCI's protocol embeds the digest in the request itself —
    /// `/v2/{name}/blobs/sha256:<digest>` for blobs and the
    /// `Docker-Content-Digest` header for manifests. The use case reads
    /// the digest from the `VerifiedIngestRequest::ProtocolNative` variant
    /// rather than calling
    /// [`upstream_checksum_metadata_path`](FormatHandler::upstream_checksum_metadata_path),
    /// which stays at its default `None` (see ADR 0006 §9).
    fn protocol_native_integrity(&self) -> bool {
        true
    }

    /// Reads `content` under [`MANIFEST_BLOB_REFS_MAX_BYTES`] and delegates
    /// the parse to [`hort_domain::oci::manifest_blob_refs`] — the pure
    /// domain helper is the single source of truth for the single-image
    /// manifest shape, shared with the provenance cascade's
    /// `manifest_blob_digests`.
    fn extract_oci_manifest_blob_refs(
        &self,
        _coords: &ArtifactCoords,
        content: &mut dyn Read,
    ) -> DomainResult<Vec<ManifestBlobRef>> {
        let mut buf = Vec::new();
        content
            .take(MANIFEST_BLOB_REFS_MAX_BYTES)
            .read_to_end(&mut buf)
            .map_err(|e| DomainError::Invariant(format!("manifest re-read failed: {e}")))?;
        hort_domain::oci::manifest_blob_refs(&buf)
    }
}

#[cfg(test)]
mod tests {
    use hort_domain::entities::repository::RepositoryFormat;

    use super::*;

    fn handler() -> OciFormatHandler {
        OciFormatHandler
    }

    #[test]
    fn format_returns_oci() {
        assert_eq!(handler().format_key(), "oci");
    }

    #[test]
    fn normalize_name_is_identity() {
        // Mixed case, separators, nested paths — all must pass through
        // untouched. OCI image names are canonical as uploaded per the
        // distribution-spec name grammar.
        assert_eq!(handler().normalize_name("nginx"), "nginx");
        assert_eq!(handler().normalize_name("library/nginx"), "library/nginx");
        assert_eq!(
            handler().normalize_name("example.com/org/repo"),
            "example.com/org/repo"
        );
        assert_eq!(handler().normalize_name(""), "");
    }

    #[test]
    fn parse_download_path_returns_validation_error() {
        let err = handler()
            .parse_download_path("/v2/library/nginx/manifests/latest")
            .unwrap_err();
        match err {
            DomainError::Validation(msg) => {
                assert!(
                    msg.contains("oci handlers supply coords directly"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn classify_group_member_returns_none() {
        // Covers all OCI ingest shapes: a blob path, a manifest path,
        // an empty path. None must return group membership.
        let coords = ArtifactCoords {
            name: "library/nginx".into(),
            name_as_published: "library/nginx".into(),
            version: Some("sha256:abc".into()),
            path: "blobs/sha256:abc".into(),
            format: RepositoryFormat::Oci,
            metadata: serde_json::Value::Null,
        };
        assert!(handler()
            .classify_group_member(&coords, &coords.path)
            .is_none());

        let empty_path = ArtifactCoords {
            path: String::new(),
            ..coords.clone()
        };
        assert!(handler()
            .classify_group_member(&empty_path, &empty_path.path)
            .is_none());
    }

    /// OCI overrides `protocol_native_integrity` to `true` because the
    /// protocol embeds the digest in the request (see ADR 0006 §9).
    #[test]
    fn protocol_native_integrity_is_true() {
        assert!(handler().protocol_native_integrity());
    }

    /// OCI does not implement the `VersionDiscovery` capability group
    /// (issue #58) — `version_discovery()` inherits the `FormatHandler`
    /// accessor's `None` default. Structural replacement for the two
    /// former per-method tests (`extract_dependency_specs_inherits_default_empty_vec`
    /// / `resolve_range_max_inherits_default_none`), which lost their
    /// subject when those methods moved off `FormatHandler` onto
    /// `VersionDiscovery` — their reasoning is preserved here rather than
    /// discarded:
    ///
    /// - **No declared runtime deps.** OCI tags are exact pointers, not
    ///   version ranges; there is no notion of "declared runtime deps"
    ///   for an OCI image at this layer (honest-degradation rule: OCI
    ///   quarantine `503`s rather than substitute).
    /// - **No range concept.** OCI tags are not ranges, so there is
    ///   nothing for `resolve_range_max` to resolve against.
    ///
    /// Regression guard: OCI declaring `VersionDiscovery` participation
    /// would silently start enqueuing prefetch jobs for OCI artifacts,
    /// reintroducing the substitution behaviour the OCI handler explicitly
    /// rejects (see explanation/prefetch-pipeline.md).
    #[test]
    fn does_not_implement_version_discovery() {
        assert!(handler().version_discovery().is_none());
    }

    // ------------------------------------------------------------------
    // extract_oci_manifest_blob_refs (oci-membership-edge-backfill)
    // ------------------------------------------------------------------

    fn manifest_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "library/nginx".into(),
            name_as_published: "library/nginx".into(),
            version: None,
            path: "manifests/sha256:abc".into(),
            format: RepositoryFormat::Oci,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn extract_oci_manifest_blob_refs_parses_config_and_layers() {
        let hc = "c".repeat(64);
        let ha = "a".repeat(64);
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": { "digest": format!("sha256:{hc}") },
            "layers": [ { "digest": format!("sha256:{ha}") } ],
        })
        .to_string();
        let mut reader = body.as_bytes();
        let refs = handler()
            .extract_oci_manifest_blob_refs(&manifest_coords(), &mut reader)
            .expect("valid manifest parses");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].role, hort_domain::oci::ManifestBlobRole::Config);
        assert_eq!(refs[0].hash.as_ref(), hc.as_str());
        assert_eq!(refs[1].role, hort_domain::oci::ManifestBlobRole::Layer);
        assert_eq!(refs[1].hash.as_ref(), ha.as_str());
    }

    #[test]
    fn extract_oci_manifest_blob_refs_rejects_malformed_json() {
        let mut reader: &[u8] = b"not json";
        let err = handler()
            .extract_oci_manifest_blob_refs(&manifest_coords(), &mut reader)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn extract_oci_manifest_blob_refs_bounds_the_read() {
        // A body larger than the cap must not be fully buffered — the
        // truncated (and therefore invalid) JSON surfaces as a
        // Validation error, never an unbounded read.
        let oversized = vec![b'a'; (MANIFEST_BLOB_REFS_MAX_BYTES as usize) + 1024];
        let mut reader: &[u8] = &oversized;
        let err = handler()
            .extract_oci_manifest_blob_refs(&manifest_coords(), &mut reader)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    /// Every non-OCI-shaped call still parses through the trait's
    /// default-free OCI override (OCI is the only implementer that
    /// overrides this method) — an empty manifest (an index, or a
    /// config-less/layer-less object) yields `Ok(vec![])`, not an error.
    #[test]
    fn extract_oci_manifest_blob_refs_empty_object_is_empty() {
        let mut reader: &[u8] = b"{}";
        let refs = handler()
            .extract_oci_manifest_blob_refs(&manifest_coords(), &mut reader)
            .expect("empty object is a valid (empty) manifest");
        assert!(refs.is_empty());
    }
}
