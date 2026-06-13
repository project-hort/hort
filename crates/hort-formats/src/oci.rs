// OCI manifest streaming projector (see ADR 0026).
pub mod projection;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::format_handler::{FormatHandler, GroupMembership};
use hort_domain::types::ArtifactCoords;

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

    /// OCI inherits the trait-default empty Vec for
    /// `extract_dependency_specs`. OCI tags are exact pointers, not
    /// version ranges; there is no notion of "declared runtime deps" for
    /// an OCI image at this layer (honest-degradation rule: OCI quarantine
    /// `503`s rather than substitute). Regression guard: a stray override
    /// here would silently start enqueuing prefetch jobs for OCI artifacts,
    /// reintroducing the substitution behaviour the OCI handler explicitly
    /// rejects (see explanation/prefetch-pipeline.md).
    #[test]
    fn extract_dependency_specs_inherits_default_empty_vec() {
        let specs = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(b"any bytes"))
            .expect("Ok");
        assert!(specs.is_empty());
    }

    /// OCI inherits the trait-default `None` for `resolve_range_max`.
    /// OCI tags are not ranges. Same rationale as the empty-vec test
    /// above.
    #[test]
    fn resolve_range_max_inherits_default_none() {
        let out = handler()
            .resolve_range_max("anything", &["sha256:abc"])
            .expect("Ok");
        assert!(out.is_none());
    }
}
