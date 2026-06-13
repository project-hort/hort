//! OCI manifest streaming projector (see ADR 0026).
//!
//! Flat DTO over `serde_json::Deserializer::from_reader`. OCI
//! manifests are small and uniform — single image manifest ~1 KB,
//! image index ~5 KB, cosign / notary attached signatures ~200 KB
//! ceiling — so no custom Visitor or per-value cap is needed (the
//! storage-side backstop already bounds the whole body). The
//! projector extracts the four fields the layer-fetch orchestrator
//! needs: schema_version, media_type, config descriptor, and the
//! layers descriptor array.

use serde::Deserialize;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::upstream_proxy::MetadataProjector;

/// Projection of the four manifest fields the layer-fetch
/// orchestrator + the prefetch blob-warmer consume.
#[derive(Debug, Clone, Default)]
pub struct OciManifestProjection {
    pub schema_version: Option<u32>,
    pub media_type: Option<String>,
    pub config: Option<OciDescriptor>,
    pub layers: Vec<OciDescriptor>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    pub digest: Option<String>,
    pub size: Option<u64>,
}

/// Streaming projector. Stateless; manifests are small enough that
/// the storage-side backstop is the only meaningful guard.
#[derive(Debug, Default, Clone, Copy)]
pub struct OciManifestProjector;

impl OciManifestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl MetadataProjector for OciManifestProjector {
    type Projection = OciManifestProjection;
    fn project<R: std::io::Read>(self, reader: R) -> DomainResult<OciManifestProjection> {
        let wire: OciManifestWire = serde_json::from_reader(reader)
            .map_err(|e| DomainError::Validation(format!("oci manifest parse: {e}")))?;
        Ok(OciManifestProjection {
            schema_version: wire.schema_version,
            media_type: wire.media_type,
            config: wire.config,
            layers: wire.layers.unwrap_or_default(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct OciManifestWire {
    #[serde(rename = "schemaVersion")]
    schema_version: Option<u32>,
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    config: Option<OciDescriptor>,
    layers: Option<Vec<OciDescriptor>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn project(body: &[u8]) -> DomainResult<OciManifestProjection> {
        OciManifestProjector::new().project(Cursor::new(body))
    }

    #[test]
    fn empty_object_yields_empty_projection() {
        let p = project(b"{}").unwrap();
        assert!(p.config.is_none());
        assert!(p.layers.is_empty());
    }

    #[test]
    fn single_image_manifest_round_trip_config_and_layers() {
        // `digest` round-trips so upstream-checksum verification works
        // against the projection (see ADR 0006 §7).
        let body = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:aaaa",
                "size": 100
            },
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                 "digest": "sha256:bbbb", "size": 1000},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                 "digest": "sha256:cccc", "size": 2000}
            ]
        }"#;
        let p = project(body).unwrap();
        assert_eq!(p.schema_version, Some(2));
        assert_eq!(
            p.media_type.as_deref(),
            Some("application/vnd.oci.image.manifest.v1+json")
        );
        let cfg = p.config.as_ref().expect("config");
        assert_eq!(cfg.digest.as_deref(), Some("sha256:aaaa"));
        assert_eq!(cfg.size, Some(100));
        assert_eq!(p.layers.len(), 2);
        assert_eq!(p.layers[0].digest.as_deref(), Some("sha256:bbbb"));
        assert_eq!(p.layers[1].digest.as_deref(), Some("sha256:cccc"));
    }

    #[test]
    fn image_index_has_no_config_or_layers() {
        // Image indexes carry `manifests[*]` instead — the projector
        // collapses to absent config + empty layers (streaming projector
        // ignores fields it doesn't know).
        let body = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:abcd", "platform": {"architecture": "amd64"}}
            ]
        }"#;
        let p = project(body).unwrap();
        assert!(p.config.is_none());
        assert!(p.layers.is_empty());
    }

    #[test]
    fn unknown_root_fields_are_skipped() {
        let body = br#"{
            "schemaVersion": 2,
            "annotations": {"org.opencontainers.image.created": "2024-01-01"},
            "subject": {"digest": "sha256:dead"},
            "config": {"digest": "sha256:abcd"},
            "layers": []
        }"#;
        let p = project(body).unwrap();
        assert_eq!(p.schema_version, Some(2));
        assert_eq!(
            p.config.as_ref().unwrap().digest.as_deref(),
            Some("sha256:abcd")
        );
    }

    #[test]
    fn malformed_returns_validation() {
        let err = project(br#"{"schemaVersion": INVALID}"#).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }
}
