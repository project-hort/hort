//! Canonical `ArtifactCoords` builders for OCI artifacts.
//!
//! The OCI handler layer builds coords explicitly rather than calling
//! `FormatHandler::parse_download_path` (`OciFormatHandler::parse_download_path`
//! returns a validation error and is never on the hot path). These helpers
//! keep the mapping from `(image-name, digest)` to `ArtifactCoords` in one
//! place so blob-pull, manifest-pull, and push paths all agree on the path
//! layout.
//!
//! ## Path layout
//!
//! - **Blob** — `path = "blobs/sha256:<hex>"`. Matches the OCI
//!   Distribution URL (`/v2/<name>/blobs/sha256:<hex>`) minus the
//!   leading `/v2/<name>/`. Stored as the `Artifact.path` column so
//!   `ArtifactRepository::find_by_path(repo, &path)` is a single indexed
//!   lookup per client request.
//! - **Manifest** — `path = "manifests/sha256:<hex>"`. Same shape as
//!   blobs but with a distinct prefix so the same content hash can hold
//!   both a manifest and a blob artifact under the same name without
//!   colliding on the `(repository_id, path)` UNIQUE constraint. A
//!   digest-by-ref manifest GET (`…/manifests/sha256:<hex>`) resolves
//!   directly by path; a tag GET resolves the tag to a hash via
//!   `RefUseCase::get(…)` and then hits the same manifest coords by
//!   hash.
//!
//! ## Identity fields
//!
//! - `name`, `name_as_published` — the raw image name (e.g.
//!   `library/nginx`). OCI image names are canonical as uploaded (see
//!   `OciFormatHandler::normalize_name` — identity function), so both
//!   fields carry the same value.
//! - `version = None` — OCI artifacts are addressable by content hash,
//!   not version string. A tag pointing at the manifest is a
//!   `MutableRef`, not a version on the artifact.
//! - `format = RepositoryFormat::Oci` — matches the
//!   repository's format and keeps cross-format queries (group lookups,
//!   metric labels) honest.
//! - `metadata = Value::Null` — `ArtifactCoords.metadata` is the output
//!   of `FormatHandler::parse_download_path`, which OCI does not use;
//!   payload metadata (media-type, subject digest) travels on
//!   `IngestRequest::payload_metadata` at ingest time, not on coords.

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::types::{ArtifactCoords, ContentHash};

/// Build `ArtifactCoords` for an OCI blob addressed by `(name, digest)`.
///
/// The `path` field lays out as `blobs/sha256:<hex>`, so the coords
/// can feed `ArtifactRepository::find_by_path(repo_id, &coords.path)`
/// directly in the pull handler.
pub fn oci_blob_coords(name: &str, digest: &ContentHash) -> ArtifactCoords {
    ArtifactCoords {
        name: name.to_string(),
        name_as_published: name.to_string(),
        version: None,
        path: format!("blobs/sha256:{}", digest.as_ref()),
        format: RepositoryFormat::Oci,
        metadata: serde_json::Value::Null,
    }
}

/// Build `ArtifactCoords` for an OCI manifest addressed by
/// `(name, digest)`.
///
/// Distinct prefix from [`oci_blob_coords`] so the same content hash can
/// hold both a manifest row and a blob row under the same image name
/// without colliding on the `(repository_id, path)` UNIQUE constraint —
/// legitimate for re-usable config blobs whose bytes happen to match a
/// manifest in some pathological test corpus, and load-bearing for
/// Item 12's manifest ingest path.
pub fn oci_manifest_coords(name: &str, digest: &ContentHash) -> ArtifactCoords {
    ArtifactCoords {
        name: name.to_string(),
        name_as_published: name.to_string(),
        version: None,
        path: format!("manifests/sha256:{}", digest.as_ref()),
        format: RepositoryFormat::Oci,
        metadata: serde_json::Value::Null,
    }
}

/// Build `ArtifactCoords` for the OCI manifest-group root addressed by
/// `(name, manifest_digest)`.
///
/// §2.14.1 contract: `path` is EMPTY (`String::new()`) and `metadata` is
/// `Value::Null`. These zero values are load-bearing — the cross-format
/// `(repository_id, coords_json)` UNIQUE index canonicalises the coords
/// row at INSERT time, so a non-zero `path` or non-Null `metadata` here
/// would register a distinct group for every manifest PUT and break
/// idempotence on re-push.
///
/// The identity fields (`name`, `name_as_published`, `version`) mirror
/// [`oci_manifest_coords`] so a manifest artifact and its group root
/// share the `(name, version)` pair and can be joined back during read.
/// `version = None` because OCI groups are keyed by content hash on
/// their primary member's descriptor, carried in the group's member
/// coords, not on the group root itself.
pub fn oci_group_coords(name: &str, _manifest_digest: &ContentHash) -> ArtifactCoords {
    ArtifactCoords {
        name: name.to_string(),
        name_as_published: name.to_string(),
        version: None,
        // MUST be empty — §2.14.1 zero-path contract.
        path: String::new(),
        format: RepositoryFormat::Oci,
        // MUST be Value::Null — §2.14.1 zero-metadata contract.
        metadata: serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn sample_hash() -> ContentHash {
        SAMPLE_HEX.parse().unwrap()
    }

    #[test]
    fn blob_coords_path_is_blobs_sha256_hex() {
        let c = oci_blob_coords("library/nginx", &sample_hash());
        assert_eq!(c.path, format!("blobs/sha256:{SAMPLE_HEX}"));
    }

    #[test]
    fn blob_coords_name_fields_match_input_verbatim() {
        // Identity normalisation (§2.14.1) — the same string goes in
        // both `name` and `name_as_published` so drift-resilience
        // lookups stay consistent with OCI's grammar being canonical.
        let c = oci_blob_coords("Library/NGINX", &sample_hash());
        assert_eq!(c.name, "Library/NGINX");
        assert_eq!(c.name_as_published, "Library/NGINX");
    }

    #[test]
    fn blob_coords_version_is_none_and_metadata_is_null() {
        let c = oci_blob_coords("library/nginx", &sample_hash());
        assert_eq!(c.version, None);
        assert!(c.metadata.is_null());
    }

    #[test]
    fn blob_coords_format_is_oci() {
        let c = oci_blob_coords("x", &sample_hash());
        match c.format {
            RepositoryFormat::Oci => {}
            other => panic!("expected RepositoryFormat::Oci, got {other:?}"),
        }
    }

    #[test]
    fn manifest_coords_path_is_manifests_sha256_hex() {
        let c = oci_manifest_coords("library/nginx", &sample_hash());
        assert_eq!(c.path, format!("manifests/sha256:{SAMPLE_HEX}"));
    }

    #[test]
    fn group_coords_path_is_empty() {
        // §2.14.1: the cross-format `(repository_id, coords_json)`
        // UNIQUE index depends on this being the exact empty string.
        // A non-empty path here would register a distinct group per
        // manifest PUT and break the idempotence-on-re-push contract.
        let c = oci_group_coords("library/nginx", &sample_hash());
        assert_eq!(c.path, "");
    }

    #[test]
    fn group_coords_metadata_is_null() {
        let c = oci_group_coords("library/nginx", &sample_hash());
        assert!(
            c.metadata.is_null(),
            "group metadata must be Null (§2.14.1)"
        );
    }

    #[test]
    fn group_coords_name_matches_input() {
        let c = oci_group_coords("library/nginx", &sample_hash());
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.name_as_published, "library/nginx");
    }

    #[test]
    fn group_coords_format_is_oci() {
        let c = oci_group_coords("x", &sample_hash());
        match c.format {
            RepositoryFormat::Oci => {}
            other => panic!("expected RepositoryFormat::Oci, got {other:?}"),
        }
    }

    #[test]
    fn group_coords_version_is_none() {
        // Groups are keyed by name, not by version — manifest digest
        // travels on the group's member coords, not the root.
        let c = oci_group_coords("x", &sample_hash());
        assert!(c.version.is_none());
    }

    #[test]
    fn group_coords_same_for_same_name_different_digest() {
        // Critical for idempotence: two PUTs to the same image name but
        // different manifest digests must resolve to the SAME group
        // coords. The manifest digest is carried on group members, not
        // on the group root.
        let hash_a: ContentHash = SAMPLE_HEX.parse().unwrap();
        let hash_b: ContentHash = "a".repeat(64).parse().unwrap();
        let a = oci_group_coords("library/nginx", &hash_a);
        let b = oci_group_coords("library/nginx", &hash_b);
        assert_eq!(a.name, b.name);
        assert_eq!(a.path, b.path);
        assert_eq!(a.version, b.version);
    }

    #[test]
    fn blob_and_manifest_paths_never_collide_for_same_hash() {
        // Load-bearing: both rows are keyed by `(repository_id, path)`
        // in the adapter — if the prefixes ever collapsed, a legitimate
        // blob+manifest pair sharing bytes (pathological but legal)
        // would violate the UNIQUE constraint. Regression guard.
        let b = oci_blob_coords("x", &sample_hash());
        let m = oci_manifest_coords("x", &sample_hash());
        assert_ne!(b.path, m.path);
        assert!(b.path.starts_with("blobs/"));
        assert!(m.path.starts_with("manifests/"));
    }
}
