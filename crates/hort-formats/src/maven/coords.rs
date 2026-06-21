//! Maven coordinate identity, path build/parse, and publish-input
//! validation.
//!
//! All Maven-specific path logic lives here (design §5, §18 WIT-forward
//! containment). Pure domain code — zero I/O, no tracing.
//!
//! ## Identity
//!
//! A Maven `Artifact.name` is the **colon-joined** GA form
//! `"{groupId}:{artifactId}"` (e.g. `"com.google.guava:guava"`);
//! `version` is the Maven version string (`"31.1-jre"`, `"1.0-SNAPSHOT"`).
//! `name_as_published == name` — Maven is case-sensitive, so
//! `normalize_name` is identity (no folding).
//!
//! ## Stored path shape (default layout)
//!
//! `{groupId-with-dots-as-slashes}/{artifactId}/{version}/{filename}` —
//! the file's own filename is embedded verbatim (it is the real upstream
//! artifact filename, not an identity segment).
//!
//! ## Path-shape marker
//!
//! Three repo-relative path shapes are distinguished so the HTTP layer can
//! route. The shape is carried on
//! [`ArtifactCoords::metadata`](hort_domain::types::ArtifactCoords::metadata)
//! as a small JSON object `{"maven_path_kind": <kind>}` where `<kind>` is
//! one of [`MAVEN_KIND_FILE`], [`MAVEN_KIND_METADATA_A`], or
//! [`MAVEN_KIND_METADATA_V`]. The `metadata` field is the documented home
//! for per-request coordinate-derived attributes (see the
//! `ArtifactCoords` docstring), so this is exactly the right carrier — no
//! new typed field on the format-agnostic struct (§18).

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::types::ArtifactCoords;

use crate::maven::snapshot::{is_snapshot_version, parse_snapshot_timestamp};

/// Per-segment byte cap for a Maven coordinate component (`groupId`
/// segment, `artifactId`, `version`, `filename`). Real coordinates are far
/// shorter; the cap is a belt-and-braces guard against attacker-controlled
/// bytes flowing into log lines and downstream URL composition (mirrors
/// the cargo/pypi/npm name caps). 256 is generous over the longest real
/// Maven segments seen in the wild while still bounding pathological input.
pub const MAVEN_SEGMENT_MAX: usize = 256;

/// Marker value: the path addresses an artifact file or a checksum
/// sidecar of one (`…/{artifactId}/{version}/{filename}[.{sum}]`).
pub const MAVEN_KIND_FILE: &str = "file";

/// Marker value: the path addresses A-level (artifact-level)
/// `maven-metadata.xml` (`…/{artifactId}/maven-metadata.xml[.{sum}]`,
/// NO version segment). `version` is `None`.
pub const MAVEN_KIND_METADATA_A: &str = "metadata_a";

/// Marker value: the path addresses V-level (version-level) snapshot
/// `maven-metadata.xml`
/// (`…/{artifactId}/{version}/maven-metadata.xml[.{sum}]` where `version`
/// ends `-SNAPSHOT`). `version` is `Some(version)`.
pub const MAVEN_KIND_METADATA_V: &str = "metadata_v";

/// JSON key under which the path-shape marker is stored on
/// [`ArtifactCoords::metadata`].
pub const MAVEN_PATH_KIND_KEY: &str = "maven_path_kind";

/// The four checksum-sidecar extensions Maven clients fetch/publish.
/// `.md5`/`.sha1` are the historic pair; `.sha256`/`.sha512` are the
/// per-publisher stronger digests. A `<file>.{ext}` request addresses the
/// digest of the stored `<file>`, never a distinct stored object.
pub const SIDECAR_EXTENSIONS: [&str; 4] = ["sha1", "md5", "sha256", "sha512"];

/// The Maven metadata document filename (default layout).
pub const MAVEN_METADATA_FILENAME: &str = "maven-metadata.xml";

/// Build the JSON path-shape marker object for one of the `MAVEN_KIND_*`
/// constants.
fn kind_marker(kind: &str) -> serde_json::Value {
    serde_json::json!({ MAVEN_PATH_KIND_KEY: kind })
}

/// Read the `maven_path_kind` marker off a coords' `metadata`, if present.
/// Returns `None` when the field is absent or not the expected shape
/// (e.g. group coords, whose `metadata` is canonicalised to `Null`).
#[must_use]
pub fn path_kind(coords: &ArtifactCoords) -> Option<&str> {
    coords
        .metadata
        .get(MAVEN_PATH_KIND_KEY)
        .and_then(serde_json::Value::as_str)
}

/// The colon-joined GA identity name for a `(groupId, artifactId)` pair.
#[must_use]
pub fn ga_name(group_id: &str, artifact_id: &str) -> String {
    format!("{group_id}:{artifact_id}")
}

/// Split a colon-joined GA `name` into `(groupId, artifactId)`.
///
/// Maven coordinates use exactly one `:` between groupId and artifactId in
/// the GA form. A name without a `:`, or with the artifact/group half
/// empty, is a structural error.
pub fn split_ga(name: &str) -> DomainResult<(&str, &str)> {
    let (group, artifact) = name.split_once(':').ok_or_else(|| {
        DomainError::Validation(
            "maven.coordinate: name must be the colon-joined groupId:artifactId form".to_string(),
        )
    })?;
    if group.is_empty() || artifact.is_empty() {
        return Err(DomainError::Validation(
            "maven.coordinate: groupId and artifactId must both be non-empty".to_string(),
        ));
    }
    Ok((group, artifact))
}

/// Validate a Maven coordinate's components before any persistence side
/// effect (publish path; mirrors `validate_cargo_name`).
///
/// Rejects: path traversal (`..` as a whole component or embedded), control
/// characters (CR/LF/NUL and any other ASCII control byte), over-length
/// segments (each capped at [`MAVEN_SEGMENT_MAX`]), and empty
/// groupId/artifactId/version.
///
/// `version` is `None` for an A-level metadata request (no version
/// segment) — the version-empty check is skipped in that case, but every
/// other rule still applies to `group_id`/`artifact_id`.
///
/// Error messages are prefixed `maven.coordinate:` and **never** echo the
/// offending bytes (log-pollution risk — the input can be
/// attacker-controlled).
pub fn validate_maven_coordinate(
    group_id: &str,
    artifact_id: &str,
    version: Option<&str>,
) -> DomainResult<()> {
    validate_component("groupId", group_id, true)?;
    validate_component("artifactId", artifact_id, false)?;
    if let Some(v) = version {
        validate_component("version", v, false)?;
    }
    Ok(())
}

/// Validate one coordinate component.
///
/// `dotted` is `true` for the groupId, whose segments are `.`-separated
/// (each dot-segment is validated as if it were its own path component, so
/// `com..evil` and an over-long sub-segment are both caught). For the
/// non-dotted components (artifactId, version) the whole string is one
/// segment.
fn validate_component(label: &str, value: &str, dotted: bool) -> DomainResult<()> {
    if value.is_empty() {
        return Err(DomainError::Validation(format!(
            "maven.coordinate: {label} is empty"
        )));
    }
    // Control bytes (CR/LF/NUL + every other ASCII control) anywhere in the
    // raw value, before any splitting.
    if value.bytes().any(|b| b.is_ascii_control()) {
        return Err(DomainError::Validation(format!(
            "maven.coordinate: {label} contains a control character"
        )));
    }
    // A `/` inside groupId is fine only as the dotted→slashed transform's
    // own doing — but here groupId is still in DOT form, so a literal slash
    // is a traversal/injection attempt. artifactId/version must never carry
    // a path separator.
    if value.contains('/') {
        return Err(DomainError::Validation(format!(
            "maven.coordinate: {label} contains a path separator"
        )));
    }
    // A literal backslash is never legitimate in a Maven coordinate component;
    // reject it as a path separator (defense-in-depth — harmless on POSIX, and
    // gated by the filename-prefix match, but cheap insurance against a
    // Windows-style traversal/injection attempt). Never echo the bytes.
    if value.contains('\\') {
        return Err(DomainError::Validation(format!(
            "maven.coordinate: {label} contains a path separator"
        )));
    }
    let segments: Vec<&str> = if dotted {
        value.split('.').collect()
    } else {
        vec![value]
    };
    for seg in segments {
        if seg.is_empty() {
            // An empty dot-segment (`com..evil`, leading/trailing dot)
            // collapses to a `//` in the slashed path — reject.
            return Err(DomainError::Validation(format!(
                "maven.coordinate: {label} has an empty segment"
            )));
        }
        if seg == ".." || seg == "." {
            return Err(DomainError::Validation(format!(
                "maven.coordinate: {label} contains a path-traversal segment"
            )));
        }
        if seg.len() > MAVEN_SEGMENT_MAX {
            return Err(DomainError::Validation(format!(
                "maven.coordinate: {label} segment exceeds {MAVEN_SEGMENT_MAX}-byte cap"
            )));
        }
    }
    Ok(())
}

/// Validate a filename segment (the last path component of a file request).
///
/// A filename must be non-empty, control-char-free, carry no path
/// separator, contain no traversal component, and be within the segment
/// cap. Never echoes the bytes.
fn validate_filename(filename: &str) -> DomainResult<()> {
    if filename.is_empty() {
        return Err(DomainError::Validation(
            "maven.coordinate: filename is empty".to_string(),
        ));
    }
    if filename.bytes().any(|b| b.is_ascii_control()) {
        return Err(DomainError::Validation(
            "maven.coordinate: filename contains a control character".to_string(),
        ));
    }
    if filename.contains('/') {
        return Err(DomainError::Validation(
            "maven.coordinate: filename contains a path separator".to_string(),
        ));
    }
    // Reject a literal backslash too (defense-in-depth; see `validate_component`).
    if filename.contains('\\') {
        return Err(DomainError::Validation(
            "maven.coordinate: filename contains a path separator".to_string(),
        ));
    }
    if filename == ".." || filename == "." {
        return Err(DomainError::Validation(
            "maven.coordinate: filename is a path-traversal segment".to_string(),
        ));
    }
    if filename.len() > MAVEN_SEGMENT_MAX {
        return Err(DomainError::Validation(format!(
            "maven.coordinate: filename exceeds {MAVEN_SEGMENT_MAX}-byte cap"
        )));
    }
    Ok(())
}

/// Build the stored logical path for a Maven file.
///
/// `name` is the colon-joined GA identity; `filename` is REQUIRED (a Maven
/// path is always file-addressed — there is no name+version→filename
/// derivation as for cargo/npm). Produces
/// `{group-with-slashes}/{artifactId}/{version}/{filename}` with `filename`
/// verbatim.
pub fn build_logical_path(
    name: &str,
    version: &str,
    filename: Option<&str>,
) -> DomainResult<String> {
    let filename = filename.ok_or_else(|| {
        DomainError::Validation(
            "maven.coordinate: filename is required to build a Maven artifact path".to_string(),
        )
    })?;
    let (group_id, artifact_id) = split_ga(name)?;
    validate_maven_coordinate(group_id, artifact_id, Some(version))?;
    validate_filename(filename)?;
    let group_path = group_id.replace('.', "/");
    Ok(format!("{group_path}/{artifact_id}/{version}/{filename}"))
}

/// Strip a trailing checksum-sidecar extension from `filename`, returning
/// `(base_filename, Some(ext))` when present, else `(filename, None)`.
///
/// `ext` is the sidecar algorithm without the leading dot (`"sha1"`, …).
#[must_use]
pub fn strip_sidecar_ext(filename: &str) -> (&str, Option<&str>) {
    for ext in SIDECAR_EXTENSIONS {
        if let Some(base) = filename.strip_suffix(ext).and_then(|s| s.strip_suffix('.')) {
            // Guard against an empty base (`.sha1` alone) — that is not a
            // sidecar OF anything, treat it as a plain (odd) filename.
            if !base.is_empty() {
                return (base, Some(ext));
            }
        }
    }
    (filename, None)
}

/// Parse a Maven checksum-sidecar body to a bare lowercase hex digest.
///
/// Maven `.sha1`/`.sha256`/`.sha512`/`.md5` sidecars are a **bare** hex
/// digest (e.g. `da39a3ee5e6b4b0d3255bfef95601890afd80709`). Some publishers
/// emit the GNU coreutils shape (`<hex>  <filename>`), so this tolerates a
/// trailing whitespace-delimited suffix: it takes the **first** whitespace-
/// delimited token and lowercases it.
///
/// Returns `Err(DomainError::Validation)` on an empty / whitespace-only body
/// (no soft-fail — ADR 0006). Shape validation (hex length per algorithm,
/// hex-only) is the caller's job via
/// [`UpstreamPublishedChecksum::new`](hort_domain::types::checksum::UpstreamPublishedChecksum::new);
/// this helper only isolates and lowercases the digest token.
///
/// Lives in the format layer so both the serve-path negotiation
/// (`hort-http-maven`) and the trait-method floor
/// ([`parse_upstream_checksum`](crate::maven::MavenFormatHandler)) share one
/// parser.
pub fn parse_sidecar_hex(body: &str) -> DomainResult<String> {
    let token = body.split_whitespace().next().ok_or_else(|| {
        DomainError::Validation("maven.sidecar: checksum body is empty".to_string())
    })?;
    if token.is_empty() {
        return Err(DomainError::Validation(
            "maven.sidecar: checksum body is empty".to_string(),
        ));
    }
    Ok(token.to_ascii_lowercase())
}

/// Whether `base_filename` is a plausible file for `(artifact_id, version)`.
///
/// A release/classifier/timestamped-snapshot artifact filename starts with
/// `{artifactId}-{version}` for a release/V-level-base request, OR — for a
/// SNAPSHOT — with `{artifactId}-{snapshotBase}` where the file carries the
/// timestamped form. We accept the filename when it begins with
/// `{artifactId}-` AND, after that prefix, the remainder begins with the
/// requested `version` OR (when the requested version is `X-SNAPSHOT`) with
/// the snapshot BASE `X` followed by a `-` (the timestamped suffix).
fn filename_matches_coords(base_filename: &str, artifact_id: &str, version: &str) -> bool {
    let prefix = format!("{artifact_id}-");
    let Some(rest) = base_filename.strip_prefix(&prefix) else {
        return false;
    };
    // Exact-version match: `{artifactId}-{version}...` (release, classifier,
    // and the literal `-SNAPSHOT` unresolved form).
    if rest == version
        || rest.starts_with(&format!("{version}."))
        || rest.starts_with(&format!("{version}-"))
    {
        return true;
    }
    // Timestamped SNAPSHOT: the requested version is `X-SNAPSHOT`, the file
    // is `{artifactId}-X-{yyyyMMdd.HHmmss}-{N}[-classifier].ext`. Strip the
    // `-SNAPSHOT` suffix to get the base `X`, then require the remainder to
    // begin `X-` and parse as a timestamped build.
    if let Some(base) = version.strip_suffix("-SNAPSHOT") {
        let ts_prefix = format!("{base}-");
        if let Some(after_base) = rest.strip_prefix(&ts_prefix) {
            // `after_base` should start with a parseable `yyyyMMdd.HHmmss-N`.
            if parse_snapshot_timestamp(after_base).is_some() {
                return true;
            }
        }
    }
    false
}

/// Parse a repo-relative Maven path (the `:repo_key` prefix already
/// stripped) into [`ArtifactCoords`], recognising the three path shapes and
/// tagging the shape on `metadata` (see the module docstring).
///
/// This is the exact inverse of [`build_logical_path`] for the file shape.
pub fn parse_download_path(tail: &str) -> DomainResult<ArtifactCoords> {
    let tail = tail.strip_prefix('/').unwrap_or(tail);
    if tail.is_empty() {
        return Err(DomainError::Validation(
            "maven.coordinate: empty path".to_string(),
        ));
    }
    let parts: Vec<&str> = tail.split('/').collect();
    // A Maven path is at minimum `{group}/{artifactId}/maven-metadata.xml`
    // (A-level) → 3 segments. Anything shorter cannot carry a groupId.
    if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(DomainError::Validation(
            "maven.coordinate: path too short or has an empty segment".to_string(),
        ));
    }

    let last = parts[parts.len() - 1];

    // --- maven-metadata.xml shapes ----------------------------------------
    // The last segment is `maven-metadata.xml` or a sidecar of it.
    let (last_base, _last_sidecar) = strip_sidecar_ext(last);
    if last_base == MAVEN_METADATA_FILENAME {
        return parse_metadata_path(&parts, tail);
    }

    // --- file (or sidecar of a file) shape --------------------------------
    // `{g1}/.../{artifactId}/{version}/{filename}` — parse from the RIGHT.
    // filename = last; version = 2nd-to-last; artifactId = 3rd-to-last;
    // groupId = the rest joined with '.'. Need at least 4 segments
    // (one group segment + artifactId + version + filename).
    if parts.len() < 4 {
        return Err(DomainError::Validation(
            "maven.coordinate: file path needs groupId/artifactId/version/filename".to_string(),
        ));
    }
    let filename = last;
    let version = parts[parts.len() - 2];
    let artifact_id = parts[parts.len() - 3];
    let group_id = parts[..parts.len() - 3].join(".");

    validate_maven_coordinate(&group_id, artifact_id, Some(version))?;
    validate_filename(filename)?;

    // The filename must belong to (artifactId, version): either the file
    // itself or a checksum sidecar of such a file.
    let (file_base, _sidecar) = strip_sidecar_ext(filename);
    if !filename_matches_coords(file_base, artifact_id, version) {
        return Err(DomainError::Validation(
            "maven.coordinate: filename does not match {artifactId}-{version}".to_string(),
        ));
    }

    let name = ga_name(&group_id, artifact_id);
    Ok(ArtifactCoords {
        name,
        name_as_published: ga_name(&group_id, artifact_id),
        version: Some(version.to_string()),
        path: tail.to_string(),
        format: RepositoryFormat::Maven,
        metadata: kind_marker(MAVEN_KIND_FILE),
    })
}

/// Parse a `maven-metadata.xml[.{sum}]` path into A-level or V-level coords.
///
/// Disambiguation rule (design §5): the segment immediately before
/// `maven-metadata.xml` is the **version** (V-level) iff it ends with
/// `-SNAPSHOT`; otherwise it is the **artifactId** (A-level).
fn parse_metadata_path(parts: &[&str], tail: &str) -> DomainResult<ArtifactCoords> {
    // `parts` ends with the metadata (or its sidecar) filename. The segment
    // before it is either the version (V-level) or the artifactId (A-level).
    let before_meta = parts[parts.len() - 2];

    if is_snapshot_version(before_meta) {
        // V-level: `{g1}/.../{artifactId}/{version}/maven-metadata.xml`.
        // Need at least 4 segments: one group + artifactId + version + meta.
        if parts.len() < 4 {
            return Err(DomainError::Validation(
                "maven.coordinate: V-level metadata needs groupId/artifactId/version".to_string(),
            ));
        }
        let version = before_meta;
        let artifact_id = parts[parts.len() - 3];
        let group_id = parts[..parts.len() - 3].join(".");
        validate_maven_coordinate(&group_id, artifact_id, Some(version))?;
        let name = ga_name(&group_id, artifact_id);
        return Ok(ArtifactCoords {
            name: name.clone(),
            name_as_published: name,
            version: Some(version.to_string()),
            path: tail.to_string(),
            format: RepositoryFormat::Maven,
            metadata: kind_marker(MAVEN_KIND_METADATA_V),
        });
    }

    // A-level: `{g1}/.../{artifactId}/maven-metadata.xml`. The segment
    // before the metadata file is the artifactId; the rest is the groupId.
    // Need at least 3 segments: one group + artifactId + meta.
    let artifact_id = before_meta;
    let group_id = parts[..parts.len() - 2].join(".");
    validate_maven_coordinate(&group_id, artifact_id, None)?;
    let name = ga_name(&group_id, artifact_id);
    Ok(ArtifactCoords {
        name: name.clone(),
        name_as_published: name,
        version: None,
        path: tail.to_string(),
        format: RepositoryFormat::Maven,
        metadata: kind_marker(MAVEN_KIND_METADATA_A),
    })
}
