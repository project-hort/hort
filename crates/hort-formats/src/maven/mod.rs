//! Maven / Gradle format handler — pure coordinate/identity/group logic.
//!
//! Compiled-in Rust struct behind the `FormatHandler` trait boundary
//! (design §5–§7, §18; ADR 0005 MultiFileArtifact capability realised via
//! the `classify_group_member`/`ArtifactGroup` push model). Pure domain
//! code: zero I/O, no tracing, no sqlx/reqwest/axum.
//!
//! This module covers the identity + path + group + snapshot-resolution
//! surface (backlog Item 4). The HTTP crate (`hort-http-maven`), metadata
//! XML builder, on-demand sidecars, and pull-through are later items.
//!
//! ## What Maven overrides on the trait
//!
//! - [`FormatHandler::format_key`] → `"maven"`.
//! - [`FormatHandler::normalize_name`] → identity (Maven is case-sensitive;
//!   no folding). `collision_key` stays at the default `None`.
//! - [`FormatHandler::build_artifact_logical_path`] / `parse_download_path`
//!   → the GA:V + filename ⇄ repo-path inverse pair (see [`coords`]).
//! - [`FormatHandler::classify_group_member`] → role assignment for content
//!   files (pom/jar/sources/javadoc/module), `None` for sidecars + metadata.
//! - [`FormatHandler::resolve_mutable_version`] → SNAPSHOT timestamped-build
//!   resolution (see [`snapshot`]).
//!
//! Everything else (upstream-pull metadata, dependency extraction, prefetch
//! URL composition, SBOM) is inherited at the trait default and wired by
//! later/deferred items.

pub mod coords;
pub mod metadata;
pub mod snapshot;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::format_handler::{FormatHandler, GroupMembership};
use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};
use hort_domain::types::ArtifactCoords;

pub use coords::{
    build_logical_path, parse_download_path, parse_sidecar_hex, validate_maven_coordinate,
    MAVEN_KIND_FILE, MAVEN_KIND_METADATA_A, MAVEN_KIND_METADATA_V, MAVEN_PATH_KIND_KEY,
};

/// Maven (and Gradle) format handler.
///
/// One handler serves both `RepositoryFormat::Maven` and
/// `RepositoryFormat::Gradle` — Gradle publishes to Maven-layout repos with
/// the identical wire protocol (the only Gradle-specific addition is the
/// `.module` GMM member, role `module`, handled by [`classify_role`]).
pub struct MavenFormatHandler;

/// Classify a content filename into a group-member role, or `None` if it is
/// not a real content file (checksum sidecar or `maven-metadata.xml`).
///
/// Roles (design §6): `pom`, `jar`, `sources`, `javadoc`, `module` (Gradle
/// GMM). Classification is by the filename's classifier/extension:
/// - `*-sources.jar` → `sources`
/// - `*-javadoc.jar` → `javadoc`
/// - `*.module` → `module`
/// - `*.jar` (no recognised classifier) → `jar`
/// - `*.pom` → `pom`
/// - anything else (other extensions, e.g. `.war`, `.aar`) → `jar`
///   (treated as the primary binary artifact for grouping purposes)
///
/// Returns `None` for checksum sidecars (`.sha1/.md5/.sha256/.sha512`) and
/// for `maven-metadata.xml` — neither is a group member.
fn classify_role(filename: &str) -> Option<&'static str> {
    // Checksum sidecars are not group members.
    let (base, sidecar) = coords::strip_sidecar_ext(filename);
    if sidecar.is_some() {
        return None;
    }
    // maven-metadata.xml (any sidecar already stripped) is not a member.
    if base == coords::MAVEN_METADATA_FILENAME {
        return None;
    }

    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".module") {
        return Some("module");
    }
    if lower.ends_with("-sources.jar") {
        return Some("sources");
    }
    if lower.ends_with("-javadoc.jar") {
        return Some("javadoc");
    }
    if lower.ends_with(".pom") {
        return Some("pom");
    }
    // The main binary artifact: `.jar` and any other packaging
    // (`.war`/`.aar`/`.ear`/…) all classify as the binary role for grouping.
    Some("jar")
}

impl MavenFormatHandler {
    /// The group's primary role is the binary `jar`.
    ///
    /// **is_primary choice (design §6):** `is_primary = true` ONLY for the
    /// `jar` role. The design permits marking `pom` primary "when packaging
    /// is pom", but packaging is NOT knowable from the path alone — it lives
    /// inside the POM XML, which this pure path-level handler does not parse.
    /// So for v1 a `pom` is never primary from the path; a pom-only artifact
    /// (parent POM, BOM) simply has no primary member set on its group,
    /// which the `ArtifactGroup` aggregate tolerates (`primary_role` stays
    /// unset until a `jar` arrives). Marking pom primary unconditionally
    /// would mis-set `primary_role = "pom"` for the common jar+pom artifact
    /// whenever the pom is ingested first (PUT order is not guaranteed,
    /// design §5), then conflict when the jar arrives also claiming primary.
    /// Path-driven packaging detection is deferred to a POM-parsing item.
    fn is_primary_role(role: &str) -> bool {
        role == "jar"
    }
}

impl FormatHandler for MavenFormatHandler {
    fn format_key(&self) -> &str {
        "maven"
    }

    /// Parse a repo-relative Maven path (the `:repo_key` prefix already
    /// stripped by the HTTP layer) into coordinates, tagging the path shape
    /// on `metadata` (`maven_path_kind`). See [`coords::parse_download_path`].
    fn parse_download_path(&self, path: &str) -> DomainResult<ArtifactCoords> {
        parse_download_path(path)
    }

    /// Build the stored logical path for a Maven file. `filename` is
    /// REQUIRED — a Maven path is always file-addressed. See
    /// [`coords::build_logical_path`].
    fn build_artifact_logical_path(
        &self,
        name: &str,
        version: &str,
        filename: Option<&str>,
    ) -> DomainResult<String> {
        build_logical_path(name, version, filename)
    }

    /// Identity normalisation — Maven is case-sensitive, so this is the
    /// identity function (no case folding, no separator folding). The
    /// `groupId:artifactId` name is the wire contract verbatim.
    fn normalize_name(&self, name: &str) -> String {
        name.to_string()
    }

    /// Classify an uploaded Maven file as a group member.
    ///
    /// Returns `Some(GroupMembership)` for content files (pom/jar/sources/
    /// javadoc/module), `None` for checksum sidecars and `maven-metadata.xml`.
    ///
    /// **Canonicalisation contract:** the returned `group_coords` carry ONLY
    /// the identity fields (`name`, `name_as_published`, `version`,
    /// `format`) with `path` empty and `metadata` Null. For a SNAPSHOT the
    /// group's version is the **base** `X-SNAPSHOT` (NOT the timestamped
    /// form) even though the file path uses the timestamped filename — so all
    /// timestamped builds of one snapshot collapse into one group.
    fn classify_group_member(
        &self,
        coords: &ArtifactCoords,
        path: &str,
    ) -> Option<GroupMembership> {
        // Only file-shaped requests can be group members. A metadata path
        // (A- or V-level) is never a member; its marker says so.
        if let Some(kind) = coords::path_kind(coords) {
            if kind != MAVEN_KIND_FILE {
                return None;
            }
        }
        // The role classification is driven by the filename (last segment of
        // the stored path). Prefer the explicit `path` argument (the stored
        // logical path) over `coords.path`.
        let filename = path.rsplit('/').next().unwrap_or(path);
        let role = classify_role(filename)?;

        // Group version = the coords version, canonicalised to the SNAPSHOT
        // base. coords.version for a file is the directory's version segment,
        // which is already the base `X-SNAPSHOT` for snapshots (the stored
        // path is `.../X-SNAPSHOT/foo-X-{ts}-N.jar`), so it is already the
        // base. Carry it through unchanged.
        let group_version = coords.version.clone();

        let group_coords = ArtifactCoords {
            name: coords.name.clone(),
            name_as_published: coords.name_as_published.clone(),
            version: group_version,
            path: String::new(),
            format: coords.format.clone(),
            metadata: serde_json::Value::Null,
        };

        Some(GroupMembership {
            group_coords,
            role: role.to_string(),
            is_primary: Self::is_primary_role(role),
        })
    }

    /// Resolve an unresolved SNAPSHOT request path to the highest
    /// timestamped build matching the requested `(classifier, extension)`.
    /// `Ok(None)` for a non-mutable request or no match. See
    /// [`snapshot::resolve_mutable_version`].
    fn resolve_mutable_version(
        &self,
        requested_path: &str,
        available_paths: &[&str],
    ) -> DomainResult<Option<String>> {
        Ok(snapshot::resolve_mutable_version(
            requested_path,
            available_paths,
        ))
    }

    /// The SHA-1 **floor** sidecar path for a Maven artifact — the single
    /// path the generic prefetch-leaf consumer fetches (design §8, ADR 0033).
    ///
    /// Returns `Some("{coords.path}.sha1")`: Maven Central (and every Maven
    /// layout repo) guarantees a `.sha1` sidecar on every artifact, so the
    /// floor is always present where `.sha256`/`.sha512` may not be. The
    /// returned path is the stored logical path (= the request tail) with the
    /// `.sha1` suffix appended, which the upstream proxy composes onto the
    /// mapping base (the Maven path maps 1:1 to the upstream Maven layout).
    ///
    /// **Asymmetry (intentional, design §8/§15).** This single-path floor
    /// backs the **DEFERRED** Maven scheduled-prefetch consumer
    /// (`upstream_checksum_metadata_path` → fetch → `parse_upstream_checksum`).
    /// The **serve-path** pull-through (`hort-http-maven/src/upstream_pull.rs`)
    /// does NOT use these methods — it runs its own `.sha512`→`.sha256`→`.sha1`
    /// strength-preferring negotiation. Both satisfy ADR 0006 (every
    /// pull-through verifies); the floor is the conservative single-path form a
    /// generic consumer can rely on, the serve-path opportunistically upgrades.
    ///
    /// Returns `None` for a path with no version (an A-level metadata coords)
    /// or an empty path — there is no per-artifact checksum to fetch for a
    /// catalog-level request.
    fn upstream_checksum_metadata_path(&self, coords: &ArtifactCoords) -> Option<String> {
        if coords.version.is_none() || coords.path.is_empty() {
            return None;
        }
        Some(format!("{}.sha1", coords.path))
    }

    /// Parse a Maven `.sha1` sidecar body into the floor
    /// [`UpstreamPublishedChecksum`] (`HashAlgorithm::Sha1`).
    ///
    /// Backs the DEFERRED prefetch consumer (see
    /// [`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path)).
    /// The body is a bare lowercase hex digest; a trailing ` filename` suffix
    /// (GNU coreutils shape) is tolerated — the shared
    /// [`coords::parse_sidecar_hex`] isolates the first whitespace-delimited
    /// token and lowercases it. `UpstreamPublishedChecksum::new` then enforces
    /// the 40-char SHA-1 length + hex-only shape.
    ///
    /// `Err(DomainError::Validation)` on a malformed / empty body — there is
    /// no soft-fail (ADR 0006). The whole sidecar body is tiny (one digest
    /// line), so reading it to a `String` honours the streaming-contract
    /// intent (no multi-MB buffering — a sidecar is bounded by construction).
    fn parse_upstream_checksum(
        &self,
        body: &mut dyn std::io::Read,
        _coords: &ArtifactCoords,
    ) -> DomainResult<UpstreamPublishedChecksum> {
        let mut buf = String::new();
        std::io::Read::read_to_string(body, &mut buf).map_err(|e| {
            DomainError::Validation(format!("maven.sidecar: failed to read checksum body: {e}"))
        })?;
        let hex = parse_sidecar_hex(&buf)?;
        UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::error::DomainError;

    fn handler() -> MavenFormatHandler {
        MavenFormatHandler
    }

    // -- format_key / normalize_name -----------------------------------------

    #[test]
    fn format_key_is_maven() {
        assert_eq!(handler().format_key(), "maven");
    }

    #[test]
    fn normalize_name_is_identity_case_sensitive() {
        // Maven is case-sensitive — no folding of case or separators.
        assert_eq!(
            handler().normalize_name("com.google.guava:guava"),
            "com.google.guava:guava"
        );
        assert_eq!(
            handler().normalize_name("Com.Google.Guava:Guava"),
            "Com.Google.Guava:Guava"
        );
        assert_eq!(handler().normalize_name("a_b:c-d"), "a_b:c-d");
        assert_eq!(handler().normalize_name(""), "");
    }

    #[test]
    fn collision_key_is_none_default() {
        // Maven inherits the trait default — no registration-collision fold.
        assert_eq!(handler().collision_key("com.example:foo"), None);
    }

    // -- build_artifact_logical_path -----------------------------------------

    #[test]
    fn build_logical_path_release_jar() {
        let p = handler()
            .build_artifact_logical_path(
                "com.google.guava:guava",
                "31.1-jre",
                Some("guava-31.1-jre.jar"),
            )
            .unwrap();
        assert_eq!(p, "com/google/guava/guava/31.1-jre/guava-31.1-jre.jar");
    }

    #[test]
    fn build_logical_path_sources_classifier() {
        let p = handler()
            .build_artifact_logical_path(
                "com.google.guava:guava",
                "31.1-jre",
                Some("guava-31.1-jre-sources.jar"),
            )
            .unwrap();
        assert_eq!(
            p,
            "com/google/guava/guava/31.1-jre/guava-31.1-jre-sources.jar"
        );
    }

    #[test]
    fn build_logical_path_requires_filename() {
        let err = handler()
            .build_artifact_logical_path("com.example:foo", "1.0", None)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maven.coordinate"));
    }

    #[test]
    fn build_logical_path_rejects_bad_name() {
        let err = handler()
            .build_artifact_logical_path("no-colon-here", "1.0", Some("x.jar"))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maven.coordinate"));
    }

    // -- build ⇄ parse round-trips -------------------------------------------

    /// Round-trip helper: build a path from (name, version, filename), parse
    /// it back, assert identity + path equality, and assert the path-kind
    /// marker is `file`.
    fn assert_file_round_trip(name: &str, version: &str, filename: &str) {
        let built = handler()
            .build_artifact_logical_path(name, version, Some(filename))
            .unwrap();
        let coords = handler().parse_download_path(&built).unwrap();
        assert_eq!(coords.name, name, "name mismatch for {built}");
        assert_eq!(coords.name_as_published, name);
        assert_eq!(coords.version.as_deref(), Some(version));
        assert_eq!(coords.path, built);
        assert_eq!(coords.format, RepositoryFormat::Maven);
        assert_eq!(coords::path_kind(&coords), Some(MAVEN_KIND_FILE));
        // Rebuilding from the parsed coords reproduces the path (symmetry).
        let filename_again = built.rsplit('/').next().unwrap();
        let rebuilt = handler()
            .build_artifact_logical_path(
                &coords.name,
                coords.version.as_deref().unwrap(),
                Some(filename_again),
            )
            .unwrap();
        assert_eq!(rebuilt, built);
    }

    #[test]
    fn round_trip_release_jar() {
        assert_file_round_trip("com.google.guava:guava", "31.1-jre", "guava-31.1-jre.jar");
    }

    #[test]
    fn round_trip_sources_and_javadoc() {
        assert_file_round_trip(
            "com.google.guava:guava",
            "31.1-jre",
            "guava-31.1-jre-sources.jar",
        );
        assert_file_round_trip(
            "com.google.guava:guava",
            "31.1-jre",
            "guava-31.1-jre-javadoc.jar",
        );
    }

    #[test]
    fn round_trip_pom() {
        assert_file_round_trip("com.example:foo", "1.0", "foo-1.0.pom");
    }

    #[test]
    fn round_trip_module_gradle_gmm() {
        assert_file_round_trip("com.example:foo", "1.0", "foo-1.0.module");
    }

    #[test]
    fn round_trip_timestamped_snapshot_jar() {
        // The file path uses the timestamped filename under the base
        // -SNAPSHOT directory; the version segment is the base.
        assert_file_round_trip(
            "com.example:foo",
            "1.0-SNAPSHOT",
            "foo-1.0-20231201.120000-3.jar",
        );
    }

    #[test]
    fn round_trip_deep_group_id() {
        assert_file_round_trip(
            "org.springframework.boot:spring-boot-starter",
            "3.2.0",
            "spring-boot-starter-3.2.0.jar",
        );
    }

    // -- parse: checksum sidecar of a file -----------------------------------

    #[test]
    fn parse_checksum_sidecar_of_file() {
        let coords = handler()
            .parse_download_path("com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha1")
            .unwrap();
        assert_eq!(coords.name, "com.google.guava:guava");
        assert_eq!(coords.version.as_deref(), Some("31.1-jre"));
        assert_eq!(coords::path_kind(&coords), Some(MAVEN_KIND_FILE));
        // Every sidecar algorithm parses.
        for ext in ["sha1", "md5", "sha256", "sha512"] {
            let path = format!("com/example/foo/1.0/foo-1.0.jar.{ext}");
            let c = handler().parse_download_path(&path).unwrap();
            assert_eq!(c.name, "com.example:foo");
            assert_eq!(coords::path_kind(&c), Some(MAVEN_KIND_FILE));
        }
    }

    // -- parse: A-level metadata ---------------------------------------------

    #[test]
    fn parse_a_level_metadata() {
        let coords = handler()
            .parse_download_path("com/google/guava/guava/maven-metadata.xml")
            .unwrap();
        assert_eq!(coords.name, "com.google.guava:guava");
        // A-level has NO version.
        assert_eq!(coords.version, None);
        assert_eq!(coords::path_kind(&coords), Some(MAVEN_KIND_METADATA_A));
    }

    #[test]
    fn parse_a_level_metadata_sidecar() {
        let coords = handler()
            .parse_download_path("com/example/foo/maven-metadata.xml.sha1")
            .unwrap();
        assert_eq!(coords.name, "com.example:foo");
        assert_eq!(coords.version, None);
        assert_eq!(coords::path_kind(&coords), Some(MAVEN_KIND_METADATA_A));
    }

    // -- parse: V-level snapshot metadata ------------------------------------

    #[test]
    fn parse_v_level_snapshot_metadata() {
        let coords = handler()
            .parse_download_path("com/example/foo/1.0-SNAPSHOT/maven-metadata.xml")
            .unwrap();
        assert_eq!(coords.name, "com.example:foo");
        // V-level carries the snapshot version.
        assert_eq!(coords.version.as_deref(), Some("1.0-SNAPSHOT"));
        assert_eq!(coords::path_kind(&coords), Some(MAVEN_KIND_METADATA_V));
    }

    #[test]
    fn parse_v_level_snapshot_metadata_sidecar() {
        let coords = handler()
            .parse_download_path("com/example/foo/2.3-SNAPSHOT/maven-metadata.xml.md5")
            .unwrap();
        assert_eq!(coords.version.as_deref(), Some("2.3-SNAPSHOT"));
        assert_eq!(coords::path_kind(&coords), Some(MAVEN_KIND_METADATA_V));
    }

    #[test]
    fn parse_metadata_disambiguation_non_snapshot_is_a_level() {
        // A non-snapshot segment before maven-metadata.xml is the artifactId,
        // NOT a version → A-level. Here `1.0` is a normal release "version"
        // shape but, sitting before maven-metadata.xml and NOT ending
        // -SNAPSHOT, the disambiguation rule treats it as the artifactId.
        let coords = handler()
            .parse_download_path("com/example/1.0/maven-metadata.xml")
            .unwrap();
        // groupId = com.example, artifactId = "1.0".
        assert_eq!(coords.name, "com.example:1.0");
        assert_eq!(coords.version, None);
        assert_eq!(coords::path_kind(&coords), Some(MAVEN_KIND_METADATA_A));
    }

    // -- parse: rejects -------------------------------------------------------

    #[test]
    fn parse_rejects_empty_and_short() {
        assert!(handler().parse_download_path("").is_err());
        assert!(handler().parse_download_path("a/b").is_err()); // too short
    }

    #[test]
    fn parse_rejects_filename_not_matching_coords() {
        // filename does not start with {artifactId}-{version}.
        let err = handler()
            .parse_download_path("com/example/foo/1.0/totally-unrelated.jar")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maven.coordinate"));
    }

    #[test]
    fn parse_rejects_empty_segment() {
        let err = handler()
            .parse_download_path("com//foo/1.0/foo-1.0.jar")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- validate_maven_coordinate (every reject path) -----------------------

    #[test]
    fn validate_rejects_traversal() {
        let err = validate_maven_coordinate("..", "foo", Some("1.0")).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maven.coordinate"));
        // Embedded traversal inside the dotted groupId.
        let err = validate_maven_coordinate("com...evil", "foo", Some("1.0")).unwrap_err();
        assert!(err.to_string().contains("maven.coordinate"));
        // Traversal in artifactId / version.
        assert!(validate_maven_coordinate("com.example", "..", Some("1.0")).is_err());
        assert!(validate_maven_coordinate("com.example", "foo", Some("..")).is_err());
        // The literal `..` in the dotted group as a standalone segment.
        assert!(validate_maven_coordinate("com..example", "foo", Some("1.0")).is_err());
    }

    #[test]
    fn validate_rejects_control_chars() {
        for bad in ["com\rexample", "com\nexample", "com\0example"] {
            let err = validate_maven_coordinate(bad, "foo", Some("1.0")).unwrap_err();
            assert!(matches!(err, DomainError::Validation(_)));
            assert!(err.to_string().contains("maven.coordinate"));
            // Never echo the offending bytes.
            assert!(!err.to_string().contains('\r'));
            assert!(!err.to_string().contains('\n'));
            assert!(!err.to_string().contains('\0'));
        }
        // Control char in artifactId / version too.
        assert!(validate_maven_coordinate("com.example", "fo\no", Some("1.0")).is_err());
        assert!(validate_maven_coordinate("com.example", "foo", Some("1.\r0")).is_err());
    }

    #[test]
    fn validate_rejects_path_separator() {
        // A literal slash in any component is traversal/injection.
        assert!(validate_maven_coordinate("com/example", "foo", Some("1.0")).is_err());
        assert!(validate_maven_coordinate("com.example", "fo/o", Some("1.0")).is_err());
        assert!(validate_maven_coordinate("com.example", "foo", Some("1/0")).is_err());
    }

    #[test]
    fn validate_rejects_backslash() {
        // A literal backslash in any coordinate component is rejected
        // (defense-in-depth: Windows-style separator / traversal attempt).
        let err = validate_maven_coordinate("com\\example", "foo", Some("1.0")).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maven.coordinate"));
        // The error must not echo the offending bytes.
        assert!(!err.to_string().contains('\\'));
        assert!(validate_maven_coordinate("com.example", "fo\\o", Some("1.0")).is_err());
        assert!(validate_maven_coordinate("com.example", "foo", Some("1\\0")).is_err());

        // A backslash in the filename segment is rejected by `validate_filename`
        // on the public parse path. `foo-1.0\evil.jar` is a single Maven path
        // segment (the splitter only breaks on `/`), so the backslash reaches
        // the filename validator.
        let err = handler()
            .parse_download_path("com/example/foo/1.0/foo-1.0\\evil.jar")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maven.coordinate"));
        assert!(!err.to_string().contains('\\'));
    }

    #[test]
    fn validate_rejects_over_length() {
        let long = "a".repeat(coords::MAVEN_SEGMENT_MAX + 1);
        // Over-long group dot-segment.
        let err = validate_maven_coordinate(&long, "foo", Some("1.0")).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maven.coordinate"));
        // The error must not echo the (huge) input.
        assert!(!err.to_string().contains(&long));
        // Over-long artifactId / version.
        assert!(validate_maven_coordinate("com.example", &long, Some("1.0")).is_err());
        assert!(validate_maven_coordinate("com.example", "foo", Some(&long)).is_err());
        // Boundary: exactly MAX is accepted.
        let at_max = "a".repeat(coords::MAVEN_SEGMENT_MAX);
        validate_maven_coordinate(&at_max, "foo", Some("1.0")).expect("at-cap segment accepted");
    }

    #[test]
    fn validate_rejects_empty() {
        let err = validate_maven_coordinate("", "foo", Some("1.0")).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maven.coordinate"));
        assert!(validate_maven_coordinate("com.example", "", Some("1.0")).is_err());
        assert!(validate_maven_coordinate("com.example", "foo", Some("")).is_err());
        // An empty version is rejected only when present; None skips it.
        validate_maven_coordinate("com.example", "foo", None).expect("None version is fine");
    }

    #[test]
    fn validate_accepts_real_coordinates() {
        validate_maven_coordinate("com.google.guava", "guava", Some("31.1-jre")).unwrap();
        validate_maven_coordinate(
            "org.springframework.boot",
            "spring-boot-starter",
            Some("3.2.0"),
        )
        .unwrap();
        validate_maven_coordinate("com.example", "foo", Some("1.0-SNAPSHOT")).unwrap();
    }

    // -- classify_group_member -----------------------------------------------

    /// Build a file-shaped coords for a stored path (the shape the ingest
    /// hook hands `classify_group_member`).
    fn file_coords(name: &str, version: &str, path: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: Some(version.to_string()),
            path: path.to_string(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::json!({ MAVEN_PATH_KIND_KEY: MAVEN_KIND_FILE }),
        }
    }

    #[test]
    fn classify_jar_is_primary() {
        let path = "com/example/foo/1.0/foo-1.0.jar";
        let c = file_coords("com.example:foo", "1.0", path);
        let m = handler().classify_group_member(&c, path).unwrap();
        assert_eq!(m.role, "jar");
        assert!(m.is_primary);
        // Canonicalisation contract: identity-only group coords.
        assert_eq!(m.group_coords.name, "com.example:foo");
        assert_eq!(m.group_coords.name_as_published, "com.example:foo");
        assert_eq!(m.group_coords.version.as_deref(), Some("1.0"));
        assert_eq!(m.group_coords.path, "");
        assert_eq!(m.group_coords.metadata, serde_json::Value::Null);
        assert_eq!(m.group_coords.format, RepositoryFormat::Maven);
    }

    #[test]
    fn classify_pom_is_not_primary() {
        let path = "com/example/foo/1.0/foo-1.0.pom";
        let c = file_coords("com.example:foo", "1.0", path);
        let m = handler().classify_group_member(&c, path).unwrap();
        assert_eq!(m.role, "pom");
        // is_primary=false (packaging not knowable from path — see
        // `is_primary_role` docstring).
        assert!(!m.is_primary);
    }

    #[test]
    fn classify_sources_and_javadoc() {
        let sp = "com/example/foo/1.0/foo-1.0-sources.jar";
        let m = handler()
            .classify_group_member(&file_coords("com.example:foo", "1.0", sp), sp)
            .unwrap();
        assert_eq!(m.role, "sources");
        assert!(!m.is_primary);

        let jp = "com/example/foo/1.0/foo-1.0-javadoc.jar";
        let m = handler()
            .classify_group_member(&file_coords("com.example:foo", "1.0", jp), jp)
            .unwrap();
        assert_eq!(m.role, "javadoc");
        assert!(!m.is_primary);
    }

    #[test]
    fn classify_module_gradle_gmm() {
        let path = "com/example/foo/1.0/foo-1.0.module";
        let m = handler()
            .classify_group_member(&file_coords("com.example:foo", "1.0", path), path)
            .unwrap();
        assert_eq!(m.role, "module");
        assert!(!m.is_primary);
    }

    #[test]
    fn classify_returns_none_for_sidecars() {
        for ext in ["sha1", "md5", "sha256", "sha512"] {
            let path = format!("com/example/foo/1.0/foo-1.0.jar.{ext}");
            let c = file_coords("com.example:foo", "1.0", &path);
            assert!(
                handler().classify_group_member(&c, &path).is_none(),
                ".{ext} sidecar must not be a group member"
            );
        }
    }

    #[test]
    fn classify_returns_none_for_metadata() {
        // A-level metadata coords (version None, marker metadata_a).
        let a = ArtifactCoords {
            name: "com.example:foo".into(),
            name_as_published: "com.example:foo".into(),
            version: None,
            path: "com/example/foo/maven-metadata.xml".into(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::json!({ MAVEN_PATH_KIND_KEY: MAVEN_KIND_METADATA_A }),
        };
        assert!(handler().classify_group_member(&a, &a.path).is_none());

        // V-level metadata coords.
        let v = ArtifactCoords {
            name: "com.example:foo".into(),
            name_as_published: "com.example:foo".into(),
            version: Some("1.0-SNAPSHOT".into()),
            path: "com/example/foo/1.0-SNAPSHOT/maven-metadata.xml".into(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::json!({ MAVEN_PATH_KIND_KEY: MAVEN_KIND_METADATA_V }),
        };
        assert!(handler().classify_group_member(&v, &v.path).is_none());

        // Even a file-shaped coords whose filename is maven-metadata.xml
        // returns None (defence in depth on the filename classifier).
        let mp = "com/example/foo/1.0/maven-metadata.xml";
        let c = file_coords("com.example:foo", "1.0", mp);
        assert!(handler().classify_group_member(&c, mp).is_none());
    }

    #[test]
    fn classify_snapshot_group_uses_base_version() {
        // A timestamped snapshot file's stored path sits under the base
        // -SNAPSHOT directory; coords.version is that base. The group's
        // version is therefore the base (NOT the timestamped form).
        let path = "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar";
        let c = file_coords("com.example:foo", "1.0-SNAPSHOT", path);
        let m = handler().classify_group_member(&c, path).unwrap();
        assert_eq!(m.role, "jar");
        assert!(m.is_primary);
        // Group version is the base -SNAPSHOT, not the timestamp.
        assert_eq!(m.group_coords.version.as_deref(), Some("1.0-SNAPSHOT"));
        assert_eq!(m.group_coords.path, "");
        assert_eq!(m.group_coords.metadata, serde_json::Value::Null);
    }

    #[test]
    fn classify_war_and_other_packaging_is_jar_role() {
        // Non-jar binary packaging (.war/.aar/.ear) classifies as the binary
        // `jar` role for grouping purposes.
        for path in [
            "com/example/foo/1.0/foo-1.0.war",
            "com/example/foo/1.0/foo-1.0.aar",
        ] {
            let c = file_coords("com.example:foo", "1.0", path);
            let m = handler().classify_group_member(&c, path).unwrap();
            assert_eq!(m.role, "jar");
            assert!(m.is_primary);
        }
    }

    // -- resolve_mutable_version (trait method) -------------------------------

    #[test]
    fn resolve_mutable_version_picks_highest() {
        let avail = [
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-1.jar",
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar",
        ];
        let refs: Vec<&str> = avail.to_vec();
        let got = handler()
            .resolve_mutable_version("com/example/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar", &refs)
            .unwrap();
        assert_eq!(
            got.as_deref(),
            Some("com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar")
        );
    }

    #[test]
    fn resolve_mutable_version_none_for_non_snapshot() {
        let got = handler()
            .resolve_mutable_version(
                "com/example/foo/1.0/foo-1.0.jar",
                &["com/example/foo/1.0/foo-1.0.jar"],
            )
            .unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn resolve_mutable_version_none_for_empty_available() {
        let got = handler()
            .resolve_mutable_version("com/example/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar", &[])
            .unwrap();
        assert_eq!(got, None);
    }

    // -- upstream_checksum_metadata_path (deferred prefetch floor) ------------

    /// Sample file coords for the trait-method floor tests.
    fn sample_file_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "com.google.guava:guava".into(),
            name_as_published: "com.google.guava:guava".into(),
            version: Some("31.1-jre".into()),
            path: "com/google/guava/guava/31.1-jre/guava-31.1-jre.jar".into(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::json!({ MAVEN_PATH_KIND_KEY: MAVEN_KIND_FILE }),
        }
    }

    #[test]
    fn upstream_checksum_metadata_path_returns_sha1_floor() {
        let coords = sample_file_coords();
        assert_eq!(
            handler().upstream_checksum_metadata_path(&coords),
            Some("com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha1".to_string()),
            "the floor is the artifact path + .sha1 (ADR 0033)"
        );
    }

    #[test]
    fn upstream_checksum_metadata_path_none_without_version() {
        // An A-level metadata coords (version None) has no per-artifact
        // checksum to fetch.
        let coords = ArtifactCoords {
            name: "com.example:foo".into(),
            name_as_published: "com.example:foo".into(),
            version: None,
            path: "com/example/foo/maven-metadata.xml".into(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::json!({ MAVEN_PATH_KIND_KEY: MAVEN_KIND_METADATA_A }),
        };
        assert_eq!(handler().upstream_checksum_metadata_path(&coords), None);
    }

    #[test]
    fn upstream_checksum_metadata_path_none_for_empty_path() {
        // Group coords (path empty) carry no fetchable sidecar path.
        let coords = ArtifactCoords {
            name: "com.example:foo".into(),
            name_as_published: "com.example:foo".into(),
            version: Some("1.0".into()),
            path: String::new(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::Value::Null,
        };
        assert_eq!(handler().upstream_checksum_metadata_path(&coords), None);
    }

    // -- parse_upstream_checksum (deferred prefetch floor) -------------------

    const SHA1_HEX: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    #[test]
    fn parse_upstream_checksum_bare_hex_to_sha1() {
        let coords = sample_file_coords();
        let cs = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(SHA1_HEX.as_bytes()), &coords)
            .unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha1);
        assert_eq!(cs.hex(), SHA1_HEX);
    }

    #[test]
    fn parse_upstream_checksum_tolerates_trailing_filename() {
        // GNU coreutils shape: `<hex>  <filename>` — take the first token.
        let coords = sample_file_coords();
        let body = format!("{SHA1_HEX}  guava-31.1-jre.jar");
        let cs = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body.as_bytes()), &coords)
            .unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha1);
        assert_eq!(cs.hex(), SHA1_HEX);
    }

    #[test]
    fn parse_upstream_checksum_uppercase_is_lowercased() {
        let coords = sample_file_coords();
        let upper = SHA1_HEX.to_ascii_uppercase();
        let cs = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(upper.as_bytes()), &coords)
            .unwrap();
        assert_eq!(cs.hex(), SHA1_HEX);
    }

    #[test]
    fn parse_upstream_checksum_empty_body_rejected() {
        let coords = sample_file_coords();
        for body in ["", "   ", "\n\t "] {
            let err = handler()
                .parse_upstream_checksum(&mut std::io::Cursor::new(body.as_bytes()), &coords)
                .unwrap_err();
            assert!(
                matches!(err, DomainError::Validation(_)),
                "empty/whitespace body must be Validation, got {err:?}"
            );
        }
    }

    #[test]
    fn parse_upstream_checksum_garbage_body_rejected() {
        // A non-hex / wrong-length token fails the SHA-1 shape check in
        // UpstreamPublishedChecksum::new (no soft-fail, ADR 0006).
        let coords = sample_file_coords();
        for body in ["not-a-digest", "deadbeef", "z".repeat(40).as_str()] {
            let err = handler()
                .parse_upstream_checksum(&mut std::io::Cursor::new(body.as_bytes()), &coords)
                .unwrap_err();
            assert!(
                matches!(err, DomainError::Validation(_)),
                "garbage body must be Validation, got {err:?}"
            );
        }
    }

    // -- parse_sidecar_hex (shared bare-hex token parser) --------------------

    #[test]
    fn parse_sidecar_hex_bare_and_suffixed() {
        assert_eq!(parse_sidecar_hex(SHA1_HEX).unwrap(), SHA1_HEX);
        assert_eq!(
            parse_sidecar_hex(&format!("{SHA1_HEX}  foo.jar")).unwrap(),
            SHA1_HEX
        );
        // Leading whitespace + trailing newline are tolerated.
        assert_eq!(
            parse_sidecar_hex(&format!("  {SHA1_HEX}\n")).unwrap(),
            SHA1_HEX
        );
        // Mixed case is lowercased.
        assert_eq!(
            parse_sidecar_hex(&SHA1_HEX.to_ascii_uppercase()).unwrap(),
            SHA1_HEX
        );
    }

    #[test]
    fn parse_sidecar_hex_empty_rejected() {
        assert!(matches!(
            parse_sidecar_hex(""),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            parse_sidecar_hex("   \n\t"),
            Err(DomainError::Validation(_))
        ));
    }
}
