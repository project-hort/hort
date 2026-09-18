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
//! - [`FormatHandler::version_discovery`] → `Some(self)`: Maven declares the
//!   `VersionDiscovery` capability group (ADR 0005). The upstream version
//!   set comes from the A-level `maven-metadata.xml` ([`metadata`]) and the
//!   declared compile- and runtime-scope dependencies from the POM's own
//!   `<dependencies>` ([`pom`]).
//!
//! Everything else (prefetch download-URL composition, SBOM) is inherited at
//! the trait default and wired by later/deferred items.

pub mod coords;
pub mod metadata;
pub mod pom;
pub mod snapshot;
pub(crate) mod xml;

use std::io::{Cursor, Read};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::format_handler::{
    DependencySpec, FormatHandler, GroupMembership, PayloadSbom, PayloadSbomExtraction,
    SbomResolution, VersionDiscovery,
};
use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};
use hort_domain::types::{ArtifactCoords, Ecosystem, PayloadAccess, Sbom, SbomComponent};

use crate::sbom_helpers::build_subject_component;

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
        body: &mut dyn Read,
        _coords: &ArtifactCoords,
    ) -> DomainResult<UpstreamPublishedChecksum> {
        let mut buf = String::new();
        Read::read_to_string(body, &mut buf).map_err(|e| {
            DomainError::Validation(format!("maven.sidecar: failed to read checksum body: {e}"))
        })?;
        let hex = parse_sidecar_hex(&buf)?;
        UpstreamPublishedChecksum::new(HashAlgorithm::Sha1, hex)
    }

    /// Maven declares the `VersionDiscovery` capability group (ADR 0005).
    ///
    /// The two members that carry the group for Maven are
    /// [`VersionDiscovery::extract_upstream_versions`] (the A-level
    /// `maven-metadata.xml` version list) and
    /// [`VersionDiscovery::extract_dependency_specs`] (the POM's own
    /// compile- and runtime-scope `<dependencies>`). Together they are what gives a
    /// Maven proxy a warm-up path: unlike npm, PyPI and cargo, nothing
    /// else in the Maven protocol makes a proxy self-warm, so without them
    /// a non-zero quarantine window on a Maven proxy surfaces to a build
    /// as a resolver failure.
    fn version_discovery(&self) -> Option<&dyn VersionDiscovery> {
        Some(self)
    }

    /// `Some(self)` — Maven implements [`PayloadSbom`]. Maven's declared
    /// dependencies live in the `.pom` itself (or, for a `.jar`/`.war`, in
    /// its embedded `META-INF/maven/{g}/{a}/pom.xml`) — there is no
    /// separate index/publish-body JSON the way npm and cargo have, so
    /// `format_metadata` carries nothing `FormatHandler::extract_sbom`
    /// could read. The payload IS the manifest; see the impl block below.
    fn payload_sbom(&self) -> Option<&dyn PayloadSbom> {
        Some(self)
    }
}

impl VersionDiscovery for MavenFormatHandler {
    /// Extract the upstream-published version set from an A-level
    /// `maven-metadata.xml` body.
    ///
    /// Delegates to [`metadata::parse_upstream_versions`], which reads
    /// `<versioning><versions><version>` and preserves document order (the
    /// planner owns ordering and de-duplication). Degrades open on a
    /// malformed body — `Ok` with whatever was read — matching the npm and
    /// cargo readers: on the discovery tier a mis-served body is a
    /// transient condition the next tick re-evaluates, not a reason to
    /// surface an error.
    ///
    /// Bounded by [`metadata::UPSTREAM_METADATA_MAX_BYTES`]; a body over
    /// the cap is `Validation`.
    fn extract_upstream_versions(&self, body: &mut dyn Read) -> DomainResult<Vec<String>> {
        let bytes = crate::stream_helpers::read_to_capped_vec(
            body,
            metadata::UPSTREAM_METADATA_MAX_BYTES,
            |len, max| {
                format!("maven upstream metadata body is {len} bytes; per-format max is {max}")
            },
        )?;
        Ok(metadata::parse_upstream_versions(&bytes))
    }

    /// The A-level `maven-metadata.xml` path for a `groupId:artifactId`.
    ///
    /// **Differs** from
    /// [`FormatHandler::upstream_checksum_metadata_path`], which is the
    /// per-FILE `.sha1` floor. Maven is, with PyPI, one of the formats
    /// where the version-set document and the checksum document are
    /// structurally distinct: the version set lives at the artifact level
    /// (`g/a/maven-metadata.xml`) and each checksum lives beside its own
    /// file. Reading the checksum path here would fetch a sidecar and find
    /// no versions in it.
    ///
    /// `None` when `package` is not the colon-joined GA form or fails the
    /// coordinate guard — a caller that cannot name an artifact has no
    /// version list to fetch.
    fn upstream_metadata_path(&self, package: &str) -> Option<String> {
        let (group_id, artifact_id) = coords::split_ga(package).ok()?;
        validate_maven_coordinate(group_id, artifact_id, None).ok()?;
        let group_path = group_id.replace('.', "/");
        Some(format!(
            "/{group_path}/{artifact_id}/{}",
            coords::MAVEN_METADATA_FILENAME
        ))
    }

    /// Maven has no content negotiation — `maven-metadata.xml` is the
    /// upstream's only representation. Same inert value npm and cargo
    /// supply.
    fn upstream_metadata_accept(&self) -> Vec<String> {
        Vec::new()
    }

    /// Extract the declared compile- and runtime-scope dependencies from a
    /// stored POM.
    ///
    /// **Input is the POM's own bytes** — unlike npm/cargo/pypi, Maven's
    /// declared dependencies are not inside an archive: the `.pom` IS the
    /// manifest, stored as its own group member, so there is no container
    /// to open and no `archive_bounds` guard in the path.
    ///
    /// Resolution and its ceiling are [`pom::parse_pom_dependencies`]'s;
    /// see that module for what a pure function over one POM can and
    /// cannot see. Everything it could not resolve is counted per
    /// [`pom::PomSkipReason`] and emitted here as one structured `debug!`
    /// per reason that occurred, so an operator can tell a tree the
    /// cascade genuinely warmed from one whose versions all live in a
    /// parent.
    ///
    /// **`Err` versus `Ok(vec![])`.** `Err` means the bytes are not a POM
    /// (not XML, wrong root element, over the size cap). A well-formed POM
    /// always yields `Ok`, however little of it resolved — a POM whose
    /// every version is inherited returns `Ok(vec![])` with the skips
    /// counted. Inverting that would abort the cascade for every
    /// parent-managed POM instead of partially warming it, which is worse
    /// than the no-op this method replaces.
    fn extract_dependency_specs(
        &self,
        content: &mut dyn Read,
    ) -> DomainResult<Vec<DependencySpec>> {
        let extraction = pom::parse_pom_dependencies(content)?;
        for (reason, count) in extraction.skip_counts() {
            if count > 0 {
                tracing::debug!(
                    reason = reason.as_str(),
                    count,
                    resolved = extraction.specs.len(),
                    "maven.pom: declared dependencies skipped — this reader sees only the \
                     POM's own bytes, so a version held by a parent POM or an imported BOM \
                     is out of reach",
                );
            }
        }
        Ok(extraction.specs)
    }

    /// Resolve a declared Maven dependency version against an `available`
    /// set.
    ///
    /// Maven's bare `<version>` is a **soft requirement** — "use exactly
    /// this unless something else in the resolve wins" — so the only
    /// version that satisfies it is itself. This resolver is therefore an
    /// exact match against `available`, which is precisely the grammar
    /// [`extract_dependency_specs`](Self::extract_dependency_specs)
    /// produces: a hard range never reaches here, because a range is a
    /// counted [`pom::PomSkipReason::UnsupportedRange`] skip rather than a
    /// spec (ADR 0053 D2 — a range upstream cannot satisfy is skipped and
    /// logged, never guessed at).
    ///
    /// `None` when the declared version is not published upstream, which
    /// the cascade reads as "skip this dep".
    fn resolve_range_max(&self, range: &str, available: &[&str]) -> DomainResult<Option<String>> {
        let wanted = range.trim();
        Ok(available
            .iter()
            .find(|candidate| candidate.trim() == wanted)
            .map(|candidate| (*candidate).to_string()))
    }

    /// Maven has no separate download-config document — a Maven download
    /// URL is the mapping base plus the layout path. Same inert value npm
    /// and pypi supply; a format returning `None` here must never reach
    /// [`compose_download_url_from_config`](Self::compose_download_url_from_config).
    fn download_config_path(&self) -> Option<String> {
        None
    }

    /// Unreachable for Maven — see
    /// [`download_config_path`](Self::download_config_path).
    fn compose_download_url_from_config(
        &self,
        body: &mut dyn Read,
        package: &str,
        version: &str,
        cksum_hex: Option<&str>,
    ) -> DomainResult<String> {
        let _ = (body, package, version, cksum_hex);
        Err(DomainError::Validation(
            "compose_download_url_from_config not supported for maven".into(),
        ))
    }

    /// Unreachable for Maven. A Maven artifact's download URL is composed
    /// from the layout path (`build_artifact_logical_path`), not resolved
    /// out of a metadata body: `maven-metadata.xml` carries the version
    /// list, never per-version download URLs.
    fn resolve_download_url_from_metadata(
        &self,
        body: &mut dyn Read,
        coords: &ArtifactCoords,
    ) -> DomainResult<String> {
        let _ = (body, coords);
        Err(DomainError::Validation(
            "resolve_download_url_from_metadata not supported for maven".into(),
        ))
    }
}

/// Maven's [`PayloadSbom`] participation — the SBOM the **scan** path
/// uses.
///
/// Only the two roles that carry a Maven manifest produce a non-`None`
/// BOM: a `.pom` payload IS the manifest, and a `.jar`/`.war` payload MAY
/// embed one at `META-INF/maven/{groupId}/{artifactId}/pom.xml`. Every
/// other role — checksum sidecars, `maven-metadata.xml`, `-sources.jar`,
/// `-javadoc.jar`, Gradle `.module` — carries no dependency information
/// this format can extract, so [`classify_role`] (the same classifier
/// [`FormatHandler::classify_group_member`] uses) gates which branch runs.
///
/// **Three outcomes, three postures**, mirroring cargo's
/// [`PayloadSbom`] impl:
///
/// | Payload | Components | [`SbomResolution`] |
/// |---|---|---|
/// | `.pom`/embedded pom.xml parses | resolved, exact versions | `Resolved` |
/// | `.jar`/`.war` with no embedded pom.xml | none — subject only | `NoLockfile` |
/// | pom bytes present but not a well-formed POM, or the jar is not a valid zip | none — subject only | `UnusableLockfile` |
///
/// **Every failure is soft.** No arm returns `Err` for malformed payload
/// bytes — SBOM enrichment is not release authority, and a
/// publisher-controlled byte sequence must not be able to abort a scan.
/// `Err` only propagates from [`coords::split_ga`] on a stored
/// coordinate whose `name` is not the colon-joined GA form, which
/// publish-time validation should never allow through.
impl PayloadSbom for MavenFormatHandler {
    fn extract_sbom_from_payload(
        &self,
        coords: &ArtifactCoords,
        _format_metadata: &serde_json::Value,
        payload: PayloadAccess<'_>,
    ) -> DomainResult<PayloadSbomExtraction> {
        let filename = coords
            .path
            .rsplit('/')
            .next()
            .unwrap_or(coords.path.as_str());
        match classify_role(filename) {
            Some("pom") => {
                let subject = maven_subject_component(coords)?;
                let mut slice;
                let mut stream;
                let content: &mut dyn Read = match payload {
                    PayloadAccess::Bytes(b) => {
                        slice = b;
                        &mut slice
                    }
                    PayloadAccess::ReadStream(r) => {
                        stream = r;
                        &mut stream
                    }
                };
                match pom::parse_pom_dependencies(content) {
                    Ok(deps) => Ok(PayloadSbomExtraction {
                        sbom: Some(Sbom {
                            subject: Some(subject),
                            components: maven_sbom_components(&deps.specs),
                        }),
                        resolution: SbomResolution::Resolved,
                        skipped_non_registry: 0,
                    }),
                    Err(e) => {
                        tracing::warn!(
                            artifact = %coords.name,
                            error = %e,
                            "maven SBOM: stored .pom did not parse; degrading to subject-only",
                        );
                        Ok(subject_only(subject, SbomResolution::UnusableLockfile))
                    }
                }
            }
            Some("jar") => {
                let subject = maven_subject_component(coords)?;
                let (group_id, artifact_id) = coords::split_ga(&coords.name)?;
                extract_jar_embedded_pom_sbom(coords, group_id, artifact_id, subject, payload)
            }
            _ => Ok(PayloadSbomExtraction {
                sbom: None,
                resolution: SbomResolution::NoLockfile,
                skipped_non_registry: 0,
            }),
        }
    }
}

/// Build the [`Sbom::subject`] component for a Maven coordinate:
/// `pkg:maven/{groupId}/{artifactId}@{version}`, `Ecosystem::Maven`.
fn maven_subject_component(coords: &ArtifactCoords) -> DomainResult<SbomComponent> {
    let (group_id, artifact_id) = coords::split_ga(&coords.name)?;
    let purl_name = format!("{group_id}/{artifact_id}");
    Ok(build_subject_component(
        coords,
        Ecosystem::Maven,
        "pkg:maven/",
        &purl_name,
        Vec::new(),
    ))
}

/// Turn resolved POM dependency specs into [`SbomComponent`]s.
///
/// Each [`DependencySpec::name`] is the colon-joined `groupId:artifactId`
/// the POM reader produces; the PURL form needs them slash-joined instead.
/// A spec whose name is not colon-joined cannot happen from this crate's
/// own POM reader, so a malformed one is skipped rather than panicking or
/// aborting the whole SBOM.
fn maven_sbom_components(specs: &[DependencySpec]) -> Vec<SbomComponent> {
    specs
        .iter()
        .filter_map(|spec| {
            let (group_id, artifact_id) = coords::split_ga(&spec.name).ok()?;
            Some(SbomComponent {
                purl: format!("pkg:maven/{group_id}/{artifact_id}@{}", spec.range),
                name: spec.name.clone(),
                version: Some(spec.range.clone()),
                ecosystem: Ecosystem::Maven,
                licenses: Vec::new(),
                direct_dependency: true,
            })
        })
        .collect()
}

/// A subject-only [`PayloadSbomExtraction`] — no components, just the
/// artifact's own coordinate. Used for every degrade-soft arm: a
/// `.jar`/`.war` with no embedded POM still lets OSV query the artifact's
/// own coordinate, and a POM that failed to parse degrades to the same
/// shape rather than dropping the SBOM entirely.
fn subject_only(subject: SbomComponent, resolution: SbomResolution) -> PayloadSbomExtraction {
    PayloadSbomExtraction {
        sbom: Some(Sbom {
            subject: Some(subject),
            components: Vec::new(),
        }),
        resolution,
        skipped_non_registry: 0,
    }
}

/// Whether any `/`-separated segment of a zip entry name is a literal
/// `..` — a path-traversal-shaped entry. The embedded-POM lookup below
/// only ever reads the one entry whose name exactly equals the expected
/// `META-INF/maven/{g}/{a}/pom.xml` path (itself built from validated
/// coordinates, so it can never contain `..`), which already can't match
/// a traversal-shaped name — this check is defense-in-depth so a
/// traversal-named entry is refused explicitly rather than relying
/// solely on the exact-match property.
fn has_traversal_segment(name: &str) -> bool {
    name.split('/').any(|segment| segment == "..")
}

/// Read `META-INF/maven/{group_id}/{artifact_id}/pom.xml` out of a
/// `.jar`/`.war` payload and extract its declared dependencies.
///
/// Bounded by [`crate::archive_bounds::BoundsConfig::default_for_metadata_extraction`]
/// (10 MiB decompressed / 10x compression-ratio / 1024 entries — the same
/// cap the PyPI wheel-METADATA extractor uses). Degrades to
/// [`subject_only`] rather than erroring on every non-fatal outcome: no
/// embedded POM (the common case — most Maven jars don't embed one),
/// a corrupt/non-ZIP jar, or an embedded POM that isn't well-formed XML.
/// A bounds trip (entry-count or decompression-ratio cap exceeded) is the
/// one outcome treated as hostile input and also degrades softly, logged
/// at `warn` — SBOM enrichment must never abort a scan.
fn extract_jar_embedded_pom_sbom(
    coords: &ArtifactCoords,
    group_id: &str,
    artifact_id: &str,
    subject: SbomComponent,
    payload: PayloadAccess<'_>,
) -> DomainResult<PayloadSbomExtraction> {
    // ZIP parsing needs `Read + Seek`; materialise into memory the same
    // way the PyPI wheel-METADATA extractor does — the ingest hook has
    // already buffered the artifact for the primary-content-hash
    // computation, so the memory cost is already paid at this point.
    let buf: Vec<u8> = match payload {
        PayloadAccess::Bytes(b) => b.to_vec(),
        PayloadAccess::ReadStream(mut r) => {
            let mut v = Vec::new();
            if r.read_to_end(&mut v).is_err() {
                return Ok(subject_only(subject, SbomResolution::UnusableLockfile));
            }
            v
        }
    };

    // Unlike the storage/download layout path (where groupId is
    // slash-expanded), the JAR's own internal `META-INF/maven/` convention
    // keeps groupId as a single literal dotted path segment — real-world
    // jars embed e.g. `META-INF/maven/org.springframework.boot/spring-boot/pom.xml`,
    // not a slash-expanded one.
    let expected_path = format!("META-INF/maven/{group_id}/{artifact_id}/pom.xml");

    let mut pom_bytes: Option<Vec<u8>> = None;
    let mut read_err: Option<String> = None;
    let iter_result = crate::archive_bounds::iter_zip_entries(
        Cursor::new(&buf),
        crate::archive_bounds::BoundsConfig::default_for_metadata_extraction(),
        |name, reader| {
            if read_err.is_some() || pom_bytes.is_some() {
                return;
            }
            if has_traversal_segment(name) || name != expected_path {
                return;
            }
            let mut out = Vec::new();
            match reader.read_to_end(&mut out) {
                Ok(_) => pom_bytes = Some(out),
                Err(e) => read_err = Some(format!("maven jar embedded pom read failed: {e}")),
            }
        },
    );

    match iter_result {
        Ok(()) => {}
        // Not a valid ZIP — non-fatal: the same leaf outcome as a jar
        // with no embedded POM. The primary-content-hash check already
        // verified this artifact at ingest; SBOM extraction just can't
        // say more about it.
        Err(crate::archive_bounds::ZipIterError::Open(_)) => {
            return Ok(subject_only(subject, SbomResolution::NoLockfile));
        }
        Err(e) => {
            tracing::warn!(
                artifact = %coords.name,
                error = %e,
                "maven SBOM: jar zip rejected during embedded-POM extraction; degrading to subject-only",
            );
            return Ok(subject_only(subject, SbomResolution::UnusableLockfile));
        }
    }
    if let Some(msg) = read_err {
        tracing::warn!(
            artifact = %coords.name,
            error = %msg,
            "maven SBOM: embedded pom.xml read failed; degrading to subject-only",
        );
        return Ok(subject_only(subject, SbomResolution::UnusableLockfile));
    }

    let Some(pom_bytes) = pom_bytes else {
        // No embedded POM — the leaf case. OSV can still query the
        // artifact's own coordinate via the subject.
        return Ok(subject_only(subject, SbomResolution::NoLockfile));
    };

    match pom::parse_pom_dependencies(&mut Cursor::new(pom_bytes)) {
        Ok(deps) => Ok(PayloadSbomExtraction {
            sbom: Some(Sbom {
                subject: Some(subject),
                components: maven_sbom_components(&deps.specs),
            }),
            resolution: SbomResolution::Resolved,
            skipped_non_registry: 0,
        }),
        Err(e) => {
            tracing::warn!(
                artifact = %coords.name,
                error = %e,
                "maven SBOM: embedded pom.xml did not parse; degrading to subject-only",
            );
            Ok(subject_only(subject, SbomResolution::UnusableLockfile))
        }
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
            .parse_upstream_checksum(&mut Cursor::new(SHA1_HEX.as_bytes()), &coords)
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
            .parse_upstream_checksum(&mut Cursor::new(body.as_bytes()), &coords)
            .unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha1);
        assert_eq!(cs.hex(), SHA1_HEX);
    }

    #[test]
    fn parse_upstream_checksum_uppercase_is_lowercased() {
        let coords = sample_file_coords();
        let upper = SHA1_HEX.to_ascii_uppercase();
        let cs = handler()
            .parse_upstream_checksum(&mut Cursor::new(upper.as_bytes()), &coords)
            .unwrap();
        assert_eq!(cs.hex(), SHA1_HEX);
    }

    #[test]
    fn parse_upstream_checksum_empty_body_rejected() {
        let coords = sample_file_coords();
        for body in ["", "   ", "\n\t "] {
            let err = handler()
                .parse_upstream_checksum(&mut Cursor::new(body.as_bytes()), &coords)
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
                .parse_upstream_checksum(&mut Cursor::new(body.as_bytes()), &coords)
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

    // -- VersionDiscovery ----------------------------------------------------

    /// The capability group, via the accessor the consumers actually call.
    fn discovery() -> &'static dyn VersionDiscovery {
        static HANDLER: MavenFormatHandler = MavenFormatHandler;
        HANDLER
            .version_discovery()
            .expect("maven declares VersionDiscovery")
    }

    #[test]
    fn maven_declares_version_discovery() {
        assert!(handler().version_discovery().is_some());
    }

    #[test]
    fn upstream_metadata_path_is_the_a_level_document() {
        assert_eq!(
            discovery().upstream_metadata_path("com.google.guava:guava"),
            Some("/com/google/guava/guava/maven-metadata.xml".to_string()),
        );
    }

    #[test]
    fn upstream_metadata_path_differs_from_the_per_file_checksum_floor() {
        // The two are structurally distinct for Maven: the version set is
        // artifact-level, each checksum sits beside its own file.
        let coords = sample_file_coords();
        assert_ne!(
            discovery().upstream_metadata_path(&coords.name),
            handler().upstream_checksum_metadata_path(&coords),
        );
    }

    #[test]
    fn upstream_metadata_path_rejects_a_non_ga_or_unsafe_package() {
        for package in [
            "no-colon-here",
            ":empty-group",
            "group:",
            "com.example:..",
            "com..example:foo",
            "com/example:foo",
            "com.example:fo\no",
        ] {
            assert_eq!(
                discovery().upstream_metadata_path(package),
                None,
                "{package} must not compose an upstream path"
            );
        }
    }

    #[test]
    fn upstream_metadata_accept_is_empty() {
        assert!(discovery().upstream_metadata_accept().is_empty());
    }

    #[test]
    fn extract_upstream_versions_reads_the_a_level_list() {
        let body = br#"<metadata><versioning><versions>
            <version>31.1-jre</version><version>32.1.3-jre</version>
        </versions></versioning></metadata>"#;
        let got = discovery()
            .extract_upstream_versions(&mut Cursor::new(&body[..]))
            .unwrap();
        assert_eq!(got, ["31.1-jre", "32.1.3-jre"]);
    }

    #[test]
    fn extract_upstream_versions_degrades_open_on_a_malformed_body() {
        let got = discovery()
            .extract_upstream_versions(&mut Cursor::new(b"not xml".as_slice()))
            .expect("a malformed body is no signal, not an error");
        assert!(got.is_empty());
    }

    #[test]
    fn extract_upstream_versions_rejects_an_over_cap_body() {
        let oversized = vec![b'x'; metadata::UPSTREAM_METADATA_MAX_BYTES + 1];
        let err = discovery()
            .extract_upstream_versions(&mut Cursor::new(oversized.as_slice()))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn extract_dependency_specs_reads_the_poms_own_dependencies() {
        let body = br#"<project>
            <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
            <dependencies>
              <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>
                <version>31.1-jre</version></dependency>
              <dependency><groupId>org.junit</groupId><artifactId>junit</artifactId>
                <version>5.10.0</version><scope>test</scope></dependency>
            </dependencies>
        </project>"#;
        let specs = discovery()
            .extract_dependency_specs(&mut Cursor::new(&body[..]))
            .unwrap();
        assert_eq!(
            specs,
            [DependencySpec {
                name: "com.google.guava:guava".to_string(),
                range: "31.1-jre".to_string(),
            }]
        );
    }

    #[test]
    fn extract_dependency_specs_is_ok_empty_when_every_version_is_inherited() {
        // The distinction the cascade depends on: a POM this reader cannot
        // fully resolve partially warms the tree, it does not abort it.
        let body = br#"<project>
            <parent><groupId>org.springframework.boot</groupId>
              <artifactId>spring-boot-starter-parent</artifactId>
              <version>3.2.0</version></parent>
            <artifactId>demo</artifactId>
            <dependencies><dependency><groupId>org.springframework.boot</groupId>
              <artifactId>spring-boot-starter-web</artifactId></dependency></dependencies>
        </project>"#;
        let specs = discovery()
            .extract_dependency_specs(&mut Cursor::new(&body[..]))
            .expect("a parent-managed POM is valid input");
        assert!(specs.is_empty());
    }

    #[test]
    fn extract_dependency_specs_errs_on_non_pom_bytes() {
        let err = discovery()
            .extract_dependency_specs(&mut Cursor::new(b"PK\x03\x04".as_slice()))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn resolve_range_max_pins_the_soft_requirement_exactly() {
        let available = ["31.0-jre", "31.1-jre", "32.1.3-jre"];
        assert_eq!(
            discovery()
                .resolve_range_max("31.1-jre", &available)
                .unwrap()
                .as_deref(),
            Some("31.1-jre"),
            "a bare Maven version is a soft requirement — only itself satisfies it",
        );
    }

    #[test]
    fn resolve_range_max_is_none_when_upstream_lacks_the_version() {
        assert_eq!(
            discovery()
                .resolve_range_max("9.9.9", &["1.0", "2.0"])
                .unwrap(),
            None
        );
        assert_eq!(discovery().resolve_range_max("1.0", &[]).unwrap(), None);
    }

    #[test]
    fn resolve_range_max_ignores_surrounding_whitespace() {
        assert_eq!(
            discovery()
                .resolve_range_max("  1.0  ", &["1.0"])
                .unwrap()
                .as_deref(),
            Some("1.0")
        );
    }

    #[test]
    fn resolve_range_max_returns_the_upstream_spelling_verbatim() {
        // The returned string feeds a pull-through path, so it must be the
        // upstream entry, not a re-serialisation of the declared version.
        let out = discovery()
            .resolve_range_max("1.0", &[" 1.0 "])
            .unwrap()
            .expect("matched");
        assert_eq!(out, " 1.0 ");
    }

    #[test]
    fn download_config_members_are_inert_for_maven() {
        assert_eq!(discovery().download_config_path(), None);
        assert!(discovery()
            .compose_download_url_from_config(
                &mut Cursor::new(b"{}".as_slice()),
                "com.example:foo",
                "1.0",
                None,
            )
            .is_err());
        assert!(discovery()
            .resolve_download_url_from_metadata(
                &mut Cursor::new(b"<metadata/>".as_slice()),
                &sample_file_coords(),
            )
            .is_err());
    }

    // -- PayloadSbom / extract_sbom_from_payload ------------------------------

    fn payload_sbom() -> &'static dyn PayloadSbom {
        static HANDLER: MavenFormatHandler = MavenFormatHandler;
        HANDLER.payload_sbom().expect("maven declares PayloadSbom")
    }

    /// Wrap a `<dependencies>`/`<dependencyManagement>` fragment in a
    /// minimal well-formed POM, mirroring `pom.rs`'s own `pom_with` test
    /// helper.
    fn pom_wrapped(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.2.3</version>
{body}
</project>"#
        )
    }

    #[test]
    fn maven_declares_payload_sbom() {
        assert!(handler().payload_sbom().is_some());
    }

    #[test]
    fn extract_sbom_pom_yields_three_components_and_subject() {
        let xml = pom_wrapped(
            r#"<dependencyManagement>
                 <dependencies>
                   <dependency>
                     <groupId>com.example</groupId><artifactId>managed-lib</artifactId>
                     <version>2.0</version>
                   </dependency>
                 </dependencies>
               </dependencyManagement>
               <dependencies>
                 <dependency>
                   <groupId>com.example</groupId><artifactId>compile-lib</artifactId>
                   <version>1.1</version>
                 </dependency>
                 <dependency>
                   <groupId>com.example</groupId><artifactId>runtime-lib</artifactId>
                   <version>1.2</version><scope>runtime</scope>
                 </dependency>
                 <dependency>
                   <groupId>com.example</groupId><artifactId>managed-lib</artifactId>
                 </dependency>
               </dependencies>"#,
        );
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.pom",
        );
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::Bytes(xml.as_bytes()),
            )
            .expect("well-formed pom parses");
        assert_eq!(extraction.resolution, SbomResolution::Resolved);
        assert_eq!(extraction.skipped_non_registry, 0);
        let sbom = extraction.sbom.expect("sbom present");
        let subject = sbom.subject.expect("subject present");
        assert_eq!(subject.purl, "pkg:maven/com.example/app@1.2.3");
        assert_eq!(subject.ecosystem, Ecosystem::Maven);
        assert!(subject.direct_dependency);
        assert_eq!(sbom.components.len(), 3);
        let purls: Vec<&str> = sbom.components.iter().map(|c| c.purl.as_str()).collect();
        assert!(purls.contains(&"pkg:maven/com.example/compile-lib@1.1"));
        assert!(purls.contains(&"pkg:maven/com.example/runtime-lib@1.2"));
        assert!(
            purls.contains(&"pkg:maven/com.example/managed-lib@2.0"),
            "the dependencyManagement-resolved dependency must carry its managed version"
        );
        for c in &sbom.components {
            assert!(c.direct_dependency);
            assert!(c.licenses.is_empty());
            assert_eq!(c.ecosystem, Ecosystem::Maven);
        }
    }

    #[test]
    fn extract_sbom_pom_omits_property_and_range_dependencies_but_keeps_the_subject() {
        let xml = pom_wrapped(
            r#"<dependencies>
                 <dependency>
                   <groupId>com.example</groupId><artifactId>prop-lib</artifactId>
                   <version>${undeclared.version}</version>
                 </dependency>
                 <dependency>
                   <groupId>com.example</groupId><artifactId>range-lib</artifactId>
                   <version>[1.0,2.0)</version>
                 </dependency>
               </dependencies>"#,
        );
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.pom",
        );
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::Bytes(xml.as_bytes()),
            )
            .expect("well-formed pom parses even when every dependency is skipped");
        assert_eq!(extraction.resolution, SbomResolution::Resolved);
        let sbom = extraction.sbom.expect("sbom present");
        assert!(
            sbom.components.is_empty(),
            "an unresolved property and an unsupported range must not become components"
        );
        assert!(
            sbom.subject.is_some(),
            "subject stays present so osv can still query the artifact's own coordinate"
        );
    }

    #[test]
    fn extract_sbom_pom_reads_from_a_streaming_payload() {
        let xml = pom_wrapped(
            r#"<dependencies>
                 <dependency>
                   <groupId>com.example</groupId><artifactId>compile-lib</artifactId>
                   <version>1.1</version>
                 </dependency>
               </dependencies>"#,
        );
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.pom",
        );
        let stream: Box<dyn Read + Send> = Box::new(Cursor::new(xml.into_bytes()));
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::ReadStream(stream),
            )
            .expect("pom parses from a streaming payload");
        assert_eq!(extraction.resolution, SbomResolution::Resolved);
        assert_eq!(extraction.sbom.expect("sbom present").components.len(), 1);
    }

    #[test]
    fn extract_sbom_pom_degrades_to_unusable_lockfile_on_malformed_xml() {
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.pom",
        );
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::Bytes(b"not xml"),
            )
            .expect("a malformed pom degrades softly rather than erroring");
        assert_eq!(extraction.resolution, SbomResolution::UnusableLockfile);
        let sbom = extraction.sbom.expect("subject-only fallback");
        assert!(sbom.components.is_empty());
        assert!(sbom.subject.is_some());
    }

    #[test]
    fn extract_sbom_jar_with_embedded_pom_matches_the_pom_case() {
        let xml = pom_wrapped(
            r#"<dependencies>
                 <dependency>
                   <groupId>com.example</groupId><artifactId>compile-lib</artifactId>
                   <version>1.1</version>
                 </dependency>
               </dependencies>"#,
        );
        let jar_bytes = crate::test_support::build_wheel_zip(&[
            ("META-INF/maven/com.example/app/pom.xml", xml.as_bytes()),
            ("com/example/App.class", b"\xCA\xFE\xBA\xBE".as_slice()),
        ]);
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.jar",
        );
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::Bytes(&jar_bytes),
            )
            .expect("jar zip opens");
        assert_eq!(extraction.resolution, SbomResolution::Resolved);
        let sbom = extraction.sbom.expect("sbom present");
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(
            sbom.components[0].purl,
            "pkg:maven/com.example/compile-lib@1.1"
        );
        let subject = sbom.subject.expect("subject present");
        assert_eq!(subject.purl, "pkg:maven/com.example/app@1.2.3");
    }

    #[test]
    fn extract_sbom_jar_without_embedded_pom_is_a_subject_only_leaf() {
        let jar_bytes = crate::test_support::build_wheel_zip(&[(
            "com/example/App.class",
            b"\xCA\xFE\xBA\xBE".as_slice(),
        )]);
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.jar",
        );
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::Bytes(&jar_bytes),
            )
            .expect("jar zip opens");
        assert_eq!(extraction.resolution, SbomResolution::NoLockfile);
        let sbom = extraction
            .sbom
            .expect("sbom present — the leaf case still lets osv query the artifact");
        assert!(sbom.components.is_empty());
        let subject = sbom.subject.expect("subject present");
        assert_eq!(subject.purl, "pkg:maven/com.example/app@1.2.3");
    }

    #[test]
    fn extract_sbom_jar_ignores_a_traversal_named_entry_without_panicking() {
        let xml = pom_wrapped(
            r#"<dependencies>
                 <dependency>
                   <groupId>com.example</groupId><artifactId>compile-lib</artifactId>
                   <version>1.1</version>
                 </dependency>
               </dependencies>"#,
        );
        // Not the exact expected embedded-POM path — a traversal-shaped
        // entry name must never be treated as the artifact's own POM.
        let jar_bytes = crate::test_support::build_wheel_zip(&[(
            "META-INF/maven/../../../../etc/passwd",
            xml.as_bytes(),
        )]);
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.jar",
        );
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::Bytes(&jar_bytes),
            )
            .expect("jar zip opens without panicking on a traversal-shaped entry name");
        assert_eq!(extraction.resolution, SbomResolution::NoLockfile);
        assert!(extraction
            .sbom
            .expect("subject-only leaf")
            .components
            .is_empty());
    }

    #[test]
    fn extract_sbom_jar_degrades_to_subject_only_when_not_a_valid_zip() {
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.jar",
        );
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::Bytes(b"not a zip"),
            )
            .expect("a non-zip jar degrades softly rather than erroring");
        assert_eq!(extraction.resolution, SbomResolution::NoLockfile);
        let sbom = extraction.sbom.expect("subject-only fallback");
        assert!(sbom.components.is_empty());
        assert!(sbom.subject.is_some());
    }

    #[test]
    fn extract_sbom_jar_reads_from_a_streaming_payload() {
        let jar_bytes = crate::test_support::build_wheel_zip(&[(
            "com/example/App.class",
            b"\xCA\xFE\xBA\xBE".as_slice(),
        )]);
        let coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.jar",
        );
        let stream: Box<dyn Read + Send> = Box::new(Cursor::new(jar_bytes));
        let extraction = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::ReadStream(stream),
            )
            .expect("jar zip opens from a streaming payload");
        assert_eq!(extraction.resolution, SbomResolution::NoLockfile);
    }

    #[test]
    fn extract_sbom_returns_none_for_non_manifest_roles() {
        for path in [
            "com/example/app/1.2.3/app-1.2.3.jar.sha1",
            "com/example/app/maven-metadata.xml",
            "com/example/app/1.2.3/app-1.2.3-sources.jar",
            "com/example/app/1.2.3/app-1.2.3-javadoc.jar",
            "com/example/app/1.2.3/app-1.2.3.module",
        ] {
            let coords = file_coords("com.example:app", "1.2.3", path);
            let extraction = payload_sbom()
                .extract_sbom_from_payload(
                    &coords,
                    &serde_json::Value::Null,
                    PayloadAccess::Bytes(b"<project/>"),
                )
                .unwrap_or_else(|e| panic!("non-manifest role {path} must never error: {e}"));
            assert_eq!(extraction.sbom, None, "role for {path} must yield no SBOM");
            assert_eq!(extraction.resolution, SbomResolution::NoLockfile);
            assert_eq!(extraction.skipped_non_registry, 0);
        }
    }

    #[test]
    fn extract_sbom_errs_when_coords_name_is_not_colon_joined() {
        let mut coords = file_coords(
            "com.example:app",
            "1.2.3",
            "com/example/app/1.2.3/app-1.2.3.pom",
        );
        coords.name = "not-a-ga-name".to_string();
        let err = payload_sbom()
            .extract_sbom_from_payload(
                &coords,
                &serde_json::Value::Null,
                PayloadAccess::Bytes(b"<project/>"),
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }
}
