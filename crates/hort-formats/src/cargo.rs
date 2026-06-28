pub mod config;
// Cargo `IndexBuilder` impl (emits the sparse-index NDJSON document from
// a `Vec<VersionEntry>`). The matching `CargoVersionPayload` lives in
// `hort_app::use_cases::index_serve` and is re-exported through
// `index::CargoVersionPayload`. See explanation/index-construction.md.
pub mod index;
// Cargo sparse-index NDJSON streaming projector (see ADR 0026).
pub mod projection;

use std::io::BufRead as _;

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::format_handler::{DependencySpec, FormatHandler};
use hort_domain::ports::upstream_proxy::CountingReader;
use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};
use hort_domain::types::{ArtifactCoords, Ecosystem, PayloadAccess, Sbom, SbomComponent};

use crate::range_resolvers::resolve_semver_range_max;
use crate::sbom_helpers::{build_subject_component, strip_version_constraint};

/// Cargo format handler (RFC 2789 sparse registry).
///
/// Compiled-in Rust struct behind the `FormatHandler` trait boundary.
/// See explanation/format-handlers.md + ADR 0005.
pub struct CargoFormatHandler;

/// Maximum length of a cargo crate name in bytes.
///
/// Mirrors the upstream cargo grammar (`rust-lang/cargo`'s
/// `valid_package_name`): `[a-zA-Z0-9_-]{1,64}`. Values above 64 are
/// rejected at the path-parser boundary.
const CARGO_NAME_MAX: usize = 64;

/// Maximum length of a cargo version string accepted by the path
/// parser. Real semver values are well under this; the cap is a
/// belt-and-braces guard against attacker-controlled bytes flowing
/// into log lines and downstream URL composition.
const CARGO_VERSION_MAX: usize = 64;

/// Compressed-input cap for the whole stored cargo `.crate` artifact fed to
/// [`CargoFormatHandler::extract_dependency_specs`].
///
/// The cascade caller reads the artifact from CAS under a 32 MiB
/// **compressed** bound (`prefetch_dependencies::read_artifact_bytes`) before
/// handing it here, so this cap is set to that same 32 MiB to admit every
/// artifact the cascade can present while still bounding the buffer if a
/// future caller streams an unbounded reader in. It is a *compressed* cap (a
/// plausibility/storage bound, large — feedback_cap_taxonomy_streaming_vs_buffered);
/// the decompressed-output / compression-ratio / entry-count bomb guards live
/// in [`crate::archive_bounds::read_tar_gz_entry`], not here.
/// Deliberately mirrors npm's `NPM_TARBALL_MAX_BYTES`.
const CARGO_CRATE_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Parser-input sanity cap for a single `Cargo.toml` manifest EXTRACTED
/// from a `.crate` (the body [`parse_cargo_toml_runtime_dependencies`]
/// parses — NOT the `.crate`, NOT the sparse-index page). A memory-safety
/// bound generous over real manifests (typically < 16 KiB) but tight enough
/// to reject a pathological manifest. Decoupled from the publish-side
/// sparse-index per-entry cap so retuning one cannot move the other. The
/// archive-level decompression-bomb guard is `archive_bounds`' job, not this
/// cap.
const CARGO_MANIFEST_MAX_BYTES: usize = 1024 * 1024;

/// Parser-input sanity cap for the sparse-registry index `config.json`
/// ([`CargoFormatHandler::compose_download_url_from_config`] reads it). The
/// document is a tiny fixed object (`{"dl":…,"api":…}`, typically < 256 B);
/// 64 KiB is generous defence-in-depth above the fetch-time storage
/// backstop while tight enough to reject a pathological body without an
/// unbounded read. Far below `CARGO_MANIFEST_MAX_BYTES` — `config.json` is
/// structurally smaller than a manifest.
const CARGO_CONFIG_MAX_BYTES: usize = 64 * 1024;

/// Validate that `name` is a legal cargo crate name per the upstream
/// grammar (`[a-zA-Z0-9_-]{1,64}`).
///
/// Returns [`DomainError::Validation`] tagged with the structured
/// field name `cargo.name`. Error messages **never** include the
/// rejected input (it can be megabytes of attacker-controlled bytes
/// — log-pollution risk).
///
/// Visibility: `pub` so the cargo HTTP adapter (`hort-http-cargo`) can
/// reuse the same validator on the publish path before any storage
/// write. The download path (`parse_download_path`) was the original call
/// site; the publish path now shares it so the rejection grammar is
/// single-sourced.
pub fn validate_cargo_name(name: &str) -> DomainResult<()> {
    if name.is_empty() {
        return Err(DomainError::Validation(
            "cargo.name: empty crate name is not permitted".to_string(),
        ));
    }
    if name.len() > CARGO_NAME_MAX {
        return Err(DomainError::Validation(format!(
            "cargo.name: exceeds {CARGO_NAME_MAX}-byte cap"
        )));
    }
    for b in name.as_bytes() {
        let ok = b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-';
        if !ok {
            return Err(DomainError::Validation(
                "cargo.name: contains a byte outside [a-zA-Z0-9_-]".to_string(),
            ));
        }
    }
    Ok(())
}

/// crates.io registration-uniqueness key: lowercase AND fold `-`/`_` to a
/// single canonical separator (`-`). Spec 075.
///
/// DISTINCT from [`CargoFormatHandler::normalize_name`] (lowercase only,
/// separators PRESERVED — the index *lookup* key). This is used ONLY to
/// detect registration collisions at publish time:
///
/// ```text
///   normalize_name("Foo_Bar") = "foo_bar"   (lookup / storage / path)
///   cargo_collision_key("Foo_Bar") = "foo-bar"   (registration uniqueness)
/// ```
///
/// The canonical separator is `-` (not `_`), matching PEP 503's hyphen
/// canonical so the two formats' folds read consistently; the direction is
/// internal — it never reaches an upstream URL or the served index, only
/// the publish-time collision probe.
#[must_use]
pub fn cargo_collision_key(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// Validate that `version` matches a semver-ish allowlist:
/// `[0-9]+(\.[0-9]+){0,2}(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?`.
///
/// The check is intentionally permissive enough to accept the shapes
/// cargo emits in the wild (`1.2.3`, `1.2.3-rc.1`, `1.2.3+sha.abc`)
/// while rejecting anything carrying path separators, control bytes,
/// or wildcards. Returns [`DomainError::Validation`] tagged with
/// `cargo.version`.
///
/// Note: this is intentionally stricter than semver.org §9 — hyphens
/// inside prerelease/build segments are rejected. Cargo itself emits
/// dotted forms (e.g. `-rc.1`, not `-rc-1`) and the tighter charset
/// reduces parser surface. If a real-world cargo version ever fails
/// this validator, loosen the rule deliberately rather than as a
/// "bug fix".
///
/// Visibility: `pub` so the cargo HTTP adapter (`hort-http-cargo`) can
/// reuse the same validator on the publish path before any storage write.
pub fn validate_cargo_version(version: &str) -> DomainResult<()> {
    if version.is_empty() {
        return Err(DomainError::Validation(
            "cargo.version: empty version is not permitted".to_string(),
        ));
    }
    if version.len() > CARGO_VERSION_MAX {
        return Err(DomainError::Validation(format!(
            "cargo.version: exceeds {CARGO_VERSION_MAX}-byte cap"
        )));
    }

    // Split on optional `+<build>` suffix first.
    let (core_and_pre, build) = match version.split_once('+') {
        Some((lhs, rhs)) => (lhs, Some(rhs)),
        None => (version, None),
    };
    // Split the remainder on optional `-<prerelease>` suffix.
    let (core, prerelease) = match core_and_pre.split_once('-') {
        Some((lhs, rhs)) => (lhs, Some(rhs)),
        None => (core_and_pre, None),
    };

    // Core must be 1..=3 dot-separated numeric components, each
    // non-empty and digit-only.
    if core.is_empty() {
        return Err(DomainError::Validation(
            "cargo.version: core component is empty".to_string(),
        ));
    }
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err(DomainError::Validation(
            "cargo.version: core must be MAJOR[.MINOR[.PATCH]]".to_string(),
        ));
    }
    for p in &parts {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DomainError::Validation(
                "cargo.version: core components must be numeric".to_string(),
            ));
        }
    }

    // Prerelease and build, when present, are non-empty and limited to
    // ASCII alnum + `.` (matching the regex above).
    for (label, suffix) in [("prerelease", prerelease), ("build", build)] {
        if let Some(s) = suffix {
            if s.is_empty() {
                return Err(DomainError::Validation(format!(
                    "cargo.version: {label} segment is empty"
                )));
            }
            if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.') {
                return Err(DomainError::Validation(format!(
                    "cargo.version: {label} segment contains a byte outside [a-zA-Z0-9.]"
                )));
            }
        }
    }

    Ok(())
}

impl FormatHandler for CargoFormatHandler {
    fn format_key(&self) -> &str {
        "cargo"
    }

    /// Parse `api/v1/crates/{name}/{version}/download` into coordinates.
    ///
    /// The stored path uses the normalized (lowercased) crate name for
    /// consistent matching via `find_by_path`.
    fn parse_download_path(&self, path: &str) -> DomainResult<ArtifactCoords> {
        let path = path.strip_prefix('/').unwrap_or(path);

        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 6
            || parts[0] != "api"
            || parts[1] != "v1"
            || parts[2] != "crates"
            || parts[5] != "download"
            || parts[3].is_empty()
            || parts[4].is_empty()
        {
            return Err(DomainError::Validation(format!(
                "invalid Cargo download path: expected api/v1/crates/{{name}}/{{version}}/download, got: {path}"
            )));
        }

        let raw_name = parts[3];
        let version = parts[4];

        // Strict path-component validation BEFORE any further use. The
        // cargo grammar forbids `..`, control bytes, and >64-byte names;
        // the version allowlist forbids wildcards and path separators.
        // Both validators emit structured `cargo.<field>` error messages
        // without echoing the rejected input.
        validate_cargo_name(raw_name)?;
        validate_cargo_version(version)?;

        let name = self.normalize_name(raw_name);

        // The read path uses the SSOT constructor so it can never diverge
        // from the write-sites. `build` re-normalizes (same lowercase result),
        // so passing `raw_name` is equivalent to passing the already-normalized
        // `name`. cargo derives the filename from name+version, so `filename = None`.
        let path = self.build_artifact_logical_path(raw_name, version, None)?;

        Ok(ArtifactCoords {
            name,
            name_as_published: raw_name.to_string(),
            version: Some(version.to_string()),
            path,
            format: RepositoryFormat::Cargo,
            metadata: serde_json::Value::Null,
        })
    }

    /// The single logical-projection-path constructor for cargo.
    /// `crates/{n}/{version}/{n}-{version}.crate` with
    /// `n = normalize_name(name)` (lowercase, separators preserved per the
    /// registry-index spec). `filename` is ignored — cargo derives the
    /// canonical `.crate` filename from name+version.
    fn build_artifact_logical_path(
        &self,
        name: &str,
        version: &str,
        filename: Option<&str>,
    ) -> DomainResult<String> {
        let _ = filename;
        let n = self.normalize_name(name);
        Ok(format!("crates/{n}/{version}/{n}-{version}.crate"))
    }

    /// Lowercase the crate name. Cargo is effectively case-insensitive
    /// (crates.io reserves all case variants at registration), and the
    /// index path MUST use the lowercased form per RFC 2789.
    fn normalize_name(&self, name: &str) -> String {
        name.to_lowercase()
    }

    /// Cargo's registration-uniqueness key. crates.io forbids
    /// publishing a crate whose name collides under case AND `-`/`_`
    /// folding (`error-def` ≡ `error_def`), even though the index *lookup*
    /// path (`normalize_name`) preserves separators. So the collision key
    /// folds BOTH — distinct from `normalize_name`, which folds case only.
    fn collision_key(&self, name: &str) -> Option<String> {
        Some(cargo_collision_key(name))
    }

    /// Upload-payload metadata cap for cargo — 8 MiB.
    ///
    /// **No longer the upstream-body cap.** The streaming
    /// `parse_upstream_checksum` / `extract_upstream_versions` methods cap
    /// at the streaming plausibility ceiling
    /// ([`STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES`](crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES))
    /// per the cap taxonomy — a streamed path's cap is the plausibility /
    /// storage bound, not this small in-memory ceiling. This override
    /// survives because it is still a LIVE non-test caller's input: the
    /// upload-payload metadata cap model reads it via
    /// `IngestUseCase::effective_metadata_cap` (dynamic dispatch on
    /// `&dyn FormatHandler`) as the fallback ceiling for the
    /// `payload_metadata` carried on the cargo upstream-pull ingest paths
    /// (`hort-http-cargo::upstream_pull`). That payload is presently tiny
    /// (a `{source, upstream_url}` object), so the value is non-load-
    /// bearing in practice, but removing the override would silently drop
    /// cargo's upload-metadata cap to the 64 KiB trait default — a change
    /// to a different axis from this fix.
    ///
    /// 8 MiB was calibrated from a pessimistic 1000 versions × ~5 KiB per
    /// entry = ~5 MiB, plus headroom. The 64 KiB value lives only in
    /// `parse_publish_body` as `PUBLISH_META_CAP`, where the per-entry
    /// sizing is correct (the publish frame carries one version's metadata,
    /// structurally comparable to a single sparse-index entry).
    fn metadata_expected_max_bytes(&self) -> usize {
        8 * 1024 * 1024
    }

    /// Return the sparse-index path for `coords.name` so the upstream
    /// adapter knows where to fetch the NDJSON index file.
    ///
    /// Path is absolute (prefixed `/`) as required by
    /// `FormatHandler::upstream_checksum_metadata_path` callers.
    fn upstream_checksum_metadata_path(&self, coords: &ArtifactCoords) -> Option<String> {
        Some(format!("/{}", index_path_for(&coords.name)))
    }

    /// Parse the NDJSON body returned from the sparse index, find the line
    /// whose `vers` matches `coords.version`, and return the `cksum` value
    /// as an [`UpstreamPublishedChecksum`] with SHA-256.
    ///
    /// Each non-empty line must be a valid JSON object. The first matching
    /// line wins; all other fields are ignored.
    ///
    /// **Streaming.** `body` is a streaming reader over the sparse-index
    /// NDJSON. The walk is line-by-line via [`std::io::BufRead`] — one
    /// NDJSON line in memory at a time, never the whole page — preserving
    /// the error taxonomy byte-identically (requires-a-version,
    /// not-valid-NDJSON, no-entry-for-version, has-no-cksum, input-size
    /// cap, and the skip-line-without-`vers` policy). The shared
    /// [`CargoSparseIndexProjector`](crate::cargo::projection::CargoSparseIndexProjector)
    /// is NOT used here: it is fail-closed on a missing-`vers` line, but
    /// this method's contract is to SKIP such lines, so the streaming line
    /// walk reproduces the exact behaviour.
    fn parse_upstream_checksum(
        &self,
        body: &mut dyn std::io::Read,
        coords: &ArtifactCoords,
    ) -> DomainResult<UpstreamPublishedChecksum> {
        let version = coords.version.as_deref().ok_or_else(|| {
            DomainError::Validation(
                "upstream Cargo index parser requires a version in coords".to_string(),
            )
        })?;

        // Streaming plausibility size cap — defence in depth above the
        // fetch-time streaming cap. Because this method STREAMS the body
        // line-by-line, the ceiling is the plausibility / storage bound
        // (`STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES`, aligned with
        // `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE`), NOT a small in-memory
        // ceiling. The retired byte-slice impl checked `body.len() > max`
        // BEFORE parsing, so an over-cap body was always rejected regardless
        // of where the matching line sat. To preserve that, the walk reads
        // the WHOLE body (counted, one NDJSON line in memory at a time —
        // never the whole page), then applies the cap on the true total
        // before returning the captured first-match. Diagnostic names cap
        // and observed length but never echoes the body bytes.
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let mut reader = std::io::BufReader::new(CountingReader::new(body));
        let counter = {
            // Recover the shared counter from the BufReader's inner.
            reader.get_ref().counter()
        };

        let mut matched: Option<DomainResult<UpstreamPublishedChecksum>> = None;
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = reader
                .read_until(b'\n', &mut line)
                .map_err(|e| DomainError::Validation(format!("cargo index read error: {e}")))?;
            if n == 0 {
                break;
            }
            // Skip empty / whitespace-only lines.
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let entry: serde_json::Value = serde_json::from_slice(&line).map_err(|e| {
                DomainError::Validation(format!(
                    "upstream Cargo index body is not valid NDJSON: {e}"
                ))
            })?;
            let Some(vers) = entry.get("vers").and_then(|v| v.as_str()) else {
                continue;
            };
            if vers != version || matched.is_some() {
                continue;
            }
            // First matching line — extract cksum (captured; the loop
            // continues to EOF so the size cap sees the full body).
            matched = Some(match entry.get("cksum").and_then(|v| v.as_str()) {
                Some(cksum) => {
                    UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, cksum.to_lowercase())
                }
                None => Err(DomainError::Validation(format!(
                    "upstream Cargo index entry for {}@{} has no cksum",
                    coords.name, version
                ))),
            });
        }

        let total = counter.load(std::sync::atomic::Ordering::Relaxed);
        if total > max as u64 {
            return Err(DomainError::Validation(format!(
                "upstream cargo metadata body is {total} bytes; streaming plausibility max is {max}"
            )));
        }

        matched.unwrap_or_else(|| {
            Err(DomainError::Validation(format!(
                "upstream Cargo index has no entry for {}@{}",
                coords.name, version
            )))
        })
    }

    /// Extract the upstream-published version-string set from a cargo
    /// sparse-index NDJSON body.
    ///
    /// One non-blank line per published version; each line is a JSON
    /// object with a `vers` field. Same shape as the hot-path trigger
    /// reader in `crates/hort-http-cargo/src/index_cache.rs::parse_upstream_versions`
    /// (lifted verbatim) so the cron-tier and serve-site readers
    /// stay in lock-step. Lines that fail to parse / lack `vers` are
    /// skipped per the hot-path policy (a single malformed line on
    /// `crates.io` must not starve the rest of the catalog).
    ///
    /// Bounded by the streaming plausibility ceiling
    /// ([`STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES`](crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES)
    /// = 64 MiB) — this method STREAMS the body line-by-line, so per the
    /// cap taxonomy its ceiling is the plausibility / storage bound
    /// (aligned with the `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE` fetch
    /// backstop), NOT a small in-memory ceiling. Bodies above that are
    /// rejected as `Validation`.
    ///
    /// **Streaming.** `body` is a streaming reader over the NDJSON page;
    /// the walk is line-by-line via [`std::io::BufRead`] (one line in
    /// memory at a time, never the whole page) and SKIPS lines that fail
    /// to parse or lack `vers`. The size cap is enforced mid-stream. The
    /// fail-closed shared projector is not used (it would reject a
    /// missing-`vers` line that this method skips).
    fn extract_upstream_versions(&self, body: &mut dyn std::io::Read) -> DomainResult<Vec<String>> {
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let mut reader = std::io::BufReader::new(CountingReader::new(body));
        let counter = reader.get_ref().counter();
        let mut out: Vec<String> = Vec::new();
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = reader
                .read_until(b'\n', &mut line)
                .map_err(|e| DomainError::Validation(format!("cargo index read error: {e}")))?;
            if n == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if let Some(v) = serde_json::from_slice::<serde_json::Value>(&line)
                .ok()
                .and_then(|v| v.get("vers").and_then(|x| x.as_str()).map(str::to_string))
            {
                out.push(v);
            }
        }
        let total = counter.load(std::sync::atomic::Ordering::Relaxed);
        if total > max as u64 {
            return Err(DomainError::Validation(format!(
                "cargo upstream metadata body is {total} bytes; streaming plausibility max is {max}"
            )));
        }
        Ok(out)
    }

    /// Cargo sparse-index path — version-agnostic. Coincides with the
    /// per-crate checksum-metadata path
    /// ([`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path))
    /// because the sparse-index entry is one NDJSON document carrying
    /// every version + its `cksum`. The path layout (1-char, 2-char,
    /// 3-char prefix buckets) is encoded in [`index_path_for`].
    fn upstream_metadata_path(&self, package: &str) -> Option<String> {
        Some(format!("/{}", index_path_for(package)))
    }

    /// Extract a deterministic SBOM from the cargo metadata the handler
    /// captured at ingest. Pure function — does not read `payload`.
    ///
    /// Recognises both shapes:
    /// - **Registry-index / publish-body shape:** the JSON object with a
    ///   top-level `deps: [{name, req, optional, ...}]` array. This is
    ///   what `parse_publish_body` produces and what the sparse index
    ///   stores per version.
    /// - **Cargo.toml-as-JSON shape:** an object with `dependencies`,
    ///   `dev-dependencies`, and `build-dependencies` tables (each an
    ///   object mapping crate name → `string` or `{version, ...}`).
    ///
    /// PURL form is `pkg:cargo/{name}@{version}` (cargo names are
    /// case-insensitive lowercase ASCII, no escaping needed). Licenses
    /// come from `package.license` (string SPDX expression). The
    /// `license-file` form is intentionally ignored — it points to a
    /// path on disk, not an SPDX identifier.
    ///
    /// `direct_dependency`:
    /// - Index-shape: `true` unless `optional=true`.
    /// - Cargo.toml-shape: `true` for `dependencies`, `false` for
    ///   `dev-dependencies` and `build-dependencies`.
    ///
    /// See explanation/scanning-pipeline.md for the SBOM extraction design.
    fn extract_sbom(
        &self,
        coords: &ArtifactCoords,
        format_metadata: &serde_json::Value,
        _payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Sbom>> {
        let licenses = extract_cargo_license_list(format_metadata);

        // Build the subject from coords so the crate itself appears in
        // the BOM — required for osv-scanner to detect vulnerabilities
        // on the crate (not just its declared deps).
        let subject = build_subject_component(
            coords,
            Ecosystem::Cargo,
            "pkg:cargo/",
            &coords.name,
            licenses.clone(),
        );

        let mut components = Vec::new();

        // Registry-index / publish-body shape.
        if let Some(deps) = format_metadata.get("deps").and_then(|v| v.as_array()) {
            for dep in deps {
                let Some(name) = dep.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let version = dep
                    .get("req")
                    .and_then(|v| v.as_str())
                    .map(strip_version_constraint)
                    .filter(|v| !v.is_empty());
                let purl = match version.as_deref() {
                    Some(v) => format!("pkg:cargo/{name}@{v}"),
                    None => format!("pkg:cargo/{name}"),
                };
                let optional = dep
                    .get("optional")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                components.push(SbomComponent {
                    purl,
                    name: name.to_string(),
                    version,
                    ecosystem: Ecosystem::Cargo,
                    licenses: licenses.clone(),
                    direct_dependency: !optional,
                });
            }
            return Ok(Some(Sbom {
                subject: Some(subject),
                components,
            }));
        }

        // Cargo.toml-shape fallback (top-level dependency tables).
        let sections: &[(&str, bool)] = &[
            ("dependencies", true),
            ("dev-dependencies", false),
            ("build-dependencies", false),
        ];
        for (section, direct) in sections {
            let Some(table) = format_metadata.get(*section).and_then(|v| v.as_object()) else {
                continue;
            };
            for (name, value) in table {
                let version = cargo_toml_version_from_value(value);
                let purl = match version.as_deref() {
                    Some(v) => format!("pkg:cargo/{name}@{v}"),
                    None => format!("pkg:cargo/{name}"),
                };
                components.push(SbomComponent {
                    purl,
                    name: name.clone(),
                    version,
                    ecosystem: Ecosystem::Cargo,
                    licenses: licenses.clone(),
                    direct_dependency: *direct,
                });
            }
        }

        Ok(Some(Sbom {
            subject: Some(subject),
            components,
        }))
    }

    /// Extract the *declared runtime* dependency specs from the **stored
    /// cargo `.crate` artifact stream**.
    ///
    /// **Input is the gzip-tar `.crate` artifact, NOT a sparse-index entry.**
    /// The transitive prefetch cascade hands this method the raw stored
    /// artifact it read from CAS (`read_artifact_bytes`), which for cargo is
    /// the `.crate` — a gzip-tarball with a single top-level
    /// `{name}-{version}/` directory containing `Cargo.toml`. The declared
    /// runtime dependencies live in that `Cargo.toml`'s `[dependencies]`
    /// table, so this method locates and reads that entry, then parses it.
    ///
    /// **The sparse-index NDJSON parser is unchanged and still in use.**
    /// [`extract_upstream_versions`](Self::extract_upstream_versions) and
    /// [`parse_upstream_checksum`](Self::parse_upstream_checksum) legitimately
    /// read the sparse index (that is what the registry serves them); only
    /// THIS method switched to `Cargo.toml`. The two paths read different
    /// bytes for different purposes and do not share a parser.
    ///
    /// **Runtime classes only.** The extracted manifest is parsed by
    /// [`parse_cargo_toml_runtime_dependencies`], which reads ONLY the
    /// `[dependencies]` table. `[dev-dependencies]` (test-only) and
    /// `[build-dependencies]` (`build.rs`-only) are intentionally dropped.
    /// **`[target.*.dependencies]` are out of scope for v1** (best-effort,
    /// consistent with cascade warming — a platform-gated dep is not on the
    /// universal run path); this limitation is explicit, not silent.
    ///
    /// **Renamed deps.** `foo = { package = "bar", version = "1" }`
    /// declares a dep on crate `bar`; the parser uses the `package` value as
    /// the spec name, never the TOML key (see
    /// [`parse_cargo_toml_runtime_dependencies`]).
    ///
    /// **Archive bounds.** Extraction routes through the audited
    /// [`crate::archive_bounds::read_tar_gz_entry`]: the gzip decompressor is
    /// wrapped in a `BoundedReader` (compression-ratio + cumulative-output
    /// cap), entry count is bounded, and nested archives are rejected. The cap
    /// is *cumulative* across the sequential tar scan, so `Cargo.toml`
    /// MUST be an early entry — which every real `.crate` satisfies (cargo
    /// writes the manifest near the front).
    ///
    /// **Caps.** The compressed `.crate` stream is read into a capped buffer
    /// bounded by [`CARGO_CRATE_MAX_BYTES`] (32 MiB compressed, matching the
    /// cascade's own artifact bound); the *extracted* `Cargo.toml` entry is
    /// then bounded by [`CARGO_MANIFEST_MAX_BYTES`] as a parser-input sanity
    /// cap. The decompression-bomb guard is `archive_bounds`' job, not a cap
    /// here.
    ///
    /// **Errors.**
    /// - Input not a gzip-tar → `Validation` — reported honestly, not as a
    ///   JSON/TOML parse error.
    /// - No top-level `{dir}/Cargo.toml` in the archive → `Validation`
    ///   (a well-formed `.crate` always has it; absence is corruption).
    /// - Manifest present but unparseable TOML → `Validation` (non-retry).
    /// - Any `archive_bounds` guard trip → `Validation` (non-retry).
    /// - A well-formed manifest with zero declared runtime deps →
    ///   `Ok(vec![])`, never `Err`.
    ///
    /// **Streaming.** `content` stays a `&mut dyn Read` (the streaming-port
    /// signature is unchanged). The compressed bytes are read into a capped
    /// `Vec` to obtain the length the gzip ratio-bound needs (gzip carries no
    /// reliable size header) — the cascade already buffers the compressed
    /// artifact, so this adds no second fetch.
    fn extract_dependency_specs(
        &self,
        content: &mut dyn std::io::Read,
    ) -> DomainResult<Vec<DependencySpec>> {
        // Read the compressed .crate into a capped buffer to obtain its
        // length (gzip has no reliable decompressed-size header, so the
        // ratio bound needs the compressed length passed explicitly).
        let buf = crate::stream_helpers::read_to_capped_vec(
            content,
            CARGO_CRATE_MAX_BYTES,
            |len, max| format!("cargo artifact is {len} bytes; cargo crate max is {max}"),
        )?;
        // Locate the single top-level `{dir}/Cargo.toml` inside the gzip-tar
        // under the audited archive_bounds caps. Cargo.toml must be an early
        // entry. The predicate matches an entry path with exactly one segment
        // before `/Cargo.toml` (the `{name}-{version}/` dir) without
        // hardcoding the crate name or version.
        let manifest = crate::archive_bounds::read_tar_gz_entry(
            &buf[..],
            buf.len() as u64,
            crate::archive_bounds::BoundsConfig::default_for_metadata_extraction(),
            is_top_level_cargo_toml,
        )?
        .ok_or_else(|| {
            DomainError::Validation(
                "cargo .crate is missing a top-level {name}-{version}/Cargo.toml (corrupt artifact)"
                    .to_string(),
            )
        })?;
        parse_cargo_toml_runtime_dependencies(&manifest)
    }

    /// Resolve a cargo semver range against an `available` set,
    /// returning the highest matching version string.
    ///
    /// Cargo's range grammar IS the `semver` crate's default
    /// interpretation (caret, tilde, wildcards, comparison
    /// operators, AND-combined comma-separated clauses); the
    /// resolver is identical to npm's. See
    /// [`resolve_semver_range_max`] for the pre-release inclusion
    /// policy and best-effort contract.
    ///
    /// Returns the matching version's original string from
    /// `available` (NOT a re-serialised form), so the caller can
    /// feed it back into the sparse-index lookup verbatim.
    fn resolve_range_max(&self, range: &str, available: &[&str]) -> DomainResult<Option<String>> {
        Ok(resolve_semver_range_max(range, available))
    }

    /// cargo's download URL is authoritatively defined by the sparse
    /// registry index `config.json` `dl` field, so the prefetch
    /// orchestrator must fetch `/config.json` from the index host before it
    /// can compose a download URL. See `explanation/prefetch-pipeline.md`
    /// and <https://doc.rust-lang.org/cargo/reference/registry-index.html#index-configuration>.
    fn download_config_path(&self) -> Option<String> {
        Some("/config.json".to_string())
    }

    /// Compose the absolute `.crate` download URL for `(package, version)`
    /// from the registry's `config.json` document — the authoritative
    /// resolution the cargo spec prescribes (the `dl` field), identical to
    /// the client-driven pull-through's
    /// [`compose_download_url`](crate::cargo::config::compose_download_url)
    /// path so prefetch and serve-site cannot diverge.
    ///
    /// **Streaming** (ADR 0026): `body` is a `&mut dyn Read` so the document
    /// never lands in a buffer at the port boundary. It is read under a
    /// small bounded cap ([`CARGO_CONFIG_MAX_BYTES`] = 64 KiB — `config.json`
    /// is a tiny fixed object) via
    /// [`read_to_capped_vec`](crate::stream_helpers::read_to_capped_vec); a
    /// body over the cap is rejected as `Validation` before parsing.
    ///
    /// Parses the bytes via
    /// [`parse_registry_config`](crate::cargo::config::parse_registry_config)
    /// (a malformed body / missing `dl` is `Validation`), then substitutes
    /// the spec's five `dl` placeholders — or appends the spec-default
    /// `/{crate}/{version}/download` suffix when the template has none
    /// (crates.io's shape). `cksum_hex` feeds the `{sha256-checksum}`
    /// placeholder for registries that template on it.
    fn compose_download_url_from_config(
        &self,
        body: &mut dyn std::io::Read,
        package: &str,
        version: &str,
        cksum_hex: Option<&str>,
    ) -> DomainResult<String> {
        let buf =
            crate::stream_helpers::read_to_capped_vec(body, CARGO_CONFIG_MAX_BYTES, |len, max| {
                format!("cargo config.json body is {len} bytes; cargo config max is {max}")
            })?;
        let config = config::parse_registry_config(&buf)?;
        let url = config::compose_download_url(&config, package, version, cksum_hex);
        // Defense-in-depth, symmetric with npm's
        // `resolve_download_url_from_metadata` scheme reject: the `dl` value is
        // asserted by the upstream registry's `config.json`, so a hostile or
        // compromised registry could point it at a non-http(s) target
        // (`file://`, `ftp://`, a schemeless string, …). Reject a non-http(s)
        // scheme at resolution so it never reaches the fetch layer. `http` is
        // permitted — cargo plaintext is the operator-tracked
        // `insecure_upstream_url` opt-in (unlike npm's stricter https-only).
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(DomainError::Validation(format!(
                "cargo registry config `dl` composed a non-http(s) download URL: {url}"
            )));
        }
        Ok(url)
    }
}

/// Extract a version string from a Cargo.toml-shape dependency value.
///
/// Cargo accepts either:
/// - `"1.0"` — bare semver-range string.
/// - `{ "version": "1.0", "features": [...] }` — table form.
///
/// The version is stripped of `^`/`~`/`=` prefixes the same way npm
/// strips them. Path-only or git-only deps (no `version` key) yield
/// `None`.
fn cargo_toml_version_from_value(value: &serde_json::Value) -> Option<String> {
    let raw = match value {
        serde_json::Value::String(s) => Some(s.as_str()),
        serde_json::Value::Object(map) => map.get("version").and_then(|v| v.as_str()),
        _ => None,
    }?;
    let stripped = strip_version_constraint(raw);
    if stripped.is_empty() {
        None
    } else {
        Some(stripped)
    }
}

/// Whether `path` is the single top-level `Cargo.toml` of a `.crate`
/// archive.
///
/// A real `.crate` lays out a single top-level `{name}-{version}/`
/// directory; the manifest is at `{name}-{version}/Cargo.toml`. This
/// predicate matches an entry path with EXACTLY one path segment before
/// `/Cargo.toml` — robust to any `{name}-{version}` spelling, without
/// hardcoding the crate name or version. Nested manifests
/// (`{dir}/vendor/x/Cargo.toml`, `{dir}/Cargo.toml.orig`, …) are NOT
/// matched. A leading `./` (some tar writers prefix paths) is tolerated.
fn is_top_level_cargo_toml(path: &str) -> bool {
    let path = path.strip_prefix("./").unwrap_or(path);
    let Some(dir) = path.strip_suffix("/Cargo.toml") else {
        return false;
    };
    // Exactly one segment before `/Cargo.toml`: a non-empty `{dir}` with no
    // further `/`.
    !dir.is_empty() && !dir.contains('/')
}

/// Parse the *declared runtime* dependency specs from a `Cargo.toml`
/// manifest body.
///
/// **Runtime classes only.** Reads ONLY the top-level `[dependencies]`
/// table. `[dev-dependencies]` (test-only) and `[build-dependencies]`
/// (`build.rs`-only) are intentionally dropped — neither carries into the
/// production artifact, and following them inflates the transitive prefetch
/// cascade for no run-path value (mirrors the npm runtime-only boundary).
/// `[target.*.dependencies]` are out of scope for v1 (best-effort; see the
/// [`CargoFormatHandler::extract_dependency_specs`] doc).
///
/// **Renamed deps.** For `foo = { package = "bar", version = "1" }`
/// the dependency is on crate **`bar`** (the fetch target), not `foo`. The
/// published `.crate` `Cargo.toml` preserves the `package` rename key, so the
/// parser uses it as the [`DependencySpec::name`] when present, else the TOML
/// key. Using the TOML key would enqueue a prefetch for a non-existent crate.
///
/// **Version range.** Comes from the string value (`serde = "1"`) or the
/// table's `version` key (`tokio = { version = "1", .. }`), kept VERBATIM —
/// [`CargoFormatHandler::resolve_range_max`] re-parses it as a semver range,
/// so it must not be pre-stripped here.
///
/// **Best-effort tolerance.** An entry with neither a string value nor a
/// resolvable `version` key (path-only / git-only deps) is skipped rather
/// than surfaced with an empty range — `resolve_range_max("")` would
/// unparseable-fail anyway. This mirrors the pre-076 sparse-index impl's
/// "drop a dep without a `req`" tolerance.
///
/// Bounded by [`CARGO_MANIFEST_MAX_BYTES`] as a parser-input sanity cap;
/// a manifest above that is rejected as `Validation`. Only a body that is
/// not valid TOML at all surfaces a `Validation` error; an absent
/// `[dependencies]` table returns `Ok(vec![])`.
fn parse_cargo_toml_runtime_dependencies(manifest: &[u8]) -> DomainResult<Vec<DependencySpec>> {
    if manifest.len() > CARGO_MANIFEST_MAX_BYTES {
        return Err(DomainError::Validation(format!(
            "cargo Cargo.toml body is {} bytes; cargo manifest max is {CARGO_MANIFEST_MAX_BYTES}",
            manifest.len()
        )));
    }
    let text = std::str::from_utf8(manifest)
        .map_err(|e| DomainError::Validation(format!("Cargo.toml is not valid UTF-8: {e}")))?;
    let doc: toml::Value = toml::from_str(text)
        .map_err(|e| DomainError::Validation(format!("Cargo.toml is not valid TOML: {e}")))?;
    let Some(deps) = doc.get("dependencies").and_then(|v| v.as_table()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(deps.len());
    for (key, value) in deps {
        // Renamed dep: `{ package = "bar", .. }` declares a dep on `bar`,
        // not on the TOML key. Use the `package` value as the name when
        // present, else the TOML key.
        let name = value
            .as_table()
            .and_then(|t| t.get("package"))
            .and_then(|p| p.as_str())
            .unwrap_or(key.as_str())
            .to_string();
        // Range comes from the string value or the table's `version` key,
        // kept verbatim for `resolve_range_max`. A dep with neither
        // (path-only / git-only) is best-effort dropped.
        let Some(range) = cargo_toml_range_from_value(value) else {
            continue;
        };
        out.push(DependencySpec { name, range });
    }
    Ok(out)
}

/// Extract a VERBATIM version range from a `Cargo.toml`-shape dependency
/// value, for [`parse_cargo_toml_runtime_dependencies`].
///
/// Cargo accepts either `serde = "1"` (bare range string) or
/// `tokio = { version = "1", .. }` (table form). Returns the range string
/// unmodified — unlike [`cargo_toml_version_from_value`] (which strips
/// `^`/`~`/`=` for SBOM purl emission), the cascade re-parses this as a
/// semver range, so it must NOT be pre-stripped. A value with neither a
/// string nor a `version` key (path-only / git-only) yields `None`.
fn cargo_toml_range_from_value(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(s) if !s.is_empty() => Some(s.clone()),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

/// Read a license expression out of a cargo manifest.
///
/// Looks at the top-level `license` first (registry-index shape, which
/// flattens `package.license` into the top), then falls back to
/// `package.license` (Cargo.toml shape). The `license-file` field is
/// deliberately NOT surfaced — it's a path, not an SPDX identifier, and
/// downstream consumers expect identifiers.
fn extract_cargo_license_list(metadata: &serde_json::Value) -> Vec<String> {
    if let Some(s) = metadata.get("license").and_then(|v| v.as_str()) {
        if !s.is_empty() {
            return vec![s.to_string()];
        }
    }
    if let Some(s) = metadata
        .get("package")
        .and_then(|p| p.get("license"))
        .and_then(|v| v.as_str())
    {
        if !s.is_empty() {
            return vec![s.to_string()];
        }
    }
    Vec::new()
}

/// Compute the Cargo index prefix for a crate name per RFC 2789.
///
/// | Name length | Prefix           |
/// |-------------|------------------|
/// | 1           | `1`              |
/// | 2           | `2`              |
/// | 3           | `3/{first}`      |
/// | 4+          | `{aa}/{bb}`      |
///
/// Uses char-aware slicing rather than byte-slicing so non-ASCII input cannot
/// panic. Cargo itself restricts names to ASCII, so this is defensive only.
///
/// # Panics
///
/// Panics on empty input. The caller is expected to have validated crate
/// name length earlier in the pipeline.
pub(crate) fn prefix_for(crate_name: &str) -> String {
    let lower = crate_name.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    match chars.len() {
        0 => panic!("crate name must be non-empty"),
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", chars[0]),
        _ => {
            let aa: String = chars[..2].iter().collect();
            let bb: String = chars[2..4].iter().collect();
            format!("{aa}/{bb}")
        }
    }
}

/// Build the sparse-index path for a crate name per RFC 2789.
///
/// # Panics
///
/// Panics on empty input. The caller is expected to have validated crate
/// name length earlier in the pipeline.
pub fn index_path_for(crate_name: &str) -> String {
    let lower = crate_name.to_lowercase();
    let prefix = prefix_for(crate_name);
    format!("{prefix}/{lower}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> CargoFormatHandler {
        CargoFormatHandler
    }

    // -- format_key -----------------------------------------------------------

    #[test]
    fn format_key_is_cargo() {
        assert_eq!(handler().format_key(), "cargo");
    }

    // -- normalize_name -------------------------------------------------------

    #[test]
    fn normalize_lowercases_mixed_case() {
        assert_eq!(handler().normalize_name("Serde"), "serde");
    }

    #[test]
    fn normalize_preserves_already_lowercase() {
        assert_eq!(handler().normalize_name("tokio"), "tokio");
    }

    #[test]
    fn normalize_preserves_hyphens_and_underscores() {
        // Unlike PyPI, cargo does NOT fold separators together.
        assert_eq!(handler().normalize_name("rust_decimal"), "rust_decimal");
        assert_eq!(handler().normalize_name("my-crate"), "my-crate");
    }

    // -- parse_download_path --------------------------------------------------

    #[test]
    fn parse_valid_download_path() {
        let coords = handler()
            .parse_download_path("api/v1/crates/serde/1.0.0/download")
            .unwrap();
        assert_eq!(coords.name, "serde");
        assert_eq!(coords.version.as_deref(), Some("1.0.0"));
        assert_eq!(coords.path, "crates/serde/1.0.0/serde-1.0.0.crate");
        assert_eq!(coords.format, RepositoryFormat::Cargo);
    }

    #[test]
    fn parse_download_path_with_leading_slash() {
        let coords = handler()
            .parse_download_path("/api/v1/crates/tokio/1.35.1/download")
            .unwrap();
        assert_eq!(coords.name, "tokio");
        assert_eq!(coords.version.as_deref(), Some("1.35.1"));
        assert_eq!(coords.path, "crates/tokio/1.35.1/tokio-1.35.1.crate");
    }

    #[test]
    fn parse_download_path_lowercases_name() {
        let coords = handler()
            .parse_download_path("api/v1/crates/Serde/1.0.0/download")
            .unwrap();
        assert_eq!(coords.name, "serde");
        // Stored path also uses the lowercased form for consistent lookup.
        assert_eq!(coords.path, "crates/serde/1.0.0/serde-1.0.0.crate");
    }

    #[test]
    fn parse_download_path_preserves_prerelease_version() {
        let coords = handler()
            .parse_download_path("api/v1/crates/my-crate/1.0.0-beta.1/download")
            .unwrap();
        assert_eq!(coords.version.as_deref(), Some("1.0.0-beta.1"));
        assert_eq!(
            coords.path,
            "crates/my-crate/1.0.0-beta.1/my-crate-1.0.0-beta.1.crate"
        );
    }

    // -- build_artifact_logical_path ------------------------------------------

    /// `crates/{n}/{version}/{n}-{version}.crate` with `n` lowercased.
    /// `filename` is ignored (cargo derives it from name+version).
    #[test]
    fn build_logical_path_basic() {
        assert_eq!(
            handler()
                .build_artifact_logical_path("serde", "1.0.0", None)
                .unwrap(),
            "crates/serde/1.0.0/serde-1.0.0.crate"
        );
    }

    /// `filename` is ignored for cargo.
    #[test]
    fn build_logical_path_ignores_filename() {
        assert_eq!(
            handler()
                .build_artifact_logical_path("serde", "1.0.0", Some("garbage"))
                .unwrap(),
            "crates/serde/1.0.0/serde-1.0.0.crate"
        );
    }

    /// Round-trip / inverse: the canonical download request parses to the
    /// canonical path, and rebuilding from the parsed (name, version)
    /// yields the same path.
    #[test]
    fn build_logical_path_round_trip() {
        let coords = handler()
            .parse_download_path("api/v1/crates/serde/1.0.0/download")
            .unwrap();
        assert_eq!(coords.path, "crates/serde/1.0.0/serde-1.0.0.crate");
        assert_eq!(
            handler()
                .build_artifact_logical_path(&coords.name, coords.version.as_deref().unwrap(), None)
                .unwrap(),
            coords.path
        );
    }

    /// Case-folds: `Serde` and `serde` collapse to the same path
    /// (`normalize_name` lowercases).
    #[test]
    fn build_logical_path_case_folds() {
        let upper = handler()
            .build_artifact_logical_path("Serde", "1.0.0", None)
            .unwrap();
        let lower = handler()
            .build_artifact_logical_path("serde", "1.0.0", None)
            .unwrap();
        assert_eq!(upper, "crates/serde/1.0.0/serde-1.0.0.crate");
        assert_eq!(upper, lower);
    }

    /// Separators are PRESERVED (NOT folded): `foo-bar` and `foo_bar`
    /// build DISTINCT paths. Pins the cargo registry-index rule — folding
    /// `-`/`_` would silently break the separator invariant.
    #[test]
    fn build_logical_path_preserves_separators_distinct() {
        let hyphen = handler()
            .build_artifact_logical_path("foo-bar", "1.0.0", None)
            .unwrap();
        let underscore = handler()
            .build_artifact_logical_path("foo_bar", "1.0.0", None)
            .unwrap();
        assert_eq!(hyphen, "crates/foo-bar/1.0.0/foo-bar-1.0.0.crate");
        assert_eq!(underscore, "crates/foo_bar/1.0.0/foo_bar-1.0.0.crate");
        assert_ne!(hyphen, underscore);
    }

    // -- cargo_collision_key + collision_key ----------------------------------

    /// The collision key folds BOTH case and `-`/`_` (to `-`) — the
    /// crates.io registration-uniqueness key, DISTINCT from `normalize_name`
    /// (case-only).
    #[test]
    fn cargo_collision_key_folds_case_and_separators() {
        assert_eq!(cargo_collision_key("Foo_Bar"), "foo-bar");
        assert_eq!(cargo_collision_key("foo-bar"), "foo-bar");
        assert_eq!(cargo_collision_key("foo_bar"), "foo-bar");
        assert_eq!(cargo_collision_key("FOO"), "foo");
        assert_eq!(cargo_collision_key("a_b-c"), "a-b-c");
        // Contrast with normalize_name, which preserves separators.
        assert_eq!(handler().normalize_name("foo_bar"), "foo_bar");
        assert_ne!(
            handler().normalize_name("foo_bar"),
            cargo_collision_key("foo_bar")
        );
    }

    /// cargo opts INTO the registration-collision check.
    #[test]
    fn collision_key_is_some_and_matches_helper() {
        assert_eq!(
            handler().collision_key("Foo_Bar"),
            Some("foo-bar".to_string())
        );
    }

    #[test]
    fn parse_invalid_path_wrong_prefix() {
        let err = handler()
            .parse_download_path("crates/serde/1.0.0/download")
            .unwrap_err();
        assert!(err.to_string().contains("invalid Cargo download path"));
    }

    #[test]
    fn parse_invalid_path_missing_download_suffix() {
        let err = handler()
            .parse_download_path("api/v1/crates/serde/1.0.0")
            .unwrap_err();
        assert!(err.to_string().contains("invalid Cargo download path"));
    }

    #[test]
    fn parse_invalid_path_wrong_suffix() {
        let err = handler()
            .parse_download_path("api/v1/crates/serde/1.0.0/sources")
            .unwrap_err();
        assert!(err.to_string().contains("invalid Cargo download path"));
    }

    #[test]
    fn parse_invalid_path_empty_name() {
        let err = handler()
            .parse_download_path("api/v1/crates//1.0.0/download")
            .unwrap_err();
        assert!(err.to_string().contains("invalid Cargo download path"));
    }

    #[test]
    fn parse_invalid_path_empty() {
        let err = handler().parse_download_path("").unwrap_err();
        assert!(err.to_string().contains("invalid Cargo download path"));
    }

    // -- strict path-component validation ------------------------------------
    //
    // The cargo grammar restricts crate names to `[a-zA-Z0-9_-]{1,64}`
    // (rust-lang/cargo `valid_package_name`). Versions are restricted to a
    // semver-ish allowlist. Every deviation surfaces as a
    // `DomainError::Validation` carrying a structured `cargo.<field>` prefix
    // so downstream log scrapers can route on it. Error messages must NOT
    // include the rejected input (it can be megabytes of attacker-controlled
    // bytes).

    #[test]
    fn validate_cargo_name_rejects_dotdot() {
        let err = validate_cargo_name("..").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("cargo.name"),
            "must include structured field name: {err}"
        );
    }

    #[test]
    fn validate_cargo_name_rejects_path_traversal() {
        let err = validate_cargo_name("../etc").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.name"));
    }

    #[test]
    fn validate_cargo_name_rejects_crlf() {
        let err = validate_cargo_name("\r\nFoo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.name"));
    }

    #[test]
    fn validate_cargo_name_rejects_control_byte() {
        let err = validate_cargo_name("foo\x00bar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.name"));
    }

    #[test]
    fn validate_cargo_name_rejects_65_chars() {
        let s = "a".repeat(65);
        let err = validate_cargo_name(&s).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.name"));
    }

    #[test]
    fn validate_cargo_name_rejects_empty() {
        let err = validate_cargo_name("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.name"));
    }

    #[test]
    fn validate_cargo_name_accepts_64_char_boundary() {
        let s = "a".repeat(64);
        validate_cargo_name(&s).expect("64 chars is the boundary, must accept");
    }

    #[test]
    fn validate_cargo_name_accepts_alnum_with_underscore_and_hyphen() {
        validate_cargo_name("valid_pkg-1").expect("charset OK");
    }

    #[test]
    fn validate_cargo_version_rejects_non_semver() {
        let err = validate_cargo_version("not.semver.*").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.version"));
    }

    #[test]
    fn validate_cargo_version_accepts_release() {
        validate_cargo_version("1.2.3").expect("plain semver triple must pass");
    }

    #[test]
    fn validate_cargo_version_accepts_prerelease() {
        validate_cargo_version("1.2.3-rc.1").expect("prerelease must pass");
    }

    #[test]
    fn validate_cargo_version_accepts_build_metadata() {
        validate_cargo_version("1.2.3+sha.abc").expect("build metadata must pass");
    }

    #[test]
    fn validate_cargo_version_rejects_empty() {
        let err = validate_cargo_version("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.version"));
    }

    #[test]
    fn parse_download_path_rejects_traversal_in_name() {
        let err = handler()
            .parse_download_path("api/v1/crates/../1.0.0/download")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.name"));
    }

    #[test]
    fn parse_download_path_rejects_percent_decoded_traversal_segment() {
        // The literal `%` byte is outside the cargo name charset
        // `[a-zA-Z0-9_-]`, so this is rejected at the validator regardless
        // of whether an upstream layer decoded `%2F` → `/`. The test pins
        // that the validator does not need to know about percent-encoding
        // to defend against the traversal class.
        let err = handler()
            .parse_download_path("api/v1/crates/..%2Fetc/1.0.0/download")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_download_path_rejects_bad_version() {
        let err = handler()
            .parse_download_path("api/v1/crates/serde/not.semver.*/download")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("cargo.version"));
    }

    // -- index_path_for -------------------------------------------------------

    #[test]
    fn index_path_single_char() {
        assert_eq!(index_path_for("a"), "1/a");
    }

    #[test]
    fn index_path_two_chars() {
        assert_eq!(index_path_for("ab"), "2/ab");
    }

    #[test]
    fn index_path_three_chars() {
        assert_eq!(index_path_for("abc"), "3/a/abc");
    }

    #[test]
    fn index_path_four_chars() {
        assert_eq!(index_path_for("serde"), "se/rd/serde");
    }

    #[test]
    fn index_path_long_name() {
        assert_eq!(
            index_path_for("tokio-tungstenite"),
            "to/ki/tokio-tungstenite"
        );
    }

    #[test]
    fn index_path_lowercases_input() {
        assert_eq!(index_path_for("Serde"), "se/rd/serde");
    }

    #[test]
    fn index_path_char_aware_does_not_panic_on_non_ascii() {
        // Cargo enforces ASCII crate names, so this input is purely defensive.
        // Assert only that the helper does not panic on multi-byte chars —
        // exact output shape is unspecified.
        let _ = index_path_for("crate-αβγδ");
    }

    #[test]
    #[should_panic(expected = "crate name must be non-empty")]
    fn index_path_panics_on_empty() {
        let _ = index_path_for("");
    }

    // -- metadata_expected_max_bytes -----------------------------------------

    #[test]
    fn metadata_expected_max_bytes_is_8_mib() {
        assert_eq!(handler().metadata_expected_max_bytes(), 8 * 1024 * 1024);
    }

    // -- upstream_checksum_metadata_path -------------------------------------

    #[test]
    fn upstream_checksum_metadata_path_returns_sparse_index_path_for_serde() {
        let coords = handler()
            .parse_download_path("api/v1/crates/serde/1.0.214/download")
            .unwrap();
        let path = handler().upstream_checksum_metadata_path(&coords);
        assert_eq!(path, Some("/se/rd/serde".to_string()));
    }

    // -- parse_upstream_checksum ---------------------------------------------

    fn serde_coords(version: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: "serde".to_string(),
            name_as_published: "serde".to_string(),
            version: Some(version.to_string()),
            path: format!("crates/serde/{version}/serde-{version}.crate"),
            format: RepositoryFormat::Cargo,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn parse_upstream_checksum_happy_path_returns_correct_hex() {
        let body = include_bytes!("../tests/fixtures/cargo/serde_v1.0.214.ndjson");
        let coords = serde_coords("1.0.214");
        let cs = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap();
        assert_eq!(
            cs.hex(),
            "f55c3193aca71c12ad7890f1785d2b73e1b9f63a0bbc353c08ef26fe03fc56b5"
        );
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha256);
    }

    #[test]
    fn parse_upstream_checksum_version_not_found_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/cargo/version_not_found.ndjson");
        let coords = serde_coords("0.0.0-not-real");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("no entry for serde@0.0.0-not-real"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_cksum_missing_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/cargo/cksum_missing.ndjson");
        let coords = serde_coords("1.0.214");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("has no cksum"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_malformed_body_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/cargo/malformed.txt");
        let coords = serde_coords("1.0.214");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("not valid NDJSON"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_none_version_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/cargo/serde_v1.0.214.ndjson");
        let coords = ArtifactCoords {
            name: "serde".to_string(),
            name_as_published: "serde".to_string(),
            version: None,
            path: String::new(),
            format: RepositoryFormat::Cargo,
            metadata: serde_json::Value::Null,
        };
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("requires a version in coords"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_wrong_length_cksum_propagates_validation_error() {
        // A synthesised NDJSON line with a 63-char cksum (one char short of SHA-256).
        let body = br#"{"name":"serde","vers":"1.0.214","deps":[],"features":{},"cksum":"f55c3193aca71c12ad7890f1785d2b73e1b9f63a0bbc353c08ef26fe03fc56b"}"#;
        let coords = serde_coords("1.0.214");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- parse_upstream_checksum body cap (streaming cap taxonomy) -----------
    //
    // `parse_upstream_checksum` STREAMS the sparse-index page line-by-line,
    // so per the cap taxonomy its ceiling is the streaming plausibility
    // bound (`STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES` = 64 MiB), NOT the
    // small in-memory `metadata_expected_max_bytes()` (now the
    // upload-payload cap only). The cap-check rejects with a diagnostic
    // that names cap and observed length but never echoes the body bytes.
    //
    // The cap is 64 MiB, so a materialised over-cap `Vec` would be a
    // 64 MiB allocation. The tests use a LAZY reader instead: a small
    // valid NDJSON line chained with `std::io::repeat(b' ')` whitespace
    // padding (the parser skips lines where every byte is ASCII
    // whitespace), so no large buffer is ever held.

    /// A small valid cargo NDJSON line (entry + newline) for
    /// `vers="1.0.214"`, used as the head of the lazily-padded cap-test
    /// readers.
    fn cargo_entry_line() -> Vec<u8> {
        let entry = br#"{"name":"serde","vers":"1.0.214","deps":[],"features":{},"cksum":"f55c3193aca71c12ad7890f1785d2b73e1b9f63a0bbc353c08ef26fe03fc56b5"}"#;
        let mut out = Vec::with_capacity(entry.len() + 1);
        out.extend_from_slice(entry);
        out.push(b'\n');
        out
    }

    /// Lazy reader: the valid NDJSON entry line followed by `pad` bytes of
    /// whitespace, for a total length of `entry_line.len() + pad`. No
    /// large buffer is allocated — the whitespace streams from
    /// [`std::io::repeat`].
    fn cargo_lazy_padded_reader(target_len: usize) -> impl std::io::Read {
        let head = cargo_entry_line();
        let pad = (target_len - head.len()) as u64;
        std::io::Read::chain(
            std::io::Cursor::new(head),
            std::io::Read::take(std::io::repeat(b' '), pad),
        )
    }

    #[test]
    fn parse_upstream_checksum_accepts_body_one_byte_under_cap() {
        // Just-under-cap body parses normally — boundary admits below the
        // streaming plausibility ceiling. Streamed via a lazy reader to
        // avoid a ~64 MiB allocation.
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let mut body = cargo_lazy_padded_reader(max - 1);
        let coords = serde_coords("1.0.214");
        let cs = handler()
            .parse_upstream_checksum(&mut body, &coords)
            .expect("just-under-cap body must parse");
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(
            cs.hex(),
            "f55c3193aca71c12ad7890f1785d2b73e1b9f63a0bbc353c08ef26fe03fc56b5"
        );
    }

    #[test]
    fn parse_upstream_checksum_rejects_body_one_byte_over_cap() {
        // Just-over-cap body must be rejected with a Validation error
        // naming cap and observed length but never echoing input bytes.
        // The matching line is at the top of the body so the parser
        // would short-circuit success WITHOUT the cap check — this test
        // proves the cap fires first. Streamed via a lazy reader to avoid
        // a ~64 MiB allocation.
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let mut body = cargo_lazy_padded_reader(max + 1);
        // The body carries the sentinel `cksum` / `serde` tokens; assert
        // the error message does not echo them (error messages MUST NOT
        // echo offending input verbatim).
        let coords = serde_coords("1.0.214");
        let err = handler()
            .parse_upstream_checksum(&mut body, &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("upstream cargo metadata body is")
                && msg.contains(&(max + 1).to_string())
                && msg.contains(&max.to_string())
                && msg.contains("streaming plausibility max is"),
            "size diagnostic missing: {msg}"
        );
        // No body bytes echoed — `cksum` is the canonical sentinel
        // present in the body, and the cargo-grammar tokens such as the
        // crate name `serde` must not appear in the error message.
        assert!(
            !msg.contains("cksum"),
            "error must not echo body bytes (sentinel `cksum` leaked): {msg}"
        );
        assert!(
            !msg.contains("serde"),
            "error must not echo body bytes (sentinel `serde` leaked): {msg}"
        );
    }

    // -- extract_sbom ---------------------------------------------------------

    use hort_domain::types::{Ecosystem, PayloadAccess};

    fn sbom_coords(name: &str, version: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: Some(version.to_string()),
            path: format!("crates/{name}/{version}/{name}-{version}.crate"),
            format: RepositoryFormat::Cargo,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn extract_sbom_cargo_registry_index_shape_happy_path() {
        // The cargo publish body / sparse-index entry shape:
        //   {"name": ..., "vers": ..., "deps": [{"name": ..., "req": ...}], ...}
        // This is the shape the cargo handler stores at ingest.
        let metadata = serde_json::json!({
            "name": "myapp",
            "vers": "1.0.0",
            "license": "MIT OR Apache-2.0",
            "deps": [
                { "name": "serde", "req": "^1.0", "optional": false },
                { "name": "tokio", "req": "1.40.0", "optional": false },
                { "name": "criterion", "req": "0.5", "optional": true },
            ],
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = handler()
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert_eq!(sbom.components.len(), 3);

        let serde = sbom
            .components
            .iter()
            .find(|c| c.name == "serde")
            .expect("serde present");
        assert_eq!(serde.purl, "pkg:cargo/serde@1.0");
        assert_eq!(serde.version.as_deref(), Some("1.0"));
        assert_eq!(serde.ecosystem, Ecosystem::Cargo);
        assert!(serde.direct_dependency);
        assert_eq!(serde.licenses, vec!["MIT OR Apache-2.0".to_string()]);

        let tokio = sbom
            .components
            .iter()
            .find(|c| c.name == "tokio")
            .expect("tokio present");
        assert_eq!(tokio.purl, "pkg:cargo/tokio@1.40.0");
        assert!(tokio.direct_dependency);

        // optional=true → direct_dependency=false
        let criterion = sbom
            .components
            .iter()
            .find(|c| c.name == "criterion")
            .expect("criterion present");
        assert!(!criterion.direct_dependency);
    }

    #[test]
    fn extract_sbom_cargo_toml_shape_happy_path() {
        // Cargo.toml-style JSON (e.g. via toml→serde_json conversion).
        let metadata = serde_json::json!({
            "package": {
                "name": "myapp",
                "version": "1.0.0",
                "license": "MIT",
            },
            "dependencies": {
                "serde": "1.0",
                "tokio": { "version": "1.40", "features": ["full"] },
            },
            "dev-dependencies": {
                "proptest": "1.0",
            },
            "build-dependencies": {
                "cc": "^1.0",
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = handler()
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert_eq!(sbom.components.len(), 4);

        let serde = sbom
            .components
            .iter()
            .find(|c| c.name == "serde")
            .expect("serde present");
        assert_eq!(serde.purl, "pkg:cargo/serde@1.0");
        assert!(serde.direct_dependency);

        let tokio = sbom
            .components
            .iter()
            .find(|c| c.name == "tokio")
            .expect("tokio present");
        assert_eq!(tokio.purl, "pkg:cargo/tokio@1.40");
        assert_eq!(tokio.version.as_deref(), Some("1.40"));
        assert!(tokio.direct_dependency);

        // dev-dependencies → direct=false
        let proptest = sbom
            .components
            .iter()
            .find(|c| c.name == "proptest")
            .expect("proptest present");
        assert!(!proptest.direct_dependency);

        // build-dependencies → direct=false; caret stripped
        let cc = sbom
            .components
            .iter()
            .find(|c| c.name == "cc")
            .expect("cc present");
        assert_eq!(cc.purl, "pkg:cargo/cc@1.0");
        assert!(!cc.direct_dependency);

        // license bubbles up from `package.license`.
        assert_eq!(serde.licenses, vec!["MIT".to_string()]);
    }

    #[test]
    fn extract_sbom_cargo_dep_with_no_req_yields_no_version() {
        let metadata = serde_json::json!({
            "name": "myapp",
            "vers": "1.0.0",
            "deps": [
                { "name": "noreq" },
            ],
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = handler()
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].purl, "pkg:cargo/noreq");
        assert!(sbom.components[0].version.is_none());
    }

    #[test]
    fn extract_sbom_cargo_empty_metadata_returns_some_empty() {
        let metadata = serde_json::json!({});
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = handler()
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn extract_sbom_cargo_null_metadata_returns_some_empty() {
        let metadata = serde_json::Value::Null;
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = handler()
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert!(sbom.components.is_empty());
    }

    /// Leaf cargo crate: subject is populated from coords even when the
    /// manifest is empty/null.
    #[test]
    fn extract_sbom_cargo_leaf_crate_populates_subject_from_coords() {
        let metadata = serde_json::json!({}); // crate with no deps
        let coords = sbom_coords("anyhow", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = handler()
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");

        let subject = sbom.subject.as_ref().expect("subject must be populated");
        assert_eq!(subject.purl, "pkg:cargo/anyhow@1.0.0");
        assert_eq!(subject.name, "anyhow");
        assert_eq!(subject.ecosystem, Ecosystem::Cargo);
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn extract_sbom_cargo_null_metadata_still_populates_subject_from_coords() {
        let coords = sbom_coords("anyhow", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = handler()
            .extract_sbom(&coords, &serde_json::Value::Null, payload)
            .expect("Some")
            .expect("Some");
        let subject = sbom
            .subject
            .as_ref()
            .expect("subject must be populated even when metadata is Null");
        assert_eq!(subject.purl, "pkg:cargo/anyhow@1.0.0");
    }

    #[test]
    fn extract_sbom_cargo_license_file_field_falls_back() {
        // Crates.io accepts either `license` or `license-file`. We only
        // surface `license` (SPDX); `license-file` (path) is left out
        // because it isn't an SPDX identifier and downstream consumers
        // expect identifiers, not paths.
        let metadata = serde_json::json!({
            "package": {
                "license-file": "LICENSE.txt",
            },
            "dependencies": { "serde": "1.0" },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = handler()
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert!(sbom.components[0].licenses.is_empty());
    }

    // -- upstream_metadata_path -----------------------------------------------

    #[test]
    fn upstream_metadata_path_cargo_returns_sparse_index_path() {
        // Cargo's metadata-index path is the sparse-index entry —
        // version-agnostic. Coincides with `upstream_checksum_metadata_path`
        // because the NDJSON entry carries both the version-set and
        // per-version `cksum`. Uses the same `index_path_for` helper
        // as the checksum path; the prefix-bucket layout (1/2/3-char
        // buckets) is the cargo registry convention.
        let handler = handler();
        // Long names use the standard prefix-bucket convention.
        assert_eq!(
            handler.upstream_metadata_path("encoding_rs"),
            Some(format!("/{}", index_path_for("encoding_rs"))),
        );
        // 1-char names use the `1/` bucket.
        assert_eq!(
            handler.upstream_metadata_path("a"),
            Some(format!("/{}", index_path_for("a"))),
        );
    }

    #[test]
    fn upstream_metadata_accept_cargo_inherits_trait_default_empty() {
        // Cargo sparse-index serves NDJSON only — no content
        // negotiation. Inherits the trait default `Vec::new()`. Same
        // regression-guard intent as the npm test of the same shape.
        assert!(handler().upstream_metadata_accept().is_empty());
    }

    // -- extract_upstream_versions -------------------------------------------

    #[test]
    fn extract_upstream_versions_cargo_reads_vers_field_per_line() {
        let body = br#"{"name":"serde","vers":"1.0.0","cksum":"abc","yanked":false}
{"name":"serde","vers":"1.0.1","cksum":"def","yanked":false}
{"name":"serde","vers":"1.1.0","cksum":"ghi","yanked":false}
"#;
        let vs = handler()
            .extract_upstream_versions(&mut std::io::Cursor::new(body))
            .expect("Ok");
        assert_eq!(
            vs,
            vec![
                "1.0.0".to_string(),
                "1.0.1".to_string(),
                "1.1.0".to_string()
            ]
        );
    }

    #[test]
    fn extract_upstream_versions_cargo_skips_blank_lines() {
        let body = b"\n\n{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"a\"}\n\n\n";
        let vs = handler()
            .extract_upstream_versions(&mut std::io::Cursor::new(body))
            .expect("Ok");
        assert_eq!(vs, vec!["1.0.0".to_string()]);
    }

    #[test]
    fn extract_upstream_versions_cargo_drops_lines_without_vers_field() {
        // Mirror of hot-path policy in
        // `index_cache.rs::parse_upstream_versions`: a malformed line
        // is dropped, not error.
        let body = b"{\"name\":\"x\"}\n{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"a\"}\nnot json at all\n";
        let vs = handler()
            .extract_upstream_versions(&mut std::io::Cursor::new(body))
            .expect("Ok");
        assert_eq!(vs, vec!["1.0.0".to_string()]);
    }

    #[test]
    fn extract_upstream_versions_cargo_empty_body_is_empty() {
        let vs = handler()
            .extract_upstream_versions(&mut std::io::Cursor::new(b""))
            .expect("Ok");
        assert!(vs.is_empty());
    }

    #[test]
    fn extract_upstream_versions_cargo_over_cap_returns_validation_error() {
        // Streaming method → ceiling is the plausibility bound (64 MiB).
        // Lazy reader of `max + 1` newline bytes (all whitespace lines the
        // parser skips) — no ~64 MiB allocation.
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let mut body = std::io::Read::take(std::io::repeat(b'\n'), max as u64 + 1);
        let err = handler().extract_upstream_versions(&mut body).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- is_top_level_cargo_toml ------------------------------------------

    #[test]
    fn is_top_level_cargo_toml_matches_single_dir_manifest() {
        assert!(is_top_level_cargo_toml("demo-0.1.0/Cargo.toml"));
        assert!(is_top_level_cargo_toml("serde-1.0.150/Cargo.toml"));
        // Some tar writers prefix paths with `./`.
        assert!(is_top_level_cargo_toml("./demo-0.1.0/Cargo.toml"));
    }

    #[test]
    fn is_top_level_cargo_toml_rejects_nested_and_lookalikes() {
        // Nested manifest (vendored / workspace member).
        assert!(!is_top_level_cargo_toml("demo-0.1.0/vendor/x/Cargo.toml"));
        // Manifest at the archive root with no `{dir}/` segment.
        assert!(!is_top_level_cargo_toml("Cargo.toml"));
        // `Cargo.toml.orig` (cargo also ships this) is not the manifest.
        assert!(!is_top_level_cargo_toml("demo-0.1.0/Cargo.toml.orig"));
        // Other files in the top-level dir.
        assert!(!is_top_level_cargo_toml("demo-0.1.0/src/lib.rs"));
        // Empty dir segment.
        assert!(!is_top_level_cargo_toml("/Cargo.toml"));
    }

    // -- parse_cargo_toml_runtime_dependencies --------------------------------

    #[test]
    fn parse_cargo_toml_runtime_drops_dev_and_build_and_honors_rename() {
        // Plain string dep, table dep, and a RENAMED dep (the `package`
        // key names the real crate); a [dev-dependencies] table that must
        // be excluded; a [build-dependencies] table that must be excluded.
        let manifest = br#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1"
tokio = { version = "1", features = ["full"] }
foo = { package = "bar", version = "1" }

[dev-dependencies]
proptest = "1"

[build-dependencies]
cc = "1"
"#;
        let specs = parse_cargo_toml_runtime_dependencies(manifest).expect("Ok");
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();

        // Runtime deps survive. The renamed dep yields the `package`
        // value ("bar"), NOT the TOML key ("foo").
        assert!(names.contains(&"serde"), "missing serde: {names:?}");
        assert!(names.contains(&"tokio"), "missing tokio: {names:?}");
        assert!(
            names.contains(&"bar"),
            "renamed dep must surface its `package` value 'bar': {names:?}"
        );
        assert!(
            !names.contains(&"foo"),
            "renamed dep must NOT surface the TOML key 'foo': {names:?}"
        );

        // dev/build classes excluded — the load-bearing boundary.
        assert!(
            !names.contains(&"proptest"),
            "dev dep proptest leaked: {names:?}"
        );
        assert!(!names.contains(&"cc"), "build dep cc leaked: {names:?}");

        // Version range comes through verbatim (string + table-`version`).
        assert_eq!(specs.iter().find(|s| s.name == "serde").unwrap().range, "1");
        assert_eq!(specs.iter().find(|s| s.name == "tokio").unwrap().range, "1");
        assert_eq!(specs.iter().find(|s| s.name == "bar").unwrap().range, "1");
    }

    #[test]
    fn parse_cargo_toml_runtime_empty_when_no_dependencies_table() {
        let manifest = br#"
[package]
name = "leaf"
version = "1.0.0"
"#;
        assert!(parse_cargo_toml_runtime_dependencies(manifest)
            .expect("Ok")
            .is_empty());
    }

    #[test]
    fn parse_cargo_toml_runtime_drops_path_only_and_git_only_deps() {
        // A dep with neither a string value nor a resolvable `version`
        // (path-only / git-only) is best-effort dropped — mirrors the
        // pre-076 sparse-index impl's tolerance.
        let manifest = br#"
[dependencies]
local = { path = "../local" }
remote = { git = "https://example.invalid/x.git" }
real = "2.3"
"#;
        let specs = parse_cargo_toml_runtime_dependencies(manifest).expect("Ok");
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["real"]);
        assert_eq!(specs[0].range, "2.3");
    }

    #[test]
    fn parse_cargo_toml_runtime_malformed_toml_returns_validation_error() {
        let manifest = b"[dependencies\nthis = is = not = toml";
        let err = parse_cargo_toml_runtime_dependencies(manifest).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- extract_dependency_specs (archive-aware) -----------------------------

    /// Build a gzip-tar (`.crate`-shape) archive in memory from
    /// `(path, body)` pairs. Mirrors the npm/archive_bounds fixtures.
    fn make_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("set_path");
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, *body).expect("append entry");
        }
        let gz = builder.into_inner().expect("finish tar");
        gz.finish().expect("finish gzip")
    }

    /// A real `.crate` is a gzip-tar with a single top-level
    /// `{name}-{version}/` dir containing `Cargo.toml` as an EARLY entry
    /// (the manifest must precede the cumulative cap).
    #[test]
    fn extract_dependency_specs_cargo_from_crate_runtime_only_with_rename() {
        let manifest = br#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1"
tokio = { version = "1", features = ["full"] }
foo = { package = "bar", version = "1" }

[dev-dependencies]
proptest = "1"
"#;
        let archive = make_tar_gz(&[
            // Cargo.toml first (early entry) so the cumulative cap is
            // reached after it.
            ("demo-0.1.0/Cargo.toml", manifest),
            ("demo-0.1.0/src/lib.rs", b"// code"),
        ]);
        let specs = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(archive))
            .expect("Ok");
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"serde"), "{names:?}");
        assert!(names.contains(&"tokio"), "{names:?}");
        assert!(names.contains(&"bar"), "rename → bar: {names:?}");
        assert!(!names.contains(&"foo"), "rename key must win: {names:?}");
        assert!(!names.contains(&"proptest"), "dev dep leaked: {names:?}");
    }

    #[test]
    fn extract_dependency_specs_cargo_zero_deps_crate_is_empty_vec() {
        let manifest = br#"
[package]
name = "leaf"
version = "1.0.0"
"#;
        let archive = make_tar_gz(&[
            ("leaf-1.0.0/Cargo.toml", manifest),
            ("leaf-1.0.0/src/lib.rs", b""),
        ]);
        let specs = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(archive))
            .expect("Ok");
        assert!(specs.is_empty(), "{specs:?}");
    }

    #[test]
    fn extract_dependency_specs_cargo_non_gzip_input_errors() {
        let garbage = b"this is not a gzip-tar .crate archive".to_vec();
        let err = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(garbage))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn extract_dependency_specs_cargo_absent_cargo_toml_errors() {
        // A gzip-tar with NO top-level Cargo.toml (corrupt .crate).
        let archive = make_tar_gz(&[
            ("demo-0.1.0/src/lib.rs", b"// code"),
            ("demo-0.1.0/README.md", b"hi"),
        ]);
        let err = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(archive))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn extract_dependency_specs_cargo_corrupt_cargo_toml_errors() {
        let manifest = b"[dependencies\nbroken = = =";
        let archive = make_tar_gz(&[("demo-0.1.0/Cargo.toml", manifest)]);
        let err = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(archive))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- resolve_range_max ---------------------------------------------------

    #[test]
    fn resolve_range_max_cargo_caret_picks_highest() {
        let avail = ["1.1.0", "1.2.0", "1.2.5", "1.3.0", "2.0.0"];
        let out = handler().resolve_range_max("^1.2", &avail).expect("Ok");
        assert_eq!(out.as_deref(), Some("1.3.0"));
    }

    #[test]
    fn resolve_range_max_cargo_exact_pin() {
        let avail = ["1.0.0", "1.0.150", "2.0.0"];
        // Cargo `=1.0.150` is an exact-pin via the `semver` crate's
        // `=` operator.
        let out = handler().resolve_range_max("=1.0.150", &avail).expect("Ok");
        assert_eq!(out.as_deref(), Some("1.0.150"));
    }

    #[test]
    fn resolve_range_max_cargo_no_match_returns_none() {
        let avail = ["1.0.0"];
        assert_eq!(handler().resolve_range_max("^2", &avail).expect("Ok"), None);
    }

    #[test]
    fn resolve_range_max_cargo_empty_available_returns_none() {
        assert_eq!(handler().resolve_range_max("^1.0", &[]).expect("Ok"), None);
    }

    // -- download_config_path / compose_download_url_from_config -------------

    #[test]
    fn download_config_path_is_config_json() {
        // cargo's download URL is config.json-driven: the prefetch
        // orchestrator must fetch `/config.json` from the index host.
        assert_eq!(
            handler().download_config_path(),
            Some("/config.json".to_string())
        );
    }

    #[test]
    fn compose_download_url_from_config_crates_io_uses_dl_field_not_index_host() {
        // crates.io-shaped config.json (placeholder-free `dl`) → the spec
        // default suffix is appended to the `dl` host, NOT the index host.
        // This is the bug fix: the URL must point at static.crates.io
        // (the `dl` value), never index.crates.io.
        let body = include_bytes!("../tests/fixtures/cargo/crates_io_config.json");
        let url = handler()
            .compose_download_url_from_config(
                &mut std::io::Cursor::new(&body[..]),
                "serde",
                "1.0.214",
                None,
            )
            .expect("Ok");
        assert_eq!(
            url,
            "https://static.crates.io/crates/serde/1.0.214/download"
        );
    }

    #[test]
    fn compose_download_url_from_config_private_registry_templated_dl() {
        // A private registry with a templated `dl`
        // (`{prefix}/{lowerprefix}/{crate}-{version}.crate`) composes via
        // the spec placeholders — the case the old heuristic could never
        // resolve.
        let body = include_bytes!("../tests/fixtures/cargo/private_registry_config.json");
        let url = handler()
            .compose_download_url_from_config(
                &mut std::io::Cursor::new(&body[..]),
                "serde",
                "1.0.214",
                None,
            )
            .expect("Ok");
        assert_eq!(
            url,
            "https://artifacts.example.com/se/rd/se/rd/serde-1.0.214.crate"
        );
    }

    #[test]
    fn compose_download_url_from_config_checksum_template_substitutes_cksum() {
        let body = include_bytes!("../tests/fixtures/cargo/template_with_checksum.json");
        let cksum = "f55c3193aca71c12ad7890f1785d2b73e1b9f63a0bbc353c08ef26fe03fc56b5";
        let url = handler()
            .compose_download_url_from_config(
                &mut std::io::Cursor::new(&body[..]),
                "serde",
                "1.0.214",
                Some(cksum),
            )
            .expect("Ok");
        assert_eq!(
            url,
            format!("https://artifacts.example.com/crates/serde/1.0.214/{cksum}.crate")
        );
    }

    #[test]
    fn compose_download_url_from_config_malformed_body_is_validation_error() {
        // A garbage / missing-`dl` config.json fails closed (Validation),
        // never a fabricated URL.
        for body in [&b"not-json"[..], &br#"{"api":"https://x"}"#[..]] {
            let err = handler()
                .compose_download_url_from_config(
                    &mut std::io::Cursor::new(body),
                    "serde",
                    "1.0.0",
                    None,
                )
                .unwrap_err();
            assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        }
    }

    #[test]
    fn compose_download_url_from_config_body_over_cap_is_validation_error() {
        // A pathological config.json over CARGO_CONFIG_MAX_BYTES is rejected
        // by the bounded read BEFORE parsing — defence-in-depth above the
        // fetch-time storage backstop (never an unbounded read).
        let body = vec![b' '; CARGO_CONFIG_MAX_BYTES + 1];
        let err = handler()
            .compose_download_url_from_config(
                &mut std::io::Cursor::new(&body[..]),
                "serde",
                "1.0.0",
                None,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        assert!(
            err.to_string().contains("cargo config max is"),
            "over-cap error must name the cap: {err}"
        );
    }

    #[test]
    fn compose_download_url_from_config_non_http_scheme_is_validation_error() {
        // A hostile / compromised registry `config.json` could assert a
        // non-http(s) `dl` (a downgrade / exfil target). It is rejected at
        // resolution — symmetric with npm's tarball scheme reject — before it
        // can reach the fetch layer.
        let body = br#"{"dl":"ftp://evil.example.com/crates","api":"https://crates.io"}"#;
        let err = handler()
            .compose_download_url_from_config(
                &mut std::io::Cursor::new(&body[..]),
                "serde",
                "1.0.0",
                None,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        assert!(
            err.to_string().contains("non-http(s)"),
            "scheme-reject error must name the cause: {err}"
        );
    }

    #[test]
    fn compose_download_url_from_config_allows_http_scheme() {
        // `http` IS permitted (unlike npm's https-only): cargo plaintext is the
        // operator-tracked `insecure_upstream_url` opt-in, so the resolution
        // layer allows it and leaves the plaintext decision to that gate.
        let body = br#"{"dl":"http://internal-mirror.example.com/crates"}"#;
        let url = handler()
            .compose_download_url_from_config(
                &mut std::io::Cursor::new(&body[..]),
                "serde",
                "1.0.0",
                None,
            )
            .expect("http dl is allowed");
        assert_eq!(
            url,
            "http://internal-mirror.example.com/crates/serde/1.0.0/download"
        );
    }
}
