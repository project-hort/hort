use std::io::{Cursor, Read};

use bytes::Bytes;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::format_handler::{DependencySpec, FormatHandler};
use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};
use hort_domain::types::{ArtifactCoords, Ecosystem, PayloadAccess, Sbom, SbomComponent};

use crate::range_resolvers::resolve_pep440_range_max;
use crate::sbom_helpers::build_subject_component;

/// Internal cap on the wheel `<dist-info>/METADATA` body extracted by
/// [`PyPiFormatHandler::extract_wheel_metadata_bytes`]. 1 MiB. A
/// real-world wheel METADATA file sits well below 100 KiB even for
/// projects with long descriptions and extensive classifier lists; 1 MiB
/// is a generous safety net that still rejects hostile expansion
/// (zip-bomb METADATA member declaring gigabytes uncompressed). Above
/// this cap the call returns [`DomainError::Validation`] — never
/// silently truncated.
const PYPI_WHEEL_METADATA_MAX_BYTES: u64 = 1024 * 1024;

/// Buffered cap for a single per-version PyPI JSON document
/// (`/pypi/{name}/{version}/json`, the `urls[]` body
/// `parse_upstream_checksum` parses). Memory-safety bound; one version's
/// JSON is small. HARD-CODED + decoupled from `metadata_expected_max_bytes`.
const PYPI_VERSION_JSON_MAX_BYTES: u64 = 128 * 1024;

/// Compressed-input cap for the whole stored PyPI distribution artifact
/// (a wheel zip or an sdist gzip) fed to
/// [`PyPiFormatHandler::extract_dependency_specs`]. The cascade caller reads
/// the artifact from CAS under a 32 MiB **compressed** bound
/// (`prefetch_dependencies::read_artifact_bytes`) before handing it here, so
/// this cap is set to that same 32 MiB to admit every artifact the cascade
/// can present while still bounding the buffer if a future caller streams an
/// unbounded reader in. It is a *compressed* container cap (a plausibility /
/// storage bound, large — mirrors npm's `NPM_TARBALL_MAX_BYTES`; see
/// The decompressed-output /
/// compression-ratio / entry-count bomb guards for the wheel-zip path live in
/// `archive_bounds::iter_zip_entries`, NOT here; the extracted METADATA entry
/// is separately bounded by [`PYPI_WHEEL_METADATA_MAX_BYTES`].
const PYPI_DIST_MAX_BYTES: usize = 32 * 1024 * 1024;

// Per-format unified index builders (see explanation/index-construction.md).
// Houses `PypiHtmlIndexBuilder` + `PypiJsonIndexBuilder` (the two
// `IndexBuilder` impls that emit PEP 503 HTML / PEP 691 JSON
// simple-index documents from `Vec<VersionEntry>`) and re-exports
// `PypiVersionPayload` + `PypiVersionFile` (defined in
// `hort-app::use_cases::index_serve` for dep-graph reasons).
pub mod index;
// PyPI simple-index JSON streaming projector (see ADR 0026).
// Projects the PEP 691 simple-index `files[]` array; the production
// consumer uses `files[]`, not the `releases{}` map shape.
pub mod projection;

/// PyPI format handler (PEP 503 compliant).
///
/// Compiled-in Rust struct behind the `FormatHandler` trait boundary.
/// See explanation/format-handlers.md + ADR 0005.
pub struct PyPiFormatHandler;

/// Maximum length of a PEP 503 normalised project name in bytes. PEP 503
/// itself does not impose a hard cap; PEP 426 metadata sets practical
/// limits well below 256 bytes. Rejected at the path-parser boundary.
const PYPI_NAME_MAX: usize = 256;

/// Maximum length of a PyPI artifact filename (wheel per PEP 427 §3 or
/// sdist per PEP 625 §1) accepted by the path parser. Real-world wheel
/// filenames sit comfortably under 256 bytes even with long platform tags.
const PYPI_FILENAME_MAX: usize = 256;

/// Maximum length of a PyPI version string accepted by the publish-side
/// validator. PEP 440 imposes no hard byte cap, but real-world version
/// strings are well under 64 bytes; 256 leaves generous headroom for
/// local-version identifiers
/// (`1.0+ubuntu.20.04.1`) without admitting log-pollution payloads.
const PYPI_VERSION_MAX: usize = 256;

/// Validate that `name` is a legal PEP 503 §3 normalised project name.
///
/// Rules:
/// - Charset `^[A-Za-z0-9_.-]+$` (case-insensitive — normalisation
///   collapses runs of `-_.` to a single `-` and lowercases, but that
///   happens AFTER validation).
/// - Length 1..=256 bytes.
/// - First byte must not be `-` or `.` (a leading separator is not a
///   legal name in PEP 503's collapsing grammar — `..` and `-foo`
///   normalise to nothing or to a leading hyphen).
/// - No control bytes (`\x00`-`\x1f`, `\x7f`).
///
/// Returns [`DomainError::Validation`] tagged with the structured field
/// name `pypi.name`. Error messages **never** include the rejected input
/// (it can be megabytes of attacker-controlled bytes — log-pollution
/// risk).
///
/// Visibility: `pub` rather than `pub(crate)` because the publish-side
/// caller (`crates/hort-http-pypi/src/lib.rs::upload`) sits in a different
/// crate — `pub(crate)` would not compile across crate boundaries.
pub fn validate_pep_503_name(name: &str) -> DomainResult<()> {
    if name.is_empty() {
        return Err(DomainError::Validation(
            "pypi.name: empty project name is not permitted".to_string(),
        ));
    }
    if name.len() > PYPI_NAME_MAX {
        return Err(DomainError::Validation(format!(
            "pypi.name: exceeds {PYPI_NAME_MAX}-byte cap"
        )));
    }
    // safe: `name` is non-empty (checked above), so as_bytes()[0] exists.
    let first = name.as_bytes()[0];
    if first == b'-' || first == b'.' {
        return Err(DomainError::Validation(
            "pypi.name: must not start with '-' or '.'".to_string(),
        ));
    }
    for b in name.as_bytes() {
        let in_charset = b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-');
        if !in_charset {
            return Err(DomainError::Validation(
                "pypi.name: contains a byte outside [A-Za-z0-9_.-]".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validate that `filename` is a legal PyPI artifact filename (PEP 427
/// wheel or PEP 625 sdist).
///
/// Rules:
/// - Charset `^[A-Za-z0-9._+-]+$`. The `+` is required to admit PEP 440
///   local-version identifiers embedded in filenames
///   (e.g. `example-1.0+local.tar.gz`).
/// - Length 1..=256 bytes.
/// - No path separators (`/`, `\`).
/// - No control bytes (`\x00`-`\x1f`, `\x7f`).
///
/// Returns [`DomainError::Validation`] tagged with the structured field
/// name `pypi.filename`. The path-separator and control-byte checks are
/// implicit in the charset allowlist, but the structured error message
/// makes the intent legible at the call site.
///
/// Visibility: `pub` rather than `pub(crate)` because the publish-side
/// caller (`crates/hort-http-pypi/src/lib.rs::upload`) sits in a different
/// crate. This validator supersedes the weaker `validate_publish_filename`
/// previously living in `hort-http-pypi`.
pub fn validate_pypi_filename(filename: &str) -> DomainResult<()> {
    if filename.is_empty() {
        return Err(DomainError::Validation(
            "pypi.filename: empty filename is not permitted".to_string(),
        ));
    }
    if filename.len() > PYPI_FILENAME_MAX {
        return Err(DomainError::Validation(format!(
            "pypi.filename: exceeds {PYPI_FILENAME_MAX}-byte cap"
        )));
    }
    for b in filename.as_bytes() {
        let in_charset = b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'+');
        if !in_charset {
            return Err(DomainError::Validation(
                "pypi.filename: contains a byte outside [A-Za-z0-9._+-]".to_string(),
            ));
        }
    }
    // A filename consisting entirely of dots (`.`, `..`, `...`, …) is
    // accepted by the charset above but expresses traversal intent
    // when concatenated into a path template like
    // `simple/{project}/{filename}`. PyPI never emits such filenames
    // (every legitimate sdist or wheel carries a `{name}-{version}`
    // prefix), so rejecting them is invisible to real clients and
    // closes the gap that the deleted `validate_publish_filename`
    // previously covered.
    if filename.bytes().all(|b| b == b'.') {
        return Err(DomainError::Validation(
            "pypi.filename: must not consist entirely of dots".to_string(),
        ));
    }
    Ok(())
}

/// Validate that `version` is a syntactically plausible PyPI version
/// string for the publish-side multipart `version` field.
///
/// Rules:
/// - Charset `^[A-Za-z0-9.+!_-]+$`. Covers the PEP 440 surface
///   (release segments, pre/post/dev, epoch with `!`, local-version
///   identifiers with `+`) plus the `_` and `-` characters that
///   appear in legacy-but-real-world version strings.
/// - Length 1..=256 bytes.
/// - No leading or trailing whitespace (the charset allowlist
///   already excludes interior whitespace, but the no-leading /
///   no-trailing rule is restated for symmetry with PEP 440's
///   "normalised version has no surrounding whitespace" guarantee).
///
/// **Scope (NARROW):** this is a permissive PEP 440 *charset* gate,
/// **not** a full PEP 440 parser. It rejects log-injection
/// (`\r\n`), null bytes, traversal markers (`/`, `\`), and oversize
/// payloads. It does NOT enforce PEP 440 component grammar
/// (`<release>(<.dev>...)?(<+local>)?`) because the cost of full
/// parsing here is unjustified — the downstream
/// `PyPiFormatHandler::normalize_name` does not consume the version,
/// and the upstream PyPI metadata fetch handles semantic version
/// comparison on its own. If a future need requires stricter semantics,
/// this validator can call into a dedicated PEP 440 parser; the
/// structured error shape stays stable.
///
/// Returns [`DomainError::Validation`] tagged with the structured
/// field name `pypi.version`. Error messages **never** include the
/// rejected input (log-pollution / response-reflection risk).
pub fn validate_pypi_version(version: &str) -> DomainResult<()> {
    if version.is_empty() {
        return Err(DomainError::Validation(
            "pypi.version: empty version is not permitted".to_string(),
        ));
    }
    if version.len() > PYPI_VERSION_MAX {
        return Err(DomainError::Validation(format!(
            "pypi.version: exceeds {PYPI_VERSION_MAX}-byte cap"
        )));
    }
    // Charset allowlist already excludes interior whitespace; explicit
    // leading/trailing checks would be redundant. Keeping a single
    // charset loop for legibility and so the error message names the
    // exact rule that fired.
    for b in version.as_bytes() {
        let in_charset = b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'!' | b'_' | b'-');
        if !in_charset {
            return Err(DomainError::Validation(
                "pypi.version: contains a byte outside [A-Za-z0-9.+!_-]".to_string(),
            ));
        }
    }
    Ok(())
}

/// Extract a version string from a PyPI distribution filename, mirroring
/// the helper in
/// `crates/hort-http-pypi/src/simple_index.rs::pypi_extract_version_from_filename`
/// verbatim. The two copies stay in lock-step on purpose: keeping the
/// filename grammar in `hort-formats` lets the format handler's
/// `extract_upstream_versions` parse the upstream simple-index without
/// reaching across the layering into `hort-http-pypi` (forbidden by the
/// dep graph).
///
/// Returns `None` for filenames whose suffix is not a recognised
/// distribution archive or whose stem has no `-`. Callers treat `None`
/// as "skip this entry"; the prefetch-tick walk drops unparseable
/// entries silently per the hot-path policy.
///
/// `pub` so the `hort-formats-upstream` discovery seam can derive its
/// version list from the cached `PypiSimpleIndexProjection`'s `files[]`
/// filenames.
pub fn pypi_extract_version_from_filename(filename: &str) -> Option<String> {
    // Wheels: longest extension wins so `.whl` isn't shadowed.
    if let Some(stem) = filename.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        let _name = parts.next()?;
        let version = parts.next()?;
        if version.is_empty() {
            return None;
        }
        return Some(version.to_string());
    }
    // Sdists. Longest suffixes first so `.tar.gz` doesn't accidentally
    // short-circuit on `.gz`.
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".egg"] {
        if let Some(stem) = filename.strip_suffix(ext) {
            let (_, version) = stem.rsplit_once('-')?;
            if version.is_empty() {
                return None;
            }
            return Some(version.to_string());
        }
    }
    None
}

/// Extract the basename of an `href="…"` attribute value (the filename —
/// the last `/`-delimited segment, with both the `?…` query and the
/// `#…` fragment stripped). Used by the PyPI simple-index
/// version-extractor walk; PEP 503 publishes the file digest in a
/// `#sha256=…` fragment that must NOT leak into the filename grammar.
fn pypi_filename_from_href(href: &str) -> Option<&str> {
    let no_fragment = href.split('#').next().unwrap_or(href);
    let no_query = no_fragment.split('?').next().unwrap_or(no_fragment);
    let basename = no_query.rsplit('/').next()?;
    if basename.is_empty() {
        None
    } else {
        Some(basename)
    }
}

/// Scan a PEP 503 simple-index HTML body for the `href="..."` value of
/// every `<a ...>` anchor. Hand-rolled so the `hort-formats` crate stays
/// regex-free; `hort-http-pypi` uses `regex::Regex` (`FULL_ANCHOR_RE`)
/// but that dependency isn't worth adding here. The scanner only needs
/// the `href`-attribute values; PEP 503 §Content forbids tags that would
/// confuse a `<a` substring scan inside attribute values.
fn pypi_scan_href_values(html: &str) -> Vec<&str> {
    let bytes = html.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0;
    while i + 2 < bytes.len() {
        // Find `<a` (ASCII-case-insensitive) followed by whitespace.
        if (bytes[i] == b'<')
            && (bytes[i + 1] == b'a' || bytes[i + 1] == b'A')
            && matches!(bytes[i + 2], b' ' | b'\t' | b'\n' | b'\r')
        {
            // Scan forward for `href=` (ASCII case-insensitive) up to
            // the next `>`; bail at the tag close.
            let tag_start = i;
            let mut j = i + 2;
            let mut href_value: Option<&str> = None;
            while j < bytes.len() && bytes[j] != b'>' {
                // Match the substring `href=` case-insensitively.
                if j + 5 <= bytes.len()
                    && bytes[j..j + 4].eq_ignore_ascii_case(b"href")
                    && bytes[j + 4] == b'='
                {
                    let after_eq = j + 5;
                    if after_eq < bytes.len()
                        && (bytes[after_eq] == b'"' || bytes[after_eq] == b'\'')
                    {
                        let quote = bytes[after_eq];
                        let value_start = after_eq + 1;
                        if let Some(rel_end) = bytes[value_start..].iter().position(|&b| b == quote)
                        {
                            let value_end = value_start + rel_end;
                            // safe: the slice originates from a `&str` (`html`) and we cut
                            // strictly on ASCII bytes (`"` / `'`), so the resulting bytes are
                            // a valid UTF-8 substring.
                            if let Ok(s) = std::str::from_utf8(&bytes[value_start..value_end]) {
                                href_value = Some(s);
                            }
                            j = value_end + 1;
                            continue;
                        }
                    }
                }
                j += 1;
            }
            if let Some(v) = href_value {
                out.push(v);
            }
            i = j.max(tag_start + 1);
            continue;
        }
        i += 1;
    }
    out
}

/// Find the wheel's `<dist-info>/METADATA` member in a ZIP byte buffer
/// and return its contents bounded by [`PYPI_WHEEL_METADATA_MAX_BYTES`].
///
/// Separated from the `FormatHandler` impl so the bytes-in-/bytes-out
/// kernel is testable directly without manufacturing a
/// [`PayloadAccess`]. Lives next to the only caller; not exported.
///
/// Returns:
/// - `Ok(None)` — buffer is not a valid ZIP, or the ZIP carries zero
///   `*.dist-info/METADATA` entries. Non-fatal: the wheel ingest
///   already succeeded; PEP 658 is simply not advertised.
/// - `Ok(Some(bytes))` — METADATA bytes (first matching entry; the
///   wheel spec mandates exactly one, but a malformed wheel with
///   multiple entries logs `debug!` and uses the first).
/// - `Err(DomainError::Validation)` — the entry's reported
///   uncompressed size exceeds the cap (checked **before** the read,
///   so a header-claimed multi-GB entry is rejected without I/O).
fn extract_wheel_metadata_bytes_from_zip(buf: &[u8]) -> DomainResult<Option<Bytes>> {
    let cursor = Cursor::new(buf);
    let Ok(mut archive) = zip::ZipArchive::new(cursor) else {
        // Non-fatal: corrupt ZIP / non-ZIP bytes claiming to be a
        // wheel. The wheel ingest already succeeded; PEP 658
        // simply does not apply for this artifact.
        return Ok(None);
    };

    // PEP 427 §A wheel format: exactly one `*.dist-info/` directory at
    // the archive root, with `METADATA` inside it. Walk by index so we
    // can short-circuit on the first match; bypasses the second-match
    // borrow-checker issue with by_name.
    let mut first_match_index: Option<usize> = None;
    let mut match_count: usize = 0;
    for i in 0..archive.len() {
        // Iteration is bounded by `archive.len()`, which is read from
        // the ZIP central directory — itself bounded by the byte
        // buffer's length.
        let Ok(entry) = archive.by_index(i) else {
            // skip unreadable entries
            continue;
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name();
        if is_wheel_metadata_path(name) {
            match_count += 1;
            if first_match_index.is_none() {
                first_match_index = Some(i);
            }
        }
    }

    let Some(idx) = first_match_index else {
        // Zero `*.dist-info/METADATA` entries — malformed wheel that
        // verified primary content. Non-fatal.
        return Ok(None);
    };
    if match_count > 1 {
        // Wheel spec mandates exactly one. pip picks the first; we do
        // the same and log for the operator. Does NOT error.
        tracing::debug!(
            match_count,
            "wheel has multiple *.dist-info/METADATA entries — picking the first"
        );
    }

    // Open the chosen entry. Check the header-reported uncompressed
    // size BEFORE reading any bytes — defends against a maliciously-
    // crafted entry whose header claims gigabytes uncompressed but
    // compresses to a few KB.
    let mut entry = archive.by_index(idx).map_err(|_| {
        // Re-opening the same index that succeeded above is a logic
        // error, not user-facing data corruption — but the only
        // honest return shape is `Validation` since we don't have an
        // `Invariant` arm reachable here without ergonomic noise.
        DomainError::Validation(
            "wheel METADATA entry became unreadable between scan and read".to_string(),
        )
    })?;
    let declared_size = entry.size();
    if declared_size > PYPI_WHEEL_METADATA_MAX_BYTES {
        return Err(DomainError::Validation(format!(
            "wheel METADATA entry declared {declared_size} bytes uncompressed; cap is {PYPI_WHEEL_METADATA_MAX_BYTES}"
        )));
    }
    // Defense-in-depth: cap the actual read at the same limit, so an
    // entry that lies on its uncompressed-size header (real read
    // overflows) is still bounded. The bytes read may legitimately
    // differ from `declared_size` for stored (no-compression) entries
    // whose declared size matches; the cap rules either case.
    let mut bytes_out: Vec<u8> = Vec::new();
    let mut limited = (&mut entry).take(PYPI_WHEEL_METADATA_MAX_BYTES + 1);
    if limited.read_to_end(&mut bytes_out).is_err() {
        // Read error mid-entry — corrupted wheel. Non-fatal.
        return Ok(None);
    }
    if bytes_out.len() as u64 > PYPI_WHEEL_METADATA_MAX_BYTES {
        return Err(DomainError::Validation(format!(
            "wheel METADATA entry read overran cap of {PYPI_WHEEL_METADATA_MAX_BYTES} bytes \
             (entry header lied about uncompressed size)"
        )));
    }
    Ok(Some(Bytes::from(bytes_out)))
}

/// PEP 427 §A — wheel METADATA lives at
/// `<distribution>-<version>.dist-info/METADATA` at the archive root.
/// Match by suffix `/METADATA` whose parent component ends with
/// `.dist-info`. Forbids deeper nesting (a path like
/// `foo/bar.dist-info/METADATA` is not the wheel METADATA).
fn is_wheel_metadata_path(name: &str) -> bool {
    let Some(parent) = name.strip_suffix("/METADATA") else {
        return false;
    };
    // The parent must contain no further `/` (root-level dist-info)
    // and must end with `.dist-info`.
    !parent.contains('/') && parent.ends_with(".dist-info")
}

impl FormatHandler for PyPiFormatHandler {
    fn format_key(&self) -> &str {
        "pypi"
    }

    /// Parse a download path like `simple/{project}/{filename}` into coordinates.
    ///
    /// Version is not extracted from the filename — it comes from upload
    /// metadata during ingest, not from the download path.
    fn parse_download_path(&self, path: &str) -> DomainResult<ArtifactCoords> {
        // Strip leading slash if present.
        let path = path.strip_prefix('/').unwrap_or(path);

        // Expected: simple/{project}/{filename}
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() != 3 || parts[0] != "simple" || parts[1].is_empty() || parts[2].is_empty() {
            return Err(DomainError::Validation(format!(
                "invalid PyPI download path: expected simple/{{project}}/{{filename}}, got: {path}"
            )));
        }

        let project = parts[1];
        let filename = parts[2];

        // Strict path-component validation BEFORE any further use. Rejects
        // `..`, control bytes, mixed path-separator injection, and
        // >256-byte attacker-supplied names.
        // PEP 503 §3 charset for the project; PEP 427 / PEP 625 charset
        // for the filename. Both surface as `DomainError::Validation`
        // with structured `pypi.<field>` tags.
        validate_pep_503_name(project)?;
        validate_pypi_filename(filename)?;

        // The read path uses the SSOT constructor so it embeds the PEP 503
        // NORMALIZED project segment (was the raw project — a PEP 503
        // violation that split `Foo.Bar`/`foo_bar` into separate projection
        // rows). pypi carries no version in the path, so `version = ""`;
        // the filename is required and embedded verbatim.
        let path = self.build_artifact_logical_path(project, "", Some(filename))?;
        Ok(ArtifactCoords {
            name: self.normalize_name(project),
            name_as_published: project.to_string(),
            version: None,
            path,
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        })
    }

    /// The single logical-projection-path constructor for pypi.
    /// `simple/{n}/{filename}` with `n = normalize_name(name)` (PEP
    /// 503: lowercase + collapse `[-_.]+` → `-`) and the filename embedded
    /// VERBATIM. `filename` is REQUIRED (pypi is multi-distribution — one
    /// `(name, version)` maps to many files); `None` is rejected.
    /// `version` is ignored (pypi paths carry no version segment).
    fn build_artifact_logical_path(
        &self,
        name: &str,
        version: &str,
        filename: Option<&str>,
    ) -> DomainResult<String> {
        let _ = version;
        let filename = filename.ok_or_else(|| {
            DomainError::Validation("pypi build_artifact_logical_path requires a filename".into())
        })?;
        let n = self.normalize_name(name);
        Ok(format!("simple/{n}/{filename}"))
    }

    /// PyPI METADATA (including long description) — 128 KB cap
    /// (calibrated against real-world METADATA sizes).
    fn metadata_expected_max_bytes(&self) -> usize {
        131_072
    }

    /// Per-version JSON API path:
    /// `/pypi/{normalized_name}/{version}/json`. The name is normalised
    /// per PEP 503 to match pypi.org's canonical URL form.
    ///
    /// Returns `None` if `coords.version` is `None`. File-pull paths
    /// derive a version from the filename before reaching this method,
    /// so in practice the orchestrator always passes a version; the
    /// `None`-on-missing-version branch matches the trait's `Option`
    /// shape (no `DomainResult` to surface a `Validation` through) and
    /// the orchestrator surfaces the missing-checksum-path case at
    /// dispatch time.
    fn upstream_checksum_metadata_path(&self, coords: &ArtifactCoords) -> Option<String> {
        let version = coords.version.as_deref()?;
        let normalized = self.normalize_name(&coords.name);
        Some(format!("/pypi/{normalized}/{version}/json"))
    }

    /// Extract the upstream-published version-string set from a PyPI
    /// simple-index body (PEP 503 HTML *or* PEP 691 JSON; the format is
    /// sniffed from the leading bytes).
    ///
    /// HTML path: scans `<a ... href="...">` anchors and applies the
    /// filename → version helper ([`pypi_extract_version_from_filename`])
    /// to each anchor's basename. Mirrors the hot-path trigger reader in
    /// `crates/hort-http-pypi/src/simple_index.rs::parse_upstream_versions_pypi`
    /// (the HTML arm).
    ///
    /// JSON path (PEP 691): reads the `versions[]` array directly when
    /// present; otherwise falls back to the helper-via-filename walk
    /// across `files[]`. Mirrors the hot-path JSON arm.
    ///
    /// Unparseable bodies (binary garbage, neither valid UTF-8 nor
    /// JSON) yield `Ok(Vec::new())` — same degrade-open policy as the
    /// hot-path trigger; the next tick re-evaluates.
    ///
    /// Bounded by the existing 128 KB
    /// [`metadata_expected_max_bytes`](Self::metadata_expected_max_bytes)
    /// cap, raised here to a 10 MiB ceiling to admit
    /// realistic simple-index pages (the per-version JSON cap was
    /// sized for METADATA only — a project with thousands of versions
    /// publishes a much larger HTML index). Bodies above 10 MiB are
    /// rejected as `Validation` (same shape as the npm 5 MB cap).
    ///
    /// Streaming (see ADR 0026): `body` is a streaming reader over the
    /// simple-index page. The PyPI simple-index walk is dual-mode —
    /// PEP 503 HTML (anchor scan over the whole body as a `&str`) OR PEP
    /// 691 JSON (`versions[]` / `files[]`); both modes need the body in
    /// memory. The body is read into a buffer bounded by the 10 MiB
    /// simple-index cap (so an over-cap body cannot force an unbounded
    /// allocation), then the existing byte-slice logic runs unchanged —
    /// byte-identical version list, HTML/JSON sniffing, and degrade-open
    /// policy. (The `PypiSimpleIndexProjector` only covers the PEP 691
    /// JSON `files[]` arm, not the HTML arm or the `versions[]` array,
    /// so it is not a drop-in here; the discovery seam in
    /// `hort-formats-upstream` uses the projector for the JSON-only
    /// serve path.)
    fn extract_upstream_versions(&self, body: &mut dyn Read) -> DomainResult<Vec<String>> {
        // Simple-index pages are bounded separately from per-version
        // JSON metadata; 10 MiB hard cap (a project with O(10^4) versions,
        // average filename ~80 bytes per anchor,
        // tops out under 4 MiB — leaving 2.5x headroom).
        const SIMPLE_INDEX_MAX_BYTES: usize = 10 * 1024 * 1024;
        let body =
            crate::stream_helpers::read_to_capped_vec(body, SIMPLE_INDEX_MAX_BYTES, |len, max| {
                format!("pypi simple-index body is {len} bytes; per-format max is {max}")
            })?;
        let body = body.as_slice();

        // PEP 691 JSON path — peek for a leading `{` after any
        // whitespace. Cheap pre-check; the full sniff is the serde
        // parse below.
        let leading = body.iter().find(|&&b| !b.is_ascii_whitespace()).copied();
        if leading == Some(b'{') {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                let mut out: Vec<String> = Vec::new();
                if let Some(arr) = value.get("versions").and_then(|v| v.as_array()) {
                    for entry in arr {
                        if let Some(s) = entry.as_str() {
                            out.push(s.to_string());
                        }
                    }
                }
                if out.is_empty() {
                    if let Some(files) = value.get("files").and_then(|v| v.as_array()) {
                        for f in files {
                            let filename = f
                                .get("filename")
                                .and_then(|x| x.as_str())
                                .map(str::to_string)
                                .or_else(|| {
                                    f.get("url")
                                        .and_then(|x| x.as_str())
                                        .and_then(|u| u.rsplit('/').next().map(str::to_string))
                                });
                            if let Some(fn_str) = filename {
                                if let Some(v) = pypi_extract_version_from_filename(&fn_str) {
                                    out.push(v);
                                }
                            }
                        }
                    }
                }
                return Ok(out);
            }
            // Falls through to HTML path on malformed JSON — a
            // mis-served body labelled JSON but actually shaped like
            // HTML still gets one more chance.
        }

        // HTML path — anchor walk + per-filename version extract.
        let Ok(html) = std::str::from_utf8(body) else {
            return Ok(Vec::new());
        };
        let mut out: Vec<String> = Vec::new();
        for href in pypi_scan_href_values(html) {
            if let Some(filename) = pypi_filename_from_href(href) {
                if let Some(v) = pypi_extract_version_from_filename(filename) {
                    out.push(v);
                }
            }
        }
        Ok(out)
    }

    /// Parse a per-version PyPI JSON API body, find the `urls[]` entry
    /// whose `filename` matches the basename of `coords.path`, and
    /// extract `digests.sha256`.
    ///
    /// SHA-1 / MD5 fallback is REJECTED: an entry with only `md5` in
    /// `digests` produces `Validation`, not a softer fallback.
    ///
    /// Streaming (see ADR 0026): `body` is a streaming reader over the
    /// per-version JSON API body. Unlike the npm packument / cargo
    /// sparse-index pages, this body is the small per-version metadata
    /// (bounded by the 128 KiB [`PYPI_VERSION_JSON_MAX_BYTES`] cap, a
    /// dedicated buffer bound decoupled from `metadata_expected_max_bytes`);
    /// it is read into a capped buffer and parsed — same `urls[]` walk,
    /// same SHA-256 / md5-rejection / no-urls-array / file-not-published
    /// error taxonomy (the per-version-JSON projector's flattened
    /// `Vec<files>` cannot distinguish "no urls array" from "empty urls",
    /// which gate distinct upstream-verification diagnostics). The cap and
    /// `>`-boundary are preserved.
    fn parse_upstream_checksum(
        &self,
        body: &mut dyn Read,
        coords: &ArtifactCoords,
    ) -> DomainResult<UpstreamPublishedChecksum> {
        let filename = coords.path.rsplit('/').next().unwrap_or("");
        if filename.is_empty() {
            return Err(DomainError::Validation(
                "upstream PyPI parser requires a non-empty path basename in coords".to_string(),
            ));
        }

        // Pre-parse size cap — defence in depth above the fetch-streaming
        // cap. The body is read into a buffer bounded by the cap (so an
        // over-cap body cannot force an unbounded allocation). Two layers
        // protect against parse-bomb workloads:
        //   (a) the cap bounds INPUT SIZE;
        //   (b) serde_json's built-in recursion limit (default 128) bounds
        //       PARSE-TREE DEPTH.
        // Do NOT call Deserializer::disable_recursion_limit on this path.
        let max = PYPI_VERSION_JSON_MAX_BYTES as usize;
        let body = crate::stream_helpers::read_to_capped_vec(body, max, |len, max| {
            format!("upstream metadata body is {len} bytes; pypi version-json max is {max}")
        })?;

        let doc: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            DomainError::Validation(format!("upstream PyPI response is not valid JSON: {e}"))
        })?;

        let urls = doc.get("urls").and_then(|v| v.as_array()).ok_or_else(|| {
            DomainError::Validation("upstream PyPI response has no urls array".to_string())
        })?;

        let entry = urls
            .iter()
            .find(|u| u.get("filename").and_then(|v| v.as_str()) == Some(filename))
            .ok_or_else(|| {
                let version = coords.version.as_deref().unwrap_or("?");
                DomainError::Validation(format!(
                    "upstream PyPI does not publish file {filename} for {}@{version}",
                    coords.name
                ))
            })?;

        let sha256 = entry
            .get("digests")
            .and_then(|v| v.get("sha256"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                DomainError::Validation(format!(
                    "upstream PyPI does not publish a SHA-256 digest for {filename}; \
                     SHA-1/MD5 fallback is not accepted"
                ))
            })?;

        UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, sha256.to_lowercase())
    }

    /// Normalize a package name per PEP 503 §4:
    /// replace any run of `-`, `_`, or `.` with a single `-`, then lowercase.
    fn normalize_name(&self, name: &str) -> String {
        let mut result = String::with_capacity(name.len());
        let mut in_separator_run = false;

        for c in name.chars() {
            if c == '-' || c == '_' || c == '.' {
                if !in_separator_run && !result.is_empty() {
                    result.push('-');
                    in_separator_run = true;
                }
            } else {
                in_separator_run = false;
                result.extend(c.to_lowercase());
            }
        }

        // Remove trailing separator.
        if result.ends_with('-') {
            result.pop();
        }

        result
    }

    /// Extract a deterministic SBOM from the per-release JSON the
    /// handler captured at ingest. Pure function — does not read
    /// `payload`.
    ///
    /// Recognises both shapes the registry returns:
    /// - `info.requires_dist: Vec<String>` (full per-release packument).
    /// - `requires_dist: Vec<String>` at the top level (single-version slice).
    ///
    /// Each PEP 508 requirement string is parsed into a `(name, version)`
    /// pair: extras (`name [extras]`) and environment markers (`; python_version >= '3.8'`)
    /// are dropped; an exact-pin constraint (`==`) populates the version,
    /// any other operator leaves it as `None`. The PURL is the canonical
    /// `pkg:pypi/{pep503_name}@{version}` shape, with the name normalised
    /// per PEP 503 §4.
    ///
    /// Licenses are pulled from `info.license` (string) or, when that is
    /// empty/absent, from `info.classifiers` (any entry beginning
    /// `License ::`).
    ///
    /// PyPI PEP 503 simple-index path — version-agnostic.
    /// **Differs** from [`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path)
    /// (which returns `/pypi/<name>/<version>/json` and requires a
    /// version). The simple-index document carries the version SET;
    /// the per-version JSON carries the per-version checksum. PyPI is
    /// the format where the metadata-index path and the per-version
    /// checksum path are structurally distinct (for npm + cargo the
    /// two coincide — see their `upstream_metadata_path` overrides).
    ///
    /// Returns the path with the PEP 503 `normalize_name` form. The
    /// upstream-proxy adapter composes onto the mapping's
    /// `upstream_url` base; pairs with
    /// [`upstream_metadata_accept`](Self::upstream_metadata_accept)
    /// which prefers PEP 691 JSON over HTML.
    fn upstream_metadata_path(&self, package: &str) -> Option<String> {
        let normalized = self.normalize_name(package);
        Some(format!("/simple/{normalized}/"))
    }

    /// PEP 691 content negotiation — prefer JSON (cheap parse), fall
    /// back to HTML. Upstream PyPI (`pypi.org`) and the modern mirrors
    /// (`pypi.python.org` redirects, devpi, simpleindex, recent
    /// Bandersnatch builds) serve both; the JSON path hits the cheap
    /// [`serde_json`] parser, the HTML fallback uses the slower
    /// [`FULL_ANCHOR_RE`](crate::pypi::FULL_ANCHOR_RE)-shaped walk.
    fn upstream_metadata_accept(&self) -> Vec<String> {
        vec![
            "application/vnd.pypi.simple.v1+json".to_string(),
            "text/html;q=0.5".to_string(),
        ]
    }

    /// Build an SBOM from a PyPI per-version JSON API body. Narrowed to
    /// PEP 508 requirements rather than free-form `requirements.txt`.
    fn extract_sbom(
        &self,
        coords: &ArtifactCoords,
        format_metadata: &serde_json::Value,
        _payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Sbom>> {
        // Locate `requires_dist` under either the `info` wrapper or the
        // top level. Either way it must be an array of strings.
        let requires_dist = format_metadata
            .get("info")
            .and_then(|info| info.get("requires_dist"))
            .or_else(|| format_metadata.get("requires_dist"))
            .and_then(|v| v.as_array());

        let licenses = extract_pypi_license_list(format_metadata);

        // Build the subject from coords regardless of whether the
        // PyPI metadata exposes `requires_dist`. A leaf wheel (no
        // declared deps) still needs the subject so osv-scanner can
        // detect vulnerabilities on the wheel itself.
        let subject_purl_name = self.normalize_name(&coords.name);
        let subject = build_subject_component(
            coords,
            Ecosystem::PyPI,
            "pkg:pypi/",
            &subject_purl_name,
            licenses.clone(),
        );

        let Some(reqs) = requires_dist else {
            return Ok(Some(Sbom {
                subject: Some(subject),
                components: vec![],
            }));
        };

        let mut components = Vec::new();
        for raw in reqs {
            let Some(req_str) = raw.as_str() else {
                continue;
            };
            let Some((name, version)) = parse_pep_508_requirement(req_str) else {
                continue;
            };
            let normalised_name = self.normalize_name(&name);
            let purl = match version.as_deref() {
                Some(v) => format!("pkg:pypi/{normalised_name}@{v}"),
                None => format!("pkg:pypi/{normalised_name}"),
            };
            components.push(SbomComponent {
                purl,
                name: normalised_name,
                version,
                ecosystem: Ecosystem::PyPI,
                licenses: licenses.clone(),
                direct_dependency: true,
            });
        }

        Ok(Some(Sbom {
            subject: Some(subject),
            components,
        }))
    }

    /// Open the wheel ZIP, seek to `<pkg>-<version>.dist-info/METADATA`,
    /// and return its raw bytes for the PEP 658 metadata-files endpoint.
    ///
    /// Recognises a wheel by the path's `.whl` suffix (PEP 427 §3
    /// filename grammar). Sdists (`.tar.gz`, `.zip`, `.tgz`, …) and any
    /// non-wheel path return `Ok(None)` — PEP 658 applies only to
    /// wheels.
    ///
    /// Non-fatal failure modes (`Ok(None)`):
    ///
    /// - Path is not a wheel (sdist or unrecognised suffix).
    /// - Payload bytes are not a valid ZIP (corrupted wheel that
    ///   somehow passed primary-content-hash verification).
    /// - Wheel ZIP has zero `*.dist-info/METADATA` entries (malformed
    ///   wheel that nonetheless verified).
    ///
    /// The non-fatal posture is intentional: a corrupt wheel that
    /// primary-content-hash-verified must not block ingest; PEP 658
    /// simply does not advertise for it and pip falls back to
    /// whole-wheel download.
    ///
    /// Fatal failure mode (`Err(DomainError::Validation)`):
    ///
    /// - The METADATA entry's reported uncompressed size exceeds
    ///   [`PYPI_WHEEL_METADATA_MAX_BYTES`] (1 MiB). Checked on the
    ///   ZIP header **before** reading any bytes — so a maliciously
    ///   crafted entry claiming 1 KB compressed expanding to 1 GB is
    ///   rejected on the header, not after OOM. Defense-in-depth: the
    ///   actual read is also capped at 1 MiB.
    ///
    /// Malformed wheel with multiple `*.dist-info/METADATA` entries
    /// (the wheel spec mandates exactly one): picks the first matching
    /// entry and logs `debug!`. Does NOT error — pip's behaviour is
    /// the same (first-match wins).
    fn extract_wheel_metadata_bytes(
        &self,
        coords: &ArtifactCoords,
        payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Bytes>> {
        // PEP 427 §3 — wheel filenames end `.whl`. Reuses the same
        // suffix check `pypi_extract_version_from_filename` uses; a
        // factored helper would be one-liner indirection that the
        // hot path does not need.
        if !coords.path.ends_with(".whl") {
            return Ok(None);
        }
        // Materialise the payload into memory. ZIP parsing needs
        // `Read + Seek`; PyPI wheels rarely exceed ~100 MB and the
        // ingest hook has already buffered the artifact for the
        // primary-content-hash computation, so the memory cost is
        // already paid at this point in the pipeline.
        let buf: Vec<u8> = match payload {
            PayloadAccess::Bytes(b) => b.to_vec(),
            PayloadAccess::ReadStream(mut r) => {
                let mut v = Vec::new();
                if r.read_to_end(&mut v).is_err() {
                    // Non-fatal: a stream that errored on read can't
                    // be PEP-658-advertised; pip falls back. The wheel
                    // ingest succeeded before this method is invoked.
                    return Ok(None);
                }
                v
            }
        };
        extract_wheel_metadata_bytes_from_zip(&buf)
    }

    /// Extract the *declared runtime* dependency specs from the **stored
    /// PyPI distribution artifact stream**.
    ///
    /// **Input is the stored distribution container, NOT a pre-selected
    /// METADATA body.** The transitive prefetch cascade hands this method the
    /// raw stored artifact it read from CAS (`read_artifact_bytes`), which for
    /// PyPI is either a **wheel** (`.whl` = a zip, magic `PK\x03\x04`) or an
    /// **sdist** (`.tar.gz` = gzip, magic `\x1f\x8b`). The method has no
    /// filename, so it sniffs the leading magic bytes to pick the container:
    ///
    /// - **wheel (zip):** a wheel's runtime deps are `Requires-Dist:` headers
    ///   in `{distribution}-{version}.dist-info/METADATA` (PEP 566 — RFC
    ///   5322-style headers). This method locates that entry INSIDE the zip via
    ///   the audited [`archive_bounds::iter_zip_entries`](crate::archive_bounds::iter_zip_entries)
    ///   and runs the private [`parse_wheel_metadata_into_specs`] parser on it.
    ///   A wheel with no `*.dist-info/METADATA` entry is corruption → `Err`.
    /// - **sdist (gzip):** best-effort skipped → `Ok(vec![])`. An sdist's
    ///   `PKG-INFO` frequently lacks `Requires-Dist` (the deps live in
    ///   `setup.py`/`pyproject.toml`, which require executing/parsing build
    ///   config), so the cascade skips sdists rather than emitting a partial
    ///   closure. Logged at `debug!`, not silent. (The PEP 658 `.metadata`
    ///   sidecar is a cleaner future dependency source for the wheel case;
    ///   out of scope here.)
    /// - **anything else:** a clear `Err` ("unrecognised pypi distribution
    ///   container") — raw METADATA or arbitrary bytes where a container is
    ///   expected, reported honestly.
    ///
    /// **Runtime classes only.** The extracted METADATA is parsed by
    /// [`parse_wheel_metadata_into_specs`], which walks `Requires-Dist:` lines
    /// but drops any gated by an `extra == '<name>'` environment marker — those
    /// are optional-extras deps (`pip install pkg[test]`) that balloon the
    /// transitive fan-out by the test/dev/docs extras production installs never
    /// pull. Plain markers without an `extra ==` clause (`; python_version >=
    /// '3.8'`) ARE kept — they constrain the platform but the dep is runtime.
    ///
    /// **Caps.** The compressed container stream is read into a capped buffer
    /// bounded by [`PYPI_DIST_MAX_BYTES`] (32 MiB compressed, matching the
    /// cascade's own artifact bound). The wheel-zip path's decompression-bomb /
    /// entry-count guards are `archive_bounds`' job; the *extracted* METADATA
    /// entry is separately bounded by [`PYPI_WHEEL_METADATA_MAX_BYTES`] (1 MiB)
    /// as a parser-input sanity cap on this identical content.
    ///
    /// **Errors.**
    /// - Input is neither a wheel zip nor an sdist gzip → `Validation`
    ///   ("unrecognised pypi distribution container").
    /// - Wheel zip is malformed / unreadable → `Validation`.
    /// - `*.dist-info/METADATA` absent from a wheel zip → `Validation`.
    /// - METADATA present but not valid UTF-8 → `Validation` (non-retry).
    /// - A well-formed wheel with zero declared runtime deps → `Ok(vec![])`.
    /// - sdist gzip → `Ok(vec![])` (best-effort skip).
    ///
    /// Streaming (see ADR 0026): `content` is a `&mut dyn Read`. The
    /// compressed bytes are read into a capped `Vec` to give
    /// `iter_zip_entries` the `Read + Seek` it needs (via a `Cursor`) and
    /// to sniff the leading magic — the cascade already buffers the
    /// compressed artifact, so this adds no second fetch.
    fn extract_dependency_specs(
        &self,
        content: &mut dyn Read,
    ) -> DomainResult<Vec<DependencySpec>> {
        // Read the compressed distribution container into a capped buffer:
        // we need the leading bytes to sniff the container type and a
        // `Read + Seek` (`Cursor`) for the zip central-directory walk.
        let buf =
            crate::stream_helpers::read_to_capped_vec(content, PYPI_DIST_MAX_BYTES, |len, max| {
                format!("pypi distribution artifact is {len} bytes; pypi distribution max is {max}")
            })?;

        match buf.as_slice() {
            // Wheel = zip. Magic `PK\x03\x04` (local file header).
            [0x50, 0x4B, 0x03, 0x04, ..] => {
                let metadata = locate_wheel_metadata_in_zip(&buf)?.ok_or_else(|| {
                    DomainError::Validation(
                        "pypi wheel is missing a *.dist-info/METADATA entry (corrupt artifact)"
                            .to_string(),
                    )
                })?;
                parse_wheel_metadata_into_specs(&metadata)
            }
            // sdist = gzip. Magic `\x1f\x8b`. Best-effort skip — sdist
            // PKG-INFO frequently lacks Requires-Dist.
            [0x1F, 0x8B, ..] => {
                tracing::debug!(
                    "pypi sdist (gzip) dependency specs are best-effort skipped \
                     (PKG-INFO frequently lacks Requires-Dist)"
                );
                Ok(Vec::new())
            }
            // Neither container — unrecognised bytes, reported honestly.
            _ => Err(DomainError::Validation(
                "unrecognised pypi distribution container: expected a wheel zip \
                 (PK\\x03\\x04) or an sdist gzip (\\x1f\\x8b)"
                    .to_string(),
            )),
        }
    }

    /// Resolve a PEP 440 specifier against an `available` set, returning
    /// the highest matching version string.
    ///
    /// See [`resolve_pep440_range_max`] for the full PEP 440 grammar
    /// coverage and the pre-release inclusion policy (pip-equivalent:
    /// pre-releases excluded unless the range explicitly names one,
    /// with a pre-only fallback when no final satisfies).
    ///
    /// Returns the matching version's original string from `available`
    /// (NOT a re-serialised `Version::to_string()`), so the caller can
    /// reuse it as the artifact-coords version string verbatim.
    fn resolve_range_max(&self, range: &str, available: &[&str]) -> DomainResult<Option<String>> {
        Ok(resolve_pep440_range_max(range, available))
    }

    /// PyPI returns the empty vec from `build_pull_url`.
    ///
    /// PyPI publishes a variable number of distributions per version
    /// (sdist + N wheels, each with its own checksum); a single
    /// `(package, version)` coordinate corresponds to MULTIPLE
    /// downloadable files. Composing those URLs requires fetching the
    /// per-version JSON manifest at
    /// `{upstream_url}/pypi/{normalized_name}/{version}/json` and
    /// walking its `urls[]` array — an I/O step that breaks the
    /// trait's purity contract.
    ///
    /// The leaf [`PrefetchIngestHandler`](
    /// crate::pypi) therefore special-cases PyPI: it uses
    /// [`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path)
    /// to discover the per-version JSON URL, fetches it via
    /// `UpstreamProxy::fetch_metadata`, parses `urls[]` to enumerate
    /// the per-distribution files, and ingests each via
    /// `IngestUseCase::ingest_verified`. Mirrors the hot-path
    /// `fire_prefetch_trigger_pypi` fan-out in
    /// `crates/hort-http-pypi/src/simple_index.rs`.
    ///
    /// Returns `Ok(Vec::new())` unconditionally — the leaf handler
    /// detects PyPI by `format_key() == "pypi"` and dispatches to
    /// the JSON-manifest-fan-out path instead of iterating the empty
    /// vec.
    fn build_pull_url(
        &self,
        _upstream_url: &str,
        _package: &str,
        _version: &str,
    ) -> DomainResult<Vec<String>> {
        Ok(Vec::new())
    }
}

/// Locate the first `*.dist-info/METADATA` member in a wheel ZIP byte buffer
/// and return its bytes, bounded by [`PYPI_WHEEL_METADATA_MAX_BYTES`].
///
/// Routes through [`archive_bounds::iter_zip_entries`](crate::archive_bounds::iter_zip_entries)
/// — the single sanctioned home for ZIP extraction: entry count is bounded by
/// [`MAX_ENTRIES`](crate::archive_bounds::MAX_ENTRIES) and each entry's
/// decompressed output is bounded by the compression-ratio guard.
/// `iter_zip_entries` reads the central directory and seeks to each entry, so
/// reaching the METADATA member does not decompress the whole archive.
///
/// Distinct from [`extract_wheel_metadata_bytes_from_zip`] (the PEP 658
/// path), which uses the `zip` crate directly and returns `Ok(None)` for
/// a corrupt / non-ZIP buffer because that path is non-fatal at ingest. Here
/// the buffer has already been magic-sniffed as a zip, so a parse failure is a
/// genuine corrupt-wheel signal the cascade must surface as `Err`.
///
/// Returns:
/// - `Ok(Some(bytes))` — the first matching METADATA entry's bytes.
/// - `Ok(None)` — the zip is valid but carries no `*.dist-info/METADATA`
///   entry (the caller maps this to a corrupt-wheel `Err`).
/// - `Err(DomainError::Validation)` — the buffer is not a readable ZIP, or an
///   `archive_bounds` guard tripped (entry-count / compression-ratio), or the
///   matched entry exceeds [`PYPI_WHEEL_METADATA_MAX_BYTES`].
fn locate_wheel_metadata_in_zip(buf: &[u8]) -> DomainResult<Option<Vec<u8>>> {
    let mut found: Option<Vec<u8>> = None;
    let mut read_err: Option<String> = None;
    crate::archive_bounds::iter_zip_entries(
        Cursor::new(buf),
        crate::archive_bounds::BoundsConfig::default_for_metadata_extraction(),
        |name, reader| {
            // First match wins (the wheel spec mandates exactly one
            // `*.dist-info/METADATA`); skip every other entry without reading.
            if found.is_some() || read_err.is_some() || !is_wheel_metadata_path(name) {
                return;
            }
            // Parser-input sanity cap on the EXTRACTED entry (the
            // archive-level bomb guard is `iter_zip_entries`' job). `take`
            // bounds the allocation; a read overrun past the cap is rejected.
            let mut bytes = Vec::new();
            let mut limited = reader.take(PYPI_WHEEL_METADATA_MAX_BYTES + 1);
            match limited.read_to_end(&mut bytes) {
                Ok(_) if bytes.len() as u64 > PYPI_WHEEL_METADATA_MAX_BYTES => {
                    read_err = Some(format!(
                        "wheel METADATA entry exceeds cap of {PYPI_WHEEL_METADATA_MAX_BYTES} bytes"
                    ));
                }
                Ok(_) => found = Some(bytes),
                // A read error here is an `archive_bounds` bounds trip or a
                // corrupt entry — surface it as Err, never a silent skip.
                Err(e) => read_err = Some(format!("wheel METADATA entry read failed: {e}")),
            }
        },
    )
    .map_err(|e| DomainError::Validation(format!("pypi wheel is not a readable zip: {e}")))?;

    if let Some(msg) = read_err {
        return Err(DomainError::Validation(msg));
    }
    Ok(found)
}

/// Parse the *declared runtime* dependency specs from a wheel `METADATA`
/// (PEP 566) file body.
///
/// Factored out of [`PyPiFormatHandler::extract_dependency_specs`] so the
/// bytes-in/specs-out kernel is unit-testable directly without manufacturing
/// a wheel ZIP.
///
/// **Runtime classes only.** Walks `Requires-Dist:` lines but FILTERS OUT any
/// line carrying an `extra == '<name>'` environment marker (via
/// [`is_extras_gated_requirement`]) — those are optional-extras deps a plain
/// `pip install pkg` never activates. Plain markers without an `extra ==`
/// clause (`; python_version >= '3.8'`) ARE kept.
///
/// Each surviving line is parsed via [`parse_requires_dist_into_spec`] — name +
/// parenthesised-or-inline version specifier. The specifier (e.g. `(>=1.0,<2)`)
/// becomes the `range` field verbatim (no specifier → empty `range`). Lines
/// that don't parse as `Requires-Dist:` (other headers, the description body
/// after the first blank line, malformed continuations) are silently skipped.
///
/// Input must be valid UTF-8 (PEP 566 §3) — otherwise `Validation`. Bounded by
/// [`PYPI_WHEEL_METADATA_MAX_BYTES`] (1 MiB) as a parser-input sanity cap on
/// this identical content (the same canonical cap
/// [`extract_wheel_metadata_bytes`](PyPiFormatHandler::extract_wheel_metadata_bytes)
/// uses), decoupled from `metadata_expected_max_bytes`.
fn parse_wheel_metadata_into_specs(metadata: &[u8]) -> DomainResult<Vec<DependencySpec>> {
    if metadata.len() as u64 > PYPI_WHEEL_METADATA_MAX_BYTES {
        return Err(DomainError::Validation(format!(
            "pypi METADATA body is {} bytes; wheel METADATA max is {PYPI_WHEEL_METADATA_MAX_BYTES}",
            metadata.len()
        )));
    }
    let text = std::str::from_utf8(metadata).map_err(|e| {
        DomainError::Validation(format!("pypi METADATA body is not valid UTF-8: {e}"))
    })?;

    let mut out = Vec::new();
    for line in text.lines() {
        // RFC 5322 headers end at the first blank line — everything after is
        // the description body, which the wheel METADATA spec calls out
        // explicitly.
        if line.is_empty() {
            break;
        }
        let Some(value) = line.strip_prefix("Requires-Dist:") else {
            continue;
        };
        let value = value.trim();
        // Drop extras-gated deps: `; extra == 'test'` / `; extra == "dev"`.
        // pip's source (`pip._internal.req.constructors`) does an equivalent
        // check at install time. The cascade never asks for extras → drop.
        if is_extras_gated_requirement(value) {
            continue;
        }
        let Some((name, range)) = parse_requires_dist_into_spec(value) else {
            continue;
        };
        out.push(DependencySpec { name, range });
    }
    Ok(out)
}

/// True if a PEP 508 requirement string is gated by an `extra == '...'`
/// environment marker — i.e. it is an optional-extras dependency that a
/// plain `pip install pkg` (no `[extras]`) would never activate.
///
/// Mirrors pip's behaviour: a `Requires-Dist: foo ; extra == 'test'`
/// line is only realised when the user explicitly requests the `test`
/// extra. The transitive prefetch cascade never asks for extras, so
/// the dep must be dropped. Non-extras markers (`python_version >=
/// '3.8'`, `sys_platform == 'linux'`) constrain platform compat but
/// don't gate the dep on user opt-in — those are kept.
///
/// Heuristic — looks for `extra` followed by `==`, `!=`, `in`, or
/// `not in` after the first `;`. PEP 508 admits whitespace anywhere
/// in the marker; the match is lowercase+whitespace-collapsed for
/// robustness.
///
/// Also covers the list-form (`extra in ['test', 'dev']`) and
/// negation-form (`extra not in ['test']`) marker syntaxes — PEP 508
/// permits both alongside the more common `==` / `!=`. Without this, a
/// `Requires-Dist: foo ; extra in ['test', 'dev']` line was treated
/// as a runtime dep and inflated the cascade fan-out.
fn is_extras_gated_requirement(req: &str) -> bool {
    let Some(marker) = req.split_once(';').map(|(_, m)| m) else {
        return false;
    };
    // Strip whitespace + lowercase for the comparison. PEP 508 markers
    // are case-sensitive for the `extra` env-marker name; lowercasing
    // here is a safety net against minor publisher inconsistency.
    let marker = marker
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    // Patterns observed in the wild:
    //   `extra=='test'`, `extra!='dev'`,
    //   `extra=='test'andpython_version>='3'` (combined marker),
    //   `extrain['test','dev']`        (list form — PEP 508 §"in" operator),
    //   `extranotin['test']`           (negated list form).
    // The whitespace-stripped+lowercased marker collapses
    //   `extra in [...]`       → `extrain[`
    //   `extra not in [...]`   → `extranotin[`
    // so a substring match on either is sufficient.
    marker.contains("extra==")
        || marker.contains("extra!=")
        || marker.contains("extrain[")
        || marker.contains("extranotin[")
}

/// Parse a `Requires-Dist` value into `(name, range)`. The `range` is
/// the version specifier verbatim — empty string when none is present.
///
/// Reuses the conventions of [`parse_pep_508_requirement`] but keeps
/// the *original* specifier string instead of distilling it down to an
/// exact-pin (which is what the SBOM path wants). The range grammar is
/// what the cascade feeds back into
/// [`PyPiFormatHandler::resolve_range_max`], so it must round-trip.
fn parse_requires_dist_into_spec(line: &str) -> Option<(String, String)> {
    // Drop the marker — only the requirement proper carries the range.
    let head = line.split(';').next()?.trim();
    if head.is_empty() {
        return None;
    }
    // Strip extras (`name[extras]`).
    let head_no_extras = if let Some(start) = head.find('[') {
        if let Some(end) = head[start..].find(']') {
            let mut s = String::with_capacity(head.len());
            s.push_str(head[..start].trim_end());
            s.push_str(head[start + end + 1..].trim_start());
            s
        } else {
            head.to_string()
        }
    } else {
        head.to_string()
    };

    // Parenthesised specifier — `name (>=1.0,<2)`.
    if let Some(open) = head_no_extras.find('(') {
        let close = head_no_extras[open..].find(')')?;
        let name = head_no_extras[..open].trim().to_string();
        let range = head_no_extras[open + 1..open + close].trim().to_string();
        if name.is_empty() {
            return None;
        }
        return Some((name, range));
    }

    // Inline specifier — `name>=1.0`.
    let bytes = head_no_extras.as_bytes();
    let mut split = None;
    for (i, b) in bytes.iter().enumerate() {
        if matches!(b, b'=' | b'>' | b'<' | b'~' | b'!') {
            split = Some(i);
            break;
        }
    }
    let (name, range) = match split {
        Some(i) => (
            head_no_extras[..i].trim().to_string(),
            head_no_extras[i..].trim().to_string(),
        ),
        None => (head_no_extras.trim().to_string(), String::new()),
    };
    if name.is_empty() {
        return None;
    }
    Some((name, range))
}

/// Parse a single PEP 508 requirement line into `(name, Option<version>)`.
///
/// Handled syntax (covers what registry-published `requires_dist` strings
/// realistically use):
/// - `name`
/// - `name [extras]`
/// - `name (==1.0)` / `name (>=1.0)` / `name (~=1.0,<2)` etc.
/// - `name==1.0` / `name>=1.0` (the legacy comma-less form)
/// - `name ; python_version >= '3.8'` (environment marker dropped)
///
/// Only the `==` exact-pin operator promotes to a concrete version; any
/// other operator (including the parenthesised forms) leaves the version
/// as `None`. We deliberately do NOT ship a full PEP 508 grammar parser —
/// the intent is to parse what's needed, not re-derive the full grammar.
fn parse_pep_508_requirement(line: &str) -> Option<(String, Option<String>)> {
    // 1. Drop the environment marker (everything after the first `;`).
    let head = line.split(';').next()?;
    let head = head.trim();
    if head.is_empty() {
        return None;
    }

    // 2. Strip extras (`[…]`) — they don't change identity for SBOM.
    let head_no_extras = if let Some(start) = head.find('[') {
        if let Some(end) = head[start..].find(']') {
            let mut s = String::with_capacity(head.len() - (end - start + 1));
            s.push_str(head[..start].trim_end());
            s.push_str(head[start + end + 1..].trim_start());
            s
        } else {
            head.to_string()
        }
    } else {
        head.to_string()
    };

    // 3. Split off the parenthesised version constraint, if any.
    //    `name (==1.0)` → name="name", spec="==1.0".
    let (name_part, spec_part) = if let Some(open) = head_no_extras.find('(') {
        let close = head_no_extras[open..].find(')')?;
        let name = head_no_extras[..open].trim().to_string();
        let spec = head_no_extras[open + 1..open + close].trim().to_string();
        (name, Some(spec))
    } else {
        // No parens — the version operator (if any) is inline.
        // Find the first byte that starts an operator and split.
        let bytes = head_no_extras.as_bytes();
        let mut split = None;
        for (i, b) in bytes.iter().enumerate() {
            if matches!(b, b'=' | b'>' | b'<' | b'~' | b'!') {
                split = Some(i);
                break;
            }
        }
        match split {
            Some(i) => (
                head_no_extras[..i].trim().to_string(),
                Some(head_no_extras[i..].trim().to_string()),
            ),
            None => (head_no_extras.trim().to_string(), None),
        }
    };

    if name_part.is_empty() {
        return None;
    }

    // 4. From the spec, recover an exact-pin version. PEP 508 allows
    //    comma-separated constraints (`==1.0,!=1.0.1`) — pick the first
    //    `==` clause.
    let version = spec_part.and_then(|spec| {
        for clause in spec.split(',') {
            let clause = clause.trim();
            if let Some(rest) = clause.strip_prefix("==") {
                let v = rest.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        None
    });

    Some((name_part, version))
}

/// Extract a license list from a PyPI per-release metadata JSON.
///
/// Reads `info.license` as the primary source (a free-form string).
/// When that is empty or absent, falls back to the PEP 639-style
/// `License ::` classifier in `info.classifiers`. Returns an empty
/// `Vec` when no license information is recoverable.
fn extract_pypi_license_list(metadata: &serde_json::Value) -> Vec<String> {
    let info = metadata.get("info");

    // Primary: `info.license` string.
    if let Some(s) = info.and_then(|i| i.get("license")).and_then(|v| v.as_str()) {
        if !s.is_empty() {
            return vec![s.to_string()];
        }
    }

    // Fallback: `License ::` classifiers.
    let mut out = Vec::new();
    if let Some(classifiers) = info
        .and_then(|i| i.get("classifiers"))
        .and_then(|v| v.as_array())
    {
        for c in classifiers {
            if let Some(s) = c.as_str() {
                if let Some(rest) = s.strip_prefix("License ::") {
                    out.push(rest.trim().to_string());
                }
            }
        }
    }
    out
}

/// Extract the upstream file URL for `filename` from a per-version PyPI JSON
/// API body.
///
/// Walks `urls[]` looking for an entry whose `filename` field equals
/// `filename` exactly (no case-folding — wheels and sdists are case-sensitive
/// on disk; PEP 503 normalisation applies to project names, not filenames),
/// then returns the entry's `url` field as a `String`.
///
/// The URL is required to begin with `https://`. `http://`, missing scheme,
/// or any other scheme is rejected as a `Validation` error so we never
/// promote a downgrade-attack target to a fetch URL.
///
/// `max_bytes` is the per-format input-size ceiling. The caller must pass
/// [`PyPiFormatHandler::metadata_expected_max_bytes`]; the parameter is
/// explicit because this is a free function with no `&self` to read it
/// from. A body larger than `max_bytes` is rejected as
/// [`DomainError::Validation`] before serde_json sees it.
///
/// Kept independent of `parse_upstream_checksum` on purpose: the redundant
/// `serde_json::from_slice` is cheap (PyPI single-version JSON is < 50 KB)
/// and the two parsers are called from different orchestration paths.
/// Combine only if profiling shows a hotspot.
///
/// Visibility: `pub` rather than `pub(crate)` because the sole external
/// caller (`crates/hort-http-pypi/src/upstream_pull.rs:232`) sits in a
/// different crate.
pub fn extract_upstream_file_url(
    body: &[u8],
    filename: &str,
    max_bytes: usize,
) -> DomainResult<String> {
    // Pre-parse size cap. See the matching block in
    // `PyPiFormatHandler::parse_upstream_checksum` for the full
    // defence-in-depth explanation.
    if body.len() > max_bytes {
        return Err(DomainError::Validation(format!(
            "upstream metadata body is {} bytes; per-format max is {}",
            body.len(),
            max_bytes
        )));
    }

    let doc: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        DomainError::Validation(format!("upstream PyPI response is not valid JSON: {e}"))
    })?;

    let urls = doc.get("urls").and_then(|v| v.as_array()).ok_or_else(|| {
        DomainError::Validation("upstream PyPI response has no urls array".to_string())
    })?;

    let entry = urls
        .iter()
        .find(|u| u.get("filename").and_then(|v| v.as_str()) == Some(filename))
        .ok_or_else(|| {
            DomainError::Validation(format!("upstream PyPI does not publish file {filename}"))
        })?;

    let url = entry.get("url").and_then(|v| v.as_str()).ok_or_else(|| {
        DomainError::Validation(format!(
            "upstream PyPI urls[] entry for {filename} is missing a string url field"
        ))
    })?;

    if !url.starts_with("https://") {
        return Err(DomainError::Validation(format!(
            "upstream PyPI returned non-https URL: {url}"
        )));
    }

    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> PyPiFormatHandler {
        PyPiFormatHandler
    }

    // -- normalize_name -------------------------------------------------------

    #[test]
    fn normalize_simple_lowercase() {
        assert_eq!(handler().normalize_name("requests"), "requests");
    }

    #[test]
    fn normalize_uppercase() {
        assert_eq!(handler().normalize_name("Requests"), "requests");
    }

    #[test]
    fn normalize_underscores_to_hyphens() {
        assert_eq!(handler().normalize_name("my_package"), "my-package");
    }

    #[test]
    fn normalize_dots_to_hyphens() {
        assert_eq!(handler().normalize_name("my.package"), "my-package");
    }

    #[test]
    fn normalize_mixed_separators() {
        assert_eq!(handler().normalize_name("My_Package.v2"), "my-package-v2");
    }

    #[test]
    fn normalize_consecutive_separators_collapse() {
        assert_eq!(handler().normalize_name("a-._b"), "a-b");
    }

    #[test]
    fn normalize_leading_separator_stripped() {
        assert_eq!(handler().normalize_name("_leading"), "leading");
    }

    #[test]
    fn normalize_trailing_separator_stripped() {
        assert_eq!(handler().normalize_name("trailing_"), "trailing");
    }

    #[test]
    fn normalize_empty() {
        assert_eq!(handler().normalize_name(""), "");
    }

    // -- parse_download_path --------------------------------------------------

    #[test]
    fn parse_valid_download_path() {
        let coords = handler()
            .parse_download_path("simple/requests/requests-2.31.0.tar.gz")
            .unwrap();
        assert_eq!(coords.name, "requests");
        assert_eq!(coords.version, None);
        assert_eq!(coords.path, "simple/requests/requests-2.31.0.tar.gz");
        assert_eq!(coords.format, RepositoryFormat::Pypi);
    }

    #[test]
    fn parse_download_path_with_leading_slash() {
        let coords = handler()
            .parse_download_path("/simple/my-pkg/my-pkg-1.0.0.whl")
            .unwrap();
        assert_eq!(coords.name, "my-pkg");
        assert_eq!(coords.path, "simple/my-pkg/my-pkg-1.0.0.whl");
    }

    #[test]
    fn parse_download_path_normalizes_project_name() {
        let coords = handler()
            .parse_download_path("simple/My_Package/My_Package-1.0.tar.gz")
            .unwrap();
        assert_eq!(coords.name, "my-package");
        // The stored path embeds the PEP 503 NORMALIZED project segment,
        // not the raw one — `simple/{normalized}/{filename verbatim}`.
        // Previously this wrote `simple/My_Package/...`,
        // a PEP-503-violating, variant-row-splitting path.
        assert_eq!(coords.path, "simple/my-package/My_Package-1.0.tar.gz");
        // `name_as_published` keeps the as-typed spelling for display/audit.
        assert_eq!(coords.name_as_published, "My_Package");
    }

    // -- build_artifact_logical_path ------------------------------------------

    /// `simple/{n}/{filename}` with `n` PEP-503-normalized and the
    /// filename embedded VERBATIM. `version` is ignored.
    #[test]
    fn build_logical_path_basic() {
        assert_eq!(
            handler()
                .build_artifact_logical_path("requests", "", Some("requests-2.31.0.tar.gz"))
                .unwrap(),
            "simple/requests/requests-2.31.0.tar.gz"
        );
    }

    /// The project segment is normalized but the filename is verbatim:
    /// a raw-cased project + a raw-cased filename normalizes only the
    /// path segment.
    #[test]
    fn build_logical_path_normalizes_only_project_segment() {
        assert_eq!(
            handler()
                .build_artifact_logical_path("My_Package", "1.0", Some("My_Package-1.0.tar.gz"))
                .unwrap(),
            "simple/my-package/My_Package-1.0.tar.gz"
        );
    }

    /// `version` is ignored — pypi paths carry no version segment.
    #[test]
    fn build_logical_path_ignores_version() {
        let with_ver = handler()
            .build_artifact_logical_path("foo", "9.9.9", Some("foo-1.0.tar.gz"))
            .unwrap();
        let empty_ver = handler()
            .build_artifact_logical_path("foo", "", Some("foo-1.0.tar.gz"))
            .unwrap();
        assert_eq!(with_ver, "simple/foo/foo-1.0.tar.gz");
        assert_eq!(with_ver, empty_ver);
    }

    /// `filename = None` is rejected — pypi is multi-distribution and the
    /// filename is required to make the path reachable.
    #[test]
    fn build_logical_path_requires_filename() {
        let err = handler()
            .build_artifact_logical_path("requests", "", None)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    /// pypi `normalize_name` already collapses `[-_.]` at the identity
    /// layer (PEP 503), so variants merge into one project at publish — no
    /// separate registration-collision check is needed.
    #[test]
    fn collision_key_is_none() {
        assert_eq!(handler().collision_key("Foo.Bar"), None);
        assert_eq!(handler().collision_key("foo_bar"), None);
    }

    /// Round-trip / inverse: the canonical request path parses to the
    /// canonical (normalized) path, and rebuilding from the parsed
    /// (name, filename) yields the same path.
    #[test]
    fn build_logical_path_round_trip() {
        // `foo-bar` is already PEP 503 canonical, so parse(p).path == p.
        let p = "simple/foo-bar/foo_bar-1.0.tar.gz";
        let coords = handler().parse_download_path(p).unwrap();
        assert_eq!(coords.path, p);
        let filename = coords.path.rsplit('/').next().unwrap();
        assert_eq!(
            handler()
                .build_artifact_logical_path(&coords.name, "", Some(filename))
                .unwrap(),
            p
        );
    }

    /// Variant collapse (the PEP 503 identity guard): `Foo.Bar` and
    /// `foo_bar` build the SAME path (`simple/foo-bar/...`).
    #[test]
    fn build_logical_path_variant_collapse() {
        let a = handler()
            .build_artifact_logical_path("Foo.Bar", "", Some("x-1.0.tar.gz"))
            .unwrap();
        let b = handler()
            .build_artifact_logical_path("foo_bar", "", Some("x-1.0.tar.gz"))
            .unwrap();
        assert_eq!(a, "simple/foo-bar/x-1.0.tar.gz");
        assert_eq!(a, b);
    }

    #[test]
    fn parse_invalid_path_missing_filename() {
        let err = handler()
            .parse_download_path("simple/requests")
            .unwrap_err();
        assert!(err.to_string().contains("invalid PyPI download path"));
    }

    #[test]
    fn parse_invalid_path_wrong_prefix() {
        let err = handler()
            .parse_download_path("packages/requests/requests-1.0.tar.gz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid PyPI download path"));
    }

    #[test]
    fn parse_invalid_path_empty_project() {
        let err = handler()
            .parse_download_path("simple//requests-1.0.tar.gz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid PyPI download path"));
    }

    #[test]
    fn parse_invalid_path_empty() {
        let err = handler().parse_download_path("").unwrap_err();
        assert!(err.to_string().contains("invalid PyPI download path"));
    }

    // -- validate_pep_503_name -----------------------------------------------

    #[test]
    fn validate_pep_503_name_rejects_empty() {
        let err = validate_pep_503_name("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("pypi.name"),
            "must include structured field name: {err}"
        );
    }

    #[test]
    fn validate_pep_503_name_rejects_257_bytes() {
        let s = "a".repeat(257);
        let err = validate_pep_503_name(&s).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_accepts_256_byte_boundary() {
        let s = "a".repeat(256);
        validate_pep_503_name(&s).expect("256 bytes is the boundary, must accept");
    }

    #[test]
    fn validate_pep_503_name_rejects_leading_hyphen() {
        let err = validate_pep_503_name("-foo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_rejects_leading_dot() {
        let err = validate_pep_503_name(".foo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_rejects_dotdot() {
        let err = validate_pep_503_name("..").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_rejects_path_traversal() {
        let err = validate_pep_503_name("../etc").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_rejects_control_byte() {
        let err = validate_pep_503_name("foo\x00bar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_rejects_crlf() {
        let err = validate_pep_503_name("\r\nfoo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_rejects_del_byte() {
        // 0x7F (DEL) is a control character per the spec.
        let err = validate_pep_503_name("foo\x7fbar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_rejects_path_separator() {
        let err = validate_pep_503_name("foo/bar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_rejects_outside_charset() {
        // `@` is not in the PEP 503 §3 normalised name grammar.
        let err = validate_pep_503_name("foo@bar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn validate_pep_503_name_accepts_basic_lowercase() {
        validate_pep_503_name("requests").expect("lowercase ASCII must pass");
    }

    #[test]
    fn validate_pep_503_name_accepts_mixed_case() {
        validate_pep_503_name("Flask").expect("PEP 503 §3 allows mixed case");
    }

    #[test]
    fn validate_pep_503_name_accepts_hyphens() {
        validate_pep_503_name("django-rest-framework").expect("hyphens allowed");
    }

    #[test]
    fn validate_pep_503_name_accepts_underscores_and_dots() {
        validate_pep_503_name("my_package.v2").expect("underscore + dot allowed");
    }

    #[test]
    fn validate_pep_503_name_accepts_digits() {
        validate_pep_503_name("zope2").expect("digits allowed");
    }

    // -- validate_pypi_filename ----------------------------------------------

    #[test]
    fn validate_pypi_filename_rejects_empty() {
        let err = validate_pypi_filename("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("pypi.filename"),
            "must include structured field name: {err}"
        );
    }

    #[test]
    fn validate_pypi_filename_rejects_257_bytes() {
        let s = "a".repeat(257);
        let err = validate_pypi_filename(&s).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_accepts_256_byte_boundary() {
        let s = "a".repeat(256);
        validate_pypi_filename(&s).expect("256 bytes is the boundary, must accept");
    }

    #[test]
    fn validate_pypi_filename_rejects_forward_slash() {
        let err = validate_pypi_filename("foo/bar.tar.gz").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_rejects_backslash() {
        let err = validate_pypi_filename("foo\\bar.tar.gz").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_rejects_control_byte() {
        let err = validate_pypi_filename("foo\x00.tar.gz").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_rejects_crlf() {
        let err = validate_pypi_filename("foo\r\n.tar.gz").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_rejects_del_byte() {
        let err = validate_pypi_filename("foo\x7f.tar.gz").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_rejects_outside_charset() {
        // `@` is not in the wheel/sdist filename charset.
        let err = validate_pypi_filename("foo@bar.tar.gz").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_accepts_sdist() {
        validate_pypi_filename("requests-2.31.0.tar.gz").expect("sdist filename must pass");
    }

    #[test]
    fn validate_pypi_filename_accepts_wheel() {
        // PEP 427 §3 wheel filename
        // {distribution}-{version}(-{build})?-{python.tag}-{abi.tag}-{platform.tag}.whl
        validate_pypi_filename("numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.whl")
            .expect("wheel filename must pass");
    }

    #[test]
    fn validate_pypi_filename_accepts_local_version_with_plus() {
        // PEP 440 local version identifier (e.g. `1.0+local`) embeds in
        // wheel/sdist filenames; the `+` must be admitted.
        validate_pypi_filename("example-1.0+local.tar.gz")
            .expect("PEP 440 local version `+` must be admitted");
    }

    #[test]
    fn validate_pypi_filename_accepts_wheel_with_build_number() {
        // PEP 427 §3 build tag — purely numeric; just confirm typical shape.
        validate_pypi_filename("foo-1.0-1-py3-none-any.whl").expect("build-tag wheel must pass");
    }

    #[test]
    fn validate_pypi_filename_rejects_dotdot() {
        // `..` is in the charset (just two `.` bytes) but expresses
        // traversal intent and is never a legitimate PyPI sdist / wheel
        // filename.
        let err = validate_pypi_filename("..").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_rejects_single_dot() {
        // `.` would collapse to the current-directory marker if
        // concatenated into a path template — same class as `..`.
        let err = validate_pypi_filename(".").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn validate_pypi_filename_rejects_only_dots_long() {
        // Any-length all-dots filename is rejected.
        let err = validate_pypi_filename("....").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    // -- validate_pypi_version ------------------------------------------------

    #[test]
    fn validate_pypi_version_rejects_empty() {
        let err = validate_pypi_version("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("pypi.version"),
            "must include structured field name: {err}"
        );
    }

    #[test]
    fn validate_pypi_version_rejects_257_bytes() {
        let s = "1".repeat(257);
        let err = validate_pypi_version(&s).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_accepts_256_byte_boundary() {
        let s = "1".repeat(256);
        validate_pypi_version(&s).expect("256 bytes is the boundary, must accept");
    }

    #[test]
    fn validate_pypi_version_rejects_crlf() {
        let err = validate_pypi_version("1.0\r\nInjected").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_rejects_lf_only() {
        let err = validate_pypi_version("1.0\nfoo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_rejects_null_byte() {
        let err = validate_pypi_version("1.0\x00bad").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_rejects_del_byte() {
        let err = validate_pypi_version("1.0\x7fbad").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_rejects_forward_slash() {
        let err = validate_pypi_version("1.0/etc").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_rejects_backslash() {
        let err = validate_pypi_version("1.0\\etc").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_rejects_space() {
        // Whitespace is outside the charset.
        let err = validate_pypi_version("1.0 beta").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_rejects_outside_charset() {
        // `@` is outside the PEP 440 character set used here.
        let err = validate_pypi_version("1.0@beta").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.version"));
    }

    #[test]
    fn validate_pypi_version_accepts_simple_release() {
        validate_pypi_version("1.0.0").expect("simple release version must pass");
    }

    #[test]
    fn validate_pypi_version_accepts_pre_release() {
        validate_pypi_version("1.0.0a1").expect("PEP 440 pre-release must pass");
        validate_pypi_version("1.0.0rc1").expect("PEP 440 rc must pass");
    }

    #[test]
    fn validate_pypi_version_accepts_post_and_dev() {
        validate_pypi_version("1.0.post1").expect("PEP 440 post must pass");
        validate_pypi_version("1.0.dev1").expect("PEP 440 dev must pass");
    }

    #[test]
    fn validate_pypi_version_accepts_epoch() {
        // PEP 440 epoch uses `!`.
        validate_pypi_version("1!1.0.0").expect("PEP 440 epoch must pass");
    }

    #[test]
    fn validate_pypi_version_accepts_local_version() {
        // PEP 440 local version uses `+`.
        validate_pypi_version("1.0.0+ubuntu.20.04.1").expect("PEP 440 local version must pass");
    }

    #[test]
    fn validate_pypi_version_accepts_legacy_underscore() {
        // Legacy version strings sometimes contain `_` (PEP 440
        // permits it under normalization rules). The charset gate
        // admits it; downstream consumers normalise as needed.
        validate_pypi_version("1.0_alpha").expect("underscore must pass charset gate");
    }

    // -- parse_download_path strict-validation tests -------------------------

    #[test]
    fn parse_download_path_rejects_dotdot_in_name() {
        let err = handler()
            .parse_download_path("simple/../requests-1.0.tar.gz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn parse_download_path_rejects_traversal_in_name() {
        // Without a path separator the wildcard accepts `..%2Fetc` as a
        // single segment after splitn(3); the validator catches the `%`
        // (outside the PEP 503 charset).
        let err = handler()
            .parse_download_path("simple/..%2Fetc/foo-1.0.tar.gz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn parse_download_path_rejects_control_byte_in_name() {
        let err = handler()
            .parse_download_path("simple/foo\x00bar/foo-1.0.tar.gz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn parse_download_path_rejects_oversize_name() {
        let big = "a".repeat(257);
        let err = handler()
            .parse_download_path(&format!("simple/{big}/foo-1.0.tar.gz"))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn parse_download_path_rejects_leading_hyphen_in_name() {
        let err = handler()
            .parse_download_path("simple/-foo/foo-1.0.tar.gz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn parse_download_path_rejects_leading_dot_in_name() {
        let err = handler()
            .parse_download_path("simple/.foo/foo-1.0.tar.gz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.name"));
    }

    #[test]
    fn parse_download_path_rejects_control_byte_in_filename() {
        let err = handler()
            .parse_download_path("simple/foo/foo\x00-1.0.tar.gz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn parse_download_path_rejects_oversize_filename() {
        let big = "a".repeat(257);
        let err = handler()
            .parse_download_path(&format!("simple/foo/{big}"))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn parse_download_path_rejects_outside_charset_in_filename() {
        // `@` not in the filename charset.
        let err = handler()
            .parse_download_path("simple/foo/foo@bar-1.0.tar.gz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("pypi.filename"));
    }

    #[test]
    fn parse_download_path_accepts_local_version_filename() {
        // PEP 440 local version with `+` survives the filename validator.
        let coords = handler()
            .parse_download_path("simple/example/example-1.0+local.tar.gz")
            .unwrap();
        assert_eq!(coords.name, "example");
    }

    #[test]
    fn parse_download_path_accepts_full_wheel_filename() {
        let coords = handler()
            .parse_download_path("simple/numpy/numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.whl")
            .unwrap();
        assert_eq!(coords.name, "numpy");
    }

    // -- format_key -----------------------------------------------------------

    #[test]
    fn format_key_is_pypi() {
        assert_eq!(handler().format_key(), "pypi");
    }

    // -- metadata_expected_max_bytes -----------------------------------------

    #[test]
    fn metadata_expected_max_bytes_is_128_kb() {
        assert_eq!(handler().metadata_expected_max_bytes(), 131_072);
    }

    // -- upstream_checksum_metadata_path -------------------------------------

    fn coords_for(name: &str, version: Option<&str>, filename: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: version.map(str::to_string),
            path: format!("simple/{name}/{filename}"),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn upstream_checksum_metadata_path_happy_path() {
        let coords = coords_for("requests", Some("2.31.0"), "requests-2.31.0.tar.gz");
        assert_eq!(
            handler().upstream_checksum_metadata_path(&coords),
            Some("/pypi/requests/2.31.0/json".to_string())
        );
    }

    #[test]
    fn upstream_checksum_metadata_path_normalises_pep503() {
        // Mixed case + underscore must collapse to lowercased + `-` form.
        let coords = ArtifactCoords {
            name: "My_Package".to_string(),
            name_as_published: "My_Package".to_string(),
            version: Some("1.0.0".to_string()),
            path: "simple/My_Package/My_Package-1.0.0.tar.gz".to_string(),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        };
        assert_eq!(
            handler().upstream_checksum_metadata_path(&coords),
            Some("/pypi/my-package/1.0.0/json".to_string())
        );
    }

    #[test]
    fn upstream_checksum_metadata_path_returns_none_when_version_missing() {
        let coords = coords_for("requests", None, "requests-2.31.0.tar.gz");
        assert_eq!(handler().upstream_checksum_metadata_path(&coords), None);
    }

    // -- parse_upstream_checksum ---------------------------------------------

    const REQUESTS_WHEEL_SHA256: &str =
        "58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f";
    const REQUESTS_SDIST_SHA256: &str =
        "942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1";

    #[test]
    fn parse_upstream_checksum_wheel_happy_path() {
        let body = include_bytes!("../tests/fixtures/pypi/requests_2.31.0.json");
        let coords = coords_for(
            "requests",
            Some("2.31.0"),
            "requests-2.31.0-py3-none-any.whl",
        );
        let cs = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(cs.hex(), REQUESTS_WHEEL_SHA256);
    }

    #[test]
    fn parse_upstream_checksum_sdist_happy_path() {
        let body = include_bytes!("../tests/fixtures/pypi/requests_2.31.0.json");
        let coords = coords_for("requests", Some("2.31.0"), "requests-2.31.0.tar.gz");
        let cs = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(cs.hex(), REQUESTS_SDIST_SHA256);
    }

    /// Regression guard: the stored `coords.path` name segment uses the
    /// PEP-503-normalized form (`simple/{normalized}/{filename}`).
    /// `coords.path` is **dual-use**: besides keying the projection, its
    /// BASENAME (`rsplit('/').next()`) is what `parse_upstream_checksum`
    /// matches against the upstream `urls[]` entry to pull `digests.sha256`
    /// — the mandatory upstream-checksum verification (Origin pillar). The
    /// existing happy-path tests use already-canonical names (`requests`),
    /// so they do NOT exercise a path whose name segment was normalized
    /// FROM a raw input. This pins that the normalized `simple/my-package/`
    /// prefix does not perturb the basename match: a raw `My_Package`
    /// builds `simple/my-package/My_Package-1.0.tar.gz` (segment normalized,
    /// filename verbatim) and still resolves the checksum.
    #[test]
    fn parse_upstream_checksum_resolves_through_normalized_prefix_path() {
        const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // The SSOT constructor normalizes the name segment but keeps the
        // filename verbatim.
        let path = handler()
            .build_artifact_logical_path("My_Package", "", Some("My_Package-1.0.tar.gz"))
            .unwrap();
        assert_eq!(path, "simple/my-package/My_Package-1.0.tar.gz");

        let coords = ArtifactCoords {
            name: "my-package".to_string(),
            name_as_published: "My_Package".to_string(),
            version: Some("1.0".to_string()),
            path,
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        };

        let body = format!(
            r#"{{"urls":[{{"filename":"My_Package-1.0.tar.gz","digests":{{"sha256":"{SHA}"}}}}]}}"#
        );
        let cs = handler()
            .parse_upstream_checksum(&mut Cursor::new(body.as_bytes()), &coords)
            .unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(cs.hex(), SHA);
    }

    #[test]
    fn parse_upstream_checksum_md5_only_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/pypi/legacy_md5_only.json");
        let coords = coords_for("legacy", Some("1.0"), "legacy-1.0-py3-none-any.whl");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("does not publish a SHA-256 digest"),
            "unexpected message: {err}"
        );
        assert!(
            err.to_string()
                .contains("SHA-1/MD5 fallback is not accepted"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_empty_urls_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/pypi/empty_urls.json");
        let coords = coords_for("ghost", Some("0.0.1"), "ghost-0.0.1.tar.gz");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        // urls[] is present but empty, so the no-match branch fires.
        assert!(
            err.to_string()
                .contains("does not publish file ghost-0.0.1.tar.gz for ghost@0.0.1"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_malformed_body_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/pypi/malformed.txt");
        let coords = coords_for("anything", Some("1.0"), "anything-1.0.tar.gz");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("not valid JSON"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_missing_urls_key_returns_validation_error() {
        // Synthesised body with no `urls` key at all.
        let body = br#"{"info":{},"releases":{}}"#;
        let coords = coords_for("anything", Some("1.0"), "anything-1.0.tar.gz");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("upstream PyPI response has no urls array"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_urls_not_array_returns_validation_error() {
        // `urls` exists but is not an array — same error as missing.
        let body = br#"{"info":{},"releases":{},"urls":{"not":"an array"}}"#;
        let coords = coords_for("anything", Some("1.0"), "anything-1.0.tar.gz");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("upstream PyPI response has no urls array"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_filename_not_in_urls_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/pypi/requests_2.31.0.json");
        let coords = coords_for("requests", Some("2.31.0"), "nonexistent-2.31.0.whl");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("does not publish file nonexistent-2.31.0.whl for requests@2.31.0"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_wrong_length_sha256_propagates_validation_error() {
        // Synthesised JSON with a too-short sha256 — the constructor of
        // UpstreamPublishedChecksum must reject it.
        let body = br#"{"urls":[{"filename":"x-1.0.tar.gz","digests":{"sha256":"deadbeef"}}]}"#;
        let coords = coords_for("x", Some("1.0"), "x-1.0.tar.gz");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_upstream_checksum_non_hex_sha256_propagates_validation_error() {
        // 64 chars but with non-hex 'g' — checksum constructor must reject.
        let bad = "g".repeat(64);
        let body = format!(
            r#"{{"urls":[{{"filename":"x-1.0.tar.gz","digests":{{"sha256":"{bad}"}}}}]}}"#,
        );
        let coords = coords_for("x", Some("1.0"), "x-1.0.tar.gz");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body.as_bytes()), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_upstream_checksum_empty_path_returns_validation_error() {
        // Defensive: caller bug where coords.path is empty.
        let body = include_bytes!("../tests/fixtures/pypi/requests_2.31.0.json");
        let coords = ArtifactCoords {
            name: "requests".to_string(),
            name_as_published: "requests".to_string(),
            version: Some("2.31.0".to_string()),
            path: String::new(),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        };
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("non-empty path basename"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_uppercase_sha256_normalised() {
        // The constructor of UpstreamPublishedChecksum requires lowercase
        // hex; the parser lowercases incoming sha256 to be defensive
        // against upstream encoding variations.
        let upper = REQUESTS_WHEEL_SHA256.to_ascii_uppercase();
        let body = format!(
            r#"{{"urls":[{{"filename":"requests-2.31.0-py3-none-any.whl","digests":{{"sha256":"{upper}"}}}}]}}"#,
        );
        let coords = coords_for(
            "requests",
            Some("2.31.0"),
            "requests-2.31.0-py3-none-any.whl",
        );
        let cs = handler()
            .parse_upstream_checksum(&mut Cursor::new(body.as_bytes()), &coords)
            .unwrap();
        assert_eq!(cs.hex(), REQUESTS_WHEEL_SHA256);
    }

    #[test]
    fn parse_upstream_checksum_empty_digests_returns_validation_error() {
        // urls[] entry exists, filename matches, but `digests` is empty.
        let body = br#"{"urls":[{"filename":"x-1.0.tar.gz","digests":{}}]}"#;
        let coords = coords_for("x", Some("1.0"), "x-1.0.tar.gz");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("does not publish a SHA-256 digest"),
            "unexpected message: {err}"
        );
    }

    // -- extract_upstream_file_url -------------------------------------------

    /// Cap used by every `extract_upstream_file_url` test. Matches
    /// `PyPiFormatHandler::metadata_expected_max_bytes()`; declared as a
    /// constant so the boundary tests below stay legible. The tests for
    /// the size gate use the live `metadata_expected_max_bytes()` value
    /// to exercise the contract.
    const PYPI_TEST_MAX: usize = 131_072;

    const REQUESTS_WHEEL_URL: &str = "https://files.pythonhosted.org/packages/70/8e/0e2d847013cb52cd35b38c009bb167a1a26b2ce6cd6965bf26b47bc0bf44/requests-2.31.0-py3-none-any.whl";
    const REQUESTS_SDIST_URL: &str = "https://files.pythonhosted.org/packages/9d/be/10918a2eac4ae9f02f6cfe6414b7a155ccd8f7f9d4380d62fd5b955065c3/requests-2.31.0.tar.gz";

    #[test]
    fn extract_upstream_file_url_wheel_happy_path() {
        let body = include_bytes!("../tests/fixtures/pypi/requests_2.31.0.json");
        let url =
            extract_upstream_file_url(body, "requests-2.31.0-py3-none-any.whl", PYPI_TEST_MAX)
                .unwrap();
        assert_eq!(url, REQUESTS_WHEEL_URL);
    }

    #[test]
    fn extract_upstream_file_url_sdist_happy_path() {
        let body = include_bytes!("../tests/fixtures/pypi/requests_2.31.0.json");
        let url = extract_upstream_file_url(body, "requests-2.31.0.tar.gz", PYPI_TEST_MAX).unwrap();
        assert_eq!(url, REQUESTS_SDIST_URL);
    }

    #[test]
    fn extract_upstream_file_url_non_https_url_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/pypi/non_https_url.json");
        let err = extract_upstream_file_url(body, "shady-1.0-py3-none-any.whl", PYPI_TEST_MAX)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("non-https"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_file_url_filename_not_in_urls_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/pypi/requests_2.31.0.json");
        let err = extract_upstream_file_url(body, "nonexistent.whl", PYPI_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("does not publish file nonexistent.whl"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_file_url_malformed_body_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/pypi/malformed.txt");
        let err =
            extract_upstream_file_url(body, "anything-1.0.tar.gz", PYPI_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("not valid JSON"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_file_url_empty_urls_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/pypi/empty_urls.json");
        let err = extract_upstream_file_url(body, "ghost-0.0.1.tar.gz", PYPI_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        // urls[] is present but empty, so the no-match branch fires.
        assert!(
            err.to_string()
                .contains("does not publish file ghost-0.0.1.tar.gz"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_file_url_missing_urls_key_returns_validation_error() {
        // Synthesised body with no `urls` key at all.
        let body = br#"{"info":{},"releases":{}}"#;
        let err =
            extract_upstream_file_url(body, "anything-1.0.tar.gz", PYPI_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("upstream PyPI response has no urls array"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_file_url_urls_not_array_returns_validation_error() {
        // `urls` exists but is not an array — same error as missing.
        let body = br#"{"urls":{"not":"an array"}}"#;
        let err =
            extract_upstream_file_url(body, "anything-1.0.tar.gz", PYPI_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string()
                .contains("upstream PyPI response has no urls array"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_file_url_entry_missing_url_field_returns_validation_error() {
        // urls[] entry matches the filename but has no `url` field at all.
        let body = br#"{"urls":[{"filename":"x-1.0.tar.gz"}]}"#;
        let err = extract_upstream_file_url(body, "x-1.0.tar.gz", PYPI_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("missing a string url field"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_file_url_url_not_string_returns_validation_error() {
        // url present but not a string (e.g. a number).
        let body = br#"{"urls":[{"filename":"x-1.0.tar.gz","url":42}]}"#;
        let err = extract_upstream_file_url(body, "x-1.0.tar.gz", PYPI_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("missing a string url field"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_file_url_http_scheme_explicitly_rejected() {
        // Distinct from the file-fixture test: confirm http:// specifically
        // hits the non-https branch (regression guard against accidentally
        // accepting http via a typo like `http`).
        let body =
            br#"{"urls":[{"filename":"x-1.0.tar.gz","url":"http://example.com/x-1.0.tar.gz"}]}"#;
        let err = extract_upstream_file_url(body, "x-1.0.tar.gz", PYPI_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("non-https"),
            "unexpected message: {err}"
        );
    }

    // -- pre-parse size cap ---------------------------------------------------
    //
    // Defence in depth above the fetch-streaming cap. The parse path must
    // refuse a body larger than the per-format `metadata_expected_max_bytes()`
    // ceiling BEFORE handing it to serde_json. The pair (size cap +
    // serde_json's default recursion limit of 128) bounds both INPUT SIZE and
    // PARSE-TREE DEPTH.

    /// Build a valid PyPI per-version JSON body padded to exactly
    /// `target_len` bytes by inserting whitespace inside the document.
    /// Whitespace between JSON tokens is legal per RFC 8259 §2 — the
    /// padded body must still parse.
    fn pypi_padded_body(filename: &str, target_len: usize) -> Vec<u8> {
        // 64-hex sha256 (deterministic — content does not matter).
        let sha = "a".repeat(64);
        let core = format!(
            r#"{{"urls":[{{"filename":"{filename}","digests":{{"sha256":"{sha}"}},"url":"https://example.com/{filename}"}}]}}"#
        );
        assert!(
            core.len() <= target_len,
            "core body ({} bytes) exceeds target ({})",
            core.len(),
            target_len
        );
        let mut out = Vec::with_capacity(target_len);
        // Insert padding whitespace right after the leading `{`. JSON
        // permits whitespace between any pair of structural tokens, so
        // a space after `{` is well-formed.
        out.push(b'{');
        let pad = target_len - core.len();
        out.extend(std::iter::repeat_n(b' ', pad));
        out.extend_from_slice(&core.as_bytes()[1..]);
        debug_assert_eq!(out.len(), target_len);
        out
    }

    #[test]
    fn parse_upstream_checksum_rejects_body_one_byte_over_cap() {
        // Cap is the dedicated per-version-JSON bound, NOT
        // `metadata_expected_max_bytes`.
        let max = PYPI_VERSION_JSON_MAX_BYTES as usize;
        let body = pypi_padded_body("x-1.0.tar.gz", max + 1);
        let coords = coords_for("x", Some("1.0"), "x-1.0.tar.gz");
        let err = handler()
            .parse_upstream_checksum(&mut Cursor::new(&body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("upstream metadata body is")
                && msg.contains(&(max + 1).to_string())
                && msg.contains(&max.to_string())
                && msg.contains("pypi version-json max is"),
            "size diagnostic missing: {msg}"
        );
    }

    #[test]
    fn parse_upstream_checksum_accepts_body_at_cap_boundary() {
        // Body sized exactly at the cap parses normally — the size gate
        // must use `>` not `>=` so the boundary admits.
        let max = PYPI_VERSION_JSON_MAX_BYTES as usize;
        let body = pypi_padded_body("x-1.0.tar.gz", max);
        let coords = coords_for("x", Some("1.0"), "x-1.0.tar.gz");
        let cs = handler()
            .parse_upstream_checksum(&mut Cursor::new(&body), &coords)
            .expect("at-cap body must parse");
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha256);
    }

    #[test]
    fn extract_upstream_file_url_rejects_body_one_byte_over_cap() {
        // The free function gains an explicit `max_bytes` parameter
        // because it has no `&self` to read from the handler.
        let max = PyPiFormatHandler.metadata_expected_max_bytes();
        let body = pypi_padded_body("x-1.0.tar.gz", max + 1);
        let err = extract_upstream_file_url(&body, "x-1.0.tar.gz", max).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("upstream metadata body is")
                && msg.contains(&(max + 1).to_string())
                && msg.contains(&max.to_string())
                && msg.contains("per-format max is"),
            "size diagnostic missing: {msg}"
        );
    }

    #[test]
    fn extract_upstream_file_url_accepts_body_at_cap_boundary() {
        let max = PyPiFormatHandler.metadata_expected_max_bytes();
        let body = pypi_padded_body("x-1.0.tar.gz", max);
        let url =
            extract_upstream_file_url(&body, "x-1.0.tar.gz", max).expect("at-cap body must parse");
        assert_eq!(url, "https://example.com/x-1.0.tar.gz");
    }

    // -- extract_sbom ---------------------------------------------------------

    use hort_domain::types::{Ecosystem, PayloadAccess};

    fn sbom_coords(name: &str, version: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: Some(version.to_string()),
            path: format!("simple/{name}/{name}-{version}.tar.gz"),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn extract_sbom_pypi_happy_path_with_info_wrapper() {
        // PyPI's per-release JSON has the `info.requires_dist` shape.
        let metadata = serde_json::json!({
            "info": {
                "name": "myapp",
                "version": "1.0.0",
                "license": "MIT",
                "requires_dist": [
                    "requests (==2.31.0)",
                    "click >=8.0",
                ],
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");

        assert_eq!(sbom.components.len(), 2);
        let requests = sbom
            .components
            .iter()
            .find(|c| c.name == "requests")
            .expect("requests present");
        assert_eq!(requests.purl, "pkg:pypi/requests@2.31.0");
        assert_eq!(requests.version.as_deref(), Some("2.31.0"));
        assert_eq!(requests.ecosystem, Ecosystem::PyPI);
        assert!(requests.direct_dependency);
        assert_eq!(requests.licenses, vec!["MIT".to_string()]);

        // Non-`==` constraint → version is None
        let click = sbom
            .components
            .iter()
            .find(|c| c.name == "click")
            .expect("click present");
        assert!(click.version.is_none());
        assert_eq!(click.purl, "pkg:pypi/click");
    }

    #[test]
    fn extract_sbom_pypi_happy_path_without_info_wrapper() {
        // Some shapes carry `requires_dist` at the top level (single-version slice).
        let metadata = serde_json::json!({
            "name": "myapp",
            "license": "Apache-2.0",
            "requires_dist": [
                "urllib3 (==1.26.0)",
            ],
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        // No info wrapper → license currently unavailable; OK.
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "urllib3");
        assert_eq!(sbom.components[0].purl, "pkg:pypi/urllib3@1.26.0");
    }

    #[test]
    fn extract_sbom_pypi_environment_marker_is_stripped() {
        // PEP 508 env markers are dropped from the canonical name+version.
        let metadata = serde_json::json!({
            "info": {
                "requires_dist": [
                    "importlib-metadata (==4.0.0); python_version >= '3.8'",
                ],
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert_eq!(sbom.components.len(), 1);
        let comp = &sbom.components[0];
        // PEP 503 normalisation is applied to the name in the PURL.
        assert_eq!(comp.name, "importlib-metadata");
        assert_eq!(comp.purl, "pkg:pypi/importlib-metadata@4.0.0");
        assert_eq!(comp.version.as_deref(), Some("4.0.0"));
    }

    #[test]
    fn extract_sbom_pypi_extras_are_stripped() {
        // PEP 508 extras (`name [extras] (==1.0)`) are dropped from name.
        let metadata = serde_json::json!({
            "info": {
                "requires_dist": [
                    "requests[security] (==2.31.0)",
                ],
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "requests");
        assert_eq!(sbom.components[0].purl, "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn extract_sbom_pypi_normalises_pep503_name_in_purl() {
        // PEP 503 §4: `Foo_Bar.baz` normalises to `foo-bar-baz`.
        let metadata = serde_json::json!({
            "info": {
                "requires_dist": [
                    "Foo_Bar.baz (==1.0)",
                ],
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "foo-bar-baz");
        assert_eq!(sbom.components[0].purl, "pkg:pypi/foo-bar-baz@1.0");
    }

    #[test]
    fn extract_sbom_pypi_empty_requires_dist_returns_some_empty() {
        let metadata = serde_json::json!({
            "info": { "requires_dist": [] },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn extract_sbom_pypi_no_requires_dist_returns_some_empty() {
        // Manifest exists but has no requires_dist key.
        let metadata = serde_json::json!({ "info": { "name": "myapp" } });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn extract_sbom_pypi_null_metadata_returns_some_empty() {
        let metadata = serde_json::Value::Null;
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert!(sbom.components.is_empty());
    }

    /// Leaf PyPI package: subject is populated from coords even when the
    /// wheel has no declared dependencies.
    #[test]
    fn extract_sbom_pypi_leaf_package_populates_subject_from_coords() {
        let metadata = serde_json::json!({
            "info": {
                "license": "MIT",
                "requires_dist": [],
            },
        });
        let coords = sbom_coords("requests", "2.31.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");

        let subject = sbom.subject.as_ref().expect("subject must be populated");
        assert_eq!(subject.purl, "pkg:pypi/requests@2.31.0");
        assert_eq!(subject.name, "requests");
        assert_eq!(subject.ecosystem, Ecosystem::PyPI);
        assert!(sbom.components.is_empty());
    }

    /// Subject is populated even when no `requires_dist` field is
    /// present, and when the manifest itself is null.
    #[test]
    fn extract_sbom_pypi_null_metadata_still_populates_subject_from_coords() {
        let coords = sbom_coords("requests", "2.31.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &serde_json::Value::Null, payload)
            .expect("Some")
            .expect("Some");
        let subject = sbom
            .subject
            .as_ref()
            .expect("subject must be populated even when metadata is Null");
        assert_eq!(subject.purl, "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn extract_sbom_pypi_license_from_classifier_is_extracted() {
        // When `info.license` is empty, fall back to PEP 639-style
        // `License ::` classifiers.
        let metadata = serde_json::json!({
            "info": {
                "license": "",
                "classifiers": [
                    "Development Status :: 4 - Beta",
                    "License :: OSI Approved :: BSD License",
                ],
                "requires_dist": ["foo (==1.0)"],
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = PyPiFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert!(
            sbom.components[0]
                .licenses
                .iter()
                .any(|l| l.contains("BSD License")),
            "license classifier not surfaced: {:?}",
            sbom.components[0].licenses
        );
    }

    // -- upstream_metadata_path + upstream_metadata_accept -------------------

    #[test]
    fn upstream_metadata_path_pypi_uses_pep503_simple_index_normalised() {
        // PyPI is the format where the metadata-index path
        // (/simple/<name>/) differs structurally from
        // `upstream_checksum_metadata_path` (/pypi/<name>/<version>/json,
        // per-version). PEP 503 §"Normalized name" — punctuation and
        // case collapse before lookup.
        let handler = handler();
        // Lower-case unchanged.
        assert_eq!(
            handler.upstream_metadata_path("requests"),
            Some("/simple/requests/".to_string()),
        );
        // Mixed case normalises to lower.
        assert_eq!(
            handler.upstream_metadata_path("Requests"),
            Some("/simple/requests/".to_string()),
        );
        // Underscore + dash + dot collapse to a single dash per
        // `PyPiFormatHandler::normalize_name` (PEP 503).
        assert_eq!(
            handler.upstream_metadata_path("zope.interface"),
            Some("/simple/zope-interface/".to_string()),
        );
    }

    #[test]
    fn upstream_metadata_accept_pypi_negotiates_pep691_json_first() {
        // PEP 691 content negotiation — JSON preferred, HTML fallback.
        // The order matters: pypi.org and modern mirrors honour
        // Accept-quality preference; emitting JSON first means a
        // cached JSON response always wins over a cached HTML one.
        let accept = handler().upstream_metadata_accept();
        assert!(
            accept
                .iter()
                .any(|a| a.contains("application/vnd.pypi.simple") && a.contains("+json")),
            "PEP 691 JSON Accept must be present; got {accept:?}"
        );
        assert!(
            accept.iter().any(|a| a.contains("text/html")),
            "text/html fallback must be present; got {accept:?}"
        );
        // JSON listed before HTML — the order is load-bearing for
        // quality-value-based selection by some upstreams.
        let json_pos = accept.iter().position(|a| a.contains("+json")).unwrap();
        let html_pos = accept.iter().position(|a| a.contains("text/html")).unwrap();
        assert!(
            json_pos < html_pos,
            "JSON Accept must precede HTML fallback; got {accept:?}"
        );
    }

    // -- extract_upstream_versions -------------------------------------------

    #[test]
    fn extract_upstream_versions_pypi_html_walks_anchors_and_extracts_filename_versions() {
        // Realistic PEP 503 fragment. Anchor text doesn't matter; the
        // walker only consumes the `href=` attribute value.
        let body = br#"<!DOCTYPE html>
<html><body>
<a href="/packages/source/r/requests/requests-2.31.0.tar.gz#sha256=abc">requests-2.31.0.tar.gz</a>
<a href="/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl">requests-2.31.0-py3-none-any.whl</a>
<a href="/packages/source/r/requests/requests-2.32.0.tar.gz">requests-2.32.0.tar.gz</a>
</body></html>"#;
        let vs = handler()
            .extract_upstream_versions(&mut Cursor::new(body))
            .expect("Ok");
        // Note: the wheel + sdist for 2.31.0 each yield one entry —
        // the planner dedups via its `seen_upstream` HashMap; the
        // extractor does NOT dedup at this layer.
        assert!(vs.contains(&"2.31.0".to_string()));
        assert!(vs.contains(&"2.32.0".to_string()));
        assert_eq!(vs.iter().filter(|v| *v == "2.31.0").count(), 2);
    }

    #[test]
    fn extract_upstream_versions_pypi_html_handles_single_quotes_and_case() {
        // Mixed-case `HREF`, single-quote attribute value — both
        // accepted (PEP 503 says nothing about which the upstream
        // uses).
        let body = br#"<a HREF='/packages/x/example-1.0.tar.gz'>example-1.0.tar.gz</a>"#;
        let vs = handler()
            .extract_upstream_versions(&mut Cursor::new(body))
            .expect("Ok");
        assert_eq!(vs, vec!["1.0".to_string()]);
    }

    #[test]
    fn extract_upstream_versions_pypi_html_strips_query_string_from_href() {
        // `#sha256=…` fragment + `?token=…` query both stripped before
        // basename extraction (mirrors the simple-index helper).
        let body = br#"<a href="/x/foo-1.2.tar.gz?download=1#sha256=ab">foo-1.2.tar.gz</a>"#;
        let vs = handler()
            .extract_upstream_versions(&mut Cursor::new(body))
            .expect("Ok");
        assert_eq!(vs, vec!["1.2".to_string()]);
    }

    #[test]
    fn extract_upstream_versions_pypi_html_skips_unrecognised_suffix() {
        // `.rar` is not a PyPI distribution suffix; the filename
        // helper returns None and the entry is dropped.
        let body = br#"<a href="x/foo-1.0.rar">foo-1.0.rar</a>"#;
        let vs = handler()
            .extract_upstream_versions(&mut Cursor::new(body))
            .expect("Ok");
        assert!(vs.is_empty());
    }

    #[test]
    fn extract_upstream_versions_pypi_json_pep691_reads_versions_array() {
        let body = br#"{
            "name": "requests",
            "files": [],
            "versions": ["2.31.0", "2.32.0", "3.0.0"]
        }"#;
        let vs = handler()
            .extract_upstream_versions(&mut Cursor::new(body))
            .expect("Ok");
        assert_eq!(
            vs,
            vec![
                "2.31.0".to_string(),
                "2.32.0".to_string(),
                "3.0.0".to_string()
            ]
        );
    }

    #[test]
    fn extract_upstream_versions_pypi_json_fallback_to_files_filename() {
        // PEP 691 body with no `versions[]` but well-formed `files[]`
        // — the walker derives a version from each filename.
        let body = br#"{
            "name": "foo",
            "files": [
                {"filename": "foo-1.0.tar.gz", "url": "https://x/foo-1.0.tar.gz"},
                {"filename": "foo-2.0-py3-none-any.whl", "url": "https://x/foo-2.0.whl"}
            ]
        }"#;
        let vs = handler()
            .extract_upstream_versions(&mut Cursor::new(body))
            .expect("Ok");
        assert!(vs.contains(&"1.0".to_string()));
        assert!(vs.contains(&"2.0".to_string()));
    }

    #[test]
    fn extract_upstream_versions_pypi_invalid_utf8_returns_empty_vec() {
        // Degrade-open: a body that's neither valid JSON nor valid
        // UTF-8 yields an empty vec, not an error.
        let body = &[0xffu8, 0xfe, 0xfd, 0x00, 0xab];
        let vs = handler()
            .extract_upstream_versions(&mut Cursor::new(body))
            .expect("Ok");
        assert!(vs.is_empty());
    }

    #[test]
    fn extract_upstream_versions_pypi_over_cap_returns_validation_error() {
        // 10 MiB cap declared inside the impl; any body above
        // 10 * 1024 * 1024 bytes is rejected.
        let body = vec![b'a'; 10 * 1024 * 1024 + 1];
        let err = handler()
            .extract_upstream_versions(&mut Cursor::new(&body))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- extract_wheel_metadata_bytes ----------------------------------------

    // Wheel-ZIP fixtures live in the crate-shared
    // `test_support::build_wheel_zip` helper (gated by the same
    // `test-support` feature `archive_bounds::build_zip_bytes` is)
    // so the cross-crate consumer (`hort-http-pypi`'s `.metadata`
    // cache-miss tests) can reuse the same construction without taking
    // a direct `zip` dep.
    use crate::test_support::build_wheel_zip;

    /// Canonical METADATA body shape — RFC 5322-style headers with a
    /// `Metadata-Version` first line (PEP 566 §3). The "starts with
    /// `Metadata-Version:`" assertion in the happy-path test is the
    /// load-bearing PEP 658 wire-format check.
    fn sample_metadata_body() -> &'static [u8] {
        b"Metadata-Version: 2.1\n\
          Name: example\n\
          Version: 1.0.0\n\
          Summary: example package for PEP 658\n\
          Requires-Python: >=3.8\n\
          Requires-Dist: requests (>=2.25)\n\
          \n\
          Long description body\n"
    }

    #[test]
    fn extract_wheel_metadata_bytes_pypi_wheel_with_metadata_returns_bytes() {
        // Happy path: a wheel ZIP carrying the canonical
        // `<pkg>-<version>.dist-info/METADATA` entry returns the bytes
        // verbatim, starting with `Metadata-Version:` per PEP 566 §3.
        let zip_bytes = build_wheel_zip(&[
            ("example-1.0.0.dist-info/METADATA", sample_metadata_body()),
            ("example-1.0.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            ("example/__init__.py", b""),
        ]);
        let coords = coords_for("example", Some("1.0.0"), "example-1.0.0-py3-none-any.whl");
        let payload = PayloadAccess::Bytes(&zip_bytes);
        let out = handler()
            .extract_wheel_metadata_bytes(&coords, payload)
            .expect("Ok")
            .expect("Some");
        assert!(
            out.starts_with(b"Metadata-Version:"),
            "PEP 566 METADATA must begin with `Metadata-Version:` — got {:?}",
            std::str::from_utf8(&out[..20.min(out.len())]).unwrap_or("<non-utf8>"),
        );
        assert_eq!(out.as_ref(), sample_metadata_body());
    }

    #[test]
    fn extract_wheel_metadata_bytes_pypi_sdist_returns_none() {
        // PEP 658 applies only to wheels. A `.tar.gz` sdist path
        // short-circuits at the `.whl` suffix check — no ZIP open
        // attempted, even if the payload bytes happen to be a valid ZIP.
        let coords = coords_for("example", Some("1.0.0"), "example-1.0.0.tar.gz");
        let payload = PayloadAccess::Bytes(b"PK\x03\x04any zip-shaped bytes");
        let out = handler()
            .extract_wheel_metadata_bytes(&coords, payload)
            .expect("Ok");
        assert!(out.is_none());
    }

    #[test]
    fn extract_wheel_metadata_bytes_pypi_wheel_without_metadata_member_returns_none() {
        // Malformed wheel: a valid ZIP that does not carry a
        // `*.dist-info/METADATA` entry. Non-fatal — the wheel ingest
        // already succeeded; PEP 658 simply does not advertise for
        // this artifact.
        let zip_bytes = build_wheel_zip(&[("example/__init__.py", b""), ("README.txt", b"hi")]);
        let coords = coords_for("example", Some("1.0.0"), "example-1.0.0-py3-none-any.whl");
        let payload = PayloadAccess::Bytes(&zip_bytes);
        let out = handler()
            .extract_wheel_metadata_bytes(&coords, payload)
            .expect("Ok");
        assert!(
            out.is_none(),
            "wheel without METADATA member must be non-fatal Ok(None)"
        );
    }

    #[test]
    fn extract_wheel_metadata_bytes_pypi_oversized_metadata_returns_validation_error() {
        // A wheel METADATA entry whose uncompressed size exceeds
        // PYPI_WHEEL_METADATA_MAX_BYTES (1 MiB) is rejected on the
        // header — checked BEFORE the read, so a header-claimed multi-
        // GB entry is refused without OOM.
        let oversized = vec![b'A'; 1024 * 1024 + 1];
        let zip_bytes =
            build_wheel_zip(&[("example-1.0.0.dist-info/METADATA", oversized.as_slice())]);
        let coords = coords_for("example", Some("1.0.0"), "example-1.0.0-py3-none-any.whl");
        let payload = PayloadAccess::Bytes(&zip_bytes);
        let err = handler()
            .extract_wheel_metadata_bytes(&coords, payload)
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(_)),
            "oversized METADATA must surface as Validation, got: {err:?}",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("METADATA") && msg.contains("cap"),
            "size diagnostic missing: {msg}",
        );
    }

    #[test]
    fn extract_wheel_metadata_bytes_pypi_corrupt_zip_returns_none() {
        // A `.whl` path with bytes that are not a valid ZIP archive
        // (e.g. truncated, garbage, non-PK header) must be non-fatal —
        // the wheel ingest already succeeded by primary-content hash
        // verification; PEP 658 simply does not advertise. Returning
        // `Err` here would bring down the ingest request.
        let coords = coords_for("example", Some("1.0.0"), "example-1.0.0-py3-none-any.whl");
        let payload = PayloadAccess::Bytes(b"not a zip at all");
        let out = handler()
            .extract_wheel_metadata_bytes(&coords, payload)
            .expect("Ok");
        assert!(
            out.is_none(),
            "corrupt-ZIP wheel must be non-fatal Ok(None)"
        );
    }

    #[test]
    fn extract_wheel_metadata_bytes_pypi_multiple_metadata_entries_picks_first() {
        // Malformed wheel with two `*.dist-info/METADATA` entries (the
        // wheel spec mandates exactly one). The implementation picks
        // the FIRST matching entry and logs a `debug!` — does NOT
        // error. Mirrors pip's first-match-wins behaviour.
        let first_body = b"Metadata-Version: 2.1\nName: first\nVersion: 1.0.0\n" as &[u8];
        let second_body = b"Metadata-Version: 2.1\nName: second\nVersion: 2.0.0\n" as &[u8];
        let zip_bytes = build_wheel_zip(&[
            ("first-1.0.0.dist-info/METADATA", first_body),
            ("second-2.0.0.dist-info/METADATA", second_body),
        ]);
        let coords = coords_for("first", Some("1.0.0"), "first-1.0.0-py3-none-any.whl");
        let payload = PayloadAccess::Bytes(&zip_bytes);
        let out = handler()
            .extract_wheel_metadata_bytes(&coords, payload)
            .expect("Ok")
            .expect("Some");
        assert_eq!(
            out.as_ref(),
            first_body,
            "multi-dist-info wheel must pick the FIRST METADATA entry",
        );
    }

    #[test]
    fn extract_wheel_metadata_bytes_pypi_read_stream_payload_is_supported() {
        // `PayloadAccess::ReadStream` is the streaming-input variant.
        // The implementation slurps it into memory (ZIP parsing needs
        // Read + Seek); a stream that errors on read is non-fatal.
        let zip_bytes =
            build_wheel_zip(&[("example-1.0.0.dist-info/METADATA", sample_metadata_body())]);
        let coords = coords_for("example", Some("1.0.0"), "example-1.0.0-py3-none-any.whl");
        let stream: Box<dyn Read + Send + '_> = Box::new(zip_bytes.as_slice());
        let payload = PayloadAccess::ReadStream(stream);
        let out = handler()
            .extract_wheel_metadata_bytes(&coords, payload)
            .expect("Ok")
            .expect("Some");
        assert_eq!(out.as_ref(), sample_metadata_body());
    }

    #[test]
    fn extract_wheel_metadata_bytes_pypi_metadata_at_cap_boundary_is_accepted() {
        // Boundary regression: an entry exactly at the cap (1 MiB)
        // must be accepted; the size gate uses `>` not `>=` so the
        // boundary admits. Without this guard a future "fix" tightening
        // to `>=` would silently reject a legitimate 1 MiB entry.
        let exactly_at_cap = vec![b'M'; 1024 * 1024];
        let zip_bytes = build_wheel_zip(&[(
            "example-1.0.0.dist-info/METADATA",
            exactly_at_cap.as_slice(),
        )]);
        let coords = coords_for("example", Some("1.0.0"), "example-1.0.0-py3-none-any.whl");
        let payload = PayloadAccess::Bytes(&zip_bytes);
        let out = handler()
            .extract_wheel_metadata_bytes(&coords, payload)
            .expect("Ok")
            .expect("Some");
        assert_eq!(out.len(), 1024 * 1024);
    }

    #[test]
    fn is_wheel_metadata_path_recognises_canonical_layout() {
        // PEP 427 §A — `<pkg>-<version>.dist-info/METADATA` at the
        // archive root. Recognised forms:
        assert!(is_wheel_metadata_path("example-1.0.0.dist-info/METADATA"));
        assert!(is_wheel_metadata_path(
            "complex_name-2.0.0rc1.dist-info/METADATA"
        ));
    }

    #[test]
    fn is_wheel_metadata_path_rejects_deeper_nesting_and_lookalikes() {
        // Not the wheel METADATA — must NOT match:
        assert!(!is_wheel_metadata_path("subdir/foo.dist-info/METADATA"));
        assert!(!is_wheel_metadata_path("METADATA"));
        assert!(!is_wheel_metadata_path("example.dist-info/OTHER"));
        assert!(!is_wheel_metadata_path("example/METADATA"));
        assert!(!is_wheel_metadata_path(
            "example-1.0.0.dist-info/sub/METADATA"
        ));
    }

    // -- parse_wheel_metadata_into_specs (private parser) ------------------
    //
    // These test the pure `Requires-Dist` METADATA-text parse logic DIRECTLY
    // against the factored-out private fn (METADATA bytes in, specs out). They
    // do NOT exercise the archive/magic-sniff layer — that is covered by the
    // `_from_wheel_zip` / `_sdist_gzip` / `_unknown_magic` archive-shape tests
    // below. The split mirrors the npm
    // `parse_npm_runtime_dependencies`-vs-`_from_tgz` test split.

    /// Real-shape wheel `METADATA` fragment with a mix of runtime
    /// deps, platform-marker deps, and extras-gated deps. The
    /// runtime-vs-extras boundary is the load-bearing assertion:
    /// extras-gated lines MUST drop out, plain-marker lines stay.
    /// Modelled on a trimmed-down `requests-2.31.0` METADATA.
    #[test]
    fn parse_wheel_metadata_drops_extras_keeps_runtime_and_plain_markers() {
        let body = b"Metadata-Version: 2.1\n\
Name: requests\n\
Version: 2.31.0\n\
Summary: Python HTTP for Humans.\n\
License: Apache 2.0\n\
Requires-Python: >=3.7\n\
Requires-Dist: charset-normalizer (<4,>=2)\n\
Requires-Dist: idna (<4,>=2.5)\n\
Requires-Dist: urllib3 (<3,>=1.21.1)\n\
Requires-Dist: certifi (>=2017.4.17)\n\
Requires-Dist: PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'\n\
Requires-Dist: chardet (<6,>=3.0.2) ; extra == 'use_chardet_on_py3'\n\
Requires-Dist: pytest ; extra == 'test'\n\
Requires-Dist: typing_extensions ; python_version < \"3.8\"\n\
\n\
This is the long description body that follows the blank line.\n\
It MUST NOT be parsed for Requires-Dist.\n\
Requires-Dist: not-real (>=1.0)\n";

        let specs = parse_wheel_metadata_into_specs(body).expect("Ok");
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();

        // Runtime + plain-marker deps survive.
        for expected in &[
            "charset-normalizer",
            "idna",
            "urllib3",
            "certifi",
            "typing_extensions",
        ] {
            assert!(
                names.contains(expected),
                "missing runtime dep {expected}: {names:?}"
            );
        }
        // Extras-gated deps drop out.
        for forbidden in &["PySocks", "chardet", "pytest"] {
            assert!(
                !names.contains(forbidden),
                "extras-gated dep {forbidden} leaked into specs: {names:?}"
            );
        }
        // The post-blank-line "Requires-Dist:" line in the description
        // body MUST NOT be picked up.
        assert!(
            !names.contains(&"not-real"),
            "description-body Requires-Dist line leaked: {names:?}"
        );

        // Ranges are preserved verbatim (the parenthesised specifier
        // form) so `resolve_range_max` gets the original grammar.
        let charset = specs
            .iter()
            .find(|s| s.name == "charset-normalizer")
            .expect("charset-normalizer present");
        assert_eq!(charset.range, "<4,>=2");
    }

    #[test]
    fn parse_wheel_metadata_inline_specifier_form() {
        // The legacy comma-less form `name>=1.0` (no parens) — pip
        // emits this for old-style metadata. Range still round-trips.
        let body = b"Metadata-Version: 2.1\n\
Name: legacy\n\
Requires-Dist: foo>=1.0\n\
Requires-Dist: bar==2.3\n\
\n";
        let specs = parse_wheel_metadata_into_specs(body).expect("Ok");
        assert_eq!(specs.len(), 2);
        let map: std::collections::HashMap<&str, &str> = specs
            .iter()
            .map(|s| (s.name.as_str(), s.range.as_str()))
            .collect();
        assert_eq!(map.get("foo"), Some(&">=1.0"));
        assert_eq!(map.get("bar"), Some(&"==2.3"));
    }

    #[test]
    fn parse_wheel_metadata_no_requires_dist_is_empty_vec() {
        // A leaf wheel — no declared deps. NOT an error.
        let body = b"Metadata-Version: 2.1\n\
Name: leaf\n\
Version: 1.0.0\n\
\n";
        let specs = parse_wheel_metadata_into_specs(body).expect("Ok");
        assert!(specs.is_empty());
    }

    #[test]
    fn parse_wheel_metadata_invalid_utf8_returns_validation_error() {
        // METADATA must be UTF-8 per PEP 566 §3. Invalid bytes are a
        // genuine structural error.
        let body = b"Metadata-Version: 2.1\nName: bad\n\xff\xfe";
        let err = parse_wheel_metadata_into_specs(body).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_wheel_metadata_over_cap_returns_validation_error() {
        // The parser-input cap is the canonical wheel-METADATA bound (1 MiB),
        // the SAME cap `extract_wheel_metadata_bytes` uses for this identical
        // content — NOT `metadata_expected_max_bytes`. A blank-header body one
        // byte over the cap is rejected.
        let max = PYPI_WHEEL_METADATA_MAX_BYTES as usize;
        let body = vec![b' '; max + 1];
        let err = parse_wheel_metadata_into_specs(&body).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("wheel METADATA max is") && msg.contains(&max.to_string()),
            "size diagnostic missing: {msg}"
        );
    }

    #[test]
    fn parse_wheel_metadata_at_cap_boundary_is_accepted() {
        // A body sized exactly at the wheel-METADATA cap parses (gate is
        // `>`, not `>=`). An all-space body has no blank line and no
        // `Requires-Dist:` header, so it yields zero deps.
        let max = PYPI_WHEEL_METADATA_MAX_BYTES as usize;
        let body = vec![b' '; max];
        let out = parse_wheel_metadata_into_specs(&body).expect("at-cap body must parse");
        assert!(out.is_empty());
    }

    #[test]
    fn parse_wheel_metadata_requirement_with_no_version_keeps_empty_range() {
        // `Requires-Dist: foo` — no specifier at all. The cascade
        // sees an empty range and `resolve_range_max("")` → None.
        let body = b"Metadata-Version: 2.1\n\
Name: pkg\n\
Requires-Dist: foo\n\
\n";
        let specs = parse_wheel_metadata_into_specs(body).expect("Ok");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "foo");
        assert_eq!(specs[0].range, "");
    }

    #[test]
    fn parse_wheel_metadata_requirement_with_extras_strips_extras() {
        // `name[extras]` — the extras list is dropped (we ingest the
        // BASE dep). PEP 508 extras are about installing the base
        // package with optional features, not about declaring
        // additional deps.
        let body = b"Metadata-Version: 2.1\n\
Name: pkg\n\
Requires-Dist: requests[socks] (>=2.31)\n\
\n";
        let specs = parse_wheel_metadata_into_specs(body).expect("Ok");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "requests");
        assert_eq!(specs[0].range, ">=2.31");
    }

    // -- resolve_range_max ---------------------------------------------------

    #[test]
    fn resolve_range_max_pypi_compatible_release_picks_highest() {
        let avail = ["1.3.0", "1.4.0", "1.4.5", "1.5.0", "2.0.0"];
        let out = handler().resolve_range_max("~=1.4", &avail).expect("Ok");
        assert_eq!(out.as_deref(), Some("1.5.0"));
    }

    #[test]
    fn resolve_range_max_pypi_compound_range() {
        let avail = ["1.0.0", "1.5.0", "1.9.0", "2.0.0"];
        let out = handler()
            .resolve_range_max(">=1.0,<2.0", &avail)
            .expect("Ok");
        assert_eq!(out.as_deref(), Some("1.9.0"));
    }

    #[test]
    fn resolve_range_max_pypi_no_match_returns_none() {
        let avail = ["1.0.0", "1.1.0"];
        assert_eq!(
            handler().resolve_range_max(">=2", &avail).expect("Ok"),
            None
        );
    }

    #[test]
    fn resolve_range_max_pypi_unparseable_range_returns_none() {
        let avail = ["1.0.0"];
        assert_eq!(
            handler()
                .resolve_range_max("<<not a specifier>>", &avail)
                .expect("Ok"),
            None
        );
    }

    #[test]
    fn resolve_range_max_pypi_empty_available_returns_none() {
        assert_eq!(handler().resolve_range_max(">=1", &[]).expect("Ok"), None);
    }

    #[test]
    fn resolve_range_max_pypi_prereleases_excluded_by_default() {
        // `>=1.0` does NOT explicitly admit pre-releases — final 1.5.0
        // wins over the alpha. Matches pip's default behaviour.
        let avail = ["1.0.0", "2.0.0a1", "1.5.0"];
        let out = handler().resolve_range_max(">=1.0", &avail).expect("Ok");
        assert_eq!(out.as_deref(), Some("1.5.0"));
    }

    // -- build_pull_url ------------------------------------------------------

    #[test]
    fn build_pull_url_pypi_returns_empty_vec_for_multi_distribution_format() {
        // PyPI publishes multiple distributions per version (sdist +
        // wheels); a single (package, version) coordinate cannot be
        // resolved to a single URL by a pure string operation. The
        // PrefetchIngestHandler special-cases PyPI and fans out via
        // the per-version JSON manifest. `build_pull_url` returns the
        // empty vec to signal "no compose-style URL" — same shape the
        // default impl produces for oci/maven.
        let urls = handler()
            .build_pull_url("https://pypi.org", "requests", "2.31.0")
            .expect("Ok");
        assert_eq!(urls, Vec::<String>::new());
    }

    // -- is_extras_gated_requirement -----------------------------------------
    //
    // Covers `==`/`!=` recognition plus the list-form (`in [...]`) and
    // negated-list-form (`not in [...]`) marker syntaxes that PEP 508
    // permits.

    #[test]
    fn is_extras_gated_requirement_recognises_extra_in_list_form() {
        assert!(is_extras_gated_requirement(
            "foo ; extra in ['test', 'dev']"
        ));
        assert!(is_extras_gated_requirement(
            "foo (>=1.0) ; extra in [\"test\"]"
        ));
    }

    #[test]
    fn is_extras_gated_requirement_recognises_extra_not_in_negation() {
        assert!(is_extras_gated_requirement(
            "foo ; extra not in ['test', 'dev']"
        ));
    }

    #[test]
    fn is_extras_gated_requirement_still_recognises_eq_neq_from_item_11() {
        // Regression: list-form extension must not break ==/ != coverage.
        assert!(is_extras_gated_requirement("foo ; extra == 'test'"));
        assert!(is_extras_gated_requirement("foo ; extra != 'dev'"));
    }

    #[test]
    fn is_extras_gated_requirement_does_not_match_non_extras_markers() {
        // platform / python-version markers must NOT be classified as
        // extras-gated (those are runtime deps the cascade follows).
        assert!(!is_extras_gated_requirement(
            "foo ; python_version >= '3.8'"
        ));
        assert!(!is_extras_gated_requirement(
            "foo ; sys_platform == 'linux'"
        ));
        assert!(!is_extras_gated_requirement("foo"));
    }

    #[test]
    fn parse_wheel_metadata_drops_extra_in_list_form_requirement() {
        // Bonus regression: a Requires-Dist line gated by `extra in [...]`
        // must NOT appear in the cascade's dependency specs (it would inflate
        // the prefetch fan-out by closures the cascade never actually wants).
        let body = b"Metadata-Version: 2.1\n\
Name: example\n\
Version: 1.0.0\n\
Requires-Dist: real-dep>=1.0\n\
Requires-Dist: extras-only-dep ; extra in ['test', 'dev']\n\
Requires-Dist: also-extras ; extra not in ['prod']\n";
        let specs = parse_wheel_metadata_into_specs(body).expect("Ok");
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["real-dep"]);
    }

    // -- extract_dependency_specs ARCHIVE-AWARE ------------------------------------
    //
    // The cascade hands `extract_dependency_specs` the *stored distribution
    // artifact* — a wheel (zip, `PK\x03\x04`) or an sdist (gzip, `\x1f\x8b`),
    // NOT a pre-selected METADATA body. A wheel's runtime deps live in
    // `*.dist-info/METADATA` INSIDE the zip; an sdist is best-effort skipped.
    // The pure `Requires-Dist` parse logic is unit tested directly against the
    // private `parse_wheel_metadata_into_specs`
    // fn (the `_metadata` tests above); these tests build a real
    // distribution container and assert the trait method routes correctly.

    /// Build a minimal sdist `.tar.gz` (gzip-tar, `\x1f\x8b` magic) in
    /// memory. Used to assert the sdist arm of `extract_dependency_specs`
    /// best-effort skips (returns `Ok(vec![])`).
    fn make_sdist_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("make_sdist_tar_gz: set_path");
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append(&header, *body)
                .expect("make_sdist_tar_gz: append");
        }
        let gz = builder.into_inner().expect("make_sdist_tar_gz: finish tar");
        gz.finish().expect("make_sdist_tar_gz: finish gzip")
    }

    /// Feeding the trait method a real `.whl` (a zip carrying
    /// `<dist>-<ver>.dist-info/METADATA`, as the cascade does) must locate
    /// the METADATA entry INSIDE the zip and return ONLY the runtime deps —
    /// extras-gated lines dropped. Before the archive-aware fix this failed
    /// because the impl parsed the zip bytes as METADATA text and found no
    /// `Requires-Dist:` headers (zip magic is not RFC-5322).
    #[test]
    fn extract_dependency_specs_pypi_from_wheel_zip_returns_only_runtime_deps() {
        let metadata = b"Metadata-Version: 2.1\n\
Name: requests\n\
Version: 2.31.0\n\
Requires-Python: >=3.7\n\
Requires-Dist: charset-normalizer (<4,>=2)\n\
Requires-Dist: idna (<4,>=2.5)\n\
Requires-Dist: typing_extensions ; python_version < \"3.8\"\n\
Requires-Dist: pytest ; extra == 'test'\n\
Requires-Dist: PySocks (>=1.5.6) ; extra == 'socks'\n\
\n\
Long description body.\n" as &[u8];
        let whl = build_wheel_zip(&[
            ("requests-2.31.0.dist-info/METADATA", metadata),
            ("requests-2.31.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            ("requests/__init__.py", b""),
        ]);
        let specs = handler()
            .extract_dependency_specs(&mut Cursor::new(whl))
            .expect("a real .whl with dist-info/METADATA must parse");
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        // Runtime + plain-marker deps survive.
        for expected in &["charset-normalizer", "idna", "typing_extensions"] {
            assert!(
                names.contains(expected),
                "missing runtime dep {expected}: {names:?}"
            );
        }
        // Extras-gated deps drop out.
        for forbidden in &["pytest", "PySocks"] {
            assert!(
                !names.contains(forbidden),
                "extras-gated dep {forbidden} leaked from the wheel: {names:?}"
            );
        }
        // Range round-trips verbatim.
        let charset = specs
            .iter()
            .find(|s| s.name == "charset-normalizer")
            .expect("charset-normalizer present");
        assert_eq!(charset.range, "<4,>=2");
    }

    /// An sdist (`.tar.gz`, gzip magic `\x1f\x8b`) → best-effort skip,
    /// `Ok(vec![])`. sdist `PKG-INFO` frequently lacks `Requires-Dist`,
    /// so the cascade skips it rather than erroring.
    #[test]
    fn extract_dependency_specs_pypi_sdist_gzip_returns_empty_vec() {
        let sdist = make_sdist_tar_gz(&[(
            "requests-2.31.0/PKG-INFO",
            b"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
        )]);
        let specs = handler()
            .extract_dependency_specs(&mut Cursor::new(sdist))
            .expect("sdist is best-effort skipped, not an error");
        assert!(
            specs.is_empty(),
            "sdist deps are best-effort skipped: {specs:?}"
        );
    }

    /// A valid wheel zip that carries NO `*.dist-info/METADATA` entry is
    /// corruption for a wheel → `Err` (the cascade fails the walk
    /// non-retry; absence is corruption, not a leaf package).
    #[test]
    fn extract_dependency_specs_pypi_wheel_missing_metadata_is_err() {
        let whl = build_wheel_zip(&[("requests/__init__.py", b""), ("README.txt", b"hi")]);
        let err = handler()
            .extract_dependency_specs(&mut Cursor::new(whl))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    /// Bytes whose leading magic is neither `PK\x03\x04` (wheel/zip) nor
    /// `\x1f\x8b` (sdist/gzip) → a clear `Err` (raw METADATA or arbitrary
    /// bytes handed where a distribution container is expected).
    #[test]
    fn extract_dependency_specs_pypi_unknown_magic_is_err() {
        let body = b"Metadata-Version: 2.1\nRequires-Dist: foo>=1.0\n";
        let err = handler()
            .extract_dependency_specs(&mut Cursor::new(body))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
        assert!(
            err.to_string().contains("pypi distribution container"),
            "error must name the container mismatch: {err}"
        );
    }
}
