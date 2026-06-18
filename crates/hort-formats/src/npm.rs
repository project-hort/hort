use base64::Engine as _;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::format_handler::{DependencySpec, FormatHandler, MetadataStrategy};
use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};
use hort_domain::types::{ArtifactCoords, Ecosystem, PayloadAccess, Sbom, SbomComponent};

use hort_domain::ports::upstream_proxy::MetadataProjector;

use crate::npm::projection::NpmPackumentProjector;
use crate::range_resolvers::resolve_semver_range_max;
use crate::sbom_helpers::{build_subject_component, strip_version_constraint};

// npm `IndexBuilder` impl (emits the packument JSON from
// `Vec<VersionEntry>`). Re-exports `NpmVersionPayload` (defined in
// `hort-app::use_cases::index_serve` for dep-graph reasons — see that
// module's docstring). See explanation/index-construction.md.
pub mod index;
// npm packument streaming projector (see ADR 0026).
pub mod projection;

/// npm format handler.
///
/// Compiled-in Rust struct behind the `FormatHandler` trait boundary.
/// See explanation/format-handlers.md + ADR 0005.
pub struct NpmFormatHandler;

/// Per-version-object cap used when the `FormatHandler`
/// trait methods drive the [`NpmPackumentProjector`]. The HTTP-adapter
/// serve path threads the `HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE`
/// operator knob through `per_version_object_max_bytes`; the trait
/// boundary has no config handle, so it uses the same 2 MiB default the
/// adapter falls back to. The cap is defence-in-depth above the per-format
/// body cap (`metadata_expected_max_bytes`) and is non-load-bearing on
/// legitimate packuments (per-version objects are KiB-scale).
const fn npm_projector_per_version_cap() -> u64 {
    2 * 1024 * 1024
}

/// Parser-input sanity cap for a single `package/package.json` manifest
/// EXTRACTED from a `.tgz` (the body `parse_npm_runtime_dependencies`
/// parses — NOT the packument, NOT the tarball). Memory-safety bound sized
/// to a per-version object (a manifest is a per-version object), generous
/// headroom over real manifests (typically < 50 KiB). Deliberately
/// HARD-CODED + decoupled from `metadata_expected_max_bytes` (the
/// upload/HashReference threshold) so retuning that threshold can't move
/// this buffer cap. The archive-level decompression-bomb guard is
/// `archive_bounds`' job, not a second cap here.
const NPM_MANIFEST_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Compressed-input cap for the whole stored npm `.tgz` artifact fed to
/// [`NpmFormatHandler::extract_dependency_specs`]. The cascade caller reads
/// the artifact from CAS under a 32 MiB **compressed** bound
/// (`prefetch_dependencies::read_artifact_bytes`) before handing it here, so
/// this cap is set to that same 32 MiB to admit every artifact the cascade
/// can present while still bounding the buffer if a future caller streams an
/// unbounded reader in. It is a *compressed* cap (a plausibility/storage
/// bound, large); the
/// decompressed-output / compression-ratio / entry-count bomb guards live in
/// `archive_bounds::read_tar_gz_entry`, not here.
const NPM_TARBALL_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Maximum length of an npm package name in bytes (including any
/// `@scope/` prefix). Mirrors npm's published cap, enforced at the
/// `parse_download_path` boundary.
const NPM_NAME_MAX: usize = 214;

/// Parse the *declared runtime* dependency specs from an npm
/// `package.json` manifest body.
///
/// **Runtime classes only.** Reads ONLY the top-level `dependencies`
/// object. `devDependencies`, `peerDependencies`, `optionalDependencies`,
/// and `bundleDependencies` are intentionally dropped (the runtime-vs-dev
/// boundary the cascade depends on).
///
/// Dependency *values* that are not version-range strings — the
/// `git+https://`, `file:./local`, `npm:alias-name@^1` forms — are kept as
/// opaque range strings; `resolve_range_max` will best-effort fail to parse
/// them and return `None`, which the cascade reads as "skip this dep".
///
/// Empty `dependencies`, missing `dependencies` key, or a non-object
/// manifest all return `Ok(vec![])` — a well-formed manifest with no
/// declared deps is not an error. Only a body that is not valid JSON at all
/// surfaces a `Validation` error.
///
/// Bounded by [`NPM_MANIFEST_MAX_BYTES`] as a parser-input sanity cap —
/// manifests above that are rejected as `Validation`. (This is the
/// extracted-entry cap; the archive-level bomb guard lives in
/// `archive_bounds`.)
fn parse_npm_runtime_dependencies(manifest: &[u8]) -> DomainResult<Vec<DependencySpec>> {
    if manifest.len() > NPM_MANIFEST_MAX_BYTES {
        return Err(DomainError::Validation(format!(
            "npm manifest body is {} bytes; npm manifest max is {NPM_MANIFEST_MAX_BYTES}",
            manifest.len()
        )));
    }
    let doc: serde_json::Value = serde_json::from_slice(manifest).map_err(|e| {
        DomainError::Validation(format!("npm manifest body is not valid JSON: {e}"))
    })?;
    let Some(obj) = doc.as_object() else {
        return Ok(Vec::new());
    };
    let Some(deps) = obj.get("dependencies").and_then(|v| v.as_object()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(deps.len());
    for (name, raw_range) in deps {
        // Strings are the common case; anything else gets stringified
        // best-effort so the cascade still sees the dep name. The range
        // string is opaque here — `resolve_range_max` decides whether the
        // value is a parseable range or an alias / git ref.
        let range = match raw_range {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.push(DependencySpec {
            name: name.clone(),
            range,
        });
    }
    Ok(out)
}

/// Validate that `name` is a legal npm package name.
///
/// This is the canonical npm-name validator and the **single entry
/// point** for both scoped and unscoped names — callers pass the FULL
/// composed name (including any `@scope/` prefix) and the validator
/// itself decides whether to dispatch the scoped-vs-unscoped split:
///
///   - if `name` begins with `@`, the rest must match `<scope>/<pkg>`
///     and BOTH components are validated as separate npm name
///     components against the charset / leading-byte / non-empty rules
///     below. A bare `@` (no `/`) or a `@scope` with no slash is
///     rejected. The leading-`@` check is folded into the validator so
///     callers do not need a parallel `if !scope.starts_with('@')` guard.
///   - otherwise `name` is treated as a single unscoped component.
///
/// Rules (mirroring `validate-npm-package-name`):
///
///   - lowercase ASCII letters, digits, `-`, `_`, `.`
///   - first char of every component must NOT be `.` or `_`
///   - optional `@scope/` prefix where scope follows the same charset
///   - both scope and package components must be non-empty
///   - total length ≤ 214 bytes (including the `@scope/` prefix)
///
/// Returns [`DomainError::Validation`] tagged with the structured
/// field name `npm.name`. Error messages **never** include the
/// rejected input (it can be megabytes of attacker-controlled bytes
/// — log-pollution risk).
pub fn validate_npm_name(name: &str) -> DomainResult<()> {
    if name.is_empty() {
        return Err(DomainError::Validation(
            "npm.name: empty package name is not permitted".to_string(),
        ));
    }
    if name.len() > NPM_NAME_MAX {
        return Err(DomainError::Validation(format!(
            "npm.name: exceeds {NPM_NAME_MAX}-byte cap"
        )));
    }

    let (scope, pkg) = if let Some(rest) = name.strip_prefix('@') {
        let (scope, pkg) = rest.split_once('/').ok_or_else(|| {
            DomainError::Validation("npm.name: scoped name must match @scope/pkg".to_string())
        })?;
        (Some(scope), pkg)
    } else {
        (None, name)
    };

    if let Some(scope) = scope {
        validate_npm_name_component(scope, "scope")?;
    }
    validate_npm_name_component(pkg, "package")?;

    Ok(())
}

/// Validate a single npm name component (scope or package). Charset:
/// ASCII lowercase letters, digits, `-`, `_`, `.`. First byte must
/// not be `.` or `_`. Component must be non-empty.
fn validate_npm_name_component(component: &str, label: &str) -> DomainResult<()> {
    if component.is_empty() {
        return Err(DomainError::Validation(format!(
            "npm.name: {label} component is empty"
        )));
    }
    // safe: `.` (0x2E) and `_` (0x5F) are pure ASCII; multi-byte UTF-8 leading bytes are all >= 0x80 and would be rejected by the subsequent charset loop.
    let first = component.as_bytes()[0];
    if first == b'.' || first == b'_' {
        return Err(DomainError::Validation(format!(
            "npm.name: {label} component must not start with '.' or '_'"
        )));
    }
    for b in component.as_bytes() {
        let lc = b.is_ascii_lowercase() || b.is_ascii_digit();
        let punct = matches!(b, b'-' | b'_' | b'.');
        if !(lc || punct) {
            return Err(DomainError::Validation(format!(
                "npm.name: {label} component contains a byte outside [a-z0-9._-]"
            )));
        }
    }
    Ok(())
}

/// Keys preserved from the per-version packument block when building the
/// inline summary under [`MetadataStrategy::HashReference`]. The list is
/// deliberately locked to what the resolver + `npm view` minimally need —
/// everything else (readme, description, keywords, bin, scripts, …) stays
/// in the CAS blob.
const NPM_SUMMARY_KEYS: &[&str] = &[
    "name",
    "version",
    "dist",
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "engines",
];

impl FormatHandler for NpmFormatHandler {
    fn format_key(&self) -> &str {
        "npm"
    }

    /// Parse a tarball download path into coordinates.
    ///
    /// Accepts both shapes:
    /// - Unscoped: `{name}/-/{filename}` where `filename = {name}-{version}.tgz`
    /// - Scoped: `@{scope}/{pkg}/-/{filename}` where `filename = {pkg}-{version}.tgz`
    ///
    /// The stored `path` field is the full logical path (no leading slash).
    fn parse_download_path(&self, path: &str) -> DomainResult<ArtifactCoords> {
        let path = path.strip_prefix('/').unwrap_or(path);
        let parts: Vec<&str> = path.split('/').collect();

        let (name, unscoped_basename, filename) = match parts.as_slice() {
            [scope, pkg, "-", filename] if scope.starts_with('@') && !pkg.is_empty() => {
                (format!("{scope}/{pkg}"), *pkg, *filename)
            }
            [pkg, "-", filename] if !pkg.is_empty() => (pkg.to_string(), *pkg, *filename),
            _ => {
                return Err(invalid_path(path));
            }
        };

        // Strict path-component validation BEFORE any further use. Rejects
        // `..`, control bytes, mixed case, Unicode, names over 214 bytes,
        // and leading `.`/`_`. Surfaces as `DomainError::Validation` with
        // structured `npm.name` field tag.
        validate_npm_name(&name)?;

        let version =
            extract_version(filename, unscoped_basename).ok_or_else(|| invalid_path(path))?;

        // The read path uses the SSOT constructor so it
        // can never diverge from the write-sites. npm derives the filename
        // from name+version, so `filename = None` here.
        let logical_path = self.build_artifact_logical_path(&name, &version, None)?;
        // npm is case-preserving — `normalize_name` is a no-op identity
        // (after URL-decoding) for an already-decoded path. `name` and
        // `name_as_published` coincide here; they diverge for upload
        // handlers that receive URL-encoded scope separators.
        Ok(ArtifactCoords {
            name: name.clone(),
            name_as_published: name,
            version: Some(version),
            path: logical_path,
            format: RepositoryFormat::Npm,
            metadata: serde_json::Value::Null,
        })
    }

    /// The single logical-projection-path constructor for npm.
    /// `{n}/-/{basename}-{version}.tgz` with `n = normalize_name(name)`
    /// (URL-decode, case-preserving) and `basename` the unscoped tail of
    /// `n` (`@scope/pkg → pkg`). `filename` is ignored — npm derives the
    /// canonical tarball filename from name+version.
    fn build_artifact_logical_path(
        &self,
        name: &str,
        version: &str,
        filename: Option<&str>,
    ) -> DomainResult<String> {
        let _ = filename;
        let n = self.normalize_name(name);
        let basename = n.rsplit('/').next().unwrap_or(&n);
        Ok(format!("{n}/-/{basename}-{version}.tgz"))
    }

    /// URL-decode the package name (handles `@scope%2Fpkg` → `@scope/pkg`)
    /// and preserve case. npm package name uniqueness is case-insensitive
    /// on the registry, but metadata (packument `name`, tarball filenames)
    /// must echo the original case — so case-preserving storage is required.
    fn normalize_name(&self, name: &str) -> String {
        urlencoding::decode(name)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_else(|_| name.to_string())
    }

    /// npm per-version packument entry — 5 MB cap.
    ///
    /// This is the full-payload ceiling under
    /// [`MetadataStrategy::HashReference`]: the cap check runs BEFORE
    /// the split decision, so the cap must admit packuments that the
    /// HashReference strategy is designed to spill to CAS.
    /// Real-world measurements observed a 1.37 MB max
    /// (`@mui/icons-material`) against a p99 of ~141 KB; 5 MB keeps
    /// headroom for long-tail growth while staying well below the
    /// global 10 MB blob safety cap. The 256 KB split threshold is
    /// enforced separately via `metadata_strategy`.
    fn metadata_expected_max_bytes(&self) -> usize {
        5 * 1024 * 1024
    }

    /// npm persists payload metadata via
    /// [`MetadataStrategy::HashReference`]: packuments under 256 KB
    /// stay inline for read-path cheapness, anything larger spills the
    /// full payload to CAS and keeps a handler-extracted summary inline
    /// on the event + projection row. The threshold was calibrated
    /// against a real-world corpus (p99 ~141 KB, max 1.37 MB); 256 KB
    /// leaves the overwhelming majority of real packages on the inline
    /// path while still kicking the long-tail outliers to the blob path.
    fn metadata_strategy(&self) -> MetadataStrategy {
        MetadataStrategy::HashReference {
            inline_threshold_bytes: 256 * 1024,
        }
    }

    /// Extract the resolver-essential subset of a per-version packument
    /// block for the inline summary. Filters `full` to the fixed key
    /// set declared by [`NPM_SUMMARY_KEYS`]; fields not present in
    /// `full` are simply omitted (NOT filled with `Value::Null`) so
    /// summary-only consumers get the exact shape the client
    /// published. Returns `Value::Null` when `full` is not an object
    /// (the defensive branch for non-object input).
    fn extract_metadata_summary(&self, full: &serde_json::Value) -> serde_json::Value {
        let Some(obj) = full.as_object() else {
            return serde_json::Value::Null;
        };
        // Iterate the locked key list, not the input object, so the
        // summary field order is stable regardless of input ordering.
        let mut summary = serde_json::Map::with_capacity(NPM_SUMMARY_KEYS.len());
        for key in NPM_SUMMARY_KEYS {
            if let Some(v) = obj.get(*key) {
                summary.insert((*key).to_string(), v.clone());
            }
        }
        serde_json::Value::Object(summary)
    }

    /// npm packument path: `/{url-encoded-name}`.
    ///
    /// For unscoped names this is just `/{name}`. For scoped names
    /// (`@scope/pkg`) the `/` between scope and name URL-encodes to
    /// lowercase `%2f` per the npm registry convention; `@` stays
    /// unescaped. Other characters are not encoded — npm package names
    /// are constrained to a small ASCII subset (lowercase letters,
    /// digits, `-`, `_`, `.`, plus the `@` and `/` of the scope
    /// separator).
    ///
    /// Returns `Some(_)` unconditionally — the packument path does not
    /// depend on `coords.version`. The orchestrator passes the parsed
    /// per-version body to the caller alongside the version it cares about.
    ///
    /// See ADR 0006 §11 and the npm registry API spec.
    fn upstream_checksum_metadata_path(&self, coords: &ArtifactCoords) -> Option<String> {
        Some(format!("/{}", url_encode_npm_name(&coords.name)))
    }

    /// Parse an npm packument body, locate `versions[coords.version]`,
    /// and decode `dist.integrity` (an SRI string of the form
    /// `sha512-<base64>`) into an [`UpstreamPublishedChecksum`].
    ///
    /// SHA-1 `dist.shasum` fallback is **rejected**: a packument that
    /// publishes only `dist.shasum` without `dist.integrity` produces a
    /// `Validation` error, not a softer fallback. SHA-1 has been
    /// collision-broken since 2017 (SHAttered).
    ///
    /// Multi-algorithm SRI strings (space-separated, e.g.
    /// `sha512-... sha384-...`) pick the strongest sha512 entry; if no
    /// sha512 entry is present, the parser rejects.
    ///
    /// **Streaming.** `body` is a streaming reader over the packument;
    /// the parse runs through a memory-bounded walk that captures only
    /// the target version's `dist.integrity` (never the 50 MiB body).
    /// The full error taxonomy is: missing-version-in-coords,
    /// no-versions-object, version-not-found, no-dist.integrity, the SRI
    /// length/hex/algorithm checks, and the input-size cap.
    fn parse_upstream_checksum(
        &self,
        body: &mut dyn std::io::Read,
        coords: &ArtifactCoords,
    ) -> DomainResult<UpstreamPublishedChecksum> {
        let version = coords.version.as_deref().ok_or_else(|| {
            DomainError::Validation(
                "upstream npm packument parser requires a version in coords".to_string(),
            )
        })?;

        // Streaming plausibility size cap — defence in depth above the
        // fetch-streaming cap. Because this method STREAMS the body, the
        // ceiling is the plausibility / storage bound
        // (`STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES`, aligned with
        // `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE`), NOT the small in-memory
        // `metadata_expected_max_bytes()`. Enforced AFTER the streaming walk
        // (the cap fundamentally needs the total body length); the walk keeps
        // memory bounded meanwhile. See
        // `stream_helpers::project_with_byte_cap` for the ordering note.
        //
        // A dedicated streaming walk (not the shared `NpmPackumentProjector`)
        // is used here because `parse_upstream_checksum`'s error taxonomy is
        // finer than the projector's flattened `Vec<NpmVersionEntry>`:
        // it distinguishes "no versions object" / "not valid JSON" /
        // "version not found" / "no dist.integrity", each gating the upstream
        // checksum path (see ADR 0006). The walk uses the same serde streaming
        // technique (`deserialize_map` + `IgnoredAny`) so it never materialises
        // a `serde_json::Value` tree for the 50 MiB packument.
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let outcome = crate::stream_helpers::project_with_byte_cap(
            body,
            max,
            NpmChecksumProjector {
                version: version.to_string(),
            },
            |len, max| {
                format!(
                    "upstream metadata body is {len} bytes; streaming plausibility max is {max}"
                )
            },
        )?;

        let integrity = match outcome {
            NpmChecksumOutcome::Integrity(s) => s,
            NpmChecksumOutcome::VersionMissingIntegrity => {
                return Err(DomainError::Validation(format!(
                    "upstream npm version {}@{version} publishes no dist.integrity \
                     (legacy packument); SHA-1 dist.shasum fallback is not accepted",
                    coords.name
                )))
            }
            NpmChecksumOutcome::VersionNotFound => {
                return Err(DomainError::Validation(format!(
                    "upstream npm packument has no version {version} for {}",
                    coords.name
                )))
            }
            NpmChecksumOutcome::NoVersionsObject => {
                return Err(DomainError::Validation(
                    "upstream npm packument has no versions object".to_string(),
                ))
            }
        };

        let hex = decode_sha512_sri(&integrity).map_err(|e| {
            DomainError::Validation(format!(
                "upstream npm dist.integrity for {}@{version} is malformed: {e}",
                coords.name
            ))
        })?;

        UpstreamPublishedChecksum::new(HashAlgorithm::Sha512, hex)
    }

    /// Extract the upstream-published version-string set from an npm
    /// packument body.
    ///
    /// Reads the top-level `versions{}` object and returns its keys in
    /// iteration order (serde_json's object iteration preserves
    /// insertion order). Same shape as the hot-path trigger in
    /// `crates/hort-http-npm/src/packument.rs::fire_prefetch_trigger_npm`
    /// (lifted verbatim) so the cron-tier and serve-site readers stay
    /// in lock-step. A body that fails to parse, is not an object, or
    /// has no `versions` key returns `Ok(Vec::new())` — the prefetch
    /// tick treats this as "no upstream signal" and skips. Hard-error
    /// would be surface-noise here: a malformed upstream is a
    /// transient problem the next tick re-evaluates.
    ///
    /// Bounded by the streaming plausibility ceiling
    /// ([`STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES`](crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES)
    /// = 64 MiB) — this method STREAMS the body through the projector, so
    /// per the cap taxonomy its ceiling is the plausibility / storage
    /// bound (aligned with the `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE`
    /// fetch backstop), NOT the small in-memory
    /// [`metadata_expected_max_bytes`](Self::metadata_expected_max_bytes)
    /// ceiling. Bodies above that are rejected as `Validation`; the
    /// projection keeps memory bounded by the version-string list, not the
    /// body. Without the larger cap, prefetch would reject legitimately
    /// large packuments (e.g. ~50 MiB `@types/node`) the serve path
    /// streams fine.
    ///
    /// **Streaming.** Projects the packument via
    /// [`NpmPackumentProjector`](crate::npm::projection::NpmPackumentProjector)
    /// and returns its `versions[].version` keys in document order.
    /// A body that fails to parse degrades to `Ok(Vec::new())` (degrade-open
    /// policy); the 5 MiB input-size cap is preserved. A malformed body OR a
    /// trip of the per-version object cap likewise degrades to an empty list
    /// here (this is the best-effort prefetch-cron tier — surfacing an error
    /// would only add noise the next tick re-evaluates); only a genuine trip
    /// of the whole-body plausibility cap still surfaces `Validation`.
    fn extract_upstream_versions(&self, body: &mut dyn std::io::Read) -> DomainResult<Vec<String>> {
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let result = crate::stream_helpers::project_with_byte_cap(
            body,
            max,
            NpmPackumentProjector::new(npm_projector_per_version_cap()),
            |len, max| {
                format!(
                    "npm upstream metadata body is {len} bytes; streaming plausibility max is {max}"
                )
            },
        );
        match result {
            Ok(projection) => Ok(projection.versions.into_iter().map(|v| v.version).collect()),
            // Degrade-open on a malformed body, but a genuine over-cap
            // rejection still surfaces as `Validation`.
            Err(DomainError::Validation(ref m)) if m.contains("streaming plausibility max is") => {
                Err(DomainError::Validation(m.clone()))
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// npm packument path — version-agnostic. Coincides with the
    /// per-package checksum-metadata path
    /// ([`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path))
    /// because the npm packument carries both the version set AND
    /// `dist.integrity` checksums. Scoped packages encode `/` as
    /// `%2f` per the npm registry API.
    fn upstream_metadata_path(&self, package: &str) -> Option<String> {
        Some(format!("/{}", url_encode_npm_name(package)))
    }

    /// Extract a deterministic SBOM from the per-version packument
    /// metadata the handler produced at ingest. Pure function — does
    /// not read `payload`.
    ///
    /// Reads `dependencies`, `peerDependencies`, `optionalDependencies`
    /// (direct dependencies) and `devDependencies` (transitive build-time
    /// deps). Each entry becomes one [`SbomComponent`] keyed by the
    /// canonical PURL `pkg:npm/{name}@{version}` (scoped names encode `@`
    /// as `%40` per the PURL spec). The license is extracted from the
    /// manifest's `license` field — string form (`"MIT"`) and the legacy
    /// object form (`{"type":"MIT"}`) are both supported. Missing licence
    /// → empty `Vec`.
    ///
    /// Returns `Some(Sbom { components: vec![] })` (NOT `None`) when the
    /// manifest exists but lists no dependencies. `None` is reserved for
    /// formats with no machine-readable manifest at all (the trait
    /// default).
    ///
    fn extract_sbom(
        &self,
        coords: &ArtifactCoords,
        format_metadata: &serde_json::Value,
        _payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Sbom>> {
        // Build the subject regardless of whether the manifest is
        // parseable — for an npm artifact ingested under known
        // `coords.name`/`coords.version`, the subject is well-defined
        // even when format_metadata is null (e.g. proxied pulls that
        // never landed a parsed package.json). Without the subject,
        // leaf packages like lodash@4.17.20 would produce an empty SBOM
        // and osv-scanner would find nothing.
        let purl_name = encode_npm_purl_name(&coords.name);
        let Some(obj) = format_metadata.as_object() else {
            let subject =
                build_subject_component(coords, Ecosystem::Npm, "pkg:npm/", &purl_name, Vec::new());
            return Ok(Some(Sbom {
                subject: Some(subject),
                components: vec![],
            }));
        };

        let licenses = extract_npm_license_list(obj);
        let subject = build_subject_component(
            coords,
            Ecosystem::Npm,
            "pkg:npm/",
            &purl_name,
            licenses.clone(),
        );
        let mut components = Vec::new();

        // (key, direct?) — `direct=true` for runtime/peer/optional
        // dependencies that ride into the artifact at install time;
        // `direct=false` for `devDependencies` which only matter at
        // build time.
        let kinds: &[(&str, bool)] = &[
            ("dependencies", true),
            ("peerDependencies", true),
            ("optionalDependencies", true),
            ("devDependencies", false),
        ];

        for (key, direct) in kinds {
            let Some(deps) = obj.get(*key).and_then(|v| v.as_object()) else {
                continue;
            };
            for (name, raw_version) in deps {
                let version = npm_version_from_value(raw_version);
                let purl_name = encode_npm_purl_name(name);
                let purl = match version.as_deref() {
                    Some(v) => format!("pkg:npm/{purl_name}@{v}"),
                    None => format!("pkg:npm/{purl_name}"),
                };
                components.push(SbomComponent {
                    purl,
                    name: name.clone(),
                    version,
                    ecosystem: Ecosystem::Npm,
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
    /// npm `.tgz` artifact stream**.
    ///
    /// **Input is the gzip-tar artifact, NOT a pre-selected manifest.**
    /// The transitive prefetch cascade hands this method the raw stored
    /// artifact it read from CAS (`read_artifact_bytes`), which for npm is
    /// the `.tgz` gzip tarball. npm's published `package.json` (carrying
    /// `dependencies`) lives at `package/package.json` INSIDE that tarball,
    /// so this method locates and reads that entry, then parses it. (The
    /// earlier contract — "a pre-selected `package.json` JSON body" — was
    /// incorrect: the cascade never pre-selects the manifest, so the impl
    /// tripped on the gzip magic byte.)
    ///
    /// **Runtime classes only.** The extracted manifest is parsed by
    /// [`parse_npm_runtime_dependencies`], which reads ONLY the
    /// `dependencies` field. `devDependencies`, `peerDependencies`,
    /// `optionalDependencies`, and `bundleDependencies` (sometimes spelled
    /// `bundledDependencies`) are intentionally dropped — following them
    /// inflates the transitive prefetch cascade by 10–100× for no run-path
    /// value. See the trait docstring for the full runtime-vs-dev rationale.
    ///
    /// **Archive bounds.** Extraction routes through the
    /// audited [`archive_bounds::read_tar_gz_entry`], the single sanctioned
    /// home for archive decoding: the gzip decompressor is wrapped in a
    /// `BoundedReader` (compression-ratio + cumulative-output cap), entry
    /// count is bounded, and nested archives are rejected. The cap is
    /// *cumulative* across the sequential tar scan, so `package/package.json`
    /// MUST be an early entry — which every real npm tarball satisfies.
    ///
    /// **Caps.** The compressed `.tgz` stream is read into a capped buffer
    /// bounded by [`NPM_TARBALL_MAX_BYTES`] (32 MiB compressed, matching the
    /// cascade's own artifact bound); the *extracted* `package.json` entry is
    /// then bounded by [`NPM_MANIFEST_MAX_BYTES`] as a parser-input sanity
    /// cap. The decompression-bomb guard is `archive_bounds`' job, not a cap
    /// here.
    ///
    /// **Errors.**
    /// - Input not a gzip-tar → `Validation` with a clear "expected gzip-tar"
    ///   message — reported honestly, not as a JSON parse error.
    /// - `package/package.json` absent from the tarball → `Validation`
    ///   naming the missing entry (a well-formed npm tarball always has it;
    ///   absence is corruption).
    /// - Manifest present but unparseable JSON → `Validation` (non-retry).
    /// - Any `archive_bounds` guard trip → `Validation` (non-retry).
    /// - A well-formed manifest with zero declared runtime deps →
    ///   `Ok(vec![])`, never `Err`.
    ///
    /// **Streaming.** `content` is a `&mut dyn Read` (streaming-port
    /// signature). The compressed bytes are read into a capped `Vec` to
    /// obtain the length the gzip ratio-bound needs (gzip carries no reliable
    /// size header) — the cascade already buffers the compressed artifact, so
    /// this adds no second fetch.
    fn extract_dependency_specs(
        &self,
        content: &mut dyn std::io::Read,
    ) -> DomainResult<Vec<DependencySpec>> {
        // Read the compressed .tgz into a capped buffer to obtain its length
        // (gzip has no reliable decompressed-size header, so the ratio bound
        // needs the compressed length passed explicitly).
        let buf = crate::stream_helpers::read_to_capped_vec(
            content,
            NPM_TARBALL_MAX_BYTES,
            |len, max| format!("npm artifact is {len} bytes; npm tarball max is {max}"),
        )?;
        // Locate package/package.json inside the gzip-tar under the audited
        // archive_bounds caps. The manifest must be an early entry.
        let manifest = crate::archive_bounds::read_tar_gz_entry(
            &buf[..],
            buf.len() as u64,
            crate::archive_bounds::BoundsConfig::default_for_metadata_extraction(),
            |path| path == "package/package.json",
        )?
        .ok_or_else(|| {
            DomainError::Validation(
                "npm tarball is missing package/package.json (corrupt artifact)".to_string(),
            )
        })?;
        parse_npm_runtime_dependencies(&manifest)
    }

    /// Resolve an npm-style semver range against an `available` set,
    /// returning the highest matching version string.
    ///
    /// Uses the `semver` crate's `VersionReq` / `Version` types — npm's
    /// range grammar (caret `^`, tilde `~`, comparison operators,
    /// AND-combined comma-separated clauses, hyphen ranges via
    /// "X.Y.Z - A.B.C", and the bare `*` / `x` / empty wildcards) maps
    /// onto the same Cargo-flavoured semver grammar the `semver` crate
    /// parses. Pre-releases follow semver §11.4: a pre-release
    /// candidate is excluded from a range unless the range explicitly
    /// names a pre-release at the same `MAJOR.MINOR.PATCH` (which is
    /// what `semver::VersionReq::matches` enforces).
    ///
    /// Best-effort:
    /// - Unparseable range → `Ok(None)` (silent no-op; the cascade
    ///   reads this as "skip this dep").
    /// - `available` entries that fail to parse as `Version` are
    ///   silently dropped from the candidate set (one bad upstream
    ///   line must not starve the whole rest of the lookup).
    /// - Empty `available` → `Ok(None)`.
    /// - No version matches → `Ok(None)`.
    ///
    /// Returns the matching version's *original string form* from
    /// `available` (NOT a normalised `Version::to_string()`), so the
    /// caller can feed it straight back into a pull-through URL that
    /// requires the exact upstream-published spelling.
    fn resolve_range_max(&self, range: &str, available: &[&str]) -> DomainResult<Option<String>> {
        Ok(resolve_semver_range_max(range, available))
    }

    /// Compose the upstream tarball URL for an npm `(package, version)`
    /// coordinate.
    ///
    /// Conventional npm tarball path:
    ///
    /// - **Unscoped** (`express` → `4.18.0`):
    ///   `{upstream_url}/express/-/express-4.18.0.tgz`
    /// - **Scoped** (`@types/node` → `20.0.0`):
    ///   `{upstream_url}/@types/node/-/node-20.0.0.tgz`
    ///
    /// Note the scoped form uses the *unscoped basename* (`node`) in
    /// the filename — this is the npm convention and matches
    /// [`parse_download_path`](Self::parse_download_path)'s scoped
    /// branch + the canonical logical path on
    /// [`crate::npm::extract_upstream_tarball_url`]'s output (the
    /// `https://registry.npmjs.org/{pkg}/-/{pkg}-{version}.tgz` shape).
    ///
    /// The implementation strips a trailing `/` from `upstream_url`
    /// before composition so callers can pass either form. Returns a
    /// single-element vec — npm publishes one tarball per version.
    ///
    /// Pure: no I/O. The leaf [`PrefetchIngestHandler`](
    /// crate::npm) fetches the URL via `UpstreamProxy::fetch_artifact`
    /// and ingests via `IngestUseCase::ingest_verified`.
    fn build_pull_url(
        &self,
        upstream_url: &str,
        package: &str,
        version: &str,
    ) -> DomainResult<Vec<String>> {
        if package.is_empty() || version.is_empty() {
            return Err(DomainError::Validation(
                "npm build_pull_url requires non-empty package and version".to_string(),
            ));
        }
        let base = upstream_url.trim_end_matches('/');
        // Scoped basename: `@scope/pkg` → `pkg`. Unscoped: `pkg` → `pkg`.
        let basename = package.rsplit('/').next().unwrap_or(package);
        let url = format!("{base}/{package}/-/{basename}-{version}.tgz");
        Ok(vec![url])
    }
}

/// Read an npm dependency value into a stripped version string.
///
/// npm allows the value to be either a SemVer range (`"^1.2.3"`,
/// `"1.0.0"`) or a non-string form (`null`, an object describing a git
/// or url reference). For the SBOM the bare version is what we want;
/// when we can't recover one we return `None` and the PURL emits
/// without an `@version` suffix.
fn npm_version_from_value(value: &serde_json::Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        let stripped = strip_version_constraint(s);
        // A value like `"git+https://..."` is left
        // alone after stripping. We intentionally do not validate semver
        // here — npm itself stores whatever the publisher set.
        if stripped.is_empty() {
            None
        } else {
            Some(stripped)
        }
    } else {
        None
    }
}

/// Extract a `license` list from an npm package manifest object.
///
/// npm has historically permitted two shapes:
/// - String: `"license": "MIT"` (modern, SPDX expression).
/// - Object: `"license": {"type": "MIT", "url": "..."}` (deprecated but
///   still on the registry for older packages).
///
/// We pull whichever is present. Missing or unrecognisable shapes return
/// an empty `Vec`. We do NOT attempt SPDX validation — that's a
/// downstream policy concern.
fn extract_npm_license_list(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let Some(value) = obj.get("license") else {
        return Vec::new();
    };
    if let Some(s) = value.as_str() {
        if s.is_empty() {
            Vec::new()
        } else {
            vec![s.to_string()]
        }
    } else if let Some(t) = value.get("type").and_then(|v| v.as_str()) {
        vec![t.to_string()]
    } else {
        Vec::new()
    }
}

/// Encode an npm package name for inclusion in a PURL.
///
/// Per the PURL spec npm convention:
/// - Scoped names (`@scope/pkg`) encode the leading `@` as `%40` and
///   keep the `/` literal: `%40scope/pkg`.
/// - Plain names pass through unchanged (npm restricts the charset to a
///   tiny ASCII subset, all of which is PURL-safe).
fn encode_npm_purl_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        format!("%40{rest}")
    } else {
        name.to_string()
    }
}

/// Extract the upstream tarball URL for `version` from an npm packument body.
///
/// Walks `versions[version].dist.tarball` and returns it as a `String`. The
/// canonical shape on `registry.npmjs.org` is
/// `https://registry.npmjs.org/{pkg}/-/{pkg}-{version}.tgz`, but mirrors and
/// scoped packages produce other valid origins; the only invariant enforced
/// here is the `https://` prefix.
///
/// The URL is required to begin with `https://`. `http://`, missing scheme,
/// or any other scheme is rejected as a `Validation` error so we never
/// promote a downgrade-attack target to a fetch URL.
///
/// `max_bytes` is the per-format input-size ceiling. The caller must pass
/// [`NpmFormatHandler::metadata_expected_max_bytes`]; the parameter is
/// explicit because this is a free function with no `&self` to read it
/// from. A body larger than `max_bytes` is rejected as
/// [`DomainError::Validation`] before serde_json sees it.
///
/// Kept independent of [`NpmFormatHandler::parse_upstream_checksum`] on
/// purpose: the redundant `serde_json::from_slice` is cheap (npm packuments
/// cap at 5 MB and are often two orders of magnitude smaller) and the two
/// parsers are called from different orchestration paths. Combine only if
/// profiling shows a hotspot.
///
/// `crates/hort-http-npm/src/upstream_pull.rs` is the primary caller —
/// the orchestrator pairs this helper with `parse_upstream_checksum` to drive
/// the verified ingest. Mirrors the precedent in
/// [`crate::pypi::extract_upstream_file_url`] / `hort-http-cargo`.
///
/// Visibility: `pub` rather than `pub(crate)` because the sole external
/// caller (`crates/hort-http-npm/src/upstream_pull.rs`) sits in a
/// different crate. Same trade-off as
/// [`crate::pypi::extract_upstream_file_url`].
pub fn extract_upstream_tarball_url(
    body: &[u8],
    version: &str,
    max_bytes: usize,
) -> DomainResult<String> {
    // Pre-parse size cap. See the matching block in
    // `NpmFormatHandler::parse_upstream_checksum` for the full
    // defence-in-depth explanation.
    if body.len() > max_bytes {
        return Err(DomainError::Validation(format!(
            "upstream metadata body is {} bytes; per-format max is {}",
            body.len(),
            max_bytes
        )));
    }

    let doc: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        DomainError::Validation(format!("upstream npm packument is not valid JSON: {e}"))
    })?;

    let versions = doc
        .get("versions")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            DomainError::Validation("upstream npm packument has no versions object".to_string())
        })?;

    let entry = versions.get(version).ok_or_else(|| {
        DomainError::Validation(format!("upstream npm packument has no version {version}"))
    })?;

    let tarball = entry
        .get("dist")
        .and_then(|d| d.get("tarball"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            DomainError::Validation(format!(
                "upstream npm version {version} is missing dist.tarball"
            ))
        })?;

    if !tarball.starts_with("https://") {
        return Err(DomainError::Validation(format!(
            "upstream npm returned non-https tarball URL: {tarball}"
        )));
    }

    Ok(tarball.to_string())
}

/// URL-encode an npm package name for use in registry URLs.
///
/// Encoding rules (per the npm registry convention):
/// - `/` → `%2f` (lowercase). Scoped names (`@scope/pkg`) thus encode
///   to `@scope%2fpkg`.
/// - `@` is **not** encoded — it appears literally in scoped names.
/// - Every other character that npm allows in a package name (lowercase
///   letters, digits, `-`, `_`, `.`) is passed through verbatim.
///
/// Falls back to passing any other byte through unchanged. npm
/// constrains package names to a small ASCII subset, so the fallback
/// is unreachable in practice; it is documented as defensive.
fn url_encode_npm_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    for c in name.chars() {
        match c {
            '/' => out.push_str("%2f"),
            _ => out.push(c),
        }
    }
    out
}

/// Decode an SRI string and return the lowercase hex of the sha512
/// component.
///
/// Accepts:
/// - A single algorithm: `sha512-<base64>`
/// - Multi-algorithm: space-separated entries; the first sha512 entry
///   wins.
///
/// Rejects:
/// - Empty / whitespace-only input.
/// - All-non-sha512 input (`sha384-...`, `sha256-...`).
/// - Entries that are not `<algorithm>-<base64>`.
/// - sha512 entry whose base64 doesn't decode.
/// - sha512 entry whose decoded length is not 64 bytes.
fn decode_sha512_sri(integrity: &str) -> Result<String, String> {
    // TDD-incremental implementation: the next failing test drives the
    // next branch.
    for entry in integrity.split_ascii_whitespace() {
        let Some((alg, b64)) = entry.split_once('-') else {
            continue;
        };
        if alg != "sha512" {
            continue;
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("sha512 base64 decode failed: {e}"))?;
        if raw.len() != 64 {
            return Err(format!(
                "sha512 SRI decoded to {} bytes, expected 64",
                raw.len()
            ));
        }
        let mut hex = String::with_capacity(128);
        for byte in &raw {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").expect("writing to String never fails");
        }
        return Ok(hex);
    }
    Err("SRI string contains no sha512 entry".to_string())
}

// ---------------------------------------------------------------------------
// Streaming checksum walk for `parse_upstream_checksum` (see ADR 0026).
//
// A dedicated `MetadataProjector` that walks the packument once via serde
// streaming (`deserialize_map` + `IgnoredAny`), capturing ONLY the target
// version's `dist.integrity` string. Memory is bounded by that single
// string — the 50 MiB packument never lands in a `serde_json::Value` tree.
// ---------------------------------------------------------------------------

/// What the streaming checksum walk found for the requested version.
enum NpmChecksumOutcome {
    /// `versions[version].dist.integrity` string (validated downstream).
    Integrity(String),
    /// The version entry exists but has no `dist.integrity`.
    VersionMissingIntegrity,
    /// A `versions{}` object was present but lacked the requested version.
    VersionNotFound,
    /// No `versions{}` object at all (missing key OR non-object value).
    NoVersionsObject,
}

struct NpmChecksumProjector {
    version: String,
}

impl MetadataProjector for NpmChecksumProjector {
    type Projection = NpmChecksumOutcome;
    fn project<R: std::io::Read>(self, reader: R) -> DomainResult<NpmChecksumOutcome> {
        let mut de = serde_json::Deserializer::from_reader(reader);
        serde::de::Deserializer::deserialize_map(
            &mut de,
            NpmChecksumTopVisitor {
                version: self.version,
            },
        )
        .map_err(|e| {
            DomainError::Validation(format!("upstream npm packument is not valid JSON: {e}"))
        })
    }
}

struct NpmChecksumTopVisitor {
    version: String,
}

impl<'de> serde::de::Visitor<'de> for NpmChecksumTopVisitor {
    type Value = NpmChecksumOutcome;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an npm packument object")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> Result<NpmChecksumOutcome, A::Error> {
        let mut outcome = NpmChecksumOutcome::NoVersionsObject;
        let mut seen_versions = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "versions" && !seen_versions {
                seen_versions = true;
                outcome = map.next_value_seed(NpmChecksumVersionsSeed {
                    version: &self.version,
                })?;
            } else {
                let _: serde::de::IgnoredAny = map.next_value()?;
            }
        }
        Ok(outcome)
    }
}

struct NpmChecksumVersionsSeed<'a> {
    version: &'a str,
}

impl<'de, 'a> serde::de::DeserializeSeed<'de> for NpmChecksumVersionsSeed<'a> {
    type Value = NpmChecksumOutcome;
    fn deserialize<D: serde::de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<NpmChecksumOutcome, D::Error> {
        // `deserialize_any` so a non-object `versions` value (the
        // `{"versions":[...]}` case) is tolerated and mapped to
        // `NoVersionsObject` rather than surfacing a serde type error.
        deserializer.deserialize_any(NpmChecksumVersionsVisitor {
            version: self.version,
        })
    }
}

struct NpmChecksumVersionsVisitor<'a> {
    version: &'a str,
}

impl<'de, 'a> serde::de::Visitor<'de> for NpmChecksumVersionsVisitor<'a> {
    type Value = NpmChecksumOutcome;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the npm packument versions{} map")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> Result<NpmChecksumOutcome, A::Error> {
        let mut result = NpmChecksumOutcome::VersionNotFound;
        while let Some(ver) = map.next_key::<String>()? {
            if ver == self.version {
                let entry: NpmChecksumVersionEntry = map.next_value()?;
                result = match entry.dist.and_then(|d| d.integrity) {
                    Some(i) => NpmChecksumOutcome::Integrity(i),
                    None => NpmChecksumOutcome::VersionMissingIntegrity,
                };
            } else {
                let _: serde::de::IgnoredAny = map.next_value()?;
            }
        }
        Ok(result)
    }
    // Any non-map `versions` value → no usable versions object.
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> Result<NpmChecksumOutcome, A::Error> {
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(NpmChecksumOutcome::NoVersionsObject)
    }
    fn visit_str<E: serde::de::Error>(self, _v: &str) -> Result<NpmChecksumOutcome, E> {
        Ok(NpmChecksumOutcome::NoVersionsObject)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<NpmChecksumOutcome, E> {
        Ok(NpmChecksumOutcome::NoVersionsObject)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<NpmChecksumOutcome, E> {
        Ok(NpmChecksumOutcome::NoVersionsObject)
    }
    fn visit_bool<E: serde::de::Error>(self, _v: bool) -> Result<NpmChecksumOutcome, E> {
        Ok(NpmChecksumOutcome::NoVersionsObject)
    }
    fn visit_i64<E: serde::de::Error>(self, _v: i64) -> Result<NpmChecksumOutcome, E> {
        Ok(NpmChecksumOutcome::NoVersionsObject)
    }
    fn visit_u64<E: serde::de::Error>(self, _v: u64) -> Result<NpmChecksumOutcome, E> {
        Ok(NpmChecksumOutcome::NoVersionsObject)
    }
    fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<NpmChecksumOutcome, E> {
        Ok(NpmChecksumOutcome::NoVersionsObject)
    }
}

/// Sparse per-version DTO for the checksum walk — only `dist.integrity`
/// is captured; every other field passes through `deserialize_ignored_any`.
#[derive(serde::Deserialize)]
struct NpmChecksumVersionEntry {
    #[serde(default)]
    dist: Option<NpmChecksumDist>,
}

#[derive(serde::Deserialize)]
struct NpmChecksumDist {
    integrity: Option<String>,
}

fn extract_version(filename: &str, basename: &str) -> Option<String> {
    let prefix = format!("{basename}-");
    let stripped = filename.strip_prefix(&prefix)?.strip_suffix(".tgz")?;
    if stripped.is_empty() {
        None
    } else {
        Some(stripped.to_string())
    }
}

fn invalid_path(path: &str) -> DomainError {
    DomainError::Validation(format!(
        "invalid npm download path: expected {{name}}/-/{{filename}} or @{{scope}}/{{name}}/-/{{filename}}, got: {path}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> NpmFormatHandler {
        NpmFormatHandler
    }

    // -- format_key -----------------------------------------------------------

    #[test]
    fn format_key_is_npm() {
        assert_eq!(handler().format_key(), "npm");
    }

    // -- normalize_name -------------------------------------------------------

    #[test]
    fn normalize_name_preserves_case() {
        // npm metadata must echo exact case back to the client — do NOT
        // fold to lowercase like cargo/PyPI do.
        assert_eq!(handler().normalize_name("MyPackage"), "MyPackage");
        assert_eq!(handler().normalize_name("express"), "express");
    }

    #[test]
    fn normalize_name_decodes_percent_encoded_slash() {
        assert_eq!(handler().normalize_name("@types%2Fnode"), "@types/node");
    }

    #[test]
    fn normalize_name_decodes_mixed_percent_encoding() {
        assert_eq!(handler().normalize_name("%40types%2Fnode"), "@types/node");
    }

    #[test]
    fn normalize_name_passthrough_plain_scoped() {
        assert_eq!(handler().normalize_name("@types/node"), "@types/node");
    }

    #[test]
    fn normalize_name_invalid_encoding_falls_back_to_input() {
        // `urlencoding::decode` returns `Err` only when the decoded bytes
        // form invalid UTF-8. `%80` is a lone continuation byte — valid
        // percent-encoding, but decoded as a single byte 0x80 which is
        // not a legal UTF-8 start byte. The fallback arm must return the
        // original input unchanged. (Malformed `%`-sequences like
        // `"bad%name"` do NOT trigger this — `urlencoding::decode` is
        // lenient about those and passes the literal `%` through.)
        let input = "%80";
        let out = handler().normalize_name(input);
        assert_eq!(out, input);
    }

    // -- parse_download_path — unscoped ---------------------------------------

    #[test]
    fn parse_unscoped_tarball() {
        let coords = handler()
            .parse_download_path("express/-/express-4.18.2.tgz")
            .unwrap();
        assert_eq!(coords.name, "express");
        assert_eq!(coords.version.as_deref(), Some("4.18.2"));
        assert_eq!(coords.path, "express/-/express-4.18.2.tgz");
        assert_eq!(coords.format, RepositoryFormat::Npm);
    }

    #[test]
    fn parse_unscoped_tarball_with_leading_slash() {
        let coords = handler()
            .parse_download_path("/express/-/express-4.18.2.tgz")
            .unwrap();
        assert_eq!(coords.name, "express");
        assert_eq!(coords.path, "express/-/express-4.18.2.tgz");
    }

    /// Mixed case is rejected at the parse boundary. The npm registry's
    /// case-insensitive uniqueness rule means a mixed-case download URL
    /// is always either an attacker probe or a buggy client. Upload-side
    /// case preservation continues to flow through
    /// [`NpmFormatHandler::normalize_name`] — that path is unaffected.
    #[test]
    fn parse_unscoped_rejects_mixed_case() {
        let err = handler()
            .parse_download_path("MyPackage/-/MyPackage-1.0.0.tgz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn parse_unscoped_prerelease_version() {
        let coords = handler()
            .parse_download_path("pkg/-/pkg-1.0.0-beta.1.tgz")
            .unwrap();
        assert_eq!(coords.version.as_deref(), Some("1.0.0-beta.1"));
    }

    // -- parse_download_path — scoped -----------------------------------------

    #[test]
    fn parse_scoped_tarball() {
        let coords = handler()
            .parse_download_path("@types/node/-/node-20.17.33.tgz")
            .unwrap();
        assert_eq!(coords.name, "@types/node");
        assert_eq!(coords.version.as_deref(), Some("20.17.33"));
        assert_eq!(coords.path, "@types/node/-/node-20.17.33.tgz");
    }

    #[test]
    fn parse_scoped_tarball_with_leading_slash() {
        let coords = handler()
            .parse_download_path("/@types/node/-/node-20.0.0.tgz")
            .unwrap();
        assert_eq!(coords.name, "@types/node");
    }

    // -- build_artifact_logical_path ------------------------------------------

    /// Unscoped: `{name}/-/{name}-{version}.tgz`. `filename` is ignored
    /// (npm derives it from name+version).
    #[test]
    fn build_logical_path_unscoped() {
        assert_eq!(
            handler()
                .build_artifact_logical_path("express", "4.18.2", None)
                .unwrap(),
            "express/-/express-4.18.2.tgz"
        );
    }

    /// Scoped: the filename uses the UNSCOPED basename
    /// (`@scope/pkg/-/pkg-{v}.tgz`) per the npm tarball convention.
    #[test]
    fn build_logical_path_scoped_uses_unscoped_basename() {
        assert_eq!(
            handler()
                .build_artifact_logical_path("@types/node", "20.17.33", None)
                .unwrap(),
            "@types/node/-/node-20.17.33.tgz"
        );
    }

    /// `filename` is ignored for npm — a bogus filename does not change
    /// the derived canonical path.
    #[test]
    fn build_logical_path_ignores_filename() {
        assert_eq!(
            handler()
                .build_artifact_logical_path("express", "4.18.2", Some("garbage.tgz"))
                .unwrap(),
            "express/-/express-4.18.2.tgz"
        );
    }

    /// Round-trip / inverse: for a canonical request path `p`,
    /// `parse_download_path(p).path == p`, and rebuilding from the parsed
    /// (name, version) yields `p`. Structural now that `parse_download_path`
    /// delegates to `build_artifact_logical_path`.
    #[test]
    fn build_logical_path_round_trip_unscoped() {
        let p = "express/-/express-4.18.2.tgz";
        let coords = handler().parse_download_path(p).unwrap();
        assert_eq!(coords.path, p);
        assert_eq!(
            handler()
                .build_artifact_logical_path(&coords.name, coords.version.as_deref().unwrap(), None)
                .unwrap(),
            p
        );
    }

    #[test]
    fn build_logical_path_round_trip_scoped() {
        let p = "@types/node/-/node-20.17.33.tgz";
        let coords = handler().parse_download_path(p).unwrap();
        assert_eq!(coords.path, p);
        assert_eq!(
            handler()
                .build_artifact_logical_path(&coords.name, coords.version.as_deref().unwrap(), None)
                .unwrap(),
            p
        );
    }

    /// npm is case-SENSITIVE (`normalize_name` is decode-only, no folding):
    /// `Foo` and `foo` build DISTINCT paths. Pins that the npm distinction
    /// is preserved (folding would break legacy mixed-case resolution).
    #[test]
    fn build_logical_path_case_sensitive_distinct() {
        let upper = handler()
            .build_artifact_logical_path("Foo", "1.0.0", None)
            .unwrap();
        let lower = handler()
            .build_artifact_logical_path("foo", "1.0.0", None)
            .unwrap();
        assert_eq!(upper, "Foo/-/Foo-1.0.0.tgz");
        assert_eq!(lower, "foo/-/foo-1.0.0.tgz");
        assert_ne!(upper, lower);
    }

    /// npm is case-sensitive and folds no separators, so it needs no
    /// registration-collision check — `collision_key` is `None` and the
    /// publish path skips the gate.
    #[test]
    fn collision_key_is_none() {
        assert_eq!(handler().collision_key("Foo_Bar"), None);
        assert_eq!(handler().collision_key("foo-bar"), None);
    }

    /// Scoped names with any non-lowercase component are rejected at
    /// `parse_download_path` (see [`parse_unscoped_rejects_mixed_case`] for
    /// the rationale).
    #[test]
    fn parse_scoped_rejects_mixed_case_in_any_part() {
        let err = handler()
            .parse_download_path("@MyOrg/MyPkg/-/MyPkg-1.0.0.tgz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    /// Scoped tarball filenames use the **unscoped** basename as the prefix —
    /// the tarball for `@types/node@20.0.0` is `node-20.0.0.tgz`, not
    /// `@types/node-20.0.0.tgz`. Regression guard for a past gotcha.
    #[test]
    fn parse_scoped_filename_uses_unscoped_basename() {
        // A filename with the scope baked in should NOT parse — npm never
        // produces one. This is a negative test that confirms the prefix
        // matching uses the unscoped package name only.
        let err = handler()
            .parse_download_path("@types/node/-/@types-node-20.0.0.tgz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    // -- parse_download_path — invalid ---------------------------------------

    #[test]
    fn parse_missing_dash_segment() {
        let err = handler()
            .parse_download_path("express/express-4.18.2.tgz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    #[test]
    fn parse_wrong_filename_prefix() {
        let err = handler()
            .parse_download_path("express/-/other-4.18.2.tgz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    #[test]
    fn parse_wrong_extension() {
        let err = handler()
            .parse_download_path("express/-/express-4.18.2.zip")
            .unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    #[test]
    fn parse_missing_version_in_filename() {
        // `express-.tgz` has an empty version — extract_version returns None.
        let err = handler()
            .parse_download_path("express/-/express-.tgz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    #[test]
    fn parse_empty_path() {
        let err = handler().parse_download_path("").unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    #[test]
    fn parse_empty_package_name_unscoped() {
        let err = handler()
            .parse_download_path("/-/pkg-1.0.0.tgz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    #[test]
    fn parse_scope_without_at_sign_is_rejected() {
        // Bare `types/node/-/node-1.0.0.tgz` has 4 segments but the first
        // does not start with `@` — it should NOT be treated as scoped.
        // It also doesn't match the 3-segment unscoped shape, so it's invalid.
        let err = handler()
            .parse_download_path("types/node/-/node-1.0.0.tgz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    #[test]
    fn parse_scoped_missing_package_is_rejected() {
        let err = handler()
            .parse_download_path("@types//-/node-1.0.0.tgz")
            .unwrap_err();
        assert!(err.to_string().contains("invalid npm download path"));
    }

    // -- strict path-component validation -----------------------------------
    //
    // npm package-name grammar (mirrors `validate-npm-package-name`):
    //
    //   - lowercase ASCII letters, digits, `-`, `_`, `.`
    //   - first char must NOT be `.` or `_`
    //   - optional `@scope/` prefix where scope follows the same charset
    //   - total length ≤ 214 chars (including `@scope/` prefix)
    //
    // Every deviation returns `DomainError::Validation` carrying the
    // structured `npm.name` field tag. Error messages MUST NOT echo the
    // rejected input (log-pollution risk).

    #[test]
    fn validate_npm_name_rejects_dotdot() {
        let err = validate_npm_name("..").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("npm.name"),
            "must include structured field name: {err}"
        );
    }

    #[test]
    fn validate_npm_name_rejects_mixed_case() {
        let err = validate_npm_name("Foo-Bar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_scoped_with_mixed_case_pkg() {
        let err = validate_npm_name("@scope/Foo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_scoped_with_mixed_case_scope() {
        let err = validate_npm_name("@Scope/foo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_accepts_scoped_lowercase() {
        validate_npm_name("@scope/foo-bar").expect("scoped lowercase OK");
    }

    #[test]
    fn validate_npm_name_accepts_unscoped_lowercase() {
        validate_npm_name("foo-bar").expect("unscoped lowercase OK");
    }

    #[test]
    fn validate_npm_name_accepts_lodash_merge_dot() {
        // `lodash.merge` is a real published package — `.` must be allowed
        // in non-leading positions.
        validate_npm_name("lodash.merge").expect("dot in non-leading position OK");
    }

    #[test]
    fn validate_npm_name_rejects_unicode() {
        let err = validate_npm_name("foö").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_215_chars() {
        let s = "a".repeat(215);
        let err = validate_npm_name(&s).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_accepts_214_char_boundary() {
        let s = "a".repeat(214);
        validate_npm_name(&s).expect("214 chars is the boundary, must accept");
    }

    #[test]
    fn validate_npm_name_rejects_leading_underscore() {
        let err = validate_npm_name("_foo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_leading_dot() {
        let err = validate_npm_name(".foo").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_empty() {
        let err = validate_npm_name("").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_control_byte() {
        let err = validate_npm_name("foo\x00bar").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_scope_without_pkg() {
        let err = validate_npm_name("@scope/").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_at_without_scope() {
        let err = validate_npm_name("@").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn parse_download_path_rejects_dotdot_name() {
        let err = handler()
            .parse_download_path("../-/..-1.0.0.tgz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_download_path_rejects_mixed_case_unscoped() {
        // Note: `parse_unscoped_preserves_case` documented case preservation
        // for upload-side ingestion (`MyPackage`); for the strict
        // download-path grammar we now require lowercase, matching the npm
        // registry's case-insensitive uniqueness rule.
        let err = handler()
            .parse_download_path("MyPackage/-/MyPackage-1.0.0.tgz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    #[test]
    fn parse_download_path_rejects_mixed_case_scoped() {
        let err = handler()
            .parse_download_path("@types/Foo/-/Foo-1.0.0.tgz")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("npm.name"));
    }

    // -- metadata_expected_max_bytes -----------------------------------------

    #[test]
    fn metadata_expected_max_bytes_is_5_mb() {
        // Raised from 256 KB to 5 MB so the cap check does not pre-empt
        // the HashReference split-decision for real-world long-tail
        // packuments (observed max 1.37 MB against p99 ~141 KB).
        assert_eq!(handler().metadata_expected_max_bytes(), 5 * 1024 * 1024);
    }

    // -- metadata_strategy ----------------------------------------------------

    #[test]
    fn metadata_strategy_is_hash_reference_with_256_kb_threshold() {
        // npm is the sole Phase-A format that flips to HashReference.
        // The 256 KB threshold is distinct from the 5 MB max-bytes cap
        // above: max-bytes gates the whole payload, threshold decides
        // inline-vs-split.
        assert_eq!(
            handler().metadata_strategy(),
            MetadataStrategy::HashReference {
                inline_threshold_bytes: 256 * 1024,
            }
        );
    }

    // -- extract_metadata_summary --------------------------------------------

    #[test]
    fn extract_metadata_summary_keeps_only_locked_seven_keys() {
        // Full realistic-ish packument entry. Non-summary keys
        // (readme, description, keywords, bin, scripts, _id, _from,
        // author, maintainers) MUST NOT appear in the output.
        let full = serde_json::json!({
            "name": "express",
            "version": "4.18.2",
            "dist": { "tarball": "https://example/e-4.18.2.tgz", "shasum": "abc" },
            "dependencies":     { "body-parser": "^1.20" },
            "devDependencies":  { "mocha":       "^10"   },
            "peerDependencies": { "node":        ">=14"  },
            "engines":          { "node": ">=14" },
            // Everything below stays in the blob:
            "readme":      "very long prose",
            "description": "Fast, unopinionated, minimalist web framework",
            "keywords":    ["web", "framework"],
            "bin":         { "express": "./bin/express.js" },
            "scripts":     { "test": "mocha" },
            "_id":         "express@4.18.2",
            "_from":       "express@*",
            "author":      "TJ Holowaychuk",
            "maintainers": [],
        });

        let out = handler().extract_metadata_summary(&full);
        let obj = out.as_object().expect("summary must be an object");

        // Exactly the seven locked keys — as a set. Output-key order
        // is `serde_json::Map`'s concern (alphabetical without the
        // `preserve_order` feature, which this workspace does not
        // enable); the contract is "these keys, no others".
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = vec![
            "name",
            "version",
            "dist",
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "engines",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);

        // Values copied through verbatim.
        assert_eq!(obj["name"], "express");
        assert_eq!(obj["version"], "4.18.2");
        assert_eq!(
            obj["dist"],
            serde_json::json!({ "tarball": "https://example/e-4.18.2.tgz", "shasum": "abc" })
        );

        // Non-summary keys MUST NOT appear.
        for forbidden in [
            "readme",
            "description",
            "keywords",
            "bin",
            "scripts",
            "_id",
            "_from",
            "author",
            "maintainers",
        ] {
            assert!(
                !obj.contains_key(forbidden),
                "non-summary key {forbidden} leaked into summary"
            );
        }
    }

    #[test]
    fn extract_metadata_summary_omits_missing_keys_rather_than_nulling_them() {
        // Realistic scoped-package block often lacks peerDependencies,
        // devDependencies, engines. Missing keys must NOT appear at all
        // — NOT `"peerDependencies": null`. Summary-only consumers rely
        // on key-presence semantics.
        let full = serde_json::json!({
            "name":         "@types/node",
            "version":      "20.0.0",
            "dist":         { "tarball": "u", "shasum": "s" },
            "dependencies": {},
            // devDependencies, peerDependencies, engines all absent.
        });

        let out = handler().extract_metadata_summary(&full);
        let obj = out.as_object().unwrap();

        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("version"));
        assert!(obj.contains_key("dist"));
        assert!(obj.contains_key("dependencies"));
        assert!(
            !obj.contains_key("devDependencies"),
            "missing key must be absent, NOT null"
        );
        assert!(!obj.contains_key("peerDependencies"));
        assert!(!obj.contains_key("engines"));
    }

    #[test]
    fn extract_metadata_summary_returns_null_for_non_object_input() {
        // Defensive branch: if the ingest site somehow produced a
        // non-object payload (Value::Null, a bare string, a number,
        // an array) the handler returns Value::Null rather than
        // panicking or unwrapping into a broken shape. Summary-only
        // consumers see "no data"; full-payload consumers still follow
        // the blob.
        assert_eq!(
            handler().extract_metadata_summary(&serde_json::Value::Null),
            serde_json::Value::Null
        );
        assert_eq!(
            handler().extract_metadata_summary(&serde_json::json!("a string")),
            serde_json::Value::Null
        );
        assert_eq!(
            handler().extract_metadata_summary(&serde_json::json!(42)),
            serde_json::Value::Null
        );
        assert_eq!(
            handler().extract_metadata_summary(&serde_json::json!([1, 2, 3])),
            serde_json::Value::Null
        );
    }

    #[test]
    fn extract_metadata_summary_empty_object_yields_empty_object() {
        // Edge case: an object with none of the seven keys present
        // yields an empty object, NOT Value::Null. This is deliberate
        // — `full` was a well-formed object, just an empty one;
        // Value::Null is reserved for the non-object defensive branch.
        let out = handler().extract_metadata_summary(&serde_json::json!({}));
        assert_eq!(out, serde_json::json!({}));
    }

    // -- upstream_checksum_metadata_path (see ADR 0006 §11) -----------------

    fn coords_for(name: &str, version: Option<&str>, path: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: version.map(str::to_string),
            path: path.to_string(),
            format: RepositoryFormat::Npm,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn upstream_checksum_metadata_path_unscoped() {
        // Plain unscoped name — the path is just `/{name}`.
        let coords = coords_for("express", Some("4.18.2"), "express/-/express-4.18.2.tgz");
        assert_eq!(
            handler().upstream_checksum_metadata_path(&coords),
            Some("/express".to_string())
        );
    }

    #[test]
    fn upstream_checksum_metadata_path_scoped_encodes_slash_as_percent_2f_lowercase() {
        // Scoped names: `@types/node` → `/@types%2fnode`. The `@` stays
        // unescaped (npm registry convention); only the `/` between the
        // scope and the name URL-encodes — to lowercase `%2f` per the
        // npm registry convention. Regression guard.
        let coords = coords_for(
            "@types/node",
            Some("20.0.0"),
            "@types/node/-/node-20.0.0.tgz",
        );
        assert_eq!(
            handler().upstream_checksum_metadata_path(&coords),
            Some("/@types%2fnode".to_string())
        );
    }

    // -- parse_upstream_checksum ---------------------------------------------

    #[test]
    fn parse_upstream_checksum_malformed_body_returns_validation_error() {
        // Body is not JSON at all → Validation.
        let body = b"not valid json {{{";
        let coords = coords_for("anything", Some("1.0.0"), "anything/-/anything-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("not valid JSON"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_no_versions_object_returns_validation_error() {
        // Well-formed JSON but no `versions` key at all → Validation.
        let body = br#"{"name":"empty","dist-tags":{}}"#;
        let coords = coords_for("empty", Some("1.0.0"), "empty/-/empty-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("no versions object"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_versions_not_object_returns_validation_error() {
        // `versions` exists but is not an object — same error as missing.
        let body = br#"{"name":"empty","versions":["not","an","object"]}"#;
        let coords = coords_for("empty", Some("1.0.0"), "empty/-/empty-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("no versions object"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_missing_version_returns_validation_error() {
        // versions object is present but the requested version is not.
        let body = br#"{"versions":{"1.0.0":{"dist":{"integrity":"sha512-x"}}}}"#;
        let coords = coords_for("pkg", Some("9.9.9"), "pkg/-/pkg-9.9.9.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        // Message must quote the requested version.
        assert!(
            err.to_string().contains("9.9.9"),
            "unexpected message: {err}"
        );
        assert!(
            err.to_string().contains("no version"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_missing_version_in_coords_returns_validation_error() {
        // Defensive: caller bug where coords.version is None.
        let body = br#"{"versions":{}}"#;
        let coords = coords_for("pkg", None, "pkg/-/pkg-1.0.0.tgz");
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
    fn parse_upstream_checksum_legacy_no_integrity_returns_validation_error() {
        // Synthesised packument with `dist.shasum` but NO `dist.integrity`.
        // SHA-1 fallback is collision-broken; this validates we reject it.
        let body = include_bytes!("../tests/fixtures/npm/legacy_no_integrity.packument.json");
        let coords = coords_for(
            "legacy-pkg",
            Some("0.0.1"),
            "legacy-pkg/-/legacy-pkg-0.0.1.tgz",
        );
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("legacy-pkg@0.0.1"),
            "message must quote name@version: {err}"
        );
        assert!(
            err.to_string().contains("publishes no dist.integrity"),
            "unexpected message: {err}"
        );
        assert!(
            err.to_string()
                .contains("SHA-1 dist.shasum fallback is not accepted"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_dist_present_but_integrity_missing_returns_validation_error() {
        // Belt-and-braces: a `dist` block exists but no `integrity` field
        // at all (no `shasum` either) — same legacy-style rejection.
        let body = br#"{"versions":{"1.0.0":{"dist":{"tarball":"https://x/y.tgz"}}}}"#;
        let coords = coords_for("pkg", Some("1.0.0"), "pkg/-/pkg-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("publishes no dist.integrity"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_dist_missing_entirely_returns_validation_error() {
        // No `dist` block at all on the version entry — same legacy-style
        // rejection (the `and_then` chain short-circuits at the missing
        // `dist`, but the resulting message is the no-integrity one
        // because that is the user-meaningful failure mode).
        let body = br#"{"versions":{"1.0.0":{"name":"pkg"}}}"#;
        let coords = coords_for("pkg", Some("1.0.0"), "pkg/-/pkg-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("publishes no dist.integrity"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_wrong_algorithm_only_returns_validation_error() {
        // `dist.integrity` is present but only carries `sha384-...` — no
        // sha512 entry, so the parser must reject. Modern npm publishes
        // sha512; sha256/sha384-only packuments do not exist on
        // registry.npmjs.org but defensively reject.
        let body = include_bytes!("../tests/fixtures/npm/wrong_algo_integrity.packument.json");
        let coords = coords_for(
            "wrong-algo-pkg",
            Some("1.0.0"),
            "wrong-algo-pkg/-/wrong-algo-pkg-1.0.0.tgz",
        );
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("malformed"),
            "unexpected message: {err}"
        );
        assert!(
            err.to_string().contains("no sha512 entry"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_empty_integrity_returns_validation_error() {
        // dist.integrity is the empty string. The split loop produces
        // no entries; the no-sha512 fallback fires.
        let body = br#"{"versions":{"1.0.0":{"dist":{"integrity":""}}}}"#;
        let coords = coords_for("pkg", Some("1.0.0"), "pkg/-/pkg-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("no sha512 entry"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_sri_entry_without_dash_separator_is_skipped() {
        // An SRI entry with no `-` is not a valid <alg>-<base64> shape
        // and is skipped (split_once returns None). When followed by no
        // valid sha512 entry, the no-sha512 fallback fires. Covers the
        // `Some((alg, b64)) else continue` branch of decode_sha512_sri.
        let body = br#"{"versions":{"1.0.0":{"dist":{"integrity":"garbage_no_dash"}}}}"#;
        let coords = coords_for("pkg", Some("1.0.0"), "pkg/-/pkg-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("no sha512 entry"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_invalid_base64_returns_validation_error() {
        // sha512- with garbage that is not valid base64 at all (illegal
        // characters in the standard alphabet). Synthesised inline so
        // the failure mode is obvious from reading the test.
        let body = br#"{"versions":{"1.0.0":{"dist":{"integrity":"sha512-!!!notbase64!!!"}}}}"#;
        let coords = coords_for("pkg", Some("1.0.0"), "pkg/-/pkg-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("base64 decode failed"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_truncated_base64_returns_validation_error() {
        // Synthesised packument with sha512-<base64> where the base64
        // decodes to 32 bytes instead of 64 — must reject as wrong
        // length. The 64-byte invariant is load-bearing for the
        // SHA-512 verification pipeline.
        let body = include_bytes!("../tests/fixtures/npm/truncated_base64.packument.json");
        let coords = coords_for(
            "truncated-pkg",
            Some("1.0.0"),
            "truncated-pkg/-/truncated-pkg-1.0.0.tgz",
        );
        let err = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("malformed"),
            "unexpected message: {err}"
        );
        assert!(
            err.to_string().contains("32 bytes") && err.to_string().contains("expected 64"),
            "decoded-length error must quote actual and expected: {err}"
        );
    }

    /// SHA-512 of the deterministic synthesised payload that is
    /// base64-encoded into `multi_algo_integrity.packument.json`. Generated
    /// by `python3 -c "import hashlib, base64; print(hashlib.sha512(b'npm-fixture-sha512').hexdigest())"`.
    const MULTI_ALGO_SHA512_HEX: &str =
        "0e98d13012a34bec77293eaef4ac9e7996f3b8bb4848076b432308d4c02773afdf08a0dee03f145064cc0055c903a46f9054fc033ef08e2c5216999b42fb8f5d";

    /// SHA-512 of the express@4.18.2 tarball, decoded from the
    /// real packument's `dist.integrity` value
    /// (`sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ==`).
    const EXPRESS_4_18_2_SHA512_HEX: &str =
        "e7f3ec2fa8863dd7d0fe528cd54ba27a5620bf7054a097f3d5a53053dbc767e27b832bf07505c510120421ac5e19fd0621cade013372044c6d6a58ac0dbb8ca9";

    #[test]
    fn parse_upstream_checksum_real_express_packument_happy_path() {
        // Real packument captured from registry.npmjs.org. The decoded
        // SHA-512 hex is the value the verification pipeline will
        // compare a fetched tarball against.
        let body = include_bytes!("../tests/fixtures/npm/express_4.18.2.packument.json");
        let coords = coords_for("express", Some("4.18.2"), "express/-/express-4.18.2.tgz");
        let cs = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha512);
        assert_eq!(cs.hex(), EXPRESS_4_18_2_SHA512_HEX);
    }

    #[test]
    fn parse_upstream_checksum_real_express_packument_resolves_other_version() {
        // Same fixture, different version — confirms `versions[ver]` is
        // honoured (not just "first version wins"). Picked an
        // intentionally older version that is also in the packument.
        let body = include_bytes!("../tests/fixtures/npm/express_4.18.2.packument.json");
        let coords = coords_for("express", Some("4.0.0"), "express/-/express-4.0.0.tgz");
        let cs = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap();
        // Length-only assertion — we just need to confirm a different
        // sha512 came out, not encode the exact value (which would be
        // a duplicate of the express@4.0.0 integrity-decoded hex; the
        // happy-path assertion above already proves the decoding logic).
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha512);
        assert_eq!(cs.hex().len(), 128);
        assert_ne!(cs.hex(), EXPRESS_4_18_2_SHA512_HEX);
    }

    // -- extract_upstream_tarball_url ----------------------------------------
    //
    /// Cap used by `extract_upstream_tarball_url` tests. Matches
    /// `NpmFormatHandler::metadata_expected_max_bytes()`; declared as a
    /// constant so the boundary tests below stay legible. The tests for
    /// the size gate use the live `metadata_expected_max_bytes()`
    /// value to exercise the contract.
    const NPM_TEST_MAX: usize = 5 * 1024 * 1024;

    #[test]
    fn extract_upstream_tarball_url_happy_path() {
        let body = include_bytes!("../tests/fixtures/npm/express_4.18.2.packument.json");
        let url = extract_upstream_tarball_url(body, "4.18.2", NPM_TEST_MAX).unwrap();
        assert!(
            url.starts_with("https://"),
            "tarball url must be https: {url}"
        );
        assert!(
            url.ends_with("express-4.18.2.tgz"),
            "tarball url must point at the version-stamped tgz: {url}"
        );
    }

    #[test]
    fn extract_upstream_tarball_url_unknown_version_returns_validation_error() {
        let body = include_bytes!("../tests/fixtures/npm/express_4.18.2.packument.json");
        let err = extract_upstream_tarball_url(body, "99.99.99", NPM_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("99.99.99"),
            "message must quote the missing version: {err}"
        );
        assert!(
            err.to_string().contains("no version"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_tarball_url_missing_dist_tarball_returns_validation_error() {
        // Synthesised packument where versions["1.0.0"].dist exists but lacks
        // the `tarball` field. Belt-and-braces against malformed upstream
        // metadata.
        let body = br#"{"versions":{"1.0.0":{"dist":{"shasum":"abc"}}}}"#;
        let err = extract_upstream_tarball_url(body, "1.0.0", NPM_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("dist.tarball"),
            "unexpected message: {err}"
        );
        assert!(
            err.to_string().contains("1.0.0"),
            "message must quote the version: {err}"
        );
    }

    #[test]
    fn extract_upstream_tarball_url_non_https_returns_validation_error() {
        // Downgrade-attack guard: any scheme other than https must be rejected
        // even if the rest of the packument shape is well-formed.
        let body = br#"{"versions":{"1.0.0":{"dist":{"tarball":"http://evil.example/foo.tgz"}}}}"#;
        let err = extract_upstream_tarball_url(body, "1.0.0", NPM_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("https"),
            "message must mention https: {err}"
        );
    }

    #[test]
    fn extract_upstream_tarball_url_invalid_json_returns_validation_error() {
        let err = extract_upstream_tarball_url(b"not json", "1.0.0", NPM_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("not valid JSON"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn extract_upstream_tarball_url_no_versions_object_returns_validation_error() {
        // Body parses as JSON but has no `versions` key at all. The error
        // message must be distinguishable from the unknown-version case so
        // operators can tell a malformed packument apart from a missing
        // version pin.
        let body = br#"{"name":"x"}"#;
        let err = extract_upstream_tarball_url(body, "1.0.0", NPM_TEST_MAX).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("no versions object"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_upstream_checksum_multi_algo_picks_sha512() {
        // SRI: `sha512-... sha384-...`. The parser must pick the sha512
        // entry and ignore the sha384 entry. The fixture's sha512 base64
        // decodes to the deterministic 64-byte
        // `sha512(b"npm-fixture-sha512")` value (see fixture comment).
        let body = include_bytes!("../tests/fixtures/npm/multi_algo_integrity.packument.json");
        let coords = coords_for(
            "multi-algo-pkg",
            Some("1.0.0"),
            "multi-algo-pkg/-/multi-algo-pkg-1.0.0.tgz",
        );
        let cs = handler()
            .parse_upstream_checksum(&mut std::io::Cursor::new(body), &coords)
            .unwrap();
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha512);
        assert_eq!(cs.hex(), MULTI_ALGO_SHA512_HEX);
    }

    // -- size caps (see ADR 0026 for the cap taxonomy) -----------------------
    //
    // Two ceilings apply:
    //
    //   - the STREAMING `parse_upstream_checksum` projects the body through
    //     a counting reader, so its ceiling is the plausibility / storage
    //     bound `STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES` (64 MiB).
    //     Tests exercise that boundary via a LAZY reader (no 64 MiB
    //     allocation).
    //   - the BUFFERED `extract_upstream_tarball_url` free function reads
    //     `&[u8]` fully, so it keeps the small in-memory
    //     `metadata_expected_max_bytes()` ceiling (npm's 5 MiB).
    //
    // The pair (size cap + serde_json's default recursion limit of 128)
    // bounds both INPUT SIZE and PARSE-TREE DEPTH.

    /// Build a valid npm packument body for `version` padded to exactly
    /// `target_len` bytes by inserting whitespace inside the document.
    /// Whitespace between JSON tokens is legal per RFC 8259 §2 — the
    /// padded body must still parse.
    ///
    /// The `dist.integrity` carries a sha512 of 64 zero-bytes
    /// (deterministic — `decode_sha512_sri` only checks length, not value).
    fn npm_padded_body(version: &str, target_len: usize) -> Vec<u8> {
        // base64("\0" * 64) — 64 zero-bytes — produces exactly 88 base64 chars.
        let zero_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let core = format!(
            r#"{{"versions":{{"{version}":{{"dist":{{"integrity":"sha512-{zero_b64}","tarball":"https://example.com/x-{version}.tgz"}}}}}}}}"#
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

    /// Lazy reader of a valid npm packument for `version` padded with
    /// whitespace to exactly `target_len` bytes, WITHOUT materialising the
    /// padding. Mirrors [`npm_padded_body`] (whitespace inserted right
    /// after the leading `{`, legal per RFC 8259 §2) but streams the
    /// padding from [`std::io::repeat`], so the streaming-cap tests can
    /// exercise the 64 MiB plausibility boundary without a 64 MiB
    /// allocation.
    fn npm_lazy_padded_reader(version: &str, target_len: usize) -> impl std::io::Read {
        let zero_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let core = format!(
            r#"{{"versions":{{"{version}":{{"dist":{{"integrity":"sha512-{zero_b64}","tarball":"https://example.com/x-{version}.tgz"}}}}}}}}"#
        );
        assert!(
            core.len() <= target_len,
            "core body ({} bytes) exceeds target ({})",
            core.len(),
            target_len
        );
        let pad = (target_len - core.len()) as u64;
        // `{` + whitespace pad + the rest of `core` (everything after `{`).
        let head = std::io::Cursor::new(vec![b'{']);
        let tail = std::io::Cursor::new(core.as_bytes()[1..].to_vec());
        std::io::Read::chain(
            std::io::Read::chain(head, std::io::Read::take(std::io::repeat(b' '), pad)),
            tail,
        )
    }

    #[test]
    fn parse_upstream_checksum_rejects_body_one_byte_over_cap() {
        // Streaming method → ceiling is the plausibility bound (64 MiB).
        // Lazy reader avoids a ~64 MiB allocation.
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let mut body = npm_lazy_padded_reader("1.0.0", max + 1);
        let coords = coords_for("pkg", Some("1.0.0"), "pkg/-/pkg-1.0.0.tgz");
        let err = handler()
            .parse_upstream_checksum(&mut body, &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("upstream metadata body is")
                && msg.contains(&(max + 1).to_string())
                && msg.contains(&max.to_string())
                && msg.contains("streaming plausibility max is"),
            "size diagnostic missing: {msg}"
        );
    }

    #[test]
    fn parse_upstream_checksum_accepts_body_at_cap_boundary() {
        // Body sized exactly at the streaming plausibility cap parses
        // normally — the size gate must use `>` not `>=` so the boundary
        // admits. Lazy reader avoids a ~64 MiB allocation.
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let mut body = npm_lazy_padded_reader("1.0.0", max);
        let coords = coords_for("pkg", Some("1.0.0"), "pkg/-/pkg-1.0.0.tgz");
        let cs = handler()
            .parse_upstream_checksum(&mut body, &coords)
            .expect("at-cap body must parse");
        assert_eq!(cs.algorithm(), HashAlgorithm::Sha512);
    }

    #[test]
    fn extract_upstream_tarball_url_rejects_body_one_byte_over_cap() {
        // The free function gains an explicit `max_bytes` parameter
        // because it has no `&self` to read from the handler.
        let max = NpmFormatHandler.metadata_expected_max_bytes();
        let body = npm_padded_body("1.0.0", max + 1);
        let err = extract_upstream_tarball_url(&body, "1.0.0", max).unwrap_err();
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
    fn extract_upstream_tarball_url_accepts_body_at_cap_boundary() {
        let max = NpmFormatHandler.metadata_expected_max_bytes();
        let body = npm_padded_body("1.0.0", max);
        let url =
            extract_upstream_tarball_url(&body, "1.0.0", max).expect("at-cap body must parse");
        assert_eq!(url, "https://example.com/x-1.0.0.tgz");
    }

    // -- extract_sbom ---------------------------------------------------------

    use hort_domain::types::{Ecosystem, PayloadAccess};

    fn sbom_coords(name: &str, version: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: Some(version.to_string()),
            path: format!("{name}/-/{name}-{version}.tgz"),
            format: RepositoryFormat::Npm,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn extract_sbom_npm_happy_path_three_dependency_kinds() {
        // Per-version packument entry as the npm registry returns it.
        // Direct deps (`dependencies`, `peerDependencies`,
        // `optionalDependencies`) are tagged direct=true; `devDependencies`
        // are tagged direct=false (they don't ride into the artifact at
        // install time).
        let metadata = serde_json::json!({
            "name": "myapp",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "~4.18.2"
            },
            "devDependencies": {
                "jest": "^29.0.0"
            },
            "peerDependencies": {
                "react": "^18.0.0"
            }
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("extract_sbom must succeed")
            .expect("npm handler must return Some(Sbom) for a packument");
        assert_eq!(sbom.components.len(), 4);

        // dependencies → direct=true, version stripped
        let lodash = sbom
            .components
            .iter()
            .find(|c| c.name == "lodash")
            .expect("lodash present");
        assert_eq!(lodash.purl, "pkg:npm/lodash@4.17.21");
        assert_eq!(lodash.version.as_deref(), Some("4.17.21"));
        assert_eq!(lodash.ecosystem, Ecosystem::Npm);
        assert!(lodash.direct_dependency);
        assert_eq!(lodash.licenses, vec!["MIT".to_string()]);

        let express = sbom
            .components
            .iter()
            .find(|c| c.name == "express")
            .expect("express present");
        assert_eq!(express.purl, "pkg:npm/express@4.18.2");
        assert!(express.direct_dependency);

        // devDependencies → direct=false
        let jest = sbom
            .components
            .iter()
            .find(|c| c.name == "jest")
            .expect("jest present");
        assert!(!jest.direct_dependency);
        assert_eq!(jest.purl, "pkg:npm/jest@29.0.0");

        // peerDependencies → direct=true
        let react = sbom
            .components
            .iter()
            .find(|c| c.name == "react")
            .expect("react present");
        assert!(react.direct_dependency);
        assert_eq!(react.purl, "pkg:npm/react@18.0.0");
    }

    /// `extract_sbom` MUST populate `Sbom::subject` from `ArtifactCoords`
    /// so the artifact itself is in the BOM. Without this, leaf packages
    /// (no manifest-declared dependencies) produced an
    /// `Sbom { components: vec![] }`, `build_cyclonedx_json` rendered
    /// `{components: []}`, and osv-scanner found 0 packages.
    /// lodash@4.17.20 is the canonical repro — a leaf npm package that
    /// has CVE-2021-23337.
    #[test]
    fn extract_sbom_npm_leaf_package_populates_subject_from_coords() {
        // Manifest with NO dependencies — exactly what the npm registry
        // returns for `lodash@4.17.20`.
        let metadata = serde_json::json!({
            "name": "lodash",
            "version": "4.17.20",
            "license": "MIT"
        });
        let coords = sbom_coords("lodash", "4.17.20");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("extract_sbom must succeed")
            .expect("npm handler must return Some(Sbom)");

        let subject = sbom
            .subject
            .as_ref()
            .expect("subject must be populated for a known npm artifact");
        assert_eq!(subject.purl, "pkg:npm/lodash@4.17.20");
        assert_eq!(subject.name, "lodash");
        assert_eq!(subject.version.as_deref(), Some("4.17.20"));
        assert_eq!(subject.ecosystem, Ecosystem::Npm);
        assert_eq!(subject.licenses, vec!["MIT".to_string()]);

        // Leaf package — components is empty, but the subject carries
        // lodash forward to osv-scanner.
        assert!(
            sbom.components.is_empty(),
            "lodash@4.17.20 has no deps; components must be empty: {:?}",
            sbom.components
        );
    }

    /// When the manifest is absent / null (e.g. a proxied pull that never
    /// parsed a `package.json`), the subject still comes from `coords` and
    /// the SBOM is non-empty.
    #[test]
    fn extract_sbom_npm_null_metadata_still_populates_subject_from_coords() {
        let coords = sbom_coords("lodash", "4.17.20");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &serde_json::Value::Null, payload)
            .expect("extract_sbom must succeed")
            .expect("npm handler must return Some(Sbom)");

        let subject = sbom
            .subject
            .as_ref()
            .expect("subject must be populated even when metadata is Null");
        assert_eq!(subject.purl, "pkg:npm/lodash@4.17.20");
        assert!(subject.licenses.is_empty());
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn extract_sbom_npm_empty_manifest_returns_some_with_empty_components() {
        // The manifest exists but has no dependency keys → Some(Sbom { vec![] }).
        // Distinct from None (which would mean the format is opaque).
        let metadata = serde_json::json!({});
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("extract_sbom must succeed")
            .expect("empty manifest still yields Some(Sbom)");
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn extract_sbom_npm_non_object_metadata_returns_some_with_empty_components() {
        // Defensive — handler must not panic on Value::Null.
        let metadata = serde_json::Value::Null;
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("extract_sbom must succeed")
            .expect("Value::Null still yields Some(Sbom)");
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn extract_sbom_npm_dependency_with_no_version_omits_version_suffix() {
        // npm allows dependencies whose value is `null` or non-string
        // (e.g. `{"foo": {"version": "1.0"}}` style — git/url specs).
        // When we cannot recover a version string, the PURL has no
        // `@version` suffix and `version` is None.
        let metadata = serde_json::json!({
            "dependencies": {
                "oddball": null,
                "fromgit": { "version": "git+https://example.com/foo.git" },
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("extract_sbom must succeed")
            .expect("Some");
        let oddball = sbom
            .components
            .iter()
            .find(|c| c.name == "oddball")
            .expect("oddball present");
        assert_eq!(oddball.purl, "pkg:npm/oddball");
        assert!(oddball.version.is_none());
    }

    #[test]
    fn extract_sbom_npm_scoped_name_uses_percent_encoded_at() {
        // PURL spec for npm: scoped names encode `@` as `%40` and keep
        // the `/` literal — `pkg:npm/%40foo/bar@1.0.0`.
        let metadata = serde_json::json!({
            "dependencies": {
                "@scope/pkg": "1.0.0",
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("extract_sbom must succeed")
            .expect("Some");
        assert_eq!(sbom.components.len(), 1);
        let scoped = &sbom.components[0];
        assert_eq!(scoped.name, "@scope/pkg");
        assert_eq!(scoped.purl, "pkg:npm/%40scope/pkg@1.0.0");
        assert_eq!(scoped.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn extract_sbom_npm_license_object_form_is_extracted() {
        // npm publishes either string `"MIT"` or legacy object `{type:"MIT"}`.
        let metadata = serde_json::json!({
            "license": { "type": "Apache-2.0" },
            "dependencies": {
                "foo": "1.0.0",
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert_eq!(sbom.components[0].licenses, vec!["Apache-2.0".to_string()]);
    }

    #[test]
    fn extract_sbom_npm_missing_license_field_yields_empty_license_list() {
        let metadata = serde_json::json!({
            "dependencies": { "foo": "1.0.0" },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        assert!(sbom.components[0].licenses.is_empty());
    }

    #[test]
    fn extract_sbom_npm_strips_caret_and_tilde_constraints() {
        let metadata = serde_json::json!({
            "dependencies": {
                "with-caret": "^1.2.3",
                "with-tilde": "~2.3.4",
                "exact": "3.4.5",
            },
        });
        let coords = sbom_coords("myapp", "1.0.0");
        let payload = PayloadAccess::Bytes(b"");

        let sbom = NpmFormatHandler
            .extract_sbom(&coords, &metadata, payload)
            .expect("Some")
            .expect("Some");
        let by_name = |n: &str| {
            sbom.components
                .iter()
                .find(|c| c.name == n)
                .map(|c| (c.purl.clone(), c.version.clone()))
                .unwrap()
        };
        assert_eq!(
            by_name("with-caret"),
            ("pkg:npm/with-caret@1.2.3".to_string(), Some("1.2.3".into()))
        );
        assert_eq!(
            by_name("with-tilde"),
            ("pkg:npm/with-tilde@2.3.4".to_string(), Some("2.3.4".into()))
        );
        assert_eq!(
            by_name("exact"),
            ("pkg:npm/exact@3.4.5".to_string(), Some("3.4.5".into()))
        );
    }

    // -- upstream_metadata_path ---------------------------------------------

    #[test]
    fn upstream_metadata_path_npm_unscoped_returns_root_slash_name() {
        // npm packument is `/<url-encoded-name>` — version-agnostic.
        // Coincides with `upstream_checksum_metadata_path` because the
        // packument carries both the version-set and dist.integrity.
        assert_eq!(
            handler().upstream_metadata_path("express"),
            Some("/express".to_string()),
        );
    }

    #[test]
    fn upstream_metadata_path_npm_scoped_encodes_slash_as_percent_2f() {
        // Scoped packages (`@scope/name`) require `/` → `%2f` per npm
        // registry API. Mirrors the existing
        // `upstream_checksum_metadata_path_scoped_encodes_slash_as_percent_2f_lowercase`
        // shape — same helper (`url_encode_npm_name`) underneath.
        let path = handler()
            .upstream_metadata_path("@scope/pkg")
            .expect("Some");
        assert!(
            path.contains("%2f") || path.contains("%2F"),
            "scoped path must percent-encode the slash; got {path}"
        );
    }

    #[test]
    fn upstream_metadata_accept_npm_inherits_trait_default_empty() {
        // npm needs no content negotiation — the upstream's default
        // packument representation (JSON) is the only one. Inherits
        // the trait default `Vec::new()`. Regression guard: if a
        // future override emits non-empty here, the prefetch-tick path
        // would start sending an Accept header that npm registries
        // would either ignore (best case) or 406 (worst case).
        assert!(handler().upstream_metadata_accept().is_empty());
    }

    // -- extract_upstream_versions ------------------------------------------

    #[test]
    fn extract_upstream_versions_npm_reads_versions_object_keys() {
        let body = br#"{
            "name": "express",
            "versions": {
                "1.0.0": {"dist": {"integrity": "sha512-x"}},
                "1.1.0": {"dist": {"integrity": "sha512-y"}},
                "2.0.0-beta.1": {"dist": {"integrity": "sha512-z"}}
            }
        }"#;
        let vs = handler()
            .extract_upstream_versions(&mut std::io::Cursor::new(body))
            .expect("Ok");
        assert!(vs.contains(&"1.0.0".to_string()));
        assert!(vs.contains(&"1.1.0".to_string()));
        assert!(vs.contains(&"2.0.0-beta.1".to_string()));
        assert_eq!(vs.len(), 3);
    }

    #[test]
    fn extract_upstream_versions_npm_malformed_body_returns_empty_vec() {
        // Hot-path policy: a malformed upstream is transient; the
        // tick degrades to "no signal" rather than failing the walk.
        let vs = handler()
            .extract_upstream_versions(&mut std::io::Cursor::new(b"<<not json>>"))
            .expect("Ok");
        assert!(vs.is_empty());
    }

    #[test]
    fn extract_upstream_versions_npm_no_versions_key_returns_empty_vec() {
        let body = br#"{"name":"empty","dist-tags":{}}"#;
        let vs = handler()
            .extract_upstream_versions(&mut std::io::Cursor::new(body))
            .expect("Ok");
        assert!(vs.is_empty());
    }

    #[test]
    fn extract_upstream_versions_npm_versions_not_object_returns_empty_vec() {
        let body = br#"{"name":"x","versions":["bogus","array"]}"#;
        let vs = handler()
            .extract_upstream_versions(&mut std::io::Cursor::new(body))
            .expect("Ok");
        assert!(vs.is_empty());
    }

    #[test]
    fn extract_upstream_versions_npm_over_cap_returns_validation_error() {
        // Streaming method → ceiling is the plausibility bound (64 MiB).
        // A `max + 1` body that is BOTH malformed (all `a`) AND over-cap
        // must surface the cap `Validation` error (not degrade to empty).
        // Lazy reader avoids a ~64 MiB allocation.
        let max = crate::stream_helpers::STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES;
        let mut body = std::io::Read::take(std::io::repeat(b'a'), max as u64 + 1);
        let err = handler().extract_upstream_versions(&mut body).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- extract_dependency_specs -------------------------------------------
    //
    // `extract_dependency_specs` is fed the *stored `.tgz` artifact* (the
    // cascade hands it `read_artifact_bytes`, a gzip tarball, not a
    // pre-selected manifest). The archive-shape tests below build a real
    // `.tgz` and assert the trait method locates `package/package.json`
    // inside it. The pure JSON parse logic is unit tested directly against
    // the private `parse_npm_runtime_dependencies` fn further down (those
    // tests do NOT go through the archive layer).

    /// Build a minimal npm `.tgz` (gzip-tar) in memory from `(name, body)`
    /// entries, in order. The npm convention is that the package tree is
    /// rooted at `package/`, so the manifest lives at `package/package.json`.
    /// The manifest MUST be placed as an EARLY entry — the cumulative
    /// decompressed-output cap aborts the scan before any entry ordered
    /// after >cap decompressed bytes.
    fn make_npm_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("make_npm_tgz: set_path");
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append(&header, *body)
                .expect("make_npm_tgz: append entry");
        }
        let gz = builder.into_inner().expect("make_npm_tgz: finish tar");
        gz.finish().expect("make_npm_tgz: finish gzip")
    }

    /// Feeding the trait method a real `.tgz` (the stored artifact, as the
    /// cascade does) must locate `package/package.json` INSIDE the tarball
    /// and return ONLY the runtime deps — never `devDependencies`.
    #[test]
    fn extract_dependency_specs_npm_from_tgz_returns_only_runtime_deps() {
        let manifest = br#"{
            "name": "is-even",
            "version": "1.0.0",
            "dependencies": { "is-odd": "^0.1.2" },
            "devDependencies": { "mocha": "^10.2.0", "tap": "^16.0.0" }
        }"#;
        // package.json placed FIRST (must be an early entry per archive bounds),
        // followed by a non-manifest entry to prove the scan does not stop early.
        let tgz = make_npm_tgz(&[
            ("package/package.json", manifest),
            ("package/README.md", b"# is-even"),
        ]);

        let specs = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(tgz))
            .expect("a real .tgz with package/package.json must parse");
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(specs.len(), 1, "only the single runtime dep: {specs:?}");
        assert_eq!(names, vec!["is-odd"]);
        for forbidden in &["mocha", "tap"] {
            assert!(
                !names.contains(forbidden),
                "devDependency {forbidden} leaked from the tarball: {names:?}"
            );
        }
    }

    /// Non-gzip input (e.g. the H11 failure mode: raw JSON / arbitrary
    /// bytes handed where a `.tgz` is now expected) → a clear `Err`, not a
    /// JSON parse on gzip bytes.
    #[test]
    fn extract_dependency_specs_npm_non_gzip_input_is_err() {
        let body = br#"{"dependencies":{"is-odd":"^0.1.2"}}"#;
        let err = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(body))
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "got {err:?}");
    }

    /// A well-formed `.tgz` that does NOT contain `package/package.json`
    /// is corruption for npm → `Err` naming the missing entry.
    #[test]
    fn extract_dependency_specs_npm_tgz_missing_manifest_is_err() {
        // The single entry's body must be INCOMPRESSIBLE so the compressed
        // size stays ~= decompressed size; then output_cap_for(compressed)
        // = 10× comfortably clears the decompressed tar (content + 512-byte
        // block overhead) and the scan reaches the "absent" branch rather
        // than tripping the cumulative output cap on tar padding.
        // (Mirrors the archive_bounds `read_tar_gz_entry_returns_none_when_absent`
        // test's incompressible-fixture rationale.)
        let body: Vec<u8> = {
            let mut state: u32 = 0x1357_9bdf;
            (0..4096)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> 24) as u8
                })
                .collect()
        };
        let tgz = make_npm_tgz(&[("package/README.md", &body)]);
        let err = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(tgz))
            .unwrap_err();
        match err {
            DomainError::Validation(msg) => assert!(
                msg.contains("package/package.json"),
                "error must name the missing entry: {msg}"
            ),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    /// A `.tgz` whose manifest declares zero runtime deps → `Ok(vec![])`
    /// (a leaf package is not an error).
    #[test]
    fn extract_dependency_specs_npm_tgz_zero_dep_manifest_is_empty_vec() {
        let manifest = br#"{"name":"leaf","version":"1.0.0"}"#;
        let tgz = make_npm_tgz(&[("package/package.json", manifest)]);
        let specs = handler()
            .extract_dependency_specs(&mut std::io::Cursor::new(tgz))
            .expect("Ok");
        assert!(specs.is_empty(), "leaf package has no runtime deps");
    }

    // -- parse_npm_runtime_dependencies (private parser) -------------------
    //
    // These test the JSON `dependencies`-only parse logic DIRECTLY against
    // the factored-out private fn (manifest bytes in, specs out). They do
    // NOT exercise the archive layer — that is covered by the `_from_tgz`
    // tests above.

    /// Real-shape per-version `package.json` fragment with all four
    /// dependency classes. The runtime-vs-dev boundary is the
    /// load-bearing assertion: ONLY `dependencies` survives into the
    /// extracted spec list.
    #[test]
    fn parse_npm_runtime_dependencies_runtime_only_drops_all_other_classes() {
        // Mirrors what npm itself publishes in a per-version packument
        // block (express@4.18.2 trimmed down to a handful of deps from
        // each class).
        let body = br#"{
            "name": "express",
            "version": "4.18.2",
            "dependencies": {
                "body-parser": "1.20.1",
                "accepts": "~1.3.8"
            },
            "devDependencies": {
                "mocha": "^10.2.0",
                "supertest": "^6.3.0"
            },
            "peerDependencies": {
                "node": ">=14"
            },
            "optionalDependencies": {
                "fsevents": "^2.0.0"
            },
            "bundleDependencies": ["something"]
        }"#;

        let specs = parse_npm_runtime_dependencies(body).expect("Ok");
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        // Exactly the runtime deps, nothing else.
        assert_eq!(specs.len(), 2, "got {specs:?}");
        assert!(
            names.contains(&"body-parser"),
            "missing body-parser: {names:?}"
        );
        assert!(names.contains(&"accepts"), "missing accepts: {names:?}");
        // Each of the dev / peer / optional / bundle names MUST NOT
        // appear — that's the runtime-vs-dev boundary the cascade
        // depends on.
        for forbidden in &["mocha", "supertest", "node", "fsevents", "something"] {
            assert!(
                !names.contains(forbidden),
                "non-runtime dep {forbidden} leaked into specs: {names:?}"
            );
        }
    }

    #[test]
    fn parse_npm_runtime_dependencies_range_is_preserved_opaque() {
        // The range string round-trips verbatim. The `range` value is
        // OPAQUE — `resolve_range_max` decides how to parse it.
        let body = br#"{
            "dependencies": {
                "lodash": "^4.17.21",
                "tilde-dep": "~1.2.3",
                "exact": "=1.0.0",
                "git-ref": "git+https://github.com/foo/bar.git",
                "alias": "npm:underscore@^1.13"
            }
        }"#;
        let specs = parse_npm_runtime_dependencies(body).expect("Ok");
        let map: std::collections::HashMap<&str, &str> = specs
            .iter()
            .map(|s| (s.name.as_str(), s.range.as_str()))
            .collect();
        assert_eq!(map.get("lodash"), Some(&"^4.17.21"));
        assert_eq!(map.get("tilde-dep"), Some(&"~1.2.3"));
        assert_eq!(map.get("exact"), Some(&"=1.0.0"));
        // git refs are kept verbatim — `resolve_range_max` will
        // unparseable-fail and return None, which the cascade reads
        // as "skip this dep".
        assert_eq!(
            map.get("git-ref"),
            Some(&"git+https://github.com/foo/bar.git")
        );
        assert_eq!(map.get("alias"), Some(&"npm:underscore@^1.13"));
    }

    #[test]
    fn parse_npm_runtime_dependencies_empty_dependencies_object_is_empty_vec() {
        // Explicit empty object — NOT an error.
        let body = br#"{"dependencies": {}}"#;
        let specs = parse_npm_runtime_dependencies(body).expect("Ok");
        assert!(specs.is_empty());
    }

    #[test]
    fn parse_npm_runtime_dependencies_missing_dependencies_key_is_empty_vec() {
        // A leaf package (no declared deps at all) — NOT an error.
        let body = br#"{"name":"leaf","version":"1.0.0"}"#;
        let specs = parse_npm_runtime_dependencies(body).expect("Ok");
        assert!(specs.is_empty());
    }

    #[test]
    fn parse_npm_runtime_dependencies_non_object_body_is_empty_vec() {
        // Top-level JSON is a string / array / number / null — no
        // dependencies could possibly live there; not an error.
        for body in [
            br#""just a string""#.as_slice(),
            br#"["array"]"#.as_slice(),
            br#"42"#.as_slice(),
            br#"null"#.as_slice(),
        ] {
            let specs = parse_npm_runtime_dependencies(body).expect("Ok");
            assert!(specs.is_empty(), "body {body:?} should yield empty");
        }
    }

    #[test]
    fn parse_npm_runtime_dependencies_malformed_json_returns_validation_error() {
        // Structurally invalid bytes — surface as `Validation`, not
        // silent empty Vec. The cascade can distinguish "no deps"
        // from "could not parse".
        let body = b"{not even close to valid json";
        let err = parse_npm_runtime_dependencies(body).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_npm_runtime_dependencies_over_cap_returns_validation_error() {
        // The parser-input sanity cap is the dedicated per-version-manifest
        // bound, NOT `metadata_expected_max_bytes` (the upload/HashReference
        // threshold). An over-cap manifest is rejected.
        let body = vec![b' '; NPM_MANIFEST_MAX_BYTES + 1];
        let err = parse_npm_runtime_dependencies(&body).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("npm manifest max is")
                && msg.contains(&NPM_MANIFEST_MAX_BYTES.to_string()),
            "size diagnostic missing: {msg}"
        );
    }

    #[test]
    fn parse_npm_runtime_dependencies_at_cap_boundary_is_accepted() {
        // A manifest sized exactly at the cap parses (the gate is `>`, not
        // `>=`). Use a `{}`-shaped body padded with trailing whitespace to
        // exactly the cap so it is both at-boundary AND valid JSON.
        let mut body = b"{}".to_vec();
        body.resize(NPM_MANIFEST_MAX_BYTES, b' ');
        let out = parse_npm_runtime_dependencies(&body).expect("at-cap body must parse");
        assert!(out.is_empty());
    }

    // -- resolve_range_max -------------------------------------------------

    #[test]
    fn resolve_range_max_npm_caret_picks_highest_in_minor_window() {
        let avail = ["1.1.0", "1.2.0", "1.2.5", "1.3.0", "2.0.0"];
        let out = handler().resolve_range_max("^1.2", &avail).expect("Ok");
        assert_eq!(out.as_deref(), Some("1.3.0"));
    }

    #[test]
    fn resolve_range_max_npm_no_match_returns_none() {
        let avail = ["1.0.0", "1.5.0"];
        assert_eq!(handler().resolve_range_max("^2", &avail).expect("Ok"), None);
    }

    #[test]
    fn resolve_range_max_npm_unparseable_range_returns_none() {
        // Best-effort: a git-ref or alias is not a parseable range —
        // resolve to None silently. The cascade reads None as "skip".
        let avail = ["1.0.0"];
        assert_eq!(
            handler()
                .resolve_range_max("git+https://github.com/foo/bar.git", &avail)
                .expect("Ok"),
            None
        );
    }

    #[test]
    fn resolve_range_max_npm_empty_available_returns_none() {
        assert_eq!(handler().resolve_range_max("^1.0", &[]).expect("Ok"), None);
    }

    // -- build_pull_url ---------------------------------------------------

    #[test]
    fn build_pull_url_npm_unscoped_uses_canonical_tarball_path() {
        // Mirrors the real registry URL shape:
        // `https://registry.npmjs.org/express/-/express-4.18.2.tgz`.
        let urls = handler()
            .build_pull_url("https://registry.npmjs.org", "express", "4.18.2")
            .expect("Ok");
        assert_eq!(
            urls,
            vec!["https://registry.npmjs.org/express/-/express-4.18.2.tgz".to_string()]
        );
    }

    #[test]
    fn build_pull_url_npm_scoped_uses_unscoped_basename_in_filename() {
        // Scoped tarball convention: `@types/node@20.0.0` lives at
        // `/@types/node/-/node-20.0.0.tgz` (note the basename is the
        // *unscoped* package name `node`, not `@types/node`).
        let urls = handler()
            .build_pull_url("https://registry.npmjs.org", "@types/node", "20.0.0")
            .expect("Ok");
        assert_eq!(
            urls,
            vec!["https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz".to_string()]
        );
    }

    #[test]
    fn build_pull_url_npm_trims_trailing_slash_on_upstream_url() {
        // Operators frequently set `upstream_url` with a trailing /.
        // Composition strips it so the URL is well-formed (no double /).
        let urls = handler()
            .build_pull_url("https://registry.npmjs.org/", "lodash", "4.17.21")
            .expect("Ok");
        assert_eq!(
            urls,
            vec!["https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()]
        );
    }

    #[test]
    fn build_pull_url_npm_empty_package_or_version_is_validation_error() {
        let err = handler()
            .build_pull_url("https://r.example.com", "", "1.0.0")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let err = handler()
            .build_pull_url("https://r.example.com", "lodash", "")
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }
}
