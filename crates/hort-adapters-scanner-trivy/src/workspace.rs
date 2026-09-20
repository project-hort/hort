//! Scan-workspace materialisation: putting an artifact's bytes on disk in
//! the shape Trivy's analyzers actually look for.
//!
//! Trivy selects analyzers by **file name, extension and directory
//! layout**, and against a directory target it does not open archives. So
//! handing it a directory containing one opaque blob is handing it
//! nothing: no analyzer claims the file, the report comes back with no
//! `Results`, and an empty finding list is indistinguishable from a clean
//! scan. The layout is only half of it — the **subcommand** decides which
//! analyzers are eligible in the first place, so the two are chosen
//! together below. The materialisation is therefore not a detail of this
//! module — it *is* the scan's evidence.
//!
//! # Materialisation by kind
//!
//! The mode column is not a free choice. Trivy's coverage matrix
//! (<https://trivy.dev/docs/latest/coverage/language/>) states, per
//! analyzer, which of its four **targets** — Container Image, Filesystem,
//! Rootfs, Repository — runs it, and the split falls almost exactly along
//! the pre-build / post-build line: a **built artifact** (`JAR`/`WAR`/
//! `EAR`/`PAR`, a Python `egg`/`wheel`, a `package.json` under
//! `node_modules`, a cargo-auditable or Go binary) is analysed by **Image
//! and Rootfs only**, while a **pre-build declaration** (`pom.xml`,
//! `package-lock.json`, `requirements.txt`, `poetry.lock`, `uv.lock`,
//! `gradle.lockfile`) is analysed by **Filesystem and Repository only**.
//! `Cargo.lock` is read by all four. Hort has no container image to scan,
//! so the choice for every row is `rootfs` or `fs`, and picking the wrong
//! one means the analyzer never runs: the report comes back with no
//! analysed target and the artifact can never get a verdict.
//!
//! | [`ArtifactKind`]              | on disk                                  | Trivy mode | why that mode |
//! |-------------------------------|------------------------------------------|------------|---------------|
//! | `MavenJar`                    | one file, keeping its `.jar`/`.war`/`.ear`/`.par` name | `rootfs` | a Java archive is post-build: Image and Rootfs targets only |
//! | `MavenPom`                    | one file named `pom.xml`                 | `fs`       | `pom.xml` is pre-build: Filesystem and Repository targets only |
//! | `NpmTarball`                  | gzip-tar extracted to `node_modules/<name>/`, the archive's own root directory stripped | `rootfs` | a `package.json` is only claimed under `node_modules`, and that analyzer is Image/Rootfs only |
//! | `CargoCrate`                  | gzip-tar extracted into the workspace    | `fs`       | the evidence a `.crate` can carry is `Cargo.lock`, read by every target; `fs` keeps the pre-build `Cargo.toml` side readable too |
//! | `PySdist`                     | gzip-tar extracted into the workspace    | `rootfs`   | an sdist's `*.egg-info/PKG-INFO` is a post-build egg: Image and Rootfs targets only |
//! | `PyWheel`                     | ZIP extracted into the workspace         | `rootfs`   | a wheel's `*.dist-info/METADATA` is post-build: Image and Rootfs targets only |
//! | `OciBlob` (a tar layer)       | tar/gzip-tar extracted as a root filesystem | `rootfs` | a layer *is* a root filesystem; only that target reads its OS package database |
//! | `OciBlob` (anything else)     | nothing — no scanner invocation          | —          | an image config carries no package surface |
//! | `OciManifest`                 | nothing — no scanner invocation          | —          | a manifest carries no package surface |
//! | `Other`                       | nothing — no scanner invocation          | —          | no handler claims these bytes |
//!
//! Why each layout is what it is:
//!
//! - A **Java archive** needs only its extension. Trivy's JAR analyzer
//!   opens the archive itself and reads the embedded
//!   `META-INF/maven/**/pom.properties` coordinates
//!   (<https://trivy.dev/latest/docs/coverage/language/java/>), so a
//!   single correctly-named file is the whole materialisation.
//! - A **POM** is claimed by the Maven analyzer, which keys on the name
//!   `pom.xml` (same page). The artifact's own file name
//!   (`log4j-core-2.14.1.pom`) matches nothing.
//! - **Wheels and sdists** are claimed through paths *inside* them —
//!   `*.dist-info/METADATA` for a wheel, `PKG-INFO` for an sdist
//!   (<https://trivy.dev/latest/docs/coverage/language/python/>) — and
//!   Trivy will not reach inside the container, so the container has to
//!   be opened here.
//! - An **npm tarball** needs both halves: extraction, *and* the
//!   installed layout. Trivy claims a `package.json` only when its path
//!   lies under `node_modules`, so the package is planted at
//!   `node_modules/<name>/` with the tarball's own root directory
//!   (conventionally `package/`) stripped — which is exactly what
//!   `npm install` does with the same bytes.
//! - A **`.crate` file** exposes `<dir>/Cargo.toml` once extracted, plus
//!   `Cargo.lock` when the crate ships one. Note what that buys: a
//!   manifest declares dependency *ranges*, not a resolved set, so a
//!   library crate yields package identity and licences but no lockfile
//!   to match advisories against. That is the honest ceiling for the
//!   format, not a gap in this module.
//! - An **OCI layer** is a root filesystem, and its package evidence is
//!   the distro package database (`var/lib/dpkg/status`,
//!   `lib/apk/db/installed`, `var/lib/rpm/*`) plus any language
//!   lockfiles it ships. `trivy rootfs` is the subcommand documented for
//!   exactly that shape
//!   (<https://trivy.dev/latest/docs/target/rootfs/>).
//! - **Manifests, image configs and unclaimed payloads** have no package
//!   surface at all. They are not materialised and no scanner is spawned:
//!   spawning one would produce an empty report that the caller could
//!   only read as "nothing analysed" anyway, at the cost of a process and
//!   a CAS read.
//!
//! # Fail-closed, not best-effort
//!
//! Nothing here degrades. A payload whose container cannot be opened, or
//! whose entries trip a bound in [`crate::extract`], yields
//! [`NotAnalysable::UnusableArchive`] and no scan — never a partially
//! extracted tree. A half-unpacked archive scanned as if it were whole is
//! precisely the false-clean this module exists to eliminate.
//!
//! Cleanup is RAII: the returned [`TempDir`] removes the whole tree on
//! `Drop`, which fires whether the scan succeeded, failed, or panicked.
//! The downloaded archive is written *outside* the directory Trivy is
//! pointed at (and removed once extracted), so the raw payload is never
//! itself a scan target.
//!
//! Bytes are streamed from `StoragePort::get` to disk in fixed-size chunks
//! with a running byte count — no full-artifact RAM buffer — bounded by
//! `max_artifact_size` from [`TrivyConfig`](crate::TrivyConfig).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scanner::{NotAnalysable, ScanTarget};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{ArtifactCoords, ArtifactKind, ContentHash};
use tempfile::{Builder, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::extract::{extract_tar, extract_zip, ExtractBounds, ExtractError, ExtractStats};

/// Chunk size for the streaming CAS→tempfile copy. 64 KiB is the
/// usual sweet spot for `read`/`write` syscall amortisation without
/// holding a meaningful amount of artifact bytes resident.
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// Name of the directory inside the workspace that Trivy is pointed at.
/// Kept distinct from the temp-dir root so the downloaded archive can sit
/// beside it without becoming a scan target.
const TARGET_SUBDIR: &str = "target";

/// Name the downloaded archive is written under, beside (never inside)
/// [`TARGET_SUBDIR`].
const DOWNLOAD_FILENAME: &str = "payload.download";

/// Directory an archive that needs relocating is unpacked into first,
/// beside (never inside) [`TARGET_SUBDIR`]. Extracting straight into the
/// scan tree and moving afterwards would leave the pre-move layout
/// visible if the move failed; staging outside it means the scan
/// directory only ever holds the finished shape.
const STAGING_SUBDIR: &str = "staging";

/// Directory Trivy requires a `package.json` to sit under before its
/// Node analyzer will claim it
/// (<https://trivy.dev/docs/latest/coverage/language/nodejs/>).
const NODE_MODULES_DIR: &str = "node_modules";

/// Package directory used when an npm artifact's coordinates yield no
/// safe name. Keeps the package under `node_modules` — which is the part
/// that decides whether the analyzer runs at all — without inventing a
/// name that could name a path.
const FALLBACK_NPM_PACKAGE_NAME: &str = "package";

/// Relative file names listed in the "no analysed target" diagnostic.
/// Enough to recognise the shape of a tree (a `package.json` at the
/// wrong depth, an archive that unpacked to one stray file) without
/// turning one log line into a directory dump.
const MAX_LISTED_FILES: usize = 20;

/// Ceiling on directory entries walked while building that listing. A
/// diagnostic must not cost more than the scan it explains, and a
/// refused-but-extracted tree can hold hundreds of thousands of entries.
const MAX_WALKED_ENTRIES: usize = 4096;

/// Fallback file name for a Java archive whose coordinates yield nothing
/// usable. Keeps the extension — which is the entire point of the
/// single-file materialisation — without inventing a coordinate.
const FALLBACK_JAVA_ARCHIVE_NAME: &str = "artifact.jar";

/// File extensions Trivy's Java-archive analyzer claims
/// (<https://trivy.dev/latest/docs/coverage/language/java/>). An artifact
/// materialised under any other suffix is never inspected.
const JAVA_ARCHIVE_EXTENSIONS: &[&str] = &["jar", "war", "ear", "par"];

/// Which Trivy subcommand the materialised workspace is meant for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanMode {
    /// `trivy fs <dir>` — language-manifest and single-file analyzers.
    Fs,
    /// `trivy rootfs <dir>` — the extracted tree is a root filesystem, so
    /// the OS-package analyzers apply on top of the language ones.
    Rootfs,
}

impl ScanMode {
    /// The Trivy subcommand literal.
    pub(crate) fn subcommand(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Rootfs => "rootfs",
        }
    }
}

/// A materialised scan workspace. Holds the `TempDir` so the caller keeps
/// the tree alive across the Trivy invocation; drop removes it.
#[derive(Debug)]
pub(crate) struct ScanWorkspace {
    /// RAII handle. Drop → directory tree removed.
    #[allow(dead_code)] // held solely for its Drop
    tmp: TempDir,
    /// The directory Trivy is pointed at.
    target_dir: PathBuf,
    /// Symlink and hardlink entries skipped while materialising this
    /// workspace. Zero for a `SingleFile` plan, which extracts nothing.
    skipped_links: usize,
}

impl ScanWorkspace {
    /// The path the Trivy CLI gets pointed at.
    pub(crate) fn dir(&self) -> &Path {
        &self.target_dir
    }

    /// Symlink and hardlink entries skipped while materialising this
    /// workspace — never a refusal, but worth surfacing when the report
    /// comes back with nothing analysed.
    pub(crate) fn skipped_links(&self) -> usize {
        self.skipped_links
    }

    /// The workspace's file names, relative to [`Self::dir`], for the
    /// diagnostic emitted when Trivy reports no analysed target.
    ///
    /// That warning is otherwise unactionable: "no analyzer claimed
    /// anything" and "the tree does not look like what I expected" are
    /// the same log line, and only the second is a bug in this adapter.
    /// The listing is what tells them apart, so it names files (the
    /// things analyzers key on) and is sorted for a stable read.
    ///
    /// Bounded twice — at most [`MAX_LISTED_FILES`] names from at most
    /// [`MAX_WALKED_ENTRIES`] directory entries — because the tree is
    /// attacker-influenced and this is a diagnostic, not evidence. A
    /// truncated listing is marked with a trailing `…`; an unreadable
    /// directory yields whatever was collected before it, since failing
    /// the scan over a failed diagnostic would be backwards.
    pub(crate) async fn listing(&self) -> String {
        let mut names: Vec<String> = Vec::new();
        let mut queue: Vec<PathBuf> = vec![self.target_dir.clone()];
        let mut walked = 0usize;
        let mut truncated = false;

        while let Some(dir) = queue.pop() {
            let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
                continue;
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                walked += 1;
                if walked > MAX_WALKED_ENTRIES {
                    truncated = true;
                    break;
                }
                let path = entry.path();
                match entry.file_type().await {
                    Ok(ft) if ft.is_dir() => queue.push(path),
                    // Symlinks are never materialised by the extractor,
                    // so anything that is not a directory here is a
                    // regular file the scanner could have claimed.
                    Ok(_) => {
                        if names.len() >= MAX_LISTED_FILES {
                            truncated = true;
                            break;
                        }
                        let rel = path.strip_prefix(&self.target_dir).unwrap_or(&path);
                        names.push(rel.to_string_lossy().into_owned());
                    }
                    Err(_) => {}
                }
            }
            if truncated {
                break;
            }
        }

        names.sort();
        if truncated {
            names.push("…".to_string());
        }
        names.join(", ")
    }
}

/// Outcome of materialising one [`ScanTarget`].
#[derive(Debug)]
pub(crate) enum Materialised {
    /// The workspace is ready; invoke Trivy in `mode` against
    /// `ws.dir()`.
    Ready { ws: ScanWorkspace, mode: ScanMode },
    /// No scanner invocation applies. Carries the reason the caller
    /// surfaces as `ScanAnalysis::NothingAnalysable`.
    Nothing(NotAnalysable),
}

/// How a kind's bytes are put on disk, paired with the Trivy target that
/// reads that layout. Derived purely from the [`ScanTarget`], so the
/// whole table is unit-testable without storage — and lives in one match
/// so a layout can never drift away from the mode that reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// Write the bytes as a single file under this name.
    SingleFile { name: String, mode: ScanMode },
    /// Extract a gzip-tar into the target directory.
    GzipTar { mode: ScanMode },
    /// Extract a gzip-tar into `dest` (relative to the target directory),
    /// stripping the archive's own single root directory on the way.
    Relocated { dest: String, mode: ScanMode },
    /// Extract a ZIP into the target directory.
    Zip { mode: ScanMode },
    /// An OCI blob: the container decides. A tar (plain or gzip) is a
    /// layer and becomes a root filesystem; anything else is not layer
    /// content.
    OciBlob,
    /// Nothing a scanner can analyse.
    NotApplicable,
}

/// Whether this adapter has a materialisation for `kind` at all — the
/// kind axis of the capability map.
///
/// Exhaustive by construction so a future [`ArtifactKind`] has to state
/// its answer rather than inherit one, and pinned against [`plan_for`]
/// by `kind_materialisation_agrees_with_the_plan_table` so the two can
/// never drift: a kind that maps to [`Plan::NotApplicable`] is a kind no
/// scanner invocation is attempted for, which is exactly the kind this
/// predicate must call unanalysable.
fn kind_is_materialisable(kind: ArtifactKind) -> bool {
    match kind {
        ArtifactKind::MavenJar
        | ArtifactKind::MavenPom
        | ArtifactKind::NpmTarball
        | ArtifactKind::CargoCrate
        | ArtifactKind::PySdist
        | ArtifactKind::PyWheel
        // An OCI blob that is a layer becomes a root filesystem; one
        // that is not (the image config) yields `NotApplicable` at
        // sniff time. The format is analysable because the first shape
        // exists, and that is what a per-format answer can say.
        | ArtifactKind::OciBlob => true,
        ArtifactKind::OciManifest | ArtifactKind::Other => false,
    }
}

/// The artifact kinds each compiled-in format handler declares through
/// `FormatHandler::scan_kind`.
///
/// The adapter is handed only the format string, and it must not depend
/// on `hort-formats` (a scanner adapter depends on `hort-domain` alone),
/// so the association is static here. The worker's parity guard is what
/// keeps it honest: it asks every registered handler for its key and
/// compares this adapter's answer against the static record the apply
/// path reads, so a handler whose kinds change without this table
/// changing fails the build's test gate rather than silently shrinking
/// the map.
const FORMAT_KINDS: &[(&str, &[ArtifactKind])] = &[
    ("oci", &[ArtifactKind::OciBlob, ArtifactKind::OciManifest]),
    ("maven", &[ArtifactKind::MavenJar, ArtifactKind::MavenPom]),
    ("pypi", &[ArtifactKind::PyWheel, ArtifactKind::PySdist]),
    ("npm", &[ArtifactKind::NpmTarball]),
    ("cargo", &[ArtifactKind::CargoCrate]),
];

/// Whether Trivy can produce a verdict for at least one artifact kind of
/// `format` — the adapter's own half of the scanner capability map.
///
/// Two conditions, and both are load-bearing:
///
/// 1. **Materialisation.** At least one of the format's kinds has a
///    [`Plan`] other than [`Plan::NotApplicable`]. Derived here from
///    [`FORMAT_KINDS`] × [`kind_is_materialisable`] rather than
///    hand-listed, so the answer is computed from the very table that
///    decides what lands on disk.
/// 2. **Evidence.** A test materialises a known-vulnerable fixture of
///    that format through this adapter and gets back at least one
///    finding. Materialisation alone only proves bytes reach the
///    scanner, not that an analyzer claims them — and a format whose
///    bytes no analyzer claims is a pairing that would accept at apply
///    and analyse nothing at runtime. The evidence per format lives in
///    `tests/materialisation_evidence.rs`:
///
///    | format  | evidence test |
///    |---------|---------------|
///    | `oci`   | `an_oci_layer_with_an_os_package_database_yields_findings` |
///    | `maven` | `a_known_vulnerable_jar_yields_its_cve`, `a_pom_is_analysed_rather_than_ignored` |
///    | `pypi`  | `a_known_vulnerable_wheel_yields_at_least_one_finding` |
///    | `npm`   | `a_known_vulnerable_npm_tarball_yields_its_own_advisory` |
///    | `cargo` | `a_binary_crate_with_a_lockfile_yields_a_dependency_advisory` |
///
/// Every format in [`FORMAT_KINDS`] currently carries such a test, so
/// the second condition adds no exclusion today. It is stated because
/// removing a cell is the correct response to losing its evidence — not
/// leaving the cell standing on the materialisation half alone.
pub(crate) fn format_is_analysable(format: &str) -> bool {
    FORMAT_KINDS
        .iter()
        .any(|(f, kinds)| *f == format && kinds.iter().copied().any(kind_is_materialisable))
}

/// Decide the materialisation for a target. The module doc's table is
/// this function; the "why that mode" column cites Trivy's coverage
/// matrix, which is the authority on which target runs which analyzer.
fn plan_for(target: &ScanTarget<'_>) -> Plan {
    match target.kind {
        // A Java archive is a post-build artifact, claimed only by the
        // Image and Rootfs targets.
        ArtifactKind::MavenJar => Plan::SingleFile {
            name: java_archive_filename(target.coords),
            mode: ScanMode::Rootfs,
        },
        // Trivy's Maven analyzer keys on the literal name `pom.xml`; the
        // artifact's own `<artifactId>-<version>.pom` matches nothing.
        // A POM is a pre-build declaration: Filesystem and Repository.
        ArtifactKind::MavenPom => Plan::SingleFile {
            name: "pom.xml".to_string(),
            mode: ScanMode::Fs,
        },
        // A `package.json` is claimed only under `node_modules`, and only
        // by the Image and Rootfs targets.
        ArtifactKind::NpmTarball => Plan::Relocated {
            dest: npm_package_dir(target.coords),
            mode: ScanMode::Rootfs,
        },
        // A `.crate`'s analysable content is `Cargo.toml` plus, when the
        // crate ships one, `Cargo.lock` — which every target reads.
        ArtifactKind::CargoCrate => Plan::GzipTar { mode: ScanMode::Fs },
        // An sdist's `*.egg-info/PKG-INFO` is post-build egg metadata:
        // Image and Rootfs.
        ArtifactKind::PySdist => Plan::GzipTar {
            mode: ScanMode::Rootfs,
        },
        // A wheel's `*.dist-info/METADATA` likewise.
        ArtifactKind::PyWheel => Plan::Zip {
            mode: ScanMode::Rootfs,
        },
        ArtifactKind::OciBlob => Plan::OciBlob,
        ArtifactKind::OciManifest | ArtifactKind::Other => Plan::NotApplicable,
    }
}

/// The directory an npm package is planted in, relative to the scan
/// target directory: `node_modules/<name>`, keeping a scoped package's
/// `@scope/` directory.
///
/// The `node_modules` prefix is load-bearing rather than cosmetic —
/// Trivy's Node analyzer refuses a `package.json` outside it — so a name
/// that cannot be used safely falls back to
/// [`FALLBACK_NPM_PACKAGE_NAME`] rather than dropping the prefix.
///
/// A published npm name is at most one `@scope/` segment plus the
/// package segment, and every segment is checked for being a single,
/// contained file name: a registry name is repository data, and a name
/// with a `..` or a separator in it must never reach a `join`.
fn npm_package_dir(coords: &ArtifactCoords) -> String {
    let segments: Vec<&str> = coords.name.split('/').collect();
    let usable = match segments.as_slice() {
        [name] => is_safe_filename(name),
        [scope, name] => {
            scope.starts_with('@') && is_safe_filename(scope) && is_safe_filename(name)
        }
        _ => false,
    };
    if usable {
        format!("{NODE_MODULES_DIR}/{}", coords.name)
    } else {
        format!("{NODE_MODULES_DIR}/{FALLBACK_NPM_PACKAGE_NAME}")
    }
}

/// The file name a Java archive is materialised under.
///
/// Preference order:
///
/// 1. The last segment of the artifact's stored path, when it is a plain
///    file name with a Java-archive extension. This is the artifact's
///    real name (`log4j-core-2.14.1.jar`), which is what shows up in the
///    scanner's report target — worth far more to whoever reads the
///    finding than a digest.
/// 2. `<artifactId>-<version>.jar` reconstructed from the coordinates,
///    for a row whose path is unexpected.
/// 3. [`FALLBACK_JAVA_ARCHIVE_NAME`].
///
/// Every candidate is checked for being a single, contained file name: a
/// stored path is repository data, and a name with a separator or a `..`
/// in it must never reach a `join`.
fn java_archive_filename(coords: &ArtifactCoords) -> String {
    let basename = coords.path.rsplit('/').next().unwrap_or(&coords.path);
    if is_safe_filename(basename) && has_java_archive_extension(basename) {
        return basename.to_string();
    }
    // `groupId:artifactId` → `artifactId`; the group adds nothing to a
    // file name and its dots would read as extensions.
    let artifact_id = coords.name.rsplit(':').next().unwrap_or(&coords.name);
    let version = coords.version.as_deref().unwrap_or("unknown");
    let reconstructed = format!("{artifact_id}-{version}.jar");
    if is_safe_filename(&reconstructed) {
        return reconstructed;
    }
    FALLBACK_JAVA_ARCHIVE_NAME.to_string()
}

/// Whether `name` is a single path segment safe to `join` onto a
/// directory: non-empty, no separator, not a relative-path token, no NUL.
fn is_safe_filename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// Whether `name` ends in one of the extensions Trivy's Java-archive
/// analyzer claims.
fn has_java_archive_extension(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, ext)| {
        let ext = ext.to_ascii_lowercase();
        JAVA_ARCHIVE_EXTENSIONS.contains(&ext.as_str())
    })
}

/// What a blob's leading bytes say its container is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    /// gzip stream — an OCI `tar+gzip` layer.
    Gzip,
    /// Uncompressed tar, identified by the POSIX `ustar` magic.
    Tar,
    /// A compression container this adapter has no decoder for (zstd,
    /// xz, bzip2). Distinguished from "not an archive" because refusing
    /// a layer it *could* have scanned is a gap worth naming in the log,
    /// whereas an image config is simply not layer content.
    UnsupportedCompression(&'static str),
    /// Not an archive — for an OCI blob, this is the image config JSON.
    NotAnArchive,
}

/// Classify a blob's container from its leading bytes.
///
/// Sniffing rather than trusting a declared media type is not a shortcut
/// here: an OCI blob row carries `application/octet-stream` whatever role
/// the manifest assigns it, so there is no media type to trust. The
/// `ustar` magic at offset 257 is the POSIX tar identifier; pre-POSIX v7
/// tars have no magic and land on `NotAnArchive`, which fails closed.
fn sniff_container(head: &[u8]) -> Container {
    const TAR_MAGIC_OFFSET: usize = 257;
    if head.starts_with(&[0x1f, 0x8b]) {
        return Container::Gzip;
    }
    if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Container::UnsupportedCompression("zstd");
    }
    if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return Container::UnsupportedCompression("xz");
    }
    if head.starts_with(b"BZh") {
        return Container::UnsupportedCompression("bzip2");
    }
    if head.len() >= TAR_MAGIC_OFFSET + 5
        && &head[TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + 5] == b"ustar"
    {
        return Container::Tar;
    }
    Container::NotAnArchive
}

/// Materialise `target`'s bytes into a fresh workspace.
///
/// Errors (`DomainError`) are reserved for failures that are **not** a
/// property of the payload: an unreadable CAS stream, a temp-dir the
/// worker cannot create, or an artifact over `max_artifact_size`. A
/// payload the adapter can read but cannot safely open is not an error —
/// it is [`Materialised::Nothing`] with a reason, because the scan axis
/// has a state for "no verdict" and the job queue should not retry a
/// deterministic refusal.
pub(crate) async fn materialise(
    storage: &Arc<dyn StoragePort>,
    target: &ScanTarget<'_>,
    max_artifact_size: u64,
) -> DomainResult<Materialised> {
    let plan = plan_for(target);
    if plan == Plan::NotApplicable {
        // No CAS read at all: there is no materialisation for these
        // bytes, so paying a storage round-trip to write a file nothing
        // will analyse is pure cost.
        tracing::debug!(
            scanner = "trivy",
            kind = target.kind.as_str(),
            format = target.format,
            "trivy adapter: artifact kind carries no analysable surface; skipping invocation"
        );
        return Ok(Materialised::Nothing(NotAnalysable::NotApplicable));
    }

    let tmp = Builder::new()
        .prefix("hort-scan-trivy-")
        .tempdir()
        .map_err(|e| {
            DomainError::Invariant(format!(
                "trivy adapter: failed to create temp workspace: {e}"
            ))
        })?;
    let target_dir = tmp.path().join(TARGET_SUBDIR);
    tokio::fs::create_dir(&target_dir).await.map_err(|e| {
        DomainError::Invariant(format!(
            "trivy adapter: failed to create scan target directory: {e}"
        ))
    })?;

    match plan {
        Plan::NotApplicable => unreachable!("handled above"),
        Plan::SingleFile { name, mode } => {
            let path = target_dir.join(&name);
            stream_to_file(storage, target.content_hash, &path, max_artifact_size).await?;
            Ok(Materialised::Ready {
                ws: ScanWorkspace {
                    tmp,
                    target_dir,
                    skipped_links: 0,
                },
                mode,
            })
        }
        Plan::GzipTar { .. } | Plan::Relocated { .. } | Plan::Zip { .. } | Plan::OciBlob => {
            let download = tmp.path().join(DOWNLOAD_FILENAME);
            let size =
                stream_to_file(storage, target.content_hash, &download, max_artifact_size).await?;
            let bounds = ExtractBounds::default_for_scan_materialisation();
            let extract_dir = target_dir.clone();
            let staging_dir = tmp.path().join(STAGING_SUBDIR);
            let kind = target.kind;
            let joined = tokio::task::spawn_blocking(move || {
                extract_blocking(&plan, &download, size, &extract_dir, &staging_dir, bounds)
            })
            .await;

            let outcome = match joined {
                Ok(outcome) => outcome,
                // A panicked extraction task is the same fact to an
                // operator as a refused archive: no tree was produced.
                Err(join) => Err(ExtractError::Malformed(format!(
                    "extraction task did not complete: {join}"
                ))),
            };

            match outcome {
                Ok(Some((mode, stats))) => {
                    tracing::debug!(
                        scanner = "trivy",
                        kind = kind.as_str(),
                        entries = stats.entries,
                        bytes = stats.bytes,
                        skipped_links = stats.skipped_links,
                        "trivy adapter: materialised scan workspace"
                    );
                    Ok(Materialised::Ready {
                        ws: ScanWorkspace {
                            tmp,
                            target_dir,
                            skipped_links: stats.skipped_links,
                        },
                        mode,
                    })
                }
                Ok(None) => {
                    tracing::debug!(
                        scanner = "trivy",
                        kind = kind.as_str(),
                        "trivy adapter: blob is not layer content; skipping invocation"
                    );
                    Ok(Materialised::Nothing(NotAnalysable::NotApplicable))
                }
                Err(e) => {
                    // `warn!`, not `error!`: the worker is healthy and the
                    // artifact is held, which is the designed outcome. The
                    // guard that fired is the actionable part; the
                    // artifact id stays on the span.
                    tracing::warn!(
                        scanner = "trivy",
                        kind = kind.as_str(),
                        format = target.format,
                        reason = %e,
                        "trivy adapter: refusing to materialise archive; no scan will run"
                    );
                    Ok(Materialised::Nothing(NotAnalysable::UnusableArchive))
                }
            }
        }
    }
}

/// The blocking half of extraction.
///
/// `Ok(Some((mode, stats)))` — a tree was produced, scan it in `mode`.
/// `Ok(None)` — the payload is not layer content (an OCI config); no
/// scan applies. `Err` — the archive was refused.
fn extract_blocking(
    plan: &Plan,
    download: &Path,
    size: u64,
    target_dir: &Path,
    staging_dir: &Path,
    bounds: ExtractBounds,
) -> Result<Option<(ScanMode, ExtractStats)>, ExtractError> {
    let open = || {
        std::fs::File::open(download)
            .map_err(|e| ExtractError::Malformed(format!("downloaded payload unreadable: {e}")))
    };
    let result = match plan {
        Plan::GzipTar { mode } => {
            let file = open()?;
            extract_tar(flate2::read::GzDecoder::new(file), size, target_dir, bounds)
                .map(|stats| Some((*mode, stats)))
        }
        Plan::Relocated { dest, mode } => {
            let file = open()?;
            std::fs::create_dir_all(staging_dir)
                .map_err(|e| ExtractError::Malformed(format!("staging directory: {e}")))?;
            let stats = extract_tar(
                flate2::read::GzDecoder::new(file),
                size,
                staging_dir,
                bounds,
            )?;
            relocate_extracted(staging_dir, target_dir, dest).map(|()| Some((*mode, stats)))
        }
        Plan::Zip { mode } => {
            let file = open()?;
            extract_zip(file, size, target_dir, bounds).map(|stats| Some((*mode, stats)))
        }
        Plan::OciBlob => {
            let mut file = open()?;
            let mut head = vec![0u8; 512];
            let read = read_head(&mut file, &mut head)?;
            head.truncate(read);
            match sniff_container(&head) {
                Container::Gzip => {
                    let file = open()?;
                    extract_tar(flate2::read::GzDecoder::new(file), size, target_dir, bounds)
                        .map(|stats| Some((ScanMode::Rootfs, stats)))
                }
                Container::Tar => {
                    let file = open()?;
                    extract_tar(file, size, target_dir, bounds)
                        .map(|stats| Some((ScanMode::Rootfs, stats)))
                }
                // A layer this adapter could scan if it could decompress
                // it. Refusing names the gap instead of silently
                // reporting the layer clean.
                Container::UnsupportedCompression(name) => Err(ExtractError::Malformed(format!(
                    "unsupported layer compression: {name}"
                ))),
                // The image config JSON (or any other non-archive blob):
                // genuinely no package surface, not a refusal.
                Container::NotAnArchive => Ok(None),
            }
        }
        Plan::SingleFile { .. } | Plan::NotApplicable => {
            unreachable!("extraction is only reached for archive plans")
        }
    };
    // The raw payload lives beside the scan directory, never inside it,
    // so Trivy would not have seen it either way — removing it once the
    // tree exists just halves the workspace's peak disk use.
    let _ = std::fs::remove_file(download);
    result
}

/// Move a staged tree into `target_dir/dest`, stripping the archive's own
/// single root directory.
///
/// A registry tarball wraps its content in one root directory —
/// conventionally `package/` for npm — that is not part of the installed
/// path: `npm install` strips it, and Trivy reads the *installed* layout,
/// `node_modules/<name>/package.json`. Leaving the wrapper in place would
/// put the manifest one level too deep.
///
/// The wrapper is identified structurally (exactly one entry in the
/// staged root, and it is a directory) rather than by name, because the
/// name is archive data. An archive of any other shape is planted whole:
/// guessing which of several roots was meant would be inventing evidence.
///
/// The move is a `rename` within the one temp directory, so it is a
/// single metadata operation rather than a second copy of the tree.
fn relocate_extracted(
    staging_dir: &Path,
    target_dir: &Path,
    dest: &str,
) -> Result<(), ExtractError> {
    let source = single_child_directory(staging_dir).unwrap_or_else(|| staging_dir.to_path_buf());
    let full = target_dir.join(dest);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ExtractError::Malformed(format!("could not create the package directory: {e}"))
        })?;
    }
    std::fs::rename(&source, &full)
        .map_err(|e| ExtractError::Malformed(format!("could not move the extracted package: {e}")))
}

/// The one child of `dir`, when `dir` holds exactly one entry and that
/// entry is a directory.
fn single_child_directory(dir: &Path) -> Option<PathBuf> {
    let mut entries = std::fs::read_dir(dir).ok()?;
    let first = entries.next()?.ok()?;
    if entries.next().is_some() {
        return None;
    }
    if first.file_type().ok()?.is_dir() {
        Some(first.path())
    } else {
        None
    }
}

/// Read up to `buf.len()` bytes, tolerating a short file.
fn read_head(file: &mut std::fs::File, buf: &mut [u8]) -> Result<usize, ExtractError> {
    use std::io::Read as _;
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => {
                return Err(ExtractError::Malformed(format!(
                    "downloaded payload unreadable: {e}"
                )))
            }
        }
    }
    Ok(filled)
}

/// Streaming, size-capped CAS→file copy. Returns the number of bytes
/// written, which the ratio cap downstream is measured against.
///
/// The copy reads the storage stream in [`COPY_CHUNK_BYTES`] chunks and
/// maintains a running `written` total. The cap check is
/// `written + chunk_len > max_artifact_size` *before* the chunk is
/// written, so a stream whose length is *exactly* the cap succeeds (the
/// next `read` yields EOF, not an over-cap chunk) while a stream that
/// produces even one byte beyond the cap is rejected — this is what
/// distinguishes "hit the cap" from a legitimate at-cap EOF.
async fn stream_to_file(
    storage: &Arc<dyn StoragePort>,
    content_hash: &ContentHash,
    path: &Path,
    max_artifact_size: u64,
) -> DomainResult<u64> {
    let mut reader = storage.get(content_hash).await?;
    let mut file = tokio::fs::File::create(path).await.map_err(|e| {
        DomainError::Invariant(format!(
            "trivy adapter: failed to create artifact file: {e}"
        ))
    })?;

    // Bounded streaming copy: fixed-size chunks, running byte count,
    // no full-artifact RAM buffer. `buf` is reused across iterations
    // so resident memory is O(COPY_CHUNK_BYTES), not O(artifact size).
    let mut buf = vec![0u8; COPY_CHUNK_BYTES];
    let mut written: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await.map_err(|e| {
            DomainError::Invariant(format!("trivy adapter: failed to read storage stream: {e}"))
        })?;
        if n == 0 {
            // EOF — the at-cap artifact lands here without ever
            // tripping the over-cap branch below.
            break;
        }
        // Cap check *before* writing this chunk. `written + n` cannot
        // wrap: `written <= max_artifact_size` holds on entry and `n`
        // fits in `usize`/`u64`.
        if written + (n as u64) > max_artifact_size {
            // RAII: the caller's `TempDir` (and the partial file inside
            // it) is removed when it drops on this error path.
            tracing::warn!(
                scanner = "trivy",
                content_hash = %content_hash,
                max_artifact_size,
                "trivy adapter: artifact exceeds max-artifact-size cap; rejecting pre-scan"
            );
            return Err(DomainError::Invariant(format!(
                "trivy adapter: artifact exceeds max-artifact-size cap \
                 ({max_artifact_size} bytes); rejected pre-scan to protect the worker"
            )));
        }
        file.write_all(&buf[..n]).await.map_err(|e| {
            DomainError::Invariant(format!(
                "trivy adapter: failed to write artifact bytes: {e}"
            ))
        })?;
        written += n as u64;
    }

    file.flush().await.map_err(|e| {
        DomainError::Invariant(format!("trivy adapter: failed to flush artifact file: {e}"))
    })?;

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::io::Write as _;

    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::ports::storage::{PutResult, StoragePort};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ByteRange;
    use tokio::io::AsyncRead;

    /// What the one test storage stub does when the materialiser calls
    /// `get`. Every other `StoragePort` method is unreachable on this
    /// path, so one impl with a behaviour selector replaces what would
    /// otherwise be three near-identical stubs.
    enum Get {
        /// Yield these bytes.
        Bytes(Vec<u8>),
        /// Fail the read, to assert the error propagates as an error
        /// rather than as a missing verdict.
        NotFound,
        /// Panic — asserts a kind must not cost a CAS read at all.
        Forbidden,
    }

    struct StubStorage(Get);

    impl StoragePort for StubStorage {
        fn put(
            &self,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<PutResult>> {
            Box::pin(async { unreachable!("test stub") })
        }
        fn get(
            &self,
            _hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            let bytes = match &self.0 {
                Get::Bytes(b) => Some(b.clone()),
                Get::NotFound => None,
                Get::Forbidden => panic!("this artifact kind must not cost a CAS read"),
            };
            Box::pin(async move {
                match bytes {
                    Some(b) => {
                        let r: Box<dyn AsyncRead + Send + Unpin> = Box::new(Cursor::new(b));
                        Ok(r)
                    }
                    None => Err(DomainError::NotFound {
                        entity: "content",
                        id: "x".into(),
                    }),
                }
            })
        }
        fn get_range(
            &self,
            _hash: &ContentHash,
            _range: ByteRange,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { unreachable!("test stub") })
        }
        fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { unreachable!("test stub") })
        }
        fn size_of(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
            Box::pin(async { unreachable!("test stub") })
        }
    }

    fn sample_hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    fn coords(name: &str, version: Option<&str>, path: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: version.map(str::to_string),
            path: path.to_string(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::Value::Null,
        }
    }

    fn storage_of(bytes: Vec<u8>) -> Arc<dyn StoragePort> {
        Arc::new(StubStorage(Get::Bytes(bytes)))
    }

    /// Build a gzip-tar from `(name, body)` pairs.
    ///
    /// The entry name is written straight into the header field rather
    /// than through `Header::set_path`, which refuses `..` — sensible for
    /// an archive writer, and exactly why it cannot build the hostile
    /// fixture the containment guard exists to refuse.
    fn gzip_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            let bytes = name.as_bytes();
            let field = &mut header.as_old_mut().name;
            field.fill(0);
            field[..bytes.len()].copy_from_slice(bytes);
            header.set_cksum();
            builder.append(&header, *body).expect("append");
        }
        let tar = builder.into_inner().expect("finish tar");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&tar).expect("gz write");
        enc.finish().expect("gz finish")
    }

    /// Build a gzip-tar from `(path, entry_type, body_or_link_target)`
    /// triples. A link entry carries its target in the third element and
    /// no body, mirroring `extract`'s own test builder.
    fn gzip_tar_typed(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, kind, body) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(*kind);
            header.set_mode(0o644);
            let is_link = *kind == tar::EntryType::Symlink || *kind == tar::EntryType::Link;
            let payload: &[u8] = if is_link { &[] } else { body };
            header.set_size(payload.len() as u64);
            if is_link {
                header
                    .set_link_name(std::str::from_utf8(body).expect("link name is utf-8"))
                    .expect("set_link_name");
            }
            header.set_path(path).expect("set_path");
            header.set_cksum();
            builder.append(&header, payload).expect("append");
        }
        let tar = builder.into_inner().expect("finish tar");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&tar).expect("gz write");
        enc.finish().expect("gz finish")
    }

    /// Build a plain (uncompressed) tar from `(name, body)` pairs.
    fn plain_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_path(name).expect("set_path");
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, *body).expect("append");
        }
        builder.into_inner().expect("finish tar")
    }

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, body) in entries {
                zw.start_file(*name, opts).expect("start_file");
                zw.write_all(body).expect("write_all");
            }
            zw.finish().expect("finish");
        }
        buf
    }

    /// Materialise `bytes` for `kind` and return the outcome.
    async fn materialise_kind(
        kind: ArtifactKind,
        coords: &ArtifactCoords,
        bytes: Vec<u8>,
    ) -> DomainResult<Materialised> {
        let storage = storage_of(bytes);
        let hash = sample_hash();
        let target = ScanTarget {
            content_hash: &hash,
            format: "maven",
            coords,
            kind,
        };
        materialise(&storage, &target, u64::MAX).await
    }

    fn expect_ready(m: Materialised) -> (ScanWorkspace, ScanMode) {
        match m {
            Materialised::Ready { ws, mode } => (ws, mode),
            Materialised::Nothing(reason) => {
                panic!("expected a materialised workspace, got Nothing({reason})")
            }
        }
    }

    fn expect_nothing(m: &Materialised) -> NotAnalysable {
        match m {
            Materialised::Nothing(reason) => *reason,
            Materialised::Ready { .. } => panic!("expected Nothing, got a workspace"),
        }
    }

    // -- plan derivation (pure) ----------------------------------------

    /// Resolve the plan for `kind` against `c`, without storage.
    fn plan_of(kind: ArtifactKind, c: &ArtifactCoords) -> Plan {
        let hash = sample_hash();
        plan_for(&ScanTarget {
            content_hash: &hash,
            format: "maven",
            coords: c,
            kind,
        })
    }

    #[test]
    fn plan_per_kind_matches_the_materialisation_table() {
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        assert_eq!(
            plan_of(ArtifactKind::MavenJar, &c),
            Plan::SingleFile {
                name: "a-1.0.jar".to_string(),
                mode: ScanMode::Rootfs,
            }
        );
        assert_eq!(
            plan_of(ArtifactKind::MavenPom, &c),
            Plan::SingleFile {
                name: "pom.xml".to_string(),
                mode: ScanMode::Fs,
            }
        );
        assert_eq!(
            plan_of(
                ArtifactKind::NpmTarball,
                &coords("lodash", Some("4.17.21"), "")
            ),
            Plan::Relocated {
                dest: "node_modules/lodash".to_string(),
                mode: ScanMode::Rootfs,
            }
        );
        assert_eq!(
            plan_of(ArtifactKind::CargoCrate, &c),
            Plan::GzipTar { mode: ScanMode::Fs }
        );
        assert_eq!(
            plan_of(ArtifactKind::PySdist, &c),
            Plan::GzipTar {
                mode: ScanMode::Rootfs
            }
        );
        assert_eq!(
            plan_of(ArtifactKind::PyWheel, &c),
            Plan::Zip {
                mode: ScanMode::Rootfs
            }
        );
        assert_eq!(plan_of(ArtifactKind::OciBlob, &c), Plan::OciBlob);
        assert_eq!(plan_of(ArtifactKind::OciManifest, &c), Plan::NotApplicable);
        assert_eq!(plan_of(ArtifactKind::Other, &c), Plan::NotApplicable);
    }

    /// The whole point of this item: the subcommand a kind is scanned
    /// with decides whether any analyzer runs at all. Trivy's coverage
    /// matrix puts every post-build artifact behind the Image and Rootfs
    /// targets and every pre-build declaration behind Filesystem and
    /// Repository, so a post-build kind on `fs` can never produce a
    /// verdict — which is exactly the shape of the defect this pins.
    #[test]
    fn scan_mode_per_kind_follows_the_coverage_matrix() {
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        let subcommand_of = |kind| match plan_of(kind, &c) {
            Plan::SingleFile { mode, .. }
            | Plan::GzipTar { mode }
            | Plan::Relocated { mode, .. }
            | Plan::Zip { mode } => Some(mode.subcommand()),
            // An OCI blob that turns out to be a layer is always a root
            // filesystem; one that does not is never scanned.
            Plan::OciBlob => Some(ScanMode::Rootfs.subcommand()),
            Plan::NotApplicable => None,
        };
        for (kind, expected) in [
            // Post-build artifacts: Image and Rootfs targets only.
            (ArtifactKind::MavenJar, Some("rootfs")),
            (ArtifactKind::PyWheel, Some("rootfs")),
            (ArtifactKind::PySdist, Some("rootfs")),
            (ArtifactKind::NpmTarball, Some("rootfs")),
            (ArtifactKind::OciBlob, Some("rootfs")),
            // Pre-build declarations: Filesystem and Repository targets.
            (ArtifactKind::MavenPom, Some("fs")),
            // `Cargo.lock` is read by every target.
            (ArtifactKind::CargoCrate, Some("fs")),
            // No package surface, no invocation.
            (ArtifactKind::OciManifest, None),
            (ArtifactKind::Other, None),
        ] {
            assert_eq!(subcommand_of(kind), expected, "{kind}");
        }
    }

    // -- capability map (pure) -----------------------------------------

    /// The kind axis of the capability map must not drift from the plan
    /// table it summarises: a kind with no plan is a kind no invocation
    /// is attempted for, so it can never yield a verdict.
    #[test]
    fn kind_materialisation_agrees_with_the_plan_table() {
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        for kind in [
            ArtifactKind::MavenJar,
            ArtifactKind::MavenPom,
            ArtifactKind::NpmTarball,
            ArtifactKind::CargoCrate,
            ArtifactKind::PySdist,
            ArtifactKind::PyWheel,
            ArtifactKind::OciBlob,
            ArtifactKind::OciManifest,
            ArtifactKind::Other,
        ] {
            assert_eq!(
                kind_is_materialisable(kind),
                plan_of(kind, &c) != Plan::NotApplicable,
                "{kind}: the capability answer must follow the plan table"
            );
        }
    }

    /// Pin the format set. A change here is a deliberate capability
    /// change — a cell gained or lost its known-vulnerable-fixture
    /// evidence — and the worker's parity guard makes the static record
    /// the apply path reads move with it.
    #[test]
    fn analysable_formats_are_the_five_compiled_in_handler_keys() {
        for format in ["oci", "maven", "pypi", "npm", "cargo"] {
            assert!(format_is_analysable(format), "{format} must be analysable");
        }
        // No compiled-in handler serves these, so every artifact under
        // them is kind `Other` and no materialisation applies.
        for format in ["gradle", "generic", "nuget", "", "OCI"] {
            assert!(
                !format_is_analysable(format),
                "{format} has no materialisable kind"
            );
        }
    }

    /// The format axis is derived, not hand-listed: every entry in the
    /// table owes its "yes" to a kind the plan table materialises.
    #[test]
    fn every_analysable_format_owes_its_answer_to_a_materialisable_kind() {
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        for (format, kinds) in FORMAT_KINDS {
            let materialisable: Vec<ArtifactKind> = kinds
                .iter()
                .copied()
                .filter(|k| plan_of(*k, &c) != Plan::NotApplicable)
                .collect();
            assert!(
                !materialisable.is_empty(),
                "{format} claims coverage but no kind of it has a plan"
            );
            assert!(format_is_analysable(format));
        }
    }

    #[test]
    fn npm_package_dir_keeps_a_scope_directory_and_refuses_unsafe_names() {
        let dir = |name: &str| npm_package_dir(&coords(name, Some("1.0.0"), ""));
        assert_eq!(dir("lodash"), "node_modules/lodash");
        assert_eq!(dir("@types/node"), "node_modules/@types/node");
        // A name that is not a registry name: the package still has to
        // land under node_modules or no analyzer will look at it, so the
        // prefix survives and only the leaf is replaced.
        assert_eq!(dir("../../evil"), "node_modules/package");
        assert_eq!(dir("scope/pkg"), "node_modules/package");
        assert_eq!(dir("@scope/a/b"), "node_modules/package");
        assert_eq!(dir(""), "node_modules/package");
        assert_eq!(dir(".."), "node_modules/package");
    }

    #[test]
    fn java_archive_filename_prefers_the_artifacts_own_name() {
        for (path, expected) in [
            (
                "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
                "log4j-core-2.14.1.jar",
            ),
            ("com/example/app/1.0/app-1.0.war", "app-1.0.war"),
            ("com/example/app/1.0/app-1.0.EAR", "app-1.0.EAR"),
        ] {
            assert_eq!(
                java_archive_filename(&coords("com.example:app", Some("1.0"), path)),
                expected
            );
        }
    }

    #[test]
    fn java_archive_filename_reconstructs_from_coordinates_when_the_path_is_unusable() {
        // A path whose last segment is not a Java archive name at all.
        assert_eq!(
            java_archive_filename(&coords(
                "org.apache.logging.log4j:log4j-core",
                Some("2.14.1"),
                "org/apache/logging/log4j/log4j-core/2.14.1/"
            )),
            "log4j-core-2.14.1.jar"
        );
        // No version recorded.
        assert_eq!(
            java_archive_filename(&coords("g:a", None, "")),
            "a-unknown.jar"
        );
    }

    /// The reconstructed name must never smuggle a path separator out of
    /// repository data.
    #[test]
    fn java_archive_filename_falls_back_when_coordinates_are_unsafe() {
        assert_eq!(
            java_archive_filename(&coords("g:../../evil", Some("1.0"), "no-extension")),
            FALLBACK_JAVA_ARCHIVE_NAME
        );
    }

    #[test]
    fn is_safe_filename_refuses_separators_and_relative_tokens() {
        assert!(is_safe_filename("a-1.0.jar"));
        assert!(!is_safe_filename(""));
        assert!(!is_safe_filename("."));
        assert!(!is_safe_filename(".."));
        assert!(!is_safe_filename("a/b.jar"));
        assert!(!is_safe_filename("a\\b.jar"));
        assert!(!is_safe_filename("a\0b.jar"));
    }

    #[test]
    fn java_archive_extension_matching_is_case_insensitive_and_exact() {
        assert!(has_java_archive_extension("a.jar"));
        assert!(has_java_archive_extension("a.WAR"));
        assert!(has_java_archive_extension("a.Ear"));
        assert!(has_java_archive_extension("a.par"));
        assert!(!has_java_archive_extension("a.aar"));
        assert!(!has_java_archive_extension("a.jar.sha1"));
        assert!(!has_java_archive_extension("jar"));
    }

    #[test]
    fn scan_mode_maps_to_the_documented_subcommands() {
        assert_eq!(ScanMode::Fs.subcommand(), "fs");
        assert_eq!(ScanMode::Rootfs.subcommand(), "rootfs");
    }

    // -- container sniffing (pure) -------------------------------------

    #[test]
    fn sniff_recognises_gzip_and_the_unsupported_compressors() {
        assert_eq!(sniff_container(&[0x1f, 0x8b, 0x08]), Container::Gzip);
        assert_eq!(
            sniff_container(&[0x28, 0xb5, 0x2f, 0xfd, 0x00]),
            Container::UnsupportedCompression("zstd")
        );
        assert_eq!(
            sniff_container(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
            Container::UnsupportedCompression("xz")
        );
        assert_eq!(
            sniff_container(b"BZh9something"),
            Container::UnsupportedCompression("bzip2")
        );
    }

    #[test]
    fn sniff_recognises_a_posix_tar_by_its_magic() {
        let tar = plain_tar(&[("etc/hostname", b"host")]);
        assert_eq!(sniff_container(&tar), Container::Tar);
    }

    #[test]
    fn sniff_treats_json_and_short_input_as_not_an_archive() {
        assert_eq!(
            sniff_container(br#"{"architecture":"amd64"}"#),
            Container::NotAnArchive
        );
        assert_eq!(sniff_container(&[]), Container::NotAnArchive);
        assert_eq!(sniff_container(&[0x1f]), Container::NotAnArchive);
    }

    // -- materialisation: single file ----------------------------------

    #[tokio::test]
    async fn maven_jar_is_written_under_its_own_name_in_rootfs_mode() {
        let c = coords(
            "org.apache.logging.log4j:log4j-core",
            Some("2.14.1"),
            "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
        );
        let m = materialise_kind(ArtifactKind::MavenJar, &c, b"PK\x03\x04fake jar".to_vec())
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(
            mode,
            ScanMode::Rootfs,
            "a Java archive is post-build; only the Image and Rootfs targets run its analyzer"
        );
        let written =
            std::fs::read(ws.dir().join("log4j-core-2.14.1.jar")).expect("jar must be written");
        assert_eq!(written, b"PK\x03\x04fake jar");
    }

    #[tokio::test]
    async fn maven_pom_is_written_as_pom_xml() {
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.pom");
        let m = materialise_kind(ArtifactKind::MavenPom, &c, b"<project/>".to_vec())
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(mode, ScanMode::Fs);
        assert_eq!(
            std::fs::read(ws.dir().join("pom.xml")).expect("pom.xml must be written"),
            b"<project/>"
        );
        assert!(
            !ws.dir().join("a-1.0.pom").exists(),
            "the artifact's own name matches no analyzer and must not be used"
        );
    }

    // -- materialisation: extraction -----------------------------------

    /// Trivy claims a `package.json` only when its path lies under
    /// `node_modules`, and the tarball's own `package/` root is not part
    /// of the installed path — so the manifest has to end up at
    /// `node_modules/<name>/package.json`, exactly where `npm install`
    /// would put it. One level too deep and the analyzer never runs.
    #[tokio::test]
    async fn npm_tarball_is_extracted_into_node_modules_under_its_package_name() {
        let c = coords("lodash", Some("4.17.21"), "lodash/-/lodash-4.17.21.tgz");
        let bytes = gzip_tar(&[
            ("package/package.json", br#"{"name":"lodash"}"#),
            ("package/index.js", b"module.exports = {};"),
        ]);
        let m = materialise_kind(ArtifactKind::NpmTarball, &c, bytes)
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(mode, ScanMode::Rootfs);
        assert_eq!(
            std::fs::read(ws.dir().join("node_modules/lodash/package.json")).expect("read"),
            br#"{"name":"lodash"}"#
        );
        assert!(
            ws.dir().join("node_modules/lodash/index.js").exists(),
            "the rest of the package travels with the manifest"
        );
        assert!(
            !ws.dir().join("node_modules/lodash/package").exists(),
            "the tarball's own root directory is not part of the installed path"
        );
    }

    /// A scoped package keeps its `@scope/` directory — that is the
    /// installed layout, and the scope is part of the name Trivy reads
    /// back out of the path.
    #[tokio::test]
    async fn a_scoped_npm_tarball_keeps_its_scope_directory() {
        let c = coords(
            "@types/node",
            Some("20.1.0"),
            "@types/node/-/node-20.1.0.tgz",
        );
        let bytes = gzip_tar(&[("package/package.json", br#"{"name":"@types/node"}"#)]);
        let m = materialise_kind(ArtifactKind::NpmTarball, &c, bytes)
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(mode, ScanMode::Rootfs);
        assert_eq!(
            std::fs::read(ws.dir().join("node_modules/@types/node/package.json")).expect("read"),
            br#"{"name":"@types/node"}"#
        );
    }

    /// An archive that is not wrapped in a single root directory is
    /// planted whole rather than guessed at: there is no wrapper to
    /// strip, and stripping one of several roots would invent evidence.
    #[tokio::test]
    async fn an_npm_tarball_without_a_single_root_directory_is_planted_whole() {
        let c = coords("flat", Some("1.0.0"), "flat/-/flat-1.0.0.tgz");
        let bytes = gzip_tar(&[
            ("package.json", br#"{"name":"flat"}"#),
            ("index.js", b"module.exports = {};"),
        ]);
        let m = materialise_kind(ArtifactKind::NpmTarball, &c, bytes)
            .await
            .expect("materialise");
        let (ws, _) = expect_ready(m);
        assert_eq!(
            std::fs::read(ws.dir().join("node_modules/flat/package.json")).expect("read"),
            br#"{"name":"flat"}"#
        );
    }

    #[tokio::test]
    async fn wheel_is_extracted_so_the_dist_info_metadata_is_a_real_path() {
        let c = coords(
            "urllib3",
            Some("1.26.4"),
            "simple/urllib3/urllib3-1.26.4-py2.py3-none-any.whl",
        );
        let bytes = zip_of(&[(
            "urllib3-1.26.4.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: urllib3\nVersion: 1.26.4\n",
        )]);
        let m = materialise_kind(ArtifactKind::PyWheel, &c, bytes)
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(
            mode,
            ScanMode::Rootfs,
            "a wheel's dist-info is post-build metadata; only Image and Rootfs read it"
        );
        assert!(ws.dir().join("urllib3-1.26.4.dist-info/METADATA").exists());
    }

    #[tokio::test]
    async fn an_sdist_is_extracted_in_rootfs_mode() {
        let c = coords(
            "evidence",
            Some("1.0.0"),
            "simple/evidence/evidence-1.0.0.tar.gz",
        );
        let bytes = gzip_tar(&[(
            "evidence-1.0.0/evidence.egg-info/PKG-INFO",
            b"Metadata-Version: 2.1\nName: evidence\nVersion: 1.0.0\n",
        )]);
        let m = materialise_kind(ArtifactKind::PySdist, &c, bytes)
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(mode, ScanMode::Rootfs);
        assert!(ws
            .dir()
            .join("evidence-1.0.0/evidence.egg-info/PKG-INFO")
            .exists());
    }

    #[tokio::test]
    async fn a_cargo_crate_is_extracted_in_fs_mode() {
        let c = coords(
            "evidence",
            Some("1.0.0"),
            "crates/evidence/1.0.0/evidence-1.0.0.crate",
        );
        let bytes = gzip_tar(&[
            (
                "evidence-1.0.0/Cargo.toml",
                b"[package]\nname = \"evidence\"\n",
            ),
            ("evidence-1.0.0/Cargo.lock", b"version = 3\n"),
        ]);
        let m = materialise_kind(ArtifactKind::CargoCrate, &c, bytes)
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(
            mode,
            ScanMode::Fs,
            "Cargo.lock is read by every target, and fs also reads the pre-build side"
        );
        assert!(ws.dir().join("evidence-1.0.0/Cargo.lock").exists());
    }

    #[tokio::test]
    async fn oci_gzip_layer_is_extracted_as_a_rootfs() {
        let c = coords("library/nginx", None, "blobs/sha256:aa");
        let bytes = gzip_tar(&[("var/lib/dpkg/status", b"Package: zlib1g\n")]);
        let m = materialise_kind(ArtifactKind::OciBlob, &c, bytes)
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(
            mode,
            ScanMode::Rootfs,
            "a layer's package database is only read by the rootfs target"
        );
        assert!(ws.dir().join("var/lib/dpkg/status").exists());
    }

    #[tokio::test]
    async fn oci_uncompressed_tar_layer_is_extracted_as_a_rootfs() {
        let c = coords("library/nginx", None, "blobs/sha256:aa");
        let bytes = plain_tar(&[("lib/apk/db/installed", b"P:musl\n")]);
        let m = materialise_kind(ArtifactKind::OciBlob, &c, bytes)
            .await
            .expect("materialise");
        let (ws, mode) = expect_ready(m);
        assert_eq!(mode, ScanMode::Rootfs);
        assert!(ws.dir().join("lib/apk/db/installed").exists());
    }

    /// The regression this change exists for: a real root filesystem
    /// layer's absolute symlink (`/bin/sh -> /bin/busybox`) must not
    /// refuse the archive. Before this fix the layer's regular files
    /// released fine but the layer itself held forever on
    /// `UnusableArchive`, because the extractor treated the ordinary
    /// shape of a root filesystem as an escape attempt.
    #[tokio::test]
    async fn oci_layer_with_an_absolute_symlink_extracts_and_skips_the_link() {
        let c = coords("library/alpine", None, "blobs/sha256:aa");
        let bytes = gzip_tar_typed(&[
            ("bin/busybox", tar::EntryType::Regular, b"binary"),
            ("bin/sh", tar::EntryType::Symlink, b"/bin/busybox"),
            ("lib/apk/db/installed", tar::EntryType::Regular, b"P:musl\n"),
        ]);
        let m = materialise_kind(ArtifactKind::OciBlob, &c, bytes)
            .await
            .expect("an absolute symlink target must not refuse the archive");
        let (ws, mode) = expect_ready(m);
        assert_eq!(mode, ScanMode::Rootfs);
        assert!(ws.dir().join("bin/busybox").exists());
        assert!(ws.dir().join("lib/apk/db/installed").exists());
        assert!(
            !ws.dir().join("bin/sh").exists(),
            "a symlink entry must not be materialised"
        );
        assert_eq!(
            ws.skipped_links(),
            1,
            "the absolute symlink target must be skipped and counted, not refused"
        );
    }

    /// The raw payload is never a scan target: it is written beside the
    /// directory Trivy is pointed at, and removed once extracted.
    #[tokio::test]
    async fn the_downloaded_archive_is_not_left_inside_the_scan_directory() {
        let c = coords("lodash", Some("1.0.0"), "lodash/-/lodash-1.0.0.tgz");
        let bytes = gzip_tar(&[("package/package.json", b"{}")]);
        let m = materialise_kind(ArtifactKind::NpmTarball, &c, bytes)
            .await
            .expect("materialise");
        let (ws, _) = expect_ready(m);
        assert!(!ws.dir().join(DOWNLOAD_FILENAME).exists());
        let entries: Vec<String> = std::fs::read_dir(ws.dir())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec![NODE_MODULES_DIR.to_string()]);
    }

    /// The staging directory an npm tarball is unpacked into before the
    /// move lives *outside* the tree Trivy is pointed at, so the
    /// pre-strip layout is never a scan target.
    #[tokio::test]
    async fn the_relocation_staging_directory_is_not_a_scan_target() {
        let c = coords("lodash", Some("1.0.0"), "lodash/-/lodash-1.0.0.tgz");
        let bytes = gzip_tar(&[("package/package.json", b"{}")]);
        let m = materialise_kind(ArtifactKind::NpmTarball, &c, bytes)
            .await
            .expect("materialise");
        let (ws, _) = expect_ready(m);
        assert!(!ws.dir().join(STAGING_SUBDIR).exists());
    }

    // -- workspace listing (the empty-report diagnostic) ----------------

    /// The listing is the half of the "no analysed target" warning that
    /// says what the scanner was actually pointed at. Names are relative
    /// to the scan directory and sorted, so two runs read the same.
    #[tokio::test]
    async fn the_workspace_listing_names_files_relative_to_the_scan_directory() {
        let c = coords("lodash", Some("4.17.21"), "lodash/-/lodash-4.17.21.tgz");
        let bytes = gzip_tar(&[
            ("package/package.json", br#"{"name":"lodash"}"#),
            ("package/index.js", b"module.exports = {};"),
        ]);
        let m = materialise_kind(ArtifactKind::NpmTarball, &c, bytes)
            .await
            .expect("materialise");
        let (ws, _) = expect_ready(m);
        assert_eq!(
            ws.listing().await,
            "node_modules/lodash/index.js, node_modules/lodash/package.json"
        );
    }

    /// A tree with more files than the cap is truncated rather than
    /// dumped: this is a diagnostic on an already-failed scan, not
    /// evidence, and the tree is attacker-influenced.
    #[tokio::test]
    async fn the_workspace_listing_is_capped_and_marks_the_truncation() {
        let entries: Vec<(String, Vec<u8>)> = (0..MAX_LISTED_FILES + 5)
            .map(|i| (format!("evidence-1.0.0/f{i:03}.py"), b"x".to_vec()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let c = coords("evidence", Some("1.0.0"), "simple/evidence/e-1.0.0.tar.gz");
        let m = materialise_kind(ArtifactKind::PySdist, &c, gzip_tar(&borrowed))
            .await
            .expect("materialise");
        let (ws, _) = expect_ready(m);
        let listing = ws.listing().await;
        assert_eq!(
            listing.split(", ").count(),
            MAX_LISTED_FILES + 1,
            "{MAX_LISTED_FILES} names plus the truncation marker: {listing}"
        );
        assert!(listing.ends_with('…'), "{listing}");
    }

    // -- materialisation: nothing to analyse ---------------------------

    #[tokio::test]
    async fn manifest_and_unclaimed_kinds_are_not_applicable_without_a_cas_read() {
        // A `get` must not even be attempted; `Get::Forbidden` panics if
        // one is, which is what makes the "no CAS read" claim assertable.
        let storage: Arc<dyn StoragePort> = Arc::new(StubStorage(Get::Forbidden));
        let hash = sample_hash();
        let c = coords("library/nginx", None, "manifests/sha256:aa");
        for kind in [ArtifactKind::OciManifest, ArtifactKind::Other] {
            let target = ScanTarget {
                content_hash: &hash,
                format: "oci",
                coords: &c,
                kind,
            };
            let m = materialise(&storage, &target, u64::MAX)
                .await
                .expect("materialise");
            assert_eq!(expect_nothing(&m), NotAnalysable::NotApplicable, "{kind}");
        }
    }

    /// An OCI config blob is JSON, not a layer: no package surface, and
    /// that is a clean "not applicable", not a refusal.
    #[tokio::test]
    async fn oci_config_blob_is_not_applicable() {
        let c = coords("library/nginx", None, "blobs/sha256:aa");
        let m = materialise_kind(
            ArtifactKind::OciBlob,
            &c,
            br#"{"architecture":"amd64","os":"linux"}"#.to_vec(),
        )
        .await
        .expect("materialise");
        assert_eq!(expect_nothing(&m), NotAnalysable::NotApplicable);
    }

    /// A zstd layer is an archive this adapter cannot open. It is refused
    /// — named as unusable rather than reported clean — so the gap is
    /// visible instead of silently passing.
    #[tokio::test]
    async fn oci_zstd_layer_is_an_unusable_archive() {
        let c = coords("library/nginx", None, "blobs/sha256:aa");
        let m = materialise_kind(
            ArtifactKind::OciBlob,
            &c,
            vec![0x28, 0xb5, 0x2f, 0xfd, 0x01, 0x02, 0x03],
        )
        .await
        .expect("materialise");
        assert_eq!(expect_nothing(&m), NotAnalysable::UnusableArchive);
    }

    #[tokio::test]
    async fn a_payload_that_is_not_the_declared_container_is_an_unusable_archive() {
        let c = coords("lodash", Some("1.0.0"), "lodash/-/lodash-1.0.0.tgz");
        let m = materialise_kind(
            ArtifactKind::NpmTarball,
            &c,
            b"this is not a gzip-tar".to_vec(),
        )
        .await
        .expect("materialise");
        assert_eq!(expect_nothing(&m), NotAnalysable::UnusableArchive);
    }

    #[tokio::test]
    async fn an_archive_whose_entry_escapes_the_workspace_is_refused() {
        let c = coords("lodash", Some("1.0.0"), "lodash/-/lodash-1.0.0.tgz");
        let bytes = gzip_tar(&[("../escaped.js", b"payload")]);
        let m = materialise_kind(ArtifactKind::NpmTarball, &c, bytes)
            .await
            .expect("materialise");
        assert_eq!(expect_nothing(&m), NotAnalysable::UnusableArchive);
    }

    #[tokio::test]
    async fn a_wheel_that_is_not_a_zip_is_refused() {
        let c = coords("pkg", Some("1.0"), "simple/pkg/pkg-1.0-py3-none-any.whl");
        let m = materialise_kind(ArtifactKind::PyWheel, &c, b"not a zip".to_vec())
            .await
            .expect("materialise");
        assert_eq!(expect_nothing(&m), NotAnalysable::UnusableArchive);
    }

    // -- input cap and cleanup -----------------------------------------

    #[tokio::test]
    async fn oversize_artifact_is_rejected_pre_scan() {
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        let storage = storage_of(vec![0xAB; 64]);
        let hash = sample_hash();
        let target = ScanTarget {
            content_hash: &hash,
            format: "maven",
            coords: &c,
            kind: ArtifactKind::MavenJar,
        };
        match materialise(&storage, &target, 16).await {
            Err(DomainError::Invariant(msg)) => {
                assert!(msg.contains("trivy adapter"), "{msg}");
                assert!(
                    msg.contains("16") && msg.to_lowercase().contains("exceed"),
                    "error must name the cap and that it was exceeded: {msg}"
                );
            }
            Err(other) => panic!("expected Invariant error, got {other:?}"),
            Ok(_) => panic!("oversize artifact must be rejected"),
        }
    }

    #[tokio::test]
    async fn artifact_exactly_at_the_cap_is_accepted_and_roundtrips() {
        let payload = b"exactly-thirty-two-bytes-here!!!".to_vec();
        assert_eq!(payload.len(), 32);
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        let storage = storage_of(payload.clone());
        let hash = sample_hash();
        let target = ScanTarget {
            content_hash: &hash,
            format: "maven",
            coords: &c,
            kind: ArtifactKind::MavenJar,
        };
        let m = materialise(&storage, &target, 32)
            .await
            .expect("at-cap artifact must be accepted");
        let (ws, _) = expect_ready(m);
        assert_eq!(
            std::fs::read(ws.dir().join("a-1.0.jar")).expect("read"),
            payload
        );
    }

    #[tokio::test]
    async fn storage_failures_propagate_as_errors_not_as_a_missing_verdict() {
        let storage: Arc<dyn StoragePort> = Arc::new(StubStorage(Get::NotFound));
        let hash = sample_hash();
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        let target = ScanTarget {
            content_hash: &hash,
            format: "maven",
            coords: &c,
            kind: ArtifactKind::MavenJar,
        };
        let r = materialise(&storage, &target, u64::MAX).await;
        assert!(matches!(r, Err(DomainError::NotFound { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn workspace_drop_removes_the_whole_tree() {
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        let dir_path: PathBuf;
        {
            let m = materialise_kind(ArtifactKind::MavenJar, &c, vec![1, 2, 3])
                .await
                .expect("materialise");
            let (ws, _) = expect_ready(m);
            dir_path = ws.dir().to_path_buf();
            assert!(dir_path.exists());
        }
        assert!(
            !dir_path.exists(),
            "TempDir drop should remove the workspace at {}",
            dir_path.display()
        );
    }
}
