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
//! `Cargo.lock` is read by all four. Picking the wrong one means the
//! analyzer never runs: the report comes back with no analysed target and
//! the artifact can never get a verdict.
//!
//! The table below is the **per-blob** path, and its mode column is
//! therefore `rootfs` or `fs`. There is a third mode, and it is not in
//! the table because it is not chosen by a kind: an image manifest
//! together with the config and layers its bytes name is materialised as
//! an OCI image layout and scanned with `trivy image --input`
//! (ADR 0064 D1, [`crate::oci_layout`]). That the Container Image target
//! was once written off here — "hort has no container image to scan" —
//! was a derivation, not a decision: hort holds the manifest, the config
//! and every layer, and the manifest bytes name them in order. The
//! material was always present; it was never assembled.
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
//! | `OciBlob` (JSON, or no bytes) | nothing — no scanner invocation          | —          | an image config carries no package surface |
//! | `OciBlob` (unidentifiable)    | nothing — the blob is refused            | —          | unknown bytes are not an absence of package surface; see *Fail-closed* below |
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
//!   a CAS read. For an OCI blob that reading has to be *earned* — the
//!   blob is recognised as a JSON document or as empty, never inferred
//!   from "it did not look like an archive" ([`sniff_container`]).
//!
//! # Fail-closed, not best-effort
//!
//! Nothing here degrades. A payload whose entries trip a bound in
//! [`crate::extract`] yields [`NotAnalysable::UnusableArchive`], and a
//! payload in a container this adapter has no decoder for yields
//! [`NotAnalysable::UnsupportedContainer`] ([`refusal_of`] is the one
//! definition of which is which). Either way no scan runs — never a
//! partially extracted tree. A half-unpacked archive scanned as if it
//! were whole is precisely the false-clean this module exists to
//! eliminate.
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
use hort_domain::oci::ImageBudget;
use hort_domain::ports::scanner::{ComposedImage, NotAnalysable, ScanTarget, ScanUnit};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{ArtifactCoords, ArtifactKind, ContentHash};
use tempfile::{Builder, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::extract::{extract_tar, extract_zip, ExtractBounds, ExtractError, ExtractStats};
use crate::oci_layout::write_image_layout;

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
    /// `trivy image --input <dir>` — the directory is an OCI image
    /// layout, and the scanner composes the layers itself: it applies
    /// them in manifest order, resolves whiteouts and opaque whiteouts,
    /// and derives the OS identity from the composed tree (ADR 0064 D1).
    ///
    /// The distinction from [`Self::Rootfs`] is not the analyzer set but
    /// *what the analyzers see*: `rootfs` reads one layer as if it were a
    /// whole filesystem, which is how a package database in a layer with
    /// no OS marker of its own goes unassessed.
    Image,
}

impl ScanMode {
    /// The Trivy subcommand literal.
    pub(crate) fn subcommand(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Rootfs => "rootfs",
            Self::Image => "image",
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

/// Decide the materialisation for a single stored object. The module
/// doc's table is this function; the "why that mode" column cites Trivy's
/// coverage matrix, which is the authority on which target runs which
/// analyzer.
///
/// Takes the kind and the coords rather than the whole
/// [`ScanTarget`](hort_domain::ports::scanner::ScanTarget) because the
/// table is about one blob: a composed image is materialised from its own
/// resolved description (see [`crate::oci_layout`]) and never reaches
/// here.
fn plan_for(kind: ArtifactKind, coords: &ArtifactCoords) -> Plan {
    match kind {
        // A Java archive is a post-build artifact, claimed only by the
        // Image and Rootfs targets.
        ArtifactKind::MavenJar => Plan::SingleFile {
            name: java_archive_filename(coords),
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
            dest: npm_package_dir(coords),
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
    /// Positively identified as carrying no package surface: an OCI
    /// blob that is a JSON document (the image config, and every
    /// JSON-media-type OCI artifact blob), or a blob with no bytes at
    /// all. Carries the shape for the log line.
    ///
    /// Distinct from [`Self::Unidentified`] because only this arm is a
    /// *completed fact about the artifact*. A JSON document and a blob
    /// of no bytes both exclude a package surface by construction —
    /// there is no tar header, no archive, nothing an analyzer could
    /// have claimed — so there is nothing for a hold to wait on.
    NoPackageSurface(&'static str),
    /// The leading bytes match no container this adapter decodes and no
    /// shape it recognises as carrying nothing. What is inside is
    /// unknown, which is the one answer that must not be read as "no
    /// package surface": a tar without the POSIX magic (a pre-POSIX v7
    /// archive, or one whose header was truncated) is a filesystem this
    /// blob would have been scanned as.
    ///
    /// A statement about the payload's own bytes, not about this
    /// adapter's decoder inventory — the inventory can only be named
    /// for a container that was positively identified, which this one
    /// was not (ADR 0064 D2 draws the line there). So it fails closed
    /// through [`ExtractError::Malformed`] →
    /// [`NotAnalysable::UnusableArchive`].
    Unidentified,
}

/// Classify a blob's container from its leading bytes.
///
/// Sniffing rather than trusting a declared media type is not a shortcut
/// here: an OCI blob row carries `application/octet-stream` whatever role
/// the manifest assigns it, so there is no media type to trust. The
/// `ustar` magic at offset 257 is the POSIX tar identifier.
///
/// **Every arm but the last is a positive identification, and the last
/// one fails closed.** A sniffer's residue is "I do not know what these
/// bytes are", and for an OCI blob the two candidate readings of that —
/// "this is the image config, there is nothing to scan" and "this is a
/// layer in a shape I did not recognise" — have opposite consequences
/// for the release gate. So the non-archive shapes are recognised
/// *positively* (a JSON document, an empty blob) and everything left
/// over is [`Container::Unidentified`]: a pre-POSIX v7 tar carries no
/// magic, and reading it as "no package surface" would release an
/// unassessed root filesystem.
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
    // Zero bytes hold no package surface, and that is provable rather
    // than assumed: there is nothing in them for any analyzer to claim.
    if head.is_empty() {
        return Container::NoPackageSurface("empty");
    }
    // A JSON document — the OCI image config, and the shape every
    // JSON-media-type OCI artifact blob (attestations, SBOM
    // attachments, signature payloads) takes. Leading ASCII whitespace
    // is skipped because JSON permits it; a document behind a byte-order
    // mark is left unidentified, which is the fail-closed side.
    if head
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'{' || *b == b'[')
    {
        return Container::NoPackageSurface("json");
    }
    Container::Unidentified
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
    match target.unit {
        // A composition is materialised from its own resolved
        // description and from nothing else. Note what the per-blob
        // table below would make of the same row: an image manifest's
        // kind is `OciManifest`, whose plan is `NotApplicable`, because
        // the manifest's *own* bytes carry no package surface. The
        // composition it names does, and it is a different input.
        ScanUnit::Image(image) => materialise_image(storage, target, image).await,
        ScanUnit::Blob(hash) => materialise_blob(storage, target, hash, max_artifact_size).await,
    }
}

/// Materialise a composed OCI image as an image layout and point
/// `trivy image --input` at it (ADR 0064 D1).
///
/// A refusal takes one of two shapes, and which one it takes is the
/// refusal's own answer to "would running this again help"
/// ([`LayoutRefusal::is_transient`]):
///
/// - **Deterministic** — the image declares more constituents or more
///   bytes than hort will assemble, or a constituent is simply not in
///   CAS. [`Materialised::Nothing`] carrying
///   [`NotAnalysable::IncompleteComposition`], which no assembled
///   composition can produce, so "I could not build the image" never
///   arrives looking like "I built it and it reported nothing". The scan
///   axis has a state for "no verdict" that the job queue will not spin
///   on, and re-running an over-budget image is pure delay.
/// - **Transient** — a stalled storage stream, a failed read, a full
///   scratch disk. An `Err`, because that is the answer the orchestrator
///   already reschedules: a backend that errored may succeed on the next
///   attempt, so it earns the scan job's existing attempt budget. Folding
///   it into the deterministic value instead would turn a momentary
///   infrastructure condition into a permanent-looking absence of
///   assessment.
async fn materialise_image(
    storage: &Arc<dyn StoragePort>,
    target: &ScanTarget<'_>,
    image: &ComposedImage,
) -> DomainResult<Materialised> {
    let tmp = Builder::new()
        .prefix("hort-scan-trivy-image-")
        .tempdir()
        .map_err(|e| {
            DomainError::Invariant(format!(
                "trivy adapter: failed to create temp workspace: {e}"
            ))
        })?;
    let layout_dir = tmp.path().join(TARGET_SUBDIR);
    tokio::fs::create_dir(&layout_dir).await.map_err(|e| {
        DomainError::Invariant(format!(
            "trivy adapter: failed to create image layout directory: {e}"
        ))
    })?;

    let budget = ImageBudget::default_for_composite_scan();
    match write_image_layout(storage, image, &layout_dir, budget).await {
        Ok(stats) => {
            tracing::debug!(
                scanner = "trivy",
                manifest = %image.manifest(),
                layers = image.layers().len(),
                blobs = stats.blobs,
                bytes = stats.bytes,
                "trivy adapter: materialised a composed image layout"
            );
            Ok(Materialised::Ready {
                ws: ScanWorkspace {
                    tmp,
                    target_dir: layout_dir,
                    // Nothing is unpacked on this path, so there is no
                    // archive entry to have skipped.
                    skipped_links: 0,
                },
                mode: ScanMode::Image,
            })
        }
        Err(refusal) if refusal.is_transient() => {
            // `warn!` and an `Err`: the composition did not fail to
            // exist, the machine failed to produce it, and the two must
            // not land on the same outcome. The orchestrator's
            // backend-error path reschedules under the job's own attempt
            // budget; exhausting it lands back on the deterministic
            // no-verdict below.
            tracing::warn!(
                scanner = "trivy",
                manifest = %image.manifest(),
                format = target.format,
                layers = image.layers().len(),
                reason = %refusal,
                "trivy adapter: could not assemble the composed image for a transient \
                 reason; no composite verdict this attempt"
            );
            Err(DomainError::Invariant(format!(
                "trivy adapter: composing image sha256:{} did not complete: {refusal}",
                image.manifest()
            )))
        }
        Err(refusal) => {
            // `warn!`, not `error!`: the worker is healthy and the
            // composition is held, which is the designed outcome. The
            // refusal names the constituent, which is the actionable
            // part; the artifact id stays on the span.
            tracing::warn!(
                scanner = "trivy",
                manifest = %image.manifest(),
                format = target.format,
                layers = image.layers().len(),
                reason = %refusal,
                "trivy adapter: refusing to assemble the composed image; no composite verdict"
            );
            Ok(Materialised::Nothing(NotAnalysable::IncompleteComposition))
        }
    }
}

/// Materialise one stored object by its [`ArtifactKind`] — the per-blob
/// path, unchanged, bounded per artifact by `max_artifact_size`.
async fn materialise_blob(
    storage: &Arc<dyn StoragePort>,
    target: &ScanTarget<'_>,
    content_hash: &ContentHash,
    max_artifact_size: u64,
) -> DomainResult<Materialised> {
    let plan = plan_for(target.kind, target.coords);
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
            stream_to_file(storage, content_hash, &path, max_artifact_size).await?;
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
            let size = stream_to_file(storage, content_hash, &download, max_artifact_size).await?;
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
                    let why = refusal_of(&e);
                    // `warn!`, not `error!`: the worker is healthy and the
                    // artifact is held, which is the designed outcome. The
                    // guard that fired is the actionable part; the
                    // artifact id stays on the span.
                    //
                    // `abstention` is on the line because the two
                    // refusals are different facts about different
                    // things and an operator triaging a held artifact
                    // needs to know which one happened — a compression
                    // format hort has no decoder for reads nothing like
                    // a zip bomb, and before the split they were the
                    // same line.
                    tracing::warn!(
                        scanner = "trivy",
                        kind = kind.as_str(),
                        format = target.format,
                        reason = %e,
                        abstention = why.as_str(),
                        "trivy adapter: refusing to materialise archive; no scan will run"
                    );
                    Ok(Materialised::Nothing(why))
                }
            }
        }
    }
}

/// Which abstention one extraction refusal is.
///
/// The **one** definition of the mapping, so the log line's label and
/// the value handed to the orchestrator cannot describe the refusal
/// differently. An exhaustive match rather than a wildcard: a future
/// `ExtractError` variant has to state which side it is on instead of
/// inheriting an answer.
///
/// Both answers gate the artifact today
/// ([`NotAnalysable::gates_release`]). The split says *what the refusal
/// is a statement about*, which is the thing ADR 0064 D2 turns on:
///
/// - [`NotAnalysable::UnsupportedContainer`] — "I have no decoder for
///   this container". The container was positively identified from its
///   own leading bytes and nothing inside it was reached, so this is a
///   fact about this adapter's decoder inventory, not about the
///   payload. The composition decodes `tar+zstd` without difficulty.
/// - [`NotAnalysable::UnusableArchive`] — everything else: a bound the
///   archive tripped, an entry that tried to escape the workspace, an
///   entry name that could not be put to the containment rule, or an
///   archive that could not be read. All statements about the payload's
///   own bytes.
///
/// [`ExtractError::Malformed`] is on the second side even though it
/// covers "could not be read", and that is the deliberate fail-closed
/// choice: the readers behind it (`tar::Archive::entries`,
/// `zip::ZipArchive::new`, a `GzDecoder` handed non-gzip bytes) report
/// a container they have no decoder for and a corrupt archive of a
/// container they do decode with the same error, so the distinction is
/// not available at this point. Guessing would move a real refusal off
/// the gating side.
fn refusal_of(error: &ExtractError) -> NotAnalysable {
    match error {
        ExtractError::UnsupportedContainer { .. } => NotAnalysable::UnsupportedContainer,
        ExtractError::ExtractedBytesCap { .. }
        | ExtractError::CompressionRatioCap { .. }
        | ExtractError::EntryCap { .. }
        | ExtractError::UncontainedPath
        | ExtractError::UndecodableEntryName { .. }
        | ExtractError::Malformed(_) => NotAnalysable::UnusableArchive,
    }
}

/// The blocking half of extraction.
///
/// `Ok(Some((mode, stats)))` — a tree was produced, scan it in `mode`.
/// `Ok(None)` — the payload was positively identified as holding no
/// package surface (an OCI config, an empty blob); no scan applies.
/// `Err` — the archive was refused, which an unidentifiable blob is one
/// case of.
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
                // reporting the layer clean — and it names it as a
                // missing decoder rather than as a complaint about the
                // bytes, which is a different fact (ADR 0064 D2).
                Container::UnsupportedCompression(container) => {
                    Err(ExtractError::UnsupportedContainer { container })
                }
                // A shape that was positively identified as holding no
                // package surface — the image config JSON, or a blob
                // with no bytes. Genuinely nothing to assess, not a
                // refusal. The shape is on the line because it is what
                // distinguishes this from the refusal below for whoever
                // is triaging a blob that got no verdict.
                Container::NoPackageSurface(shape) => {
                    tracing::debug!(
                        scanner = "trivy",
                        shape,
                        "trivy adapter: blob carries no package surface by construction"
                    );
                    Ok(None)
                }
                // Bytes this adapter could not identify at all. The one
                // reading that is NOT available here is "no package
                // surface": these bytes may be a root filesystem whose
                // tar header carried no magic, and a scan that never ran
                // over one must not read as a completed fact about the
                // artifact. Refused as a statement about the payload's
                // own bytes, which is the gating side of ADR 0064 D2's
                // line.
                Container::Unidentified => Err(ExtractError::Malformed(
                    "unrecognised blob container: the leading bytes match no archive this \
                     adapter decodes and no shape that excludes a package surface"
                        .to_string(),
                )),
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

/// What a bounded CAS→file copy did.
///
/// Two outcomes rather than one `Result`, because over-cap is not an
/// error of the copy: it is a fact about the object, and the two callers
/// turn it into different refusals — a per-artifact
/// `max-artifact-size` rejection on the single-blob path, a whole-image
/// budget refusal on the composition path. Centralising the loop and
/// leaving the verdict to the caller is what keeps one copy of the
/// chunking and the off-by-one and no copies of the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BoundedCopy {
    /// The whole object was written, in this many bytes.
    Written(u64),
    /// The stream produced more than `cap` bytes. Whatever was written
    /// before the cap tripped is still on disk — the caller owns the
    /// cleanup, and both of them discard the whole workspace rather than
    /// handing a truncated file to a scanner.
    OverCap,
}

/// Streaming, size-capped CAS→file copy.
///
/// Reads the storage stream in [`COPY_CHUNK_BYTES`] chunks with a running
/// `written` total — no full-artifact RAM buffer, so resident memory is
/// `O(COPY_CHUNK_BYTES)` rather than `O(object size)`. The cap check is
/// `written + chunk_len > cap` *before* the chunk is written, so a stream
/// whose length is *exactly* the cap succeeds (the next `read` yields
/// EOF, not an over-cap chunk) while a stream that produces even one byte
/// beyond the cap is refused — this is what distinguishes "hit the cap"
/// from a legitimate at-cap EOF.
///
/// **The read verifies.** `StoragePort::get` is the verified read path
/// (ADR 0003): every adapter wraps its backend stream in a reader that
/// recomputes the SHA-256 and fails at EOF on a mismatch. So a corrupt
/// object surfaces here as an `Err` from `read`, never as a short file
/// the caller cannot tell from a complete one.
pub(crate) async fn copy_capped(
    storage: &Arc<dyn StoragePort>,
    content_hash: &ContentHash,
    path: &Path,
    cap: u64,
) -> DomainResult<BoundedCopy> {
    let mut reader = storage.get(content_hash).await?;
    let mut file = tokio::fs::File::create(path).await.map_err(|e| {
        DomainError::Invariant(format!(
            "trivy adapter: failed to create artifact file: {e}"
        ))
    })?;

    let mut buf = vec![0u8; COPY_CHUNK_BYTES];
    let mut written: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await.map_err(|e| {
            DomainError::Invariant(format!("trivy adapter: failed to read storage stream: {e}"))
        })?;
        if n == 0 {
            // EOF — the at-cap object lands here without ever tripping
            // the over-cap branch below.
            break;
        }
        // Cap check *before* writing this chunk. `written + n` cannot
        // wrap: `written <= cap` holds on entry and `n` fits in
        // `usize`/`u64`.
        if written + (n as u64) > cap {
            return Ok(BoundedCopy::OverCap);
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

    Ok(BoundedCopy::Written(written))
}

/// [`copy_capped`] with the single-blob path's verdict on an over-cap
/// object: reject the artifact pre-scan. Returns the number of bytes
/// written, which the ratio cap downstream is measured against.
async fn stream_to_file(
    storage: &Arc<dyn StoragePort>,
    content_hash: &ContentHash,
    path: &Path,
    max_artifact_size: u64,
) -> DomainResult<u64> {
    match copy_capped(storage, content_hash, path, max_artifact_size).await? {
        BoundedCopy::Written(written) => Ok(written),
        BoundedCopy::OverCap => {
            // RAII: the caller's `TempDir` (and the partial file inside
            // it) is removed when it drops on this error path.
            tracing::warn!(
                scanner = "trivy",
                content_hash = %content_hash,
                max_artifact_size,
                "trivy adapter: artifact exceeds max-artifact-size cap; rejecting pre-scan"
            );
            Err(DomainError::Invariant(format!(
                "trivy adapter: artifact exceeds max-artifact-size cap \
                 ({max_artifact_size} bytes); rejected pre-scan to protect the worker"
            )))
        }
    }
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
        /// Fail the read with a **backend** error rather than an
        /// absence — the two must not reach the same outcome, since only
        /// one of them can change on a later attempt.
        Broken,
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
            enum Served {
                Bytes(Vec<u8>),
                Absent,
                Broken,
            }
            let served = match &self.0 {
                Get::Bytes(b) => Served::Bytes(b.clone()),
                Get::NotFound => Served::Absent,
                Get::Broken => Served::Broken,
                Get::Forbidden => panic!("this artifact kind must not cost a CAS read"),
            };
            Box::pin(async move {
                match served {
                    Served::Bytes(b) => {
                        let r: Box<dyn AsyncRead + Send + Unpin> = Box::new(Cursor::new(b));
                        Ok(r)
                    }
                    Served::Absent => Err(DomainError::NotFound {
                        entity: "content",
                        id: "x".into(),
                    }),
                    Served::Broken => Err(DomainError::Invariant(
                        "object store returned 503".to_string(),
                    )),
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

    /// A one-layer composition, for the refusal tests — the digests are
    /// synthetic because no read ever succeeds in them.
    fn sample_composed_image() -> ComposedImage {
        use hort_domain::oci::{ImageLayout, ImageLayoutLayer, OCI_IMAGE_MANIFEST_MEDIA_TYPE};
        ComposedImage::new(
            sample_hash(),
            ImageLayout {
                config: sample_hash(),
                layers: vec![ImageLayoutLayer {
                    hash: sample_hash(),
                    media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
                }],
                manifest_media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
            },
        )
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

    /// Build a **pre-POSIX v7** tar: a well-formed tar whose header
    /// carries no `ustar` magic, which is what a v7 archive looks like
    /// and what GNU tar still emits under `--format=v7`. The `tar` crate
    /// has no v7 writer, so the magic/version field (offset 257, 8
    /// bytes) is zeroed and the header checksum recomputed over the
    /// result — the archive stays readable by any tar reader.
    fn v7_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = plain_tar(entries);
        let mut offset = 0usize;
        while offset + 512 <= out.len() {
            // A header block whose name field is all-NUL is the
            // end-of-archive padding, not a header.
            if out[offset..offset + 100].iter().all(|b| *b == 0) {
                break;
            }
            out[offset + 257..offset + 265].fill(0);
            // The checksum field (offset 148, 8 bytes) is the octal sum
            // of every header byte with the field itself read as spaces.
            out[offset + 148..offset + 156].fill(b' ');
            let sum: u32 = out[offset..offset + 512]
                .iter()
                .map(|b| u32::from(*b))
                .sum();
            let encoded = format!("{sum:06o}\0 ");
            out[offset + 148..offset + 156].copy_from_slice(encoded.as_bytes());
            let size = entries
                .iter()
                .find(|(name, _)| out[offset..offset + 100].starts_with(name.as_bytes()))
                .map_or(0, |(_, body)| body.len());
            offset += 512 + size.div_ceil(512) * 512;
        }
        out
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
            unit: ScanUnit::Blob(&hash),
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

    #[test]
    fn plan_per_kind_matches_the_materialisation_table() {
        let c = coords("g:a", Some("1.0"), "g/a/1.0/a-1.0.jar");
        assert_eq!(
            plan_for(ArtifactKind::MavenJar, &c),
            Plan::SingleFile {
                name: "a-1.0.jar".to_string(),
                mode: ScanMode::Rootfs,
            }
        );
        assert_eq!(
            plan_for(ArtifactKind::MavenPom, &c),
            Plan::SingleFile {
                name: "pom.xml".to_string(),
                mode: ScanMode::Fs,
            }
        );
        assert_eq!(
            plan_for(
                ArtifactKind::NpmTarball,
                &coords("lodash", Some("4.17.21"), "")
            ),
            Plan::Relocated {
                dest: "node_modules/lodash".to_string(),
                mode: ScanMode::Rootfs,
            }
        );
        assert_eq!(
            plan_for(ArtifactKind::CargoCrate, &c),
            Plan::GzipTar { mode: ScanMode::Fs }
        );
        assert_eq!(
            plan_for(ArtifactKind::PySdist, &c),
            Plan::GzipTar {
                mode: ScanMode::Rootfs
            }
        );
        assert_eq!(
            plan_for(ArtifactKind::PyWheel, &c),
            Plan::Zip {
                mode: ScanMode::Rootfs
            }
        );
        assert_eq!(plan_for(ArtifactKind::OciBlob, &c), Plan::OciBlob);
        assert_eq!(plan_for(ArtifactKind::OciManifest, &c), Plan::NotApplicable);
        assert_eq!(plan_for(ArtifactKind::Other, &c), Plan::NotApplicable);
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
        let subcommand_of = |kind| match plan_for(kind, &c) {
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
                plan_for(kind, &c) != Plan::NotApplicable,
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
                .filter(|k| plan_for(*k, &c) != Plan::NotApplicable)
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

    /// The two shapes a blob may be read as holding no package surface,
    /// and the fact that both are *positive* identifications.
    #[test]
    fn sniff_recognises_the_no_package_surface_shapes_positively() {
        assert_eq!(
            sniff_container(br#"{"architecture":"amd64"}"#),
            Container::NoPackageSurface("json")
        );
        assert_eq!(
            sniff_container(b"  \n[{\"mediaType\":\"x\"}]"),
            Container::NoPackageSurface("json"),
            "JSON permits leading whitespace, and an array is a JSON document too"
        );
        assert_eq!(sniff_container(&[]), Container::NoPackageSurface("empty"));
    }

    /// **The S9b-1 regression.** Anything the sniffer cannot place is
    /// `Unidentified`, never "no package surface": a truncated gzip
    /// header and a tar whose POSIX magic is absent are both bytes that
    /// may be a root filesystem, and reading them as an absence of
    /// surface hands an unassessed filesystem a release-authorizing
    /// scan.
    #[test]
    fn sniff_leaves_unplaceable_bytes_unidentified() {
        // A one-byte truncated gzip magic.
        assert_eq!(sniff_container(&[0x1f]), Container::Unidentified);
        // A pre-POSIX v7 tar: a well-formed tar header with the `ustar`
        // magic field zeroed, which is how v7 archives are written.
        assert_eq!(
            sniff_container(&v7_tar(&[("etc/hostname", b"host")])),
            Container::Unidentified
        );
        // Arbitrary binary.
        assert_eq!(
            sniff_container(&[0x00, 0x61, 0x73, 0x6d]),
            Container::Unidentified
        );
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
                unit: ScanUnit::Blob(&hash),
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

    // -- a composition that could not be assembled --------------------

    /// A composed image whose constituents are **absent** from CAS: a
    /// deterministic refusal, reported as the no-verdict value the job
    /// queue will not spin on. By the time the adapter sees this, the
    /// application layer has already decided whether the absence could be
    /// acquired — so re-running reads the same absence.
    #[tokio::test]
    async fn an_absent_constituent_is_a_deterministic_no_verdict() {
        let storage: Arc<dyn StoragePort> = Arc::new(StubStorage(Get::NotFound));
        let image = sample_composed_image();
        let c = coords("library/nginx", None, "manifests/sha256:aa");
        let target = ScanTarget {
            unit: ScanUnit::Image(&image),
            format: "oci",
            coords: &c,
            kind: ArtifactKind::OciManifest,
        };
        let m = materialise(&storage, &target, u64::MAX)
            .await
            .expect("a deterministic refusal is not an error");
        assert_eq!(expect_nothing(&m), NotAnalysable::IncompleteComposition);
    }

    /// The same shape of refusal with a **failed** read instead of an
    /// absence: an `Err`, which is the answer the orchestrator already
    /// reschedules. Folding it into the deterministic value would turn a
    /// storage hiccup into a permanent-looking absence of assessment.
    #[tokio::test]
    async fn a_failed_constituent_read_is_a_retryable_error_not_a_no_verdict() {
        let storage: Arc<dyn StoragePort> = Arc::new(StubStorage(Get::Broken));
        let image = sample_composed_image();
        let c = coords("library/nginx", None, "manifests/sha256:aa");
        let target = ScanTarget {
            unit: ScanUnit::Image(&image),
            format: "oci",
            coords: &c,
            kind: ArtifactKind::OciManifest,
        };
        let r = materialise(&storage, &target, u64::MAX).await;
        let Err(e) = r else {
            panic!("a transient refusal must not arrive as a no-verdict: {r:?}");
        };
        let rendered = e.to_string();
        assert!(rendered.contains("did not complete"), "{rendered}");
        assert!(
            rendered.contains("object store returned 503"),
            "the backend's own words survive: {rendered}"
        );
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

    /// An empty blob holds no package surface, and that is provable
    /// rather than assumed — there is nothing in zero bytes for an
    /// analyzer to claim.
    #[tokio::test]
    async fn an_empty_oci_blob_is_not_applicable() {
        let c = coords("library/nginx", None, "blobs/sha256:aa");
        let m = materialise_kind(ArtifactKind::OciBlob, &c, Vec::new())
            .await
            .expect("materialise");
        assert_eq!(expect_nothing(&m), NotAnalysable::NotApplicable);
    }

    /// **The S9b-1 regression, end to end.** An OCI blob whose bytes are
    /// a pre-POSIX v7 tar — a real root filesystem with no `ustar`
    /// magic — must not produce a release-authorizing scan. It used to
    /// reach `NotApplicable`, which does not gate, so a layer nothing
    /// ever looked at recorded `ScanCompleted(0, not_applicable)` and
    /// released under `ScanSucceeded`.
    #[tokio::test]
    async fn an_oci_blob_whose_tar_carries_no_posix_magic_is_refused_not_waved_through() {
        let c = coords("library/nginx", None, "blobs/sha256:aa");
        let bytes = v7_tar(&[("var/lib/dpkg/status", b"Package: zlib1g\n")]);
        // The fixture really is a readable tar — otherwise the test
        // would pass for the wrong reason (unreadable bytes rather than
        // an unrecognised container).
        assert!(
            tar::Archive::new(Cursor::new(&bytes))
                .entries()
                .expect("v7 entries")
                .next()
                .expect("one entry")
                .is_ok(),
            "the v7 fixture must be a tar a reader accepts"
        );
        let m = materialise_kind(ArtifactKind::OciBlob, &c, bytes)
            .await
            .expect("an unidentifiable blob is a no-verdict, not an error");
        assert_eq!(
            expect_nothing(&m),
            NotAnalysable::UnusableArchive,
            "an unidentifiable blob is a statement about the payload's own bytes, so it gates \
             (ADR 0064 D2) — `NotApplicable` would release an unassessed root filesystem"
        );
        assert!(
            expect_nothing(&m).gates_release(
                ArtifactKind::OciBlob,
                hort_domain::entities::scan_policy::CompositeVerdictMode::Promoted
            ),
            "and it gates even under a promoted composite verdict: the decoder-inventory \
             exemption needs a container that was positively identified"
        );
    }

    /// **The mapping table, by value.** Every `ExtractError` variant
    /// reaches the side [`refusal_of`] assigns it, asserted on the
    /// classifier itself so the table is pinned independently of which
    /// payload happens to reach which variant.
    ///
    /// The exhaustive `match` inside `refusal_of` is what makes a new
    /// variant a compile error there; this is what makes the *answers*
    /// a test failure here.
    #[test]
    fn every_extraction_refusal_reaches_the_side_the_mapping_assigns_it() {
        // Statements about the payload's own bytes.
        for about_the_bytes in [
            ExtractError::ExtractedBytesCap { cap: 1 },
            ExtractError::CompressionRatioCap {
                limit: 100,
                compressed: 7,
            },
            ExtractError::EntryCap { cap: 1 },
            ExtractError::UncontainedPath,
            ExtractError::UndecodableEntryName { index: 0 },
            // The undecidable case, deliberately on this side: the
            // readers behind it report "no decoder for this" and "a
            // corrupt archive of a container I do decode" identically,
            // so there is nothing to tell them apart with and
            // fail-closed is which way that goes.
            ExtractError::Malformed("expected a tar archive: invalid gzip header".to_string()),
        ] {
            assert_eq!(
                refusal_of(&about_the_bytes),
                NotAnalysable::UnusableArchive,
                "{about_the_bytes} is a statement about the payload's bytes"
            );
        }

        // The one statement about this adapter's decoder inventory.
        assert_eq!(
            refusal_of(&ExtractError::UnsupportedContainer { container: "zstd" }),
            NotAnalysable::UnsupportedContainer,
        );

        // And what the two now do, asserted here as a pair as well,
        // because the mapping is what an operator sees: on a constituent
        // whose composition carries the filesystem verdict the missing
        // decoder stops holding the layer, while the hostile archive — a
        // statement about these bytes — holds it either way
        // (ADR 0064 D2). This adapter decides the *reason*; where each
        // reason lands is `NotAnalysable::gates_release`'s.
        let kind = ArtifactKind::OciBlob;
        let promoted = hort_domain::entities::scan_policy::CompositeVerdictMode::Promoted;
        assert!(
            refusal_of(&ExtractError::UncontainedPath).gates_release(kind, promoted),
            "an entry that tried to escape the workspace is about these bytes"
        );
        assert!(
            !refusal_of(&ExtractError::UnsupportedContainer { container: "zstd" })
                .gates_release(kind, promoted),
            "a container this adapter cannot decode is a statement about hort; the \
             composition that reads these bytes carries the verdict"
        );
    }

    /// A container this adapter has no decoder for, reached end to end
    /// through `materialise` without invoking Trivy — the magic bytes
    /// are all `sniff_container` reads, so a seven-byte payload is a
    /// sufficient fixture and no real zstd/xz/bzip2 stream is needed.
    ///
    /// `tar+zstd` is ADR 0064 D2's measured case: the scanner composes
    /// it identically to `tar+gzip`, so these are bytes hort refuses and
    /// a composition reads without difficulty. It is still refused here
    /// rather than reported clean — the gap stays visible — but it is
    /// now refused under its own name.
    #[tokio::test]
    async fn a_layer_in_a_container_with_no_decoder_is_named_as_such() {
        for (container, magic) in [
            ("zstd", vec![0x28u8, 0xb5, 0x2f, 0xfd, 0x01, 0x02, 0x03]),
            ("xz", vec![0xfd, b'7', b'z', b'X', b'Z', 0x00, 0x00]),
            ("bzip2", vec![b'B', b'Z', b'h', b'9', 0x01, 0x02, 0x03]),
        ] {
            let c = coords("library/nginx", None, "blobs/sha256:aa");
            let m = materialise_kind(ArtifactKind::OciBlob, &c, magic)
                .await
                .expect("a missing decoder is a no-verdict, not an error");
            assert_eq!(
                expect_nothing(&m),
                NotAnalysable::UnsupportedContainer,
                "a {container} layer is a container with no decoder, not a complaint about its \
                 bytes"
            );
        }
    }

    /// The other half of the split, at the same layer: a payload whose
    /// container *is* decoded and whose bytes are the problem keeps
    /// reaching `UnusableArchive`.
    ///
    /// Asserted beside the test above rather than inferred from it,
    /// because the two together are the claim — the statements are
    /// different and both still gate.
    #[tokio::test]
    async fn a_layer_whose_bytes_are_the_problem_is_still_an_unusable_archive() {
        let c = coords("library/nginx", None, "blobs/sha256:aa");
        // A real gzip stream (so the container is decoded) wrapping a
        // tar entry that tries to escape the workspace.
        let bytes = gzip_tar(&[("../escaped", b"payload")]);
        let m = materialise_kind(ArtifactKind::OciBlob, &c, bytes)
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
            unit: ScanUnit::Blob(&hash),
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
            unit: ScanUnit::Blob(&hash),
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
            unit: ScanUnit::Blob(&hash),
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
