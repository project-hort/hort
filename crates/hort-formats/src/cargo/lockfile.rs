//! Cargo lockfile extraction and the per-crate **resolved-dependency
//! closure**.
//!
//! A published `.crate` embeds a `Cargo.lock` next to its manifest. That
//! lockfile names every dependency at its **exact resolved version**,
//! which is what a vulnerability scanner needs: a declared range floor
//! (`serde = "1"` scanned as version `1`) matches advisories that the
//! actually-built `serde 1.0.x` never had.
//!
//! This module is pure machinery, split into the two halves the scan path
//! needs:
//!
//! 1. [`extract_lockfile_bytes`] — a streaming walk of the `.crate`
//!    gzip-tarball that yields the `{dir}/Cargo.lock` entry, or `None`
//!    when the archive has no lockfile. It mirrors the manifest walk in
//!    [`CargoFormatHandler::extract_dependency_specs`](super::CargoFormatHandler)
//!    exactly: same `&mut dyn Read` port shape, same audited
//!    [`archive_bounds`](crate::archive_bounds) caps.
//! 2. [`CargoLockfile::parse`] + [`CargoLockfile::resolve_closure`] — the
//!    closure walk, a pure function over parsed bytes with **no I/O**.
//!
//! # What the embedded lockfile actually contains
//!
//! `cargo package` does **not** copy the workspace lockfile into the
//! `.crate`. It re-resolves the packaged crate on its own and writes a
//! lockfile scoped to *that crate's* dependency graph — a `.crate` for a
//! workspace member carries neither its sibling members nor their
//! dependencies. Verified against cargo 1.94 output: packaging one member
//! of a 730-package workspace produced a 163-package lockfile with no
//! sibling-only crates in it.
//!
//! The graph it *does* carry is still wider than the published crate's
//! consumers ever build, because the packaged crate is the resolve root
//! and a root's **dev-dependencies participate in the resolve**. In the
//! same measurement, 22 of 162 reachable packages — `proptest`, `rand`,
//! `rustix`, `tempfile`, `zerocopy` and their trees — were reachable only
//! through dev-dependency edges. Nothing that consumes the published
//! crate ever compiles them, so an advisory against one of them is a
//! false positive against this artifact.
//!
//! Lockfile `dependencies` edges carry no dependency **kind**, so the
//! lockfile alone cannot tell a dev edge from a normal one. The published
//! crate's own registry-index metadata can: its `deps` entries carry
//! `kind`. [`non_dev_first_hop`] projects that metadata into the set of
//! first-hop package names worth walking, and
//! [`resolve_closure`](CargoLockfile::resolve_closure) takes it as an
//! optional seed filter. Only the **root** node needs filtering: cargo
//! ignores the dev-dependencies of non-root packages entirely, so every
//! node below the first hop is already dev-free.
//!
//! Without that seed the walk keeps every first-hop edge — an
//! over-approximation that is safe (no false negatives) but noisy.
//!
//! # Registry packages only
//!
//! A component is emitted only for a package whose `source` names a
//! registry (`registry+…` / `sparse+…`); those are the packages an
//! advisory database can be queried about. Path- and git-sourced entries
//! carry no registry coordinates, so they are skipped and **counted** in
//! [`ResolvedClosure::skipped_non_registry`] — the walk still traverses
//! *through* them so registry packages behind such a node stay reachable.
//! The resolve root itself is neither emitted (it is the BOM subject, not
//! a component) nor counted.

use std::collections::{BTreeMap, BTreeSet};

use hort_domain::error::{DomainError, DomainResult};

use super::{is_top_level_entry, CARGO_CRATE_MAX_BYTES};
use crate::archive_bounds::{read_tar_gz_entry, BoundsConfig};

/// Parser-input sanity cap for a `Cargo.lock` extracted from a `.crate`.
///
/// A lockfile costs roughly 260 bytes per resolved package (measured on
/// this workspace's own 730-package lockfile), so 4 MiB admits a graph of
/// ~16 000 packages — an order of magnitude above anything real — while
/// still refusing to hand an unbounded body to the TOML parser. The
/// decompression-bomb, cumulative-output and entry-count guards belong to
/// [`read_tar_gz_entry`], not to this cap.
const CARGO_LOCKFILE_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Longest excerpt of a lockfile-sourced token echoed into an error
/// message. Lockfile bytes inside a `.crate` are fully publisher-
/// controlled, so a diagnostic quotes at most this many characters and
/// drops anything that is not printable ASCII (see [`token_excerpt`]).
/// Sized to the cargo crate-name grammar's own 64-byte ceiling.
const ERROR_EXCERPT_MAX_CHARS: usize = 64;

/// One dependency of the published crate, at the version the lockfile
/// resolved it to.
///
/// `checksum` is the lockfile's own `checksum` field — the SHA-256 of the
/// registry `.crate` — when the lockfile records one. Lockfile formats v1
/// and v2 kept checksums in a separate `[metadata]` table instead of on
/// the package entry; those parse fine here but yield `None`. The field
/// is advisory provenance, not an input to vulnerability matching (which
/// needs only name and version), so the degradation is harmless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedComponent {
    /// Package name exactly as the lockfile spells it.
    pub name: String,
    /// Exact resolved version — never a range.
    pub version: String,
    /// Registry checksum when the lockfile records one (v3+).
    pub checksum: Option<String>,
}

/// The outcome of a [`resolve_closure`](CargoLockfile::resolve_closure)
/// walk.
///
/// `skipped_non_registry` is deliberately a plain count and not a metric
/// emission: `hort-formats` holds no `metrics` dependency (it is pure
/// format machinery, like `hort-domain`), and the metrics-ownership rule
/// puts a result enum in the layer that emits it. The scan orchestration
/// that calls this walk owns both the enum and the counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedClosure {
    /// Registry-sourced components, deduplicated and ordered by
    /// `(name, version)` so the same artifact always yields the same BOM.
    pub components: Vec<ResolvedComponent>,
    /// How many reachable packages were skipped for having no registry
    /// source (path- or git-sourced entries). Excludes the resolve root.
    pub skipped_non_registry: usize,
}

/// A parsed `Cargo.lock`.
///
/// Construct with [`CargoLockfile::parse`]; walk with
/// [`CargoLockfile::resolve_closure`]. Holds no I/O handles — the whole
/// type is a value.
#[derive(Debug, Clone)]
pub struct CargoLockfile {
    packages: Vec<LockPackage>,
    /// `name → indices into `packages``, so edge resolution does not
    /// rescan the package list for every edge.
    by_name: BTreeMap<String, Vec<usize>>,
}

/// One `[[package]]` entry.
#[derive(Debug, Clone, serde::Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    /// Absent for path packages (the resolve root and any workspace
    /// sibling); `registry+…` / `sparse+…` for registry packages;
    /// `git+…` for git packages.
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
    /// Edge strings naming other `[[package]]` entries. See
    /// [`CargoLockfile::resolve_edge`] for the grammar.
    #[serde(default)]
    dependencies: Vec<String>,
}

/// The lockfile document. Every other top-level key (`version`,
/// `[metadata]`, `[[patch.unused]]`) is ignored — this walk needs the
/// package table and nothing else, and tolerating unknown keys is what
/// lets one parser read v1 through v4.
#[derive(Debug, serde::Deserialize)]
struct RawLockfile {
    #[serde(default)]
    package: Vec<LockPackage>,
}

/// Extract `{name}-{version}/Cargo.lock` from a `.crate` gzip-tarball.
///
/// Returns `Ok(None)` when the archive carries no top-level lockfile — an
/// expected, truthful state (nothing forces a `.crate` to embed one), and
/// never an error. `Err` is reserved for an archive that is broken or
/// hostile: not a gzip-tar, a tripped [`archive_bounds`](crate::archive_bounds)
/// guard, or a lockfile entry above [`CARGO_LOCKFILE_MAX_BYTES`].
///
/// `Ok(None)` therefore means "the scan reached the end of the archive and
/// found no lockfile", never "the scan gave up". An archive that
/// decompresses past the cumulative output cap before the scan completes
/// surfaces that bounds error instead — the two are different facts and
/// only the caller can decide what posture each deserves.
///
/// **Streaming port shape.** `content` is a `&mut dyn Read`, so the
/// caller never has to materialise the artifact to call this. The
/// compressed bytes are then read into a [`CARGO_CRATE_MAX_BYTES`]-capped
/// buffer for exactly the reason
/// [`extract_dependency_specs`](super::CargoFormatHandler) buffers them:
/// gzip carries no reliable decompressed-size header, so the
/// compression-ratio bound needs the compressed length passed in
/// explicitly. Memory is bounded by that cap, and the decompressed side
/// is bounded independently by `archive_bounds`.
///
/// **Entry-order reliance.** `archive_bounds`' output cap is *cumulative*
/// across the sequential tar scan, so the lockfile must be an early
/// entry. It is: cargo writes `.crate` members in sorted path order,
/// which puts `{dir}/Cargo.lock` second — ahead of even `Cargo.toml`,
/// which the manifest walk already relies on being early.
///
/// **Predicate.** The entry is matched structurally (exactly one
/// directory segment before `/Cargo.lock`) rather than by composing
/// `{name}-{version}`, so a publisher's own casing of the directory name
/// cannot make a present lockfile look absent.
pub fn extract_lockfile_bytes(content: &mut dyn std::io::Read) -> DomainResult<Option<Vec<u8>>> {
    let buf =
        crate::stream_helpers::read_to_capped_vec(content, CARGO_CRATE_MAX_BYTES, |len, max| {
            format!("cargo artifact is {len} bytes; cargo crate max is {max}")
        })?;
    let entry = read_tar_gz_entry(
        &buf[..],
        buf.len() as u64,
        BoundsConfig::default_for_metadata_extraction(),
        is_top_level_cargo_lock,
    )?;
    if let Some(ref bytes) = entry {
        if bytes.len() > CARGO_LOCKFILE_MAX_BYTES {
            return Err(DomainError::Validation(format!(
                "cargo Cargo.lock body is {} bytes; cargo lockfile max is {CARGO_LOCKFILE_MAX_BYTES}",
                bytes.len()
            )));
        }
    }
    Ok(entry)
}

/// Whether `path` is the `.crate`'s single top-level `Cargo.lock`.
///
/// Same structural rule as the manifest predicate: exactly one directory
/// segment before the file name, so a vendored
/// `{dir}/vendor/x/Cargo.lock` never matches.
fn is_top_level_cargo_lock(path: &str) -> bool {
    is_top_level_entry(path, "Cargo.lock")
}

/// Project the first-hop package names worth walking out of a published
/// crate's **registry-index-shape** format metadata.
///
/// Returns `None` when the metadata carries no `deps` array — the caller
/// then has no kind information and must walk unfiltered. Returns
/// `Some(set)` otherwise, including `Some(empty)` for a crate that
/// genuinely declares no non-dev dependencies.
///
/// Index-shape `deps` entries name the package in `package` when the
/// dependency is renamed in `Cargo.toml` and in `name` otherwise, so the
/// real package name — the one a lockfile edge uses — is
/// `package` falling back to `name`. `kind` is optional in the index
/// format and defaults to `normal`.
///
/// **`build` is kept, `dev` is dropped.** A build-dependency is compiled
/// whenever a consumer builds this crate, so it is genuinely part of the
/// artifact's supply chain; a dev-dependency is not built by consumers at
/// all. **Optional dependencies are kept**: cargo resolves them into the
/// lockfile regardless of feature activation, and a component that some
/// feature selection compiles belongs in a security BOM.
pub fn non_dev_first_hop(format_metadata: &serde_json::Value) -> Option<BTreeSet<String>> {
    let deps = format_metadata.get("deps")?.as_array()?;
    let mut keep = BTreeSet::new();
    for dep in deps {
        let kind = dep
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or(NORMAL_KIND);
        if kind == DEV_KIND {
            continue;
        }
        let name = dep
            .get("package")
            .and_then(|v| v.as_str())
            .or_else(|| dep.get("name").and_then(|v| v.as_str()));
        if let Some(name) = name {
            keep.insert(name.to_string());
        }
    }
    Some(keep)
}

/// Index-format `kind` value for a dependency consumers build.
const NORMAL_KIND: &str = "normal";
/// Index-format `kind` value for a dependency only this crate's own tests
/// and benches build.
const DEV_KIND: &str = "dev";

impl CargoLockfile {
    /// Parse `Cargo.lock` bytes.
    ///
    /// A present-but-unusable lockfile is an `Err`, never a silent empty
    /// result: "this `.crate` has no lockfile" and "this `.crate`'s
    /// lockfile is corrupt" are different facts, and only the caller can
    /// decide what posture each deserves.
    pub fn parse(bytes: &[u8]) -> DomainResult<Self> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| DomainError::Validation(format!("Cargo.lock is not valid UTF-8: {e}")))?;
        let raw: RawLockfile = toml::from_str(text)
            .map_err(|e| DomainError::Validation(format!("Cargo.lock is not valid TOML: {e}")))?;
        let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (idx, package) in raw.package.iter().enumerate() {
            by_name.entry(package.name.clone()).or_default().push(idx);
        }
        Ok(Self {
            packages: raw.package,
            by_name,
        })
    }

    /// Walk the resolved-dependency closure of `name`@`version`.
    ///
    /// Starts at that package's `[[package]]` entry, follows
    /// `dependencies` edges transitively, and returns every reachable
    /// registry package exactly once. Pure — no I/O, no clock, no
    /// randomness; the same lockfile always yields the same
    /// [`ResolvedClosure`].
    ///
    /// `first_hop` filters the **root's own edges** only (see the module
    /// docs): `Some(set)` keeps an edge only when its package name is in
    /// `set`, `None` keeps every edge. A dev-dependency that is *also*
    /// reachable through a kept edge still appears in the closure, which
    /// is correct — a consumer does build it.
    ///
    /// # Errors
    ///
    /// `Validation` when the lockfile is not a self-consistent resolve:
    /// no entry for the published crate, an edge naming a package that is
    /// not in the file, or an edge whose shortest-unambiguous form is in
    /// fact ambiguous. Cargo never writes such a file, so each of these
    /// means the embedded lockfile cannot be trusted to describe what was
    /// built.
    pub fn resolve_closure(
        &self,
        name: &str,
        version: &str,
        first_hop: Option<&BTreeSet<String>>,
    ) -> DomainResult<ResolvedClosure> {
        let root = self.find_root(name, version)?;

        // The root is visited up-front so a dependency cycle back onto it
        // (dev-dependency cycles are legal and common — `serde` /
        // `serde_derive` shaped) terminates, and so the root is never
        // emitted as a component: it is the BOM subject.
        let mut visited: BTreeSet<usize> = BTreeSet::new();
        visited.insert(root);

        let mut stack: Vec<usize> = Vec::new();
        for edge in &self.packages[root].dependencies {
            if let Some(keep) = first_hop {
                if !keep.contains(edge_package_name(edge)) {
                    continue;
                }
            }
            stack.push(self.resolve_edge(edge)?);
        }

        let mut components = Vec::new();
        let mut skipped_non_registry = 0usize;
        while let Some(idx) = stack.pop() {
            if !visited.insert(idx) {
                continue;
            }
            let package = &self.packages[idx];
            if is_registry_source(package.source.as_deref()) {
                components.push(ResolvedComponent {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    checksum: package.checksum.clone(),
                });
            } else {
                // Counted, not emitted — but still traversed, so a
                // registry package reachable only through it is not lost.
                skipped_non_registry += 1;
            }
            for edge in &package.dependencies {
                stack.push(self.resolve_edge(edge)?);
            }
        }

        components.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        Ok(ResolvedClosure {
            components,
            skipped_non_registry,
        })
    }

    /// Locate the published crate's own `[[package]]` entry.
    ///
    /// The name is compared case-insensitively because `coords.name` is
    /// the registry-normalised (lowercased) spelling while the lockfile
    /// keeps the publisher's; the version must match exactly, since
    /// picking a differently-versioned entry would silently scan the
    /// wrong resolve.
    fn find_root(&self, name: &str, version: &str) -> DomainResult<usize> {
        self.packages
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(name) && p.version == version)
            .ok_or_else(|| {
                DomainError::Validation(format!(
                    "Cargo.lock has no [[package]] entry for the published crate {name}@{version}"
                ))
            })
    }

    /// Resolve one `dependencies` edge to a package index.
    ///
    /// An edge is `"<name>"`, `"<name> <version>"`, or
    /// `"<name> <version> <source>"` — cargo writes the shortest form
    /// that identifies the package unambiguously. Lockfile v1/v2 wrapped
    /// the source in parentheses (`"a 1.0.0 (registry+…)"`); the parens
    /// are stripped so one resolver reads every format version.
    fn resolve_edge(&self, edge: &str) -> DomainResult<usize> {
        let mut parts = edge.split_whitespace();
        let Some(name) = parts.next() else {
            return Err(DomainError::Validation(
                "Cargo.lock contains an empty dependency edge".to_string(),
            ));
        };
        let want_version = parts.next();
        let want_source = parts
            .next()
            .map(|s| s.trim_start_matches('(').trim_end_matches(')'));

        let candidates = self.by_name.get(name).map_or(&[][..], Vec::as_slice);
        let mut matches = candidates.iter().copied().filter(|&idx| {
            let package = &self.packages[idx];
            want_version.is_none_or(|v| package.version == v)
                && want_source.is_none_or(|s| package.source.as_deref() == Some(s))
        });

        match (matches.next(), matches.next()) {
            (Some(idx), None) => Ok(idx),
            (Some(_), Some(_)) => Err(DomainError::Validation(format!(
                "Cargo.lock dependency edge `{}` matches more than one [[package]] entry; \
                 the file is not a self-consistent resolve",
                token_excerpt(edge)
            ))),
            (None, _) => Err(DomainError::Validation(format!(
                "Cargo.lock dependency edge `{}` names no [[package]] entry; \
                 the file is not a self-consistent resolve",
                token_excerpt(edge)
            ))),
        }
    }
}

/// The package-name token of a `dependencies` edge (everything before the
/// first space). An empty edge yields `""`, which matches no package name
/// and is rejected downstream.
fn edge_package_name(edge: &str) -> &str {
    edge.split_whitespace().next().unwrap_or("")
}

/// Whether a `[[package]]` `source` names a registry an advisory database
/// can be queried about. `registry+` is the git-index form, `sparse+` the
/// HTTP-index form (RFC 2789); both cover private registries as well as
/// crates.io. Everything else — `git+…`, and the absent source of a path
/// package — has no registry coordinates.
fn is_registry_source(source: Option<&str>) -> bool {
    matches!(source, Some(s) if s.starts_with("registry+") || s.starts_with("sparse+"))
}

/// Render a publisher-controlled lockfile token safe to put in an error
/// message: printable ASCII only, at most [`ERROR_EXCERPT_MAX_CHARS`]
/// characters, with any dropped tail marked by an ellipsis. Keeps a
/// diagnostic useful without letting a hostile `.crate` write arbitrary
/// bytes (control characters, megabytes of padding) into the log.
fn token_excerpt(token: &str) -> String {
    let mut out: String = token
        .chars()
        .take(ERROR_EXCERPT_MAX_CHARS)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if token.chars().nth(ERROR_EXCERPT_MAX_CHARS).is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- fixtures ---------------------------------------------------------

    /// Render a `[[package]]` entry. `source` of `None` makes a path
    /// package (the shape of a resolve root); `Some("registry+…")` /
    /// `Some("git+…")` make the other two.
    fn pkg(
        name: &str,
        version: &str,
        source: Option<&str>,
        checksum: Option<&str>,
        deps: &[&str],
    ) -> String {
        let mut out = format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n");
        if let Some(source) = source {
            out.push_str(&format!("source = \"{source}\"\n"));
        }
        if let Some(checksum) = checksum {
            out.push_str(&format!("checksum = \"{checksum}\"\n"));
        }
        if !deps.is_empty() {
            out.push_str("dependencies = [\n");
            for dep in deps {
                out.push_str(&format!(" \"{dep}\",\n"));
            }
            out.push_str("]\n");
        }
        out.push('\n');
        out
    }

    /// The canonical crates.io registry source string.
    const REG: &str = "registry+https://github.com/rust-lang/crates.io-index";
    /// A private sparse registry, to prove `sparse+` counts as a registry.
    const SPARSE: &str = "sparse+https://hort.example/api/v1/crates/";

    fn lockfile(packages: &[String]) -> String {
        let mut out = String::from(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\nversion = 4\n\n",
        );
        for package in packages {
            out.push_str(package);
        }
        out
    }

    /// The workspace-shaped fixture the table-driven cases walk.
    ///
    /// `demo 0.1.0` is the published (path) root. Its edges cover every
    /// case the closure walk has to get right:
    ///
    /// - `serde` — a normal dep with a transitive chain
    ///   (`serde → serde_derive → syn`);
    /// - `cc` — a build-dependency (indistinguishable from a normal one
    ///   in the lockfile, kept by the non-dev seed);
    /// - `proptest` — a dev-dependency with a private tree
    ///   (`proptest → rand`), the over-approximation the seed removes;
    /// - `sibling` — a path package with no registry source, skipped and
    ///   counted, but still traversed to reach `shared 1.0.0`;
    /// - `dup 1.0.0` / `dup 2.0.0` — two versions of one crate, reached
    ///   through disambiguated `"dup <version>"` edges;
    /// - `gitdep` — a git-sourced package, skipped and counted.
    fn workspace_fixture() -> CargoLockfile {
        let text = lockfile(&[
            pkg(
                "demo",
                "0.1.0",
                None,
                None,
                &["cc", "dup 1.0.0", "gitdep", "proptest", "serde", "sibling"],
            ),
            pkg("cc", "1.2.0", Some(REG), Some("ccsum"), &[]),
            pkg("dup", "1.0.0", Some(REG), Some("dup1sum"), &["dup 2.0.0"]),
            pkg("dup", "2.0.0", Some(REG), Some("dup2sum"), &[]),
            pkg(
                "gitdep",
                "0.3.0",
                Some("git+https://example.test/g#abc"),
                None,
                &[],
            ),
            pkg("proptest", "1.5.0", Some(REG), Some("propsum"), &["rand"]),
            pkg("rand", "0.8.5", Some(REG), Some("randsum"), &[]),
            pkg(
                "serde",
                "1.0.200",
                Some(REG),
                Some("serdesum"),
                &["serde_derive"],
            ),
            pkg(
                "serde_derive",
                "1.0.200",
                Some(REG),
                Some("sdsum"),
                &["syn"],
            ),
            pkg("shared", "1.0.0", Some(SPARSE), Some("sharedsum"), &[]),
            pkg("sibling", "0.1.0", None, None, &["shared"]),
            pkg("syn", "2.0.90", Some(REG), Some("synsum"), &[]),
        ]);
        CargoLockfile::parse(text.as_bytes()).expect("fixture parses")
    }

    fn names(closure: &ResolvedClosure) -> Vec<String> {
        closure
            .components
            .iter()
            .map(|c| format!("{}@{}", c.name, c.version))
            .collect()
    }

    /// `demo`'s registry-index-shape metadata: every declared dependency
    /// with its `kind`, including a renamed one.
    fn demo_index_metadata() -> serde_json::Value {
        serde_json::json!({
            "deps": [
                {"name": "serde", "req": "1", "kind": "normal", "package": null},
                {"name": "cc", "req": "1", "kind": "build", "package": null},
                {"name": "proptest", "req": "1", "kind": "dev", "package": null},
                {"name": "sibling", "req": "0.1", "kind": "normal", "package": null},
                {"name": "gitdep", "req": "0.3", "kind": "normal", "package": null},
                {"name": "dup", "req": "1", "kind": "normal", "package": null},
            ]
        })
    }

    /// `len` bytes that deflate cannot shrink, from a fixed seed so the
    /// fixture is byte-identical run to run.
    ///
    /// Needed because `archive_bounds` bounds decompressed output at ten
    /// times the *compressed* input: an all-one-byte fixture compresses
    /// ~1000×, so a scan of it trips the ratio guard long before any real
    /// `.crate` would. Padding a fixture with incompressible bytes keeps
    /// its ratio realistic.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// Build a `.crate`-shaped gzip-tar from `(path, body)` pairs, in the
    /// order given. Mirrors the sibling fixture in `cargo.rs`.
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

    // ---- closure walk, table-driven ---------------------------------------

    #[test]
    fn closure_cases() {
        let lock = workspace_fixture();
        let all_kinds: BTreeSet<String> = ["cc", "dup", "gitdep", "proptest", "serde", "sibling"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let non_dev: BTreeSet<String> = ["cc", "dup", "gitdep", "serde", "sibling"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let only_serde: BTreeSet<String> = ["serde"].iter().map(|s| (*s).to_string()).collect();

        struct Case<'a> {
            label: &'a str,
            first_hop: Option<&'a BTreeSet<String>>,
            expect_components: &'a [&'a str],
            expect_skipped: usize,
        }

        let cases = [
            Case {
                // No seed: the dev tree (`proptest`, `rand`) rides along.
                // This is the accepted over-approximation, exercised so
                // both resolutions of the dev-dep question are pinned.
                label: "unseeded keeps the dev tree",
                first_hop: None,
                expect_components: &[
                    "cc@1.2.0",
                    "dup@1.0.0",
                    "dup@2.0.0",
                    "proptest@1.5.0",
                    "rand@0.8.5",
                    "serde@1.0.200",
                    "serde_derive@1.0.200",
                    "shared@1.0.0",
                    "syn@2.0.90",
                ],
                // `sibling` (path) + `gitdep` (git).
                expect_skipped: 2,
            },
            Case {
                // A seed that happens to list every edge behaves exactly
                // like no seed — the filter is the only difference.
                label: "seed naming every edge equals unseeded",
                first_hop: Some(&all_kinds),
                expect_components: &[
                    "cc@1.2.0",
                    "dup@1.0.0",
                    "dup@2.0.0",
                    "proptest@1.5.0",
                    "rand@0.8.5",
                    "serde@1.0.200",
                    "serde_derive@1.0.200",
                    "shared@1.0.0",
                    "syn@2.0.90",
                ],
                expect_skipped: 2,
            },
            Case {
                // The chosen resolution: the dev edge is dropped at the
                // root, taking its private tree (`rand`) with it, while
                // the build-dependency `cc` is kept.
                label: "non-dev seed drops the dev tree and keeps build deps",
                first_hop: Some(&non_dev),
                expect_components: &[
                    "cc@1.2.0",
                    "dup@1.0.0",
                    "dup@2.0.0",
                    "serde@1.0.200",
                    "serde_derive@1.0.200",
                    "shared@1.0.0",
                    "syn@2.0.90",
                ],
                expect_skipped: 2,
            },
            Case {
                // Narrow seed: only the `serde` chain survives, and the
                // skipped counter drops with the unreached path/git nodes
                // — it counts what the walk actually reached.
                label: "narrow seed walks only the reachable chain",
                first_hop: Some(&only_serde),
                expect_components: &["serde@1.0.200", "serde_derive@1.0.200", "syn@2.0.90"],
                expect_skipped: 0,
            },
        ];

        for case in &cases {
            let closure = lock
                .resolve_closure("demo", "0.1.0", case.first_hop)
                .unwrap_or_else(|e| panic!("{}: {e}", case.label));
            assert_eq!(names(&closure), case.expect_components, "{}", case.label);
            assert_eq!(
                closure.skipped_non_registry, case.expect_skipped,
                "{}",
                case.label
            );
        }
    }

    #[test]
    fn closure_carries_checksums_and_tolerates_their_absence() {
        let lock = workspace_fixture();
        let closure = lock
            .resolve_closure("demo", "0.1.0", None)
            .expect("walk succeeds");
        let serde = closure
            .components
            .iter()
            .find(|c| c.name == "serde")
            .expect("serde present");
        assert_eq!(serde.checksum.as_deref(), Some("serdesum"));

        // A v1/v2-shaped lockfile keeps checksums in `[metadata]`, so the
        // package entry has none. Name and version — the only inputs
        // vulnerability matching needs — must still come through.
        let text = lockfile(&[
            pkg("solo", "1.0.0", None, None, &["dep"]),
            pkg("dep", "2.0.0", Some(REG), None, &[]),
        ]);
        let lock = CargoLockfile::parse(text.as_bytes()).expect("parses");
        let closure = lock
            .resolve_closure("solo", "1.0.0", None)
            .expect("walk succeeds");
        assert_eq!(
            closure.components,
            vec![ResolvedComponent {
                name: "dep".to_string(),
                version: "2.0.0".to_string(),
                checksum: None,
            }]
        );
    }

    #[test]
    fn closure_output_is_sorted_and_deduplicated() {
        // Two independent paths reach `shared`; it must appear once, and
        // the ordering must be by (name, version) regardless of the order
        // the walk happened to visit nodes in.
        let text = lockfile(&[
            pkg("root", "1.0.0", None, None, &["zeta", "alpha"]),
            pkg("alpha", "1.0.0", Some(REG), None, &["shared"]),
            pkg("shared", "1.0.0", Some(REG), None, &[]),
            pkg("zeta", "1.0.0", Some(REG), None, &["shared"]),
        ]);
        let lock = CargoLockfile::parse(text.as_bytes()).expect("parses");
        let closure = lock
            .resolve_closure("root", "1.0.0", None)
            .expect("walk succeeds");
        assert_eq!(
            names(&closure),
            vec!["alpha@1.0.0", "shared@1.0.0", "zeta@1.0.0"]
        );
    }

    #[test]
    fn closure_terminates_on_a_dependency_cycle() {
        // Dev-dependency cycles are legal in a lockfile (the classic
        // `serde` / `serde_derive` shape). The walk must terminate and
        // must not emit the root as one of its own components.
        let text = lockfile(&[
            pkg("root", "1.0.0", None, None, &["a"]),
            pkg("a", "1.0.0", Some(REG), None, &["b"]),
            pkg("b", "1.0.0", Some(REG), None, &["a", "root"]),
        ]);
        let lock = CargoLockfile::parse(text.as_bytes()).expect("parses");
        let closure = lock
            .resolve_closure("root", "1.0.0", None)
            .expect("walk succeeds");
        assert_eq!(names(&closure), vec!["a@1.0.0", "b@1.0.0"]);
        assert_eq!(closure.skipped_non_registry, 0);
    }

    #[test]
    fn closure_root_name_match_is_case_insensitive_but_version_is_exact() {
        let text = lockfile(&[
            pkg("Mixed_Case", "1.0.0", None, None, &["dep"]),
            pkg("dep", "1.0.0", Some(REG), None, &[]),
        ]);
        let lock = CargoLockfile::parse(text.as_bytes()).expect("parses");
        // `coords.name` arrives registry-normalised (lowercase).
        assert_eq!(
            names(
                &lock
                    .resolve_closure("mixed_case", "1.0.0", None)
                    .expect("ok")
            ),
            vec!["dep@1.0.0"]
        );
        let err = lock
            .resolve_closure("mixed_case", "1.0.1", None)
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(ref m) if m.contains("no [[package]] entry")),
            "{err:?}"
        );
    }

    #[test]
    fn closure_resolves_every_edge_form() {
        // `"name"`, `"name version"`, `"name version source"`, and the
        // v1/v2 parenthesised source form all address the same package.
        let text = lockfile(&[
            pkg(
                "root",
                "1.0.0",
                None,
                None,
                &[
                    "bare",
                    "twin 1.0.0",
                    &format!("triple 1.0.0 {REG}"),
                    &format!("legacy 1.0.0 ({REG})"),
                ],
            ),
            pkg("bare", "9.9.9", Some(REG), None, &[]),
            pkg("twin", "1.0.0", Some(REG), None, &[]),
            pkg("twin", "2.0.0", Some(REG), None, &[]),
            pkg("triple", "1.0.0", Some(REG), None, &[]),
            pkg("triple", "1.0.0", Some(SPARSE), None, &[]),
            pkg("legacy", "1.0.0", Some(REG), None, &[]),
        ]);
        let lock = CargoLockfile::parse(text.as_bytes()).expect("parses");
        let closure = lock
            .resolve_closure("root", "1.0.0", None)
            .expect("walk succeeds");
        assert_eq!(
            names(&closure),
            vec!["bare@9.9.9", "legacy@1.0.0", "triple@1.0.0", "twin@1.0.0"]
        );
    }

    #[test]
    fn closure_rejects_an_inconsistent_resolve() {
        struct Case<'a> {
            label: &'a str,
            text: String,
            fragment: &'a str,
        }
        let cases = [
            Case {
                label: "dangling edge",
                text: lockfile(&[pkg("root", "1.0.0", None, None, &["ghost"])]),
                fragment: "names no [[package]] entry",
            },
            Case {
                label: "ambiguous bare edge",
                text: lockfile(&[
                    pkg("root", "1.0.0", None, None, &["twin"]),
                    pkg("twin", "1.0.0", Some(REG), None, &[]),
                    pkg("twin", "2.0.0", Some(REG), None, &[]),
                ]),
                fragment: "matches more than one [[package]] entry",
            },
            Case {
                label: "dangling edge below the first hop",
                text: lockfile(&[
                    pkg("root", "1.0.0", None, None, &["a"]),
                    pkg("a", "1.0.0", Some(REG), None, &["ghost"]),
                ]),
                fragment: "names no [[package]] entry",
            },
            Case {
                label: "missing root entry",
                text: lockfile(&[pkg("other", "1.0.0", Some(REG), None, &[])]),
                fragment: "no [[package]] entry for the published crate",
            },
        ];
        for case in &cases {
            let lock = CargoLockfile::parse(case.text.as_bytes()).expect("parses");
            let err = lock
                .resolve_closure("root", "1.0.0", None)
                .expect_err(case.label);
            assert!(
                matches!(err, DomainError::Validation(ref m) if m.contains(case.fragment)),
                "{}: {err:?}",
                case.label
            );
        }
    }

    #[test]
    fn closure_rejects_an_empty_dependency_edge() {
        let text = lockfile(&[pkg("root", "1.0.0", None, None, &["   "])]);
        let lock = CargoLockfile::parse(text.as_bytes()).expect("parses");
        let err = lock.resolve_closure("root", "1.0.0", None).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(ref m) if m.contains("empty dependency edge")),
            "{err:?}"
        );
    }

    #[test]
    fn closure_traverses_through_a_skipped_path_package() {
        // The counted skip must not truncate the walk: `shared` sits
        // behind the path-sourced `sibling` and has to be reached.
        let lock = workspace_fixture();
        let closure = lock
            .resolve_closure("demo", "0.1.0", None)
            .expect("walk succeeds");
        assert!(
            names(&closure).contains(&"shared@1.0.0".to_string()),
            "{:?}",
            names(&closure)
        );
    }

    // ---- parse ------------------------------------------------------------

    #[test]
    fn parse_rejects_malformed_and_non_utf8_lockfiles() {
        let err = CargoLockfile::parse(b"[[package]\nname = ").unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(ref m) if m.contains("not valid TOML")),
            "{err:?}"
        );

        let err = CargoLockfile::parse(&[0xff, 0xfe, 0x00]).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(ref m) if m.contains("not valid UTF-8")),
            "{err:?}"
        );

        // Well-formed TOML whose `[[package]]` entries are the wrong
        // shape is still a malformed lockfile, not an empty one.
        let err = CargoLockfile::parse(b"[[package]]\nname = 7\n").unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(ref m) if m.contains("not valid TOML")),
            "{err:?}"
        );
    }

    #[test]
    fn parse_ignores_unknown_top_level_keys() {
        // `version`, `[metadata]` and `[[patch.unused]]` are all real
        // lockfile keys this walk has no use for; tolerating them is what
        // lets one parser read v1 through v4.
        let text = format!(
            "version = 3\n\n{}\n[metadata]\n\"checksum dep 1.0.0 ({REG})\" = \"abc\"\n\n\
             [[patch.unused]]\nname = \"ghost\"\nversion = \"0.1.0\"\n",
            pkg("root", "1.0.0", None, None, &[])
        );
        let lock = CargoLockfile::parse(text.as_bytes()).expect("parses");
        let closure = lock
            .resolve_closure("root", "1.0.0", None)
            .expect("walk succeeds");
        assert!(closure.components.is_empty());
    }

    #[test]
    fn parse_accepts_a_lockfile_with_no_packages() {
        let lock = CargoLockfile::parse(b"version = 4\n").expect("parses");
        let err = lock.resolve_closure("root", "1.0.0", None).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "{err:?}");
    }

    // ---- non_dev_first_hop -------------------------------------------------

    #[test]
    fn non_dev_first_hop_keeps_normal_and_build_drops_dev() {
        let seed = non_dev_first_hop(&demo_index_metadata()).expect("deps present");
        assert!(seed.contains("serde"), "{seed:?}");
        assert!(seed.contains("cc"), "build dep kept: {seed:?}");
        assert!(!seed.contains("proptest"), "dev dep dropped: {seed:?}");
    }

    #[test]
    fn non_dev_first_hop_uses_the_original_name_of_a_renamed_dep() {
        // Index shape: `name` is the alias in Cargo.toml, `package` the
        // real crate — and the lockfile edge names the real crate.
        let metadata = serde_json::json!({
            "deps": [{"name": "alias", "req": "1", "kind": "normal", "package": "real"}]
        });
        let seed = non_dev_first_hop(&metadata).expect("deps present");
        assert_eq!(seed.iter().collect::<Vec<_>>(), vec!["real"]);
    }

    #[test]
    fn non_dev_first_hop_defaults_absent_kind_to_normal() {
        let metadata = serde_json::json!({"deps": [{"name": "serde", "req": "1"}]});
        let seed = non_dev_first_hop(&metadata).expect("deps present");
        assert!(seed.contains("serde"), "{seed:?}");
    }

    #[test]
    fn non_dev_first_hop_skips_entries_with_no_usable_name() {
        let metadata = serde_json::json!({"deps": [{"req": "1"}, {"name": "serde"}]});
        let seed = non_dev_first_hop(&metadata).expect("deps present");
        assert_eq!(seed.iter().collect::<Vec<_>>(), vec!["serde"]);
    }

    #[test]
    fn non_dev_first_hop_distinguishes_absent_deps_from_empty_deps() {
        // `None` means "no kind information — walk unfiltered".
        assert!(non_dev_first_hop(&serde_json::json!({})).is_none());
        assert!(non_dev_first_hop(&serde_json::json!({"deps": "not-an-array"})).is_none());
        // `Some(empty)` means "this crate declares no non-dev deps" —
        // a real answer, and a different one.
        let seed = non_dev_first_hop(&serde_json::json!({"deps": []})).expect("deps present");
        assert!(seed.is_empty());
        let seed = non_dev_first_hop(&serde_json::json!({"deps": [{"name": "p", "kind": "dev"}]}))
            .expect("deps present");
        assert!(seed.is_empty());
    }

    #[test]
    fn non_dev_first_hop_composes_with_the_walk_end_to_end() {
        let lock = workspace_fixture();
        let seed = non_dev_first_hop(&demo_index_metadata()).expect("deps present");
        let closure = lock
            .resolve_closure("demo", "0.1.0", Some(&seed))
            .expect("walk succeeds");
        assert!(!names(&closure).contains(&"proptest@1.5.0".to_string()));
        assert!(!names(&closure).contains(&"rand@0.8.5".to_string()));
        assert!(names(&closure).contains(&"cc@1.2.0".to_string()));
        assert!(names(&closure).contains(&"syn@2.0.90".to_string()));
    }

    // ---- extract_lockfile_bytes -------------------------------------------

    #[test]
    fn extract_lockfile_bytes_reads_the_top_level_lockfile() {
        let lock_body = b"version = 4\n";
        let archive = make_tar_gz(&[
            ("demo-0.1.0/.cargo_vcs_info.json", b"{}"),
            ("demo-0.1.0/Cargo.lock", lock_body),
            ("demo-0.1.0/Cargo.toml", b"[package]\nname = \"demo\"\n"),
            ("demo-0.1.0/src/lib.rs", b"// code"),
        ]);
        let found = extract_lockfile_bytes(&mut std::io::Cursor::new(archive)).expect("Ok");
        assert_eq!(found.as_deref(), Some(&lock_body[..]));
    }

    #[test]
    fn extract_lockfile_bytes_returns_none_when_the_crate_has_no_lockfile() {
        let filler = incompressible(8 * 1024);
        let archive = make_tar_gz(&[
            ("demo-0.1.0/Cargo.toml", b"[package]\nname = \"demo\"\n"),
            ("demo-0.1.0/src/lib.rs", b"// code"),
            ("demo-0.1.0/src/data.bin", &filler),
        ]);
        assert_eq!(
            extract_lockfile_bytes(&mut std::io::Cursor::new(archive)).expect("Ok"),
            None,
            "an absent lockfile is None, never an error"
        );
    }

    #[test]
    fn extract_lockfile_bytes_ignores_a_vendored_lockfile() {
        // Only the archive's own top-level lockfile counts; a vendored
        // one describes somebody else's resolve.
        let filler = incompressible(8 * 1024);
        let archive = make_tar_gz(&[
            ("demo-0.1.0/vendor/dep/Cargo.lock", b"version = 4\n"),
            ("demo-0.1.0/Cargo.toml", b"[package]\n"),
            ("demo-0.1.0/src/data.bin", &filler),
        ]);
        assert_eq!(
            extract_lockfile_bytes(&mut std::io::Cursor::new(archive)).expect("Ok"),
            None
        );
    }

    #[test]
    fn extract_lockfile_bytes_reports_an_exhausted_scan_as_an_error_not_as_absence() {
        // A lockfile-less archive whose contents compress better than the
        // archive-bounds ratio guard allows cannot be scanned to the end,
        // so the honest answer is the bounds error — "we could not finish
        // looking" is not the same fact as "there is nothing there", and
        // collapsing it into `Ok(None)` would report a clean absence the
        // walk never established.
        let archive = make_tar_gz(&[
            ("demo-0.1.0/Cargo.toml", b"[package]\n"),
            ("demo-0.1.0/src/pad.txt", &vec![b'a'; 512 * 1024]),
        ]);
        let err = extract_lockfile_bytes(&mut std::io::Cursor::new(archive)).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(ref m) if m.contains("output cap exceeded")),
            "{err:?}"
        );
    }

    #[test]
    fn extract_lockfile_bytes_rejects_an_artifact_over_the_compressed_cap() {
        // The reader is bounded before anything is decompressed, so an
        // oversized artifact is refused rather than buffered whole. Zeros
        // are fine here: the cap is on the compressed input, and nothing
        // gets as far as inflating them.
        let err = extract_lockfile_bytes(&mut std::io::Cursor::new(vec![
            0u8;
            CARGO_CRATE_MAX_BYTES + 1
        ]))
        .unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(ref m) if m.contains("cargo crate max is")),
            "{err:?}"
        );
    }

    #[test]
    fn extract_lockfile_bytes_rejects_a_non_gzip_input() {
        let err = extract_lockfile_bytes(&mut std::io::Cursor::new(
            b"this is not a gzip-tar .crate".to_vec(),
        ))
        .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "{err:?}");
    }

    #[test]
    fn extract_lockfile_bytes_rejects_a_lockfile_over_the_parser_cap() {
        // Incompressible, so the entry clears the parser cap while its
        // compression ratio keeps it inside the archive's output cap —
        // the parser cap is what must reject it, not the bounds guard.
        let oversized = incompressible(CARGO_LOCKFILE_MAX_BYTES + 1);
        let archive = make_tar_gz(&[("demo-0.1.0/Cargo.lock", &oversized)]);
        let err = extract_lockfile_bytes(&mut std::io::Cursor::new(archive)).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation(ref m) if m.contains("cargo lockfile max is")),
            "{err:?}"
        );
    }

    #[test]
    fn extract_lockfile_bytes_feeds_the_walk_end_to_end() {
        let text = lockfile(&[
            pkg("demo", "0.1.0", None, None, &["serde"]),
            pkg("serde", "1.0.200", Some(REG), Some("sum"), &[]),
        ]);
        let archive = make_tar_gz(&[("demo-0.1.0/Cargo.lock", text.as_bytes())]);
        let bytes = extract_lockfile_bytes(&mut std::io::Cursor::new(archive))
            .expect("Ok")
            .expect("lockfile present");
        let closure = CargoLockfile::parse(&bytes)
            .expect("parses")
            .resolve_closure("demo", "0.1.0", None)
            .expect("walk succeeds");
        assert_eq!(names(&closure), vec!["serde@1.0.200"]);
    }

    // ---- predicates and helpers -------------------------------------------

    // ---- real-lockfile regression ------------------------------------------

    #[test]
    fn walks_this_workspace_own_lockfile() {
        // The fixtures above are synthetic. This one parses the real
        // 730-package v4 lockfile sitting two directories up — mixed
        // `"name"` / `"name version"` edge forms, path-sourced workspace
        // members, and a `version = 4` header — so a format detail the
        // hand-written fixtures happen to miss cannot pass unnoticed.
        // Skipped rather than failed when the file is absent, so the test
        // survives being run from a packaged `.crate`.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("Cargo.lock");
        let Ok(bytes) = std::fs::read(&root) else {
            return;
        };
        let lock = CargoLockfile::parse(&bytes).expect("the workspace lockfile parses");
        let version = env!("CARGO_PKG_VERSION");
        let closure = lock
            .resolve_closure("hort-formats", version, None)
            .expect("this crate's own closure walks");

        // Direct registry deps and a transitive one must be present...
        let found = names(&closure);
        for expected in ["flate2", "tar", "toml", "serde_json"] {
            assert!(
                found.iter().any(|c| c.starts_with(&format!("{expected}@"))),
                "{expected} missing from {}",
                found.len()
            );
        }
        // ...the path-sourced workspace siblings must be counted, not
        // emitted...
        assert!(
            !found.iter().any(|c| c.starts_with("hort-domain@")),
            "a path-sourced sibling leaked into the components"
        );
        assert!(
            closure.skipped_non_registry >= 2,
            "expected the path-sourced siblings to be counted, got {}",
            closure.skipped_non_registry
        );
        // ...and every emitted component must carry an exact version, the
        // whole point of reading the lockfile instead of the manifest.
        for component in &closure.components {
            assert!(
                !component.version.is_empty()
                    && !component.version.starts_with(['^', '~', '=', '>', '<']),
                "{component:?} is not an exact resolved version"
            );
        }
    }

    #[test]
    fn is_top_level_cargo_lock_matches_only_the_single_dir_lockfile() {
        assert!(is_top_level_cargo_lock("demo-0.1.0/Cargo.lock"));
        assert!(is_top_level_cargo_lock("./demo-0.1.0/Cargo.lock"));
        assert!(!is_top_level_cargo_lock("Cargo.lock"));
        assert!(!is_top_level_cargo_lock("/Cargo.lock"));
        assert!(!is_top_level_cargo_lock("demo-0.1.0/vendor/x/Cargo.lock"));
        assert!(!is_top_level_cargo_lock("demo-0.1.0/Cargo.lock.orig"));
        assert!(!is_top_level_cargo_lock("demo-0.1.0/Cargo.toml"));
    }

    #[test]
    fn is_registry_source_accepts_both_index_forms_only() {
        assert!(is_registry_source(Some(REG)));
        assert!(is_registry_source(Some(SPARSE)));
        assert!(!is_registry_source(Some("git+https://example.test/g#abc")));
        assert!(!is_registry_source(None));
    }

    #[test]
    fn edge_package_name_takes_the_leading_token() {
        assert_eq!(edge_package_name("serde"), "serde");
        assert_eq!(edge_package_name("serde 1.0.200"), "serde");
        assert_eq!(edge_package_name(&format!("serde 1.0.200 {REG}")), "serde");
        assert_eq!(edge_package_name("   "), "");
    }

    #[test]
    fn token_excerpt_truncates_and_scrubs_publisher_bytes() {
        assert_eq!(token_excerpt("serde 1.0.200"), "serde 1.0.200");
        assert_eq!(token_excerpt("a\nb\tc"), "a?b?c");
        let long = "x".repeat(ERROR_EXCERPT_MAX_CHARS + 10);
        let out = token_excerpt(&long);
        assert_eq!(out.chars().count(), ERROR_EXCERPT_MAX_CHARS + 1);
        assert!(out.ends_with('…'), "{out}");
        // Exactly at the cap: nothing dropped, so no ellipsis.
        let at_cap = "y".repeat(ERROR_EXCERPT_MAX_CHARS);
        assert_eq!(token_excerpt(&at_cap), at_cap);
    }

    #[test]
    fn an_inconsistent_edge_error_quotes_a_scrubbed_excerpt() {
        // The edge carries a TOML unicode escape that decodes to a real
        // control byte (U+0007) — publisher-controlled bytes that must
        // never reach a log line verbatim. The padding pushes the edge
        // past the excerpt cap so the truncation arm is exercised on a
        // real error too.
        let hostile = format!(r"gh\u0007ost{}", "z".repeat(ERROR_EXCERPT_MAX_CHARS));
        let text = lockfile(&[pkg("root", "1.0.0", None, None, &[&hostile])]);
        let lock = CargoLockfile::parse(text.as_bytes()).expect("parses");
        let err = lock.resolve_closure("root", "1.0.0", None).unwrap_err();
        let DomainError::Validation(message) = err else {
            panic!("expected Validation");
        };
        assert!(!message.contains('\u{7}'), "{message}");
        assert!(message.contains("gh?ost"), "{message}");
        assert!(
            message.contains('…'),
            "excerpt must be truncated: {message}"
        );
    }
}
