//! Bounded, fail-closed archive extraction for scan materialisation.
//!
//! Trivy's filesystem mode does not open archives: it picks analyzers
//! from file names and directory layout. A wheel, an npm tarball, a
//! `.crate` or an OCI layer therefore has to be **unpacked onto disk**
//! before the scanner sees anything at all. That makes this module the
//! one place in the workspace that writes attacker-supplied archive
//! entries to a filesystem path, so every guard lives here and every
//! guard refuses the whole archive rather than skipping past a bad entry.
//!
//! # Why not `hort-formats::archive_bounds`
//!
//! That helper is the sanctioned route for archive *metadata* reads: it
//! pulls one named entry into memory and never touches a path. It has no
//! extract-to-disk API, and adding one would put path-traversal and
//! link-escape handling in a crate whose callers do not need it, while
//! this adapter (which depends only on `hort-domain`, per the port
//! contract) cannot reach it anyway. The caps below are deliberately the
//! same *shape* as that helper's — output bytes, entry count,
//! compression ratio — so the two read as one policy.
//!
//! # The guards
//!
//! Every one of them is a refusal, not a repair. A legitimate wheel,
//! tarball or image layer trips none of them; tripping one means the
//! payload is hostile or pathological, and the caller turns that into
//! `NotAnalysable::UnusableArchive` → a fail-closed hold. Continuing with
//! a partially-extracted tree would be worse than refusing, because the
//! scanner would adjudicate the fragment as if it were the artifact.
//!
//! 1. **Extracted-bytes cap** — an absolute ceiling on bytes written,
//!    independent of how well the input compressed.
//! 2. **Decompression-ratio cap** — bytes written relative to the
//!    compressed input size. This is what catches the classic bomb: a
//!    few KiB expanding to gigabytes trips the ratio long before it
//!    trips the absolute cap.
//! 3. **Entry-count cap** — bounds the per-entry syscall and inode cost
//!    of an archive made of a million one-byte files.
//! 4. **Path containment** — an entry's own **name** must be relative and
//!    must not contain a `..` component. Checked **lexically, before any
//!    filesystem call**, so nothing is created outside the root even
//!    transiently. A name that escapes is refused: it is the one property
//!    that decides whether extraction ever writes outside the root.
//! 5. **Stripped permissions** — files land `0o644`, directories
//!    `0o755`, regardless of the archive's mode bits. setuid/setgid and
//!    world-writable modes from an untrusted archive have no business on
//!    the worker's disk, and Trivy reads content, not modes.
//!
//! A symlink or hardlink entry is **never materialised**, regardless of
//! where its target points: a link carries no bytes of its own, so
//! creating it would only hand the scanner another path to follow for no
//! added evidence. Because it is never created, an out-of-root or
//! absolute *target* cannot write, read or expose anything either — only
//! the entry's own name (guard 4, above) can. So every link entry is
//! skipped and counted (`skipped_links`), never a refusal: a root
//! filesystem is full of absolute symlinks (`/bin/sh -> /bin/busybox`,
//! merged-usr `lib -> usr/lib`), which is the normal shape of the payload,
//! not an attack.
//!
//! Anything that is neither a regular file, a directory, nor a link —
//! device nodes, FIFOs, sockets — is likewise skipped without being
//! created, though not counted: such an entry carries nothing to analyse
//! and materialising one is pure risk, but it is not the fact
//! [`ExtractStats::skipped_links`] exists to surface.

use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Caps for one extraction. Compile-time policy, **not** an operator
/// surface: these are safety bounds on untrusted input, and an operator
/// who could raise them could re-open the bomb surface the adapter exists
/// to close. Tests construct tightened values directly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExtractBounds {
    /// Absolute ceiling on bytes written across the whole archive.
    pub(crate) max_extracted_bytes: u64,
    /// Ceiling on `extracted / compressed`. Real-world archives sit in
    /// the single digits; a rootfs of many small text files can reach the
    /// low tens.
    pub(crate) max_compression_ratio: u64,
    /// Ceiling on entries iterated from one archive.
    pub(crate) max_entries: usize,
}

/// Absolute extracted-bytes ceiling. 4 GiB: above any real image layer
/// or distribution archive (layers are typically well under 1 GiB
/// uncompressed, and the input copy is already capped at
/// `max_artifact_size`), and low enough that one artifact cannot fill a
/// worker's scratch disk.
const MAX_EXTRACTED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Decompression-ratio ceiling. 100× is generous — gzipped source trees
/// land around 3–5×, and a rootfs layer of many small text files in the
/// low tens — while a decompression bomb's whole point is achieving
/// 1000× or more.
const MAX_COMPRESSION_RATIO: u64 = 100;

/// Entry-count ceiling. 200 000: a Debian-based rootfs layer carries tens
/// of thousands of files and a large wheel a few thousand, so this leaves
/// an order of magnitude of headroom while still refusing the
/// million-tiny-entries inode-exhaustion shape.
const MAX_ENTRIES: usize = 200_000;

impl ExtractBounds {
    /// The shipped caps. See the module doc for what each one defends.
    pub(crate) const fn default_for_scan_materialisation() -> Self {
        Self {
            max_extracted_bytes: MAX_EXTRACTED_BYTES,
            max_compression_ratio: MAX_COMPRESSION_RATIO,
            max_entries: MAX_ENTRIES,
        }
    }
}

/// Why an extraction was refused.
///
/// Every variant is terminal for that archive. None of them means "retry
/// with a bigger cap": the caller maps all of them to the same
/// fail-closed `UnusableArchive` outcome, and the variants exist so the
/// log line names which guard fired.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ExtractError {
    #[error("extracted-bytes cap exceeded ({cap} bytes)")]
    ExtractedBytesCap { cap: u64 },
    #[error("decompression-ratio cap exceeded ({limit}x of {compressed} compressed bytes)")]
    CompressionRatioCap { limit: u64, compressed: u64 },
    #[error("archive entry cap exceeded ({cap} entries)")]
    EntryCap { cap: usize },
    #[error("archive entry path is not contained in the workspace")]
    UncontainedPath,
    #[error("archive could not be read: {0}")]
    Malformed(String),
}

/// What an extraction produced, for the caller's log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ExtractStats {
    /// Entries iterated (including directories and skipped entries).
    pub(crate) entries: usize,
    /// Bytes written to disk.
    pub(crate) bytes: u64,
    /// Symlink and hardlink entries skipped: never materialised, and
    /// never a reason to refuse the archive regardless of where their
    /// target points. Surfaced so a caller's log line can tell "this
    /// archive carried N links" from "this archive carried none".
    pub(crate) skipped_links: usize,
}

/// Running byte budget shared by the absolute cap and the ratio cap.
struct ByteBudget {
    bounds: ExtractBounds,
    compressed: u64,
    written: u64,
}

impl ByteBudget {
    fn new(bounds: ExtractBounds, compressed: u64) -> Self {
        Self {
            bounds,
            compressed,
            written: 0,
        }
    }

    /// Account `n` freshly-written bytes, refusing if either ceiling is
    /// now exceeded. Both are checked every time so the error names the
    /// guard that actually fired rather than whichever was checked first
    /// by accident.
    fn charge(&mut self, n: u64) -> Result<(), ExtractError> {
        self.written = self.written.saturating_add(n);
        if self.written > self.bounds.max_extracted_bytes {
            return Err(ExtractError::ExtractedBytesCap {
                cap: self.bounds.max_extracted_bytes,
            });
        }
        // `saturating_mul` so a huge compressed size cannot wrap the
        // product into a small (and therefore over-tight) allowance.
        let ratio_allowance = self
            .compressed
            .saturating_mul(self.bounds.max_compression_ratio);
        if self.written > ratio_allowance {
            return Err(ExtractError::CompressionRatioCap {
                limit: self.bounds.max_compression_ratio,
                compressed: self.compressed,
            });
        }
        Ok(())
    }
}

/// How an archive entry's lexically-validated path relates to the
/// extraction root.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathContainment {
    /// A safe, non-empty, root-relative path.
    Relative(PathBuf),
    /// The name normalises to the workspace root itself: made only of
    /// `CurDir` components (`.`, `./`, `./.`, …). Every `tar -C dir .`
    /// producer emits this as the archive's own first entry, and it
    /// names a location that already exists — not a traversal.
    Root,
}

/// Lexically validate an archive entry path.
///
/// Returns `None` — meaning refuse the archive — for an absolute path, a
/// Windows prefix, or any `..` component. `.` components are dropped; if
/// that drops the path to nothing, the entry named the workspace root
/// itself ([`PathContainment::Root`]), not an escape. **No filesystem
/// call happens here**: containment is decided from the bytes of the
/// path alone, so a hostile entry never reaches a `create_dir_all` or an
/// `open`.
fn contained_relative_path(raw: &Path) -> Option<PathContainment> {
    let mut out = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            // Absolute, drive-prefixed, or upward-traversing: all three
            // can name a location outside the root, so the archive is
            // refused rather than the entry sanitised. Sanitising is what
            // lets a crafted archive smuggle a payload in under a name
            // the operator never sees.
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => return None,
        }
    }
    if out.as_os_str().is_empty() {
        return Some(PathContainment::Root);
    }
    Some(PathContainment::Relative(out))
}

/// Create `root`-relative `rel` as a directory with permissions stripped
/// to `0o755`.
fn create_dir(root: &Path, rel: &Path) -> Result<(), ExtractError> {
    let full = root.join(rel);
    fs::create_dir_all(&full).map_err(|e| ExtractError::Malformed(e.to_string()))?;
    set_mode(&full, 0o755)
}

/// Write one entry's bytes to `root`-relative `rel`, charging the byte
/// budget as the copy proceeds so a lying header size cannot buy an
/// unbounded write.
///
/// The copy is chunked and the budget is charged **per chunk**: the
/// refusal therefore lands after at most one chunk past the cap, not
/// after the whole entry. That matters because the tar header's declared
/// size is attacker-controlled and is never trusted as the bound.
fn write_file<R: Read>(
    root: &Path,
    rel: &Path,
    reader: &mut R,
    budget: &mut ByteBudget,
) -> Result<u64, ExtractError> {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).map_err(|e| ExtractError::Malformed(e.to_string()))?;
    }
    let mut file = fs::File::create(&full).map_err(|e| ExtractError::Malformed(e.to_string()))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| ExtractError::Malformed(e.to_string()))?;
        if n == 0 {
            break;
        }
        budget.charge(n as u64)?;
        io::Write::write_all(&mut file, &buf[..n])
            .map_err(|e| ExtractError::Malformed(e.to_string()))?;
        total += n as u64;
    }
    io::Write::flush(&mut file).map_err(|e| ExtractError::Malformed(e.to_string()))?;
    drop(file);
    set_mode(&full, 0o644)?;
    Ok(total)
}

/// Force a fixed mode on a freshly-created path, discarding whatever the
/// archive declared. Non-Unix targets have no mode bits to strip, so the
/// call is a no-op there.
fn set_mode(path: &Path, mode: u32) -> Result<(), ExtractError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| ExtractError::Malformed(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// Extract a tar stream into `root` under `bounds`.
///
/// `input` is the **decompressed** tar byte stream; `compressed_size` is
/// the size of the bytes it was decompressed *from* (equal to the tar's
/// own size when there is no compression layer), which is what the ratio
/// cap is measured against. The caller supplies the decoder, so one
/// implementation serves plain tar and gzip-tar alike.
pub(crate) fn extract_tar<R: Read>(
    input: R,
    compressed_size: u64,
    root: &Path,
    bounds: ExtractBounds,
) -> Result<ExtractStats, ExtractError> {
    let mut archive = tar::Archive::new(input);
    let mut budget = ByteBudget::new(bounds, compressed_size);
    let mut stats = ExtractStats::default();

    let entries = archive
        .entries()
        .map_err(|e| ExtractError::Malformed(format!("expected a tar archive: {e}")))?;

    for entry in entries {
        if stats.entries >= bounds.max_entries {
            return Err(ExtractError::EntryCap {
                cap: bounds.max_entries,
            });
        }
        stats.entries += 1;

        let mut entry = entry.map_err(|e| ExtractError::Malformed(format!("tar entry: {e}")))?;
        let entry_type = entry.header().entry_type();

        // Extension headers (PAX/GNU long-name records) carry no
        // materialisable content — the `tar` crate has already folded
        // them into the following entry's path — and a global extension
        // header has no path of its own to validate.
        if entry_type.is_pax_global_extensions() || entry_type.is_gnu_longname() {
            continue;
        }

        let raw = entry
            .path()
            .map_err(|e| ExtractError::Malformed(format!("tar entry path: {e}")))?
            .into_owned();
        let rel = match contained_relative_path(&raw) {
            None => return Err(ExtractError::UncontainedPath),
            Some(PathContainment::Root) => {
                // The archive's own root entry: nothing to create for a
                // directory, since the root already exists. A regular
                // file cannot be named "the workspace root" — refuse
                // only if it actually carries a body; an empty one is
                // the same no-op as the directory case.
                if entry_type.is_dir() || entry.size() == 0 {
                    continue;
                }
                return Err(ExtractError::Malformed(
                    "archive root entry cannot be a regular file with content".to_string(),
                ));
            }
            Some(PathContainment::Relative(rel)) => rel,
        };

        if entry_type.is_symlink() || entry_type.is_hard_link() {
            // Never materialised, so the target is never followed and
            // never validated: an absolute or escaping target cannot
            // write, read or expose anything if it is never created. Only
            // the entry's own name, validated above, matters.
            stats.skipped_links += 1;
            continue;
        }

        if entry_type.is_dir() {
            create_dir(root, &rel)?;
            continue;
        }

        if !entry_type.is_file() {
            // Device nodes, FIFOs, sockets: nothing to analyse, and
            // creating one on the worker's disk is pure risk.
            continue;
        }

        stats.bytes += write_file(root, &rel, &mut entry, &mut budget)?;
    }

    Ok(stats)
}

/// Extract a ZIP archive into `root` under `bounds`.
///
/// `compressed_size` is the archive's own byte length, for the ratio cap.
/// ZIP needs `Seek` because entries are located through the central
/// directory rather than by scanning.
pub(crate) fn extract_zip<R: Read + io::Seek>(
    input: R,
    compressed_size: u64,
    root: &Path,
    bounds: ExtractBounds,
) -> Result<ExtractStats, ExtractError> {
    let mut archive = zip::ZipArchive::new(input)
        .map_err(|e| ExtractError::Malformed(format!("expected a zip archive: {e}")))?;
    let mut budget = ByteBudget::new(bounds, compressed_size);
    let mut stats = ExtractStats::default();

    for i in 0..archive.len() {
        if stats.entries >= bounds.max_entries {
            return Err(ExtractError::EntryCap {
                cap: bounds.max_entries,
            });
        }
        stats.entries += 1;

        let mut entry = archive
            .by_index(i)
            .map_err(|e| ExtractError::Malformed(format!("zip entry {i}: {e}")))?;

        // The entry's declared name goes through the same lexical
        // containment check as a tar path rather than through the zip
        // crate's own sanitiser, so one rule governs both containers and
        // a hostile name is a refusal in both.
        let raw = PathBuf::from(entry.name());
        let rel = match contained_relative_path(&raw) {
            None => return Err(ExtractError::UncontainedPath),
            Some(PathContainment::Root) => {
                // Same reasoning as the tar path: the archive's own root
                // entry is a no-op for a directory (or an empty file),
                // and a refusal only if a "root" file actually carries a
                // body.
                if entry.is_dir() || entry.size() == 0 {
                    continue;
                }
                return Err(ExtractError::Malformed(
                    "archive root entry cannot be a regular file with content".to_string(),
                ));
            }
            Some(PathContainment::Relative(rel)) => rel,
        };

        if entry.is_symlink() {
            // Same reasoning as the tar path: never materialised, target
            // never followed, so never a refusal regardless of where it
            // points.
            stats.skipped_links += 1;
            continue;
        }

        if entry.is_dir() {
            create_dir(root, &rel)?;
            continue;
        }
        if !entry.is_file() {
            continue;
        }

        stats.bytes += write_file(root, &rel, &mut entry, &mut budget)?;
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::io::Write as _;

    /// Tight bounds so a fixture of a few hundred bytes can trip a cap
    /// without building a real bomb.
    fn tight() -> ExtractBounds {
        ExtractBounds {
            max_extracted_bytes: 4096,
            max_compression_ratio: 4,
            max_entries: 8,
        }
    }

    /// Write `name` straight into the header's name field, bypassing
    /// `Header::set_path`'s own validation.
    ///
    /// `set_path` refuses absolute and `..`-bearing paths — sensible for
    /// an archive *writer*, and exactly why it cannot build the hostile
    /// fixtures this module's guards exist to refuse. A real attacker's
    /// tar is bytes, not a `tar::Builder` call, so the fixtures are bytes
    /// too.
    fn set_raw_path(header: &mut tar::Header, name: &str) {
        let bytes = name.as_bytes();
        assert!(bytes.len() <= 100, "raw tar name must fit the ustar field");
        let field = &mut header.as_old_mut().name;
        field.fill(0);
        field[..bytes.len()].copy_from_slice(bytes);
    }

    /// Build a tar archive from `(path, entry_type, body_or_link_target)`.
    /// Link entries carry their target in the third element.
    fn tar_bytes(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, kind, body) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(*kind);
            header.set_mode(0o777);
            let is_link = *kind == tar::EntryType::Symlink || *kind == tar::EntryType::Link;
            let payload: &[u8] = if is_link { &[] } else { body };
            header.set_size(payload.len() as u64);
            if is_link {
                header
                    .set_link_name(std::str::from_utf8(body).expect("link name is utf-8"))
                    .expect("set_link_name");
            }
            set_raw_path(&mut header, path);
            header.set_cksum();
            builder.append(&header, payload).expect("append entry");
        }
        builder.into_inner().expect("finish tar")
    }

    fn file_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let owned: Vec<(&str, tar::EntryType, &[u8])> = entries
            .iter()
            .map(|(p, b)| {
                let kind = if p.ends_with('/') {
                    tar::EntryType::Directory
                } else {
                    tar::EntryType::Regular
                };
                (*p, kind, *b)
            })
            .collect();
        tar_bytes(&owned)
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o777);
            for (name, body) in entries {
                zw.start_file(*name, opts).expect("start_file");
                zw.write_all(body).expect("write_all");
            }
            zw.finish().expect("finish zip");
        }
        buf
    }

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // -- happy paths ---------------------------------------------------

    #[test]
    fn extract_tar_writes_files_and_directories() {
        let bytes = file_tar(&[
            ("pkg/", b""),
            ("pkg/package.json", br#"{"name":"x"}"#),
            ("pkg/lib/index.js", b"module.exports = 1;"),
        ]);
        let dir = root();
        let len = bytes.len() as u64;
        let stats = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("extract");
        assert_eq!(
            fs::read(dir.path().join("pkg/package.json")).expect("read"),
            br#"{"name":"x"}"#
        );
        assert!(dir.path().join("pkg/lib/index.js").exists());
        assert!(stats.bytes > 0);
        assert_eq!(stats.entries, 3);
    }

    #[test]
    fn extract_zip_writes_nested_entries() {
        let bytes = zip_bytes(&[
            ("urllib3-1.26.4.dist-info/METADATA", b"Name: urllib3\n"),
            ("urllib3/__init__.py", b"# urllib3\n"),
        ]);
        let dir = root();
        let len = bytes.len() as u64;
        extract_zip(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("extract");
        assert_eq!(
            fs::read(dir.path().join("urllib3-1.26.4.dist-info/METADATA")).expect("read"),
            b"Name: urllib3\n"
        );
        assert!(dir.path().join("urllib3/__init__.py").exists());
    }

    /// Permissions are stripped: an archive declaring `0o777` (or
    /// setuid) must not produce a world-writable or executable file on
    /// the worker's disk.
    #[cfg(unix)]
    #[test]
    fn extracted_permissions_are_stripped_to_a_fixed_mode() {
        use std::os::unix::fs::PermissionsExt;
        let bytes = file_tar(&[("dir/", b""), ("dir/f", b"x")]);
        let dir = root();
        let len = bytes.len() as u64;
        extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("extract");
        let file_mode = fs::metadata(dir.path().join("dir/f"))
            .expect("stat file")
            .permissions()
            .mode()
            & 0o7777;
        let dir_mode = fs::metadata(dir.path().join("dir"))
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(file_mode, 0o644, "file mode must be forced to 0o644");
        assert_eq!(dir_mode, 0o755, "dir mode must be forced to 0o755");
    }

    // -- bound: entry count --------------------------------------------

    #[test]
    fn extract_tar_refuses_over_entry_cap() {
        let bodies: Vec<(String, Vec<u8>)> =
            (0..12).map(|i| (format!("f{i}"), b"x".to_vec())).collect();
        let refs: Vec<(&str, &[u8])> = bodies
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let bytes = file_tar(&refs);
        let dir = root();
        let len = bytes.len() as u64;
        let err = extract_tar(Cursor::new(bytes), len, dir.path(), tight())
            .expect_err("entry cap must trip");
        assert_eq!(err, ExtractError::EntryCap { cap: 8 });
    }

    #[test]
    fn extract_zip_refuses_over_entry_cap() {
        let bodies: Vec<(String, Vec<u8>)> =
            (0..12).map(|i| (format!("f{i}"), b"x".to_vec())).collect();
        let refs: Vec<(&str, &[u8])> = bodies
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let bytes = zip_bytes(&refs);
        let dir = root();
        let len = bytes.len() as u64;
        let err = extract_zip(Cursor::new(bytes), len, dir.path(), tight())
            .expect_err("entry cap must trip");
        assert_eq!(err, ExtractError::EntryCap { cap: 8 });
    }

    // -- bound: extracted bytes ----------------------------------------

    #[test]
    fn extract_tar_refuses_over_extracted_bytes_cap() {
        // 8 KiB of content against a 4 KiB absolute cap, with the ratio
        // allowance kept generous so the absolute cap is unambiguously
        // the guard that fires.
        let body = vec![b'A'; 8 * 1024];
        let bytes = file_tar(&[("big", &body)]);
        let dir = root();
        let bounds = ExtractBounds {
            max_extracted_bytes: 4096,
            max_compression_ratio: 1_000_000,
            max_entries: 8,
        };
        let len = bytes.len() as u64;
        let err = extract_tar(Cursor::new(bytes), len, dir.path(), bounds)
            .expect_err("byte cap must trip");
        assert_eq!(err, ExtractError::ExtractedBytesCap { cap: 4096 });
    }

    // -- bound: compression ratio --------------------------------------

    /// The bomb shape: a tiny gzip stream expanding far beyond its
    /// compressed size. The ratio cap must fire before the absolute cap,
    /// which is what makes it the useful guard — the absolute cap alone
    /// would happily admit a 1 KiB input expanding to 4 GiB.
    #[test]
    fn extract_tar_refuses_over_compression_ratio() {
        let body = vec![0u8; 512 * 1024];
        let tar = file_tar(&[("bomb", &body)]);
        let gz = {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(&tar).expect("gz write");
            enc.finish().expect("gz finish")
        };
        let compressed_len = gz.len() as u64;
        assert!(
            compressed_len * 100 < 512 * 1024,
            "fixture must actually be a >100x expansion; got {compressed_len} compressed"
        );
        let dir = root();
        let err = extract_tar(
            flate2::read::GzDecoder::new(Cursor::new(gz)),
            compressed_len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect_err("ratio cap must trip");
        match err {
            ExtractError::CompressionRatioCap { limit, .. } => assert_eq!(limit, 100),
            other => panic!("expected the ratio cap to fire, got {other:?}"),
        }
    }

    /// A gzip-tar whose expansion is ordinary must extract cleanly —
    /// the ratio cap must not false-positive on real archives.
    #[test]
    fn extract_tar_accepts_an_ordinary_gzip_tar() {
        // Pseudorandom (incompressible) bodies keep the ratio near 1.
        let body: Vec<u8> = {
            let mut state: u32 = 0x1234_5678;
            (0..8192)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> 24) as u8
                })
                .collect()
        };
        let tar = file_tar(&[
            ("package/package.json", br#"{"name":"x"}"#),
            ("package/blob", &body),
        ]);
        let gz = {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(&tar).expect("gz write");
            enc.finish().expect("gz finish")
        };
        let compressed_len = gz.len() as u64;
        let dir = root();
        let stats = extract_tar(
            flate2::read::GzDecoder::new(Cursor::new(gz)),
            compressed_len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("an ordinary gzip-tar must extract");
        assert!(dir.path().join("package/package.json").exists());
        assert_eq!(stats.entries, 2);
    }

    // -- bound: path containment ---------------------------------------

    #[test]
    fn extract_tar_refuses_a_traversing_entry_path() {
        for path in ["../escape", "a/../../escape", "./../escape"] {
            let bytes = file_tar(&[(path, b"payload")]);
            let dir = root();
            let len = bytes.len() as u64;
            let err = extract_tar(
                Cursor::new(bytes),
                len,
                dir.path(),
                ExtractBounds::default_for_scan_materialisation(),
            )
            .expect_err("traversal must be refused");
            assert_eq!(err, ExtractError::UncontainedPath, "path {path}");
        }
    }

    #[test]
    fn extract_zip_refuses_a_traversing_entry_path() {
        let bytes = zip_bytes(&[("../escape", b"payload")]);
        let dir = root();
        let len = bytes.len() as u64;
        let err = extract_zip(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect_err("traversal must be refused");
        assert_eq!(err, ExtractError::UncontainedPath);
    }

    /// A refusal must leave nothing behind outside the root. The
    /// containment check is lexical and runs before any filesystem call,
    /// so there is no window in which the escaping path exists.
    #[test]
    fn a_refused_traversal_creates_nothing_outside_the_root() {
        let outer = root();
        let inner = outer.path().join("scan-root");
        fs::create_dir(&inner).expect("mkdir inner");
        let bytes = file_tar(&[("../escaped.txt", b"payload")]);
        let len = bytes.len() as u64;
        let _ = extract_tar(
            Cursor::new(bytes),
            len,
            &inner,
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect_err("traversal must be refused");
        assert!(
            !outer.path().join("escaped.txt").exists(),
            "the refused entry must not have been written outside the root"
        );
    }

    #[test]
    fn absolute_entry_paths_are_refused() {
        let bytes = tar_bytes(&[("/etc/passwd", tar::EntryType::Regular, b"root:x:0:0")]);
        let dir = root();
        let len = bytes.len() as u64;
        let err = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect_err("absolute path must be refused");
        assert_eq!(err, ExtractError::UncontainedPath);
    }

    /// The shape every `tar -C dir .` producer emits: the archive's own
    /// first entry is the root directory `./`, followed by ordinary
    /// `./`-prefixed paths. None of it is a traversal — `./` names the
    /// workspace root, which already exists — so the whole archive must
    /// extract, not refuse on the first entry.
    #[test]
    fn extract_tar_accepts_its_own_root_entry() {
        let bytes = file_tar(&[("./", b""), ("./usr/", b""), ("./usr/share/x.crt", b"cert")]);
        let dir = root();
        let len = bytes.len() as u64;
        let stats = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("a tar -C dir . root entry must not refuse the archive");
        assert_eq!(
            fs::read(dir.path().join("usr/share/x.crt")).expect("read"),
            b"cert"
        );
        assert_eq!(stats.entries, 3);
    }

    #[test]
    fn extract_zip_accepts_its_own_root_entry() {
        let bytes = zip_bytes(&[("./", b""), ("./usr/share/x.crt", b"cert")]);
        let dir = root();
        let len = bytes.len() as u64;
        extract_zip(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("a zip root entry must not refuse the archive");
        assert_eq!(
            fs::read(dir.path().join("usr/share/x.crt")).expect("read"),
            b"cert"
        );
    }

    /// A root entry carrying an actual body is a malformed archive shape
    /// (a regular file cannot be named "the workspace root"), not a path
    /// escape — the refusal must be `Malformed`, not `UncontainedPath`.
    #[test]
    fn extract_tar_refuses_a_root_entry_with_a_body_as_malformed() {
        let bytes = tar_bytes(&[(".", tar::EntryType::Regular, b"unexpected")]);
        let dir = root();
        let len = bytes.len() as u64;
        let err = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect_err("a root entry with a body must be refused");
        assert!(matches!(err, ExtractError::Malformed(_)), "{err:?}");
    }

    // -- links: skipped and counted, never a refusal --------------------

    #[test]
    fn extract_tar_skips_and_counts_a_symlink_escaping_the_root() {
        let bytes = tar_bytes(&[("evil", tar::EntryType::Symlink, b"../../etc/passwd")]);
        let dir = root();
        let len = bytes.len() as u64;
        let stats = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("an escaping symlink target must not refuse the archive");
        assert_eq!(stats.skipped_links, 1);
        assert!(!dir.path().join("evil").exists());
    }

    #[test]
    fn extract_tar_skips_and_counts_an_absolute_symlink_target() {
        let bytes = tar_bytes(&[("evil", tar::EntryType::Symlink, b"/etc/passwd")]);
        let dir = root();
        let len = bytes.len() as u64;
        let stats = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("an absolute symlink target must not refuse the archive");
        assert_eq!(stats.skipped_links, 1);
        assert!(!dir.path().join("evil").exists());
    }

    #[test]
    fn extract_tar_skips_and_counts_a_hardlink_escaping_the_root() {
        let bytes = tar_bytes(&[("evil", tar::EntryType::Link, b"../outside")]);
        let dir = root();
        let len = bytes.len() as u64;
        let stats = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("an escaping hardlink target must not refuse the archive");
        assert_eq!(stats.skipped_links, 1);
        assert!(!dir.path().join("evil").exists());
    }

    /// A link entry is skipped and counted regardless of where its target
    /// points, contained or not: it carries no bytes, so creating it
    /// would only give the scanner another path to follow.
    #[test]
    fn a_link_is_skipped_and_counted_whether_or_not_its_target_is_contained() {
        let bytes = tar_bytes(&[
            ("real.txt", tar::EntryType::Regular, b"content"),
            ("link.txt", tar::EntryType::Symlink, b"real.txt"),
            ("sub/up.txt", tar::EntryType::Symlink, b"../real.txt"),
            ("escaping.txt", tar::EntryType::Symlink, b"/etc/passwd"),
        ]);
        let dir = root();
        let len = bytes.len() as u64;
        let stats = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("no link, contained or not, refuses the archive");
        assert!(dir.path().join("real.txt").exists());
        assert!(
            !dir.path().join("link.txt").exists(),
            "a link entry must not be materialised"
        );
        assert!(!dir.path().join("sub/up.txt").exists());
        assert!(!dir.path().join("escaping.txt").exists());
        assert_eq!(stats.skipped_links, 3);
    }

    /// The busybox-shaped root filesystem this change exists for: a real
    /// distro layer's ordinary mix of an absolute symlink, a relative
    /// symlink, an escaping symlink and a hardlink, none of which are an
    /// attack — a `/bin/sh -> /bin/busybox` is exactly what every real OS
    /// layer looks like.
    #[test]
    fn a_busybox_shaped_layer_extracts_its_regular_files_and_skips_every_link() {
        let bytes = tar_bytes(&[
            ("bin/busybox", tar::EntryType::Regular, b"#!/bin/busybox\n"),
            ("bin/sh", tar::EntryType::Symlink, b"/bin/busybox"),
            ("lib", tar::EntryType::Symlink, b"usr/lib"),
            ("usr/lib/libc.so", tar::EntryType::Regular, b"not real"),
            ("etc/passwd", tar::EntryType::Regular, b"root:x:0:0\n"),
            (
                "etc/escape",
                tar::EntryType::Symlink,
                b"../../../../outside",
            ),
            ("etc/hardlink", tar::EntryType::Link, b"etc/passwd"),
        ]);
        let dir = root();
        let len = bytes.len() as u64;
        let stats = extract_tar(
            Cursor::new(bytes),
            len,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect("a real root filesystem's absolute symlinks must not refuse the archive");

        assert_eq!(stats.skipped_links, 4);
        assert!(dir.path().join("bin/busybox").exists());
        assert!(dir.path().join("usr/lib/libc.so").exists());
        assert!(dir.path().join("etc/passwd").exists());
        for link in ["bin/sh", "lib", "etc/escape", "etc/hardlink"] {
            assert!(
                !dir.path().join(link).exists(),
                "link entry {link} must not be materialised"
            );
        }
    }

    // -- malformed input -----------------------------------------------

    #[test]
    fn extract_zip_refuses_a_non_zip_input() {
        let dir = root();
        let err = extract_zip(
            Cursor::new(b"not a zip".to_vec()),
            9,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect_err("non-zip must be refused");
        assert!(matches!(err, ExtractError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn extract_tar_refuses_a_truncated_archive() {
        let mut bytes = file_tar(&[("f", &vec![b'x'; 2048])]);
        bytes.truncate(700);
        let dir = root();
        let err = extract_tar(
            Cursor::new(bytes),
            700,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect_err("a truncated archive must be refused");
        assert!(matches!(err, ExtractError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn extract_tar_of_a_non_tar_input_is_refused() {
        let dir = root();
        let err = extract_tar(
            Cursor::new(b"definitely not a tar archive at all".to_vec()),
            35,
            dir.path(),
            ExtractBounds::default_for_scan_materialisation(),
        )
        .expect_err("non-tar must be refused");
        assert!(matches!(err, ExtractError::Malformed(_)), "{err:?}");
    }

    // -- pure helpers --------------------------------------------------

    #[test]
    fn contained_relative_path_normalises_and_refuses() {
        assert_eq!(
            contained_relative_path(Path::new("./a/./b")),
            Some(PathContainment::Relative(PathBuf::from("a/b")))
        );
        assert_eq!(
            contained_relative_path(Path::new("a/b")),
            Some(PathContainment::Relative(PathBuf::from("a/b")))
        );
        assert_eq!(
            contained_relative_path(Path::new("")),
            Some(PathContainment::Root)
        );
        assert_eq!(
            contained_relative_path(Path::new(".")),
            Some(PathContainment::Root)
        );
        assert_eq!(
            contained_relative_path(Path::new("./")),
            Some(PathContainment::Root)
        );
        assert_eq!(contained_relative_path(Path::new("/abs")), None);
        assert_eq!(contained_relative_path(Path::new("../up")), None);
        assert_eq!(contained_relative_path(Path::new("a/../../up")), None);
    }

    #[test]
    fn byte_budget_charges_both_ceilings() {
        let bounds = ExtractBounds {
            max_extracted_bytes: 100,
            max_compression_ratio: 2,
            max_entries: 8,
        };
        // Ratio allowance is 2 x 10 = 20, below the absolute 100, so the
        // ratio is what fires.
        let mut budget = ByteBudget::new(bounds, 10);
        assert!(budget.charge(20).is_ok(), "at the ratio allowance is fine");
        assert!(matches!(
            budget.charge(1),
            Err(ExtractError::CompressionRatioCap { .. })
        ));
        // With a compressed size large enough that the ratio allowance
        // exceeds the absolute cap, the absolute cap fires instead.
        let mut budget = ByteBudget::new(bounds, 1_000);
        assert!(budget.charge(100).is_ok());
        assert!(matches!(
            budget.charge(1),
            Err(ExtractError::ExtractedBytesCap { cap: 100 })
        ));
    }

    /// A compressed size large enough to wrap the ratio multiplication
    /// must not produce a *tighter* allowance than intended.
    #[test]
    fn byte_budget_ratio_saturates_instead_of_wrapping() {
        let bounds = ExtractBounds {
            max_extracted_bytes: u64::MAX,
            max_compression_ratio: 100,
            max_entries: 8,
        };
        let mut budget = ByteBudget::new(bounds, u64::MAX);
        assert!(budget.charge(1_000_000).is_ok());
    }

    #[test]
    fn shipped_bounds_are_the_documented_values() {
        let b = ExtractBounds::default_for_scan_materialisation();
        assert_eq!(b.max_extracted_bytes, 4 * 1024 * 1024 * 1024);
        assert_eq!(b.max_compression_ratio, 100);
        assert_eq!(b.max_entries, 200_000);
    }

    #[test]
    fn extract_errors_name_their_guard() {
        assert!(ExtractError::ExtractedBytesCap { cap: 7 }
            .to_string()
            .contains("extracted-bytes cap"));
        assert!(ExtractError::CompressionRatioCap {
            limit: 100,
            compressed: 5
        }
        .to_string()
        .contains("decompression-ratio cap"));
        assert!(ExtractError::EntryCap { cap: 3 }
            .to_string()
            .contains("entry cap"));
        assert!(ExtractError::UncontainedPath
            .to_string()
            .contains("not contained"));
        assert!(ExtractError::Malformed("why".into())
            .to_string()
            .contains("why"));
    }

    #[test]
    fn extract_stats_defaults_to_empty() {
        let s = ExtractStats::default();
        assert_eq!(s.entries, 0);
        assert_eq!(s.bytes, 0);
        assert_eq!(s.skipped_links, 0);
    }
}
