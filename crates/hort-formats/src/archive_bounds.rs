//! # archive_bounds — bounded archive metadata extraction
//!
//! **Preventive helper.** All ZIP/gzip-tar extraction in this workspace
//! routes through this module to clamp the decompression-bomb attack
//! surface — bounded output, bounded entry count, no nested archives.
//!
//! ## Invariants the helper enforces
//!
//! 1. **Bounded decompressed output.** Wrap the decompressor in
//!    [`BoundedReader::new`] with `output_cap = min(10 × compressed_size,
//!    [`MAX_OUTPUT_BYTES`])`. Reads past the cap return
//!    [`BoundsError::OutputCapExceeded`] before the underlying reader can
//!    yield more bytes — a 1 KiB gzip-bomb expanding to gigabytes is
//!    rejected after `output_cap` bytes, not after the kernel kills the
//!    process for OOM.
//!
//! 2. **Bounded entry count.** When iterating archive entries (e.g.
//!    `tar::Archive::entries()`), call [`EntryCounter::tick`] before
//!    processing each entry. The counter trips after [`MAX_ENTRIES`]
//!    entries with [`BoundsError::EntryCapExceeded`].
//!
//! 3. **No nested archives.** [`BoundsConfig::allow_nested`] is hard-coded
//!    to `false` in [`BoundsConfig::default_for_metadata_extraction`] and
//!    cannot be flipped at runtime. Callers that detect a tar-in-tar /
//!    zip-in-tar etc. MUST return [`BoundsError::NestedArchiveRejected`]
//!    rather than recursing. Recursion is a capability that has to be
//!    re-introduced in a reviewed change.
//!
//! ## Why this module exists despite zero current call sites
//!
//! Without a
//! pre-existing helper, the natural pattern is for a contributor to
//! `cargo add tar flate2` directly inside an `hort-http-<format>` or `hort-
//! formats` module and write the extraction inline — at which point the
//! caps are easy to forget. By putting the helper here first and adding
//! the `cargo-deny [bans]` rule that limits `tar` / `zip` / `flate2` /
//! `bzip2` / `xz2` to the `hort-formats` crate (via the `wrappers`
//! exception), every new archive consumer is forced through this module.
//!
//! ## How a future caller integrates a real archive crate
//!
//! 1. Add the concrete archive crate as a direct dependency of
//!    `hort-formats` (`flate2` is already in the lockfile transitively;
//!    `tar` / `zip` / `bzip2` / `xz2` are not). The [bans] rule's
//!    `wrappers = ["hort-formats"]` exception permits it here and only
//!    here.
//!
//! 2. Wrap the decompressor: `BoundedReader::new(GzDecoder::new(input),
//!    config.output_cap_for(compressed_size))`.
//!
//! 3. For tar entry iteration: `let mut counter =
//!    EntryCounter::new(config.max_entries); for entry in
//!    archive.entries()? { counter.tick()?; ... }`. Wrap each
//!    `entry.take(config.per_entry_cap)` to bound per-entry output too.
//!
//! 4. If an entry's name suggests another archive (`*.tar`, `*.zip`,
//!    `*.tar.gz`, …), return [`BoundsError::NestedArchiveRejected`]. The
//!    helper does not auto-detect; the caller knows the format-specific
//!    file naming.
//!
//! ## What this helper does NOT do
//!
//! - Provide a generic "extract archive at path" API. There is no such
//!   thing — every metadata extractor is format-specific (PyPI's
//!   `PKG-INFO` lives at `<root>/PKG-INFO`; npm's `package.json` lives
//!   at `package/package.json`; …). The helper provides primitives,
//!   not a one-size-fits-all extraction.
//!
//! - Open the archive itself. Callers construct the decompressor /
//!   archive reader with the concrete crate; this module only supplies
//!   the bounded `Read` wrapper, the entry counter, and the config.
//!
//! - Hold a direct dep on any archive crate today. If we did, the
//!   `[bans]` exception would already be exercised, but the lockfile
//!   would acquire `tar` / etc. without a real consumer. The exception
//!   activates the moment a future PR plumbs a concrete decoder
//!   through this helper.

use std::io::{self, Read, Seek};

/// Hard cap on decompressed bytes per archive metadata extraction.
///
/// 10 MiB. Real-world metadata files are tiny: a PyPI sdist `PKG-INFO`
/// is a few KB; npm `package.json` is single-digit KB at most; Maven
/// POMs sit under 100 KB even for large multi-module projects.
/// 10 MiB sits well above any legitimate metadata file and well below
/// "we OOM'd extracting metadata".
pub const MAX_OUTPUT_BYTES: u64 = 10 * 1024 * 1024;

/// Compression-ratio multiplier on the compressed input size.
///
/// The effective output cap is `min(COMPRESSION_RATIO_LIMIT × compressed,
/// MAX_OUTPUT_BYTES)`. A legitimate gzipped text file rarely exceeds 5×
/// compression; a zip-bomb's whole point is achieving 1000× or more.
/// 10× is the recommended threshold.
pub const COMPRESSION_RATIO_LIMIT: u64 = 10;

/// Hard cap on the number of entries iterated from a single archive.
///
/// Set to 1024. Real metadata extraction typically reads one or two
/// named entries (`PKG-INFO`, `package.json`,
/// `<groupId>/<artifactId>.pom`); 1024 sits an order of magnitude above
/// any plausible legitimate count and four orders of magnitude below
/// "tar with a million 1-byte entries used as a CPU exhaustion vector".
pub const MAX_ENTRIES: usize = 1024;

/// Entry-count cap for trusted bulk feeds.
///
/// ~1e5 (100 000). Sized for full-ecosystem OSV bulk archives: the npm
/// ecosystem zip currently contains ~20 000 advisories; PyPI and Maven
/// are in the same order of magnitude; a factor-5 headroom covers
/// realistic multi-year growth without relaxing the cap to "unbounded".
/// A malicious zip-bomb payload with 100 001 entries is still rejected.
pub const MAX_ENTRIES_TRUSTED_BULK: usize = 100_000;

/// Per-entry output-byte ceiling for trusted bulk feeds.
///
/// 2 GiB.  This cap is applied **per advisory JSON entry** by
/// [`BoundsConfig::output_cap_for`] — a fresh [`BoundedReader`] is
/// constructed for each zip entry and discarded after the visitor returns.
/// There is **no archive-aggregate output accumulator**; entries are processed
/// one at a time.
///
/// The effective limit per entry is `min(COMPRESSION_RATIO_LIMIT × compressed,
/// 2 GiB)`.  A single advisory JSON record in the OSV dataset is typically a
/// few KB to a few hundred KB; the 2 GiB ceiling is unreachably high in
/// practice and exists solely to reject a per-entry decompression bomb.
///
/// The decompression-bomb defenses for the trusted bulk feed are:
/// 1. Finite entry-count cap (`MAX_ENTRIES_TRUSTED_BULK = 1e5`).
/// 2. Per-entry compression-ratio bound (`COMPRESSION_RATIO_LIMIT = 10×`).
/// 3. This per-entry hard ceiling as the backstop when the ratio bound alone
///    is insufficient (e.g. an enormous compressed input).
///
/// The 2 GiB value is intentionally conservative — raising it has no
/// operational benefit given realistic advisory JSON sizes, and lowering it
/// below the largest possible legitimate advisory would cause false rejections.
pub const MAX_OUTPUT_BYTES_TRUSTED_BULK: u64 = 2 * 1024 * 1024 * 1024;

/// Configuration for a single bounded archive read.
///
/// Construct via [`BoundsConfig::default_for_metadata_extraction`]; the
/// fields are public for tests and for callers that need a tighter cap
/// (e.g. a format that knows its metadata file is at most 64 KiB), but
/// the defaults are the policy floor and must not be raised.
#[derive(Debug, Clone, Copy)]
pub struct BoundsConfig {
    /// Hard ceiling on decompressed output, in bytes. Combined with
    /// `compression_ratio_limit` and the compressed input size to derive
    /// the effective cap via [`BoundsConfig::output_cap_for`].
    pub max_output_bytes: u64,
    /// Multiplier on compressed input size. The effective cap is
    /// `min(compression_ratio_limit × compressed, max_output_bytes)`.
    pub compression_ratio_limit: u64,
    /// Hard ceiling on entries iterated from a single archive.
    pub max_entries: usize,
    /// Whether nested archives may be opened. **Always `false`** in the
    /// helper-supplied default. The field exists so that a future,
    /// reviewed change has a single named knob to flip — it should not
    /// be flipped without an audit-trail-worthy justification.
    pub allow_nested: bool,
}

impl BoundsConfig {
    /// Default config for archive metadata extraction.
    ///
    /// `max_output_bytes = MAX_OUTPUT_BYTES` (10 MiB),
    /// `compression_ratio_limit = COMPRESSION_RATIO_LIMIT` (10×),
    /// `max_entries = MAX_ENTRIES` (1024),
    /// `allow_nested = false`.
    /// Format-specific callers MAY tighten any field but MUST NOT loosen it.
    #[must_use]
    pub const fn default_for_metadata_extraction() -> Self {
        Self {
            max_output_bytes: MAX_OUTPUT_BYTES,
            compression_ratio_limit: COMPRESSION_RATIO_LIMIT,
            max_entries: MAX_ENTRIES,
            allow_nested: false,
        }
    }

    /// Config for trusted, large bulk feeds.
    ///
    /// **Do NOT use this for untrusted or user-controlled archives.** This
    /// config is sized for full-ecosystem OSV advisory bulk archives fetched
    /// from `osv-vulnerabilities.storage.googleapis.com` over verified TLS —
    /// a source the operator trusts and that is separate from
    /// user-uploaded artifacts.
    ///
    /// `max_entries = MAX_ENTRIES_TRUSTED_BULK` (~1e5), large enough for any
    /// realistic OSV ecosystem zip. `max_output_bytes =
    /// MAX_OUTPUT_BYTES_TRUSTED_BULK` (2 GiB), sized for full-ecosystem
    /// decompression. `compression_ratio_limit = COMPRESSION_RATIO_LIMIT`
    /// (10×) unchanged — decompression-bomb protection still applies.
    /// `allow_nested = false` — OSV zips do not contain nested archives.
    ///
    /// Contrast with [`BoundsConfig::default_for_metadata_extraction`]: the
    /// metadata extraction caps (1024 entries, 10 MiB) MUST NOT be reused for
    /// bulk feeds — doing so silently drops all advisories beyond entry 1024
    /// (entire ecosystem ingests abort as `ParseError`).
    #[must_use]
    pub const fn for_trusted_bulk_feed() -> Self {
        Self {
            max_output_bytes: MAX_OUTPUT_BYTES_TRUSTED_BULK,
            compression_ratio_limit: COMPRESSION_RATIO_LIMIT,
            max_entries: MAX_ENTRIES_TRUSTED_BULK,
            allow_nested: false,
        }
    }

    /// Compute the effective decompressed-output cap for a given
    /// compressed input size.
    ///
    /// Returns `min(compression_ratio_limit × compressed_size,
    /// max_output_bytes)`. Saturating multiplication so a malicious
    /// 4 EiB compressed-size header can't wrap to a small cap.
    #[must_use]
    pub fn output_cap_for(&self, compressed_size: u64) -> u64 {
        compressed_size
            .saturating_mul(self.compression_ratio_limit)
            .min(self.max_output_bytes)
    }
}

/// Errors a bounded archive read may emit.
///
/// All variants represent a refusal to continue — none of them are
/// recoverable in the sense that "try again with a larger cap" is the
/// fix. A real legitimate metadata file does not trip these; tripping
/// any of them is a signal that the artifact is hostile or
/// pathologically large.
#[derive(Debug, thiserror::Error)]
pub enum BoundsError {
    /// Decompressed output exceeded the cap derived from
    /// [`BoundsConfig::output_cap_for`]. The reader stops yielding bytes
    /// at the cap; this error is returned on the very next `read()`
    /// call.
    #[error("decompressed output cap exceeded ({cap} bytes)")]
    OutputCapExceeded {
        /// The cap that was hit, in bytes.
        cap: u64,
    },
    /// Iterated past [`BoundsConfig::max_entries`] entries from a
    /// single archive.
    #[error("archive entry cap exceeded ({cap} entries)")]
    EntryCapExceeded {
        /// The entry-count cap that was hit.
        cap: usize,
    },
    /// Encountered a nested archive (e.g. `*.tar` inside a `*.tar.gz`)
    /// while [`BoundsConfig::allow_nested`] was `false`.
    #[error("nested archive rejected: {reason}")]
    NestedArchiveRejected {
        /// Format-specific description of what was detected — included
        /// in logs but not in user-facing errors. Avoid putting
        /// attacker-controlled bytes in here directly; use a fixed
        /// description like "tar entry name had archive extension".
        reason: &'static str,
    },
}

impl BoundsError {
    /// Convert to an [`io::Error`] for plumbing through `Read`-based
    /// pipelines. Uses [`io::ErrorKind::InvalidData`] — the input is
    /// syntactically refused, not an I/O failure.
    #[must_use]
    pub fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }
}

/// A `Read` wrapper that enforces a hard cap on the number of bytes
/// yielded.
///
/// Use this to wrap a decompressor (e.g. `flate2::read::GzDecoder`)
/// with a cap derived from [`BoundsConfig::output_cap_for`]. Once `cap`
/// bytes have been read, every subsequent `read()` returns an
/// [`io::Error`] of kind [`io::ErrorKind::InvalidData`] wrapping
/// [`BoundsError::OutputCapExceeded`].
///
/// **Why not `Read::take`?** `take(n)` returns `Ok(0)` (clean EOF) at
/// the cap, which a downstream tar / zip parser would interpret as a
/// truncated-but-valid stream rather than a refusal. The format
/// handler would silently emit a "partial metadata" event with whatever
/// fragment fit under the cap — exactly the bug `BoundedReader`
/// exists to prevent. We return an `Err` instead so the parser
/// propagates the failure.
///
/// Streaming guarantee: SHA-256 / hashing of the input still works,
/// because the wrapper doesn't buffer — it forwards each `read()` to
/// the inner reader and counts bytes as they pass.
pub struct BoundedReader<R: Read> {
    inner: R,
    cap: u64,
    consumed: u64,
}

impl<R: Read> BoundedReader<R> {
    /// Wrap `inner` with a `cap` on bytes yielded.
    #[must_use]
    pub fn new(inner: R, cap: u64) -> Self {
        Self {
            inner,
            cap,
            consumed: 0,
        }
    }

    /// Bytes yielded so far. Useful for telemetry / diagnostics; the
    /// invariant `consumed <= cap` always holds.
    #[must_use]
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// The cap configured at construction. Immutable.
    #[must_use]
    pub fn cap(&self) -> u64 {
        self.cap
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.consumed >= self.cap {
            return Err(BoundsError::OutputCapExceeded { cap: self.cap }.into_io());
        }
        // Cast cap-consumed (u64) to usize bounded by buf.len().
        // saturating_sub handles the (unreachable due to the guard
        // above) consumed > cap case defensively.
        let remaining = self.cap.saturating_sub(self.consumed);
        let limit = remaining.min(buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..limit])?;
        // u64 += usize cannot overflow because n <= limit <= remaining
        // <= cap <= u64::MAX.
        self.consumed += n as u64;
        Ok(n)
    }
}

/// Counts archive entries and trips after `max` entries have been
/// ticked.
///
/// Caller-driven: the iterator (e.g. `tar::Archive::entries()`) is
/// not aware of this counter. Callers MUST invoke
/// [`EntryCounter::tick`] before processing each entry; tick returns
/// [`BoundsError::EntryCapExceeded`] once the cap is hit.
pub struct EntryCounter {
    max: usize,
    seen: usize,
}

impl EntryCounter {
    /// Construct a counter that trips after `max` entries.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self { max, seen: 0 }
    }

    /// Increment the count. Returns [`BoundsError::EntryCapExceeded`]
    /// if the increment would exceed `max`.
    pub fn tick(&mut self) -> Result<(), BoundsError> {
        if self.seen >= self.max {
            return Err(BoundsError::EntryCapExceeded { cap: self.max });
        }
        self.seen += 1;
        Ok(())
    }

    /// Entries observed so far.
    #[must_use]
    pub fn seen(&self) -> usize {
        self.seen
    }
}

// ---------------------------------------------------------------------------
// ZIP iteration with bounds enforcement
// ---------------------------------------------------------------------------

/// Errors returned by [`iter_zip_entries`].
#[derive(Debug, thiserror::Error)]
pub enum ZipIterError {
    /// The reader could not be opened as a valid ZIP archive.
    #[error("zip open failed: {0}")]
    Open(zip::result::ZipError),
    /// Opening a specific archive entry by index failed.
    #[error("zip entry {index} failed: {source}")]
    Entry {
        index: usize,
        source: zip::result::ZipError,
    },
    /// Archive entry count exceeded [`BoundsConfig::max_entries`].
    #[error("{0}")]
    Bounds(BoundsError),
}

/// Open a ZIP archive from `reader` and call `visit(name, reader)` for
/// every file entry; directory entries are silently skipped.
///
/// Each entry's decompressed stream is wrapped in a [`BoundedReader`] with
/// a cap derived from [`BoundsConfig::output_cap_for`] applied to the
/// entry's compressed size.  The entry counter trips after
/// [`BoundsConfig::max_entries`] entries (counting all entries, including
/// directories).
///
/// The visitor receives `(name: &str, reader: &mut dyn Read)` and has no
/// return value — errors encountered while reading an entry should be handled
/// inside `visit` (e.g. skip on `is_err()`).  To abort early, use a shared
/// flag set inside the closure and checked by the caller after return.
///
/// # Security
///
/// - Entry count is bounded by [`BoundsConfig::max_entries`].
/// - Each entry's decompressed output is bounded by
///   [`BoundsConfig::output_cap_for`](compressed_size).
/// - Nested archive detection is the caller's responsibility: check
///   whether `name` ends with a known archive extension and return without
///   reading if [`BoundsConfig::allow_nested`] is `false`.
pub fn iter_zip_entries<R, F>(
    reader: R,
    config: BoundsConfig,
    mut visit: F,
) -> Result<(), ZipIterError>
where
    R: Read + Seek,
    F: FnMut(&str, &mut dyn Read),
{
    let mut archive = zip::ZipArchive::new(reader).map_err(ZipIterError::Open)?;
    let mut counter = EntryCounter::new(config.max_entries);
    for i in 0..archive.len() {
        counter.tick().map_err(ZipIterError::Bounds)?;
        let mut entry = archive.by_index(i).map_err(|e| ZipIterError::Entry {
            index: i,
            source: e,
        })?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        let cap = config.output_cap_for(entry.compressed_size());
        let mut bounded = BoundedReader::new(&mut entry, cap);
        visit(&name, &mut bounded);
    }
    Ok(())
}

/// Build a minimal ZIP archive in memory, for use in tests.
///
/// Available only with the `test-support` Cargo feature.  Each element of
/// `files` is `(entry_name, utf8_content)`; all entries are stored with
/// DEFLATE compression.
#[cfg(feature = "test-support")]
pub fn build_zip_bytes(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write as _;
    use zip::write::SimpleFileOptions;
    let mut buf: Vec<u8> = Vec::new();
    let cursor = io::Cursor::new(&mut buf);
    let mut zw = zip::ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in files {
        zw.start_file(*name, opts)
            .expect("build_zip_bytes: start_file");
        zw.write_all(body.as_bytes())
            .expect("build_zip_bytes: write_all");
    }
    zw.finish().expect("build_zip_bytes: finish");
    buf
}

// ---------------------------------------------------------------------------
// gzip-tar single-entry reading with bounds enforcement
// ---------------------------------------------------------------------------

/// Archive-file extensions that signal a nested archive. A tar entry whose
/// path ends with any of these is rejected (`allow_nested = false`) rather
/// than read, per [`BoundsError::NestedArchiveRejected`].
const NESTED_ARCHIVE_SUFFIXES: &[&str] = &[
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".zip", ".gz", ".bz2", ".xz",
];

/// Read a single matched entry from a gzip-tar (`.tgz` / `.crate`) archive
/// under the audited `archive_bounds` caps.
///
/// `input` is the **compressed** gzip-tar byte stream; `compressed_size` is
/// its length in bytes. gzip carries no reliable decompressed-size header,
/// so the compression-ratio bound needs the compressed length passed in
/// explicitly. The decompressor is wrapped in a [`BoundedReader`] with a cap
/// derived from [`BoundsConfig::output_cap_for`]`(compressed_size)`, exactly
/// as the module's *"How a future caller integrates a real archive crate"*
/// guide prescribes. Entries are iterated with an [`EntryCounter`]
/// (`tick` before each entry); any entry whose path names a nested archive is
/// rejected without reading it.
///
/// The first entry for which `want(path)` returns `true` has its bytes read
/// (in memory, never extracted to disk — no path-traversal surface) and
/// returned as `Ok(Some(bytes))`. If the scan completes without a match,
/// returns `Ok(None)`. Any bounds trip (output-cap / compression-ratio /
/// entry-count / nested-archive) or a malformed / non-gzip-tar archive
/// returns `Err(DomainError::Validation)` — never a silent `Ok`/`Ok(None)`.
///
/// # Note — the output cap is CUMULATIVE, not per-entry
///
/// `BoundedReader` wraps the *single* gzip stream, so its cap bounds the
/// **cumulative** decompressed bytes across the whole sequential tar scan,
/// not each entry independently. Reaching a tar entry means decompressing
/// everything physically before it, so a manifest ordered after more than
/// `output_cap_for(compressed_size)` decompressed bytes is **unreachable** —
/// the cap trips first and the read aborts (best-effort). This is acceptable
/// because npm and cargo place the manifest (`package/package.json`,
/// `<dir>/Cargo.toml`) as an early entry; **callers MUST rely on the
/// manifest being an early entry**, and test fixtures MUST place it early.
/// Zip is unaffected: [`iter_zip_entries`] reads the central directory and
/// seeks to the target, so it does not decompress the whole archive to reach
/// a late entry.
///
/// # Security
///
/// - Cumulative decompressed output is bounded by
///   [`BoundsConfig::output_cap_for`]`(compressed_size)`.
/// - Entry count is bounded by [`BoundsConfig::max_entries`].
/// - Nested archives are rejected (`allow_nested = false` in
///   [`BoundsConfig::default_for_metadata_extraction`]).
pub fn read_tar_gz_entry<R, F>(
    input: R,
    compressed_size: u64,
    config: BoundsConfig,
    mut want: F,
) -> hort_domain::error::DomainResult<Option<Vec<u8>>>
where
    R: Read,
    F: FnMut(&str) -> bool,
{
    use hort_domain::error::DomainError;

    let cap = config.output_cap_for(compressed_size);
    let bounded = BoundedReader::new(flate2::read::GzDecoder::new(input), cap);
    let mut archive = tar::Archive::new(bounded);
    let mut counter = EntryCounter::new(config.max_entries);

    let entries = archive
        .entries()
        .map_err(|e| DomainError::Validation(format!("expected gzip-tar archive: {e}")))?;

    for entry in entries {
        counter
            .tick()
            .map_err(|e| DomainError::Validation(e.to_string()))?;
        let mut entry = entry
            .map_err(|e| DomainError::Validation(format!("gzip-tar entry read failed: {e}")))?;

        let path = entry
            .path()
            .map_err(|e| DomainError::Validation(format!("gzip-tar entry path invalid: {e}")))?
            .to_string_lossy()
            .into_owned();

        // Nested-archive rejection (allow_nested is hard-false in the
        // metadata-extraction config). Detect by extension before reading.
        if !config.allow_nested && is_nested_archive_name(&path) {
            return Err(DomainError::Validation(
                BoundsError::NestedArchiveRejected {
                    reason: "tar entry name had archive extension",
                }
                .to_string(),
            ));
        }

        if want(&path) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| {
                DomainError::Validation(format!("gzip-tar entry decompression failed: {e}"))
            })?;
            return Ok(Some(buf));
        }
    }

    Ok(None)
}

/// Whether `name` ends with a known nested-archive extension (case-folded).
fn is_nested_archive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    NESTED_ARCHIVE_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ---- BoundsConfig ----------------------------------------------------

    #[test]
    fn default_config_matches_audit_thresholds() {
        let c = BoundsConfig::default_for_metadata_extraction();
        assert_eq!(c.max_output_bytes, MAX_OUTPUT_BYTES);
        assert_eq!(c.compression_ratio_limit, COMPRESSION_RATIO_LIMIT);
        assert_eq!(c.max_entries, MAX_ENTRIES);
        assert!(!c.allow_nested);
    }

    #[test]
    fn output_cap_clamps_to_compression_ratio_for_small_input() {
        let c = BoundsConfig::default_for_metadata_extraction();
        // 1 KiB compressed × 10 = 10 KiB, well under the 10 MiB ceiling.
        assert_eq!(c.output_cap_for(1024), 10_240);
    }

    #[test]
    fn output_cap_clamps_to_ceiling_for_large_input() {
        let c = BoundsConfig::default_for_metadata_extraction();
        // 100 MiB compressed × 10 = 1 GiB, but the ceiling is 10 MiB.
        let big = 100 * 1024 * 1024;
        assert_eq!(c.output_cap_for(big), MAX_OUTPUT_BYTES);
    }

    #[test]
    fn output_cap_saturates_on_multiplication_overflow() {
        let c = BoundsConfig::default_for_metadata_extraction();
        // u64::MAX × 10 would wrap; saturating_mul plus the .min()
        // gives MAX_OUTPUT_BYTES. Defends against a malicious header
        // that claims compressed_size = u64::MAX / 2.
        assert_eq!(c.output_cap_for(u64::MAX), MAX_OUTPUT_BYTES);
    }

    // ---- BoundedReader ---------------------------------------------------

    #[test]
    fn bounded_reader_passes_data_under_cap() {
        let data = b"hello world";
        let mut r = BoundedReader::new(Cursor::new(data), 100);
        let mut buf = Vec::new();
        let n = r.read_to_end(&mut buf).expect("read under cap");
        assert_eq!(n, data.len());
        assert_eq!(buf.as_slice(), data);
        assert_eq!(r.consumed(), data.len() as u64);
        assert_eq!(r.cap(), 100);
    }

    #[test]
    fn bounded_reader_yields_exactly_cap_bytes_then_errors() {
        // Stream of 100 'A' bytes; cap at 10. The first read should
        // return at most 10 bytes; the next read must error.
        let data = vec![b'A'; 100];
        let mut r = BoundedReader::new(Cursor::new(data), 10);
        let mut buf = [0u8; 64];
        let mut total = 0;
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) => {
                    // Cap-exceeded error reaches us once consumed == cap.
                    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                    assert!(format!("{e}").contains("cap exceeded"));
                    break;
                }
            }
        }
        assert_eq!(total, 10);
        assert_eq!(r.consumed(), 10);
    }

    #[test]
    fn bounded_reader_simulated_zip_bomb_ratio_fails_before_oom() {
        // Simulate a 1 KiB compressed input that "decompresses" to
        // 100 KiB of zeros (a 100× ratio — well over the 10× legit
        // threshold). With output_cap_for(1024) = 10_240, the wrapper
        // must error before the full 100 KiB is read.
        let compressed_size: u64 = 1024;
        let decompressed = vec![0u8; 100 * 1024];
        let cfg = BoundsConfig::default_for_metadata_extraction();
        let cap = cfg.output_cap_for(compressed_size);
        assert_eq!(cap, 10 * 1024);

        let mut r = BoundedReader::new(Cursor::new(decompressed), cap);
        let mut sink = Vec::new();
        let res = r.read_to_end(&mut sink);
        assert!(res.is_err(), "expected zip-bomb-ratio read to fail");
        assert_eq!(r.consumed(), cap);
        // We got cap bytes through before the wrapper refused — i.e.
        // 10 KiB of zeros, not the 100 KiB the attacker wanted to
        // expand to.
        assert_eq!(sink.len() as u64, cap);
    }

    #[test]
    fn bounded_reader_zero_cap_errors_immediately() {
        let mut r = BoundedReader::new(Cursor::new(b"any"), 0);
        let mut buf = [0u8; 8];
        let res = r.read(&mut buf);
        assert!(res.is_err(), "zero-cap read must error on first call");
    }

    // ---- EntryCounter ----------------------------------------------------

    #[test]
    fn entry_counter_allows_up_to_max() {
        let mut c = EntryCounter::new(3);
        assert!(c.tick().is_ok());
        assert!(c.tick().is_ok());
        assert!(c.tick().is_ok());
        assert_eq!(c.seen(), 3);
    }

    #[test]
    fn entry_counter_trips_on_overflow() {
        let mut c = EntryCounter::new(2);
        c.tick().expect("1st");
        c.tick().expect("2nd");
        let err = c.tick().expect_err("3rd must trip");
        match err {
            BoundsError::EntryCapExceeded { cap } => assert_eq!(cap, 2),
            _ => panic!("expected EntryCapExceeded, got {err:?}"),
        }
    }

    #[test]
    fn entry_counter_zero_max_trips_on_first_tick() {
        let mut c = EntryCounter::new(0);
        let err = c.tick().expect_err("zero-max counter must trip");
        match err {
            BoundsError::EntryCapExceeded { cap } => assert_eq!(cap, 0),
            _ => panic!("expected EntryCapExceeded"),
        }
    }

    // ---- BoundsError -----------------------------------------------------

    #[test]
    fn bounds_error_into_io_uses_invalid_data() {
        let e = BoundsError::OutputCapExceeded { cap: 42 };
        let io_err = e.into_io();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bounds_error_nested_archive_carries_reason() {
        let e = BoundsError::NestedArchiveRejected {
            reason: "tar entry name had archive extension",
        };
        let s = format!("{e}");
        assert!(s.contains("tar entry name had archive extension"));
    }

    #[test]
    fn bounds_error_entry_cap_exceeded_displays_cap() {
        let e = BoundsError::EntryCapExceeded { cap: 1024 };
        let s = format!("{e}");
        assert!(s.contains("1024"));
    }

    // ---- iter_zip_entries ---------------------------------------------------

    fn make_zip(files: &[(&str, &[u8])]) -> Cursor<Vec<u8>> {
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;
        let mut buf: Vec<u8> = Vec::new();
        let cursor = Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in files {
            zw.start_file(*name, opts).expect("start_file");
            zw.write_all(body).expect("write_all");
        }
        zw.finish().expect("finish");
        Cursor::new(buf)
    }

    #[test]
    fn iter_zip_entries_visits_all_files() {
        let zip = make_zip(&[("a.json", b"aaa"), ("b.json", b"bbb")]);
        let mut names: Vec<String> = Vec::new();
        iter_zip_entries(
            zip,
            BoundsConfig::default_for_metadata_extraction(),
            |name, _r| {
                names.push(name.to_string());
            },
        )
        .expect("no error");
        assert_eq!(names, vec!["a.json", "b.json"]);
    }

    #[test]
    fn iter_zip_entries_skips_directory_entries() {
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts = SimpleFileOptions::default();
            zw.add_directory("dir/", opts).expect("add_directory");
            zw.start_file("dir/file.json", opts).expect("start_file");
            zw.write_all(b"{}").expect("write_all");
            zw.finish().expect("finish");
        }
        let mut names: Vec<String> = Vec::new();
        iter_zip_entries(
            Cursor::new(buf),
            BoundsConfig::default_for_metadata_extraction(),
            |name, _r| {
                names.push(name.to_string());
            },
        )
        .expect("no error");
        assert_eq!(names, vec!["dir/file.json"]);
    }

    #[test]
    fn iter_zip_entries_entry_cap_trips() {
        let zip = make_zip(&[("a.json", b"a"), ("b.json", b"b"), ("c.json", b"c")]);
        let cfg = BoundsConfig {
            max_entries: 2,
            ..BoundsConfig::default_for_metadata_extraction()
        };
        let err = iter_zip_entries(zip, cfg, |_, _| {}).expect_err("cap must trip");
        match err {
            ZipIterError::Bounds(BoundsError::EntryCapExceeded { cap }) => {
                assert_eq!(cap, 2);
            }
            other => panic!("expected Bounds(EntryCapExceeded), got {other:?}"),
        }
    }

    /// Governance regression test: bounds-tripped on the **metadata-extraction**
    /// config must always be `Err(ZipIterError::Bounds(_))` — NOT `Ok(...)`.
    /// This pins the fail-safe-by-construction property so a future change
    /// cannot silently re-weaken the contract.
    #[test]
    fn iter_zip_entries_metadata_config_bounds_trip_is_err_not_ok() {
        // Build a zip with 3 entries but cap at 2 via `default_for_metadata_extraction`
        // override — callers using the metadata config must receive Err on bounds trip,
        // not Ok, so they cannot accidentally proceed with a truncated untrusted archive.
        let zip = make_zip(&[("a.json", b"a"), ("b.json", b"b"), ("c.json", b"c")]);
        let cfg = BoundsConfig {
            max_entries: 2,
            ..BoundsConfig::default_for_metadata_extraction()
        };
        let result = iter_zip_entries(zip, cfg, |_, _| {});
        assert!(
            result.is_err(),
            "bounds trip on metadata config must be Err, not Ok — \
             fail-safe-by-construction must hold"
        );
        assert!(
            matches!(result, Err(ZipIterError::Bounds(_))),
            "expected Err(Bounds(_)), got {result:?}"
        );
    }

    #[test]
    fn iter_zip_entries_trusted_bulk_config_completes_all_for_large_archive() {
        // Verify that for_trusted_bulk_feed() allows >1024 entries without
        // tripping. With the restored original contract, Ok(()) means all entries visited.
        let n: usize = 1030;
        let files: Vec<(String, Vec<u8>)> = (0..n)
            .map(|i| {
                (
                    format!("advisory-{i:04}.json"),
                    format!("{{\"id\":{i}}}").into_bytes(),
                )
            })
            .collect();
        let file_refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, body)| (name.as_str(), body.as_slice()))
            .collect();
        let zip = make_zip(&file_refs);
        let mut count = 0usize;
        iter_zip_entries(zip, BoundsConfig::for_trusted_bulk_feed(), |_, _| {
            count += 1;
        })
        .expect("trusted bulk config must not error for 1030-entry archive");
        assert_eq!(count, n, "all {n} entries must be visited");
    }

    #[test]
    fn iter_zip_entries_reader_enforces_output_cap() {
        // Build a zip whose entries are large enough that the 1× ratio cap
        // triggers when we try to read them through the bounded reader.
        // Use a very tight config: ratio=1 so cap = compressed_size.
        // The entry is 100 bytes uncompressed; deflate won't expand it so
        // compressed_size ≈ 100. We read up to that limit via read_to_end.
        // This test just verifies the bounded reader is in the pipeline —
        // a cap of 10 on 100-byte content should produce an error when
        // the visitor tries to read the full content.
        let payload = vec![0u8; 200]; // 200 bytes, mostly zeros — compresses well
        let zip = make_zip(&[("big.json", &payload)]);
        let cfg = BoundsConfig {
            max_output_bytes: 10,
            compression_ratio_limit: 1,
            ..BoundsConfig::default_for_metadata_extraction()
        };
        let mut read_error = false;
        iter_zip_entries(zip, cfg, |_, reader| {
            let mut buf = Vec::new();
            if reader.read_to_end(&mut buf).is_err() {
                read_error = true;
            }
        })
        .expect("iter itself succeeds; read error is inside visitor");
        assert!(
            read_error,
            "output-cap-exceeded error must reach the visitor"
        );
    }

    #[test]
    fn iter_zip_entries_errors_on_invalid_zip() {
        let garbage = Cursor::new(b"not a zip".to_vec());
        let err = iter_zip_entries(
            garbage,
            BoundsConfig::default_for_metadata_extraction(),
            |_, _| {},
        )
        .expect_err("invalid zip must Err");
        assert!(
            matches!(err, ZipIterError::Open(_)),
            "expected Open variant, got {err:?}"
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn build_zip_bytes_roundtrips_through_iter() {
        let zip_bytes = build_zip_bytes(&[("hello.txt", "world"), ("data.json", "{}")]);
        let mut names: Vec<String> = Vec::new();
        iter_zip_entries(
            Cursor::new(zip_bytes),
            BoundsConfig::default_for_metadata_extraction(),
            |name, _| {
                names.push(name.to_string());
            },
        )
        .expect("roundtrip");
        assert_eq!(names, vec!["hello.txt", "data.json"]);
    }

    // ---- read_tar_gz_entry --------------------------------------------------

    /// Build a gzip-tar (`.tgz`) archive in memory from `(name, body)`
    /// pairs. Mirrors `make_zip` for the tar/gzip path.
    fn make_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header
                .set_path(name)
                .expect("make_tar_gz: set_path on header");
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append(&header, *body)
                .expect("make_tar_gz: append entry");
        }
        let gz = builder.into_inner().expect("make_tar_gz: finish tar");
        gz.finish().expect("make_tar_gz: finish gzip")
    }

    #[test]
    fn read_tar_gz_entry_finds_matched_entry() {
        let archive = make_tar_gz(&[
            ("package/package.json", br#"{"name":"x"}"#),
            ("package/README.md", b"hello"),
        ]);
        let compressed_len = archive.len() as u64;
        let got = read_tar_gz_entry(
            Cursor::new(archive),
            compressed_len,
            BoundsConfig::default_for_metadata_extraction(),
            |name| name == "package/package.json",
        )
        .expect("read must succeed")
        .expect("entry must be present");
        assert_eq!(got, br#"{"name":"x"}"#);
    }

    #[test]
    fn read_tar_gz_entry_returns_none_when_absent() {
        // An incompressible (LCG-pseudorandom) body keeps the compressed
        // size ~= the decompressed size, so output_cap_for(compressed) =
        // 10× comfortably exceeds the decompressed tar's content + fixed
        // 512-byte-block overhead — the scan completes and reports a clean
        // Ok(None). (A small or compressible fixture would trip the
        // cumulative cap on tar block padding; real npm/cargo archives are
        // never that small.)
        let body: Vec<u8> = {
            let mut state: u32 = 0x1234_5678;
            (0..4096)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> 24) as u8
                })
                .collect()
        };
        let archive = make_tar_gz(&[("package/README.md", &body)]);
        let compressed_len = archive.len() as u64;
        let got = read_tar_gz_entry(
            Cursor::new(archive),
            compressed_len,
            BoundsConfig::default_for_metadata_extraction(),
            |name| name == "package/package.json",
        )
        .expect("read must succeed");
        assert!(
            got.is_none(),
            "absent entry must yield Ok(None), got {got:?}"
        );
    }

    /// Governance regression test (mirrors
    /// `iter_zip_entries_metadata_config_bounds_trip_is_err_not_ok`):
    /// an **output-size / compression-ratio trip** on the metadata-extraction
    /// config must be `Err`, never a silent `Ok`/`Ok(None)`. The target
    /// entry decompresses to far more than `output_cap_for(compressed_size)`
    /// allows.
    #[test]
    fn read_tar_gz_entry_output_cap_trip_is_err_not_ok() {
        // A 1 MiB run of zeros compresses to a tiny gzip stream, so the
        // cumulative decompressed size massively exceeds
        // output_cap_for(compressed_size) = 10 × compressed.
        let big = vec![0u8; 1024 * 1024];
        let archive = make_tar_gz(&[("package/package.json", &big)]);
        let compressed_len = archive.len() as u64;
        let result = read_tar_gz_entry(
            Cursor::new(archive),
            compressed_len,
            BoundsConfig::default_for_metadata_extraction(),
            |name| name == "package/package.json",
        );
        assert!(
            result.is_err(),
            "output-cap trip on metadata config must be Err, not Ok — \
             fail-safe-by-construction must hold; got {result:?}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("output cap exceeded"),
            "expected an output/compression-ratio trip, got: {msg}"
        );
    }

    /// Governance regression test: an **entry-count trip** before the
    /// target entry must be `Err`, never a silent `Ok(None)`. More than
    /// `max_entries` entries precede the target.
    #[test]
    fn read_tar_gz_entry_entry_cap_trip_is_err_not_ok() {
        // Build an archive with several entries, then the target, and clamp
        // max_entries below the target's position. The filler bodies are
        // incompressible so the *output* cap stays generous (compressed
        // size is large) and the failure is unambiguously the *entry-count*
        // trip, not a coincidental output-cap trip.
        let filler: Vec<u8> = {
            let mut state: u32 = 0xA5A5_5A5A;
            (0..1024)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> 24) as u8
                })
                .collect()
        };
        let archive = make_tar_gz(&[
            ("filler-0", &filler),
            ("filler-1", &filler),
            ("filler-2", &filler),
            ("package/package.json", br#"{"name":"x"}"#),
        ]);
        let compressed_len = archive.len() as u64;
        let cfg = BoundsConfig {
            max_entries: 2,
            ..BoundsConfig::default_for_metadata_extraction()
        };
        let result = read_tar_gz_entry(Cursor::new(archive), compressed_len, cfg, |name| {
            name == "package/package.json"
        });
        assert!(
            result.is_err(),
            "entry-cap trip before the target must be Err, not Ok(None) — \
             fail-safe-by-construction must hold; got {result:?}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("entry cap exceeded"),
            "expected an entry-count trip, got: {msg}"
        );
    }

    #[test]
    fn read_tar_gz_entry_rejects_nested_archive() {
        // An entry whose name has an archive extension must be rejected
        // (allow_nested = false), not read.
        let archive = make_tar_gz(&[("package/inner.tar.gz", b"\x1f\x8bnested")]);
        let compressed_len = archive.len() as u64;
        let result = read_tar_gz_entry(
            Cursor::new(archive),
            compressed_len,
            BoundsConfig::default_for_metadata_extraction(),
            |name| name == "package/inner.tar.gz",
        );
        assert!(
            result.is_err(),
            "nested archive entry must be Err, not silently read; got {result:?}"
        );
    }

    #[test]
    fn is_nested_archive_name_matches_known_extensions_case_insensitively() {
        assert!(is_nested_archive_name("package/inner.tar.gz"));
        assert!(is_nested_archive_name("X.TGZ"));
        assert!(is_nested_archive_name("a/b.ZIP"));
        assert!(is_nested_archive_name("data.tar.bz2"));
        assert!(is_nested_archive_name("x.xz"));
        // Negatives: ordinary manifest / text entries are not archives.
        assert!(!is_nested_archive_name("package/package.json"));
        assert!(!is_nested_archive_name("Cargo.toml"));
        assert!(!is_nested_archive_name("README.md"));
        assert!(!is_nested_archive_name("gzip-notes.txt"));
    }

    #[test]
    fn read_tar_gz_entry_errors_on_non_gzip_input() {
        // Container-mismatch: plain bytes are not gzip-tar.
        let garbage = b"not a gzip-tar archive".to_vec();
        let compressed_len = garbage.len() as u64;
        let result = read_tar_gz_entry(
            Cursor::new(garbage),
            compressed_len,
            BoundsConfig::default_for_metadata_extraction(),
            |_| true,
        );
        assert!(
            result.is_err(),
            "non-gzip input must Err (container mismatch); got {result:?}"
        );
    }
}
