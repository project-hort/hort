//! Cross-crate test fixtures for archive construction.
//!
//! Available only with the `test-support` Cargo feature (or under
//! `#[cfg(test)]` inside this crate). Centralises the in-memory ZIP
//! builders so downstream test consumers (`hort-http-pypi`, future format
//! crates) do not need to depend on `zip` directly — `deny.toml`'s
//! `[bans] wrappers = ["hort-formats"]` rule for the `zip` crate is
//! enforced at the dep-tree level, so the only way to keep that rule
//! green while still building wheel ZIPs for tests is to tunnel through
//! this module. Archive extractors must route through
//! `hort-formats::archive_bounds` to prevent zip-bomb attacks.
//!
//! The sibling `archive_bounds::build_zip_bytes` takes `&str` bodies
//! and is the lowest-friction option for OSV-style JSON fixtures
//! (`hort-adapters-advisory-osv`). [`build_wheel_zip`] takes `&[u8]`
//! bodies — needed for the PyPI wheel-metadata test surface where one
//! fixture is 1 MiB+1 of zeros (oversized-METADATA cap test) and the
//! happy-path body is a binary METADATA blob.

use std::io::Cursor;
use std::io::Write as _;

use zip::write::SimpleFileOptions;

/// Hand-craft a minimal ZIP archive in memory from `(entry_name, body)`
/// pairs. Each entry is stored with DEFLATE compression. Returns the
/// full archive bytes ready to hand to any reader (`zip::ZipArchive`,
/// `hort-formats::archive_bounds::iter_zip_entries`, the in-process
/// wheel-metadata extractor, etc.).
///
/// Bodies are `&[u8]` (not `&str`) because the PyPI wheel-metadata
/// fixtures include both binary METADATA blobs and a deliberately
/// oversized 1 MiB+1 zero-fill that does not represent text. For
/// UTF-8 fixtures see [`crate::archive_bounds::build_zip_bytes`].
pub fn build_wheel_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor = Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in files {
            zw.start_file(*name, opts)
                .expect("build_wheel_zip: start_file");
            zw.write_all(body).expect("build_wheel_zip: write_all");
        }
        zw.finish().expect("build_wheel_zip: finish");
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_wheel_zip_round_trips_through_zip_archive() {
        let bytes = build_wheel_zip(&[
            (
                "example-1.0.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\n",
            ),
            ("example/__init__.py", b""),
        ]);
        // Sanity: header + central directory present (a non-empty
        // archive is well above the empty-EOCD threshold of 22 bytes).
        assert!(bytes.len() > 22, "archive is suspiciously small");
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).expect("re-open built archive");
        assert_eq!(archive.len(), 2);
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_owned())
            .collect();
        assert!(names
            .iter()
            .any(|n| n == "example-1.0.0.dist-info/METADATA"));
        assert!(names.iter().any(|n| n == "example/__init__.py"));
    }

    #[test]
    fn build_wheel_zip_accepts_binary_bodies() {
        // 1 MiB+1 zero-fill, the oversized-METADATA fixture shape.
        let big = vec![0u8; (1 << 20) + 1];
        let bytes = build_wheel_zip(&[("dist-info/METADATA", big.as_slice())]);
        let archive = zip::ZipArchive::new(Cursor::new(&bytes)).expect("re-open built archive");
        assert_eq!(archive.len(), 1);
    }
}
