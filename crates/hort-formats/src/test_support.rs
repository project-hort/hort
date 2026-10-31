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
//!
//! [`build_tar_gz_bytes`] is the gzip-tar counterpart, for npm `.tgz` and
//! cargo `.crate` fixtures, with [`build_npm_tarball`] /
//! [`build_cargo_crate`] on top of it for the common case: a real archive
//! whose manifest declares a given name and version. Those two exist
//! because the hosted publish paths now read the identity an archive
//! declares about itself and refuse a disagreement, so a publish fixture
//! carrying opaque bytes is a fixture of the refusal path.
//! [`build_maven_pom`] / [`build_maven_jar`] are the Maven equivalents.

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

/// Hand-craft a minimal gzip-tar archive in memory from
/// `(entry_name, body)` pairs — the shape npm `.tgz` and cargo `.crate`
/// publishes carry.
///
/// Entries appear in the given order, which is load-bearing for fixtures:
/// `archive_bounds::read_tar_gz_entry` bounds the *cumulative* decompressed
/// output across a sequential scan, so a manifest placed after megabytes of
/// other entries is unreachable. Put the manifest first, as `npm pack` and
/// `cargo package` do.
///
/// Lives here rather than in each consumer because `tar` / `flate2` are
/// `deny.toml`-locked to `hort-formats` (`[bans] wrappers`), so this module
/// is the only cross-crate tunnel for building one in a test.
pub fn build_tar_gz_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_bytes: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, *name, *body)
                .expect("build_tar_gz_bytes: append_data");
        }
        builder.finish().expect("build_tar_gz_bytes: finish");
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&tar_bytes)
        .expect("build_tar_gz_bytes: gzip write");
    encoder.finish().expect("build_tar_gz_bytes: gzip finish")
}

/// A minimal npm publish tarball whose `package/package.json` declares
/// `name` and `version`.
///
/// This is the fixture shape every npm publish test needs now that the
/// publish path reads the tarball's own declaration of its identity: a
/// publish body carrying opaque bytes is a publish the server refuses,
/// which is the whole point of the check. Pass a `name`/`version` that
/// differ from the ones the request is made under to build the
/// divergence case.
pub fn build_npm_tarball(name: &str, version: &str) -> Vec<u8> {
    let manifest = serde_json::json!({ "name": name, "version": version }).to_string();
    build_tar_gz_bytes(&[
        ("package/package.json", manifest.as_bytes()),
        ("package/index.js", b"module.exports = {};"),
    ])
}

/// A minimal cargo `.crate` whose archive-root `Cargo.toml` declares
/// `[package] name` / `version`.
///
/// `dir` is the single top-level directory segment. `cargo package` always
/// writes `{name}-{version}`, but the segment's *name* is not what the
/// identity check reads — the manifest inside it is — so a fixture can set
/// the two independently to prove which one the check stands on.
pub fn build_cargo_crate(dir: &str, name: &str, version: &str) -> Vec<u8> {
    let manifest =
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n");
    build_tar_gz_bytes(&[
        (&format!("{dir}/Cargo.toml"), manifest.as_bytes()),
        (&format!("{dir}/src/lib.rs"), b"pub fn f() {}"),
    ])
}

/// A minimal Maven POM document declaring `groupId` / `artifactId` /
/// `version`.
pub fn build_maven_pom(group_id: &str, artifact_id: &str, version: &str) -> Vec<u8> {
    format!(
        "<project>\
           <modelVersion>4.0.0</modelVersion>\
           <groupId>{group_id}</groupId>\
           <artifactId>{artifact_id}</artifactId>\
           <version>{version}</version>\
         </project>"
    )
    .into_bytes()
}

/// A minimal Java archive carrying one `maven-archiver`-shaped build
/// descriptor at `META-INF/maven/{group_id}/{artifact_id}/pom.properties`.
///
/// Note the internal convention: inside the jar the groupId stays a single
/// dotted segment, unlike the slash-expanded repository layout path.
pub fn build_maven_jar(group_id: &str, artifact_id: &str, version: &str) -> Vec<u8> {
    let descriptor = format!(
        "#Generated by Maven\ngroupId={group_id}\nartifactId={artifact_id}\nversion={version}\n"
    );
    build_wheel_zip(&[
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        (
            &format!("META-INF/maven/{group_id}/{artifact_id}/pom.properties"),
            descriptor.as_bytes(),
        ),
    ])
}

/// A Java archive with no `META-INF/maven/**` descriptor at all — what a
/// Gradle, Bazel, sbt or `addMavenDescriptor=false` build produces.
pub fn build_maven_jar_without_descriptor() -> Vec<u8> {
    build_wheel_zip(&[
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ("com/example/App.class", b"\xca\xfe\xba\xbe"),
    ])
}

/// An artifact row carrying nothing but a `path`, for exercising
/// [`FormatHandler::scan_kind`](hort_domain::ports::format_handler::FormatHandler::scan_kind).
///
/// Every handler's classification reads the stored path and nothing else
/// (an OCI blob's `content_type` is `application/octet-stream` whatever
/// role the manifest assigns it, so it carries no signal), which is why
/// one fixture serves all of them. Centralised here so five handler test
/// modules plus the cross-format classification guard do not each carry a
/// copy of the struct literal.
pub fn artifact_row_at(path: &str) -> hort_domain::entities::artifact::Artifact {
    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    Artifact {
        // `Default::default()` rather than a named `Uuid` — hort-formats
        // has no direct `uuid` dependency to name the type with.
        id: Default::default(),
        repository_id: Default::default(),
        name: "fixture".into(),
        name_as_published: "fixture".into(),
        version: Some("1.0.0".into()),
        path: path.into(),
        size_bytes: 1,
        sha256_checksum: "a".repeat(64).parse().expect("64 hex chars parse"),
        sha1_checksum: None,
        md5_checksum: None,
        content_type: "application/octet-stream".into(),
        quarantine_status: QuarantineStatus::Quarantined,
        rejection_reason: None,
        quarantine_window_start: None,
        quarantine_deadline: None,
        provenance_hold_indefinite: false,
        upstream_published_at: None,
        uploaded_by: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        deleted_at: None,
    }
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
            .map(|i| {
                archive
                    .by_index(i)
                    .unwrap()
                    .name()
                    .expect("built archive names are ASCII, so they decode")
                    .into_owned()
            })
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
