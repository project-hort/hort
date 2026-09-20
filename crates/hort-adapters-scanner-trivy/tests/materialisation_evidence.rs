//! Evidence tests — a **real** `trivy` binary, one case per artifact
//! kind, proving the materialisation actually reaches the analyzers.
//!
//! # Why these exist and why they need a real binary
//!
//! Every other test in this crate can assert what the adapter *does*:
//! which file name it writes, which subcommand it picks, which archives
//! it refuses. None of them can assert the thing that matters — that
//! Trivy's analyzers then claim the result. That is a fact about Trivy's
//! analyzer selection, not about this code, and the only way to establish
//! it is to run the scanner. The bug these tests close was invisible for
//! exactly that reason: the adapter wrote a well-formed file, Trivy
//! returned a well-formed empty report, and every unit test passed.
//!
//! # Running them
//!
//! Gated on `TRIVY_BIN` pointing at a `trivy` executable, mirroring
//! `tests/timeout.rs`'s fake-binary pattern in reverse. Without it every
//! test here **self-skips** (returns early, reported as passed), so the
//! ordinary `cargo test --workspace` gate stays green on a host with no
//! scanner installed.
//!
//! ```text
//! TRIVY_BIN=$(command -v trivy) \
//!   cargo test -p hort-adapters-scanner-trivy --test materialisation_evidence
//! ```
//!
//! The vulnerability-detection cases additionally need Trivy's databases.
//! Trivy downloads the vulnerability DB on first use, and `trivy-java-db`
//! when it meets a JAR its embedded `pom.properties` / `MANIFEST.MF` do
//! not identify — the fixture here carries `pom.properties`, so that
//! second download should not be needed. Either way the host needs
//! network access or a warm, **writable** `--cache-dir`. Set
//! `TRIVY_CACHE_DIR` to point the adapter at a pre-populated cache on an
//! air-gapped host. A DB-less run surfaces as a scan error, which these
//! tests report as a failure with Trivy's own message rather than
//! silently passing.
//!
//! # What each case pins
//!
//! The target column is the adapter's own choice, derived from the kind
//! — these tests exercise it rather than set it, which is the point: a
//! post-build artifact scanned under `fs` runs no analyzer at all, and
//! the finding assertions below are what catches that.
//!
//! | kind      | fixture                                          | target   | asserted |
//! |-----------|--------------------------------------------------|----------|----------|
//! | `MavenJar`| JAR with `log4j-core 2.14.1` maven coordinates    | `rootfs` | `CVE-2021-44228` |
//! | `PyWheel` | wheel with `urllib3 1.26.4` `dist-info/METADATA`  | `rootfs` | ≥ 1 finding |
//! | `OciBlob` | layer tar with a vulnerable `var/lib/dpkg/status`| `rootfs` | ≥ 1 finding |
//! | `MavenPom`| a POM naming a vulnerable dependency             | `fs`     | analysed |
//! | `NpmTarball` | a tarball naming itself `lodash 4.17.20`      | `rootfs` | a `lodash@4.17.20` finding |
//! | `CargoCrate` | a `.crate` whose `Cargo.lock` pins `smallvec 1.6.0` | `fs` | a `smallvec` finding |
//! | `NpmTarball` | a manifest-only tarball                       | `rootfs` | analysed, no findings |
//! | `CargoCrate` | a lockfile-less `.crate`                      | `fs`     | analysed, no findings |
//! | `OciBlob` | a CA-certificate-only layer, no package database | `rootfs` | `NotApplicable` |
//!
//! Together these are the evidence behind every "yes" in the scanner
//! capability map's `trivy` row — the rule being that a cell is "yes"
//! only where a known-vulnerable fixture of that format yields at least
//! one finding through this adapter.
//!
//! The two paired `NpmTarball` / `CargoCrate` rows say what each "yes"
//! covers, which is not the same for both halves. For npm it is the
//! package's **own identity**: the tarball names itself, so its own
//! advisories are attributable, while the dependency *ranges* its
//! `package.json` declares are not. For cargo it is the opposite — the
//! lockfile pins exact dependency versions, and a `.crate` without one
//! carries nothing to match. Asserting *zero* findings in the second
//! row of each pair documents that ceiling rather than pretending to
//! coverage; if a future Trivy release starts attributing advisories to
//! `package.json` ranges, that test failing is the signal to revisit the
//! map, not a defect. The CA-certificate-layer row is a different
//! outcome again: no package identity at all, which every analyzer
//! agrees on, so it must come back `NotApplicable` rather than held.
//!
//! # Fixtures are built here, not committed
//!
//! Each archive is assembled in-process from its declared bytes. A
//! committed binary fixture would be unreviewable — a reader could not
//! tell a `pom.properties` naming log4j 2.14.1 from one naming 2.17.1 —
//! and the whole value of these tests is that the coordinates Trivy reads
//! are visible in the source.

#![cfg(unix)]

use std::io::{Cursor, Write as _};
use std::path::PathBuf;
use std::sync::Arc;

use hort_adapters_scanner_trivy::{TrivyAdapter, TrivyConfig};
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scanner::{NotAnalysable, ScanAnalysis, ScanTarget, ScannerPort};
use hort_domain::ports::storage::{PutResult, StoragePort};
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ArtifactCoords, ArtifactKind, ByteRange, ContentHash, Finding};
use tokio::io::AsyncRead;

/// The `trivy` binary under test, or `None` to skip.
fn trivy_bin() -> Option<PathBuf> {
    let raw = std::env::var("TRIVY_BIN").ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(raw))
}

/// Storage returning a fixed payload — the artifact bytes under test.
struct FixtureStorage {
    bytes: Vec<u8>,
}

impl StoragePort for FixtureStorage {
    fn put(&self, _s: Box<dyn AsyncRead + Send + Unpin>) -> BoxFuture<'_, DomainResult<PutResult>> {
        Box::pin(async { unreachable!("evidence tests never write") })
    }
    fn get(
        &self,
        _h: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        let cursor = Cursor::new(self.bytes.clone());
        Box::pin(async move {
            let r: Box<dyn AsyncRead + Send + Unpin> = Box::new(cursor);
            Ok(r)
        })
    }
    fn get_range(
        &self,
        _h: &ContentHash,
        _r: ByteRange,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        Box::pin(async { unreachable!() })
    }
    fn exists(&self, _h: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
        Box::pin(async { unreachable!() })
    }
    fn size_of(&self, _h: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
        Box::pin(async { unreachable!() })
    }
}

fn placeholder_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .expect("64 hex chars parse")
}

fn coords(
    name: &str,
    version: Option<&str>,
    path: &str,
    format: RepositoryFormat,
) -> ArtifactCoords {
    ArtifactCoords {
        name: name.to_string(),
        name_as_published: name.to_string(),
        version: version.map(str::to_string),
        path: path.to_string(),
        format,
        metadata: serde_json::Value::Null,
    }
}

/// Run the real `trivy` against `bytes` materialised as `kind`.
///
/// Returns `None` when `TRIVY_BIN` is unset, so each test can self-skip.
async fn scan_fixture(
    kind: ArtifactKind,
    coords: &ArtifactCoords,
    bytes: Vec<u8>,
) -> Option<DomainResult<ScanAnalysis>> {
    let bin = trivy_bin()?;
    let config = TrivyConfig {
        trivy_bin: bin,
        // A real DB download on a cold cache can take a while; the
        // adapter's own default (5 min) is the same bound production
        // uses, so keep it rather than inventing a test-only value.
        db_dir: std::env::var("TRIVY_CACHE_DIR").ok().map(PathBuf::from),
        ..TrivyConfig::default()
    };
    let adapter = TrivyAdapter::new(config, Arc::new(FixtureStorage { bytes }));
    let hash = placeholder_hash();
    let target = ScanTarget {
        content_hash: &hash,
        format: match coords.format {
            RepositoryFormat::Maven => "maven",
            RepositoryFormat::Npm => "npm",
            RepositoryFormat::Cargo => "cargo",
            RepositoryFormat::Pypi => "pypi",
            _ => "oci",
        },
        coords,
        kind,
    };
    Some(adapter.scan(&target, None).await)
}

/// Unwrap an analysis that must be a verdict, reporting Trivy's own error
/// text on failure so a missing vulnerability DB is diagnosable rather
/// than mysterious.
fn expect_verdict(result: DomainResult<ScanAnalysis>, what: &str) -> Vec<Finding> {
    match result {
        Ok(ScanAnalysis::Analysed(findings)) => findings,
        Ok(ScanAnalysis::NothingAnalysable(reason)) => panic!(
            "{what}: trivy analysed nothing ({reason}). The materialisation did not reach any \
             analyzer — this is the defect these tests exist to catch."
        ),
        Err(DomainError::Invariant(msg)) => panic!(
            "{what}: the trivy invocation failed: {msg}. If this mentions a database, the host \
             needs network access or a warm TRIVY_CACHE_DIR."
        ),
        Err(other) => panic!("{what}: unexpected scan error: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

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
        zw.finish().expect("finish zip");
    }
    buf
}

/// Build a tar archive from `(path, entry_type, body_or_link_target)`
/// triples. A link entry carries its target in the third element and no
/// body.
fn tar_bytes(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
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
    builder.into_inner().expect("finish tar")
}

fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let typed: Vec<(&str, tar::EntryType, &[u8])> = entries
        .iter()
        .map(|(path, body)| (*path, tar::EntryType::Regular, *body))
        .collect();
    tar_bytes(&typed)
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).expect("gz write");
    enc.finish().expect("gz finish")
}

/// A JAR whose embedded Maven coordinates name `log4j-core 2.14.1`.
///
/// Trivy's JAR analyzer identifies a Java archive from
/// `META-INF/maven/<groupId>/<artifactId>/pom.properties` when present,
/// which is what lets a synthetic archive stand in for the real 1.8 MB
/// download (<https://trivy.dev/latest/docs/coverage/language/java/>).
fn log4j_core_jar() -> Vec<u8> {
    zip_of(&[
        (
            "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
            b"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n",
        ),
        (
            "org/apache/logging/log4j/core/Logger.class",
            b"\xca\xfe\xba\xbe not real bytecode",
        ),
    ])
}

/// A wheel whose `*.dist-info/METADATA` declares `urllib3 1.26.4`.
///
/// Trivy's Python analyzer keys on the `*.dist-info/METADATA` path
/// (<https://trivy.dev/latest/docs/coverage/language/python/>), which is
/// only a path once the wheel has been extracted.
fn urllib3_wheel() -> Vec<u8> {
    zip_of(&[
        (
            "urllib3-1.26.4.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: urllib3\nVersion: 1.26.4\n",
        ),
        (
            "urllib3-1.26.4.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nGenerator: bdist_wheel\nRoot-Is-Purelib: true\nTag: py2-none-any\n",
        ),
        ("urllib3/__init__.py", b"__version__ = \"1.26.4\"\n"),
    ])
}

/// A `tar+gzip` image layer carrying a Debian package database that
/// declares a long-superseded `zlib1g`, plus the absolute symlink every
/// real root filesystem carries (`/bin/sh -> /bin/busybox`).
///
/// `var/lib/dpkg/status` is the file Trivy's Debian analyzer reads, and it
/// is only reachable once the layer is extracted as a root filesystem and
/// scanned with `trivy rootfs` (<https://trivy.dev/latest/docs/target/rootfs/>).
/// The symlink is not read by any analyzer; it is here so this evidence
/// test also pins the regression this change fixes — an absolute link
/// target must not stop the package database beneath it from being read.
fn debian_layer() -> Vec<u8> {
    let status = b"Package: zlib1g\n\
Status: install ok installed\n\
Priority: required\n\
Section: libs\n\
Installed-Size: 163\n\
Architecture: amd64\n\
Source: zlib\n\
Version: 1:1.2.11.dfsg-2\n\
Description: compression library - runtime\n\
\n";
    gzip(&tar_bytes(&[
        (
            "etc/debian_version",
            tar::EntryType::Regular,
            b"11.0\n" as &[u8],
        ),
        (
            "etc/os-release",
            tar::EntryType::Regular,
            b"ID=debian\nVERSION_ID=\"11\"\nVERSION_CODENAME=bullseye\n" as &[u8],
        ),
        (
            "var/lib/dpkg/status",
            tar::EntryType::Regular,
            status as &[u8],
        ),
        ("bin/sh", tar::EntryType::Symlink, b"/bin/busybox" as &[u8]),
    ]))
}

// ---------------------------------------------------------------------------
// "yes" cells — the materialisation reaches an analyzer
// ---------------------------------------------------------------------------

/// The scenario this whole change exists for: a known-vulnerable JAR must
/// produce its CVE. Before materialisation by kind the same artifact was
/// written as `<sha256>.bin`, matched no analyzer, and scanned clean —
/// and correcting only the file name was still not enough, because
/// Trivy's Java analyzer runs under the Image and Rootfs targets and not
/// under Filesystem.
#[tokio::test]
async fn a_known_vulnerable_jar_yields_its_cve() {
    let c = coords(
        "org.apache.logging.log4j:log4j-core",
        Some("2.14.1"),
        "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
        RepositoryFormat::Maven,
    );
    let Some(result) = scan_fixture(ArtifactKind::MavenJar, &c, log4j_core_jar()).await else {
        return; // TRIVY_BIN unset — self-skip.
    };
    let findings = expect_verdict(result, "log4j-core 2.14.1 JAR");
    assert!(
        findings
            .iter()
            .any(|f| f.vulnerability_id.eq_ignore_ascii_case("CVE-2021-44228")),
        "expected CVE-2021-44228 against log4j-core 2.14.1; got {:?}",
        findings
            .iter()
            .map(|f| f.vulnerability_id.as_str())
            .collect::<Vec<_>>()
    );
}

/// A wheel's advisories are only reachable through its extracted
/// `*.dist-info/METADATA`. The specific CVE is not asserted — Python
/// advisory sets churn — but a vulnerable, four-years-superseded urllib3
/// must produce *something*, and zero findings means the extraction never
/// reached the analyzer.
#[tokio::test]
async fn a_known_vulnerable_wheel_yields_at_least_one_finding() {
    let c = coords(
        "urllib3",
        Some("1.26.4"),
        "simple/urllib3/urllib3-1.26.4-py2.py3-none-any.whl",
        RepositoryFormat::Pypi,
    );
    let Some(result) = scan_fixture(ArtifactKind::PyWheel, &c, urllib3_wheel()).await else {
        return;
    };
    let findings = expect_verdict(result, "urllib3 1.26.4 wheel");
    assert!(
        !findings.is_empty(),
        "expected at least one advisory against urllib3 1.26.4; the wheel's \
         dist-info/METADATA must have reached Trivy's python analyzer"
    );
}

/// An OCI layer's OS packages are only reachable through an extracted
/// root filesystem scanned with `trivy rootfs`.
#[tokio::test]
async fn an_oci_layer_with_an_os_package_database_yields_findings() {
    let c = coords(
        "library/debian",
        None,
        "blobs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        RepositoryFormat::Oci,
    );
    let Some(result) = scan_fixture(ArtifactKind::OciBlob, &c, debian_layer()).await else {
        return;
    };
    let findings = expect_verdict(result, "debian layer with a dpkg status file");
    assert!(
        !findings.is_empty(),
        "expected at least one advisory against zlib1g 1:1.2.11.dfsg-2 on bullseye; \
         the layer's var/lib/dpkg/status must have reached Trivy's debian analyzer"
    );
}

/// A POM is analysed as `pom.xml`. Whether Trivy attributes advisories to
/// a POM's declared dependencies depends on whether it can resolve them,
/// so only the *analysis* is asserted: the report must name an analysed
/// target, not come back with nothing.
#[tokio::test]
async fn a_pom_is_analysed_rather_than_ignored() {
    let pom = br#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>evidence</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
"#;
    let c = coords(
        "com.example:evidence",
        Some("1.0.0"),
        "com/example/evidence/1.0.0/evidence-1.0.0.pom",
        RepositoryFormat::Maven,
    );
    let Some(result) = scan_fixture(ArtifactKind::MavenPom, &c, pom.to_vec()).await else {
        return;
    };
    // A verdict of any shape proves the pom.xml name reached the Maven
    // analyzer; an abstention would mean it did not.
    let _ = expect_verdict(result, "a POM materialised as pom.xml");
}

/// A `tar+gzip` image layer with no package database at all: a handful of
/// CA-certificate files (the shape a real multi-layer image carries — see
/// `nginx:alpine`'s certificate layer) plus one absolute symlink, and
/// nothing an OS-package, language or binary analyzer claims.
///
/// Every real OS-package analyzer runs over this tree and finds no
/// package surface, which is a completed "nothing to assess" fact about
/// the layer, not an unassessed pairing.
fn package_less_layer() -> Vec<u8> {
    gzip(&tar_bytes(&[
        (
            "usr/share/ca-certificates/example.crt",
            tar::EntryType::Regular,
            b"-----BEGIN CERTIFICATE-----\nnot a real certificate\n-----END CERTIFICATE-----\n"
                as &[u8],
        ),
        (
            "etc/ssl/certs/example.pem",
            tar::EntryType::Symlink,
            b"/usr/share/ca-certificates/example.crt" as &[u8],
        ),
    ]))
}

// ---------------------------------------------------------------------------
// "nothing to assess" cell — rootfs walked, no package surface at all
// ---------------------------------------------------------------------------

/// The other half of the OS-package layer test above: a layer that
/// carries files but no package database at all must come back
/// `NotApplicable`, not held as `NoAnalyzerMatched` — the defect observed
/// in staging UAT on `nginx:alpine`'s CA-certificate layer.
#[tokio::test]
async fn a_package_less_layer_is_not_applicable() {
    let c = coords(
        "library/nginx",
        None,
        "blobs/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        RepositoryFormat::Oci,
    );
    let Some(result) = scan_fixture(ArtifactKind::OciBlob, &c, package_less_layer()).await else {
        return;
    };
    match result {
        Ok(ScanAnalysis::NothingAnalysable(NotAnalysable::NotApplicable)) => {}
        Ok(other) => {
            panic!("package-less layer: expected NotApplicable (nothing to assess), got {other:?}")
        }
        Err(e) => panic!("package-less layer: the trivy invocation failed: {e:?}"),
    }
}

// ---------------------------------------------------------------------------
// "no" cells — analysed, but with nothing to attribute
// ---------------------------------------------------------------------------

/// A known-vulnerable npm package must produce its **own** advisories.
///
/// This is the npm cell of the capability map, and it is about identity
/// rather than dependencies: the tarball names itself `lodash@4.17.20`,
/// a version with published advisories, and extraction into
/// `node_modules/lodash/` is what lets Trivy's Node analyzer read that
/// name at all. A tarball planted anywhere else yields nothing, which
/// is indistinguishable from a clean scan — the defect this file exists
/// to catch.
///
/// The sibling test below pins the other half of the same ceiling: no
/// advisory is attributed to the *ranges* a `package.json` declares.
/// Together they say exactly what a "yes" on `trivy × npm` covers.
#[tokio::test]
async fn a_known_vulnerable_npm_tarball_yields_its_own_advisory() {
    let manifest = br#"{"name":"lodash","version":"4.17.20"}"#;
    let tarball = gzip(&tar_of(&[
        ("package/package.json", manifest),
        ("package/index.js", b"module.exports = {};\n"),
    ]));
    let c = coords(
        "lodash",
        Some("4.17.20"),
        "lodash/-/lodash-4.17.20.tgz",
        RepositoryFormat::Npm,
    );
    let Some(result) = scan_fixture(ArtifactKind::NpmTarball, &c, tarball).await else {
        return;
    };
    let findings = expect_verdict(result, "lodash 4.17.20 tarball");
    assert!(
        findings
            .iter()
            .any(|f| f.purl.contains("lodash") && f.purl.contains("4.17.20")),
        "expected an advisory attributed to lodash@4.17.20 (CVE-2021-23337 / \
         CVE-2020-28500 era); the tarball's package.json must have been planted \
         under node_modules/ for Trivy's node analyzer to claim it. Got {:?}",
        findings
            .iter()
            .map(|f| (f.vulnerability_id.as_str(), f.purl.as_str()))
            .collect::<Vec<_>>()
    );
}

/// A binary crate published with a `Cargo.lock` pins exact dependency
/// versions, and Trivy's Cargo analyzer reads that lockfile under every
/// target — so this is the one `.crate` shape whose declared
/// dependencies can be matched against advisories.
///
/// `smallvec 1.6.0` carries RUSTSEC-2021-0003 / CVE-2021-25900. The
/// manifest alone (`smallvec = "1"`) is a range and proves nothing; the
/// lockfile is what makes the finding attributable, which is precisely
/// the distinction the `trivy × cargo` cell rests on.
#[tokio::test]
async fn a_binary_crate_with_a_lockfile_yields_a_dependency_advisory() {
    let manifest = br#"[package]
name = "evidence"
version = "1.0.0"
edition = "2021"

[dependencies]
smallvec = "1"
"#;
    // Cargo lockfile format v3, the shape `cargo` has written since
    // 1.53 and the one a published binary crate ships.
    let lockfile = br#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "evidence"
version = "1.0.0"
dependencies = [
 "smallvec",
]

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1a55ca5f3b68e41c979bf8c46a6f1da892ca4db8f94023ce0bd32407573b1ac0"
"#;
    let crate_file = gzip(&tar_of(&[
        ("evidence-1.0.0/Cargo.toml", manifest),
        ("evidence-1.0.0/Cargo.lock", lockfile),
        ("evidence-1.0.0/src/main.rs", b"fn main() {}\n"),
    ]));
    let c = coords(
        "evidence",
        Some("1.0.0"),
        "crates/evidence/1.0.0/evidence-1.0.0.crate",
        RepositoryFormat::Cargo,
    );
    let Some(result) = scan_fixture(ArtifactKind::CargoCrate, &c, crate_file).await else {
        return;
    };
    let findings = expect_verdict(result, "binary crate with a Cargo.lock");
    assert!(
        findings.iter().any(|f| f.purl.contains("smallvec")),
        "expected an advisory attributed to smallvec 1.6.0 (CVE-2021-25900 / \
         RUSTSEC-2021-0003); the .crate's Cargo.lock must have reached Trivy's \
         cargo analyzer. Got {:?}",
        findings
            .iter()
            .map(|f| (f.vulnerability_id.as_str(), f.purl.as_str()))
            .collect::<Vec<_>>()
    );
}

/// An npm tarball carries a `package.json`: dependency *ranges*, not a
/// resolved set. Extraction into `node_modules/<name>/` — the only place
/// Trivy reads one — makes the package identity visible, and that is the
/// whole ceiling: a published tarball has no lockfile, so no advisory can
/// be attributed to a concrete dependency version.
///
/// Asserting zero findings documents that ceiling. If a future Trivy
/// release starts attributing advisories to `package.json` ranges, this
/// test failing is the signal to revisit the coverage map, not a defect.
#[tokio::test]
async fn an_npm_tarball_is_analysed_with_nothing_to_attribute() {
    let manifest = br#"{"name":"evidence","version":"1.0.0","dependencies":{"lodash":"^4.17.20"}}"#;
    let tarball = gzip(&tar_of(&[
        ("package/package.json", manifest),
        ("package/index.js", b"module.exports = {};\n"),
    ]));
    let c = coords(
        "evidence",
        Some("1.0.0"),
        "evidence/-/evidence-1.0.0.tgz",
        RepositoryFormat::Npm,
    );
    let Some(result) = scan_fixture(ArtifactKind::NpmTarball, &c, tarball).await else {
        return;
    };
    assert_no_attributable_findings(result, "npm tarball");
}

/// A library `.crate` carries `Cargo.toml` (requirements) and no
/// `Cargo.lock`, so the same ceiling applies. A *binary* crate published
/// with a lockfile is the exception, and there Trivy does read it — which
/// is why the fixture here is deliberately lockfile-free.
#[tokio::test]
async fn a_cargo_crate_is_analysed_with_nothing_to_attribute() {
    let manifest = br#"[package]
name = "evidence"
version = "1.0.0"
edition = "2021"

[dependencies]
serde = "1"
"#;
    let crate_file = gzip(&tar_of(&[
        ("evidence-1.0.0/Cargo.toml", manifest),
        ("evidence-1.0.0/src/lib.rs", b"pub fn evidence() {}\n"),
    ]));
    let c = coords(
        "evidence",
        Some("1.0.0"),
        "crates/evidence/1.0.0/evidence-1.0.0.crate",
        RepositoryFormat::Cargo,
    );
    let Some(result) = scan_fixture(ArtifactKind::CargoCrate, &c, crate_file).await else {
        return;
    };
    assert_no_attributable_findings(result, "cargo crate");
}

/// Assert that a "no" cell produced no attributable advisory.
///
/// Both outcomes are acceptable and both are honest: Trivy may claim the
/// manifest as an analysed target with an empty vulnerability list, or it
/// may claim nothing at all. What must **not** happen is a finding — that
/// would mean an advisory was attributed to a dependency version the
/// artifact does not pin, which is the false-positive-with-gate-power
/// class the SBOM path already excludes for proxied repositories.
fn assert_no_attributable_findings(result: DomainResult<ScanAnalysis>, what: &str) {
    match result {
        Ok(ScanAnalysis::Analysed(findings)) => assert!(
            findings.is_empty(),
            "{what}: no advisory can be attributed without a lockfile, got {:?}",
            findings
                .iter()
                .map(|f| f.vulnerability_id.as_str())
                .collect::<Vec<_>>()
        ),
        // No analyzer claimed the extracted manifest. Honest, and the
        // orchestrator holds the artifact fail-closed rather than
        // recording a clean scan.
        Ok(ScanAnalysis::NothingAnalysable(_)) => {}
        Err(e) => panic!("{what}: the trivy invocation failed: {e:?}"),
    }
}
