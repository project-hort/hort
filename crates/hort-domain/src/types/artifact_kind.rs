//! What an artifact's stored bytes **are** — the fact a content-scanning
//! adapter needs before it can put those bytes somewhere its analyzers
//! will look at them.
//!
//! A scanner like Trivy selects its analyzers by file name, file
//! extension and directory layout: `*.jar`/`*.war`/`*.ear`/`*.par` go to
//! the Java-archive analyzer, `pom.xml` to the Maven analyzer,
//! `*.dist-info/METADATA` to the Python analyzer, an OS package database
//! under `var/lib/…` to the distro analyzers. It does not sniff content
//! and, in filesystem mode, does not open archives. So the bytes alone
//! are not enough: the adapter has to know whether it is holding a Java
//! archive, a POM, a wheel, a source tarball or a container layer in
//! order to materialise it under a name (or as a tree) the analyzers
//! recognise.
//!
//! That knowledge belongs to the format, not to the scanner, which is
//! why it arrives through
//! [`FormatHandler::scan_kind`](crate::ports::format_handler::FormatHandler::scan_kind)
//! and travels to the adapter on
//! [`ScanTarget`](crate::ports::scanner::ScanTarget). Each handler
//! answers from what it already knows about its own layout — a Maven
//! path's extension, an OCI row's path prefix, the single payload shape
//! npm and cargo publish.
//!
//! [`ArtifactKind::Other`] is the honest default for anything no handler
//! claims. It does **not** mean "scan it generically": there is no
//! generic materialisation that makes an unknown blob analysable, so a
//! scanner that receives it reports that it had nothing to analyse
//! rather than an empty — and therefore clean-looking — finding list.

use std::fmt;

/// The shape of an artifact's payload, as its format handler
/// understands it.
///
/// Deliberately coarse: one variant per *materialisation* a scanner
/// adapter has to perform, not one per media type. Two media types that
/// end up as the same file-with-this-extension or the same extracted
/// tree share a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A Java archive — `.jar`, `.war`, `.ear` or `.par`. Analysed as a
    /// single file; the analyzer opens the archive itself and reads the
    /// embedded `META-INF/maven/**/pom.properties` coordinates, so the
    /// only thing that matters is that the file keeps its extension.
    MavenJar,
    /// A Maven POM — an XML dependency declaration, analysed under the
    /// name `pom.xml`.
    MavenPom,
    /// An npm package tarball (gzip-tar, `package/` prefixed).
    NpmTarball,
    /// A cargo `.crate` file (gzip-tar, `<name>-<version>/` prefixed).
    CargoCrate,
    /// A Python wheel — a ZIP carrying `*.dist-info/METADATA`.
    PyWheel,
    /// A Python source distribution — gzip-tar carrying `PKG-INFO`.
    PySdist,
    /// An OCI blob: either an image layer (a tar, possibly compressed)
    /// or an image config (a JSON document).
    ///
    /// The two are **not** distinguishable from a stored row: every blob
    /// is projected at the same path prefix and stored with
    /// `application/octet-stream` regardless of the role the manifest
    /// that names it assigns it, so no handler can tell a layer from a
    /// config without opening the bytes. The adapter therefore decides
    /// by container: a tar (plain or gzip) is a layer and is extracted
    /// as a root filesystem; anything else carries no package surface.
    OciBlob,
    /// An OCI manifest or index — a JSON descriptor that names blobs by
    /// digest and carries no package content of its own.
    OciManifest,
    /// No handler claims these bytes. There is no materialisation that
    /// makes them analysable.
    Other,
}

impl ArtifactKind {
    /// Stable lowercase identifier for logs and metric labels.
    ///
    /// Not a wire format: nothing persists an `ArtifactKind`, so these
    /// strings exist only so an operator reading a `warn!` can see which
    /// kind a scanner was handed.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MavenJar => "maven_jar",
            Self::MavenPom => "maven_pom",
            Self::NpmTarball => "npm_tarball",
            Self::CargoCrate => "cargo_crate",
            Self::PyWheel => "py_wheel",
            Self::PySdist => "py_sdist",
            Self::OciBlob => "oci_blob",
            Self::OciManifest => "oci_manifest",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant has a distinct identifier — a collision would make
    /// two different materialisations indistinguishable in a log line.
    #[test]
    fn as_str_is_unique_per_variant() {
        let all = [
            ArtifactKind::MavenJar,
            ArtifactKind::MavenPom,
            ArtifactKind::NpmTarball,
            ArtifactKind::CargoCrate,
            ArtifactKind::PyWheel,
            ArtifactKind::PySdist,
            ArtifactKind::OciBlob,
            ArtifactKind::OciManifest,
            ArtifactKind::Other,
        ];
        let mut seen: Vec<&str> = all.iter().map(ArtifactKind::as_str).collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total, "identifiers must be unique: {seen:?}");
    }

    #[test]
    fn as_str_is_snake_case_lowercase() {
        for kind in [
            ArtifactKind::MavenJar,
            ArtifactKind::MavenPom,
            ArtifactKind::NpmTarball,
            ArtifactKind::CargoCrate,
            ArtifactKind::PyWheel,
            ArtifactKind::PySdist,
            ArtifactKind::OciBlob,
            ArtifactKind::OciManifest,
            ArtifactKind::Other,
        ] {
            let s = kind.as_str();
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{s} must be lowercase snake_case"
            );
        }
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(ArtifactKind::MavenJar.to_string(), "maven_jar");
        assert_eq!(ArtifactKind::Other.to_string(), "other");
    }

    /// `Copy` + `PartialEq` are load-bearing: the orchestrator computes
    /// the kind once and hands copies to every configured backend, and
    /// tests compare against an expected variant.
    #[test]
    fn kind_is_copy_and_comparable() {
        let a = ArtifactKind::PyWheel;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, ArtifactKind::PySdist);
    }
}
