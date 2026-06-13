//! Tiny pure helpers shared between the per-format
//! [`FormatHandler::extract_sbom`](hort_domain::ports::format_handler::FormatHandler::extract_sbom)
//! impls. Lifted out here when the same line of code reappears in two or
//! more handlers — the threshold is "exact duplicate." A function used by
//! exactly one handler stays inside that handler's module.
//!
//! See explanation/scanning-pipeline.md for the SBOM extraction design.

use hort_domain::types::sbom::{Ecosystem, SbomComponent};
use hort_domain::types::ArtifactCoords;

/// Strip the leading version-range operator a manifest commonly carries
/// (`^1.2.3`, `~1.2.3`, `=1.2.3`, plain `1.2.3`) and return the trimmed
/// version string.
///
/// `^` and `~` prefixes are stripped, and ASCII whitespace at either edge
/// is removed. We deliberately do NOT attempt full semver-range parsing
/// here — for SBOM purposes the bare version is what npm / cargo
/// themselves resolve to at install time, and over-parsing inflates the
/// risk of misclassifying a real version (e.g. `>=1.0.0` left intact is
/// harmless; mishandled becomes wrong).
pub(crate) fn strip_version_constraint(s: &str) -> String {
    s.trim()
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches('=')
        .trim()
        .to_string()
}

/// Build the [`SbomComponent`] that goes into [`Sbom::subject`] — the
/// CycloneDX `metadata.component` describing the artifact the BOM is
/// about.
///
/// `purl_prefix` is the ecosystem-specific `pkg:<type>/` portion (e.g.
/// `"pkg:npm/"`, `"pkg:pypi/"`, `"pkg:cargo/"`). `purl_name` is the
/// PURL-encoded package name (each format handler owns the encoding
/// rule — npm percent-encodes `@`, PyPI applies PEP-503 normalisation,
/// cargo passes through verbatim). The version, when known, is appended
/// as `@<version>`; when `None`, the PURL omits the suffix per the
/// PURL spec.
///
/// `direct_dependency` is set to `true` on the subject. It's a slight
/// semantic abuse — the subject isn't a "dependency" of anything — but
/// it's the truth value that makes the most sense if a consumer
/// downstream filters `components` by `direct_dependency == true` (the
/// artifact IS in the BOM directly).
pub(crate) fn build_subject_component(
    coords: &ArtifactCoords,
    ecosystem: Ecosystem,
    purl_prefix: &str,
    purl_name: &str,
    licenses: Vec<String>,
) -> SbomComponent {
    let version = coords.version.clone();
    let purl = match version.as_deref() {
        Some(v) => format!("{purl_prefix}{purl_name}@{v}"),
        None => format!("{purl_prefix}{purl_name}"),
    };
    SbomComponent {
        purl,
        name: coords.name.clone(),
        version,
        ecosystem,
        licenses,
        direct_dependency: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_caret_prefix() {
        assert_eq!(strip_version_constraint("^1.2.3"), "1.2.3");
    }

    #[test]
    fn strip_tilde_prefix() {
        assert_eq!(strip_version_constraint("~1.2.3"), "1.2.3");
    }

    #[test]
    fn strip_equals_prefix() {
        assert_eq!(strip_version_constraint("=1.2.3"), "1.2.3");
    }

    #[test]
    fn passthrough_bare_version() {
        assert_eq!(strip_version_constraint("1.2.3"), "1.2.3");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(strip_version_constraint("  ^1.2.3  "), "1.2.3");
    }

    #[test]
    fn empty_string_round_trips() {
        assert_eq!(strip_version_constraint(""), "");
    }

    #[test]
    fn does_not_strip_gt_or_lt_operators() {
        // Conservative: leave operator intact rather than mangle the
        // version. Documented behaviour — only ^/~/= get stripped.
        assert_eq!(strip_version_constraint(">=1.0.0"), ">=1.0.0");
        assert_eq!(strip_version_constraint("<2.0.0"), "<2.0.0");
    }

    // ---- build_subject_component -----------------------------------------

    use hort_domain::entities::repository::RepositoryFormat;

    fn coords(name: &str, version: Option<&str>, format: RepositoryFormat) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: version.map(str::to_string),
            path: format!("{name}/{name}-{}.tgz", version.unwrap_or("0")),
            format,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn build_subject_component_for_npm_with_version_emits_pkg_npm_purl() {
        let c = coords("lodash", Some("4.17.20"), RepositoryFormat::Npm);
        let s = build_subject_component(&c, Ecosystem::Npm, "pkg:npm/", "lodash", vec![]);
        assert_eq!(s.purl, "pkg:npm/lodash@4.17.20");
        assert_eq!(s.name, "lodash");
        assert_eq!(s.version.as_deref(), Some("4.17.20"));
        assert_eq!(s.ecosystem, Ecosystem::Npm);
        assert!(s.direct_dependency, "subject must be marked direct");
    }

    #[test]
    fn build_subject_component_for_pypi_with_version_emits_pkg_pypi_purl() {
        let c = coords("requests", Some("2.31.0"), RepositoryFormat::Pypi);
        let s = build_subject_component(&c, Ecosystem::PyPI, "pkg:pypi/", "requests", vec![]);
        assert_eq!(s.purl, "pkg:pypi/requests@2.31.0");
        assert_eq!(s.ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn build_subject_component_without_version_omits_at_suffix() {
        // PURL spec permits the `@<version>` suffix to be absent. The
        // helper MUST NOT emit a trailing `@` when version is None —
        // that would produce `pkg:npm/lodash@`, which osv-scanner
        // parses as version=empty-string and matches nothing.
        let c = coords("lodash", None, RepositoryFormat::Npm);
        let s = build_subject_component(&c, Ecosystem::Npm, "pkg:npm/", "lodash", vec![]);
        assert_eq!(s.purl, "pkg:npm/lodash");
        assert!(s.version.is_none());
    }

    #[test]
    fn build_subject_component_passes_licenses_through() {
        let c = coords("any", Some("1.0.0"), RepositoryFormat::Cargo);
        let s = build_subject_component(
            &c,
            Ecosystem::Cargo,
            "pkg:cargo/",
            "any",
            vec!["MIT".into(), "Apache-2.0".into()],
        );
        assert_eq!(s.licenses, vec!["MIT", "Apache-2.0"]);
    }
}
