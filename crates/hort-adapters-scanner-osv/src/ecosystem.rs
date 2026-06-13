//! Ecosystem mapping helpers for the osv-scanner adapter.
//!
//! Two directions:
//!
//! 1. **Domain `Ecosystem` → OSV ecosystem string.** Used for diagnostics
//!    and (in some future ecosystem-aware filtering paths) for
//!    determining whether a component should ship to osv-scanner. OSV
//!    ecosystem identifiers live in the closed set documented at
//!    <https://ossf.github.io/osv-schema/#affectedpackage-field>.
//!    Mirrored from `hort-adapters-advisory-osv/src/ecosystem.rs` —
//!    duplicated rather than imported because adapters do not depend
//!    on each other.
//!
//! 2. **OSV `package.ecosystem` string → PURL type.** Used by `parse.rs`
//!    when lowering an osv-scanner result into a [`Finding`] PURL.
//!    osv-scanner emits ecosystem labels matching OSV's documented set
//!    (`npm`, `PyPI`, `crates.io`, `Maven`, `Go`, `RubyGems`, `NuGet`,
//!    `Packagist`, `Hex`, `Pub`, `Conda`); we map these back to the
//!    PURL `pkg:<type>` namespace so the produced finding's PURL
//!    matches the SBOM-component PURL (`Finding.purl ==
//!    SbomComponent.purl`, the correlation invariant in §4.4).

use hort_domain::types::Ecosystem;

/// Map a domain [`Ecosystem`] to the OSV ecosystem string.
///
/// Returns `None` for ecosystems osv-scanner cannot match
/// (`Helm`, `OciImage`, `Unknown`); callers skip those components when
/// building the CycloneDX input.
///
/// Currently surfaced for diagnostics and forward-compat (the
/// orchestrator may want to log the OSV-side ecosystem label when
/// dispatching). The CycloneDX serialiser uses
/// `cyclonedx::ecosystem_supported` directly because it only needs the
/// boolean filter.
#[allow(dead_code)]
pub(crate) fn osv_ecosystem_for(eco: &Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::PyPI => Some("PyPI"),
        Ecosystem::Cargo => Some("crates.io"),
        Ecosystem::Maven => Some("Maven"),
        Ecosystem::Go => Some("Go"),
        Ecosystem::RubyGems => Some("RubyGems"),
        Ecosystem::NuGet => Some("NuGet"),
        Ecosystem::Composer => Some("Packagist"),
        Ecosystem::Hex => Some("Hex"),
        Ecosystem::Pub => Some("Pub"),
        Ecosystem::Conda => Some("Conda"),
        Ecosystem::Helm => None,
        Ecosystem::OciImage => None,
        Ecosystem::Unknown(_) => None,
    }
}

/// Map an osv-scanner `package.ecosystem` string back to the PURL
/// `pkg:<type>` namespace used by the canonical SBOM-component PURL.
///
/// Unknown ecosystems fall through to `"generic"` — the produced PURL is
/// still well-formed; operators just lose cross-source dedup with the
/// SBOM-side PURL when osv-scanner emits a non-standard label.
pub(crate) fn osv_ecosystem_to_purl_type(eco: &str) -> &'static str {
    match eco {
        "npm" => "npm",
        "PyPI" => "pypi",
        "crates.io" => "cargo",
        "Maven" => "maven",
        "Go" => "golang",
        "RubyGems" => "gem",
        "NuGet" => "nuget",
        "Packagist" => "composer",
        "Hex" => "hex",
        "Pub" => "pub",
        "Conda" => "conda",
        // OS-level ecosystems osv-scanner can scan but the SBOM model
        // does not currently produce. Map them to PURL types defined in
        // <https://github.com/package-url/purl-spec> for
        // forward-compat.
        "Alpine" => "apk",
        "Debian" => "deb",
        "Ubuntu" => "deb",
        "AlmaLinux" | "Rocky Linux" | "Red Hat" => "rpm",
        _ => "generic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- osv_ecosystem_for ------------------------------------------------

    #[test]
    fn supported_ecosystems_map_to_osv_labels() {
        assert_eq!(osv_ecosystem_for(&Ecosystem::Npm), Some("npm"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::PyPI), Some("PyPI"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::Cargo), Some("crates.io"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::Maven), Some("Maven"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::Go), Some("Go"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::RubyGems), Some("RubyGems"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::NuGet), Some("NuGet"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::Composer), Some("Packagist"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::Hex), Some("Hex"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::Pub), Some("Pub"));
        assert_eq!(osv_ecosystem_for(&Ecosystem::Conda), Some("Conda"));
    }

    #[test]
    fn helm_returns_none() {
        assert_eq!(osv_ecosystem_for(&Ecosystem::Helm), None);
    }

    #[test]
    fn oci_image_returns_none() {
        assert_eq!(osv_ecosystem_for(&Ecosystem::OciImage), None);
    }

    #[test]
    fn unknown_returns_none_regardless_of_inner_label() {
        assert_eq!(osv_ecosystem_for(&Ecosystem::Unknown("foo".into())), None);
        assert_eq!(osv_ecosystem_for(&Ecosystem::Unknown("".into())), None);
    }

    // ----- osv_ecosystem_to_purl_type ---------------------------------------

    #[test]
    fn osv_npm_maps_to_npm_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("npm"), "npm");
    }

    #[test]
    fn osv_pypi_maps_to_pypi_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("PyPI"), "pypi");
    }

    #[test]
    fn osv_crates_io_maps_to_cargo_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("crates.io"), "cargo");
    }

    #[test]
    fn osv_maven_maps_to_maven_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("Maven"), "maven");
    }

    #[test]
    fn osv_go_maps_to_golang_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("Go"), "golang");
    }

    #[test]
    fn osv_rubygems_maps_to_gem_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("RubyGems"), "gem");
    }

    #[test]
    fn osv_packagist_maps_to_composer_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("Packagist"), "composer");
    }

    #[test]
    fn osv_alpine_maps_to_apk_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("Alpine"), "apk");
    }

    #[test]
    fn osv_debian_and_ubuntu_map_to_deb_purl_type() {
        assert_eq!(osv_ecosystem_to_purl_type("Debian"), "deb");
        assert_eq!(osv_ecosystem_to_purl_type("Ubuntu"), "deb");
    }

    #[test]
    fn osv_rpm_family_maps_to_rpm_purl_type() {
        for label in ["AlmaLinux", "Rocky Linux", "Red Hat"] {
            assert_eq!(osv_ecosystem_to_purl_type(label), "rpm", "label {label}");
        }
    }

    #[test]
    fn osv_unknown_label_falls_through_to_generic() {
        assert_eq!(osv_ecosystem_to_purl_type("brand-new-format"), "generic");
        assert_eq!(osv_ecosystem_to_purl_type(""), "generic");
    }
}
