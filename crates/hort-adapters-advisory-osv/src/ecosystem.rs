//! [`Ecosystem`] → OSV ecosystem-string mapping.
//!
//! OSV uses a closed set of ecosystem identifiers — see
//! <https://ossf.github.io/osv-schema/#affectedpackage-field>.
//! Consumes the typed `Ecosystem` enum from
//! `hort-domain` and routes through the same set of OSV labels.
//!
//! Pure function; no I/O.

use hort_domain::types::Ecosystem;

/// Map an [`Ecosystem`] to the OSV ecosystem-identifier string. Returns
/// `None` for ecosystems OSV does not cover (Helm, OCI images,
/// `Ecosystem::Unknown`); callers skip these components in the batch
/// query rather than erroring.
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
        // Helm charts and OCI images are not OSV-tracked package
        // ecosystems. Trivy's image-scan path covers OCI; Helm has no
        // OSV equivalent today. The orchestrator routes those formats
        // through the scanner port instead of the advisory port.
        Ecosystem::Helm => None,
        Ecosystem::OciImage => None,
        Ecosystem::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
