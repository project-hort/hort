//! Derives which compiled-in `FormatHandler`s declare the
//! `VersionDiscovery` capability group (ADR 0005) — the composition-root
//! fact `gitops_boot`'s apply-time linter (row 6b) and the offline
//! `validate-config` CLI both need to reject a `PrefetchPolicy.triggers`
//! entry a repository's format cannot honour.
//!
//! Reads the fact off the same compiled-in handler registry
//! `hort-worker`'s composition wires for the runtime prefetch task
//! handlers — never a maintained format-name list, so a format that
//! starts (or stops) declaring `VersionDiscovery` changes the derived set
//! with no edit at either call site.

use std::collections::HashSet;

use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::CargoFormatHandler;
use hort_formats::maven::MavenFormatHandler;
use hort_formats::npm::NpmFormatHandler;
use hort_formats::oci::OciFormatHandler;
use hort_formats::pypi::PyPiFormatHandler;

/// The `format_key()` of every compiled-in `FormatHandler` whose
/// `version_discovery()` declares the group — today `npm`, `cargo`,
/// `pypi`, `maven`. OCI is instantiated here too, alongside the
/// participating formats, so the set stays correct the moment it starts
/// declaring the group, with no second edit at any call site.
pub fn version_discovery_capable_formats() -> HashSet<String> {
    let handlers: Vec<Box<dyn FormatHandler>> = vec![
        Box::new(NpmFormatHandler),
        Box::new(CargoFormatHandler),
        Box::new(PyPiFormatHandler),
        Box::new(MavenFormatHandler),
        Box::new(OciFormatHandler),
    ];
    handlers
        .into_iter()
        .filter(|h| h.version_discovery().is_some())
        .map(|h| h.format_key().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_cargo_pypi_maven_declare_version_discovery() {
        let set = version_discovery_capable_formats();
        assert!(set.contains("npm"));
        assert!(set.contains("cargo"));
        assert!(set.contains("pypi"));
        assert!(set.contains("maven"));
    }

    #[test]
    fn oci_does_not_declare_version_discovery() {
        assert!(!version_discovery_capable_formats().contains("oci"));
    }

    #[test]
    fn gradle_is_absent_because_no_handler_is_registered_under_that_key() {
        // `MavenFormatHandler` serves gradle repositories at the protocol
        // level, but it reports `format_key() == "maven"` and no handler
        // is registered under `"gradle"` in either composition root — so a
        // gradle repository resolves no handler and the capability does
        // not apply to it. Registering one would change this.
        assert!(!version_discovery_capable_formats().contains("gradle"));
    }

    #[test]
    fn set_has_exactly_the_four_participating_formats() {
        assert_eq!(version_discovery_capable_formats().len(), 4);
    }
}
