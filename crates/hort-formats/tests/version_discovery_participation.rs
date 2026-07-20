//! `VersionDiscovery` capability-group participation guard (issue #58,
//! `docs/adr/0005-wasm-format-modules-capability-taxonomy.md`).
//!
//! DB-free, network-free, sub-second structural guard `#[test]` (in the
//! spirit of `ephemeral_keyspace_exhaustive` /
//! `retention_registration_guard`) over which formats declare the
//! `VersionDiscovery` capability group via
//! [`FormatHandler::version_discovery`].
//!
//! ## What it asserts
//!
//! 1. **Exhaustiveness.** A `match` over **every** [`RepositoryFormat`]
//!    variant — **no `_` wildcard arm** — classifies each as
//!    participating or not. Because `RepositoryFormat` is not
//!    `#[non_exhaustive]` at the match-arm level (the trailing
//!    `Other(String)` variant is itself an explicit, named arm — not a
//!    wildcard), a future variant added in `hort-domain` fails to
//!    COMPILE this match until consciously classified. That is the
//!    structural close this initiative exists to deliver: with a flat
//!    `FormatHandler` interface there was no way to tell which
//!    capability a method served at all; with participation expressed as
//!    an exhaustive match, a new format cannot silently inherit
//!    ambiguous behaviour.
//! 2. **Cross-check against the real handlers.** For every
//!    `RepositoryFormat` this crate has a concrete `FormatHandler` for
//!    (npm, cargo, pypi, oci, maven), the pure classification is
//!    cross-checked against that handler's actual
//!    `version_discovery().is_some()` — so the exhaustive match and the
//!    real implementations cannot drift apart silently.
//! 3. **Count.** Exactly 3 participating (npm, cargo, pypi) out of the
//!    full `RepositoryFormat` domain, so a silent reclassification is
//!    caught.

#![allow(clippy::expect_used)]

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::CargoFormatHandler;
use hort_formats::maven::MavenFormatHandler;
use hort_formats::npm::NpmFormatHandler;
use hort_formats::oci::OciFormatHandler;
use hort_formats::pypi::PyPiFormatHandler;

/// Classify a [`RepositoryFormat`] for `VersionDiscovery` participation.
///
/// Exhaustive on purpose — **no `_` wildcard arm** (see module doc). Only
/// npm / cargo / pypi participate today; every other format (including
/// every OCI-family alias, every not-yet-implemented format, and the
/// WASM-plugin `Other(String)` escape hatch) does not.
///
/// Deliberately narrow: this function answers "does the format declared
/// by an `ArtifactRepository` participate", NOT "would the underlying
/// protocol support it" — Maven not participating today is a scope
/// decision (design §5 / this initiative's directive), not a technical
/// ceiling, and enabling it requires a conscious edit here plus the
/// `MavenFormatHandler::version_discovery` override plus the coupled
/// `ordering_for_format` sites (see
/// `self_service_prefetch_use_case.rs::ordering_for_format`'s doc).
fn version_discovery_participates(format: &RepositoryFormat) -> bool {
    match format {
        RepositoryFormat::Npm | RepositoryFormat::Cargo | RepositoryFormat::Pypi => true,
        RepositoryFormat::Maven
        | RepositoryFormat::Gradle
        | RepositoryFormat::Nuget
        | RepositoryFormat::Go
        | RepositoryFormat::Rubygems
        | RepositoryFormat::Docker
        | RepositoryFormat::Oci
        | RepositoryFormat::Helm
        | RepositoryFormat::Rpm
        | RepositoryFormat::Debian
        | RepositoryFormat::Conan
        | RepositoryFormat::Generic
        | RepositoryFormat::Podman
        | RepositoryFormat::Buildx
        | RepositoryFormat::Oras
        | RepositoryFormat::WasmOci
        | RepositoryFormat::HelmOci
        | RepositoryFormat::Poetry
        | RepositoryFormat::Conda
        | RepositoryFormat::Yarn
        | RepositoryFormat::Bower
        | RepositoryFormat::Pnpm
        | RepositoryFormat::Chocolatey
        | RepositoryFormat::Powershell
        | RepositoryFormat::Terraform
        | RepositoryFormat::Opentofu
        | RepositoryFormat::Alpine
        | RepositoryFormat::CondaNative
        | RepositoryFormat::Composer
        | RepositoryFormat::Hex
        | RepositoryFormat::Cocoapods
        | RepositoryFormat::Swift
        | RepositoryFormat::Pub
        | RepositoryFormat::Sbt
        | RepositoryFormat::Chef
        | RepositoryFormat::Puppet
        | RepositoryFormat::Ansible
        | RepositoryFormat::Gitlfs
        | RepositoryFormat::Vscode
        | RepositoryFormat::Jetbrains
        | RepositoryFormat::Huggingface
        | RepositoryFormat::Mlmodel
        | RepositoryFormat::Cran
        | RepositoryFormat::Vagrant
        | RepositoryFormat::Opkg
        | RepositoryFormat::P2
        | RepositoryFormat::Bazel
        | RepositoryFormat::Protobuf
        | RepositoryFormat::Incus
        | RepositoryFormat::Lxc
        | RepositoryFormat::Other(_) => false,
    }
}

/// Every `RepositoryFormat` variant with a concrete `FormatHandler` in
/// this crate, paired with its classification. Not every
/// `RepositoryFormat` variant has a handler yet (most are reserved for
/// future formats) — this is the subset the cross-check test can
/// actually instantiate and call.
fn handlers_with_expected_participation() -> Vec<(RepositoryFormat, bool, Box<dyn FormatHandler>)> {
    vec![
        (RepositoryFormat::Npm, true, Box::new(NpmFormatHandler)),
        (RepositoryFormat::Cargo, true, Box::new(CargoFormatHandler)),
        (RepositoryFormat::Pypi, true, Box::new(PyPiFormatHandler)),
        (RepositoryFormat::Oci, false, Box::new(OciFormatHandler)),
        (RepositoryFormat::Maven, false, Box::new(MavenFormatHandler)),
    ]
}

#[test]
fn npm_cargo_pypi_participate() {
    assert!(version_discovery_participates(&RepositoryFormat::Npm));
    assert!(version_discovery_participates(&RepositoryFormat::Cargo));
    assert!(version_discovery_participates(&RepositoryFormat::Pypi));
    assert!(NpmFormatHandler.version_discovery().is_some());
    assert!(CargoFormatHandler.version_discovery().is_some());
    assert!(PyPiFormatHandler.version_discovery().is_some());
}

#[test]
fn oci_maven_helm_do_not_participate() {
    assert!(!version_discovery_participates(&RepositoryFormat::Oci));
    assert!(!version_discovery_participates(&RepositoryFormat::Maven));
    assert!(!version_discovery_participates(&RepositoryFormat::Helm));
    assert!(OciFormatHandler.version_discovery().is_none());
    assert!(MavenFormatHandler.version_discovery().is_none());
    // Helm has no dedicated `FormatHandler` struct in this crate yet
    // (helm/helm_oci repos are served through the OCI handler) — the
    // pure classification above is the only assertion available for it.
}

#[test]
fn pure_classification_matches_every_instantiable_handler() {
    for (format, expected, handler) in handlers_with_expected_participation() {
        assert_eq!(
            version_discovery_participates(&format),
            expected,
            "version_discovery_participates({format:?}) disagrees with this test's own \
             expectation table",
        );
        assert_eq!(
            handler.version_discovery().is_some(),
            expected,
            "{format:?}'s FormatHandler::version_discovery().is_some() disagrees with the \
             exhaustive classification — the match in version_discovery_participates() and \
             the real impl have drifted apart",
        );
    }
}

#[test]
fn exactly_three_formats_participate() {
    // Every named RepositoryFormat variant (Other(String) excluded — it
    // is an open-ended escape hatch, not an enumerable set of formats).
    let named: &[RepositoryFormat] = &[
        RepositoryFormat::Maven,
        RepositoryFormat::Gradle,
        RepositoryFormat::Npm,
        RepositoryFormat::Pypi,
        RepositoryFormat::Nuget,
        RepositoryFormat::Go,
        RepositoryFormat::Rubygems,
        RepositoryFormat::Docker,
        RepositoryFormat::Oci,
        RepositoryFormat::Helm,
        RepositoryFormat::Rpm,
        RepositoryFormat::Debian,
        RepositoryFormat::Conan,
        RepositoryFormat::Cargo,
        RepositoryFormat::Generic,
        RepositoryFormat::Podman,
        RepositoryFormat::Buildx,
        RepositoryFormat::Oras,
        RepositoryFormat::WasmOci,
        RepositoryFormat::HelmOci,
        RepositoryFormat::Poetry,
        RepositoryFormat::Conda,
        RepositoryFormat::Yarn,
        RepositoryFormat::Bower,
        RepositoryFormat::Pnpm,
        RepositoryFormat::Chocolatey,
        RepositoryFormat::Powershell,
        RepositoryFormat::Terraform,
        RepositoryFormat::Opentofu,
        RepositoryFormat::Alpine,
        RepositoryFormat::CondaNative,
        RepositoryFormat::Composer,
        RepositoryFormat::Hex,
        RepositoryFormat::Cocoapods,
        RepositoryFormat::Swift,
        RepositoryFormat::Pub,
        RepositoryFormat::Sbt,
        RepositoryFormat::Chef,
        RepositoryFormat::Puppet,
        RepositoryFormat::Ansible,
        RepositoryFormat::Gitlfs,
        RepositoryFormat::Vscode,
        RepositoryFormat::Jetbrains,
        RepositoryFormat::Huggingface,
        RepositoryFormat::Mlmodel,
        RepositoryFormat::Cran,
        RepositoryFormat::Vagrant,
        RepositoryFormat::Opkg,
        RepositoryFormat::P2,
        RepositoryFormat::Bazel,
        RepositoryFormat::Protobuf,
        RepositoryFormat::Incus,
        RepositoryFormat::Lxc,
    ];
    let participating = named
        .iter()
        .filter(|f| version_discovery_participates(f))
        .count();
    assert_eq!(
        participating, 3,
        "expected exactly 3 participating formats (npm, cargo, pypi); got {participating}. \
         If this changed deliberately, update this count AND the ADR 0005 amendment's \
         VersionDiscovery participation table.",
    );
    assert!(!version_discovery_participates(&RepositoryFormat::Other(
        "some-wasm-plugin-format".to_string()
    )));
}
