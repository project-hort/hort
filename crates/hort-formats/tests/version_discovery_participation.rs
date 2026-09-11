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
//! 3. **Count.** Exactly 4 participating (npm, cargo, pypi, maven) out of
//!    the full `RepositoryFormat` domain, so a silent reclassification is
//!    caught.
//! 4. **Participation implies a version ordering.** For every variant,
//!    `version_discovery().is_some()` iff
//!    `hort_app::use_cases::index_serve_filter::ordering_for_format(..)
//!    .is_some()`. Declaring the capability group is what opens the
//!    apply-time gate for `prefetchPolicy.triggers: [scheduled]`, and
//!    the runtime consumers cannot plan a single version without a
//!    comparator — so a format on one side of that pairing alone is a
//!    policy accepted at apply and inert at runtime (the ADR 0015 hard
//!    block). Asserting the iff here is what turns "remember to change
//!    both" into a sub-second, DB-free test failure.

#![allow(clippy::expect_used)]

use hort_app::use_cases::index_serve_filter::ordering_for_format;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::CargoFormatHandler;
use hort_formats::maven::MavenFormatHandler;
use hort_formats::npm::NpmFormatHandler;
use hort_formats::oci::OciFormatHandler;
use hort_formats::pypi::PyPiFormatHandler;

/// Classify a [`RepositoryFormat`] for `VersionDiscovery` participation.
///
/// Exhaustive on purpose — **no `_` wildcard arm** (see module doc). npm /
/// cargo / pypi / maven participate today; every other format (including
/// every OCI-family alias, every not-yet-implemented format, and the
/// WASM-plugin `Other(String)` escape hatch) does not.
///
/// Deliberately narrow: this function answers "does the format declared
/// by an `ArtifactRepository` participate", NOT "would the underlying
/// protocol support it". Two consequences worth stating:
///
/// - **Gradle does not participate even though `MavenFormatHandler` serves
///   it.** The compiled-in handler registry (`hort-worker`'s composition,
///   `hort-server::format_capabilities`) registers that handler under the
///   `"maven"` key only, so a `gradle` repository resolves no handler at
///   all and never reaches the capability group. Registering it under
///   `"gradle"` is what would change this answer.
/// - **Participation implies a version ordering, and vice versa.** The
///   prefetch consumers resolve a comparator through
///   `index_serve_filter::ordering_for_format`; a participant with no
///   comparator cannot plan a version, so the two sets must be equal.
///   `version_discovery_implies_a_canonical_version_ordering` below is
///   the assertion that keeps them so.
fn version_discovery_participates(format: &RepositoryFormat) -> bool {
    match format {
        RepositoryFormat::Npm
        | RepositoryFormat::Cargo
        | RepositoryFormat::Pypi
        | RepositoryFormat::Maven => true,
        RepositoryFormat::Gradle
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
        (RepositoryFormat::Maven, true, Box::new(MavenFormatHandler)),
    ]
}

#[test]
fn npm_cargo_pypi_maven_participate() {
    assert!(version_discovery_participates(&RepositoryFormat::Npm));
    assert!(version_discovery_participates(&RepositoryFormat::Cargo));
    assert!(version_discovery_participates(&RepositoryFormat::Pypi));
    assert!(version_discovery_participates(&RepositoryFormat::Maven));
    assert!(NpmFormatHandler.version_discovery().is_some());
    assert!(CargoFormatHandler.version_discovery().is_some());
    assert!(PyPiFormatHandler.version_discovery().is_some());
    assert!(MavenFormatHandler.version_discovery().is_some());
}

#[test]
fn oci_gradle_helm_do_not_participate() {
    assert!(!version_discovery_participates(&RepositoryFormat::Oci));
    assert!(!version_discovery_participates(&RepositoryFormat::Helm));
    assert!(OciFormatHandler.version_discovery().is_none());
    // Gradle is served BY `MavenFormatHandler` at the protocol level but
    // is not registered under the `"gradle"` key in either composition
    // root, so a gradle repository resolves no handler and the capability
    // never applies to it. See `version_discovery_participates`' doc.
    assert!(!version_discovery_participates(&RepositoryFormat::Gradle));
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

/// Every named `RepositoryFormat` variant (`Other(String)` excluded — it
/// is an open-ended escape hatch, not an enumerable set of formats).
///
/// Kept as one list so the count guard and the ordering-parity guard
/// walk exactly the same domain; a variant added to `hort-domain` fails
/// `version_discovery_participates`' exhaustive match to compile, and
/// then belongs here too.
fn named_formats() -> Vec<RepositoryFormat> {
    vec![
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
    ]
}

#[test]
fn exactly_four_formats_participate() {
    let participating = named_formats()
        .iter()
        .filter(|f| version_discovery_participates(f))
        .count();
    assert_eq!(
        participating, 4,
        "expected exactly 4 participating formats (npm, cargo, pypi, maven); got \
         {participating}. If this changed deliberately, update this count AND the ADR 0005 \
         amendment's VersionDiscovery participation table.",
    );
    assert!(!version_discovery_participates(&RepositoryFormat::Other(
        "some-wasm-plugin-format".to_string()
    )));
}

/// The structural close: `VersionDiscovery` participation and a
/// resolvable `VersionOrdering` are the same set, across every named
/// variant plus the `Other(String)` escape hatch.
///
/// Changing either side alone fails here. That matters because the two
/// sides sit at opposite ends of the same operator promise: declaring
/// the capability group is what makes gitops apply ACCEPT
/// `prefetchPolicy.triggers: [scheduled]` on a repository of that
/// format, and the comparator is what the scheduled tick and the
/// self-service endpoint need to plan even one version. A format with
/// the first and not the second is a policy an operator set, Hort
/// accepted, and Hort then silently ignores.
#[test]
fn version_discovery_implies_a_canonical_version_ordering() {
    for format in named_formats() {
        assert_eq!(
            version_discovery_participates(&format),
            ordering_for_format(&format).is_some(),
            "{format:?}: VersionDiscovery participation and \
             index_serve_filter::ordering_for_format disagree. A format must declare both or \
             neither — declaring the capability group opens the apply-time gate for \
             `prefetchPolicy.triggers: [scheduled]`, and without a comparator the prefetch \
             consumers cannot plan a single version, so the accepted policy would be inert at \
             runtime.",
        );
    }
    assert!(
        ordering_for_format(&RepositoryFormat::Other(
            "some-wasm-plugin-format".to_string()
        ))
        .is_none(),
        "the WASM-plugin escape hatch declares no VersionDiscovery, so it must resolve no \
         ordering either",
    );
}

/// The parity above is only worth as much as the handler cross-check
/// beside it: assert the ordering side directly against every concrete
/// `FormatHandler` this crate can instantiate, so the pairing is pinned
/// to the real impls and not just to this file's classification match.
#[test]
fn every_instantiable_handler_agrees_with_the_canonical_ordering() {
    for (format, _, handler) in handlers_with_expected_participation() {
        assert_eq!(
            handler.version_discovery().is_some(),
            ordering_for_format(&format).is_some(),
            "{format:?}'s FormatHandler::version_discovery() and \
             index_serve_filter::ordering_for_format disagree",
        );
    }
}
