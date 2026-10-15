//! Census of `FormatHandler::payload_contains_components` across the
//! compiled-in handlers (ADR 0005 capability declaration, ADR 0056 as
//! amended).
//!
//! DB-free, network-free, sub-second structural guard in the family of
//! `version_discovery_participation` — it runs under
//! `cargo test --workspace` by virtue of being a `tests/` target.
//!
//! ## What it asserts, and why a test rather than convention
//!
//! The declaration decides whether a finding against a **non-subject**
//! component of an artifact's SBOM is a finding about that artifact. Get
//! it wrong in the `true` direction and a source distribution is
//! condemned over code it does not carry (the failure ADR 0056's
//! amendment was written for: a crate terminally rejected over an
//! advisory against a version read out of its own embedded lockfile,
//! which a consumer's build never resolves). Get it wrong in the `false`
//! direction and an image's layer findings stop gating.
//!
//! Neither mistake shows up anywhere else: the declaration is a one-line
//! `bool`, the orchestrator's own tests drive it through doubles, and no
//! compile error follows from deleting an override — the trait default
//! simply takes over. So the census is asserted here, against the real
//! handlers.
//!
//! Its blind spot is the one a census has: a handler this crate does not
//! compile in (a future WASM format module) is not reached. The trait
//! default (`true`, fail-closed — every finding keeps the authority it
//! has today) is what covers that case.

#![allow(clippy::expect_used)]

use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::CargoFormatHandler;
use hort_formats::maven::MavenFormatHandler;
use hort_formats::npm::NpmFormatHandler;
use hort_formats::oci::OciFormatHandler;
use hort_formats::pypi::PyPiFormatHandler;

/// Every compiled-in handler, paired with the answer it must give.
fn census() -> Vec<(&'static str, bool, Box<dyn FormatHandler>)> {
    vec![
        // A `.crate` is a source tarball; the components come from the
        // maintainer's `Cargo.lock` and none of their code is shipped.
        ("cargo", false, Box::new(CargoFormatHandler)),
        // A published tarball carries no `node_modules`; the components
        // are `package.json` ranges the installer resolves later.
        ("npm", false, Box::new(NpmFormatHandler)),
        // A wheel or sdist ships its own modules; the components are
        // `Requires-Dist` declarations.
        ("pypi", false, Box::new(PyPiFormatHandler)),
        // A POM's `<dependencies>` are coordinates resolved from the
        // repository at build time; a jar carries its own classes.
        ("maven", false, Box::new(MavenFormatHandler)),
        // An image carries its layers — the one format for which the
        // non-subject components of a BOM are code in the artifact.
        ("oci", true, Box::new(OciFormatHandler)),
    ]
}

#[test]
fn every_compiled_in_handler_declares_its_containment() {
    for (key, expected, handler) in census() {
        assert_eq!(
            handler.format_key(),
            key,
            "census entry is keyed on the handler's own format key"
        );
        assert_eq!(
            handler.payload_contains_components(),
            expected,
            "`{key}` must declare payload_contains_components = {expected}: flipping it \
             changes whether a finding against a non-subject component of a `{key}` \
             artifact's SBOM may condemn that artifact"
        );
    }
}

/// The four formats whose BOM is a *declaration* rather than a shipped
/// closure are exactly cargo, npm, pypi and maven. Stated as a set so a
/// sixth handler arriving with the inherited default, or a fifth
/// override appearing, is a visible change rather than a silent one.
#[test]
fn exactly_the_four_declaring_formats_ship_none_of_their_components() {
    let declaring: Vec<&str> = census()
        .into_iter()
        .filter(|(_, _, h)| !h.payload_contains_components())
        .map(|(key, _, _)| key)
        .collect();
    assert_eq!(declaring, vec!["cargo", "npm", "pypi", "maven"]);
}
