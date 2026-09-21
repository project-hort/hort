//! Evidence tests — a **real** `osv-scanner` binary, proving a
//! known-vulnerable SBOM actually yields findings through this adapter.
//!
//! # Why these exist and why they need a real binary
//!
//! The fixture tests in `parse_fixtures.rs` prove the parser lowers an
//! osv-scanner report correctly. They cannot prove the step before it:
//! that the CycloneDX document this adapter writes is one osv-scanner
//! reads, and that a component in it is matched against the advisory
//! database. That is a fact about osv-scanner's input handling, not
//! about this code, and the only way to establish it is to run the
//! binary. A document osv-scanner silently ignores comes back as an
//! empty report — which, read as a finding list, is indistinguishable
//! from a clean scan.
//!
//! These are the `osv` row of the scanner capability map's evidence:
//! the rule is that a cell is "yes" only where a known-vulnerable
//! fixture of that format yields at least one finding, and this file is
//! where that is demonstrated for the SBOM-capable formats.
//!
//! # Running them
//!
//! Gated on `OSV_SCANNER_BIN` pointing at an `osv-scanner` executable,
//! mirroring the Trivy adapter's `TRIVY_BIN` pattern. Without it every
//! test here **self-skips** (returns early, reported as passed), so the
//! ordinary `cargo test --workspace` gate stays green on a host with no
//! scanner installed.
//!
//! ```text
//! OSV_SCANNER_BIN=$(command -v osv-scanner) \
//!   cargo test -p hort-adapters-scanner-osv --test sbom_evidence
//! ```
//!
//! osv-scanner resolves advisories against the OSV database, so the host
//! needs network access (or an operator-configured offline database). A
//! run without either surfaces as a scan error, which these tests report
//! as a failure with osv-scanner's own message rather than silently
//! passing.
//!
//! # What each case pins
//!
//! | format  | component               | asserted |
//! |---------|-------------------------|----------|
//! | `npm`   | `lodash 4.17.20`        | ≥ 1 finding on `lodash` |
//! | `cargo` | `smallvec 1.6.0`        | ≥ 1 finding on `smallvec` |
//! | `pypi`  | `urllib3 1.26.4`        | ≥ 1 finding on `urllib3` |
//! | `maven` | `org.apache.logging.log4j:log4j-core 2.14.1` | ≥ 1 finding |
//! | —       | an SBOM with no components | a verdict, not an abstention |
//!
//! The components are named in source rather than committed as a
//! fixture for the same reason the Trivy evidence file builds its
//! archives in-process: a reader must be able to see that the version
//! under test is the vulnerable one.

#![cfg(unix)]

use std::path::PathBuf;

use hort_adapters_scanner_osv::{OsvScannerAdapter, OsvScannerConfig};
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::scanner::{ScanAnalysis, ScanTarget, ScannerPort};
use hort_domain::types::sbom::SbomComponent;
use hort_domain::types::{ArtifactCoords, ArtifactKind, ContentHash, Ecosystem, Finding, Sbom};

/// The `osv-scanner` binary under test, or `None` to skip.
fn osv_bin() -> Option<PathBuf> {
    let raw = std::env::var("OSV_SCANNER_BIN").ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(raw))
}

fn placeholder_hash() -> ContentHash {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .expect("64 hex chars parse")
}

fn coords(name: &str, version: &str, format: RepositoryFormat) -> ArtifactCoords {
    ArtifactCoords {
        name: name.to_string(),
        name_as_published: name.to_string(),
        version: Some(version.to_string()),
        path: format!("{name}/{version}"),
        format,
        metadata: serde_json::Value::Null,
    }
}

fn component(purl: &str, name: &str, version: &str, ecosystem: Ecosystem) -> SbomComponent {
    SbomComponent {
        purl: purl.to_string(),
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem,
        licenses: vec![],
        direct_dependency: true,
    }
}

/// Run the real `osv-scanner` against `sbom`.
///
/// Returns `None` when `OSV_SCANNER_BIN` is unset, so each test can
/// self-skip.
async fn scan_sbom(coords: &ArtifactCoords, sbom: &Sbom) -> Option<DomainResult<ScanAnalysis>> {
    let bin = osv_bin()?;
    let config = OsvScannerConfig {
        osv_scanner_bin: bin,
        ..OsvScannerConfig::default()
    };
    let adapter = OsvScannerAdapter::new(config);
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
        // This backend reads only the SBOM, so the kind is carried for
        // trait conformance and never consulted.
        kind: ArtifactKind::Other,
    };
    Some(adapter.scan(&target, Some(sbom)).await)
}

/// Unwrap an analysis that must be a verdict, reporting osv-scanner's
/// own error text on failure so a database/network problem is
/// diagnosable rather than mysterious.
fn expect_verdict(result: DomainResult<ScanAnalysis>, what: &str) -> Vec<Finding> {
    match result {
        Ok(ScanAnalysis::Analysed(findings)) => findings,
        Ok(ScanAnalysis::NothingAnalysable(reason)) => panic!(
            "{what}: osv-scanner analysed nothing ({reason}). The CycloneDX document this \
             adapter wrote did not reach the matcher — this is the defect these tests exist \
             to catch."
        ),
        Err(DomainError::Invariant(msg)) => panic!(
            "{what}: the osv-scanner invocation failed: {msg}. If this mentions a database \
             or a network error, the host needs access to the OSV database."
        ),
        Err(other) => panic!("{what}: unexpected scan error: {other:?}"),
    }
}

/// Assert that at least one finding was attributed to `package`.
fn assert_attributed(findings: &[Finding], package: &str, what: &str) {
    assert!(
        findings.iter().any(|f| f.purl.contains(package)),
        "{what}: expected at least one advisory attributed to {package}; got {:?}",
        findings
            .iter()
            .map(|f| (f.vulnerability_id.as_str(), f.purl.as_str()))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// "yes" cells — the SBOM reaches the matcher, per format
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_known_vulnerable_npm_sbom_yields_a_finding() {
    let c = coords("lodash", "4.17.20", RepositoryFormat::Npm);
    let sbom = Sbom {
        subject: Some(component(
            "pkg:npm/lodash@4.17.20",
            "lodash",
            "4.17.20",
            Ecosystem::Npm,
        )),
        components: vec![],
    };
    let Some(result) = scan_sbom(&c, &sbom).await else {
        return; // OSV_SCANNER_BIN unset — self-skip.
    };
    let findings = expect_verdict(result, "npm lodash 4.17.20");
    assert_attributed(&findings, "lodash", "npm lodash 4.17.20");
}

#[tokio::test]
async fn a_known_vulnerable_cargo_sbom_yields_a_finding() {
    let c = coords("evidence", "1.0.0", RepositoryFormat::Cargo);
    let sbom = Sbom {
        subject: Some(component(
            "pkg:cargo/evidence@1.0.0",
            "evidence",
            "1.0.0",
            Ecosystem::Cargo,
        )),
        // The resolved dependency a `.crate`'s `Cargo.lock` pins —
        // RUSTSEC-2021-0003 / CVE-2021-25900.
        components: vec![component(
            "pkg:cargo/smallvec@1.6.0",
            "smallvec",
            "1.6.0",
            Ecosystem::Cargo,
        )],
    };
    let Some(result) = scan_sbom(&c, &sbom).await else {
        return;
    };
    let findings = expect_verdict(result, "cargo smallvec 1.6.0");
    assert_attributed(&findings, "smallvec", "cargo smallvec 1.6.0");
}

#[tokio::test]
async fn a_known_vulnerable_pypi_sbom_yields_a_finding() {
    let c = coords("urllib3", "1.26.4", RepositoryFormat::Pypi);
    let sbom = Sbom {
        subject: Some(component(
            "pkg:pypi/urllib3@1.26.4",
            "urllib3",
            "1.26.4",
            Ecosystem::PyPI,
        )),
        components: vec![],
    };
    let Some(result) = scan_sbom(&c, &sbom).await else {
        return;
    };
    let findings = expect_verdict(result, "pypi urllib3 1.26.4");
    assert_attributed(&findings, "urllib3", "pypi urllib3 1.26.4");
}

#[tokio::test]
async fn a_known_vulnerable_maven_sbom_yields_a_finding() {
    let c = coords(
        "org.apache.logging.log4j:log4j-core",
        "2.14.1",
        RepositoryFormat::Maven,
    );
    let sbom = Sbom {
        subject: Some(component(
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "org.apache.logging.log4j:log4j-core",
            "2.14.1",
            Ecosystem::Maven,
        )),
        components: vec![],
    };
    let Some(result) = scan_sbom(&c, &sbom).await else {
        return;
    };
    let findings = expect_verdict(result, "maven log4j-core 2.14.1");
    assert_attributed(&findings, "log4j-core", "maven log4j-core 2.14.1");
}

// ---------------------------------------------------------------------------
// The clean case — analysed, and nothing found
// ---------------------------------------------------------------------------

/// An SBOM whose components carry no advisories must come back a
/// **verdict** with an empty finding list, not an abstention. The
/// distinction is the whole point of the return type: this artifact was
/// examined and found clean, and it earns the release authority that
/// fact deserves — unlike the no-SBOM case, which earns none.
#[tokio::test]
async fn an_sbom_with_no_advisories_is_a_clean_verdict_not_an_abstention() {
    let c = coords("evidence", "1.0.0", RepositoryFormat::Npm);
    let sbom = Sbom {
        // A package name no registry publishes, so no advisory can
        // match it — while still being a well-formed component the
        // matcher reads.
        subject: Some(component(
            "pkg:npm/hort-evidence-no-such-package@1.0.0",
            "hort-evidence-no-such-package",
            "1.0.0",
            Ecosystem::Npm,
        )),
        components: vec![],
    };
    let Some(result) = scan_sbom(&c, &sbom).await else {
        return;
    };
    match result {
        Ok(ScanAnalysis::Analysed(findings)) => assert!(
            findings.is_empty(),
            "an unpublished package must match no advisory, got {:?}",
            findings
                .iter()
                .map(|f| f.vulnerability_id.as_str())
                .collect::<Vec<_>>()
        ),
        Ok(ScanAnalysis::NothingAnalysable(reason)) => panic!(
            "a well-formed SBOM was examined, so the result is a clean verdict, not \
             {reason}"
        ),
        Err(e) => panic!("the osv-scanner invocation failed: {e:?}"),
    }
}
