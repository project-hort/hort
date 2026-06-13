//! Fixture-driven osv-scanner parser tests.
//!
//! Each fixture is a real-shape osv-scanner `--format json` document
//! checked into `tests/fixtures/`. They test the parser end-to-end:
//! JSON deserialise → aggregate → `Vec<Finding>`. If osv-scanner's
//! output schema evolves, the fixtures move with it; the assertions
//! below pin the parser's contract.

use hort_adapters_scanner_osv::parse_findings_from_json;
use hort_domain::entities::scan_policy::SeverityThreshold;

const CLEAN: &[u8] = include_bytes!("fixtures/clean_scan.json");
const MIXED: &[u8] = include_bytes!("fixtures/mixed_severities.json");
const NO_MAX_SEVERITY: &[u8] = include_bytes!("fixtures/no_max_severity_with_inline_score.json");
const MANY_FIXED: &[u8] = include_bytes!("fixtures/many_fixed_versions.json");

#[test]
fn clean_scan_returns_empty_findings() {
    let findings = parse_findings_from_json(CLEAN).expect("parse");
    assert!(
        findings.is_empty(),
        "clean fixture must produce no findings: {findings:?}"
    );
}

#[test]
fn mixed_severities_yields_three_findings_with_correct_purls() {
    let findings = parse_findings_from_json(MIXED).expect("parse");
    assert_eq!(findings.len(), 3, "got {findings:#?}");

    // Order: as declared in the fixture (npm package first, cargo
    // second). Severities mapped via groups[].max_severity:
    //   - GHSA-35jh: 7.2 → High
    //   - GHSA-jf85: 9.1 → Critical
    //   - RUSTSEC-2023-0033: 5.5 → Medium
    assert_eq!(findings[0].vulnerability_id, "GHSA-35jh-r3h4-6jhm");
    assert_eq!(findings[0].purl, "pkg:npm/lodash@4.17.20");
    assert_eq!(findings[0].severity, SeverityThreshold::High);
    assert_eq!(findings[0].cvss_score, Some(7.2));
    assert_eq!(findings[0].source_scanner, "osv");

    assert_eq!(findings[1].vulnerability_id, "GHSA-jf85-cpcp-j695");
    assert_eq!(findings[1].purl, "pkg:npm/lodash@4.17.20");
    assert_eq!(findings[1].severity, SeverityThreshold::Critical);
    assert_eq!(findings[1].cvss_score, Some(9.1));

    assert_eq!(findings[2].vulnerability_id, "RUSTSEC-2023-0033");
    assert_eq!(findings[2].purl, "pkg:cargo/openssl-src@111.18.0");
    assert_eq!(findings[2].severity, SeverityThreshold::Medium);
    assert_eq!(findings[2].cvss_score, Some(5.5));
}

#[test]
fn vulnerability_with_no_max_severity_falls_back_to_severity_array_score() {
    // Fixture: groups[].max_severity = "" (empty), severity[].score
    // carries a CVSS vector with a trailing /8.1.
    let findings = parse_findings_from_json(NO_MAX_SEVERITY).expect("parse");
    assert_eq!(findings.len(), 1, "got {findings:#?}");
    let f = &findings[0];
    assert_eq!(f.vulnerability_id, "GHSA-9wx4-h78v-vm56");
    // 8.1 falls in the `[7.0, 9.0)` High band.
    assert_eq!(f.cvss_score, Some(8.1));
    assert_eq!(f.severity, SeverityThreshold::High);
    assert_eq!(f.purl, "pkg:pypi/requests@2.20.0");
}

#[test]
fn aliases_are_appended_to_references_on_finding() {
    // The mixed fixture's first finding carries aliases=["CVE-2021-23337"]
    // alongside two `references[]` entries. The parser must surface the
    // CVE alias as an NVD URL and include the canonical OSV page for
    // the primary GHSA id.
    let findings = parse_findings_from_json(MIXED).expect("parse");
    let f = findings
        .iter()
        .find(|f| f.vulnerability_id == "GHSA-35jh-r3h4-6jhm")
        .expect("first lodash finding");

    // The two `references[].url` entries from the fixture survive.
    assert!(
        f.references
            .iter()
            .any(|r| r == "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"),
        "GHSA advisory URL missing: {:?}",
        f.references
    );
    assert!(
        f.references
            .iter()
            .any(|r| r == "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"),
        "NVD URL from references[] missing: {:?}",
        f.references
    );
    // The canonical OSV page for the primary GHSA id is appended.
    assert!(
        f.references
            .iter()
            .any(|r| r == "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"),
        "canonical OSV URL missing: {:?}",
        f.references
    );
}

#[test]
fn fixed_versions_are_deduplicated_and_capped() {
    // Fixture has 35 distinct `fixed` events with one duplicated `v1`.
    // After dedupe: 35 distinct values; after capping at 32: first 32
    // entries (v1..v32) survive in declaration order.
    let findings = parse_findings_from_json(MANY_FIXED).expect("parse");
    assert_eq!(findings.len(), 1);
    let f = &findings[0];

    assert_eq!(
        f.fixed_versions.len(),
        32,
        "fixed_versions must be capped at 32: {:?}",
        f.fixed_versions
    );

    // First entry is v1 (dedupe preserved order, kept first occurrence
    // of the duplicate).
    assert_eq!(f.fixed_versions[0], "v1");
    // Last entry within the cap is v32 (declaration-order truncation).
    assert_eq!(f.fixed_versions[31], "v32");
    // No duplicates.
    let mut sorted = f.fixed_versions.clone();
    sorted.sort();
    let original_len = sorted.len();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        original_len,
        "fixed_versions must contain no duplicates: {:?}",
        f.fixed_versions
    );
}

#[test]
fn malformed_json_propagates_validation_error() {
    let r = parse_findings_from_json(b"{not json");
    match r {
        Err(e) => {
            let s = format!("{e}");
            assert!(s.contains("osv adapter"), "{s}");
        }
        Ok(v) => panic!("expected error, got {v:?}"),
    }
}
