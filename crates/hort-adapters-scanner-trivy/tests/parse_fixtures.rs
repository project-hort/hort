//! Fixture-driven Trivy parser tests.
//!
//! Each fixture is a real-shape Trivy `--format json` document checked
//! into `tests/fixtures/`. They test the parser end-to-end: JSON
//! deserialise → aggregate → `Vec<Finding>`. If Trivy's output schema
//! evolves, the fixtures move with it; the assertions below pin the
//! parser's contract.

use hort_adapters_scanner_trivy::parse_findings_from_json;
use hort_domain::entities::scan_policy::SeverityThreshold;

const CLEAN: &[u8] = include_bytes!("fixtures/clean_scan.json");
const MIXED: &[u8] = include_bytes!("fixtures/mixed_severities.json");
const MISSING: &[u8] = include_bytes!("fixtures/missing_title_and_cvss.json");

#[test]
fn clean_scan_returns_empty_findings() {
    let findings = parse_findings_from_json(CLEAN).expect("parse");
    assert!(
        findings.is_empty(),
        "clean fixture must produce no findings: {findings:?}"
    );
}

#[test]
fn mixed_severities_yields_three_findings() {
    let findings = parse_findings_from_json(MIXED).expect("parse");
    assert_eq!(findings.len(), 3, "got {findings:#?}");

    // Order: as declared in the fixture (npm result first, cargo
    // second). Severities in declaration order: HIGH, CRITICAL, MEDIUM.
    assert_eq!(findings[0].severity, SeverityThreshold::High);
    assert_eq!(findings[0].vulnerability_id, "CVE-2021-23337");
    assert_eq!(findings[0].purl, "pkg:npm/lodash@4.17.20");
    assert_eq!(findings[0].source_scanner, "trivy");

    assert_eq!(findings[1].severity, SeverityThreshold::Critical);
    assert_eq!(findings[1].vulnerability_id, "CVE-2024-99999");
    assert_eq!(findings[1].purl, "pkg:npm/node-shell-quote@1.6.0");

    assert_eq!(findings[2].severity, SeverityThreshold::Medium);
    assert_eq!(findings[2].vulnerability_id, "RUSTSEC-2023-0033");
    assert_eq!(findings[2].purl, "pkg:cargo/openssl-src@111.18.0");
}

#[test]
fn mixed_severities_picks_nvd_v3score_over_other_scorers() {
    // CVE-2021-23337 has nvd.V3Score=7.2 and redhat.V3Score=7.0; the
    // extractor must prefer NVD.
    let findings = parse_findings_from_json(MIXED).expect("parse");
    let lodash = findings
        .iter()
        .find(|f| f.vulnerability_id == "CVE-2021-23337")
        .expect("lodash finding");
    assert_eq!(lodash.cvss_score, Some(7.2));
}

#[test]
fn vulnerability_with_missing_title_falls_back_to_id() {
    // The first vuln in the missing-fixture has no Title — the parser
    // populates `title` from `vulnerability_id`.
    let findings = parse_findings_from_json(MISSING).expect("parse");
    let busybox = findings
        .iter()
        .find(|f| f.vulnerability_id == "CVE-2025-00001")
        .expect("busybox finding");
    assert_eq!(busybox.title, "CVE-2025-00001");
}

#[test]
fn vulnerability_with_no_cvss_returns_none_score() {
    let findings = parse_findings_from_json(MISSING).expect("parse");
    let busybox = findings
        .iter()
        .find(|f| f.vulnerability_id == "CVE-2025-00001")
        .expect("busybox finding");
    assert_eq!(busybox.cvss_score, None);
}

#[test]
fn alpine_finding_uses_apk_purl_type() {
    let findings = parse_findings_from_json(MISSING).expect("parse");
    let busybox = findings
        .iter()
        .find(|f| f.vulnerability_id == "CVE-2025-00001")
        .expect("busybox finding");
    assert_eq!(busybox.purl, "pkg:apk/busybox@1.36.0-r0");
}

#[test]
fn jar_finding_splits_groupid_artifactid_and_uses_maven_purl_type() {
    let findings = parse_findings_from_json(MISSING).expect("parse");
    let foo = findings
        .iter()
        .find(|f| f.vulnerability_id == "CVE-2024-00002")
        .expect("foo finding");
    assert_eq!(foo.purl, "pkg:maven/com.example/foo@1.2.3");
}

#[test]
fn jar_finding_severity_is_case_insensitive() {
    // Fixture spells "high" (lowercase) — the parser is lenient.
    let findings = parse_findings_from_json(MISSING).expect("parse");
    let foo = findings
        .iter()
        .find(|f| f.vulnerability_id == "CVE-2024-00002")
        .expect("foo finding");
    assert_eq!(foo.severity, SeverityThreshold::High);
}

#[test]
fn comma_separated_fixed_versions_split_into_vec() {
    // Fixture has FixedVersion="1.2.4, 1.3.0".
    let findings = parse_findings_from_json(MISSING).expect("parse");
    let foo = findings
        .iter()
        .find(|f| f.vulnerability_id == "CVE-2024-00002")
        .expect("foo finding");
    assert_eq!(foo.fixed_versions, vec!["1.2.4", "1.3.0"]);
}

#[test]
fn malformed_json_propagates_validation_error() {
    let r = parse_findings_from_json(b"{not json");
    match r {
        Err(e) => {
            // Domain error wrapper has the adapter's prefix.
            let s = format!("{e}");
            assert!(s.contains("trivy adapter"), "{s}");
        }
        Ok(v) => panic!("expected error, got {v:?}"),
    }
}

#[test]
fn fixture_dedupes_repeated_primary_url_in_references() {
    // CVE-2021-23337 has PrimaryURL = `.../cve-2021-23337` and
    // References including the NVD URL but NOT the primary URL —
    // ensure references[0] is the primary URL and the rest aren't
    // duplicated.
    let findings = parse_findings_from_json(MIXED).expect("parse");
    let lodash = findings
        .iter()
        .find(|f| f.vulnerability_id == "CVE-2021-23337")
        .expect("lodash finding");
    assert_eq!(
        lodash.references[0],
        "https://avd.aquasec.com/nvd/cve-2021-23337"
    );
    // Three URLs total: primary + two references.
    assert_eq!(lodash.references.len(), 3);
}
