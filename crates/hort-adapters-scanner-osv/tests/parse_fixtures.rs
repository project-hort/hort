//! Fixture-driven osv-scanner parser tests.
//!
//! Each fixture is a real-shape osv-scanner `--format json` document
//! checked into `tests/fixtures/`. They test the parser end-to-end:
//! JSON deserialise → aggregate → `Vec<Finding>`. If osv-scanner's
//! output schema evolves, the fixtures move with it; the assertions
//! below pin the parser's contract.

use hort_adapters_scanner_osv::parse_findings_from_json;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::types::finding::severity_summary_from_findings;

const CLEAN: &[u8] = include_bytes!("fixtures/clean_scan.json");
const MIXED: &[u8] = include_bytes!("fixtures/mixed_severities.json");
const NO_MAX_SEVERITY: &[u8] = include_bytes!("fixtures/no_max_severity_with_inline_score.json");
const MANY_FIXED: &[u8] = include_bytes!("fixtures/many_fixed_versions.json");
const INFORMATIONAL: &[u8] = include_bytes!("fixtures/informational_unmaintained.json");
const MARVIN_VECTOR_ONLY: &[u8] = include_bytes!("fixtures/marvin_vector_only.json");

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
fn marvin_vector_only_advisory_computes_cvss_v3_base_score_to_medium() {
    // Real OSV record for RUSTSEC-2023-0071 (the Marvin timing-oracle
    // advisory on the `rsa` crate), verified against api.osv.dev:
    // `groups[].max_severity` is empty and the only score is the CVSS
    // vector itself — no pre-computed numeric severity anywhere in the
    // record. The base score (5.9) must be computed from the vector,
    // banding to Medium, rather than falling through to the SUP-4
    // Critical fail-closed fallback.
    let findings = parse_findings_from_json(MARVIN_VECTOR_ONLY).expect("parse");
    assert_eq!(findings.len(), 1, "got {findings:#?}");
    let f = &findings[0];
    assert_eq!(f.vulnerability_id, "RUSTSEC-2023-0071");
    assert_eq!(f.purl, "pkg:cargo/rsa@0.9.6");
    assert_eq!(f.cvss_score, Some(5.9));
    assert_eq!(f.severity, SeverityThreshold::Medium);
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

#[test]
fn informational_unmaintained_advisory_rides_the_negligible_lane() {
    // Real osv-scanner 2.3.8 capture for proc-macro-error2 (RUSTSEC-2026-0173,
    // `affected[].database_specific.informational == "unmaintained"`). The
    // advisory has no CVSS score; without the informational carve-out it would
    // hit the SUP-4 Critical fail-closed fallback and over-block. Routed onto
    // the non-enforcing negligible lane instead.
    let findings = parse_findings_from_json(INFORMATIONAL).expect("parse");
    assert_eq!(findings.len(), 1, "got {findings:#?}");
    let f = &findings[0];

    assert_eq!(f.vulnerability_id, "RUSTSEC-2026-0173");
    assert_eq!(f.purl, "pkg:cargo/proc-macro-error2@2.0.1");
    // The raw OSV informational class is stored verbatim (the fact); the
    // boolean derives from it via the domain recognizer.
    assert_eq!(
        f.informational_class.as_deref(),
        Some("unmaintained"),
        "raw informational class must be stored: {f:?}"
    );
    assert!(f.is_informational(), "must be marked informational: {f:?}");
    // Severity is cosmetic for informational findings — it must NOT be the
    // Critical fail-closed fallback (that is the over-block this fix removes).
    assert_ne!(f.severity, SeverityThreshold::Critical);
    assert_eq!(f.severity, SeverityThreshold::Low);

    // The summary that feeds the release-gate decision counts it as negligible
    // (never enforced), not critical.
    let summary = severity_summary_from_findings(&findings);
    assert_eq!(summary.negligible, 1, "{summary:?}");
    assert_eq!(summary.critical, 0, "{summary:?}");
    assert_eq!(summary.high, 0, "{summary:?}");
    assert_eq!(summary.medium, 0, "{summary:?}");
    assert_eq!(summary.low, 0, "{summary:?}");
}

// ---------------------------------------------------------------------------
// Alias-group collapsing (ADR 0059)
//
// osv-scanner forwards the upstream OSV records verbatim, so it reports a
// RustSec advisory and its GitHub-reviewed GHSA mirror as two
// vulnerabilities on the same package. The mirror usually carries neither
// a severity nor an informational marker, so it lowers to the SUP-4
// fail-closed `Critical` and shadows the sibling that does carry the
// advisory's metadata — and the cross-backend merge cannot reconcile the
// pair, because the two records have different advisory ids.
// ---------------------------------------------------------------------------

const ALIAS_MIRROR_PAIR: &[u8] = include_bytes!("fixtures/alias_mirror_pair.json");
const ALIAS_GROUP_SCORED: &[u8] = include_bytes!("fixtures/alias_group_scored_member.json");
const ALIAS_GROUP_VIA_GROUPS: &[u8] = include_bytes!("fixtures/alias_group_via_groups_only.json");

/// `rand 0.7.3` — `GHSA-cq8v-f236-94qc` (no severity, no informational
/// marker) alongside `RUSTSEC-2026-0097` (`informational: unsound`). The
/// pair collapses to the informational reading, which rides the negligible
/// lane instead of rejecting the artifact.
#[test]
fn alias_mirror_pair_collapses_to_the_informational_record() {
    let findings = parse_findings_from_json(ALIAS_MIRROR_PAIR).expect("parse");

    assert_eq!(
        findings.len(),
        1,
        "the mirror pair is one advisory: {findings:#?}"
    );
    let f = &findings[0];
    assert_eq!(f.vulnerability_id, "RUSTSEC-2026-0097");
    assert_eq!(f.purl, "pkg:cargo/rand@0.7.3");
    assert!(f.is_informational(), "the classification must survive");
    assert!(
        f.aliases.iter().any(|a| a == "GHSA-cq8v-f236-94qc"),
        "the collapsed-away id stays matchable by an exclusion: {:?}",
        f.aliases,
    );

    let summary = severity_summary_from_findings(&findings);
    assert_eq!(summary.negligible, 1);
    assert_eq!(summary.critical, 0);
}

/// **The load-bearing negative.** `traitobject 0.1.1` — the alias-linked
/// `GHSA-pp8r-vv2j-9j5v` / `RUSTSEC-2020-0027` pair carries a
/// `max_severity` of 9.8, and a *separate* group holds the unmaintained
/// `RUSTSEC-2021-0144`. The scored pair must collapse to a scored
/// `Critical` — a real CVSS outranks a classification, so the package
/// stays blocking — while the unrelated advisory stays its own finding.
#[test]
fn alias_group_with_a_scored_member_stays_blocking() {
    let findings = parse_findings_from_json(ALIAS_GROUP_SCORED).expect("parse");

    assert_eq!(
        findings.len(),
        2,
        "the alias pair collapses; the separate advisory does not: {findings:#?}",
    );

    let scored = findings
        .iter()
        .find(|f| f.cvss_score.is_some())
        .expect("the scored member survives its group");
    assert_eq!(scored.cvss_score, Some(9.8));
    assert_eq!(scored.severity, SeverityThreshold::Critical);
    assert!(
        !scored.is_informational(),
        "a scored advisory must never be demoted onto the negligible lane",
    );

    // One finding on the ENFORCED lane is what keeps the artifact
    // rejected; the unmaintained advisory rides the negligible lane.
    let summary = severity_summary_from_findings(&findings);
    assert_eq!(summary.critical, 1);
    assert_eq!(summary.negligible, 1);
}

/// Neither record in this fixture names the other in its own `aliases`
/// array — the only link is osv-scanner's `groups[].ids`. Folding those
/// sibling ids into the lowered finding's aliases is what lets the shared
/// collapse see the group, so the pair still becomes one advisory.
#[test]
fn records_linked_only_by_the_scanner_group_still_collapse() {
    let findings = parse_findings_from_json(ALIAS_GROUP_VIA_GROUPS).expect("parse");

    assert_eq!(
        findings.len(),
        1,
        "the group is one advisory: {findings:#?}"
    );
    let f = &findings[0];
    assert_eq!(f.vulnerability_id, "RUSTSEC-2019-0039");
    assert!(f.is_informational());
    assert!(
        f.aliases.iter().any(|a| a == "GHSA-vfv3-9w6v-23jp"),
        "the collapsed-away id stays matchable: {:?}",
        f.aliases,
    );
    assert_eq!(severity_summary_from_findings(&findings).negligible, 1);
}

/// A package whose vulnerabilities are unrelated must not over-collapse —
/// the `mixed_severities` fixture has three distinct advisories and must
/// still yield three findings.
#[test]
fn unrelated_advisories_are_not_collapsed() {
    let findings = parse_findings_from_json(MIXED).expect("parse");
    assert_eq!(findings.len(), 3);
}
