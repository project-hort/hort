//! osv-scanner JSON output parser → [`Vec<Finding>`].
//!
//! Pure module: serde shapes mirroring the osv-scanner JSON schema and
//! a mapper that lowers each `OsvVulnerability` into a domain
//! [`Finding`]. No I/O, no allocation outside the wire types and the
//! returned vector.
//!
//! Reference shape (real osv-scanner output, captured 2026):
//!
//! ```json
//! {
//!   "results": [
//!     {
//!       "source": {"path": "/tmp/sbom.cdx.json", "type": "lockfile"},
//!       "packages": [
//!         {
//!           "package": {"name": "lodash", "ecosystem": "npm",
//!                       "version": "4.17.20"},
//!           "vulnerabilities": [
//!             {"id": "GHSA-...", "aliases": ["CVE-..."], "summary": "...",
//!              "severity": [{"type": "CVSS_V3",
//!                             "score": "CVSS:3.1/.../A:H"}],
//!              "affected": [...], "references": [...]}
//!           ],
//!           "groups": [{"ids": ["GHSA-..."], "max_severity": "7.2"}]
//!         }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! Findings that fail [`Finding::validate`] are dropped with
//! `tracing::warn!` and the rest are returned. The orchestrator never
//! sees a malformed finding; caps are an adapter-side hygiene gate
//! (mirrors the Trivy adapter's `aggregate_findings`).

use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::types::Finding;
use serde::Deserialize;

use crate::ecosystem::osv_ecosystem_to_purl_type;
use crate::severity::{
    cvss_score_to_severity, extract_score_from_cvss_vector, label_to_severity, parse_max_severity,
};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Top-level osv-scanner JSON document.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct OsvScannerReport {
    /// Per-source result list. Empty on a clean scan; osv-scanner
    /// omits the key entirely in some clean-scan layouts (handled by
    /// `default`).
    #[serde(default)]
    pub(crate) results: Vec<OsvSource>,
}

/// One source (lockfile / SBOM) inside an osv-scanner report.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct OsvSource {
    #[serde(default)]
    pub(crate) packages: Vec<OsvPackageEntry>,
}

/// One package-with-vulnerabilities entry inside an [`OsvSource`].
#[derive(Debug, Deserialize, Default)]
pub(crate) struct OsvPackageEntry {
    #[serde(default)]
    pub(crate) package: OsvPackage,
    #[serde(default)]
    pub(crate) vulnerabilities: Vec<OsvVulnerability>,
    /// `groups[].max_severity` is the cleanest source of a numeric
    /// severity for the worst vuln in a group; we use it when the
    /// vulnerability's `severity[]` array does not surface a parseable
    /// score.
    #[serde(default)]
    pub(crate) groups: Vec<OsvGroup>,
}

/// Package identification — `(ecosystem, name, version)` triple. Used
/// to construct the `Finding.purl`.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct OsvPackage {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) ecosystem: String,
    #[serde(default)]
    pub(crate) version: String,
}

/// One vulnerability entry. Mirrors the OSV vulnerability schema —
/// osv-scanner forwards the upstream OSV record verbatim.
#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvVulnerability {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) aliases: Vec<String>,
    #[serde(default)]
    pub(crate) summary: Option<String>,
    #[serde(default)]
    pub(crate) details: Option<String>,
    #[serde(default)]
    pub(crate) severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub(crate) affected: Vec<OsvAffected>,
    #[serde(default)]
    pub(crate) references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvSeverity {
    /// CVSS vector string. The numeric base score is sometimes embedded
    /// in the trailing portion (`/<float>`); we extract it best-effort.
    #[serde(default)]
    pub(crate) score: String,
    /// Severity vector type — `"CVSS_V3"`, `"CVSS_V4"`, etc. Captured
    /// for forward-compat; current parsing does not branch on it.
    #[serde(default, rename = "type")]
    #[allow(dead_code)]
    pub(crate) kind: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvAffected {
    #[serde(default)]
    pub(crate) ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvRange {
    #[serde(default)]
    pub(crate) events: Vec<OsvRangeEvent>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvRangeEvent {
    #[serde(default)]
    pub(crate) fixed: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvReference {
    #[serde(default)]
    pub(crate) url: String,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct OsvGroup {
    /// Vulnerability ids in this group. Used to find the right
    /// `max_severity` for a given `OsvVulnerability.id`.
    #[serde(default)]
    pub(crate) ids: Vec<String>,
    /// Bare numeric string — `"7.2"`, `"9.8"`, `""` for unscored.
    #[serde(default)]
    pub(crate) max_severity: String,
}

// ---------------------------------------------------------------------------
// Public parse + lowering API
// ---------------------------------------------------------------------------

/// Parse an osv-scanner `--format json` document. Empty stdout is
/// treated as a clean scan.
pub(crate) fn parse_osv_scanner_report(
    stdout: &[u8],
) -> Result<OsvScannerReport, serde_json::Error> {
    if stdout.is_empty() {
        return Ok(OsvScannerReport::default());
    }
    serde_json::from_slice(stdout)
}

/// Lower a parsed [`OsvScannerReport`] into a deduplicated `Vec<Finding>`.
///
/// Every `OsvVulnerability` becomes one [`Finding`]; over-cap findings
/// are dropped with a `tracing::warn!`. Output preserves the
/// scanner-given order so fixture tests stay stable.
pub(crate) fn aggregate_findings(report: &OsvScannerReport) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for src in &report.results {
        for entry in &src.packages {
            for vuln in &entry.vulnerabilities {
                let finding = vuln_to_finding(&entry.package, &entry.groups, vuln);
                match finding.validate() {
                    Ok(()) => out.push(finding),
                    Err(e) => {
                        tracing::warn!(
                            scanner = "osv",
                            vulnerability_id = %vuln.id,
                            error = %e,
                            "osv adapter: dropping over-cap finding"
                        );
                    }
                }
            }
        }
    }
    out
}

/// Build the canonical `pkg:<type>/<name>@<version>` PURL for the
/// produced finding. Maven `name` ships as `groupId:artifactId`; we
/// split on the first colon for that case.
fn build_purl(eco: &str, name: &str, version: &str) -> String {
    let purl_type = osv_ecosystem_to_purl_type(eco);
    if purl_type == "maven" {
        if let Some((group, artifact)) = name.split_once(':') {
            return format!("pkg:maven/{group}/{artifact}@{version}");
        }
    }
    format!("pkg:{purl_type}/{name}@{version}")
}

/// Find the `max_severity` string for `vuln_id` by searching through
/// `groups`. Returns `None` if no group lists `vuln_id` or if the
/// matching group's `max_severity` is empty.
fn max_severity_for(groups: &[OsvGroup], vuln_id: &str) -> Option<f32> {
    for g in groups {
        if g.ids.iter().any(|id| id == vuln_id) {
            return parse_max_severity(&g.max_severity);
        }
    }
    None
}

/// Pick the best-effort numeric score for `vuln`. Precedence:
/// 1. `groups[].max_severity` matching this vuln's id.
/// 2. The first parseable trailing-numeric segment in any
///    `vuln.severity[].score` CVSS vector.
fn pick_cvss_score(groups: &[OsvGroup], vuln: &OsvVulnerability) -> Option<f32> {
    if let Some(s) = max_severity_for(groups, &vuln.id) {
        return Some(s);
    }
    for sv in &vuln.severity {
        if let Some(s) = extract_score_from_cvss_vector(&sv.score) {
            return Some(s);
        }
    }
    None
}

/// Lower one [`OsvVulnerability`] into a [`Finding`]. Pure; no
/// validation — caller filters via [`Finding::validate`].
fn vuln_to_finding(pkg: &OsvPackage, groups: &[OsvGroup], vuln: &OsvVulnerability) -> Finding {
    let purl = build_purl(&pkg.ecosystem, &pkg.name, &pkg.version);

    let cvss_score = pick_cvss_score(groups, vuln);
    let severity = cvss_score
        .and_then(cvss_score_to_severity)
        // Fallback: try labelled severity inside the CVSS vector. Some
        // older OSV records spell "HIGH" inside a `score` string.
        .or_else(|| {
            vuln.severity
                .iter()
                .find_map(|sv| label_to_severity(&sv.score))
        })
        // Final fallback: §4.3 of the design doc — missing severity
        // maps to Medium.
        .unwrap_or(SeverityThreshold::Medium);

    let title = vuln
        .summary
        .clone()
        .or_else(|| vuln.details.clone())
        .unwrap_or_else(|| vuln.id.clone());

    // fixed_versions: gather every `fixed` event across all
    // `affected[].ranges[].events[]`, dedupe in input order, cap at
    // 32. Mirrors the advisory adapter's fixed-version logic.
    let mut fixed_versions: Vec<String> = Vec::new();
    for aff in &vuln.affected {
        for rng in &aff.ranges {
            for ev in &rng.events {
                if let Some(v) = &ev.fixed {
                    if !v.is_empty() && !fixed_versions.contains(v) {
                        fixed_versions.push(v.clone());
                        if fixed_versions.len() >= 32 {
                            break;
                        }
                    }
                }
            }
            if fixed_versions.len() >= 32 {
                break;
            }
        }
        if fixed_versions.len() >= 32 {
            break;
        }
    }

    // references: deduped URL list from `references[].url`, plus any
    // CVE-shaped aliases (so operators see the CVE id even when the
    // primary id is GHSA), plus the canonical OSV vulnerability page.
    // Cap at 32 — the canonical page is reserved a slot at the end.
    let mut references: Vec<String> = Vec::new();
    for r in &vuln.references {
        if !r.url.is_empty() && !references.contains(&r.url) {
            references.push(r.url.clone());
            if references.len() >= 31 {
                // leave room for the canonical OSV page
                break;
            }
        }
    }
    for alias in &vuln.aliases {
        // OSV publishes CVE / GHSA / OSV ids as aliases. Surface them as
        // human-readable URLs where possible — the NVD entry for CVEs,
        // the OSV page for everything else. Cheap and pure (no I/O).
        let alias_url = if alias.starts_with("CVE-") {
            format!("https://nvd.nist.gov/vuln/detail/{alias}")
        } else {
            format!("https://osv.dev/vulnerability/{alias}")
        };
        if !references.contains(&alias_url) {
            references.push(alias_url);
            if references.len() >= 31 {
                break;
            }
        }
    }
    if !vuln.id.is_empty() {
        let osv_page = format!("https://osv.dev/vulnerability/{}", vuln.id);
        if !references.iter().any(|r| r == &osv_page) {
            // If we still have room, append; otherwise replace the last.
            if references.len() >= 32 {
                references.pop();
            }
            references.push(osv_page);
        }
    }

    // aliases: dedup-trimmed copy of `vuln.aliases`. OSV uses GHSA / OSV-* as the primary `vuln.id`, with
    // any CVE id in `aliases`. The exclusion matcher
    // (`hort_domain::policy::exclusion::cve_matches`) checks both the
    // primary id and this list so an operator-typed `cveId:
    // CVE-2021-23337` exclusion clears the corresponding GHSA-keyed
    // finding. Trimmed to a small dedup'd set so a malicious upstream
    // can't blow up the per-finding wire shape; the domain validator
    // caps at `MAX_ALIASES`.
    let mut aliases: Vec<String> = Vec::new();
    for a in &vuln.aliases {
        let trimmed = a.trim();
        if trimmed.is_empty() {
            continue;
        }
        if aliases.iter().any(|x| x.eq_ignore_ascii_case(trimmed)) {
            continue;
        }
        aliases.push(trimmed.to_string());
        // Defence-in-depth: hard cap at 16 (mirrors
        // `hort_domain::types::finding::MAX_ALIASES`). The domain
        // validator would reject anything larger; truncating here
        // surfaces a clean Finding rather than a Validation error
        // that aborts the whole scan run.
        if aliases.len() >= 16 {
            break;
        }
    }

    Finding {
        purl,
        vulnerability_id: vuln.id.clone(),
        severity,
        cvss_score,
        title,
        fixed_versions,
        source_scanner: "osv".to_string(),
        references,
        aliases,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, eco: &str, version: &str) -> OsvPackage {
        OsvPackage {
            name: name.into(),
            ecosystem: eco.into(),
            version: version.into(),
        }
    }

    fn vuln_skeleton() -> OsvVulnerability {
        OsvVulnerability {
            id: "GHSA-aaaa-bbbb-cccc".into(),
            ..Default::default()
        }
    }

    // ----- empty stdout fallback --------------------------------------------

    #[test]
    fn parse_empty_stdout_returns_empty_report() {
        let r = parse_osv_scanner_report(b"").expect("parse");
        assert!(r.results.is_empty());
    }

    #[test]
    fn parse_empty_results_object_returns_empty_report() {
        let r = parse_osv_scanner_report(b"{}").expect("parse");
        assert!(r.results.is_empty());
    }

    #[test]
    fn parse_malformed_json_propagates_serde_error() {
        let r = parse_osv_scanner_report(b"{not json");
        assert!(r.is_err());
    }

    // ----- build_purl --------------------------------------------------------

    #[test]
    fn build_purl_npm_uses_npm_purl_type() {
        assert_eq!(
            build_purl("npm", "lodash", "4.17.20"),
            "pkg:npm/lodash@4.17.20"
        );
    }

    #[test]
    fn build_purl_maven_splits_groupid_artifactid() {
        assert_eq!(
            build_purl("Maven", "com.example:foo", "1.2.3"),
            "pkg:maven/com.example/foo@1.2.3"
        );
    }

    #[test]
    fn build_purl_maven_without_colon_falls_through() {
        assert_eq!(
            build_purl("Maven", "spring-core", "5.3.27"),
            "pkg:maven/spring-core@5.3.27"
        );
    }

    #[test]
    fn build_purl_crates_io_maps_to_cargo() {
        assert_eq!(
            build_purl("crates.io", "openssl-src", "111.18.0"),
            "pkg:cargo/openssl-src@111.18.0"
        );
    }

    // ----- max_severity_for --------------------------------------------------

    #[test]
    fn max_severity_for_finds_matching_group() {
        let groups = vec![OsvGroup {
            ids: vec!["GHSA-1".into(), "GHSA-2".into()],
            max_severity: "7.2".into(),
        }];
        assert_eq!(max_severity_for(&groups, "GHSA-1"), Some(7.2));
        assert_eq!(max_severity_for(&groups, "GHSA-2"), Some(7.2));
        assert_eq!(max_severity_for(&groups, "GHSA-3"), None);
    }

    #[test]
    fn max_severity_for_returns_none_when_group_has_empty_max_severity() {
        let groups = vec![OsvGroup {
            ids: vec!["GHSA-1".into()],
            max_severity: "".into(),
        }];
        assert_eq!(max_severity_for(&groups, "GHSA-1"), None);
    }

    // ----- pick_cvss_score precedence ---------------------------------------

    #[test]
    fn pick_cvss_score_prefers_groups_max_severity_over_severity_array() {
        let groups = vec![OsvGroup {
            ids: vec!["GHSA-1".into()],
            max_severity: "9.8".into(),
        }];
        let mut v = vuln_skeleton();
        v.id = "GHSA-1".into();
        v.severity = vec![OsvSeverity {
            score: "CVSS:3.1/AV:N/AC:L/.../7.2".into(),
            kind: "CVSS_V3".into(),
        }];
        assert_eq!(pick_cvss_score(&groups, &v), Some(9.8));
    }

    #[test]
    fn pick_cvss_score_falls_back_to_severity_array_when_group_absent() {
        let groups: Vec<OsvGroup> = Vec::new();
        let mut v = vuln_skeleton();
        v.severity = vec![OsvSeverity {
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/7.5".into(),
            kind: "CVSS_V3".into(),
        }];
        assert_eq!(pick_cvss_score(&groups, &v), Some(7.5));
    }

    #[test]
    fn pick_cvss_score_returns_none_when_no_score_present() {
        let groups: Vec<OsvGroup> = Vec::new();
        let v = vuln_skeleton();
        assert_eq!(pick_cvss_score(&groups, &v), None);
    }

    // ----- vuln_to_finding ---------------------------------------------------

    #[test]
    fn missing_summary_falls_back_to_details_then_id() {
        let pkg = pkg("lodash", "npm", "4.17.20");
        let mut v = vuln_skeleton();
        v.details = Some("long description".into());
        let f = vuln_to_finding(&pkg, &[], &v);
        assert_eq!(f.title, "long description");

        let v2 = vuln_skeleton();
        let f2 = vuln_to_finding(&pkg, &[], &v2);
        assert_eq!(f2.title, "GHSA-aaaa-bbbb-cccc");
    }

    #[test]
    fn fixed_versions_collected_from_all_ranges_and_deduped() {
        let pkg = pkg("foo", "npm", "1");
        let mut v = vuln_skeleton();
        v.affected = vec![
            OsvAffected {
                ranges: vec![OsvRange {
                    events: vec![
                        OsvRangeEvent {
                            fixed: Some("1.2.3".into()),
                        },
                        OsvRangeEvent {
                            fixed: Some("1.3.0".into()),
                        },
                        OsvRangeEvent {
                            fixed: Some("1.2.3".into()), // duplicate
                        },
                    ],
                }],
            },
            OsvAffected {
                ranges: vec![OsvRange {
                    events: vec![OsvRangeEvent {
                        fixed: Some("2.0.0".into()),
                    }],
                }],
            },
        ];
        let f = vuln_to_finding(&pkg, &[], &v);
        assert_eq!(f.fixed_versions, vec!["1.2.3", "1.3.0", "2.0.0"]);
    }

    #[test]
    fn fixed_versions_capped_at_32() {
        let pkg = pkg("foo", "npm", "1");
        let mut v = vuln_skeleton();
        let events: Vec<OsvRangeEvent> = (0..50)
            .map(|i| OsvRangeEvent {
                fixed: Some(format!("v{i}")),
            })
            .collect();
        v.affected = vec![OsvAffected {
            ranges: vec![OsvRange { events }],
        }];
        let f = vuln_to_finding(&pkg, &[], &v);
        assert_eq!(f.fixed_versions.len(), 32);
        // First 32 in declaration order.
        assert_eq!(f.fixed_versions[0], "v0");
        assert_eq!(f.fixed_versions[31], "v31");
    }

    #[test]
    fn aliases_appear_as_reference_urls() {
        let pkg = pkg("lodash", "npm", "4.17.20");
        let mut v = vuln_skeleton();
        v.id = "GHSA-zzzz".into();
        v.aliases = vec!["CVE-2024-99999".into(), "OSV-2024-1".into()];
        let f = vuln_to_finding(&pkg, &[], &v);
        // Each alias surfaces as a URL.
        assert!(
            f.references
                .iter()
                .any(|r| r == "https://nvd.nist.gov/vuln/detail/CVE-2024-99999"),
            "expected NVD URL for CVE alias: {f:?}"
        );
        assert!(
            f.references
                .iter()
                .any(|r| r == "https://osv.dev/vulnerability/OSV-2024-1"),
            "expected OSV URL for non-CVE alias: {f:?}"
        );
        // Canonical OSV page for the primary id is also present.
        assert!(
            f.references
                .iter()
                .any(|r| r == "https://osv.dev/vulnerability/GHSA-zzzz"),
            "canonical OSV URL missing: {f:?}"
        );
    }

    #[test]
    fn severity_falls_back_to_medium_when_score_absent() {
        let pkg = pkg("lodash", "npm", "4.17.20");
        let v = vuln_skeleton();
        let f = vuln_to_finding(&pkg, &[], &v);
        assert_eq!(f.severity, SeverityThreshold::Medium);
        assert_eq!(f.cvss_score, None);
    }

    #[test]
    fn severity_uses_groups_max_severity_band() {
        let pkg = pkg("lodash", "npm", "4.17.20");
        let mut v = vuln_skeleton();
        v.id = "GHSA-1".into();
        let groups = vec![OsvGroup {
            ids: vec!["GHSA-1".into()],
            max_severity: "9.8".into(),
        }];
        let f = vuln_to_finding(&pkg, &groups, &v);
        assert_eq!(f.severity, SeverityThreshold::Critical);
        assert_eq!(f.cvss_score, Some(9.8));
    }

    #[test]
    fn references_dedupe_repeated_urls() {
        let pkg = pkg("foo", "npm", "1");
        let mut v = vuln_skeleton();
        v.references = vec![
            OsvReference {
                url: "https://example.com/a".into(),
            },
            OsvReference {
                url: "https://example.com/a".into(),
            },
            OsvReference {
                url: "https://example.com/b".into(),
            },
            OsvReference { url: "".into() },
        ];
        let f = vuln_to_finding(&pkg, &[], &v);
        // Two distinct URLs + canonical OSV page = 3.
        assert_eq!(f.references.len(), 3);
        assert_eq!(f.references[0], "https://example.com/a");
        assert_eq!(f.references[1], "https://example.com/b");
    }

    // ----- aggregate_findings drops over-cap and preserves order ------------

    #[test]
    fn aggregate_drops_over_cap_findings_and_keeps_valid_ones() {
        let big_title = "x".repeat(1100);
        let report = OsvScannerReport {
            results: vec![OsvSource {
                packages: vec![OsvPackageEntry {
                    package: pkg("ok", "npm", "1"),
                    vulnerabilities: vec![
                        OsvVulnerability {
                            id: "OSV-1".into(),
                            summary: Some("ok".into()),
                            ..Default::default()
                        },
                        OsvVulnerability {
                            id: "OSV-2".into(),
                            summary: Some(big_title),
                            ..Default::default()
                        },
                    ],
                    groups: vec![],
                }],
            }],
        };
        let findings = aggregate_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vulnerability_id, "OSV-1");
    }

    #[test]
    fn aggregate_skips_results_with_no_vulnerabilities() {
        let report = OsvScannerReport {
            results: vec![OsvSource {
                packages: vec![OsvPackageEntry {
                    package: pkg("ok", "npm", "1"),
                    vulnerabilities: vec![],
                    groups: vec![],
                }],
            }],
        };
        assert!(aggregate_findings(&report).is_empty());
    }
}
