//! Trivy JSON output parser → [`Vec<Finding>`].
//!
//! Pure module: serde shapes mirroring the Trivy JSON schema and a
//! mapper that lowers each `TrivyVulnerability` into a domain
//! [`Finding`]. No I/O, no allocation outside the wire types and the
//! returned vector.
//!
//! The wire shapes (`TrivyReport`, `TrivyResult`, `TrivyVulnerability`,
//! `TrivyCvss`). A `CVSS` map captured here. Field
//! renames stay aligned with Trivy's `JSON.Name` capitalisation.
//!
//! Findings that fail [`Finding::validate`] (over-cap purl, title,
//! references, etc.) are dropped with a `tracing::warn!` and the rest
//! are returned. The orchestrator never sees a malformed finding;
//! caps are an adapter-side hygiene gate.

use std::collections::BTreeMap;

use hort_domain::types::{
    parse_advisory_published_at, ComponentRelation, Finding, FindingStatement,
};
use serde::Deserialize;

use crate::purl::build_purl;
use crate::severity::trivy_severity_to_threshold;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Top-level Trivy JSON document.
///
/// `Results` **absent or `null` means nothing was analysed** — no
/// analyzer claimed any file in the workspace — which is a different fact
/// from a present-but-vulnerability-free result, and the adapter maps the
/// two to different outcomes. Both shapes occur in practice: Trivy elides
/// the key entirely in some modes, and Go marshals a nil result slice as
/// an explicit `null`.
///
/// `#[serde(default)]` alone covers only the *missing* key — serde still
/// fails on an explicit `null` for a non-`Option` field — so the field
/// deserialises through [`null_as_empty`]. Without that, a `null` report
/// is a parse error, which fails the scan as a backend malfunction and
/// burns the retry budget instead of being read as what it is.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct TrivyReport {
    #[serde(rename = "Results", default, deserialize_with = "null_as_empty")]
    pub(crate) results: Vec<TrivyResult>,
}

/// Deserialise a possibly-`null` JSON array into a `Vec`, mapping `null`
/// to the empty vector. See [`TrivyReport::results`].
fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// One scan target inside a Trivy report. `Type` carries the package
/// source identifier used to construct the PURL; `Vulnerabilities` is
/// the per-component finding list (absent on clean targets).
#[derive(Debug, Deserialize)]
pub(crate) struct TrivyResult {
    #[serde(rename = "Target", default)]
    #[allow(dead_code)] // diagnostic-only field; not lowered into Finding
    pub(crate) target: String,
    #[serde(rename = "Class", default)]
    #[allow(dead_code)] // diagnostic-only field; not lowered into Finding
    pub(crate) class: String,
    #[serde(rename = "Type", default)]
    pub(crate) result_type: String,
    #[serde(rename = "Vulnerabilities", default)]
    pub(crate) vulnerabilities: Option<Vec<TrivyVulnerability>>,
}

/// One Trivy finding. `FixedVersion` is `Option<String>` because clean
/// or yet-unfixed advisories elide the field. `CVSS` is a free-form
/// map keyed by scorer name (`"nvd"`, `"redhat"`, `"ghsa"`, …); the
/// extractor picks `nvd` first, then any other entry.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub(crate) vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pub(crate) pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    pub(crate) installed_version: String,
    #[serde(rename = "FixedVersion", default)]
    pub(crate) fixed_version: Option<String>,
    #[serde(rename = "Severity", default)]
    pub(crate) severity: String,
    #[serde(rename = "Title", default)]
    pub(crate) title: Option<String>,
    #[serde(rename = "PrimaryURL", default)]
    pub(crate) primary_url: Option<String>,
    #[serde(rename = "References", default)]
    pub(crate) references: Vec<String>,
    /// Vendor-specific identifiers that alias the primary
    /// `VulnerabilityID`. Trivy populates this when the primary id is
    /// a vendor advisory (e.g. `RHSA-2023-1234`) and the underlying
    /// CVE id sits in this list. Surfaced through `Finding.aliases` so
    /// the exclusion matcher can resolve CVE-keyed exclusions against
    /// vendor-advisory-keyed findings.
    #[serde(rename = "VendorIDs", default)]
    pub(crate) vendor_ids: Vec<String>,
    /// Free-form CVSS map keyed by scorer name. Empty when Trivy did
    /// not attach a score (legitimate case for many advisories).
    #[serde(rename = "CVSS", default)]
    pub(crate) cvss: BTreeMap<String, TrivyCvss>,
    /// Trivy `PublishedDate` — RFC 3339. trivy-db's own field comment
    /// reads *"Take from NVD or GHSA"*, so which event this dates
    /// depends on which source supplied the advisory, and it is not in
    /// general the same event OSV's `published` dates (see
    /// `Finding::advisory_published_at`). The key is absent, not null,
    /// when the source carried no date — `*time.Time` with
    /// `json:",omitempty"` — and the field reaches the vulnerability
    /// level of the report because `DetectedVulnerability` embeds
    /// `types.Vulnerability`. `None` is therefore an ordinary outcome
    /// here, not a parse failure.
    ///
    /// Raw string, interpreted by the domain's single
    /// `parse_advisory_published_at`, for the same reason the OSV
    /// adapter keeps it unparsed: one malformed timestamp must cost that
    /// finding its publication date, not cost the run its whole report.
    #[serde(rename = "PublishedDate", default)]
    pub(crate) published_date: Option<String>,
}

/// One scorer's CVSS entry inside the per-finding `CVSS` map. We only
/// consume `V3Score` for v1; `V3Vector` is kept around for diagnostics
/// (it appears in some scorers' entries) but never lowered.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct TrivyCvss {
    #[serde(rename = "V3Score", default)]
    pub(crate) v3_score: Option<f32>,
    #[serde(rename = "V3Vector", default)]
    #[allow(dead_code)]
    pub(crate) v3_vector: Option<String>,
}

// ---------------------------------------------------------------------------
// Report sections and what they are statements about
// ---------------------------------------------------------------------------

/// Which section of a Trivy report a finding was read out of.
///
/// One variant, because hort consumes one section: [`aggregate_findings`]
/// reads `Results[].Vulnerabilities` and nothing else. Trivy also emits
/// `Results[].Secrets` (its secret scanner is on by default),
/// `Misconfigurations` and `Licenses`; none of them is deserialised by
/// [`TrivyResult`], so none of them reaches a [`Finding`] today.
///
/// The enum exists so that changes when a section is added. ADR 0064 D2
/// splits findings by whether the claim is about the bytes or about the
/// filesystem those bytes compose into, and the section a finding came
/// out of is what decides which — a secret is in the bytes however they
/// are composed; an installed package is a fact about an assembled tree.
/// Deserialising a second section without answering that question would
/// silently give a byte statement the composition's posture, which is how
/// a later secrets backend gets disarmed by a decision taken before it
/// existed. Here, the compiler asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportSection {
    /// `Results[].Vulnerabilities` — an installed package matched an
    /// advisory. A claim about the package set of the tree Trivy walked.
    Vulnerabilities,
}

/// What a finding read out of `section` is a statement **about**
/// (ADR 0064 D2).
///
/// The section is the **adapter's own** fact and nothing downstream can
/// recover it: the report is consumed here, and which of its sections an
/// entry came out of is exactly what decides whether the claim is about
/// the bytes or about the filesystem they compose into.
///
/// What it deliberately does *not* decide is **whose** filesystem. That
/// is a property of the artifact under scan rather than of the report,
/// and a release-authority decision resting on an adapter echoing back a
/// value the application layer handed it is a decision one adapter could
/// get wrong for every artifact. So this answers the half it knows — the
/// half that persists on the finding — and
/// [`Finding::may_condemn_artifact`](hort_domain::types::Finding::may_condemn_artifact)
/// composes it with the row's `ArtifactKind` where the verdict is taken.
/// There is no value this function could return that means "a
/// constituent's filesystem": the enum has no such variant, by design.
///
/// Exhaustive over [`ReportSection`] with no wildcard arm: a section
/// added to the taxonomy has to state its side here or it does not
/// compile.
pub(crate) const fn statement_of(section: ReportSection) -> FindingStatement {
    match section {
        ReportSection::Vulnerabilities => FindingStatement::Filesystem,
    }
}

// ---------------------------------------------------------------------------
// Public parse + lowering API
// ---------------------------------------------------------------------------

/// Parse a Trivy `--format json` document. Returns
/// [`DomainError::Validation`](hort_domain::error::DomainError::Validation)
/// (wrapped via the adapter) on malformed JSON; the adapter is
/// responsible for that wrap — this function returns
/// `serde_json::Error` so the parser stays pure.
pub(crate) fn parse_trivy_report(stdout: &[u8]) -> Result<TrivyReport, serde_json::Error> {
    if stdout.is_empty() {
        // An empty stdout from Trivy fs (no Results key, no JSON
        // document at all) is observationally a clean scan. Treat as
        // such instead of erroring.
        return Ok(TrivyReport::default());
    }
    serde_json::from_slice(stdout)
}

/// Lower a parsed [`TrivyReport`] into a deduplicated `Vec<Finding>`.
///
/// Every `TrivyVulnerability` becomes one [`Finding`]; findings whose
/// shape exceeds the per-finding caps in [`Finding::validate`] are
/// dropped with a `tracing::warn!`. The output preserves the
/// scanner-given order so fixture-driven tests remain stable.
pub(crate) fn aggregate_findings(report: &TrivyReport) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for result in &report.results {
        let Some(vulns) = result.vulnerabilities.as_deref() else {
            continue;
        };
        for vuln in vulns {
            let finding = vuln_to_finding(&result.result_type, vuln);
            match finding.validate() {
                Ok(()) => out.push(finding),
                Err(e) => {
                    tracing::warn!(
                        scanner = "trivy",
                        vulnerability_id = %vuln.vulnerability_id,
                        error = %e,
                        "trivy adapter: dropping over-cap finding"
                    );
                }
            }
        }
    }
    out
}

/// Convert one [`TrivyVulnerability`] into a [`Finding`]. Pure; no
/// validation — the caller filters via [`Finding::validate`].
fn vuln_to_finding(trivy_type: &str, vuln: &TrivyVulnerability) -> Finding {
    let purl = build_purl(trivy_type, &vuln.pkg_name, &vuln.installed_version);
    let (severity, severity_basis) = trivy_severity_to_threshold(&vuln.severity);
    let cvss_score = extract_cvss(vuln);
    let title = vuln
        .title
        .clone()
        .unwrap_or_else(|| vuln.vulnerability_id.clone());

    // fixed_versions: Trivy reports a single string; some advisories
    // pack multiple comma-separated versions. Split on `,` and trim
    // each entry; preserve order. Cap at 32 entries (Finding::validate
    // would otherwise reject the whole finding).
    let fixed_versions: Vec<String> = match &vuln.fixed_version {
        Some(s) => s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .take(32)
            .collect(),
        None => Vec::new(),
    };

    // references: Trivy provides both `PrimaryURL` and a `References`
    // array. Merge — primary first if set, then the rest in order;
    // dedupe by exact string match; cap at 32.
    let mut references: Vec<String> = Vec::new();
    if let Some(p) = &vuln.primary_url {
        if !p.is_empty() {
            references.push(p.clone());
        }
    }
    for r in &vuln.references {
        if !r.is_empty() && !references.contains(r) {
            references.push(r.clone());
        }
        if references.len() >= 32 {
            break;
        }
    }

    // aliases: dedup-trimmed copy of `vuln.vendor_ids`. Trivy typically uses CVE-* as the primary
    // `vulnerability_id`, but vendor-advisory primaries (RHSA, ALAS, …)
    // surface the CVE in `VendorIDs`. Mirrors the OSV adapter's
    // population: case-insensitive dedup, hard cap matching
    // `hort_domain::types::finding::MAX_ALIASES`.
    let mut aliases: Vec<String> = Vec::new();
    for a in &vuln.vendor_ids {
        let trimmed = a.trim();
        if trimmed.is_empty() {
            continue;
        }
        if aliases.iter().any(|x| x.eq_ignore_ascii_case(trimmed)) {
            continue;
        }
        aliases.push(trimmed.to_string());
        if aliases.len() >= 16 {
            break;
        }
    }

    Finding {
        purl,
        vulnerability_id: vuln.vulnerability_id.clone(),
        severity,
        cvss_score,
        title,
        fixed_versions,
        source_scanner: "trivy".to_string(),
        references,
        aliases,
        // Trivy has no informational-advisory concept; every Trivy
        // finding is a scored vulnerability. The negligible lane is
        // populated only by the OSV adapters' `database_specific.informational`
        // discriminator.
        informational_class: None,
        // `Unassessed` exactly when the severity band was unreadable and
        // `trivy_severity_to_threshold` fell back to the SUP-4 `Critical`
        // floor; `Assessed` for every band Trivy actually reported.
        severity_basis,
        component_relation: ComponentRelation::NotEstablished,
        // Read out of the one section this parser deserialises
        // (ADR 0064 D2). The mapping is [`statement_of`]'s, not this
        // site's, so a second deserialised section cannot pick its own
        // answer here.
        statement: statement_of(ReportSection::Vulnerabilities),
        // Trivy's `PublishedDate`. It dates the VULNERABILITY rather
        // than this scan, which is what the retention grace-period
        // anchor asks for. Where it disagrees with an OSV entry date
        // for the same advisory, the anchor resolver takes the earlier
        // and records which feed it came from.
        advisory_published_at: vuln
            .published_date
            .as_deref()
            .and_then(parse_advisory_published_at),
    }
}

/// Pick the most authoritative CVSS V3 score from the per-finding map.
///
/// Precedence:
///   1. `nvd` scorer's `V3Score` if present.
///   2. The first scorer (BTreeMap ordering — alphabetical) with a
///      `V3Score`.
///   3. `None` if no scorer attached a V3 score.
///
/// CVSS V2 (`V2Score`) is intentionally NOT consulted — V3 is the
/// industry default and conflating versions in one numeric field
/// would mislead the policy view.
fn extract_cvss(vuln: &TrivyVulnerability) -> Option<f32> {
    if let Some(nvd) = vuln.cvss.get("nvd") {
        if let Some(score) = nvd.v3_score {
            return Some(score);
        }
    }
    for entry in vuln.cvss.values() {
        if let Some(score) = entry.v3_score {
            return Some(score);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::entities::scan_policy::SeverityThreshold;

    fn vuln_skeleton() -> TrivyVulnerability {
        TrivyVulnerability {
            vulnerability_id: "CVE-2024-00001".into(),
            pkg_name: "foo".into(),
            installed_version: "1.0.0".into(),
            fixed_version: None,
            severity: "HIGH".into(),
            title: Some("placeholder".into()),
            primary_url: None,
            references: Vec::new(),
            vendor_ids: Vec::new(),
            cvss: BTreeMap::new(),
            published_date: None,
        }
    }

    // ----- the three "nothing analysed" report shapes -----------------------

    /// All three shapes Trivy emits when no analyzer claimed anything must
    /// parse to zero results — not to a parse error. A parse error here
    /// would be read as a backend malfunction: the scan would fail,
    /// consume a retry, and only reach the fail-closed hold after the
    /// attempt budget ran out, mislabelled as an execution failure.
    #[test]
    fn a_report_with_no_analysed_target_parses_to_zero_results() {
        for doc in [
            // Key elided entirely.
            &b"{}"[..],
            // Explicit JSON null — what Go produces for a nil slice.
            &b"{\"Results\":null}"[..],
            // Present and empty.
            &b"{\"Results\":[]}"[..],
        ] {
            let report = parse_trivy_report(doc)
                .unwrap_or_else(|e| panic!("{} must parse: {e}", String::from_utf8_lossy(doc)));
            assert!(
                report.results.is_empty(),
                "{} must yield zero results",
                String::from_utf8_lossy(doc)
            );
        }
    }

    /// A malformed `Results` value is still a parse error — the
    /// null-tolerance above must not turn into "accept anything".
    #[test]
    fn a_report_with_a_non_array_results_value_is_still_a_parse_error() {
        assert!(parse_trivy_report(b"{\"Results\":\"nope\"}").is_err());
    }

    // ----- empty stdout fallback --------------------------------------------

    #[test]
    fn parse_empty_stdout_returns_empty_report() {
        let r = parse_trivy_report(b"").expect("parse");
        assert!(r.results.is_empty());
    }

    #[test]
    fn parse_empty_results_object_returns_empty_report() {
        let r = parse_trivy_report(b"{}").expect("parse");
        assert!(r.results.is_empty());
    }

    #[test]
    fn parse_malformed_json_propagates_serde_error() {
        let r = parse_trivy_report(b"{not json");
        assert!(r.is_err());
    }

    // ----- which side of ADR 0064 D2's line a finding is on -----------------

    /// A `Vulnerabilities` entry is a claim about an installed package
    /// set, which is a claim about an assembled filesystem rather than
    /// about the bytes — the side of ADR 0064 D2's line this adapter can
    /// answer from what it read.
    ///
    /// The mapping is exhaustive over the sections hort deserialises, so
    /// the pin is one assertion today and a compile error the day a second
    /// section lands. A `Secrets` entry would be
    /// [`FindingStatement::Bytes`]; Trivy's secret scanner is on by
    /// default and its findings are simply not deserialised
    /// ([`TrivyResult`] has no field for them), which is why hort consumes
    /// only the second kind today.
    #[test]
    fn a_vulnerability_is_a_statement_about_an_assembled_filesystem() {
        assert_eq!(
            statement_of(ReportSection::Vulnerabilities),
            FindingStatement::Filesystem,
        );
    }

    /// And the mapping reaches the finding rather than living beside it.
    #[test]
    fn the_lowered_finding_carries_the_statement_its_section_put_it_on() {
        let v = vuln_skeleton();
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.statement, FindingStatement::Filesystem);
    }

    /// Every finding in a report, not just the first: a batch where one
    /// entry carried no statement would be a batch with one unexplained
    /// gating decision in it.
    #[test]
    fn every_finding_of_a_report_states_its_side() {
        let doc = br#"{"Results":[{"Target":"image","Class":"os-pkgs","Type":"debian",
            "Vulnerabilities":[
              {"VulnerabilityID":"CVE-2024-1","PkgName":"a","InstalledVersion":"1","Severity":"HIGH"},
              {"VulnerabilityID":"CVE-2024-2","PkgName":"b","InstalledVersion":"2","Severity":"LOW"}
            ]}]}"#;
        let report = parse_trivy_report(doc).expect("parse");
        let findings = aggregate_findings(&report);
        assert_eq!(findings.len(), 2);
        for f in &findings {
            assert_eq!(
                f.statement,
                FindingStatement::Filesystem,
                "{}: every entry states its side",
                f.vulnerability_id
            );
        }
    }

    // ----- PublishedDate ----------------------------------------------------

    /// Trivy's `PublishedDate` reaches the finding. For a CVE-primary
    /// entry this is usually the NVD publication date, which is a fact
    /// about the vulnerability and so what the retention grace-period
    /// anchor asks for.
    #[test]
    fn trivy_published_date_reaches_the_finding() {
        let doc = br#"{"Results":[{"Target":"image","Class":"os-pkgs","Type":"debian",
            "Vulnerabilities":[
              {"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash",
               "InstalledVersion":"4.17.20","Severity":"HIGH",
               "PublishedDate":"2021-02-15T11:15:00Z",
               "LastModifiedDate":"2023-11-07T03:30:00Z"}
            ]}]}"#;
        let report = parse_trivy_report(doc).expect("parse");
        let findings = aggregate_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].advisory_published_at,
            parse_advisory_published_at("2021-02-15T11:15:00Z")
        );
    }

    /// Trivy omits the key for advisories its sources carry no date for,
    /// which is common for vendor and language-ecosystem advisories.
    /// That is an ordinary outcome, not a parse failure: the anchor falls
    /// back to our own later observation of the vulnerability.
    #[test]
    fn a_trivy_entry_without_a_published_date_yields_none() {
        let doc = br#"{"Results":[{"Target":"Cargo.lock","Class":"lang-pkgs","Type":"cargo",
            "Vulnerabilities":[
              {"VulnerabilityID":"RUSTSEC-2023-0033","PkgName":"openssl-src",
               "InstalledVersion":"111.18.0","Severity":"MEDIUM"}
            ]}]}"#;
        let report = parse_trivy_report(doc).expect("parse");
        let findings = aggregate_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].advisory_published_at, None);
    }

    /// A malformed date costs that finding its publication date and
    /// nothing else — the report still parses and the finding is still
    /// produced with its severity intact.
    #[test]
    fn a_malformed_trivy_published_date_costs_only_that_findings_date() {
        let mut v = vuln_skeleton();
        v.published_date = Some("2021-02-15".into());
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.advisory_published_at, None);
        assert_eq!(f.severity, SeverityThreshold::High);
    }

    // ----- vuln_to_finding lowering -----------------------------------------

    #[test]
    fn missing_title_falls_back_to_vulnerability_id() {
        let mut v = vuln_skeleton();
        v.title = None;
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.title, "CVE-2024-00001");
    }

    #[test]
    fn missing_fixed_version_yields_empty_vec() {
        let v = vuln_skeleton();
        let f = vuln_to_finding("npm", &v);
        assert!(f.fixed_versions.is_empty());
    }

    #[test]
    fn comma_separated_fixed_versions_split_and_trimmed() {
        let mut v = vuln_skeleton();
        v.fixed_version = Some("1.2.3, 1.3.0,2.0.0".into());
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.fixed_versions, vec!["1.2.3", "1.3.0", "2.0.0"]);
    }

    #[test]
    fn primary_url_is_first_reference_when_present() {
        let mut v = vuln_skeleton();
        v.primary_url = Some("https://avd.aquasec.com/cve-1".into());
        v.references = vec![
            "https://github.com/x/y/security/advisories/GHSA-1".into(),
            "https://nvd.nist.gov/vuln/detail/CVE-2024-00001".into(),
        ];
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.references[0], "https://avd.aquasec.com/cve-1");
        assert_eq!(f.references.len(), 3);
    }

    #[test]
    fn duplicate_primary_url_in_references_is_deduped() {
        let mut v = vuln_skeleton();
        let url = "https://avd.aquasec.com/cve-1";
        v.primary_url = Some(url.into());
        v.references = vec![url.into(), "https://other".into()];
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.references.len(), 2);
        assert_eq!(f.references[0], url);
    }

    #[test]
    fn no_cvss_map_yields_none_score() {
        let v = vuln_skeleton();
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.cvss_score, None);
    }

    #[test]
    fn nvd_scorer_takes_precedence_over_other_scorers() {
        let mut v = vuln_skeleton();
        v.cvss.insert(
            "redhat".into(),
            TrivyCvss {
                v3_score: Some(5.0),
                v3_vector: None,
            },
        );
        v.cvss.insert(
            "nvd".into(),
            TrivyCvss {
                v3_score: Some(8.5),
                v3_vector: None,
            },
        );
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.cvss_score, Some(8.5));
    }

    #[test]
    fn falls_back_to_first_scorer_when_nvd_absent() {
        let mut v = vuln_skeleton();
        v.cvss.insert(
            "redhat".into(),
            TrivyCvss {
                v3_score: Some(7.2),
                v3_vector: None,
            },
        );
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.cvss_score, Some(7.2));
    }

    #[test]
    fn skips_scorer_without_v3_score() {
        // A scorer entry that has only a V2 score (V3Score absent)
        // must fall through to the next scorer.
        let mut v = vuln_skeleton();
        v.cvss.insert(
            "ghsa".into(),
            TrivyCvss {
                v3_score: None,
                v3_vector: None,
            },
        );
        v.cvss.insert(
            "redhat".into(),
            TrivyCvss {
                v3_score: Some(6.5),
                v3_vector: None,
            },
        );
        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.cvss_score, Some(6.5));
    }

    // ----- aggregate_findings — drops over-cap entries -----------------------

    #[test]
    fn aggregate_drops_over_cap_findings_and_keeps_valid_ones() {
        // First vuln: well-formed. Second vuln: title 1100 bytes,
        // exceeds the 1024 cap. Aggregator should keep #1, drop #2.
        let big_title = "x".repeat(1100);
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "Cargo.lock".into(),
                class: "lang-pkgs".into(),
                result_type: "cargo".into(),
                vulnerabilities: Some(vec![
                    TrivyVulnerability {
                        vulnerability_id: "CVE-1".into(),
                        pkg_name: "ok".into(),
                        installed_version: "1".into(),
                        fixed_version: None,
                        severity: "LOW".into(),
                        title: Some("ok".into()),
                        primary_url: None,
                        references: Vec::new(),
                        vendor_ids: Vec::new(),
                        cvss: BTreeMap::new(),
                        published_date: None,
                    },
                    TrivyVulnerability {
                        vulnerability_id: "CVE-2".into(),
                        pkg_name: "bad".into(),
                        installed_version: "1".into(),
                        fixed_version: None,
                        severity: "HIGH".into(),
                        title: Some(big_title),
                        primary_url: None,
                        references: Vec::new(),
                        vendor_ids: Vec::new(),
                        cvss: BTreeMap::new(),
                        published_date: None,
                    },
                ]),
            }],
        };
        let findings = aggregate_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vulnerability_id, "CVE-1");
    }

    #[test]
    fn aggregate_skips_results_with_no_vulnerabilities_field() {
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "Cargo.lock".into(),
                class: "lang-pkgs".into(),
                result_type: "cargo".into(),
                vulnerabilities: None,
            }],
        };
        assert!(aggregate_findings(&report).is_empty());
    }

    #[test]
    fn vuln_lowers_with_full_finding_shape() {
        // Sanity check: end-to-end shape mapping for a complete vuln.
        let mut v = vuln_skeleton();
        v.severity = "CRITICAL".into();
        v.installed_version = "4.17.20".into();
        v.pkg_name = "lodash".into();
        v.title = Some("Command injection".into());
        v.fixed_version = Some("4.17.21".into());
        v.primary_url = Some("https://nvd.nist.gov/vuln/detail/CVE-2024-00001".into());
        v.cvss.insert(
            "nvd".into(),
            TrivyCvss {
                v3_score: Some(9.8),
                v3_vector: None,
            },
        );

        let f = vuln_to_finding("npm", &v);
        assert_eq!(f.purl, "pkg:npm/lodash@4.17.20");
        assert_eq!(f.vulnerability_id, "CVE-2024-00001");
        assert_eq!(f.severity, SeverityThreshold::Critical);
        assert_eq!(f.cvss_score, Some(9.8));
        assert_eq!(f.title, "Command injection");
        assert_eq!(f.fixed_versions, vec!["4.17.21"]);
        assert_eq!(f.source_scanner, "trivy");
        assert_eq!(
            f.references,
            vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-00001"]
        );
    }
}
