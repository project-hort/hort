//! Per-finding vulnerability record — the unit of identity in the
//! `(purl, vulnerability_id)`-keyed `compute_added_findings` delta
//! function and the row shape in the `scan_findings`
//! projection.
//!
//! `Finding` is a pure value type with `validate()` enforcing
//! length caps. The caps
//! are byte-counted (`String::len()`), not char-counted — they exist
//! to prevent runaway scanner output from blowing up the
//! per-finding blob, and the storage cost is bytes-on-disk.
//!
//! `Deserialize` does NOT re-validate. Findings round-trip from the
//! event store JSONB column; events that were once written must still
//! parse, even if their shape would now be rejected by the
//! constructor / validator. This mirrors
//! [`UpstreamPublishedChecksum`](super::checksum::UpstreamPublishedChecksum) —
//! the constructor / `validate()` are the only enforcement points.
//! Tested in `finding_deserialises_without_revalidation`.
//!
//! See `docs/architecture/explanation/scanning-pipeline.md`.

use serde::{Deserialize, Serialize};

use crate::entities::scan_policy::SeverityThreshold;
use crate::error::{DomainError, DomainResult};
use crate::events::SeveritySummary;

/// Per-finding length caps. Bytes, not chars. Each is
/// validated in [`Finding::validate`]; violators surface as
/// [`DomainError::Validation`] naming the field and the offending
/// size.
const MAX_PURL_LEN: usize = 512;
const MAX_VULNERABILITY_ID_LEN: usize = 128;
const MAX_TITLE_LEN: usize = 1024;
const MAX_FIXED_VERSIONS: usize = 32;
const MAX_REFERENCES: usize = 32;
/// Cap on `Finding.aliases`. OSV vulnerabilities typically carry 1-3
/// aliases (one CVE id plus optional vendor advisory id); the cap
/// leaves headroom for vulnerabilities that span multiple advisory
/// databases without becoming a vector for unbounded scanner output.
/// Each alias is byte-capped via [`MAX_VULNERABILITY_ID_LEN`] (same
/// cap as the primary `vulnerability_id` field).
const MAX_ALIASES: usize = 16;

/// One vulnerability finding produced by a scanner backend, keyed on
/// `(purl, vulnerability_id)` for delta computation against a prior
/// scan. Severity reuses the
/// [`SeverityThreshold`](crate::entities::scan_policy::SeverityThreshold)
/// enum so the policy evaluator and the finding payload share one
/// taxonomy.
///
/// Construction is unchecked — `validate()` is the single enforcement
/// point. The application layer calls it after assembling a finding
/// from scanner output and rejects the entire scan run on failure.
/// `Deserialize` never re-runs validation: events round-tripped from
/// the event-store JSONB column must accept any shape that was once
/// written.
//
// SAFETY: `Deserialize` is required, not optional. `Finding` is
// reconstructed from JSON in two non-API code paths that both round-trip
// values *we ourselves wrote*:
//   1. `quarantine_use_case::hydrate_prior_findings` reads the CAS-stored
//      `findings_blob` written by a previous `ScanCompleted` and parses
//      `Vec<Finding>` out of it (the hash-referenced per-finding
//      blob).
//   2. `hort-adapters-advisory-osv` caches OSV query results as JSON-encoded
//      `Vec<Finding>` in Redis to absorb the daily-diff scan storm.
// Neither path crosses an HTTP boundary — both deserialise bytes the
// service produced. The usual no-`Deserialize`
// `assert_not_impl_any!` lock would be
// inappropriate here; the no-API-deser invariant is held by the absence
// of any `Finding` field on the per-format HTTP request types instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub purl: String,
    pub vulnerability_id: String,
    pub severity: SeverityThreshold,
    pub cvss_score: Option<f32>,
    pub title: String,
    pub fixed_versions: Vec<String>,
    pub source_scanner: String,
    pub references: Vec<String>,
    /// Alternate identifiers for the same vulnerability, e.g. the CVE
    /// id when `vulnerability_id` is a GHSA primary. OSV publishes
    /// these via `vulns[].aliases`; Trivy publishes them via
    /// `VendorIDs`. Used by
    /// [`crate::policy::exclusion::cve_matches`] so an operator
    /// exclusion keyed by CVE-id matches a finding whose primary id
    /// is the corresponding GHSA (and vice versa). The original
    /// design treated `vulnerability_id`
    /// as an opaque string, but the operator-facing exclusion
    /// surface needs cross-id resolution to honour the "exclude this
    /// CVE" promise against any scanner that primaries on GHSA /
    /// OSV id.
    ///
    /// `#[serde(default)]` for round-trip compatibility with
    /// in-flight events / cached blobs written before this field
    /// landed. The `Deserialize` impl never re-runs `validate()`, so
    /// a payload missing this field deserialises with the default
    /// empty vec — same posture as every other shape-evolution on
    /// this struct.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The raw OSV `database_specific.informational` class verbatim — the
    /// fact the advisory database published, not a derived interpretation.
    /// RustSec/OSV informational advisories carry `"unmaintained"`,
    /// `"unsound"`, or `"notice"` here (under `affected[].database_specific`
    /// for full records); these are maintenance signals published without a
    /// CVSS score by design, not exploitable defects. `None` means a scored
    /// vulnerability — no informational marker.
    ///
    /// Persisting the class string (the fact) rather than a derived boolean
    /// keeps the interpretation re-derivable: a future per-class policy
    /// (e.g. block `unsound`, ignore `unmaintained`) can re-evaluate from
    /// stored findings, which a baked-in boolean would have lost. The
    /// boolean is derived on demand via [`Finding::is_informational`].
    ///
    /// Informational findings are routed onto the non-enforcing
    /// **negligible** lane by [`severity_summary_from_findings`] and the
    /// post-exclusion block-decision summary, so they never trip a
    /// severity threshold. `severity` is cosmetic for these (the OSV
    /// adapters map it to `Low`); the negligible routing — keyed on
    /// [`Finding::is_informational`], not on `severity` — is what makes them
    /// non-blocking.
    ///
    /// `#[serde(default)]` for round-trip compatibility with events /
    /// cached blobs written before this field landed: a payload missing
    /// it deserialises as `None` (a scored vulnerability), the same
    /// no-re-validation posture as every other shape-evolution on this
    /// struct.
    #[serde(default)]
    pub informational_class: Option<String>,
}

/// Recognises the OSV `database_specific.informational` classes that mark a
/// finding as informational rather than a scored vulnerability:
/// `unmaintained` / `unsound` / `notice` (ASCII case-insensitive). This is
/// the canonical recognizer shared by the OSV adapters (which decide the
/// finding's severity from it) and the negligible-lane routing
/// ([`Finding::is_informational`]); a finding's raw informational class is
/// persisted, and this function re-derives the boolean interpretation from
/// it at decision time. Any other (or absent) value is not informational,
/// preserving the SUP-4 fail-closed Critical fallback for genuinely-unscored
/// vulnerabilities.
pub fn is_informational_class(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "unmaintained" | "unsound" | "notice"
    )
}

/// Per-tier count over `findings` — single source of truth
/// for the `ScanCompleted.severity_summary` aggregate. Lifted from
/// previously-duplicated copies in `hort-app::scan_orchestration` and
/// `hort-app::quarantine_use_case` so both
/// callers reuse one helper. A finding for which
/// [`Finding::is_informational`] holds is counted in `negligible` (the
/// non-enforcing lane) regardless of its cosmetic `severity`; the
/// `SeverityThreshold` enum has no Negligible variant — informational
/// is a property of the finding, not a severity tier.
pub fn severity_summary_from_findings(findings: &[Finding]) -> SeveritySummary {
    let mut s = SeveritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        negligible: 0,
    };
    for f in findings {
        if f.is_informational() {
            s.negligible += 1;
            continue;
        }
        match f.severity {
            SeverityThreshold::Critical => s.critical += 1,
            SeverityThreshold::High => s.high += 1,
            SeverityThreshold::Medium => s.medium += 1,
            SeverityThreshold::Low => s.low += 1,
        }
    }
    s
}

/// Lowercase wire string for the `severity` metric label.
/// Mirrors `SeverityThreshold`'s `Display` impl exactly so the catalog
/// stays the single source of truth. Lifted
/// from the previously-duplicated copies in
/// `hort-app::scan_orchestration` and `hort-app::quarantine_use_case`.
pub fn severity_label(s: SeverityThreshold) -> &'static str {
    match s {
        SeverityThreshold::Critical => "critical",
        SeverityThreshold::High => "high",
        SeverityThreshold::Medium => "medium",
        SeverityThreshold::Low => "low",
    }
}

/// Pick the highest severity tier among `findings`.
/// `Critical > High > Medium > Low`. Returns `None` for an empty slice.
/// The
/// `hort_artifact_became_vulnerable_total.severity` label takes the top
/// tier of the post-delta `new_findings` set. Lifted into the domain
/// crate so the orchestrator and quarantine use
/// cases share one helper.
pub fn highest_severity(findings: &[Finding]) -> Option<SeverityThreshold> {
    let mut best: Option<SeverityThreshold> = None;
    for f in findings {
        let tier = severity_tier(f.severity);
        let best_tier = best.map(severity_tier);
        if best_tier.map(|bt| tier < bt).unwrap_or(true) {
            best = Some(f.severity);
        }
    }
    best
}

/// Numeric tier where `0 = Critical` and `3 = Low`. Lower number =
/// higher severity. Internal helper for [`highest_severity`] and the
/// `merge_findings` collision policy in `hort-app::scan_orchestration`.
fn severity_tier(s: SeverityThreshold) -> u8 {
    match s {
        SeverityThreshold::Critical => 0,
        SeverityThreshold::High => 1,
        SeverityThreshold::Medium => 2,
        SeverityThreshold::Low => 3,
    }
}

impl Finding {
    /// Whether this finding is informational — derived at decision time
    /// from the persisted [`Finding::informational_class`] fact via the
    /// canonical [`is_informational_class`] recognizer. `None` (a scored
    /// vulnerability) or an unrecognised class is not informational.
    /// Routing onto the non-enforcing negligible lane keys on this, not on
    /// `severity`.
    ///
    /// A finding carrying any `cvss_score` is never informational, even
    /// with a recognised class: informational advisories carry no CVSS
    /// by design, so a scored finding stays on the enforced lane
    /// regardless of any class string. Gating on the absence of a CVSS
    /// score preserves the fail-closed posture — a genuinely-scored
    /// vulnerability cannot be demoted off the threshold gate.
    pub fn is_informational(&self) -> bool {
        self.cvss_score.is_none()
            && self
                .informational_class
                .as_deref()
                .is_some_and(is_informational_class)
    }

    /// Validate the per-finding length caps.
    /// Returns `DomainError::Validation` naming the offending field
    /// and its observed size on failure. Lengths are byte-counted via
    /// `String::len()` and `Vec::len()`.
    pub fn validate(&self) -> DomainResult<()> {
        if self.purl.len() > MAX_PURL_LEN {
            return Err(DomainError::Validation(format!(
                "Finding.purl is {} bytes, max is {}",
                self.purl.len(),
                MAX_PURL_LEN,
            )));
        }
        if self.vulnerability_id.len() > MAX_VULNERABILITY_ID_LEN {
            return Err(DomainError::Validation(format!(
                "Finding.vulnerability_id is {} bytes, max is {}",
                self.vulnerability_id.len(),
                MAX_VULNERABILITY_ID_LEN,
            )));
        }
        if self.title.len() > MAX_TITLE_LEN {
            return Err(DomainError::Validation(format!(
                "Finding.title is {} bytes, max is {}",
                self.title.len(),
                MAX_TITLE_LEN,
            )));
        }
        if self.fixed_versions.len() > MAX_FIXED_VERSIONS {
            return Err(DomainError::Validation(format!(
                "Finding.fixed_versions has {} entries, max is {}",
                self.fixed_versions.len(),
                MAX_FIXED_VERSIONS,
            )));
        }
        if self.references.len() > MAX_REFERENCES {
            return Err(DomainError::Validation(format!(
                "Finding.references has {} entries, max is {}",
                self.references.len(),
                MAX_REFERENCES,
            )));
        }
        if self.aliases.len() > MAX_ALIASES {
            return Err(DomainError::Validation(format!(
                "Finding.aliases has {} entries, max is {}",
                self.aliases.len(),
                MAX_ALIASES,
            )));
        }
        for (idx, alias) in self.aliases.iter().enumerate() {
            if alias.len() > MAX_VULNERABILITY_ID_LEN {
                return Err(DomainError::Validation(format!(
                    "Finding.aliases[{idx}] is {} bytes, max is {}",
                    alias.len(),
                    MAX_VULNERABILITY_ID_LEN,
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_finding() -> Finding {
        Finding {
            purl: "pkg:npm/lodash@4.17.20".into(),
            vulnerability_id: "CVE-2021-23337".into(),
            severity: SeverityThreshold::High,
            cvss_score: Some(7.2),
            title: "Command Injection in lodash".into(),
            fixed_versions: vec!["4.17.21".into()],
            source_scanner: "trivy".into(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".into()],
            aliases: vec!["GHSA-35jh-r3h4-6jhm".into()],
            informational_class: None,
        }
    }

    // ----- Serde round-trips -----------------------------------------------

    #[test]
    fn finding_round_trips_through_serde_when_fully_populated() {
        let f = valid_finding();
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn finding_round_trips_with_empty_optional_and_collection_fields() {
        let f = Finding {
            purl: "pkg:cargo/anyhow@1.0.0".into(),
            vulnerability_id: "GHSA-aaaa-bbbb-cccc".into(),
            severity: SeverityThreshold::Low,
            cvss_score: None,
            title: "advisory".into(),
            fixed_versions: vec![],
            source_scanner: "osv".into(),
            references: vec![],
            aliases: vec![],
            informational_class: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn finding_deserialises_with_default_aliases_when_field_absent() {
        // `aliases` is `#[serde(default)]`
        // so an event / cached blob written before the field landed
        // round-trips with an empty alias list rather than failing to
        // deserialise. Mirrors the no-re-validation posture of every
        // other shape-evolution on this struct.
        let legacy_json = r#"{
            "purl": "pkg:npm/lodash@4.17.20",
            "vulnerability_id": "GHSA-35jh-r3h4-6jhm",
            "severity": "High",
            "cvss_score": null,
            "title": "Command Injection in lodash",
            "fixed_versions": ["4.17.21"],
            "source_scanner": "osv",
            "references": []
        }"#;
        let back: Finding = serde_json::from_str(legacy_json).unwrap();
        assert!(back.aliases.is_empty());
        assert_eq!(back.vulnerability_id, "GHSA-35jh-r3h4-6jhm");
    }

    #[test]
    fn validate_accepts_aliases_at_cap() {
        let mut f = valid_finding();
        f.aliases = (0..MAX_ALIASES).map(|i| format!("CVE-2024-{i}")).collect();
        assert!(f.validate().is_ok());
    }

    #[test]
    fn validate_rejects_aliases_over_cap() {
        let mut f = valid_finding();
        f.aliases = (0..(MAX_ALIASES + 1))
            .map(|i| format!("CVE-2024-{i}"))
            .collect();
        let err = f.validate().unwrap_err();
        assert!(err.to_string().contains("aliases"), "{err}");
    }

    #[test]
    fn validate_rejects_overlong_alias_element() {
        let mut f = valid_finding();
        f.aliases = vec!["a".repeat(MAX_VULNERABILITY_ID_LEN + 1)];
        let err = f.validate().unwrap_err();
        assert!(err.to_string().contains("aliases[0]"), "{err}");
    }

    // ----- validate() — at-cap (passes) ------------------------------------

    #[test]
    fn validate_accepts_purl_at_exactly_512_bytes() {
        let mut f = valid_finding();
        f.purl = "a".repeat(MAX_PURL_LEN);
        assert_eq!(f.purl.len(), 512);
        f.validate().unwrap();
    }

    #[test]
    fn validate_accepts_vulnerability_id_at_exactly_128_bytes() {
        let mut f = valid_finding();
        f.vulnerability_id = "a".repeat(MAX_VULNERABILITY_ID_LEN);
        assert_eq!(f.vulnerability_id.len(), 128);
        f.validate().unwrap();
    }

    #[test]
    fn validate_accepts_title_at_exactly_1024_bytes() {
        let mut f = valid_finding();
        f.title = "a".repeat(MAX_TITLE_LEN);
        assert_eq!(f.title.len(), 1024);
        f.validate().unwrap();
    }

    #[test]
    fn validate_accepts_fixed_versions_at_exactly_32_entries() {
        let mut f = valid_finding();
        f.fixed_versions = (0..MAX_FIXED_VERSIONS).map(|i| i.to_string()).collect();
        assert_eq!(f.fixed_versions.len(), 32);
        f.validate().unwrap();
    }

    #[test]
    fn validate_accepts_references_at_exactly_32_entries() {
        let mut f = valid_finding();
        f.references = (0..MAX_REFERENCES).map(|i| i.to_string()).collect();
        assert_eq!(f.references.len(), 32);
        f.validate().unwrap();
    }

    // ----- validate() — at-cap-plus-one (rejects) --------------------------

    #[test]
    fn validate_rejects_purl_at_513_bytes() {
        let mut f = valid_finding();
        f.purl = "a".repeat(MAX_PURL_LEN + 1);
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("purl"), "{msg}");
        assert!(msg.contains("513"), "{msg}");
    }

    #[test]
    fn validate_rejects_vulnerability_id_at_129_bytes() {
        let mut f = valid_finding();
        f.vulnerability_id = "a".repeat(MAX_VULNERABILITY_ID_LEN + 1);
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("vulnerability_id"), "{msg}");
        assert!(msg.contains("129"), "{msg}");
    }

    #[test]
    fn validate_rejects_title_at_1025_bytes() {
        let mut f = valid_finding();
        f.title = "a".repeat(MAX_TITLE_LEN + 1);
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("title"), "{msg}");
        assert!(msg.contains("1025"), "{msg}");
    }

    #[test]
    fn validate_rejects_fixed_versions_at_33_entries() {
        let mut f = valid_finding();
        f.fixed_versions = (0..=MAX_FIXED_VERSIONS).map(|i| i.to_string()).collect();
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("fixed_versions"), "{msg}");
        assert!(msg.contains("33"), "{msg}");
    }

    #[test]
    fn validate_rejects_references_at_33_entries() {
        let mut f = valid_finding();
        f.references = (0..=MAX_REFERENCES).map(|i| i.to_string()).collect();
        let err = f.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("references"), "{msg}");
        assert!(msg.contains("33"), "{msg}");
    }

    // ----- validate() — happy path -----------------------------------------

    #[test]
    fn validate_accepts_a_non_trivial_valid_finding() {
        let f = valid_finding();
        f.validate().unwrap();
    }

    // ----- Re-export reachability (mirrors the checksum precedent) ---------

    #[test]
    fn finding_is_re_exported_from_types_module() {
        // The mod.rs convention re-exports public types so callers can
        // write `crate::types::Finding` rather than
        // `crate::types::finding::Finding`. This test is a compile-time
        // assertion via a type alias — if the re-export disappears, the
        // alias fails to resolve and compilation breaks.
        // `unused_qualifications` would normally flag this because
        // `Finding` is in scope via `super::*`; here the explicit path
        // is the test, so allow it.
        #[allow(unused_qualifications)]
        type _Reexported = crate::types::Finding;
    }

    // ----- severity_summary_from_findings ----------------------------------

    #[test]
    fn severity_summary_from_findings_buckets_each_tier() {
        // Mixed input across all four `SeverityThreshold` tiers — the
        // helper must bucket each finding into the correct counter and
        // leave `negligible` at zero (the enum has no Negligible variant
        // today; the field stays for forward compatibility with the
        // event schema).
        let findings = vec![
            Finding {
                purl: "pkg:npm/a@1".into(),
                vulnerability_id: "CVE-A".into(),
                severity: SeverityThreshold::Critical,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            },
            Finding {
                purl: "pkg:npm/b@1".into(),
                vulnerability_id: "CVE-B".into(),
                severity: SeverityThreshold::High,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            },
            Finding {
                purl: "pkg:npm/c@1".into(),
                vulnerability_id: "CVE-C".into(),
                severity: SeverityThreshold::High,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            },
            Finding {
                purl: "pkg:npm/d@1".into(),
                vulnerability_id: "CVE-D".into(),
                severity: SeverityThreshold::Medium,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            },
            Finding {
                purl: "pkg:npm/e@1".into(),
                vulnerability_id: "CVE-E".into(),
                severity: SeverityThreshold::Low,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            },
        ];
        let s = severity_summary_from_findings(&findings);
        assert_eq!(
            s,
            SeveritySummary {
                critical: 1,
                high: 2,
                medium: 1,
                low: 1,
                negligible: 0,
            }
        );
    }

    #[test]
    fn severity_summary_from_findings_returns_zeros_for_empty_input() {
        let s = severity_summary_from_findings(&[]);
        assert_eq!(
            s,
            SeveritySummary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            }
        );
    }

    #[test]
    fn severity_summary_routes_informational_to_negligible_regardless_of_severity() {
        // An informational finding is counted in `negligible` (the
        // non-enforcing lane) even though its cosmetic `severity` is a real
        // tier — the routing is keyed on `is_informational()` (derived from
        // the class), not on `severity`. A Critical-tier informational
        // finding must NOT land in the critical bucket, or it would block
        // under the default threshold. Informational advisories carry no
        // CVSS score by design, so the fixture has `cvss_score = None`.
        let mut critical_but_informational = valid_finding();
        critical_but_informational.severity = SeverityThreshold::Critical;
        critical_but_informational.cvss_score = None;
        critical_but_informational.informational_class = Some("unmaintained".to_string());

        let mut real_critical = valid_finding();
        real_critical.severity = SeverityThreshold::Critical;
        real_critical.informational_class = None;

        let s = severity_summary_from_findings(&[critical_but_informational, real_critical]);
        assert_eq!(
            s,
            SeveritySummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 1,
            }
        );
    }

    #[test]
    fn scored_finding_with_informational_class_stays_enforced() {
        // A finding carrying BOTH a real `cvss_score` AND a recognised
        // informational class must NOT route onto the negligible lane —
        // informational advisories carry no CVSS by design, so a scored
        // finding stays on the enforced lane (ADR 0040 §4). Demoting it
        // would let a scored Critical escape the threshold gate.
        let scored_but_classed = Finding {
            cvss_score: Some(9.0),
            informational_class: Some("unmaintained".to_string()),
            severity: SeverityThreshold::Critical,
            ..valid_finding()
        };
        assert!(
            !scored_but_classed.is_informational(),
            "a scored finding is never informational, regardless of class"
        );

        let s = severity_summary_from_findings(&[scored_but_classed]);
        assert_eq!(
            s,
            SeveritySummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                negligible: 0,
            },
            "a scored Critical with a class counts as critical, not negligible"
        );
    }

    #[test]
    fn finding_deserialises_with_default_informational_class_none_when_field_absent() {
        // `informational_class` is `#[serde(default)]`: a legacy event /
        // cached blob written before the field landed must round-trip as
        // `None` (a scored vulnerability), preserving fail-closed behaviour
        // for old findings.
        let legacy_json = r#"{
            "purl": "pkg:cargo/proc-macro-error2@2.0.1",
            "vulnerability_id": "RUSTSEC-2026-0173",
            "severity": "Critical",
            "cvss_score": null,
            "title": "unmaintained",
            "fixed_versions": [],
            "source_scanner": "osv",
            "references": [],
            "aliases": []
        }"#;
        let back: Finding = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(back.informational_class, None);
        assert!(!back.is_informational());
    }

    #[test]
    fn is_informational_class_recognises_the_three_classes_and_rejects_others() {
        // The canonical recognizer: case-insensitive `unmaintained` /
        // `unsound` / `notice`; everything else (including a made-up class)
        // is not informational.
        assert!(is_informational_class("unmaintained"));
        assert!(is_informational_class("unsound"));
        assert!(is_informational_class("notice"));
        assert!(is_informational_class("UNMAINTAINED"));
        assert!(is_informational_class("  Unsound  "));
        assert!(!is_informational_class("some-future-class"));
        assert!(!is_informational_class(""));
        assert!(!is_informational_class("critical"));
    }

    #[test]
    fn is_informational_derives_the_boolean_from_the_persisted_class() {
        // A recognised class → informational; `None` or a made-up class → not.
        // The made-up string is stored verbatim (the fact) but does not flip
        // the derived boolean — the interpretation lives in the recognizer,
        // not in the stored value. Informational advisories carry no CVSS
        // score by design, so the fixture clears `cvss_score`.
        let mut f = valid_finding();
        f.cvss_score = None;
        f.informational_class = Some("unsound".to_string());
        assert!(f.is_informational());

        f.informational_class = Some("some-future-class".to_string());
        assert_eq!(
            f.informational_class.as_deref(),
            Some("some-future-class"),
            "the raw class is stored verbatim"
        );
        assert!(!f.is_informational());

        f.informational_class = None;
        assert!(!f.is_informational());
    }

    #[test]
    fn severity_label_maps_each_tier_to_its_lowercase_wire_string() {
        // Mirrors the metric-catalog label values exactly so the
        // catalog stays the single source of truth (the registry's
        // `severity` label is one of `critical|high|medium|low`).
        assert_eq!(severity_label(SeverityThreshold::Critical), "critical");
        assert_eq!(severity_label(SeverityThreshold::High), "high");
        assert_eq!(severity_label(SeverityThreshold::Medium), "medium");
        assert_eq!(severity_label(SeverityThreshold::Low), "low");
    }

    #[test]
    fn highest_severity_picks_the_top_tier() {
        let findings = vec![
            Finding {
                purl: "pkg:npm/a@1".into(),
                vulnerability_id: "CVE-A".into(),
                severity: SeverityThreshold::Low,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            },
            Finding {
                purl: "pkg:npm/b@1".into(),
                vulnerability_id: "CVE-B".into(),
                severity: SeverityThreshold::High,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            },
            Finding {
                purl: "pkg:npm/c@1".into(),
                vulnerability_id: "CVE-C".into(),
                severity: SeverityThreshold::Medium,
                cvss_score: None,
                title: "t".into(),
                fixed_versions: vec![],
                source_scanner: "trivy".into(),
                references: vec![],
                aliases: vec![],
                informational_class: None,
            },
        ];
        assert_eq!(highest_severity(&findings), Some(SeverityThreshold::High));
    }

    #[test]
    fn highest_severity_returns_none_for_empty_input() {
        assert_eq!(highest_severity(&[]), None);
    }

    // ----- Deserialise without re-validation -------------------------------

    #[test]
    fn finding_deserialises_without_revalidation() {
        // Mirrors `published_checksum_deserializes_without_re_validating`.
        // A finding with a 600-byte purl exceeds MAX_PURL_LEN but the
        // event-store contract says serde must accept any shape that
        // was once written; only validate() rejects.
        let big_purl = "x".repeat(600);
        let raw = serde_json::json!({
            "purl": big_purl,
            "vulnerability_id": "CVE-2024-99999",
            "severity": "High",
            "cvss_score": null,
            "title": "title",
            "fixed_versions": [],
            "source_scanner": "trivy",
            "references": [],
        })
        .to_string();
        let parsed: Finding = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.purl.len(), 600);
        // ... and validate() rejects the same value.
        let err = parsed.validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }
}
