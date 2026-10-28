//! The **finding-age anchor** — how long the vulnerability has been
//! known.
//!
//! [`PolicyPredicate::HasFindingDetectedFor`](super::PolicyPredicate::HasFindingDetectedFor)
//! is the grace-period leg of the canonical operator policy
//! `Composite(And, [HasFindingAboveSeverity, HasFixAvailable,
//! HasFindingDetectedFor(7d)])` — "delete what has carried a fixable
//! severe finding for a week". A match **expires the artifact**: the
//! evaluator returns `Matched` and the retention path appends
//! `ArtifactExpired`.
//!
//! The question the predicate asks is about the **vulnerability**, not
//! about us: the longer a vulnerability has been public, the likelier it
//! is exploited, and that is what an operator's grace period is pricing.
//! Nothing in an artifact's own scan history answers it. An anchor taken
//! from the artifact's first scan dates *when we started looking*, so a
//! finding that appeared yesterday on a long-scanned artifact satisfies
//! "seven days" immediately and the artifact is expired on the next
//! pass — the maximum possible age, asserted from no evidence, by a
//! predicate that deletes.
//!
//! ## The ladder, per vulnerability
//!
//! For each `vulnerability_id` the artifact's **last scan** reported:
//!
//! 1. the advisory's **publication date**
//!    ([`Finding::advisory_published_at`]) — the upstream fact, and the
//!    only source that dates the vulnerability itself. Where several
//!    backends report the same vulnerability with different dates, the
//!    **earliest wins** and the backend that supplied it is recorded;
//! 2. else **our own first observation** of that vulnerability on that
//!    artifact — `MIN(scan_findings.detected_at)` over every scan,
//!    supplied by the caller. Later than publication by construction,
//!    and therefore the non-deleting reading;
//! 3. else nothing: that vulnerability contributes no anchor.
//!
//! The artifact's anchor is then the **earliest** of its vulnerabilities'
//! known-since dates. A newly-published advisory must not make an
//! artifact that has carried a year-old one look young, which is exactly
//! what resolving the ladder artifact-wide rather than per-vulnerability
//! would do.
//!
//! **No anchor at all ⇒ the predicate does not match.** This is the rule
//! `RetentionUseCase::scan_is_fresh` already applies one question over:
//! a security predicate must never expire an artifact whose evidence is
//! unprovable. An unprovable *age* gets the same answer — not the
//! largest value available.
//!
//! ## Why the minimum, and why provenance travels with it
//!
//! The minimum is the security-conservative reading of a disagreement
//! (the vulnerability has been known at least that long), and it mirrors
//! the quarantine anchor's "minimum of the applicable age sources, which
//! may move the anchor earlier and never later" (ADR 0054). It is not
//! *robust*: one feed dating systematically early drags every anchor
//! forward. The mitigation is that the chosen date never travels without
//! the source that supplied it — [`FindingAgeAnchor::source`] reaches the
//! persisted `ArtifactExpired` reason, so a skewed feed is diagnosable
//! from the expiry record instead of being a decision nobody can
//! re-derive.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::Finding;

/// Which source supplied the chosen [`FindingAgeAnchor::known_since`].
///
/// Serialised into the `ArtifactExpired` reason, so the variants are a
/// wire form: add, never rename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingAgeAnchorSource {
    /// An advisory publication date, as reported by the named backend
    /// ([`Finding::source_scanner`] of the finding that carried the
    /// winning date). The string is the **feed**, not the adapter: both
    /// the osv-scanner backend and the OSV advisory-enrichment path
    /// report `"osv"`.
    AdvisoryPublication(String),
    /// Our own earliest observation of the vulnerability on this
    /// artifact — no backend published a date for any of its
    /// vulnerabilities.
    FirstObservation,
}

/// How long the vulnerability has been known, and where that date came
/// from. One scalar per artifact: the earliest known-since date across
/// the vulnerabilities its last scan reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingAgeAnchor {
    /// The date from which the elapsed-time comparison runs.
    pub known_since: DateTime<Utc>,
    /// The source that supplied [`Self::known_since`].
    pub source: FindingAgeAnchorSource,
}

/// Resolve the artifact's finding-age anchor from its last scan's
/// findings plus our own first observation of each vulnerability.
///
/// Pure: `first_observed` is the caller's (app-layer) read of
/// `MIN(scan_findings.detected_at)` per
/// (`artifact_id`, `vulnerability_id`), keyed by **lowercased**
/// vulnerability id — the same case-insensitive identity the
/// cross-backend finding merge uses, so one feed spelling `ghsa-…` and
/// another `GHSA-…` are one vulnerability here too.
///
/// `None` means no source dated any of the artifact's vulnerabilities,
/// and [`PolicyPredicate::HasFindingDetectedFor`](super::PolicyPredicate::HasFindingDetectedFor)
/// then does not match.
///
/// The two rungs are a **priority, not a comparison**: a vulnerability
/// with a publication date uses it even where our own observation of
/// that vulnerability is earlier. The upstream date is a statement about
/// the advisory; our observation is only a bound on it, and a bound is
/// not evidence against the thing it bounds. The minimum is taken
/// *across* a vulnerability's sources and *across* the artifact's
/// vulnerabilities, never between the two rungs of one vulnerability.
///
/// Equal dates resolve deterministically rather than by a rule anyone
/// has to remember: the comparisons are strict and the iteration order
/// is the findings list's, so the first-listed of two tied candidates
/// keeps the anchor.
pub fn resolve_finding_age_anchor(
    findings: &[Finding],
    first_observed: &[(String, DateTime<Utc>)],
) -> Option<FindingAgeAnchor> {
    let mut best: Option<FindingAgeAnchor> = None;
    for vuln_id in distinct_vulnerability_ids(findings) {
        let per_vuln = published_anchor(findings, &vuln_id)
            .or_else(|| observed_anchor(first_observed, &vuln_id));
        let Some(candidate) = per_vuln else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|b| candidate.known_since < b.known_since)
        {
            best = Some(candidate);
        }
    }
    best
}

/// The artifact's vulnerability ids, lowercased and de-duplicated, in
/// first-seen order.
///
/// **Public because the caller has to key its port read with exactly
/// this set.** The ids the app layer asks
/// [`RetentionScanReader::first_observed_at`](crate::ports::retention_scan_reader::RetentionScanReader::first_observed_at)
/// about and the ids this module folds over have to be the same ids: a
/// query keyed case-sensitively against a fold keyed case-insensitively
/// would silently drop an earlier observation recorded under the other
/// spelling, and nothing would report it. One definition, two callers.
///
/// Lowercased because that is the vulnerability identity the
/// cross-backend finding merge already uses, so one feed spelling
/// `ghsa-…` and another `GHSA-…` are one vulnerability here too.
///
/// Order only decides which of two *equal* dates keeps the anchor, and
/// the comparison in [`resolve_finding_age_anchor`] is strict, so the
/// winner is the first-listed of the tied vulnerabilities —
/// deterministic for a given findings list.
pub fn distinct_vulnerability_ids(findings: &[Finding]) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for f in findings {
        let id = f.vulnerability_id.to_ascii_lowercase();
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// Rung 1 for one vulnerability: the earliest publication date any
/// backend reported for it, carrying that backend's name.
fn published_anchor(findings: &[Finding], vuln_id: &str) -> Option<FindingAgeAnchor> {
    findings
        .iter()
        .filter(|f| f.vulnerability_id.eq_ignore_ascii_case(vuln_id))
        .filter_map(|f| f.advisory_published_at.map(|at| (at, &f.source_scanner)))
        .min_by_key(|(at, _)| *at)
        .map(|(at, scanner)| FindingAgeAnchor {
            known_since: at,
            source: FindingAgeAnchorSource::AdvisoryPublication(scanner.clone()),
        })
}

/// Rung 2 for one vulnerability: our own first observation of it.
fn observed_anchor(
    first_observed: &[(String, DateTime<Utc>)],
    vuln_id: &str,
) -> Option<FindingAgeAnchor> {
    first_observed
        .iter()
        .filter(|(id, _)| id.eq_ignore_ascii_case(vuln_id))
        .map(|(_, at)| *at)
        .min()
        .map(|at| FindingAgeAnchor {
            known_since: at,
            source: FindingAgeAnchorSource::FirstObservation,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::scan_policy::SeverityThreshold;
    use crate::types::{ComponentRelation, FindingStatement, SeverityBasis};

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("ts")
    }

    fn finding(vuln: &str, scanner: &str, published: Option<DateTime<Utc>>) -> Finding {
        Finding {
            purl: format!("pkg:npm/x@1#{vuln}"),
            vulnerability_id: vuln.into(),
            severity: SeverityThreshold::High,
            cvss_score: Some(7.0),
            title: "t".into(),
            fixed_versions: vec![],
            source_scanner: scanner.into(),
            references: vec![],
            aliases: vec![],
            informational_class: None,
            severity_basis: SeverityBasis::Assessed,
            component_relation: ComponentRelation::NotEstablished,
            statement: FindingStatement::Unstated,
            advisory_published_at: published,
        }
    }

    // -- rung 3: no anchor --------------------------------------------------

    /// The case the whole decision exists for: nothing dated the
    /// vulnerability, so there is no anchor and the predicate cannot
    /// match. The old ladder answered `created_at` here and deleted.
    #[test]
    fn no_publication_and_no_observation_yields_no_anchor() {
        let f = [finding("CVE-1", "trivy", None)];
        assert_eq!(resolve_finding_age_anchor(&f, &[]), None);
    }

    #[test]
    fn no_findings_yields_no_anchor() {
        assert_eq!(
            resolve_finding_age_anchor(&[], &[("cve-1".into(), ts(0))]),
            None
        );
    }

    /// An observation for a vulnerability the last scan no longer
    /// reports must not become this artifact's anchor: the caller keys
    /// its read on the last scan's ids, and the fold ignores anything
    /// else it is handed.
    #[test]
    fn observation_for_an_unreported_vulnerability_is_ignored() {
        let f = [finding("CVE-1", "trivy", None)];
        let observed = [("cve-retracted".into(), ts(0))];
        assert_eq!(resolve_finding_age_anchor(&f, &observed), None);
    }

    // -- rung 2: our own first observation ---------------------------------

    #[test]
    fn falls_back_to_first_observation_when_nothing_published_a_date() {
        let f = [finding("CVE-1", "trivy", None)];
        let observed = [("cve-1".into(), ts(500))];
        assert_eq!(
            resolve_finding_age_anchor(&f, &observed),
            Some(FindingAgeAnchor {
                known_since: ts(500),
                source: FindingAgeAnchorSource::FirstObservation,
            })
        );
    }

    /// The caller's key is lowercased; the finding's id keeps whatever
    /// case its backend used. The two have to meet.
    #[test]
    fn observation_lookup_is_case_insensitive() {
        let f = [finding("GHSA-Abcd", "osv", None)];
        let observed = [("ghsa-abcd".into(), ts(500))];
        assert_eq!(
            resolve_finding_age_anchor(&f, &observed)
                .expect("anchor")
                .known_since,
            ts(500)
        );
    }

    /// Two observation rows for the same vulnerability (the caller may
    /// group case-insensitively or not) collapse to the earliest.
    #[test]
    fn duplicate_observation_rows_collapse_to_the_earliest() {
        let f = [finding("CVE-1", "trivy", None)];
        let observed = [("cve-1".into(), ts(900)), ("CVE-1".into(), ts(400))];
        assert_eq!(
            resolve_finding_age_anchor(&f, &observed)
                .expect("anchor")
                .known_since,
            ts(400)
        );
    }

    // -- rung 1: the advisory's publication date ---------------------------

    #[test]
    fn publication_date_beats_a_later_observation() {
        let f = [finding("CVE-1", "osv", Some(ts(100)))];
        let observed = [("cve-1".into(), ts(500))];
        assert_eq!(
            resolve_finding_age_anchor(&f, &observed),
            Some(FindingAgeAnchor {
                known_since: ts(100),
                source: FindingAgeAnchorSource::AdvisoryPublication("osv".into()),
            })
        );
    }

    /// Rung 1 is consulted before rung 2 for a vulnerability, so a
    /// publication date is used even when it is LATER than our own
    /// observation of the same vulnerability. The upstream fact is the
    /// better statement about the vulnerability; our observation is only
    /// a bound on it.
    #[test]
    fn publication_date_is_used_even_when_later_than_the_observation() {
        let f = [finding("CVE-1", "osv", Some(ts(900)))];
        let observed = [("cve-1".into(), ts(100))];
        assert_eq!(
            resolve_finding_age_anchor(&f, &observed),
            Some(FindingAgeAnchor {
                known_since: ts(900),
                source: FindingAgeAnchorSource::AdvisoryPublication("osv".into()),
            })
        );
    }

    /// Two backends, one vulnerability, two dates: the earliest wins and
    /// the stored provenance names the backend it came from.
    #[test]
    fn earliest_publication_date_wins_across_sources_with_its_provenance() {
        let f = [
            finding("CVE-1", "trivy", Some(ts(900))),
            finding("CVE-1", "osv", Some(ts(300))),
        ];
        assert_eq!(
            resolve_finding_age_anchor(&f, &[]),
            Some(FindingAgeAnchor {
                known_since: ts(300),
                source: FindingAgeAnchorSource::AdvisoryPublication("osv".into()),
            })
        );
    }

    /// Same pair the other way round, so the result is the earliest date
    /// rather than the first- or last-listed finding.
    #[test]
    fn earliest_publication_date_wins_irrespective_of_order() {
        let f = [
            finding("CVE-1", "osv", Some(ts(300))),
            finding("CVE-1", "trivy", Some(ts(900))),
        ];
        assert_eq!(
            resolve_finding_age_anchor(&f, &[]).expect("anchor").source,
            FindingAgeAnchorSource::AdvisoryPublication("osv".into())
        );
    }

    /// One backend dated it, another did not. The dated one supplies the
    /// anchor; the undated sibling does not drag it to rung 2.
    #[test]
    fn a_dated_sibling_supplies_the_anchor_for_an_undated_one() {
        let f = [
            finding("CVE-1", "trivy", None),
            finding("CVE-1", "osv", Some(ts(300))),
        ];
        assert_eq!(
            resolve_finding_age_anchor(&f, &[("cve-1".into(), ts(999))]),
            Some(FindingAgeAnchor {
                known_since: ts(300),
                source: FindingAgeAnchorSource::AdvisoryPublication("osv".into()),
            })
        );
    }

    // -- the artifact-wide fold --------------------------------------------

    /// A freshly-published advisory must not make an artifact that also
    /// carries a long-known one look young: the ladder runs per
    /// vulnerability and the artifact takes the earliest result.
    #[test]
    fn a_fresh_advisory_does_not_mask_a_long_observed_one() {
        let f = [
            finding("CVE-NEW", "osv", Some(ts(950))),
            finding("CVE-OLD", "trivy", None),
        ];
        let observed = [("cve-old".into(), ts(10))];
        assert_eq!(
            resolve_finding_age_anchor(&f, &observed),
            Some(FindingAgeAnchor {
                known_since: ts(10),
                source: FindingAgeAnchorSource::FirstObservation,
            })
        );
    }

    /// And the reverse: a long-published advisory wins over a
    /// recently-observed sibling.
    #[test]
    fn the_earliest_of_several_vulnerabilities_wins() {
        let f = [
            finding("CVE-A", "osv", Some(ts(700))),
            finding("CVE-B", "osv", Some(ts(200))),
            finding("CVE-C", "trivy", None),
        ];
        let observed = [("cve-c".into(), ts(800))];
        assert_eq!(
            resolve_finding_age_anchor(&f, &observed),
            Some(FindingAgeAnchor {
                known_since: ts(200),
                source: FindingAgeAnchorSource::AdvisoryPublication("osv".into()),
            })
        );
    }

    /// One vulnerability contributes nothing (rung 3) while another
    /// does: the artifact still gets an anchor rather than none.
    #[test]
    fn an_undatable_vulnerability_does_not_veto_a_datable_sibling() {
        let f = [
            finding("CVE-A", "trivy", None),
            finding("CVE-B", "osv", Some(ts(200))),
        ];
        assert_eq!(
            resolve_finding_age_anchor(&f, &[])
                .expect("anchor")
                .known_since,
            ts(200)
        );
    }

    /// The same vulnerability id spelled two ways is one vulnerability,
    /// matching the cross-backend merge's case-insensitive identity.
    #[test]
    fn mixed_case_ids_are_one_vulnerability() {
        let f = [
            finding("GHSA-xyz", "osv", Some(ts(400))),
            finding("GHSA-XYZ", "trivy", Some(ts(100))),
        ];
        assert_eq!(
            resolve_finding_age_anchor(&f, &[]),
            Some(FindingAgeAnchor {
                known_since: ts(100),
                source: FindingAgeAnchorSource::AdvisoryPublication("trivy".into()),
            })
        );
    }

    /// Equal dates: the strict comparison keeps the first-resolved
    /// vulnerability's anchor, so the result does not depend on a
    /// tiebreak nobody specified.
    #[test]
    fn equal_dates_keep_the_first_resolved_anchor() {
        let f = [
            finding("CVE-A", "osv", Some(ts(300))),
            finding("CVE-B", "trivy", Some(ts(300))),
        ];
        assert_eq!(
            resolve_finding_age_anchor(&f, &[]).expect("anchor").source,
            FindingAgeAnchorSource::AdvisoryPublication("osv".into())
        );
    }

    // -- value-type surface ------------------------------------------------

    /// The key set the caller must query with: lowercased,
    /// de-duplicated, first-seen order.
    #[test]
    fn distinct_vulnerability_ids_lowercases_and_dedups_in_order() {
        let f = [
            finding("GHSA-Xyz", "osv", None),
            finding("CVE-1", "trivy", None),
            finding("ghsa-xyz", "trivy", None),
        ];
        assert_eq!(distinct_vulnerability_ids(&f), ["ghsa-xyz", "cve-1"]);
    }

    #[test]
    fn distinct_vulnerability_ids_of_no_findings_is_empty() {
        assert!(distinct_vulnerability_ids(&[]).is_empty());
    }

    #[test]
    fn anchor_source_round_trips_through_serde() {
        for src in [
            FindingAgeAnchorSource::AdvisoryPublication("osv".into()),
            FindingAgeAnchorSource::FirstObservation,
        ] {
            let json = serde_json::to_string(&src).expect("serialize");
            let back: FindingAgeAnchorSource = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(src, back);
        }
    }

    /// The wire spellings are persisted in `ArtifactExpired` reasons, so
    /// they are pinned rather than left to the derive.
    #[test]
    fn anchor_source_wire_spellings_are_pinned() {
        assert_eq!(
            serde_json::to_string(&FindingAgeAnchorSource::AdvisoryPublication("osv".into()))
                .expect("serialize"),
            r#"{"AdvisoryPublication":"osv"}"#
        );
        assert_eq!(
            serde_json::to_string(&FindingAgeAnchorSource::FirstObservation).expect("serialize"),
            r#""FirstObservation""#
        );
    }

    #[test]
    fn anchor_is_debug_and_clone() {
        let a = FindingAgeAnchor {
            known_since: ts(1),
            source: FindingAgeAnchorSource::FirstObservation,
        };
        assert_eq!(a.clone(), a);
        assert!(format!("{a:?}").contains("FindingAgeAnchor"));
    }
}
