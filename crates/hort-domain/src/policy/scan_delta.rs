//! Delta computation for newly-vulnerable detection.
//!
//! Pure function — no I/O, no `Utc::now`, no allocation beyond the
//! returned `Vec<Finding>`. The caller is responsible for loading
//! `prior` (the most recent prior `ScanCompleted` payload's findings,
//! hydrated from CAS via `findings_blob`) and `current` (the assembled
//! findings of the run that's about to be appended).
//!
//! See `docs/architecture/explanation/scanning-pipeline.md`.

use std::collections::HashSet;

use crate::types::Finding;

/// Return the findings present in `current` that were absent from
/// `prior`, keyed on `(purl, vulnerability_id)` with case-sensitive
/// PURL and case-insensitive vulnerability id (`CVE-2024-12345 ==
/// cve-2024-12345`). Returned findings appear in the order they appear
/// in `current` — order-stable.
///
/// # Boundary semantics
/// - empty `prior`, non-empty `current` → returns `current.to_vec()`.
/// - non-empty `prior`, empty `current` → returns `vec![]`.
/// - both empty → returns `vec![]`.
/// - identical sets → `vec![]`.
/// - `prior` strictly subset → returns the diff in `current`'s order.
/// - `prior` strictly superset → `vec![]` (no additions).
///
/// # Case rules
/// - PURL is **case-sensitive**: `pkg:NPM/foo@1` != `pkg:npm/foo@1`.
///   Two such entries are different components by design — PURL
///   canonicalisation is upstream's responsibility.
/// - Vulnerability ID is **case-insensitive**: `CVE-2024-1` ==
///   `cve-2024-1`. Aligned with the OSV convention.
///
/// # Duplicates
/// `current` is not deduplicated by this function. If `current`
/// contains two equal `(purl, vulnerability_id)` rows that are absent
/// from `prior`, both come through. Deduplication is the orchestrator's
/// concern (it dedupes across scanner backends before persistence).
pub fn compute_added_findings<'a>(prior: &'a [Finding], current: &'a [Finding]) -> Vec<Finding> {
    if current.is_empty() {
        return Vec::new();
    }
    // Borrow `purl` directly — the prior set lives only as long as
    // this function call, so we can key on `&str` and avoid cloning
    // every PURL once per prior finding (and again on every lookup).
    // Vulnerability IDs are case-folded for comparison, which forces
    // an owned `String` for that half of the key.
    let prior_keys: HashSet<(&'a str, String)> = prior
        .iter()
        .map(|f| (f.purl.as_str(), f.vulnerability_id.to_ascii_lowercase()))
        .collect();
    current
        .iter()
        .filter(|f| {
            !prior_keys.contains(&(f.purl.as_str(), f.vulnerability_id.to_ascii_lowercase()))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::scan_policy::SeverityThreshold;

    fn finding(purl: &str, vuln: &str) -> Finding {
        Finding {
            purl: purl.into(),
            vulnerability_id: vuln.into(),
            severity: SeverityThreshold::High,
            cvss_score: None,
            title: "t".into(),
            fixed_versions: vec![],
            source_scanner: "trivy".into(),
            references: vec![],
            aliases: vec![],
        }
    }

    #[test]
    fn compute_added_findings_returns_current_when_prior_is_empty() {
        let current = vec![
            finding("pkg:npm/a@1", "CVE-1"),
            finding("pkg:npm/b@2", "CVE-2"),
        ];
        let out = compute_added_findings(&[], &current);
        assert_eq!(out, current);
    }

    #[test]
    fn compute_added_findings_returns_empty_when_current_is_empty() {
        let prior = vec![finding("pkg:npm/a@1", "CVE-1")];
        let out = compute_added_findings(&prior, &[]);
        assert!(out.is_empty());
    }

    #[test]
    fn compute_added_findings_returns_empty_when_both_empty() {
        let out = compute_added_findings(&[], &[]);
        assert!(out.is_empty());
    }

    #[test]
    fn compute_added_findings_returns_empty_when_sets_identical() {
        let v = vec![
            finding("pkg:npm/a@1", "CVE-1"),
            finding("pkg:npm/b@2", "CVE-2"),
        ];
        let out = compute_added_findings(&v, &v);
        assert!(out.is_empty());
    }

    #[test]
    fn compute_added_findings_returns_diff_when_prior_strict_subset() {
        let prior = vec![finding("pkg:npm/a@1", "CVE-1")];
        // Order chosen so we can assert order-preservation: c, b, d
        let current = vec![
            finding("pkg:npm/c@3", "CVE-3"),
            finding("pkg:npm/a@1", "CVE-1"),
            finding("pkg:npm/b@2", "CVE-2"),
            finding("pkg:npm/d@4", "CVE-4"),
        ];
        let out = compute_added_findings(&prior, &current);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].vulnerability_id, "CVE-3");
        assert_eq!(out[1].vulnerability_id, "CVE-2");
        assert_eq!(out[2].vulnerability_id, "CVE-4");
    }

    #[test]
    fn compute_added_findings_returns_empty_when_prior_strict_superset() {
        let prior = vec![
            finding("pkg:npm/a@1", "CVE-1"),
            finding("pkg:npm/b@2", "CVE-2"),
            finding("pkg:npm/c@3", "CVE-3"),
        ];
        let current = vec![finding("pkg:npm/a@1", "CVE-1")];
        let out = compute_added_findings(&prior, &current);
        assert!(out.is_empty());
    }

    #[test]
    fn compute_added_findings_returns_just_new_ids_with_partial_overlap() {
        let prior = vec![
            finding("pkg:npm/a@1", "CVE-1"),
            finding("pkg:npm/b@2", "CVE-2"),
        ];
        let current = vec![
            finding("pkg:npm/a@1", "CVE-1"),
            finding("pkg:npm/b@2", "CVE-NEW"),
            finding("pkg:npm/c@3", "CVE-3"),
        ];
        let out = compute_added_findings(&prior, &current);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].vulnerability_id, "CVE-NEW");
        assert_eq!(out[0].purl, "pkg:npm/b@2");
        assert_eq!(out[1].vulnerability_id, "CVE-3");
    }

    #[test]
    fn compute_added_findings_treats_vulnerability_id_case_insensitive() {
        let prior = vec![finding("pkg:npm/a@1", "CVE-2024-1")];
        let current = vec![finding("pkg:npm/a@1", "cve-2024-1")];
        let out = compute_added_findings(&prior, &current);
        assert!(
            out.is_empty(),
            "case-insensitive vuln-id match must suppress the addition; got {out:?}"
        );
    }

    #[test]
    fn compute_added_findings_treats_purl_case_sensitive() {
        let prior = vec![finding("pkg:NPM/foo@1", "CVE-1")];
        let current = vec![finding("pkg:npm/foo@1", "CVE-1")];
        let out = compute_added_findings(&prior, &current);
        assert_eq!(
            out.len(),
            1,
            "case-sensitive PURL distinguishes pkg:NPM/foo@1 from pkg:npm/foo@1"
        );
        assert_eq!(out[0].purl, "pkg:npm/foo@1");
    }

    #[test]
    fn compute_added_findings_handles_duplicates_within_current() {
        // Function doesn't dedupe `current` — orchestrator's job. Both
        // identical entries come through.
        let prior: Vec<Finding> = vec![];
        let dup = finding("pkg:npm/a@1", "CVE-1");
        let current = vec![dup.clone(), dup.clone()];
        let out = compute_added_findings(&prior, &current);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], dup);
        assert_eq!(out[1], dup);
    }
}
