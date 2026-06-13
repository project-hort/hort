//! Exclusion filter for scan findings.
//!
//! This module
//! takes the per-finding result of a scan (`&[Finding]`) plus the active
//! exclusion set, drops findings matched by an active exclusion, and
//! returns the surviving findings, the post-exclusion `SeveritySummary`
//! (computed from the survivors — single source of truth), and audit
//! metadata (which exclusions matched, how many findings were dropped).
//!
//! Exact CVE-ID matching against `ExclusionProjection.cve_id`.
//!
//! ## Matching rules
//!
//! 1. An exclusion is **active** when its `expires_at` is `None` or
//!    strictly in the future relative to the supplied `now`. Equality at
//!    the boundary (`expires_at == now`) is treated as expired —
//!    `expires_at > now` is the active predicate.
//! 2. An exclusion **matches a finding** when:
//!    - its `cve_id` equals `finding.vulnerability_id` ASCII
//!      case-insensitively (`CVE-2024-1` == `cve-2024-1`, mirroring the
//!      case rule in [`crate::policy::scan_delta::compute_added_findings`]);
//!      AND
//!    - its `package_pattern` is `None` ("global pattern") OR matches
//!      the artifact's `coords.name` via the simple `*`-glob matcher
//!      [`pattern_matches`].
//! 3. A finding is dropped when **at least one** active+matching
//!    exclusion exists. Multiple exclusions matching the same finding
//!    each appear in `matched_exclusion_ids` — operators want the full
//!    audit trail.
//!
//! ## Glob matcher
//!
//! `pattern_matches` is a deliberately tiny `*`-only matcher — `*`
//! matches any (possibly empty) substring, every other character is
//! literal. Patterns without `*` collapse to exact-string equality.
//! Two-character classes (`?`, character ranges) and the full glob
//! grammar are out of scope for v1 — the YAML schema accepted by the
//! gitops admission validation documents the supported syntax. This
//! matcher avoids a glob/regex dependency in `hort-domain`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::scan_policy::{ExclusionProjection, SeverityThreshold};
use crate::events::SeveritySummary;
use crate::types::{ArtifactCoords, Finding};

/// Result of [`filter_excluded_findings`]: the surviving findings, the
/// derived post-exclusion severity summary, plus audit metadata for
/// caller observability.
///
/// `remaining_findings` is the un-excluded subset of the input vec, in
/// the input's order. `remaining` is the per-tier count over
/// `remaining_findings` (single source of truth — no separate aggregate
/// supplied by the caller). `excluded_count` is exactly
/// `findings.len() - remaining_findings.len()`.
/// `matched_exclusion_ids` records every active+matching exclusion id
/// whose match fired against at least one finding, deduplicated and in
/// first-fire order.
#[derive(Debug, Clone, PartialEq)]
pub struct FilteredFindings {
    pub remaining: SeveritySummary,
    pub remaining_findings: Vec<Finding>,
    pub excluded_count: u32,
    pub matched_exclusion_ids: Vec<Uuid>,
}

/// Filters per-finding scan output against the active+matching subset
/// of `exclusions`. See module rustdoc for the matching rules.
pub fn filter_excluded_findings(
    findings: &[Finding],
    exclusions: &[ExclusionProjection],
    coords: &ArtifactCoords,
    now: DateTime<Utc>,
) -> FilteredFindings {
    let mut remaining_findings: Vec<Finding> = Vec::with_capacity(findings.len());
    let mut matched_exclusion_ids: Vec<Uuid> = Vec::new();

    for f in findings {
        let mut drop_finding = false;
        for ex in exclusions {
            if !is_active(ex, now) {
                continue;
            }
            if !cve_matches(ex, f) {
                continue;
            }
            if !matches_coords(ex, coords) {
                continue;
            }
            // Active + CVE-id match + package match.
            drop_finding = true;
            if !matched_exclusion_ids.contains(&ex.exclusion_id) {
                matched_exclusion_ids.push(ex.exclusion_id);
            }
        }
        if !drop_finding {
            remaining_findings.push(f.clone());
        }
    }

    let remaining = summary_of(&remaining_findings);
    let excluded_count = (findings.len() - remaining_findings.len()) as u32;

    FilteredFindings {
        remaining,
        remaining_findings,
        excluded_count,
        matched_exclusion_ids,
    }
}

/// Per-tier count over `findings`. Single source of truth for the
/// post-exclusion summary returned in [`FilteredFindings::remaining`].
/// `negligible` is always zero — `Finding.severity` is a
/// [`SeverityThreshold`] which has no `Negligible` variant; the v1
/// scanner mapping never emits findings in that tier.
fn summary_of(findings: &[Finding]) -> SeveritySummary {
    let mut s = SeveritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        negligible: 0,
    };
    for f in findings {
        match f.severity {
            SeverityThreshold::Critical => s.critical += 1,
            SeverityThreshold::High => s.high += 1,
            SeverityThreshold::Medium => s.medium += 1,
            SeverityThreshold::Low => s.low += 1,
        }
    }
    s
}

/// Returns true when the exclusion is active relative to `now`.
/// `expires_at: None` means "never expires." A timestamp at or before
/// `now` deactivates the exclusion (an expiry of "right now" means
/// "expired now"; the predicate is `expires_at > now`).
fn is_active(ex: &ExclusionProjection, now: DateTime<Utc>) -> bool {
    match ex.expires_at {
        None => true,
        Some(expires_at) => expires_at > now,
    }
}

/// Returns true when the exclusion's CVE id matches the finding's
/// primary `vulnerability_id` **or any of its `aliases`**, ASCII
/// case-insensitively. `CVE-2024-1` == `cve-2024-1` mirrors the case
/// rule in [`crate::policy::scan_delta::compute_added_findings`].
///
/// Scanners disagree on which identifier
/// is "primary". OSV primaries on the GHSA / OSV-* id and carries the
/// CVE in `aliases`; Trivy usually primaries on the CVE but
/// vendor-advisory entries (RHSA, ALAS, …) carry the CVE in
/// `VendorIDs` (lowered into `aliases`). An operator-typed exclusion
/// is keyed by the human-facing CVE id — without the alias check a
/// `cveId: CVE-2021-23337` exclusion would silently fail to match a
/// `vulnerability_id = GHSA-…` finding, which is the exact gap that
/// once left the scanning smoke test's re-evaluation leg unable to
/// clear an OSV-produced rejection. The check is symmetric: an exclusion
/// keyed by a GHSA matches a finding whose CVE is primary and whose
/// GHSA sits in `aliases`.
fn cve_matches(ex: &ExclusionProjection, f: &Finding) -> bool {
    if ex.cve_id.eq_ignore_ascii_case(&f.vulnerability_id) {
        return true;
    }
    f.aliases
        .iter()
        .any(|alias| ex.cve_id.eq_ignore_ascii_case(alias))
}

/// Returns true when the exclusion's package_pattern (or absence of
/// it) matches the artifact's `coords.name`.
fn matches_coords(ex: &ExclusionProjection, coords: &ArtifactCoords) -> bool {
    match ex.package_pattern.as_deref() {
        None => true, // unscoped exclusion matches any package
        Some(pattern) => pattern_matches(pattern, &coords.name),
    }
}

/// Aggregate-summary exclusion filter — used by the
/// promotion and post-exclusion-add re-evaluation paths
/// ([`crate::policy::evaluate_promotion`],
/// [`crate::policy::re_evaluate_after_exclusion`]) which receive a
/// historical [`SeveritySummary`] reconstructed from the artifact's
/// most recent `ScanCompleted` event rather than per-finding rows.
///
/// The per-scan path uses
/// [`filter_excluded_findings`] with `&[Finding]` for exact CVE-ID
/// matching. The promotion + re-eval paths do not have findings
/// readily available (the use cases work off `read_last_scan_summary`
/// which surfaces the cached aggregate); this helper preserves the
/// original highest-tier-first decrement semantics for those callers.
///
/// The semantics: each active+pattern-matching exclusion decrements
/// **one count** from the highest non-zero severity tier in the
/// summary (Critical → High → Medium → Low). `negligible` is never
/// decremented because it never enforces (see
/// [`crate::policy::threshold`]). If every meaningful tier is already
/// zero the exclusion has no effect on the summary but is still
/// recorded in `matched_exclusion_ids` for audit.
pub fn filter_excluded_summary(
    summary: &SeveritySummary,
    exclusions: &[ExclusionProjection],
    coords: &ArtifactCoords,
    now: DateTime<Utc>,
) -> FilteredSummary {
    let mut remaining = summary.clone();
    let mut excluded_count = 0u32;
    let mut matched_exclusion_ids = Vec::new();

    for ex in exclusions {
        if !is_active(ex, now) {
            continue;
        }
        if !matches_coords(ex, coords) {
            continue;
        }

        matched_exclusion_ids.push(ex.exclusion_id);

        if remaining.critical > 0 {
            remaining.critical -= 1;
            excluded_count += 1;
        } else if remaining.high > 0 {
            remaining.high -= 1;
            excluded_count += 1;
        } else if remaining.medium > 0 {
            remaining.medium -= 1;
            excluded_count += 1;
        } else if remaining.low > 0 {
            remaining.low -= 1;
            excluded_count += 1;
        }
    }

    FilteredSummary {
        remaining,
        excluded_count,
        matched_exclusion_ids,
    }
}

/// Result of [`filter_excluded_summary`]. Mirrors [`FilteredFindings`]
/// minus the `remaining_findings` slice (the aggregate-summary path
/// has no per-finding granularity to surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredSummary {
    pub remaining: SeveritySummary,
    pub excluded_count: u32,
    pub matched_exclusion_ids: Vec<Uuid>,
}

/// Tiny `*`-only glob matcher. `*` matches any (possibly empty)
/// substring, every other character is literal. See module rustdoc
/// for the rationale.
pub(crate) fn pattern_matches(pattern: &str, name: &str) -> bool {
    // Greedy backtracking implementation — adequate for short package
    // names and short patterns. Worst-case `O(name * pattern)`; the
    // YAML admission webhook caps `package_pattern` length at 512
    // characters.
    let p_bytes = pattern.as_bytes();
    let n_bytes = name.as_bytes();
    matches_inner(p_bytes, n_bytes)
}

fn matches_inner(pattern: &[u8], name: &[u8]) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    if pattern[0] == b'*' {
        // `*` matches the empty string, or any prefix of `name`.
        for split in 0..=name.len() {
            if matches_inner(&pattern[1..], &name[split..]) {
                return true;
            }
        }
        return false;
    }
    if name.is_empty() {
        return false;
    }
    if pattern[0] != name[0] {
        return false;
    }
    matches_inner(&pattern[1..], &name[1..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::repository::RepositoryFormat;
    use crate::events::PolicyScope;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("fixed timestamp")
    }

    fn coords(name: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.to_string(),
            name_as_published: name.to_string(),
            version: None,
            path: format!("/{name}"),
            format: RepositoryFormat::Npm,
            metadata: serde_json::Value::Null,
        }
    }

    fn exclusion(
        id: u128,
        cve_id: &str,
        package_pattern: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> ExclusionProjection {
        ExclusionProjection {
            exclusion_id: Uuid::from_u128(id),
            policy_id: Uuid::from_u128(0xfeed),
            cve_id: cve_id.to_string(),
            package_pattern: package_pattern.map(str::to_string),
            scope: PolicyScope::Global,
            reason: "test".into(),
            added_by_actor_id: None,
            expires_at,
        }
    }

    fn finding(vuln: &str, sev: SeverityThreshold) -> Finding {
        Finding {
            purl: format!("pkg:npm/{}@1", vuln.to_ascii_lowercase()),
            vulnerability_id: vuln.into(),
            severity: sev,
            cvss_score: None,
            title: "t".into(),
            fixed_versions: vec![],
            source_scanner: "trivy".into(),
            references: vec![],
            aliases: vec![],
        }
    }

    /// Finding whose primary id is `primary` (e.g. a GHSA) and whose
    /// `aliases` carry `alias` (e.g. the CVE id). Models the OSV
    /// scanner's id shape so the alias-matching tests reflect the
    /// real producer.
    fn finding_with_alias(primary: &str, alias: &str, sev: SeverityThreshold) -> Finding {
        Finding {
            purl: "pkg:npm/lodash@4.17.20".into(),
            vulnerability_id: primary.into(),
            severity: sev,
            cvss_score: None,
            title: "t".into(),
            fixed_versions: vec![],
            source_scanner: "osv".into(),
            references: vec![],
            aliases: vec![alias.into()],
        }
    }

    fn empty_summary() -> SeveritySummary {
        SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        }
    }

    // ---- pattern_matches helper -------------------------------------------

    #[test]
    fn pattern_matches_exact_string() {
        assert!(pattern_matches("xz-utils", "xz-utils"));
        assert!(!pattern_matches("xz-utils", "xz"));
        assert!(!pattern_matches("xz", "xz-utils"));
    }

    #[test]
    fn pattern_matches_star_at_end() {
        assert!(pattern_matches("xz-*", "xz-utils"));
        assert!(pattern_matches("xz-*", "xz-"));
        assert!(!pattern_matches("xz-*", "lz-utils"));
    }

    #[test]
    fn pattern_matches_star_at_start() {
        assert!(pattern_matches("*-utils", "xz-utils"));
        assert!(pattern_matches("*-utils", "-utils"));
        assert!(!pattern_matches("*-utils", "xz-tools"));
    }

    #[test]
    fn pattern_matches_star_in_middle() {
        assert!(pattern_matches("xz*utils", "xzutils"));
        assert!(pattern_matches("xz*utils", "xz-some-utils"));
        assert!(!pattern_matches("xz*utils", "xz"));
    }

    #[test]
    fn pattern_matches_lone_star_matches_any() {
        assert!(pattern_matches("*", ""));
        assert!(pattern_matches("*", "anything"));
    }

    #[test]
    fn pattern_matches_double_star_treated_as_two_stars() {
        // No special handling of `**` — equivalent to `*`. Adequate
        // for v1; if operators want recursive globs they can land a
        // future glob-engine swap.
        assert!(pattern_matches("**", "anything"));
        assert!(pattern_matches("xz**", "xz-utils"));
    }

    #[test]
    fn pattern_matches_empty_pattern_only_matches_empty() {
        assert!(pattern_matches("", ""));
        assert!(!pattern_matches("", "x"));
    }

    // ---- filter_excluded_findings: empty / no exclusions ------------------

    #[test]
    fn empty_findings_yields_empty_remaining() {
        let r = filter_excluded_findings(&[], &[], &coords("xz-utils"), ts(0));
        assert_eq!(r.remaining, empty_summary());
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 0);
        assert!(r.matched_exclusion_ids.is_empty());
    }

    #[test]
    fn no_exclusions_passthrough_with_full_summary_recomputation() {
        let findings = vec![
            finding("CVE-A", SeverityThreshold::Critical),
            finding("CVE-B", SeverityThreshold::High),
            finding("CVE-C", SeverityThreshold::Medium),
            finding("CVE-D", SeverityThreshold::Low),
        ];
        let r = filter_excluded_findings(&findings, &[], &coords("xz-utils"), ts(0));
        assert_eq!(r.remaining_findings, findings);
        assert_eq!(
            r.remaining,
            SeveritySummary {
                critical: 1,
                high: 1,
                medium: 1,
                low: 1,
                negligible: 0,
            }
        );
        assert_eq!(r.excluded_count, 0);
        assert!(r.matched_exclusion_ids.is_empty());
    }

    // ---- one matching exclusion -------------------------------------------

    #[test]
    fn one_matching_exclusion_drops_one_finding() {
        let findings = vec![
            finding("CVE-A", SeverityThreshold::Critical),
            finding("CVE-B", SeverityThreshold::High),
        ];
        let exs = vec![exclusion(1, "CVE-A", Some("xz-*"), None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("xz-utils"), ts(0));
        assert_eq!(r.remaining_findings.len(), 1);
        assert_eq!(r.remaining_findings[0].vulnerability_id, "CVE-B");
        assert_eq!(
            r.remaining,
            SeveritySummary {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                negligible: 0,
            }
        );
        assert_eq!(r.excluded_count, 1);
        assert_eq!(r.matched_exclusion_ids, vec![Uuid::from_u128(1)]);
    }

    #[test]
    fn exclusion_not_matching_cve_keeps_finding() {
        let findings = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-DIFFERENT", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), ts(0));
        assert_eq!(r.remaining_findings, findings);
        assert_eq!(r.excluded_count, 0);
        assert!(r.matched_exclusion_ids.is_empty());
    }

    #[test]
    fn exclusion_with_non_matching_package_pattern_keeps_finding() {
        let findings = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", Some("nothing*"), None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("xz-utils"), ts(0));
        assert_eq!(r.remaining_findings, findings);
        assert_eq!(r.excluded_count, 0);
        assert!(r.matched_exclusion_ids.is_empty());
    }

    // ---- expiry ------------------------------------------------------------

    #[test]
    fn expired_exclusion_does_not_drop() {
        let now = ts(2_000_000);
        let findings = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, Some(ts(1_000_000)))];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), now);
        assert_eq!(r.remaining_findings, findings);
        assert_eq!(r.excluded_count, 0);
        assert!(r.matched_exclusion_ids.is_empty());
    }

    #[test]
    fn at_expiry_exact_now_is_expired() {
        // expires_at == now → expired (strictly-greater check).
        let now = ts(2_000_000);
        let findings = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, Some(now))];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), now);
        assert_eq!(r.remaining_findings, findings);
        assert_eq!(r.excluded_count, 0);
    }

    #[test]
    fn future_expiry_is_active() {
        let now = ts(1_000_000);
        let future = ts(2_000_000);
        let findings = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, Some(future))];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), now);
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
    }

    #[test]
    fn no_expiry_is_always_active() {
        let findings = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), ts(0));
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
    }

    // ---- case-insensitive CVE id matching ---------------------------------

    #[test]
    fn cve_id_match_is_case_insensitive_lowercase_finding() {
        let findings = vec![finding("cve-2024-1", SeverityThreshold::High)];
        let exs = vec![exclusion(1, "CVE-2024-1", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), ts(0));
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
    }

    #[test]
    fn cve_id_match_is_case_insensitive_lowercase_exclusion() {
        let findings = vec![finding("CVE-2024-1", SeverityThreshold::High)];
        let exs = vec![exclusion(1, "cve-2024-1", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), ts(0));
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
    }

    #[test]
    fn package_pattern_glob_matches_lodash_with_lo_star() {
        let findings = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-A", Some("lo*"), None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("lodash"), ts(0));
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
    }

    // ---- multiple findings and exclusions ---------------------------------

    #[test]
    fn multiple_findings_one_matching_exclusion_drops_only_that_finding() {
        // Three findings, exclusion matches only one of them.
        let findings = vec![
            finding("CVE-A", SeverityThreshold::Critical),
            finding("CVE-B", SeverityThreshold::High),
            finding("CVE-C", SeverityThreshold::Medium),
        ];
        let exs = vec![exclusion(1, "CVE-B", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), ts(0));
        assert_eq!(r.remaining_findings.len(), 2);
        let ids: Vec<&str> = r
            .remaining_findings
            .iter()
            .map(|f| f.vulnerability_id.as_str())
            .collect();
        assert_eq!(ids, vec!["CVE-A", "CVE-C"]);
        assert_eq!(r.excluded_count, 1);
        assert_eq!(r.matched_exclusion_ids, vec![Uuid::from_u128(1)]);
    }

    #[test]
    fn multiple_exclusions_each_drops_a_distinct_finding() {
        let findings = vec![
            finding("CVE-A", SeverityThreshold::Critical),
            finding("CVE-B", SeverityThreshold::High),
            finding("CVE-C", SeverityThreshold::Medium),
        ];
        let exs = vec![
            exclusion(1, "CVE-A", None, None),
            exclusion(2, "CVE-C", None, None),
        ];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), ts(0));
        assert_eq!(r.remaining_findings.len(), 1);
        assert_eq!(r.remaining_findings[0].vulnerability_id, "CVE-B");
        assert_eq!(r.excluded_count, 2);
        assert_eq!(
            r.matched_exclusion_ids,
            vec![Uuid::from_u128(1), Uuid::from_u128(2)]
        );
    }

    #[test]
    fn two_exclusions_matching_same_finding_each_recorded_finding_dropped_once() {
        // Two exclusions for the same CVE — both recorded in the audit
        // trail; the finding is dropped once (set semantics).
        let findings = vec![finding("CVE-A", SeverityThreshold::Critical)];
        let exs = vec![
            exclusion(1, "CVE-A", None, None),
            exclusion(2, "cve-a", None, None),
        ];
        let r = filter_excluded_findings(&findings, &exs, &coords("any"), ts(0));
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
        assert_eq!(
            r.matched_exclusion_ids,
            vec![Uuid::from_u128(1), Uuid::from_u128(2)]
        );
    }

    // ---- mixed expired / non-matching / matching --------------------------

    #[test]
    fn mixed_exclusion_set_only_active_matching_fires() {
        let now = ts(2_000_000);
        let findings = vec![
            finding("CVE-A", SeverityThreshold::Critical),
            finding("CVE-B", SeverityThreshold::High),
        ];
        let exs = vec![
            exclusion(1, "CVE-A", Some("nothing*"), None), // non-matching pattern
            exclusion(2, "CVE-A", Some("xz-*"), Some(ts(0))), // expired
            exclusion(3, "CVE-A", Some("xz-*"), None),     // active + matching
            exclusion(4, "CVE-B", None, None),             // active + global match
        ];
        let r = filter_excluded_findings(&findings, &exs, &coords("xz-utils"), now);
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 2);
        assert_eq!(
            r.matched_exclusion_ids,
            vec![Uuid::from_u128(3), Uuid::from_u128(4)]
        );
    }

    // ---- pattern interactions --------------------------------------------

    #[test]
    fn pattern_match_against_artifact_name_not_path() {
        // Make sure we match on `coords.name`, not `coords.path`.
        let mut c = coords("evil-package");
        c.path = "/different/path/evil-package".into();
        let findings = vec![finding("CVE-X", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-X", Some("evil-*"), None)];
        let r = filter_excluded_findings(&findings, &exs, &c, ts(0));
        assert_eq!(r.excluded_count, 1);
    }

    #[test]
    fn unscoped_exclusion_matches_every_package() {
        let findings = vec![finding("CVE-X", SeverityThreshold::Critical)];
        let exs = vec![exclusion(1, "CVE-X", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("anything"), ts(0));
        assert_eq!(r.excluded_count, 1);
    }

    // ---- alias matching ----------------------------------------------------

    #[test]
    fn cve_exclusion_matches_ghsa_primary_via_alias() {
        // The OSV-shaped case that broke the scanning smoke: finding's
        // primary id is the GHSA, the CVE lives in `aliases`. An
        // operator-typed `cveId: CVE-2021-23337` exclusion must clear
        // it.
        let findings = vec![finding_with_alias(
            "GHSA-35jh-r3h4-6jhm",
            "CVE-2021-23337",
            SeverityThreshold::High,
        )];
        let exs = vec![exclusion(1, "CVE-2021-23337", Some("lodash"), None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("lodash"), ts(0));
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
        assert_eq!(r.matched_exclusion_ids, vec![Uuid::from_u128(1)]);
    }

    #[test]
    fn cve_alias_match_is_case_insensitive() {
        let findings = vec![finding_with_alias(
            "GHSA-aaaa-bbbb-cccc",
            "CVE-2021-23337",
            SeverityThreshold::High,
        )];
        let exs = vec![exclusion(1, "cve-2021-23337", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("anything"), ts(0));
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
    }

    #[test]
    fn ghsa_exclusion_matches_cve_primary_via_alias_symmetric() {
        // Symmetric direction: finding primaries on the CVE, GHSA in
        // aliases (Trivy-vendor-advisory shape). An exclusion keyed by
        // the GHSA must still match.
        let findings = vec![finding_with_alias(
            "CVE-2021-23337",
            "GHSA-35jh-r3h4-6jhm",
            SeverityThreshold::High,
        )];
        let exs = vec![exclusion(1, "GHSA-35jh-r3h4-6jhm", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("anything"), ts(0));
        assert!(r.remaining_findings.is_empty());
        assert_eq!(r.excluded_count, 1);
    }

    #[test]
    fn exclusion_not_in_primary_or_aliases_keeps_finding() {
        // Defence: a CVE that is neither the primary nor any alias must
        // NOT drop the finding (the bug we are guarding against is an
        // over-broad alias match, not just the under-broad one).
        let findings = vec![finding_with_alias(
            "GHSA-35jh-r3h4-6jhm",
            "CVE-2021-23337",
            SeverityThreshold::High,
        )];
        let exs = vec![exclusion(1, "CVE-2020-28500", None, None)];
        let r = filter_excluded_findings(&findings, &exs, &coords("lodash"), ts(0));
        assert_eq!(r.remaining_findings, findings);
        assert_eq!(r.excluded_count, 0);
        assert!(r.matched_exclusion_ids.is_empty());
    }

    #[test]
    fn one_exclusion_per_distinct_cve_clears_multi_vuln_package() {
        // The full lodash@4.17.20 shape after OSV dataset drift: five
        // distinct CVEs, each carried as the alias of a distinct GHSA
        // primary. Five exclusions (one per CVE) clear all five — the
        // realistic operator workflow the updated smoke fixture
        // exercises.
        let findings = vec![
            finding_with_alias(
                "GHSA-29mw-wpgm-hmr9",
                "CVE-2020-28500",
                SeverityThreshold::Medium,
            ),
            finding_with_alias(
                "GHSA-35jh-r3h4-6jhm",
                "CVE-2021-23337",
                SeverityThreshold::High,
            ),
            finding_with_alias(
                "GHSA-f23m-r3pf-42rh",
                "CVE-2026-2950",
                SeverityThreshold::High,
            ),
            finding_with_alias(
                "GHSA-r5fr-rjxr-66jc",
                "CVE-2026-4800",
                SeverityThreshold::Medium,
            ),
            finding_with_alias(
                "GHSA-xxjr-mmjv-4gpg",
                "CVE-2025-13465",
                SeverityThreshold::Medium,
            ),
        ];
        let exs = vec![
            exclusion(1, "CVE-2020-28500", Some("lodash"), None),
            exclusion(2, "CVE-2021-23337", Some("lodash"), None),
            exclusion(3, "CVE-2026-2950", Some("lodash"), None),
            exclusion(4, "CVE-2026-4800", Some("lodash"), None),
            exclusion(5, "CVE-2025-13465", Some("lodash"), None),
        ];
        let r = filter_excluded_findings(&findings, &exs, &coords("lodash"), ts(0));
        assert!(
            r.remaining_findings.is_empty(),
            "all five findings should be cleared; survivors: {:?}",
            r.remaining_findings
        );
        assert_eq!(r.excluded_count, 5);
    }
}
