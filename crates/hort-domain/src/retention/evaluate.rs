//! Pure retention-predicate evaluator.
//!
//! This is the **security boundary** of retention: deciding whether an
//! artifact matches a [`PolicyPredicate`] against a snapshot of its
//! scan findings + age + usage, and producing the
//! [`ExpirationReason`] that goes onto the `ArtifactExpired` event.
//! It is pure (zero I/O, zero clock, zero `tracing`/metrics) so the
//! `hort-domain` 100%-coverage tier exhaustively pins every match arm,
//! every threshold boundary, and every `Composite` combination.
//!
//! The app layer ([`hort-app`'s `RetentionUseCase`]) owns the I/O:
//! reading the projection rows, the §6-invariant-7 freshness gate, the
//! `(policy_id, artifact_id)` idempotency check, the §6-invariant-1
//! quarantine/rejected filter, the `HasFindingDetectedFor` stream
//! anchor, and event append + metrics. It calls [`evaluate`] with the
//! already-resolved inputs.
//!
//! ## §4-vs-code divergence — `HasFixAvailable`
//!
//! §4 sources `HasFixAvailable` from "a non-empty `fixed_versions`
//! array on its source advisory". The v1 `scan_findings` projection
//! does not carry `fixed_versions` (see
//! [`crate::ports::retention_scan_reader`] module docs), so with the
//! projection-only adapter every [`Finding::fixed_versions`] is empty
//! and `HasFixAvailable` never matches. The predicate logic here is
//! still written against `fixed_versions` so a future blob-sourced
//! adapter makes it correct unchanged. Recorded in the B3 report.

use chrono::{DateTime, Utc};

use crate::entities::scan_policy::SeverityThreshold;
use crate::types::Finding;

use super::predicate::{BooleanOp, PolicyPredicate};
use super::reason::ExpirationReason;

/// Resolved, pure inputs the evaluator needs. Assembled by the app
/// layer from the artifact row, the artifact stream, and the scan
/// projection — the evaluator itself never does I/O.
#[derive(Debug, Clone)]
pub struct EvaluationInputs<'a> {
    /// Evaluation wall-clock (the sweep's pinned `now`).
    pub now: DateTime<Utc>,
    /// `Artifact.created_at` — the `AgeExceeds` anchor (also the
    /// cold-data fallback anchor for `HasFindingDetectedFor`).
    pub created_at: DateTime<Utc>,
    /// Most recent download wall-clock, `None` if never downloaded —
    /// the `UnusedFor` anchor.
    pub last_downloaded_at: Option<DateTime<Utc>>,
    /// `KeepLastN` ranking: this artifact's 1-based position among its
    /// sibling versions, newest = 1, and the sibling total. `None`
    /// when the app layer could not resolve a ranking (then
    /// `KeepLastN` cannot match — fail safe, never expire).
    pub keep_rank: Option<(u32, u32)>,
    /// Current scan findings for the artifact (the `scan_findings`
    /// projection rows mapped to [`Finding`]).
    pub findings: &'a [Finding],
    /// The `(purl, vulnerability_id)`-anchored "first detected at" for
    /// the matched security findings, resolved by the app layer from
    /// the artifact stream (earliest `ScanCompleted` carrying the
    /// matched pair, or `ArtifactBecameVulnerable.previously_clean_at`,
    /// or `created_at` cold-data fallback). Only consulted when a
    /// security predicate matches.
    pub first_detected_at: DateTime<Utc>,
    /// Wall-clock of the most recent `ScanCompleted` for the artifact
    /// (the freshness-gate timestamp). Carried into the
    /// `SecurityFinding` reason snapshot as `latest_scan_at`.
    pub latest_scan_at: DateTime<Utc>,
}

/// Severity ordering: `Critical` is the strongest. `true` iff `have`
/// is at-or-above `threshold` (the §4 "at-or-above" semantics for
/// `HasFindingAboveSeverity`). Pure; mirrors the private
/// `finding::severity_tier` ranking without widening its visibility.
pub fn severity_at_or_above(have: SeverityThreshold, threshold: SeverityThreshold) -> bool {
    fn rank(s: SeverityThreshold) -> u8 {
        match s {
            SeverityThreshold::Critical => 3,
            SeverityThreshold::High => 2,
            SeverityThreshold::Medium => 1,
            SeverityThreshold::Low => 0,
        }
    }
    rank(have) >= rank(threshold)
}

/// `true` iff this predicate (or, for a `Composite`, the subtree that
/// actually fired) is one of the four scan-data variants — i.e. the
/// match was security-driven and the reason must be
/// [`ExpirationReason::SecurityFinding`]. Delegates to the B1
/// [`PolicyPredicate::is_security_driven`] classification, but only for
/// the *matching* arm so a `Composite(Or, [AgeExceeds, HasFix..])`
/// that matched purely on age yields an age reason.
fn matched_via_security(pred: &PolicyPredicate, inputs: &EvaluationInputs) -> bool {
    match pred {
        PolicyPredicate::HasFindingAboveSeverity(_)
        | PolicyPredicate::HasFindingAboveCvss(_)
        | PolicyPredicate::HasFixAvailable
        | PolicyPredicate::HasFindingDetectedFor(_) => true,
        PolicyPredicate::Composite(op, kids) => match op {
            BooleanOp::And => kids.iter().any(|k| matched_via_security(k, inputs)),
            BooleanOp::Or => kids
                .iter()
                .any(|k| matches_bool(k, inputs) && matched_via_security(k, inputs)),
        },
        PolicyPredicate::AgeExceeds(_)
        | PolicyPredicate::UnusedFor(_)
        | PolicyPredicate::KeepLastN(_) => false,
    }
}

/// Pure boolean match for one predicate against the inputs. The
/// security-driven anchor (`HasFindingDetectedFor`) compares against
/// the app-resolved [`EvaluationInputs::first_detected_at`].
pub fn matches_bool(pred: &PolicyPredicate, inputs: &EvaluationInputs) -> bool {
    match pred {
        PolicyPredicate::AgeExceeds(secs) => elapsed_at_least(inputs.created_at, inputs.now, *secs),
        PolicyPredicate::UnusedFor(secs) => match inputs.last_downloaded_at {
            // Never downloaded → "unused since creation": the artifact
            // is unused for at least its full age.
            None => elapsed_at_least(inputs.created_at, inputs.now, *secs),
            Some(dl) => elapsed_at_least(dl, inputs.now, *secs),
        },
        PolicyPredicate::KeepLastN(keep) => match inputs.keep_rank {
            // No ranking resolved → fail safe, never expire.
            None => false,
            Some((rank, _total)) => rank > *keep,
        },
        PolicyPredicate::HasFindingAboveSeverity(threshold) => inputs
            .findings
            .iter()
            .any(|f| severity_at_or_above(f.severity, *threshold)),
        PolicyPredicate::HasFindingAboveCvss(min) => inputs
            .findings
            .iter()
            // NULL cvss counts as not-matched (§4 — some advisories
            // carry no CVSS).
            .any(|f| f.cvss_score.map(|c| c >= *min).unwrap_or(false)),
        PolicyPredicate::HasFixAvailable => {
            inputs.findings.iter().any(|f| !f.fixed_versions.is_empty())
        }
        PolicyPredicate::HasFindingDetectedFor(secs) => {
            // Only meaningful when there is at least one finding; the
            // anchor was resolved by the app layer for the matched
            // pair (or the cold-data fallback).
            !inputs.findings.is_empty()
                && elapsed_at_least(inputs.first_detected_at, inputs.now, *secs)
        }
        PolicyPredicate::Composite(op, kids) => match op {
            BooleanOp::And => kids.iter().all(|k| matches_bool(k, inputs)),
            BooleanOp::Or => kids.iter().any(|k| matches_bool(k, inputs)),
        },
    }
}

/// `true` iff at least `secs` seconds have elapsed between `anchor`
/// and `now`. Negative spans (clock skew / future anchor) are treated
/// as "not elapsed" rather than panicking — a future-dated `created_at`
/// must never spuriously expire an artifact.
fn elapsed_at_least(anchor: DateTime<Utc>, now: DateTime<Utc>, secs: u64) -> bool {
    let delta = now.signed_duration_since(anchor);
    match delta.to_std() {
        Ok(d) => d.as_secs() >= secs,
        Err(_) => false, // negative duration (anchor in the future)
    }
}

/// Snapshot the matched security findings into the
/// [`ExpirationReason::SecurityFinding`] payload (§4). `max_severity`
/// is the strongest tier present; `max_cvss` the highest non-null
/// score (or `None`); `fix_available` whether any finding has a
/// non-empty `fixed_versions`.
fn security_reason(inputs: &EvaluationInputs) -> ExpirationReason {
    let mut max_sev = SeverityThreshold::Low;
    for f in inputs.findings {
        if severity_at_or_above(f.severity, max_sev) {
            max_sev = f.severity;
        }
    }
    let max_cvss = inputs
        .findings
        .iter()
        .filter_map(|f| f.cvss_score)
        .fold(None::<f32>, |acc, c| Some(acc.map_or(c, |a| a.max(c))));
    let fix_available = inputs.findings.iter().any(|f| !f.fixed_versions.is_empty());
    ExpirationReason::SecurityFinding {
        max_severity: max_sev,
        max_cvss,
        finding_count: u32::try_from(inputs.findings.len()).unwrap_or(u32::MAX),
        fix_available,
        first_detected_at: inputs.first_detected_at,
        latest_scan_at: inputs.latest_scan_at,
    }
}

/// The outcome of evaluating one policy predicate against one artifact.
#[derive(Debug, Clone, PartialEq)]
pub enum EvaluationOutcome {
    /// The predicate did not match — no expiry.
    NoMatch,
    /// The predicate matched; carry the snapshotted reason for the
    /// `ArtifactExpired` event.
    Matched(ExpirationReason),
}

/// Evaluate `pred` against `inputs`, producing the
/// [`ExpirationReason`] snapshot on a match.
///
/// Reason selection: if the firing arm is security-driven the reason
/// is [`ExpirationReason::SecurityFinding`]; otherwise it is the
/// age / unused / keep-last reason that matched. A `Composite` that
/// fires on a mix prefers the security reason (the operator's
/// canonical pattern `Composite(And, [HasFindingAboveSeverity,
/// HasFixAvailable, HasFindingDetectedFor])` must record the security
/// snapshot, §1/§4).
pub fn evaluate(pred: &PolicyPredicate, inputs: &EvaluationInputs) -> EvaluationOutcome {
    if !matches_bool(pred, inputs) {
        return EvaluationOutcome::NoMatch;
    }
    if matched_via_security(pred, inputs) {
        return EvaluationOutcome::Matched(security_reason(inputs));
    }
    EvaluationOutcome::Matched(non_security_reason(pred, inputs))
}

/// Build the non-security reason for the matching arm. For a
/// `Composite` the first matching non-security child's reason is used
/// (deterministic left-to-right). A `Composite` reaching here is
/// guaranteed to have a matching non-security leaf (otherwise
/// `matched_via_security` would have been true).
fn non_security_reason(pred: &PolicyPredicate, inputs: &EvaluationInputs) -> ExpirationReason {
    match pred {
        PolicyPredicate::AgeExceeds(secs) => ExpirationReason::AgeExceeded {
            published_at: inputs.created_at,
            ttl_secs: *secs,
        },
        PolicyPredicate::UnusedFor(secs) => ExpirationReason::UnusedTtl {
            last_downloaded_at: inputs.last_downloaded_at,
            ttl_secs: *secs,
        },
        PolicyPredicate::KeepLastN(keep) => {
            let (rank, total) = inputs.keep_rank.unwrap_or((keep.saturating_add(1), *keep));
            ExpirationReason::KeepLastN {
                keep: *keep,
                total,
                rank,
            }
        }
        PolicyPredicate::Composite(_, kids) => kids
            .iter()
            .find(|k| matches_bool(k, inputs) && !matched_via_security(k, inputs))
            .map(|k| non_security_reason(k, inputs))
            // Unreachable in practice (a non-security Composite match
            // always has a matching non-security leaf), but the domain
            // tier forbids `unwrap`/`panic` on an unproven branch — a
            // defensive age reason keeps the function total.
            .unwrap_or(ExpirationReason::AgeExceeded {
                published_at: inputs.created_at,
                ttl_secs: 0,
            }),
        // A security variant never reaches here (the caller routed it
        // through `security_reason`); kept total for exhaustiveness.
        PolicyPredicate::HasFindingAboveSeverity(_)
        | PolicyPredicate::HasFindingAboveCvss(_)
        | PolicyPredicate::HasFixAvailable
        | PolicyPredicate::HasFindingDetectedFor(_) => security_reason(inputs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn finding(sev: SeverityThreshold, cvss: Option<f32>, fixed: Vec<&str>) -> Finding {
        Finding {
            purl: "pkg:npm/x@1".into(),
            vulnerability_id: "CVE-1".into(),
            severity: sev,
            cvss_score: cvss,
            title: "t".into(),
            fixed_versions: fixed.into_iter().map(String::from).collect(),
            source_scanner: "trivy".into(),
            references: vec![],
            aliases: vec![],
        }
    }

    fn inputs<'a>(findings: &'a [Finding]) -> EvaluationInputs<'a> {
        EvaluationInputs {
            now: ts(1_000_000),
            created_at: ts(0),
            last_downloaded_at: None,
            keep_rank: None,
            findings,
            first_detected_at: ts(0),
            latest_scan_at: ts(900_000),
        }
    }

    // -- severity_at_or_above ------------------------------------------------

    #[test]
    fn severity_ordering_critical_is_strongest() {
        use SeverityThreshold::*;
        assert!(severity_at_or_above(Critical, Low));
        assert!(severity_at_or_above(Critical, Critical));
        assert!(severity_at_or_above(High, Medium));
        assert!(!severity_at_or_above(Medium, High));
        assert!(!severity_at_or_above(Low, Critical));
        assert!(severity_at_or_above(Low, Low));
    }

    // -- AgeExceeds ----------------------------------------------------------

    #[test]
    fn age_exceeds_just_below_does_not_match() {
        let f = vec![];
        let mut i = inputs(&f);
        i.created_at = ts(999_000);
        i.now = ts(1_000_000); // 1000s elapsed
        let p = PolicyPredicate::AgeExceeds(1001);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn age_exceeds_just_above_matches_with_age_reason() {
        let f = vec![];
        let mut i = inputs(&f);
        i.created_at = ts(0);
        i.now = ts(1000);
        let p = PolicyPredicate::AgeExceeds(1000);
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::AgeExceeded { ttl_secs, .. }) => {
                assert_eq!(ttl_secs, 1000);
            }
            other => panic!("expected AgeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn age_exceeds_future_created_at_never_matches() {
        let f = vec![];
        let mut i = inputs(&f);
        i.created_at = ts(2_000_000); // after `now`
        i.now = ts(1_000_000);
        let p = PolicyPredicate::AgeExceeds(1);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    // -- UnusedFor -----------------------------------------------------------

    #[test]
    fn unused_for_never_downloaded_uses_created_anchor() {
        let f = vec![];
        let mut i = inputs(&f);
        i.created_at = ts(0);
        i.now = ts(5000);
        i.last_downloaded_at = None;
        let p = PolicyPredicate::UnusedFor(4000);
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::UnusedTtl {
                last_downloaded_at,
                ttl_secs,
            }) => {
                assert_eq!(last_downloaded_at, None);
                assert_eq!(ttl_secs, 4000);
            }
            other => panic!("expected UnusedTtl, got {other:?}"),
        }
    }

    #[test]
    fn unused_for_recent_download_does_not_match() {
        let f = vec![];
        let mut i = inputs(&f);
        i.now = ts(5000);
        i.last_downloaded_at = Some(ts(4900)); // 100s ago
        let p = PolicyPredicate::UnusedFor(1000);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn unused_for_old_download_matches() {
        let f = vec![];
        let mut i = inputs(&f);
        i.now = ts(10_000);
        i.last_downloaded_at = Some(ts(1000)); // 9000s ago
        let p = PolicyPredicate::UnusedFor(8000);
        assert!(matches!(
            evaluate(&p, &i),
            EvaluationOutcome::Matched(ExpirationReason::UnusedTtl { .. })
        ));
    }

    // -- KeepLastN -----------------------------------------------------------

    #[test]
    fn keep_last_n_no_ranking_never_matches() {
        let f = vec![];
        let mut i = inputs(&f);
        i.keep_rank = None;
        let p = PolicyPredicate::KeepLastN(3);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn keep_last_n_inside_window_does_not_match() {
        let f = vec![];
        let mut i = inputs(&f);
        i.keep_rank = Some((3, 10)); // rank == keep → inside window
        let p = PolicyPredicate::KeepLastN(3);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn keep_last_n_outside_window_matches_with_reason() {
        let f = vec![];
        let mut i = inputs(&f);
        i.keep_rank = Some((4, 10));
        let p = PolicyPredicate::KeepLastN(3);
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::KeepLastN { keep, total, rank }) => {
                assert_eq!((keep, total, rank), (3, 10, 4));
            }
            other => panic!("expected KeepLastN, got {other:?}"),
        }
    }

    // -- HasFindingAboveSeverity --------------------------------------------

    #[test]
    fn severity_zero_findings_no_match() {
        let f = vec![];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn severity_just_below_threshold_no_match() {
        let f = vec![finding(SeverityThreshold::Medium, None, vec![])];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn severity_at_threshold_matches_security_reason() {
        let f = vec![finding(SeverityThreshold::High, Some(7.0), vec![])];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High);
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding {
                max_severity,
                max_cvss,
                finding_count,
                ..
            }) => {
                assert_eq!(max_severity, SeverityThreshold::High);
                assert_eq!(max_cvss, Some(7.0));
                assert_eq!(finding_count, 1);
            }
            other => panic!("expected SecurityFinding, got {other:?}"),
        }
    }

    #[test]
    fn severity_mixed_picks_strongest_tier() {
        let f = vec![
            finding(SeverityThreshold::Low, Some(2.0), vec![]),
            finding(SeverityThreshold::Critical, Some(9.8), vec![]),
            finding(SeverityThreshold::Medium, None, vec![]),
        ];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High);
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding {
                max_severity,
                max_cvss,
                finding_count,
                ..
            }) => {
                assert_eq!(max_severity, SeverityThreshold::Critical);
                assert_eq!(max_cvss, Some(9.8));
                assert_eq!(finding_count, 3);
            }
            other => panic!("expected SecurityFinding, got {other:?}"),
        }
    }

    // -- HasFindingAboveCvss -------------------------------------------------

    #[test]
    fn cvss_missing_score_counts_as_not_matched() {
        let f = vec![finding(SeverityThreshold::Critical, None, vec![])];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingAboveCvss(7.0);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn cvss_just_below_no_match() {
        let f = vec![finding(SeverityThreshold::High, Some(6.9), vec![])];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingAboveCvss(7.0);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn cvss_at_threshold_matches() {
        let f = vec![finding(SeverityThreshold::High, Some(7.0), vec![])];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingAboveCvss(7.0);
        assert!(matches!(
            evaluate(&p, &i),
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding { .. })
        ));
    }

    #[test]
    fn cvss_max_is_highest_non_null() {
        let f = vec![
            finding(SeverityThreshold::Low, Some(3.1), vec![]),
            finding(SeverityThreshold::High, None, vec![]),
            finding(SeverityThreshold::Critical, Some(9.1), vec![]),
        ];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingAboveCvss(3.0);
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding { max_cvss, .. }) => {
                assert_eq!(max_cvss, Some(9.1))
            }
            other => panic!("expected SecurityFinding, got {other:?}"),
        }
    }

    // -- HasFixAvailable -----------------------------------------------------

    #[test]
    fn fix_available_empty_fixed_versions_no_match() {
        let f = vec![finding(SeverityThreshold::High, Some(7.0), vec![])];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFixAvailable;
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn fix_available_non_empty_fixed_versions_matches_with_fix_flag() {
        let f = vec![finding(SeverityThreshold::High, Some(7.0), vec!["1.2.4"])];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFixAvailable;
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding {
                fix_available, ..
            }) => assert!(fix_available),
            other => panic!("expected SecurityFinding fix_available, got {other:?}"),
        }
    }

    // -- HasFindingDetectedFor ----------------------------------------------

    #[test]
    fn detected_for_no_findings_no_match() {
        let f = vec![];
        let i = inputs(&f);
        let p = PolicyPredicate::HasFindingDetectedFor(100);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn detected_for_just_below_grace_no_match() {
        let f = vec![finding(SeverityThreshold::High, Some(7.0), vec![])];
        let mut i = inputs(&f);
        i.first_detected_at = ts(900);
        i.now = ts(1000); // detected 100s ago
        let p = PolicyPredicate::HasFindingDetectedFor(101);
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn detected_for_just_above_grace_matches() {
        let f = vec![finding(SeverityThreshold::High, Some(7.0), vec![])];
        let mut i = inputs(&f);
        i.first_detected_at = ts(0);
        i.now = ts(1000);
        let p = PolicyPredicate::HasFindingDetectedFor(1000);
        assert!(matches!(
            evaluate(&p, &i),
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding { .. })
        ));
    }

    // -- Composite -----------------------------------------------------------

    #[test]
    fn composite_and_all_must_match() {
        let f = vec![finding(SeverityThreshold::High, Some(7.0), vec!["1.2.4"])];
        let mut i = inputs(&f);
        i.first_detected_at = ts(0);
        i.now = ts(700_000); // 7d+ since detection
                             // Canonical operator pattern (§1/§4).
        let p = PolicyPredicate::Composite(
            BooleanOp::And,
            vec![
                PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                PolicyPredicate::HasFixAvailable,
                PolicyPredicate::HasFindingDetectedFor(7 * 24 * 3600),
            ],
        );
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding {
                max_severity,
                fix_available,
                ..
            }) => {
                assert_eq!(max_severity, SeverityThreshold::High);
                assert!(fix_available);
            }
            other => panic!("expected SecurityFinding, got {other:?}"),
        }
    }

    #[test]
    fn composite_and_one_child_fails_no_match() {
        let f = vec![finding(SeverityThreshold::High, Some(7.0), vec![])]; // no fix
        let mut i = inputs(&f);
        i.first_detected_at = ts(0);
        i.now = ts(700_000);
        let p = PolicyPredicate::Composite(
            BooleanOp::And,
            vec![
                PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                PolicyPredicate::HasFixAvailable, // fails
            ],
        );
        assert_eq!(evaluate(&p, &i), EvaluationOutcome::NoMatch);
    }

    #[test]
    fn composite_or_age_only_yields_age_reason_not_security() {
        let f = vec![finding(SeverityThreshold::Low, None, vec![])];
        let mut i = inputs(&f);
        i.created_at = ts(0);
        i.now = ts(10_000);
        // Or: age matches, the security child does not.
        let p = PolicyPredicate::Composite(
            BooleanOp::Or,
            vec![
                PolicyPredicate::AgeExceeds(5000),
                PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::Critical),
            ],
        );
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::AgeExceeded { ttl_secs, .. }) => {
                assert_eq!(ttl_secs, 5000);
            }
            other => panic!("expected AgeExceeded (non-security), got {other:?}"),
        }
    }

    #[test]
    fn composite_or_security_child_matches_yields_security_reason() {
        let f = vec![finding(SeverityThreshold::Critical, Some(9.0), vec![])];
        let mut i = inputs(&f);
        i.created_at = ts(0);
        i.now = ts(10); // age does NOT match
        let p = PolicyPredicate::Composite(
            BooleanOp::Or,
            vec![
                PolicyPredicate::AgeExceeds(5000),
                PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::Critical),
            ],
        );
        assert!(matches!(
            evaluate(&p, &i),
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding { .. })
        ));
    }

    #[test]
    fn composite_nested_and_inside_or() {
        let f = vec![finding(SeverityThreshold::High, Some(8.0), vec!["2.0"])];
        let mut i = inputs(&f);
        i.first_detected_at = ts(0);
        i.now = ts(1_000_000);
        let inner = PolicyPredicate::Composite(
            BooleanOp::And,
            vec![
                PolicyPredicate::HasFixAvailable,
                PolicyPredicate::HasFindingDetectedFor(1000),
            ],
        );
        let p = PolicyPredicate::Composite(
            BooleanOp::Or,
            vec![PolicyPredicate::AgeExceeds(u64::MAX), inner],
        );
        assert!(matches!(
            evaluate(&p, &i),
            EvaluationOutcome::Matched(ExpirationReason::SecurityFinding { .. })
        ));
    }

    #[test]
    fn non_security_reason_keep_last_n_without_ranking_is_total() {
        // Defensive: a non-security Composite where the matching child
        // is KeepLastN but keep_rank is None can't actually match
        // (matches_bool returns false), so this path is about the
        // `non_security_reason` fallback totality. Build a single
        // KeepLastN with a ranking to hit the rank/total snapshot.
        let f = vec![];
        let mut i = inputs(&f);
        i.keep_rank = Some((9, 12));
        let p = PolicyPredicate::Composite(BooleanOp::Or, vec![PolicyPredicate::KeepLastN(5)]);
        match evaluate(&p, &i) {
            EvaluationOutcome::Matched(ExpirationReason::KeepLastN { keep, total, rank }) => {
                assert_eq!((keep, total, rank), (5, 12, 9))
            }
            other => panic!("expected KeepLastN, got {other:?}"),
        }
    }

    #[test]
    fn evaluation_outcome_clone_debug_eq() {
        let a = EvaluationOutcome::NoMatch;
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(
            a,
            EvaluationOutcome::Matched(ExpirationReason::AgeExceeded {
                published_at: ts(0),
                ttl_secs: 1,
            })
        );
        assert!(format!("{a:?}").contains("NoMatch"));
    }

    #[test]
    fn evaluation_inputs_clone_debug() {
        let f = vec![];
        let i = inputs(&f);
        let j = i.clone();
        assert_eq!(j.findings.len(), 0);
        assert!(format!("{i:?}").contains("EvaluationInputs"));
    }
}
